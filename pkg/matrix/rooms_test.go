package matrix

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"maunium.net/go/mautrix/event"
)

const (
	testRoom     = "!test:test"
	testAlias    = "#test:test"
	testRoomPath = "/_matrix/client/v3/rooms/" + testRoom
)

func stateEvent(typ, stateKey string, content map[string]any) map[string]any {
	return map[string]any{"type": typ, "state_key": stateKey, "content": content}
}

func baseState() []map[string]any {
	return []map[string]any{
		stateEvent("m.room.create", "", map[string]any{}),
		stateEvent("m.room.name", "", map[string]any{"name": "Test room"}),
		stateEvent("m.room.canonical_alias", "", map[string]any{"alias": testAlias}),
	}
}

func message(id, sender, typ string, timestamp int, content map[string]any) map[string]any {
	return map[string]any{"event_id": id, "sender": sender, "type": typ, "origin_server_ts": timestamp, "content": content}
}

func textBody(text string) map[string]any { return map[string]any{"msgtype": "m.text", "body": text} }

func TestPlainRoomsAndMessages(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /_matrix/client/v3/directory/room/"+testAlias, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, 200, map[string]any{"room_id": testRoom, "servers": []string{"test"}})
	})
	mux.HandleFunc("POST /_matrix/client/v3/join/"+testRoom, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("via") != "test" {
			t.Errorf("missing join route: %s", r.URL.RawQuery)
		}
		writeJSON(t, w, 200, map[string]string{"room_id": testRoom})
	})
	mux.HandleFunc("GET /_matrix/client/v3/joined_rooms", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, 200, map[string]any{"joined_rooms": []string{testRoom}})
	})
	mux.HandleFunc("GET "+testRoomPath+"/state", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, 200, baseState())
	})
	mux.HandleFunc("PUT "+testRoomPath+"/send/m.room.message/{txn}", func(w http.ResponseWriter, r *http.Request) {
		var content event.MessageEventContent
		if json.NewDecoder(r.Body).Decode(&content) != nil || content.MsgType != event.MsgText || content.Body != "sent by alias" {
			t.Error("invalid plaintext event")
		}
		writeJSON(t, w, 200, map[string]string{"event_id": "$own"})
	})
	mux.HandleFunc("GET "+testRoomPath+"/messages", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("dir") != "b" || !json.Valid([]byte(q.Get("filter"))) {
			t.Error("missing history direction or event filter")
		}
		switch q.Get("from") {
		case "":
			if q.Get("limit") != "2" {
				t.Error("unexpected first page limit")
			}
			writeJSON(t, w, 200, map[string]any{"end": "page2", "chunk": []any{
				message("$own", "@alice:test", "m.room.message", 4, textBody("sent by alias")),
				message("$skip", "@bob:test", "m.reaction", 3, map[string]any{}),
			}})
		case "page2":
			if q.Get("limit") != "1" {
				t.Error("unexpected second page limit")
			}
			writeJSON(t, w, 200, map[string]any{"end": "page3", "chunk": []any{
				message("$other", "@bob:test", "m.room.message", 2, textBody("older message")),
			}})
		default:
			t.Error("read did not stop after reaching the limit")
			http.NotFound(w, r)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	svc := testService(t)
	seedSession(t, svc, server.URL)
	ctx := t.Context()
	wantRoom := Room{ID: testRoom, Name: "Test room", Alias: testAlias}
	room, err := svc.RoomInfo(ctx, testAlias)
	require.NoError(t, err)
	require.Equal(t, wantRoom, room)
	rooms, err := svc.ListRooms(ctx)
	require.NoError(t, err)
	require.Equal(t, []Room{wantRoom}, rooms)
	joined, err := svc.JoinRoom(ctx, testAlias)
	require.NoError(t, err)
	require.EqualValues(t, testRoom, joined)
	evt, err := svc.Send(ctx, testAlias, "sent by alias")
	require.NoError(t, err)
	require.EqualValues(t, "$own", evt)
	messages, err := svc.Read(ctx, testRoom, 2)
	require.NoError(t, err)
	require.Len(t, messages, 2)
	require.Equal(t, "older message", messages[0].Body)
	require.Equal(t, "sent by alias", messages[1].Body)
	require.EqualValues(t, "@alice:test", messages[1].Sender)
}

func TestInvalidOperationArguments(t *testing.T) {
	svc := New("invalid-relative-path", nil) // Validation must run before session access.
	_, err := svc.Read(t.Context(), testRoom, 0)
	require.ErrorContains(t, err, "the read limit must be positive")
	_, err = svc.Send(t.Context(), "room", "message")
	require.ErrorContains(t, err, "enter a room ID")
	_, err = svc.Send(t.Context(), testRoom, " ")
	require.ErrorContains(t, err, "the message must not be empty")
	_, err = svc.JoinRoom(t.Context(), "#missing-server")
	require.ErrorContains(t, err, "a room alias must have the form")
}

func TestNeverSendsPlaintextWhenEncryptionCannotBeDone(t *testing.T) {
	for _, mode := range []string{"unknown state", "incomplete state", "unsupported algorithm", "crypto setup failed"} {
		t.Run(mode, func(t *testing.T) {
			var sends atomic.Int32
			mux := http.NewServeMux()
			mux.HandleFunc("GET "+testRoomPath+"/state", func(w http.ResponseWriter, _ *http.Request) {
				switch mode {
				case "unknown state":
					http.Error(w, "private error: test-original-access", http.StatusForbidden)
				case "incomplete state":
					writeJSON(t, w, 200, []any{})
				default:
					algorithm := "m.megolm.v1.aes-sha2"
					if mode == "unsupported algorithm" {
						algorithm = "m.unsupported"
					}
					writeJSON(t, w, 200, append(baseState(), stateEvent("m.room.encryption", "", map[string]any{"algorithm": algorithm})))
				}
			})
			mux.HandleFunc("POST /_matrix/client/v3/keys/query", func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "private error: test-original-access", http.StatusForbidden)
			})
			mux.HandleFunc("PUT "+testRoomPath+"/send/{type}/{txn}", func(w http.ResponseWriter, _ *http.Request) {
				sends.Add(1)
				writeJSON(t, w, 200, map[string]string{"event_id": "$unexpected"})
			})
			server := httptest.NewServer(mux)
			defer server.Close()
			svc := testService(t)
			seedSession(t, svc, server.URL)
			_, err := svc.Send(t.Context(), testRoom, "do not leak")
			require.Error(t, err)
			require.NotContains(t, err.Error(), "test-original-access")
			require.Zero(t, sends.Load())
		})
	}
}
