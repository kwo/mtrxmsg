package matrix

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/mockserver"
)

// TestEncryptedRoundTrip uses real Olm and Megolm keys. Only the HTTP server is simulated.
func TestEncryptedRoundTrip(t *testing.T) {
	ctx := t.Context()
	ms := mockserver.Create(t)
	alice, _ := ms.Login(t, ctx, "@alice:test", "ALICE")
	bob, _ := ms.Login(t, ctx, "@bob:test", "BOB")
	a, b := testService(t), testService(t)
	for _, pair := range []struct {
		svc *Service
		cli *mautrix.Client
	}{{a, alice}, {b, bob}} {
		sess := seedSession(t, pair.svc, ms.Server.URL)
		sess.UserID, sess.DeviceID, sess.AccessToken = pair.cli.UserID, pair.cli.DeviceID, pair.cli.AccessToken
		// Each application store must start on a device without uploaded keys.
		delete(ms.DeviceKeys[pair.cli.UserID], pair.cli.DeviceID)
		delete(ms.OneTimeKeys[pair.cli.UserID], pair.cli.DeviceID)
		require.NoError(t, pair.svc.save(sess))
	}
	var mu sync.Mutex
	var nextBatch int
	var history []map[string]any
	var ackedBobKeys bool
	ms.Router.HandleFunc("GET "+testRoomPath+"/state", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, 200, append(baseState(),
			stateEvent("m.room.encryption", "", map[string]any{"algorithm": "m.megolm.v1.aes-sha2"}),
			stateEvent("m.room.member", alice.UserID.String(), map[string]any{"membership": "join"}),
			stateEvent("m.room.member", bob.UserID.String(), map[string]any{"membership": "join"}),
		))
	})
	ms.Router.HandleFunc("GET /_matrix/client/v3/sync", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		u, d := alice.UserID, alice.DeviceID
		if r.Header.Get("Authorization") == "Bearer "+bob.AccessToken {
			u, d = bob.UserID, bob.DeviceID
			if ackedBobKeys && r.URL.Query().Get("since") == "" {
				t.Error("Bob did not reopen his saved sync position")
			}
		}
		events := ms.DeviceInbox[u][d]
		delete(ms.DeviceInbox[u], d)
		if u == bob.UserID && len(events) > 0 {
			ackedBobKeys = true
		}
		nextBatch++
		writeJSON(t, w, 200, map[string]any{
			"next_batch": fmt.Sprint(nextBatch), "device_one_time_keys_count": map[string]int{"signed_curve25519": 50},
			"to_device": map[string][]event.Event{"events": events},
		})
	})
	ms.Router.HandleFunc("PUT "+testRoomPath+"/send/{type}/{txn}", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		typ := r.PathValue("type")
		var content map[string]any
		if json.NewDecoder(r.Body).Decode(&content) != nil || typ != "m.room.encrypted" || content["body"] != nil || content["ciphertext"] == nil {
			t.Error("the send did not use encrypted event content")
		}
		evtID := fmt.Sprintf("$encrypted%d", len(history)+1)
		sender := alice.UserID
		if r.Header.Get("Authorization") == "Bearer "+bob.AccessToken {
			sender = bob.UserID
		}
		history = append([]map[string]any{message(evtID, sender.String(), typ, len(history)+1, content)}, history...)
		writeJSON(t, w, 200, map[string]string{"event_id": evtID})
	})
	ms.Router.HandleFunc("GET "+testRoomPath+"/messages", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		writeJSON(t, w, 200, map[string]any{"chunk": history})
	})

	_, err := b.Read(ctx, testRoom, 20) // Upload Bob's device keys before Alice sends.
	require.NoError(t, err)
	_, err = a.Send(ctx, testRoom, "encrypted alpha")
	require.NoError(t, err)
	for _, receiver := range []*Service{a, b, New(b.dir, nil)} {
		messages, err := receiver.Read(ctx, testRoom, 20)
		require.NoError(t, err)
		require.Len(t, messages, 1)
		require.Equal(t, "encrypted alpha", messages[0].Body)
	}
	fi, err := os.Stat(filepath.Join(b.dir, cryptoFile))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())

	_, err = b.Send(ctx, testRoom, "encrypted beta")
	require.NoError(t, err)
	messages, err := a.Read(ctx, testRoom, 20)
	require.NoError(t, err)
	require.Len(t, messages, 2)
	require.Equal(t, "encrypted alpha", messages[0].Body)
	require.Equal(t, "encrypted beta", messages[1].Body)

	missing := map[string]any{}
	for key, value := range history[0]["content"].(map[string]any) {
		missing[key] = value
	}
	missing["session_id"] = strings.Repeat("A", 43)
	mu.Lock()
	history = append([]map[string]any{message("$missing", "@bob:test", "m.room.encrypted", 3, missing)}, history...)
	mu.Unlock()
	messages, err = a.Read(ctx, testRoom, 20)
	require.NoError(t, err)
	require.Len(t, messages, 3)
	require.Equal(t, "encrypted beta", messages[1].Body)
	require.Equal(t, Message{ID: id.EventID("$missing"), Sender: bob.UserID, Time: messages[2].Time, Undecryptable: true}, messages[2])
}
