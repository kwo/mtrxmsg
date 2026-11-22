package matrix

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"time"

	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/cryptohelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	_ "modernc.org/sqlite"
)

// History is decrypted on demand. Do not let cryptohelper start background
// decryption, session requests, or long waits for events from /sync.
type keySyncer struct{ *mautrix.DefaultSyncer }

func (s keySyncer) OnEventType(typ event.Type, handler mautrix.EventHandler) {
	if typ != event.EventEncrypted {
		s.DefaultSyncer.OnEventType(typ, handler)
	}
}

func (s *Service) openCrypto(ctx context.Context, cli *mautrix.Client, sess *session) (*cryptohelper.CryptoHelper, error) {
	path := filepath.Join(s.dir, cryptoFile)
	if err := checkPrivateFile(path); errors.Is(err, os.ErrNotExist) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("create the crypto database: %w", err)
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	uri := url.URL{Scheme: "file", Path: path, RawQuery: "_pragma=foreign_keys(1)"}
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return nil, fmt.Errorf("open the crypto database: %w", err)
	}
	db.SetMaxOpenConns(1)
	wrapped, err := dbutil.NewWithDB(db, "sqlite3")
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("prepare the crypto database: %w", err)
	}
	cli.Syncer = keySyncer{mautrix.NewDefaultSyncer()}
	helper, err := cryptohelper.NewCryptoHelper(cli, []byte(sess.PickleKey), wrapped)
	if err == nil {
		err = helper.Init(ctx)
	}
	if err != nil {
		_ = db.Close()
		var httpErr mautrix.HTTPError
		if errors.As(err, &httpErr) || ctx.Err() != nil {
			return nil, requestError("initialize Matrix encryption", err)
		}
		// Crypto errors can wrap data returned by the server.
		return nil, errors.New("initialize Matrix encryption: cannot open the crypto store or validate the device keys")
	}
	cli.Crypto = helper
	return helper, nil
}

func syncKeys(ctx context.Context, cli *mautrix.Client, wait time.Duration) (*mautrix.RespSync, error) {
	ignored := &mautrix.FilterPart{NotTypes: []event.Type{event.NewEventType("*")}}
	stateTypes := []event.Type{event.StateMember, event.StateEncryption, event.StateHistoryVisibility}
	filter, err := json.Marshal(mautrix.Filter{
		Presence: ignored, AccountData: ignored,
		Room: &mautrix.RoomFilter{
			Ephemeral: ignored, AccountData: ignored, IncludeLeave: true,
			State:    &mautrix.FilterPart{Types: stateTypes},
			Timeline: &mautrix.FilterPart{Types: stateTypes, Limit: 20},
		},
	})
	if err != nil {
		return nil, err
	}
	since, err := cli.Store.LoadNextBatch(ctx, cli.UserID)
	if err != nil {
		return nil, errors.New("load the crypto sync position")
	}
	resp, err := cli.SyncRequest(ctx, int(wait.Milliseconds()), since, string(filter), false, event.PresenceOffline)
	if err != nil {
		return nil, requestError("sync encryption keys", err)
	}
	if resp == nil || resp.NextBatch == "" {
		return nil, errors.New("missing sync position in the Matrix response")
	}
	if err := cli.Syncer.ProcessResponse(ctx, resp, since); err != nil {
		return nil, errors.New("process Matrix encryption updates: invalid sync response")
	}
	if err := cli.Store.SaveNextBatch(ctx, cli.UserID, resp.NextBatch); err != nil {
		return nil, errors.New("save the crypto sync position")
	}
	return resp, nil
}

func (s *Service) encrypt(ctx context.Context, sess *session, cli *mautrix.Client, roomID id.RoomID, state mautrix.RoomStateMap, content *event.MessageEventContent) (*event.EncryptedEventContent, error) {
	enc, ok := state[event.StateEncryption][""].Content.Parsed.(*event.EncryptionEventContent)
	if !ok || enc.Algorithm != id.AlgorithmMegolmV1 {
		return nil, errors.New("the room uses an unsupported encryption algorithm")
	}
	helper, err := s.openCrypto(ctx, cli, sess)
	if err != nil {
		return nil, err
	}
	defer func() { _ = helper.Close() }()
	if _, err := syncKeys(ctx, cli, 0); err != nil {
		return nil, err
	}
	// Get current membership after sync. Do not reuse a session shared with
	// former members or devices whose removal a limited sync could have missed.
	state, err = roomState(ctx, cli, roomID)
	if err != nil {
		return nil, err
	}
	encEvent := state[event.StateEncryption][""]
	if encEvent == nil {
		return nil, errors.New("the room encryption state changed during send")
	}
	enc, ok = encEvent.Content.Parsed.(*event.EncryptionEventContent)
	if !ok || enc.Algorithm != id.AlgorithmMegolmV1 {
		return nil, errors.New("the room uses an unsupported encryption algorithm")
	}
	if err := cli.StateStore.SetEncryptionEvent(ctx, roomID, enc); err != nil {
		return nil, errors.New("store the room encryption state")
	}
	visibility := &event.HistoryVisibilityEventContent{HistoryVisibility: event.HistoryVisibilityShared}
	if evt := state[event.StateHistoryVisibility][""]; evt != nil {
		visibility, ok = evt.Content.Parsed.(*event.HistoryVisibilityEventContent)
		if !ok {
			return nil, errors.New("invalid room history visibility")
		}
	}
	if err := cli.StateStore.SetHistoryVisibility(ctx, roomID, visibility); err != nil {
		return nil, errors.New("store the room history visibility")
	}
	members := slices.Collect(maps.Values(state[event.StateMember]))
	joined := false
	for _, evt := range members {
		member, ok := evt.Content.Parsed.(*event.MemberEventContent)
		if !ok || member.Membership == "" {
			return nil, errors.New("invalid room membership")
		}
		joined = joined || (evt.GetStateKey() == cli.UserID.String() && member.Membership == event.MembershipJoin)
	}
	if !joined {
		return nil, errors.New("join the encrypted room before you send a message")
	}
	if err := cli.StateStore.ReplaceCachedMembers(ctx, roomID, members); err != nil {
		return nil, errors.New("store the room membership")
	}
	users, err := cli.StateStore.GetRoomJoinedOrInvitedMembers(ctx, roomID)
	if err != nil {
		return nil, errors.New("load the room membership")
	}
	mach := helper.Machine()
	if err := mach.CryptoStore.RemoveOutboundGroupSession(ctx, roomID); err != nil {
		return nil, errors.New("renew the room encryption session")
	}
	if _, err := mach.FetchKeys(ctx, users, true); err != nil {
		return nil, requestError("get room members' device keys", err)
	}
	payload, err := helper.Encrypt(ctx, roomID, event.EventMessage, content)
	if err != nil {
		return nil, requestError("encrypt the message", err)
	}
	return payload, nil
}

func (s *Service) readHistory(ctx context.Context, sess *session, cli *mautrix.Client, roomID id.RoomID, limit int) ([]Message, error) {
	state, err := roomState(ctx, cli, roomID)
	if err != nil {
		return nil, err
	}
	var helper *cryptohelper.CryptoHelper
	if state[event.StateEncryption][""] != nil {
		helper, err = s.openCrypto(ctx, cli, sess)
		if err != nil {
			return nil, err
		}
		defer func() { _ = helper.Close() }()
		if _, err := syncKeys(ctx, cli, 0); err != nil {
			s.log.WarnContext(ctx, "Cannot sync encryption keys. Read with the keys in the crypto store", "error", err)
		}
	}
	var messages []Message
	seen := make(map[id.EventID]bool)
	seenPages := make(map[string]bool)
	from := ""
	waited := false
	filter := &mautrix.FilterPart{Types: []event.Type{event.EventMessage, event.EventEncrypted}}
	for len(messages) < limit {
		resp, err := cli.Messages(ctx, roomID, from, "", mautrix.DirectionBackward, filter, min(limit-len(messages), 100))
		if err != nil {
			return nil, requestError("read room messages", err)
		}
		if resp == nil {
			return nil, errors.New("missing room messages in the Matrix response")
		}
		for _, evt := range resp.Chunk {
			if evt == nil || evt.StateKey != nil || evt.ID == "" || seen[evt.ID] {
				continue
			}
			seen[evt.ID] = true
			evt.RoomID = roomID
			evt.Type.Class = event.MessageEventType
			msg := Message{ID: evt.ID, Sender: evt.Sender, Time: time.UnixMilli(evt.Timestamp).UTC()}
			if evt.Type == event.EventEncrypted {
				plain, err := decrypt(ctx, helper, evt)
				if !waited && errors.Is(err, crypto.ErrNoSessionFound) {
					waited = true
					plain, err = awaitKey(ctx, cli, helper, evt)
				}
				if err != nil {
					msg.Undecryptable = true
				} else {
					evt = plain
				}
			}
			if !msg.Undecryptable {
				if evt.Type != event.EventMessage {
					continue
				}
				if evt.Content.Parsed == nil && evt.Content.ParseRaw(evt.Type) != nil {
					continue
				}
				content := evt.Content.AsMessage()
				if content.MsgType == "" || content.MsgType == event.MsgVerificationRequest {
					continue
				}
				msg.Body = content.Body
			}
			messages = append(messages, msg)
			if len(messages) == limit {
				break
			}
		}
		if resp.End == "" || resp.End == from || seenPages[resp.End] {
			break
		}
		seenPages[resp.End] = true
		from = resp.End
	}
	slices.Reverse(messages)
	return messages, nil
}

func decrypt(ctx context.Context, helper *cryptohelper.CryptoHelper, evt *event.Event) (*event.Event, error) {
	if helper == nil {
		return nil, errors.New("the crypto store is not open")
	}
	if evt.Content.Parsed == nil {
		if err := evt.Content.ParseRaw(evt.Type); err != nil {
			return nil, err
		}
	}
	return helper.Decrypt(ctx, evt)
}

func awaitKey(ctx context.Context, cli *mautrix.Client, helper *cryptohelper.CryptoHelper, evt *event.Event) (*event.Event, error) {
	grace, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var plain *event.Event
	err := crypto.ErrNoSessionFound
	for grace.Err() == nil {
		resp, syncErr := syncKeys(grace, cli, 2*time.Second)
		if syncErr != nil || len(resp.ToDevice.Events) == 0 {
			break
		}
		plain, err = decrypt(ctx, helper, evt)
		if !errors.Is(err, crypto.ErrNoSessionFound) {
			break
		}
	}
	return plain, err
}
