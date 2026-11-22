package matrix

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/cryptohelper"
	"maunium.net/go/mautrix/crypto/verificationhelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/mockserver"
)

func TestVerifyDeviceSAS(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	ms := mockserver.Create(t)
	peer, _ := ms.Login(t, ctx, "@alice:test", "PEER")
	device, _ := ms.Login(t, ctx, peer.UserID, "CLI")
	delete(ms.DeviceKeys[device.UserID], device.DeviceID)
	delete(ms.OneTimeKeys[device.UserID], device.DeviceID)

	// The mock server has no synchronization. Serialize its handlers and use
	// only this listener once both device loops start.
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_matrix/client/v3/sync" && r.URL.Query().Get("timeout") != "0" {
			time.Sleep(5 * time.Millisecond)
		}
		mu.Lock()
		defer mu.Unlock()
		ms.Router.ServeHTTP(w, r)
	}))
	defer server.Close()
	peer.HomeserverURL, _ = mautrix.ParseAndNormalizeBaseURL(server.URL)
	var batch int
	ms.Router.HandleFunc("GET /_matrix/client/v3/sync", func(w http.ResponseWriter, r *http.Request) {
		dev := device.DeviceID
		if r.Header.Get("Authorization") == "Bearer "+peer.AccessToken {
			dev = peer.DeviceID
		}
		inbox := ms.DeviceInbox[device.UserID]
		events := inbox[dev]
		delete(inbox, dev)
		batch++
		writeJSON(t, w, 200, map[string]any{
			"next_batch": fmt.Sprint(batch), "device_one_time_keys_count": map[string]int{"signed_curve25519": 50},
			"to_device": map[string][]event.Event{"events": events},
		})
	})

	machine := peer.Crypto.(*cryptohelper.CryptoHelper).Machine()
	keys, err := machine.GenerateCrossSigningKeys()
	require.NoError(t, err)
	require.NoError(t, machine.PublishCrossSigningKeys(ctx, keys, nil))
	peerEvents := &verificationEvents{}
	verifier := verificationhelper.NewVerificationHelper(peer, machine, nil, peerEvents, false, false, true)
	require.NoError(t, verifier.Init(ctx))

	svc := testService(t)
	sess := seedSession(t, svc, server.URL)
	sess.DeviceID, sess.AccessToken = device.DeviceID, device.AccessToken
	require.NoError(t, svc.save(sess))
	ready := make(chan Identity, 1)
	peerSAS := make(chan SAS, 1)
	result := make(chan error, 1)
	go func() {
		result <- svc.VerifyDevice(ctx, func(i Identity) error {
			ready <- i
			return nil
		}, func(ctx context.Context, s SAS) (bool, error) {
			select {
			case p := <-peerSAS:
				return s.OtherDevice == peer.DeviceID && len(s.Emojis) > 0 && slices.Equal(s.Emojis, p.Emojis) && slices.Equal(s.Decimals, p.Decimals), nil
			case <-ctx.Done():
				return false, ctx.Err()
			}
		})
	}()
	select {
	case i := <-ready:
		require.Equal(t, sess.Identity, i)
	case err := <-result:
		t.Fatalf("verification did not start: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// Refresh the peer's device list after the CLI uploads its keys.
	_, err = machine.FetchKeys(ctx, []id.UserID{device.UserID}, true)
	require.NoError(t, err)
	txn, err := verifier.StartVerification(ctx, device.UserID)
	require.NoError(t, err)
	for {
		select {
		case e := <-result:
			if e != nil {
				t.Fatalf("mtrxmsg verification: %v", e)
			}
			result <- e
		default:
		}
		_, err := syncKeys(ctx, peer, 100*time.Millisecond)
		require.NoError(t, err)
		for update, ok := peerEvents.pop(); ok; update, ok = peerEvents.pop() {
			require.Equal(t, txn, update.txn)
			switch update.kind {
			case verifyCompare:
				peerSAS <- update.sas
				require.NoError(t, verifier.ConfirmSAS(ctx, txn))
			case verifyCancelled:
				t.Fatal("peer cancelled verification")
			case verifyDone:
				select {
				case err := <-result:
					require.NoError(t, err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				return
			}
		}
	}
}
