package matrix

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"maunium.net/go/mautrix/oauth"
)

func testService(t *testing.T) *Service {
	t.Helper()
	return New(filepath.Join(t.TempDir(), "state"), nil)
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, data any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		t.Error(err)
	}
}

func seedSession(t *testing.T, svc *Service, homeserver string) *session {
	t.Helper()
	sess := &session{
		Identity: Identity{Homeserver: homeserver, UserID: "@alice:test", DeviceID: "TESTDEVICE"},
		ClientID: "client", AccessToken: "test-original-access", RefreshToken: "test-original-refresh", PickleKey: "test-pickle-key",
	}
	require.NoError(t, svc.locked(t.Context(), func() error { return svc.save(sess) }))
	return sess
}

func TestLogin(t *testing.T) {
	var requests atomic.Int32
	var authorization atomic.Value // url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := "http://" + r.Host
		switch r.Method + " " + r.URL.Path {
		case "GET /_matrix/client/v1/auth_metadata":
			writeJSON(t, w, 200, oauth.ServerMetadata{
				RegistrationEndpoint: origin + "/register", AuthorizationEndpoint: origin + "/authorize",
				TokenEndpoint: origin + "/token", RevocationEndpoint: origin + "/revoke",
			})
		case "POST /register":
			var req oauth.ClientMetadata
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
			}
			if req.ApplicationType != oauth.ApplicationTypeNative || req.TokenEndpointAuthMethod != oauth.AuthMethodNone ||
				len(req.RedirectURIs) != 1 || req.RedirectURIs[0] != registeredRedirect {
				t.Errorf("unexpected client registration: %+v", req)
			}
			writeJSON(t, w, 201, map[string]string{"client_id": "client"})
		case "POST /token":
			requests.Add(1)
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			auth, _ := authorization.Load().(url.Values)
			challenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if r.Form.Get("code") != "synthetic-code" || r.Form.Get("client_id") != "client" ||
				r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("redirect_uri") != auth.Get("redirect_uri") ||
				base64.RawURLEncoding.EncodeToString(challenge[:]) != auth.Get("code_challenge") {
				t.Error("invalid authorization code exchange")
			}
			writeJSON(t, w, 200, map[string]any{
				"token_type": "Bearer", "access_token": "login-access", "refresh_token": "login-refresh", "expires_in": 3600,
			})
		case "GET /_matrix/client/v3/account/whoami":
			if r.Header.Get("Authorization") != "Bearer login-access" {
				t.Error("whoami did not use the issued access token")
			}
			writeJSON(t, w, 200, map[string]string{"user_id": "@alice:test", "device_id": "TESTDEVICE"})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	svc := testService(t)
	// Reserve a fixed port, then release it so Login can bind it.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	identity, err := svc.Login(t.Context(), server.URL, port, func(raw string) error {
		authURL, err := url.Parse(raw)
		if err != nil {
			return err
		}
		auth := authURL.Query()
		authorization.Store(auth)
		redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", port)
		if auth.Get("redirect_uri") != redirect || auth.Get("response_mode") != "query" ||
			auth.Get("code_challenge_method") != "S256" || !strings.HasPrefix(auth.Get("scope"), "urn:matrix:client:api:* urn:matrix:client:device:") {
			return fmt.Errorf("invalid authorization request")
		}
		for _, tc := range []struct {
			state  string
			status int
		}{{"wrong", 400}, {auth.Get("state"), 200}} {
			if requests.Load() != 0 {
				return fmt.Errorf("the code exchange started too early")
			}
			q := url.Values{"state": {tc.state}, "code": {"synthetic-code"}}
			res, err := httpClient.Get(redirect + "?" + q.Encode())
			if err != nil {
				return err
			}
			_ = res.Body.Close()
			if res.StatusCode != tc.status {
				return fmt.Errorf("callback returned HTTP %d, want %d", res.StatusCode, tc.status)
			}
		}
		return nil
	})
	require.NoError(t, err)
	require.EqualValues(t, "@alice:test", identity.UserID)
	require.EqualValues(t, "TESTDEVICE", identity.DeviceID)
	require.EqualValues(t, 1, requests.Load())
	saved, err := New(svc.dir, nil).Whoami(t.Context())
	require.NoError(t, err)
	require.Equal(t, identity, saved)
	f, err := os.Stat(filepath.Join(svc.dir, sessionFile))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), f.Mode().Perm())
}

func TestCallbackTimeoutAndOccupiedPort(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = ln.Close() })
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
		defer cancel()
		_, err = waitForCallback(ctx, ln, "expected", func() error { return nil })
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})
	t.Run("occupied", func(t *testing.T) {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = ln.Close() })
		announced := false
		_, err = testService(t).Login(t.Context(), "https://example.test", ln.Addr().(*net.TCPAddr).Port, func(string) error {
			announced = true
			return nil
		})
		require.ErrorContains(t, err, "listen for the OAuth callback")
		require.False(t, announced)
	})
}

func TestRefreshAndRevoke(t *testing.T) {
	var revoked atomic.Bool
	var failRevocation atomic.Bool
	failRevocation.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := "http://" + r.Host
		switch r.Method + " " + r.URL.Path {
		case "GET /_matrix/client/v1/auth_metadata":
			writeJSON(t, w, 200, oauth.ServerMetadata{TokenEndpoint: origin + "/token", RevocationEndpoint: origin + "/revoke"})
		case "POST /token":
			if r.ParseForm() != nil || r.Form.Get("grant_type") != "refresh_token" ||
				r.Form.Get("client_id") != "client" || r.Form.Get("refresh_token") != "test-original-refresh" {
				t.Error("invalid refresh grant")
			}
			writeJSON(t, w, 200, map[string]any{
				"token_type": "Bearer", "access_token": "rotated-access", "refresh_token": "rotated-refresh", "expires_in": 3600,
			})
		case "GET /_matrix/client/v3/account/whoami":
			if r.Header.Get("Authorization") != "Bearer rotated-access" {
				t.Error("whoami did not use the rotated token")
			}
			writeJSON(t, w, 200, map[string]string{"user_id": "@alice:test", "device_id": "TESTDEVICE"})
		case "POST /revoke":
			if r.ParseForm() != nil || r.Form.Get("token_type_hint") != "refresh_token" || r.Form.Get("token") != "rotated-refresh" {
				t.Error("invalid revocation request")
			}
			if failRevocation.Load() {
				http.Error(w, "token was rotated-refresh", http.StatusUnauthorized)
				return
			}
			revoked.Store(true)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	svc := testService(t)
	sess := seedSession(t, svc, server.URL)
	sess.ExpiresAt = time.Now().Add(-time.Minute)
	require.NoError(t, svc.save(sess))
	cryptoPath := filepath.Join(svc.dir, cryptoFile)
	require.NoError(t, os.WriteFile(cryptoPath, []byte("test"), 0o600))
	identity, err := svc.Whoami(t.Context())
	require.NoError(t, err)
	require.Equal(t, sess.Identity, identity)
	rotated, err := svc.load()
	require.NoError(t, err)
	require.Equal(t, "rotated-access", rotated.AccessToken)
	require.Equal(t, "rotated-refresh", rotated.RefreshToken)
	require.True(t, rotated.ExpiresAt.After(time.Now()))
	err = svc.Logout(t.Context())
	require.ErrorContains(t, err, "401")
	require.NotContains(t, err.Error(), "rotated-refresh")
	require.FileExists(t, cryptoPath)
	require.FileExists(t, filepath.Join(svc.dir, sessionFile))
	failRevocation.Store(false)
	require.NoError(t, svc.Logout(t.Context()))
	require.True(t, revoked.Load())
	require.NoFileExists(t, cryptoPath)
	require.NoFileExists(t, filepath.Join(svc.dir, sessionFile))
}
