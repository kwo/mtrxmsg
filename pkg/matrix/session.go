package matrix

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/oauth"
)

const registeredRedirect = "http://127.0.0.1/callback"

var httpClient = &http.Client{
	Timeout: requestTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func endpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("invalid URL")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && (u.Scheme != "http" || !ip.IsLoopback()) {
		return nil, errors.New("the URL must use HTTPS or loopback HTTP")
	}
	return u, nil
}

func newClient(identity Identity, token string) (*mautrix.Client, error) {
	u, err := endpoint(identity.Homeserver)
	if err != nil || u.RawQuery != "" {
		return nil, errors.New("the homeserver must be an HTTPS or loopback HTTP URL without a query")
	}
	cli, err := mautrix.NewClient(u.String(), identity.UserID, token)
	if err != nil {
		return nil, errors.New("invalid homeserver URL")
	}
	cli.DeviceID = identity.DeviceID
	cli.Client = httpClient
	cli.UserAgent = "mtrxmsg"
	return cli, nil
}

// requestError omits URLs, server error bodies, and request data from errors.
func requestError(operation string, err error) error {
	var he mautrix.HTTPError
	switch {
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("%s: %w", operation, context.Canceled)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%s: %w", operation, context.DeadlineExceeded)
	case errors.As(err, &he) && he.Response != nil:
		status := he.Response.StatusCode
		if status >= 200 && status < 300 {
			return fmt.Errorf("%s: invalid response", operation)
		}
		return fmt.Errorf("%s: HTTP %d", operation, status)
	default:
		return fmt.Errorf("%s: request failed", operation)
	}
}

func oauthRequest(ctx context.Context, operation, method, rawURL, contentType string, body io.Reader, result any) error {
	u, err := endpoint(rawURL)
	if err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return requestError(operation, err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("User-Agent", "mtrxmsg")
	res, err := httpClient.Do(req)
	if err != nil {
		return requestError(operation, err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("%s: HTTP %d", operation, res.StatusCode)
	}
	if result != nil && json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(result) != nil {
		return fmt.Errorf("%s: invalid response", operation)
	}
	return nil
}

func metadata(ctx context.Context, cli *mautrix.Client) (*oauth.ServerMetadata, error) {
	var meta oauth.ServerMetadata
	err := oauthRequest(ctx, "discover OAuth endpoints", http.MethodGet, cli.BuildClientURL("v1", "auth_metadata"), "", nil, &meta)
	return &meta, err
}

func tokens(ctx context.Context, operation, target string, values url.Values, sess *session) error {
	var r oauth.TokenResponse
	values.Set("client_id", sess.ClientID)
	start := time.Now()
	if err := oauthRequest(ctx, operation, http.MethodPost, target, "application/x-www-form-urlencoded", strings.NewReader(values.Encode()), &r); err != nil {
		return err
	}
	if r.AccessToken == "" || !strings.EqualFold(r.TokenType, "Bearer") || r.ExpiresIn.Duration < 0 {
		return fmt.Errorf("%s: invalid token response", operation)
	}
	sess.AccessToken = r.AccessToken
	if r.RefreshToken != "" {
		sess.RefreshToken = r.RefreshToken
	}
	sess.ExpiresAt = time.Time{}
	if r.ExpiresIn.Duration > 0 {
		sess.ExpiresAt = start.Add(r.ExpiresIn.Duration)
	}
	return nil
}

// Login starts browser sign-in and saves the session after Matrix confirms the identity.
// showURL receives the authorization URL. A zero port selects an available loopback port.
func (s *Service) Login(ctx context.Context, homeserver string, port int, showURL func(string) error) (identity Identity, err error) {
	cli, err := newClient(Identity{Homeserver: homeserver}, "")
	if err != nil {
		return identity, err
	}
	if port < 0 || port > 65535 || showURL == nil {
		return identity, errors.New("login requires a callback port from 0 to 65535 and a sign-in URL handler")
	}
	ctx, cancel := context.WithTimeout(ctx, interactiveTimeout)
	defer cancel()
	err = s.locked(ctx, func() error {
		if _, err := os.Lstat(filepath.Join(s.dir, sessionFile)); err == nil {
			return errors.New("a session already exists. Run logout before you sign in again")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		sess := session{Identity: Identity{Homeserver: cli.HomeserverURL.String()}, PickleKey: rand.Text() + rand.Text()}
		if err := s.login(ctx, cli, &sess, port, showURL); err != nil {
			return err
		}
		if err := s.save(&sess); err != nil {
			return fmt.Errorf("save the session: %w", err)
		}
		identity = sess.Identity
		return nil
	})
	return identity, err
}

func (s *Service) login(ctx context.Context, cli *mautrix.Client, sess *session, port int, showURL func(string) error) error {
	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("listen for the OAuth callback: %w", err)
	}
	defer func() { _ = listener.Close() }()
	s.log.DebugContext(ctx, "Discover OAuth endpoints")
	meta, err := metadata(ctx, cli)
	if err != nil {
		return err
	}
	for _, target := range []string{meta.TokenEndpoint, meta.RevocationEndpoint, meta.RegistrationEndpoint, meta.AuthorizationEndpoint} {
		if _, err := endpoint(target); err != nil {
			return errors.New("OAuth metadata lacks a valid authorization, registration, token, or revocation endpoint")
		}
	}
	registration, err := json.Marshal(oauth.ClientMetadata{
		ApplicationType:         oauth.ApplicationTypeNative,
		ClientName:              "mtrxmsg",
		ClientURI:               "https://github.com/kwo/mtrxmsg",
		GrantTypes:              []oauth.GrantType{oauth.GrantTypeAuthorizationCode, oauth.GrantTypeRefreshToken},
		RedirectURIs:            []string{registeredRedirect},
		ResponseTypes:           []oauth.ResponseType{oauth.ResponseTypeCode},
		TokenEndpointAuthMethod: oauth.AuthMethodNone,
	})
	if err != nil {
		return errors.New("encode the OAuth client registration")
	}
	var registered oauth.ClientMetadata
	if err := oauthRequest(ctx, "register the OAuth client", http.MethodPost, meta.RegistrationEndpoint, "application/json", bytes.NewReader(registration), &registered); err != nil {
		return err
	}
	if registered.ClientID == "" {
		return errors.New("OAuth registration did not return a client ID")
	}
	sess.ClientID = registered.ClientID
	redirect := "http://" + listener.Addr().String() + "/callback"
	state, verifier := rand.Text(), base64.RawURLEncoding.EncodeToString(randomVerifier())
	challenge := sha256.Sum256([]byte(verifier))
	authURL, err := endpoint(meta.AuthorizationEndpoint)
	if err != nil {
		return err
	}
	query := authURL.Query()
	query.Set("client_id", sess.ClientID)
	query.Set("redirect_uri", redirect)
	query.Set("response_type", "code")
	query.Set("response_mode", "query")
	query.Set("scope", oauth.ScopeList{oauth.ScopeClientAPI, oauth.ScopeDevice(id.DeviceID(rand.Text()))}.String())
	query.Set("state", state)
	query.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	query.Set("code_challenge_method", "S256")
	authURL.RawQuery = query.Encode()
	code, err := waitForCallback(ctx, listener, state, func() error { return showURL(authURL.String()) })
	if err != nil {
		return err
	}
	if err := tokens(ctx, "exchange the OAuth code", meta.TokenEndpoint, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "code_verifier": {verifier},
	}, sess); err != nil {
		return err
	}
	cli.AccessToken = sess.AccessToken
	identity, err := whoami(ctx, cli)
	if err == nil {
		sess.Identity = identity
	}
	return err
}

func randomVerifier() []byte {
	buf := make([]byte, 32)
	rand.Read(buf)
	return buf
}

type callbackResult struct {
	code string
	err  error
}

func waitForCallback(ctx context.Context, listener net.Listener, state string, announce func() error) (string, error) {
	result := make(chan callbackResult, 1)
	serveErr := make(chan error, 1)
	var accepted atomic.Bool
	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      5 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Referrer-Policy", "no-referrer")
			if r.Method != http.MethodGet || r.URL.Path != "/callback" || r.Host != listener.Addr().String() {
				http.NotFound(w, r)
				return
			}
			q, err := url.ParseQuery(r.URL.RawQuery)
			if err != nil || len(q["state"]) != 1 || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1 {
				http.Error(w, "Invalid sign-in state.", http.StatusBadRequest)
				return
			}
			failed := q.Get("error") != ""
			if !failed && (len(q["code"]) != 1 || q.Get("code") == "") {
				http.Error(w, "Missing sign-in code.", http.StatusBadRequest)
				return
			}
			if !accepted.CompareAndSwap(false, true) {
				http.Error(w, "The CLI already received a response.", http.StatusConflict)
				return
			}
			if failed {
				http.Error(w, "The authorization server declined sign-in.", http.StatusBadRequest)
				result <- callbackResult{err: errors.New("the authorization server declined sign-in")}
				return
			}
			_, _ = fmt.Fprintln(w, "The CLI received the sign-in response. Return to the terminal for the result.")
			result <- callbackResult{code: q.Get("code")}
		}),
	}
	go func() { serveErr <- server.Serve(listener) }()
	defer func() { _ = server.Close() }()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := announce(); err != nil {
		return "", fmt.Errorf("show the sign-in URL: %w", err)
	}
	select {
	case <-ctx.Done():
		return "", fmt.Errorf("wait for the OAuth callback: %w", ctx.Err())
	case err := <-serveErr:
		return "", fmt.Errorf("serve the OAuth callback: %w", err)
	case r := <-result:
		shutdown, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		return r.code, r.err
	}
}

func whoami(ctx context.Context, cli *mautrix.Client) (Identity, error) {
	resp, err := cli.Whoami(ctx)
	if err != nil {
		return Identity{}, requestError("get the Matrix identity", err)
	}
	if resp == nil || resp.UserID == "" || resp.DeviceID == "" {
		return Identity{}, errors.New("missing user or device ID in the Matrix response")
	}
	return Identity{Homeserver: cli.HomeserverURL.String(), UserID: resp.UserID, DeviceID: resp.DeviceID}, nil
}

func (s *Service) withSession(ctx context.Context, op func(*session, *mautrix.Client) error) error {
	return s.locked(ctx, func() error {
		sess, err := s.load()
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("no saved session. Run login first")
		}
		if err != nil {
			return err
		}
		cli, err := newClient(sess.Identity, sess.AccessToken)
		if err != nil {
			return err
		}
		return op(sess, cli)
	})
}

func (s *Service) refresh(ctx context.Context, sess *session, cli *mautrix.Client) error {
	if sess.ExpiresAt.IsZero() || time.Until(sess.ExpiresAt) > time.Minute {
		return nil
	}
	if sess.RefreshToken == "" {
		if time.Now().Before(sess.ExpiresAt) {
			return nil
		}
		return errors.New("the Matrix session expired without a refresh token. Run logout, then login")
	}
	s.log.DebugContext(ctx, "Refresh the Matrix session")
	meta, err := metadata(ctx, cli)
	if err != nil {
		return err
	}
	if err := tokens(ctx, "refresh the Matrix session", meta.TokenEndpoint, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {sess.RefreshToken},
	}, sess); err != nil {
		return err
	}
	if err := s.save(sess); err != nil {
		return fmt.Errorf("save the refreshed session: %w", err)
	}
	cli.AccessToken = sess.AccessToken
	return nil
}

// Whoami confirms the user and device of the saved session with Matrix.
func (s *Service) Whoami(ctx context.Context) (identity Identity, err error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	err = s.withSession(ctx, func(sess *session, cli *mautrix.Client) error {
		if err := s.refresh(ctx, sess, cli); err != nil {
			return err
		}
		identity, err = whoami(ctx, cli)
		if err == nil && (identity.UserID != sess.UserID || identity.DeviceID != sess.DeviceID) {
			return errors.New("the Matrix identity does not match the saved session")
		}
		return err
	})
	return identity, err
}

// Logout revokes the OAuth session before it removes local credentials and encryption state.
func (s *Service) Logout(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	return s.withSession(ctx, func(sess *session, cli *mautrix.Client) error {
		meta, err := metadata(ctx, cli)
		if err != nil {
			return err
		}
		token, hint := sess.RefreshToken, "refresh_token"
		if token == "" {
			token, hint = sess.AccessToken, "access_token"
		}
		values := url.Values{"token": {token}, "token_type_hint": {hint}, "client_id": {sess.ClientID}}
		if err := oauthRequest(ctx, "revoke the Matrix session", http.MethodPost, meta.RevocationEndpoint,
			"application/x-www-form-urlencoded", strings.NewReader(values.Encode()), nil); err != nil {
			return err
		}
		return s.clear()
	})
}
