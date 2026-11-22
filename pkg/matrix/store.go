// Package matrix implements the Matrix operations used by mtrxmsg.
package matrix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
	"maunium.net/go/mautrix/id"
)

const (
	sessionFile        = "session.json"
	cryptoFile         = "crypto.db"
	requestTimeout     = 45 * time.Second
	interactiveTimeout = 5 * time.Minute
)

// Service manages a single Matrix session in a private state directory.
type Service struct {
	dir string
	log *slog.Logger
}

// New constructs a service. It does not open files or make requests.
func New(stateDir string, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Service{dir: stateDir, log: logger}
}

// DefaultStateDir returns the mtrxmsg directory under XDG_DATA_HOME.
func DefaultStateDir() (string, error) {
	if dir := os.Getenv("XDG_DATA_HOME"); filepath.IsAbs(dir) {
		return filepath.Join(dir, "mtrxmsg"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "mtrxmsg"), nil
}

// Identity contains the public details of a Matrix session.
type Identity struct {
	Homeserver string      `json:"homeserver"`
	UserID     id.UserID   `json:"user_id"`
	DeviceID   id.DeviceID `json:"device_id"`
}

type session struct {
	Identity
	ClientID     string    `json:"client_id"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	PickleKey    string    `json:"pickle_key"`
}

func (s *Service) locked(ctx context.Context, op func() error) (err error) {
	if !filepath.IsAbs(s.dir) {
		return errors.New("the state directory must be an absolute path")
	}
	if err = os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("create the state directory: %w", err)
	}
	fi, err := os.Lstat(s.dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode().Perm()&0o077 != 0 {
		return errors.New("the state directory must be a private directory (mode 0700)")
	}
	lockPath := filepath.Join(s.dir, "session.lock")
	if err := checkPrivateFile(lockPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	lock := flock.New(lockPath, flock.SetPermissions(0o600))
	ok, err := lock.TryLockContext(ctx, 100*time.Millisecond)
	if err != nil {
		return fmt.Errorf("lock the state directory: %w", err)
	}
	if !ok {
		return errors.New("the state directory is in use")
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	return op()
}

func checkPrivateFile(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s must be a private file (mode 0600)", filepath.Base(path))
	}
	return nil
}

func (s *Service) load() (*session, error) {
	path := filepath.Join(s.dir, sessionFile)
	if err := checkPrivateFile(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sess session
	if json.Unmarshal(data, &sess) != nil || sess.ClientID == "" || sess.AccessToken == "" ||
		sess.UserID == "" || sess.DeviceID == "" || sess.PickleKey == "" {
		return nil, errors.New("the session file is invalid")
	}
	return &sess, nil
}

func (s *Service) save(sess *session) error {
	f, err := os.CreateTemp(s.dir, ".session-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	writeErr := json.NewEncoder(f).Encode(sess)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), filepath.Join(s.dir, sessionFile)); err != nil {
		return err
	}
	dir, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func (s *Service) clear() error {
	// Keep the session if crypto cleanup fails, so logout can be retried.
	for _, name := range []string{cryptoFile + "-shm", cryptoFile + "-wal", cryptoFile + "-journal", cryptoFile, sessionFile} {
		if err := os.Remove(filepath.Join(s.dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove local state: %w", err)
		}
	}
	return nil
}
