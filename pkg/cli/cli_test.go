package cli

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kwo/mtrxmsg/pkg/matrix"
)

func execute(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := New()
	cmd.SetArgs(args)
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	err := cmd.ExecuteContext(t.Context())
	return stdout.String(), stderr.String(), err
}

func TestLogLevel(t *testing.T) {
	for _, tc := range []struct {
		base  string
		count int
		want  slog.Level
	}{
		{"", 0, slog.LevelError}, {"ERROR", 1, slog.LevelWarn}, {"", 2, slog.LevelInfo},
		{"", 3, slog.LevelDebug}, {"WARN", 1, slog.LevelInfo}, {"INFO", 5, slog.LevelDebug},
		{"DEBUG", 0, slog.LevelDebug},
	} {
		got, err := logLevel(tc.base, tc.count)
		require.NoError(t, err)
		require.Equal(t, tc.want, got)
	}
	_, err := logLevel("TRACE", 0)
	require.ErrorContains(t, err, "log_level")
}

func TestVersionAndHelpDoNotAccessState(t *testing.T) {
	t.Setenv("log_level", "")
	state := filepath.Join(t.TempDir(), "not-created")
	t.Setenv("XDG_DATA_HOME", state)
	out, stderr, err := execute(t, "version")
	require.NoError(t, err)
	require.Empty(t, stderr)
	require.Equal(t, "devel\n", out)
	out, _, err = execute(t, "-vv", "version")
	require.NoError(t, err)
	require.Equal(t, "devel unknown unknown "+runtime.Version()+"\n", out)
	t.Setenv("log_level", "WARN")
	out, _, err = execute(t, "version", "-v")
	require.NoError(t, err)
	require.Equal(t, "devel unknown unknown "+runtime.Version()+"\n", out)
	out, _, err = execute(t, "--help")
	require.NoError(t, err)
	require.Contains(t, out, "Send and read Matrix messages")
	_, _, err = execute(t, "--version")
	require.ErrorContains(t, err, "unknown flag: --version")
	_, err = os.Stat(state)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestCLIValidation(t *testing.T) {
	t.Setenv("log_level", "")
	state := filepath.Join(t.TempDir(), "not-created")
	t.Setenv("XDG_DATA_HOME", state)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"send", "#test:test"}, "accepts 2 arg"},
		{[]string{"read", "!test", "--limit", "0"}, "the read limit must be positive"},
		{[]string{"login"}, "required flag(s)"},
		{[]string{"room", "info"}, "accepts 1 arg"},
	} {
		out, _, err := execute(t, tc.args...)
		require.ErrorContains(t, err, tc.want)
		require.Empty(t, out)
	}
	t.Setenv("log_level", "not-a-level")
	out, _, err := execute(t, "whoami")
	require.ErrorContains(t, err, "log_level must be")
	require.Empty(t, out)
	_, err = os.Stat(state)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestConfirmSASRequiresExplicitMatch(t *testing.T) {
	sas := matrix.SAS{OtherDevice: "OTHER", Emojis: []rune{'🐶'}, EmojiDescriptions: []string{"Dog"}, Decimals: []int{1123, 4567, 8910}}
	for _, input := range []string{"yes\n", "no\n", "\n", ""} {
		var out bytes.Buffer
		got, err := compareSAS(t.Context(), strings.NewReader(input), &out, sas)
		require.NoError(t, err)
		require.Equal(t, input == "yes\n", got)
		require.Contains(t, out.String(), "🐶 (Dog)")
		require.Contains(t, out.String(), "1123 4567 8910")
	}
}
