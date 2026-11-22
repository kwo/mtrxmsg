// Package cli defines the mtrxmsg commands and formats their results.
package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/kwo/mtrxmsg/pkg/matrix"
	"github.com/kwo/mtrxmsg/pkg/version"
)

// New returns the mtrxmsg root command.
func New() *cobra.Command {
	var verbose int
	var level slog.Level
	var logger *slog.Logger
	root := &cobra.Command{
		Use:               "mtrxmsg",
		Short:             "Send and read Matrix messages",
		Args:              cobra.NoArgs,
		SilenceUsage:      true,
		SilenceErrors:     true,
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			var err error
			level, err = logLevel(os.Getenv("log_level"), verbose)
			if err != nil {
				return err
			}
			logger = slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: level}))
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	root.PersistentFlags().CountVarP(&verbose, "verbose", "v", "Increase log verbosity. Repeat for more detail.")
	root.AddCommand(&cobra.Command{
		Use: "version", Short: "Show the version", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), version.Line(level <= slog.LevelInfo))
			return err
		},
	})

	run := func(fn func(*cobra.Command, *matrix.Service, []string) error) func(*cobra.Command, []string) error {
		return func(cmd *cobra.Command, args []string) error {
			dir, err := matrix.DefaultStateDir()
			if err != nil {
				return fmt.Errorf("find the state directory: %w", err)
			}
			return fn(cmd, matrix.New(dir, logger), args)
		}
	}
	var homeserver string
	var port int
	login := &cobra.Command{
		Use: "login", Short: "Sign in through a browser", Args: cobra.NoArgs,
		Long: "Sign in through a browser. If the browser runs on another machine, copy the\n" +
			"full loopback callback URL from its address bar. Open that URL with curl on\n" +
			"the machine running mtrxmsg, in a second terminal.",
		RunE: run(func(cmd *cobra.Command, svc *matrix.Service, _ []string) error {
			identity, err := svc.Login(cmd.Context(), homeserver, port, func(url string) error {
				_, err := fmt.Fprintf(cmd.OutOrStdout(), "Open this URL in your browser:\n%s\n", url)
				return err
			})
			if err != nil {
				return err
			}
			return printIdentity(cmd.OutOrStdout(), identity)
		}),
	}
	login.Flags().StringVar(&homeserver, "homeserver", "", "Matrix homeserver URL (required)")
	login.Flags().IntVar(&port, "callback-port", 0, "Loopback callback port. Use a fixed port for an SSH tunnel.")
	// The flag was declared immediately above.
	_ = login.MarkFlagRequired("homeserver")
	root.AddCommand(login, &cobra.Command{
		Use: "logout", Short: "Revoke the session and remove local state", Args: cobra.NoArgs,
		RunE: run(func(cmd *cobra.Command, svc *matrix.Service, _ []string) error {
			if err := svc.Logout(cmd.Context()); err != nil {
				return err
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "Signed out.")
			return err
		}),
	}, &cobra.Command{
		Use: "whoami", Short: "Show the signed-in Matrix identity", Args: cobra.NoArgs,
		RunE: run(func(cmd *cobra.Command, svc *matrix.Service, _ []string) error {
			identity, err := svc.Whoami(cmd.Context())
			if err != nil {
				return err
			}
			return printIdentity(cmd.OutOrStdout(), identity)
		}),
	}, &cobra.Command{
		Use: "send <room> <message>", Short: "Send a text message", Args: cobra.ExactArgs(2),
		RunE: run(func(cmd *cobra.Command, svc *matrix.Service, args []string) error {
			id, err := svc.Send(cmd.Context(), args[0], args[1])
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), safeLine(id.String()))
			return err
		}),
	})

	var limit int
	read := &cobra.Command{
		Use: "read <room>", Short: "Read recent messages and exit", Args: cobra.ExactArgs(1),
		RunE: run(func(cmd *cobra.Command, svc *matrix.Service, args []string) error {
			messages, err := svc.Read(cmd.Context(), args[0], limit)
			if err != nil {
				return err
			}
			for _, msg := range messages {
				body := safeLine(msg.Body)
				if msg.Undecryptable {
					body = "[cannot decrypt]"
				}
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s %s: %s\n", msg.Time.Format(time.RFC3339), safeLine(msg.Sender.String()), body); err != nil {
					return err
				}
			}
			return nil
		}),
	}
	read.Flags().IntVar(&limit, "limit", 20, "Maximum number of messages")
	root.AddCommand(read)

	room := &cobra.Command{Use: "room", Short: "List, inspect, and join rooms", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() }}
	room.AddCommand(&cobra.Command{
		Use: "list", Short: "List joined rooms", Args: cobra.NoArgs,
		RunE: run(func(cmd *cobra.Command, svc *matrix.Service, _ []string) error {
			rooms, err := svc.ListRooms(cmd.Context())
			if err != nil {
				return err
			}
			for _, room := range rooms {
				fields := []string{safeLine(room.ID.String())}
				if room.Alias != "" {
					fields = append(fields, safeLine(room.Alias.String()))
				}
				if room.Name != "" {
					fields = append(fields, safeLine(room.Name))
				}
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), strings.Join(fields, "\t")); err != nil {
					return err
				}
			}
			return nil
		}),
	}, &cobra.Command{
		Use: "info <room>", Short: "Show room details", Args: cobra.ExactArgs(1),
		RunE: run(func(cmd *cobra.Command, svc *matrix.Service, args []string) error {
			room, err := svc.RoomInfo(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Room ID: %s\nName: %s\nAlias: %s\nEncrypted: %t\n",
				safeLine(room.ID.String()), safeLine(room.Name), safeLine(room.Alias.String()), room.Encrypted)
			return err
		}),
	}, &cobra.Command{
		Use: "join <room>", Short: "Join a room", Args: cobra.ExactArgs(1),
		RunE: run(func(cmd *cobra.Command, svc *matrix.Service, args []string) error {
			id, err := svc.JoinRoom(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), safeLine(id.String()))
			return err
		}),
	})
	root.AddCommand(room)

	device := &cobra.Command{Use: "device", Short: "Manage this Matrix device", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() }}
	device.AddCommand(&cobra.Command{
		Use: "verify", Short: "Verify this device from another Matrix client", Args: cobra.NoArgs,
		RunE: run(func(cmd *cobra.Command, svc *matrix.Service, _ []string) error {
			out := cmd.OutOrStdout()
			err := svc.VerifyDevice(cmd.Context(), func(identity matrix.Identity) error {
				_, err := fmt.Fprintf(out, "From another client on %s, start verification for device %s. Use emoji or numbers, not a QR code.\n",
					safeLine(identity.UserID.String()), safeLine(identity.DeviceID.String()))
				return err
			}, func(ctx context.Context, sas matrix.SAS) (bool, error) {
				return compareSAS(ctx, cmd.InOrStdin(), out, sas)
			})
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(out, "Device verified.")
			return err
		}),
	})
	root.AddCommand(device)
	return root
}

func logLevel(base string, verbose int) (slog.Level, error) {
	var level slog.Level
	switch base {
	case "", "ERROR":
		level = slog.LevelError
	case "WARN":
		level = slog.LevelWarn
	case "INFO":
		level = slog.LevelInfo
	case "DEBUG":
		level = slog.LevelDebug
	default:
		return 0, fmt.Errorf("log_level must be ERROR, WARN, INFO, or DEBUG")
	}
	return max(slog.LevelDebug, level-slog.Level(min(3, max(0, verbose)))*4), nil
}

func printIdentity(out io.Writer, identity matrix.Identity) error {
	_, err := fmt.Fprintf(out, "User: %s\nHomeserver: %s\nDevice: %s\n",
		safeLine(identity.UserID.String()), safeLine(identity.Homeserver), safeLine(identity.DeviceID.String()))
	return err
}

// Do not let room content or remote identifiers insert terminal controls.
func safeLine(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) || r == '\u2028' || r == '\u2029' {
			return '\uFFFD'
		}
		return r
	}, s)
}

func compareSAS(ctx context.Context, in io.Reader, out io.Writer, sas matrix.SAS) (bool, error) {
	var prompt strings.Builder
	fmt.Fprintf(&prompt, "Compare these values with device %s:\n", safeLine(sas.OtherDevice.String()))
	for i, char := range sas.Emojis {
		fmt.Fprintf(&prompt, "%c", char)
		if i < len(sas.EmojiDescriptions) {
			fmt.Fprintf(&prompt, " (%s)", sas.EmojiDescriptions[i])
		}
		prompt.WriteByte('\n')
	}
	if len(sas.Decimals) > 0 {
		fmt.Fprintln(&prompt, "Numbers:", sas.Decimals)
	}
	prompt.WriteString("If the values match on both devices, type yes and press Enter: ")
	if _, err := io.WriteString(out, prompt.String()); err != nil {
		return false, err
	}
	answer := make(chan bool, 1)
	go func() {
		line, err := bufio.NewReader(io.LimitReader(in, 128)).ReadString('\n')
		answer <- err == nil && strings.TrimSpace(line) == "yes"
	}()
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case matches := <-answer:
		return matches, nil
	}
}
