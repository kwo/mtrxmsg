package matrix

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/verificationhelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// SAS contains the short authentication string for comparison on both devices.
type SAS struct {
	OtherDevice       id.DeviceID
	Emojis            []rune
	EmojiDescriptions []string
	Decimals          []int
}

// VerifyDevice waits for a verification request from another device on the
// same account. ready gives the caller the identity to look for on that device.
// compare must return true only after the user compares the values on both devices.
func (s *Service) VerifyDevice(ctx context.Context, ready func(Identity) error, compare func(context.Context, SAS) (bool, error)) error {
	if ready == nil || compare == nil {
		return errors.New("device verification requires a status handler and a comparison handler")
	}
	ctx, cancel := context.WithTimeout(ctx, interactiveTimeout)
	defer cancel()
	return s.withClient(ctx, func(sess *session, cli *mautrix.Client) error {
		helper, err := s.openCrypto(ctx, cli, sess)
		if err != nil {
			return err
		}
		defer func() { _ = helper.Close() }()
		store := verificationhelper.NewInMemoryVerificationStore()
		events := &verificationEvents{}
		verifier := verificationhelper.NewVerificationHelper(cli, helper.Machine(), store, events, false, false, true)
		if err := verifier.Init(ctx); err != nil {
			return errors.New("initialize device verification")
		}
		var active id.VerificationTransactionID
		var other id.DeviceID
		defer func() {
			clean, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if active != "" {
				_ = verifier.CancelVerification(clean, active, event.VerificationCancelCodeUser, "Verification stopped")
			}
			// The mautrix helper starts expiry timers for received requests.
			// Remove ignored requests so those timers cannot send after return.
			txns, _ := store.GetAllVerificationTransactions(clean)
			for _, txn := range txns {
				_ = store.DeleteVerification(clean, txn.TransactionID)
			}
		}()
		if err := ready(sess.Identity); err != nil {
			return err
		}
		confirmed := false
		for wait := time.Duration(0); ; wait = 5 * time.Second {
			if err := s.refresh(ctx, sess, cli); err != nil {
				return err
			}
			if _, err := syncKeys(ctx, cli, wait); err != nil {
				return err
			}
			// The helper calls callbacks under its mutex. Act only after the
			// callback returns to avoid taking the helper lock recursively.
			for update, ok := events.pop(); ok; update, ok = events.pop() {
				if active == "" && update.kind == verifyRequest && update.from == cli.UserID && update.device != "" {
					active, other = update.txn, update.device
					if err := verifier.AcceptVerification(ctx, active); err != nil {
						return requestError("accept device verification", err)
					}
				}
				if active == "" || update.txn != active {
					continue
				}
				switch update.kind {
				case verifyReady:
					if !update.supportsSAS {
						return errors.New("the other device does not support code comparison")
					}
					if err := verifier.StartSAS(ctx, active); err != nil {
						return requestError("start code comparison", err)
					}
				case verifyCompare:
					if confirmed {
						continue
					}
					update.sas.OtherDevice = other
					matches, err := compare(ctx, update.sas)
					if err != nil {
						return err
					}
					if !matches {
						_ = verifier.CancelVerification(ctx, active, event.VerificationCancelCodeSASMismatch, "The codes do not match")
						active = ""
						return errors.New("device verification was not confirmed")
					}
					if err := s.refresh(ctx, sess, cli); err != nil {
						return err
					}
					if err := verifier.ConfirmSAS(ctx, active); err != nil {
						return requestError("confirm the device verification", err)
					}
					confirmed = true
				case verifyCancelled:
					active = ""
					return errors.New("device verification was cancelled")
				case verifyDone:
					active = ""
					if !confirmed {
						return errors.New("device verification ended without local confirmation")
					}
					return nil
				}
			}
		}
	})
}

type verificationKind int

const (
	verifyRequest verificationKind = iota
	verifyReady
	verifyCompare
	verifyCancelled
	verifyDone
)

type verificationEvent struct {
	kind        verificationKind
	txn         id.VerificationTransactionID
	from        id.UserID
	device      id.DeviceID
	supportsSAS bool
	sas         SAS
}

type verificationEvents struct {
	mu      sync.Mutex
	pending []verificationEvent
}

func (q *verificationEvents) add(evt verificationEvent) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.pending = append(q.pending, evt)
}

func (q *verificationEvents) pop() (verificationEvent, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.pending) == 0 {
		return verificationEvent{}, false
	}
	evt := q.pending[0]
	q.pending[0] = verificationEvent{}
	q.pending = q.pending[1:]
	return evt, true
}

func (q *verificationEvents) VerificationRequested(_ context.Context, txn id.VerificationTransactionID, from id.UserID, device id.DeviceID) {
	q.add(verificationEvent{kind: verifyRequest, txn: txn, from: from, device: device})
}

func (q *verificationEvents) VerificationReady(_ context.Context, txn id.VerificationTransactionID, _ id.DeviceID, supportsSAS, _ bool, _ *verificationhelper.QRCode) {
	q.add(verificationEvent{kind: verifyReady, txn: txn, supportsSAS: supportsSAS})
}

func (q *verificationEvents) VerificationCancelled(_ context.Context, txn id.VerificationTransactionID, _ event.VerificationCancelCode, _ string) {
	q.add(verificationEvent{kind: verifyCancelled, txn: txn})
}

func (q *verificationEvents) VerificationDone(_ context.Context, txn id.VerificationTransactionID, _ event.VerificationMethod) {
	q.add(verificationEvent{kind: verifyDone, txn: txn})
}

func (q *verificationEvents) ShowSAS(_ context.Context, txn id.VerificationTransactionID, emojis []rune, descriptions []string, decimals []int) {
	q.add(verificationEvent{kind: verifyCompare, txn: txn, sas: SAS{
		Emojis: slices.Clone(emojis), EmojiDescriptions: slices.Clone(descriptions), Decimals: slices.Clone(decimals),
	}})
}
