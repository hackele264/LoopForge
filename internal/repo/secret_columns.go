package repo

// Package-level helpers for credential columns sealed with secretbox. The
// keyring is injected into the owning domain repos by newStore (it is not a
// shared dep). Each value is bound to its table, column and row ID as
// additional authenticated data, so a sealed value copied to another row does
// not open.
//
// Reads accept legacy plaintext (no envelope prefix) so an upgrade keeps
// working; writes seal whenever a key is configured. Rewriting existing rows
// is an operator action (cmd/loopforge-secrets), never a startup step.

import (
	"errors"
	"fmt"
	"strings"

	"agentflow/internal/secretbox"
)

// ErrStoredSecretsUnreadable means a sealed credential could not be opened
// with the configured keys.
var ErrStoredSecretsUnreadable = errors.New("stored credentials cannot be decrypted; check " +
	secretbox.EnvKey + "/" + secretbox.EnvKeyFile + " and " + secretbox.EnvPreviousKeys)

// SecretsReport counts the credential rows of one table by storage state.
// It never carries values.
type SecretsReport struct {
	Table string `json:"table"`
	// Rows is every row scanned.
	Rows int `json:"rows"`
	// Plaintext rows have no envelope (written before a key was configured).
	Plaintext int `json:"plaintext"`
	// Current rows are sealed under the current key.
	Current int `json:"current"`
	// Previous rows are sealed under a previous (rotated) key.
	Previous int `json:"previous"`
	// Rewritten is the number of rows sealed or re-sealed by a pass; always
	// 0 for a status check or a dry run.
	Rewritten int `json:"rewritten"`
}

func secretAAD(table, column, id string) []byte {
	return []byte("loopforge/" + table + "." + column + "/" + id)
}

// sealText seals a credential for a text column; without a key it is
// returned unchanged.
func sealText(box *secretbox.Keyring, aad []byte, plain string) (string, error) {
	if !box.Enabled() {
		return plain, nil
	}
	return box.Seal([]byte(plain), aad)
}

// openText returns the plaintext of a stored text credential. Legacy
// plaintext passes through; a sealed value that does not open is an error.
func openText(box *secretbox.Keyring, aad []byte, stored string) (string, error) {
	if !secretbox.IsSealed(stored) {
		return stored, nil
	}
	plain, err := box.Open(stored, aad)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrStoredSecretsUnreadable, err)
	}
	return string(plain), nil
}

// classify sorts a stored value into plaintext / current / previous and
// checks that a sealed value opens. It returns the plaintext.
func classify(box *secretbox.Keyring, aad []byte, sealed string, isSealed bool, report *SecretsReport) ([]byte, error) {
	report.Rows++
	if !isSealed {
		report.Plaintext++
		return nil, nil
	}
	plain, err := box.Open(sealed, aad)
	if err != nil {
		return nil, err
	}
	if box.IsCurrent(sealed) {
		report.Current++
	} else {
		report.Previous++
	}
	return plain, nil
}

// StoredSecretsStatus opens every sealed credential and counts rows by
// state. It fails, naming the row and the key variables, when any sealed
// value cannot be opened (missing or wrong key). The platform runs it at
// startup and refuses to start on error.
func StoredSecretsStatus(s *Store) ([]SecretsReport, error) {
	conns, err := s.ConnectionsRepo.connectionSecretsPass(false, true)
	if err != nil {
		return nil, err
	}
	bots, err := s.UsersRepo.botCredentialsPass(false, true)
	if err != nil {
		return nil, err
	}
	return []SecretsReport{conns, bots}, nil
}

// ReencryptStoredSecrets seals every plaintext credential and re-seals
// values under a previous key with the current key. It is idempotent; with
// dryRun it only counts. It needs a configured key.
func ReencryptStoredSecrets(s *Store, dryRun bool) ([]SecretsReport, error) {
	if !s.ConnectionsRepo.secrets.Enabled() || !s.UsersRepo.secrets.Enabled() {
		return nil, fmt.Errorf("no encryption key configured: set %s or %s", secretbox.EnvKey, secretbox.EnvKeyFile)
	}
	conns, err := s.ConnectionsRepo.connectionSecretsPass(true, dryRun)
	if err != nil {
		return nil, err
	}
	bots, err := s.UsersRepo.botCredentialsPass(true, dryRun)
	if err != nil {
		return nil, err
	}
	return []SecretsReport{conns, bots}, nil
}

func unreadable(table, id string, err error) error {
	return fmt.Errorf("%w: %s row %s: %v", ErrStoredSecretsUnreadable, table, strings.TrimSpace(id), err)
}
