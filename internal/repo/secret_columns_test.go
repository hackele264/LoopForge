package repo

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"agentflow/internal/domain"
	"agentflow/internal/secretbox"
)

func keyring(t *testing.T, current byte, previous ...byte) *secretbox.Keyring {
	t.Helper()
	var prev [][]byte
	for _, p := range previous {
		prev = append(prev, bytes.Repeat([]byte{p}, secretbox.KeySize))
	}
	k, err := secretbox.New(bytes.Repeat([]byte{current}, secretbox.KeySize), prev...)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func rawSecrets(t *testing.T, s *Store, id string) string {
	t.Helper()
	var raw []byte
	if err := s.DB.Raw("SELECT secrets FROM connections WHERE id = ?", id).Row().Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func putConn(t *testing.T, s *Store, id, secret string) {
	t.Helper()
	now := time.Now().UTC()
	if err := s.PutConnection(domain.Connection{ID: id, ProjectID: "p", ConnectorID: "virustotal", Name: id, Secrets: map[string]string{"api_key": secret}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
}

func TestConnectionSecretsSealedAtRest(t *testing.T) {
	s, err := OpenTest(WithSecretKeyring(keyring(t, 1)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	putConn(t, s, "cn-1", "top-secret")
	raw := rawSecrets(t, s, "cn-1")
	if !strings.HasPrefix(raw, `"`+secretbox.Prefix) || strings.Contains(raw, "top-secret") {
		t.Fatalf("column = %s", raw)
	}
	got, err := s.Connection("cn-1")
	if err != nil || got.Secrets["api_key"] != "top-secret" {
		t.Fatalf("read = %+v, %v", got.Secrets, err)
	}
	if _, err := s.Connection("missing"); !errors.Is(err, ErrConnectionNotFound) {
		t.Fatalf("missing = %v", err)
	}

	// Legacy plaintext rows still read.
	if err := s.DB.Exec(`UPDATE connections SET secrets = ? WHERE id = ?`, `{"api_key":"legacy"}`, "cn-1").Error; err != nil {
		t.Fatal(err)
	}
	if got, err := s.Connection("cn-1"); err != nil || got.Secrets["api_key"] != "legacy" {
		t.Fatalf("legacy read = %+v, %v", got.Secrets, err)
	}
}

func TestConnectionSecretsBoundToRow(t *testing.T) {
	s, err := OpenTest(WithSecretKeyring(keyring(t, 1)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	putConn(t, s, "cn-1", "one")
	putConn(t, s, "cn-2", "two")
	if err := s.DB.Exec(`UPDATE connections SET secrets = ? WHERE id = ?`, rawSecrets(t, s, "cn-1"), "cn-2").Error; err != nil {
		t.Fatal(err)
	}
	if c, err := s.Connection("cn-2"); !errors.Is(err, ErrStoredSecretsUnreadable) || c.Secrets != nil {
		t.Fatalf("swapped ciphertext read = %+v, %v", c.Secrets, err)
	}
	if _, err := StoredSecretsStatus(s); !errors.Is(err, ErrStoredSecretsUnreadable) || !strings.Contains(err.Error(), "cn-2") {
		t.Fatalf("status = %v", err)
	}
}

func TestConnectionSecretsWrongOrMissingKey(t *testing.T) {
	s, err := OpenTest(WithSecretKeyring(keyring(t, 1)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	putConn(t, s, "cn-1", "top-secret")
	for name, other := range map[string]*Store{
		"wrong key": ReopenTest(s, WithSecretKeyring(keyring(t, 2))),
		"no key":    ReopenTest(s),
	} {
		if c, err := other.Connection("cn-1"); !errors.Is(err, ErrStoredSecretsUnreadable) || c.Secrets != nil {
			t.Fatalf("%s: read = %+v, %v", name, c.Secrets, err)
		}
		if _, err := StoredSecretsStatus(other); !errors.Is(err, ErrStoredSecretsUnreadable) {
			t.Fatalf("%s: status = %v", name, err)
		} else if strings.Contains(err.Error(), "top-secret") {
			t.Fatalf("%s: error leaks the secret", name)
		}
		// The list never needs the key.
		if list, err := other.Connections("p", ""); err != nil || len(list) != 1 {
			t.Fatalf("%s: list = %v, %v", name, list, err)
		}
	}
	// Without a key, plaintext writes keep working (and read back).
	plain := ReopenTest(s)
	putConn(t, plain, "cn-3", "plain")
	if raw := rawSecrets(t, plain, "cn-3"); !strings.Contains(raw, "plain") {
		t.Fatalf("plaintext mode column = %s", raw)
	}
}

func TestReencryptStoredSecrets(t *testing.T) {
	old, err := OpenTest(WithSecretKeyring(keyring(t, 1)))
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	putConn(t, old, "cn-old", "under-old-key")
	plain := ReopenTest(old)
	putConn(t, plain, "cn-plain", "plaintext")
	if err := plain.UsersRepo.putBotCredential(plain.DB, "bot-1", "bot-secret"); err != nil {
		t.Fatal(err)
	}
	if err := old.UsersRepo.putBotCredential(old.DB, "bot-2", "bot-secret-2"); err != nil {
		t.Fatal(err)
	}
	var before time.Time
	if err := old.DB.Raw("SELECT updated_at FROM connections WHERE id = ?", "cn-plain").Row().Scan(&before); err != nil || before.IsZero() {
		t.Fatalf("updated_at = %v, %v", before, err)
	}

	if _, err := ReencryptStoredSecrets(plain, false); err == nil {
		t.Fatal("re-encryption without a key should fail")
	}
	rotated := ReopenTest(old, WithSecretKeyring(keyring(t, 2, 1)))
	status, err := StoredSecretsStatus(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if c := status[0]; c.Rows != 2 || c.Plaintext != 1 || c.Previous != 1 || c.Current != 0 {
		t.Fatalf("connections status = %+v", c)
	}
	if b := status[1]; b.Rows != 2 || b.Plaintext != 1 || b.Previous != 1 {
		t.Fatalf("bot status = %+v", b)
	}

	rawBefore := rawSecrets(t, rotated, "cn-plain")
	dry, err := ReencryptStoredSecrets(rotated, true)
	if err != nil || dry[0].Rewritten != 0 || dry[0].Plaintext != 1 || rawSecrets(t, rotated, "cn-plain") != rawBefore {
		t.Fatalf("dry run = %+v, %v", dry, err)
	}

	done, err := ReencryptStoredSecrets(rotated, false)
	if err != nil || done[0].Rewritten != 2 || done[1].Rewritten != 2 {
		t.Fatalf("encrypt = %+v, %v", done, err)
	}
	again, err := ReencryptStoredSecrets(rotated, false)
	if err != nil || again[0].Rewritten != 0 || again[1].Rewritten != 0 || again[0].Current != 2 || again[1].Current != 2 {
		t.Fatalf("second pass = %+v, %v", again, err)
	}

	// Everything now opens with the new key alone.
	newOnly := ReopenTest(old, WithSecretKeyring(keyring(t, 2)))
	for id, want := range map[string]string{"cn-old": "under-old-key", "cn-plain": "plaintext"} {
		if c, err := newOnly.Connection(id); err != nil || c.Secrets["api_key"] != want {
			t.Fatalf("%s = %+v, %v", id, c.Secrets, err)
		}
	}
	for id, want := range map[string]string{"bot-1": "bot-secret", "bot-2": "bot-secret-2"} {
		if got, err := newOnly.BotCredential(id); err != nil || got != want {
			t.Fatalf("%s = %q, %v", id, got, err)
		}
	}
	if _, err := old.BotCredential("bot-1"); !errors.Is(err, ErrStoredSecretsUnreadable) {
		t.Fatalf("old key read new bot credential: %v", err)
	}
	var after time.Time
	old.DB.Raw("SELECT updated_at FROM connections WHERE id = ?", "cn-plain").Row().Scan(&after)
	if !after.Equal(before) {
		t.Fatalf("updated_at changed: %v -> %v", before, after)
	}
}

func TestBotCredentialSealedAtRest(t *testing.T) {
	s, err := OpenTest(WithSecretKeyring(keyring(t, 1)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.UsersRepo.putBotCredential(s.DB, "bot-1", "hook-secret"); err != nil {
		t.Fatal(err)
	}
	var raw string
	s.DB.Raw("SELECT ciphertext FROM user_bot_credentials WHERE bot_id = ?", "bot-1").Row().Scan(&raw)
	if !secretbox.IsSealed(raw) || strings.Contains(raw, "hook-secret") {
		t.Fatalf("column = %s", raw)
	}
	if got, err := s.BotCredential("bot-1"); err != nil || got != "hook-secret" {
		t.Fatalf("read = %q, %v", got, err)
	}
	// Moved to another bot's row: does not open.
	s.DB.Exec("INSERT INTO user_bot_credentials (bot_id, ciphertext) VALUES (?, ?)", "bot-2", raw)
	if got, err := s.BotCredential("bot-2"); !errors.Is(err, ErrStoredSecretsUnreadable) || got != "" {
		t.Fatalf("moved = %q, %v", got, err)
	}
}
