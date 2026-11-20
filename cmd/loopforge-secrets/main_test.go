package main

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"agentflow/internal/domain"
	"agentflow/internal/repo"
	"agentflow/internal/secretbox"
)

func TestEncryptCommand(t *testing.T) {
	base, err := repo.OpenTest()
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	now := time.Now().UTC()
	if err := base.PutConnection(domain.Connection{ID: "cn-1", ProjectID: "p", ConnectorID: "virustotal", Name: "vt", Secrets: map[string]string{"api_key": "plain-secret"}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	open := func(box *secretbox.Keyring) (*repo.Store, error) {
		return repo.ReopenTest(base, repo.WithSecretKeyring(box)), nil
	}
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, secretbox.KeySize))
	env := map[string]string{secretbox.EnvKey: key}
	getenv := func(k string) string { return env[k] }
	exec := func(args ...string) string {
		t.Helper()
		var out bytes.Buffer
		if err := run(args, getenv, open, &out); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if strings.Contains(out.String(), "plain-secret") || strings.Contains(out.String(), key) {
			t.Fatalf("output leaks a value: %s", out.String())
		}
		return out.String()
	}

	if out := exec("encrypt", "-dry-run"); !strings.Contains(out, "connections: rows=1 plaintext=1 current=0 previous-key=0 would-rewrite=1") || !strings.Contains(out, "dry run") {
		t.Fatalf("dry run output:\n%s", out)
	}
	if c, _ := base.Connection("cn-1"); c.Secrets["api_key"] != "plain-secret" {
		t.Fatal("dry run changed the row")
	}
	if out := exec("encrypt"); !strings.Contains(out, "connections: rows=1 plaintext=1 current=0 previous-key=0 rewritten=1") {
		t.Fatalf("encrypt output:\n%s", out)
	}
	if out := exec("encrypt"); !strings.Contains(out, "connections: rows=1 plaintext=0 current=1 previous-key=0 rewritten=0") {
		t.Fatalf("second encrypt output:\n%s", out)
	}
	if out := exec("status"); !strings.Contains(out, "connections: rows=1 plaintext=0 current=1") {
		t.Fatalf("status output:\n%s", out)
	}
	// The plaintext store can no longer read the sealed row.
	if _, err := base.Connection("cn-1"); err == nil {
		t.Fatal("sealed row read without a key")
	}

	// Rotation: new current key, old key as previous.
	newKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, secretbox.KeySize))
	env = map[string]string{secretbox.EnvKey: newKey, secretbox.EnvPreviousKeys: key}
	if out := exec("encrypt"); !strings.Contains(out, "previous-key=1 rewritten=1") {
		t.Fatalf("rotation output:\n%s", out)
	}
	env = map[string]string{secretbox.EnvKey: newKey}
	if out := exec("status"); !strings.Contains(out, "current=1 previous-key=0") {
		t.Fatalf("status after rotation:\n%s", out)
	}

	// Failures: no key for encrypt, wrong key for status, bad usage.
	env = map[string]string{}
	var out bytes.Buffer
	if err := run([]string{"encrypt"}, getenv, open, &out); err == nil {
		t.Fatal("encrypt without key succeeded")
	}
	env = map[string]string{secretbox.EnvKey: key}
	if err := run([]string{"status"}, getenv, open, &out); err == nil || !strings.Contains(err.Error(), secretbox.EnvKey) {
		t.Fatalf("status with old key = %v", err)
	}
	for _, args := range [][]string{nil, {"bogus"}, {"status", "-dry-run"}, {"encrypt", "extra"}} {
		if err := run(args, getenv, open, &out); err == nil {
			t.Fatalf("%v accepted", args)
		}
	}
	out.Reset()
	if err := run([]string{"genkey"}, getenv, open, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := secretbox.ParseKey(out.String()); err != nil {
		t.Fatalf("genkey output: %v", err)
	}
}
