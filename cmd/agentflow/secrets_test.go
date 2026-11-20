package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"agentflow/internal/domain"
	"agentflow/internal/repo"
	"agentflow/internal/secretbox"
)

func TestCheckStoredSecrets(t *testing.T) {
	keyA, _ := secretbox.New(bytes.Repeat([]byte{1}, secretbox.KeySize))
	keyB, _ := secretbox.New(bytes.Repeat([]byte{2}, secretbox.KeySize))
	base, err := repo.OpenTest()
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	var logs []string
	logf := func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }

	// No key, no encrypted rows: starts with a warning.
	if err := checkStoredSecrets(base, nil, logf); err != nil || len(logs) != 1 || !strings.Contains(logs[0], "WARNING") || !strings.Contains(logs[0], secretbox.EnvKeyFile) {
		t.Fatalf("plaintext mode: %v %q", err, logs)
	}

	sealed := repo.ReopenTest(base, repo.WithSecretKeyring(keyA))
	now := time.Now().UTC()
	if err := sealed.PutConnection(domain.Connection{ID: "cn-1", ProjectID: "p", ConnectorID: "virustotal", Name: "vt", Secrets: map[string]string{"api_key": "x"}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	logs = nil
	if err := checkStoredSecrets(sealed, keyA, logf); err != nil || !strings.Contains(strings.Join(logs, "\n"), "key="+keyA.CurrentKeyID()) {
		t.Fatalf("right key: %v %q", err, logs)
	}
	for name, box := range map[string]*secretbox.Keyring{"no key": nil, "wrong key": keyB} {
		err := checkStoredSecrets(repo.ReopenTest(base, repo.WithSecretKeyring(box)), box, logf)
		if err == nil || !strings.Contains(err.Error(), "refusing to start") || !strings.Contains(err.Error(), secretbox.EnvKey) || !strings.Contains(err.Error(), "cn-1") {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
