package main

import (
	"fmt"

	"agentflow/internal/repo"
	"agentflow/internal/secretbox"
)

// checkStoredSecrets runs at startup, before any request is served. It opens
// every encrypted credential and refuses to start when one cannot be
// decrypted (missing or wrong key), so the platform never runs actions with
// empty or wrong secrets. Without a key it keeps working in plaintext and
// warns. It never rewrites rows: that is loopforge-secrets' job.
func checkStoredSecrets(s *repo.Store, box *secretbox.Keyring, logf func(string, ...any)) error {
	reports, err := repo.StoredSecretsStatus(s)
	if err != nil {
		return fmt.Errorf("%w\nrefusing to start: configure the key these rows were encrypted with in %s or %s (older keys in %s)",
			err, secretbox.EnvKey, secretbox.EnvKeyFile, secretbox.EnvPreviousKeys)
	}
	plaintext, previous := 0, 0
	for _, r := range reports {
		plaintext += r.Plaintext
		previous += r.Previous
	}
	if !box.Enabled() {
		logf("WARNING: no credential encryption key: connection secrets and bot credentials are stored in plaintext. Set %s (or %s) and run loopforge-secrets encrypt; see docs/deployment.md", secretbox.EnvKeyFile, secretbox.EnvKey)
		return nil
	}
	logf("credential encryption on key=%s", box.CurrentKeyID())
	if plaintext > 0 || previous > 0 {
		logf("credential encryption: %d plaintext row(s) and %d row(s) under a previous key; run loopforge-secrets encrypt", plaintext, previous)
	}
	return nil
}
