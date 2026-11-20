// loopforge-secrets is the operator command for credential encryption at
// rest. It never runs on service startup.
//
//	loopforge-secrets status              count rows by state; fails on undecryptable rows
//	loopforge-secrets encrypt [-dry-run]  seal plaintext rows, re-seal rows under a previous key
//	loopforge-secrets genkey              print a new random key (base64 of 32 bytes)
//
// It reads AGENTFLOW_MYSQL_DSN and the same key variables as the platform
// (AGENTFLOW_SECRET_KEY / AGENTFLOW_SECRET_KEY_FILE,
// AGENTFLOW_SECRET_KEYS_PREVIOUS / AGENTFLOW_SECRET_KEYS_PREVIOUS_FILE).
// Output is counts only, never values.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"agentflow/internal/repo"
	"agentflow/internal/secretbox"
)

func main() {
	var store *repo.Store
	open := func(box *secretbox.Keyring) (*repo.Store, error) {
		s, err := repo.Open("", repo.WithSecretKeyring(box))
		store = s
		return s, err
	}
	err := run(os.Args[1:], os.Getenv, open, os.Stdout)
	if store != nil {
		store.Close()
	}
	if err != nil {
		log.Fatal(err)
	}
}

const usage = "usage: loopforge-secrets status | encrypt [-dry-run] | genkey"

func run(args []string, getenv func(string) string, open func(*secretbox.Keyring) (*repo.Store, error), stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	cmd, rest := args[0], args[1:]
	fs := flag.NewFlagSet("loopforge-secrets "+cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dryRun := fs.Bool("dry-run", false, "count the rows that would be rewritten without writing")
	if err := fs.Parse(rest); err != nil {
		return fmt.Errorf("%v\n%s", err, usage)
	}
	if fs.NArg() != 0 || (*dryRun && cmd != "encrypt") {
		return errors.New(usage)
	}
	switch cmd {
	case "genkey":
		key, err := secretbox.GenerateKey()
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, key)
		return err
	case "status", "encrypt":
	default:
		return errors.New(usage)
	}
	box, err := secretbox.LoadEnv(getenv)
	if err != nil {
		return err
	}
	if cmd == "encrypt" && !box.Enabled() {
		return fmt.Errorf("no encryption key: set %s or %s", secretbox.EnvKeyFile, secretbox.EnvKey)
	}
	s, err := open(box)
	if err != nil {
		return err
	}
	var reports []repo.SecretsReport
	if cmd == "status" {
		reports, err = repo.StoredSecretsStatus(s)
	} else {
		reports, err = repo.ReencryptStoredSecrets(s, *dryRun)
	}
	if err != nil {
		return err
	}
	if box.Enabled() {
		fmt.Fprintf(stdout, "current key id: %s\n", box.CurrentKeyID())
	} else {
		fmt.Fprintln(stdout, "no encryption key configured")
	}
	for _, r := range reports {
		fmt.Fprintf(stdout, "%s: rows=%d plaintext=%d current=%d previous-key=%d", r.Table, r.Rows, r.Plaintext, r.Current, r.Previous)
		switch {
		case cmd == "encrypt" && *dryRun:
			fmt.Fprintf(stdout, " would-rewrite=%d\n", r.Plaintext+r.Previous)
		case cmd == "encrypt":
			fmt.Fprintf(stdout, " rewritten=%d\n", r.Rewritten)
		default:
			fmt.Fprintln(stdout)
		}
	}
	if cmd == "encrypt" && *dryRun {
		fmt.Fprintln(stdout, "dry run: nothing written")
	}
	return nil
}
