package secretbox

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKey(b byte) []byte { return bytes.Repeat([]byte{b}, KeySize) }

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestSealOpenRoundTrip(t *testing.T) {
	k, err := New(testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := k.Seal([]byte(`{"api_key":"s3cret"}`), []byte("row-1"))
	if err != nil {
		t.Fatal(err)
	}
	if !IsSealed(sealed) || !strings.HasPrefix(sealed, Prefix+k.CurrentKeyID()+":") {
		t.Fatalf("unexpected envelope %q", sealed)
	}
	if strings.Contains(sealed, "s3cret") || strings.Contains(sealed, base64.StdEncoding.EncodeToString(testKey(1))) {
		t.Fatal("envelope leaks plaintext or key")
	}
	plain, err := k.Open(sealed, []byte("row-1"))
	if err != nil || string(plain) != `{"api_key":"s3cret"}` {
		t.Fatalf("open = %q, %v", plain, err)
	}
	again, _ := k.Seal([]byte(`{"api_key":"s3cret"}`), []byte("row-1"))
	if again == sealed {
		t.Fatal("nonce reused")
	}
}

func TestOpenWrongKeyFails(t *testing.T) {
	a, _ := New(testKey(1))
	b, _ := New(testKey(2))
	sealed, _ := a.Seal([]byte("x"), []byte("row"))
	if _, err := b.Open(sealed, []byte("row")); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey, got %v", err)
	}
	// Same kid, different key material (forged kid): authentication fails.
	kid := a.CurrentKeyID()
	forged := Prefix + kid + ":" + strings.SplitN(strings.TrimPrefix(sealed, Prefix), ":", 2)[1]
	b.byID[kid] = b.current
	if _, err := b.Open(forged, []byte("row")); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("want ErrDecrypt, got %v", err)
	}
	var none *Keyring
	if _, err := none.Open(sealed, []byte("row")); !errors.Is(err, ErrNoKeyring) {
		t.Fatalf("want ErrNoKeyring, got %v", err)
	}
}

func TestOpenAADMismatchFails(t *testing.T) {
	k, _ := New(testKey(1))
	sealed, _ := k.Seal([]byte("x"), []byte("row-1"))
	if _, err := k.Open(sealed, []byte("row-2")); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("want ErrDecrypt, got %v", err)
	}
}

func TestOpenTamperedAndMalformed(t *testing.T) {
	k, _ := New(testKey(1))
	sealed, _ := k.Seal([]byte("hello"), nil)
	raw, _ := base64.StdEncoding.DecodeString(sealed[len(Prefix)+9:])
	raw[len(raw)-1] ^= 1
	tampered := sealed[:len(Prefix)+9] + base64.StdEncoding.EncodeToString(raw)
	if _, err := k.Open(tampered, nil); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("want ErrDecrypt, got %v", err)
	}
	for _, bad := range []string{"plain", Prefix, Prefix + "abc", Prefix + "abc:!!!", Prefix + k.CurrentKeyID() + ":AAAA"} {
		if _, err := k.Open(bad, nil); err == nil {
			t.Fatalf("%q opened", bad)
		}
	}
}

func TestRotation(t *testing.T) {
	old, _ := New(testKey(1))
	sealed, _ := old.Seal([]byte("v"), []byte("r"))
	rotated, err := New(testKey(2), testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	if rotated.IsCurrent(sealed) {
		t.Fatal("old value reported current")
	}
	plain, err := rotated.Open(sealed, []byte("r"))
	if err != nil || string(plain) != "v" {
		t.Fatalf("open with previous = %q, %v", plain, err)
	}
	resealed, _ := rotated.Seal(plain, []byte("r"))
	if !rotated.IsCurrent(resealed) {
		t.Fatal("reseal not under current key")
	}
	if _, err := old.Open(resealed, []byte("r")); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("old keyring opened new value: %v", err)
	}
}

func TestLoadEnv(t *testing.T) {
	k1 := base64.StdEncoding.EncodeToString(testKey(1))
	k2 := base64.RawURLEncoding.EncodeToString(testKey(2))
	k3 := base64.StdEncoding.EncodeToString(testKey(3))

	if k, err := LoadEnv(env(nil)); err != nil || k != nil || k.Enabled() {
		t.Fatalf("empty env = %v, %v", k, err)
	}
	k, err := LoadEnv(env(map[string]string{EnvKey: k1, EnvPreviousKeys: k2 + ", " + k3}))
	if err != nil || k.CurrentKeyID() != KeyID(testKey(1)) || len(k.byID) != 3 {
		t.Fatalf("inline = %v, %v", k, err)
	}

	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	prevFile := filepath.Join(dir, "prev")
	if err := os.WriteFile(keyFile, []byte(k2+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(prevFile, []byte("# old keys\n"+k1+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k, err = LoadEnv(env(map[string]string{EnvKeyFile: keyFile, EnvPreviousKeysFile: prevFile}))
	if err != nil || k.CurrentKeyID() != KeyID(testKey(2)) || len(k.byID) != 2 {
		t.Fatalf("file = %v, %v", k, err)
	}

	for name, bad := range map[string]map[string]string{
		"both":          {EnvKey: k1, EnvKeyFile: keyFile},
		"short":         {EnvKey: base64.StdEncoding.EncodeToString([]byte("short"))},
		"not base64":    {EnvKey: "%%%"},
		"missing file":  {EnvKeyFile: filepath.Join(dir, "nope")},
		"previous only": {EnvPreviousKeys: k1},
		"bad previous":  {EnvKey: k1, EnvPreviousKeys: "zz"},
	} {
		if _, err := LoadEnv(env(bad)); err == nil {
			t.Errorf("%s: no error", name)
		} else if strings.Contains(err.Error(), k1) {
			t.Errorf("%s: error leaks key", name)
		}
	}
}

func TestGenerateKey(t *testing.T) {
	s, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseKey(s); err != nil {
		t.Fatal(err)
	}
}
