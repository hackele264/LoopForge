// Package secretbox encrypts stored credentials (connector connection
// secrets, bot credentials) with AES-256-GCM.
//
// A sealed value is a self-describing text envelope:
//
//	lfenc:v1:<kid>:<base64(nonce | ciphertext+tag)>
//
// kid is a short hash of the key that sealed it (never the key itself), so a
// value sealed under a previous key can still be opened after rotation while
// writes always use the current key. The caller binds every value to its row
// with additional authenticated data (table, column and row ID), so a sealed
// value copied to another row fails to open.
//
// The package has no dependency on storage or HTTP code.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Prefix starts every sealed value.
const Prefix = "lfenc:v1:"

// KeySize is the AES-256 key length in bytes.
const KeySize = 32

// Environment variables read by LoadEnv.
const (
	EnvKey              = "AGENTFLOW_SECRET_KEY"
	EnvKeyFile          = "AGENTFLOW_SECRET_KEY_FILE"
	EnvPreviousKeys     = "AGENTFLOW_SECRET_KEYS_PREVIOUS"
	EnvPreviousKeysFile = "AGENTFLOW_SECRET_KEYS_PREVIOUS_FILE"
)

var (
	// ErrMalformed is returned for a value that has the envelope prefix but
	// cannot be parsed.
	ErrMalformed = errors.New("secretbox: malformed sealed value")
	// ErrNoKeyring is returned when a sealed value is read but no key is
	// configured.
	ErrNoKeyring = errors.New("secretbox: value is encrypted but no key is configured; set " + EnvKey + " or " + EnvKeyFile)
	// ErrUnknownKey is returned when the value was sealed with a key that is
	// neither the current key nor a previous one.
	ErrUnknownKey = errors.New("secretbox: value was encrypted with a key that is not configured; set the current key in " + EnvKey + "/" + EnvKeyFile + " and older keys in " + EnvPreviousKeys)
	// ErrDecrypt is returned when authentication fails: wrong key, tampered
	// ciphertext, or a value moved to another row.
	ErrDecrypt = errors.New("secretbox: decryption failed (wrong key, tampered value or value moved between rows)")
)

type key struct {
	id   string
	aead cipher.AEAD
}

// Keyring holds the current key, used for every write, and previous keys,
// used only to open values sealed before a rotation. A nil *Keyring means
// encryption is not configured; its methods are safe to call.
type Keyring struct {
	current *key
	byID    map[string]*key
}

// New builds a keyring from raw 32-byte keys. previous may be empty.
func New(current []byte, previous ...[]byte) (*Keyring, error) {
	cur, err := newKey(current)
	if err != nil {
		return nil, fmt.Errorf("current key: %w", err)
	}
	k := &Keyring{current: cur, byID: map[string]*key{cur.id: cur}}
	for i, raw := range previous {
		p, err := newKey(raw)
		if err != nil {
			return nil, fmt.Errorf("previous key %d: %w", i+1, err)
		}
		if _, dup := k.byID[p.id]; !dup {
			k.byID[p.id] = p
		}
	}
	return k, nil
}

func newKey(raw []byte) (*key, error) {
	if len(raw) != KeySize {
		return nil, fmt.Errorf("secretbox: key must be %d bytes, got %d", KeySize, len(raw))
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &key{id: KeyID(raw), aead: aead}, nil
}

// KeyID is the public identifier of a key: the first 8 hex characters of a
// domain-separated SHA-256 of the key.
func KeyID(raw []byte) string {
	h := sha256.New()
	h.Write([]byte("loopforge-secretbox-kid\x00"))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))[:8]
}

// ParseKey decodes a base64 (standard or URL alphabet, padded or not) key and
// checks its length.
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err := enc.DecodeString(s); err == nil {
			if len(raw) != KeySize {
				return nil, fmt.Errorf("secretbox: key must decode to %d bytes, got %d", KeySize, len(raw))
			}
			return raw, nil
		}
	}
	return nil, errors.New("secretbox: key is not valid base64")
}

// GenerateKey returns a new random key, base64 encoded.
func GenerateKey() (string, error) {
	raw := make([]byte, KeySize)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// LoadEnv builds the keyring from the environment (getenv is os.Getenv in
// production). It returns (nil, nil) when no key is configured.
//
//   - AGENTFLOW_SECRET_KEY or AGENTFLOW_SECRET_KEY_FILE (not both): the
//     current key, base64 of 32 bytes.
//   - AGENTFLOW_SECRET_KEYS_PREVIOUS and/or AGENTFLOW_SECRET_KEYS_PREVIOUS_FILE:
//     older keys, separated by commas or newlines, used only to decrypt.
func LoadEnv(getenv func(string) string) (*Keyring, error) {
	inline := strings.TrimSpace(getenv(EnvKey))
	file := strings.TrimSpace(getenv(EnvKeyFile))
	if inline != "" && file != "" {
		return nil, fmt.Errorf("set only one of %s and %s", EnvKey, EnvKeyFile)
	}
	current := inline
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", EnvKeyFile, err)
		}
		current = strings.TrimSpace(string(b))
		if current == "" {
			return nil, fmt.Errorf("%s: file %s is empty", EnvKeyFile, file)
		}
	}
	prevText := getenv(EnvPreviousKeys)
	if pf := strings.TrimSpace(getenv(EnvPreviousKeysFile)); pf != "" {
		b, err := os.ReadFile(pf)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", EnvPreviousKeysFile, err)
		}
		prevText += "\n" + string(b)
	}
	var previous [][]byte
	for _, field := range strings.FieldsFunc(prevText, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		field = strings.TrimSpace(field)
		if field == "" || strings.HasPrefix(field, "#") {
			continue
		}
		raw, err := ParseKey(field)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", EnvPreviousKeys, err)
		}
		previous = append(previous, raw)
	}
	if current == "" {
		if len(previous) > 0 {
			return nil, fmt.Errorf("%s is set but there is no current key in %s or %s", EnvPreviousKeys, EnvKey, EnvKeyFile)
		}
		return nil, nil
	}
	raw, err := ParseKey(current)
	if err != nil {
		name := EnvKey
		if file != "" {
			name = EnvKeyFile
		}
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return New(raw, previous...)
}

// Enabled reports whether a key is configured.
func (k *Keyring) Enabled() bool { return k != nil && k.current != nil }

// CurrentKeyID is the kid new values are sealed with, or "" when disabled.
func (k *Keyring) CurrentKeyID() string {
	if !k.Enabled() {
		return ""
	}
	return k.current.id
}

// Seal encrypts plaintext under the current key, bound to aad.
func (k *Keyring) Seal(plaintext, aad []byte) (string, error) {
	if !k.Enabled() {
		return "", ErrNoKeyring
	}
	nonce := make([]byte, k.current.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := k.current.aead.Seal(nonce, nonce, plaintext, aad)
	return Prefix + k.current.id + ":" + base64.StdEncoding.EncodeToString(out), nil
}

// Open decrypts a sealed value bound to aad. It never returns partial or
// empty plaintext on failure.
func (k *Keyring) Open(sealed string, aad []byte) ([]byte, error) {
	kid, body, err := split(sealed)
	if err != nil {
		return nil, err
	}
	if !k.Enabled() {
		return nil, ErrNoKeyring
	}
	key, ok := k.byID[kid]
	if !ok {
		return nil, fmt.Errorf("%w (key id %s)", ErrUnknownKey, kid)
	}
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil || len(raw) < key.aead.NonceSize()+key.aead.Overhead() {
		return nil, ErrMalformed
	}
	n := key.aead.NonceSize()
	plain, err := key.aead.Open(nil, raw[:n], raw[n:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plain, nil
}

// IsSealed reports whether s carries the envelope prefix.
func IsSealed(s string) bool { return strings.HasPrefix(s, Prefix) }

// SealedKeyID returns the kid of a sealed value.
func SealedKeyID(sealed string) (string, error) {
	kid, _, err := split(sealed)
	return kid, err
}

// IsCurrent reports whether a sealed value uses the current key, so a
// re-encryption pass can skip it.
func (k *Keyring) IsCurrent(sealed string) bool {
	kid, err := SealedKeyID(sealed)
	return err == nil && k.Enabled() && kid == k.current.id
}

func split(sealed string) (kid, body string, err error) {
	rest, ok := strings.CutPrefix(sealed, Prefix)
	if !ok {
		return "", "", ErrMalformed
	}
	kid, body, ok = strings.Cut(rest, ":")
	if !ok || kid == "" || body == "" {
		return "", "", ErrMalformed
	}
	return kid, body, nil
}
