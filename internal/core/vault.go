package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/box"
)

// User-secret vault: third-party credentials (Jira, Confluence, ...) a user
// supplies for their own pods. The design goal is that nobody but the user can
// decrypt them: the gateway stores ciphertext it has no key for.
//
//	K_user   = Argon2id(passphrase, salt)          derived on the user's machine, kept in their keychain
//	DEK      = random 32 bytes per entry
//	blob     = AES-256-GCM(DEK, secrets JSON, AAD = subject|adapter|version)
//	wrapped  = AES-256-GCM(K_user, DEK, AAD = subject|adapter)
//
// Tier A: the client sends K_user per request; the gateway unwraps in memory
// for that request only. Tier B: the user's companion decrypts locally and
// seals the plaintext to the pod's ephemeral public key (nacl box), so the
// gateway only ever carries ciphertext.

// VaultVersion is the on-wire format version.
const VaultVersion = 1

// ArgonParams are the KDF parameters recorded with each entry.
type ArgonParams struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"` // KiB
	Threads uint8  `json:"threads"`
}

// DefaultArgon is the recommended interactive setting (64 MiB, 3 passes).
var DefaultArgon = ArgonParams{Time: 3, Memory: 64 * 1024, Threads: 4}

// SealedEntry is what the gateway stores and returns: ciphertext only.
type SealedEntry struct {
	Version    int         `json:"version"`
	Salt       []byte      `json:"salt"`
	Argon      ArgonParams `json:"argon"`
	WrappedDEK []byte      `json:"wrappedDek"` // nonce || ciphertext
	Nonce      []byte      `json:"nonce"`
	Ciphertext []byte      `json:"ciphertext"`
	// Names lists the secret names inside (never values) so the UI and audit can show what exists.
	Names     []string  `json:"names"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// ErrVaultKey is returned when the user key does not open an entry.
var ErrVaultKey = errors.New("vault: wrong key or corrupted entry")

// NewSalt returns 16 random bytes.
func NewSalt() []byte {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// DeriveUserKey derives K_user from a passphrase.
func DeriveUserKey(passphrase string, salt []byte, p ArgonParams) []byte {
	return argon2.IDKey([]byte(passphrase), salt, p.Time, p.Memory, p.Threads, 32)
}

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func aad(parts ...string) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return h.Sum(nil)
}

// SealEntry encrypts secrets for (subject, adapter) under the user key.
func SealEntry(userKey []byte, salt []byte, params ArgonParams, subject, adapter string, secrets map[string]string) (*SealedEntry, error) {
	if len(userKey) != 32 {
		return nil, errors.New("vault: user key must be 32 bytes")
	}
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	defer Zero(dek)
	plaintext, err := json.Marshal(secrets)
	if err != nil {
		return nil, err
	}
	defer Zero(plaintext)
	entryAEAD, err := gcm(dek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, entryAEAD.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := entryAEAD.Seal(nil, nonce, plaintext, aad(subject, adapter, fmt.Sprint(VaultVersion)))

	wrapAEAD, err := gcm(userKey)
	if err != nil {
		return nil, err
	}
	wn := make([]byte, wrapAEAD.NonceSize())
	if _, err := rand.Read(wn); err != nil {
		return nil, err
	}
	wrapped := wrapAEAD.Seal(wn, wn, dek, aad(subject, adapter))

	names := make([]string, 0, len(secrets))
	for k := range secrets {
		names = append(names, k)
	}
	return &SealedEntry{Version: VaultVersion, Salt: salt, Argon: params, WrappedDEK: wrapped, Nonce: nonce,
		Ciphertext: ct, Names: names, UpdatedAt: time.Now().UTC()}, nil
}

// OpenEntry decrypts an entry. The caller must Zero the returned values after use.
func OpenEntry(userKey []byte, subject, adapter string, e *SealedEntry) (map[string]string, error) {
	if e == nil || e.Version != VaultVersion {
		return nil, fmt.Errorf("vault: unsupported entry version")
	}
	wrapAEAD, err := gcm(userKey)
	if err != nil {
		return nil, err
	}
	ns := wrapAEAD.NonceSize()
	if len(e.WrappedDEK) < ns {
		return nil, ErrVaultKey
	}
	dek, err := wrapAEAD.Open(nil, e.WrappedDEK[:ns], e.WrappedDEK[ns:], aad(subject, adapter))
	if err != nil {
		return nil, ErrVaultKey
	}
	defer Zero(dek)
	entryAEAD, err := gcm(dek)
	if err != nil {
		return nil, err
	}
	pt, err := entryAEAD.Open(nil, e.Nonce, e.Ciphertext, aad(subject, adapter, fmt.Sprint(e.Version)))
	if err != nil {
		return nil, ErrVaultKey
	}
	defer Zero(pt)
	var out map[string]string
	if err := json.Unmarshal(pt, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Zero overwrites a byte slice.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ZeroMap overwrites the values of a map (strings are immutable in Go; this
// drops the references so they are collectable; callers must not retain them).
func ZeroMap(m map[string]string) {
	for k := range m {
		delete(m, k)
	}
}

// --- tier B: sealing to a pod's ephemeral key -------------------------------

// PodKeyPair is the wrapper's per-incarnation X25519 key.
type PodKeyPair struct {
	Public  *[32]byte
	Private *[32]byte
}

// NewPodKeyPair generates a key.
func NewPodKeyPair() (*PodKeyPair, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &PodKeyPair{Public: pub, Private: priv}, nil
}

// SealToPod encrypts secrets so that only the holder of the pod's private key can read them.
func SealToPod(podPublic *[32]byte, secrets map[string]string) ([]byte, error) {
	pt, err := json.Marshal(secrets)
	if err != nil {
		return nil, err
	}
	defer Zero(pt)
	return box.SealAnonymous(nil, pt, podPublic, rand.Reader)
}

// OpenFromClient decrypts a SealToPod blob inside the pod.
func (k *PodKeyPair) OpenFromClient(blob []byte) (map[string]string, error) {
	pt, ok := box.OpenAnonymous(nil, blob, k.Public, k.Private)
	if !ok {
		return nil, errors.New("sealed secrets: cannot open with this pod's key")
	}
	defer Zero(pt)
	var out map[string]string
	if err := json.Unmarshal(pt, &out); err != nil {
		return nil, err
	}
	return out, nil
}
