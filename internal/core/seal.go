package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// Sealer encrypts small secrets (pod tokens) for storage outside the process.
type Sealer interface {
	Seal(plaintext string) (string, error)
	Open(ciphertext string) (string, error)
}

// AESGCM seals with a 16/24/32-byte key encryption key (the gateway KEK).
type AESGCM struct{ aead cipher.AEAD }

var _ Sealer = (*AESGCM)(nil)

// NewAESGCM builds a cipher from a 16/24/32-byte key.
func NewAESGCM(key []byte) (*AESGCM, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &AESGCM{aead: aead}, nil
}

// Seal encrypts with a random nonce; output is base64(nonce || ciphertext).
func (a *AESGCM) Seal(plaintext string) (string, error) {
	nonce := make([]byte, a.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := a.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.RawStdEncoding.EncodeToString(ct), nil
}

// Open decrypts a Seal output.
func (a *AESGCM) Open(ciphertext string) (string, error) {
	raw, err := base64.RawStdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	ns := a.aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("ciphertext too short")
	}
	pt, err := a.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
