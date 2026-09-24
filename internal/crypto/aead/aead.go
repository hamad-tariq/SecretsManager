// Package aead encrypts and decrypts with XChaCha20-Poly1305 and a small
// versioned envelope. The 24-byte nonce is random, which is safe for any
// realistic number of messages per key, so one algorithm serves both data
// encryption and key wrapping.
//
// Envelope: version(1) ‖ keyID(4, big endian) ‖ nonce(24) ‖ ciphertext+tag(16).
// The version and keyID are authenticated together with the caller's AAD.
package aead

import (
	"crypto/rand"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KeySize    = chacha20poly1305.KeySize
	version1   = 1
	headerSize = 1 + 4
	nonceSize  = chacha20poly1305.NonceSizeX
	// Overhead is how many bytes Seal adds to the plaintext.
	Overhead = headerSize + nonceSize + chacha20poly1305.Overhead
)

var (
	ErrKeySize   = errors.New("aead: key must be 32 bytes")
	ErrMalformed = errors.New("aead: malformed ciphertext")
	ErrAuth      = errors.New("aead: message authentication failed")
)

// NewKey returns a fresh random 32-byte key.
func NewKey() []byte {
	k := make([]byte, KeySize)
	_, _ = rand.Read(k) // never fails since Go 1.24
	return k
}

// Seal encrypts plaintext under key, tagging the output with keyID so the
// caller can find the right key again. aad must be passed unchanged to Open;
// bind it to where the ciphertext is stored (e.g. path + version) so it
// cannot be moved elsewhere.
func Seal(key []byte, keyID uint32, plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, nonceSize)
	_, _ = rand.Read(nonce)
	return seal(key, keyID, nonce, plaintext, aad)
}

func seal(key []byte, keyID uint32, nonce, plaintext, aad []byte) ([]byte, error) {
	c, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrKeySize
	}
	out := make([]byte, headerSize, Overhead+len(plaintext))
	out[0] = version1
	binary.BigEndian.PutUint32(out[1:headerSize], keyID)
	out = append(out, nonce...)
	return c.Seal(out, nonce, plaintext, fullAAD(out[:headerSize], aad)), nil
}

// KeyID reads the key ID from a ciphertext without decrypting it.
func KeyID(ciphertext []byte) (uint32, error) {
	if len(ciphertext) < Overhead || ciphertext[0] != version1 {
		return 0, ErrMalformed
	}
	return binary.BigEndian.Uint32(ciphertext[1:headerSize]), nil
}

// Open decrypts a ciphertext produced by Seal.
func Open(key, ciphertext, aad []byte) ([]byte, error) {
	if _, err := KeyID(ciphertext); err != nil {
		return nil, err
	}
	c, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrKeySize
	}
	header := ciphertext[:headerSize]
	nonce := ciphertext[headerSize : headerSize+nonceSize]
	pt, err := c.Open(nil, nonce, ciphertext[headerSize+nonceSize:], fullAAD(header, aad))
	if err != nil {
		return nil, ErrAuth
	}
	return pt, nil
}

// fullAAD prefixes the header to the caller's AAD. The header is fixed-size,
// so the concatenation is unambiguous.
func fullAAD(header, aad []byte) []byte {
	out := make([]byte, 0, len(header)+len(aad))
	out = append(out, header...)
	return append(out, aad...)
}
