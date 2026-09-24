package aead

import (
	"bytes"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

var aad = []byte("prod/db@v1")

func TestRoundTrip(t *testing.T) {
	key := NewKey()
	for _, size := range []int{0, 1, 31, 32, 1000, 64 << 10} {
		pt := bytes.Repeat([]byte{0xAB}, size)
		ct, err := Seal(key, 42, pt, aad)
		if err != nil {
			t.Fatal(err)
		}
		if len(ct) != len(pt)+Overhead {
			t.Fatalf("size %d: ciphertext length %d", size, len(ct))
		}
		if id, _ := KeyID(ct); id != 42 {
			t.Fatalf("KeyID = %d", id)
		}
		got, err := Open(key, ct, aad)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("size %d: round trip failed: %v", size, err)
		}
	}
}

// TestFrozenVector pins the envelope format; if this fails, stored data
// written by older versions would no longer decrypt.
func TestFrozenVector(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	nonce := make([]byte, nonceSize)
	for i := range nonce {
		nonce[i] = byte(0x40 + i)
	}
	want, _ := hex.DecodeString("0100000007" +
		"404142434445464748494a4b4c4d4e4f5051525354555657" +
		"b24b6a0ab58eb5041a64695453350e7613e0ea99e7e0")

	got, err := seal(key, 7, nonce, []byte("frozen"), aad)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("format changed:\n got %x\nwant %x", got, want)
	}
	pt, err := Open(key, want, aad)
	if err != nil || string(pt) != "frozen" {
		t.Fatalf("cannot open frozen vector: %v", err)
	}

	// Independent check: the body is plain XChaCha20-Poly1305 with AAD = header ‖ aad.
	raw, _ := chacha20poly1305.NewX(key)
	pt, err = raw.Open(nil, nonce, want[headerSize+nonceSize:], append(want[:headerSize:headerSize], aad...))
	if err != nil || string(pt) != "frozen" {
		t.Fatalf("envelope does not match primitive: %v", err)
	}
}

func TestEveryByteIsAuthenticated(t *testing.T) {
	key := NewKey()
	ct, _ := Seal(key, 1, []byte("attack at dawn"), aad)
	for i := range ct {
		bad := bytes.Clone(ct)
		bad[i] ^= 0x01
		if _, err := Open(key, bad, aad); err == nil {
			t.Fatalf("flipping byte %d went undetected", i)
		}
	}
}

func TestOpenFailures(t *testing.T) {
	key := NewKey()
	ct, _ := Seal(key, 1, []byte("secret"), aad)

	cases := map[string]struct {
		key, ct, aad []byte
		want         error
	}{
		"wrong aad":       {key, ct, []byte("prod/db@v2"), ErrAuth},
		"nil aad":         {key, ct, nil, ErrAuth},
		"wrong key":       {NewKey(), ct, aad, ErrAuth},
		"short key":       {key[:16], ct, aad, ErrKeySize},
		"truncated":       {key, ct[:Overhead-1], aad, ErrMalformed},
		"empty":           {key, nil, aad, ErrMalformed},
		"unknown version": {key, append([]byte{2}, ct[1:]...), aad, ErrMalformed},
	}
	for name, c := range cases {
		if _, err := Open(c.key, c.ct, c.aad); err != c.want {
			t.Errorf("%s: got %v want %v", name, err, c.want)
		}
	}
	if _, err := Seal(key[:31], 1, nil, nil); err != ErrKeySize {
		t.Errorf("Seal short key: got %v", err)
	}
}

func TestNoncesAndKeysAreFresh(t *testing.T) {
	key := NewKey()
	a, _ := Seal(key, 1, []byte("same"), aad)
	b, _ := Seal(key, 1, []byte("same"), aad)
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same plaintext are identical")
	}
	if bytes.Equal(NewKey(), NewKey()) {
		t.Fatal("NewKey repeated")
	}
}

func FuzzOpen(f *testing.F) {
	key := NewKey()
	ct, _ := Seal(key, 1, []byte("seed"), aad)
	f.Add(ct, aad)
	f.Fuzz(func(t *testing.T, ct, a []byte) {
		_, _ = Open(key, ct, a) // must not panic
	})
}

func FuzzRoundTrip(f *testing.F) {
	key := NewKey()
	f.Add([]byte("hello"), []byte("a"), uint32(0))
	f.Fuzz(func(t *testing.T, pt, a []byte, id uint32) {
		ct, err := Seal(key, id, pt, a)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Open(key, ct, a)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatal("round trip failed")
		}
		if gotID, _ := KeyID(ct); gotID != id {
			t.Fatal("key id changed")
		}
	})
}
