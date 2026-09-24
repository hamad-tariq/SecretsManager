package barrier

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"

	"github.com/awnumar/memguard"

	"github.com/hamad-tariq/SecretsManager/internal/crypto/aead"
)

// keySet holds the root key and every keyring term in ONE locked buffer.
// Locked memory is scarce (Windows working-set quota, Linux RLIMIT_MEMLOCK),
// so the number of live locked buffers must not grow with rotations: one
// buffer per term crashed after a few dozen allocations on Windows.
type keySet struct {
	buf       *memguard.LockedBuffer // root key, then one key per term
	terms     map[uint32]int         // term → offset in buf
	active    uint32
	rootAdmin string // identity with unrestricted access, set at init
}

// keyringJSON is the decoded keyring (and version 1's JSON form); it only
// exists briefly and its keys are wiped.
type keyringJSON struct {
	Active    uint32            `json:"active"`
	Keys      map[uint32][]byte `json:"keys"`
	RootAdmin string            `json:"root_admin"` // encrypted with the keys, so disk tampering can't change it
}

// newKeySet copies root and the given terms into locked memory and wipes the sources.
func newKeySet(root []byte, active uint32, terms map[uint32][]byte, rootAdmin string) *keySet {
	ks := &keySet{buf: memguard.NewBuffer(aead.KeySize * (1 + len(terms))), terms: map[uint32]int{}, active: active, rootAdmin: rootAdmin}
	b := ks.buf.Bytes()
	copy(b, root)
	memguard.WipeBytes(root)
	off := aead.KeySize
	for t, k := range terms {
		copy(b[off:], k)
		memguard.WipeBytes(k)
		ks.terms[t] = off
		off += aead.KeySize
	}
	return ks
}

// freshKeySet generates a new root key and keyring term 1.
func freshKeySet(rootAdmin string) *keySet {
	root := make([]byte, aead.KeySize)
	term := make([]byte, aead.KeySize)
	_, _ = rand.Read(root)
	_, _ = rand.Read(term)
	return newKeySet(root, 1, map[uint32][]byte{1: term}, rootAdmin)
}

func (ks *keySet) root() []byte { return ks.buf.Bytes()[:aead.KeySize] }

func (ks *keySet) key(term uint32) ([]byte, bool) {
	off, ok := ks.terms[term]
	if !ok {
		return nil, false
	}
	return ks.buf.Bytes()[off : off+aead.KeySize], true
}

func (ks *keySet) destroy() {
	if ks != nil {
		ks.buf.Destroy()
	}
}

// withNewTerm returns a copy with one more random term, made active.
func (ks *keySet) withNewTerm() *keySet {
	next := uint32(0)
	for t := range ks.terms {
		next = max(next, t)
	}
	next++
	old := ks.buf.Bytes()
	n := &keySet{buf: memguard.NewBuffer(len(old) + aead.KeySize), terms: map[uint32]int{}, active: next, rootAdmin: ks.rootAdmin}
	b := n.buf.Bytes()
	copy(b, old)
	for t, off := range ks.terms {
		n.terms[t] = off
	}
	n.terms[next] = len(old)
	_, _ = rand.Read(b[len(old):])
	return n
}

// Keyring plaintext, version 2 (binary):
//
//	0x02 | active u32 | len(rootAdmin) u16 | rootAdmin | n u32 | n × (term u32 | key 32 bytes)
//
// Written straight into one buffer that is wiped after encryption. Version 1
// was JSON (first byte '{'), which encoding/json copies through its own
// pooled buffers that can't be wiped; it is still read.
const keyringV2 = 0x02

// encryptKeyring seals the terms (not the root) under the root key.
func (ks *keySet) encryptKeyring() ([]byte, error) {
	if len(ks.rootAdmin) > 0xFFFF {
		return nil, errors.New("barrier: root admin identity too long")
	}
	pt := make([]byte, 0, 1+4+2+len(ks.rootAdmin)+4+len(ks.terms)*(4+aead.KeySize))
	defer func() { memguard.WipeBytes(pt[:cap(pt)]) }()
	pt = append(pt, keyringV2)
	pt = binary.BigEndian.AppendUint32(pt, ks.active)
	pt = binary.BigEndian.AppendUint16(pt, uint16(len(ks.rootAdmin))) // #nosec G115 -- checked above
	pt = append(pt, ks.rootAdmin...)
	pt = binary.BigEndian.AppendUint32(pt, uint32(len(ks.terms))) // #nosec G115 -- terms are few
	for t := range ks.terms {
		k, _ := ks.key(t)
		pt = binary.BigEndian.AppendUint32(pt, t)
		pt = append(pt, k...)
	}
	return aead.Seal(ks.root(), 0, pt, keyringAAD)
}

// decodeKeyring parses either plaintext version. On error it wipes whatever
// key material it already extracted.
func decodeKeyring(pt []byte) (kr keyringJSON, err error) {
	defer func() {
		if err != nil {
			for _, k := range kr.Keys {
				memguard.WipeBytes(k)
			}
		}
	}()
	if len(pt) > 0 && pt[0] == '{' { // version 1
		err = json.Unmarshal(pt, &kr)
		return kr, err
	}
	bad := errors.New("barrier: malformed keyring")
	if len(pt) < 1+4+2 || pt[0] != keyringV2 {
		return kr, bad
	}
	kr.Active = binary.BigEndian.Uint32(pt[1:])
	n := int(binary.BigEndian.Uint16(pt[5:]))
	rest := pt[7:]
	if len(rest) < n+4 {
		return kr, bad
	}
	kr.RootAdmin, rest = string(rest[:n]), rest[n:]
	count := binary.BigEndian.Uint32(rest)
	rest = rest[4:]
	if uint64(len(rest)) != uint64(count)*(4+aead.KeySize) {
		return kr, bad
	}
	kr.Keys = make(map[uint32][]byte, count)
	for len(rest) > 0 {
		kr.Keys[binary.BigEndian.Uint32(rest)] = append([]byte(nil), rest[4:4+aead.KeySize]...)
		rest = rest[4+aead.KeySize:]
	}
	return kr, nil
}

// openKeySet decrypts a stored keyring with root and returns it with root in
// one locked buffer. root is wiped either way.
func openKeySet(root, keyringCT []byte) (*keySet, error) {
	pt, err := aead.Open(root, keyringCT, keyringAAD)
	if err != nil {
		memguard.WipeBytes(root)
		return nil, err
	}
	defer memguard.WipeBytes(pt)
	kr, err := decodeKeyring(pt)
	if err == nil {
		if _, ok := kr.Keys[kr.Active]; !ok {
			err = errors.New("barrier: keyring has no active key")
		}
		for _, k := range kr.Keys {
			if len(k) != aead.KeySize {
				err = errors.New("barrier: keyring has a malformed key")
			}
		}
	}
	if err != nil {
		memguard.WipeBytes(root)
		for _, k := range kr.Keys {
			memguard.WipeBytes(k)
		}
		return nil, err
	}
	return newKeySet(root, kr.Active, kr.Keys, kr.RootAdmin), nil
}
