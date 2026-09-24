// Package barrier encrypts everything the server stores and owns the
// seal/unseal lifecycle that makes the keys available.
//
// Key hierarchy (same shape as Vault/OpenBao):
//
//	unseal key   rebuilt from Shamir shares, used once per unseal, never stored
//	  └─ root key       RAM only on unsealed nodes; stored only wrapped by the unseal key
//	       └─ keyring   terms 1, 2, ... ; stored encrypted by the root key
//	            └─ every value written through the Barrier
//
// Rekey (new shares) re-wraps the root key only, so nodes that are already
// unsealed keep working. Rotate adds a keyring term.
//
// Values are bound to their storage key (AEAD additional data), so ciphertext
// copied to another key fails to decrypt. Key names are stored in plaintext;
// don't put secrets in paths.
package barrier

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/hamad-tariq/SecretsManager/internal/crypto/aead"
	"github.com/hamad-tariq/SecretsManager/internal/storage"
)

// rawPrefix holds the barrier's own record; it is unreachable through the
// Barrier's Backend methods.
const (
	rawPrefix = "raw/"
	sealKey   = rawPrefix + "seal"
)

var (
	ErrSealed   = errors.New("barrier: sealed")
	ErrReserved = errors.New("barrier: keys under raw/ are reserved")

	// Distinct AADs so the two ciphertexts in the record can't be swapped.
	rootAAD    = []byte(sealKey + "#root")
	keyringAAD = []byte(sealKey + "#keyring")
)

// sealRecord is everything the barrier stores, in one value so it always
// changes atomically (one Raft write). Every change is a check-and-set
// against the bytes read, so concurrent Init/Rotate/Rekey can't clobber
// each other.
type sealRecord struct {
	SealConfig
	WrappedRoot []byte `json:"wrapped_root"` // root key, encrypted under the unseal key
	Keyring     []byte `json:"keyring"`      // keyringJSON, encrypted under the root key

	raw []byte // stored bytes this record was read from; nil for a new record
}

// Barrier is a storage.Backend that encrypts on the way in and decrypts on the
// way out. It is unusable (ErrSealed) until unsealed.
type Barrier struct {
	raw storage.Backend

	mu sync.RWMutex
	ks *keySet // nil while sealed
}

var _ storage.Backend = (*Barrier)(nil)

func New(raw storage.Backend) *Barrier { return &Barrier{raw: raw} }

func (b *Barrier) loadRecord() (sealRecord, error) {
	v, err := b.raw.Get(sealKey)
	if err != nil {
		return sealRecord{}, err
	}
	r := sealRecord{raw: v}
	return r, json.Unmarshal(v, &r)
}

// saveRecord writes r only if the stored record is still r.raw.
func (b *Barrier) saveRecord(r sealRecord) error {
	v, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return b.raw.PutIf(sealKey, v, r.raw)
}

// unwrapRoot decrypts the root key onto the heap; callers wipe it or hand it
// to openKeySet, which does. A wrong unseal key fails here, which is how bad
// shares are detected.
func unwrapRoot(unsealKey []byte, r sealRecord) ([]byte, error) {
	return aead.Open(unsealKey, r.WrappedRoot, rootAAD)
}

// unseal loads the keyring with root (wiping root).
func (b *Barrier) unseal(root []byte) error {
	r, err := b.loadRecord()
	if err != nil {
		clear(root)
		return err
	}
	ks, err := openKeySet(root, r.Keyring)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ks.destroy()
	b.ks = ks
	return nil
}

// Seal wipes every key from memory. The Barrier refuses all operations until
// it is unsealed again.
func (b *Barrier) Seal() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ks.destroy()
	b.ks = nil
}

// RootAdmin is the identity given unrestricted access at init ("" while sealed).
func (b *Barrier) RootAdmin() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.ks == nil {
		return ""
	}
	return b.ks.rootAdmin
}

func (b *Barrier) Sealed() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.ks == nil
}

// Rotate adds a new keyring term and returns it. New writes use it; older
// terms stay for reading existing data.
func (b *Barrier) Rotate() (uint32, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ks == nil {
		return 0, ErrSealed
	}
	// Start from the stored keyring (another node may have rotated already),
	// and write back only if nobody changed it since this one read.
	r, err := b.loadRecord()
	if err != nil {
		return 0, err
	}
	current, err := b.openWithRoot(r)
	if err != nil {
		return 0, err
	}
	next := current.withNewTerm()
	current.destroy()
	if r.Keyring, err = next.encryptKeyring(); err == nil {
		// On an ambiguous write error the new term may be stored anyway;
		// that's harmless: Get reloads the keyring when it meets a new term.
		err = b.saveRecord(r)
	}
	if err != nil {
		next.destroy()
		return 0, err
	}
	b.ks.destroy()
	b.ks = next
	return next.active, nil
}

// openWithRoot decrypts r's keyring with the in-memory root key.
func (b *Barrier) openWithRoot(r sealRecord) (*keySet, error) {
	root := make([]byte, aead.KeySize)
	copy(root, b.ks.root())
	return openKeySet(root, r.Keyring)
}

// reload refreshes the keyring after another node rotated it.
func (b *Barrier) reload() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ks == nil {
		return ErrSealed
	}
	r, err := b.loadRecord()
	if err != nil {
		return err
	}
	ks, err := b.openWithRoot(r)
	if err != nil {
		return err
	}
	b.ks.destroy()
	b.ks = ks
	return nil
}

func checkKey(key string) error {
	if strings.HasPrefix(key, rawPrefix) {
		return ErrReserved
	}
	return nil
}

func (b *Barrier) encrypt(key string, value []byte) ([]byte, error) {
	if err := checkKey(key); err != nil {
		return nil, err
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.ks == nil {
		return nil, ErrSealed
	}
	k, _ := b.ks.key(b.ks.active)
	return aead.Seal(k, b.ks.active, value, []byte(key))
}

func (b *Barrier) Put(key string, value []byte) error {
	ct, err := b.encrypt(key, value)
	if err != nil {
		return err
	}
	return b.raw.Put(key, ct)
}

// PutIf writes value only if the stored ciphertext is still token (from
// GetToken; nil = key must not exist). Otherwise storage.ErrConflict.
func (b *Barrier) PutIf(key string, value, token []byte) error {
	ct, err := b.encrypt(key, value)
	if err != nil {
		return err
	}
	return b.raw.PutIf(key, ct, token)
}

// GetToken is Get plus a token (the stored ciphertext) for a later PutIf.
func (b *Barrier) GetToken(key string) (value, token []byte, err error) {
	if err := checkKey(key); err != nil {
		return nil, nil, err
	}
	if b.Sealed() {
		return nil, nil, ErrSealed
	}
	ct, err := b.raw.Get(key)
	if err != nil {
		return nil, nil, err
	}
	pt, err := b.decrypt(key, ct)
	return pt, ct, err
}

var errUnknownTerm = errors.New("unknown keyring term")

func (b *Barrier) Get(key string) ([]byte, error) {
	if err := checkKey(key); err != nil {
		return nil, err
	}
	if b.Sealed() {
		return nil, ErrSealed
	}
	ct, err := b.raw.Get(key)
	if err != nil {
		return nil, err
	}
	return b.decrypt(key, ct)
}

func (b *Barrier) decrypt(key string, ct []byte) ([]byte, error) {
	term, err := aead.KeyID(ct)
	if err != nil {
		return nil, fmt.Errorf("barrier: %s: %w", key, err)
	}
	pt, err := b.open(term, ct, key)
	if errors.Is(err, errUnknownTerm) {
		if err := b.reload(); err != nil {
			return nil, err
		}
		pt, err = b.open(term, ct, key)
	}
	if err != nil {
		return nil, fmt.Errorf("barrier: %s: %w", key, err)
	}
	return pt, nil
}

func (b *Barrier) open(term uint32, ct []byte, key string) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.ks == nil {
		return nil, ErrSealed
	}
	k, ok := b.ks.key(term)
	if !ok {
		return nil, errUnknownTerm
	}
	return aead.Open(k, ct, []byte(key))
}

func (b *Barrier) Delete(key string) error {
	if err := checkKey(key); err != nil {
		return err
	}
	if b.Sealed() {
		return ErrSealed
	}
	return b.raw.Delete(key)
}

func (b *Barrier) List(prefix string) ([]string, error) {
	if b.Sealed() {
		return nil, ErrSealed
	}
	keys, err := b.raw.List(prefix)
	if err != nil {
		return nil, err
	}
	out := keys[:0]
	for _, k := range keys {
		if !strings.HasPrefix(k, rawPrefix) {
			out = append(out, k)
		}
	}
	return out, nil
}
