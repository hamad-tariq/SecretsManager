package barrier

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/awnumar/memguard"

	"github.com/hamad-tariq/SecretsManager/internal/crypto/aead"
	"github.com/hamad-tariq/SecretsManager/internal/crypto/shamir"
	"github.com/hamad-tariq/SecretsManager/internal/storage"
)

// ProgressTTL is how long submitted shares wait for the rest before they're discarded.
const ProgressTTL = 10 * time.Minute

const shareLen = aead.KeySize + shamir.ShareOverhead

var (
	ErrAlreadyInitialized = errors.New("barrier: already initialized")
	ErrNotInitialized     = errors.New("barrier: not initialized")
	// ErrInvalidShares is all a caller learns when a full set of shares fails:
	// Shamir can't say which share was wrong, and we wouldn't reveal it anyway.
	ErrInvalidShares = errors.New("barrier: shares did not reconstruct the unseal key; progress reset")
	ErrBadShare      = errors.New("barrier: malformed share")
	ErrDuplicate     = errors.New("barrier: share already submitted")
	// ErrRekeyUnknown comes with the new shares: the write's outcome is unknown,
	// so holders must keep both old and new shares until one set unseals.
	ErrRekeyUnknown = errors.New("barrier: rekey outcome unknown; keep BOTH old and new shares until one set is confirmed")

	ErrSealedDuringUnseal = errors.New("barrier: sealed while unsealing; submit the shares again if that was intended")
)

// SealConfig is stored in plaintext; it holds no secrets.
type SealConfig struct {
	Shares    int `json:"shares"`
	Threshold int `json:"threshold"`
}

// Status is safe to show to anyone (health endpoint).
type Status struct {
	Initialized bool `json:"initialized"`
	Sealed      bool `json:"sealed"`
	Shares      int  `json:"shares,omitempty"`
	Threshold   int  `json:"threshold,omitempty"`
	Progress    int  `json:"progress"`
}

// Seal manages one node's sealed/unsealed state on top of a Barrier.
type Seal struct {
	*Barrier

	mu      sync.Mutex
	pending *memguard.LockedBuffer // submitted shares, back to back (one locked buffer)
	count   int
	started time.Time
	gen     uint64 // bumped by Seal: an unseal in flight across a Seal must not complete
	now     func() time.Time

	afterCombine func() // test hook: runs between rebuilding the key and installing it
}

// NewSeal wraps raw storage (normally the cluster node). It starts sealed.
func NewSeal(raw storage.Backend) *Seal {
	return &Seal{Barrier: New(raw), now: time.Now}
}

func (s *Seal) record() (sealRecord, error) {
	r, err := s.loadRecord()
	if errors.Is(err, storage.ErrNotFound) {
		return sealRecord{}, ErrNotInitialized
	}
	return r, err
}

func (s *Seal) Status() (Status, error) {
	r, err := s.record()
	if errors.Is(err, ErrNotInitialized) {
		return Status{Sealed: true}, nil
	}
	if err != nil {
		return Status{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	return Status{Initialized: true, Sealed: s.Sealed(), Shares: r.Shares, Threshold: r.Threshold, Progress: s.count}, nil
}

// Init creates the unseal key, root key and first keyring, and returns the
// shares. rootAdmin (an identity string) gets unrestricted access. With recipients (age X25519 public keys, one per share) each share
// is encrypted to its holder; without, shares are plain base64.
// The node stays sealed: holders must unseal it, which also proves the shares
// work. Shares are returned exactly once and never stored.
func (s *Seal) Init(shares, threshold int, recipients []string, rootAdmin string) ([]string, error) {
	if rootAdmin == "" {
		return nil, errors.New("barrier: a root admin identity is required")
	}
	if _, err := s.record(); err == nil {
		return nil, ErrAlreadyInitialized
	} else if !errors.Is(err, ErrNotInitialized) {
		return nil, err
	}
	encrypt, err := shareEncoder(shares, recipients)
	if err != nil {
		return nil, err
	}

	unsealKey := memguard.NewBufferRandom(aead.KeySize)
	defer unsealKey.Destroy()
	out, err := splitShares(unsealKey.Bytes(), shares, threshold, encrypt)
	if err != nil {
		return nil, err
	}

	ks := freshKeySet(rootAdmin)
	defer ks.destroy()
	r := sealRecord{SealConfig: SealConfig{Shares: shares, Threshold: threshold}}
	if r.WrappedRoot, err = aead.Seal(unsealKey.Bytes(), 0, ks.root(), rootAAD); err != nil {
		return nil, err
	}
	if r.Keyring, err = ks.encryptKeyring(); err != nil {
		return nil, err
	}
	// Create-only write: of two concurrent Inits exactly one succeeds.
	if err := s.saveRecord(r); err != nil {
		if errors.Is(err, storage.ErrConflict) {
			return nil, ErrAlreadyInitialized
		}
		return nil, err
	}
	return out, nil
}

// Unseal submits one base64 share. Once the threshold is reached it tries to
// rebuild the unseal key; on failure all progress is discarded.
func (s *Seal) Unseal(share string) (Status, error) {
	r, err := s.record()
	if err != nil {
		return Status{}, err
	}
	if !s.Sealed() {
		return s.Status()
	}
	raw, err := decodeShare(share)
	if err != nil {
		return Status{}, err
	}
	defer memguard.WipeBytes(raw)

	s.mu.Lock()
	s.expireLocked()
	if s.pending != nil && s.pending.Size() < r.Threshold*shareLen {
		s.resetLocked() // threshold changed (rekey) mid-progress: start over
	}
	if s.pending == nil {
		s.pending = memguard.NewBuffer(r.Threshold * shareLen)
		s.started = s.now()
	}
	p := s.pending.Bytes()
	for i := range s.count {
		// Same x coordinate = same share slot, whatever the y values.
		if p[i*shareLen+shareLen-1] == raw[shareLen-1] {
			s.mu.Unlock()
			return Status{}, ErrDuplicate
		}
	}
	copy(p[s.count*shareLen:], raw)
	s.count++
	if s.count < r.Threshold {
		s.mu.Unlock()
		return s.Status()
	}

	parts := make([][]byte, s.count)
	for i := range parts {
		parts[i] = p[i*shareLen : (i+1)*shareLen]
	}
	unsealKey, err := shamir.Combine(parts)
	s.resetLocked()
	gen := s.gen
	s.mu.Unlock()
	if err != nil {
		return Status{}, ErrInvalidShares
	}
	if s.afterCombine != nil {
		s.afterCombine()
	}
	root, err := unwrapRoot(unsealKey, r)
	memguard.WipeBytes(unsealKey)
	if err != nil {
		return Status{}, ErrInvalidShares
	}
	// Install the keys only if nobody pressed Seal meanwhile: an emergency
	// seal must win over an unseal that was already under way.
	s.mu.Lock()
	if s.gen != gen {
		s.mu.Unlock()
		memguard.WipeBytes(root)
		return Status{}, ErrSealedDuringUnseal
	}
	err = s.unseal(root)
	s.mu.Unlock()
	if err != nil {
		return Status{}, err
	}
	return s.Status()
}

// Seal wipes keys and any pending shares (the emergency button).
func (s *Seal) Seal() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gen++
	s.resetLocked()
	s.Barrier.Seal()
}

// Rekey replaces the shares, given at least `threshold` current ones. Only the
// wrapping of the root key changes; data, the keyring and unsealed nodes are
// unaffected. Old shares stop working.
func (s *Seal) Rekey(current []string, shares, threshold int, recipients []string) ([]string, error) {
	r, err := s.record()
	if err != nil {
		return nil, err
	}
	if len(current) < r.Threshold {
		return nil, ErrInvalidShares
	}
	encrypt, err := shareEncoder(shares, recipients)
	if err != nil {
		return nil, err
	}

	var parts [][]byte
	defer func() {
		for _, p := range parts {
			memguard.WipeBytes(p)
		}
	}()
	for _, c := range current {
		p, err := decodeShare(c)
		if err != nil {
			return nil, err
		}
		parts = append(parts, p)
	}
	oldKey, err := shamir.Combine(parts)
	if err != nil {
		return nil, ErrInvalidShares
	}
	root, err := unwrapRoot(oldKey, r)
	memguard.WipeBytes(oldKey)
	if err != nil {
		return nil, ErrInvalidShares
	}
	defer memguard.WipeBytes(root)

	newKey := memguard.NewBufferRandom(aead.KeySize)
	defer newKey.Destroy()
	out, err := splitShares(newKey.Bytes(), shares, threshold, encrypt)
	if err != nil {
		return nil, err
	}
	r.SealConfig = SealConfig{Shares: shares, Threshold: threshold}
	if r.WrappedRoot, err = aead.Seal(newKey.Bytes(), 0, root, rootAAD); err != nil {
		return nil, err
	}
	if err := s.saveRecord(r); err != nil {
		// A failed write may still commit later (e.g. a timeout while the
		// entry is in the Raft log). Never throw away shares that might be
		// the only way in; only a definite "no" may.
		if errors.Is(err, storage.ErrConflict) {
			return nil, err // the check-and-set failed: nothing was written
		}
		if stored, rerr := s.record(); rerr == nil {
			if k, uerr := unwrapRoot(newKey.Bytes(), stored); uerr == nil {
				memguard.WipeBytes(k)
				return out, nil // it did commit
			}
			if !bytes.Equal(stored.raw, r.raw) {
				return nil, err // another write replaced the record: ours can never commit
			}
		}
		// Record unchanged (or unreadable): ours may still land.
		return out, ErrRekeyUnknown
	}
	return out, nil
}

// VerifyShares checks that the given shares (at least the threshold)
// reconstruct the current unseal key. It changes nothing; it lets an action
// demand the share holders' authority rather than a certificate's.
func (s *Seal) VerifyShares(current []string) error {
	r, err := s.record()
	if err != nil {
		return err
	}
	if len(current) < r.Threshold {
		return ErrInvalidShares
	}
	var parts [][]byte
	defer func() {
		for _, p := range parts {
			memguard.WipeBytes(p)
		}
	}()
	for _, c := range current {
		p, err := decodeShare(c)
		if err != nil {
			return err
		}
		parts = append(parts, p)
	}
	key, err := shamir.Combine(parts)
	if err != nil {
		return ErrInvalidShares
	}
	root, err := unwrapRoot(key, r)
	memguard.WipeBytes(key)
	if err != nil {
		return ErrInvalidShares
	}
	memguard.WipeBytes(root)
	return nil
}

func decodeShare(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != shareLen {
		return nil, ErrBadShare
	}
	return raw, nil
}

// splitShares splits key and encodes each share for its holder.
func splitShares(key []byte, n, m int, encode func(i int, share string) (string, error)) ([]string, error) {
	parts, err := shamir.Split(key, n, m)
	if err != nil {
		return nil, err
	}
	out := make([]string, n)
	for i, p := range parts {
		b64 := base64.StdEncoding.EncodeToString(p)
		memguard.WipeBytes(p)
		if out[i], err = encode(i, b64); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// shareEncoder returns plain base64 without recipients, or age encryption
// to recipient i for share i. Holders decrypt to the base64 form Unseal takes.
func shareEncoder(shares int, recipients []string) (func(int, string) (string, error), error) {
	if recipients == nil {
		return func(_ int, s string) (string, error) { return s, nil }, nil
	}
	if len(recipients) != shares {
		return nil, fmt.Errorf("barrier: need one recipient per share (%d), got %d", shares, len(recipients))
	}
	parsed := make([]age.Recipient, len(recipients))
	for i, r := range recipients {
		p, err := age.ParseX25519Recipient(strings.TrimSpace(r))
		if err != nil {
			return nil, fmt.Errorf("barrier: recipient %d: %w", i+1, err)
		}
		parsed[i] = p
	}
	return func(i int, share string) (string, error) {
		var buf bytes.Buffer
		aw := armor.NewWriter(&buf)
		w, err := age.Encrypt(aw, parsed[i])
		if err != nil {
			return "", err
		}
		if _, err := w.Write([]byte(share)); err != nil {
			return "", err
		}
		if err := w.Close(); err != nil {
			return "", err
		}
		if err := aw.Close(); err != nil {
			return "", err
		}
		return buf.String(), nil
	}, nil
}

func (s *Seal) expireLocked() {
	if s.pending != nil && s.now().Sub(s.started) > ProgressTTL {
		s.resetLocked()
	}
}

func (s *Seal) resetLocked() {
	if s.pending != nil {
		s.pending.Destroy()
	}
	s.pending, s.count = nil, 0
}
