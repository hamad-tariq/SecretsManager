package barrier

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"

	"github.com/hamad-tariq/SecretsManager/internal/cluster"
	"github.com/hamad-tariq/SecretsManager/internal/crypto/aead"
	"github.com/hamad-tariq/SecretsManager/internal/pki"
	"github.com/hamad-tariq/SecretsManager/internal/storage"
)

const canary = "CANARY-plaintext-4f2a9c"

// newSeal registers cleanup: locked memory is a per-process quota, so tests
// must release it like production code does.
func newSeal(t *testing.T, raw storage.Backend) *Seal {
	s := NewSeal(raw)
	t.Cleanup(s.Seal)
	return s
}

func initSeal(t *testing.T, raw storage.Backend, n, m int) (*Seal, []string) {
	t.Helper()
	s := newSeal(t, raw)
	shares, err := s.Init(n, m, nil, "spiffe://sm/admin/root")
	if err != nil {
		t.Fatal(err)
	}
	return s, shares
}

func unsealWith(t *testing.T, s *Seal, shares []string) {
	t.Helper()
	for _, sh := range shares {
		if _, err := s.Unseal(sh); err != nil {
			t.Fatal(err)
		}
	}
	if s.Sealed() {
		t.Fatal("still sealed")
	}
}

func TestSealedRefusesEverything(t *testing.T) {
	raw := storage.NewInmem()
	s := newSeal(t, raw)
	if st, _ := s.Status(); st.Initialized || !st.Sealed {
		t.Fatalf("fresh status %+v", st)
	}
	if _, err := s.Unseal("x"); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("unseal before init: %v", err)
	}
	if _, err := s.Init(5, 3, nil, "spiffe://sm/admin/root"); err != nil {
		t.Fatal(err)
	}
	if err := s.Put("a", []byte("b")); !errors.Is(err, ErrSealed) {
		t.Error("Put while sealed")
	}
	if _, err := s.Get("a"); !errors.Is(err, ErrSealed) {
		t.Error("Get while sealed")
	}
	if err := s.Delete("a"); !errors.Is(err, ErrSealed) {
		t.Error("Delete while sealed")
	}
	if _, err := s.List(""); !errors.Is(err, ErrSealed) {
		t.Error("List while sealed")
	}
	if _, err := s.Rotate(); !errors.Is(err, ErrSealed) {
		t.Error("Rotate while sealed")
	}
}

func TestInitUnsealAllSubsets(t *testing.T) {
	raw := storage.NewInmem()
	s, shares := initSeal(t, raw, 5, 3)
	if _, err := s.Init(5, 3, nil, "spiffe://sm/admin/root"); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("second init: %v", err)
	}

	for i, sh := range shares[:2] {
		st, err := s.Unseal(sh)
		if err != nil || !st.Sealed || st.Progress != i+1 || st.Threshold != 3 || st.Shares != 5 {
			t.Fatalf("after share %d: %+v %v", i+1, st, err)
		}
	}
	st, err := s.Unseal(shares[2])
	if err != nil || st.Sealed || st.Progress != 0 {
		t.Fatalf("after threshold: %+v %v", st, err)
	}
	if err := s.Put("prod/db", []byte(canary)); err != nil {
		t.Fatal(err)
	}

	// Every 3-of-5 subset unseals an independent node over the same storage.
	for mask := range 1 << 5 {
		if bits.OnesCount(uint(mask)) != 3 {
			continue
		}
		var sub []string
		for i := range 5 {
			if mask&(1<<i) != 0 {
				sub = append(sub, shares[i])
			}
		}
		other := newSeal(t, raw)
		unsealWith(t, other, sub)
		if v, err := other.Get("prod/db"); err != nil || string(v) != canary {
			t.Fatalf("subset %05b: %q %v", mask, v, err)
		}
		other.Seal()
	}

	if _, err := newSeal(t, raw).Init(1, 1, nil, "spiffe://sm/admin/root"); err == nil {
		t.Fatal("bad Shamir params accepted")
	}
}

func TestNoPlaintextAtRest(t *testing.T) {
	raw := storage.NewInmem()
	s, shares := initSeal(t, raw, 3, 2)
	unsealWith(t, s, shares[:2])
	for i := range 50 {
		if err := s.Put(fmt.Sprintf("prod/k%d", i), []byte(canary)); err != nil {
			t.Fatal(err)
		}
	}
	term1, _ := s.ks.key(1)
	secrets := [][]byte{[]byte(canary), s.ks.root(), term1}
	for k, v := range raw.Snapshot() {
		for _, sec := range secrets {
			if bytes.Contains(v, sec) {
				t.Fatalf("raw value at %s contains secret material", k)
			}
		}
	}
}

func TestCiphertextBoundToKeyAndTamperProof(t *testing.T) {
	raw := storage.NewInmem()
	s, shares := initSeal(t, raw, 3, 2)
	unsealWith(t, s, shares[:2])
	_ = s.Put("prod/a", []byte("secret-a"))
	ct, _ := raw.Get("prod/a")

	_ = raw.Put("prod/b", ct) // copy ciphertext to another path
	if _, err := s.Get("prod/b"); err == nil {
		t.Fatal("ciphertext moved to another key still decrypted")
	}
	bad := bytes.Clone(ct)
	bad[len(bad)-1] ^= 1
	_ = raw.Put("prod/a", bad)
	if _, err := s.Get("prod/a"); err == nil {
		t.Fatal("tampered ciphertext decrypted")
	}
	_ = raw.Put("prod/c", []byte{9, 9})
	if _, err := s.Get("prod/c"); err == nil {
		t.Fatal("garbage decrypted")
	}
	if _, err := s.Get("missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("missing key: %v", err)
	}
}

func TestReservedKeys(t *testing.T) {
	raw := storage.NewInmem()
	s, shares := initSeal(t, raw, 3, 2)
	unsealWith(t, s, shares[:2])
	if err := s.Put("raw/seal", []byte("x")); !errors.Is(err, ErrReserved) {
		t.Error("Put raw/ allowed")
	}
	if _, err := s.Get("raw/seal"); !errors.Is(err, ErrReserved) {
		t.Error("Get raw/ allowed")
	}
	if err := s.Delete("raw/seal"); !errors.Is(err, ErrReserved) {
		t.Error("Delete raw/ allowed")
	}
	_ = s.Put("a", []byte("1"))
	keys, err := s.List("")
	if err != nil || len(keys) != 1 || keys[0] != "a" {
		t.Fatalf("List leaked raw keys: %v %v", keys, err)
	}
	if err := s.Delete("a"); err != nil {
		t.Fatal(err)
	}
}

func TestBadShares(t *testing.T) {
	raw := storage.NewInmem()
	s, shares := initSeal(t, raw, 5, 3)
	_, foreign := initSeal(t, storage.NewInmem(), 5, 3)

	for _, bad := range []string{"not base64!", "AAAA", shares[0] + "AAAA"} {
		if _, err := s.Unseal(bad); !errors.Is(err, ErrBadShare) {
			t.Errorf("share %q: %v", bad, err)
		}
	}

	if _, err := s.Unseal(shares[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Unseal(shares[0]); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate: %v", err)
	}

	// Two good shares + one from another cluster: rejected, progress reset.
	_, _ = s.Unseal(shares[1])
	var err error
	for _, f := range foreign {
		if _, err = s.Unseal(f); !errors.Is(err, ErrDuplicate) {
			break // first foreign share with a fresh x coordinate
		}
	}
	if !errors.Is(err, ErrInvalidShares) {
		t.Fatalf("foreign share: %v", err)
	}
	if st, _ := s.Status(); !st.Sealed || st.Progress != 0 {
		t.Fatalf("after invalid set: %+v", st)
	}
	unsealWith(t, s, shares[2:])
}

func TestProgressExpires(t *testing.T) {
	raw := storage.NewInmem()
	s, shares := initSeal(t, raw, 5, 3)
	now := time.Now()
	s.now = func() time.Time { return now }
	_, _ = s.Unseal(shares[0])
	_, _ = s.Unseal(shares[1])
	now = now.Add(ProgressTTL + time.Second)
	if st, _ := s.Status(); st.Progress != 0 {
		t.Fatalf("progress not expired: %+v", st)
	}
	if st, _ := s.Unseal(shares[2]); !st.Sealed || st.Progress != 1 {
		t.Fatalf("expired shares still counted: %+v", st)
	}
}

func TestSealNow(t *testing.T) {
	raw := storage.NewInmem()
	s, shares := initSeal(t, raw, 3, 2)
	unsealWith(t, s, shares[:2])
	if st, _ := s.Unseal(shares[2]); st.Sealed {
		t.Fatal("unseal on unsealed node changed state")
	}
	s.Seal()
	if _, err := s.Get("a"); !errors.Is(err, ErrSealed) {
		t.Fatal("still serving after Seal")
	}
	_, _ = s.Unseal(shares[0])
	s.Seal()
	if st, _ := s.Status(); st.Progress != 0 {
		t.Fatal("Seal kept pending shares")
	}
	unsealWith(t, s, shares[1:])
}

func TestRotateAcrossNodes(t *testing.T) {
	raw := storage.NewInmem() // shared storage stands in for the cluster
	a, shares := initSeal(t, raw, 3, 2)
	unsealWith(t, a, shares[:2])
	b := newSeal(t, raw)
	unsealWith(t, b, shares[1:])

	_ = a.Put("old", []byte("term1"))
	term, err := a.Rotate()
	if err != nil || term != 2 {
		t.Fatalf("rotate: %d %v", term, err)
	}
	_ = a.Put("new", []byte("term2"))
	if id := keyID(t, raw, "new"); id != 2 {
		t.Fatalf("new write used term %d", id)
	}
	// b still has only term 1 in memory; reading term-2 data reloads.
	for k, want := range map[string]string{"old": "term1", "new": "term2"} {
		if v, err := b.Get(k); err != nil || string(v) != want {
			t.Fatalf("b.Get(%s): %q %v", k, v, err)
		}
	}
	if term, _ := b.Rotate(); term != 3 {
		t.Fatalf("second rotate from other node: term %d", term)
	}
}

func keyID(t *testing.T, raw storage.Backend, key string) uint32 {
	ct, _ := raw.Get(key)
	return uint32(ct[1])<<24 | uint32(ct[2])<<16 | uint32(ct[3])<<8 | uint32(ct[4])
}

func TestRekey(t *testing.T) {
	raw := storage.NewInmem()
	a, old := initSeal(t, raw, 5, 3)
	unsealWith(t, a, old[:3])
	b := newSeal(t, raw)
	unsealWith(t, b, old[2:])
	_ = a.Put("data", []byte(canary))

	if _, err := a.Rekey(old[:2], 4, 2, nil); !errors.Is(err, ErrInvalidShares) {
		t.Fatalf("too few shares: %v", err)
	}
	_, foreign := initSeal(t, storage.NewInmem(), 5, 3)
	if _, err := a.Rekey(foreign[:3], 4, 2, nil); !errors.Is(err, ErrInvalidShares) {
		t.Fatalf("wrong shares: %v", err)
	}
	if _, err := a.Rekey([]string{"x", "y", "z"}, 4, 2, nil); !errors.Is(err, ErrBadShare) {
		t.Fatalf("malformed shares: %v", err)
	}

	fresh, err := a.Rekey(old[1:4], 4, 2, nil)
	if err != nil || len(fresh) != 4 {
		t.Fatalf("rekey: %v", err)
	}

	// Already-unsealed node b keeps working, even through a rotation.
	if _, err := a.Rotate(); err != nil {
		t.Fatal(err)
	}
	_ = a.Put("after", []byte("x"))
	if _, err := b.Get("after"); err != nil {
		t.Fatalf("unsealed node broke after rekey+rotate: %v", err)
	}

	// Old shares no longer unseal; new ones (new threshold 2) do.
	c := newSeal(t, raw)
	_, _ = c.Unseal(old[0])
	if _, err := c.Unseal(old[1]); !errors.Is(err, ErrInvalidShares) || !c.Sealed() {
		t.Fatalf("old shares after rekey: %v", err)
	}
	unsealWith(t, c, fresh[2:])
	if v, _ := c.Get("data"); string(v) != canary {
		t.Fatal("data lost across rekey")
	}
	if st, _ := c.Status(); st.Shares != 4 || st.Threshold != 2 {
		t.Fatalf("config after rekey: %+v", st)
	}
}

// flaky fails writes to the seal record, optionally after applying them,
// and can fail reads too.
type flaky struct {
	*storage.Inmem
	commit, failGet bool
	later, conflict bool // later: the write lands after the caller gave up; conflict: a definite CAS failure
	armed, tried    bool
	pending         func() // the delayed write, for later
}

func (f *flaky) Put(k string, v []byte) error {
	if f.armed && k == sealKey {
		f.tried = true
		if f.commit {
			_ = f.Inmem.Put(k, v)
		}
		return errors.New("timeout")
	}
	return f.Inmem.Put(k, v)
}

func (f *flaky) PutIf(k string, v, expected []byte) error {
	if f.armed && k == sealKey {
		f.tried = true
		switch {
		case f.conflict:
			return storage.ErrConflict
		case f.later:
			f.pending = func() { _ = f.Inmem.PutIf(k, v, expected) }
		case f.commit:
			_ = f.Inmem.PutIf(k, v, expected)
		}
		return errors.New("timeout")
	}
	return f.Inmem.PutIf(k, v, expected)
}

func (f *flaky) Get(k string) ([]byte, error) {
	if f.armed && f.failGet && f.tried {
		return nil, errors.New("unreachable")
	}
	return f.Inmem.Get(k)
}

func TestRekeyAmbiguousWrite(t *testing.T) {
	for _, c := range []struct {
		name                          string
		commit, failGet, later, confl bool
		wantShares                    bool
		wantErr                       error
		newSharesWork                 bool
	}{
		{"committed despite error", true, false, false, false, true, nil, true},
		// Not visible yet: it may still commit, so the shares must be kept.
		{"not committed yet", false, false, false, false, true, ErrRekeyUnknown, false},
		{"commits after rekey gave up", false, false, true, false, true, ErrRekeyUnknown, true},
		{"read fails", true, true, false, false, true, ErrRekeyUnknown, true},
		{"definite conflict", false, false, false, true, false, errAny, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := &flaky{Inmem: storage.NewInmem(), commit: c.commit, failGet: c.failGet, later: c.later, conflict: c.confl}
			s, old := initSeal(t, f, 3, 2)
			f.armed = true
			fresh, err := s.Rekey(old[:2], 3, 2, nil)
			f.armed = false
			if f.pending != nil {
				f.pending() // the Raft entry commits after all
			}
			if (fresh != nil) != c.wantShares {
				t.Fatalf("shares returned: %v", fresh != nil)
			}
			if c.wantErr == nil && err != nil || c.wantErr == ErrRekeyUnknown && !errors.Is(err, ErrRekeyUnknown) || c.wantErr == errAny && err == nil {
				t.Fatalf("err = %v", err)
			}
			n := newSeal(t, f)
			use := old
			if c.newSharesWork {
				use = fresh
			}
			unsealWith(t, n, use[:2])
		})
	}
}

var errAny = errors.New("any error")

func TestAgeEncryptedShares(t *testing.T) {
	var ids []*age.X25519Identity
	var recips []string
	for range 3 {
		id, _ := age.GenerateX25519Identity()
		ids = append(ids, id)
		recips = append(recips, id.Recipient().String())
	}
	raw := storage.NewInmem()
	s := newSeal(t, raw)
	if _, err := s.Init(3, 2, recips[:2], "spiffe://sm/admin/root"); err == nil {
		t.Fatal("recipient count mismatch accepted")
	}
	if _, err := s.Init(3, 2, []string{"age1bad", "x", "y"}, "spiffe://sm/admin/root"); err == nil {
		t.Fatal("bad recipient accepted")
	}
	enc, err := s.Init(3, 2, recips, "spiffe://sm/admin/root")
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range enc {
		if !strings.HasPrefix(e, "-----BEGIN AGE ENCRYPTED FILE-----") {
			t.Fatalf("share %d not armored", i)
		}
		if _, err := decryptShare(ids[(i+1)%3], e); err == nil {
			t.Fatal("share decrypted by the wrong holder")
		}
	}
	for i := range 2 {
		plain, err := decryptShare(ids[i], enc[i])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Unseal(plain); err != nil {
			t.Fatal(err)
		}
	}
	if s.Sealed() {
		t.Fatal("age-decrypted shares did not unseal")
	}
}

func decryptShare(id age.Identity, armored string) (string, error) {
	r, err := age.Decrypt(armor.NewReader(strings.NewReader(armored)), id)
	if err != nil {
		return "", err
	}
	b, err := io.ReadAll(r)
	return string(b), err
}

// TestNoPlaintextOnClusterDisk runs the barrier on a real Raft node and
// greps every file it wrote (log, stable store, snapshots) for the canary.
func TestNoPlaintextOnClusterDisk(t *testing.T) {
	root, _ := pki.NewRoot("test", time.Hour)
	roots := x509.NewCertPool()
	roots.AddCert(root.Cert)
	key, _ := pki.NewKey()
	cert, _ := root.Issue(pki.Identity{Kind: pki.Node, Name: "node-1"}, key.Public(), time.Hour, "127.0.0.1")
	rc := raft.DefaultConfig()
	rc.HeartbeatTimeout, rc.ElectionTimeout, rc.LeaderLeaseTimeout = 150*time.Millisecond, 150*time.Millisecond, 100*time.Millisecond
	rc.SnapshotThreshold, rc.TrailingLogs, rc.SnapshotInterval = 20, 5, 100*time.Millisecond
	dir := t.TempDir()
	node, err := cluster.Start(cluster.Config{ID: "node-1", RaftAddr: "127.0.0.1:0", RPCAddr: "127.0.0.1:0",
		DataDir: dir, Cert: pki.TLSCertificate(cert, key), Roots: roots, Bootstrap: true,
		Raft: rc, Logger: hclog.NewNullLogger(), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}

	s, shares := initSeal(t, node, 3, 2)
	unsealWith(t, s, shares[:2])
	for i := range 100 {
		if err := s.Put(fmt.Sprintf("prod/k%d", i), []byte(canary)); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(500 * time.Millisecond) // let a snapshot happen
	node.Shutdown()

	files := 0
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, _ := os.ReadFile(p)
		files++
		if bytes.Contains(data, []byte(canary)) {
			t.Errorf("plaintext found in %s", p)
		}
		return nil
	})
	if files < 2 {
		t.Fatalf("expected raft.db and snapshot files, found %d", files)
	}
}

// TestLockedMemoryIsBounded rotates far more often than locked-memory quotas
// allow buffers for (Windows allows a few dozen by default). One buffer per
// term used to panic here.
func TestLockedMemoryIsBounded(t *testing.T) {
	raw := storage.NewInmem()
	a, shares := initSeal(t, raw, 3, 2)
	unsealWith(t, a, shares[:2])
	b := newSeal(t, raw)
	unsealWith(t, b, shares[1:])
	for i := range 200 {
		if _, err := a.Rotate(); err != nil {
			t.Fatal(err)
		}
		k := fmt.Sprintf("k%d", i)
		_ = a.Put(k, []byte(k))
		if v, err := b.Get(k); err != nil || string(v) != k { // b reloads every time
			t.Fatalf("rotation %d: %q %v", i, v, err)
		}
	}
	if len(a.ks.terms) != 201 {
		t.Fatalf("terms = %d", len(a.ks.terms))
	}
}

func TestConcurrentInitOneWins(t *testing.T) {
	raw := storage.NewInmem()
	a, b := newSeal(t, raw), newSeal(t, raw)
	results := make(chan error, 2)
	for _, s := range []*Seal{a, b} {
		go func() { _, err := s.Init(3, 2, nil, "spiffe://sm/admin/root"); results <- err }()
	}
	var ok, lost int
	for range 2 {
		switch err := <-results; {
		case err == nil:
			ok++
		case errors.Is(err, ErrAlreadyInitialized):
			lost++
		default:
			t.Fatal(err)
		}
	}
	if ok != 1 || lost != 1 {
		t.Fatalf("ok=%d lost=%d", ok, lost)
	}
	if _, err := newSeal(t, raw).Init(3, 2, nil, ""); err == nil {
		t.Fatal("init without root admin accepted")
	}
}

func TestPutIfThroughBarrier(t *testing.T) {
	raw := storage.NewInmem()
	s, shares := initSeal(t, raw, 3, 2)
	if s.RootAdmin() != "" {
		t.Fatal("root admin visible while sealed")
	}
	unsealWith(t, s, shares[:2])
	if s.RootAdmin() != "spiffe://sm/admin/root" {
		t.Fatalf("root admin = %q", s.RootAdmin())
	}
	if err := s.PutIf("k", []byte("v1"), nil); err != nil {
		t.Fatal(err)
	}
	v, tok, err := s.GetToken("k")
	if err != nil || string(v) != "v1" {
		t.Fatalf("GetToken: %q %v", v, err)
	}
	if err := s.PutIf("k", []byte("v2"), tok); err != nil {
		t.Fatal(err)
	}
	if err := s.PutIf("k", []byte("v3"), tok); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("stale token: %v", err)
	}
	if _, _, err := s.GetToken("raw/seal"); !errors.Is(err, ErrReserved) {
		t.Fatal("GetToken on raw/ allowed")
	}
	if _, _, err := s.GetToken("missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("GetToken missing key")
	}
	s.Seal()
	if _, _, err := s.GetToken("k"); !errors.Is(err, ErrSealed) {
		t.Fatal("GetToken while sealed")
	}
	if err := s.PutIf("k", nil, nil); !errors.Is(err, ErrSealed) {
		t.Fatal("PutIf while sealed")
	}
}

// An emergency seal must win over an unseal already past Combine.
func TestSealWinsOverUnsealInFlight(t *testing.T) {
	raw := storage.NewInmem()
	s, shares := initSeal(t, raw, 3, 2)
	s.Seal()
	if _, err := s.Unseal(shares[0]); err != nil {
		t.Fatal(err)
	}
	s.afterCombine = s.Seal // the operator presses seal at the worst moment
	if _, err := s.Unseal(shares[1]); !errors.Is(err, ErrSealedDuringUnseal) {
		t.Fatalf("unseal completed across a seal: %v", err)
	}
	if !s.Sealed() {
		t.Fatal("node is unsealed after the emergency seal")
	}
	s.afterCombine = nil
	unsealWith(t, s, shares[:2]) // and a deliberate unseal afterwards works
}

func TestKeyringEncoding(t *testing.T) {
	ks := freshKeySet("spiffe://sm/admin/alice").withNewTerm()
	defer ks.destroy()
	ct, err := ks.encryptKeyring()
	if err != nil {
		t.Fatal(err)
	}
	root := append([]byte(nil), ks.root()...)
	back, err := openKeySet(root, ct)
	if err != nil {
		t.Fatal(err)
	}
	defer back.destroy()
	k1, _ := ks.key(1)
	k2, _ := back.key(1)
	if back.active != 2 || back.rootAdmin != ks.rootAdmin || !bytes.Equal(k1, k2) || len(back.terms) != 2 {
		t.Fatalf("round trip: active %d admin %q terms %d", back.active, back.rootAdmin, len(back.terms))
	}

	// Version 1 (JSON) keyrings written before this change still open.
	old, _ := json.Marshal(keyringJSON{Active: 1, Keys: map[uint32][]byte{1: bytes.Repeat([]byte{7}, 32)}, RootAdmin: "x"})
	legacy, _ := aead.Seal(ks.root(), 0, old, keyringAAD)
	root = append([]byte(nil), ks.root()...)
	lk, err := openKeySet(root, legacy)
	if err != nil || lk.rootAdmin != "x" || lk.active != 1 {
		t.Fatalf("legacy keyring: %v", err)
	}
	lk.destroy()

	// Truncated or inconsistent plaintexts are refused.
	for _, pt := range [][]byte{{}, {keyringV2}, {keyringV2, 0, 0, 0, 1, 0, 9}, append([]byte{keyringV2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1}, make([]byte, 20)...)} {
		if _, err := decodeKeyring(pt); err == nil {
			t.Errorf("malformed keyring %v accepted", pt)
		}
	}
	// No active key.
	bad := []byte{keyringV2, 0, 0, 0, 9, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1}
	bad = append(bad, make([]byte, 32)...)
	ctBad, _ := aead.Seal(ks.root(), 0, bad, keyringAAD)
	root = append([]byte(nil), ks.root()...)
	if _, err := openKeySet(root, ctBad); err == nil {
		t.Error("keyring without its active key accepted")
	}
}
