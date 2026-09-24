package kv

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/hamad-tariq/SecretsManager/internal/barrier"
	"github.com/hamad-tariq/SecretsManager/internal/storage"
)

func newStore(t *testing.T) (*Store, *storage.Inmem) {
	t.Helper()
	raw := storage.NewInmem()
	s := barrier.NewSeal(raw)
	t.Cleanup(s.Seal)
	shares, err := s.Init(3, 2, nil, "spiffe://sm/admin/root")
	if err != nil {
		t.Fatal(err)
	}
	for _, sh := range shares[:2] {
		if _, err := s.Unseal(sh); err != nil {
			t.Fatal(err)
		}
	}
	return New(s.Barrier), raw
}

func TestVersionsAndLabels(t *testing.T) {
	s, _ := newStore(t)
	for i := 1; i <= 3; i++ {
		v, err := s.Put("prod/db", fmt.Appendf(nil, "v%d", i), -1)
		if err != nil || v != i {
			t.Fatalf("put %d: version %d %v", i, v, err)
		}
	}
	check := func(version int, label, want string) {
		t.Helper()
		sec, err := s.Get("prod/db", version, label)
		if err != nil || string(sec.Value) != want {
			t.Fatalf("Get(%d,%q) = %q %v, want %q", version, label, sec.Value, err, want)
		}
	}
	check(0, "", "v3")
	check(0, LabelCurrent, "v3")
	check(0, LabelPrevious, "v2")
	check(1, "", "v1")
	if _, err := s.Get("prod/db", 9, ""); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing version")
	}
	if _, err := s.Get("prod/db", 0, "pending"); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing label")
	}
	if _, err := s.Get("nope", 0, ""); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing secret")
	}

	m, err := s.Metadata("prod/db")
	if err != nil || m.Latest != 3 || len(m.Versions) != 3 || m.Labels[LabelCurrent] != 3 || m.Labels[LabelPrevious] != 2 {
		t.Fatalf("metadata %+v %v", m, err)
	}
	if _, err := s.Metadata("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal("metadata of missing secret")
	}
}

func TestTrimKeepsLabelled(t *testing.T) {
	s, _ := newStore(t)
	s.MaxVersions = 3
	for i := range 10 {
		_, _ = s.Put("a", []byte{byte(i)}, -1)
	}
	m, _ := s.Metadata("a")
	var nums []int
	for _, v := range m.Versions {
		nums = append(nums, v.Version)
	}
	if !slices.Equal(nums, []int{8, 9, 10}) {
		t.Fatalf("kept versions %v", nums)
	}
}

func TestCheckAndSet(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.Put("a", []byte("1"), 0); err != nil {
		t.Fatalf("create-only on new secret: %v", err)
	}
	if _, err := s.Put("a", []byte("x"), 0); !errors.Is(err, ErrCASMismatch) {
		t.Fatal("create-only on existing secret")
	}
	if _, err := s.Put("a", []byte("x"), 5); !errors.Is(err, ErrCASMismatch) {
		t.Fatal("wrong version accepted")
	}
	if v, err := s.Put("a", []byte("2"), 1); err != nil || v != 2 {
		t.Fatalf("correct cas: %d %v", v, err)
	}
	if _, err := s.Put("new", []byte("x"), 1); !errors.Is(err, ErrCASMismatch) {
		t.Fatal("cas > 0 on missing secret")
	}
}

func TestConcurrentWritersLoseNothing(t *testing.T) {
	s, _ := newStore(t)
	s.MaxVersions = 1000
	var wg sync.WaitGroup
	var mu sync.Mutex
	versions := map[int]bool{}
	var busy int
	for w := range 8 {
		wg.Go(func() {
			for i := range 10 {
				v, err := s.Put("hot", fmt.Appendf(nil, "%d-%d", w, i), -1)
				mu.Lock()
				if errors.Is(err, ErrBusy) {
					busy++
				} else if err != nil {
					t.Error(err)
				} else if versions[v] {
					t.Errorf("version %d handed out twice", v)
				} else {
					versions[v] = true
				}
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	m, _ := s.Metadata("hot")
	if m.Latest != len(versions) || len(m.Versions) != len(versions) {
		t.Fatalf("latest %d, stored %d, acknowledged %d (busy %d)", m.Latest, len(m.Versions), len(versions), busy)
	}
}

func TestSoftDeleteUndeleteAndPurge(t *testing.T) {
	s, raw := newStore(t)
	now := time.Now()
	s.now = func() time.Time { return now }
	_, _ = s.Put("a", []byte("1"), -1)

	if err := s.Undelete("a"); !errors.Is(err, ErrNotDeleted) {
		t.Fatal("undelete of live secret")
	}
	if err := s.Delete("a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("a"); !errors.Is(err, ErrNotFound) {
		t.Fatal("double delete")
	}
	if _, err := s.Get("a", 0, ""); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted secret readable")
	}
	if m, err := s.Metadata("a"); err != nil || m.DeletedAt == nil {
		t.Fatal("metadata should show deleted secret")
	}
	if err := s.Undelete("a"); err != nil {
		t.Fatal(err)
	}
	if sec, _ := s.Get("a", 0, ""); string(sec.Value) != "1" {
		t.Fatal("undelete lost data")
	}

	_ = s.Delete("a")
	now = now.Add(s.Recovery + time.Minute)
	if err := s.Undelete("a"); !errors.Is(err, ErrNotFound) {
		t.Fatal("undelete after recovery window")
	}
	if _, err := raw.Get("kv/a"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("expired secret not purged from storage")
	}

	// Writing to a soft-deleted secret revives it with a new version.
	_, _ = s.Put("b", []byte("1"), -1)
	_ = s.Delete("b")
	if v, err := s.Put("b", []byte("2"), 0); err != nil || v != 2 {
		t.Fatalf("revive: %d %v", v, err)
	}
	if err := s.Undelete("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatal("undelete missing")
	}
}

func TestDestroyAndList(t *testing.T) {
	s, raw := newStore(t)
	for _, p := range []string{"prod/a", "prod/b", "stage/a"} {
		_, _ = s.Put(p, []byte("x"), -1)
	}
	got, err := s.List("prod/")
	if err != nil || !slices.Equal(got, []string{"prod/a", "prod/b"}) {
		t.Fatalf("list: %v %v", got, err)
	}
	if err := s.Destroy("prod/a"); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Get("kv/prod/a"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("destroy left data behind")
	}
	if _, err := raw.Get("kv/prod/b"); err != nil {
		t.Fatal("destroy removed the wrong secret")
	}
}

func TestCorruptRecord(t *testing.T) {
	raw := storage.NewInmem()
	seal := barrier.NewSeal(raw)
	t.Cleanup(seal.Seal)
	shares, _ := seal.Init(3, 2, nil, "spiffe://sm/admin/root")
	_, _ = seal.Unseal(shares[0])
	_, _ = seal.Unseal(shares[1])
	_ = seal.Put("kv/bad", []byte("{not json"))
	if _, err := New(seal.Barrier).Get("bad", 0, ""); err == nil {
		t.Fatal("corrupt record accepted")
	}
	seal.Seal()
	if _, err := New(seal.Barrier).Get("x", 0, ""); !errors.Is(err, barrier.ErrSealed) {
		t.Fatalf("sealed: %v", err)
	}
}

func TestPendingAndPromote(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.Put("app/db", []byte("old"), -1); err != nil {
		t.Fatal(err)
	}
	p, err := s.PutPending("app/db", []byte("new"))
	if err != nil || p != 2 {
		t.Fatalf("pending: %d %v", p, err)
	}
	if cur, _ := s.Get("app/db", 0, ""); string(cur.Value) != "old" {
		t.Fatalf("pending must not change current, got %q", cur.Value)
	}
	if pend, _ := s.Get("app/db", 0, LabelPending); string(pend.Value) != "new" {
		t.Fatalf("pending label: %q", pend.Value)
	}
	if err := s.Promote("app/db", 7); !errors.Is(err, ErrCASMismatch) {
		t.Fatalf("promoting a non-pending version: %v", err)
	}
	for range 2 { // second promotion is a no-op
		if err := s.Promote("app/db", p); err != nil {
			t.Fatal(err)
		}
	}
	cur, _ := s.Get("app/db", 0, "")
	prev, _ := s.Get("app/db", 0, LabelPrevious)
	if string(cur.Value) != "new" || string(prev.Value) != "old" {
		t.Fatalf("after promote: current %q previous %q", cur.Value, prev.Value)
	}
	if _, err := s.Get("app/db", 0, LabelPending); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pending label should be gone: %v", err)
	}
	// First value of a new secret can arrive through rotation too.
	if v, err := s.PutPending("fresh", []byte("x")); err != nil || s.Promote("fresh", v) != nil {
		t.Fatalf("fresh secret: %v", err)
	}
	if got, _ := s.Get("fresh", 0, ""); string(got.Value) != "x" {
		t.Fatalf("fresh current %q", got.Value)
	}
}

func TestMustNotExistRefusesSoftDeleted(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.Put("a", []byte("old"), MustNotExist); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put("a", []byte("new"), MustNotExist); !errors.Is(err, ErrCASMismatch) {
		t.Fatalf("revived a soft-deleted secret: %v", err)
	}
}
