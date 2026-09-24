package lease

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hamad-tariq/SecretsManager/internal/audit"
	"github.com/hamad-tariq/SecretsManager/internal/barrier"
	"github.com/hamad-tariq/SecretsManager/internal/kv"
	"github.com/hamad-tariq/SecretsManager/internal/storage"
)

func newSeal(t *testing.T) *barrier.Seal {
	t.Helper()
	s := barrier.NewSeal(storage.NewInmem())
	t.Cleanup(s.Seal)
	shares, err := s.Init(2, 2, nil, "spiffe://sm/admin/root")
	if err != nil {
		t.Fatal(err)
	}
	for _, sh := range shares {
		if _, err := s.Unseal(sh); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// fakeDB is a database with users and open sessions, and switchable failures.
type fakeDB struct {
	mu                   sync.Mutex
	users                map[string]User
	sessions             map[string]int
	failCreate, failDrop bool
}

func newFakeDB(t *testing.T) *fakeDB {
	db := &fakeDB{users: map[string]User{}, sessions: map[string]int{}}
	Databases["fake"] = db
	t.Cleanup(func() { delete(Databases, "fake") })
	return db
}

func (d *fakeDB) Create(_ context.Context, admin string, u User) error {
	if admin != "admin-dsn" {
		return errors.New("bad admin")
	}
	if err := check(u); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failCreate { // e.g. a grant failed: the transaction rolls back
		return errors.New("permission denied for schema public")
	}
	d.users[u.Name] = u
	return nil
}

func (d *fakeDB) Drop(_ context.Context, _ string, u User) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failDrop {
		return errors.New("connection refused")
	}
	delete(d.users, u.Name)
	delete(d.sessions, u.Name)
	return nil
}

func (d *fakeDB) connect(user, pw string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if u, ok := d.users[user]; ok && u.Password == pw {
		d.sessions[user]++
		return true
	}
	return false
}

func (d *fakeDB) count() (users, sessions int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, n := range d.sessions {
		sessions += n
	}
	return len(d.users), sessions
}

func setup(t *testing.T, leader func() bool) (*Manager, *fakeDB, *clock) {
	t.Helper()
	s := newSeal(t)
	db := newFakeDB(t)
	clk := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	m := New(Config{Backend: s.Barrier, Sealed: s.Sealed, Leader: leader, Audit: audit.New(io.Discard, nil, audit.Head{}),
		Identity: "spiffe://sm/node/test", Log: slog.New(slog.DiscardHandler)})
	m.now = clk.now
	if _, err := kv.New(s.Barrier).Put("db/admin", []byte("admin-dsn"), -1); err != nil {
		t.Fatal(err)
	}
	if err := m.PutRole("orders-rw", Role{Plugin: "fake", Admin: "db/admin", Grants: []string{"GRANT ALL ON orders TO {{name}}"},
		DefaultTTL: "1h", MaxTTL: "24h"}); err != nil {
		t.Fatal(err)
	}
	return m, db, clk
}

func always() bool { return true }

const svc = "spiffe://sm/svc/orders-api"

func TestIssueRenewRevoke(t *testing.T) {
	m, db, clk := setup(t, always)
	ctx := context.Background()

	c, err := m.Issue(ctx, "orders-rw", svc, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c.LeaseID, "db/orders-rw/") || !strings.HasPrefix(c.Username, "v_orders_rw_") || len(c.Password) != 32 {
		t.Fatalf("credentials %+v", c)
	}
	if !c.Expires.Equal(clk.now().Add(time.Hour)) || !c.MaxExpires.Equal(clk.now().Add(24*time.Hour)) {
		t.Fatalf("ttl: expires %v max %v", c.Expires, c.MaxExpires)
	}
	if !db.connect(c.Username, c.Password) || !db.users[c.Username].ValidUntil.Equal(c.MaxExpires) {
		t.Fatal("user not created as issued")
	}
	if got := db.users[c.Username].Grants; len(got) != 1 {
		t.Fatalf("grants %v", got)
	}

	// Requested TTLs are clamped to [MinTTL, max].
	if c2, _ := m.Issue(ctx, "orders-rw", svc, 100*time.Hour); !c2.Expires.Equal(clk.now().Add(24 * time.Hour)) {
		t.Fatalf("long ttl not capped: %v", c2.Expires)
	}
	if c3, _ := m.Issue(ctx, "orders-rw", svc, time.Second); !c3.Expires.Equal(clk.now().Add(MinTTL)) {
		t.Fatalf("short ttl not raised: %v", c3.Expires)
	}

	// Renew: owner only, by the original TTL, never past max.
	if _, err := m.Renew(c.LeaseID, "spiffe://sm/svc/billing", 0); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("renew by another identity: %v", err)
	}
	clk.add(50 * time.Minute)
	l, err := m.Renew(c.LeaseID, svc, 0)
	if err != nil || !l.Expires.Equal(clk.now().Add(time.Hour)) {
		t.Fatalf("renew: %v %v", l, err)
	}
	for range 23 { // a client renewing every 55 minutes
		clk.add(55 * time.Minute)
		if _, err := m.Renew(c.LeaseID, svc, 0); err != nil {
			t.Fatal(err)
		}
	}
	if l, err = m.Renew(c.LeaseID, svc, 5*time.Hour); err != nil || !l.Expires.Equal(c.MaxExpires) {
		t.Fatalf("renew past max: %v %v", l, err)
	}
	clk.add(3 * time.Hour)
	if _, err := m.Renew(c.LeaseID, svc, 0); !errors.Is(err, ErrExpired) {
		t.Fatalf("renew after expiry: %v", err)
	}

	// Revoke: owner only (or privileged, identity ""); the user and its sessions go.
	c4, _ := m.Issue(ctx, "orders-rw", svc, 0)
	db.connect(c4.Username, c4.Password)
	if err := m.Revoke(ctx, c4.LeaseID, "spiffe://sm/svc/billing"); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("revoke by another identity: %v", err)
	}
	if err := m.Revoke(ctx, c4.LeaseID, svc); err != nil {
		t.Fatal(err)
	}
	if db.connect(c4.Username, c4.Password) || db.sessions[c4.Username] != 0 {
		t.Fatal("revoked user still works")
	}
	if err := m.Revoke(ctx, c4.LeaseID, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second revoke: %v", err)
	}
	if _, err := m.Issue(ctx, "nope", svc, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown role: %v", err)
	}
}

func TestRevokePrefixEndsEverySession(t *testing.T) {
	m, db, _ := setup(t, always)
	ctx := context.Background()
	if err := m.PutRole("billing-ro", Role{Plugin: "fake", Admin: "db/admin"}); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		c, _ := m.Issue(ctx, "orders-rw", svc, 0)
		db.connect(c.Username, c.Password)
		db.connect(c.Username, c.Password)
	}
	other, _ := m.Issue(ctx, "billing-ro", "spiffe://sm/svc/billing", 0)
	db.connect(other.Username, other.Password)

	n, err := m.RevokePrefix(ctx, "db/orders-rw/")
	if err != nil || n != 5 {
		t.Fatalf("revoked %d: %v", n, err)
	}
	if users, sessions := db.count(); users != 1 || sessions != 1 {
		t.Fatalf("left: %d users, %d sessions; want only billing's", users, sessions)
	}
	if left, _ := m.List(""); len(left) != 1 || left[0].ID != other.LeaseID {
		t.Fatalf("leases left: %+v", left)
	}
}

func TestExpiryAndFailures(t *testing.T) {
	leader := true
	m, db, clk := setup(t, func() bool { return leader })
	ctx := context.Background()

	// Creation fails (bad grant): no user and no lease remain.
	db.failCreate = true
	if _, err := m.Issue(ctx, "orders-rw", svc, 0); !errors.Is(err, ErrDatabase) {
		t.Fatalf("create failure: %v", err)
	}
	db.failCreate = false
	if users, _ := db.count(); users != 0 {
		t.Fatal("user left after failed create")
	}
	if l, _ := m.List(""); len(l) != 0 {
		t.Fatalf("lease left after failed create: %+v", l)
	}

	c, _ := m.Issue(ctx, "orders-rw", svc, 0)
	clk.add(59 * time.Minute)
	m.Tick(ctx)
	if users, _ := db.count(); users != 1 {
		t.Fatal("dropped before expiry")
	}
	clk.add(time.Minute)
	leader = false
	m.Tick(ctx)
	if users, _ := db.count(); users != 1 {
		t.Fatal("a follower revoked")
	}
	leader = true

	// Database down: the lease stays, marked, and the next tick retries.
	db.failDrop = true
	m.Tick(ctx)
	l, _ := m.List("")
	if len(l) != 1 || !strings.Contains(l[0].LastError, "connection refused") {
		t.Fatalf("failed drop: %+v", l)
	}
	if err := m.Revoke(ctx, c.LeaseID, svc); !errors.Is(err, ErrDatabase) {
		t.Fatalf("revoke while down: %v", err)
	}
	db.failDrop = false
	m.Tick(ctx)
	if users, _ := db.count(); users != 0 {
		t.Fatal("expired user not dropped")
	}
	if l, _ := m.List(""); len(l) != 0 {
		t.Fatal("expired lease not removed")
	}

	// A lease whose user was never created (crash between the two writes)
	// expires cleanly too.
	id := "db/orders-rw/crashed"
	if err := m.save(&Lease{ID: id, Username: "v_orders_rw_dead", Plugin: "fake", Admin: "db/admin", Expires: clk.now()}, nil); err != nil {
		t.Fatal(err)
	}
	m.Tick(ctx)
	if l, _ := m.List(""); len(l) != 0 {
		t.Fatal("orphan lease not cleaned")
	}
}

func TestRoleValidation(t *testing.T) {
	m, _, _ := setup(t, always)
	bad := map[string]Role{
		"plugin":      {Plugin: "oracle", Admin: "db/admin"},
		"admin path":  {Plugin: "postgres", Admin: "../x"},
		"host on pg":  {Plugin: "postgres", Admin: "db/admin", Host: "%"},
		"bad host":    {Plugin: "mysql", Admin: "db/admin", Host: "x' OR 1"},
		"empty grant": {Plugin: "postgres", Admin: "db/admin", Grants: []string{" "}},
		"ttl order":   {Plugin: "postgres", Admin: "db/admin", DefaultTTL: "48h", MaxTTL: "24h"},
		"ttl ceiling": {Plugin: "postgres", Admin: "db/admin", MaxTTL: "1000h"},
		"ttl floor":   {Plugin: "postgres", Admin: "db/admin", DefaultTTL: "10s"},
	}
	for name, r := range bad {
		if err := m.PutRole("x", r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := m.PutRole("Bad_Name", Role{Plugin: "postgres", Admin: "db/admin"}); err == nil {
		t.Error("bad role name accepted")
	}
	if err := m.PutRole("x", Role{Plugin: "mysql", Admin: "db/admin", Host: "10.0.%"}); err != nil {
		t.Fatal(err)
	}
	if err := m.PutRole("x", Role{Plugin: "postgres", Admin: "db/admin"}); err != nil { // overwrite
		t.Fatal(err)
	}
	if r, _ := m.Role("x"); r.Plugin != "postgres" {
		t.Fatalf("role not overwritten: %+v", r)
	}
	if err := m.DeleteRole("x"); err != nil || !errors.Is(m.DeleteRole("x"), ErrNotFound) {
		t.Fatalf("delete role: %v", err)
	}
}

// Exit criterion: no orphaned database users after 24 h of churn. Simulated
// minute by minute: services request, renew, revoke and abandon credentials
// while the database fails now and then. After every step, every database
// user has a lease; at the end, everything has expired and been dropped.
func TestChurnLeavesNoOrphans(t *testing.T) {
	m, db, clk := setup(t, always)
	ctx := context.Background()
	rng := rand.New(rand.NewPCG(1, 2))
	var live []Credentials
	issued := 0
	for minute := range 24 * 60 {
		db.failCreate, db.failDrop = rng.IntN(10) == 0, rng.IntN(10) == 0
		switch op := rng.IntN(10); {
		case op < 4:
			if c, err := m.Issue(ctx, "orders-rw", svc, time.Duration(1+rng.IntN(120))*time.Minute); err == nil {
				live = append(live, c)
				issued++
			}
		case op < 7 && len(live) > 0:
			_, _ = m.Renew(live[rng.IntN(len(live))].LeaseID, svc, 0)
		case op < 8 && len(live) > 0:
			i := rng.IntN(len(live))
			if m.Revoke(ctx, live[i].LeaseID, svc) == nil {
				live = append(live[:i], live[i+1:]...)
			}
		}
		clk.add(time.Minute)
		m.Tick(ctx)

		leases, _ := m.List("")
		owned := map[string]bool{}
		for _, l := range leases {
			owned[l.Username] = true
		}
		db.mu.Lock()
		for u := range db.users {
			if !owned[u] {
				db.mu.Unlock()
				t.Fatalf("minute %d: database user %s has no lease", minute, u)
			}
		}
		db.mu.Unlock()
	}
	db.failCreate, db.failDrop = false, false
	clk.add(25 * time.Hour) // past every max TTL
	m.Tick(ctx)
	users, sessions := db.count()
	leases, _ := m.List("")
	if users != 0 || sessions != 0 || len(leases) != 0 {
		t.Fatalf("after churn: %d users, %d sessions, %d leases", users, sessions, len(leases))
	}
	if issued < 300 {
		t.Fatalf("only %d credentials issued; churn too light", issued)
	}
	t.Logf("24 h simulated: %d credentials issued, 0 orphans", issued)
}

func TestMissingAdminCredentialsLeaveNothing(t *testing.T) {
	m, db, _ := setup(t, always)
	if err := m.PutRole("no-admin", Role{Plugin: "fake", Admin: "db/missing"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Issue(context.Background(), "no-admin", svc, 0); !errors.Is(err, ErrDatabase) {
		t.Fatalf("issue: %v", err)
	}
	if l, _ := m.List(""); len(l) != 0 {
		t.Fatalf("lease left: %+v", l)
	}
	if users, _ := db.count(); users != 0 {
		t.Fatal("user created")
	}
}

// Prefixes match whole segments: db/orders is not a prefix of db/orders-rw,
// so permission on one can't list or revoke the other.
func TestPrefixMatchesWholeSegments(t *testing.T) {
	m, _, _ := setup(t, always)
	ctx := context.Background()
	if err := m.PutRole("orders", Role{Plugin: "fake", Admin: "db/admin"}); err != nil {
		t.Fatal(err)
	}
	mine, _ := m.Issue(ctx, "orders", svc, 0)
	theirs, _ := m.Issue(ctx, "orders-rw", svc, 0)
	if l, _ := m.List("db/orders"); len(l) != 1 || l[0].ID != mine.LeaseID {
		t.Fatalf("db/orders listed %+v", l)
	}
	if l, _ := m.List(theirs.LeaseID); len(l) != 1 || l[0].ID != theirs.LeaseID {
		t.Fatalf("full id listed %+v", l)
	}
	if l, _ := m.List(theirs.LeaseID[:len(theirs.LeaseID)-2]); len(l) != 0 {
		t.Fatalf("partial id listed %+v", l)
	}
	if n, err := m.RevokePrefix(ctx, "db/orders"); err != nil || n != 1 {
		t.Fatalf("revoked %d: %v", n, err)
	}
	if l, _ := m.List(""); len(l) != 1 || l[0].ID != theirs.LeaseID {
		t.Fatalf("left %+v", l)
	}
}
