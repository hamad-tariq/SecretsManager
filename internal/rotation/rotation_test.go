package rotation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hamad-tariq/SecretsManager/internal/audit"
	"github.com/hamad-tariq/SecretsManager/internal/barrier"
	"github.com/hamad-tariq/SecretsManager/internal/kv"
	"github.com/hamad-tariq/SecretsManager/internal/pki"
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

// clock is a settable time source.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func newEngine(s *barrier.Seal, leader func() bool, clk *clock) *Engine {
	e := New(Config{Backend: s.Barrier, Sealed: s.Sealed, Leader: leader, Audit: audit.New(io.Discard, nil, audit.Head{}),
		Identity: "spiffe://sm/node/test", Log: discardLog()})
	e.now = clk.now
	return e
}

func always() bool { return true }

func discardLog() *slog.Logger { return slog.New(slog.DiscardHandler) }

// register adds a test plugin for the duration of the test.
func register(t *testing.T, name string, p Plugin) {
	plugins[name] = p
	t.Cleanup(func() { delete(plugins, name) })
}

// fake is a plugin whose steps are scripted.
type fake struct {
	random
	set, test func(ctx context.Context, v []byte) error
}

func (f fake) Validate(map[string]string) error { return nil }
func (f fake) Set(ctx context.Context, _ Target, v []byte) error {
	if f.set == nil {
		return nil
	}
	return f.set(ctx, v)
}
func (f fake) Test(ctx context.Context, _ Target, v []byte) error {
	if f.test == nil {
		return nil
	}
	return f.test(ctx, v)
}

func TestRandomRotationSchedule(t *testing.T) {
	s := newSeal(t)
	clk := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	e := newEngine(s, always, clk)
	store := kv.New(s.Barrier)

	if _, err := Configure(s.Barrier, "app/api-key", Settings{Interval: "24h", Plugin: "random", Params: map[string]string{"length": "20"}}, clk.now()); err != nil {
		t.Fatal(err)
	}
	e.Tick(context.Background()) // new configuration: due immediately
	first, err := store.Get("app/api-key", 0, "")
	if err != nil || len(first.Value) != 20 || !alnumRe.Match(first.Value) {
		t.Fatalf("first value %q %v", first.Value, err)
	}
	r, _ := Get(s.Barrier, "app/api-key")
	if r.Step != "" || r.Pending != 0 || !r.NextDue.Equal(clk.now().Add(24*time.Hour)) {
		t.Fatalf("after rotation: %+v", r)
	}

	clk.add(23 * time.Hour)
	e.Tick(context.Background())
	if cur, _ := store.Get("app/api-key", 0, ""); cur.Version != first.Version {
		t.Fatal("rotated before it was due")
	}
	clk.add(time.Hour)
	e.Tick(context.Background())
	cur, _ := store.Get("app/api-key", 0, "")
	prev, _ := store.Get("app/api-key", 0, kv.LabelPrevious)
	if cur.Version == first.Version || prev.Version != first.Version || string(cur.Value) == string(first.Value) {
		t.Fatalf("second rotation: current v%d previous v%d", cur.Version, prev.Version)
	}

	// Trigger rotates now; Remove stops rotation but keeps the secret.
	if _, err := Trigger(s.Barrier, "app/api-key", clk.now()); err != nil {
		t.Fatal(err)
	}
	e.Tick(context.Background())
	if now, _ := store.Get("app/api-key", 0, ""); now.Version != cur.Version+1 {
		t.Fatalf("trigger: version %d", now.Version)
	}
	if err := Remove(s.Barrier, "app/api-key"); err != nil {
		t.Fatal(err)
	}
	if _, err := Get(s.Barrier, "app/api-key"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after remove: %v", err)
	}
	if _, err := store.Get("app/api-key", 0, ""); err != nil {
		t.Fatalf("secret must survive remove: %v", err)
	}
	if _, err := Trigger(s.Barrier, "nope", clk.now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("trigger unknown: %v", err)
	}
}

func TestSettingsValidation(t *testing.T) {
	s := newSeal(t)
	bad := map[string]Settings{
		"short interval":  {Interval: "30s", Plugin: "random"},
		"bad interval":    {Interval: "soon", Plugin: "random"},
		"unknown plugin":  {Interval: "1h", Plugin: "ldap"},
		"bad length":      {Interval: "1h", Plugin: "random", Params: map[string]string{"length": "8"}},
		"unknown param":   {Interval: "1h", Plugin: "random", Params: map[string]string{"colour": "red"}},
		"bad format":      {Interval: "1h", Plugin: "random", Params: map[string]string{"format": "emoji"}},
		"three users":     {Interval: "1h", Plugin: "postgres", Params: map[string]string{"admin": "db/admin", "users": "a,b,c"}},
		"injection user":  {Interval: "1h", Plugin: "postgres", Params: map[string]string{"admin": "db/admin", "users": "a';DROP"}},
		"no admin":        {Interval: "1h", Plugin: "postgres", Params: map[string]string{"users": "a"}},
		"host on pg":      {Interval: "1h", Plugin: "postgres", Params: map[string]string{"admin": "db/admin", "users": "a", "host": "%"}},
		"bad mysql host":  {Interval: "1h", Plugin: "mysql", Params: map[string]string{"admin": "db/admin", "users": "a", "host": "x' OR"}},
		"plain http hook": {Interval: "1h", Plugin: "http", Params: map[string]string{"url": "http://x/rotate", "identity": "svc/x"}},
		"hook no ident":   {Interval: "1h", Plugin: "http", Params: map[string]string{"url": "https://x/rotate"}},
	}
	for name, st := range bad {
		if _, err := Configure(s.Barrier, "app/x", st, time.Now()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Configure(s.Barrier, "../x", Settings{Interval: "1h", Plugin: "random"}, time.Now()); err == nil {
		t.Error("bad path accepted")
	}
	good := []Settings{
		{Interval: "720h", Plugin: "random", Params: map[string]string{"format": "hex", "length": "64"}},
		{Interval: "720h", Plugin: "postgres", Params: map[string]string{"admin": "db/admin", "users": "app_a,app_b"}},
		{Interval: "720h", Plugin: "mysql", Params: map[string]string{"admin": "db/admin", "users": "app", "host": "10.0.%"}},
		{Interval: "720h", Plugin: "http", Params: map[string]string{"url": "https://billing:8443/rotate", "identity": "svc/billing"}},
	}
	for _, st := range good {
		if _, err := Configure(s.Barrier, "app/x", st, time.Now()); err != nil {
			t.Errorf("%s: %v", st.Plugin, err)
		}
	}
}

func TestFailuresBackOffAndNeverPromote(t *testing.T) {
	s := newSeal(t)
	clk := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	e := newEngine(s, always, clk)
	store := kv.New(s.Barrier)
	if _, err := store.Put("app/tok", []byte("original"), -1); err != nil {
		t.Fatal(err)
	}
	var sets, tests atomic.Int32
	failTests := int32(2)
	register(t, "fake", fake{
		set: func(context.Context, []byte) error { sets.Add(1); return nil },
		test: func(context.Context, []byte) error {
			if tests.Add(1) <= failTests {
				return errors.New("login refused")
			}
			return nil
		},
	})
	if _, err := Configure(s.Barrier, "app/tok", Settings{Interval: "1h", Plugin: "fake"}, clk.now()); err != nil {
		t.Fatal(err)
	}

	e.Tick(context.Background())
	r, _ := Get(s.Barrier, "app/tok")
	if r.Attempts != 1 || r.Step != StepSet || !strings.Contains(r.LastError, "login refused") || !r.NextAttempt.Equal(clk.now().Add(time.Minute)) {
		t.Fatalf("after first failure: %+v", r)
	}
	if cur, _ := store.Get("app/tok", 0, ""); string(cur.Value) != "original" {
		t.Fatal("pending was promoted despite a failed test")
	}

	e.Tick(context.Background()) // still backing off
	if tests.Load() != 1 {
		t.Fatal("retried before the backoff expired")
	}
	clk.add(time.Minute)
	e.Tick(context.Background())
	r, _ = Get(s.Barrier, "app/tok")
	if r.Attempts != 2 || !r.NextAttempt.Equal(clk.now().Add(2*time.Minute)) {
		t.Fatalf("backoff should double: %+v", r)
	}
	clk.add(2 * time.Minute)
	e.Tick(context.Background())
	r, _ = Get(s.Barrier, "app/tok")
	cur, _ := store.Get("app/tok", 0, "")
	if r.Step != "" || r.Attempts != 0 || r.LastError != "" || string(cur.Value) == "original" {
		t.Fatalf("should have completed: %+v current %q", r, cur.Value)
	}
	if sets.Load() != 3 || tests.Load() != 3 {
		t.Fatalf("a failed test must re-run set: sets %d tests %d", sets.Load(), tests.Load())
	}
	if m, _ := store.Metadata("app/tok"); m.Latest != 2 {
		t.Fatalf("retries must reuse the pending version, latest is %d", m.Latest)
	}

	// Backoff is capped.
	failTests = 1 << 30
	for range 20 {
		if _, err := Trigger(s.Barrier, "app/tok", clk.now()); err != nil {
			t.Fatal(err)
		}
		e.Tick(context.Background())
	}
	r, _ = Get(s.Barrier, "app/tok")
	if d := r.NextAttempt.Sub(clk.now()); d > maxBackoff {
		t.Fatalf("backoff %s exceeds cap", d)
	}
}

func TestNothingRunsOnFollowerOrSealed(t *testing.T) {
	s := newSeal(t)
	clk := &clock{t: time.Now()}
	if _, err := Configure(s.Barrier, "app/k", Settings{Interval: "1h", Plugin: "random"}, clk.now()); err != nil {
		t.Fatal(err)
	}
	newEngine(s, func() bool { return false }, clk).Tick(context.Background())
	if _, err := kv.New(s.Barrier).Get("app/k", 0, ""); !errors.Is(err, kv.ErrNotFound) {
		t.Fatal("a follower rotated")
	}
	s.Seal()
	newEngine(s, always, clk).Tick(context.Background()) // must not panic or error-spin
}

// Exit criterion: the leader dies mid-rotation; the next leader finishes it
// from the saved step, reusing the same pending value. Both engines share
// one store, as Raft replicas do.
func TestLeaderFailoverResumesRotation(t *testing.T) {
	s := newSeal(t)
	clk := &clock{t: time.Now()}
	var leader atomic.Value
	leader.Store("a")
	ctxA, killA := context.WithCancel(context.Background())
	defer killA()

	var mu sync.Mutex
	var setValues [][]byte
	creates := 0
	register(t, "fake", fake{
		set: func(ctx context.Context, v []byte) error {
			mu.Lock()
			setValues = append(setValues, v)
			first := len(setValues) == 1
			mu.Unlock()
			if first { // node a dies half way through applying the value
				killA()
				leader.Store("b")
				return ctx.Err()
			}
			return nil
		},
	})
	plugins["fake"] = countingCreate{plugins["fake"].(fake), &creates}

	if _, err := Configure(s.Barrier, "db/app", Settings{Interval: "1h", Plugin: "fake"}, clk.now()); err != nil {
		t.Fatal(err)
	}
	a := newEngine(s, func() bool { return leader.Load() == "a" }, clk)
	b := newEngine(s, func() bool { return leader.Load() == "b" }, clk)

	a.Tick(ctxA)
	r, _ := Get(s.Barrier, "db/app")
	if r.Step != StepSet || r.Attempts != 0 || r.Pending == 0 {
		t.Fatalf("a crash is not a failure; progress should stop at set: %+v", r)
	}
	a.Tick(context.Background()) // a is no longer leader: no-op
	b.Tick(context.Background())

	r, _ = Get(s.Barrier, "db/app")
	cur, err := kv.New(s.Barrier).Get("db/app", 0, "")
	if err != nil || r.Step != "" {
		t.Fatalf("b should have finished: %+v %v", r, err)
	}
	if creates != 1 || len(setValues) != 2 || string(setValues[0]) != string(setValues[1]) || string(cur.Value) != string(setValues[0]) {
		t.Fatalf("creates %d, sets %q, current %q", creates, setValues, cur.Value)
	}
}

type countingCreate struct {
	fake
	n *int
}

func (c countingCreate) Create(ctx context.Context, t Target) ([]byte, error) {
	*c.n++
	return c.fake.Create(ctx, t)
}

// fakeDB is a database with password logins, used through the real SQL
// plugin logic (user alternation, credential checks).
type fakeDB struct {
	mu sync.Mutex
	pw map[string]string
}

func (d *fakeDB) setPassword(_ context.Context, admin, user, _, pw string) error {
	if admin != "admin-dsn" {
		return errors.New("bad admin credentials")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pw[user] = pw
	return nil
}

func (d *fakeDB) login(_ context.Context, _, user, pw string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if p, ok := d.pw[user]; !ok || p != pw {
		return errors.New("password authentication failed")
	}
	return nil
}

// Exit criterion: clients reading continuously during rotations never hold
// a credential the database rejects. The contract being tested is dual
// validity: a credential keeps working until the rotation AFTER the one that
// replaced it, so clients that refresh at least once per interval never fail.
// The rotator models that by waiting, between rotations, until every reader
// has re-read since the last one.
func TestRotationUnderLoadHasNoAuthFailures(t *testing.T) {
	s := newSeal(t)
	clk := &clock{t: time.Now()}
	db := &fakeDB{pw: map[string]string{}}
	register(t, "fakesql", sqlPlugin{dialect: db})
	store := kv.New(s.Barrier)
	if _, err := store.Put("db/admin", []byte("admin-dsn"), -1); err != nil {
		t.Fatal(err)
	}
	if _, err := Configure(s.Barrier, "db/orders", Settings{Interval: "1h", Plugin: "fakesql",
		Params: map[string]string{"admin": "db/admin", "users": "app_a,app_b"}}, clk.now()); err != nil {
		t.Fatal(err)
	}
	e := newEngine(s, always, clk)
	e.Tick(context.Background()) // initial credential

	const rotations, readers = 30, 8
	var reads, failures, gen atomic.Int64
	var seen [readers]atomic.Int64 // generation each reader last read in
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := range readers {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				g := gen.Load()
				sec, err := store.Get("db/orders", 0, "")
				var c credential
				if err == nil {
					err = json.Unmarshal(sec.Value, &c)
				}
				if err == nil {
					err = db.login(context.Background(), "", c.Username, c.Password)
				}
				reads.Add(1)
				if err != nil {
					failures.Add(1)
				}
				seen[i].Store(g)
			}
		})
	}
	users := map[string]bool{}
	for range rotations {
		if _, err := Trigger(s.Barrier, "db/orders", clk.now()); err != nil {
			t.Fatal(err)
		}
		e.Tick(context.Background())
		sec, _ := store.Get("db/orders", 0, "")
		var c credential
		_ = json.Unmarshal(sec.Value, &c)
		users[c.Username] = true
		g := gen.Add(1)
		for i := range seen { // every client refreshes before the next rotation
			for seen[i].Load() < g {
				time.Sleep(50 * time.Microsecond)
			}
		}
	}
	close(stop)
	wg.Wait()

	m, _ := store.Metadata("db/orders")
	if m.Latest != rotations+1 || len(users) != 2 {
		t.Fatalf("latest %d, users used %v", m.Latest, users)
	}
	if failures.Load() != 0 || reads.Load() < rotations {
		t.Fatalf("%d of %d reads got a rejected credential", failures.Load(), reads.Load())
	}
	t.Logf("%d rotations, %d reads, 0 auth failures", rotations, reads.Load())
}

func TestSQLPluginRejectsForeignValues(t *testing.T) {
	p := sqlPlugin{dialect: &fakeDB{pw: map[string]string{}}}
	tgt := Target{Params: map[string]string{"admin": "db/admin", "users": "app_a,app_b"},
		Lookup: func(string) ([]byte, error) { return []byte("admin-dsn"), nil }}
	for _, v := range []string{
		`{"username":"app_a","password":"x' OR '1"}`, // not what Create makes
		`{"username":"root","password":"abc"}`,       // not a configured user
		`not json`,
	} {
		if err := p.Set(context.Background(), tgt, []byte(v)); err == nil {
			t.Errorf("accepted %s", v)
		}
	}
	// Alternation: a (or nothing) → a/b → the other.
	for cur, want := range map[string]string{"": "app_a", `{"username":"app_a"}`: "app_b", `{"username":"app_b"}`: "app_a", `{"username":"gone"}`: "app_a"} {
		tgt.Current = []byte(cur)
		v, _ := p.Create(context.Background(), tgt)
		var c credential
		_ = json.Unmarshal(v, &c)
		if c.Username != want || len(c.Password) != 32 {
			t.Errorf("current %q: next %+v", cur, c)
		}
	}
}

func TestAlnum(t *testing.T) {
	seen := map[byte]bool{}
	for range 200 {
		v := Alnum(50)
		if len(v) != 50 || !alnumRe.Match(v) {
			t.Fatalf("alnum %q", v)
		}
		for _, c := range v {
			seen[c] = true
		}
	}
	if len(seen) != 62 {
		t.Fatalf("only %d distinct characters", len(seen))
	}
}

func TestHookPlugin(t *testing.T) {
	root, err := pki.NewRoot("root", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root.Cert)
	certFor := func(id pki.Identity, hosts ...string) tls.Certificate {
		key, _ := pki.NewKey()
		c, err := root.Issue(id, key.Public(), time.Hour, hosts...)
		if err != nil {
			t.Fatal(err)
		}
		return pki.TLSCertificate(c, key)
	}
	nodeTLS := pki.ClientTLS(certFor(pki.Identity{Kind: pki.Node, Name: "node-1"}), roots)

	var got []map[string]string
	var mu sync.Mutex
	received := func() []map[string]string {
		mu.Lock()
		defer mu.Unlock()
		return append([]map[string]string(nil), got...)
	}
	var status atomic.Int32
	status.Store(http.StatusOK)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, err := pki.PeerIdentity(r.TLS); err != nil || id.Kind != pki.Node {
			http.Error(w, "not a node", http.StatusForbidden)
			return
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		got = append(got, body)
		mu.Unlock()
		w.Header().Set("Location", "http://127.0.0.1:1/cleartext") // only read on a 3xx
		w.WriteHeader(int(status.Load()))
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the rejected handshakes below are expected
	srv.TLS = pki.ServerTLS(certFor(pki.Identity{Kind: pki.Service, Name: "billing"}), roots)
	srv.StartTLS()
	defer srv.Close()

	tgt := Target{Path: "app/billing-key", TLS: nodeTLS, Params: map[string]string{"url": srv.URL + "/rotate", "identity": "svc/billing"}}
	h := hook{}
	if err := h.Validate(tgt.Params); err != nil {
		t.Fatal(err)
	}
	v, _ := h.Create(context.Background(), tgt)
	if err := h.Set(context.Background(), tgt, v); err != nil {
		t.Fatal(err)
	}
	if err := h.Test(context.Background(), tgt, v); err != nil {
		t.Fatal(err)
	}
	if got := received(); len(got) != 2 || got[0]["step"] != "set" || got[1]["step"] != "test" || got[0]["value"] != string(v) || got[0]["path"] != "app/billing-key" {
		t.Fatalf("hook received %v", got)
	}

	// Wrong identity: the value is never sent.
	wrong := tgt
	wrong.Params = map[string]string{"url": srv.URL, "identity": "svc/payments"}
	if err := h.Set(context.Background(), wrong, v); err == nil || !strings.Contains(err.Error(), "svc/billing") {
		t.Fatalf("wrong identity: %v", err)
	}
	// A certificate from another CA is rejected too.
	other, _ := pki.NewRoot("other", time.Hour)
	otherPool := x509.NewCertPool()
	otherPool.AddCert(other.Cert)
	foreign := tgt
	foreign.TLS = pki.ClientTLS(nodeTLS.Certificates[0], otherPool)
	if err := h.Set(context.Background(), foreign, v); err == nil {
		t.Fatal("hook trusted a server outside our CA")
	}
	if len(received()) != 2 {
		t.Fatal("value sent to an unverified server")
	}
	// A revoked hook certificate (by identity or serial) gets nothing.
	revoked := tgt
	revoked.Revoked = func(c *x509.Certificate) (bool, error) {
		id, _ := pki.IdentityFromCert(c)
		return id.Name == "billing", nil
	}
	if err := h.Set(context.Background(), revoked, v); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked hook: %v", err)
	}
	if len(received()) != 2 {
		t.Fatal("value sent to a revoked service")
	}
	status.Store(http.StatusInternalServerError)
	if err := h.Set(context.Background(), tgt, v); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("non-2xx must fail: %v", err)
	}
	// Redirects aren't followed (the Location is plain http).
	status.Store(http.StatusTemporaryRedirect)
	if err := h.Set(context.Background(), tgt, v); err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("redirect must fail, not be followed: %v", err)
	}
}
