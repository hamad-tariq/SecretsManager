// Package lease issues short-lived database users ("dynamic credentials").
//
// An operator configures a role (sys/db-roles/<name>): which database, the
// kv path of its admin connection string, the grants a new user gets, and
// TTLs. Each request creates a fresh user and a lease (sys/leases/db/<role>/<id>)
// that expires after the TTL unless renewed, and never later than the max TTL.
// When a lease is revoked or expires, the user's sessions are killed and the
// user is dropped.
//
// No orphans by construction: the lease is written before the user is
// created, and deleted only after the user is dropped. A crash in between
// leaves a lease whose expiry drops a user that may not exist (a no-op).
package lease

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/hamad-tariq/SecretsManager/internal/audit"
	"github.com/hamad-tariq/SecretsManager/internal/kv"
	"github.com/hamad-tariq/SecretsManager/internal/policy"
	"github.com/hamad-tariq/SecretsManager/internal/rotation"
	"github.com/hamad-tariq/SecretsManager/internal/storage"
)

const (
	rolePrefix  = "sys/db-roles/"
	leasePrefix = "sys/leases/"

	DefaultTTL    = time.Hour
	DefaultMaxTTL = 24 * time.Hour
	MinTTL        = time.Minute
	CeilingTTL    = 30 * 24 * time.Hour
)

var (
	ErrNotFound = errors.New("lease: not found")
	ErrNotOwner = errors.New("lease: belongs to another identity")
	ErrExpired  = errors.New("lease: expired")
	ErrDatabase = errors.New("lease: database error")
)

// Role is what an operator configures for one kind of credential.
type Role struct {
	Plugin string `json:"plugin"` // postgres | mysql
	Admin  string `json:"admin"`  // kv path of the admin connection string
	// Grants run right after the user is created (in the same transaction on
	// PostgreSQL). {{name}} becomes the quoted user: "v_x" or 'v_x'@'host'.
	Grants     []string `json:"grants"`
	Host       string   `json:"host,omitempty"`        // MySQL account host, default "%"
	DefaultTTL string   `json:"default_ttl,omitempty"` // default 1h
	MaxTTL     string   `json:"max_ttl,omitempty"`     // default 24h
}

var (
	hostRe = regexp.MustCompile(`^[A-Za-z0-9_.%:-]{1,255}$`)
	nameRe = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)
)

func (r Role) ttls() (def, maxTTL time.Duration, err error) {
	def, maxTTL = DefaultTTL, DefaultMaxTTL
	if r.DefaultTTL != "" {
		if def, err = time.ParseDuration(r.DefaultTTL); err != nil {
			return 0, 0, errors.New("lease: bad default_ttl")
		}
	}
	if r.MaxTTL != "" {
		if maxTTL, err = time.ParseDuration(r.MaxTTL); err != nil {
			return 0, 0, errors.New("lease: bad max_ttl")
		}
	}
	if def < MinTTL || def > maxTTL || maxTTL > CeilingTTL {
		return 0, 0, fmt.Errorf("lease: need %s <= default_ttl <= max_ttl <= %s", MinTTL, CeilingTTL)
	}
	return def, maxTTL, nil
}

// Validate checks a role's settings.
func (r Role) Validate() error {
	if _, ok := Databases[r.Plugin]; !ok {
		return fmt.Errorf("lease: unknown plugin %q", r.Plugin)
	}
	if policy.ValidPath(r.Admin) != nil {
		return errors.New("lease: admin must be the kv path of the admin connection string")
	}
	if r.Host != "" && (r.Plugin != "mysql" || !hostRe.MatchString(r.Host)) {
		return errors.New("lease: host is a MySQL account host like % or 10.0.%")
	}
	for _, g := range r.Grants {
		if strings.TrimSpace(g) == "" {
			return errors.New("lease: empty grant statement")
		}
	}
	_, _, err := r.ttls()
	return err
}

// Lease records one issued user. The password is never stored.
type Lease struct {
	ID         string        `json:"lease_id"`
	Role       string        `json:"role"`
	Username   string        `json:"username"`
	Identity   string        `json:"identity"` // who requested it; only they may renew it
	Plugin     string        `json:"plugin"`   // role settings at issue time, so revocation
	Admin      string        `json:"admin"`    // works even if the role changes or is deleted
	Host       string        `json:"host,omitempty"`
	TTL        time.Duration `json:"ttl"`
	Issued     time.Time     `json:"issued"`
	Expires    time.Time     `json:"expires"`
	MaxExpires time.Time     `json:"max_expires"`
	LastError  string        `json:"last_error,omitempty"` // last failed revocation
}

// Credentials go to the requester once.
type Credentials struct {
	LeaseID    string    `json:"lease_id"`
	Username   string    `json:"username"`
	Password   string    `json:"password"`
	Expires    time.Time `json:"expires"`
	MaxExpires time.Time `json:"max_expires"`
}

type Config struct {
	Backend  kv.Backend // the barrier
	Sealed   func() bool
	Leader   func() bool
	Audit    *audit.Logger
	Identity string // this node, for audit entries of expirations
	Tick     time.Duration
	Log      *slog.Logger
}

type Manager struct {
	cfg Config
	kv  *kv.Store
	now func() time.Time
}

func New(cfg Config) *Manager {
	if cfg.Tick <= 0 {
		cfg.Tick = 10 * time.Second
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Manager{cfg: cfg, kv: kv.New(cfg.Backend), now: time.Now}
}

// ---- roles ----

func (m *Manager) PutRole(name string, r Role) error {
	if !nameRe.MatchString(name) {
		return errors.New("lease: role names are 1-63 of [a-z0-9-]")
	}
	if err := r.Validate(); err != nil {
		return err
	}
	v, _ := json.Marshal(r)
	return m.cfg.Backend.PutIf(rolePrefix+name, v, m.token(rolePrefix+name))
}

// token returns the current check-and-set token (nil if absent), so PutRole
// overwrites whatever is there without a separate unconditional Put.
func (m *Manager) token(key string) []byte {
	_, tok, _ := m.cfg.Backend.GetToken(key)
	return tok
}

func (m *Manager) Role(name string) (Role, error) {
	var r Role
	raw, _, err := m.cfg.Backend.GetToken(rolePrefix + name)
	if errors.Is(err, storage.ErrNotFound) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	return r, json.Unmarshal(raw, &r)
}

// DeleteRole stops new credentials; existing leases run their course.
func (m *Manager) DeleteRole(name string) error {
	if _, err := m.Role(name); err != nil {
		return err
	}
	return m.cfg.Backend.Delete(rolePrefix + name)
}

// ---- leases ----

func (m *Manager) load(id string) (*Lease, []byte, error) {
	raw, tok, err := m.cfg.Backend.GetToken(leasePrefix + id)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	var l Lease
	if err := json.Unmarshal(raw, &l); err != nil {
		return nil, nil, fmt.Errorf("lease: corrupt %s: %w", id, err)
	}
	return &l, tok, nil
}

func (m *Manager) save(l *Lease, tok []byte) error {
	v, _ := json.Marshal(l)
	return m.cfg.Backend.PutIf(leasePrefix+l.ID, v, tok)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Issue creates a database user for role on behalf of identity. ttl 0 means
// the role's default; longer requests are cut to the max TTL.
func (m *Manager) Issue(ctx context.Context, roleName, identity string, ttl time.Duration) (Credentials, error) {
	role, err := m.Role(roleName)
	if err != nil {
		return Credentials{}, err
	}
	def, maxTTL, err := role.ttls()
	if err != nil {
		return Credentials{}, err
	}
	if ttl <= 0 {
		ttl = def
	}
	ttl = min(max(ttl, MinTTL), maxTTL)
	now := m.now().UTC()
	// v_<role>_<random>: ≤ 25 characters (MySQL allows 32), and recognisable
	// in the database as ours.
	user := "v_" + strings.ReplaceAll(roleName[:min(len(roleName), 10)], "-", "_") + "_" + randomHex(6)
	l := &Lease{ID: "db/" + roleName + "/" + randomHex(8), Role: roleName, Username: user, Identity: identity,
		Plugin: role.Plugin, Admin: role.Admin, Host: role.Host, TTL: ttl,
		Issued: now, Expires: now.Add(ttl), MaxExpires: now.Add(maxTTL)}
	if err := m.save(l, nil); err != nil { // lease first: see package comment
		return Credentials{}, err
	}
	admin, err := m.kv.Get(role.Admin, 0, "")
	if err != nil { // nothing was created: just remove the lease
		_ = m.cfg.Backend.Delete(leasePrefix + l.ID)
		m.cfg.Log.Error("lease: admin credentials", "role", roleName, "path", role.Admin, "err", err)
		return Credentials{}, fmt.Errorf("%w: admin credentials for role %s are unavailable", ErrDatabase, roleName)
	}
	password := string(rotation.Alnum(32))
	err = Databases[role.Plugin].Create(ctx, string(admin.Value), User{Name: user, Password: password,
		Host: role.Host, ValidUntil: l.MaxExpires, Grants: role.Grants})
	err = rotation.Scrub(err, string(admin.Value))
	if err != nil {
		// Undo: drop whatever may exist and remove the lease (or leave it to
		// expiry if the drop fails too).
		_ = m.revoke(context.WithoutCancel(ctx), l)
		m.cfg.Log.Error("lease: creating database user", "role", roleName, "err", err)
		return Credentials{}, fmt.Errorf("%w: creating the user failed", ErrDatabase)
	}
	return Credentials{LeaseID: l.ID, Username: user, Password: password, Expires: l.Expires, MaxExpires: l.MaxExpires}, nil
}

// Renew extends a lease by increment (0 = its original TTL), never past its
// max TTL. Only the identity that requested it may renew it.
func (m *Manager) Renew(id, identity string, increment time.Duration) (*Lease, error) {
	for range 5 {
		l, tok, err := m.load(id)
		if err != nil {
			return nil, err
		}
		if l.Identity != identity {
			return nil, ErrNotOwner
		}
		now := m.now().UTC()
		if !now.Before(l.Expires) {
			return nil, ErrExpired
		}
		if increment <= 0 {
			increment = l.TTL
		}
		l.Expires = minTime(now.Add(max(increment, MinTTL)), l.MaxExpires)
		if err := m.save(l, tok); !errors.Is(err, storage.ErrConflict) {
			return l, err
		}
	}
	return nil, kv.ErrBusy
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// Revoke drops a lease's user now. identity "" skips the owner check (for
// callers already authorised by policy).
func (m *Manager) Revoke(ctx context.Context, id, identity string) error {
	l, _, err := m.load(id)
	if err != nil {
		return err
	}
	if identity != "" && l.Identity != identity {
		return ErrNotOwner
	}
	return m.revoke(ctx, l)
}

// RevokePrefix revokes every lease whose ID starts with prefix
// (e.g. "db/orders-rw/"). It returns how many were revoked.
func (m *Manager) RevokePrefix(ctx context.Context, prefix string) (int, error) {
	leases, err := m.List(prefix)
	if err != nil {
		return 0, err
	}
	n, errs := 0, []error(nil)
	for _, l := range leases {
		if err := m.revoke(ctx, &l); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", l.ID, err))
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

// revoke kills the user's sessions and drops it, then deletes the lease. If
// the database can't be reached, the lease stays, marked expired, and the
// expiry loop retries.
func (m *Manager) revoke(ctx context.Context, l *Lease) error {
	admin, err := m.kv.Get(l.Admin, 0, "")
	if err == nil {
		db, ok := Databases[l.Plugin]
		if !ok {
			err = fmt.Errorf("unknown plugin %q", l.Plugin)
		} else {
			err = rotation.Scrub(db.Drop(ctx, string(admin.Value), User{Name: l.Username, Host: l.Host}), string(admin.Value))
		}
	}
	if err != nil {
		m.cfg.Log.Error("lease: dropping database user", "lease", l.ID, "user", l.Username, "err", err)
		if cur, tok, lerr := m.load(l.ID); lerr == nil {
			cur.Expires, cur.LastError = minTime(cur.Expires, m.now().UTC()), err.Error()
			_ = m.save(cur, tok)
		}
		return fmt.Errorf("%w: dropping the user failed", ErrDatabase)
	}
	if err := m.cfg.Backend.Delete(leasePrefix + l.ID); err != nil && !errors.Is(err, storage.ErrNotFound) {
		return err
	}
	return nil
}

// List returns the leases under prefix (whole segments), or the one with that ID.
func (m *Manager) List(prefix string) ([]Lease, error) {
	keys, err := m.cfg.Backend.List(leasePrefix + prefix)
	if err != nil {
		return nil, err
	}
	// Whole path segments only: permission on db/orders must not reach
	// db/orders-rw. A full lease ID matches just that lease.
	prefix = strings.TrimSuffix(prefix, "/")
	out := make([]Lease, 0, len(keys))
	for _, k := range keys {
		id := strings.TrimPrefix(k, leasePrefix)
		if prefix != "" && id != prefix && !strings.HasPrefix(id, prefix+"/") {
			continue
		}
		l, _, err := m.load(id)
		if errors.Is(err, ErrNotFound) {
			continue // revoked meanwhile
		}
		if err != nil {
			return nil, err
		}
		out = append(out, *l)
	}
	return out, nil
}

// ---- expiry (leader only) ----

func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(m.cfg.Tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Tick(ctx)
		}
	}
}

// Tick revokes every expired lease.
//
// ponytail: scans all leases each tick; index by expiry if lease counts
// reach the tens of thousands.
func (m *Manager) Tick(ctx context.Context) {
	if !m.cfg.Leader() || m.cfg.Sealed() {
		return
	}
	leases, err := m.List("")
	if err != nil {
		m.cfg.Log.Error("lease: listing", "err", err)
		return
	}
	now := m.now()
	for _, l := range leases {
		if ctx.Err() != nil || !m.cfg.Leader() {
			return
		}
		if now.Before(l.Expires) {
			continue
		}
		id := randomHex(8)
		if err := m.audit(id, l.ID, "request"); err != nil {
			m.cfg.Log.Error("lease: audit", "err", err)
			return
		}
		res := "ok"
		if err := m.revoke(ctx, &l); err != nil {
			res = "error"
		}
		if err := m.audit(id, l.ID, res); err != nil {
			m.cfg.Log.Error("lease: audit", "err", err)
			return
		}
	}
}

func (m *Manager) audit(reqID, id, result string) error {
	return m.cfg.Audit.Log(audit.Entry{RequestID: reqID, Identity: m.cfg.Identity, Operation: "lease.expire",
		Path: leasePrefix + id, Result: result})
}
