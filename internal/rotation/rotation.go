// Package rotation rotates secrets on a schedule.
//
// Each rotated secret has a record at sys/rotation/<kv path> holding its
// settings (interval, plugin, parameters) and its progress. A rotation is
// four steps, and the record is saved after each one, so if the leader dies
// mid-rotation the next leader resumes where it stopped:
//
//  1. create: the plugin makes a new value, stored as the "pending" version
//  2. set:    the plugin applies it to the target (e.g. ALTER ROLE)
//  3. test:   the plugin checks the new value works (e.g. logs in with it)
//  4. finish: pending becomes current; the old current becomes previous
//
// Every step is safe to repeat. A failed step is retried with backoff
// (a failed test goes back to set); pending is never promoted until its
// test passes. Only the Raft leader runs rotations.
package rotation

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/hamad-tariq/SecretsManager/internal/audit"
	"github.com/hamad-tariq/SecretsManager/internal/kv"
	"github.com/hamad-tariq/SecretsManager/internal/metrics"
	"github.com/hamad-tariq/SecretsManager/internal/policy"
	"github.com/hamad-tariq/SecretsManager/internal/storage"
)

const (
	prefix      = "sys/rotation/"
	MinInterval = time.Minute
	maxBackoff  = time.Hour

	StepCreate = "create"
	StepSet    = "set"
	StepTest   = "test"
	StepFinish = "finish"
)

var (
	ErrNotFound = errors.New("rotation: not configured")
	ErrBusy     = errors.New("rotation: too many concurrent updates, try again")
)

// Settings is what an operator configures.
type Settings struct {
	Interval string            `json:"interval"` // Go duration, e.g. "720h"
	Plugin   string            `json:"plugin"`
	Params   map[string]string `json:"params,omitempty"` // not secret: credentials are referenced by kv path
}

// Record is Settings plus progress.
type Record struct {
	Settings
	Step        string    `json:"step,omitempty"` // next step to run; "" when idle
	Pending     int       `json:"pending_version,omitempty"`
	LastRotated time.Time `json:"last_rotated,omitzero"`
	NextDue     time.Time `json:"next_due"`
	Attempts    int       `json:"attempts,omitempty"`
	NextAttempt time.Time `json:"next_attempt,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
}

// Validate checks the interval, plugin and its parameters.
func (s Settings) Validate() error {
	d, err := time.ParseDuration(s.Interval)
	if err != nil || d < MinInterval {
		return fmt.Errorf("rotation: interval must be a duration of at least %s", MinInterval)
	}
	p, ok := plugins[s.Plugin]
	if !ok {
		return fmt.Errorf("rotation: unknown plugin %q", s.Plugin)
	}
	return p.Validate(s.Params)
}

// ---- records (also used by the API) ----

func load(b kv.Backend, path string) (*Record, []byte, error) {
	raw, tok, err := b.GetToken(prefix + path)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var r Record
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, nil, fmt.Errorf("rotation: corrupt record %s: %w", path, err)
	}
	return &r, tok, nil
}

// update applies fn to the record with check-and-set, retrying on conflict.
func update(b kv.Backend, path string, fn func(r *Record) (*Record, error)) (*Record, error) {
	for range 5 {
		r, tok, err := load(b, path)
		if err != nil {
			return nil, err
		}
		next, err := fn(r)
		if err != nil {
			return nil, err
		}
		v, _ := json.Marshal(next)
		if err := b.PutIf(prefix+path, v, tok); !errors.Is(err, storage.ErrConflict) {
			return next, err
		}
	}
	return nil, ErrBusy
}

// Configure sets a secret's rotation settings. A new configuration is due
// immediately; changing one keeps its progress and reschedules from the last
// rotation.
func Configure(b kv.Backend, path string, s Settings, now time.Time) (*Record, error) {
	if err := policy.ValidPath(path); err != nil {
		return nil, err
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return update(b, path, func(r *Record) (*Record, error) {
		if r == nil {
			return &Record{Settings: s, NextDue: now.UTC()}, nil
		}
		r.Settings = s
		if !r.LastRotated.IsZero() {
			d, _ := time.ParseDuration(s.Interval)
			r.NextDue = r.LastRotated.Add(d)
		}
		return r, nil
	})
}

func Get(b kv.Backend, path string) (*Record, error) {
	r, _, err := load(b, path)
	if err == nil && r == nil {
		err = ErrNotFound
	}
	return r, err
}

// Remove stops rotating a secret. The secret itself is untouched.
func Remove(b kv.Backend, path string) error {
	if r, err := Get(b, path); err != nil || r == nil {
		return err
	}
	return b.Delete(prefix + path)
}

// Trigger makes a rotation due now and clears any backoff.
func Trigger(b kv.Backend, path string, now time.Time) (*Record, error) {
	return update(b, path, func(r *Record) (*Record, error) {
		if r == nil {
			return nil, ErrNotFound
		}
		r.NextDue, r.NextAttempt = now.UTC(), time.Time{}
		return r, nil
	})
}

// ---- engine ----

type Config struct {
	Backend  kv.Backend // the barrier
	Sealed   func() bool
	Leader   func() bool
	Audit    *audit.Logger
	Identity string                                // this node's identity, for the audit log
	TLS      *tls.Config                           // node certificate + root CA, for plugins that call services
	Revoked  func(*x509.Certificate) (bool, error) // revocation list, for services plugins call
	Tick     time.Duration
	Log      *slog.Logger
	Metrics  *metrics.Registry // optional
}

type Engine struct {
	cfg Config
	kv  *kv.Store
	now func() time.Time
}

func New(cfg Config) *Engine {
	if cfg.Tick <= 0 {
		cfg.Tick = 10 * time.Second
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Engine{cfg: cfg, kv: kv.New(cfg.Backend), now: time.Now}
}

// Run checks for due rotations every Tick until ctx ends.
func (e *Engine) Run(ctx context.Context) {
	t := time.NewTicker(e.cfg.Tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.Tick(ctx)
		}
	}
}

// Tick runs every due rotation (on the leader, while unsealed).
//
// ponytail: rotations run one after another; a slow target delays the
// rest. Run them concurrently if many secrets rotate at the same time.
func (e *Engine) Tick(ctx context.Context) {
	if !e.cfg.Leader() || e.cfg.Sealed() {
		return
	}
	keys, err := e.cfg.Backend.List(prefix)
	if err != nil {
		e.cfg.Log.Error("rotation: listing", "err", err)
		return
	}
	for _, k := range keys {
		if ctx.Err() != nil {
			return
		}
		e.process(ctx, strings.TrimPrefix(k, prefix))
	}
}

var next = map[string]string{StepCreate: StepSet, StepSet: StepTest, StepTest: StepFinish, StepFinish: ""}

func (e *Engine) process(ctx context.Context, path string) {
	r, tok, err := load(e.cfg.Backend, path)
	if err != nil || r == nil {
		if err != nil {
			e.cfg.Log.Error("rotation: loading", "path", path, "err", err)
		}
		return
	}
	now := e.now()
	if r.Step == "" && now.Before(r.NextDue) || now.Before(r.NextAttempt) {
		return
	}
	if r.Step == "" {
		r.Step = StepCreate
	}
	for r.Step != "" {
		if !e.cfg.Leader() {
			return // leadership moved; the new leader resumes from the saved step
		}
		step, reqID := r.Step, newID()
		err := e.audit(reqID, step, path, "request")
		if err == nil {
			err = e.run(ctx, path, r)
			res := "ok"
			if err != nil {
				res = "error"
			}
			if aerr := e.audit(reqID, step, path, res); err == nil {
				err = aerr
			}
		}
		if err != nil && ctx.Err() != nil {
			return // shutting down, not a failure: the step reruns later
		}
		now := e.now().UTC()
		if err != nil {
			r.Attempts++
			r.LastError = step + ": " + err.Error()
			r.NextAttempt = now.Add(min(time.Minute<<min(r.Attempts-1, 10), maxBackoff))
			if step == StepTest {
				r.Step = StepSet // re-apply before testing again
			}
			e.cfg.Log.Error("rotation failed", "path", path, "step", step, "attempt", r.Attempts, "retry_at", r.NextAttempt, "err", err)
			e.cfg.Metrics.Add("sm_rotation_failures_total", "Failed rotation steps.", 1, "path", path, "step", step)
		} else {
			// Attempts count per rotation, not per step: set succeeding
			// and test failing, over and over, must still back off.
			r.Step, r.NextAttempt = next[step], time.Time{}
			if r.Step == "" {
				d, _ := time.ParseDuration(r.Interval)
				r.Pending, r.LastRotated, r.NextDue, r.Attempts, r.LastError = 0, now, now.Add(d), 0, ""
				e.cfg.Log.Info("secret rotated", "path", path)
				e.cfg.Metrics.Add("sm_rotations_total", "Completed rotations.", 1, "path", path)
			}
		}
		v, _ := json.Marshal(r)
		if perr := e.cfg.Backend.PutIf(prefix+path, v, tok); perr != nil {
			// Settings changed underneath us (or another leader got there):
			// the next tick reloads and repeats the step, which is safe.
			e.cfg.Log.Warn("rotation: saving progress", "path", path, "err", perr)
			return
		}
		if err != nil {
			return
		}
		// Reload: settings may have changed, or rotation been removed.
		if r, tok, err = load(e.cfg.Backend, path); err != nil || r == nil {
			return
		}
	}
}

func (e *Engine) run(ctx context.Context, path string, r *Record) error {
	p, ok := plugins[r.Plugin]
	if !ok {
		return fmt.Errorf("unknown plugin %q", r.Plugin)
	}
	t := Target{Path: path, Params: r.Params, TLS: e.cfg.TLS, Lookup: e.lookup, Revoked: e.cfg.Revoked}
	if cur, err := e.kv.Get(path, 0, ""); err == nil {
		t.Current = cur.Value
	} else if !errors.Is(err, kv.ErrNotFound) {
		return err
	}
	switch r.Step {
	case StepCreate:
		v, err := p.Create(ctx, t)
		if err != nil {
			return err
		}
		n, err := e.kv.PutPending(path, v)
		r.Pending = n
		return err
	case StepFinish:
		return e.kv.Promote(path, r.Pending)
	}
	pending, err := e.kv.Get(path, r.Pending, "")
	if err != nil {
		return fmt.Errorf("pending version %d: %w", r.Pending, err)
	}
	if r.Step == StepSet {
		return p.Set(ctx, t, pending.Value)
	}
	return p.Test(ctx, t, pending.Value)
}

func (e *Engine) lookup(path string) ([]byte, error) {
	s, err := e.kv.Get(path, 0, "")
	return s.Value, err
}

func (e *Engine) audit(reqID, step, path, result string) error {
	return e.cfg.Audit.Log(audit.Entry{RequestID: reqID, Identity: e.cfg.Identity,
		Operation: "rotation." + step, Path: "kv/" + path, Result: result})
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
