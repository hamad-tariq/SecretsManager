// Package kv stores versioned secrets on top of the barrier.
//
// Each secret is one record (all its versions, labels and metadata) at
// kv/<path>. Every change is a read-modify-write guarded by check-and-set,
// so concurrent writers on any node never lose each other's updates.
package kv

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/hamad-tariq/SecretsManager/internal/storage"
)

const (
	prefix             = "kv/"
	DefaultMaxVersions = 10
	DefaultRecovery    = 7 * 24 * time.Hour

	LabelCurrent  = "current"
	LabelPrevious = "previous"
	LabelPending  = "pending" // a rotation's new value, not yet served as current
)

var (
	ErrNotFound    = errors.New("kv: secret not found")
	ErrCASMismatch = errors.New("kv: check-and-set version mismatch")
	ErrNotDeleted  = errors.New("kv: secret is not deleted")
	ErrBusy        = errors.New("kv: too many concurrent updates, try again")
)

// Backend is what kv needs from the barrier.
type Backend interface {
	GetToken(key string) (value, token []byte, err error)
	PutIf(key string, value, token []byte) error
	Delete(key string) error
	List(prefix string) ([]string, error)
}

type version struct {
	Value   []byte    `json:"value"`
	Created time.Time `json:"created"`
}

type record struct {
	Versions  map[int]*version `json:"versions"`
	Latest    int              `json:"latest"`
	Labels    map[string]int   `json:"labels"`
	Created   time.Time        `json:"created"`
	Updated   time.Time        `json:"updated"`
	DeletedAt *time.Time       `json:"deleted_at,omitempty"`
}

type Store struct {
	b           Backend
	MaxVersions int
	Recovery    time.Duration // how long a soft-deleted secret can be undeleted
	now         func() time.Time
}

func New(b Backend) *Store {
	return &Store{b: b, MaxVersions: DefaultMaxVersions, Recovery: DefaultRecovery, now: time.Now}
}

// Secret is one version's value.
type Secret struct {
	Value   []byte    `json:"-"`
	Version int       `json:"version"`
	Created time.Time `json:"created"`
}

// Metadata describes a secret without any values.
type Metadata struct {
	Versions  []VersionInfo  `json:"versions"`
	Latest    int            `json:"latest"`
	Labels    map[string]int `json:"labels"`
	Created   time.Time      `json:"created"`
	Updated   time.Time      `json:"updated"`
	DeletedAt *time.Time     `json:"deleted_at,omitempty"`
}

type VersionInfo struct {
	Version int       `json:"version"`
	Created time.Time `json:"created"`
}

func key(path string) string { return prefix + path }

// load returns the record (nil if absent) and its check-and-set token. A
// soft-deleted record past its recovery window is purged and reported absent.
func (s *Store) load(path string) (*record, []byte, error) {
	raw, token, err := s.b.GetToken(key(path))
	if errors.Is(err, storage.ErrNotFound) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var r record
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, nil, fmt.Errorf("kv: corrupt record %s: %w", path, err)
	}
	if r.DeletedAt != nil && s.now().Sub(*r.DeletedAt) > s.Recovery {
		// ponytail: purge is lazy (on access); a background sweep can come
		// with the ops work in iteration 11 if unread deleted secrets pile up.
		if err := s.b.Delete(key(path)); err != nil {
			return nil, nil, err
		}
		return nil, nil, nil
	}
	return &r, token, nil
}

// update runs fn on the current record and writes the result with
// check-and-set, retrying if another writer got in first.
func (s *Store) update(path string, fn func(r *record) (*record, error)) error {
	for range 5 {
		r, token, err := s.load(path)
		if err != nil {
			return err
		}
		next, err := fn(r)
		if err != nil {
			return err
		}
		v, err := json.Marshal(next)
		if err != nil {
			return err
		}
		err = s.b.PutIf(key(path), v, token)
		if !errors.Is(err, storage.ErrConflict) {
			return err
		}
	}
	return ErrBusy
}

// MustNotExist is a cas for Put: fail if the secret exists, even soft-deleted
// (writing would revive its old versions).
const MustNotExist = -2

// Put writes a new version and returns its number. cas == -1 means no check;
// cas == 0 means the secret must not exist (a soft-deleted one is revived);
// cas > 0 must equal the latest version.
func (s *Store) Put(path string, value []byte, cas int) (int, error) {
	var written int
	err := s.update(path, func(r *record) (*record, error) {
		now := s.now().UTC()
		live := r != nil && r.DeletedAt == nil
		if cas == 0 && live || cas > 0 && (!live || r.Latest != cas) || cas == MustNotExist && r != nil {
			return nil, ErrCASMismatch
		}
		if r == nil {
			r = &record{Versions: map[int]*version{}, Labels: map[string]int{}, Created: now}
		}
		r.DeletedAt = nil // writing to a soft-deleted secret revives it
		r.Latest++
		r.Versions[r.Latest] = &version{Value: value, Created: now}
		if cur, ok := r.Labels[LabelCurrent]; ok {
			r.Labels[LabelPrevious] = cur
		}
		r.Labels[LabelCurrent] = r.Latest
		r.Updated = now
		s.trim(r)
		written = r.Latest
		return r, nil
	})
	return written, err
}

// PutPending writes a new version labelled pending, leaving current alone.
// A later PutPending replaces the label (the older pending version is then
// trimmed like any other).
func (s *Store) PutPending(path string, value []byte) (int, error) {
	var written int
	err := s.update(path, func(r *record) (*record, error) {
		now := s.now().UTC()
		if r == nil {
			r = &record{Versions: map[int]*version{}, Labels: map[string]int{}, Created: now}
		}
		if r.DeletedAt != nil {
			return nil, ErrNotFound
		}
		r.Latest++
		r.Versions[r.Latest] = &version{Value: value, Created: now}
		r.Labels[LabelPending] = r.Latest
		r.Updated = now
		s.trim(r)
		written = r.Latest
		return r, nil
	})
	return written, err
}

// Promote makes the pending version current (the old current becomes
// previous). Promoting a version that is already current is a no-op, so a
// retried promotion is safe.
func (s *Store) Promote(path string, version int) error {
	return s.update(path, func(r *record) (*record, error) {
		if r == nil || r.DeletedAt != nil {
			return nil, ErrNotFound
		}
		if r.Labels[LabelCurrent] == version {
			delete(r.Labels, LabelPending)
			return r, nil
		}
		if p, ok := r.Labels[LabelPending]; !ok || p != version {
			return nil, ErrCASMismatch
		}
		if cur, ok := r.Labels[LabelCurrent]; ok {
			r.Labels[LabelPrevious] = cur
		}
		r.Labels[LabelCurrent] = version
		delete(r.Labels, LabelPending)
		r.Updated = s.now().UTC()
		return r, nil
	})
}

// trim drops the oldest versions beyond MaxVersions, keeping labelled ones.
func (s *Store) trim(r *record) {
	var nums []int
	for n := range r.Versions {
		nums = append(nums, n)
	}
	slices.Sort(nums)
	for _, n := range nums {
		if len(r.Versions) <= s.MaxVersions {
			return
		}
		if !slices.Contains(labelTargets(r), n) {
			delete(r.Versions, n)
		}
	}
}

func labelTargets(r *record) []int {
	var out []int
	for _, v := range r.Labels {
		out = append(out, v)
	}
	return out
}

// Get returns a version: by number if version > 0, else by label ("" = current).
func (s *Store) Get(path string, version int, label string) (Secret, error) {
	r, _, err := s.load(path)
	if err != nil {
		return Secret{}, err
	}
	if r == nil || r.DeletedAt != nil {
		return Secret{}, ErrNotFound
	}
	if version <= 0 {
		if label == "" {
			label = LabelCurrent
		}
		n, ok := r.Labels[label]
		if !ok {
			return Secret{}, ErrNotFound
		}
		version = n
	}
	v, ok := r.Versions[version]
	if !ok {
		return Secret{}, ErrNotFound
	}
	return Secret{Value: v.Value, Version: version, Created: v.Created}, nil
}

// Metadata returns versions, labels and timestamps, never values. It also
// works on soft-deleted secrets so operators can see what can be undeleted.
func (s *Store) Metadata(path string) (Metadata, error) {
	r, _, err := s.load(path)
	if err != nil {
		return Metadata{}, err
	}
	if r == nil {
		return Metadata{}, ErrNotFound
	}
	m := Metadata{Latest: r.Latest, Labels: r.Labels, Created: r.Created, Updated: r.Updated, DeletedAt: r.DeletedAt}
	for n, v := range r.Versions {
		m.Versions = append(m.Versions, VersionInfo{Version: n, Created: v.Created})
	}
	slices.SortFunc(m.Versions, func(a, b VersionInfo) int { return a.Version - b.Version })
	return m, nil
}

// Delete soft-deletes: the secret disappears from Get but can be undeleted
// within the recovery window.
func (s *Store) Delete(path string) error {
	return s.update(path, func(r *record) (*record, error) {
		if r == nil || r.DeletedAt != nil {
			return nil, ErrNotFound
		}
		now := s.now().UTC()
		r.DeletedAt = &now
		return r, nil
	})
}

func (s *Store) Undelete(path string) error {
	return s.update(path, func(r *record) (*record, error) {
		if r == nil {
			return nil, ErrNotFound
		}
		if r.DeletedAt == nil {
			return nil, ErrNotDeleted
		}
		r.DeletedAt = nil
		return r, nil
	})
}

// Destroy removes a secret and all its versions immediately and for good.
func (s *Store) Destroy(path string) error {
	return s.b.Delete(key(path))
}

// List returns the secret paths under prefix (soft-deleted ones included).
func (s *Store) List(pathPrefix string) ([]string, error) {
	keys, err := s.b.List(key(pathPrefix))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, strings.TrimPrefix(k, prefix))
	}
	return out, nil
}
