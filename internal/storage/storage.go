// Package storage defines the key-value interface every layer above the
// cluster is written against. Values are opaque bytes; from iteration 5 on
// they are always ciphertext produced by the barrier.
package storage

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"sync"
)

var (
	ErrNotFound = errors.New("storage: key not found")
	ErrConflict = errors.New("storage: value changed since it was read")
)

type Backend interface {
	// Get returns ErrNotFound for a missing key.
	Get(key string) ([]byte, error)
	Put(key string, value []byte) error
	// Delete of a missing key is not an error.
	Delete(key string) error
	// List returns all keys starting with prefix, sorted.
	List(prefix string) ([]string, error)
	// PutIf writes only if the key currently holds exactly expected
	// (expected == nil: only if the key does not exist); else ErrConflict.
	PutIf(key string, value, expected []byte) error
}

// Inmem is a Backend held in a map, for tests and for the cluster's state machine.
type Inmem struct {
	mu sync.RWMutex
	m  map[string][]byte
}

func NewInmem() *Inmem { return &Inmem{m: map[string][]byte{}} }

func (s *Inmem) Get(key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.m[key]
	if !ok {
		return nil, ErrNotFound
	}
	return slices.Clone(v), nil
}

func (s *Inmem) Put(key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = slices.Clone(value)
	return nil
}

func (s *Inmem) PutIf(key string, value, expected []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.m[key]
	if expected == nil && ok || expected != nil && (!ok || !bytes.Equal(cur, expected)) {
		return ErrConflict
	}
	s.m[key] = slices.Clone(value)
	return nil
}

func (s *Inmem) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
	return nil
}

func (s *Inmem) List(prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var keys []string
	for k := range s.m {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	return keys, nil
}

// Snapshot returns a copy of every key and value.
func (s *Inmem) Snapshot() map[string][]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string][]byte, len(s.m))
	for k, v := range s.m {
		out[k] = slices.Clone(v)
	}
	return out
}

// Replace swaps the whole contents for m (used when restoring a snapshot).
func (s *Inmem) Replace(m map[string][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m = m
}
