// Package storagetest holds the behaviour tests every storage.Backend must pass.
package storagetest

import (
	"errors"
	"slices"
	"testing"

	"github.com/hamad-tariq/SecretsManager/internal/storage"
)

// Conformance runs the behaviour every Backend must have. The cluster
// package runs it against a live 3-node cluster.
func Conformance(t *testing.T, b storage.Backend) {
	t.Helper()
	if _, err := b.Get("missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("Get missing: %v", err)
	}
	for _, k := range []string{"a/2", "a/1", "b/1", "a/sub/x"} {
		if err := b.Put(k, []byte("v-"+k)); err != nil {
			t.Fatal(err)
		}
	}
	v, err := b.Get("a/1")
	if err != nil || string(v) != "v-a/1" {
		t.Fatalf("Get: %q %v", v, err)
	}
	v[0] = 'X' // callers may mutate what they get back
	if v2, _ := b.Get("a/1"); string(v2) != "v-a/1" {
		t.Fatal("stored value aliased the returned slice")
	}
	if err := b.Put("a/1", []byte("new")); err != nil {
		t.Fatal(err)
	}
	if v, _ := b.Get("a/1"); string(v) != "new" {
		t.Fatal("overwrite failed")
	}
	keys, err := b.List("a/")
	if err != nil || !slices.Equal(keys, []string{"a/1", "a/2", "a/sub/x"}) {
		t.Fatalf("List: %v %v", keys, err)
	}
	if err := b.Delete("a/1"); err != nil {
		t.Fatal(err)
	}
	if err := b.Delete("a/1"); err != nil {
		t.Fatalf("second delete: %v", err)
	}
	if _, err := b.Get("a/1"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("deleted key still present")
	}
	if keys, _ := b.List("zzz"); len(keys) != 0 {
		t.Fatalf("List no match: %v", keys)
	}

	// PutIf: create-only, then compare-and-swap.
	if err := b.PutIf("cas", []byte("v1"), nil); err != nil {
		t.Fatalf("PutIf create: %v", err)
	}
	if err := b.PutIf("cas", []byte("x"), nil); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("PutIf create on existing key: %v", err)
	}
	if err := b.PutIf("cas", []byte("x"), []byte("wrong")); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("PutIf with stale value: %v", err)
	}
	if err := b.PutIf("cas", []byte("v2"), []byte("v1")); err != nil {
		t.Fatalf("PutIf swap: %v", err)
	}
	if v, _ := b.Get("cas"); string(v) != "v2" {
		t.Fatalf("after swap: %q", v)
	}
	if err := b.PutIf("absent", []byte("x"), []byte("v1")); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("PutIf on missing key with expected value: %v", err)
	}
	_ = b.Delete("cas")
}
