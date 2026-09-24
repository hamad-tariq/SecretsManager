package storage_test

import (
	"slices"
	"testing"

	"github.com/hamad-tariq/SecretsManager/internal/storage"
	"github.com/hamad-tariq/SecretsManager/internal/storage/storagetest"
)

func TestInmem(t *testing.T) {
	s := storage.NewInmem()
	storagetest.Conformance(t, s)

	snap := s.Snapshot()
	s2 := storage.NewInmem()
	s2.Replace(snap)
	a, _ := s.List("")
	b, _ := s2.List("")
	if !slices.Equal(a, b) {
		t.Fatal("snapshot/replace lost keys")
	}
	snap["b/1"][0] = 'X'
	if v, _ := s.Get("b/1"); string(v) != "v-b/1" {
		t.Fatal("snapshot aliased stored values")
	}
}
