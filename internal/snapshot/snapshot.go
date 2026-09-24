// Package snapshot is the backup file format: every stored key and value as
// the cluster holds them (barrier ciphertext plus the sealed keyring), with a
// SHA-256 checksum. Nothing in it is readable without unsealing a restored
// cluster with the shares that were current when it was taken.
package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const Format = "sm-snapshot-1"

// sealRecord is the barrier's keyring record; a snapshot without it can't be
// unsealed, so it isn't a backup.
const sealRecord = "raw/seal"

type File struct {
	Format  string            `json:"format"`
	Created time.Time         `json:"created"`
	Keys    int               `json:"keys"`
	SHA256  string            `json:"sha256"` // of the canonical JSON encoding of Data
	Data    map[string][]byte `json:"data"`
}

func checksum(data map[string][]byte) string {
	b, _ := json.Marshal(data) // map keys are sorted: canonical
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func New(data map[string][]byte, now time.Time) *File {
	return &File{Format: Format, Created: now.UTC(), Keys: len(data), SHA256: checksum(data), Data: data}
}

// Verify checks the format, the checksum, and that the keyring is present.
func (f *File) Verify() error {
	if f.Format != Format {
		return fmt.Errorf("snapshot: unknown format %q", f.Format)
	}
	if f.Keys != len(f.Data) || f.SHA256 != checksum(f.Data) {
		return errors.New("snapshot: checksum mismatch; the file is corrupt or was modified")
	}
	if _, ok := f.Data[sealRecord]; !ok {
		return errors.New("snapshot: no keyring record; this isn't a snapshot of an initialised cluster")
	}
	return nil
}

// Read decodes and verifies a snapshot.
func Read(r io.Reader) (*File, error) {
	var f File
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}
	return &f, f.Verify()
}
