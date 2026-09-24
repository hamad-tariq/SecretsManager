// Package secret provides a value type for sensitive bytes that refuses to
// print, log or serialise itself. The only way to get the bytes is Reveal.
package secret

import (
	"fmt"
	"io"
	"log/slog"
)

const redacted = "[REDACTED]"

// Secret wraps sensitive bytes. The bytes sit behind a pointer so that
// reflection-based printers (fmt on a struct with an unexported Secret
// field) see an address, not the contents.
type Secret struct{ v *[]byte }

// New wraps b. The Secret takes ownership: callers must not reuse b.
func New(b []byte) Secret { return Secret{v: &b} }

// Reveal returns the underlying bytes. Callers must not log or retain them.
func (s Secret) Reveal() []byte {
	if s.v == nil {
		return nil
	}
	return *s.v
}

// Zero overwrites the bytes in place.
func (s Secret) Zero() {
	if s.v != nil {
		clear(*s.v)
	}
}

func (Secret) String() string   { return redacted }
func (Secret) GoString() string { return redacted }

// Format covers every fmt verb (%x, %q, %d, ...), not just %s and %v.
func (Secret) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) }

func (Secret) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }
