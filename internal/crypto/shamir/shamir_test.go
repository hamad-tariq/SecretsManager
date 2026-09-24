package shamir

import (
	"bytes"
	"crypto/rand"
	"math/bits"
	"testing"
)

// slowMult is a textbook shift-and-add GF(2^8) multiply, used as the reference.
func slowMult(a, b uint8) uint8 {
	var p uint8
	for b > 0 {
		if b&1 == 1 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1B
		}
		b >>= 1
	}
	return p
}

func TestFieldArithmetic(t *testing.T) {
	for a := range 256 {
		for b := range 256 {
			if got, want := mult(uint8(a), uint8(b)), slowMult(uint8(a), uint8(b)); got != want {
				t.Fatalf("mult(%d,%d)=%d want %d", a, b, got, want)
			}
		}
	}
	for a := 1; a < 256; a++ {
		if mult(uint8(a), inverse(uint8(a))) != 1 {
			t.Fatalf("inverse(%d) wrong", a)
		}
		if div(0, uint8(a)) != 0 {
			t.Fatalf("div(0,%d) != 0", a)
		}
		if div(uint8(a), uint8(a)) != 1 {
			t.Fatalf("div(%d,%d) != 1", a, a)
		}
	}
}

// Perfect secrecy: below the threshold, a share rules out no secret value.
// With threshold 2, one share's y byte must sometimes equal the secret byte
// (with a forced non-zero leading coefficient it never could).
func TestOneShareRulesNothingOut(t *testing.T) {
	const secret = 0x5a
	equal := 0
	for range 4000 {
		shares, err := Split([]byte{secret}, 5, 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, sh := range shares {
			if sh[0] == secret {
				equal++
			}
		}
	}
	// Expect about 20000/256 ≈ 78; zero would mean a value is excluded.
	if equal < 30 {
		t.Fatalf("a share equalled the secret byte %d times in 20000; some values are being excluded", equal)
	}
}

func TestShuffledXCoordinates(t *testing.T) {
	xs := shuffledXCoordinates()
	seen := map[uint8]bool{}
	for _, x := range xs {
		if x == 0 || seen[x] {
			t.Fatalf("bad x coordinates %v", xs)
		}
		seen[x] = true
	}
	if len(seen) != 255 {
		t.Fatalf("got %d coordinates", len(seen))
	}
}

// subsets calls fn with every subset of shares of size k.
func subsets(shares [][]byte, k int, fn func([][]byte)) {
	for mask := uint(0); mask < 1<<len(shares); mask++ {
		if bits.OnesCount(mask) != k {
			continue
		}
		var sub [][]byte
		for i := range shares {
			if mask&(1<<i) != 0 {
				sub = append(sub, shares[i])
			}
		}
		fn(sub)
	}
}

func TestSplitCombineAllSubsets(t *testing.T) {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)

	for _, c := range []struct{ n, m int }{{2, 2}, {3, 2}, {5, 3}, {7, 4}} {
		shares, err := Split(secret, c.n, c.m)
		if err != nil {
			t.Fatal(err)
		}
		if len(shares) != c.n || len(shares[0]) != len(secret)+ShareOverhead {
			t.Fatalf("n=%d m=%d: wrong share shape", c.n, c.m)
		}
		for k := c.m; k <= c.n; k++ {
			subsets(shares, k, func(sub [][]byte) {
				got, err := Combine(sub)
				if err != nil || !bytes.Equal(got, secret) {
					t.Fatalf("n=%d m=%d k=%d: reconstruction failed", c.n, c.m, k)
				}
			})
		}
		if c.m > 2 {
			subsets(shares, c.m-1, func(sub [][]byte) {
				got, err := Combine(sub)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Equal(got, secret) {
					t.Fatalf("n=%d m=%d: %d shares reconstructed the secret", c.n, c.m, c.m-1)
				}
			})
		}
	}
}

func TestSplitParams(t *testing.T) {
	s := []byte("x")
	for _, c := range []struct {
		secret     []byte
		parts, thr int
	}{
		{s, 3, 1}, {s, 2, 3}, {s, 256, 3}, {nil, 3, 2},
	} {
		if _, err := Split(c.secret, c.parts, c.thr); err != ErrParams {
			t.Fatalf("Split(%d bytes, %d, %d): got %v", len(c.secret), c.parts, c.thr, err)
		}
	}
	if _, err := Split(s, 255, 255); err != nil {
		t.Fatalf("255/255 should work: %v", err)
	}
}

func TestCombineErrors(t *testing.T) {
	for name, c := range map[string]struct {
		shares [][]byte
		want   error
	}{
		"one share":       {[][]byte{{1, 2}}, ErrTooFew},
		"too short":       {[][]byte{{1}, {2}}, ErrMalformed},
		"length mismatch": {[][]byte{{1, 2}, {1, 2, 3}}, ErrMalformed},
		"x is zero":       {[][]byte{{1, 0}, {1, 2}}, ErrMalformed},
		"duplicate x":     {[][]byte{{1, 5}, {2, 5}}, ErrDuplicate},
	} {
		if _, err := Combine(c.shares); err != c.want {
			t.Errorf("%s: got %v want %v", name, err, c.want)
		}
	}
}

func FuzzCombine(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4}, 2)
	f.Fuzz(func(t *testing.T, data []byte, n int) {
		if n < 1 || n > 16 || len(data) < n {
			return
		}
		size := len(data) / n
		var shares [][]byte
		for i := range n {
			shares = append(shares, data[i*size:(i+1)*size])
		}
		_, _ = Combine(shares) // must not panic
	})
}

func FuzzSplitCombine(f *testing.F) {
	f.Add([]byte("master key"), uint8(5), uint8(3))
	f.Fuzz(func(t *testing.T, secret []byte, n, m uint8) {
		shares, err := Split(secret, int(n), int(m))
		if err != nil {
			return
		}
		got, err := Combine(shares[:m])
		if err != nil || !bytes.Equal(got, secret) {
			t.Fatalf("round trip failed n=%d m=%d", n, m)
		}
	})
}
