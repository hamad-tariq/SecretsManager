// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Ported from github.com/openbao/openbao/sdk/v2/helper/shamir (v2.7.0).
// This file remains under MPL-2.0 (the rest of the repository is
// Apache-2.0); changes to it are MPL-2.0 too. Changes from upstream:
//   - Combine rejects shares with x = 0;
//   - crypto/rand errors are not propagated (it cannot fail since Go 1.24).

// Package shamir implements Shamir's secret sharing over GF(2^8).
// Each share is len(secret)+1 bytes: the y values followed by the x coordinate.
package shamir

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"math/big"
)

// ShareOverhead is the number of bytes a share adds to the secret.
const ShareOverhead = 1

var (
	ErrParams    = errors.New("shamir: need 2 <= threshold <= parts <= 255 and a non-empty secret")
	ErrTooFew    = errors.New("shamir: need at least two shares")
	ErrMalformed = errors.New("shamir: shares are malformed")
	ErrDuplicate = errors.New("shamir: duplicate share")
)

// makePolynomial returns coefficients[0] = intercept and uniformly random
// other coefficients. Every coefficient must be uniform, including the
// leading one: forcing it non-zero (as this code once did) makes one value of
// each secret byte impossible given threshold-1 shares, a small but real
// leak. A zero leading coefficient is harmless: nobody can tell which bytes
// had one.
func makePolynomial(intercept, degree uint8) []uint8 {
	c := make([]uint8, degree+1)
	c[0] = intercept
	_, _ = rand.Read(c[1:])
	return c
}

// shuffledXCoordinates returns 1..255 in random order. x=0 is excluded
// because the polynomial's value there is the secret byte.
func shuffledXCoordinates() []uint8 {
	xs := make([]uint8, 255)
	for i := range xs {
		xs[i] = uint8(i + 1)
	}
	for i := len(xs) - 1; i > 0; i-- {
		// Uniform j in [0, i]; rand.Int only errors if the reader fails.
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		k := j.Int64()
		xs[i], xs[k] = xs[k], xs[i]
	}
	return xs
}

// evaluate computes the polynomial at x using Horner's method.
func evaluate(coeffs []uint8, x uint8) uint8 {
	out := coeffs[len(coeffs)-1]
	for i := len(coeffs) - 2; i >= 0; i-- {
		out = add(mult(out, x), coeffs[i])
	}
	return out
}

// interpolateAtZero returns the Lagrange interpolation of the samples at x=0.
func interpolateAtZero(xs, ys []uint8) uint8 {
	var result uint8
	for i := range xs {
		basis := uint8(1)
		for j := range xs {
			if i == j {
				continue
			}
			basis = mult(basis, div(xs[j], add(xs[i], xs[j])))
		}
		result = add(result, mult(ys[i], basis))
	}
	return result
}

// div divides in GF(2^8). b is never zero: callers pass distinct x values.
func div(a, b uint8) uint8 {
	ret := int(mult(a, inverse(b)))
	return uint8(subtle.ConstantTimeSelect(subtle.ConstantTimeByteEq(a, 0), 0, ret)) // #nosec G115 -- selects 0 or a uint8 value
}

// inverse computes a^254 = a^-1 in GF(2^8) with a fixed multiplication chain.
func inverse(a uint8) uint8 {
	b := mult(a, a) // a^2
	c := mult(a, b) // a^3
	b = mult(c, c)  // a^6
	b = mult(b, b)  // a^12
	c = mult(b, c)  // a^15
	b = mult(b, b)  // a^24
	b = mult(b, b)  // a^48
	b = mult(b, c)  // a^63
	b = mult(b, b)  // a^126
	b = mult(a, b)  // a^127
	return mult(b, b)
}

// mult multiplies in GF(2^8) (AES polynomial 0x11B) in constant time.
func mult(a, b uint8) uint8 {
	var r uint8
	for i := 8; i > 0; i-- {
		r = (-(b >> (i - 1) & 1) & a) ^ (-(r >> 7) & 0x1B) ^ (r + r)
	}
	return r
}

// add is addition (and subtraction) in GF(2^8).
func add(a, b uint8) uint8 { return a ^ b }

// Split divides secret into `parts` shares, any `threshold` of which
// reconstruct it.
func Split(secret []byte, parts, threshold int) ([][]byte, error) {
	if threshold < 2 || parts < threshold || parts > 255 || len(secret) == 0 {
		return nil, ErrParams
	}

	xs := shuffledXCoordinates()
	out := make([][]byte, parts)
	for i := range out {
		out[i] = make([]byte, len(secret)+1)
		out[i][len(secret)] = xs[i]
	}

	// One polynomial per secret byte: GF(2^8) holds a single byte.
	for idx, val := range secret {
		p := makePolynomial(val, uint8(threshold-1)) // #nosec G115 -- threshold checked to be in [2, 255] above
		for i := range parts {
			out[i][idx] = evaluate(p, xs[i])
		}
		clear(p)
	}
	return out, nil
}

// Combine reconstructs the secret from shares. Given fewer than threshold
// shares it returns garbage, not an error: Shamir shares carry no checksum,
// so callers must verify the result (e.g. by decrypting with it).
func Combine(shares [][]byte) ([]byte, error) {
	if len(shares) < 2 {
		return nil, ErrTooFew
	}
	n := len(shares[0])
	if n < 2 {
		return nil, ErrMalformed
	}

	xs := make([]uint8, len(shares))
	seen := map[uint8]bool{}
	for i, s := range shares {
		if len(s) != n {
			return nil, ErrMalformed
		}
		x := s[n-1]
		if x == 0 {
			return nil, ErrMalformed
		}
		if seen[x] {
			return nil, ErrDuplicate
		}
		seen[x] = true
		xs[i] = x
	}

	secret := make([]byte, n-1)
	ys := make([]uint8, len(shares))
	for idx := range secret {
		for i, s := range shares {
			ys[i] = s[idx]
		}
		secret[idx] = interpolateAtZero(xs, ys)
	}
	clear(ys)
	return secret, nil
}
