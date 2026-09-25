/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"
)

// SoundnessRegime selects which proximity bound the query count is derived from.
//
// The two differ in how far from the code a malicious prover's oracle may sit
// while still being "close enough" that a single query catches it with the stated
// probability. The choice is a security assumption, not a performance knob.
type SoundnessRegime int

const (
	// Capacity assumes the list-decoding capacity bound: a query catches a
	// cheating prover except with probability rho, giving log2(1/rho) bits per
	// query.
	//
	// This is CONJECTURED, not proved. It is the regime WHIR-style constructions
	// are normally deployed under, and it is the default here, but a deployment
	// that needs a provable bound should use Johnson instead and pay roughly
	// double the queries.
	Capacity SoundnessRegime = iota

	// Johnson uses the Johnson radius, where a query is only guaranteed to catch a
	// cheating prover except with probability sqrt(rho), giving
	// log2(1/rho)/2 bits per query.
	//
	// This is what is actually PROVABLE, and it is what the Titan paper computes
	// its soundness with. Roughly twice the queries of Capacity for the same
	// security level.
	Johnson
)

// String names the regime, for error messages and benchmark labels.
func (r SoundnessRegime) String() string {
	switch r {
	case Capacity:
		return "capacity"
	case Johnson:
		return "johnson"
	default:
		return "unknown"
	}
}

// bitsPerQuery returns the numerator and denominator of the soundness bits a
// single consistency query buys, as a rational so the ceiling below is exact.
//
// With rate rho = 2^-logRate, capacity gives logRate bits per query and Johnson
// gives logRate/2. Returning a fraction rather than a float keeps
// QueryCount exact at the boundary: at logRate=3, Johnson is 1.5 bits per query,
// and 128/1.5 must come out as 86, not 85 from a truncated 1.5.
func (r SoundnessRegime) bitsPerQuery(logRate int) (num, den int) {
	if r == Johnson {
		return logRate, 2
	}
	return logRate, 1
}

// QueryCount returns the number of consistency queries needed for lambda bits of
// soundness at rate rho = 2^-logRate under the given regime.
//
//	Q = ceil(lambda / bits per query)
//
// The query term dominates the overall soundness error; every other term in the
// analysis is negligible by comparison. The folding rounds each contribute a
// Schwartz-Zippel term of about 2^-252 over BLS12-381's scalar field, and the
// domain-size term |L|/|F| is about 2^-240 at the sizes this package encodes, so
// rounding those in would not change Q.
//
// At the defaults (lambda=128, logRate=3, Capacity) this is 43. Note 42 queries
// would give only 126 bits.
func QueryCount(lambda, logRate int, regime SoundnessRegime) (int, error) {
	if lambda <= 0 {
		return 0, errors.Wrapf(ErrInvalidFoldConfig, "security parameter must be positive, got %d", lambda)
	}
	if logRate <= 0 {
		return 0, errors.Wrapf(ErrInvalidFoldConfig, "log of the inverse rate must be positive, got %d", logRate)
	}

	num, den := regime.bitsPerQuery(logRate)
	// ceil(lambda / (num/den)) == ceil(lambda*den / num)
	return (lambda*den + num - 1) / num, nil
}

// Default parameters. DefaultLogRate fixes rho = 1/8, which is the rate the
// domain blowup in commit.go is sized for, and DefaultSecurityBits is the usual
// 128-bit target.
const (
	DefaultSecurityBits = 128
	DefaultLogRate      = 3
)

// FoldConfig holds the parameters of the folding phase.
//
// Ell is the number of folding rounds, and also the coset dimension: each Merkle
// leaf holds 2^Ell points, and one leaf is exactly what a consistency query needs
// (see fold.go). The two are the same parameter by construction, not by
// coincidence.
type FoldConfig struct {
	// Ell is the number of folding rounds and the coset dimension.
	Ell int

	// LogRate is log2(1/rho); the encoding domain is 2^LogRate times the message.
	LogRate int

	// Queries is the number of consistency queries.
	Queries int

	// Regime is the proximity bound Queries was derived from. It is carried so a
	// verifier can report the soundness level a proof was built for.
	Regime SoundnessRegime
}

// DefaultEll returns the size-optimal number of folding rounds for an m-variable
// polynomial at the given rate and query count.
//
// The tradeoff: the proof carries Queries cosets of 2^Ell points each, plus the
// reduced polynomial's 2^(m-Ell) coefficients in plain. Raising Ell shrinks the
// plain part and grows the coset part,
//
//	size(Ell) ~ Queries * 2^Ell + 2^(m-Ell)
//
// and since the coset term carries the Queries factor it starts dominating well
// before Ell reaches m/2. So the optimum is below m/2 - 1: at m=12 it is 3 rather
// than 5, and at m=16 it is 5 rather than 7. Ell is a field on FoldConfig rather
// than a constant so a caller who wants the paper's m/2 - 1 can set it.
//
// Both terms are counted in group elements; the Merkle paths are logarithmic and
// do not move the optimum. The result is clamped to [1, m/2], the range
// Validate accepts.
func DefaultEll(m, queries int) int {
	if m < 2 {
		return 1
	}

	best, bestSize := 1, -1
	for ell := 1; ell <= m/2; ell++ {
		size := queries<<ell + 1<<(m-ell)
		if bestSize < 0 || size < bestSize {
			best, bestSize = ell, size
		}
	}
	return best
}

// DefaultFoldConfig returns the configuration this package recommends for an
// m-variable polynomial: rho = 1/8, 128 bits under the capacity bound, and the
// size-optimal number of folding rounds.
func DefaultFoldConfig(m int) (FoldConfig, error) {
	q, err := QueryCount(DefaultSecurityBits, DefaultLogRate, Capacity)
	if err != nil {
		return FoldConfig{}, err
	}

	cfg := FoldConfig{
		Ell:     DefaultEll(m, q),
		LogRate: DefaultLogRate,
		Queries: q,
		Regime:  Capacity,
	}
	if err := cfg.Validate(m); err != nil {
		return FoldConfig{}, err
	}
	return cfg, nil
}

// Validate checks the configuration against an m-variable polynomial.
//
// m must be even: the construction splits the variables in half and the coset
// layout assumes an exact split. Ell must be in [1, m/2] — at least one round to
// fold, and at most m/2 because Queries cosets of 2^Ell points are opened, so a
// larger Ell would make the queries cost more than the polynomial it is proving.
func (c FoldConfig) Validate(m int) error {
	if m <= 0 || m%2 != 0 {
		return errors.Wrapf(ErrInvalidFoldConfig, "number of variables must be positive and even, got %d", m)
	}
	if c.Ell < 1 || c.Ell > m/2 {
		return errors.Wrapf(ErrInvalidFoldConfig, "ell must be in [1, %d] for %d variables, got %d", m/2, m, c.Ell)
	}
	if c.LogRate <= 0 {
		return errors.Wrapf(ErrInvalidFoldConfig, "log of the inverse rate must be positive, got %d", c.LogRate)
	}
	if c.Queries <= 0 {
		return errors.Wrapf(ErrInvalidFoldConfig, "query count must be positive, got %d", c.Queries)
	}
	if c.Regime != Capacity && c.Regime != Johnson {
		return errors.Wrapf(ErrInvalidFoldConfig, "unknown soundness regime %d", int(c.Regime))
	}
	return nil
}

// SecurityBits reports the soundness level the configuration's query count
// achieves under its regime, which is the inverse of QueryCount. A caller that
// sets Queries by hand can use this to see what it bought.
func (c FoldConfig) SecurityBits() int {
	num, den := c.Regime.bitsPerQuery(c.LogRate)
	return c.Queries * num / den
}

// NumCosets returns the number of Merkle leaves the oracle has under this
// configuration: the folded domain size, 2^(m - Ell + LogRate).
func (c FoldConfig) NumCosets(m int) int { return 1 << (m - c.Ell + c.LogRate) }

// CosetSize returns the number of points in one Merkle leaf, 2^Ell.
func (c FoldConfig) CosetSize() int { return 1 << c.Ell }
