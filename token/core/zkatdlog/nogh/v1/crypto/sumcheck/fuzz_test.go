/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sumcheck

import (
	"testing"

	mathlib "github.com/IBM/mathlib"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/require"
)

// FuzzVerify drives Verify with attacker-controlled proof bytes.
//
// Verify consumes a proof that arrives from the network in a composed protocol, so
// it must never panic on arbitrary input: not on malformed scalars or points, not
// on inconsistent round counts, and not on a shape that disagrees with the proof.
// A verification failure is the correct outcome for essentially every input here;
// the property under test is that the failure is an error and not a crash.
func FuzzVerify(f *testing.F) {
	curve := mathlib.Curves[mathlib.BLS12_381_BBS_GURVY]

	// Seed with a valid proof's wire bytes, so the fuzzer starts from something
	// structurally plausible and mutates outward.
	rng, err := curve.Rand()
	require.NoError(f, err)
	evals := make([]*mathlib.Zr, 8)
	for i := range evals {
		evals[i] = curve.NewRandomZr(rng)
	}
	poly, err := NewFieldPoly(evals)
	require.NoError(f, err)
	proof, _, err := Prove(curve, &Claim{Field: []FieldPoly{poly}})
	require.NoError(f, err)

	valid := flattenField(proof)
	f.Add(3, 1, false, 4, valid)

	// Empty and truncated inputs.
	f.Add(3, 1, false, 4, []byte{})
	f.Add(3, 1, false, 4, valid[:len(valid)/2])
	f.Add(0, 0, false, 0, []byte{})
	f.Add(1, 1, true, 2, valid)

	// Oversized and negative shape parameters, to exercise the validation path
	// before any decoding happens.
	f.Add(-1, 1, false, 4, valid)
	f.Add(3, -1, false, 4, valid)
	f.Add(1000000, 1, false, 4, valid)
	f.Add(3, 1000000, false, 4, valid)

	f.Fuzz(func(t *testing.T, numVars, numFieldFactors int, hasGroup bool, evalsPerRound int, raw []byte) {
		// Keep the reconstruction bounded: the fuzzer controls sizes, and the
		// point of the target is the verifier's robustness, not an allocation
		// stress test.
		if numVars < 0 || numVars > 16 {
			return
		}
		if numFieldFactors < 0 || numFieldFactors > 8 {
			return
		}
		if evalsPerRound < 0 || evalsPerRound > 16 {
			return
		}

		shape := Shape{
			NumVars:         numVars,
			NumFieldFactors: numFieldFactors,
			HasGroupFactor:  hasGroup,
		}

		proof := rebuildProof(curve, hasGroup, numVars, evalsPerRound, raw)

		// The contract: an error, never a panic.
		_, _ = Verify(curve, shape, proof)
	})
}

// flattenField serializes a field proof's scalars into a flat byte slice, in the
// layout rebuildProof expects.
func flattenField(p *Proof) []byte {
	var out []byte
	if p.FieldSum != nil {
		out = append(out, p.FieldSum.Bytes()...)
	}
	for _, round := range p.FieldRounds {
		for _, z := range round {
			out = append(out, z.Bytes()...)
		}
	}

	return out
}

// rebuildProof reassembles a Proof from fuzzer-controlled bytes.
//
// It deliberately does not validate: chunks that are not valid scalars or points
// are what the target is probing, so they are handed to the verifier as-is where
// the conversion tolerates them and skipped only where a constructor refuses.
func rebuildProof(curve *mathlib.Curve, hasGroup bool, numVars, evalsPerRound int, raw []byte) *Proof {
	const scalarLen = 32

	proof := &Proof{}

	take := func(i int) []byte {
		start := i * scalarLen
		end := start + scalarLen
		if start >= len(raw) {
			return nil
		}
		if end > len(raw) {
			end = len(raw)
		}

		return raw[start:end]
	}

	idx := 0
	if hasGroup {
		proof.GroupRounds = make([][]*mathlib.G1, 0, numVars)
		if b := take(idx); b != nil {
			if g, err := curve.NewG1FromCompressed(b); err == nil {
				proof.GroupSum = g
			}
		}
		idx++

		for range numVars {
			round := make([]*mathlib.G1, 0, evalsPerRound)
			for range evalsPerRound {
				b := take(idx)
				idx++
				if b == nil {
					continue
				}
				if g, err := curve.NewG1FromCompressed(b); err == nil {
					round = append(round, g)
				}
			}
			proof.GroupRounds = append(proof.GroupRounds, round)
		}

		return proof
	}

	proof.FieldRounds = make([][]*mathlib.Zr, 0, numVars)
	if b := take(idx); b != nil {
		proof.FieldSum = curve.NewZrFromBytes(padTo(b, scalarLen))
	}
	idx++

	for range numVars {
		round := make([]*mathlib.Zr, 0, evalsPerRound)
		for range evalsPerRound {
			b := take(idx)
			idx++
			if b == nil {
				continue
			}
			round = append(round, curve.NewZrFromBytes(padTo(b, scalarLen)))
		}
		proof.FieldRounds = append(proof.FieldRounds, round)
	}

	return proof
}

// padTo left-pads b to n bytes, so a short trailing chunk is still a decodable
// scalar rather than being discarded.
func padTo(b []byte, n int) []byte {
	if len(b) >= n {
		return b[:n]
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)

	return out
}

// FuzzNewFieldPoly drives the field polynomial constructor with arbitrary
// evaluation tables, since it is the entry point that turns caller-supplied data
// into the protocol's internal representation.
func FuzzNewFieldPoly(f *testing.F) {
	curve := mathlib.Curves[mathlib.BLS12_381_BBS_GURVY]

	f.Add(0, []byte{})
	f.Add(1, []byte{1})
	f.Add(4, []byte{1, 2, 3, 4})
	f.Add(3, []byte{1, 2, 3})
	f.Add(1024, []byte{0xff})

	f.Fuzz(func(t *testing.T, count int, seed []byte) {
		if count < 0 || count > 4096 {
			return
		}

		evals := make([]*mathlib.Zr, count)
		for i := range evals {
			b := make([]byte, 32)
			if len(seed) > 0 {
				b[31] = seed[i%len(seed)]
			}
			evals[i] = curve.NewZrFromBytes(b)
		}

		p, err := NewFieldPoly(evals)
		if err != nil {
			return
		}

		// On success the invariants the protocol relies on must hold.
		if got := len(p); got != count {
			t.Fatalf("length changed: got %d, want %d", got, count)
		}
		if nv := p.NumVars(); 1<<nv != count {
			t.Fatalf("NumVars %d inconsistent with length %d", nv, count)
		}

		// Sum must not panic, and folding all the way down must terminate at a
		// single value rather than looping or over-shrinking.
		_ = p.Sum()

		var r fr.Element
		r.SetUint64(7)
		folded := p.Clone()
		for len(folded) > 1 {
			before := len(folded)
			folded = folded.fold(&r)
			if len(folded) >= before {
				t.Fatalf("fold did not shrink: %d -> %d", before, len(folded))
			}
		}
	})
}
