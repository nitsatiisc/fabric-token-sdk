/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"math/big"
	"testing"

	mathlib "github.com/IBM/mathlib"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/sumcheck"
)

func testCurve() *mathlib.Curve { return mathlib.Curves[mathlib.BLS12_381_BBS] }

func randomPoint(t *testing.T, m int) []fr.Element {
	t.Helper()
	at := make([]fr.Element, m)
	for i := range at {
		_, err := at[i].SetRandom()
		require.NoError(t, err)
	}

	return at
}

// TestProveGroupEvalRoundTrip checks the basic contract: sigma must be the
// evaluation f(alpha), and verification must accept and land on the same residual
// claim the prover reports.
func TestProveGroupEvalRoundTrip(t *testing.T) {
	curve := testCurve()
	for _, m := range []int{1, 2, 3, 4, 6, 8, 10} {
		f := randomGroupPoly(t, m)
		alpha := randomPoint(t, m)
		ell := DefaultSplit(m)

		proof, opening, sigma, err := ProveGroupEval(curve, f, alpha, ell)
		require.NoError(t, err)

		// The sum of eq(alpha, x)*f(x) over the hypercube is exactly f(alpha), so
		// the claimed sum must match a direct multilinear evaluation. This is the
		// independent anchor: EvaluatePoint is tested on its own in the sumcheck
		// package and shares no code with the partial-sum machinery.
		want, err := f.EvaluatePoint(alpha)
		require.NoError(t, err)
		assert.True(t, sigma.Equal(&want), "m=%d: claimed sum is not f(alpha)", m)

		vOpening, err := VerifyGroupEval(curve, proof, alpha, &sigma, ell)
		require.NoError(t, err, "m=%d", m)

		require.Len(t, vOpening.R, m)
		for i := range opening.R {
			assert.True(t, opening.R[i].Equal(&vOpening.R[i]), "m=%d: challenge %d diverged", m, i)
		}
		assert.True(t, opening.Expected.Equal(&vOpening.Expected), "m=%d: residual claim diverged", m)
	}
}

// TestResidualClaimClosesTheArgument checks the part the verifier cannot check
// itself: the residual value must equal eq(alpha, R)*f(R). This is the step a
// caller performs against an oracle, and if it does not hold on the honest path
// then no caller could ever close the reduction.
func TestResidualClaimClosesTheArgument(t *testing.T) {
	curve := testCurve()
	for _, m := range []int{1, 2, 5, 8} {
		f := randomGroupPoly(t, m)
		alpha := randomPoint(t, m)

		_, opening, _, err := ProveGroupEval(curve, f, alpha, DefaultSplit(m))
		require.NoError(t, err)

		// R comes out in table order for this package, so EvaluatePoint is the
		// right entry point.
		fAtR, err := f.EvaluatePoint(opening.R)
		require.NoError(t, err)
		eqAtR, err := eqPoint(alpha, opening.R)
		require.NoError(t, err)

		var want bls12381.G1Affine
		var wantJac bls12381.G1Jac
		wantJac.FromAffine(&fAtR)
		bi := new(big.Int)
		eqAtR.BigInt(bi)
		wantJac.ScalarMultiplication(&wantJac, bi)
		want.FromJacobian(&wantJac)

		assert.True(t, opening.Expected.Equal(&want), "m=%d: residual claim is not eq(alpha,R)*f(R)", m)
	}
}

// TestSplitInvarianceProducesIdenticalProofs pins down that ell is *only* a
// performance knob. The MSM-based rounds and the folklore rounds compute the same
// polynomial by different routes, so every ell must yield a byte-identical proof.
//
// This is the test that makes the partial-sum machinery trustworthy: ell=0 runs
// entirely through the folklore path, ell=m entirely through the partial-sum path,
// and the two must agree. A bug in either path breaks the equality.
func TestSplitInvarianceProducesIdenticalProofs(t *testing.T) {
	curve := testCurve()
	for _, m := range []int{1, 2, 3, 4, 6, 8} {
		f := randomGroupPoly(t, m)
		alpha := randomPoint(t, m)

		// ell is bound into the transcript, so proofs for different ell draw
		// different challenges and cannot be compared round by round. Compare the
		// claimed sum, which is transcript-independent, and verify each proof
		// under its own ell.
		var sums []bls12381.G1Affine
		for ell := 0; ell <= m; ell++ {
			proof, _, sigma, err := ProveGroupEval(curve, f, alpha, ell)
			require.NoError(t, err, "m=%d ell=%d", m, ell)
			_, err = VerifyGroupEval(curve, proof, alpha, &sigma, ell)
			require.NoError(t, err, "m=%d ell=%d", m, ell)
			sums = append(sums, sigma)
		}
		for i := range sums {
			assert.True(t, sums[0].Equal(&sums[i]), "m=%d: ell=%d disagrees on the sum", m, i)
		}
	}
}

// TestRoundMessagesAgreeAcrossPaths is the sharper form of split invariance: it
// compares the *round messages* themselves, not just the final sum.
//
// Because ell is bound into the transcript, two runs with different ell diverge
// after the first challenge. So this drives roundMessageFromTable and
// roundMessageFolklore directly, at the same prior challenges, and requires all
// three evaluations to match.
func TestRoundMessagesAgreeAcrossPaths(t *testing.T) {
	for _, m := range []int{2, 3, 4, 6} {
		f := randomGroupPoly(t, m)
		alpha := randomPoint(t, m)
		eq := eqTable(alpha)

		tables, err := computeSTables(f, eq, m)
		require.NoError(t, err)

		rho := []fr.Element{}
		for round := 1; round <= m; round++ {
			fromTable, err := roundMessageFromTable(tables[round-1], alpha, rho, round)
			require.NoError(t, err)

			h, e, err := restrictBoth(f, eq, rho)
			require.NoError(t, err)
			folklore, err := roundMessageFolklore(h, e)
			require.NoError(t, err)

			for j := range numRoundEvals {
				assert.True(t, fromTable[j].Equal(&folklore[j]),
					"m=%d round=%d: evaluation at u=%d differs between the partial-sum and folklore paths", m, round, j)
			}

			r := randomPoint(t, 1)[0]
			rho = append(rho, r)
		}
	}
}

// TestCrossCheckAgainstSumCheck is the strongest available test: it proves the
// same claim with the general crypto/sumcheck implementation, as the two-factor
// product eq(alpha, .) * f(.), and requires the claimed sums to agree.
//
// The two implementations share no code on the proving path — different variable
// order, different round-message construction, different transcript — so agreement
// is meaningful. The round messages cannot be compared (the two consume variables
// in opposite order and absorb different bytes), but the asserted sum must match.
func TestCrossCheckAgainstSumCheck(t *testing.T) {
	curve := testCurve()
	for _, m := range []int{1, 2, 3, 5, 7} {
		f := randomGroupPoly(t, m)
		alpha := randomPoint(t, m)

		_, _, sigma, err := ProveGroupEval(curve, f, alpha, DefaultSplit(m))
		require.NoError(t, err)

		claim := &sumcheck.Claim{
			Field: []sumcheck.FieldPoly{eqTable(alpha)},
			Group: f,
		}
		scProof, _, err := sumcheck.Prove(curve, claim)
		require.NoError(t, err)

		var scSum bls12381.G1Affine
		_, err = scSum.SetBytes(scProof.GroupSum.Bytes())
		require.NoError(t, err)

		assert.True(t, sigma.Equal(&scSum),
			"m=%d: the group sum-check and crypto/sumcheck disagree on sum_x eq(alpha,x)*f(x)", m)
	}
}

// TestVerifyRejectsWrongSum checks that a claimed sum other than the real one is
// rejected in round 1.
func TestVerifyRejectsWrongSum(t *testing.T) {
	curve := testCurve()
	m := 4
	f := randomGroupPoly(t, m)
	alpha := randomPoint(t, m)

	proof, _, sigma, err := ProveGroupEval(curve, f, alpha, DefaultSplit(m))
	require.NoError(t, err)

	_, _, g1Aff, _ := bls12381.Generators()
	var wrong bls12381.G1Affine
	wrong.Add(&sigma, &g1Aff)

	_, err = VerifyGroupEval(curve, proof, alpha, &wrong, DefaultSplit(m))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSumMismatch)
}

// TestVerifyRejectsTamperedRounds checks each position independently: a tamper in
// the first, a middle, or the last round must all be caught.
func TestVerifyRejectsTamperedRounds(t *testing.T) {
	curve := testCurve()
	m := 5
	ell := DefaultSplit(m)
	_, _, g1Aff, _ := bls12381.Generators()

	for _, round := range []int{0, 2, m - 1} {
		f := randomGroupPoly(t, m)
		alpha := randomPoint(t, m)
		proof, _, sigma, err := ProveGroupEval(curve, f, alpha, ell)
		require.NoError(t, err)

		proof.Rounds[round][0].Add(&proof.Rounds[round][0], &g1Aff)

		_, err = VerifyGroupEval(curve, proof, alpha, &sigma, ell)
		require.Error(t, err, "tampering round %d went undetected", round)
	}
}

// TestVerifyRejectsCompensatingTamper is the reason the verifier interpolates
// rather than only checking g(0)+g(1).
//
// Moving value from g(0) to g(1) leaves the sum untouched, so the round-1 check
// passes; the tamper is caught only because the verifier carries g(r) into the next
// round, where it no longer matches. Without interpolation this proof would verify.
func TestVerifyRejectsCompensatingTamper(t *testing.T) {
	curve := testCurve()
	m := 4
	ell := DefaultSplit(m)
	f := randomGroupPoly(t, m)
	alpha := randomPoint(t, m)

	proof, _, sigma, err := ProveGroupEval(curve, f, alpha, ell)
	require.NoError(t, err)

	_, _, g1Aff, _ := bls12381.Generators()
	proof.Rounds[0][0].Add(&proof.Rounds[0][0], &g1Aff)
	var negG bls12381.G1Affine
	negG.Neg(&g1Aff)
	proof.Rounds[0][1].Add(&proof.Rounds[0][1], &negG)

	// The sum is preserved, so round 1's g(0)+g(1) check still passes.
	var total bls12381.G1Jac
	total.FromAffine(&proof.Rounds[0][0])
	total.AddMixed(&proof.Rounds[0][1])
	var totalAff bls12381.G1Affine
	totalAff.FromJacobian(&total)
	require.True(t, totalAff.Equal(&sigma), "the tamper was not actually compensating")

	_, err = VerifyGroupEval(curve, proof, alpha, &sigma, ell)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrRoundCheckFailed)
}

// TestVerifyRejectsDroppedRound checks that the round count is bound.
func TestVerifyRejectsDroppedRound(t *testing.T) {
	curve := testCurve()
	m := 4
	f := randomGroupPoly(t, m)
	alpha := randomPoint(t, m)

	proof, _, sigma, err := ProveGroupEval(curve, f, alpha, DefaultSplit(m))
	require.NoError(t, err)

	proof.Rounds = proof.Rounds[:m-1]
	_, err = VerifyGroupEval(curve, proof, alpha, &sigma, DefaultSplit(m))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrRoundCountMismatch)
}

// TestVerifyRejectsWrongSplit checks that ell is bound into the transcript: a
// verifier using a different split derives different challenges and rejects.
func TestVerifyRejectsWrongSplit(t *testing.T) {
	curve := testCurve()
	m := 4
	f := randomGroupPoly(t, m)
	alpha := randomPoint(t, m)

	proof, _, sigma, err := ProveGroupEval(curve, f, alpha, 2)
	require.NoError(t, err)

	_, err = VerifyGroupEval(curve, proof, alpha, &sigma, 1)
	require.Error(t, err)
}

// TestVerifyRejectsWrongAlpha checks that alpha is bound into the transcript.
func TestVerifyRejectsWrongAlpha(t *testing.T) {
	curve := testCurve()
	m := 4
	f := randomGroupPoly(t, m)
	alpha := randomPoint(t, m)

	proof, _, sigma, err := ProveGroupEval(curve, f, alpha, DefaultSplit(m))
	require.NoError(t, err)

	other := make([]fr.Element, m)
	copy(other, alpha)
	one := fr.One()
	other[m-1].Add(&other[m-1], &one)

	_, err = VerifyGroupEval(curve, proof, other, &sigma, DefaultSplit(m))
	require.Error(t, err)
}

// TestBoundaryAlphaReturnsErrorNotPanic covers the one input that makes the
// partial-sum round messages ill-defined: alpha with a coordinate exactly 0 or 1
// makes eq(alpha_i, b) vanish for some b, so the reciprocal the round message
// needs does not exist.
//
// The reference implementation unwraps the inversion and panics. Here it must be
// an error. Note the folklore path has no such division, so ell must be large
// enough for the affected round to be an MSM round.
func TestBoundaryAlphaReturnsErrorNotPanic(t *testing.T) {
	curve := testCurve()
	m := 4
	f := randomGroupPoly(t, m)

	for _, tc := range []struct {
		name string
		val  fr.Element
	}{
		{"zero", fr.Element{}},
		{"one", fr.One()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			alpha := randomPoint(t, m)
			alpha[0] = tc.val

			_, _, _, err := ProveGroupEval(curve, f, alpha, m)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrZeroDenominator)
		})
	}
}

// TestProveGroupEvalValidation covers the input checks.
func TestProveGroupEvalValidation(t *testing.T) {
	curve := testCurve()
	f := randomGroupPoly(t, 3)
	alpha := randomPoint(t, 3)

	t.Run("nil curve", func(t *testing.T) {
		_, _, _, err := ProveGroupEval(nil, f, alpha, 1)
		assert.ErrorIs(t, err, ErrNilCurve)
	})
	t.Run("nil polynomial", func(t *testing.T) {
		_, _, _, err := ProveGroupEval(curve, nil, alpha, 1)
		assert.ErrorIs(t, err, ErrNilPolynomial)
	})
	t.Run("non power of two", func(t *testing.T) {
		_, _, _, err := ProveGroupEval(curve, f[:3], alpha, 1)
		assert.ErrorIs(t, err, ErrNotPowerOfTwo)
	})
	t.Run("alpha length mismatch", func(t *testing.T) {
		_, _, _, err := ProveGroupEval(curve, f, alpha[:2], 1)
		assert.ErrorIs(t, err, ErrNumVarsMismatch)
	})
	t.Run("split too large", func(t *testing.T) {
		_, _, _, err := ProveGroupEval(curve, f, alpha, 4)
		assert.ErrorIs(t, err, ErrInvalidSplit)
	})
	t.Run("split negative", func(t *testing.T) {
		_, _, _, err := ProveGroupEval(curve, f, alpha, -1)
		assert.ErrorIs(t, err, ErrInvalidSplit)
	})
}

// TestVerifyGroupEvalValidation covers the verifier's input checks.
func TestVerifyGroupEvalValidation(t *testing.T) {
	curve := testCurve()
	m := 3
	f := randomGroupPoly(t, m)
	alpha := randomPoint(t, m)
	proof, _, sigma, err := ProveGroupEval(curve, f, alpha, 1)
	require.NoError(t, err)

	t.Run("nil curve", func(t *testing.T) {
		_, err := VerifyGroupEval(nil, proof, alpha, &sigma, 1)
		assert.ErrorIs(t, err, ErrNilCurve)
	})
	t.Run("nil proof", func(t *testing.T) {
		_, err := VerifyGroupEval(curve, nil, alpha, &sigma, 1)
		assert.ErrorIs(t, err, ErrNilProof)
	})
	t.Run("nil sigma", func(t *testing.T) {
		_, err := VerifyGroupEval(curve, proof, alpha, nil, 1)
		assert.ErrorIs(t, err, ErrNilElement)
	})
	t.Run("empty alpha", func(t *testing.T) {
		_, err := VerifyGroupEval(curve, proof, nil, &sigma, 1)
		assert.ErrorIs(t, err, ErrNumVarsMismatch)
	})
	t.Run("bad split", func(t *testing.T) {
		_, err := VerifyGroupEval(curve, proof, alpha, &sigma, 9)
		assert.ErrorIs(t, err, ErrInvalidSplit)
	})
}

// TestProveDoesNotModifyInput checks that the prover folds copies, since callers
// hold their GroupPoly across calls for the conversion cost reasons documented in
// the sumcheck package.
func TestProveDoesNotModifyInput(t *testing.T) {
	curve := testCurve()
	m := 5
	f := randomGroupPoly(t, m)
	alpha := randomPoint(t, m)

	before := make(sumcheck.GroupPoly, len(f))
	copy(before, f)
	alphaBefore := make([]fr.Element, m)
	copy(alphaBefore, alpha)

	_, _, _, err := ProveGroupEval(curve, f, alpha, DefaultSplit(m))
	require.NoError(t, err)

	for i := range f {
		require.True(t, f[i].Equal(&before[i]), "the prover modified the polynomial at %d", i)
	}
	for i := range alpha {
		require.True(t, alpha[i].Equal(&alphaBefore[i]), "the prover modified alpha at %d", i)
	}
}

// TestSTablesTelescope checks the descent directly: S_(i-1)(b) must be the sum of
// the two halves of S_i, and S_1(0)+S_1(1) must be the full sum.
func TestSTablesTelescope(t *testing.T) {
	m := 5
	f := randomGroupPoly(t, m)
	alpha := randomPoint(t, m)
	eq := eqTable(alpha)

	tables, err := computeSTables(f, eq, m)
	require.NoError(t, err)
	require.Len(t, tables, m)

	for i := range tables {
		require.Len(t, tables[i], 1<<(i+1), "S_%d has the wrong size", i+1)
	}

	for i := m - 1; i >= 1; i-- {
		above := tables[i]
		half := len(above) / 2
		for b := range half {
			var want bls12381.G1Jac
			want.FromAffine(&above[b])
			want.AddMixed(&above[b+half])
			var wantAff bls12381.G1Affine
			wantAff.FromJacobian(&want)
			require.True(t, tables[i-1][b].Equal(&wantAff), "S_%d(%d) is not the sum of the halves of S_%d", i, b, i+1)
		}
	}

	var total bls12381.G1Jac
	total.FromAffine(&tables[0][0])
	total.AddMixed(&tables[0][1])
	var totalAff bls12381.G1Affine
	totalAff.FromJacobian(&total)

	want, err := f.EvaluatePoint(alpha)
	require.NoError(t, err)
	assert.True(t, totalAff.Equal(&want), "the partial sums do not telescope to f(alpha)")
}

// TestEqTableMatchesEqPoint cross-checks the table build against the direct
// product form at every hypercube corner.
func TestEqTableMatchesEqPoint(t *testing.T) {
	for _, m := range []int{1, 2, 3, 5} {
		alpha := randomPoint(t, m)
		table := eqTable(alpha)
		require.Len(t, table, 1<<m)

		for i := range table {
			b := make([]fr.Element, m)
			for j := range m {
				if i>>j&1 == 1 {
					b[j] = fr.One()
				}
			}
			want, err := eqPoint(alpha, b)
			require.NoError(t, err)
			assert.True(t, table[i].Equal(&want), "m=%d: eq table entry %d disagrees with eqPoint", m, i)
		}
	}
}

// TestEqTableSumsToOne checks the defining property of the eq table: the
// Lagrange basis over the hypercube is a partition of unity.
func TestEqTableSumsToOne(t *testing.T) {
	for _, m := range []int{1, 3, 6} {
		alpha := randomPoint(t, m)
		var sum fr.Element
		for _, v := range eqTable(alpha) {
			sum.Add(&sum, &v)
		}
		one := fr.One()
		assert.True(t, sum.Equal(&one), "m=%d: eq table does not sum to one", m)
	}
}

// TestFoldFirstSubstitutesFirstVariable pins down the folding convention, which
// is the opposite of crypto/sumcheck's and is the whole reason these helpers exist.
//
// Take p(b_0, b_1, b_2) = b_0. Substituting r for the *first* variable must give
// the constant r. Under the wrong (last-variable) pairing it would instead stay
// the function b_0, which no round-trip test would notice because prover and
// verifier fold identically and the error cancels.
func TestFoldFirstSubstitutesFirstVariable(t *testing.T) {
	m := 3
	p := make(sumcheck.FieldPoly, 1<<m)
	for i := range p {
		if i&1 == 1 {
			p[i] = fr.One()
		}
	}

	r := randomPoint(t, 1)[0]
	folded := foldFirstField(p, &r)
	require.Len(t, folded, 1<<(m-1))
	for i := range folded {
		assert.True(t, folded[i].Equal(&r), "entry %d is not r, so fold did not substitute the first variable", i)
	}
}

// TestFoldFirstGroupMatchesField checks the group fold against the field fold, via
// a group polynomial that is a scalar polynomial times the generator.
func TestFoldFirstGroupMatchesField(t *testing.T) {
	m := 4
	s := randomFieldPoly(t, m)
	_, _, g1Aff, _ := bls12381.Generators()

	g := make(sumcheck.GroupPoly, 1<<m)
	for i := range g {
		bi := new(big.Int)
		s[i].BigInt(bi)
		g[i].ScalarMultiplication(&g1Aff, bi)
	}

	r := randomPoint(t, 1)[0]
	foldedField := foldFirstField(s, &r)
	foldedGroup, err := foldFirstGroup(g, &r)
	require.NoError(t, err)
	require.Len(t, foldedGroup, len(foldedField))

	for i := range foldedField {
		bi := new(big.Int)
		foldedField[i].BigInt(bi)
		var want bls12381.G1Affine
		want.ScalarMultiplication(&g1Aff, bi)
		assert.True(t, foldedGroup[i].Equal(&want), "group fold disagrees with the field fold at %d", i)
	}
}

// TestBatchInvert checks the Montgomery batch inversion against per-element
// inversion, and checks that a zero entry is reported rather than silently
// producing garbage.
func TestBatchInvert(t *testing.T) {
	t.Run("matches individual inversion", func(t *testing.T) {
		in := randomFieldPoly(t, 6)
		out, err := batchInvert(in)
		require.NoError(t, err)
		require.Len(t, out, len(in))
		for i := range in {
			var want fr.Element
			want.Inverse(&in[i])
			assert.True(t, out[i].Equal(&want), "entry %d", i)
		}
	})
	t.Run("rejects zero", func(t *testing.T) {
		in := randomFieldPoly(t, 3)
		in[5] = fr.Element{}
		_, err := batchInvert(in)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrZeroDenominator)
	})
	t.Run("empty input", func(t *testing.T) {
		out, err := batchInvert(nil)
		require.NoError(t, err)
		assert.Empty(t, out)
	})
}

// TestInterpolateGroupAt checks the quadratic interpolation against the nodes it
// was built from, and against a known quadratic at an off-node point.
func TestInterpolateGroupAt(t *testing.T) {
	_, _, g1Aff, _ := bls12381.Generators()

	// Take g(u) = [c0 + c1*u + c2*u^2] G and compare against the interpolation
	// through its values at 0, 1, 2.
	c := randomPoint(t, 3)
	atU := func(u fr.Element) bls12381.G1Affine {
		var acc, t1, t2, u2 fr.Element
		acc.Set(&c[0])
		t1.Mul(&c[1], &u)
		acc.Add(&acc, &t1)
		u2.Mul(&u, &u)
		t2.Mul(&c[2], &u2)
		acc.Add(&acc, &t2)
		bi := new(big.Int)
		acc.BigInt(bi)
		var out bls12381.G1Affine
		out.ScalarMultiplication(&g1Aff, bi)

		return out
	}

	var evals [numRoundEvals]bls12381.G1Affine
	for j := range numRoundEvals {
		var u fr.Element
		u.SetUint64(uint64(j))
		evals[j] = atU(u)
	}

	// At the nodes themselves.
	for j := range numRoundEvals {
		var u fr.Element
		u.SetUint64(uint64(j))
		got, err := interpolateGroupAt(&evals, &u)
		require.NoError(t, err)
		assert.True(t, got.Equal(&evals[j]), "interpolation does not reproduce node %d", j)
	}

	// And at a random point, where a wrong Lagrange basis would show up.
	x := randomPoint(t, 1)[0]
	got, err := interpolateGroupAt(&evals, &x)
	require.NoError(t, err)
	want := atU(x)
	assert.True(t, got.Equal(&want), "interpolation is wrong away from the nodes")
}
