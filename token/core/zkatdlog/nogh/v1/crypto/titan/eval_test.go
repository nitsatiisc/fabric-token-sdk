/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"strconv"
	"testing"

	mathlib "github.com/IBM/mathlib"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/require"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/rp/csp"
	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/sumcheck"
)

// evalFixture is a committed polynomial with everything needed to prove and
// verify an evaluation against it.
type evalFixture struct {
	curve *mathlib.Curve
	f     sumcheck.FieldPoly
	gens  []bls12381.G1Affine
	dom   *Domain
	c     *Commitment
	hint  *FieldOpeningHint
	cg    *Generators
	alpha []fr.Element
	m     int
}

// newEvalFixture commits a random m-variable polynomial and picks a random point.
//
// The domain is one bit larger than the group multilinear, the smallest rate below
// 1; k = 0 keeps one codeword point per leaf. Neither choice affects the two legs,
// which touch the Pedersen tier and the sum-check, not the coset structure.
func newEvalFixture(t *testing.T, m int) *evalFixture {
	t.Helper()

	f := randomFieldPoly(t, m)
	_, numCols := matrixShape(m)
	gens := testGenerators(t, numCols)

	rowVars := m - m/2
	dom, err := NewDomain(rowVars + 1)
	require.NoError(t, err)

	c, hint, err := CommitField(f, gens, dom, 0)
	require.NoError(t, err)

	curve := testCurve()
	cg, err := NewGenerators(curve, gens)
	require.NoError(t, err)

	return &evalFixture{
		curve: curve,
		f:     f,
		gens:  gens,
		dom:   dom,
		c:     c,
		hint:  hint,
		cg:    cg,
		alpha: randomPoint(t, m),
		m:     m,
	}
}

// TestEvalRoundTripAndMatchesDirectEvaluation is the decisive test, and it is two
// assertions that must both hold.
//
// Verification accepting is necessary but nowhere near sufficient: eq(alpha, .)
// factorizes over *any* split of the variables, so a prover that swapped the row
// and column halves would produce a perfectly self-consistent proof -- of a
// different polynomial's evaluation. The second assertion, against
// FieldPoly.EvaluatePoint computed independently in crypto/sumcheck, is what
// catches that. See the note on splitAlpha.
func TestEvalRoundTripAndMatchesDirectEvaluation(t *testing.T) {
	for m := 2; m <= 12; m++ {
		t.Run(varName(m), func(t *testing.T) {
			fx := newEvalFixture(t, m)

			proof, sigma, err := fx.hint.Eval(fx.curve, fx.cg, fx.alpha)
			require.NoError(t, err)
			require.NotNil(t, proof)

			want, err := fx.f.EvaluatePoint(fx.alpha)
			require.NoError(t, err)
			require.True(t, sigma.Equal(&want),
				"sigma must be f(alpha) computed independently: got %s want %s", sigma.String(), want.String())

			opening, err := VerifyEval(fx.curve, fx.c, fx.cg, fx.alpha, sigma, proof)
			require.NoError(t, err)
			require.NotNil(t, opening)
			require.Len(t, opening.R, m-m/2, "the residual point is over the row half")
		})
	}
}

// TestEvalSigmaPartialIsTheFoldedCommitment checks the identity the whole
// construction pivots on: the element leg 1 outputs is also the Pedersen
// commitment leg 2 opens.
//
// Both are computed here from scratch, two different ways, to show they coincide
// for a structural reason rather than by construction:
//
//	as an evaluation:  sum_j eq(alphaRow, <j>) * G_j
//	as a commitment:   MSM(gens, fold(rows, alphaRow))
func TestEvalSigmaPartialIsTheFoldedCommitment(t *testing.T) {
	for _, m := range []int{2, 3, 5, 8} {
		t.Run(varName(m), func(t *testing.T) {
			fx := newEvalFixture(t, m)
			proof, _, err := fx.hint.Eval(fx.curve, fx.cg, fx.alpha)
			require.NoError(t, err)

			_, alphaRow := splitAlpha(fx.alpha, m)

			// As an evaluation of the group multilinear G.
			asEval, err := msm(fx.hint.G, eqTable(alphaRow))
			require.NoError(t, err)
			require.True(t, asEval.Equal(&proof.SigmaPartial),
				"SigmaPartial must equal sum_j eq(alphaRow,<j>)*G_j")

			// As a Pedersen commitment to the folded row vector.
			a, err := foldRows(fx.hint.Rows, fx.hint.NumRows, fx.hint.NumCols, alphaRow)
			require.NoError(t, err)
			asComm, err := msm(fx.gens[:fx.hint.NumCols], a)
			require.NoError(t, err)
			require.True(t, asComm.Equal(&proof.SigmaPartial),
				"SigmaPartial must equal MSM(gens, fold(rows, alphaRow))")

			// And the folded row must open to sigma under eq(alphaCol, .).
			alphaCol, _ := splitAlpha(fx.alpha, m)
			got, err := innerProduct(eqTable(alphaCol), a)
			require.NoError(t, err)
			want, err := fx.f.EvaluatePoint(fx.alpha)
			require.NoError(t, err)
			require.True(t, got.Equal(&want))
		})
	}
}

// TestEvalRejectsWrongSigma checks the most basic soundness requirement.
func TestEvalRejectsWrongSigma(t *testing.T) {
	fx := newEvalFixture(t, 6)
	proof, sigma, err := fx.hint.Eval(fx.curve, fx.cg, fx.alpha)
	require.NoError(t, err)

	var bad fr.Element
	one := fr.One()
	bad.Add(&sigma, &one)
	require.False(t, bad.Equal(&sigma), "the tampered value must actually differ")

	_, err = VerifyEval(fx.curve, fx.c, fx.cg, fx.alpha, bad, proof)
	require.Error(t, err)
}

// TestEvalRejectsTamperedSigmaPartial checks that the element joining the two legs
// cannot be moved.
//
// SigmaPartial is the only thing both legs read, so tampering with it must break
// at least one of them -- and this asserts it breaks the *row* leg, since that is
// the leg for which SigmaPartial is the asserted sum.
func TestEvalRejectsTamperedSigmaPartial(t *testing.T) {
	fx := newEvalFixture(t, 6)
	proof, sigma, err := fx.hint.Eval(fx.curve, fx.cg, fx.alpha)
	require.NoError(t, err)

	tampered := *proof
	var j bls12381.G1Jac
	j.FromAffine(&proof.SigmaPartial)
	j.AddAssign(&j) // doubling: certainly a different point
	tampered.SigmaPartial.FromJacobian(&j)
	require.False(t, tampered.SigmaPartial.Equal(&proof.SigmaPartial))

	_, err = VerifyEval(fx.curve, fx.c, fx.cg, fx.alpha, sigma, &tampered)
	require.ErrorIs(t, err, ErrSumMismatch)
}

// TestEvalRejectsTamperedRowLeg checks a modified sum-check round message.
func TestEvalRejectsTamperedRowLeg(t *testing.T) {
	fx := newEvalFixture(t, 6)
	proof, sigma, err := fx.hint.Eval(fx.curve, fx.cg, fx.alpha)
	require.NoError(t, err)

	rounds := make([][numRoundEvals]bls12381.G1Affine, len(proof.RowProof.Rounds))
	copy(rounds, proof.RowProof.Rounds)
	var j bls12381.G1Jac
	j.FromAffine(&rounds[0][0])
	j.AddAssign(&j)
	rounds[0][0].FromJacobian(&j)

	tampered := *proof
	tampered.RowProof = &GroupSumCheckProof{Rounds: rounds}

	_, err = VerifyEval(fx.curve, fx.c, fx.cg, fx.alpha, sigma, &tampered)
	require.Error(t, err)
}

// TestEvalRejectsTamperedColumnLeg checks a modified CSP proof.
func TestEvalRejectsTamperedColumnLeg(t *testing.T) {
	fx := newEvalFixture(t, 6)
	proof, sigma, err := fx.hint.Eval(fx.curve, fx.cg, fx.alpha)
	require.NoError(t, err)

	require.NotEmpty(t, proof.ColProof.Left)
	tamperedCol := *proof.ColProof
	left := make([]*mathlib.G1, len(proof.ColProof.Left))
	copy(left, proof.ColProof.Left)
	left[0] = left[0].Copy()
	left[0].Add(left[0])
	tamperedCol.Left = left

	tampered := *proof
	tampered.ColProof = &tamperedCol

	_, err = VerifyEval(fx.curve, fx.c, fx.cg, fx.alpha, sigma, &tampered)
	require.Error(t, err)
}

// TestEvalRejectsPermutedAlpha checks that the proof is bound to the point.
//
// Reversing alpha is the sharp case rather than a random re-draw: a reversed point
// has the same multiset of coordinates, so anything that treated alpha as an
// unordered set -- or that got the row/column halves the wrong way round -- would
// still accept.
func TestEvalRejectsPermutedAlpha(t *testing.T) {
	fx := newEvalFixture(t, 6)
	proof, sigma, err := fx.hint.Eval(fx.curve, fx.cg, fx.alpha)
	require.NoError(t, err)

	reversed := make([]fr.Element, len(fx.alpha))
	for i := range fx.alpha {
		reversed[i] = fx.alpha[len(fx.alpha)-1-i]
	}

	_, err = VerifyEval(fx.curve, fx.c, fx.cg, reversed, sigma, proof)
	require.Error(t, err)
}

// TestEvalRejectsProofForAnotherPolynomial checks that a well-formed proof for a
// different polynomial does not verify against this commitment.
//
// Note what this does and does not currently catch. The two legs are internally
// consistent for the other polynomial, so they agree with each other -- what
// breaks is that the claimed sigma is the other polynomial's. That is caught. A
// prover who *also* claims the other polynomial's sigma is not caught by this
// verifier, because closing that needs the oracle query against the committed
// root, which is step 5. See the note on VerifyEval.
func TestEvalRejectsProofForAnotherPolynomial(t *testing.T) {
	fx := newEvalFixture(t, 6)
	other := newEvalFixture(t, 6)

	proof, _, err := other.hint.Eval(other.curve, other.cg, fx.alpha)
	require.NoError(t, err)

	mySigma, err := fx.f.EvaluatePoint(fx.alpha)
	require.NoError(t, err)

	_, err = VerifyEval(fx.curve, fx.c, fx.cg, fx.alpha, mySigma, proof)
	require.Error(t, err)
}

// TestEvalLegIndependence is the test that matters most for a two-leg argument.
//
// A two-leg proof goes unsound in a characteristic way: each leg verifies on its
// own, but they describe different polynomials, because nothing forces them to
// agree. Here the legs are grafted across two commitments in both directions. Both
// grafts must fail, and they must fail *because* SigmaPartial is shared: whichever
// SigmaPartial the graft carries, the other leg was built against a different one.
//
// If this test ever passes with a swapped leg accepted, the two legs are not
// actually tied together and the scheme is broken regardless of what the
// round-trip test says.
func TestEvalLegIndependence(t *testing.T) {
	const m = 6
	a := newEvalFixture(t, m)
	b := newEvalFixture(t, m)

	// Same point for both, so the only difference is the polynomial.
	alpha := a.alpha
	b.alpha = alpha

	pa, sigmaA, err := a.hint.Eval(a.curve, a.cg, alpha)
	require.NoError(t, err)
	pb, sigmaB, err := b.hint.Eval(b.curve, b.cg, alpha)
	require.NoError(t, err)

	require.False(t, sigmaA.Equal(&sigmaB), "the two fixtures must differ")
	require.False(t, pa.SigmaPartial.Equal(&pb.SigmaPartial),
		"the two fixtures must have different partial evaluations")

	t.Run("A's row leg with B's column leg", func(t *testing.T) {
		// Carrying A's SigmaPartial: the row leg checks out, the column leg was
		// built against B's and must not.
		graft := &EvalProof{
			SigmaPartial: pa.SigmaPartial,
			RowProof:     pa.RowProof,
			ColProof:     pb.ColProof,
		}
		_, err := VerifyEval(a.curve, a.c, a.cg, alpha, sigmaA, graft)
		require.Error(t, err)
		require.Contains(t, err.Error(), "column leg", "the column leg is the one that should fail")
	})

	t.Run("B's row leg with A's column leg", func(t *testing.T) {
		graft := &EvalProof{
			SigmaPartial: pb.SigmaPartial,
			RowProof:     pb.RowProof,
			ColProof:     pa.ColProof,
		}
		_, err := VerifyEval(b.curve, b.c, b.cg, alpha, sigmaB, graft)
		require.Error(t, err)
		require.Contains(t, err.Error(), "column leg")
	})

	t.Run("A's column leg under B's SigmaPartial breaks the row leg", func(t *testing.T) {
		// The mirror image: carry B's row leg but A's SigmaPartial, so the row
		// leg's asserted sum no longer matches its own messages.
		graft := &EvalProof{
			SigmaPartial: pa.SigmaPartial,
			RowProof:     pb.RowProof,
			ColProof:     pa.ColProof,
		}
		_, err := VerifyEval(a.curve, a.c, a.cg, alpha, sigmaA, graft)
		require.Error(t, err)
		require.Contains(t, err.Error(), "row leg", "the row leg is the one that should fail")
	})
}

// TestEvalValidation covers the input checks.
func TestEvalValidation(t *testing.T) {
	fx := newEvalFixture(t, 4)
	proof, sigma, err := fx.hint.Eval(fx.curve, fx.cg, fx.alpha)
	require.NoError(t, err)

	t.Run("nil hint", func(t *testing.T) {
		var h *FieldOpeningHint
		_, _, err := h.Eval(fx.curve, fx.cg, fx.alpha)
		require.ErrorIs(t, err, ErrNilTree)
	})

	t.Run("wrong alpha length on prove", func(t *testing.T) {
		_, _, err := fx.hint.Eval(fx.curve, fx.cg, fx.alpha[:fx.m-1])
		require.ErrorIs(t, err, ErrNumVarsMismatch)
	})

	t.Run("too few generators on prove", func(t *testing.T) {
		short, err := NewGenerators(fx.curve, fx.gens[:fx.hint.NumCols-1])
		require.NoError(t, err)
		_, _, err = fx.hint.Eval(fx.curve, short, fx.alpha)
		require.ErrorIs(t, err, ErrInsufficientGenerators)
	})

	t.Run("nil generators", func(t *testing.T) {
		_, _, err := fx.hint.Eval(fx.curve, nil, fx.alpha)
		require.ErrorIs(t, err, ErrInsufficientGenerators)
	})

	t.Run("nil commitment", func(t *testing.T) {
		_, err := VerifyEval(fx.curve, nil, fx.cg, fx.alpha, sigma, proof)
		require.ErrorIs(t, err, ErrNilElement)
	})

	t.Run("nil proof", func(t *testing.T) {
		_, err := VerifyEval(fx.curve, fx.c, fx.cg, fx.alpha, sigma, nil)
		require.ErrorIs(t, err, ErrNilProof)
	})

	t.Run("missing row leg", func(t *testing.T) {
		_, err := VerifyEval(fx.curve, fx.c, fx.cg, fx.alpha, sigma, &EvalProof{ColProof: proof.ColProof})
		require.ErrorIs(t, err, ErrNilProof)
	})

	t.Run("missing column leg", func(t *testing.T) {
		_, err := VerifyEval(fx.curve, fx.c, fx.cg, fx.alpha, sigma, &EvalProof{RowProof: proof.RowProof})
		require.ErrorIs(t, err, ErrNilProof)
	})

	t.Run("alpha one shorter is rejected, though not by the shape check", func(t *testing.T) {
		// fx.m = 4 has 4 rows, and so does m = 3 -- the ambiguity checkShape
		// documents. So a 3-coordinate alpha passes the shape check and is caught
		// downstream instead, by the row leg: the split differs, so the challenges
		// and round messages no longer line up. Rejected either way, but asserting
		// ErrNumVarsMismatch here would be asserting the wrong mechanism.
		_, err := VerifyEval(fx.curve, fx.c, fx.cg, fx.alpha[:fx.m-1], sigma, proof)
		require.ErrorIs(t, err, ErrRoundCheckFailed)
	})

	t.Run("alpha of a shape the commitment cannot have", func(t *testing.T) {
		// Two shorter, which lands on a different row count and so is caught by
		// the shape check itself.
		_, err := VerifyEval(fx.curve, fx.c, fx.cg, fx.alpha[:fx.m-2], sigma, proof)
		require.ErrorIs(t, err, ErrNumVarsMismatch)
	})

	t.Run("empty alpha", func(t *testing.T) {
		_, err := VerifyEval(fx.curve, fx.c, fx.cg, nil, sigma, proof)
		require.ErrorIs(t, err, ErrNumVarsMismatch)
	})

	t.Run("too few generators on verify", func(t *testing.T) {
		short, err := NewGenerators(fx.curve, fx.gens[:fx.hint.NumCols-1])
		require.NoError(t, err)
		_, err = VerifyEval(fx.curve, fx.c, short, fx.alpha, sigma, proof)
		require.ErrorIs(t, err, ErrInsufficientGenerators)
	})

	t.Run("nil curve defaults", func(t *testing.T) {
		// A nil curve must fall back rather than panic, and the fallback must be
		// self-consistent across prove and verify. The cache has to be built on
		// the fallback curve: Generators is curve-bound on purpose, so passing a
		// cache from another variant is the misuse the next subtest covers, not
		// this one.
		cg, err := NewGenerators(nil, fx.gens[:fx.hint.NumCols])
		require.NoError(t, err)

		p, s, err := fx.hint.Eval(nil, cg, fx.alpha)
		require.NoError(t, err)
		_, err = VerifyEval(nil, fx.c, cg, fx.alpha, s, p)
		require.NoError(t, err)
	})

	t.Run("a cache from another curve variant is rejected", func(t *testing.T) {
		// fx.cg was built on testCurve(); proving against the bridge default is
		// a different curve ID, which csp would reject far downstream. prefix
		// names it here instead.
		_, _, err := fx.hint.Eval(nil, fx.cg, fx.alpha)
		require.ErrorIs(t, err, ErrNilCurve)
		require.Contains(t, err.Error(), "rebuild with NewGenerators")
	})
}

// TestCheckShape pins the shape consistency check, and documents the ambiguity
// that is the reason m is not derived from the commitment.
func TestCheckShape(t *testing.T) {
	t.Run("accepts the matching m", func(t *testing.T) {
		for m := 1; m <= 16; m++ {
			rows, cols := matrixShape(m)
			numVars, err := numVarsOf(rows)
			require.NoError(t, err)

			gotCols, err := checkShape(&Commitment{NumVars: numVars}, m)
			require.NoError(t, err)
			require.Equal(t, cols, gotCols, "m=%d", m)
		}
	})

	t.Run("the row count does not determine m", func(t *testing.T) {
		// This is why checkShape takes m rather than deriving it. Every row count
		// is produced by two different m -- an odd one and the next even one --
		// which differ only in their column count. Any function claiming to
		// recover m from the commitment alone is wrong, and this pins the reason
		// so the claim is not re-made.
		for s := 1; s <= 8; s++ {
			odd, even := 2*s-1, 2*s
			rowsOdd, colsOdd := matrixShape(odd)
			rowsEven, colsEven := matrixShape(even)
			require.Equal(t, rowsOdd, rowsEven, "m=%d and m=%d must share a row count", odd, even)
			require.NotEqual(t, colsOdd, colsEven, "and differ only in columns")

			// So both are accepted against the same commitment.
			numVars, err := numVarsOf(rowsOdd)
			require.NoError(t, err)
			c := &Commitment{NumVars: numVars}
			gotOdd, err := checkShape(c, odd)
			require.NoError(t, err)
			gotEven, err := checkShape(c, even)
			require.NoError(t, err)
			require.NotEqual(t, gotOdd, gotEven)
		}
	})

	t.Run("rejects a mismatched shape", func(t *testing.T) {
		// m = 6 has 8 rows, so a commitment over 2^3 rows is right and 2^5 is not.
		_, err := checkShape(&Commitment{NumVars: 3}, 6)
		require.NoError(t, err)
		_, err = checkShape(&Commitment{NumVars: 5}, 6)
		require.ErrorIs(t, err, ErrNumVarsMismatch)
	})

	t.Run("rejects degenerate input", func(t *testing.T) {
		_, err := checkShape(&Commitment{NumVars: 1}, 0)
		require.ErrorIs(t, err, ErrNumVarsMismatch)
		_, err = checkShape(&Commitment{NumVars: -1}, 2)
		require.ErrorIs(t, err, ErrNumVarsMismatch)
		_, err = checkShape(&Commitment{NumVars: 1 << 20}, 2)
		require.ErrorIs(t, err, ErrNumVarsMismatch)
	})
}

// TestEvalGroupRoundTrip checks the group construction's single leg.
func TestEvalGroupRoundTrip(t *testing.T) {
	for _, m := range []int{1, 2, 3, 5, 8} {
		t.Run(varName(m), func(t *testing.T) {
			curve := testCurve()
			G := randomGroupPoly(t, m)
			dom, err := NewDomain(m + 1)
			require.NoError(t, err)
			c, hint, err := CommitGroup(G, dom, 0)
			require.NoError(t, err)

			alpha := randomPoint(t, m)
			proof, sigma, err := hint.EvalGroup(curve, alpha)
			require.NoError(t, err)

			// Independent cross-check, as for the field case.
			want, err := G.EvaluatePoint(alpha)
			require.NoError(t, err)
			require.True(t, sigma.Equal(&want), "sigma must be G(alpha) computed independently")

			opening, err := VerifyEvalGroup(curve, c, alpha, &sigma, proof)
			require.NoError(t, err)
			require.Len(t, opening.R, m)
		})
	}
}

func TestEvalGroupNegatives(t *testing.T) {
	const m = 5
	curve := testCurve()
	G := randomGroupPoly(t, m)
	dom, err := NewDomain(m + 1)
	require.NoError(t, err)
	c, hint, err := CommitGroup(G, dom, 0)
	require.NoError(t, err)
	alpha := randomPoint(t, m)
	proof, sigma, err := hint.EvalGroup(curve, alpha)
	require.NoError(t, err)

	t.Run("wrong sigma", func(t *testing.T) {
		var bad bls12381.G1Affine
		var j bls12381.G1Jac
		j.FromAffine(&sigma)
		j.AddAssign(&j)
		bad.FromJacobian(&j)
		_, err := VerifyEvalGroup(curve, c, alpha, &bad, proof)
		require.ErrorIs(t, err, ErrSumMismatch)
	})

	t.Run("wrong alpha length", func(t *testing.T) {
		_, err := VerifyEvalGroup(curve, c, alpha[:m-1], &sigma, proof)
		require.ErrorIs(t, err, ErrNumVarsMismatch)
	})

	t.Run("nil sigma", func(t *testing.T) {
		_, err := VerifyEvalGroup(curve, c, alpha, nil, proof)
		require.ErrorIs(t, err, ErrNilElement)
	})

	t.Run("nil proof", func(t *testing.T) {
		_, err := VerifyEvalGroup(curve, c, alpha, &sigma, nil)
		require.ErrorIs(t, err, ErrNilProof)
	})

	t.Run("nil commitment", func(t *testing.T) {
		_, err := VerifyEvalGroup(curve, c, alpha, &sigma, &GroupEvalProof{})
		require.ErrorIs(t, err, ErrNilProof)
	})

	t.Run("nil hint", func(t *testing.T) {
		var h *GroupOpeningHint
		_, _, err := h.EvalGroup(curve, alpha)
		require.ErrorIs(t, err, ErrNilTree)
	})
}

// TestFoldRowsMatchesDirectRestriction checks the folded row vector against a
// direct restriction of the multilinear.
//
// a[c] must be the value of f restricted at the row half, read as a function of
// the column variables -- i.e. the multilinear in the column variables whose table
// is a. Evaluating that at alphaCol must give f(alpha).
func TestFoldRowsMatchesDirectRestriction(t *testing.T) {
	for _, m := range []int{2, 3, 4, 7} {
		t.Run(varName(m), func(t *testing.T) {
			f := randomFieldPoly(t, m)
			numRows, numCols := matrixShape(m)
			alpha := randomPoint(t, m)
			alphaCol, alphaRow := splitAlpha(alpha, m)

			a, err := foldRows(f, numRows, numCols, alphaRow)
			require.NoError(t, err)
			require.Len(t, a, numCols)

			got, err := sumcheck.FieldPoly(a).EvaluatePoint(alphaCol)
			require.NoError(t, err)
			want, err := f.EvaluatePoint(alpha)
			require.NoError(t, err)
			require.True(t, got.Equal(&want),
				"the folded row must be f restricted at the row half")
		})
	}
}

func TestFoldRowsValidation(t *testing.T) {
	f := randomFieldPoly(t, 4)
	_, err := foldRows(f, 3, 3, randomPoint(t, 2))
	require.ErrorIs(t, err, ErrNumVarsMismatch)

	_, err = foldRows(f, 4, 4, randomPoint(t, 1))
	require.ErrorIs(t, err, ErrNumVarsMismatch)
}

func TestInnerProductValidation(t *testing.T) {
	_, err := innerProduct(randomPoint(t, 2), randomPoint(t, 3))
	require.ErrorIs(t, err, ErrNumVarsMismatch)
}

// varName labels a subtest by its variable count.
func varName(m int) string { return "m=" + strconv.Itoa(m) }

// TestGenerators covers the cached-generator type, including the two ways it can
// be misused.
func TestGenerators(t *testing.T) {
	curve := testCurve()
	gens := testGenerators(t, 8)

	t.Run("round trip", func(t *testing.T) {
		g, err := NewGenerators(curve, gens)
		require.NoError(t, err)
		require.Equal(t, 8, g.Len())

		affine, math, err := g.prefix(curve, 4)
		require.NoError(t, err)
		require.Len(t, affine, 4)
		require.Len(t, math, 4)
		for i := range affine {
			var back bls12381.G1Affine
			_, err := back.SetBytes(math[i].Compressed())
			require.NoError(t, err)
			require.True(t, back.Equal(&affine[i]), "the two forms must agree at %d", i)
		}
	})

	t.Run("nil curve defaults", func(t *testing.T) {
		g, err := NewGenerators(nil, gens)
		require.NoError(t, err)
		require.Equal(t, 8, g.Len())
	})

	t.Run("empty is rejected", func(t *testing.T) {
		_, err := NewGenerators(curve, nil)
		require.ErrorIs(t, err, ErrInsufficientGenerators)
	})

	t.Run("infinity is rejected", func(t *testing.T) {
		bad := make([]bls12381.G1Affine, len(gens))
		copy(bad, gens)
		bad[3].SetInfinity()
		_, err := NewGenerators(curve, bad)
		require.ErrorIs(t, err, ErrPointAtInfinity)
	})

	t.Run("nil receiver", func(t *testing.T) {
		var g *Generators
		require.Zero(t, g.Len())
		_, _, err := g.prefix(curve, 1)
		require.ErrorIs(t, err, ErrInsufficientGenerators)
	})

	t.Run("too short", func(t *testing.T) {
		g, err := NewGenerators(curve, gens)
		require.NoError(t, err)
		_, _, err = g.prefix(curve, 9)
		require.ErrorIs(t, err, ErrInsufficientGenerators)
	})

	t.Run("a cache built for another curve is rejected", func(t *testing.T) {
		// The failure this guards against is nasty precisely because it is not a
		// soundness failure: csp checks element curve IDs, so a cache converted
		// onto one BLS12-381 variant and used on another is rejected deep inside
		// validation with a message about element curves. Catching it here names
		// the actual mistake.
		g, err := NewGenerators(mathlib.Curves[mathlib.BLS12_381_BBS_GURVY], gens)
		require.NoError(t, err)
		_, _, err = g.prefix(mathlib.Curves[mathlib.BLS12_381_BBS], 4)
		require.ErrorIs(t, err, ErrNilCurve)
		require.Contains(t, err.Error(), "rebuild with NewGenerators")
	})
}

// TestEvalAffineMatchesCached checks the convenience overloads agree with the
// cached path -- the proof must not depend on how the generators got converted.
func TestEvalAffineMatchesCached(t *testing.T) {
	fx := newEvalFixture(t, 6)

	_, sigmaAffine, err := fx.hint.EvalAffine(fx.curve, fx.gens, fx.alpha)
	require.NoError(t, err)
	_, sigmaCached, err := fx.hint.Eval(fx.curve, fx.cg, fx.alpha)
	require.NoError(t, err)
	require.True(t, sigmaAffine.Equal(&sigmaCached))

	// A proof from either path must verify through either path.
	proofAffine, sigma, err := fx.hint.EvalAffine(fx.curve, fx.gens, fx.alpha)
	require.NoError(t, err)
	_, err = VerifyEvalAffine(fx.curve, fx.c, fx.gens, fx.alpha, sigma, proofAffine)
	require.NoError(t, err)
	_, err = VerifyEval(fx.curve, fx.c, fx.cg, fx.alpha, sigma, proofAffine)
	require.NoError(t, err)

	proofCached, sigma2, err := fx.hint.Eval(fx.curve, fx.cg, fx.alpha)
	require.NoError(t, err)
	_, err = VerifyEvalAffine(fx.curve, fx.c, fx.gens, fx.alpha, sigma2, proofCached)
	require.NoError(t, err)
}

func TestEvalAffineValidation(t *testing.T) {
	fx := newEvalFixture(t, 4)

	t.Run("nil hint", func(t *testing.T) {
		var h *FieldOpeningHint
		_, _, err := h.EvalAffine(fx.curve, fx.gens, fx.alpha)
		require.ErrorIs(t, err, ErrNilTree)
	})

	t.Run("empty generators on prove", func(t *testing.T) {
		_, _, err := fx.hint.EvalAffine(fx.curve, nil, fx.alpha)
		require.ErrorIs(t, err, ErrInsufficientGenerators)
	})

	t.Run("empty generators on verify", func(t *testing.T) {
		proof, sigma, err := fx.hint.Eval(fx.curve, fx.cg, fx.alpha)
		require.NoError(t, err)
		_, err = VerifyEvalAffine(fx.curve, fx.c, nil, fx.alpha, sigma, proof)
		require.ErrorIs(t, err, ErrInsufficientGenerators)
	})
}

// TestEvalTranscriptHeaderIsDistinct pins leg 2's domain separator as distinct from
// leg 1's.
//
// This exists because a mutation pass found it unguarded: replacing
// evalTranscriptHeader with DomainSeparator left the whole suite green. Nothing
// observable changes when both legs share a separator -- proofs still verify -- but
// the separation is what stops a CSP proof produced elsewhere in the tree from being
// replayed as a Titan column leg. So it has to be asserted directly; no round-trip
// or negative test can reach it.
func TestEvalTranscriptHeaderIsDistinct(t *testing.T) {
	require.NotEqual(t, DomainSeparator, evalTranscriptHeader,
		"leg 2 must not share leg 1's domain separator, or a row leg could be replayed as a column leg")
	require.NotEmpty(t, evalTranscriptHeader, "an empty separator separates nothing")

	// Pinned by value: changing it is a wire-compatibility break, so it should
	// require editing this line deliberately.
	require.Equal(t, "TitanEvalColumnLeg-v1", evalTranscriptHeader)
}

// TestEvalColumnLegRejectsForeignTranscript checks the separator does real work: a
// CSP proof over the identical statement but a different transcript header must not
// verify as a column leg.
func TestEvalColumnLegRejectsForeignTranscript(t *testing.T) {
	fx := newEvalFixture(t, 6)

	proof, sigma, err := fx.hint.Eval(fx.curve, fx.cg, fx.alpha)
	require.NoError(t, err)

	_, mgens, err := fx.cg.prefix(fx.curve, fx.hint.NumCols)
	require.NoError(t, err)

	alphaCol, alphaRow := splitAlpha(fx.alpha, fx.m)
	a, err := foldRows(fx.hint.Rows, fx.hint.NumRows, fx.hint.NumCols, alphaRow)
	require.NoError(t, err)

	st, err := columnStatement(fx.curve, mgens, eqTable(alphaCol), &proof.SigmaPartial, &sigma)
	require.NoError(t, err)

	witness, err := toMathZrSlice(a, fx.curve)
	require.NoError(t, err)

	// Same statement, same witness, only the header differs.
	foreign, err := csp.ProveLinearForm(st, witness, []byte(DomainSeparator))
	require.NoError(t, err)

	require.Error(t, verifyColumnLeg(fx.curve, mgens, eqTable(alphaCol), &proof.SigmaPartial, &sigma, foreign),
		"a proof under another transcript header must not verify as a column leg")

	// The honest header must still work, so the test is not just rejecting everything.
	honest, err := csp.ProveLinearForm(st, witness, []byte(evalTranscriptHeader))
	require.NoError(t, err)
	require.NoError(t, verifyColumnLeg(fx.curve, mgens, eqTable(alphaCol), &proof.SigmaPartial, &sigma, honest))
}
