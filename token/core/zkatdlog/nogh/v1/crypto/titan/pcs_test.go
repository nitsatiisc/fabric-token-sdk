/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"fmt"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/require"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/sumcheck"
)

// pcs.go is a facade, so these tests are mostly about what the facade GUARANTEES
// rather than about the cryptography underneath, which fold_test.go and eval_test.go
// already cover. Two guarantees carry the weight:
//
//   - a prover obtained from this API always commits WITH folding, so an opening
//     from it is binding rather than a bare reduction of the claim;
//   - a verifier obtained from this API refuses a commitment that cannot support
//     that, instead of reporting 1 for a proof that establishes nothing.
//
// Both are properties of the wiring, and both would be silently lost by an
// "optimisation" that swapped CommitFieldWithFold for CommitField.

// newFieldPCS builds a field setup with the default fold configuration, plus a
// matching statement and witness.
func newFieldPCS(t *testing.T, m int) (*FieldSetup, FieldStatement, FieldWitness) {
	t.Helper()

	_, numCols := matrixShape(m)
	setup, err := NewFieldSetup(m, testGenerators(t, numCols), testCurve(), FoldConfig{})
	require.NoError(t, err)

	return setup,
		FieldStatement{Alpha: randomPoint(t, m)},
		FieldWitness{Poly: randomFieldPoly(t, m)}
}

// newGroupPCS is the group counterpart.
func newGroupPCS(t *testing.T, m int) (*GroupSetup, GroupStatement, GroupWitness) {
	t.Helper()

	setup, err := NewGroupSetup(m, testCurve(), FoldConfig{})
	require.NoError(t, err)

	return setup,
		GroupStatement{Alpha: randomPoint(t, m)},
		GroupWitness{Poly: randomGroupPoly(t, m)}
}

// TestFieldPCSRoundTrip is the API in the shape callers will use it, across the
// variable counts the field path supports.
//
// m runs over multiples of 4 from 8 up. Two independent constraints produce that
// range: folding attaches to leg 1, which runs over rowVars = m - m/2 and must be
// even (so m divisible by 4), and the default 43 queries must be drawable from the
// folded domain's 2^(rowVars-Ell+LogRate) cosets (so rowVars >= 4, i.e. m >= 8). See
// fieldRowVars and TestFieldPCSRejectsUnsupportedNumVars.
func TestFieldPCSRoundTrip(t *testing.T) {
	t.Parallel()

	for _, m := range []int{8, 12, 16} {
		setup, st, w := newFieldPCS(t, m)

		p, err := NewFieldProver(setup, st, w)
		require.NoError(t, err)

		proof, sigma, err := p.Prove()
		require.NoError(t, err)

		v, err := NewFieldVerifier(setup, st, p.Commitment())
		require.NoError(t, err)
		require.Equal(t, 1, v.Verify(proof, sigma), "m=%d: honest proof rejected", m)
		require.NoError(t, v.VerifyErr(proof, sigma), "m=%d", m)
	}
}

// TestGroupPCSRoundTrip is the same for the group construction, which has no matrix
// split and so folds all m variables. That makes m=4 the smallest usable size rather
// than m=8: the folded domain is sized by m itself, so 64 cosets are available at
// m=4 and the default 43 queries fit.
func TestGroupPCSRoundTrip(t *testing.T) {
	t.Parallel()

	for _, m := range []int{4, 6, 8, 10} {
		setup, st, w := newGroupPCS(t, m)

		p, err := NewGroupProver(setup, st, w)
		require.NoError(t, err)

		proof, sigma, err := p.Prove()
		require.NoError(t, err)

		v, err := NewGroupVerifier(setup, st, p.Commitment())
		require.NoError(t, err)
		require.Equal(t, 1, v.Verify(proof, &sigma), "m=%d: honest proof rejected", m)
		require.NoError(t, v.VerifyErr(proof, &sigma), "m=%d", m)
	}
}

// TestPCSProverAlwaysFolds is the first of the two guarantees, and the reason this
// facade exists rather than callers wiring the commit stages themselves.
//
// Without a fold proof, VerifyEval only *reduces* the claim: leg 1 shows the sum
// follows from a residual opening, leg 2 opens SigmaPartial against the generators,
// and nothing ties either to the commitment. A proof from this API must therefore
// always carry one. If someone swaps CommitFieldWithFold for CommitField in
// NewFieldProver, the round trip above still passes -- an unfolded proof verifies
// happily against its own unfolded commitment -- and only this test notices.
func TestPCSProverAlwaysFolds(t *testing.T) {
	t.Parallel()

	t.Run("field", func(t *testing.T) {
		t.Parallel()

		setup, st, w := newFieldPCS(t, 8)
		p, err := NewFieldProver(setup, st, w)
		require.NoError(t, err)

		require.NotNil(t, p.Commitment().Cosets,
			"the commitment carries no coset oracle, so its openings cannot be binding")
		require.Equal(t, setup.FoldConfig(), p.Commitment().Cosets.Fold,
			"the commitment's fold configuration must be the setup's, or the verifier "+
				"checks a different number of queries than the setup advertises")

		proof, _, err := p.Prove()
		require.NoError(t, err)
		require.NotNil(t, proof.Fold, "proof carries no fold: the claim is reduced but not closed")
	})

	t.Run("group", func(t *testing.T) {
		t.Parallel()

		setup, st, w := newGroupPCS(t, 8)
		p, err := NewGroupProver(setup, st, w)
		require.NoError(t, err)

		require.NotNil(t, p.Commitment().Cosets)
		require.Equal(t, setup.FoldConfig(), p.Commitment().Cosets.Fold)

		proof, _, err := p.Prove()
		require.NoError(t, err)
		require.NotNil(t, proof.Fold)
	})
}

// TestPCSVerifierRejectsUnfoldedCommitment is the second guarantee, from the other
// direction: a Commitment whose Cosets is nil must be refused rather than verified
// against.
//
// Unexporting the commit stages removed the ability to *construct* one of these from
// outside the package, so the remaining sources are external: a commitment
// deserialized from the wire, or one produced by an older version of this package.
// Neither is hypothetical, and neither is something the facade can rule out by
// construction -- hence a check. The fixture below reaches for the unexported stage
// only because a test can; that is the shortest way to build the shape an external
// caller might hand us.
//
// It is also the case the 0/1 return cannot express, which is why it is caught at
// construction rather than reported as a failed verification.
func TestPCSVerifierRejectsUnfoldedCommitment(t *testing.T) {
	t.Parallel()

	t.Run("field", func(t *testing.T) {
		t.Parallel()

		const m = 8
		setup, st, w := newFieldPCS(t, m)

		// Commit WITHOUT folding, to produce the shape a stale or foreign
		// commitment would have.
		_, numCols := matrixShape(m)
		com, _, err := commitField(w.Poly, testGenerators(t, numCols), setup.dom, 0)
		require.NoError(t, err)
		require.Nil(t, com.Cosets, "this fixture is meant to be unfolded")

		_, err = NewFieldVerifier(setup, st, com)
		require.ErrorIs(t, err, ErrCosetOpeningInvalid,
			"an unfolded commitment was accepted; Verify would then report 1 for a "+
				"proof that does not bind the claim to the commitment")
	})

	t.Run("group", func(t *testing.T) {
		t.Parallel()

		setup, st, w := newGroupPCS(t, 8)

		com, _, err := commitGroup(w.Poly, setup.dom, 0)
		require.NoError(t, err)
		require.Nil(t, com.Cosets)

		_, err = NewGroupVerifier(setup, st, com)
		require.ErrorIs(t, err, ErrCosetOpeningInvalid)
	})
}

// TestPCSRejectsWrongValue is the basic soundness shape through the facade: the
// proof is honest, the commitment is honest, and only the claimed value is wrong.
func TestPCSRejectsWrongValue(t *testing.T) {
	t.Parallel()

	t.Run("field", func(t *testing.T) {
		t.Parallel()

		setup, st, w := newFieldPCS(t, 8)
		p, err := NewFieldProver(setup, st, w)
		require.NoError(t, err)
		proof, sigma, err := p.Prove()
		require.NoError(t, err)

		v, err := NewFieldVerifier(setup, st, p.Commitment())
		require.NoError(t, err)

		var wrong fr.Element
		wrong.SetOne()
		wrong.Add(&wrong, &sigma)
		require.Equal(t, 0, v.Verify(proof, wrong))
		require.Error(t, v.VerifyErr(proof, wrong))
	})

	t.Run("group", func(t *testing.T) {
		t.Parallel()

		setup, st, w := newGroupPCS(t, 8)
		p, err := NewGroupProver(setup, st, w)
		require.NoError(t, err)
		proof, sigma, err := p.Prove()
		require.NoError(t, err)

		v, err := NewGroupVerifier(setup, st, p.Commitment())
		require.NoError(t, err)

		var wrong bls12381.G1Affine
		wrong.Add(&sigma, &sigma)
		require.Equal(t, 0, v.Verify(proof, &wrong))
		require.Error(t, v.VerifyErr(proof, &wrong))
	})
}

// TestPCSRejectsForeignProof is the soundness case the facade must not weaken: a
// proof honestly produced for a DIFFERENT polynomial, checked against this
// commitment. It is the end-to-end form of the lying-prover test in fold_test.go.
func TestPCSRejectsForeignProof(t *testing.T) {
	t.Parallel()

	t.Run("field", func(t *testing.T) {
		t.Parallel()

		const m = 8
		setup, st, w := newFieldPCS(t, m)

		mine, err := NewFieldProver(setup, st, w)
		require.NoError(t, err)

		// Another polynomial, honestly committed and honestly proved at the same point.
		theirs, err := NewFieldProver(setup, st, FieldWitness{Poly: randomFieldPoly(t, m)})
		require.NoError(t, err)
		proof, sigma, err := theirs.Prove()
		require.NoError(t, err)

		// It verifies against its own commitment,
		theirV, err := NewFieldVerifier(setup, st, theirs.Commitment())
		require.NoError(t, err)
		require.Equal(t, 1, theirV.Verify(proof, sigma))

		// and must not against mine.
		myV, err := NewFieldVerifier(setup, st, mine.Commitment())
		require.NoError(t, err)
		require.Equal(t, 0, myV.Verify(proof, sigma),
			"a proof for another polynomial verified against this commitment")
	})

	t.Run("group", func(t *testing.T) {
		t.Parallel()

		const m = 8
		setup, st, w := newGroupPCS(t, m)

		mine, err := NewGroupProver(setup, st, w)
		require.NoError(t, err)

		theirs, err := NewGroupProver(setup, st, GroupWitness{Poly: randomGroupPoly(t, m)})
		require.NoError(t, err)
		proof, sigma, err := theirs.Prove()
		require.NoError(t, err)

		theirV, err := NewGroupVerifier(setup, st, theirs.Commitment())
		require.NoError(t, err)
		require.Equal(t, 1, theirV.Verify(proof, &sigma))

		myV, err := NewGroupVerifier(setup, st, mine.Commitment())
		require.NoError(t, err)
		require.Equal(t, 0, myV.Verify(proof, &sigma),
			"a proof for another polynomial verified against this commitment")
	})
}

// TestPCSRejectsWrongPoint pins that the statement is part of what is checked: a
// proof for one point must not verify under a verifier built for another.
func TestPCSRejectsWrongPoint(t *testing.T) {
	t.Parallel()

	const m = 8
	setup, st, w := newGroupPCS(t, m)

	p, err := NewGroupProver(setup, st, w)
	require.NoError(t, err)
	proof, sigma, err := p.Prove()
	require.NoError(t, err)

	other := GroupStatement{Alpha: randomPoint(t, m)}
	v, err := NewGroupVerifier(setup, other, p.Commitment())
	require.NoError(t, err)
	require.Equal(t, 0, v.Verify(proof, &sigma))
}

// TestPCSVerifyErrSeparatesMisuseFromRejection is why Verify has a VerifyErr
// counterpart at all.
//
// Verify collapses "the proof is invalid" and "you called it wrong" into 0, which is
// the right answer for a caller that only wants the digit and the wrong answer for
// one debugging an integration. The sentinels distinguish them: a nil proof reports
// ErrNilProof, while a forged proof reports a fold or sum-check failure.
func TestPCSVerifyErrSeparatesMisuseFromRejection(t *testing.T) {
	t.Parallel()

	setup, st, w := newGroupPCS(t, 8)
	p, err := NewGroupProver(setup, st, w)
	require.NoError(t, err)
	proof, sigma, err := p.Prove()
	require.NoError(t, err)

	v, err := NewGroupVerifier(setup, st, p.Commitment())
	require.NoError(t, err)

	// Misuse: a nil proof and a nil value are distinguishable, not just "0".
	require.Equal(t, 0, v.Verify(nil, &sigma))
	require.ErrorIs(t, v.VerifyErr(nil, &sigma), ErrNilProof)
	require.Equal(t, 0, v.Verify(proof, nil))
	require.ErrorIs(t, v.VerifyErr(proof, nil), ErrNilElement)

	// Rejection: a tampered fold reports a coset failure, not a nil-argument error.
	tampered := *proof
	fold := *proof.Fold
	fold.Reduced = append(sumcheck.GroupPoly{}, proof.Fold.Reduced...)
	_, _, gen, _ := bls12381.Generators()
	fold.Reduced[0].Add(&fold.Reduced[0], &gen)
	tampered.Fold = &fold

	err = v.VerifyErr(&tampered, &sigma)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrNilProof,
		"a forged proof must not be reported as a malformed call")
}

// TestPCSRejectsWrongArity pins the two size checks the facade adds, since both
// mistakes are natural: sizing alpha from Commitment.NumVars (the row half on the
// field path, not the total) and passing a polynomial of the wrong degree.
func TestPCSRejectsWrongArity(t *testing.T) {
	t.Parallel()

	const m = 8
	setup, st, w := newFieldPCS(t, m)

	t.Run("short alpha", func(t *testing.T) {
		t.Parallel()
		_, err := NewFieldProver(setup, FieldStatement{Alpha: randomPoint(t, m-1)}, w)
		require.ErrorIs(t, err, ErrNumVarsMismatch)
	})

	t.Run("alpha sized from the row half", func(t *testing.T) {
		t.Parallel()
		// The mistake the error message is written for: Commitment.NumVars counts
		// rows, so a caller reading it gets m - m/2 rather than m.
		_, err := NewFieldProver(setup, FieldStatement{Alpha: randomPoint(t, fieldRowVars(m))}, w)
		require.ErrorIs(t, err, ErrNumVarsMismatch)
	})

	t.Run("wrong witness length", func(t *testing.T) {
		t.Parallel()
		_, err := NewFieldProver(setup, st, FieldWitness{Poly: randomFieldPoly(t, m-1)})
		require.ErrorIs(t, err, ErrNumVarsMismatch)
	})

	t.Run("group path", func(t *testing.T) {
		t.Parallel()
		gs, gst, gw := newGroupPCS(t, m)
		_, err := NewGroupProver(gs, GroupStatement{Alpha: randomPoint(t, m+1)}, gw)
		require.ErrorIs(t, err, ErrNumVarsMismatch)
		_, err = NewGroupProver(gs, gst, GroupWitness{Poly: randomGroupPoly(t, m-1)})
		require.ErrorIs(t, err, ErrNumVarsMismatch)

		p, err := NewGroupProver(gs, gst, gw)
		require.NoError(t, err)
		_, err = NewGroupVerifier(gs, GroupStatement{Alpha: randomPoint(t, m-1)}, p.Commitment())
		require.ErrorIs(t, err, ErrNumVarsMismatch)
	})

	t.Run("verifier alpha", func(t *testing.T) {
		t.Parallel()
		p, err := NewFieldProver(setup, st, w)
		require.NoError(t, err)
		_, err = NewFieldVerifier(setup, FieldStatement{Alpha: randomPoint(t, m+1)}, p.Commitment())
		require.ErrorIs(t, err, ErrNumVarsMismatch)
	})
}

// TestFieldPCSRejectsUnsupportedNumVars pins the field path's size constraints at the
// API boundary, where they are cheap to explain, rather than letting them surface as
// a fold-configuration error several calls deeper -- or, worse, as a transcript
// failure from inside proveFold after the commitment has already been built.
//
// Both are real constraints, not oversights, they are independent, and they are
// reported by DIFFERENT checks -- which is why this test asserts a distinct sentinel
// for each rather than one for both:
//
//   - m=6, 10: rowVars = m - m/2 is odd under the balanced split, and the fold needs
//     an even count. That is a property of the SPLIT, so it fails
//     Split.ValidateForFold with ErrInvalidMatrixSplit.
//   - m=4: the split is fine (rowVars=2, even), but that folded domain holds only 16
//     cosets and cannot supply the default 43 distinct queries. That is a property of
//     the CONFIGURATION, so it fails FoldConfig.Validate with ErrInvalidFoldConfig.
//
// Asserting the right sentinel per case is what keeps this test honest. An earlier
// version asserted ErrInvalidFoldConfig for all three; it passed only because the
// even-rowVars rule was checked inside the fold config, and it would have gone on
// passing if one of the two constraints had silently stopped being enforced.
//
// Note that both restrictions come from the BALANCED split this constructor uses,
// not from the scheme -- see TestFieldPCSSplitMakesOddSizesUsable.
func TestFieldPCSRejectsUnsupportedNumVars(t *testing.T) {
	t.Parallel()

	// Odd row half: rejected as a split.
	for _, m := range []int{6, 10} {
		_, numCols := matrixShape(m)
		_, err := NewFieldSetup(m, testGenerators(t, numCols), testCurve(), FoldConfig{})
		require.ErrorIs(t, err, ErrInvalidMatrixSplit,
			"m=%d has an odd row half under the balanced split and must be rejected at setup", m)
	}

	// Even row half, but too few cosets to draw the default queries from: rejected as
	// a configuration.
	{
		const m = 4
		_, numCols := matrixShape(m)
		_, err := NewFieldSetup(m, testGenerators(t, numCols), testCurve(), FoldConfig{})
		require.ErrorIs(t, err, ErrInvalidFoldConfig,
			"m=4 has a valid split but cannot supply the default query count")
		require.NotErrorIs(t, err, ErrInvalidMatrixSplit,
			"m=4's split is legal; blaming the split would point at the wrong parameter")
	}

	// The group path folds all m variables rather than the row half, so it needs only
	// m even -- and its domain is sized by m, so m=4 has 64 cosets and is fine.
	for _, m := range []int{4, 6, 10} {
		_, err := NewGroupSetup(m, testCurve(), FoldConfig{})
		require.NoError(t, err, "m=%d is valid for the group path", m)
	}
}

// TestPCSSetupValidation covers the remaining constructor guards.
func TestPCSSetupValidation(t *testing.T) {
	t.Parallel()

	t.Run("too few generators", func(t *testing.T) {
		t.Parallel()
		const m = 8
		_, numCols := matrixShape(m)
		_, err := NewFieldSetup(m, testGenerators(t, numCols-1), testCurve(), FoldConfig{})
		require.ErrorIs(t, err, ErrInsufficientGenerators)
	})

	t.Run("nil setup", func(t *testing.T) {
		t.Parallel()
		_, err := NewFieldProver(nil, FieldStatement{}, FieldWitness{})
		require.ErrorIs(t, err, ErrNilElement)
		_, err = NewGroupProver(nil, GroupStatement{}, GroupWitness{})
		require.ErrorIs(t, err, ErrNilElement)
		_, err = NewFieldVerifier(nil, FieldStatement{}, nil)
		require.ErrorIs(t, err, ErrNilElement)
		_, err = NewGroupVerifier(nil, GroupStatement{}, nil)
		require.ErrorIs(t, err, ErrNilElement)
	})

	t.Run("nil commitment", func(t *testing.T) {
		t.Parallel()
		setup, st, _ := newGroupPCS(t, 8)
		_, err := NewGroupVerifier(setup, st, nil)
		require.ErrorIs(t, err, ErrNilElement)
	})

	t.Run("explicit fold config is honoured", func(t *testing.T) {
		t.Parallel()
		// A smaller query count, to confirm the setup's configuration reaches the
		// commitment rather than being silently replaced by the default.
		const m = 8
		cfg, err := DefaultFoldConfig(fieldRowVars(m))
		require.NoError(t, err)
		cfg.Queries = 4

		_, numCols := matrixShape(m)
		setup, err := NewFieldSetup(m, testGenerators(t, numCols), testCurve(), cfg)
		require.NoError(t, err)
		require.Equal(t, 4, setup.FoldConfig().Queries)

		p, err := NewFieldProver(setup, FieldStatement{Alpha: randomPoint(t, m)},
			FieldWitness{Poly: randomFieldPoly(t, m)})
		require.NoError(t, err)
		require.Equal(t, 4, p.Commitment().Cosets.Fold.Queries,
			"the setup's query count did not reach the commitment, so the verifier would "+
				"check a different number of queries than the setup advertises")
	})
}

// TestPCSSetupReportsItsOwnParameters pins the accessors, and specifically that
// FieldSetup.NumVars reports the POLYNOMIAL's variable count rather than the row half.
//
// This matters because NumVars is what a caller sizes Alpha from, and the row half is
// what Commitment.NumVars reports -- the confusion checkAlpha's message is written
// for. If this accessor returned rowVars, sizing Alpha from it would produce a
// statement the prover rejects.
func TestPCSSetupReportsItsOwnParameters(t *testing.T) {
	t.Parallel()

	const m = 8
	fs, _, _ := newFieldPCS(t, m)
	require.Equal(t, m, fs.NumVars(), "field setup must report m, not rowVars")
	require.NotEqual(t, fieldRowVars(m), fs.NumVars(),
		"m and rowVars must be distinguishable at m=8, or this test proves nothing")
	require.Equal(t, 43, fs.FoldConfig().Queries)

	// Sizing alpha from the accessor must produce an acceptable statement.
	_, err := NewFieldProver(fs, FieldStatement{Alpha: randomPoint(t, fs.NumVars())},
		FieldWitness{Poly: randomFieldPoly(t, m)})
	require.NoError(t, err)

	gs, _, _ := newGroupPCS(t, m)
	require.Equal(t, m, gs.NumVars())
	require.Equal(t, 43, gs.FoldConfig().Queries)
}

// TestPCSNilReceivers pins that the value methods do not panic on a nil receiver,
// since Verify returning 0 is more useful than a crash in a verification path.
func TestPCSNilReceivers(t *testing.T) {
	t.Parallel()

	var fp *FieldProver
	_, _, err := fp.Prove()
	require.ErrorIs(t, err, ErrNilElement)

	var gp *GroupProver
	_, _, err = gp.Prove()
	require.ErrorIs(t, err, ErrNilElement)

	var fv *FieldVerifier
	require.Equal(t, 0, fv.Verify(nil, fr.Element{}))

	var gv *GroupVerifier
	require.Equal(t, 0, gv.Verify(nil, nil))
}

// TestPCSSetupSizesTheDomainByTheFoldedHalf pins the field path's domain size to
// rowVars + LogRate rather than numVars + LogRate.
//
// This is the first of the four decisions the facade's header calls out, and it is
// the only one of them a correctness test cannot see. An oversized domain still
// encodes, commits, proves and verifies: EncodeFieldOracle consumes the first
// 2^(rowVars+LogRate) points and ignores the rest, and the domain size is never
// absorbed into the transcript. Probed directly -- a prover on a 2^11 domain at m=8
// produces a proof that a verifier holding the correct 2^7 domain accepts, with no
// error. So the mistake is purely a cost, and costs need a structural assertion or
// nothing catches them.
//
// The cost is not the "twice as large" one might guess from the usual halving. The
// exponent gap is numVars - rowVars = numVars/2, so the domain grows by 2^(m/2):
// 16x at m=8, 256x at m=16, all of it paid in the commit FFT that dominates
// NewFieldProver.
//
// A benchmark would be the wrong instrument here -- it would measure the regression
// but only a human reading the numbers would notice it. This asserts the rule.
func TestPCSSetupSizesTheDomainByTheFoldedHalf(t *testing.T) {
	t.Parallel()
	for _, m := range []int{8, 12, 16} {
		_, numCols := matrixShape(m)
		s, err := NewFieldSetup(m, testGenerators(t, numCols), testCurve(), FoldConfig{})
		require.NoError(t, err)

		rowVars := fieldRowVars(m)
		require.Equal(t, rowVars+s.FoldConfig().LogRate, s.dom.LogSize,
			"m=%d: the field domain must be sized by the %d folded variables, not all %d; "+
				"sizing it by m wastes a factor of 2^%d in the commit FFT and no round "+
				"trip would notice", m, rowVars, m, m-rowVars)
		require.Less(t, s.dom.LogSize, m+s.FoldConfig().LogRate,
			"m=%d: this assertion is vacuous unless the two sizings differ", m)
	}

	// The group path is the other side of the asymmetry: it encodes all m variables,
	// so there m IS the right parameter. Asserting both keeps a "fix" that unifies
	// them from passing.
	for _, m := range []int{4, 8, 12} {
		s, err := NewGroupSetup(m, testCurve(), FoldConfig{})
		require.NoError(t, err)
		require.Equal(t, m+s.FoldConfig().LogRate, s.dom.LogSize,
			"m=%d: the group path has no matrix split, so its domain is sized by m", m)
	}
}

// TestFieldPCSSplitMakesOddSizesUsable is the point of making the matrix split a
// parameter: sizes the balanced split cannot serve become usable by moving the cut.
//
// The balanced split forces rowVars = m - m/2 to be even, i.e. m divisible by 4,
// because the fold halves the row half exactly. That is a property of the *choice*
// m1 = m/2, not of the scheme. With the cut free, the condition becomes "M - M1 is
// even", which is satisfiable at every m > 2 -- so m = 10, 14 and 18, all rejected
// outright by NewFieldSetup, prove and verify here.
//
// # Why this asserts sigma against an independent evaluator
//
// A round trip alone would be nearly worthless for this. eq factorizes over ANY
// split, so a prover and verifier that both divide alpha at the wrong point produce
// a proof that verifies against itself perfectly -- just for a different polynomial
// than the one committed. That is the failure splitAlpha's godoc warns about, and it
// is invisible to Verify() == 1. So sigma is checked against
// sumcheck.FieldPoly.EvaluatePoint, the package's own reference evaluator, which
// knows nothing about matrices or splits.
func TestFieldPCSSplitMakesOddSizesUsable(t *testing.T) {
	t.Parallel()

	// Each of these m is rejected by NewFieldSetup's balanced split; each has an M1
	// that leaves an even row half.
	cases := []struct{ m, m1 int }{
		{m: 10, m1: 4},
		{m: 10, m1: 2},
		{m: 14, m1: 6},
		{m: 18, m1: 8}, // the size the Rust reference's own config table starts at
	}

	for _, c := range cases {
		t.Run(fmt.Sprintf("m=%d/m1=%d", c.m, c.m1), func(t *testing.T) {
			t.Parallel()

			split := Split{M: c.m, M1: c.m1}
			require.NoError(t, split.ValidateForFold(),
				"m=%d M1=%d should be a legal split", c.m, c.m1)

			// The premise: the balanced constructor cannot serve this size at all.
			_, err := NewFieldSetup(c.m, testGenerators(t, 1<<(c.m/2)), testCurve(), FoldConfig{})
			require.Error(t, err, "m=%d must be unusable under the balanced split, or this test proves nothing", c.m)

			setup, err := NewFieldSetupWithSplit(split, testGenerators(t, split.Cols()), testCurve(), FoldConfig{})
			require.NoError(t, err)
			require.Equal(t, split, setup.Split())

			st := FieldStatement{Alpha: randomPoint(t, c.m)}
			w := FieldWitness{Poly: randomFieldPoly(t, c.m)}

			p, err := NewFieldProver(setup, st, w)
			require.NoError(t, err)

			// The split must reach the wire, or a verifier holding a different setup
			// could not detect the disagreement.
			require.Equal(t, c.m1, p.Commitment().ColVars,
				"the commitment must state the column half it was made with")
			require.Equal(t, split.RowVars(), p.Commitment().NumVars,
				"the commitment is over the row half")

			proof, sigma, err := p.Prove()
			require.NoError(t, err)

			// The load-bearing assertion: sigma is f(alpha) by an independent route.
			want, err := w.Poly.EvaluatePoint(st.Alpha)
			require.NoError(t, err)
			require.True(t, want.Equal(&sigma),
				"m=%d M1=%d: sigma is self-consistent but is not f(alpha) -- the halves are cut in the wrong place",
				c.m, c.m1)

			v, err := NewFieldVerifier(setup, st, p.Commitment())
			require.NoError(t, err)
			require.Equal(t, 1, v.Verify(proof, sigma))
			require.NoError(t, v.VerifyErr(proof, sigma))
		})
	}
}
