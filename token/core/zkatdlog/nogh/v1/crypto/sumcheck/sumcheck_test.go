/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sumcheck

import (
	"io"
	"strconv"
	"testing"

	mathlib "github.com/IBM/mathlib"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCurve is the curve the package targets. BLS12_381_BBS_GURVY is the variant
// the zkatdlog driver uses for this curve.
func testCurve(t testing.TB) (*mathlib.Curve, io.Reader) {
	t.Helper()
	curve := mathlib.Curves[mathlib.BLS12_381_BBS_GURVY]
	require.NotNil(t, curve)
	rng, err := curve.Rand()
	require.NoError(t, err)

	return curve, rng
}

// randomFieldPoly returns a random multilinear polynomial on numVars variables.
func randomFieldPoly(t testing.TB, curve *mathlib.Curve, rng io.Reader, numVars int) FieldPoly {
	t.Helper()
	n := 1 << numVars
	evals := make([]*mathlib.Zr, n)
	for i := range evals {
		evals[i] = curve.NewRandomZr(rng)
	}
	p, err := NewFieldPoly(evals)
	require.NoError(t, err)

	return p
}

// randomGroupPoly returns a random multilinear polynomial whose evaluations are
// G1 points, along with the scalars s_i such that eval_i = [s_i]G.
//
// Returning the discrete logs lets a test cross-check the group protocol against
// the field protocol: if g(x) = [s(x)]G for a multilinear s, then the group
// sum-check on g must produce exactly the field sum-check on s, scaled into G1.
func randomGroupPoly(t testing.TB, curve *mathlib.Curve, rng io.Reader, numVars int) (GroupPoly, FieldPoly) {
	t.Helper()
	n := 1 << numVars
	pts := make([]*mathlib.G1, n)
	scalars := make([]*mathlib.Zr, n)
	for i := range pts {
		s := curve.NewRandomZr(rng)
		scalars[i] = s
		pts[i] = curve.GenG1.Mul(s)
	}
	gp, err := NewGroupPoly(pts)
	require.NoError(t, err)
	fp, err := NewFieldPoly(scalars)
	require.NoError(t, err)

	return gp, fp
}

// bruteForceFieldSum computes the hypercube sum of the product directly, by
// iterating every point, as an independent check on the protocol's claimed sum.
func bruteForceFieldSum(factors []FieldPoly) fr.Element {
	var total fr.Element
	if len(factors) == 0 {
		return total
	}
	n := len(factors[0])
	for x := range n {
		var prod fr.Element
		prod.SetOne()
		for _, f := range factors {
			prod.Mul(&prod, &f[x])
		}
		total.Add(&total, &prod)
	}

	return total
}

// bruteForceGroupSum computes sum_x (prod_i f_i(x)) * g(x) directly.
func bruteForceGroupSum(factors []FieldPoly, g GroupPoly) bls12381.G1Affine {
	var acc bls12381.G1Jac
	for x := range len(g) {
		var prod fr.Element
		prod.SetOne()
		for _, f := range factors {
			prod.Mul(&prod, &f[x])
		}
		out := make([]bls12381.G1Affine, 1)
		_ = scaleByOne(g[x:x+1], &prod, out)
		acc.AddMixed(&out[0])
	}
	var res bls12381.G1Affine
	res.FromJacobian(&acc)

	return res
}

func TestProveVerifyField(t *testing.T) {
	curve, rng := testCurve(t)

	for _, numFactors := range []int{1, 2, 3} {
		for _, numVars := range []int{1, 2, 3, 6, 8} {
			t.Run(name(numFactors, numVars, false), func(t *testing.T) {
				factors := make([]FieldPoly, numFactors)
				for i := range factors {
					factors[i] = randomFieldPoly(t, curve, rng, numVars)
				}
				// Keep pristine copies: Prove must not mutate the caller's data.
				originals := make([]FieldPoly, numFactors)
				for i := range factors {
					originals[i] = factors[i].Clone()
				}

				claim := &Claim{Field: factors}
				proof, proverOpening, err := Prove(curve, claim)
				require.NoError(t, err)
				require.NotNil(t, proof)

				// The asserted sum must match a direct computation.
				want := bruteForceFieldSum(originals)
				claimed := fromZr(proof.FieldSum)
				assert.True(t, claimed.Equal(&want),
					"claimed sum does not match brute-force sum")

				// Prove must not have disturbed the inputs.
				for i := range factors {
					assert.Equal(t, originals[i], factors[i], "factor %d was mutated by Prove", i)
				}

				shape := Shape{NumVars: numVars, NumFieldFactors: numFactors}
				verifierOpening, err := Verify(curve, shape, proof)
				require.NoError(t, err)
				require.NotNil(t, verifierOpening)

				// Both sides must agree on the challenge point.
				require.Len(t, verifierOpening.R, numVars)
				for i := range verifierOpening.R {
					assert.True(t, verifierOpening.R[i].Equals(proverOpening.R[i]),
						"challenge %d differs between prover and verifier", i)
				}

				// The verifier's residual product must equal the product of the
				// prover's per-factor evaluations. This is the seam a caller closes
				// with a commitment opening.
				var prod fr.Element
				prod.SetOne()
				require.Len(t, proverOpening.FieldEvals, numFactors)
				for _, e := range proverOpening.FieldEvals {
					v := fromZr(e)
					prod.Mul(&prod, &v)
				}
				got := fromZr(verifierOpening.Product)
				assert.True(t, prod.Equal(&got),
					"verifier product does not match product of prover factor evaluations")

				// And the factor evaluations must be the true values at R. R is in
				// folding order as it comes off the Opening, so EvaluateOpening
				// consumes it without reordering.
				at := make([]fr.Element, numVars)
				for i, r := range verifierOpening.R {
					at[i] = fromZr(r)
				}
				for i := range originals {
					want, err := originals[i].EvaluateOpening(at)
					require.NoError(t, err)
					have := fromZr(proverOpening.FieldEvals[i])
					assert.True(t, want.Equal(&have),
						"factor %d evaluation at R is wrong", i)
				}
			})
		}
	}
}

func TestProveVerifyGroup(t *testing.T) {
	curve, rng := testCurve(t)

	for _, numFieldFactors := range []int{0, 1, 2} {
		for _, numVars := range []int{1, 2, 3, 6} {
			t.Run(name(numFieldFactors, numVars, true), func(t *testing.T) {
				factors := make([]FieldPoly, numFieldFactors)
				for i := range factors {
					factors[i] = randomFieldPoly(t, curve, rng, numVars)
				}
				group, _ := randomGroupPoly(t, curve, rng, numVars)

				originals := make([]FieldPoly, numFieldFactors)
				for i := range factors {
					originals[i] = factors[i].Clone()
				}
				groupOriginal := group.Clone()

				claim := &Claim{Field: factors, Group: group}
				proof, proverOpening, err := Prove(curve, claim)
				require.NoError(t, err)
				require.NotNil(t, proof.GroupSum)
				assert.Nil(t, proof.FieldSum, "group proof must not carry a field sum")

				// The asserted group sum must match a direct computation.
				want := bruteForceGroupSum(originals, groupOriginal)
				var claimed bls12381.G1Affine
				_, err = claimed.SetBytes(proof.GroupSum.Bytes())
				require.NoError(t, err)
				assert.True(t, claimed.Equal(&want), "claimed group sum is wrong")

				shape := Shape{
					NumVars:         numVars,
					NumFieldFactors: numFieldFactors,
					HasGroupFactor:  true,
				}
				verifierOpening, err := Verify(curve, shape, proof)
				require.NoError(t, err)

				require.Len(t, verifierOpening.R, numVars)
				for i := range verifierOpening.R {
					assert.True(t, verifierOpening.R[i].Equals(proverOpening.R[i]),
						"challenge %d differs", i)
				}

				// The verifier's residual is the whole product at R; recompute it
				// from the prover's factor evaluations and group evaluation.
				var prod fr.Element
				prod.SetOne()
				for _, e := range proverOpening.FieldEvals {
					v := fromZr(e)
					prod.Mul(&prod, &v)
				}
				var gAff bls12381.G1Affine
				_, err = gAff.SetBytes(proverOpening.GroupEval.Bytes())
				require.NoError(t, err)
				out := make([]bls12381.G1Affine, 1)
				require.NoError(t, scaleByOne(gAff2slice(gAff), &prod, out))

				var verifierAff bls12381.G1Affine
				_, err = verifierAff.SetBytes(verifierOpening.GroupEval.Bytes())
				require.NoError(t, err)
				assert.True(t, out[0].Equal(&verifierAff),
					"verifier residual does not match prover's factor evaluations")
			})
		}
	}
}

// TestGroupMatchesFieldScaled cross-checks the two protocols against each other.
//
// With g(x) = [s(x)]G for a multilinear s, the group claim
// sum_x f(x)*g(x) equals [sum_x f(x)*s(x)]G. Because both runs absorb different
// bytes into the transcript they draw different challenges, so the round
// polynomials cannot be compared directly; the claimed sums must nonetheless agree
// once the field sum is scaled into G1.
func TestGroupMatchesFieldScaled(t *testing.T) {
	curve, rng := testCurve(t)
	const numVars = 5

	for _, numFieldFactors := range []int{0, 1, 2} {
		t.Run(name(numFieldFactors, numVars, true), func(t *testing.T) {
			factors := make([]FieldPoly, numFieldFactors)
			for i := range factors {
				factors[i] = randomFieldPoly(t, curve, rng, numVars)
			}
			group, logs := randomGroupPoly(t, curve, rng, numVars)

			// Group run.
			groupClaim := &Claim{Field: clonePolys(factors), Group: group.Clone()}
			groupProof, _, err := Prove(curve, groupClaim)
			require.NoError(t, err)

			// Field run on the same product with the discrete logs substituted.
			fieldFactors := append(clonePolys(factors), logs.Clone())
			fieldClaim := &Claim{Field: fieldFactors}
			fieldProof, _, err := Prove(curve, fieldClaim)
			require.NoError(t, err)

			// [fieldSum]G must equal the group sum.
			fieldSum := fromZr(fieldProof.FieldSum)
			var gen bls12381.G1Affine
			_, err = gen.SetBytes(curve.GenG1.Bytes())
			require.NoError(t, err)
			scaled := make([]bls12381.G1Affine, 1)
			require.NoError(t, scaleByOne(gAff2slice(gen), &fieldSum, scaled))

			var groupSum bls12381.G1Affine
			_, err = groupSum.SetBytes(groupProof.GroupSum.Bytes())
			require.NoError(t, err)

			assert.True(t, scaled[0].Equal(&groupSum),
				"group sum-check disagrees with the field sum-check scaled into G1")
		})
	}
}

// TestVerifyIsIndependentOfHypercubeSize checks the verifier does not need the
// polynomials: it works from the proof and the shape alone.
func TestVerifyIsIndependentOfHypercubeSize(t *testing.T) {
	curve, rng := testCurve(t)
	const numVars = 10

	f := randomFieldPoly(t, curve, rng, numVars)
	g := randomFieldPoly(t, curve, rng, numVars)

	proof, _, err := Prove(curve, &Claim{Field: []FieldPoly{f, g}})
	require.NoError(t, err)

	// One round polynomial per variable, each with degree+1 evaluations.
	require.Len(t, proof.FieldRounds, numVars)
	for i, r := range proof.FieldRounds {
		assert.Len(t, r, 3, "round %d", i)
	}

	_, err = Verify(curve, Shape{NumVars: numVars, NumFieldFactors: 2}, proof)
	require.NoError(t, err)
}

// TestTranscriptBinding checks that a proof does not verify under a different
// claim shape, which the transcript header binds.
func TestTranscriptBinding(t *testing.T) {
	curve, rng := testCurve(t)
	const numVars = 4

	f := randomFieldPoly(t, curve, rng, numVars)
	g := randomFieldPoly(t, curve, rng, numVars)
	proof, _, err := Prove(curve, &Claim{Field: []FieldPoly{f, g}})
	require.NoError(t, err)

	// Correct shape verifies.
	_, err = Verify(curve, Shape{NumVars: numVars, NumFieldFactors: 2}, proof)
	require.NoError(t, err)

	// A shape claiming a different factor count changes both the expected degree
	// and the transcript header, so it must be rejected.
	_, err = Verify(curve, Shape{NumVars: numVars, NumFieldFactors: 3}, proof)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrRoundDegreeMismatch)
}

// TestProveWithTranscriptRoundTrip checks the composable entry points agree.
func TestProveWithTranscriptRoundTrip(t *testing.T) {
	curve, rng := testCurve(t)
	const numVars = 4

	f := randomFieldPoly(t, curve, rng, numVars)
	claim := &Claim{Field: []FieldPoly{f}}

	proverTr := newTranscript(curve, numVars, 1, false)
	proverTr.Absorb([]byte("enclosing protocol data"))
	proof, _, err := ProveWithTranscript(curve, claim, proverTr)
	require.NoError(t, err)

	verifierTr := newTranscript(curve, numVars, 1, false)
	verifierTr.Absorb([]byte("enclosing protocol data"))
	_, err = VerifyWithTranscript(curve, Shape{NumVars: numVars, NumFieldFactors: 1}, proof, verifierTr)
	require.NoError(t, err)

	// A transcript seeded with different enclosing data must not verify.
	wrongTr := newTranscript(curve, numVars, 1, false)
	wrongTr.Absorb([]byte("different protocol data"))
	_, err = VerifyWithTranscript(curve, Shape{NumVars: numVars, NumFieldFactors: 1}, proof, wrongTr)
	require.Error(t, err)
}

// clonePolys deep-copies a slice of field polynomials.
func clonePolys(in []FieldPoly) []FieldPoly {
	out := make([]FieldPoly, len(in))
	for i := range in {
		out[i] = in[i].Clone()
	}

	return out
}

// gAff2slice wraps a single point so it can be passed to the slice-based helpers.
func gAff2slice(p bls12381.G1Affine) []bls12381.G1Affine {
	return []bls12381.G1Affine{p}
}

// name builds a readable subtest name.
func name(numFieldFactors, numVars int, group bool) string {
	suffix := "field"
	if group {
		suffix = "group"
	}

	return "k_" + strconv.Itoa(numFieldFactors) + "/vars_" + strconv.Itoa(numVars) + "/" + suffix
}

// TestFoldSubstitutesLastVariable pins down the indexing convention, which is the
// one thing in this package that cannot be checked by a round-trip test: prover and
// verifier fold identically, so a convention mistake cancels out between them and
// every round-trip still passes while the polynomial being summed is not the one the
// caller meant.
//
// The table is little-endian (entry i holds p(b_0, ..., b_{mu-1}), b_j = bit j of i),
// so b_{mu-1} is the high index bit and fold must pair i with i+half. If fold were
// changed to the even/odd pairing (2i, 2i+1) it would be substituting for b_0
// instead, and these assertions fail.
func TestFoldSubstitutesLastVariable(t *testing.T) {
	mk := func(vals ...int64) FieldPoly {
		p := make(FieldPoly, len(vals))
		for i, v := range vals {
			p[i].SetInt64(v)
		}

		return p
	}

	var r fr.Element
	r.SetInt64(5)

	// On mu=2: the polynomial equal to b_0 (low bit), which ignores b_1.
	//   i=0 (b0=0,b1=0)->0  i=1 (b0=1,b1=0)->1
	//   i=2 (b0=0,b1=1)->0  i=3 (b0=1,b1=1)->1
	lowBit := mk(0, 1, 0, 1)

	// Folding the last variable (b_1) leaves the function b_0 untouched.
	got := lowBit.Clone().fold(&r)
	require.Len(t, got, 2)
	assert.Equal(t, "0", got[0].String(), "folding b_1 must leave b_0 alone")
	assert.Equal(t, "1", got[1].String(), "folding b_1 must leave b_0 alone")

	// The polynomial equal to b_1 (high bit) collapses to the constant r.
	highBit := mk(0, 0, 1, 1)
	got = highBit.Clone().fold(&r)
	require.Len(t, got, 2)
	assert.Equal(t, "5", got[0].String(), "folding b_1 must yield the constant r")
	assert.Equal(t, "5", got[1].String(), "folding b_1 must yield the constant r")

	// EvaluateOpening consumes `at` in folding order, i.e. reversed relative to the
	// table: at[0] is b_1, at[1] is b_0. So p = b_0 evaluated with at = (0, 1)
	// gives 1.
	one := fr.One()
	var zero fr.Element
	v, err := lowBit.EvaluateOpening([]fr.Element{zero, one})
	require.NoError(t, err)
	assert.Equal(t, "1", v.String(), "EvaluateOpening's at[1] must be b_0")

	v, err = lowBit.EvaluateOpening([]fr.Element{one, zero})
	require.NoError(t, err)
	assert.Equal(t, "0", v.String(), "EvaluateOpening's at[0] must be b_1, not b_0")

	// EvaluatePoint takes the same point in table order, so the two disagree on
	// argument order and must agree on the result once one side is reversed.
	v, err = lowBit.EvaluatePoint([]fr.Element{one, zero})
	require.NoError(t, err)
	assert.Equal(t, "1", v.String(), "EvaluatePoint's at[0] must be b_0")

	v, err = lowBit.EvaluatePoint([]fr.Element{zero, one})
	require.NoError(t, err)
	assert.Equal(t, "0", v.String(), "EvaluatePoint's at[1] must be b_1")
}
