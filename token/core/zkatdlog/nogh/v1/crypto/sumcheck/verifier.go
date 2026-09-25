/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sumcheck

import (
	mathlib "github.com/IBM/mathlib"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/rp/csp"
)

// Shape describes the public parameters of a claim, which the verifier needs
// without holding the polynomials themselves.
//
// NumFieldFactors and HasGroupFactor must match the claim the prover ran on;
// they determine the expected round-polynomial degree, and they are bound into the
// transcript so a proof cannot be reinterpreted under a different shape.
type Shape struct {
	NumVars         int
	NumFieldFactors int
	HasGroupFactor  bool
}

// Degree returns the expected degree of each round polynomial.
func (s Shape) Degree() int {
	d := s.NumFieldFactors
	if s.HasGroupFactor {
		d++
	}

	return d
}

// validate checks that the shape is self-consistent.
func (s Shape) validate() error {
	if s.NumVars <= 0 {
		return errors.Wrapf(ErrNumVarsMismatch, "number of variables must be positive, got %d", s.NumVars)
	}
	if s.NumFieldFactors < 0 {
		return errors.Wrapf(ErrNoFactors, "number of field factors cannot be negative, got %d", s.NumFieldFactors)
	}
	if s.NumFieldFactors == 0 && !s.HasGroupFactor {
		return ErrNoFactors
	}

	return nil
}

// Verify checks a sum-check proof against the asserted sum carried in the proof
// and returns the residual Opening.
//
// A nil error means the hypercube sum follows from the returned Opening. It does
// *not* mean the Opening is correct: sum-check reduces the claim, it does not
// close it. The caller must still check the returned evaluations against a
// commitment opening, an oracle, or a direct evaluation.
//
// Verification cost is independent of the hypercube size: it is one interpolation
// per round, so O(mu * degree) field operations, versus the prover's O(2^mu).
func Verify(curve *mathlib.Curve, shape Shape, proof *Proof) (*Opening, error) {
	if curve == nil {
		return nil, ErrNilCurve
	}
	if proof == nil {
		return nil, ErrNilProof
	}
	if err := shape.validate(); err != nil {
		return nil, err
	}

	tr := newTranscript(curve, shape.NumVars, shape.Degree(), shape.HasGroupFactor)

	return verifyWith(curve, shape, proof, tr)
}

// VerifyWithTranscript is Verify with a caller-supplied transcript, matching
// ProveWithTranscript.
//
// The transcript must be in exactly the state the prover's was in when it began
// its first round, or every challenge will diverge and verification will fail.
func VerifyWithTranscript(curve *mathlib.Curve, shape Shape, proof *Proof, tr *csp.Transcript) (*Opening, error) {
	if curve == nil {
		return nil, ErrNilCurve
	}
	if proof == nil {
		return nil, ErrNilProof
	}
	if tr == nil {
		return nil, errors.New("transcript cannot be nil")
	}
	if err := shape.validate(); err != nil {
		return nil, err
	}

	return verifyWith(curve, shape, proof, tr)
}

// verifyWith is the shared verifier body.
func verifyWith(curve *mathlib.Curve, shape Shape, proof *Proof, tr *csp.Transcript) (*Opening, error) {
	if proof.IsGroup() != shape.HasGroupFactor {
		return nil, errors.Wrapf(ErrMixedProofKind, "proof group=%t but shape group=%t", proof.IsGroup(), shape.HasGroupFactor)
	}
	if proof.Rounds() != shape.NumVars {
		return nil, errors.Wrapf(ErrRoundCountMismatch, "proof has %d rounds, expected %d", proof.Rounds(), shape.NumVars)
	}

	if shape.HasGroupFactor {
		return verifyGroup(curve, shape, proof, tr)
	}

	return verifyField(curve, shape, proof, tr)
}

// verifyField runs the field-only verification.
func verifyField(curve *mathlib.Curve, shape Shape, proof *Proof, tr *csp.Transcript) (*Opening, error) {
	degree := shape.Degree()

	if proof.FieldSum == nil {
		return nil, errors.Wrap(ErrNilProof, "field proof carries no claimed sum")
	}

	// expected is the value the current round polynomial must sum to: the asserted
	// total in round 0, and thereafter the previous round polynomial evaluated at
	// the challenge.
	expected := fromZr(proof.FieldSum)
	challenges := make([]*mathlib.Zr, 0, shape.NumVars)

	for round := range shape.NumVars {
		raw := proof.FieldRounds[round]
		if len(raw) != degree+1 {
			return nil, errors.Wrapf(ErrRoundDegreeMismatch, "round %d has %d evaluations, expected %d", round, len(raw), degree+1)
		}

		evals := make([]fr.Element, len(raw))
		for i, z := range raw {
			if z == nil {
				return nil, errors.Wrapf(ErrNilElement, "round %d evaluation %d is nil", round, i)
			}
			evals[i] = fromZr(z)
			tr.Absorb(z.Bytes())
		}

		// q(0) + q(1) must equal the sum inherited from the previous round.
		var got fr.Element
		got.Add(&evals[0], &evals[1])
		if !got.Equal(&expected) {
			if round == 0 {
				return nil, errors.Wrapf(ErrSumMismatch, "round 0 polynomial does not sum to the claimed value")
			}

			return nil, errors.Wrapf(ErrRoundCheckFailed, "round %d", round)
		}

		rFr, rZr, err := squeezeChallenge(tr)
		if err != nil {
			return nil, err
		}
		challenges = append(challenges, rZr)

		expected = interpolateAt(evals, &rFr)
	}

	// expected now holds p(r), the product of all factors at the challenge point.
	// The verifier cannot split it into per-factor values without the polynomials,
	// so it reports the product and leaves FieldEvals nil; the caller closes the
	// argument by comparing this against the product of the factor values its
	// commitment scheme opens to.
	return &Opening{
		R:       challenges,
		Product: toZr(curve, &expected),
	}, nil
}

// verifyGroup runs the verification for a claim with a group factor.
func verifyGroup(curve *mathlib.Curve, shape Shape, proof *Proof, tr *csp.Transcript) (*Opening, error) {
	degree := shape.Degree()

	if proof.GroupSum == nil {
		return nil, errors.Wrap(ErrNilProof, "group proof carries no claimed sum")
	}

	var expected bls12381.G1Affine
	if _, err := expected.SetBytes(proof.GroupSum.Bytes()); err != nil {
		return nil, errors.Wrap(err, "failed to decode claimed group sum")
	}

	challenges := make([]*mathlib.Zr, 0, shape.NumVars)

	for round := range shape.NumVars {
		raw := proof.GroupRounds[round]
		if len(raw) != degree+1 {
			return nil, errors.Wrapf(ErrRoundDegreeMismatch, "round %d has %d evaluations, expected %d", round, len(raw), degree+1)
		}

		evals := make([]bls12381.G1Affine, len(raw))
		for i, g := range raw {
			if g == nil {
				return nil, errors.Wrapf(ErrNilElement, "round %d evaluation %d is nil", round, i)
			}
			if _, err := evals[i].SetBytes(g.Bytes()); err != nil {
				return nil, errors.Wrapf(err, "failed to decode round %d evaluation %d", round, i)
			}
			tr.Absorb(g.Bytes())
		}

		var sum bls12381.G1Jac
		sum.FromAffine(&evals[0])
		sum.AddMixed(&evals[1])
		var got bls12381.G1Affine
		got.FromJacobian(&sum)

		if !got.Equal(&expected) {
			if round == 0 {
				return nil, errors.Wrapf(ErrSumMismatch, "round 0 polynomial does not sum to the claimed value")
			}

			return nil, errors.Wrapf(ErrRoundCheckFailed, "round %d", round)
		}

		rFr, rZr, err := squeezeChallenge(tr)
		if err != nil {
			return nil, err
		}
		challenges = append(challenges, rZr)

		expected = interpolateAtG1(evals, &rFr)
	}

	final, err := toG1(curve, &expected)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert final group claim")
	}

	return &Opening{
		R:         challenges,
		GroupEval: final,
	}, nil
}
