/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package csp

import (
	"math/bits"

	mathlib "github.com/IBM/mathlib"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"
)

// Exported linear-form API
//
// The compressed sigma-protocol in this package proves that a committed vector
// satisfies a *public* linear form: given a Pedersen commitment C = MSM(gen, w),
// public generators gen, and public coefficients f, it proves
//
//	<f, w> = v
//
// in 2*log2(n) group elements and 2*log2(n) field elements, without sending w.
//
// The range proof in rp.go drives the prover and verifier directly, because it
// builds the statement as part of a larger protocol. ProveLinearForm and
// VerifyLinearForm expose the same primitive to callers outside this package that
// already have a statement in hand -- notably the Titan polynomial commitment,
// whose evaluation proof reduces to exactly this statement with the linear form
// eq(alpha, .), which the verifier recomputes from the public evaluation point.
//
// # This is not zero-knowledge
//
// Deliberately so, and callers must not assume otherwise. The protocol is
// *succinct* -- it does not transmit the witness -- but it is not hiding: it is
// the "Non-ZK CSP proof" the range proof uses over an already-blinded statement,
// and the blinding lives in rp.go, not here. A caller that needs the witness
// hidden must blind the statement itself before calling, exactly as rp.go does.
// Using this on a secret witness with no blinding leaks information about it.

// LinearFormStatement is the public statement proved by ProveLinearForm and
// checked by VerifyLinearForm: that the vector committed in Commitment satisfies
// <LinearForm, w> = Value under Generators.
//
// Generators, LinearForm and the witness must all have the same length, and that
// length must be a power of two -- the protocol folds the vectors in half each
// round. Use PadToPowerOfTwo to meet that requirement.
type LinearFormStatement struct {
	// Commitment is the Pedersen commitment C = MSM(Generators, w).
	Commitment *mathlib.G1

	// Generators are the public commitment generators. None may be the point at
	// infinity: an identity generator collapses the commitment scheme.
	Generators []*mathlib.G1

	// LinearForm holds the public coefficients f of the linear form.
	LinearForm []*mathlib.Zr

	// Value is the claimed evaluation v = <f, w>.
	Value *mathlib.Zr

	// Curve is the curve everything above lives on.
	Curve *mathlib.Curve
}

// rounds returns log2(len(Generators)) after checking the statement is
// well-shaped. It is the single place the power-of-two requirement is enforced,
// so the prover and verifier cannot disagree about it.
func (st *LinearFormStatement) rounds() (uint64, error) {
	if st.Curve == nil {
		return 0, ErrNilCurve
	}
	n := len(st.Generators)
	if n == 0 {
		return 0, errors.Wrapf(ErrInvalidLength, "statement has no generators")
	}
	if bits.OnesCount(uint(n)) != 1 {
		return 0, errors.Wrapf(ErrInvalidLength, "vector length must be a power of two, got %d", n)
	}
	// A length-1 statement folds zero times, and the verifier's folded-commitment
	// MSM indexes suffProd[NumberOfRounds-1] unconditionally (csp.go:298), so
	// zero rounds panics there. rp.go never produces that case -- its cspRounds is
	// always at least 1 -- so rejecting it here is the honest fix rather than
	// changing the audited verifier for a statement with nothing to prove: with a
	// single generator the "proof" would be the witness itself.
	if n == 1 {
		return 0, errors.Wrapf(ErrInvalidLength, "vector length must be at least 2, got 1")
	}
	if len(st.LinearForm) != n {
		return 0, errors.Wrapf(ErrInvalidLength, "linear form has %d coefficients, generators %d", len(st.LinearForm), n)
	}

	return uint64(bits.TrailingZeros(uint(n))), nil
}

// ProveLinearForm proves that the vector committed in st.Commitment satisfies
// st's linear form, using witness as the opening.
//
// witness must be the actual opening of st.Commitment under st.Generators and
// must have the same length as st.Generators; the proof is meaningless otherwise
// and verification will fail. transcriptHeader domain-separates the Fiat-Shamir
// transcript and must be non-empty; the verifier has to supply the same bytes.
//
// The resulting proof is succinct but NOT zero-knowledge -- see the note at the
// top of this file.
func ProveLinearForm(st *LinearFormStatement, witness []*mathlib.Zr, transcriptHeader []byte) (*Proof, error) {
	if st == nil {
		return nil, errors.New("statement cannot be nil")
	}
	numRounds, err := st.rounds()
	if err != nil {
		return nil, errors.Wrap(err, "invalid linear form statement")
	}
	if len(witness) != len(st.Generators) {
		return nil, errors.Wrapf(ErrInvalidLength, "witness has %d entries, generators %d", len(witness), len(st.Generators))
	}

	p := &prover{
		Commitment:     st.Commitment,
		Generators:     st.Generators,
		LinearForm:     st.LinearForm,
		Value:          st.Value,
		NumberOfRounds: numRounds,
		Curve:          st.Curve,
		witness:        witness,
	}

	proof, err := p.WithTranscriptHeader(transcriptHeader).Prove()
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate linear form proof")
	}

	return proof, nil
}

// VerifyLinearForm checks proof against st, returning nil exactly when the proof
// establishes that some opening of st.Commitment satisfies the linear form.
//
// transcriptHeader must equal the bytes the prover used.
func VerifyLinearForm(st *LinearFormStatement, proof *Proof, transcriptHeader []byte) error {
	if st == nil {
		return errors.New("statement cannot be nil")
	}
	if proof == nil {
		return ErrNilProof
	}
	numRounds, err := st.rounds()
	if err != nil {
		return errors.Wrap(err, "invalid linear form statement")
	}

	v := &verifier{
		Commitment:     st.Commitment,
		Generators:     st.Generators,
		LinearForm:     st.LinearForm,
		Value:          st.Value,
		NumberOfRounds: numRounds,
		Curve:          st.Curve,
	}

	return v.WithTranscriptHeader(transcriptHeader).Verify(proof)
}

// PadToPowerOfTwo extends generators and linearForm (and witness, when non-nil)
// with neutral entries until their length is a power of two, returning the padded
// slices.
//
// The padding is (curve.GenG1, 0, 0): a zero coefficient contributes nothing to
// the linear form and a zero witness entry contributes nothing to the
// commitment, so the statement is unchanged. GenG1 is used rather than the point
// at infinity because an identity generator is rejected -- it would collapse the
// commitment scheme. This mirrors the padding rp.go applies before its own CSP
// call.
//
// Inputs are not modified; the returned slices are fresh.
func PadToPowerOfTwo(
	generators []*mathlib.G1,
	linearForm []*mathlib.Zr,
	witness []*mathlib.Zr,
	curve *mathlib.Curve,
) ([]*mathlib.G1, []*mathlib.Zr, []*mathlib.Zr, error) {
	if curve == nil {
		return nil, nil, nil, ErrNilCurve
	}
	n := len(generators)
	if n == 0 {
		return nil, nil, nil, errors.Wrapf(ErrInvalidLength, "nothing to pad")
	}
	if len(linearForm) != n {
		return nil, nil, nil, errors.Wrapf(ErrInvalidLength, "linear form has %d coefficients, generators %d", len(linearForm), n)
	}
	if witness != nil && len(witness) != n {
		return nil, nil, nil, errors.Wrapf(ErrInvalidLength, "witness has %d entries, generators %d", len(witness), n)
	}

	padded := 1
	for padded < n {
		padded <<= 1
	}

	outGen := make([]*mathlib.G1, 0, padded)
	outGen = append(outGen, generators...)
	outLF := make([]*mathlib.Zr, 0, padded)
	outLF = append(outLF, linearForm...)
	var outWit []*mathlib.Zr
	if witness != nil {
		outWit = make([]*mathlib.Zr, 0, padded)
		outWit = append(outWit, witness...)
	}

	for len(outGen) < padded {
		outGen = append(outGen, curve.GenG1)
		outLF = append(outLF, curve.NewZrFromInt(0))
		if outWit != nil {
			outWit = append(outWit, curve.NewZrFromInt(0))
		}
	}

	return outGen, outLF, outWit, nil
}
