/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	mathlib "github.com/IBM/mathlib"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/sumcheck"
)

// Titan as a polynomial commitment scheme: setup, statement, witness
//
// This file is a facade. It adds no cryptography -- every line delegates to
// CommitFieldWithFold/CommitGroupWithFold, Eval/EvalGroup and
// VerifyEval/VerifyEvalGroup -- and exists because assembling those correctly
// takes four decisions that are easy to get wrong and whose failures are silent:
//
//  1. The two paths need DIFFERENT domain sizes. The group path encodes all m
//     variables, so it needs 2^(m+logRate). The field path folds only leg 1,
//     which runs over rowVars = m - m/2 variables, so it needs
//     2^(rowVars+logRate) -- passing m there oversizes the domain by 2^(m/2), which
//     is 16x at m=8 and 256x at m=16, all of it paid in the commit FFT. Nothing
//     functional notices: the extra points are simply never read, and the domain
//     size is not absorbed into the transcript, so the mistake is pure cost. See
//     fieldRowVars, and TestPCSSetupSizesTheDomainByTheFoldedHalf, which is the
//     only thing that catches it.
//  2. Folding must be switched ON. CommitField/CommitGroup produce a commitment
//     whose Cosets is nil, and the verifier then *reduces* the claim without
//     closing it: the two legs prove an evaluation of a polynomial nobody
//     committed. Only the WithFold constructors are reachable from here, so a
//     caller cannot obtain an unsound prover from this API at all.
//  3. alpha has m coordinates, not Commitment.NumVars, which counts only the row
//     half of the field matrix. A caller who reads NumVars and sizes alpha from
//     it gets an error on the field path and a wrong answer on neither -- but the
//     mistake is natural enough to be worth removing.
//  4. Generators must be converted once. NewGenerators caches a mathlib
//     conversion that is 15-18% of a prove and the bulk of a verify; building it
//     per call is a silent ~6x on the verifier. FieldSetup does it once.
//
// The vocabulary is the usual one for an argument system. The SETUP is the public
// parameters: the number of variables, the fold configuration and (for the field
// path) the Pedersen generators. The STATEMENT is what is being asserted: the
// evaluation point, and after proving the commitment and the claimed value. The
// WITNESS is the polynomial, which only the prover has.
//
// # What Verify does and does not establish
//
// Verify answers one question: does this proof show that the polynomial behind
// this commitment evaluates to this value at this point? It returns 1 for yes.
//
// It does not establish that the commitment is to any particular polynomial --
// that is what a commitment is for, and a verifier that never saw the witness
// cannot check it. A caller must obtain the commitment from a source it trusts to
// have committed the right thing, or bind it into a larger transcript. Passing the
// prover's own Commitment() straight into the verifier, as the examples below do,
// tests the protocol and proves nothing about provenance.
//
// The scheme is NOT zero-knowledge. The reduced polynomial is sent in plain, so a
// proof reveals partial information about the witness. Deferred by design; see
// docs/crypto/titan.md section 13.13.

// FieldSetup is the public parameter set for the field construction: how many
// variables the committed polynomials have, the Pedersen generators for leg 2, and
// the folding configuration that makes an opening binding.
//
// Build it once with NewFieldSetup and share it between provers and verifiers. It
// holds the converted generators, which are the expensive part, and is read-only
// once built, so it is safe for concurrent use.
type FieldSetup struct {
	numVars int
	fold    FoldConfig
	gens    *Generators
	dom     *Domain
	curve   *mathlib.Curve
}

// NewFieldSetup builds the public parameters for field polynomials in numVars
// variables.
//
// gens must hold at least 2^(numVars/2) generators -- the column count of the
// matrix form, which is what leg 2 opens against. Surplus generators are ignored.
// Call matrixShape if you want the exact number before allocating.
//
// curve is the mathlib curve used for the transcript and leg 2; pass nil for the
// one matching this package's types.
//
// cfg is the folding configuration. Pass the zero FoldConfig to take
// DefaultFoldConfig, which targets 128 bits under the capacity bound. Note the
// field path additionally requires numVars to be divisible by 4, not merely even:
// folding attaches to leg 1, which runs over rowVars = numVars - numVars/2, and
// that must itself be even. numVars = 4, 8, 12 work; 6 and 10 do not, and are
// rejected here rather than surfacing later as a confusing fold error.
func NewFieldSetup(numVars int, gens []bls12381.G1Affine, curve *mathlib.Curve, cfg FoldConfig) (*FieldSetup, error) {
	rowVars := fieldRowVars(numVars)

	if cfg == (FoldConfig{}) {
		var err error
		if cfg, err = DefaultFoldConfig(rowVars); err != nil {
			return nil, errors.WithMessagef(err, "no default fold configuration for %d variables", numVars)
		}
	}
	// Validate against rowVars, which is what the fold phase actually runs over.
	// Validating against numVars would accept configurations the commit step then
	// rejects, and the error would point at the wrong parameter.
	if err := cfg.Validate(rowVars); err != nil {
		return nil, errors.WithMessagef(err,
			"fold configuration is not valid for %d row variables (from %d total)", rowVars, numVars)
	}

	_, numCols := matrixShape(numVars)
	if len(gens) < numCols {
		return nil, errors.Wrapf(ErrInsufficientGenerators,
			"%d variables need %d generators, got %d", numVars, numCols, len(gens))
	}

	cg, err := NewGenerators(curve, gens)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to convert the generators")
	}

	dom, err := NewDomain(rowVars + cfg.LogRate)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to build the domain for %d row variables", rowVars)
	}

	return &FieldSetup{numVars: numVars, fold: cfg, gens: cg, dom: dom, curve: curve}, nil
}

// NumVars returns the number of variables the committed polynomials have.
func (s *FieldSetup) NumVars() int { return s.numVars }

// FoldConfig returns the folding configuration, whose Queries field is the
// security parameter. Callers that record what a proof was checked against should
// record this.
func (s *FieldSetup) FoldConfig() FoldConfig { return s.fold }

// FieldStatement is what a field proof asserts: that the committed polynomial
// evaluates to some value at Alpha.
//
// Alpha has one coordinate per variable of the polynomial -- setup.NumVars() of
// them, not Commitment.NumVars, which counts only the row half of the matrix form.
type FieldStatement struct {
	Alpha []fr.Element
}

// FieldWitness is what only the prover has: the polynomial itself, as an
// evaluation table over the boolean hypercube.
type FieldWitness struct {
	Poly sumcheck.FieldPoly
}

// FieldProver proves evaluations of one committed field polynomial at one point.
//
// The commitment is built by NewFieldProver, so constructing a prover runs the FFT
// and the Merkle tree. A prover is therefore not a cheap object, and proving at k
// points by building k provers over the same polynomial repeats that work; there
// is no sharing of commitments across provers in this facade by design, so that a
// prover always owns a commitment that matches its witness.
type FieldProver struct {
	setup *FieldSetup
	st    FieldStatement
	com   *Commitment
	hint  *FieldOpeningHint
}

// NewFieldProver commits to the witness and prepares to prove the statement.
//
// The commitment is always made WITH folding, so the resulting proof is a binding
// opening rather than a bare reduction of the claim.
//
// This is the expensive call: it encodes the polynomial over the evaluation domain
// and builds the coset Merkle tree. Prove itself is comparatively cheap.
func NewFieldProver(setup *FieldSetup, st FieldStatement, w FieldWitness) (*FieldProver, error) {
	if setup == nil {
		return nil, errors.Wrap(ErrNilElement, "setup is required")
	}
	if err := setup.checkAlpha(st.Alpha); err != nil {
		return nil, err
	}
	if err := setup.checkPoly(len(w.Poly)); err != nil {
		return nil, err
	}

	com, hint, err := CommitFieldWithFold(w.Poly, setup.gens.Affine, setup.dom, 0, setup.fold)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to commit the witness")
	}

	return &FieldProver{setup: setup, st: st, com: com, hint: hint}, nil
}

// Commitment returns the commitment to the witness, to be handed to a verifier.
//
// A verifier that gets this directly from the prover learns nothing about
// provenance -- see the note at the top of this file.
func (p *FieldProver) Commitment() *Commitment { return p.com }

// Prove produces the evaluation proof and the value sigma it computed.
//
// sigma is returned rather than accepted: it is determined by the polynomial and
// the point, so a caller that already believes a value should compare it against
// this one rather than assert it into the proof.
func (p *FieldProver) Prove() (*EvalProof, fr.Element, error) {
	if p == nil {
		return nil, fr.Element{}, errors.Wrap(ErrNilElement, "prover is required")
	}
	return p.hint.Eval(p.setup.curve, p.setup.gens, p.st.Alpha)
}

// FieldVerifier checks field evaluation proofs against one commitment and point.
type FieldVerifier struct {
	setup *FieldSetup
	st    FieldStatement
	com   *Commitment
}

// NewFieldVerifier prepares to check proofs that the polynomial behind com
// evaluates to a claimed value at the statement's point.
//
// A commitment whose Cosets is nil is rejected. Such a commitment came from
// CommitField rather than CommitFieldWithFold, and its proofs only reduce the
// claim without tying it to the commitment -- accepting one here would make this
// API's Verify report 1 for a proof that establishes nothing.
func NewFieldVerifier(setup *FieldSetup, st FieldStatement, com *Commitment) (*FieldVerifier, error) {
	if setup == nil {
		return nil, errors.Wrap(ErrNilElement, "setup is required")
	}
	if com == nil {
		return nil, errors.Wrap(ErrNilElement, "commitment is required")
	}
	if com.Cosets == nil {
		return nil, errors.Wrap(ErrCosetOpeningInvalid,
			"commitment carries no coset oracle, so its proofs cannot be binding: "+
				"commit with CommitFieldWithFold or this package's NewFieldProver")
	}
	if err := setup.checkAlpha(st.Alpha); err != nil {
		return nil, err
	}

	return &FieldVerifier{setup: setup, st: st, com: com}, nil
}

// Verify reports 1 if the proof shows the committed polynomial evaluates to sigma
// at the statement's point, and 0 otherwise.
//
// 0 covers both a proof that fails to verify and a call that was malformed -- a nil
// proof, a sigma of the wrong length, a proof for a different point. Use VerifyErr
// when the difference matters, which during integration it usually does.
func (v *FieldVerifier) Verify(proof *EvalProof, sigma fr.Element) int {
	if v.VerifyErr(proof, sigma) != nil {
		return 0
	}
	return 1
}

// VerifyErr is Verify with the reason for rejection.
//
// A nil return means accepted. The error distinguishes a cryptographic failure
// from a plumbing one, which Verify's 0 cannot: errors.Is against this package's
// sentinels identifies which check failed.
func (v *FieldVerifier) VerifyErr(proof *EvalProof, sigma fr.Element) error {
	if v == nil {
		return errors.Wrap(ErrNilElement, "verifier is required")
	}
	if proof == nil {
		return ErrNilProof
	}
	// VerifyEval's residual opening is recomputed by the verifier rather than
	// trusted, and the fold check above it is what binds the claim to the
	// commitment, so there is nothing left for a caller to close and the opening is
	// deliberately dropped here. This is only true because NewFieldVerifier refuses
	// a commitment without a coset oracle.
	_, err := VerifyEval(v.setup.curve, v.com, v.setup.gens, v.st.Alpha, sigma, proof)

	return err
}

// GroupSetup is the public parameter set for the group construction: the number of
// variables and the folding configuration.
//
// There are no generators, and that is not an omission. A group polynomial's
// evaluation already is a group element, so there is no field value underneath it
// to bind and no Pedersen tier to open; the group commitment is tier 2 alone.
type GroupSetup struct {
	numVars int
	fold    FoldConfig
	dom     *Domain
	curve   *mathlib.Curve
}

// NewGroupSetup builds the public parameters for group polynomials in numVars
// variables.
//
// curve is the mathlib curve used for the transcript; pass nil for the one
// matching this package's types.
//
// cfg is the folding configuration; pass the zero FoldConfig to take
// DefaultFoldConfig. The group path has no matrix split, so it needs only numVars
// even -- unlike the field path, which needs divisibility by 4.
func NewGroupSetup(numVars int, curve *mathlib.Curve, cfg FoldConfig) (*GroupSetup, error) {
	if cfg == (FoldConfig{}) {
		var err error
		if cfg, err = DefaultFoldConfig(numVars); err != nil {
			return nil, errors.WithMessagef(err, "no default fold configuration for %d variables", numVars)
		}
	}
	if err := cfg.Validate(numVars); err != nil {
		return nil, errors.WithMessagef(err, "fold configuration is not valid for %d variables", numVars)
	}

	dom, err := NewDomain(numVars + cfg.LogRate)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to build the domain for %d variables", numVars)
	}

	return &GroupSetup{numVars: numVars, fold: cfg, dom: dom, curve: curve}, nil
}

// NumVars returns the number of variables the committed polynomials have.
func (s *GroupSetup) NumVars() int { return s.numVars }

// FoldConfig returns the folding configuration, whose Queries field is the
// security parameter.
func (s *GroupSetup) FoldConfig() FoldConfig { return s.fold }

// GroupStatement is what a group proof asserts: that the committed group
// polynomial evaluates to some group element at Alpha.
//
// Alpha has one coordinate per variable. Unlike the field path there is no matrix
// split, so this is also Commitment.NumVars.
type GroupStatement struct {
	Alpha []fr.Element
}

// GroupWitness is the group polynomial, as a table of group elements over the
// boolean hypercube.
type GroupWitness struct {
	Poly sumcheck.GroupPoly
}

// GroupProver proves evaluations of one committed group polynomial at one point.
type GroupProver struct {
	setup *GroupSetup
	st    GroupStatement
	com   *Commitment
	hint  *GroupOpeningHint
}

// NewGroupProver commits to the witness and prepares to prove the statement.
//
// As on the field path the commitment is always made WITH folding, and this is the
// expensive call rather than Prove.
func NewGroupProver(setup *GroupSetup, st GroupStatement, w GroupWitness) (*GroupProver, error) {
	if setup == nil {
		return nil, errors.Wrap(ErrNilElement, "setup is required")
	}
	if err := setup.checkAlpha(st.Alpha); err != nil {
		return nil, err
	}
	if err := setup.checkPoly(len(w.Poly)); err != nil {
		return nil, err
	}

	com, hint, err := CommitGroupWithFold(w.Poly, setup.dom, 0, setup.fold)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to commit the witness")
	}

	return &GroupProver{setup: setup, st: st, com: com, hint: hint}, nil
}

// Commitment returns the commitment to the witness, to be handed to a verifier.
func (p *GroupProver) Commitment() *Commitment { return p.com }

// Prove produces the evaluation proof and the group element sigma it computed.
//
// As on the field path sigma is returned rather than accepted, since it is
// determined by the polynomial and the point.
func (p *GroupProver) Prove() (*GroupEvalProof, bls12381.G1Affine, error) {
	if p == nil {
		return nil, bls12381.G1Affine{}, errors.Wrap(ErrNilElement, "prover is required")
	}
	return p.hint.EvalGroup(p.setup.curve, p.st.Alpha)
}

// GroupVerifier checks group evaluation proofs against one commitment and point.
type GroupVerifier struct {
	setup *GroupSetup
	st    GroupStatement
	com   *Commitment
}

// NewGroupVerifier prepares to check proofs that the group polynomial behind com
// evaluates to a claimed element at the statement's point.
//
// A commitment whose Cosets is nil is rejected, for the same reason as on the
// field path: its proofs reduce the claim without binding it to the commitment.
func NewGroupVerifier(setup *GroupSetup, st GroupStatement, com *Commitment) (*GroupVerifier, error) {
	if setup == nil {
		return nil, errors.Wrap(ErrNilElement, "setup is required")
	}
	if com == nil {
		return nil, errors.Wrap(ErrNilElement, "commitment is required")
	}
	if com.Cosets == nil {
		return nil, errors.Wrap(ErrCosetOpeningInvalid,
			"commitment carries no coset oracle, so its proofs cannot be binding: "+
				"commit with CommitGroupWithFold or this package's NewGroupProver")
	}
	if err := setup.checkAlpha(st.Alpha); err != nil {
		return nil, err
	}

	return &GroupVerifier{setup: setup, st: st, com: com}, nil
}

// Verify reports 1 if the proof shows the committed group polynomial evaluates to
// sigma at the statement's point, and 0 otherwise.
//
// As on the field path, 0 covers both a failed proof and a malformed call; use
// VerifyErr to tell them apart.
func (v *GroupVerifier) Verify(proof *GroupEvalProof, sigma *bls12381.G1Affine) int {
	if v.VerifyErr(proof, sigma) != nil {
		return 0
	}
	return 1
}

// VerifyErr is Verify with the reason for rejection; a nil return means accepted.
func (v *GroupVerifier) VerifyErr(proof *GroupEvalProof, sigma *bls12381.G1Affine) error {
	if v == nil {
		return errors.Wrap(ErrNilElement, "verifier is required")
	}
	if proof == nil {
		return ErrNilProof
	}
	if sigma == nil {
		return errors.Wrap(ErrNilElement, "claimed value is required")
	}
	// The residual opening is dropped for the same reason as on the field path: the
	// fold check binds the claim, and NewGroupVerifier guarantees it ran.
	_, err := VerifyEvalGroup(v.setup.curve, v.com, v.st.Alpha, sigma, proof)

	return err
}

// fieldRowVars returns the number of variables leg 1 of the field construction
// runs over, which is what the folding phase and the evaluation domain are sized
// by -- not the polynomial's own variable count.
//
// The matrix form splits m variables into m/2 columns and m - m/2 rows, and leg 1
// is the row half. This is the source of the m divisible by 4 requirement: rowVars
// must itself be even for the fold to attach.
func fieldRowVars(m int) int { return m - m/2 }

// checkAlpha rejects an evaluation point of the wrong arity.
//
// The message names both counts because the natural mistake is to size alpha from
// Commitment.NumVars, which on the field path is the row half rather than the
// total.
func (s *FieldSetup) checkAlpha(alpha []fr.Element) error {
	if len(alpha) != s.numVars {
		return errors.Wrapf(ErrNumVarsMismatch,
			"setup is for %d variables, statement point has %d coordinates", s.numVars, len(alpha))
	}
	return nil
}

// checkPoly rejects a witness whose table does not describe numVars variables.
func (s *FieldSetup) checkPoly(length int) error {
	if want := 1 << s.numVars; length != want {
		return errors.Wrapf(ErrNumVarsMismatch,
			"setup is for %d variables, witness holds %d evaluations, expected %d",
			s.numVars, length, want)
	}
	return nil
}

// checkAlpha rejects an evaluation point of the wrong arity.
func (s *GroupSetup) checkAlpha(alpha []fr.Element) error {
	if len(alpha) != s.numVars {
		return errors.Wrapf(ErrNumVarsMismatch,
			"setup is for %d variables, statement point has %d coordinates", s.numVars, len(alpha))
	}
	return nil
}

// checkPoly rejects a witness whose table does not describe numVars variables.
func (s *GroupSetup) checkPoly(length int) error {
	if want := 1 << s.numVars; length != want {
		return errors.Wrapf(ErrNumVarsMismatch,
			"setup is for %d variables, witness holds %d evaluations, expected %d",
			s.numVars, length, want)
	}
	return nil
}
