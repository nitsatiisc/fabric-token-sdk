/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pivot

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/rp/csp"
	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/sumcheck"
	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/titan"
)

// AbsorbCommitments is the verifier's counterpart of Commit: it binds the sizes and
// both commitments into tr, leaving it in the state Commit left the prover's in.
func AbsorbCommitments(setup *Setup, coms Commitments, tr *csp.Transcript) error {
	if setup == nil {
		return errors.Wrap(ErrInvalidSizes, "setup is required")
	}
	if tr == nil {
		return errors.New("transcript is required")
	}

	return absorbSetupAndCommitments(tr, setup.sizes, coms)
}

// Verify checks a proof that every instance behind coms satisfies the relation and
// that the statement's public columns agree with the committed H.
//
// tr must be in the state AbsorbCommitments left it in, advanced by exactly what
// the prover's caller squeezed before Prove. On success it returns the aggregation
// challenge and the revealed column aggregates.
//
// A returned error wrapping ErrMalformedProof means the proof is structurally
// wrong; one wrapping ErrVerificationFailed, or a sum-check or PCS error, means it
// is well formed but false.
func Verify(setup *Setup, rel *Relation, st *Statement, coms Commitments, proof *Proof, tr *csp.Transcript) (*Outcome, error) {
	if setup == nil {
		return nil, errors.Wrap(ErrInvalidSizes, "setup is required")
	}
	if tr == nil {
		return nil, errors.New("transcript is required")
	}
	if st == nil {
		st = &Statement{}
	}
	s := setup.sizes
	if err := st.validate(s); err != nil {
		return nil, err
	}
	if err := rel.validate(s, st.publicWidth()); err != nil {
		return nil, err
	}
	if err := proof.checkShape(rel, st); err != nil {
		return nil, err
	}

	v := &verifier{setup: setup, rel: rel, st: st, coms: coms, proof: proof, tr: tr}
	for _, step := range []func() error{
		v.bindAndAggregate, v.sc1, v.sc1Pub, v.sc2, v.sc3, v.sc4, v.batchW, v.batchG,
	} {
		if err := step(); err != nil {
			return nil, err
		}
	}

	return &Outcome{Tau: v.tau, Revealed: proof.Revealed}, nil
}

// verifier carries the state that flows between the verification steps.
type verifier struct {
	setup *Setup
	rel   *Relation
	st    *Statement
	coms  Commitments
	proof *Proof
	tr    *csp.Transcript

	tau         []fr.Element
	eqTau       []fr.Element
	t1, t1Pub   bls12381.G1Affine
	rhoC, rhoK  []fr.Element
	rhoT, rhoKP []fr.Element
	rhoL        []fr.Element
	rhoP        []fr.Element
	sigma       []fr.Element
	wPts        [][]fr.Element
}

// failed wraps a verification failure with the step that detected it.
func failed(step string) error {
	return errors.Wrapf(ErrVerificationFailed, "%s", step)
}

func (v *verifier) bindAndAggregate() error {
	absorbRelation(v.tr, v.rel)
	absorbStatement(v.tr, v.st)
	var err error
	if v.tau, err = squeezeFrs(v.tr, v.setup.sizes.LogK); err != nil {
		return err
	}
	v.eqTau = eqTable(v.tau)

	return nil
}

// sc1 checks the aggregation sum-check and its residual
//
//	p(R) = eq(rho_K, tau) * (Lambda~(rho_c) + v_P) * g~(rho_c, rho_K).
func (v *verifier) sc1() error {
	s := v.setup.sizes
	open, err := sumcheck.VerifyWithTranscript(v.setup.curve,
		sumcheck.Shape{NumVars: s.LogC + s.LogK, NumFieldFactors: 2, HasGroupFactor: true}, v.proof.SC1, v.tr)
	if err != nil {
		return errors.WithMessage(err, "SC1")
	}
	if v.t1, err = fromG1(v.proof.SC1.GroupSum); err != nil {
		return err
	}
	pt := tablePoint(open.R)
	v.rhoC, v.rhoK = pt[:s.LogC], pt[s.LogC:]
	absorbFr(v.tr, &v.proof.PEval)
	absorbG1(v.tr, &v.proof.GEval)

	coef := innerProduct(v.rel.Alpha, eqTable(v.rhoC))
	coef.Add(&coef, &v.proof.PEval)
	eqK := eqEval(v.rhoK, v.tau)
	coef.Mul(&coef, &eqK)
	want := scale(v.proof.GEval, coef)
	got, err := fromG1(open.GroupEval)
	if err != nil {
		return err
	}
	if !got.Equal(&want) {
		return failed("SC1 residual")
	}

	return nil
}

// sc1Pub checks the sum-check over the public table and closes its residual
//
//	p(R) = eq(rho_K', tau) * (LambdaPub~(rho_t) + v_P') * X~(rho_t, rho_K')
//
// where X~ is the public table's multilinear extension, which the verifier
// evaluates itself: one MSM over all cp*K public elements. This is where the
// verifier reads the per-instance public data, which it has to do in any case.
func (v *verifier) sc1Pub() error {
	cp := v.st.publicWidth()
	if cp == 0 {
		return nil
	}
	s := v.setup.sizes
	logCp := log2(cp)
	open, err := sumcheck.VerifyWithTranscript(v.setup.curve,
		sumcheck.Shape{NumVars: logCp + s.LogK, NumFieldFactors: 2, HasGroupFactor: true}, v.proof.SC1Pub, v.tr)
	if err != nil {
		return errors.WithMessage(err, "SC1Pub")
	}
	if v.t1Pub, err = fromG1(v.proof.SC1Pub.GroupSum); err != nil {
		return err
	}
	pt := tablePoint(open.R)
	v.rhoT, v.rhoKP = pt[:logCp], pt[logCp:]
	absorbFr(v.tr, &v.proof.PubEval)

	xAt, err := msm(flattenPublic(v.st.Public), eqTable(pt))
	if err != nil {
		return err
	}
	coef := innerProduct(v.rel.AlphaPub, eqTable(v.rhoT))
	coef.Add(&coef, &v.proof.PubEval)
	eqK := eqEval(v.rhoKP, v.tau)
	coef.Mul(&coef, &eqK)
	want := scale(xAt, coef)
	got, err := fromG1(open.GroupEval)
	if err != nil {
		return err
	}
	if !got.Equal(&want) {
		return failed("SC1Pub residual")
	}

	return nil
}

// sc2 checks that the public-generator sum closes the group equation,
// sum = -G0 - T1 - T1Pub, and its residual p(R) = v_Q * G~(rho_l).
func (v *verifier) sc2() error {
	s := v.setup.sizes
	sum, err := fromG1(v.proof.SC2.GroupSum)
	if err != nil {
		return err
	}
	want := neg(add(add(v.rel.G0, v.t1), v.t1Pub))
	if !sum.Equal(&want) {
		return failed("SC2 sum: the K group equations do not hold")
	}
	open, err := sumcheck.VerifyWithTranscript(v.setup.curve,
		sumcheck.Shape{NumVars: s.LogL, NumFieldFactors: 1, HasGroupFactor: true}, v.proof.SC2, v.tr)
	if err != nil {
		return errors.WithMessage(err, "SC2")
	}
	v.rhoL = tablePoint(open.R)
	absorbFr(v.tr, &v.proof.QEval)

	gAt, err := msm(v.rel.G, eqTable(v.rhoL))
	if err != nil {
		return err
	}
	want = scale(gAt, v.proof.QEval)
	got, err := fromG1(open.GroupEval)
	if err != nil {
		return err
	}
	if !got.Equal(&want) {
		return failed("SC2 residual")
	}

	return nil
}

// sc3 checks the field zero-check and its residual p(R) = eq(rho', tau) Phi(form values).
func (v *verifier) sc3() error {
	if !v.rel.hasFieldConstraint() {
		return nil
	}
	s := v.setup.sizes
	if sum := fromZr(v.proof.SC3.FieldSum); !sum.IsZero() {
		return failed("SC3 sum: the K field constraints do not hold")
	}
	open, err := sumcheck.VerifyMultiWithTranscript(v.setup.curve,
		sumcheck.MultiShape{NumVars: s.LogK, Degree: 1 + v.rel.phiDegree()}, v.proof.SC3, v.tr)
	if err != nil {
		return errors.WithMessage(err, "SC3")
	}
	v.rhoP = tablePoint(open.R)
	absorbFrs(v.tr, v.proof.FormEvals)

	want := phiValue(v.rel.Phi, v.proof.FormEvals)
	eqP := eqEval(v.rhoP, v.tau)
	want.Mul(&want, &eqP)
	if got := fromZr(open.Product); !got.Equal(&want) {
		return failed("SC3 residual")
	}

	return nil
}

// formsLinearEval returns sum_k lambda^k (linear part of L_k)~(sigma) from the eq
// table of sigma, one multiply-add per coefficient.
func formsLinearEval(forms []AffineForm, lambda fr.Element, eqSigma []fr.Element) fr.Element {
	pw := powers(lambda, len(forms))
	var out fr.Element
	for k, f := range forms {
		for _, e := range f.Coeffs {
			var t fr.Element
			t.Mul(&e.Val, &eqSigma[e.Col])
			t.Mul(&t, &pw[k])
			out.Add(&out, &t)
		}
	}

	return out
}

// sc4 checks the sparse-product sum-check against the values it discharges and its
// residual against the public selectors at sigma. The terms are those of the
// prover's sc4, in the same order: theta^j weights term j, whose selector S_j is
// evaluated from its non-zeros alone and whose W~ value is WEvals[j].
func (v *verifier) sc4() error {
	s := v.setup.sizes
	theta, err := squeezeFr(v.tr)
	if err != nil {
		return err
	}
	type term struct {
		value fr.Element                            // the value this term discharges
		sel   func(eqSigma []fr.Element) fr.Element // S_j(sigma)
		z     []fr.Element
	}
	terms := []term{
		{v.proof.PEval, func(e []fr.Element) fr.Element { return sparseEval(v.rel.B, eqTable(v.rhoC), e) }, v.rhoK},
		{v.proof.QEval, func(e []fr.Element) fr.Element { return sparseEval(v.rel.Gamma, eqTable(v.rhoL), e) }, v.tau},
	}
	if v.rel.hasFieldConstraint() {
		lambda, err := squeezeFr(v.tr)
		if err != nil {
			return err
		}
		pw := powers(lambda, len(v.rel.Forms))
		var forms fr.Element
		for k, f := range v.rel.Forms {
			var t fr.Element
			t.Sub(&v.proof.FormEvals[k], &f.Const)
			t.Mul(&t, &pw[k])
			forms.Add(&forms, &t)
		}
		terms = append(terms, term{forms, func(e []fr.Element) fr.Element { return formsLinearEval(v.rel.Forms, lambda, e) }, v.rhoP})
	}
	if v.st.publicWidth() > 0 {
		terms = append(terms, term{v.proof.PubEval, func(e []fr.Element) fr.Element { return sparseEval(v.rel.BPub, eqTable(v.rhoT), e) }, v.rhoKP})
	}

	pw := powers(theta, len(terms))
	var target fr.Element
	for j, t := range terms {
		var x fr.Element
		x.Mul(&t.value, &pw[j])
		target.Add(&target, &x)
	}
	if got := fromZr(v.proof.SC4.FieldSum); !got.Equal(&target) {
		return failed("SC4 sum: the sparse products disagree with the values they discharge")
	}

	open, err := sumcheck.VerifyMultiWithTranscript(v.setup.curve,
		sumcheck.MultiShape{NumVars: s.LogN, Degree: 2}, v.proof.SC4, v.tr)
	if err != nil {
		return errors.WithMessage(err, "SC4")
	}
	v.sigma = tablePoint(open.R)
	absorbFrs(v.tr, v.proof.WEvals)

	eqSigma := eqTable(v.sigma)
	var want fr.Element
	v.wPts = make([][]fr.Element, len(terms))
	for j, t := range terms {
		x := t.sel(eqSigma)
		x.Mul(&x, &v.proof.WEvals[j])
		x.Mul(&x, &pw[j])
		want.Add(&want, &x)
		v.wPts[j] = concat(v.sigma, t.z)
	}
	if got := fromZr(open.Product); !got.Equal(&want) {
		return failed("SC4 residual")
	}

	return nil
}

// batchW checks the reduction of the WEvals claims and the field PCS opening.
func (v *verifier) batchW() error {
	s := v.setup.sizes
	pts := v.wPts
	gamma, err := squeezeFr(v.tr)
	if err != nil {
		return err
	}
	if got, want := fromZr(v.proof.WBatch.FieldSum), batchFieldValue(v.proof.WEvals, gamma); !got.Equal(&want) {
		return failed("field batch sum")
	}
	open, err := sumcheck.VerifyWithTranscript(v.setup.curve,
		sumcheck.Shape{NumVars: s.LogN + s.LogK, NumFieldFactors: 2}, v.proof.WBatch, v.tr)
	if err != nil {
		return errors.WithMessage(err, "field evaluation batch")
	}
	rho := tablePoint(open.R)
	absorbFr(v.tr, &v.proof.WOpen)

	want := batchWeight(pts, gamma, rho)
	want.Mul(&want, &v.proof.WOpen)
	if got := fromZr(open.Product); !got.Equal(&want) {
		return failed("field batch residual")
	}

	pcs, err := titan.NewFieldVerifier(v.setup.field, titan.FieldStatement{Alpha: rho}, v.coms.W)
	if err != nil {
		return errors.WithMessage(err, "field commitment")
	}
	if err := pcs.VerifyErr(v.proof.WPCS, v.proof.WOpen); err != nil {
		return errors.WithMessage(err, "field opening")
	}

	return nil
}

// batchG checks the reduction of the g~ claims -- the SC1 value, the public columns
// against the statement, the revealed columns -- and the group PCS opening.
func (v *verifier) batchG() error {
	s := v.setup.sizes
	absorbG1s(v.tr, v.proof.Revealed)

	vals := append([]bls12381.G1Affine{v.proof.GEval}, v.proof.Revealed...)
	pts := gPoints(s, v.st, v.rhoC, v.rhoK, v.tau)

	gamma, err := squeezeFr(v.tr)
	if err != nil {
		return err
	}
	want, err := batchGroupValue(vals, gamma)
	if err != nil {
		return err
	}
	sum, err := fromG1(v.proof.GBatch.GroupSum)
	if err != nil {
		return err
	}
	if !sum.Equal(&want) {
		return failed("group batch sum: g~ disagrees with SC1 or with a revealed column")
	}
	open, err := sumcheck.VerifyWithTranscript(v.setup.curve,
		sumcheck.Shape{NumVars: s.LogC + s.LogK, NumFieldFactors: 1, HasGroupFactor: true}, v.proof.GBatch, v.tr)
	if err != nil {
		return errors.WithMessage(err, "group evaluation batch")
	}
	rho := tablePoint(open.R)
	absorbG1(v.tr, &v.proof.GOpen)

	want = scale(v.proof.GOpen, batchWeight(pts, gamma, rho))
	got, err := fromG1(open.GroupEval)
	if err != nil {
		return err
	}
	if !got.Equal(&want) {
		return failed("group batch residual")
	}

	pcs, err := titan.NewGroupVerifier(v.setup.group, titan.GroupStatement{Alpha: rho}, v.coms.G)
	if err != nil {
		return errors.WithMessage(err, "group commitment")
	}
	if err := pcs.VerifyErr(v.proof.GPCS, &v.proof.GOpen); err != nil {
		return errors.WithMessage(err, "group opening")
	}

	return nil
}
