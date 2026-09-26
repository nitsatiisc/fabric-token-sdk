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

// Committed is the prover's state after Commit: the witness, its tables, and the
// two PCS provers that hold the openings.
type Committed struct {
	setup  *Setup
	wit    *Witness
	wTable sumcheck.FieldPoly
	gTable sumcheck.GroupPoly
	fp     *titan.FieldProver
	gp     *titan.GroupProver
}

// Commitments returns the commitments to hand to the verifier.
func (c *Committed) Commitments() Commitments {
	return Commitments{W: c.fp.Commitment(), G: c.gp.Commitment()}
}

// Commit commits to the witness and binds the sizes and both commitments into tr.
//
// A caller whose relation depends on challenges squeezes them from tr after Commit
// and before Prove; the verifier does the same after AbsorbCommitments.
func Commit(setup *Setup, w *Witness, tr *csp.Transcript) (*Committed, error) {
	if setup == nil {
		return nil, errors.Wrap(ErrInvalidSizes, "setup is required")
	}
	if tr == nil {
		return nil, errors.New("transcript is required")
	}
	s := setup.sizes
	if err := w.validate(s); err != nil {
		return nil, err
	}

	// Position-first layout: entry x + (z << log n) is w^(z)[x].
	wTable := make(sumcheck.FieldPoly, s.N()*s.K())
	gTable := make(sumcheck.GroupPoly, s.C()*s.K())
	for z := range s.K() {
		copy(wTable[z*s.N():], w.W[z])
		copy(gTable[z*s.C():], w.H[z])
	}

	fp, err := titan.NewFieldProver(setup.field, titan.FieldStatement{}, titan.FieldWitness{Poly: wTable})
	if err != nil {
		return nil, errors.WithMessage(err, "failed to commit to the field witness")
	}
	gp, err := titan.NewGroupProver(setup.group, titan.GroupStatement{}, titan.GroupWitness{Poly: gTable})
	if err != nil {
		return nil, errors.WithMessage(err, "failed to commit to the group witness")
	}

	c := &Committed{setup: setup, wit: w, wTable: wTable, gTable: gTable, fp: fp, gp: gp}
	if err := absorbSetupAndCommitments(tr, s, c.Commitments()); err != nil {
		return nil, err
	}

	return c, nil
}

// Prove proves that every instance of the committed witness satisfies the relation
// and that the public columns of the statement agree with the committed H.
//
// tr must be the transcript Commit absorbed into, advanced by whatever the caller
// squeezed in between. Prove does not check the relation itself: a false witness
// produces a proof that fails verification.
//
// Besides the proof it returns the same Outcome Verify does -- the aggregation
// challenge and the revealed column aggregates -- for a caller that proves further
// statements about them, as the UTXO instantiation does with its aggregated Schnorr
// proofs.
func Prove(setup *Setup, rel *Relation, st *Statement, c *Committed, tr *csp.Transcript) (*Proof, *Outcome, error) {
	if setup == nil || c == nil || c.setup != setup {
		return nil, nil, errors.Wrap(ErrInvalidSizes, "the committed state must come from this setup")
	}
	if tr == nil {
		return nil, nil, errors.New("transcript is required")
	}
	if st == nil {
		st = &Statement{}
	}
	s := setup.sizes
	if err := st.validate(s); err != nil {
		return nil, nil, err
	}
	if err := rel.validate(s, st.publicWidth()); err != nil {
		return nil, nil, err
	}

	p := &prover{setup: setup, rel: rel, st: st, c: c, tr: tr, proof: &Proof{}}
	for _, step := range []func() error{
		p.bindAndAggregate, p.sc1, p.sc1Pub, p.sc2, p.sc3, p.sc4, p.batchW, p.batchG,
	} {
		if err := step(); err != nil {
			return nil, nil, err
		}
	}

	return p.proof, &Outcome{Tau: p.tau, Revealed: p.proof.Revealed}, nil
}

// prover carries the state that flows between the protocol steps.
type prover struct {
	setup *Setup
	rel   *Relation
	st    *Statement
	c     *Committed
	tr    *csp.Transcript
	proof *Proof

	tau   []fr.Element
	eqTau []fr.Element
	wTau  []fr.Element // W~(., tau)

	rhoC, rhoK  []fr.Element // SC1 point
	bRho        []fr.Element // B~(rho_c, .)
	wRhoK       []fr.Element // W~(., rho_K)
	rhoT, rhoKP []fr.Element // SC1Pub point
	bPubRho     []fr.Element // BPub~(rho_t, .)
	rhoL        []fr.Element // SC2 point
	rhoP        []fr.Element // SC3 point
	sigma       []fr.Element // SC4 point
	wPts        [][]fr.Element
}

// bindAndAggregate binds the relation and statement and draws tau.
func (p *prover) bindAndAggregate() error {
	absorbRelation(p.tr, p.rel)
	absorbStatement(p.tr, p.st)
	var err error
	if p.tau, err = squeezeFrs(p.tr, p.setup.sizes.LogK); err != nil {
		return err
	}
	p.eqTau = eqTable(p.tau)
	p.wTau = restrictRows(p.c.wit.W, p.eqTau, p.setup.sizes.N())

	return nil
}

// sc1 runs sum_{b,z} eq(z,tau) (alpha_b + (B w^(z))_b) g^(z)_b = T1 as the
// three-factor product eq * S * g over log c + log K variables.
func (p *prover) sc1() error {
	s := p.setup.sizes
	e1 := make(sumcheck.FieldPoly, s.C()*s.K())
	sTab := make(sumcheck.FieldPoly, s.C()*s.K())
	for z := range s.K() {
		bw := sparseApply(p.rel.B, p.c.wit.W[z], s.C())
		for b := range s.C() {
			i := b + z*s.C()
			e1[i] = p.eqTau[z]
			sTab[i].Add(&p.rel.Alpha[b], &bw[b])
		}
	}

	proof, open, err := sumcheck.ProveWithTranscript(p.setup.curve,
		&sumcheck.Claim{Field: []sumcheck.FieldPoly{e1, sTab}, Group: p.c.gTable}, p.tr)
	if err != nil {
		return errors.WithMessage(err, "SC1")
	}
	pt := tablePoint(open.R)
	p.rhoC, p.rhoK = pt[:s.LogC], pt[s.LogC:]

	eqC := eqTable(p.rhoC)
	p.bRho = sparseRowCombine(p.rel.B, eqC, s.N())
	p.wRhoK = restrictRows(p.c.wit.W, eqTable(p.rhoK), s.N())
	vP := innerProduct(p.bRho, p.wRhoK)

	// S~(rho_c, rho_K) = Lambda~(rho_c) + v_P, since alpha is constant in z.
	want := innerProduct(p.rel.Alpha, eqC)
	want.Add(&want, &vP)
	if got := fromZr(open.FieldEvals[1]); !got.Equal(&want) {
		return errors.Wrap(ErrInternal, "SC1 residual does not split as Lambda + v_P")
	}
	gEval, err := fromG1(open.GroupEval)
	if err != nil {
		return err
	}

	p.proof.SC1, p.proof.PEval, p.proof.GEval = proof, vP, gEval
	absorbFr(p.tr, &p.proof.PEval)
	absorbG1(p.tr, &p.proof.GEval)

	return nil
}

// flattenPublic returns the public table position-first: entry t + (z << log cp) is
// Public[z][t].
func flattenPublic(pub [][]bls12381.G1Affine) sumcheck.GroupPoly {
	if len(pub) == 0 {
		return nil
	}
	cp := len(pub[0])
	out := make(sumcheck.GroupPoly, cp*len(pub))
	for z, row := range pub {
		copy(out[z*cp:], row)
	}

	return out
}

// sc1Pub runs SC1 over the statement's public table instead of the committed H:
//
//	sum_{t,z} eq(z,tau) (AlphaPub_t + (BPub w^(z))_t) x^(z)_t = T1Pub
//
// The table is public, so nothing about it is committed: the verifier evaluates it
// itself at the final point. It is skipped when the statement has no public table.
func (p *prover) sc1Pub() error {
	cp := p.st.publicWidth()
	if cp == 0 {
		return nil
	}
	s := p.setup.sizes
	logCp := log2(cp)
	e1 := make(sumcheck.FieldPoly, cp*s.K())
	sTab := make(sumcheck.FieldPoly, cp*s.K())
	for z := range s.K() {
		bw := sparseApply(p.rel.BPub, p.c.wit.W[z], cp)
		for t := range cp {
			i := t + z*cp
			e1[i] = p.eqTau[z]
			sTab[i].Add(&p.rel.AlphaPub[t], &bw[t])
		}
	}

	proof, open, err := sumcheck.ProveWithTranscript(p.setup.curve,
		&sumcheck.Claim{Field: []sumcheck.FieldPoly{e1, sTab}, Group: flattenPublic(p.st.Public)}, p.tr)
	if err != nil {
		return errors.WithMessage(err, "SC1Pub")
	}
	pt := tablePoint(open.R)
	p.rhoT, p.rhoKP = pt[:logCp], pt[logCp:]

	eqT := eqTable(p.rhoT)
	p.bPubRho = sparseRowCombine(p.rel.BPub, eqT, s.N())
	vP := innerProduct(p.bPubRho, restrictRows(p.c.wit.W, eqTable(p.rhoKP), s.N()))
	want := innerProduct(p.rel.AlphaPub, eqT)
	want.Add(&want, &vP)
	if got := fromZr(open.FieldEvals[1]); !got.Equal(&want) {
		return errors.Wrap(ErrInternal, "SC1Pub residual does not split as LambdaPub + v_P'")
	}
	p.proof.SC1Pub, p.proof.PubEval = proof, vP
	absorbFr(p.tr, &p.proof.PubEval)

	return nil
}

// log2 returns log2 of a power of two.
func log2(n int) int {
	l := 0
	for 1<<l < n {
		l++
	}

	return l
}

// sc2 runs sum_y (Gamma W_tau)_y G_y = -G0 - T1 - T1Pub over log l variables.
func (p *prover) sc2() error {
	qTau := sparseApply(p.rel.Gamma, p.wTau, p.setup.sizes.L())
	gens := append(sumcheck.GroupPoly(nil), p.rel.G...)

	proof, open, err := sumcheck.ProveWithTranscript(p.setup.curve,
		&sumcheck.Claim{Field: []sumcheck.FieldPoly{qTau}, Group: gens}, p.tr)
	if err != nil {
		return errors.WithMessage(err, "SC2")
	}
	p.rhoL = tablePoint(open.R)
	p.proof.SC2, p.proof.QEval = proof, fromZr(open.FieldEvals[0])
	absorbFr(p.tr, &p.proof.QEval)

	return nil
}

// phiTerms returns SC3's terms over the pool [eq(., tau), L~_1, ..., L~_tau]: every
// monomial of Phi multiplied by the eq factor.
func phiTerms(phi []Monomial) []sumcheck.Term {
	terms := make([]sumcheck.Term, len(phi))
	for m, mono := range phi {
		factors := make([]int, 0, 1+len(mono.Vars))
		factors = append(factors, 0)
		for _, v := range mono.Vars {
			factors = append(factors, 1+v)
		}
		terms[m] = sumcheck.Term{Coeff: mono.Coeff, Factors: factors}
	}

	return terms
}

// sc3 runs the zero-check sum_z eq(z,tau) Phi(L~_1(z), ...) = 0 over log K
// variables. It is skipped when the relation has no field constraint.
func (p *prover) sc3() error {
	if !p.rel.hasFieldConstraint() {
		return nil
	}
	s := p.setup.sizes
	pool := make([]sumcheck.FieldPoly, 1+len(p.rel.Forms))
	pool[0] = append(sumcheck.FieldPoly(nil), p.eqTau...)
	for k, f := range p.rel.Forms {
		tab := make(sumcheck.FieldPoly, s.K())
		for z := range s.K() {
			tab[z] = formValue(f, p.c.wit.W[z])
		}
		pool[1+k] = tab
	}

	proof, open, err := sumcheck.ProveMultiWithTranscript(p.setup.curve,
		&sumcheck.MultiClaim{Polys: pool, Terms: phiTerms(p.rel.Phi)}, p.tr)
	if err != nil {
		return errors.WithMessage(err, "SC3")
	}
	p.rhoP = tablePoint(open.R)
	evals := make([]fr.Element, len(p.rel.Forms))
	for k := range evals {
		evals[k] = fromZr(open.FieldEvals[1+k])
	}
	p.proof.SC3, p.proof.FormEvals = proof, evals
	absorbFrs(p.tr, p.proof.FormEvals)

	return nil
}

// formsLinearCombination returns sum_k lambda^k (linear part of L_k) as a dense
// n-vector.
func formsLinearCombination(forms []AffineForm, lambda fr.Element, n int) []fr.Element {
	pw := powers(lambda, len(forms))
	out := make([]fr.Element, n)
	for k, f := range forms {
		for _, e := range f.Coeffs {
			var t fr.Element
			t.Mul(&e.Val, &pw[k])
			out[e.Col].Add(&out[e.Col], &t)
		}
	}

	return out
}

// sc4 discharges every sparse product left by the earlier sum-checks in one
// sum-check over x. Term j is theta^j S_j(x) W~(x, z_j):
//
//	j = 0: S = B~(rho_c, .),     z = rho_K    discharges v_P
//	j = 1: S = Gamma~(rho_l, .), z = tau      discharges v_Q
//	j = 2: S = A,                z = rho'     discharges sum_k lambda^k (L~_k(rho') - Const_k)
//	j = 3: S = BPub~(rho_t, .),  z = rho_K'   discharges v_P'
//
// with A = sum_k lambda^k (linear part of L_k). Terms 2 and 3 are present only with
// a field constraint and with a public table respectively; the numbering closes up.
func (p *prover) sc4() error {
	s := p.setup.sizes
	theta, err := squeezeFr(p.tr)
	if err != nil {
		return err
	}
	type sel struct {
		table []fr.Element
		z     []fr.Element
		w     []fr.Element
	}
	sels := []sel{
		{p.bRho, p.rhoK, p.wRhoK},
		{sparseRowCombine(p.rel.Gamma, eqTable(p.rhoL), s.N()), p.tau, p.wTau},
	}
	if p.rel.hasFieldConstraint() {
		lambda, err := squeezeFr(p.tr)
		if err != nil {
			return err
		}
		sels = append(sels, sel{formsLinearCombination(p.rel.Forms, lambda, s.N()), p.rhoP, nil})
	}
	if p.st.publicWidth() > 0 {
		sels = append(sels, sel{p.bPubRho, p.rhoKP, nil})
	}

	pw := powers(theta, len(sels))
	pool := make([]sumcheck.FieldPoly, 0, 2*len(sels))
	terms := make([]sumcheck.Term, len(sels))
	for j, sl := range sels {
		w := sl.w
		if w == nil {
			w = restrictRows(p.c.wit.W, eqTable(sl.z), s.N())
		}
		pool = append(pool, sl.table, w)
		terms[j] = sumcheck.Term{Coeff: pw[j], Factors: []int{2 * j, 2*j + 1}}
	}

	proof, open, err := sumcheck.ProveMultiWithTranscript(p.setup.curve,
		&sumcheck.MultiClaim{Polys: pool, Terms: terms}, p.tr)
	if err != nil {
		return errors.WithMessage(err, "SC4")
	}
	p.sigma = tablePoint(open.R)
	evals := make([]fr.Element, len(sels))
	p.wPts = make([][]fr.Element, len(sels))
	for j, sl := range sels {
		evals[j] = fromZr(open.FieldEvals[2*j+1])
		p.wPts[j] = concat(p.sigma, sl.z)
	}
	p.proof.SC4, p.proof.WEvals = proof, evals
	absorbFrs(p.tr, p.proof.WEvals)

	return nil
}

// batchW reduces the WEvals claims to one point and opens W~ there.
func (p *prover) batchW() error {
	pts := p.wPts
	gamma, err := squeezeFr(p.tr)
	if err != nil {
		return err
	}
	proof, open, err := sumcheck.ProveWithTranscript(p.setup.curve,
		&sumcheck.Claim{Field: []sumcheck.FieldPoly{batchTable(pts, gamma), p.c.wTable}}, p.tr)
	if err != nil {
		return errors.WithMessage(err, "field evaluation batch")
	}
	rho := tablePoint(open.R)
	p.proof.WBatch, p.proof.WOpen = proof, fromZr(open.FieldEvals[1])
	absorbFr(p.tr, &p.proof.WOpen)

	pcs, sigma, err := p.c.fp.ProveAt(rho)
	if err != nil {
		return errors.WithMessage(err, "failed to open the field commitment")
	}
	if !sigma.Equal(&p.proof.WOpen) {
		return errors.Wrap(ErrInternal, "field opening disagrees with the batch residual")
	}
	p.proof.WPCS = pcs

	return nil
}

// columnAggregate returns sum_k eqTau[k] H[k][col].
func columnAggregate(h [][]bls12381.G1Affine, col int, eqTau []fr.Element) (bls12381.G1Affine, error) {
	pts := make([]bls12381.G1Affine, len(h))
	for k := range h {
		pts[k] = h[k][col]
	}

	return msm(pts, eqTau)
}

// gPoints returns the points of the g~ claims: the SC1 point, then every revealed
// column at instance point tau.
func gPoints(s Sizes, st *Statement, rhoC, rhoK, tau []fr.Element) [][]fr.Element {
	pts := [][]fr.Element{concat(rhoC, rhoK)}
	for _, col := range st.RevealCols {
		pts = append(pts, concat(boolPoint(col, s.LogC), tau))
	}

	return pts
}

// batchG discloses the revealed columns, reduces every g~ claim to one point and
// opens g~ there.
func (p *prover) batchG() error {
	s := p.setup.sizes
	p.proof.Revealed = make([]bls12381.G1Affine, len(p.st.RevealCols))
	for j, col := range p.st.RevealCols {
		v, err := columnAggregate(p.c.wit.H, col, p.eqTau)
		if err != nil {
			return err
		}
		p.proof.Revealed[j] = v
	}
	absorbG1s(p.tr, p.proof.Revealed)

	pts := gPoints(s, p.st, p.rhoC, p.rhoK, p.tau)
	gamma, err := squeezeFr(p.tr)
	if err != nil {
		return err
	}
	proof, open, err := sumcheck.ProveWithTranscript(p.setup.curve,
		&sumcheck.Claim{Field: []sumcheck.FieldPoly{batchTable(pts, gamma)}, Group: p.c.gTable}, p.tr)
	if err != nil {
		return errors.WithMessage(err, "group evaluation batch")
	}
	rho := tablePoint(open.R)
	gOpen, err := fromG1(open.GroupEval)
	if err != nil {
		return err
	}
	p.proof.GBatch, p.proof.GOpen = proof, gOpen
	absorbG1(p.tr, &p.proof.GOpen)

	pcs, sigma, err := p.c.gp.ProveAt(rho)
	if err != nil {
		return errors.WithMessage(err, "failed to open the group commitment")
	}
	if !sigma.Equal(&p.proof.GOpen) {
		return errors.Wrap(ErrInternal, "group opening disagrees with the batch residual")
	}
	p.proof.GPCS = pcs

	return nil
}
