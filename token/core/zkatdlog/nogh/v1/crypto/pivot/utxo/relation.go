/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utxo

import (
	"math/big"
	"sort"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/pivot"
)

// The group equations of R_utxo
//
// Each equation is a list of terms that sum to 0_G. A term is one of
//
//	gen * w[f]      a public generator times a field slot        (Gamma)
//	c * g[s]        a private group slot times a constant        (alpha)
//	w[f] * g[s]     a private group slot times a field slot      (B)
//	c * x[t]        a public-table column times a constant       (AlphaPub)
//	w[f] * x[t]     a public-table column times a field slot     (BPub)
//	c * g1          the BBS+ constant generator                  (G0)
//
// The collapse multiplies equation t by xi^t and adds them up, which is exactly the
// single mixed equation of the pivot relation. Building alpha, B, Gamma and G0 from
// this list, rather than writing them out, keeps the parameters and the equations
// from drifting apart.

type termKind int

const (
	genField termKind = iota
	constGroup
	fieldGroup
	constPub
	fieldPub
	constG1
)

type term struct {
	kind  termKind
	gen   int
	field int
	group int
	neg   bool
}

func gf(gen, field int) term      { return term{kind: genField, gen: gen, field: field} }
func cg(group int, neg bool) term { return term{kind: constGroup, group: group, neg: neg} }
func fg(field, group int, neg bool) term {
	return term{kind: fieldGroup, field: field, group: group, neg: neg}
}
func cp(col int, neg bool) term { return term{kind: constPub, group: col, neg: neg} }
func fp(field, col int, neg bool) term {
	return term{kind: fieldPub, field: field, group: col, neg: neg}
}

// groupEquations returns the 16 group equations (U1)-(U4), (U7)-(U11) in collapse
// order: U1, U2 per input, U3 per output, U4, then U7..U11 for input 0 and input 1.
func groupEquations(kappa int) [][]term {
	eqs := [][]term{
		// U1: C_T = tau G_t + r_T H
		{gf(genGt, fTau), gf(genH, fRT), cg(gCT, true)},
		// U2: Cin_i - C_T = vin_i G_v + s_i H
		{gf(genGv, fVin0), gf(genH, fS0), cp(pCin0, true), cg(gCT, false)},
		{gf(genGv, fVin1), gf(genH, fS1), cp(pCin1, true), cg(gCT, false)},
		// U3: Cout_j - C_T = vout_j G_v + t_j H
		{gf(genGv, fVout0), gf(genH, fT0), cp(pCout0, true), cg(gCT, false)},
		{gf(genGv, fVout1), gf(genH, fT1), cp(pCout1, true), cg(gCT, false)},
		// U4: Cin_0 + Cin_1 - Cout_0 - Cout_1 = sigma H
		{gf(genH, fSigma), cp(pCin0, true), cp(pCin1, true), cp(pCout0, false), cp(pCout1, false)},
	}
	for i := range 2 {
		f := func(off int) int { return fOwn(kappa, i, off) }
		eqs = append(eqs,
			// U7: A-bar - d = -e A' + r_2 h_0
			[]term{fp(f(oE), pAPrime0+i, true), gf(genH0, f(oR2)), cg(gIn(i, gABar), true), cg(gIn(i, gD), false)},
			// U8: r_3 d = g_1 + s' h_0 + sk h_1 + ou h_2 + role h_3 + eid h_4 + rh h_5
			[]term{
				{kind: constG1}, gf(genH0, f(oSPrime)), gf(genH1, f(oSK)), gf(genH2, f(oOU)),
				gf(genH3, f(oRole)), gf(genH4, f(oEID)), gf(genH5, f(oRH)), fg(f(oR3), gIn(i, gD), true),
			},
			// U9: Nym = sk h_1 + r_nym h_0
			[]term{gf(genH1, f(oSK)), gf(genH0, f(oRNym)), cg(gIn(i, gNym), true)},
			// U10: EidNym = eid h_4 + r_eid h_0
			[]term{gf(genH4, f(oEID)), gf(genH0, f(oREid)), cp(pEidNym0+i, true)},
			// U11: RhNym = rh h_5 + r_rh h_0
			[]term{gf(genH5, f(oRH)), gf(genH0, f(oRRh)), cg(gIn(i, gRhNym), true)},
		)
	}

	return eqs
}

// lagrange returns the Lagrange coefficients L_m(x), m = 0..deg, over the nodes
// 0, 1, ..., deg.
func lagrange(x fr.Element, deg int) []fr.Element {
	// num = prod_j (x - j); L_m(x) = num / (x - m) / prod_{j != m} (m - j).
	diffs := make([]fr.Element, deg+1)
	for m := range diffs {
		var mm fr.Element
		mm.SetUint64(uint64(m))
		diffs[m].Sub(&x, &mm)
	}
	out := make([]fr.Element, deg+1)
	for m := range out {
		var num, den fr.Element
		num.SetOne()
		den.SetOne()
		for j := range deg + 1 {
			if j == m {
				continue
			}
			num.Mul(&num, &diffs[j])
			var d, mj, jj fr.Element
			mj.SetUint64(uint64(m))
			jj.SetUint64(uint64(j))
			d.Sub(&mj, &jj)
			den.Mul(&den, &d)
		}
		den.Inverse(&den)
		out[m].Mul(&num, &den)
	}

	return out
}

// buildRelation collapses R_utxo, with the range identity evaluated at eta and the
// equations combined with powers of xi, into the parameters of the pivot relation.
func (p *Params) buildRelation(sizes pivot.Sizes, eta, xi fr.Element) *pivot.Relation {
	kappa := p.Bits
	pw := make([]fr.Element, 16)
	pw[0].SetOne()
	for i := 1; i < len(pw); i++ {
		pw[i].Mul(&pw[i-1], &xi)
	}

	alpha := make([]fr.Element, sizes.C())
	alphaPub := make([]fr.Element, numPublicCols)
	bMap := map[[2]int]fr.Element{}
	bPubMap := map[[2]int]fr.Element{}
	gMap := map[[2]int]fr.Element{}
	var g0Coeff fr.Element
	for t, eq := range groupEquations(kappa) {
		for _, tm := range eq {
			c := pw[t]
			if tm.neg {
				c.Neg(&c)
			}
			switch tm.kind {
			case genField:
				v := gMap[[2]int{tm.gen, tm.field}]
				v.Add(&v, &c)
				gMap[[2]int{tm.gen, tm.field}] = v
			case constGroup:
				alpha[tm.group].Add(&alpha[tm.group], &c)
			case fieldGroup:
				v := bMap[[2]int{tm.group, tm.field}]
				v.Add(&v, &c)
				bMap[[2]int{tm.group, tm.field}] = v
			case constPub:
				alphaPub[tm.group].Add(&alphaPub[tm.group], &c)
			case fieldPub:
				v := bPubMap[[2]int{tm.group, tm.field}]
				v.Add(&v, &c)
				bPubMap[[2]int{tm.group, tm.field}] = v
			case constG1:
				g0Coeff.Add(&g0Coeff, &c)
			}
		}
	}

	rel := &pivot.Relation{
		Alpha:    alpha,
		B:        sparse(bMap),
		AlphaPub: alphaPub,
		BPub:     sparse(bPubMap),
		Gamma:    sparse(gMap),
		G:        p.gens,
		G0:       scaleG1(p.g1, g0Coeff),
	}
	rel.Forms, rel.Phi = p.fieldConstraint(eta, xi)

	return rel
}

// sparse turns a map of (row, col) -> value into sorted sparse entries.
func sparse(m map[[2]int]fr.Element) []pivot.SparseEntry {
	out := make([]pivot.SparseEntry, 0, len(m))
	for k, v := range m {
		out = append(out, pivot.SparseEntry{Row: k[0], Col: k[1], Val: v})
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Row != out[b].Row {
			return out[a].Row < out[b].Row
		}

		return out[a].Col < out[b].Col
	})

	return out
}

// fieldConstraint returns the affine forms and Phi of the field constraint: (U5)
// and (U6) at eta, combined with xi^0..xi^3.
//
//	L_j     = vout_j - sum_{l=1}^{kappa} 2^{l-1} a_{j,l}                 (U5)
//	L_{2+j} = sum_{l in S} nu_l b_{j,l},   S = {0, kappa+1, ..., 2kappa}  b_j(eta)
//	L_{4+j} = sum_{l=0}^{kappa} mu_l a_{j,l}                              a_j(eta)
//	Phi     = Z_0 + xi Z_1 + xi^2 (Z_2 - Z_4^2 + Z_4) + xi^3 (Z_3 - Z_5^2 + Z_5)
func (p *Params) fieldConstraint(eta, xi fr.Element) ([]pivot.AffineForm, []pivot.Monomial) {
	kappa := p.Bits
	mu := lagrange(eta, kappa)
	nu := lagrange(eta, 2*kappa)

	forms := make([]pivot.AffineForm, 6)
	for j := range 2 {
		one := fr.One()
		dec := []pivot.LinearEntry{{Col: fVout0 + 2*j, Val: one}}
		var pow fr.Element
		pow.SetOne()
		for l := 1; l <= kappa; l++ {
			var v fr.Element
			v.Neg(&pow)
			dec = append(dec, pivot.LinearEntry{Col: fA(kappa, j, l), Val: v})
			pow.Double(&pow)
		}
		forms[j] = pivot.AffineForm{Coeffs: dec}

		bEval := []pivot.LinearEntry{{Col: fB(kappa, j, 0), Val: nu[0]}}
		for l := kappa + 1; l <= 2*kappa; l++ {
			bEval = append(bEval, pivot.LinearEntry{Col: fB(kappa, j, l), Val: nu[l]})
		}
		forms[2+j] = pivot.AffineForm{Coeffs: bEval}

		aEval := make([]pivot.LinearEntry, 0, kappa+1)
		for l := 0; l <= kappa; l++ {
			aEval = append(aEval, pivot.LinearEntry{Col: fA(kappa, j, l), Val: mu[l]})
		}
		forms[4+j] = pivot.AffineForm{Coeffs: aEval}
	}

	var xi2, xi3 fr.Element
	xi2.Square(&xi)
	xi3.Mul(&xi2, &xi)
	neg := func(e fr.Element) fr.Element {
		e.Neg(&e)

		return e
	}
	phi := []pivot.Monomial{
		{Coeff: fr.One(), Vars: []int{0}},
		{Coeff: xi, Vars: []int{1}},
		{Coeff: xi2, Vars: []int{2}},
		{Coeff: neg(xi2), Vars: []int{4, 4}},
		{Coeff: xi2, Vars: []int{4}},
		{Coeff: xi3, Vars: []int{3}},
		{Coeff: neg(xi3), Vars: []int{5, 5}},
		{Coeff: xi3, Vars: []int{5}},
	}

	return forms, phi
}

// bigOf returns s as a big integer, for gnark's scalar multiplications.
func bigOf(s fr.Element) *big.Int {
	var bi big.Int
	s.BigInt(&bi)

	return &bi
}

// scaleG1 returns s * g.
func scaleG1(g bls12381.G1Affine, s fr.Element) bls12381.G1Affine {
	var out bls12381.G1Affine
	out.ScalarMultiplication(&g, bigOf(s))

	return out
}
