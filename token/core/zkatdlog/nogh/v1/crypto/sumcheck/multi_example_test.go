/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sumcheck_test

import (
	"fmt"

	mathlib "github.com/IBM/mathlib"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/sumcheck"
)

// ExampleProveMulti proves the hypercube sum of Phi(h0, h1) = 2 h0 h1 - h1^2 over two
// variables, verifies it, and closes the residual claim the way a caller does: by
// evaluating Phi at the pool values it would get from its commitment scheme, here
// computed directly from the tables.
func ExampleProveMulti() {
	curve := mathlib.Curves[mathlib.BLS12_381_BBS_GURVY]
	table := func(vs ...uint64) sumcheck.FieldPoly {
		p := make(sumcheck.FieldPoly, len(vs))
		for i, v := range vs {
			p[i].SetUint64(v)
		}

		return p
	}
	var two, minusOne fr.Element
	two.SetUint64(2)
	minusOne.SetOne()
	minusOne.Neg(&minusOne)

	claim := &sumcheck.MultiClaim{
		Polys: []sumcheck.FieldPoly{table(1, 2, 3, 4), table(5, 6, 7, 8)},
		Terms: []sumcheck.Term{
			{Coeff: two, Factors: []int{0, 1}},      // 2 h0 h1
			{Coeff: minusOne, Factors: []int{1, 1}}, // - h1^2
		},
	}

	proof, _, err := sumcheck.ProveMulti(curve, claim)
	if err != nil {
		panic(err)
	}
	opening, err := sumcheck.VerifyMulti(curve, claim.Shape(), proof)
	if err != nil {
		panic(err)
	}

	// Close the residual claim: the pool polynomials at R, then Phi at those values.
	at := make([]fr.Element, len(opening.R))
	for i, r := range opening.R {
		at[i].SetBytes(r.Bytes())
	}
	evals := make([]fr.Element, len(claim.Polys))
	for i, p := range claim.Polys {
		if evals[i], err = p.EvaluateOpening(at); err != nil {
			panic(err)
		}
	}
	phi, err := sumcheck.EvaluateTerms(claim.Terms, evals)
	if err != nil {
		panic(err)
	}
	var product fr.Element
	product.SetBytes(opening.Product.Bytes())

	// The sum over the four points is (10-25) + (24-36) + (42-49) + (64-64) = -34.
	var sum fr.Element
	sum.SetBytes(proof.FieldSum.Bytes())
	fmt.Println("degree:", claim.Degree())
	fmt.Println("sum:", sum.String())
	fmt.Println("residual closes:", product.Equal(&phi))
	// Output:
	// degree: 2
	// sum: -34
	// residual closes: true
}
