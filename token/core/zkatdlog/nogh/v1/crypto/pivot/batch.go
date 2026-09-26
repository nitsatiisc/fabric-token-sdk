/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pivot

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/sumcheck"
)

// Evaluation-claim batching
//
// Several claims p(z_j) = v_j on one committed multilinear p reduce to one. Each
// is a sum-check, since p(z_j) = sum_x eq(x, z_j) p(x), and on a challenge gamma
// drawn after every (z_j, v_j) is on the transcript,
//
//	sum_j gamma^j v_j = sum_x E(x) p(x),     E(x) = sum_j gamma^j eq(x, z_j).
//
// E is one public table, so the batch is the two-factor product E * p, which the
// sum-check reduces to E(rho) * p(rho) at a single random rho: the verifier computes
// E(rho) itself and one PCS opening supplies p(rho). If any claim is false, the
// batched claim holds with probability at most (J-1)/p over gamma.
//
// The z_j may have boolean coordinates, where eq(x, z_j) selects table entries.
// That is what lets the same batch close the column-slice claims, whose column
// bits are boolean and whose instance bits are tau.

// batchTable returns E = sum_j gamma^j eq(points[j], .).
func batchTable(points [][]fr.Element, gamma fr.Element) sumcheck.FieldPoly {
	pw := powers(gamma, len(points))
	var out sumcheck.FieldPoly
	for j, z := range points {
		t := eqTable(z)
		if out == nil {
			out = make(sumcheck.FieldPoly, len(t))
		}
		for i := range t {
			var s fr.Element
			s.Mul(&t[i], &pw[j])
			out[i].Add(&out[i], &s)
		}
	}

	return out
}

// batchWeight returns E(rho) = sum_j gamma^j eq(points[j], rho).
func batchWeight(points [][]fr.Element, gamma fr.Element, rho []fr.Element) fr.Element {
	pw := powers(gamma, len(points))
	var out fr.Element
	for j, z := range points {
		e := eqEval(z, rho)
		e.Mul(&e, &pw[j])
		out.Add(&out, &e)
	}

	return out
}

// batchFieldValue returns sum_j gamma^j vals[j].
func batchFieldValue(vals []fr.Element, gamma fr.Element) fr.Element {
	return innerProduct(powers(gamma, len(vals)), vals)
}

// batchGroupValue returns sum_j gamma^j vals[j].
func batchGroupValue(vals []bls12381.G1Affine, gamma fr.Element) (bls12381.G1Affine, error) {
	return msm(vals, powers(gamma, len(vals)))
}
