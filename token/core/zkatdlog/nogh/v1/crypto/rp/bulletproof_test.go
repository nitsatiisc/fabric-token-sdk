/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rp_test

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	math "github.com/IBM/mathlib"
	"github.com/hyperledger-labs/fabric-token-sdk/token/core/zkatdlog/nogh/v1/crypto/rp"
	"github.com/stretchr/testify/assert"
)

func TestBFProofVerify(t *testing.T) {
	curve := math.Curves[1]
	nr := uint64(6)
	l := uint64(1 << nr)
	leftGens := make([]*math.G1, l)
	rightGens := make([]*math.G1, l)

	rand, err := curve.Rand()
	assert.NoError(t, err)

	Q := curve.GenG1.Mul(curve.NewRandomZr(rand))
	P := curve.GenG1.Mul(curve.NewRandomZr(rand))
	H := curve.GenG1.Mul(curve.NewRandomZr(rand))
	G := curve.GenG1.Mul(curve.NewRandomZr(rand))
	for i := 0; i < len(leftGens); i++ {
		leftGens[i] = curve.HashToG1([]byte(strconv.Itoa(2 * i)))
		rightGens[i] = curve.HashToG1([]byte(strconv.Itoa(2*i + 1)))
	}
	bf := curve.NewRandomZr(rand)
	com := G.Mul(curve.NewZrFromInt(115))
	com.Add(H.Mul(bf))
	prover := rp.NewRangeProver(com, 115, []*math.G1{G, H}, bf, leftGens, rightGens, P, Q, nr, l, curve)
	verifier := rp.NewRangeVerifier(com, []*math.G1{G, H}, leftGens, rightGens, P, Q, nr, l, curve)

	/*
		f, err := os.Create("cpu.prof")
		if err != nil {
			panic(err)
		}
		defer f.Close()

		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()

	*/
	start := time.Now()
	proof, err := prover.Prove()
	dProve := time.Since(start)
	assert.NoError(t, err)
	assert.NotNil(t, proof)
	start = time.Now()
	err = verifier.Verify(proof)
	dVerify := time.Since(start)
	assert.NoError(t, err)
	fmt.Printf("Prover Time %v, Verifier time %v\n", dProve, dVerify)
}
