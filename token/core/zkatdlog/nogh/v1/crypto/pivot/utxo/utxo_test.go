/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utxo

import (
	"os"
	"strconv"
	"sync"
	"testing"

	math "github.com/IBM/mathlib"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/benchmark"
	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/pivot"
	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/rp"
	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/testutils"
	benchmark2 "github.com/LFDT-Panurus/panurus/token/services/benchmark"
	"github.com/LFDT-Panurus/panurus/token/services/identity/idemixnym"
)

const testdata = "../../../testdata"

// env is the shared fixture: a naive transfer prover under 64-bit CSP public
// parameters with IdemixNym owners, and the owner's secrets.
type env struct {
	prover *testutils.TransferProver
	params *Params
	owner  *OwnerSecrets
}

var (
	envOnce sync.Once
	envVal  *env
	envErr  error
)

func loadEnv(t *testing.T) *env {
	t.Helper()
	envOnce.Do(func() {
		curve := math.BLS12_381_BBS_GURVY
		configs, err := benchmark.NewSetupConfigurationsWithParams(benchmark.SetupParams{
			IdemixTestdataPath: testdata, Bits: []uint64{64}, CurveIDs: []math.CurveID{curve},
			OwnerIdentityType: idemixnym.IdentityType, ProofType: rp.CSPRangeProofType,
		})
		if err != nil {
			envErr = err

			return
		}
		prover, err := testutils.NewTransferProver(&benchmark2.Case{Bits: 64, CurveID: curve, NumInputs: 2, NumOutputs: 2}, configs)
		if err != nil {
			envErr = err

			return
		}
		params, err := NewParams(prover.PP)
		if err != nil {
			envErr = err

			return
		}
		sc, err := os.ReadFile(testdata + "/bls12_381_bbs/idemix/user/SignerConfig")
		if err != nil {
			envErr = err

			return
		}
		owner, err := params.LoadOwnerSecrets(sc, prover.Owner.AuditInfo)
		if err != nil {
			envErr = err

			return
		}
		envVal = &env{prover: prover, params: params, owner: owner}
	})
	require.NoError(t, envErr)

	return envVal
}

// transfers produces k naive transfers and their aggregated statements and
// witnesses.
func (e *env) transfers(t *testing.T, k int) ([]*TransferStatement, []*TransferWitness) {
	t.Helper()
	sts := make([]*TransferStatement, k)
	wits := make([]*TransferWitness, k)
	for i := range k {
		nt, err := e.prover.Prove(t.Context(), strconv.Itoa(i))
		require.NoError(t, err)
		sts[i], err = StatementFromAction(nt.Action)
		require.NoError(t, err)
		wit := &TransferWitness{Type: e.params.TypeScalar("ABC"), Owners: [2]*OwnerSecrets{e.owner, e.owner}}
		for j := range 2 {
			wit.Inputs[j], err = e.params.OpeningFromMetadata(nt.Inputs[j])
			require.NoError(t, err)
			wit.Outputs[j], err = e.params.OpeningFromMetadata(nt.Outputs[j])
			require.NoError(t, err)
		}
		wits[i] = wit
	}

	return sts, wits
}

var msg = []byte("aggregated transfer payload")

// The equations R_utxo is built from must hold, one by one, on an honestly laid-out
// transfer. This pins the equation list and the layout against each other before
// the collapse hides which equation broke.
func TestEquationsHoldOnHonestInstance(t *testing.T) {
	e := loadEnv(t)
	sts, wits := e.transfers(t, 1)
	s, err := NewSetup(e.params, 2)
	require.NoError(t, err)
	sizes := s.pivot.Sizes()
	inst, err := e.params.buildInstance(sizes.N(), sizes.C(), sts[0], wits[0])
	require.NoError(t, err)
	x := s.statement(sts, [][2]bls12381.G1Affine{inst.aPrime}).Public[0]

	for t2, eq := range groupEquations(e.params.Bits) {
		var acc bls12381.G1Jac
		for _, tm := range eq {
			var pt bls12381.G1Affine
			switch tm.kind {
			case genField:
				pt = scaleG1(e.params.gens[tm.gen], inst.w[tm.field])
			case constGroup:
				pt = inst.g[tm.group]
			case fieldGroup:
				pt = scaleG1(inst.g[tm.group], inst.w[tm.field])
			case constPub:
				pt = x[tm.group]
			case fieldPub:
				pt = scaleG1(x[tm.group], inst.w[tm.field])
			case constG1:
				pt = e.params.g1
			}
			if tm.neg {
				pt.Neg(&pt)
			}
			acc.AddMixed(&pt)
		}
		var sum bls12381.G1Affine
		sum.FromJacobian(&acc)
		assert.True(t, sum.IsInfinity(), "group equation %d", t2)
	}

	var eta, xi fr.Element
	_, _ = eta.SetRandom()
	_, _ = xi.SetRandom()
	forms, phi := e.params.fieldConstraint(eta, xi)
	z := make([]fr.Element, len(forms))
	for k, f := range forms {
		for _, c := range f.Coeffs {
			var t fr.Element
			t.Mul(&c.Val, &inst.w[c.Col])
			z[k].Add(&z[k], &t)
		}
	}
	var got fr.Element
	for _, m := range phi {
		v := m.Coeff
		for _, idx := range m.Vars {
			v.Mul(&v, &z[idx])
		}
		got.Add(&got, &v)
	}
	assert.True(t, got.IsZero(), "field constraint")
}

func TestAggregateRoundTrip(t *testing.T) {
	e := loadEnv(t)
	for _, k := range []int{2, 4} {
		t.Run("K="+strconv.Itoa(k), func(t *testing.T) {
			s, err := NewSetup(e.params, k)
			require.NoError(t, err)
			sts, wits := e.transfers(t, k)
			proof, err := Prove(s, msg, sts, wits)
			require.NoError(t, err)
			require.NoError(t, Verify(s, msg, sts, proof))
			t.Logf("K=%d: aggregated proof %d bytes", k, proof.Size())
		})
	}
}

// fixtureProof returns a setup, statements and an honest proof for K=2.
func fixtureProof(t *testing.T) (*env, *Setup, []*TransferStatement, []*TransferWitness, *Proof) {
	t.Helper()
	e := loadEnv(t)
	s, err := NewSetup(e.params, 2)
	require.NoError(t, err)
	sts, wits := e.transfers(t, 2)
	proof, err := Prove(s, msg, sts, wits)
	require.NoError(t, err)

	return e, s, sts, wits, proof
}

func TestBadTransferAmongKRejected(t *testing.T) {
	e := loadEnv(t)
	s, err := NewSetup(e.params, 2)
	require.NoError(t, err)
	sizes := s.pivot.Sizes()

	t.Run("wrong output opening", func(t *testing.T) {
		sts, wits := e.transfers(t, 2)
		wits[1].Outputs[0].Value++
		proof, err := Prove(s, msg, sts, wits)
		require.NoError(t, err)
		require.ErrorIs(t, Verify(s, msg, sts, proof), pivot.ErrVerificationFailed)
	})

	t.Run("range bit flipped", func(t *testing.T) {
		// Only the field constraint breaks: the group equations do not read bits.
		sts, wits := e.transfers(t, 2)
		insts := make([]*instance, 2)
		for k := range insts {
			insts[k], err = e.params.buildInstance(sizes.N(), sizes.C(), sts[k], wits[k])
			require.NoError(t, err)
		}
		slot := fA(e.params.Bits, 1, 7)
		one := fr.One()
		insts[1].w[slot].Sub(&one, &insts[1].w[slot])
		proof, err := s.proveInstances(msg, sts, insts)
		require.NoError(t, err)
		require.ErrorIs(t, Verify(s, msg, sts, proof), pivot.ErrVerificationFailed)
	})

	t.Run("input not owned by the pseudonym", func(t *testing.T) {
		sts, wits := e.transfers(t, 2)
		sts[0].EidNyms[1] = sts[0].Outputs[0]
		proof, err := Prove(s, msg, sts, wits)
		require.NoError(t, err)
		require.ErrorIs(t, Verify(s, msg, sts, proof), pivot.ErrVerificationFailed)
	})

	t.Run("forged credential", func(t *testing.T) {
		// With a wrong e the linear equations still hold, since the prover derives
		// A-bar from the same e; only the aggregated pairing sees that x A' != A-bar.
		sts, wits := e.transfers(t, 2)
		forged := *e.owner
		one := fr.One()
		forged.E.Add(&forged.E, &one)
		wits[1].Owners[0] = &forged
		proof, err := Prove(s, msg, sts, wits)
		require.NoError(t, err)
		require.ErrorIs(t, Verify(s, msg, sts, proof), ErrVerificationFailed)
	})
}

func TestTamperingRejected(t *testing.T) {
	_, s, sts, _, proof := fixtureProof(t)
	require.NoError(t, Verify(s, msg, sts, proof))

	t.Run("message", func(t *testing.T) {
		require.Error(t, Verify(s, []byte("another payload"), sts, proof))
	})
	t.Run("A' is the identity", func(t *testing.T) {
		bad := *proof
		bad.APrime = append([][2]bls12381.G1Affine(nil), proof.APrime...)
		bad.APrime[1][0] = bls12381.G1Affine{}
		require.ErrorIs(t, Verify(s, msg, sts, &bad), ErrVerificationFailed)
	})
	t.Run("A' replaced", func(t *testing.T) {
		bad := *proof
		bad.APrime = append([][2]bls12381.G1Affine(nil), proof.APrime...)
		bad.APrime[0][1] = addG1(bad.APrime[0][1], bad.APrime[0][1])
		require.Error(t, Verify(s, msg, sts, &bad))
	})
	t.Run("Schnorr response", func(t *testing.T) {
		bad := *proof
		one := fr.One()
		bad.Schnorr[1].Z1.Add(&bad.Schnorr[1].Z1, &one)
		require.ErrorIs(t, Verify(s, msg, sts, &bad), ErrVerificationFailed)
	})
	t.Run("statement", func(t *testing.T) {
		other := append([]*TransferStatement(nil), sts...)
		st := *sts[1]
		st.Outputs[0], st.Outputs[1] = st.Outputs[1], st.Outputs[0]
		other[1] = &st
		require.Error(t, Verify(s, msg, other, proof))
	})
	t.Run("wrong number of transfers", func(t *testing.T) {
		require.ErrorIs(t, Verify(s, msg, sts[:1], proof), pivot.ErrMalformedProof)
	})
}

func TestSetupValidation(t *testing.T) {
	e := loadEnv(t)
	for _, k := range []int{0, 1, 3, 6} {
		_, err := NewSetup(e.params, k)
		require.Error(t, err, "k = %d", k)
	}
}
