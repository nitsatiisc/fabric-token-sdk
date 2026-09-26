/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package validator_test

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"testing"

	math "github.com/IBM/mathlib"
	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/benchmark"
	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/pivot/utxo"
	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/rp"
	testing2 "github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/testutils"
	"github.com/LFDT-Panurus/panurus/token/driver"
	benchmark2 "github.com/LFDT-Panurus/panurus/token/services/benchmark"
	"github.com/LFDT-Panurus/panurus/token/services/identity"
	"github.com/LFDT-Panurus/panurus/token/services/identity/idemix"
	"github.com/LFDT-Panurus/panurus/token/services/identity/idemixnym"
	"github.com/hyperledger-labs/fabric-smart-client/node/start/profile"
	"github.com/stretchr/testify/require"
)

var testUseCase = &benchmark2.Case{
	Bits:       32,
	CurveID:    math.BLS12_381_BBS_GURVY,
	NumInputs:  2,
	NumOutputs: 2,
}

type actionType int

const (
	TransferAction actionType = iota
	RedeemAction
	IssueAction
)

func TestValidator(t *testing.T) {
	for _, identityType := range []identity.Type{idemix.IdentityType, idemixnym.IdentityType} {
		for _, proofType := range []rp.ProofType{rp.RangeProofType, rp.CSPRangeProofType} {
			t.Run("Validator is called correctly with a non-anonymous issue action", func(t *testing.T) {
				testVerifyNoErrorOnAction(t, IssueAction, identityType, proofType)
			})
			t.Run("validator is called correctly with a transfer action", func(t *testing.T) {
				testVerifyNoErrorOnAction(t, TransferAction, identityType, proofType)
			})
			t.Run("validator is called correctly with a redeem action", func(t *testing.T) {
				testVerifyNoErrorOnAction(t, RedeemAction, identityType, proofType)
			})
			t.Run("engine is called correctly with atomic swap", func(t *testing.T) {
				configurations, err := benchmark.NewSetupConfigurationsWithParams(
					benchmark.SetupParams{
						IdemixTestdataPath: "./../testdata",
						Bits:               []uint64{testUseCase.Bits},
						CurveIDs:           []math.CurveID{testUseCase.CurveID},
						OwnerIdentityType:  identityType,
						ProofType:          proofType,
					},
				)
				require.NoError(t, err)
				env, err := testing2.NewEnv(testUseCase, configurations)
				require.NoError(t, err)

				raw, err := env.TRWithSwap.Bytes()
				require.NoError(t, err)

				actions, _, err := env.Engine.VerifyTokenRequestFromRaw(t.Context(), nil, "2", raw)
				require.NoError(t, err)
				require.Len(t, actions, 2)
			})
			t.Run("when the sender's signature is not valid: wrong txID", func(t *testing.T) {
				configurations, err := benchmark.NewSetupConfigurationsWithParams(
					benchmark.SetupParams{
						IdemixTestdataPath: "./../testdata",
						Bits:               []uint64{testUseCase.Bits},
						CurveIDs:           []math.CurveID{testUseCase.CurveID},
						OwnerIdentityType:  identityType,
						ProofType:          proofType,
					},
				)
				require.NoError(t, err)
				env, err := testing2.NewEnv(testUseCase, configurations)
				require.NoError(t, err)

				request := &driver.TokenRequest{
					Actions: env.TRWithSwap.Actions,
				}
				raw, err := request.MarshalToMessageToSign([]byte("3"))
				require.NoError(t, err)

				signatures, err := env.Sender.SignTokenActions(raw)
				require.NoError(t, err)
				env.TRWithSwap.Signatures[1].Action.Signature = signatures[0]

				raw, err = env.TRWithSwap.Bytes()
				require.NoError(t, err)

				_, _, err = env.Engine.VerifyTokenRequestFromRaw(t.Context(), nil, "2", raw)
				require.Error(t, err)
				require.ErrorContains(t, err, "failed signature verification")
			})
		}
	}
}

func BenchmarkValidatorTransfer(b *testing.B) {
	pp, err := profile.New(profile.WithAll(), profile.WithPath("./profile"))
	require.NoError(b, err)
	require.NoError(b, pp.Start())
	defer pp.Stop()
	bits, curves, cases, err := benchmark2.GenerateCasesWithDefaults()
	require.NoError(b, err)
	configurations, err := benchmark.NewSetupConfigurations("./../testdata", bits, curves, idemixnym.IdentityType)
	require.NoError(b, err)

	test := benchmark2.NewTest[*testing2.Env](cases)
	test.GoBenchmark(b,
		func(c *benchmark2.Case) (*testing2.Env, error) {
			return testing2.NewEnv(c, configurations)
		},
		func(ctx context.Context, env *testing2.Env) error {
			_, _, err := env.Engine.VerifyTokenRequestFromRaw(ctx, nil, "1", env.TRWithTransferRaw)

			return err
		},
	)
}

func TestParallelBenchmarkValidatorTransfer(t *testing.T) {
	bits, curves, cases, err := benchmark2.GenerateCasesWithDefaults()
	require.NoError(t, err)
	proofType := benchmark.ProofType()
	executorProvider := benchmark.ExecutorProvider()
	configurations, err := benchmark.NewSetupConfigurationsWithParams(benchmark.SetupParams{
		IdemixTestdataPath: "./../testdata",
		Bits:               bits,
		CurveIDs:           curves,
		OwnerIdentityType:  idemixnym.IdentityType,
		ProofType:          proofType,
		ExecutorProvider:   executorProvider,
	})
	require.NoError(t, err)

	test := benchmark2.NewTest[*testing2.Env](cases)
	test.RunBenchmark(t,
		func(c *benchmark2.Case) (*testing2.Env, error) {
			return testing2.NewEnv(c, configurations)
		},
		func(ctx context.Context, env *testing2.Env) error {
			_, _, err := env.Engine.VerifyTokenRequestFromRaw(ctx, nil, "1", env.TRWithTransferRaw)

			return err
		},
	)
}

func testVerifyNoErrorOnAction(t *testing.T, actionType actionType, identityType identity.Type, proofType rp.ProofType) {
	t.Helper()
	configurations, err := benchmark.NewSetupConfigurationsWithParams(
		benchmark.SetupParams{
			IdemixTestdataPath: "./../testdata",
			Bits:               []uint64{testUseCase.Bits},
			CurveIDs:           []math.CurveID{testUseCase.CurveID},
			OwnerIdentityType:  identityType,
			ProofType:          proofType,
		},
	)
	require.NoError(t, err)
	env, err := testing2.NewEnv(testUseCase, configurations)
	require.NoError(t, err)

	var raw []byte
	switch actionType {
	case TransferAction:
		raw, err = env.TRWithTransfer.Bytes()
	case IssueAction:
		raw, err = env.TRWithIssue.Bytes()
	case RedeemAction:
		raw, err = env.TRWithRedeem.Bytes()
	}
	require.NoError(t, err)
	actions, _, err := env.Engine.VerifyTokenRequestFromRaw(t.Context(), nil, "1", raw)
	require.NoError(t, err)
	require.Len(t, actions, 1)
}

// BenchmarkValidatorTransferCSP64 benchmarks the validator's full transfer-payload
// verification for a single pinned configuration: idemixnym owner identities, the
// CSP range-proof system, and a 64-bit value range.
//
// It differs from BenchmarkValidatorTransfer in two ways:
//   - The configuration is fixed rather than flag-driven. Cases are built via
//     GenerateCases instead of GenerateCasesWithDefaults so that the -bits,
//     -curves, -num_inputs and -num_outputs flags cannot change what is measured;
//     a run of this benchmark is comparable across invocations.
//   - The range-proof system is selected explicitly via SetupParams.ProofType.
//     BenchmarkValidatorTransfer uses NewSetupConfigurations, which does not take
//     a proof type and therefore generates parameters for the default system.
//
// As in BenchmarkValidatorTransfer, the nil second argument to
// VerifyTokenRequestFromRaw is the ledger accessor (driver.GetStateFnc), so this
// measures payload verification only -- the type-and-sum proof, the CSP range
// proofs, and the idemixnym owner signatures -- with no ledger-side checks such
// as unspent-token lookups.
func BenchmarkValidatorTransferCSP64(b *testing.B) {
	pp, err := profile.New(profile.WithAll(), profile.WithPath("./profile"))
	require.NoError(b, err)
	require.NoError(b, pp.Start())
	defer pp.Stop()

	const bits = uint64(64)
	curves := []math.CurveID{math.BLS12_381_BBS_GURVY}
	cases := benchmark2.GenerateCases(
		[]uint64{bits},
		curves,
		[]int{2},
		[]int{2},
		[]int{runtime.NumCPU()},
	)

	configurations, err := benchmark.NewSetupConfigurationsWithParams(benchmark.SetupParams{
		IdemixTestdataPath: "./../testdata",
		Bits:               []uint64{bits},
		CurveIDs:           curves,
		OwnerIdentityType:  idemixnym.IdentityType,
		ProofType:          rp.CSPRangeProofType,
	})
	require.NoError(b, err)

	test := benchmark2.NewTest[*testing2.Env](cases)
	test.GoBenchmark(b,
		func(c *benchmark2.Case) (*testing2.Env, error) {
			return testing2.NewEnv(c, configurations)
		},
		func(ctx context.Context, env *testing2.Env) error {
			_, _, err := env.Engine.VerifyTokenRequestFromRaw(ctx, nil, "1", env.TRWithTransferRaw)

			return err
		},
	)
}

// BenchmarkAggregatedTransfersVsNaive compares K naive transfers with one aggregated
// proof of the same K transfers, under the configuration of
// BenchmarkValidatorTransferCSP64: 2-input, 2-output transfers, idemixnym owners and
// 64-bit CSP range proofs, on BLS12-381.
//
// For each K it reports four sub-benchmarks, each timing the whole batch of K:
//
//   - naive/prove: K runs of the production sender -- the transfer action with its
//     type-and-sum and range proofs, and the input owners' signatures (an Idemix
//     proof of knowledge of the credential plus a pseudonym signature each).
//     Auditing and endorsement are not included.
//   - naive/verify: K runs of the validator on a transfer request, as
//     BenchmarkValidatorTransferCSP64 measures one; this includes the auditor's
//     signature check, which the aggregated proof does not replace.
//   - aggregated/prove and aggregated/verify: one utxo.Prove and one utxo.Verify
//     over the K transfers' statements, read off K naive actions, so both sides
//     consume the same commitments, owner pseudonyms and public parameters.
//
// Proof size is reported as the proof-bytes metric: for naive transfers the ZK proof
// and owner signatures of all K, for the aggregated proof its full size with
// compressed points (see utxo.Proof.Size). Public data both carry -- commitments,
// owner identities -- is not counted.
func BenchmarkAggregatedTransfersVsNaive(b *testing.B) {
	const bits = uint64(64)
	curve := math.BLS12_381_BBS_GURVY
	configurations, err := benchmark.NewSetupConfigurationsWithParams(benchmark.SetupParams{
		IdemixTestdataPath: "./../testdata",
		Bits:               []uint64{bits},
		CurveIDs:           []math.CurveID{curve},
		OwnerIdentityType:  idemixnym.IdentityType,
		ProofType:          rp.CSPRangeProofType,
	})
	require.NoError(b, err)
	bc := &benchmark2.Case{Bits: bits, CurveID: curve, NumInputs: 2, NumOutputs: 2}

	env, err := testing2.NewEnv(bc, configurations)
	require.NoError(b, err)
	prover, err := testing2.NewTransferProver(bc, configurations)
	require.NoError(b, err)
	params, err := utxo.NewParams(prover.PP)
	require.NoError(b, err)
	signerConfig, err := os.ReadFile("./../testdata/bls12_381_bbs/idemix/user/SignerConfig")
	require.NoError(b, err)
	owner, err := params.LoadOwnerSecrets(signerConfig, prover.Owner.AuditInfo)
	require.NoError(b, err)
	msg := []byte("aggregated transfer payload")

	for _, k := range []int{8, 32, 64, 128} {
		// K naive transfers, and the aggregated statements and witnesses read off them.
		sts := make([]*utxo.TransferStatement, k)
		wits := make([]*utxo.TransferWitness, k)
		naiveBytes := 0
		for i := range k {
			nt, err := prover.Prove(b.Context(), strconv.Itoa(i))
			require.NoError(b, err)
			naiveBytes += nt.ProofSize()
			sts[i], err = utxo.StatementFromAction(nt.Action)
			require.NoError(b, err)
			wit := &utxo.TransferWitness{Type: params.TypeScalar("ABC"), Owners: [2]*utxo.OwnerSecrets{owner, owner}}
			for j := range 2 {
				wit.Inputs[j], err = params.OpeningFromMetadata(nt.Inputs[j])
				require.NoError(b, err)
				wit.Outputs[j], err = params.OpeningFromMetadata(nt.Outputs[j])
				require.NoError(b, err)
			}
			wits[i] = wit
		}
		setup, err := utxo.NewSetup(params, k)
		require.NoError(b, err)
		proof, err := utxo.Prove(setup, msg, sts, wits)
		require.NoError(b, err)
		require.NoError(b, utxo.Verify(setup, msg, sts, proof))

		prefix := "K=" + strconv.Itoa(k)
		b.Run(prefix+"/naive/prove", func(b *testing.B) {
			for b.Loop() {
				for i := range k {
					if _, err := prover.Prove(b.Context(), strconv.Itoa(i)); err != nil {
						b.Fatal(err)
					}
				}
			}
			b.ReportMetric(float64(naiveBytes), "proof-bytes")
		})
		b.Run(prefix+"/naive/verify", func(b *testing.B) {
			for b.Loop() {
				for range k {
					if _, _, err := env.Engine.VerifyTokenRequestFromRaw(b.Context(), nil, "1", env.TRWithTransferRaw); err != nil {
						b.Fatal(err)
					}
				}
			}
			b.ReportMetric(float64(naiveBytes), "proof-bytes")
		})
		b.Run(prefix+"/aggregated/prove", func(b *testing.B) {
			for b.Loop() {
				if _, err := utxo.Prove(setup, msg, sts, wits); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(proof.Size()), "proof-bytes")
		})
		b.Run(prefix+"/aggregated/verify", func(b *testing.B) {
			for b.Loop() {
				if err := utxo.Verify(setup, msg, sts, proof); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(proof.Size()), "proof-bytes")
		})
	}
}
