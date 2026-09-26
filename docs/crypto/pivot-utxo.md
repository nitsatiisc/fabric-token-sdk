# Aggregated UTXO Transfers (R_utxo)

**Implementation**: [`token/core/zkatdlog/nogh/v1/crypto/pivot/utxo`](../../token/core/zkatdlog/nogh/v1/crypto/pivot/utxo)
**Curve**: BLS12-381 (G1, with pairings for the BBS+ check)
**Date**: 2026-09-26

## Table of Contents
1. [Introduction](#1-introduction)
2. [What Is Aggregated](#2-what-is-aggregated)
3. [Public Inputs and Parameters](#3-public-inputs-and-parameters)
4. [The Relation](#4-the-relation)
5. [Checks Outside the Relation](#5-checks-outside-the-relation)
6. [API](#6-api)
7. [Benchmark](#7-benchmark)
8. [Security Considerations](#8-security-considerations)
9. [Testing](#9-testing)

---

## 1. Introduction

A naive zkatdlog transfer with two inputs and two outputs carries its own
type-and-sum proof and one range proof per output. Each input also needs an owner
signature: an Idemix proof of knowledge of a BBS+ credential plus a pseudonym
signature. The `utxo` package replaces the proofs and signatures of **K** such
transfers with one proof. The proof is built by the [pivot protocol](pivot.md) over
the relation `R_utxo` of the mixed-witness-aggregation write-up, and it covers
IdemixNym owners (identity type 3).

## 2. What Is Aggregated

| Naive transfer proves | `R_utxo` equation(s) |
|---|---|
| inputs and outputs share a type; values balance | (U1)–(U4), group |
| each output value is in `[0, 2^κ)` | (U5) value decomposition and (U6) the bit identity `b_j(X) = a_j(X)(a_j(X) − 1)`, field |
| the owner of each input holds a BBS+ credential whose enrollment ID is behind the input's pseudonym | (U7)–(U11), group, plus the pairing of §5 |
| the owner signs the transaction | the aggregated Schnorr proof of §5 |

The range identity is evaluated at a challenge `η`, using the Lagrange coefficients of
`a_j` and `b_j`. The 16 group equations and 4 field equations of a transfer are then
combined with powers of `ξ` into the single mixed equation of the pivot relation. The
pivot parameters `α`, `B`, `Γ`, `G0` and `Φ` are **generated** from a list of the
equations (`relation.go`), not written out, so the parameters and the equations
cannot drift apart. `TestEquationsHoldOnHonestInstance` checks every equation
separately on a real transfer.

## 3. Public Inputs and Parameters

The aggregated proof consumes exactly what the K naive transfers consume.

- **Public parameters**: `NewParams(pp)` reads the token public parameters:
  - the Pedersen generators `(G_t, G_v, H)` of the token commitments;
  - the range bit length `κ`;
  - the Idemix issuer public key, which gives `h_0, …, h_5` and `w` (the credential
    messages are `(sk, ou, role, eid, rh)` on `h_1…h_5`).

  The token curve and the Idemix curve must be the same.
- **Per transfer**: `StatementFromAction(action)` reads the naive action's input and
  output commitments, and the owners of its inputs. An IdemixNym owner identity is the
  enrollment-ID pseudonym `EidNym = eid·h_4 + r·h_0` itself.
- **Published by the proof**: the randomised credential element `A'` of every input,
  as a naive owner signature also publishes it.

The field commitment's Pedersen generators are derived by hashing to the curve, so the
setup is transparent. `NewSetup(params, K)` pads the 9 private group slots to `c = 16` or `32` so that
the group commitment's variable count is even. It also chooses the field
commitment's matrix split so that its row half is even. K may be any power of two ≥ 2.

## 4. The Relation

One transfer's witness occupies `4κ + 39` field slots (295 at `κ = 64`, padded to
`n = 512`) and 9 private group slots. Its public data is one row of the pivot
statement's public table. The layout is documented in `layout.go`.

- **Public table row, not committed:** `Cin_0, Cin_1, Cout_0, Cout_1, EidNym_0,
  EidNym_1, A'_0, A'_1`.
  - Commitments and pseudonyms enter with constant coefficients (`AlphaPub`).
  - `A'` enters through the bilinear term `−e_i·A'_i` (`BPub`).
  - The verifier evaluates the table itself, with one MSM of `8K` points.
- **Private group slots, committed:** `C_T` (the type commitment), and per input `Ā`,
  `d`, `Nym` and `RhNym`.
- **Field slots:**
  - type and sum: `τ`, `r_T`, the values, the blinding differences `s_i`, `t_j`, and
    `σ`;
  - per output: the bits `a_{j,0..κ}` and the evaluations `b_{j,·}`;
  - per input: `sk, ou, role, eid, rh`, `e`, `r_2`, `r_3`, `s'`, and the three
    pseudonym blinders.

The prover randomises each credential as in the Idemix BBS+ proof of knowledge:

```
A' = r1·A,   Ā = r1·B − e·A',   d = r1·B − r2·h_0,   r3 = 1/r1,   s' = s − r2·r3
```

It draws a fresh `C_T`, a fresh range blinding and fresh `Nym`/`RhNym` per proof.

## 5. Checks Outside the Relation

After the pivot proof, which reveals the `τ`-aggregates of `Ā_0`, `Ā_1`, `Nym_0` and
`Nym_1`:

- **Pairings, two in total:** `e(Â'_i, w) = e(Â̄_i, g_2)` for `i = 0, 1`. The
  verifier computes `Â'_i = Σ_k eq(k,τ)·A'^(k)_i` itself from the published `A'`.
- **`A' ≠ 0`:** checked on every published `A'`, 2K comparisons with no group
  operations.
- **Aggregated Schnorr, two in total:** a proof of knowledge of `(ŝk_i, r̂_i)` with
  `N̂ym_i = ŝk_i·h_1 + r̂_i·h_0`, on a challenge bound to the message `M` of the
  aggregated transaction. `M` is an input to `Prove` and `Verify`, and is taken as
  given.

The transcript absorbs `M`, all statements and all `A'` before the commitments, so
every challenge depends on them.

## 6. API

```go
params, err := utxo.NewParams(pp)                        // token public parameters
owner, err := params.LoadOwnerSecrets(signerConfig, auditInfo)
setup, err := utxo.NewSetup(params, k)

st, err := utxo.StatementFromAction(action)              // per naive transfer
wit := &utxo.TransferWitness{
    Type:   params.TypeScalar("ABC"),
    Owners: [2]*utxo.OwnerSecrets{owner, owner},
}
wit.Inputs[0], err = params.OpeningFromMetadata(inputOpening0)   // ... and so on

proof, err := utxo.Prove(setup, msg, statements, witnesses)
err = utxo.Verify(setup, msg, statements, proof)
size := proof.Size()                                     // bytes, compressed points
```

`LoadOwnerSecrets` reads its two inputs as follows:

- **`signerConfig`** is the owner's serialized `IdemixSignerConfig`. The credential
  and `sk` come from it.
- **`auditInfo`** is the owner's IdemixNym audit information. The pseudonym
  randomness comes from it.

It then verifies the credential against the issuer key with a pairing.
`testutils.NewTransferProver` produces naive transfers with the production
`TransferService`, together with their openings, which is how the tests and the
benchmark obtain statements and witnesses.

## 7. Benchmark

`BenchmarkAggregatedTransfersVsNaive` in `validator/validator_test.go` uses the
configuration of `BenchmarkValidatorTransferCSP64`: 2×2 transfers, IdemixNym owners,
64-bit CSP range proofs and BLS12-381. For each K it compares:

- K runs of the production sender with one `utxo.Prove`;
- K validator runs on a transfer request with one `utxo.Verify`;
- the total bytes of the ZK proofs and owner signatures with the aggregated proof's
  size.

Measured on an Intel i9-14900HX (32 threads), 2 iterations:

| K | Prove: naive / aggregated | Verify: naive / aggregated | Proof bytes: naive / aggregated |
|---|---|---|---|
| 8 | 935 ms / 656 ms | 136 ms / 53 ms | 75.7 K / 56.3 K |
| 32 | 3.01 s / 2.39 s | 391 ms / 67 ms | 303 K / 80 K |
| 64 | 6.86 s / 2.86 s | 1.27 s / 65 ms | 605 K / 84 K |
| 128 | 14.09 s / 7.90 s | 2.27 s / 95 ms | 1.21 M / 113 K |

At K = 2 (no longer in the benchmark's K list) the aggregated proof was 46 K against
19 K, so the size crossover lies between K = 2 and K = 8.

- **Proving** is faster than K naive senders at every measured K: 2.4× at K = 64 and
  1.8× at K = 128. Nearly
  all of the naive cost is per-transfer proving, while most of the aggregated cost is
  one group commitment over the private slots.
- **Verification** is nearly flat in K: 24× faster at K = 128.
- **Proof size** grows with log K: 10.7× smaller at K = 128. At small K the two Titan
  openings dominate.
- **Parity:** the group commitment needs `log c + log K` even, so odd `log K` pads
  the 9 private slots to 32 rather than 16. That is why K = 32 and K = 128 gain less
  than K = 64.
- **What the columns cover:** the naive verify figure includes the validator's
  deserialization and the auditor signature check. The naive prove figure excludes
  auditing.

**How the prover got here.** A first version took 16.1 s at K = 64, 2.3× *slower*
than naive. Profiling showed the Titan group commitment to `H` was about 90% of the
cost, for two reasons:

- **Double encoding.** Titan encoded the group polynomial twice, once as a flat
  codeword that nothing reads and once for the coset oracle. The flat encoding is now
  skipped, see [Titan](titan.md) §13.12.
- **Per-instance public data in `H`.** The 8 public columns were committed in `H`,
  which then had to pad to 64 columns at even `log K`. They now live in the pivot
  statement's public table, see [pivot](pivot.md) §6.

Run it with:

```
go test ./token/core/zkatdlog/nogh/v1/validator -run '^$' -bench BenchmarkAggregatedTransfersVsNaive -benchtime=3x
```

## 8. Security Considerations

- Everything in the [pivot protocol's security considerations](pivot.md#9-security-considerations)
  applies. In particular, soundness is conditional on the Titan PCS being
  evaluation-binding, and the proof is **not zero-knowledge**.
- **Linkability.** The published `A'` and the revealed aggregates `Â̄_i` and `N̂ym_i`
  are values a naive owner signature also discloses, per transfer. The aggregated
  Schnorr proof is honest-verifier zero-knowledge.
- **Who can aggregate.** The aggregating prover needs every owner's credential and
  `sk`, since they are part of the witness. Aggregation as implemented is therefore
  for a party holding all K owners' keys.
- **Message.** `M` is the same for all K transfers. How it is derived from the
  aggregated transaction's payload is left to the caller.

## 9. Testing

`utxo_test.go` runs on naive transfers produced by the production stack from the
`testdata` Idemix MSP.

- **Honest instances:** each of the 16 group equations and the field constraint
  holds on a laid-out transfer.
- **Round trips** at K = 2 (`c = 32`) and K = 4 (`c = 16`).
- **One bad transfer among K** is rejected in each of these cases:
  - a wrong output opening (group equations);
  - a flipped range bit (field constraint only);
  - an input whose pseudonym is not the owner's (group equations);
  - a forged credential with the wrong `e`. The linear equations still hold here, and
    only the aggregated pairing rejects it.
- **Tampering** is rejected:
  - the message;
  - an `A'` set to the identity;
  - an `A'` replaced by another point;
  - a Schnorr response;
  - a swapped statement;
  - the wrong number of transfers.
