# Pivot Aggregation Protocol

**Implementation**: [`token/core/zkatdlog/nogh/v1/crypto/pivot`](../../token/core/zkatdlog/nogh/v1/crypto/pivot)
**Curve**: BLS12-381 (G1)
**Date**: 2026-09-26

## Table of Contents
1. [Introduction](#1-introduction)
2. [The Relation](#2-the-relation)
3. [Witness Layout](#3-witness-layout)
4. [Protocol](#4-protocol)
5. [Evaluation-Claim Batching](#5-evaluation-claim-batching)
6. [Public Table and Revealed Columns](#6-public-table-and-revealed-columns)
7. [API](#7-api)
8. [Transcript](#8-transcript)
9. [Security Considerations](#9-security-considerations)
10. [Testing](#10-testing)
11. [References](#11-references)

---

## 1. Introduction

The pivot protocol proves that `K` instances of one mixed field/group relation all
hold, with a single proof whose size and verification cost are logarithmic in `K`.
It is the meta-protocol of the mixed-witness-aggregation write-up, built from two
existing pieces:

- [sum-check](sumcheck.md), including its sum-of-products `MultiClaim` (§4.6 there);
- the [Titan PCS](titan.md), for field polynomials (the field witnesses) and group
  polynomials (the group witnesses).

The prover commits once to all field witnesses and once to all group witnesses, runs
four sum-checks, and closes every residual claim with **one opening per commitment**.

## 2. The Relation

An instance has a private group witness `g ∈ G^c` and a private field witness
`w ∈ F^n`. The public parameters (`Relation`) are shared by all `K` instances:

```
G0 + Σ_s (alpha_s + (B w)_s) g_s + Σ_t (alphaPub_t + (BPub w)_t) x_t + Σ_i (Gamma w)_i G_i = 0_G
Phi(L_1(w), ..., L_tau(w))                                                             = 0_F
```

where `x` is the instance's row of the statement's **public table** (§6): group
elements that differ per instance but are known to the verifier.

| Parameter | Meaning |
|---|---|
| `Alpha ∈ F^c` | coefficients of the hidden group elements |
| `B ∈ F^{c×n}` (sparse) | bilinear term: each `g_s` meets a linear combination of `w` |
| `AlphaPub ∈ F^{cp}`, `BPub ∈ F^{cp×n}` (sparse) | the same for the public table's columns |
| `Gamma ∈ F^{l×n}` (sparse) | pairs the public generators `G` with linear combinations of `w` |
| `G ∈ G^l`, `G0 ∈ G` | public generators and a public constant offset |
| `Forms` | affine forms `L_k(w) = Σ coeff·w[col] + const` |
| `Phi` | a polynomial in the form values, as a list of monomials |

An empty `Phi` means there is no field constraint. All dimensions are powers of two
(`Sizes` holds their logs); callers pad.

## 3. Witness Layout

`W ∈ F^{K×n}` and `H ∈ G^{K×c}` hold one instance per row. Both tables are laid out
**position-first**: entry `x + (z << log n)` of `W~` is `w^(z)[x]`, and entry
`b + (z << log c)` of `g~` is `g^(z)[b]`. The low variables index the position within
an instance and the high variables the instance, so each instance is a contiguous
block.

Every point in the package is in **table order** (coordinate `j` is variable `j`), the
order Titan's `Alpha` and `EvaluatePoint` use. A sum-check `Opening.R` comes back in
folding order, since the rounds substitute the last variable first; it is converted
in exactly one place (`tablePoint`), pinned by `TestTablePointOrder`. A prover and a
verifier that both got the order wrong would agree with each other on a proof about a
different polynomial, which no round-trip test sees.

## 4. Protocol

After the commitments, and after `tau ← F^{log K}`:

| Step | Kind | Variables | Claim |
|---|---|---|---|
| SC1 | group, degree 3 | `log c + log K` | `Σ_{b,z} eq(z,tau)·(alpha_b + (B w^(z))_b)·g^(z)_b = T1` |
| SC1′ | group, degree 3 | `log cp + log K` | `Σ_{t,z} eq(z,tau)·(alphaPub_t + (BPub w^(z))_t)·x^(z)_t = T1′` |
| SC2 | group, degree 2 | `log l` | `Σ_y (Gamma W_tau)_y·G_y = −G0 − T1 − T1′` |
| SC3 | field `MultiClaim` | `log K` | `Σ_z eq(z,tau)·Phi(L~_1(z), …) = 0` |
| SC4 | field `MultiClaim`, degree 2 | `log n` | the sparse products left by SC1–SC3 |

- **SC1 + SC1′ + SC2** are the `eq(·, tau)`-weighted sum of the `K` group equations. The
  prover sends the sums `T1` and `T1′`, and SC2 targets `−G0 − T1 − T1′`: only the total
  must vanish, not each part.
- **SC1′** has the shape of SC1 with the public table in place of `g~`. Its residual is
  `eq(rho_K′, tau)·(LambdaPub~(rho_t) + v_P′)·X~(rho_t, rho_K′)`, and the verifier
  evaluates `X~` itself: one MSM over all `cp·K` public elements. That is where it
  reads the per-instance public data, which it must do in any case. Nothing about the
  table is committed or opened. SC1′ is skipped when the statement has no public
  table. SC1 is a single three-factor product `eq · S · g~`, where the table
  `S = alpha + B W` is formed by the prover. SC2's generators are public, so the
  verifier evaluates `G~(rho_l)` itself.
- **SC3** is the zero-check of the `K` field constraints. Its pool is
  `[eq(·,tau), L~_1, …, L~_tau]`, and each monomial of `Phi` becomes a term with the `eq`
  factor prepended. It is skipped when `Phi` is empty.
- **SC4** discharges every sparse product in one sum-check over `x`. Term `j`, weighted
  `θ^j`, is `S_j(x)·W~(x, z_j)`:

  | j | selector `S_j` | `z_j` | discharges |
  |---|---|---|---|
  | 0 | `B~(rho_c, ·)` | `rho_K` | `v_P` |
  | 1 | `Gamma~(rho_l, ·)` | `tau` | `v_Q` |
  | 2 | `A = Σ_k λ^k·(linear part of L_k)` | `rho'` | `Σ_k λ^k (L~_k(rho') − const_k)` |
  | 3 | `BPub~(rho_t, ·)` | `rho_K′` | `v_P′` |

  Term 2 is present only with a field constraint and term 3 only with a public table;
  the numbering closes up. The verifier evaluates each selector at the final point from
  its non-zeros alone. Folding SC3's residual into SC4 saves a separate `log n`
  sum-check.

SC4 leaves one claim on `W~` per term, at `(sigma, z_j)`. SC1 leaves one on `g~`, at
`(rho_c, rho_K)`.

## 5. Evaluation-Claim Batching

Several claims `p(z_j) = v_j` on one committed polynomial reduce to one. On a
challenge `γ` drawn after every `(z_j, v_j)` is on the transcript,

```
Σ_j γ^j v_j  =  Σ_x E(x)·p(x),        E(x) = Σ_j γ^j eq(x, z_j)
```

is a two-factor sum-check, `E · W~` on the field side and `E · g~` on the group side.
It ends at one random point `rho`. The verifier computes `E(rho)` itself, and one
Titan opening (`ProveAt(rho)`) supplies `p(rho)`. If any claim is false, the batch
holds with probability at most `(J−1)/p`.

The `z_j` may have boolean coordinates, which is what lets the same batch close the
revealed columns of §6.

## 6. Public Table and Revealed Columns

A `Statement` carries two things besides the relation:

- **`Public`**, the per-instance public group elements, such as commitments and
  pseudonyms, one row of width `cp` per instance. They are **not committed**:
  - they enter the relation through `AlphaPub` and `BPub`;
  - SC1′ handles them, and the verifier evaluates the table itself.

  An earlier version stored them as public columns of the committed `H` and checked
  those columns against the statement. That committed data the verifier already has,
  and it widened `H`, whose group commitment dominates the prover. Moving them out
  removed both costs.
- **`RevealCols`** are private columns of `H` whose `tau`-aggregate the proof
  discloses, for checks the caller runs outside the relation. For example, a pairing
  check that is linear in a column aggregates into one pairing on the revealed value.
  `Verify` returns them in `Outcome.Revealed`, together with `Outcome.Tau`. Each is one
  more claim on `g~`, at a point whose column bits are boolean and whose instance bits
  are `tau`. It rides on the group batch, so it adds no opening.

## 7. API

```go
setup, err := pivot.NewSetup(pivot.Sizes{LogN: 4, LogC: 2, LogL: 2, LogK: 4}, gens, curve, pivot.SetupOptions{})

// Prover.
tr := pivot.NewTranscript(curve)
committed, err := pivot.Commit(setup, witness, tr)
// ... optionally squeeze challenges from tr and derive the relation from them ...
proof, pOutcome, err := pivot.Prove(setup, relation, statement, committed, tr)
coms := committed.Commitments()

// Verifier.
vtr := pivot.NewTranscript(curve)
err = pivot.AbsorbCommitments(setup, coms, vtr)
// ... squeeze the same challenges and derive the same relation ...
outcome, err := pivot.Verify(setup, relation, statement, coms, proof, vtr)
```

`Prove` returns the same `Outcome` as `Verify` (the aggregation challenge and the
revealed column aggregates), for a caller that proves further statements about them;
`EqTable(outcome.Tau)` gives the weights of the aggregates. The [UTXO
instantiation](pivot-utxo.md) uses both for its aggregated Schnorr proofs.

The split into `Commit` and `Prove` exists for relations whose parameters depend on
challenges drawn after the commitments, as in the UTXO instantiation, whose collapse
challenges build `alpha`, `B`, `Gamma`, `G0` and `Phi`.
`TestRelationFromPostCommitmentChallenge` exercises this.

`SetupOptions` carries the field commitment's matrix split and both fold
configurations. The balanced default split only folds when `log n + log K` is a
multiple of four. Other sizes need an explicit `FieldSplit`, e.g. `{M: 6, M1: 2}`.
The group commitment needs `log c + log K` even, which `NewSetup` checks.

Errors wrapping `ErrMalformedProof` mean the proof is structurally wrong. Errors
wrapping `ErrVerificationFailed`, or a sum-check or PCS error, mean it is well formed
but false.

## 8. Transcript

One transcript under the domain separator `PivotAgg-v1` runs through the whole
protocol, in this order:

1. The sizes and both commitments (shape plus the coset-oracle root).
2. Anything the caller squeezes.
3. The relation and the statement.
4. `tau`.
5. SC1, then `v_P` and `g~(rho_c, rho_K)`.
6. SC1′ (with a public table), then `v_P′`.
7. SC2, then `v_Q`.
8. SC3, then the form values.
9. `θ` and `λ`.
10. SC4, then its `W~` values.
11. `γ_W`, the `W~` batch, and its opened value.
12. The revealed columns.
13. `γ_g`, the `g~` batch, and its opened value.

The two Titan opening proofs use their own internal transcripts. Their points and
values are fixed by this one before they run.

## 9. Security Considerations

- **Soundness is conditional on the Titan PCS being evaluation-binding.** See the
  Titan document for the regime in which that is established; it is inherited here and
  not re-argued.
- **Not zero-knowledge.** The Titan PCS is not hiding and sum-check messages are sent
  in the clear.
- **Every instance must satisfy the relation.** Padding `K` to a power of two with
  all-zero instances fails as soon as `G0 ≠ 0`; pad with valid dummy instances.
- **Soundness error.** The dominant terms are:
  - aggregation, `log K / p` per equation kind;
  - the four sum-checks, `Σ degree · variables / p`;
  - the `θ`/`λ` batching in SC4, `(τ + 2)/p`;
  - the two evaluation batches, `(J − 1)/p` each.

  All are negligible at `p ≈ 2^255`.

## 10. Testing

`pivot_test.go` builds random relations with a degree-2 field constraint:
- a product, `w2 = w0·w1 − 5`;
- a bit, `w3 ∈ {0,1}`;
- a constant term.

Each instance also has a public row of width 4, with constant coefficients on every
column and a `BPub` term on two of them. Its last private group slot is solved for so
that its group equation holds.

- **Round trips** at the balanced split (`W~` over 8 variables), at an explicit split
  (6 variables), without a field constraint, and without a public table. The revealed
  aggregate is checked
  against a direct computation.
- **One bad instance among K**, which is the test that shows aggregation happened. A
  single instance violating its group equation, or only its field constraint, is
  rejected with `ErrVerificationFailed`. The fixture's own oracle confirms which
  equation fails.
- **Public table:**
  - A public row that prover and verifier agree on but that disagrees with the witness
    breaks that instance's group equation. This is tested on a constant-coefficient
    column and on a `BPub` column.
  - A statement changed after proving desynchronises the transcript.
- **Tampering** with each prover value (`PEval`, `GEval`, `QEval`, a form value, each
  `W~` value, both opened values, a revealed value) is rejected. So is a commitment
  swapped for another witness's.
- **Structure**: missing sub-proofs and wrongly sized vectors return
  `ErrMalformedProof`.

## 11. References

- [Sum-Check Protocol](sumcheck.md), §4.6 for `MultiClaim`.
- [Titan Polynomial Commitment Scheme](titan.md), §13.12 for `ProveAt`.
- The mixed-witness-aggregation write-up: overview (the pivot relation) and the
  meta-protocol section.
