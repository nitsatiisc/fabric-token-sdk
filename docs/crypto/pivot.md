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

The pivot protocol proves that $`K`$ instances of one mixed field/group relation all
hold, with a single proof whose size and verification cost are logarithmic in $`K`$.
It is the meta-protocol of the mixed-witness-aggregation write-up, built from two
existing pieces:

- [sum-check](sumcheck.md), including its composite `MultiClaim` (§4.6 there);
- the [Titan PCS](titan.md), for field polynomials (the field witnesses) and group
  polynomials (the group witnesses).

The prover commits once to all field witnesses and once to all group witnesses, runs
four sum-checks, and closes every residual claim with **one opening per commitment**.

## 2. The Relation

An instance has a private group witness $`g \in \mathbb{G}^c`$ and a private field witness
$`w \in \mathbb{F}^n`$. The public parameters (`Relation`) are shared by all $`K`$ instances:

```math
\begin{aligned}
G_0 + \sum_s (\alpha_s + (B w)_s)\, g_s + \sum_t (\alpha^{\mathrm{pub}}_t + (B^{\mathrm{pub}} w)_t)\, x_t + \sum_i (\Gamma w)_i\, G_i &= 0_{\mathbb{G}} \\
\Phi(L_1(w), \ldots, L_{\tau}(w)) &= 0_{\mathbb{F}}
\end{aligned}
```

where $`x`$ is the instance's row of the statement's **public table** (§6): group
elements that differ per instance but are known to the verifier.

| Parameter | Meaning |
|---|---|
| $`\alpha \in \mathbb{F}^c`$ | coefficients of the hidden group elements |
| $`B \in \mathbb{F}^{c \times n}`$ (sparse) | bilinear term: each $`g_s`$ meets a linear combination of $`w`$ |
| $`\alpha^{\mathrm{pub}} \in \mathbb{F}^{c_p}`$, $`B^{\mathrm{pub}} \in \mathbb{F}^{c_p \times n}`$ (sparse) | the same for the public table's columns |
| $`\Gamma \in \mathbb{F}^{l \times n}`$ (sparse) | pairs the public generators $`G`$ with linear combinations of $`w`$ |
| $`G \in \mathbb{G}^l`$, $`G_0 \in \mathbb{G}`$ | public generators and a public constant offset |
| `Forms` | affine forms $`L_k(w) = \sum \mathit{coeff} \cdot w[\mathit{col}] + \mathit{const}`$ |
| $`\Phi`$, `PhiDegree`, `PhiLabel` | the field constraint as a function of the form values, an upper bound on its degree, and a label that binds it into the transcript |

A nil $`\Phi`$ means there is no field constraint.

$`\Phi`$ is a Go function, so it can be written directly — $`Z_0 (1 - Z_1) + Z_2`$ is one
line — and it is never expanded into monomials. Because a function cannot be
absorbed into the transcript, `PhiLabel` stands for it there and must identify its
shape and any parameter of it not already bound by the transcript. `PhiDegree` sizes
the SC3 round polynomials; an understated degree makes honest proofs fail but does
not weaken soundness. All dimensions are powers of two
(`Sizes` holds their logs); callers pad.

## 3. Witness Layout

$`W \in \mathbb{F}^{K \times n}`$ and $`H \in \mathbb{G}^{K \times c}`$ hold one instance per row. Both tables are laid out
**position-first**: entry `x + (z << log n)` of $`\tilde W`$ is $`w^{(z)}[x]`$, and entry
`b + (z << log c)` of $`\tilde g`$ is $`g^{(z)}[b]`$. The low variables index the position within
an instance and the high variables the instance, so each instance is a contiguous
block.

Every point in the package is in **table order** (coordinate $`j`$ is variable $`j`$), the
order Titan's `Alpha` and `EvaluatePoint` use. A sum-check `Opening.R` comes back in
folding order, since the rounds substitute the last variable first; it is converted
in exactly one place (`tablePoint`), pinned by `TestTablePointOrder`. A prover and a
verifier that both got the order wrong would agree with each other on a proof about a
different polynomial, which no round-trip test sees.

## 4. Protocol

After the commitments, and after $`\tau \leftarrow \mathbb{F}^{\log K}`$:

| Step | Kind | Variables | Claim |
|---|---|---|---|
| SC1 | group, degree 3 | $`\log c + \log K`$ | $`\sum_{b,z} \mathrm{eq}(z,\tau) \cdot (\alpha_b + (B w^{(z)})_b) \cdot g^{(z)}_b = T_1`$ |
| SC1′ | group, degree 3 | $`\log c_p + \log K`$ | $`\sum_{t,z} \mathrm{eq}(z,\tau) \cdot (\alpha^{\mathrm{pub}}_t + (B^{\mathrm{pub}} w^{(z)})_t) \cdot x^{(z)}_t = T_1'`$ |
| SC2 | group, degree 2 | $`\log l`$ | $`\sum_y (\Gamma W_{\tau})_y \cdot G_y = -G_0 - T_1 - T_1'`$ |
| SC3 | field `MultiClaim` | $`\log K`$ | $`\sum_z \mathrm{eq}(z,\tau) \cdot \Phi(\tilde L_1(z), \ldots) = 0`$ |
| SC4 | field `MultiClaim`, degree 2 | $`\log n`$ | the sparse products left by SC1–SC3 |

- **SC1 + SC1′ + SC2** are the $`\mathrm{eq}(\cdot, \tau)`$-weighted sum of the $`K`$ group equations. The
  prover sends the sums $`T_1`$ and `T1′`, and SC2 targets $`-G_0 - T_1 - T_1'`$: only the total
  must vanish, not each part.
- **SC1′** has the shape of SC1 with the public table in place of $`\tilde g`$. Its residual is
  $`\mathrm{eq}(\rho_K', \tau) \cdot (\tilde\Lambda^{\mathrm{pub}}(\rho_t) + v_P') \cdot \tilde X(\rho_t, \rho_K')`$, and the verifier
  evaluates $`\tilde X`$ itself: one MSM over all $`c_p \cdot K`$ public elements. That is where it
  reads the per-instance public data, which it must do in any case. Nothing about the
  table is committed or opened. SC1′ is skipped when the statement has no public
  table. SC1 is a single three-factor product $`\mathrm{eq} \cdot S \cdot \tilde g`$, where the table
  $`S = \alpha + B W`$ is formed by the prover. SC2's generators are public, so the
  verifier evaluates $`\tilde G(\rho_l)`$ itself.
- **SC3** is the zero-check of the $`K`$ field constraints. Its pool is
  $`[\mathrm{eq}(\cdot,\tau), \tilde L_1, \ldots, \tilde L_{\tau}]`$, and its composition is $`\mathrm{eq} \cdot \Phi(\tilde L_1, \ldots)`$, a
  `MultiClaim` of degree `PhiDegree + 1`. It is skipped when $`\Phi`$ is nil.
- **SC4** discharges every sparse product in one sum-check over $`x`$. Term $`j`$, weighted
  $`\theta^j`$, is $`S_j(x) \cdot \tilde W(x, z_j)`$:

  | j | selector $`S_j`$ | $`z_j`$ | discharges |
  |---|---|---|---|
  | 0 | $`\tilde B(\rho_c, \cdot)`$ | `rho_K` | $`v_P`$ |
  | 1 | $`\tilde\Gamma(\rho_l, \cdot)`$ | $`\tau`$ | $`v_Q`$ |
  | 2 | $`A = \sum_k \lambda^k \cdot (\text{linear part of } L_k)`$ | `rho'` | $`\sum_k \lambda^k (\tilde L_k(\rho') - \mathit{const}_k)`$ |
  | 3 | $`\tilde B^{\mathrm{pub}}(\rho_t, \cdot)`$ | `rho_K′` | `v_P′` |

  Term 2 is present only with a field constraint and term 3 only with a public table;
  the numbering closes up. The verifier evaluates each selector at the final point from
  its non-zeros alone. Folding SC3's residual into SC4 saves a separate $`\log n`$
  sum-check.

SC4 leaves one claim on $`\tilde W`$ per term, at $`(\sigma, z_j)`$. SC1 leaves one on $`\tilde g`$, at
$`(\rho_c, \rho_K)`$.

## 5. Evaluation-Claim Batching

Several claims $`p(z_j) = v_j`$ on one committed polynomial reduce to one. On a
challenge $`\gamma`$ drawn after every `(z_j, v_j)` is on the transcript,

```math
\sum_j \gamma^j v_j = \sum_x E(x) \cdot p(x), \qquad E(x) = \sum_j \gamma^j \mathrm{eq}(x, z_j)
```

is a two-factor sum-check, $`E \cdot \tilde W`$ on the field side and $`E \cdot \tilde g`$ on the group side.
It ends at one random point $`\rho`$. The verifier computes `E(rho)` itself, and one
Titan opening (`ProveAt(rho)`) supplies $`p(\rho)`$. If any claim is false, the batch
holds with probability at most $`(J-1)/p`$.

The $`z_j`$ may have boolean coordinates, which is what lets the same batch close the
revealed columns of §6.

## 6. Public Table and Revealed Columns

A `Statement` carries two things besides the relation:

- **`Public`**, the per-instance public group elements, such as commitments and
  pseudonyms, one row of width $`c_p`$ per instance. They are **not committed**:
  - they enter the relation through `AlphaPub` and `BPub`;
  - SC1′ handles them, and the verifier evaluates the table itself.

  An earlier version stored them as public columns of the committed $`H`$ and checked
  those columns against the statement. That committed data the verifier already has,
  and it widened $`H`$, whose group commitment dominates the prover. Moving them out
  removed both costs.
- **`RevealCols`** are private columns of $`H`$ whose $`\tau`$-aggregate the proof
  discloses, for checks the caller runs outside the relation. For example, a pairing
  check that is linear in a column aggregates into one pairing on the revealed value.
  `Verify` returns them in `Outcome.Revealed`, together with `Outcome.Tau`. Each is one
  more claim on $`\tilde g`$, at a point whose column bits are boolean and whose instance bits
  are $`\tau`$. It rides on the group batch, so it adds no opening.

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
challenges build `alpha`, $`B`$, `Gamma`, $`G_0`$ and $`\Phi`$.
`TestRelationFromPostCommitmentChallenge` exercises this.

`SetupOptions` carries the field commitment's matrix split and both fold
configurations. Left zero, they take Titan's canonical configuration, which is strict:
the field row half and $`\log c + \log K`$ must be even. Any other sizes work with custom
configurations, which Titan checks for correctness only (see [Titan](titan.md) §13.10).
The [UTXO instantiation](pivot-utxo.md) passes custom configurations, because its
sizes take either parity as K varies.

Errors wrapping `ErrMalformedProof` mean the proof is structurally wrong. Errors
wrapping `ErrVerificationFailed`, or a sum-check or PCS error, mean it is well formed
but false.

## 8. Transcript

One transcript under the domain separator `PivotAgg-v1` runs through the whole
protocol, in this order:

1. The sizes and both commitments (shape plus the coset-oracle root).
2. Anything the caller squeezes.
3. The relation and the statement. $`\Phi`$ enters as `PhiDegree` and `PhiLabel`.
4. $`\tau`$.
5. SC1, then $`v_P`$ and `g~(rho_c, rho_K)`.
6. SC1′ (with a public table), then $`v_P'`$.
7. SC2, then $`v_Q`$.
8. SC3, then the form values.
9. $`\theta`$ and $`\lambda`$.
10. SC4, then its $`\tilde W`$ values.
11. $`\gamma_W`$, the `W~` batch, and its opened value.
12. The revealed columns.
13. $`\gamma_g`$, the `g~` batch, and its opened value.

The two Titan opening proofs use their own internal transcripts. Their points and
values are fixed by this one before they run.

## 9. Security Considerations

- **Soundness is conditional on the Titan PCS being evaluation-binding.** See the
  Titan document for the regime in which that is established; it is inherited here and
  not re-argued.
- **Not zero-knowledge.** The Titan PCS is not hiding and sum-check messages are sent
  in the clear.
- **Every instance must satisfy the relation.** Padding $`K`$ to a power of two with
  all-zero instances fails as soon as $`G_0 \ne 0`$; pad with valid dummy instances.
- **Soundness error.** The dominant terms are:
  - aggregation, $`\log K / p`$ per equation kind;
  - the four sum-checks, $`\sum \mathrm{degree} \cdot \mathrm{variables} / p`$;
  - the $`\theta`$/$`\lambda`$ batching in SC4, $`(\tau + 2)/p`$;
  - the two evaluation batches, $`(J-1)/p`$ each.

  All are negligible at $`p \approx 2^{255}`$.

## 10. Testing

`pivot_test.go` builds random relations with a degree-2 field constraint:
- a product, $`w_2 = w_0 \cdot w_1 - 5`$;
- a bit, $`w_3 \in \{0,1\}`$;
- a constant term.

Each instance also has a public row of width 4, with constant coefficients on every
column and a `BPub` term on two of them. Its last private group slot is solved for so
that its group equation holds.

- **Round trips** at the balanced split ($`\tilde W`$ over 8 variables), at an explicit split
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
  $`\tilde W`$ value, both opened values, a revealed value) is rejected. So is a commitment
  swapped for another witness's.
- **Structure**: missing sub-proofs and wrongly sized vectors return
  `ErrMalformedProof`.
- **Phi**: a relation with $`\Phi`$ but no degree or label, or a degree and label
  without $`\Phi`$, returns `ErrInvalidRelation`. A proof made under one `PhiLabel`
  does not verify under another (`TestPhiLabelIsBound`).

## 11. References

- [Sum-Check Protocol](sumcheck.md), §4.6 for `MultiClaim`.
- [Titan Polynomial Commitment Scheme](titan.md), §13.12 for `ProveAt`.
- The mixed-witness-aggregation write-up: overview (the pivot relation) and the
  meta-protocol section.
