# Plan: Titan multilinear PCS — step 4 (`Eval`: completing the PCS)

Steps 1–3 are complete and committed (`ccc7e99d`, `3dd550d8`, `cdcc053c`). Step 3's
plan is preserved at `git show cdcc053c:plan.md`. **This plan covers step 4 only.**

## Goal

Add `Eval` to both the field and group constructions, so the package is a working
polynomial commitment scheme rather than a binding-but-unopenable oracle.

After step 3 we can commit and open *positions* of the codeword. We cannot prove
`f̃(α) = σ`. That is the gap step 4 closes.

## The structure of `Eval`, read from the reference

From `titanpcs.rs:221-300` (not from the paper's prose, which is vaguer). `Eval` at a
point `α` splits it across the matrix as `(α_x, α_y)` — `α_y` the row/group side,
`α_x` the column/field side — and proves **two legs**:

    sigma_partial = MSM over rows of eq(alpha_y, .)     // a group element
                  = the partial evaluation of f at alpha_y

    leg 1 (alpha_y):  group sum-check, sigma_partial against the Merkle oracle
    leg 2 (alpha_x):  prove the folded field poly evaluates to sigma,
                      against the Pedersen commitment sigma_partial

Both are required. Leg 1 alone proves `σ_partial` is consistent with the committed
oracle but binds nothing about `α_x`; leg 2 alone proves an evaluation under a
commitment nobody has tied to the oracle. Together they close `f̃(α) = σ`.

## Leg 2 is CSP, not Bulletproof — the field vector is publicly computable

The reference uses a Bulletproof IPA (`titanpcs.rs:275-287`). **We use CSP instead**,
per the user's correction, and the reason is that the linear form on leg 2 is
`eq(α_x, ·)`, which the **verifier computes itself** from the public `α_x`. There is
no secret vector to hide, so the Bulletproof machinery buys nothing over the
compressed sigma-protocol already in this repo.

`crypto/rp/csp` proves exactly the needed statement (`csp.go:47-72`): given Pedersen
commitment `C`, public generators, and a public linear form `f`, that `⟨f, w⟩ = v`
for the committed `w`, in `2·log n` group elements and no zero-knowledge
(`rp.go:430` calls it "Non-ZK CSP proof", which is what we want here).

Mapping Titan's leg 2 onto CSP's statement:

| CSP field | Titan leg 2 |
|---|---|
| `Commitment` | `σ_partial` (tier-1 Pedersen output, folded at `α_y`) |
| `Generators` | the tier-1 generators `gens[:cols]` |
| `LinearForm` | `eq(α_x, ·)` — public, verifier-recomputable |
| `Value` | `σ`, the claimed `f̃(α)` |
| `witness` | the folded field poly `a_poly = fold(f, α_y)` |

## Reuse decision: export a wrapper in `crypto/rp/csp`, convert at the boundary

Chosen by the user over a gnark-native reimplementation, so there is **one** CSP in
the tree and Titan uses the audited one.

Two frictions, both real and both measured rather than assumed:

1. **`prover`/`verifier` are unexported** (`csp.go:75`, `csp.go:208`), constructed
   only at `rp.go:431` and `rp.go:627`. Needs an exported wrapper —
   `ProveLinearForm` / `VerifyLinearForm` — in `crypto/rp/csp`. Adding a wrapper
   rather than exporting the structs keeps the existing call sites and the struct
   internals untouched, which matters because this is live range-proof code.
2. **Representation mismatch.** CSP is mathlib (`*mathlib.G1`, `*mathlib.Zr`); Titan
   is gnark-crypto (`bls12381.G1Affine`, `fr.Element`).

### Measured: the bridge works, and where its cost actually lands

Verified empirically (throwaway probe, since deleted):

- **Same curve, same scalar field.** `mathlib.BLS12_381_BBS_GURVY`'s group order is
  bit-identical to `fr.Modulus()`. (First comparison appeared to show a mismatch —
  that was mathlib printing hex against gnark printing decimal, not a real
  difference. Worth recording because the false alarm is easy to repeat.)
- **G1 round-trips** gnark → 48-byte compressed → mathlib → back, exactly.
- **Zr round-trips** via 32-byte big-endian.

Conversion cost, Apple M4 Max:

| n | G1 convert | Zr convert |
|---|---|---|
| 32 | 1.05ms | 2.19µs |
| 64 | 2.09ms | 4.32µs |
| 128 | 4.28ms | 9.28µs |
| 256 | 8.64ms | 18.3µs |

**~33µs per G1 point**, linear, because both `NewG1FromCompressed` and
`NewG1FromBytes` route through `SetBytes`, which does a subgroup check — confirmed by
reading `mathlib@v0.3.0/driver/gurvy/bls12381/bls12-381.go:531-559`. There is no
cheap path; the cost is structural to mathlib. Scalars are ~72ns each, i.e. free.

**This is why the design caches.** Naively converting per proof would cost 4.28ms at
`m = 14` (128 generators) to produce a proof of only `2·log n = 14` group elements —
the boundary would dominate the thing it enables. But the **generators are fixed
setup parameters**, so they convert **once per commitment** and are held in the
opening hint. The scalars (`a_poly`, `eq(α_x,·)`) are per-proof but cost microseconds.
So the per-proof boundary cost is ~20µs, not ~4ms.

This is the same access-pattern argument recorded for `crypto/sumcheck`: convert once
at the edge, hold the converted form, never rebuild per call.

## Step 4 sub-items

### 4.1 `crypto/rp/csp` — exported wrapper

    type LinearFormStatement struct {
        Commitment *mathlib.G1
        Generators []*mathlib.G1
        LinearForm []*mathlib.Zr
        Value      *mathlib.Zr
        Curve      *mathlib.Curve
    }
    func ProveLinearForm(st LinearFormStatement, witness []*mathlib.Zr, hdr []byte) (*Proof, error)
    func VerifyLinearForm(st LinearFormStatement, proof *Proof, hdr []byte) error

Thin: validate power-of-two length, derive `NumberOfRounds = log2(len)`, delegate to
the existing unexported `prover`/`verifier`. No change to their internals, no change
to `rp.go`'s call sites. Godoc must state that this is **not** zero-knowledge.

### 4.2 `titan/bridge.go` — the mathlib boundary

    func toMathG1(p *bls12381.G1Affine, curve *mathlib.Curve) (*mathlib.G1, error)
    func toMathG1Slice(pts []bls12381.G1Affine, curve *mathlib.Curve) ([]*mathlib.G1, error)
    func toMathZr(e *fr.Element, curve *mathlib.Curve) *mathlib.Zr
    func toMathZrSlice(es []fr.Element, curve *mathlib.Curve) []*mathlib.Zr

Isolated in one file so the cost has exactly one place to live and one place to
optimize. Must reject the point at infinity with a named error: CSP's
`validateG1Slice` rejects identity generators (`validation.go:30-46`), and a
confusing panic from deep inside mathlib is worse than an error at the boundary.

### 4.3 `titan/eval.go` — the two legs

    type EvalProof struct {
        SigmaPartial bls12381.G1Affine  // the tier-1 Pedersen commitment at alpha_y
        RowProof     *GroupSumCheckProof // leg 1
        ColProof     *csp.Proof          // leg 2
        Queries      []*MerkleProof      // oracle openings closing leg 1
    }

    func (h *FieldOpeningHint) Eval(alpha []fr.Element) (*EvalProof, fr.Element, error)
    func VerifyEval(c *Commitment, alpha []fr.Element, sigma fr.Element, proof *EvalProof, ...) error

    func (h *GroupOpeningHint) EvalGroup(alpha []fr.Element) (*GroupEvalProof, bls12381.G1Affine, error)
    func VerifyEvalGroup(...) error

The group construction gets `EvalGroup`, which is **leg 1 only** — that is not a
missing leg but the correct shape: a group polynomial's evaluation *is* a group
element, so there is no field value to bind and no second leg to prove. Worth a
comment, since "the group one has fewer legs" reads like an omission.

Cache the converted generators on `FieldOpeningHint` at commit time (4.2's cost
argument), not at `Eval` time.

### 4.4 Tests

1. **Round-trip**: `Eval` then `VerifyEval` accepts, for `m = 2..12`, odd and even.
2. **Soundness negatives**, each must be rejected: wrong `σ`; tampered
   `SigmaPartial`; tampered leg-1 round message; tampered leg-2 CSP proof; `α`
   permuted; a proof from a *different* polynomial against this root.
3. **Leg independence**: a valid leg 1 with a leg 2 from another polynomial must
   fail, and vice versa. This is the test that catches "the two legs are not
   actually tied together", which is the subtle way a two-leg proof goes unsound.
4. **Cross-check `σ`** against `f̃.EvaluatePoint(α)` from `crypto/sumcheck`,
   independently computed.
5. **`σ_partial` cross-check**: equals a direct `Σ_j eq(α_y,⟨j⟩)·G_j`.
6. **Bridge tests**: G1 and Zr round-trip; infinity rejected; order equality pinned
   as a regression test (it is an assumption the whole design rests on).
7. **Group `EvalGroup`** round-trip and negatives.
8. Mutation pass, as for steps 1–3. Candidates: swap `α_x`/`α_y`; leg 2 uses
   `eq(α_y,·)`; `σ_partial` not bound into the transcript; skip the Merkle queries.

## Deferred, with reasons

- **`O(⁴√n)`.** Unchanged, and **not** what `k = 0` controls (see below).
- **Zero-knowledge.** CSP here is the non-ZK variant, tier 1 is non-hiding Pedersen,
  and leg 2's witness is the folded polynomial. Hiding is a separate change to tier 1.
- **`Setup`.** `gens` still comes from the caller.
- **Batch `Eval`** at several points. `ProveBatch` exists on the tree; the protocol
  batching is separate work.

## Notes & Decisions

- **The `√n` vs `⁴√n` axis is NOT coset size.** The user asked whether this is still
  `O(√n)` "as we don't do coset-wise commitment yet". Still `O(√n)`, yes, but `k = 0`
  is not the reason. Reading `TitanSetupConfig` (`titanpcs.rs:66-77`), the config
  carries `l1`/`domain_g1_size` for the group oracle **and separately** `l2`/
  `domain_g2_size` for a *generator* oracle. `⁴√n` comes from folding the generator
  oracle too, so the verifier need not read `2^(m/2)` generators. With one folding
  layer we are at `√n` regardless of `k`. Coset size `k` affects query cost and proof
  size within that, not the asymptotic class. (Confidence: high on the config
  reading; I have not traced the end-to-end `⁴√n` verifier cost, so the precise
  crossover is not claimed.)
- Leg 2 is CSP, not Bulletproof, because `eq(α_x,·)` is public — user's correction,
  and it removes a whole protocol from the port.
- `make lint` still cannot run locally (`golangci-lint` absent); owed before PR.
- **Issue still owed** for the step-3 work (`gh` unavailable in this environment);
  step 4 needs one too.

### Two findings that changed the plan

- **The cache belongs to the verifier, not the prover — measured, and it inverted the
  plan.** Section "Measured" above reasoned that generators convert once per
  *commitment* and so should be held on `FieldOpeningHint`. That is prover-side state,
  and **a verifier never holds an opening hint**. Benchmarking showed the verifier is
  the side the boundary dominates (M4 Max, `-benchtime=1s`):

  | m | gens | prove cached | prove uncached | verify cached | verify uncached |
  |---|---|---|---|---|---|
  | 10 | 32 | 7.88ms | 9.01ms | 0.94ms | 2.03ms |
  | 12 | 64 | 12.58ms | 14.92ms | 1.14ms | 3.41ms |
  | 14 | 128 | 22.26ms | 26.99ms | 1.42ms | 6.04ms |

  At m=14 the cache is a **4.3x** speedup on verification and the boundary is **77%**
  of the uncached verifier, against **18%** of the prover. So the cache became a
  first-class exported `Generators` type that both sides build and hold, with
  `EvalAffine`/`VerifyEvalAffine` kept as documented one-off paths. Measured per-point
  cost is ~35us, close to the ~33us probed earlier.

- **`m` is not recoverable from a `Commitment`, and my first attempt to recover it was
  vacuous.** I wrote `varsFromCommitment` to derive `m` from the commitment, resolving
  the odd/even ambiguity "by checking the row count". **That check is vacuous**: every
  row count is produced by two different `m` (rows=2 <- m in {1,2}, ..., rows=256 <-
  m in {15,16}), differing only in the column count, which `Commitment` does not carry
  — so both candidates reproduce the row count and the even one was simply tried
  first. My own test over m=1..16 caught it. Replaced with `checkShape(c, m)`, taking
  `m` from `len(alpha)` (public input) and validating the commitment against it;
  `TestCheckShape` now pins the ambiguity so the claim cannot be re-made. A
  consequence: an `alpha` one coordinate short can pass `checkShape` and be rejected
  by leg 1 instead, so the error names the round check rather than the length.
  Adding the column count to `Commitment` would fix this properly; that is a wire
  format change and was not made.

### Smaller decisions

- **The variable split is the opposite way round from the Rust reference**, verified by
  probe for m=2..5 rather than assumed: `alphaCol = alpha[:m/2]`, `alphaRow =
  alpha[m/2:]`. Rows are contiguous blocks, so the row index is the *high* bits of the
  flat index, and little-endian makes the high bits the *last* variables. This is the
  worst available bug here because `eq` factorizes over any split — a swapped split
  self-verifies against a different polynomial. Only the independent
  `EvaluatePoint(alpha)` cross-check catches it.
- **`sigmaPartial` is taken from `ProveGroupEval`'s return, not derived a second
  time.** Deriving it twice would let the two derivations disagree silently, and
  `sigmaPartial` is the only thing binding the two legs.
- **A `Generators` cache is bound to its curve, and `prefix` enforces it.** mathlib has
  four BLS12-381 IDs sharing the group and scalar field, and CSP's `validateG1Slice`
  rejects on ID mismatch — so a cross-variant cache otherwise fails deep inside CSP
  validation with a message about element curves. Found while noticing
  `groupsumcheck_test.go` uses `BLS12_381_BBS` while `bridgeCurve()` returns
  `BLS12_381_BBS_GURVY`; pinned with a four-variant bridge test, and the guard then
  immediately caught a real mismatch in an existing `Eval` test.
- **`EvalProof` has no `Queries` field yet**, unlike the sketch in 4.3. The oracle
  openings are step 5; a present-but-nil field would imply the soundness gap is
  smaller than it is.

## Implementation Progress

- [x] 4.1 `crypto/rp/csp` exported wrapper + tests — `ProveLinearForm`/`VerifyLinearForm`
      plus `LinearFormStatement`; committed as `f8d313bc`. No change to the existing
      `prover`/`verifier` internals or to `rp.go`'s call sites.
- [x] 4.2 `titan/bridge.go` + tests — `toMathG1`/`toMathG1Slice`/`toMathZr`/
      `toMathZrSlice`/`toFieldElement`. Added `ErrPointAtInfinity`. Signatures differ
      from the plan's sketch: the `Zr` converters return an `error` too, since
      `NewZrFromBytes` can fail. Points cross one way only (CSP verifies in mathlib),
      so there is no reverse for G1; scalars do come back.
- [x] 4.3 `titan/eval.go` (field `Eval`, group `EvalGroup`) + verifiers. Two
      deviations from the plan's sketch, both recorded under Notes below:
      the generator cache is a shared `Generators` type, not a field on
      `FieldOpeningHint`; and `EvalProof` carries no `Queries` field yet, since the
      oracle queries belong to step 5 and a nil-but-present field would suggest
      otherwise.
- [x] 4.4 Tests, negatives, leg-independence. Coverage 92.6%, race-clean. The
      round-trip asserts *both* acceptance and `sigma == EvaluatePoint(alpha)`; the
      second assertion is the one that can catch a swapped variable split.
- [x] 4.5 `docs/crypto/titan.md` — Evaluation added as **§12** (not §13: References
      was §12 and is now §13), with §8's API table and §11's coverage table updated.
- [x] 4.6 Benchmarks incl. the cached-vs-uncached boundary cost. Numbers in the
      Notes below; they changed the design.

### Still owed on step 4

- [ ] `make lint` — `golangci-lint` is absent in this environment, so it has **not**
      been run and must not be claimed as passing.
- [ ] GitHub issues for steps 3 and 4 — `gh` is unavailable here. Step 3's commit
      (`cdcc053c`) already precedes its issue, inverting the intended order; the fix
      is to open the issue, then amend `cdcc053c` with `Fixes #N` before pushing.
- [x] Mutation pass over `eval.go` (item 4.4's point 8). Nine mutations, seven
      caught. **One real gap found**: leg 2 reusing leg 1's domain separator left the
      suite green, so two tests were added
      (`TestEvalTranscriptHeaderIsDistinct`, `TestEvalColumnLegRejectsForeignTranscript`)
      and the mutation now fails both. The other survivor — the prover recomputing
      `MSM(gens, a)` instead of reusing leg 1's `sigmaPartial` — is an **equivalent
      mutant**: the two values coincide by the section-12.2 identity, which
      `TestEvalSigmaPartialIsTheFoldedCommitment` already asserts, so no test can or
      should distinguish them. Documented in docs section 12.9 rather than papered
      over.
