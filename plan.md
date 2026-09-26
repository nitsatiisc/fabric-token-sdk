# Plan: R_utxo aggregation on the pivot protocol, and its benchmark

Goal: aggregate K naive 2x2 zkatdlog transfers (IdemixNym owners, CSP range proofs) into one
proof of R_utxo on top of `crypto/pivot`, consuming the same public parameters and public data
as the naive transfers, and benchmark it against K naive transfers in `validator_test.go`
(prover time, proof size, verifier time). Add API documentation for `sumcheck.MultiClaim`.

## Steps

1. Probe the fixtures: curve equality, mathlib/gnark conversions, credential parsing, BBS+
   pairing, EidNym opening.
2. `crypto/pivot/utxo`: params from token pp, slot layout, equation list -> collapse (eta, xi),
   instance building (credential randomisation, range bits), Prove/Verify with the deferred
   checks (aggregated pairings, A' != 0, aggregated Schnorr bound to M), proof size.
3. `testutils.TransferProver`: re-runnable production sender for naive transfers + openings.
4. Tests on real naive transfers: honest equations, round trips, one bad transfer among K
   (four ways), tampering.
5. `BenchmarkAggregatedTransfersVsNaive` in `validator/validator_test.go`.
6. Docs: MultiClaim API reference + runnable example; `docs/crypto/pivot-utxo.md`; pivot.md API.

## Implementation Progress

- [x] 1. Probe — all assumptions hold (curve 7 for both; `eid` is credential attribute 2,
  on `h_4`).
- [x] 2. utxo package — `params.go`, `layout.go`, `relation.go`, `witness.go`, `utxo.go`,
  `size.go`. `pivot.Prove` now also returns the `Outcome`; `pivot.EqTable` exported.
- [x] 3. `testutils/transfer_prover.go`.
- [x] 4. `utxo_test.go` — green; negatives fail at the intended check (forged credential at the
  aggregated pairing, bad opening/owner at the SC2 sum, flipped bit at SC3).
- [x] 5. Benchmark — K = 2, 8, 32; results recorded in `docs/crypto/pivot-utxo.md` §7.
- [x] 6. Docs — `sumcheck.md` §4.6 rewritten as an API reference, `multi_example_test.go`,
  `pivot-utxo.md` (linked from docs/README.md), `pivot.md` API.

### Follow-up: prover performance (K = 64)

- [x] Benchmark K = 64: aggregated prover was 16.1 s vs 7.0 s naive. Profile: Titan group
  commitment to H ~90%.
- [x] (a) titan: the fold path skips the unread flat codeword (`groupShape`); commitments
  unchanged, pinned by tests.
- [x] (b) pivot: per-instance public group elements move from committed columns of H to an
  uncommitted `Statement.Public` table, handled by SC1Pub and closed by the verifier's own MSM;
  SC4 gained a term; the public-column batch claims are gone. utxo keeps 9 private slots
  (c = 16/32).
- [x] Re-benchmarked: K = 64 prover 2.92 s (2.4x faster than naive), verify 77 ms, 84 KB.

## Notes & Decisions

- The pivot parameters are generated from an explicit list of the 16 group equations, not
  hand-written, so the collapse cannot drift from the equations.
- c = 32 or 64 group slots depending on the parity of log K; the field split is chosen with an
  even row half. K is any power of two >= 2.
- The aggregating prover needs every owner's sk and credential (they are witness).
- Naive verify timing includes the validator's auditor-signature check; naive prove excludes
  auditing.
- `make lint` still cannot run here (golangci-lint built with Go 1.25).

---

# Plan: pivot meta-protocol (mixed-witness aggregation)

Goal: implement the meta-protocol of the mixed-witness-aggregation write-up (`src/meta-protocol.tex`,
blueprint `mixed-witness-aggregation/design/pivot-protocol-blueprint.md`) as a Go package
`token/core/zkatdlog/nogh/v1/crypto/pivot`, proving the aggregate pivot relation over K instances
with the Titan field and group PCSes and sum-check.

Scope of this plan: the generic meta-protocol (SC1-SC4, evaluation-claim batching, one PCS opening
per oracle, public and revealed column slices). The R_utxo-specific checks that sit on top
(pairings, A' != 0, aggregated Schnorr) are out of scope and come in a follow-up.

## Steps

1. `sumcheck.MultiClaim`: sum-of-products claims over a shared pool of field polynomials
   (the Phi(h_1..h_p) wrapper), with `ProveMulti[WithTranscript]` / `VerifyMulti[WithTranscript]`.
2. `titan`: commit without fixing the evaluation point, open later (`ProveAt` on both provers).
3. `pivot` scaffolding: sizes/setup, relation (alpha, sparse B and Gamma, G, G0, affine forms,
   Phi monomials), witness, statement, eq helpers, table-order conversion, transcript encoding.
4. Prover and verifier: SC1, SC2, SC3 (MultiClaim), SC4 (MultiClaim), W and g evaluation-claim
   batching, one field and one group PCS opening.
5. Tests: honest round trip at two sizes (default and custom field split), a corrupted instance
   among K rejected (group equation and field constraint), public column mismatch rejected,
   tampered proof values rejected.
6. Docs: `docs/crypto/sumcheck.md` (MultiClaim), `docs/crypto/titan.md` (ProveAt),
   new `docs/crypto/pivot.md`.

## Implementation Progress

- [x] 1. MultiClaim — `sumcheck/multi.go`: pool of FieldPolys + terms naming them by index;
  standalone transcripts use kind byte 2. Tests: brute force, one-term == Claim, tampering,
  validation.
- [x] 2. titan ProveAt — nil `Alpha` allowed at construction, `ProveAt(alpha)` on both
  provers. Tests open one commitment at three points.
- [x] 3. pivot scaffolding — `params.go`, `math.go`, `transcript.go`, `batch.go`, `proof.go`.
- [x] 4. prover/verifier — `prover.go`, `verifier.go`; SC3's residual folded into SC4 as a
  third term.
- [x] 5. tests — `pivot_test.go`: pass, race-clean, 87.3% coverage. sumcheck and titan
  suites still pass.
- [x] 6. docs — `docs/crypto/pivot.md` (new, linked from docs/README.md), sumcheck.md §4.6,
  titan.md §13.12.

Not done: `make lint` could not run — the installed golangci-lint is built with Go 1.25 and
refuses the Go 1.26.5 module. No GitHub issue opened, nothing committed or pushed.
R_utxo-specific checks (pairings, A' != 0, aggregated Schnorr) are the follow-up.

## Notes & Decisions

- The titan facade commits in NewFieldProver/NewGroupProver together with the point; the
  meta-protocol only learns its points after the sum-checks, so step 2 is required, not optional.
- The L_k residual claims of SC3 are folded into SC4 as a third term (theta^2), instead of a
  separate log n sum-check. SC4 is then a 3-term MultiClaim.
- K must be a power of two and EVERY instance must satisfy the relation: zero padding does not,
  once G0 != 0. Padding with valid dummy instances is the caller's job.
- The group PCS needs an even number of variables, so log c + log K must be even.

---

# Plan: Titan multilinear PCS — step 5 (folding: closing the evaluation claim)

> ## ⏸️ PAUSED — resume here
>
> Step 5 is **functionally complete and committed** (`95eb7b4a` folding + coseting,
> `42b243d1` batching), and the PCS facade (5.14, `pcs.go`/`pcs_test.go`) is written and
> green on top of it. `Eval`/`EvalGroup` are sound polynomial commitment openings at ~128
> bits under the capacity bound, and the scheme is now reachable as an ordinary
> setup/statement/witness API. Suite green, race-clean, `go vet`/`gofmt` clean, coverage
> 91.0%. Mutation coverage: 16 over the fold verifiers, 10 over the facade; every survivor
> is either recorded as an equivalent mutant or closed by a named test.
>
> **Branch `sumcheck` is 9 commits ahead of `origin/sumcheck` and has NOT been pushed —
> no go-ahead was given.** The facade work is committed on top of that as a 10th.
>
> Two findings worth re-reading before touching `NewFieldSetup`, both from the facade's
> mutation sweep (§13.12):
> - Oversizing the field **domain** is invisible to every functional test — it is a pure
>   cost (`2^(m/2)`, 256x at m=16), because the surplus points are never read and the
>   domain size never enters the transcript. Only
>   `TestPCSSetupSizesTheDomainByTheFoldedHalf` catches it.
> - Validating the fold config against `numVars` rather than `rowVars` is an **equivalent
>   mutant**, not a missing test. Do not try to write one.
>
> To pick this up, in order:
>
> 1. **`make lint`** — `golangci-lint` is absent in this environment, so it has never been
>    run on steps 3–5 and **must not be claimed as passing**. Run it first; it is the most
>    likely source of surprises before a push.
> 2. **GitHub issues for steps 3, 4 and 5** — `gh` was unavailable here. Note step 3's
>    commit `cdcc053c` *precedes* its issue: open the issue, then amend `cdcc053c` with
>    `Fixes #N` **before** pushing, since amending after a push rewrites published history.
>    Every issue needs Assignee, Labels, Milestone, Project (`"Panurus"`) and an Issue Type
>    (via `gh api graphql` `updateIssueIssueType`) — see AGENTS.md.
> 3. **Push + PR**, only with the user's explicit go-ahead.
> 4. Optional leftover: benchmark the `EncodeGroupOracleAt`-vs-`EncodeGroupOracle`
>    crossover. The godoc claims the butterfly wins when most of the codeword is wanted;
>    that is reasoning, not measurement, and is flagged as such in the godoc.
>
> **Step 6 is planned at the end of this file:** make the outer split `m1` a parameter
> instead of hardcoding `m/2`, as the Rust `TitanSetupConfig` does. Default stays `m/2`
> (Rust's `m/2 - 2` is affordable only because it folds the generator oracle, which we do
> not). Watch `splitAlpha`, which hardcodes `m/2` independently of `matrixShape` and would
> fail *silently* if they diverged.
>
> **Next structural step after that:** the verifier is still linear in
> `2^(m−ℓ)` because `Reduced` is sent in plain. Batching removed the factor of `Q`, not
> the term. Recursing instead of sending it — fold again over the reduced oracle, repeat
> until small enough to send — is WHIR proper and is what makes the verifier
> polylogarithmic. Also still deferred by design: `O(n^(1/4))` (a second folding layer
> over the *generator* oracle, which is **not** what `k` controls), zero-knowledge,
> `Setup`, batched `Eval` at several points, serialization.
>
> **Two traps to re-read before touching the fold tests** (both cost real time here, and
> are written up in `docs/crypto/titan.md` §13.7):
> - A Merkle leaf is hashed **whole**, so `VerifyMerkleProof` rejects any tampered leaf
>   *before* the check under test runs. Four tests in this work passed for the wrong
>   reason this way; one went through three wrong versions. A negative test that tampers
>   with a leaf is almost certainly not testing what its name says.
> - `γ`-weighting in batched check 3 is **defence in depth**, not load-bearing; the
>   absorb-before-sample transcript ordering is what makes it sound. The unweighted-sum
>   mutation surviving is *correct*, not a missing test.
>
> Full narrative of this work: `claude-chat`, "Session 3".

Steps 1–4 are complete and committed (`ccc7e99d`, `3dd550d8`, `cdcc053c`, `f8d313bc`,
`94173bd4`). Earlier plans are preserved in git history (`git show cdcc053c:plan.md`).
**Step 4's plan is retained below for context; step 5 is at the end.**

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

---

# Step 5 — Folding: closing the group polynomial evaluation claim

## Goal

After step 4, **neither verifier was sound against a prover who lied about the
oracle**: both reduced `f̃(α) = σ` to a residual claim about a polynomial nobody had
queried. Step 5 closes that with `ℓ` rounds of WHIR folding, the reduced polynomial sent
in plain and tested as an `eq` dot product, and `Q` consistency queries against a
committed coset oracle.

## Implementation Progress

- [x] 5.1 `domain.go` `Squared()` + `domain_test.go` — pins `g_(d-1) = g_d²` and the
      element-squaring relation for `d ∈ 2..18`. This was an **unstated gnark-crypto
      dependency** that all cross-round index arithmetic rests on, and there was no
      `domain_test.go` at all before.
- [x] 5.2 `coset.go` + `coset_test.go` — `EncodeCosets`/`foldCoset`/`CommitCosets`/
      `OpenCoset`, built **per slice** rather than by regrouping the flat codeword.
      Gathered leaves are copies, not sub-slices of the codeword.
- [x] 5.3 `foldconfig.go` + tests — `FoldConfig`, `SoundnessRegime`, `QueryCount`,
      `DefaultEll`, `DefaultFoldConfig`, `Validate`.
- [x] 5.4 `queries.go` + `queries_test.go` — `sampleQueryIndices`, distinct and in
      range, rejection-sampled from the transcript.
- [x] 5.5 `groupsumcheck.go` — `ProveGroupEvalWithTranscript`/
      `VerifyGroupEvalWithTranscript`. The originals became thin wrappers, so
      **no existing call site changed** (the plan had anticipated 4).
- [x] 5.6 `fold.go` + `fold_test.go` — `proveFold`/`verifyFold`, `FoldProof`,
      `CosetOpening`, and the three verifier checks.
- [x] 5.7 `commit.go`/`coset.go`/`eval.go` wiring — `Commitment.Cosets`,
      `CosetCommitment.Fold`, `CommitGroupWithFold`/`CommitFieldWithFold`,
      `EvalProof.Fold`/`GroupEvalProof.Fold`, anti-downgrade in both directions.
- [x] 5.8 `encode.go` `EncodeGroupOracleAt` + tests — the fix for the verifier cost
      defect below; equivalence to the butterfly pinned at every index.
- [x] 5.9 `merkle.go` `VerifyBatch` + tests — closes the exported-prover-with-no-verifier
      asymmetry. Not used by the fold phase, which keeps a path per `CosetOpening` so a
      failure can name the query.
- [x] 5.10 Benchmarks — proof size vs `ℓ` on real serialized bytes; prove/verify vs `m`.
- [x] 5.11 Mutation pass — 16 mutations across the per-query and batched verifiers.
      **Two real gaps found and closed**; three equivalent mutants recorded, one of them
      initially misclassified as a third gap. See Notes.
- [x] 5.13 **Batch check 3 on both sides.** The two sides batch by structurally opposite
      mechanisms: the reduced-codeword side aggregates the `eq` *scalar* vectors with the
      point vector fixed (`Q·2^(m−ℓ)` → `2^(m−ℓ)` group ops, asymptotic), and the coset
      side concatenates the *points* with `eq(r)` shared (one long Pippenger instead of
      `Q` length-`2^ℓ` MSMs, constant factor). Same `γ^j` ladder on both sides, derived
      once. Measured: **19.9→1.60ms, 26.2→2.41ms, 38.2→3.98ms** at m/ℓ = 8/1, 10/2, 12/3
      — ~10×, and 226× against the original full-encode verifier at m=12.
- [x] 5.12 `docs/crypto/titan.md` — folding added as **§13** (References renumbered to
      §14), §8's API table and §11's coverage table updated, and the now-false claims in
      §6.5, §7.5 and §12.8 corrected rather than left standing.

Verification: suite green, race-clean (79.6s), `go vet` clean, `gofmt` clean, coverage
91.0%, whole-repo `go build ./...` clean.

- [x] 5.14 **`pcs.go` + `pcs_test.go` — the PCS facade.** `NewFieldSetup`/`NewGroupSetup`,
      `FieldStatement`/`FieldWitness` (and group equivalents), `NewFieldProver`/`Prove()`,
      `NewFieldVerifier`/`Verify() int` + `VerifyErr() error`. Pure wiring — no new
      cryptography — but it hides four decisions whose failures are silent: the two paths
      need **different domain sizes** (`rowVars+LogRate` vs `m+LogRate`), folding must be
      **on**, `alpha` has `m` coordinates and not `Commitment.NumVars`, and the generators
      must be converted **once** (`NewGenerators` is 15–18% of a prove and the bulk of a
      verify). Commitment is built in `NewFieldProver`, per the user's choice, so a prover
      always owns a commitment matching its witness.

      Two guarantees carry the weight, and they point in **opposite directions**: a prover
      from this API always commits *with* folding (`TestPCSProverAlwaysFolds`), and a
      verifier from this API *refuses* a commitment that cannot support folding
      (`TestPCSVerifierRejectsUnfoldedCommitment`). Both are wiring properties the round
      trip cannot see — an unfolded proof verifies happily against its own unfolded
      commitment — so each has a dedicated test whose godoc says what swap it catches.

      Verification: suite green, race-clean, `gofmt`/`go vet` clean, coverage **91.0%**,
      whole-repo `go build ./...` clean. A diagnostic probe printed the actual rejection
      reason for every negative, confirming each is rejected for the reason its name
      claims — the package's recurring wrong-reason-pass trap.

      **Mutation sweep: 10 mutations, 8 caught, 2 survivors — both on the
      `rowVars`/`numVars` axis, and different in kind.** Validating the fold config
      against `numVars` is an **equivalent mutant**: `DefaultEll` is `1` everywhere the
      field path admits, and both `m`-dependent constraints in `Validate` are *looser* at
      the larger parameter, so no test can distinguish them. Oversizing the **domain** was
      a **real gap** — and a *performance* defect, not a soundness one, which is why the
      round trips were blind to it: the surplus points are never read and the domain size
      is never absorbed into the transcript, so a proof built on a `2^11` domain at m=8 is
      accepted by a verifier holding the correct `2^7` one, with no error. Closed with
      `TestPCSSetupSizesTheDomainByTheFoldedHalf`, which asserts `dom.LogSize` on both
      paths (the group path too, so a unifying "fix" also fails) and was confirmed to kill
      the mutant. It also corrected a wrong claim in the `pcs.go` header and §13.12: the
      waste is `2^(m/2)` — 256x at m=16 — not "twice as large".

### Still owed on step 5

- [ ] `make lint` — `golangci-lint` is absent in this environment, so it has **not**
      been run and must not be claimed as passing.
- [ ] GitHub issues for steps 3, 4 and 5 — `gh` is unavailable here. Step 3's commit
      (`cdcc053c`) already precedes its issue; the fix is to open the issue, then amend
      `cdcc053c` with `Fixes #N` before pushing.
- [ ] **Do not push** — the branch is ahead of `origin/sumcheck` with no go-ahead given.
- [ ] Benchmark the `EncodeGroupOracleAt`-vs-`EncodeGroupOracle` crossover. The godoc
      claims the butterfly wins when most of the codeword is wanted; that is reasoning,
      not measurement, and is flagged as such.
- [ ] Commit the batching work (5.13) and the facade (5.14) — code, tests, and the
      §13.6/§13.7/§13.10 doc updates plus the new §13.12 ("The PCS facade"); what was
      §13.12 is now §13.13.

## Notes & Decisions — step 5

- **A coset is not a regrouping of the flat codeword.** `EncodeGroupOracle` gives
  `f̃(x, x², x⁴, …)` at every `x ∈ L`; a coset needs `f(b, powers(y))` with `b`
  **boolean**. The strided set `{y + b·N/2^ℓ}` is the fold's dependency closure but its
  *values* are different objects — three attempts to match scored 0/512, 1/512, 1/512.
  Hence the per-slice construction, with two tests pinning the negative, because a
  wrong-but-consistent layout verifies against itself.
- **`chunkIntoCosets`' comment was wrong, in exactly the way it warned about.** It
  claimed leaves must be contiguous and that striding "would still build a valid-looking
  tree over a reordering of the same points". Harmless only because every caller passed
  `k=0`. Replaced with the probe-verified rule.
- **`k = ℓ` makes one primitive serve two jobs.** `⟨leaf, eq(r)⟩` equals the reduced
  polynomial's codeword at that index, so a consistency query is a single dot product
  rather than `ℓ` fold rounds — and the same operation tests the final reduced claim.
- **MUT3: the single check that makes step 5 sound was untested.** Deleting check 3 (the
  coset-fold comparison) left the whole suite **green**. `TestFoldRejectsALyingProver`
  was being caught by the *Merkle* check, so its name overclaimed. Closing it needed a
  strictly harder attack — `TestFoldRejectsAForeignFoldWithGenuineOpenings` grafts
  genuine openings of the real oracle into a proof folded over `f'`, with
  `verifyFoldRoundsOnly` asserting checks 1–2 pass so only check 3 can reject. The older
  test's godoc was amended rather than deleted. Re-running the mutation confirms the fix.
- **MUT6: the verifier could check fewer queries than it sampled.** Sampling `Q-1` left
  the suite green, because `sampleQueryIndices` draws sequentially — `Q-1` is a *prefix*
  of the honest `Q`, so a truncated loop agrees on everything it looks at. The
  `len(proof.Queries) != cfg.Queries` guard does not help: it bounds what the prover
  **sends**, not what the verifier **reads**, and every other negative tampered with
  query `[0]`. Closed by `TestFoldChecksEveryQueryNotJustTheFirst`, which corrupts each
  position in turn including the last; re-running the mutation confirms it.
- **Two equivalent mutants, recorded not papered over.** (1) Encoding at `q.Index`
  instead of the sampled `idx` — the `q.Index != idx` guard above makes them provably
  equal, though `idx` is still better code for not depending on that guard. (2) Deleting
  the `CosetSize()` check — a leaf is hashed whole, so `VerifyMerkleProof` rejects a
  short leaf first (verified directly). `TestFoldRejectsAShortCoset`'s godoc states that
  it is the Merkle check doing the work, since a test whose name implies it pins a check
  it does not pin is worse than no test.
- **I introduced a soundness hole and caught it while wiring.** The first
  `VerifyEvalGroup` derived the query count as `len(proof.Fold.Queries)`, letting the
  prover pick its own security level. Fixed by moving `Fold FoldConfig` into
  `CosetCommitment`. A security parameter the prover chooses is not one.
- **The verifier was 15× slower than its own prover, and asymptotically wrong.** Found
  by benchmarking and `pprof`, not by assumption: `verifyFold` encoded the **whole**
  folded domain to check `Q` points (80% `mulGLV`, `EncodeGroupOracle` 84% cumulative).
  `EncodeGroupOracleAt` fixed it — m=8/10/12 verify went 177/402/901ms → 19.1/26.2/37.7ms
  against a prover at 11.1/65.9/297ms. The growth also changed character: it stopped
  tracking the codeword and started tracking the query work. **Correction to an earlier
  note here:** the residual growth is dominated by `Q·2^(m−ℓ)`, the `Q` full-length MSMs
  against the reduced polynomial — not by `Q·2^ℓ` plus Merkle paths, which I stated first
  and which is far the smaller term. Getting that attribution right is what identified
  the batching below.
- **Batching check 3 is two opposite optimisations, not one.** The reduced-codeword side
  has a *fixed* point vector and varying scalars, so `Q` MSMs collapse into one by summing
  the `eq` vectors — an asymptotic win, `Q·2^(m−ℓ)` → `2^(m−ℓ)`. The coset side cannot do
  that, because every query has different points; there the win is concatenating the
  points so one long Pippenger can bucket, where `Q` separate length-`2^ℓ` MSMs are far too
  short for bucketing to pay — a constant factor. Measured ~10× overall, 226× against the
  original full-encode verifier at m=12. Batching removes the factor of `Q`, **not** the
  `2^(m−ℓ)` term: `Reduced` is still sent in plain. Recursing instead of sending it is
  WHIR proper and is what would make the verifier polylog.
- **The γ weighting is defence in depth, and the transcript ordering is what is actually
  load-bearing.** Setting every γ power to 1 — an unweighted sum — survives mutation, and
  that is correct rather than a missing test. I first recorded it as a real soundness gap;
  it is not. Cancelling per-query errors have nowhere to live: cosets are hashed whole into
  the Merkle leaves, and `proof.Reduced`, though sent in plain and bound by no root, is
  absorbed **before** the query indices are drawn, so perturbing it reshuffles the very
  `eq` vectors the perturbation must be orthogonal to. Established by construction, not
  argument: a `d` orthogonal to both `eqCur` and `Σ_j eq(curve_j)` was built (3×3 cross
  product of the two constraint rows) and applying it made the verifier sample
  `[426 459 108 105]` instead of the prover's openings. `TestFoldReducedIsAbsorbedBefore`
  `QueriesAreSampled` now pins the ordering, and fails if the absorb moves after sampling —
  which is exactly when γ would stop being redundant.
- **Four tests in this work passed for the wrong reason before being fixed**, every one
  because `VerifyMerkleProof` rejects a tampered leaf before the check under test runs.
  The cancelling-error test went through three wrong versions on this exact hazard. This is
  the dominant failure mode of negative testing here, so each negative test's godoc now
  names which check does the rejecting — a test whose name implies it pins a check it does
  not pin is worse than no test.
- **`DefaultEll` validated on real bytes, not on the model it came from.** At m=12:
  ℓ=1→122184, ℓ=2→75928, **ℓ=3→58376 (min)**, ℓ=4→61368, ℓ=5→87016, ℓ=6→148760.
  `DefaultEll(12)` returns 3. The suggested starting point `ℓ = m/2 - 1` is 5 here, which
  measures 49% larger.
- **The field path needs `m ≡ 0 mod 4`, not just `m` even.** Folding attaches to leg 1,
  which runs over `rowVars = m - m/2`; that must be even, so m=4,8,12 work and m=6,10 do
  not. Surfaced as a `DefaultFoldConfig` rejection at m=6 that looked like a test bug and
  is not. Pinned by `TestFieldFoldRequiresMDivisibleByFour`.
- **Transcript threading is load-bearing, not cosmetic** — confirmed by mutation: a
  verifier using an unchained transcript fails both the round trip and the soundness
  test. The rejected alternative (a fresh transcript absorbing the sum-check's outputs)
  would depend on the absorb list being complete, and an omission is a silent failure
  every honest test passes — the same shape as the `evalTranscriptHeader` gap step 4
  found.
- **`Q = 43`, not 42.** `⌈128 / log₂ 8⌉ = 43`; 42 gives 126 bits. Capacity is
  **conjectured** and Johnson is what is **provable**; `SoundnessRegime`'s godoc says so
  at the type, since choosing `Capacity` is choosing a conjecture.
- **`randomLeaves` is deterministic despite its name**, so my first `VerifyBatch`
  foreign-root subtest rebuilt the *same* tree and passed vacuously. Caught because the
  subtest failed when it should have; now perturbs a leaf and asserts the roots differ
  via `require.NotEqual`, so it cannot silently degenerate again.

---

# Step 6 — Make the outer split (`m1`) a parameter

## Goal

The matrix split is hardcoded at `commit.go:379`:

```go
cols = 1 << (m / 2)
rows = 1 << (m - m/2)
```

The Rust reference treats it as a **tuned free parameter**, `TitanSetupConfig.m1`
(`titanpcs.rs:67`), and its shipped configs are deliberately asymmetric:

| m | m1 | m2 = m−m1 | l1 | domain_g1 | queries |
|---|----|-----------|----|-----------|---------|
| 18 | 8 | 10 | 1 | 11 | 70 |
| 20 | 8 | 12 | 1 | 11 | 70 |
| 22 | 9 | 13 | 2 | 11 | 70 |
| 24 | 10 | 14 | 2 | 12 | 70 |
| 26 | 11 | 15 | 3 | 12 | 70 |

At m=20 Rust uses `m1 = 8` where we force 10. Step 6 makes `m1` settable, keeping
`m1 = m/2` as the default.

## Why `m1 = m/2` here, and not Rust's `m/2 − 2`

Rust can afford a *smaller* `m1` because it folds the generator oracle too: `m2` is
the CSP/Bulletproof half, and `l2` folds it, so a larger `m2` stays cheap. **We do
not fold leg 2** (that is the deferred `O(n^¼)` layer), so every extra variable in
`m2` is paid in full as a linear CSP cost. `m1 = m/2` keeps leg 2 as small as the
split allows, which is the right default until `l2` exists.

This is the user's decision and the reason is recorded because it will look
arbitrary to anyone comparing against the Rust config table.

## What this also fixes

`checkShape` (`eval.go:523`) documents that **`m` is not recoverable from the
commitment**: `NumVars = log2(rows)` is consistent with both `m = 2·NumVars` and
`m = 2·NumVars − 1`, because the column count is not on the wire. Its godoc says
"Callers who need the column count on the wire should put it in the commitment; that
is a format change, noted rather than made here."

Carrying `m1` in the commitment is exactly that format change, so step 6 should make
it and let `checkShape` stop reasoning about ambiguity.

**It should also remove the `m ≡ 0 mod 4` constraint** (§13.10). That rule exists
only because `rowVars = m − m/2` must be even for the fold to attach; with `m1`
chosen directly the caller picks `m1` so that `m − m1` is even, and odd total `m`
becomes usable — which is why Rust runs m=18 and m=26 happily.

**Verified by probe before implementing**, enumerating `m1` with `m − m1` even and a
drawable default fold config:

| m | usable `m1` today (forced `m/2`) | usable `m1` with the split free |
|---|---|---|
| 7 | — (rowVars 4 ✓, blocked by drawability) | 1, 3 |
| 9 | — (rowVars 5, odd) | 1, 3, 5 |
| 11 | — (rowVars 6 ✓, blocked by drawability) | 1, 3, 5, 7 |
| 13 | — (rowVars 7, odd) | 1, 3, 5, 7, 9 |
| 18 | — (rowVars 9, odd) | 2, 4, 6, 8, 10, 12, 14 |
| 20 | 10 only | 2, 4, 6, 8, 10, 12, 14, 16 |

So odd `m` becomes usable and m=18 gains seven choices where it currently has none.
The constraint is an artifact of the hardcoded split, confirmed.

**Correction to the "m odd" column, found while writing `split_test.go`.** The rows
for m=7 and m=11 originally said they were blocked for being odd. They are not: under
the balanced split `rowVars = m − m/2` is even whenever `m mod 4 ∈ {0, 3}`, so m=7
(rowVars 4) and m=11 (rowVars 6) pass parity and are rejected by the *drawability*
floor instead. The parity rule is `m mod 4 ∈ {0, 3}`, not `m mod 4 == 0`, and the two
constraints coincide only on the sizes anyone uses. An assertion in `split_test.go`
that claimed "foldable iff `m % 4 == 0`" failed at m=3 and is what caught this.

## Steps

- [x] **Done** 6.1 `Split` type in `split.go` carrying `{M, M1}` with
      `RowVars()`/`ColVars()`/`Rows()`/`Cols()`, plus `DefaultMatrixSplit(m)` (named to
      avoid the pre-existing `DefaultSplit` for the sum-check `ell`). `matrixShape(m)`
      survives as a thin wrapper over the balanced default, so the call sites that do
      not care about the split are unchanged.

      **Two contracts, not one — this was the main design correction of the step.**
      `Validate()` is the commit-time rule (halves multiply back to `2^M`);
      `ValidateForFold()` adds the even-row-half rule the coset layout needs. The first
      draft put the fold rule in `Validate` and **broke every odd-`m` and `m = 2` test
      in the package at once**, because those sizes commit and open perfectly well
      through the non-folding stages. Committing at an odd row half is well defined;
      only folding is not.
- [x] **Done** 6.2 **`splitAlpha` (`eval.go:520`) independently hardcodes `m/2`** and must take
      the same split. **Probed before implementing, and the risk is lower than assumed:**
      `foldRows` already cross-checks `len(eqTable(alphaRow))` against `numRows`
      (`eval.go:570`) and returns `ErrNumVarsMismatch` on a divergence -- tried at
      `m1 ∈ {2,3,5}` against an alpha cut at `m/2`, all three errored with a clear
      message. So a mismatch is **caught, not silent**, contrary to what this plan first
      claimed on the strength of `splitAlpha`'s godoc warning (that warning is about
      getting the row/column halves the wrong way *round*, which is silent, not about
      differing split *sizes*, which is not).

      Still thread the split through both rather than rely on that guard: it is a
      defence at the point of use, not a structural guarantee, and leg 1 has no
      equivalent. Keep a test at an asymmetric `m1` checked against
      `FieldPoly.EvaluatePoint` -- the package's own reference evaluator, not a
      hand-rolled one (a hand-rolled evaluator folding `alpha[0]` first uses the wrong
      variable convention and silently disagrees; that cost time in probing).

      **Done as `splitAlphaAt(alpha, Split)`**, with `splitAlpha(alpha, m)` kept as the
      balanced-default wrapper. Threaded on both sides: the prover uses the split stored
      on `FieldOpeningHint`, the verifier the one the commitment states. The
      `FieldPoly.EvaluatePoint` test is
      `TestFieldPCSSplitMakesOddSizesUsable`, and mutating `splitAlphaAt` to swap the
      halves **passes verification and fails only that assertion** — confirming the
      silent-failure mode is real and that the round trip alone would not see it.
- [x] **Done** 6.3 `FieldSetup` gains a `split` field and a `Split()` accessor.
      Rather than change `NewFieldSetup`'s signature, added
      **`NewFieldSetupWithSplit(split, gens, curve, cfg)`**, with `NewFieldSetup`
      delegating at the balanced default — so every existing caller and test is
      untouched. Validation is `ValidateForFold` plus the generator count from
      `split.Cols()`.

      This moved a sentinel: at the setup boundary an odd row half is now
      `ErrInvalidMatrixSplit` (a property of the split) while drawability stays
      `ErrInvalidFoldConfig` (a property of the config).
      `TestFieldPCSRejectsUnsupportedNumVars` asserted one sentinel for both and was
      split accordingly — it passed before only because the parity rule lived inside
      the fold config, and would have kept passing if either constraint had stopped
      being enforced.
- [x] **Done** 6.4 `Commitment.ColVars` carries `M1`. **This is a format change.**
      `checkShape` now takes the split from it and checks `m` against *both* halves, so
      a prover and verifier disagreeing about where the matrix was cut is an error
      rather than two legs silently proving different polynomials.

      `ColVars == 0` means "not stated" — a group commitment, or a field commitment
      predating the field — and falls back to the balanced split, so older commitments
      verify exactly as before. `FieldOpeningHint.Split` is the prover-side counterpart,
      so the opening uses the cut the commitment was made with.

      Two `TestEvalValidation` subtests changed *behaviour* here, in the intended
      direction: with `m = 4, M1 = 2`, a 3-coordinate alpha is now caught by the shape
      check (`ErrNumVarsMismatch`) instead of surviving to fail the row leg as
      `ErrRoundCheckFailed`, and a 2-coordinate alpha is caught as
      `ErrInvalidMatrixSplit`. Both were rejected before; they are now rejected at the
      boundary for the right reason. The ambiguity the old `checkShape` godoc documented
      is gone.
- [ ] 6.5 **Still open.** Revisit `DefaultEll`/`DefaultFoldConfig`: both are computed
      against `RowVars` and take no account of how the split was chosen, and the
      drawability floor (§13.10) moves with the cut. Nothing is *wrong* today — a
      smaller `M1` gives a larger row half and therefore more cosets, so moving the cut
      can only relax the floor, never tighten it past what `FoldConfig.Validate` already
      checks. So this is a tuning gap, not a soundness gap, which is why it is left
      rather than rushed.
- [x] **Done** 6.6 `split_test.go` (new): the shape invariant `Rows*Cols = 2^M` over
      every valid split to `M = 20`; the `Validate`/`ValidateForFold` separation
      including the odd-row-half splits that must stay committable; degenerate splits
      and the legacy `M=1, M1=0` shape; `DefaultMatrixSplit` pinned against
      `matrixShape` as the compatibility regression; and the balanced cut's foldability
      rule.

      `pcs_test.go` gains `TestFieldPCSSplitMakesOddSizesUsable`, covering
      `m ∈ {10, 14, 18}` at asymmetric `M1` — each first asserted to be **unusable**
      under `NewFieldSetup`, so the test cannot pass vacuously — with `sigma` checked
      against `FieldPoly.EvaluatePoint`, and `ColVars`/`NumVars` checked on the wire.

      **Six mutations, all caught**: swap the halves in `splitAlphaAt`; prover
      re-derives the split instead of using the committed one; verifier divides alpha at
      the balanced cut; `checkShape` ignores `ColVars`; commitment omits `ColVars`;
      facade drops the setup split when committing.
- [ ] 6.7 **Still open.** Benchmark the `m1` sweep at fixed `m`, to see whether `m/2`
      is actually the optimum for *our* cost model (no `l2`). If it is not, say so
      rather than keeping the default on faith. The machinery to do this now exists —
      `NewFieldSetupWithSplit` at several `M1` for one `m` is the whole experiment — so
      this is measurement, not implementation.
- [x] **Done** 6.8 Docs: §13.10 rewritten with the `m mod 4 ∈ {0,3}` table and the
      correction above; §8.1 shows `CommitFieldWithFoldAt`; new **§13.13 "The outer
      matrix split as a parameter"** (the cost trade-off table, the two contracts, the
      wire format, why a round trip is a weak test here, the six mutations, and what is
      still open); §13.14 renumbered from 13.13 with cross-references fixed; §13.11 and
      §13.12 API blocks updated; the test table gains a `split_test.go` row; coverage
      restated at 90.8%. `checkShape`'s godoc keeps the old ambiguity paragraph as
      history and adds what the wire field now closes.

## Notes & Decisions — step 6

- **Query count differs from Rust and is not reconciled here.** Rust uses 70 queries
  where `QueryCount(128, 3, Capacity)` gives 43. That is a soundness-target or regime
  difference, not a consequence of `m1`, and it deserves its own investigation rather
  than being quietly aligned.
- `domain_g1_size` is a Rust config field we derive instead (`rowVars + LogRate`).
  Leaving it derived is correct — §13.12's mutation finding showed an oversized domain
  is invisible to every functional test, so it should not be hand-settable.
- **The default is unchanged and that is a compatibility guarantee, not just a
  convenience.** Every commitment made before this step used `m/2`, so changing the
  default would silently stop such commitments from verifying.
  `TestDefaultMatrixSplitIsTheBalancedCut` pins it, and also pins
  `DefaultMatrixSplit` against `matrixShape` so the two cannot drift.
- **Verification after 6.1–6.4, 6.6, 6.8:** suite green (13.7s), race-clean (84.7s),
  `gofmt` clean, `go vet` clean, whole-repo `go build ./...` clean, coverage **90.8%**
  (from 91.0% — the new error paths in `Split.Validate` and `commitFieldAt` add
  branches the negatives do not all exercise). `make lint` still cannot run here
  (`golangci-lint` absent) and must not be claimed as passing.

---

# Step 7 — Document the PCS interface and the crypto as implemented

## Goal

The PCS is functional end to end. Two documents were missing, and both were asked for:
a reference for the **public interface** (what a caller touches, in what order) and a
concise **mathematical description of the construction as implemented** — as opposed to
as specified in the paper, which is not the same thing.

`docs/crypto/titan.md` already existed but is a 1400-line design record: it explains
why the code is shaped the way it is, what the mutation passes found, and which defects
no functional test can see. It is the wrong document to hand someone who just wants to
call the package, and the wrong one to hand someone who wants the mathematics.

## Implementation Progress

- [x] **Done** — 7.1 `docs/crypto/titan-pcs-api.md`, the interface reference.
      Covers: the field/group parallel structure and why the field scheme is built on
      the group one; `NewFieldSetup` vs `NewFieldSetupWithSplit`; statement/witness
      shapes and the `Alpha` length trap (`setup.NumVars()`, **not**
      `Commitment.NumVars`); why `NewFieldProver` commits so `Commitment()` is
      available before `Prove()`; `Verify` (int) vs `VerifyErr` (sentinel) and when to
      use which; the `Commitment` fields with `NumVars != m` and `ColVars == 0` meaning
      "not stated" called out explicitly; the `Split` cost trade-off table; the
      `Validate`/`ValidateForFold` two-contract distinction *with the incident that
      caused it*; the three independent size constraints; `FoldConfig`, the `Capacity`
      ⇒ conjectured / `Johnson` ⇒ provable distinction, and why `DefaultEll` sits below
      the paper's `m/2 − 1`; the sentinel error table with `ErrCosetOpeningInvalid`
      flagged as the one that catches a lying prover; and a closing section on what the
      interface deliberately does not offer.

- [x] **Done** — 7.2 `docs/crypto/titan-crypto.tex`, the construction in mathematics.
      Self-contained (standard classes, no dependency on the paper's private macros,
      since the repo has no LaTeX infrastructure and this must build anywhere).
      Four pages. Covers the two-tier commitment (Pedersen rows → group multilinear
      `G` → power-curve codeword → coset oracle), why there are **two** Merkle roots,
      the two evaluation legs, the ℓ folding rounds with `Reduced` sent in plain, the
      three verifier checks with **check 3 identified as the binding one**, and
      `Q = ⌈λ/log₂(1/ρ)⌉ = 43`. Cites the paper's real section labels.

- [x] **Done** — 7.3 Cross-linking. Both files linked from `docs/README.md` under
      Cryptographic Primitives. `docs/crypto/titan.md` gained a "Companion documents"
      header block positioning the three documents against each other, and its
      **stale `Status` line was corrected** — it still claimed "step 1 (oracle
      encoding) complete" five steps later.

- [x] **Done** — 7.4 Verified rather than asserted. Details under Notes.

## Notes & Decisions — step 7

- **The `m_1` notation collision is real and is flagged in the `.tex`.** The paper's
  `m_1 := |\calK_1|` (§titan-commit) is a **Merkle leaf count**; our `Split.M1` is the
  number of **column** variables, which the paper calls `ℓ_q`. Anyone reading the two
  side by side will otherwise conflate them. The paper's leaf count is our
  `Commitment.NumLeaves`.
- **Every numeric claim in both documents was checked against the code**, not
  reproduced from memory: `Q=43`, Johnson's 86, `DefaultEll(12)=3`, 42 queries giving
  <128 bits, `DefaultSecurityBits=128`, `DefaultLogRate=3`, the `m mod 4 ∈ {0,3}`
  parity table over m=1..24, `NumCosets`/`CosetSize` formulas, and the two worked
  splits (`m=10, M1=4` → rowVars 6; `m=18, M1=8`). Done with a throwaway test, run
  green, then deleted — it duplicated coverage that `foldconfig_test.go` and
  `split_test.go` already own, so committing it would have been redundant.
- **The worked example in the markdown was compiled and run**, not written by eye. It
  passes end to end and its `require` lines confirmed the documented
  `com.ColVars == m/2` and `com.NumVars == m - m/2` semantics. Also deleted after
  running, for the same reason.
- **The `.tex` compiles**: `pdflatex` clean, 4 pages, no warnings and no undefined
  references. A LaTeX file that has never been built is not a document.
- **Documents were kept separate rather than merged into `titan.md`.** Three audiences
  — caller, cryptographer, maintainer — with genuinely different needs. Merging would
  have produced one file nobody reads to the end.
- `make lint` still cannot run here (`golangci-lint` absent) and must not be claimed as
  passing. These changes are docs-only plus no code, so `gofmt`/`go vet`/suite state is
  unchanged from step 6.

---

# Step 8 — Remove the uncommitted flat-codeword root

## Goal

Raised by the user while reviewing the new interface doc: *"Do we ever need
`Commitment.Root`, shouldn't we always use `Commitment.Coset`?"*

Investigation confirmed the stronger form of that suspicion. `verifyFold` takes a
`*CosetCommitment`, so its `c.Root` is `Cosets.Root`, and both `eval.go` call sites
pass `c.Cosets`. Across the whole non-test package `Commitment.Root` was **set once
(`commit.go:175`) and read never**; the only readers were tests asserting the field
against itself.

## Implementation Progress

- [x] **Done** — 8.1 `commit.go`: `commitGroup` no longer calls `BuildTree`.
      `Commitment.Root` is left nil with a godoc marking it **reserved for possible
      future use** and recording why nil beats both "populated" and "deleted".
- [x] **Done** — 8.2 Removed `GroupOpeningHint.Tree` and the exported
      `(*GroupOpeningHint).OpenLeaf` — the prover-side counterpart to the same unread
      root. `BuildTree`/`Tree` remain, used by the coset oracle in `coset.go`.
- [x] **Done** — 8.3 Corrected three now-false godocs: `commitGroup`'s summary said
      "Merkle-commits them"; its body claimed the stage produces a bindable-after-fold
      commitment; and `CommitGroupWithFold`'s "the two roots are kept separate"
      paragraph described a design that no longer exists.
- [x] **Done** — 8.4 Tests. Deleted `TestOpenLeafValidation` and the per-leaf
      open-against-root loop; replaced the root-length assertion with
      `assert.Nil(c.Root, ...)`. Re-pointed the three proxy tests (determinism,
      distinct polys, distinct generators) at `hint.G` and renamed the two whose names
      said "Roots".
- [x] **Done** — 8.5 Docs: new §7.6 in `titan.md`, a `remark` in `titan-crypto.tex`
      (§2, cross-referenced from the check-3 list), the `Commitment` section of
      `titan-pcs-api.md`, §7.2's tier-2 note, §8's "no unfolded variant" paragraph, and
      the `commit_test.go` row of the test table.

## Notes & Decisions — step 8

- **The performance saving is small and I am not going to dress it up.** Measured at
  `m = 12` with a throwaway benchmark, before vs after: 134.2ms → 133.2ms (~0.7%),
  4,317,677 → 4,252,486 B/op, 46,776 → 45,727 allocs/op. The flat tree is 512 leaves
  where the commit is dominated by 64 row MSMs and the FFT. **The reason to remove it
  is the footgun, not the microseconds.**
- **The footgun is the real finding.** An exported `[]byte` named `Root` that no
  verifier reads invites a future batching or serialization layer to
  `VerifyMerkleProof` against it — a check that passes while binding nothing. Same
  shape as the `chunkIntoCosets` comment that was wrong in the way it warned about.
- **Nil, not deleted — the user's call, and it is the right one.** Deleting frees the
  name for a future field with different semantics, which is the worse failure mode for
  anything that deserialized an old commitment. Nil keeps the name claimed and makes
  misuse fail at once.
- **The three proxy tests were re-pointed, not deleted.** Determinism and
  collision-sensitivity are real properties; only the *instrument* was wrong.
  Asserting on `hint.G` is strictly stronger than on a digest.
- **Verified rather than assumed:** a throwaway test drove both the field and group
  facades end to end and confirmed `Root == nil` while `Cosets.Root != nil` and both
  `VerifyErr`s pass — so the removal is real and not merely untested. Deleted after
  running. Suite green, `-race` clean (88.2s), `gofmt`/`go vet` clean, whole-repo
  `go build ./...` clean, coverage **90.8%** (unchanged). `.tex` rebuilds clean, 5
  pages, no undefined references.
- **Not checked against the deferred features, by the user's judgement** (*"I don't
  think any extension will use it"*). If WHIR-proper recursion or the `O(n^¼)`
  generator-oracle layer ever needs the flat codeword committed, the field name is
  still reserved and `commitGroup` is a two-line change.
- `make lint` still cannot run here (`golangci-lint` absent) and must not be claimed as
  passing.
