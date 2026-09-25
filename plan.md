# Plan: `sumcheck` package (field and group sum-check over BLS12-381 G1)

## Goal

Add `token/core/zkatdlog/nogh/v1/crypto/sumcheck` implementing an interactive
(Fiat-Shamir compiled) sum-check protocol for claims of the form

    H = sum over x in {0,1}^mu of p(x),   p(X) = f_1(X) * ... * f_k(X) * g_1(X)

where `f_i` are multilinear polynomials over the scalar field F_r, and `g_1` is
an **optional** multilinear polynomial whose evaluations are points in G1. At
most one group factor is allowed, since a product of two group elements is not
defined in this setting. `k >= 0`.

Round polynomial degree is `k+1` when a group factor is present and `k` when it
is absent, so each round sends `deg+1` evaluations and the verifier interpolates.

Challenges are always drawn from F_r, including in the group case.

## Design decisions (fixed)

1. **Transcript**: reuse `csp.Transcript` from
   `token/core/zkatdlog/nogh/v1/crypto/rp/csp`, with its own domain separator
   `"SumCheck-v1"` via `InitHasherWithDomain`. Never reset mid-protocol, so each
   challenge binds all prior data.
2. **Final evaluation claim**: `Verify` returns the challenge vector `r` together
   with the claimed per-factor evaluations and lets the caller discharge them
   (via a PCS, an oracle, or direct evaluation). Keeps the package
   commitment-scheme agnostic.
3. **Field arithmetic**: convert `*mathlib.Zr` to `fr.Element` **once** at the
   API edge, run every round in `fr.Element`, convert back only for the proof
   round polynomials, transcript absorption, and returned claims.
4. **Group arithmetic**: accumulate in `bls12381.G1Jac`, normalize to affine only
   where needed, keep `*mathlib.G1` at the API edge.
5. **Errors**: sentinel `var` errors with stdlib `errors.New` (matching
   `rp/csp/errors.go`); all *construction* and wrapping via
   `github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors`. Never
   `fmt.Errorf`.

## Measurements that shaped the design

All on Apple M4 Max, BLS12-381, n = 4096 evaluations, full fold (log n rounds).

### Field side — confirms the instruction to avoid bulk `mathlib.Zr`

| pattern                                   | mathlib `Zr` | gnark `fr` (incl. conversion) |
|-------------------------------------------|--------------|-------------------------------|
| single pass: sum of `x_i * y_i`           | 249 us       | 305 us  (**slower**)          |
| sum-check shaped: log n folds, same data  | 383 us       | 182 us  (**2.1x faster**)     |

Conclusion: the win comes from converting **once at the edge** and staying in
`fr` across all rounds. Converting per call is a loss. `fr.Element <-> Zr`
round-trips losslessly through 32 bytes (verified over 2000 random values for
round-trip identity and for mul/add/sub agreement).

Incidental: on the BLS12-381 path `mathlib.Zr` already stores an `fr.Element`
internally, so the avoided cost is per-op heap allocation (`&Zr{}` per
`Plus`/`Mul`/`Minus`) and wrapper indirection, not `big.Int` reduction.

### Group side — corrects two assumptions I had carried into the design

| measurement (n = 4096)                            | time    |
|---------------------------------------------------|---------|
| `mathlib.G1` fold (Copy/Sub/Mul/Add per element)  | 227 ms  |
| gnark `G1Jac` fold, `big.Int` per element         | 300 ms  |
| gnark `G1Jac` fold, `big.Int` **hoisted per round** | 190 ms  |
| mixed affine/Jac fold with `AddMixed`             | 198 ms  |
| **isolated: n-1 scalar multiplications**          | **161 ms** |
| **isolated: n-1 Jacobian additions**              | **1.2 ms** |
| `mathlib.G1` -> `G1Affine` conversion-in alone    | 108 ms  |

Three corrections to the earlier plan:

- **`mathlib.G1` does NOT expose the raw gnark point.** `mathlib.G1` wraps
  `driver.G1` in an **unexported** field `g1` (`math.go:415`). The embedded
  exported `G1Affine` is on the *driver* type one level down, which is not what
  callers hold. The only boundary is `Bytes()`/`Compressed()` ->
  `SetBytes`, and `SetBytes` runs a subgroup membership check, costing 108 ms for
  n = 4096 — roughly half the cost of the entire mathlib fold. So converting the
  group side in is **not** free and does not pay for itself on its own.
- **Hoisting matters more than representation.** Naive Jacobian folding is
  *slower* than mathlib (300 ms vs 227 ms) because of a per-element
  `fr.Element -> big.Int` conversion. Hoisting that conversion to once per round
  is what makes Jacobian win (190 ms), and even then only by ~1.2x.
- **85% of the fold is scalar multiplication** (161 ms of 190 ms); additions are
  137x cheaper. So the group design must be driven by *eliminating scalar
  multiplications*, not by representation tuning.

### Resulting group strategy

Fold as `g'(i) = g(i) + r * (g(i+half) - g(i))`, but note the per-round
challenge `r` is a **single** scalar shared by every element in the round. So:

- Convert `r` to `big.Int` **once per round**, never per element.
- Prefer accumulating differences and using one batched `MultiExp` per round over
  n/2 independent `ScalarMultiplication` calls, since `MultiExp` amortizes the
  window precomputation across the whole round. Additions being near-free means
  the Jac/affine mix should be chosen to minimize *inversions*, using
  `BatchJacobianToAffineG1` when a batch normalization is needed.
- Accept `*mathlib.G1` at the edge but document that a caller in a hot loop
  should hand over already-converted points, because the 108 ms conversion is
  otherwise the single largest line item.

## Implementation steps

1. `errors.go` — sentinel errors (nil curve, nil polynomial, length not a power
   of two, mismatched variable counts, more than one group polynomial, round
   polynomial degree mismatch, final check failure).
2. `poly.go` — field and group multilinear types; conversion helpers
   (`Zr <-> fr.Element`, `mathlib.G1 <-> G1Affine`) with the "convert once"
   contract documented; in-place `fold` for both; `Sum`, `Evaluate`.
3. `prover.go` — `Prove`: per round, compute the `deg+1` evaluations of the round
   polynomial, absorb, squeeze the challenge, fold every factor in place.
4. `verifier.go` — `Verify`: recompute each round's consistency check by
   interpolating the received evaluations, re-derive challenges from the same
   transcript, return `(r, fEvals, gEval)`.
5. `sumcheck_test.go` — table-driven: k = 0,1,2,3 field factors, with and without
   a group factor, mu = 1..10; completeness, and a cross-check that the group
   variant agrees with the field variant scaled into G1.
6. `sumcheck_soundness_test.go` — negatives: tampered round polynomial, wrong
   claimed sum, swapped challenge, extra/missing round, two group polynomials.
7. `fuzz_test.go` — `FuzzProofUnmarshal` over the serialized proof if a wire
   format is added; register in `.github/workflows/nightly-fuzz.yml`.
8. Docs: add `docs/cryptography/sumcheck.md` and link it from the nearest index.

## Implementation Progress

- [x] Done — 1. `errors.go` — 14 sentinels via stdlib `errors.New`, matching the
  convention in `rp/csp/errors.go`; construction and wrapping use the fsc errors
  package as AGENTS.md requires.
- [x] Done — 2. `poly.go` — `FieldPoly`/`GroupPoly` plus the conversion boundary
  (`NewFieldPoly`, `NewGroupPoly`, `toZr`, `fromZr`, `toG1`) and the fold. The group
  fold builds all differences first and scales them with a single `scaleByOne`, which
  hoists the `fr.Element -> big.Int` conversion out of the per-element loop. That one
  change took the fold from 300 ms to 190 ms and is what makes the raw-type path beat
  `mathlib` at all.
- [x] Done — 3. `prover.go` — `Prove`, `ProveWithTranscript`, shared `proveWith`.
  Round evaluations step `t` by slope addition (no multiplication); the group path
  gathers scalars and points per evaluation point and applies one MSM. `Opening`
  restated with an explicit `Product` field after the prover/verifier asymmetry
  surfaced (see Notes).
- [x] Done — 4. `verifier.go` — `Shape`, `Verify`, `VerifyWithTranscript`. Per round:
  length check, decode and absorb, `q(0)+q(1) == expected`, squeeze, interpolate.
  Cost is independent of hypercube size.
- [x] Done — 5. completeness tests — 27 `TestProveVerify*` subtests across
  `k ∈ {0..3}` × `mu ∈ {1,2,3,6,8,10}`, brute-force sum cross-check,
  input-immutability assertions, and `TestGroupMatchesFieldScaled` cross-checking the
  group protocol against the field one through the discrete logs.
- [x] Done — 6. soundness/negative tests — 38 subtests, including the compensating
  tamper that preserves `q(0)+q(1)` and must still fail via interpolation. Verified
  non-vacuous by mutation testing: reversing the fold's subtraction order and dropping
  the group `AddMixed` each produce a failure. Coverage 87.0%.
- [x] Done — 7. fuzz targets + nightly-fuzz.yml entries — `FuzzVerify` (attacker
  controlled proof bytes) and `FuzzNewFieldPoly` (arbitrary evaluation tables).
  30 s local runs: 3.66M and 2.93M execs, no crashes. Registered as
  `zkatdlog-sumcheck-verify` and `zkatdlog-sumcheck-field-poly`.
- [x] Done — 8. `docs/` page — `docs/crypto/sumcheck.md`, linked from `docs/README.md`
  under a new "Cryptographic Primitives" heading. Leads with the reduce-not-close
  caveat, and carries both measurement tables.

## Notes & Decisions

- **No new dependencies.** Investigated both candidates and rejected them:
  - gnark-crypto v0.20.1 has **no hash-based multilinear PCS**. FRI is its only
    hash-based scheme and it is univariate (`Open(p, position uint64)` opens at
    an index, not at a point in F^mu). `ecc/bls12-381/fr/polynomial.MultiLin` is
    arithmetic only, no commitment. No Ligero/Brakedown/Basefold/WHIR/Hyrax.
  - gnark v0.16.3 has two sum-check implementations, both unusable:
    `std/recursion/sumcheck` is an in-circuit **verifier** only (its own doc.go:
    "We do not yet expose prover"), with the prover path on `*big.Int`;
    `internal/gkr/bls12-381` is the right shape but under `internal/`, so it
    cannot be imported — confirmed with a real build error, not inferred:
    `use of internal package ... not allowed`. It is also generated code, fully
    unexported, GKR-specialized, and single-threaded by its own admission.
  - Adding gnark would pull ~7 transitive deps into a production token SDK for
    zero reuse.
- Reusable from gnark-crypto: `polynomial.MultiLin` (`Fold`, `Sum`, `Evaluate`,
  `Eq`, `EvalEq`, `NumVars`), `Polynomial.InterpolateOnRange`, `Pool`, plus
  `bls12381.G1Affine/G1Jac/MultiExp`.
- Borrowed conceptually from gnark's internal transcript: never reset the hash
  between rounds. `csp.Transcript` already has this property.
- MSM size dispatch: follow the benchmarked crossovers already documented in
  `rp/csp/msm.go` — plain `Mul` ~2.5x faster than `MultiScalarMul` at n=1,
  `Mul2` ~25% faster at n=2, `MultiScalarMul` wins from n>=3.
- **`Evaluate` split into `EvaluateOpening` and `EvaluatePoint`** (user request).
  Two orderings are in play: *table order* (`b_0` first, the layout documented on
  `FieldPoly`) and *folding order* (`b_{mu-1}` first, the order rounds consume
  challenges and the order `Opening.R` is already in). A single `Evaluate` had to pick
  one silently — it took folding order — so a caller holding a table-order point got a
  wrong value with no error. Now `EvaluateOpening` takes folding order and passes `R`
  straight through; `EvaluatePoint` takes table order and reverses internally via
  `reverseScalars` (which copies, so a caller's slice is never disturbed). The method
  name states the convention at the call site.
- **The fold comments were wrong; the arithmetic was right.** The user flagged that
  `fold` was documented as substituting the *first* variable, which would require an
  even/odd (`2i`, `2i+1`) pairing rather than the halves pairing (`i`, `i+half`) the
  code uses. Resolved empirically in both directions: a probe showed `p = b_0` folds to
  `[0, 1]` (untouched) and `p = b_1` to `[5, 5]` (constant at `r`), so `fold`
  substitutes the **last** variable — correct for the little-endian table, where
  `b_{mu-1}` is the high bit. Substituting the even/odd pairing as a mutation made the
  suite fail with `round consistency check failed`. So the docs were corrected, not the
  code. `TestFoldSubstitutesLastVariable` now pins the convention, because prover and
  verifier fold identically and a convention error cancels between them — no
  round-trip test can catch it.
- Target path note: the request said `nogh/crypto`, which does not exist. The
  crypto packages live under `nogh/v1/crypto` (siblings `common`, `math`, `rp`,
  `upgrade`), so the package goes there. Confirmed by the user as intended.

## Status

✅ COMPLETE — all 8 steps done. Package builds, `go vet` and `gofmt` clean, full
suite passing (27 completeness + 38 soundness/validation subtests, 87.0% statement
coverage), both fuzz targets exercised locally and registered in CI, docs published
and linked.

Verification commands:

```bash
go test ./token/core/zkatdlog/nogh/v1/crypto/sumcheck/ -cover
go test ./token/core/zkatdlog/nogh/v1/crypto/sumcheck/ -run='^$' -fuzz='^FuzzVerify$' -fuzztime=30s
go test ./token/core/zkatdlog/nogh/v1/crypto/sumcheck/ -run='^$' -fuzz='^FuzzNewFieldPoly$' -fuzztime=30s
```

Post-completion revisions (see Notes & Decisions): the `fold` doc comments were
corrected to say *last* variable, and `Evaluate` was split into `EvaluateOpening` /
`EvaluatePoint`. Re-verified after both: `gofmt` and `go vet` clean,
`go test -race -cover` passing at 86.9% of statements.

Not committed: no git operations performed, per the "never push without explicit
go-ahead" rule in AGENTS.md.
