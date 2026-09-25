# Plan: Titan multilinear PCS — steps 1 and 2

## Goal

Port the Titan polynomial commitment scheme (Kamath, Prakash, Samanta, Sekar,
Singh — *Titan: Efficient Polynomial Commitments from IOPs over Groups*) from the
Rust reference at `~/IdeaProjects/titan-implementation` to Go over BLS12-381 G1.

Titan commits a field multilinear in two tiers: Pedersen-commit the rows of the
`q × q` matrix form of `f̃`, interpolate the resulting `q` group elements into a
group multilinear `G̃`, then commit `G̃` with a WHIR-style IOPP over groups. The
reason for choosing it here is that **a group polynomial commitment falls out as a
by-product** — the inner oracle `⟦G⟧` *is* a commitment to a group multilinear, so
one scheme serves both the field and group cases zkatdlog needs.

Design reference: `~/IdeaProjects/titan/eprint_version` (most detailed version).
Rust reference: `~/IdeaProjects/titan-implementation` (Pasta curves, ~6.4k lines).

**This plan covers steps 1 and 2 only**, per the user's instruction to plan before
coding. Later steps (Merkle coset oracle, WHIR folding, CSP eval, full PCS) get
their own plan once these land.

## Scope decisions (fixed by the user)

1. **The existing `crypto/sumcheck` package stays as it is.** Efficient group
   sum-check is *not* a replacement for it. It applies only to the specialised form
   `Σ_x eq(α,x)·f̃(x) = σ` corresponding to an *evaluation claim*, and is only
   worthwhile when `f̃` is a **group** polynomial. It is an additional primitive
   used inside the Titan PCS eval path, not a general-purpose sum-check.
2. **New sibling package**, not an extension of `crypto/sumcheck`.
3. **Target the simplified `O(√n)` variant first.** The `O(⁴√n)` optimisations
   (coset-wise Merkle leaves, early CSP termination with folded generators) layer
   on afterwards.
4. **Merkle tree: adapt gnark-crypto's `accumulator/merkletree`.** The arkworks
   tree the Rust uses is heavily templatised and supports path compression; the
   first cut does **not** need path compression.
5. Commit on the existing `sumcheck` branch.

## Target location

    token/core/zkatdlog/nogh/v1/crypto/titan

Sibling of `sumcheck`, `rp`, `math`, `common`, `upgrade` under `nogh/v1/crypto`,
matching where the existing crypto packages live.

## Curve portability — checked, not assumed

| Property | Pasta (Pallas `Fq`) | BLS12-381 `Fr` | Consequence |
|---|---|---|---|
| Two-adicity | 32 | **32** | smooth domain `L ⊆ F` ports directly; `2^32` max in both |
| Scalar field bits | ~255 | ~255 | same |
| Base field bits | ~255 | **~381** | G1 elements are larger; MSM slower per element |
| Pairing | none | yes (unused) | we pay G1 size for a feature Titan does not need |

The two-adicity match is the load-bearing fact: WHIR folding needs a smooth
multiplicative subgroup `L` of size `2^d`, and BLS12-381 `Fr` supports exactly the
same `d ≤ 32` as Pallas. So no domain-construction redesign is needed. Verified by
factoring `r - 1` for both fields rather than trusting the curve documentation.

## Indexing convention — the same as ours

The Rust indexes multilinear coefficients as
`coeffs[b_1 + 2·b_2 + … + 2^{m-1}·b_m]` (`utils.rs:311`), i.e. variable 1 at the
LSB. **This is the same little-endian convention as our Go `FieldPoly`**, so
`GroupPoly`/`FieldPoly` tables port index-for-index with no relabelling.

One wrinkle to carry carefully: the Rust has **two** folds —

| Rust | pairing | substitutes |
|---|---|---|
| `MultilinearPoly::fold` (`multilinear.rs:49`) | `i`, `i + n/2` | **last** variable |
| `MultilinearPoly::fold_first` (`multilinear.rs:69`) | `2i`, `2i+1` | **first** variable |

and `group_sumcheck.rs` uses **`fold_first`** in its tail rounds. Our Go
`fold` is the *last*-variable one (pinned by `TestFoldSubstitutesLastVariable`).
So the port needs an explicit first-variable fold; it must be a **new function**,
not a change to the existing one. See step 2.

Separately, `multilinear_fft` bit-reverses before the butterfly precisely to
reconcile the two (`utils.rs:340-343`). That reconciliation has to be ported
verbatim or the encoding is silently wrong — see step 1.

## Step 1 — Group oracle encoding (`encode.go`)

Ports §"Encoding Group Oracle" of the eprint and `multilinear_fft` from
`utils.rs:326`. The paper says this "ports nearly as is", and it does.

**What it computes.** Given a group multilinear `G̃ ∈ G[X_1..X_m]` in evaluation
basis (our `GroupPoly`) and a smooth domain `L ⊆ F` with `|L| = 2^d`, `d ≥ m`,
produce the Reed-Solomon codeword `{Ĝ(x) : x ∈ L}` where

    Ĝ(X) = G̃(X, X^2, X^4, …, X^(2^(m-1)))

**How, and why it is cheap.** Never form `Ĝ` explicitly. Use the recursion

    G̃(x, x², …) = (1-x)·G̃(0, x², …) + x·G̃(1, x², …)

as a butterfly over `L`, consuming the hypercube evaluations `G_1..G_n` directly at
the final layer. Costs `(n/2)·log n` scalar multiplications against `≈ n·log n` to
build `Ĝ` explicitly.

**Sub-items:**

1. `Domain` type: a smooth multiplicative subgroup of `Fr` of size `2^d`, built
   from a generator of the `2^32`-torsion. Reject `d > 32` with a named error, and
   reject `d < m`.
2. `reverseBits` / `bitReversePermutation` — port of `utils.rs:296-322`.
3. `EncodeGroupOracle(p GroupPoly, dom *Domain) ([]bls12381.G1Affine, error)` —
   the butterfly of `utils.rs:326`, including the **bit-reversal before** the
   butterfly and the `d > m` blow-up (each coefficient repeated `2^(d-m)` times).
4. A field-side `EncodeFieldOracle` for the generator polynomial `g̃` (commit step
   4 of the paper gives the verifier `⟦g⟧`; generators are public).

**How it gets verified — this is the part that matters.** The butterfly is exactly
the kind of code that passes a round-trip test while computing the wrong thing, so:
- **Direct cross-check**: for small `m` (1..8), compute `Ĝ(x)` for every `x ∈ L` by
  naive evaluation of `G̃(x, x², …, x^(2^(m-1)))` using our existing
  `GroupPoly.EvaluatePoint`, and require equality with the butterfly output. This
  is an independent implementation, not a re-derivation.
- **Degree check**: the output must be a codeword of `RS[G, L, m]`. With `d > m`,
  inverse-FFT the result and assert coefficients above `2^m` are zero.
- **Bit-reversal mutation**: deleting the `bitReversePermutation` call must make
  the cross-check fail. If it does not, the test is not exercising the ordering and
  the convention is unpinned.

## Step 2 — Efficient group sum-check (`groupsumcheck.go`)

Ports §"Efficient Group Sumcheck" + §"Computing round messages in group sumcheck"
and `group_sumcheck.rs`. **Additive to `crypto/sumcheck`, which is untouched.**

**The claim form.** Only this shape, and only for a group `f̃`:

    Σ_{x ∈ {0,1}^m} eq(α, x) · f̃(x) = σ,   f̃ ∈ G, σ ∈ G

This is an *evaluation* claim: `σ = f̃(α)`. The specialisation is what buys the
speedup — the general `crypto/sumcheck` cannot exploit it.

**Why it is faster.** Naive group sum-check costs `O(n)` group exponentiations.
This variant costs `√n` MSMs of size `√n` plus `O(√n)` group-exp — the paper notes
an optimised Pippenger MSM is 20–50× faster than the equivalent exponentiations,
and our own measurement on the existing package agrees that scalar multiplication
is ~85% of a group fold.

**Mechanism.** With `ℓ = m/2`, precompute partial-sum tables

    S_i(b) = Σ_{x ∈ {0,1}^(m-i)} h̃(b, x),   h̃(x) = eq(α,x)·f̃(x)

- `S_ℓ` costs `2^ℓ` MSMs of size `2^ℓ`. Requires a **transpose** of both the `eq`
  and `f` tables so each slice is contiguous (`compute_Sl_poly`, `group_sumcheck.rs:37-52`).
- `S_(i-1)(b) = S_i(b,0) + S_i(b,1)` — each lower table is `2^i` group *additions*,
  which our measurements put at ~137× cheaper than scalar mults.
- Round messages for `i ≤ ℓ` come from an MSM of size `O(2^i)` over `S_i`:

      g_i(u) = Σ_{b ∈ {0,1}^i} [ eq(z,b)·eq(z,α_i) / eq(α_i,b) ] · S_i(b)

  The Rust further isolates the `u`-dependent part into two MSMs `H0`, `H1` of size
  `2^(i-1)` plus scalar factors (`compute_gi_values`), so the three evaluations
  `u ∈ {0,1,2}` share the MSM work. Port that optimisation; it is not in the paper
  text but is a clear win.
- For `i > ℓ` the polynomial is down to `O(√n)` and rounds are computed the
  folklore way — **this is where the tail uses a first-variable fold**, per the
  convention note above.

**Round degree is 2, not 1.** `h̃ = eq · f̃` is a product of two multilinears, so
`g_i` is quadratic and needs three evaluations `u ∈ {0,1,2}` — hence
`eval_triple_at_alpha` doing Lagrange interpolation on three points.

**Sub-items:**

1. `foldFirst` on `GroupPoly` and `FieldPoly` — first-variable fold, `2i`/`2i+1`.
   New function; the existing last-variable `fold` is not touched. Doc must state
   which is which and why both exist, mirroring the existing `fold` comment.
2. `eqTable(alpha)` — the `eq` evaluation table (`init_with_eq`, `multilinear.rs:27`).
   Check whether `rp/csp` already has one before writing a second.
3. `batchInvert` for the `1/eq(α_i,b)` denominators. **`eq(α_i,b)` can be zero** if
   any `α_j ∈ {0,1}`; the Rust calls `.invert().unwrap()` and would panic. Go must
   return a named error instead — and a test must feed `α_j = 0` and `α_j = 1` to
   confirm it does.

   **Resolved (user):** the boundary is avoidable and an error is the right
   behaviour. Titan does eventually need evaluations at points with `{0,1}`
   coordinates, but sum-check aggregates those into a *single random point*
   evaluation before the group sum-check runs. So `α` reaching this primitive is
   Fiat–Shamir-derived, and a boolean coordinate has negligible probability. The
   error is therefore defensive — unreachable on the honest path, never a case
   needing an alternate formula. Document it as such so a future caller does not
   read the error as a supported input mode.
4. `computeSTables(f GroupPoly, alpha []fr.Element, ell int)` — `S_ℓ` via transposed
   MSMs, then the additive descent.
5. `roundMessages` — the `H0`/`H1` split, for `u ∈ {0,1,2}`.
6. `ProveGroupEval` / `VerifyGroupEval` — Fiat-Shamir via `csp.Transcript` with its
   own domain separator, matching how `crypto/sumcheck` does it. Absorb `m`, `ℓ`,
   `α`, `σ` up front (the Rust binds `m`, `ℓ`, `α`, `σ`; keep that).

**The Rust verifier is not a usable reference.** `run_verifier_noninteractive`
(`group_sumcheck.rs:301`) is incomplete: its final check is
`let final_eval = PallasPoint::identity(); //evaluate_f_at_r(f_table, &r_vec);` —
the real evaluation is commented out, so the check compares against the identity
and the test has the verifier call commented out as well. It also loops `for i in
1..m`, one round short of `m`. **The Go verifier is written from the paper**, and it
must close the reduction properly: the final claim is discharged against
`f̃(r)·eq(α,r)`, which for the PCS comes from the WHIR oracle. Until WHIR lands
(step 3+), `VerifyGroupEval` returns the residual claim for the caller to close —
the same reduce-not-close contract as `crypto/sumcheck`, and it must be documented
as loudly.

**How it gets verified:**
- Round-trip for `m ∈ {2,4,6,8,10}`, `ℓ = m/2`, against `σ` computed by direct MSM
  evaluation of `f̃(α)`.
- **Cross-check against the existing general sum-check.** Build the same claim as a
  two-factor product (`eq` as a `FieldPoly`, `f̃` as the `GroupPoly`) and run
  `sumcheck.Prove`; the two must agree on the sum and the residual. This is the
  strongest available test — an independent implementation of the same claim.
- **`ℓ` invariance**: the result must not depend on `ℓ`. Run `ℓ = 0` (all folklore),
  `ℓ = m/2`, `ℓ = m` (all MSM) and require identical output. This catches errors in
  the `S`-table path that a single `ℓ` would hide.
- Negative cases: tampered round message, wrong `σ`, `α` of wrong length, and a
  compensating tamper preserving `g(0)+g(1)`.
- Mutation testing to confirm non-vacuity, as done for `crypto/sumcheck`.

## Deferred, with reasons

- **Merkle oracle — gnark-crypto's tree cannot be used as the builder.**
  `accumulator/merkletree` is a *streaming* tree from NebulousLabs (Sia), built for
  storage proofs over data read once from disk. It **does not store the leaves**:
  `Push`'s own doc says it keeps "only the log(n) elements necessary to build the
  Merkle root and ... a proof that a piece of data is in the tree"
  (`tree.go:201-204`). Internally it is a stack of subtree roots, merged on the fly
  by `joinAllSubTrees`.

  Hence `SetIndex`: it names, *in advance*, the one leaf a proof will later be
  wanted for, so that `Push` can capture it as it streams past
  (`tree.go:209-211`) and the joins can capture that path's siblings. It must be
  called on an empty tree (`tree.go:319-321`) because after any `Push` the data for
  every other index is already discarded, and `Prove` panics if it was never
  called. `PushSubTree` does not help — it explicitly forbids the subtree holding
  the proof index (`tree.go:254-259`).

  So `t` openings would mean `t` full rebuilds: `n·t` leaf hashes instead of `n`.
  At `n = 2^16`, `t = 100` that is ~6.5M leaf hashes vs 65k, and each leaf here is
  a serialized G1 point (or a coset of them), so re-serialization is paid too. Not
  broken — correct and RFC 6962 conformant for its intended streaming job — but
  the opposite trade from what WHIR needs (many openings, small in-memory tree).

  **Decision:** write a plain in-memory tree (~60 lines) that retains every level,
  making any number of openings pointer walks. Titan's trees are small by design
  (`O(√n)` leaves, smaller still under the `⁴√n` variant), so holding all levels
  is cheap. This also makes path compression — shared upper nodes across query
  paths, which the paper's implementation exploits — expressible later, whereas
  the streaming tree cannot represent it at all. Reuse gnark-crypto's
  `VerifyProof` and its `leafSum`/`nodeSum` domain separation so the hash format
  stays compatible and audited; replace only the builder. Path compression is out
  of scope for the first cut, per the scope decision.
- **WHIR folding, CSP eval, full `Commit`/`Eval`.** Need steps 1–2 first.
- **`O(⁴√n)` optimisations.** Explicitly deferred per the scope decision.
- **Zero-knowledge.** The paper's implementation is not ZK; hiding would come from
  hiding Pedersen commitments in the inner layer.

## Implementation Progress

- [x] Done — 1. `encode.go` + `domain.go` + `errors.go`: `Domain`, `reverseBits` /
  `bitReversePermutation`, `EncodeGroupOracle`, `EncodeFieldOracle`.
  Tests in `encode_test.go`, benchmarks in `encode_bench_test.go`.
  **98.1% statement coverage, race-clean, `go vet` clean.** Six mutations each
  independently fail the suite (see `docs/crypto/titan.md` §9). Docs written and
  linked from `docs/README.md`.
- [ ] Pending — 2. `groupsumcheck.go`: `foldFirst`, `eqTable`, `batchInvert` with a
  real zero-denominator error, `computeSTables`, `roundMessages`, `ProveGroupEval` /
  `VerifyGroupEval`, with cross-check against `crypto/sumcheck` and `ℓ`-invariance.

## Notes & Decisions

- Errors: sentinel `errors.New` + fsc `errors.Wrapf`, never `fmt.Errorf`, matching
  `crypto/sumcheck/errors.go` and the AGENTS.md rule.
- Transcript: reuse `csp.Transcript` with a `Titan-v1`-style domain separator.
- No new dependencies. gnark-crypto v0.20.1 supplies `fr`, `bls12381`, `MultiExp`
  and `accumulator/merkletree`; everything else is in-repo.
- Fuzz targets required by AGENTS.md for any parsing entry point, wired into
  `.github/workflows/nightly-fuzz.yml`.
- Docs: `docs/crypto/titan.md`, linked from `docs/README.md` under the existing
  "Cryptographic Primitives" heading, before either step is marked complete.

### Decisions taken during step 1

- **`Domain` wraps `fft.NewDomain` for the root of unity, then materializes the
  `2^d` powers.** The butterfly indexes the domain at power-of-two strides, so it
  wants an explicit slice (this is what the Rust `multilinear_fft(domain: &[F])`
  signature implies too). `fft.Domain`'s precomputed twiddles are laid out for its
  own FFT, not for this access pattern, so only `Generator` is reused.
- **`fft.NewDomain` panics past two-adicity rather than erroring** (verified:
  `m (8589934592) is too big: the required root of unity does not exist`). So
  `NewDomain` bounds `logSize` by `MaxLogDomainSize = 32` *before* calling it and
  returns `ErrDomainTooLarge`. Also verified the generator is primitive, not a
  lower-order element: `g^card == 1` while `g^(card/2) != 1`.
- **The encoders take `sumcheck.FieldPoly` / `sumcheck.GroupPoly`** rather than
  declaring parallel types, so a polynomial can be committed and sum-checked with
  no conversion. This is also what lets the naive cross-check reuse the
  independently-tested `EvaluatePoint`, so the two sides of the test share no code.
- **Group butterfly works in Jacobian coordinates** and converts to affine once at
  the end, since the inner loop is add/sub-heavy and affine addition is the more
  expensive form.
- **Deferred, deliberately: batching the butterfly by root.** Measured 10240 scalar
  mults for `m=10, d=11` (matching `(n/2)·log n`), and the early passes reuse very
  few distinct roots (pass 0: 2 roots over 1024 nodes). Grouping each pass by root
  into one MSM per root would amortize window precomputation. Output-identical, so
  it is a tuning change; kept out of the first cut to stay verifiable against the
  reference. Recorded in `docs/crypto/titan.md` §7.1.
- **No fuzz target yet** — the package has no parsing/deserialization entry point
  so far. One is owed when proof deserialization lands, and must be added to
  `.github/workflows/nightly-fuzz.yml` at that point.
- **`make lint` was not run**: `golangci-lint` is not installed in this
  environment. `gofmt -l` and `go vet` are clean; the lint gate still needs to run
  before a PR.
