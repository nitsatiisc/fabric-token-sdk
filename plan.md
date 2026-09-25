# Plan: Titan multilinear PCS — step 3 (Merkle-committed group oracle) — ✅ COMPLETE

Steps 1 and 2 are complete and committed (`ccc7e99d`, `3dd550d8`). Their plan is
preserved at `git show 3dd550d8:plan.md`; the decisions taken there are summarised
in `docs/crypto/titan.md`. **This plan covers step 3 only.**

## Goal

Commit a group multilinear `G̃` as a Merkle-rooted Reed-Solomon codeword, giving a
queryable oracle `⟦G⟧`, and expose the two-tier `Commit` that turns a *field*
multilinear into that same object.

The user's framing for this step: *"build the merkle tree, and encode G as a
codeword, and merkle-commit it. We get both things: field poly commitment and group
poly commitment."* That is exactly right, and it is the reason Titan was chosen —
**one commitment mechanism, two entry points**:

    CommitGroup(G̃)  -> Commitment        // tier 2 only
    CommitField(f̃)  -> Commitment, aux   // tier 1 (Pedersen rows) then tier 2

Both land on the same `Commitment` type, so everything downstream (WHIR folding,
CSP eval) is written once.

**What this step does NOT do.** It commits and opens *positions* of the codeword
with Merkle proofs. It does not fold (WHIR rounds), and it does not prove an
*evaluation* of `f̃` or `G̃`. So after step 3 the object is binding and queryable but
not yet a working PCS — `Eval` is step 4. Stating this because "commitment" is easy
to read as "PCS done", and it is not.

## What already exists (do not rebuild)

| Piece | Where | Status |
|---|---|---|
| Smooth domain `L`, `\|L\| = 2^d` | `domain.go` `NewDomain` | done, step 1 |
| Codeword `{Ĝ(x) : x ∈ L}` | `encode.go` `EncodeGroupOracle` | done, step 1 |
| Field-side codeword | `encode.go` `EncodeFieldOracle` | done, step 1 |
| Group sum-check (eval path) | `groupsumcheck.go` | done, step 2 |
| Pedersen row commit | — | **step 3, new** |
| Merkle tree over G1 leaves | — | **step 3, new** |

So the encoder is already there. Step 3 is the tree, the leaf serialization, and the
two-tier `Commit` that wires them to the encoder.

## Scope decision revised: gnark-crypto's tree cannot be reused at all

The step-1 plan said: *"Reuse gnark-crypto's `VerifyProof` and its
`leafSum`/`nodeSum` domain separation so the hash format stays compatible and
audited; replace only the builder."* **The second half of that is now withdrawn.**
Two things were checked in the actual v0.20.1 source and both fail:

1. **The domain separation does not exist.** `leafSum` and `nodeSum`
   (`tree.go:92-106`) read, verbatim:

       func leafSum(h hash.Hash, data []byte) []byte {
           //return sum(h, leafHashPrefix, data)
           return sum(h, data)
       }
       func nodeSum(h hash.Hash, a, b []byte) []byte {
           //return sum(h, nodeHashPrefix, a, b)
           return sum(h, a, b)
       }

   The RFC 6962 `0x00`/`0x01` prefixes survive only in the doc comments and in a
   comment inside `VerifyProof`; `grep` finds no declaration of `leafHashPrefix` or
   `nodeHashPrefix` anywhere in the package. So the tree computes `H(data)` and
   `H(l‖r)` with **no leaf/node separation**, which is the textbook
   second-preimage weakness: a two-leaf tree's root is indistinguishable from a
   one-leaf tree whose leaf is that root. Adopting this hash format to "stay
   compatible" would mean adopting the weakness.
2. **`VerifyProof` is not reusable anyway.** It is hardcoded to the streaming
   tree's orphan-merging shape (subtree completeness, `stableEnd`, orphan
   elevation — `verify.go:84-140`), which is a different tree shape from a plain
   power-of-two tree. And it takes a single `proofIndex`, so it cannot express the
   batch openings WHIR needs.

Both `leafSum`/`nodeSum` are unexported, so they could not be called even if we
wanted them.

**Revised decision: write the tree and the verifier, with real domain separation.**
Both sides are ours, `0x00`/`0x01` prefixes actually applied. This is ~120 lines
rather than ~60, and it is the honest cost of not inheriting a known weakness.
The builder-only reuse was already ruled out in step 1 for the streaming reason
(no stored leaves ⇒ `t` openings = `t` rebuilds); this adds the verifier to that.
Domains always power-of-two here (`|L| = 2^d`), so the shape is the simple one and
no orphan logic is needed.

## Leaf layout: coset-wise from the start, `k = 0` for the first cut

The Rust reference's Merkle config is `Leaf = Vec<G>` — **a coset of group elements
per leaf**, not one point (`group_whir_committer.rs:102`, `src/merkle_tree/sha256.rs`
hashes a `Vec<C>` by concatenating serialized points). `GroupWhirCommitment::new`
takes a folding dimension `k` and builds `2^k` points per leaf
(`group_whir_committer.rs:257-285`).

That coset structure is the `O(⁴√n)` optimisation, which is **deferred** per scope
decision 3. But the deferral is only about *choosing* `k > 0`; the leaf **type**
must be coset-shaped now, because retrofitting it later changes every Merkle root
and every proof format. So:

- `Leaf` is `[]bls12381.G1Affine` from the start, hashed as the concatenation of
  serialized points.
- The first cut sets `k = 0`, i.e. one point per leaf. Identical roots to a
  scalar-leaf design, but the type does not change when `k > 0` arrives.
- The `k > 0` remodel/transpose from `group_whir_committer.rs:259-266` is **not**
  ported yet; the plan records where it goes.

This is a deliberate departure from "simplest thing that works", justified by the
format-stability cost. Recorded as a decision, not smuggled in.

## Serialization: compressed, and it must be pinned by a test

A leaf hash is over serialized G1 points, so the byte encoding is part of the
commitment. gnark-crypto offers `Bytes()` (48-byte compressed) and
`RawBytes()` (96-byte uncompressed).

**Choose compressed `Bytes()`.** Halves the hashed volume, and leaves are the bulk
of the hashing. The cost is a decompression per point on the verify side, which the
verifier already pays elsewhere. Fix it with a test asserting the exact leaf byte
length (48 per point) and a known-answer root, so a future switch to `RawBytes()`
cannot happen silently.

**The infinity point needs checking, not assuming.** `Bytes()` on the identity must
produce a distinct, fixed encoding; if it produced all-zeros indistinguishably from
some other state that would be a binding problem. Verify empirically before relying
on it — do not trust the doc comment.

## Step 3 sub-items

### 3.1 `merkle.go` — the tree

    type Tree struct { levels [][][]byte; leafSize int }   // levels[0] = leaf hashes
    func BuildTree(leaves [][]bls12381.G1Affine) (*Tree, error)
    func (t *Tree) Root() []byte
    func (t *Tree) Prove(index int) (*MerkleProof, error)
    func (t *Tree) ProveBatch(indices []int) (*BatchProof, error)
    func VerifyMerkleProof(root []byte, leaf []bls12381.G1Affine, proof *MerkleProof) bool

- Retains **every level**, so an opening is a pointer walk: `t` openings cost `t·d`
  hash-free slice reads plus `t·d` verify-side hashes, against the streaming tree's
  `n·t` leaf hashes. At `n = 2^16, t = 100`: ~65k leaf hashes once, vs ~6.5M.
- `hashLeaf(points) = SHA256(0x00 ‖ p_0.Bytes() ‖ … ‖ p_{2^k-1}.Bytes())`
- `hashNode(l, r)   = SHA256(0x01 ‖ l ‖ r)`
- Leaf count must be a power of two (guaranteed: it is `|L| / 2^k`). Reject
  otherwise with `ErrNotPowerOfTwo` rather than padding — padding is a silent
  soundness footgun and we never need it.
- Reject a ragged `leaves` slice (unequal coset sizes) with a named error; this is
  the shape error that would otherwise produce a valid-looking root over
  inconsistent data.
- `ProveBatch` returns per-index paths in the first cut. Path compression (dedup of
  shared upper nodes, what the Rust's `MultiPath` does) is **deferred**, but
  `BatchProof` is a struct from day one so adding a compressed representation later
  does not change the call sites.

### 3.2 `commit.go` — tier 1 and the two-tier entry point

    type Commitment struct { Root []byte; NumVars, LogDomain, K int }
    type GroupOpeningHint struct { Codeword []bls12381.G1Affine; Tree *Tree; G sumcheck.GroupPoly }
    type FieldOpeningHint struct { GroupOpeningHint; Rows sumcheck.FieldPoly; Q int }

    func CommitGroup(G sumcheck.GroupPoly, dom *Domain, k int) (*Commitment, *GroupOpeningHint, error)
    func CommitField(f sumcheck.FieldPoly, gens []bls12381.G1Affine, dom *Domain, k int) (*Commitment, *FieldOpeningHint, error)

`CommitGroup` = `EncodeGroupOracle` → chunk into `2^k`-cosets → `BuildTree`.

`CommitField` adds tier 1 in front:
- `n = 2^m` coefficients as a `q × q` matrix, `q = 2^ceil(m/2)`. **Odd `m` needs a
  decision, not a silent floor**: `m = 2s+1` gives a `2^(s+1) × 2^s` matrix. Take
  rows `= 2^(s+1)`, so the group multilinear has `s+1` variables and row MSMs are
  length `2^s`. Assert `rows·cols == n` so the two cannot drift.
- Row `j` → `G_j = Σ_k f[j·cols + k] · gens[k]`, one MSM of length `cols`. Reuse the
  existing `msm` helper from `multilinear.go`.
- The `q` results **are** the evaluation table of `G̃` — no interpolation step; the
  little-endian table convention already makes `G_j` the value at `⟨j⟩`. Worth a
  comment, because "interpolate" in the paper's prose sounds like work that isn't
  there.
- `gens` must have length `≥ cols`; reject otherwise. Generator provenance is the
  caller's (a real setup, not derived here) — `Setup` is out of scope for this step.

`Commitment` carries `NumVars`, `LogDomain`, `K` alongside the root because the
verifier needs them to interpret proofs, and a root alone is ambiguous across
parameter choices.

### 3.3 `errors.go` additions

`ErrNilTree`, `ErrLeafIndexOutOfRange`, `ErrRaggedLeaves`, `ErrProofLengthMismatch`,
`ErrInsufficientGenerators`, `ErrInvalidCosetDim`.

### 3.4 Fuzz target — now genuinely owed

Steps 1–2 deferred fuzzing for lack of a parsing entry point. `VerifyMerkleProof`
**is** one: it consumes attacker-supplied `proof.Siblings` and a leaf. So:

    FuzzVerifyMerkleProof  — must never panic; must never return true for a
                             leaf/root pair not produced by BuildTree.

**Must be wired into `.github/workflows/nightly-fuzz.yml`** (`{name, pkg, func}` in
the `fuzz` job matrix) per AGENTS.md — a target outside that matrix only ever runs
its seed corpus.

## How it gets verified

The tree is the kind of code that round-trips happily while being unsound, so the
tests target *soundness*, not just agreement:

1. **Round-trip** every index of trees with `2^0 … 2^10` leaves, `k ∈ {0,1,2}`.
2. **Known-answer root** for a fixed 4-leaf tree, hardcoded hex. This is what pins
   the hash format — prefixes, compressed encoding, child order — so none can drift
   silently.
3. **Second-preimage separation.** Build a 2-leaf tree with root `R`, then a 1-leaf
   tree whose single leaf's serialization is the concatenation that produced `R`.
   Roots must differ. **This test fails against gnark's prefix-less format**, which
   is the whole reason for not adopting it — so it also documents the decision.
4. **Wrong-leaf / wrong-index / tampered-sibling** must all return false. Including
   a sibling swapped with its pair, which catches left/right order inversion — the
   classic Merkle bug that a round-trip test cannot see.
5. **Cross-check against an independent naive root**: a test-local recursive
   `H(0x01 ‖ recurse(left) ‖ recurse(right))` written straight from the definition,
   compared against `BuildTree`. Independent implementation, as with step 1's naive
   encoder cross-check.
6. **Tier-1 cross-check**: `G̃`'s table entry `j` must equal a direct
   `Σ_k f[j·cols+k]·gens[k]` computed without `CommitField`, and
   `G̃.EvaluatePoint` must be consistent with `f̃` on the matrix split.
7. **`k`-invariance of the underlying codeword**: changing `k` regroups leaves and
   so legitimately changes the root, but the *codeword* must be identical. Pins that
   cosets only regroup and never reorder.
8. **Determinism**: same inputs ⇒ same root, across two independent builds.
9. **Mutation testing** to confirm non-vacuity, as for steps 1–2. Planned
   mutations: drop leaf prefix; drop node prefix; swap child order; `RawBytes()` for
   `Bytes()`; off-by-one in sibling index; coset chunking strided instead of
   contiguous; row MSM using `gens` offset by one; odd-`m` rows/cols swapped.

Coverage target ≥ 90% statements, race-clean, `go vet` + `gofmt` clean, matching
steps 1–2.

## Deferred, with reasons

- **WHIR folding rounds, CSP eval, `Eval`/`Open`.** Step 4. Step 3 deliberately
  stops at a queryable oracle.
- **`Setup` / generator generation.** `CommitField` takes `gens` from the caller.
  Real generator derivation is a trust-setup question of its own.
- **Path compression in `BatchProof`.** Struct shape reserves room; the Rust's
  `MultiPath` is the model.
- **`k > 0` in practice** (`O(⁴√n)`) — type is ready, remodel not ported.
- **Zero-knowledge.** Unchanged: hiding would come from hiding Pedersen
  commitments in tier 1.

## Implementation Progress

- [x] **3.1 `merkle.go` + tests** — Done. `Tree` retains every level; `BuildTree`,
  `Root` (returns a copy), `NumLeaves`, `Depth`, `Prove`, `ProveBatch`,
  `VerifyMerkleProof`, `hashLeaf`, `hashNode`, `treeDepth`. RFC 6962 `0x00`/`0x01`
  prefixes actually applied. Leaves are `[][]bls12381.G1Affine` with `cosetSize`
  recorded on the tree. `merkle_test.go` has 19 tests including an independent naive
  recursive root, second-preimage separation, and a known-answer leaf hash.
- [x] **3.2 `commit.go` + tests** — Done. `Commitment{Root, NumVars, LogDomain, K,
  NumLeaves}`, `GroupOpeningHint`, `FieldOpeningHint`, `CommitGroup`, `CommitField`,
  `OpenLeaf`, `chunkIntoCosets` (contiguous), `matrixShape`, `numVarsOf`.
  `commit_test.go` has 12 tests; the decisive ones are the direct per-row MSM
  cross-check and the "group poly *is* the evaluation table" test.
- [x] **3.3 `errors.go` additions** — Done. `ErrNilTree`, `ErrEmptyLeaves`,
  `ErrRaggedLeaves`, `ErrLeafIndexOutOfRange`, `ErrProofLengthMismatch`,
  `ErrInvalidCosetDim`, `ErrInsufficientGenerators`.
- [x] **3.4 `FuzzVerifyMerkleProof` + `nightly-fuzz.yml` entry** — Done.
  `merkle_fuzz_test.go`, 8 seeds, two properties (never panic, never accept).
  Verified clean at 1.88M execs / 25s. Wired in as `titan-merkle-verify-proof`;
  matrix now has 26 entries, YAML validated.
- [x] **3.5 `docs/crypto/titan.md` new section** — Done. New §7 "Merkle Commitment
  and the Two Tiers" (7.1–7.5), new §8.1 "Commitment" API, new §9.3 with four
  measurement tables, §11 Testing rewritten with the new files, the 93.4% figure,
  the 13-mutation table, §11.1 fuzzing and §11.2 the M9/M12 write-up. Sections
  renumbered 7→8, 8→9, 9→10, 10→11, 11→12 with the TOC and cross-references updated.
  `docs/README.md` already links `crypto/titan.md` and its description still matches.
- [x] **3.6 Mutation testing pass** — Done. 13 mutations; 12 killed, and the
  13th established as an *equivalent* mutant with evidence. See
  "Decisions taken during step 3" below — this pass found one real soundness bug.

### Verification

- Full suite green; **93.4% statement coverage** (`BuildTree`, `Prove`, `ProveBatch`,
  `VerifyMerkleProof`, `hashLeaf`, `hashNode`, `treeDepth`, `chunkIntoCosets`,
  `matrixShape`, `numVarsOf` all 100%; `CommitGroup` 88.2%, `CommitField` 87.0%,
  `OpenLeaf` 87.5% — the uncovered lines are unreachable error returns from the
  encoder, which the callers have already validated against).
- Race-clean (22.7s), `go vet` clean, `gofmt` clean, no `fmt` import, license
  headers present. Wider `crypto/...` tree green across 8 packages.
- `make lint` **not run** — `golangci-lint` is absent in this environment. Owed
  before any PR; not claimed as passing.

### Measurements (Apple M4 Max)

| | 2^8 | 2^10 | 2^12 | 2^14 |
|---|---|---|---|---|
| `BuildTree` | 72.6µs | 236µs | 679µs | 2.62ms |

`ProveMany` at 2^14: 219ns (1 opening), 2.69µs (10), 25.5µs (100).
`VerifyMerkleProof`: 763ns at depth 10, 964ns at depth 14 — linear in depth.
`CommitField`: 8.24ms / 19.5ms / 46.8ms at `m = 10/12/14`.

The 100-openings figure is the number that justifies the custom tree: **25.5µs
against ~262ms** for a streaming tree's 100 rebuilds, ≈10,000×, and the gap widens
linearly with query count. Tier 1 dominates `CommitField` (2^m scalar
multiplications against the tree's O(√n) hashes), so the Merkle layer is not the
bottleneck and the next optimization target is elsewhere.

## Decisions taken during step 3

1. **gnark-crypto's `accumulator/merkletree` reused for neither builder nor
   verifier.** Half of a step-1 scope decision withdrawn on evidence — the RFC 6962
   prefixes are commented out in v0.20.1 and `VerifyProof` is hardcoded to the
   streaming orphan-merging shape. Recorded above as a revision rather than smuggled
   in. ~120 lines instead of ~60.
2. **Coset-shaped leaves from the start, `k = 0` in value.** Leaf shape determines
   every root and every proof format, so the type is coset-shaped now even though
   `k > 0` is deferred. A deliberate departure from "simplest thing that works".
3. **Compressed `Bytes()` (48 bytes), not `RawBytes()` (96).** Leaves dominate
   hashing; the verifier already pays decompression elsewhere. Infinity was checked
   empirically — it encodes as `0xc0` followed by zeros, distinct from all-zeros, and
   round-trips. Pinned by a known-answer test so a switch cannot happen silently.
4. **Cosets are contiguous slices, never strided.** A strided chunking builds a
   valid-looking tree over a *permutation* of the same points, which no round-trip
   test can see. Pinned by `TestCommitGroupLeavesArePartitionOfCodeword`.
5. **Odd `m` sends the extra variable to the rows** (`2^(s+1)` rows × `2^s` cols).
   Keeps row MSMs shorter and grows the group multilinear, which is the cheaper side.
   Arbitrary but must be fixed, since both sides must agree; `matrixShape` asserts
   `rows·cols == 2^m`.
6. **Mutation testing found a real forgery (M9).** Dropping the proof-length check
   left the suite green: a one-leaf tree's root *is* its leaf hash, so a prover can
   claim that leaf sits at index 0 of an 8-leaf tree with an **empty** path and the
   verifier accepts. `TestVerifyRejectsWrongProofLength` only appeared to cover this —
   its short and over-long cases are both caught incidentally by the digest
   comparison. Two tests added; mutation now killed.
7. **M12 is an equivalent mutant, not a test gap — and establishing that meant
   correcting my own wrong claim.** I first asserted the per-sibling length check
   prevented a forgery, on the strength of a real `hashNode` collision (a 20/44 split
   of 64 bytes hashes identically to 32/32). The mutation kept surviving, which proved
   the test was not reaching it. A reachability probe (sibling lengths 0..40 at every
   level of 2/4/8-leaf trees) accepted zero cases both with and without the check: the
   accumulator is always a 32-byte hash output, so only one side's length varies, and
   the collision needs the attacker to control *both* sides of one `hashNode` call. The
   check stays as documented defence-in-depth, load-bearing the moment anything feeds
   `hashNode` variable-length input. Test rewritten as
   `TestHashNodeHasNoLengthFraming`.
8. **`VerifyMerkleProof` returns `bool`, not `error`.** Deliberate: malformed input
   must not be distinguishable from a hash mismatch.
9. **Benchmark warmup noise is real and was nearly misread.** `VerifyMerkleProof` at
   depth 10 first measured 6865ns against 964ns at depth 14 — inverted, and wrong.
   Re-running at `-benchtime=2000x` gave 763ns vs 964ns, correctly linear. Twenty
   iterations is not enough to measure a sub-microsecond operation.

## Notes & Decisions

- Hash is SHA-256, matching `csp.Transcript` and the Rust reference's default.
- Errors: sentinel `errors.New` in `errors.go`, wrapped with fsc `errors.Wrapf` at
  call sites. Never `fmt`.
- No new dependencies: `crypto/sha256` is stdlib, gnark-crypto already present.
  Note the `accumulator/merkletree` import is now **not** used at all.
- Open an issue before coding, per AGENTS.md, describing the gap only.
- `make lint` still cannot run locally (`golangci-lint` absent); must run before PR.
