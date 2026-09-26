# Titan Multilinear Polynomial Commitment Scheme

**Implementation**: [`token/core/zkatdlog/nogh/v1/crypto/titan`](../../token/core/zkatdlog/nogh/v1/crypto/titan)
**Curve**: BLS12-381 (G1)
**Status**: in progress — step 1 (oracle encoding) complete
**Date**: 2026-09-25

## Table of Contents
1. [Introduction](#1-introduction)
2. [Why Titan](#2-why-titan)
3. [The Univariate-Multilinear Correspondence](#3-the-univariate-multilinear-correspondence)
4. [Oracle Encoding](#4-oracle-encoding)
5. [The Evaluation Domain](#5-the-evaluation-domain)
6. [Efficient Group Sum-Check](#6-efficient-group-sum-check)
7. [Merkle Commitment and the Two Tiers](#7-merkle-commitment-and-the-two-tiers)
8. [API](#8-api)
9. [Performance Notes](#9-performance-notes)
10. [Porting Notes: Rust/Pasta to Go/BLS12-381](#10-porting-notes-rustpasta-to-gobls12-381)
11. [Testing](#11-testing)
12. [Evaluation](#12-evaluation)
13. [Folding: Closing the Claim](#13-folding-closing-the-claim)
14. [References](#14-references)

---

## 1. Introduction

Titan is a multilinear polynomial commitment scheme (PCS) built in two tiers:

1. **Pedersen-commit the matrix form of the witness.** A multilinear `ftilde` on
   `m` variables with `n = 2^m` coefficients is viewed as a `q x q` matrix with
   `q = 2^(m/2) = sqrt(n)`. Row `i` is Pedersen-committed to a single group
   element `G_i = sum_j ftilde_i(<j>) * g_j`.
2. **Commit the resulting group vector with a WHIR-style IOPP.** The `q` group
   elements are interpolated into a *group* multilinear `Gtilde` with
   `Gtilde(<i>) = G_i`, and `Gtilde` is committed by a Reed-Solomon IOPP that
   works over group elements rather than field elements.

The oracle for `Gtilde` *is* the commitment to `ftilde`.

## 2. Why Titan

The deciding reason for this codebase: **a group polynomial commitment scheme
falls out as a by-product.** The second tier already commits a group multilinear,
so committing to a group polynomial directly needs no new machinery — the same
IOPP serves both. Since the surrounding argument needs to commit both field and
group witnesses (see [sum-check](sumcheck.md), whose claims mix field and group
factors), one scheme covering both avoids maintaining two.

The two tiers also split the cost the way we want it: the expensive
multi-exponentiation is `O(n)` once, in tier 1, and everything after it runs at
`O(sqrt(n))`.

## 3. The Univariate-Multilinear Correspondence

The IOPP is a univariate Reed-Solomon proximity test, but the committed object is
multilinear. The two are joined by evaluating the multilinear along the *power
curve*:

```
fhat(X) := ftilde(X, X^2, X^4, ..., X^(2^(m-1)))
```

`fhat` is univariate of degree at most `2^m - 1`, and the map `ftilde -> fhat` is
injective: a multilinear monomial `prod_{j in S} X_j` maps to `X^(sum_{j in S} 2^j)`,
and distinct subsets `S` give distinct binary numbers, so no two of the `2^m`
coefficients collide. Committing `fhat` therefore commits `ftilde`.

"Encoding the oracle" means evaluating `fhat` on every point of the domain `L`.

## 4. Oracle Encoding

Evaluating `fhat` pointwise would cost one multi-exponentiation per domain point.
Instead the encoder runs a butterfly in `m` passes over the domain, using the
multilinear identity in the leading variable

```
ftilde(x, x^2, ...) = ftilde(0, x^2, ...) + x * (ftilde(1, x^2, ...) - ftilde(0, x^2, ...))
```

together with the fact that a smooth multiplicative subgroup is closed under
squaring: `x` and `-x` square to the same value, so a single scalar
multiplication `factor = (hi - lo) * x` yields **both** outputs, `lo + factor` at
`x` and `lo - factor` at `-x`. That is the standard FFT butterfly, and it costs

```
(n/2) * log n     scalar multiplications
```

against roughly `n * log n` for forming the coefficients of `fhat` explicitly.

### 4.1 Two Details That Are Easy to Get Wrong

**Bit-reversal comes first.** The butterfly consumes variables from the high bit
of the index downwards, pairing the first pass with the highest power
`x^(2^(m-1))`. But this repository indexes evaluation tables **little-endian** —
entry `i` holds `p(b_0, ..., b_(m-1))` with `b_j` the `j`-th bit of `i`, so `b_0`
sits at the low bit (see [sum-check §2.2](sumcheck.md#22-representation)). A
bit-reverse permutation before the butterfly relabels the variables in reverse, so
that bit 0 holds `b_(m-1)` and the passes come out in the order the power curve
needs. Omitting it silently encodes a *different* polynomial —
`TestEncodeFieldOracleMatchesNaive` fails at `m=2` without it.

**The blow-up repeats, it does not zero-pad.** When the domain is larger than the
message (`d > m`, which is what gives the code its rate and hence the IOPP its
distance), each coefficient is repeated `2^(d-m)` times. Repetition is what makes
the first pass see a constant on each block, which is the degree-0 base case of
the recursion. Zero-padding instead produces the wrong codeword.

## 5. The Evaluation Domain

`Domain` is the multiplicative subgroup `L` of `Fr` of order `2^d`, materialized
as the full list of its elements in generator order (`Elements[i] = Generator^i`).
The butterfly indexes this slice at power-of-two strides, so laying the elements
out beats recomputing them; at the `O(sqrt(n))` sizes Titan encodes, the slice is
negligible.

`NewDomain` builds on `gnark-crypto`'s `fft.NewDomain` for the root of unity, then
enumerates the powers. `fft.NewDomain` *panics* past the field's two-adicity, so
`NewDomain` bounds `logSize` by `MaxLogDomainSize` first and returns
`ErrDomainTooLarge` instead.

## 6. Efficient Group Sum-Check

**This is additive, not a replacement.** [`crypto/sumcheck`](sumcheck.md) remains the
general sum-check primitive, and nothing here changes it. This one proves a single
shape of claim, only for a group polynomial:

```
sum over x in {0,1}^m of eq(alpha, x) * f(x) = sigma        f in G[X], sigma in G
```

which is exactly an evaluation claim, `sigma = f(alpha)`. Titan's evaluation path
needs precisely this shape, and the specialisation is what buys the speedup. A caller
with any other claim wants `crypto/sumcheck`.

### 6.1 Why It Is Faster

Naive group sum-check costs `O(n)` group exponentiations. Here the `eq` factor is
known in advance, so the prover can precompute partial sums over suffixes

```
S_i(b) = sum over x in {0,1}^(m-i) of h(b, x),     h(x) = eq(alpha, x) * f(x)
```

for every prefix `b` in `{0,1}^i`. Then:

- `S_ell` costs `2^ell` multi-exponentiations of size `2^(m-ell)`;
- every lower table follows by `S_(i-1)(b) = S_i(b,0) + S_i(b,1)` — group
  **additions**, ~137× cheaper than scalar multiplications on this curve
  (see [sumcheck](sumcheck.md#62-scalar-multiplication-dominates-the-group-path));
- rounds `i <= ell` read their message off `S_i` with MSMs of size `O(2^i)`;
- rounds past `ell` run the folklore method on a polynomial already down to
  `O(sqrt(n))` entries.

With `ell = m/2` the total is `sqrt(n)` MSMs of size `sqrt(n)` plus `O(sqrt(n))`
group exponentiations, against `O(n)` exponentiations naive.

### 6.2 Variable Order Is the Opposite of `crypto/sumcheck`

This is the single most important thing to know when reading the two packages
together, and getting it wrong is silent.

`crypto/sumcheck` consumes variables from the **last** position inward, so its fold
pairs entry `i` with `i + half`. Titan's group sum-check is specified the other way:
the round-`i` message fixes `rho_i = (r_1, ..., r_(i-1))` as a **prefix**, and the
partial-sum tables are indexed by prefixes. So this package folds the **first**
variable, pairing `2i` with `2i+1`.

| Helper | Substitutes | Pairs |
|--------|-------------|-------|
| `sumcheck.FieldPoly.fold` | the last variable | `i` with `i + half` |
| `titan.foldFirstField` / `foldFirstGroup` | the first variable | `2i` with `2i+1` |

A round-trip test **cannot** catch a mistake here: prover and verifier fold
identically, so the error cancels between them and the proof still verifies.
`TestFoldFirstSubstitutesFirstVariable` pins the convention down directly, and the
cross-implementation test in [section 10](#10-testing) catches it independently.

### 6.3 Round Degree Is 2

The summand `h = eq * f` is a product of two multilinears, so each round message is
quadratic and needs three evaluations. The package sends `g_i(0)`, `g_i(1)`,
`g_i(2)`, and the verifier interpolates on the nodes `{0,1,2}`.

Rounds `i <= ell` isolate the `u`-dependent part so the three evaluations share the
MSM work: splitting `S_i` at its newest variable gives two `u`-independent MSMs `H0`
and `H1` of size `2^(i-1)`, after which each `g_i(u)` is two scalar multiplications:

```
g_i(u) = K*(1-u)/(1-alpha_i) * H0  +  K*u/alpha_i * H1,     K = eq(rho, u, alpha_i)
```

This turns three MSMs per round into two. It comes from the reference
implementation rather than the paper text.

### 6.4 The `alpha` Boundary Case

The `H0`/`H1` form divides by `alpha_i` and `1 - alpha_i`. A coordinate of `alpha`
that is exactly `0` or `1` makes `eq(alpha_i, b)` vanish and the reciprocal
undefined. On the honest path `alpha` comes from a transcript, so this has negligible
probability — but the reference implementation calls `.invert().unwrap()` and
**panics**. Here it returns `ErrZeroDenominator`, naming the offending index.

The folklore rounds contain no such division, so the error surfaces only when the
affected round is an MSM round.

### 6.5 This Reduces the Claim; It Does Not Close It

Exactly as with `crypto/sumcheck`: a `nil` error from `VerifyGroupEval` means the sum
**follows from** the returned `GroupSumCheckOpening`. It does **not** mean the opening
is correct. A prover free to choose the residual value can prove any sum.

The caller must check `Expected` against `eq(alpha, R) * f(R)`, with `f(R)` obtained
from the WHIR oracle rather than from the prover's choice; the `eq` factor the
verifier computes itself, since `alpha` and `R` are public. Omitting that step leaves
no soundness at all.

**[Section 13](#13-folding-closing-the-claim) does this**, so a caller no longer has to.
Committing with `CommitGroupWithFold`/`CommitFieldWithFold` makes `VerifyEval`/
`VerifyEvalGroup` require a folding phase and check the opening against the committed
coset oracle. `ProveGroupEval`/`VerifyGroupEval` used on their own are still a
reduction only — the caveat above applies to them as the sum-check primitives they are.

## 7. Merkle Commitment and the Two Tiers

Titan commits a field multilinear in two tiers, and the inner tier is by itself a
commitment to a *group* multilinear. That is the whole reason the scheme was chosen
here: **one commitment mechanism, two entry points**.

| | Mechanism | Assumption | What it binds |
|---|---|---|---|
| Tier 1 | Pedersen MSM per matrix row | discrete log | row coefficients to `G_j` |
| Tier 2 | Merkle root over the RS codeword | random oracle | `G` to a queryable oracle |

```
CommitGroupWithFold(G)  = tier 2              a group polynomial commitment
CommitFieldWithFold(f)  = tier 1 then tier 2  a field polynomial commitment
```

Note the direction of tier 1: Pedersen does not commit *to* `G`, it **produces**
`G`. The group multilinear is the *output* of the first tier. `G` is already a
commitment to `f`, row by row; tier 2 then makes it queryable.

### 7.1 Tier 1: rows to a group multilinear

Read the `2^m` coefficients of `f` as a `rows x cols` matrix and Pedersen-commit
each row against public generators:

```
G_j = sum_k  f[j*cols + k] * gens[k]
```

one MSM of length `cols` per row. The `rows` results **are** the evaluation table of
`G`: in the little-endian convention this package and `crypto/sumcheck` share,
entry `j` already holds the value at the bit decomposition of `j`, so despite the
word "interpolate" in the protocol description there is no interpolation step to
perform. `TestCommitFieldGroupPolyIsTheEvaluationTable` pins this by checking
`EvaluatePoint` on boolean points against the row commitments.

**Odd `m` needs a decision, not a silent floor.** For even `m` the split is the
square `2^(m/2)` by `2^(m/2)`. For odd `m = 2s+1` no square split exists, and the
extra variable goes to the **rows**: `2^(s+1)` rows of `2^s` columns. This keeps the
row MSMs shorter and grows the group multilinear instead, which is the cheaper side
to grow. The choice is arbitrary but must be fixed, since prover and verifier have
to agree; `matrixShape` asserts `rows*cols == 2^m` so the two cannot drift.

### 7.2 Tier 2: codeword to Merkle root

`EncodeGroupOracle` (section 4) gives `|L|` group elements. Those are grouped into
cosets of `2^k` points, each coset is one Merkle leaf, and the root is the
commitment `[[G]]`.

```
hashLeaf(points) = SHA256(0x00 || p_0.Bytes() || ... || p_{2^k - 1}.Bytes())
hashNode(l, r)   = SHA256(0x01 || l || r)
```

Leaves are **compressed** (48 bytes per point, not 96): leaves dominate the hashing,
so halving their volume matters, and the verifier already pays decompression
elsewhere. The encoding is part of the commitment, so
`TestLeafHashKnownAnswer` pins the exact byte layout. The point at infinity encodes
as `0xc0` followed by zeros -- distinct from every finite point and not all-zeros,
checked empirically rather than taken from the doc comment.

### 7.3 Why gnark-crypto's Merkle tree is not used

The original plan was to reuse `accumulator/merkletree`'s verifier and hash format
and replace only the builder. **Both halves of that turned out to be unworkable**,
checked against the v0.20.1 source rather than assumed.

**It is a streaming tree.** Taken from NebulousLabs (Sia) and built for storage
proofs over data read once from disk, it does not retain leaves: `Push` keeps "only
the log(n) elements necessary to build the Merkle root and ... a proof that a piece
of data is in the tree" (`tree.go:201-204`). Hence `SetIndex`, which names *in
advance* the single leaf a proof will later be wanted for, and which must be called
on an empty tree (`tree.go:319-321`) because after any `Push` the data for every
other index is already discarded. `Prove` panics if it was never called, and
`PushSubTree` explicitly forbids the subtree holding the proof index
(`tree.go:254-259`). So `t` openings would mean `t` full rebuilds.

WHIR opens many positions of a small tree, which is the opposite trade. The
measured gap is large: see section 9.3.

**Its hash format has no domain separation.** `leafSum` and `nodeSum`
(`tree.go:92-106`) read, verbatim:

```go
func leafSum(h hash.Hash, data []byte) []byte {
	//return sum(h, leafHashPrefix, data)
	return sum(h, data)
}
func nodeSum(h hash.Hash, a, b []byte) []byte {
	//return sum(h, nodeHashPrefix, a, b)
	return sum(h, a, b)
}
```

The RFC 6962 `0x00`/`0x01` prefixes survive only in the doc comments; no
`leafHashPrefix` or `nodeHashPrefix` is declared anywhere in the package. Without
separation a leaf hash and an internal node hash are drawn from the same space, so
the root of a two-leaf tree collides with that of a one-leaf tree whose leaf is the
concatenation of the two children -- the textbook second-preimage weakness.
Adopting the format "for compatibility" would mean adopting the weakness.
`TestSecondPreimageSeparation` pins that this implementation does not share it.

Both helpers are unexported in any case, and `VerifyProof` is hardcoded to the
streaming tree's orphan-merging shape (`verify.go:84-140`), which is a different
tree shape from a plain power-of-two tree, and takes a single `proofIndex` so it
cannot express batch openings. **Neither the builder nor the verifier is reused;
the `accumulator/merkletree` import does not appear in this package.**

### 7.4 Leaves are cosets from the start, with `k = 0`

A leaf holds `2^k` group elements, not one. The `O(n^(1/4))` variant needs
coset-wise leaves -- the Rust reference's Merkle config is `Leaf = Vec<G>`
(`group_whir_committer.rs:102`) and its committer takes a folding dimension `k`
(`group_whir_committer.rs:257-285`).

Choosing `k > 0` is deferred. The leaf **shape** is not, because it determines every
root and every proof format in the scheme, and retrofitting it later would
invalidate both. So the type is coset-shaped now and the first cut passes `k = 0`,
giving one point per leaf and identical roots to a scalar-leaf design. The `k > 0`
remodel is not ported yet.

Cosets are **contiguous** blocks of the codeword, never strided. A strided chunking
would still build a valid-looking tree over a permutation of the same points, which
no round-trip test could see, so
`TestCommitGroupLeavesArePartitionOfCodeword` checks that concatenating the leaves
reproduces the codeword in order, for every `k`.

### 7.5 What this does not do

A commitment here is binding and queryable **by position** of the codeword. It is
not yet an evaluation proof: nothing in this section shows that `f(z) = v` for a
claimed `v`. That needs the group sum-check of section 6 plus the folding rounds of
[section 13](#13-folding-closing-the-claim). `Commit` and `Eval` are separate for that
reason, and "commitment" should not be read as "PCS complete".

---

## 8. API

```go
import "github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/titan"

dom, err := titan.NewDomain(11)          // |L| = 2^11, rate 1/2 for m = 10
if err != nil {
    return errors.Wrap(err, "failed to build evaluation domain")
}

codeword, err := titan.EncodeGroupOracle(groupPoly, dom)   // []bls12381.G1Affine
if err != nil {
    return errors.Wrap(err, "failed to encode group oracle")
}
```

| Function | Input | Output | Used for |
|----------|-------|--------|----------|
| `NewDomain(logSize)` | `d` | `*Domain` | the Reed-Solomon evaluation domain `L` |
| `EncodeGroupOracle(p, dom)` | `sumcheck.GroupPoly` | `[]bls12381.G1Affine` | the committed oracle for `Gtilde` |
| `EncodeFieldOracle(p, dom)` | `sumcheck.FieldPoly` | `[]fr.Element` | the public generator polynomial `gtilde`, which the verifier recomputes |
| `ProveGroupEval(curve, f, alpha, ell)` | `sumcheck.GroupPoly`, point, split | proof, opening, `sigma` | the evaluation claim `f(alpha)` |
| `VerifyGroupEval(curve, proof, alpha, sigma, ell)` | proof + public data | opening | checking that claim |
| `DefaultSplit(m)` | `m` | `m/2` | the cost-optimal split point |
| `NewGenerators(curve, gens)` | `[]bls12381.G1Affine` | `*Generators` | the converted-once generator cache for `Eval` |
| `Eval` / `VerifyEval` | see [section 12.10](#1210-api) | `*EvalProof` | the field evaluation proof `f(alpha) = sigma` |
| `EvalGroup` / `VerifyEvalGroup` | see [section 12.10](#1210-api) | `*GroupEvalProof` | the group evaluation proof |
| `CommitGroupWithFold` / `CommitFieldWithFold` | poly, domain, `k`, `FoldConfig` | commitment + hint | a commitment whose opening is **sound**; see [section 13](#13-folding-closing-the-claim) |
| `DefaultFoldConfig(m)` | `m` | `FoldConfig` | size-optimal `ell`, rate 1/8, `Q = 43` |
| `EncodeCosets(p, dom, ell)` | `sumcheck.GroupPoly` | leaves + folded domain | the coset oracle `{f(b, powers(y))}` |
| `CommitCosets(p, dom, ell)` | `sumcheck.GroupPoly` | `*CosetCommitment` + hint | the Merkle root over cosets |
| `EncodeGroupOracleAt(p, dom, i)` | poly, domain, index | one `G1Affine` | one codeword point, so the verifier stays sublinear |
| `VerifyBatch(root, leaves, proof)` | root, leaves, `*BatchProof` | `bool` | the verifier counterpart to `ProveBatch` |
| `ProveGroupEvalWithTranscript` / `VerifyGroupEvalWithTranscript` | `*csp.Transcript` + the above | as above | chaining the sum-check into the folding phase |

Both encoders take the polynomial types from
[`crypto/sumcheck`](../../token/core/zkatdlog/nogh/v1/crypto/sumcheck) rather than
redeclaring them, so a polynomial can be committed and sum-checked without
conversion. Neither modifies its input.

The domain must be at least as large as the polynomial (`ErrDomainTooSmall`
otherwise); a strictly larger domain is what gives the code a rate below 1.

The group sum-check takes `*mathlib.Curve` because it reuses
`crypto/rp/csp.Transcript` for Fiat-Shamir, under its own domain separator
`TitanGroupSumCheck-v1`. It absorbs `m`, `ell` and `alpha` before the first round, so
a proof cannot be reinterpreted under different public parameters:

```go
proof, opening, sigma, err := titan.ProveGroupEval(curve, f, alpha, titan.DefaultSplit(m))
if err != nil {
    return errors.Wrap(err, "group sum-check prover failed")
}

vOpening, err := titan.VerifyGroupEval(curve, proof, alpha, &sigma, titan.DefaultSplit(m))
if err != nil {
    return errors.Wrap(err, "group sum-check verification failed")
}
// These are the sum-check primitives, and on their own they only reduce the claim:
// see section 6.5. Eval/EvalGroup over a CommitGroupWithFold commitment close it.
```

`sigma` is returned rather than taken as an argument, since it is determined by `f`
and `alpha`. `ell` is a pure performance knob — the claim proved is the same for every
value — but it is bound into the transcript, so both sides must agree on it.


### 8.1 Commitment

`CommitGroupWithFold` is the group polynomial commitment; `CommitFieldWithFold` is the
field one and runs both tiers. Both return a `*Commitment` for the verifier and an
opening hint that is **prover state and must not be sent**.

There is no unfolded variant in the public API, and that is deliberate. The stages that
commit the flat codeword alone (`commitField`, `commitGroup`) are unexported: such a
commitment lets a verifier *reduce* an evaluation claim without closing it, so its
openings do not bind, and it is never what a caller wants. They exist only as the first
half of the `WithFold` constructors. Most callers should not use either directly — the
[PCS facade](#1312-the-pcs-facade) is the intended entry point.

```go
dom, err := titan.NewDomain(11)                  // |L| = 2^11
if err != nil {
    return errors.Wrap(err, "failed to build evaluation domain")
}
cfg, err := titan.DefaultFoldConfig(groupNumVars)
if err != nil {
    return errors.Wrap(err, "failed to choose a fold configuration")
}

// Group polynomial commitment: tier 2, with the coset oracle.
c, hint, err := titan.CommitGroupWithFold(groupPoly, dom, 0, cfg)   // k = 0, one point per leaf
if err != nil {
    return errors.Wrap(err, "failed to commit the group polynomial")
}

// Field polynomial commitment: tier 1 (Pedersen rows) then tier 2. This reads f as
// a matrix at the balanced split, m1 = m/2.
c, fhint, err := titan.CommitFieldWithFold(fieldPoly, gens, dom, 0, cfg)
if err != nil {
    return errors.Wrap(err, "failed to commit the field polynomial")
}

// To choose the split instead -- which is what makes sizes like m = 10 usable, and
// what lets the two legs' costs be traded off -- use CommitFieldWithFoldAt. The
// split is recorded in the commitment, so the verifier checks against it.
c, fhint, err = titan.CommitFieldWithFoldAt(fieldPoly, gens, dom, 0, cfg, titan.Split{M: 10, M1: 4})
if err != nil {
    return errors.Wrap(err, "failed to commit the field polynomial")
}
```

A query on the oracle is answered by a coset plus its authentication path:

```go
coset, proof, err := hint.OpenLeaf(idx)
if err != nil {
    return errors.Wrapf(err, "failed to open leaf %d", idx)
}
if !titan.VerifyMerkleProof(c.Root, coset, proof) {
    return errors.New("merkle proof did not verify")
}
```

`Commitment` carries `NumVars`, `LogDomain`, `K` and `NumLeaves` alongside `Root`,
because a root alone is ambiguous across parameter choices — a verifier must check
the shape against what it expects rather than trusting the prover's.

`gens` comes from the caller: the field commitment performs no trusted setup, and generator
provenance is a separate question this package does not answer. At least `cols`
generators are required (`ErrInsufficientGenerators`).

Committing is not opening: `Commitment` plus `OpenLeaf` is binding and queryable by
*position*, and proving `f(alpha) = sigma` is [section 12](#12-evaluation).

`VerifyMerkleProof` returns a `bool`, not an `error`, because every failure is the
same verdict — this proof does not open this root — and distinguishing malformed
input from a mismatch would hand an adversary a distinguisher.

## 9. Performance Notes

Measured on an Apple M4 Max, rate-1/2 domain (`d = m + 1`):

| `m` | Butterfly | Naive (per-point evaluation) | Speedup |
|-----|-----------|------------------------------|---------|
| 6 | 16.6 ms | 325 ms | **19.5x** |
| 8 | 82.3 ms | 5374 ms | **65x** |
| 10 | 431 ms | — | — |

The speedup grows with `m` because the naive baseline is quadratic in `n` in
scalar multiplications while the butterfly is `n log n`.

### 9.1 Where the Remaining Cost Is, and the Obvious Next Optimization

The butterfly performs exactly one scalar multiplication per node. For `m = 10`,
`d = 11` that is **10240** scalar multiplications, matching `(n/2) * log n = 11264`
to within the `d > m` bookkeeping. Since scalar multiplications are ~137x more
expensive than curve additions on this curve
([sum-check §6.2](sumcheck.md#62-scalar-multiplication-dominates-the-group-path)),
they are essentially the whole cost.

The distinct-root count per pass is heavily skewed:

| pass | nodes | distinct roots |
|------|-------|----------------|
| 0 | 1024 | 2 |
| 1 | 1024 | 4 |
| … | … | … |
| 9 | 1024 | 1024 |

So the early passes multiply many different points by the *same* few scalars.
Grouping a pass's nodes by root and applying each root with one multi-scalar
multiplication would amortize window precomputation the way `groupRoundEvals`
already does in sum-check. This is **not implemented** — it is a tuning change
with no effect on the output, deliberately deferred so the first cut stays
verifiable against the reference.

### 9.2 The Split Point, and a Bottleneck That Hid It

Measured on an Apple M4 Max, `m = 12` (4096 group coefficients), sweeping `ell`:

| `ell` | Prover | Note |
|-------|--------|------|
| 0 | 245 ms | all folklore — the baseline |
| 2 | 211 ms | |
| 4 | 72 ms | |
| **6** | **39.7 ms** | `DefaultSplit(12)`, the optimum — **6.2× the baseline** |
| 8 | 59 ms | |
| 10 | 155 ms | `S_ell` now dominates |
| 12 | 236 ms | all partial-sum |

The curve has a clear minimum at `m/2`, which is what the cost analysis predicts, and
it rises at both ends: too small an `ell` leaves work in the folklore tail, too large
makes `S_ell` itself the expensive part.

Prover scaling at `ell = m/2` is roughly 2× per additional variable — 10.3 ms at
`m = 8`, 19.0 ms at `m = 10`, 39.8 ms at `m = 12`. The verifier is flat at **1.7 ms**,
since it holds no polynomial and does `O(m)` group operations.

**The bottleneck that hid all of this.** The first working version measured *flat*
across every `ell` — 246 ms at `ell = 0` against 250 ms at `ell = 6` — which would
have meant the partial-sum machinery bought nothing. Timing the phases separately
found the cause, and it was not the scheme:

| Phase (`m=12`, `ell=6`) | Before | After |
|-------------------------|--------|-------|
| Build `S` tables | 15 ms | 15 ms |
| MSM round messages | **3 ms** | 3 ms |
| **Restrict for the folklore tail** | **221 ms** | **~8 ms** |
| Folklore tail | 7 ms | 7 ms |

The round messages were already ~80× faster than the folklore prover, exactly as
promised. But entering the folklore phase restricted the group polynomial by folding
one variable at a time, `ell` times — each a full pass of scalar multiplications over
a table starting at `2^m` entries. That single step cost more than everything else
combined and erased the entire speedup.

The fix is to do the restriction as a **contraction against the `eq(rho, .)` table**:

```
f(rho, y) = sum over b in {0,1}^|rho| of eq(rho, b) * f(b, y)
```

one MSM of length `2^|rho|` per surviving entry. The scalar-multiplication count is
unchanged; batching them into MSMs lets Pippenger amortize the window precomputation
across each slice instead of paying it per point. The reference implementation does
the same thing (and wraps it in a `"Restrict time"` timer, so its author was watching
this cost too).

No transpose is needed for this contraction, unlike in `computeSTables`. Folding the
first variable repeatedly consumes `rho` in order, which makes the consumed prefix the
low bits *within* each contiguous block, so the slice is already contiguous.
`computeSTables` needs a transpose because there it is the surviving suffix, not the
prefix, that is strided. Getting this backwards was caught immediately by the
cross-path tests.


### 9.3 Merkle Commitment, and the Cost That Justified a Custom Tree

Measured on an Apple M4 Max, one point per leaf (`k = 0`).

| Leaves | `BuildTree` |
|---|---|
| `2^8` | 72.6 us |
| `2^10` | 236 us |
| `2^12` | 679 us |
| `2^14` | 2.62 ms |

Linear in the leaf count, as expected: one leaf hash each plus `n - 1` node hashes.

Openings on a `2^14` tree, with every level retained:

| Openings | Total | Per opening |
|---|---|---|
| 1 | 219 ns | 219 ns |
| 10 | 2.69 us | 269 ns |
| 100 | 25.5 us | 255 ns |

This is the measurement that justifies not adapting gnark-crypto's streaming tree
(section 7.3). There, an opening requires a full rebuild, because leaves are not
retained. So 100 openings of a `2^14` tree would cost `100 x 2.62 ms = 262 ms`
against the **25.5 us** measured here — roughly a **10,000x** gap, and it widens
linearly with the number of queries. WHIR opens many positions of one small tree, so
this is precisely the regime where the streaming design is wrong.

Verification is linear in depth, as it should be:

| Depth | `VerifyMerkleProof` |
|---|---|
| 10 | 763 ns |
| 14 | 964 ns |

End-to-end field commitment, both tiers, rate-1/2 domain:

| `m` | `commitField` |
|---|---|
| 10 | 8.24 ms |
| 12 | 19.5 ms |
| 14 | 46.8 ms |

Tier 1 dominates: it is `rows` MSMs of length `cols`, i.e. `2^m` scalar
multiplications in total, against the tree's `O(sqrt(n))` hashes. The Merkle layer is
not the bottleneck and tuning it would be premature.

## 10. Porting Notes: Rust/Pasta to Go/BLS12-381

The reference implementation is Rust over the Pasta curves. Two things made the
port safe:

- **Two-adicity is identical.** Pallas's `Fq` and BLS12-381's `Fr` both have
  two-adicity **32** (verified by factoring `r - 1`, not by trusting
  documentation). Any smooth domain expressible in the reference is expressible
  here, so the encoding carries over with no change of domain strategy. This was
  the single largest portability risk and it is a non-issue.
- **The indexing convention already agrees.** The Rust code indexes multilinear
  coefficients as `coeffs[b_1 + 2*b_2 + ... + 2^(m-1)*b_m]`, which is the same
  little-endian layout this repository uses. The bit-reversal and butterfly port
  essentially as-is.

Where the reference is *not* usable as a guide, it is called out in
[`plan.md`](../../plan.md): the Rust group-sum-check **verifier** is incomplete
(its final evaluation is commented out and its round loop runs one round short),
so the Go verifier must be written from the paper rather than ported.

## 11. Testing

| File | Coverage |
|------|----------|
| `encode_test.go` | naive cross-check for `m ∈ 1..8` (field) and `1..6` (group) × rates `d - m ∈ {0,1,2}`; group-vs-field-scaled cross-check; degree bound via inverse DFT; domain generator primitivity and distinctness; bit-reversal semantics; input immutability; validation errors |
| `encode_bench_test.go` | butterfly vs naive baseline |
| `groupsumcheck_test.go` | round-trip for `m ∈ {1,2,3,4,6,8,10}` against a direct `f(alpha)`; residual claim equals `eq(alpha,R)*f(R)`; split invariance over all `ell`; MSM-vs-folklore round-message agreement; cross-check against `crypto/sumcheck`; `S`-table telescoping; `eq` table vs `eqPoint` and partition-of-unity; fold-convention pinning; batch inversion; quadratic interpolation; negatives (wrong sum, tampered first/middle/last round, compensating tamper, dropped round, wrong `ell`, wrong `alpha`); `alpha ∈ {0,1}` returning an error rather than panicking; input immutability; validation |
| `groupsumcheck_bench_test.go` | prover at `m ∈ {8,10,12}`, the `ell` sweep, and the verifier |
| `merkle_test.go` | round-trip at every index of trees with `2^0..2^10` leaves × coset dims `k ∈ {0,1,2}`; independent naive recursive root; second-preimage separation; known-answer leaf hash pinning the compressed encoding; wrong leaf / wrong index / tampered sibling / swapped sibling order; wrong proof length, empty path against a deep tree, and truncation at every length; `hashNode` length framing; malformed input; `BuildTree`/`Prove` validation; batch proofs; `Root` returning a copy; determinism; distinct leaves ⇒ distinct roots; `treeDepth` |
| `commit_test.go` | `CommitGroup` round-trip; leaves are a partition of the codeword in order; tier 1 against a direct per-row MSM; the group poly *is* the evaluation table; odd-`m` matrix shape table; determinism; distinct polys and distinct generators ⇒ distinct roots; validation for `CommitGroup`, `CommitField`, `OpenLeaf`; `numVarsOf` |
| `merkle_fuzz_test.go` | `FuzzVerifyMerkleProof`: never panics, never accepts |
| `merkle_bench_test.go` | `BuildTree` at `2^8..2^14`; 1/10/100 openings; verify at two depths; `CommitField` at `m ∈ {10,12,14}` |
| `bridge_test.go` | scalar-field order equality pinned as a regression test; G1 round-trip (generator, scalar multiple, negated); infinity rejected; the offending index named on slice conversion; `Zr` round-trip over `0,1,2,255,256,65535,2^40,r-1` and random; add and mul agreeing across the boundary; all four BLS12-381 curve variants preserving the caller's ID; validation; `padTo32` |
| `eval_test.go` | round-trip for `m ∈ 2..12` asserting *both* acceptance and `sigma == EvaluatePoint(alpha)`; `sigmaPartial` computed two independent ways; leg independence by grafting legs across two commitments; negatives (wrong `sigma`, tampered `sigmaPartial`, tampered row leg, tampered column leg, reversed `alpha`, a proof for another polynomial); `Generators` round-trip, nil receiver, short prefix, infinity, and cross-curve misuse; `EvalAffine` agreeing with the cached path; `checkShape` including the row-count ambiguity; `foldRows` against a direct restriction; group `EvalGroup` round-trip and negatives; leg-2 transcript separator distinctness and rejection of a foreign-header CSP proof; validation |
| `eval_bench_test.go` | `Eval` and `VerifyEval` at `m ∈ {8,10,12,14}`; `EvalGroup` at `m ∈ {8,10,12}`; the mathlib boundary for generators and scalars at `n ∈ {16,64,128,256}`; cached vs uncached across prove/verify |
| `domain_test.go` | `g_(d-1) = g_d^2` and `L_d.Elements[i]^2 = L_(d-1).Elements[i mod 2^(d-1)]` for `d ∈ 2..18` — the unstated gnark-crypto dependency all cross-round index arithmetic rests on; `Squared()` against a freshly built domain |
| `coset_test.go` | the coset **definition** against an independent `EvaluatePoint` (6 configs); `⟨leaf, eq(r)⟩` equals the reduced codeword; two negatives pinning that the coset oracle is **not** a regrouping or a strided read of the flat codeword; `CommitCosets` round-trip and binding; validation |
| `foldconfig_test.go` | `Q(λ=128, ρ=1/8) = 43` under capacity and 86 under Johnson; the `DefaultEll` size model; `Validate` over `ell ∈ [1, m/2]`, odd `m`, bad rate and bad query count; the **drawability floor** — `Queries ≤ NumCosets(m)`, so `DefaultFoldConfig(2)` is rejected and `m = 4` is the smallest default-configurable size (13.10) |
| `queries_test.go` | determinism; dependence on the transcript; distinctness and range including `n=256, q=43`; domain coverage; exhaustion at `q = n`; validation (nil transcript, non-power-of-two `n`, `q > n`) |
| `fold_test.go` | round-trip for `m ∈ {4,6,8,10}` × `ell ∈ 1..m/2`; the reduced polynomial against `foldFirstField` applied `ell` times; **a lying prover** whose fold runs over another polynomial; **a foreign fold with genuine openings** (the test that check 3 is load-bearing, with `verifyFoldRoundsOnly` asserting checks 1–2 pass); every query position corrupted in turn, including the last; 11 soundness negatives (tampered leaf/path, wrong index, swapped and permuted queries, tampered/replaced/truncated reduced poly, tampered and dropped round, dropped query); wrong claim; wrong `alpha`; short coset; end-to-end `Eval`/`EvalGroup` with folding at `m ∈ {8,12}` incl. anti-downgrade in both directions and the prover-chosen query count; the field path's two size constraints under the balanced split (`m ≡ 0 mod 4` **and** `m ≥ 8`), asserting on the *reason* for each rejection since at the `FoldConfig` level both return `ErrInvalidFoldConfig` — note these are checked against `DefaultFoldConfig(rowVars)` directly, so they are unaffected by the split becoming a parameter (13.13), which moves the parity rejection to `ErrInvalidMatrixSplit` only at the setup boundary; the batched check 3 (per-query failures, per-query sensitivity of the combined equation, and the absorb-before-sample ordering that makes the combination sound without relying on `gamma` — see 13.7); validation |
| `fold_bench_test.go` | proof size in **real serialized bytes** vs `ell ∈ 1..6` at `m = 12`; prove and verify at `m ∈ {8,10,12}`, the measurement behind the 10× batching speedup in 13.6 |
| `pcs_test.go` | the facade (13.12): round trip at `m ∈ {8,12,16}` (field) and `{4,6,8,10}` (group); the **two guarantees** — a prover always folds, a verifier refuses an unfolded commitment; wrong value, wrong point, and a foreign proof rejected on both paths; `Verify` vs `VerifyErr` separating misuse from rejection; arity errors incl. `Alpha` sized from the row half; the field path's size constraints at the API boundary, each asserting the sentinel of the check that actually fires (`ErrInvalidMatrixSplit` for an odd row half, `ErrInvalidFoldConfig` for drawability) rather than one sentinel for both; setup validation and nil receivers; the **domain-sizing rule** on both paths, which no functional test can see; **asymmetric splits** at `m ∈ {10,14,18}` — sizes the balanced path rejects outright — with `sigma` checked against `FieldPoly.EvaluatePoint` since a round trip alone cannot see a mis-cut split (13.13) |
| `split_test.go` | the shape invariant `Rows*Cols = 2^M` over every valid split to `M = 20`; the `Validate` / `ValidateForFold` separation, including the odd-row-half splits that must stay committable; degenerate splits and the legacy `M=1, M1=0` shape; `DefaultMatrixSplit` against `matrixShape` as a compatibility pin; and the balanced cut's foldability rule `m mod 4 ∈ {0,3}` (13.10) |

Statement coverage is **90.8%** overall, race-clean. (It moved from 92.6% because the
folding phase added more error paths than the negatives exercise; the soundness-critical
branches are covered, and section 13.7 records which mutations confirm that.)

Three tests carry most of the weight:

- **`TestCrossCheckAgainstSumCheck`** proves the same claim with the general
  `crypto/sumcheck` implementation, as the two-factor product `eq(alpha, .) * f(.)`,
  and requires the sums to agree. The two share no code on the proving path —
  opposite variable order, different round construction, different transcript — so
  agreement is meaningful. The round messages cannot be compared directly, since the
  two absorb different bytes and draw different challenges.
- **`TestRoundMessagesAgreeAcrossPaths`** drives `roundMessageFromTable` and
  `roundMessageFolklore` at the same prior challenges and requires all three
  evaluations to match. Since `ell` is bound into the transcript, two full runs with
  different `ell` diverge after round 1, so this is the only way to compare the two
  paths message by message.
- **`TestFoldFirstSubstitutesFirstVariable`** pins the variable-order convention of
  [section 6.2](#62-variable-order-is-the-opposite-of-cryptosumcheck), which no
  round-trip test can catch.

**Mutation testing.** Eleven semantic mutations were each confirmed to fail the
suite — the tests are not vacuous:

| Mutation | Caught by |
|----------|-----------|
| transpose dropped in `computeSTables` | round-trip, split invariance |
| `S`-descent pairs `b` with `b+1` instead of `b+half` | 5 tests incl. telescoping |
| `H0`/`H1` swapped | round-trip, cross-path |
| folklore `g(2)` uses `3*s11` instead of `4*s11` | 4 tests |
| `foldFirstField` folds the *last* variable | convention test + 5 others |
| verifier carries `g(1)` forward instead of interpolating at `r` | round-trip, split invariance |
| `eqTable` writes the low slice first (the aliasing bug its comment warns about) | 7 tests |
| `eqTable` swaps `alpha` and `1-alpha` between slices | 6 tests |
| verifier checks round consistency only in round 1 | all four negative tests |
| `restrictBoth` contracts a strided slice instead of a contiguous one | 4 tests |
| `restrictBoth` skips folding the `eq` factor | 8 tests |

The last two were added after the `restrictBoth` rewrite described in
[section 9.2](#92-the-split-point-and-a-bottleneck-that-hid-it), to confirm the
faster implementation is still covered.

The decisive test is the **naive cross-check**: for every domain point, the
butterfly output must equal `GroupPoly.EvaluatePoint` along the power curve. The
naive side reuses the independently-tested evaluator from `crypto/sumcheck`, so
the two sides share no code.

`TestEncodeGroupMatchesFieldScaled` is the strongest structural check: with
`g(x) = [s(x)]G`, the group codeword must be the field codeword scaled into G1
pointwise. An error in the group butterfly that a group-only test would reproduce
on both sides shows up here.

Tests were confirmed non-vacuous by **mutation testing** — each of these
independently fails the suite:

| Mutation | Caught by |
|----------|-----------|
| drop the bit-reversal (field) | `TestEncodeFieldOracleMatchesNaive`, `TestEncodeDegreeBound` |
| drop the bit-reversal (group) | `TestEncodeGroupOracleMatchesNaive`, `TestEncodeGroupMatchesFieldScaled` |
| root stride off by one power | all three encode tests |
| reverse the pass order | all three encode tests |
| swap the `+`/`-` butterfly outputs | `TestEncodeFieldOracleMatchesNaive` |
| zero-pad instead of repeat on blow-up | `TestEncodeFieldOracleMatchesNaive` |

### 11.1 Fuzzing `VerifyMerkleProof`

Steps 1 and 2 had no fuzz target, because the package had no entry point consuming
attacker-controlled bytes. `VerifyMerkleProof` is one: the `Siblings`, `Index` and
`NumLeaves` on a `MerkleProof` all come from the prover. `FuzzVerifyMerkleProof`
builds a fixed 8-leaf tree once and lets the fuzzer choose `(index, numLeaves, raw)`,
carving `raw` into digest-sized siblings and deliberately keeping a trailing partial
chunk so mis-sized siblings are reachable. Two properties, both absolute:

- it must never panic, and
- it must never return `true`, since no fuzzer-chosen path opens the real root.

Verified locally at 1.88M executions over 25s with no failures. It is registered in
[`.github/workflows/nightly-fuzz.yml`](../../.github/workflows/nightly-fuzz.yml) as
`titan-merkle-verify-proof`; a target absent from that matrix is only ever exercised
by its seed corpus.

```bash
go test ./token/core/zkatdlog/nogh/v1/crypto/titan/ \
  -run='^$' -fuzz='^FuzzVerifyMerkleProof$' -fuzztime=25s
```

### 11.2 Mutation Testing the Merkle Layer, and What It Found

Thirteen mutations were applied to `merkle.go` and `commit.go`. Twelve were killed.
The two interesting entries are the ones that were not killed on the first pass.

| Mutation | Caught by |
|----------|-----------|
| drop the `0x00` leaf prefix | second-preimage separation, known-answer leaf hash |
| drop the `0x01` node prefix | second-preimage separation, naive-root cross-check |
| swap child order in `hashNode` | swapped-sibling-order test, naive-root cross-check |
| `RawBytes()` (96-byte) for `Bytes()` (48-byte) | known-answer leaf hash |
| sibling index `idx` instead of `idx^1` in `Prove` | round-trip at every index |
| `idx >>= 1` dropped from the `Prove` walk | round-trip at every index |
| `chunkIntoCosets` strides instead of slicing contiguously | leaves-are-a-partition test |
| tier-1 row MSM offsets `gens` by one | direct-MSM cross-check |
| odd-`m` `matrixShape` sends the extra variable to the columns | shape table, `rows·cols` assertion |
| `Root()` returns the live slice, not a copy | `TestRootIsACopy` |
| ragged-`leaves` check dropped | `TestBuildTreeValidation` |
| **proof-length check dropped** | **nothing — a real gap, see below** |
| **per-sibling length check dropped** | **nothing — an equivalent mutant, see below** |

**The proof-length check was load-bearing, and the suite was not testing it.**
Removing `len(proof.Siblings) != treeDepth(proof.NumLeaves)` left the suite green.
The existing `TestVerifyRejectsWrongProofLength` only appeared to cover it: both its
short and its over-long cases are rejected *incidentally*, by the final digest
comparison, so the explicit check was never the thing failing them. Probing for the
gap found a genuine forgery. A one-leaf tree's root **is** its leaf hash, so a prover
holding that leaf can claim it sits at index 0 of an *8*-leaf tree and submit an
**empty** path; with the length check removed the accumulator starts and ends at the
leaf hash and the verifier accepts. Two tests were added —
`TestVerifyRejectsEmptyPathAgainstDeepTree` and
`TestVerifyRejectsTruncatedPathAtEveryLength` — and the mutation is now killed. This
is the one place in the package where mutation testing found a soundness bug rather
than a coverage hole.

**The per-sibling length check is defence-in-depth, not load-bearing — and proving
that took correcting a wrong claim of mine.** Dropping
`len(sib) != DigestSize` also left the suite green, and the first reflex was to treat
it as a second gap. `hashNode` concatenates `prefix‖left‖right` with no length
framing, so a 64-byte input genuinely does collide across splits: a 20/44 split
hashes identically to a 32/32 one. A test was written asserting that this enabled a
forgery. Re-running the sweep showed the mutation **still surviving**, which meant the
test was not reaching it. A direct reachability probe — sibling lengths 0 through 40
at every level of 2-, 4- and 8-leaf trees — accepted **zero** cases both with and
without the check.

The reason is structural: in `VerifyMerkleProof` the left-or-right accumulator is
always a 32-byte SHA-256 output, so only *one* side's length can vary, and changing
the concatenation's split requires a SHA-256 collision. The collision that does exist
needs the attacker to control **both** sides of a single `hashNode` call, which the
verifier's shape never permits. So this is an **equivalent mutant**, not a test gap,
and it is documented as such. The test was rewritten as
`TestHashNodeHasNoLengthFraming`: it pins the absence of framing as a known property
rather than claiming a forgery. The check stays, because it becomes load-bearing the
moment anything feeds `hashNode` variable-length input — batch-proof path
compression, or using a coset digest directly as an internal node.

The distinction matters. A surviving mutant is either a missing test or a mutant that
changes nothing observable, and the two call for opposite responses. Assuming the
first for M12 would have meant writing a test around a forgery that does not exist.

### 11.3 Running It

```bash
go test ./token/core/zkatdlog/nogh/v1/crypto/titan/
go test ./token/core/zkatdlog/nogh/v1/crypto/titan/ -race
go test ./token/core/zkatdlog/nogh/v1/crypto/titan/ -run='^$' -bench=. -benchtime=3x
```

## 12. Evaluation

Sections 6-11 give a commitment that is binding and queryable *by position*. They do
not prove `f(alpha) = sigma`. `Eval` closes that, and it is what makes this a
polynomial commitment scheme rather than a vector commitment with extra structure.

### 12.1 Two legs, and why neither is optional

`alpha` splits across the matrix of [section 7.1](#71-tier-1-rows-to-a-group-multilinear).
The proof has two legs, joined at a single group element:

    sigmaPartial = G(alphaRow)                       // a group element

    leg 1 (alphaRow):  group sum-check on G, asserting the sum sigmaPartial
    leg 2 (alphaCol):  CSP linear form, proving the folded row vector opens
                       to sigma under the commitment sigmaPartial

Each leg alone is worthless:

- **Leg 1 alone** shows `sigmaPartial` is consistent with the committed oracle, but
  says nothing about `alphaCol` and so nothing about `sigma`.
- **Leg 2 alone** proves an evaluation under a commitment that nobody has tied to the
  commitment the verifier holds. A prover would be free to invent `sigmaPartial`.

`sigmaPartial` is the **only** element both legs touch, and therefore the only thing
binding them. `TestEvalLegIndependence` grafts a valid leg from one polynomial's proof
onto another's and requires rejection — that is the test that catches "the two legs
are not actually tied together", which is the subtle way a two-leg proof goes unsound.

### 12.2 Why one element can be both an evaluation and a commitment

This is the pivot of the construction, and it is worth stating explicitly because it
looks like a coincidence and is not.

Tier 1 set `G_j = MSM(gens, row_j)`. Taking the `eq(alphaRow, .)` combination of the
rows therefore **commutes** with the MSM:

    sigmaPartial = sum_j eq_j * MSM(gens, row_j)
                 = MSM(gens, sum_j eq_j * row_j)
                 = MSM(gens, a)            where a = fold(rows, alphaRow)

Read left to right it is `G(alphaRow)`, an *evaluation* of the group multilinear —
which is what leg 1 proves. Read right to left it is the Pedersen *commitment* to the
folded row vector `a` — which is what leg 2 opens. One group element, two readings,
and the proof is sound precisely because they coincide.

**Linearity of the MSM in the message is the entire reason.** Any row commitment that
is not linear in the message breaks this and the two legs stop meeting. That is a
constraint on tier 1, not a free choice: it is why hiding tier 1 (adding a blinding
term) is a change that has to be made carefully rather than dropped in.

`TestEvalSigmaPartialIsTheFoldedCommitment` computes `sigmaPartial` both ways —
`msm(hint.G, eqTable(alphaRow))` and `msm(gens[:NumCols], foldRows(...))` — and
requires them equal, pinning the identity rather than the code path.

### 12.3 Leg 2 is CSP, not a Bulletproof

The Rust reference uses a Bulletproof inner-product argument. This port uses the
compressed sigma-protocol already in the tree (`crypto/rp/csp`), because leg 2's
linear form is `eq(alphaCol, .)`, which the **verifier computes itself** from the
public `alphaCol`. There is no secret vector to hide, so the Bulletproof machinery
buys nothing over CSP — and it removes an entire protocol from the port.

| CSP statement field | Titan leg 2 |
|---|---|
| `Commitment` | `sigmaPartial` |
| `Generators` | the tier-1 generators `gens[:NumCols]` |
| `LinearForm` | `eq(alphaCol, .)` — public, verifier-recomputable |
| `Value` | `sigma`, the claimed `f(alpha)` |
| witness | the folded row vector `a` |

Prover and verifier build the statement through **one shared function**
(`columnStatement`), so there is a single conversion path and no possibility of the
two sides disagreeing on an encoding.

Leg 2 runs under its own transcript header, `TitanEvalColumnLeg-v1`, distinct from
leg 1's `TitanGroupSumCheck-v1` and from anything `rp.go` uses. A CSP proof produced
for a range proof therefore cannot be replayed as a Titan column leg, nor a column
leg as a row leg.

### 12.4 The variable split is the opposite way round from the reference

    alphaCol = alpha[:m/2]     // the FIRST variables index columns
    alphaRow = alpha[m/2:]     // the LAST variables index rows

This is inverted relative to the Rust reference, and it is **verified by probe, not
assumed** — confirmed for `m = 2,3,4,5` against an independently computed `f(alpha)`.

The reason follows from the layout. Row `j` is the contiguous block
`f[j*cols : (j+1)*cols]` (section 7.1, no transpose), so the row index occupies the
**high** bits of the flat index; and in the little-endian convention this package
shares with `crypto/sumcheck`, the high bits are the **last** variables.

**Getting this backwards is the worst bug available here**, because `eq` factorizes
over *any* split of the variables. Both assignments produce a completely
self-consistent proof — it simply proves a claim about a different polynomial. No
round-trip test can see it. It fails only against an independently computed
`f(alpha)`, which is why `TestEvalRoundTripAndMatchesDirectEvaluation` asserts *two*
things: that verification accepts, **and** that `sigma` equals
`FieldPoly.EvaluatePoint(alpha)`. The second assertion is the one that matters.

`EvaluatePoint` is the valid cross-check because it takes its argument in **table
order**, matching the `alpha` convention here. (`EvaluateOpening` takes folding
order; the two differ only in argument order, which is exactly the kind of difference
that produces a plausible wrong answer.)

### 12.5 The mathlib boundary, and why the cache is shared

CSP is written against mathlib (`*mathlib.G1`, `*mathlib.Zr`); this package is
gnark-crypto (`bls12381.G1Affine`, `fr.Element`). `bridge.go` is the single place
that conversion happens, so the cost has one home and one place to optimize.

The two representations are compatible, verified rather than assumed:
`mathlib.BLS12_381_BBS_GURVY`'s group order is bit-identical to `fr.Modulus()`, G1
round-trips through the 48-byte compressed form, and `Zr` through 32-byte big-endian.
`TestBridgeScalarFieldsAreIdentical` pins the order equality as a regression test,
since the whole design rests on it. (A first comparison of the two *printed* orders
appears to show a mismatch — that is mathlib printing hex against gnark printing
decimal. The false alarm is easy to repeat, so it is recorded here.)

Points cross **one way only**. CSP proofs are verified in mathlib, so no group
element needs to come back; scalars do, which is why `toFieldElement` exists and has
no point-valued counterpart.

**Conversion costs ~35us per G1 point**, because every mathlib G1 constructor routes
through `SetBytes`, which performs a subgroup check. There is no cheap path; the cost
is structural to mathlib.

This is why generators are cached in a `Generators` value, converted once and reused.
Measured on an Apple M4 Max, `-benchtime=1s`:

| m | gens | prove cached | prove uncached | verify cached | verify uncached |
|---|---|---|---|---|---|
| 10 | 32 | 7.88ms | 9.01ms | 0.94ms | 2.03ms |
| 12 | 64 | 12.58ms | 14.92ms | 1.14ms | 3.41ms |
| 14 | 128 | 22.26ms | 26.99ms | 1.42ms | 6.04ms |

**The cache matters overwhelmingly on the verifier, not the prover.** At `m = 14` it
is a 4.3x speedup on verification (6.04ms to 1.42ms), where the boundary is **77%**
of the uncached verifier's work; on the prover the same conversion is only 18%,
because proving does enough other work to absorb it.

This overturned the original plan, which put the cache on `FieldOpeningHint` —
prover-side state. The measurement says the verifier is the side dominated by the
boundary, and a verifier never holds an opening hint. So `Generators` is a
first-class type that **both** sides construct and hold:

```go
gens := ...                                        // []bls12381.G1Affine, from setup
cached, err := titan.NewGenerators(curve, gens)    // convert once
```

`Generators` is bound to the curve it was converted for, and `prefix` rejects a
mismatch. That guard earns its place: mathlib has four BLS12-381 entries
(`BLS12_381`, `BLS12_381_BBS`, `BLS12_381_GURVY`, `BLS12_381_BBS_GURVY`) that share
the group and the scalar field but carry **distinct curve IDs**, and CSP's
`validateG1Slice` rejects any element whose ID differs from the statement's. Without
the guard, a cache built on one variant and used on another fails deep inside CSP
validation with a message about element curves — nothing that points at the actual
mistake. The bridge therefore converts onto the **caller's** curve, never a
hardcoded one.

### 12.6 `m` is not recoverable from a `Commitment`

The verifier takes `m` from `len(alpha)`, which is public input, and checks the
commitment for consistency with it (`checkShape`). It cannot derive `m` from the
commitment, and this is a genuine limitation rather than an oversight.

`Commitment` carries `NumVars = log2(rows)` only. Every row count is produced by
**two** different `m`:

    rows = 2   <-  m in {1, 2}
    rows = 4   <-  m in {3, 4}
    ...
    rows = 256 <-  m in {15, 16}

They differ only in the column count, which the commitment does not carry. An earlier
version of the code claimed to resolve the ambiguity by checking the row count; that
check is **vacuous**, since both candidates reproduce it, and a test over
`m = 1..16` caught it. `TestCheckShape` now pins the ambiguity so the claim cannot be
made again.

A consequence worth knowing: an `alpha` one coordinate short is not always caught by
the shape check — for `m = 4` and `m = 3` the row count is the same, so a 3-coordinate
`alpha` passes `checkShape` and is rejected downstream by leg 1 instead. The error is
correct, but it names the round check rather than the length.

Putting the column count into `Commitment` would remove the ambiguity. That is a wire
format change, and it is not made here.

### 12.7 The group case has one leg, and that is correct

`EvalGroup` is **leg 1 only**. This reads like a missing half and is not: a group
polynomial's evaluation already *is* a group element, so there is no field value to
bind and no Pedersen tier to open. There is nothing for a second leg to prove.

### 12.8 What is still open

This section previously read "**neither verifier is sound against a prover who lies
about the oracle**" — both reduced the claim to a residual sum-check claim at a random
point and stopped there. **[Section 13](#13-folding-closing-the-claim) closes that**, via
`ℓ` folding rounds, the reduced polynomial sent in plain, and `Q` consistency queries
against a committed coset oracle.

The distinction that remains is which constructor was used. A commitment from
`CommitGroupWithFold`/`CommitFieldWithFold` carries a coset oracle, and its verifier
*requires* a folding phase; a commitment from the plain `commitGroup`/`commitField` stages has
`Cosets == nil`, and for those a `nil` error still means the reduction holds, not that
the oracle was checked. Both godocs say so at the function.

Also still open, by design: zero-knowledge (CSP here is the non-ZK variant, tier 1 is
non-hiding Pedersen, and leg 2's witness is the folded polynomial); `Setup`; batched
`Eval` at several points; and the `O(n^(1/4))` variant, which needs a second folding
layer over the *generator* oracle and is not what `k` controls.

### 12.9 Mutation testing the two legs, and the gap it found

Nine semantic mutations were applied to `eval.go`. Seven were caught; the two
survivors are worth recording individually, because they are not the same kind of
result.

| Mutation | Caught by |
|----------|-----------|
| `alphaCol`/`alphaRow` swapped | round-trip, `sigmaPartial` cross-check, `foldRows`, validation |
| verifier's leg-2 linear form uses `eq(alphaRow, .)` | round-trip, `EvalAffine` agreement, validation |
| `sigma` computed over row 0 instead of the folded vector | round-trip, `EvalAffine` agreement, validation |
| leg 1's error ignored | tampered `sigmaPartial`, tampered row leg, leg independence |
| leg 2 reuses leg 1's domain separator | **nothing — see below** |
| prover binds leg 2 to a recomputed MSM rather than leg 1's output | **nothing — equivalent mutant, see below** |

**The separator mutation was a real gap.** Replacing `evalTranscriptHeader` with
`DomainSeparator` left the entire suite green. Nothing observable changes when both
legs share a separator — proofs still verify — but the separation is exactly what
stops a CSP proof produced elsewhere in the tree from being replayed as a Titan
column leg. No round-trip or negative test can reach it, because both sides of the
protocol move together. It needed a direct assertion, so
`TestEvalTranscriptHeaderIsDistinct` pins the value and
`TestEvalColumnLegRejectsForeignTranscript` proves the header does real work: a CSP
proof over the *identical* statement and witness but a different header must not
verify, while the honest header must.

**The other survivor is an equivalent mutant, not a gap.** Having the prover
recompute `MSM(gens, a)` instead of using the `sigmaPartial` that leg 1 returned
produces the same group element — that *is* the identity of
[section 12.2](#122-why-one-element-can-be-both-an-evaluation-and-a-commitment), and
`TestEvalSigmaPartialIsTheFoldedCommitment` asserts precisely that the two agree. No
test can distinguish them, and none should. The code takes the value from leg 1
anyway, since deriving it twice creates two places that could later drift apart while
the proof still verifies; that is a maintainability argument, not a soundness one, and
it is not a claim any test is failing to check.

### 12.10 API

| Function | Input | Output | Used for |
|----------|-------|--------|----------|
| `NewGenerators(curve, gens)` | `[]bls12381.G1Affine` | `*Generators` | convert the generators once; hold on both sides |
| `(*FieldOpeningHint).Eval(curve, gens, alpha)` | cached generators, point | `*EvalProof`, `sigma` | prove `f(alpha) = sigma` |
| `VerifyEval(curve, c, gens, alpha, sigma, proof)` | commitment + public data | residual opening | check that claim (see 12.8) |
| `(*GroupOpeningHint).EvalGroup(curve, alpha)` | point | `*GroupEvalProof`, `sigma` | prove `G(alpha) = sigma`, leg 1 only |
| `VerifyEvalGroup(curve, c, alpha, sigma, proof)` | commitment + public data | residual opening | check that claim |
| `EvalAffine` / `VerifyEvalAffine` | raw `[]bls12381.G1Affine` | as above | one-off calls; converts per call |

```go
cached, err := titan.NewGenerators(curve, gens)
if err != nil {
    return errors.Wrap(err, "failed to convert the generators")
}

proof, sigma, err := fhint.Eval(curve, cached, alpha)
if err != nil {
    return errors.Wrap(err, "failed to prove the evaluation")
}

opening, err := titan.VerifyEval(curve, c, cached, alpha, sigma, proof)
if err != nil {
    return errors.Wrap(err, "evaluation proof did not verify")
}
// opening is the residual claim; the caller MUST still close it (12.8).
```

`EvalAffine` and `VerifyEvalAffine` take generators in affine form and convert
internally. They exist for one-off calls and tests; anything in a loop, and **any
verifier**, should hold a `*Generators` instead — see the table in 12.5 for what the
difference costs.

Both verifiers return the residual `*GroupSumCheckOpening` rather than a bare error,
so the caller has the point and value the oracle queries must be made at.

## 13. Folding: Closing the Claim

Sections 6.5 and 12.8 named the gap: both verifiers reduced `f̃(α) = σ` to a residual
claim about a polynomial nobody had queried, so a prover free to choose the residual
value could prove any sum. This section is what closes it.

The shape, following WHIR: run `ℓ` rounds of folding on the group sum-check, send the
reduced polynomial's `2^(m−ℓ)` coefficients **in plain**, test the reduced claim
directly as a dot product against `eq` evaluations, and tie the whole thing to the
committed oracle with `Q` consistency queries against coset openings.

### 13.1 What a coset is, and why the flat codeword is the wrong object

A coset for a folded-domain point `y` is, by definition

    { f(b, y, y², y⁴, …) : b ∈ {0,1}^ℓ }

— boolean in the first `ℓ` coordinates, powers of `y` in the remaining `m−ℓ`.

The natural-looking shortcut is to reuse `EncodeGroupOracle`, which runs one FFT over
all of `L` and gives `codeword[i] = f̂(x) = f̃(x, x², x⁴, …)` at `x = ω^i`. The set
`{x : x^(2^ℓ) = y}` sits at strided indices `{y + b·N/2^ℓ}`, and it **is** the fold's
dependency closure — so it is easy to believe those entries are the coset. They are
not. Every entry there is a full power-curve point; none of them is
`f(b, powers(y))` with `b` boolean. Measured, three attempts to match the strided set
against the definition scored 0/512, 1/512 and 1/512 — the stray matches being
coincidences at `b = 0`.

So the coset oracle is built **per slice**: for each `b ∈ {0,1}^ℓ`, encode the slice
`f(b, ·)` over the folded domain `L^(2^ℓ)`, then gather index `y` across the `2^ℓ`
resulting codewords. Slice `b` is `f[b + i·2^ℓ]`, because the first `ℓ` variables are
the **low** index bits. Total work is the same as one big FFT — `2^ℓ` FFTs of size
`2^(m+logRate−ℓ)`.

`TestEncodeCosetsGivesSemanticCosets` pins the definition directly, against an
independent `EvaluatePoint`. Two further tests pin the negative, because this is the
kind of error a round-trip cannot see (a wrong-but-consistent layout verifies against
itself): `TestEncodeCosetsIsNotARegroupingOfTheFlatCodeword` asserts the two
constructions are not permutations of each other, and
`TestEncodeCosetsStridedSetIsNotTheCoset` asserts it over the specific wrong answer.

### 13.2 One primitive serves both checks

With coset dimension `k = ℓ`, the payoff identity is

    ⟨leaf[y], eq(r)⟩  ==  EncodeGroupOracle(reduced)[y]

where `reduced` is `f` with its first `ℓ` variables bound to the round challenges `r`.
Verified exact on m = 6, 8, 10, 12 and pinned by `TestFoldCosetMatchesReducedCodeword`.

This is why `k = ℓ` is the right choice rather than an arbitrary one: a consistency
query costs the verifier a **single `eq` dot product**, not `ℓ` fold rounds. The same
primitive tests the final reduced claim. One operation, two jobs.

It also fixes the folding direction. `foldFirstGroup` substitutes the **first**
variable, matching the coset slice indexing; reversing the `eq` order is a mutation
the suite catches (`TestFoldRoundTrip`, `TestFoldRejectsAWrongAlpha`,
`TestFoldRejectsALyingProver` all fail).

### 13.3 The three verifier checks, and which one closes the gap

`verifyFold` makes three checks, and all three are load-bearing:

| Check | What it tests | Fails without it |
|---|---|---|
| 1 | each round message sums to the previous claim | `ErrFoldRoundMismatch` |
| 2 | `⟨Reduced, eq⟩` equals the residual claim | `ErrReducedClaimMismatch` |
| 3 | each sampled coset is under the root **and** folds to the reduced codeword | `ErrCosetOpeningInvalid` |

**Check 3 is the one step 13 exists for.** Checks 1 and 2 are internal consistency: a
prover who folds an entirely different polynomial `f'` and sends `f'`'s reduced
coefficients satisfies both. Only check 3 ties the folding to the committed oracle.

That distinction is not hypothetical — it was found by mutation. Deleting check 3 left
the whole suite green, because the test named `TestFoldRejectsALyingProver` was in fact
being caught by the Merkle check, not by the fold comparison. Closing it needed a
strictly harder attack: `TestFoldRejectsAForeignFoldWithGenuineOpenings` substitutes
*genuine* openings of the *real* committed oracle into a proof folded over `f'`, so the
Merkle paths verify, checks 1 and 2 pass (asserted explicitly via
`verifyFoldRoundsOnly`), and check 3 is the only thing that can reject. See
section 13.7.

### 13.4 Soundness, and what is conjectured

Per-query soundness error is the proximity parameter. Under the **capacity** bound it
is `ρ`; under **Johnson** it is `√ρ`. So

    Q = ⌈λ / log₂(1/ρ)⌉

At `λ = 128`, `ρ = 1/8`: **Q = 43** under capacity, 86 under Johnson. (43, not 42 — 42
gives 126 bits, and `TestFoldConfigQueryCount` pins the arithmetic.)

**Capacity is conjectured; Johnson is what is provable.** `SoundnessRegime`'s godoc
says so at the type, not only here, because a caller choosing `Capacity` is choosing a
conjecture and should not have to read the docs to find that out. `Johnson` is
selectable for anyone who wants only proven bounds, at 2× the queries.

The other soundness terms are negligible by comparison and do not affect `Q`: the
folding rounds' Schwartz–Zippel error is ~2^−252, and `|L|/|F|` is ~2^−240. The query
term dominates, which is why the formula above is the whole story.

### 13.5 `ℓ` is chosen by size, and the choice was measured

Proof size trades off in `ℓ`: larger `ℓ` means fewer reduced coefficients
(`2^(m−ℓ)`) but larger cosets (`Q·2^ℓ` points). `DefaultEll` picks the minimum.

Rather than trust the size model it was derived from, the optimum was measured on real
serialized bytes at m = 12 (`BenchmarkFoldProofSize`, counting compressed G1 plus
digests):

| ℓ | 1 | 2 | **3** | 4 | 5 | 6 |
|---|---|---|---|---|---|---|
| bytes | 122184 | 75928 | **58376** | 61368 | 87016 | 148760 |

The minimum is at `ℓ = 3`, and `DefaultEll(12)` returns 3. The user's suggested
starting point of `ℓ = m/2 − 1` is 5 at m = 12, which measures 49% larger — so the
size-optimal rule earns its place.

`ℓ` must stay in `[1, m/2]`: `Q` cosets are opened, and beyond `m/2` the coset points
dominate everything saved.

### 13.6 The verifier must not encode the whole domain

The first working version had the verifier call `EncodeGroupOracle(proof.Reduced,
folded)` — the full folded codeword — to compare `Q` positions of it. That is
correct and badly wrong at once:

| m | verify (full encode) | verify (per-point) | prove |
|---|---|---|---|
| 8 | 177ms | 19.1ms | 11.1ms |
| 10 | 402ms | 26.2ms | 65.9ms |
| 12 | 901ms | 37.7ms | 297ms |

The verifier was **15× slower than its own prover** at m = 8, and linear in the
polynomial size — the opposite of the point of a polynomial commitment scheme.
Profiling attributed 80% to `mulGLV` with `EncodeGroupOracle` at 84% cumulative.

`EncodeGroupOracleAt(p, dom, i)` evaluates the codeword at **one** index, building the
power curve by `m` squarings from `dom.Elements[i]` and taking `⟨p, eq(curve)⟩`. The
verifier now calls it `Q` times instead of encoding `2^(m−ℓ+logRate)` points. At m = 12
that is 24× faster, and the growth changes character: 19→26→38ms is the `Q·2^ℓ` MSM
work plus Merkle paths, no longer the codeword.

`TestEncodeGroupOracleAtMatchesFullEncoding` pins the equivalence against the butterfly
at every index across six configurations, so the fast path cannot drift from the slow
one. The full-domain encoder is still the right tool when most of the codeword is
wanted — the prover uses it.

One correction to the attribution above, since it was stated wrongly once: the residual
19→26→38ms growth is dominated by **`Q·2^(m−ℓ)`**, the `Q` MSMs against the reduced
polynomial, *not* by `Q·2^ℓ` plus Merkle paths. The reduced polynomial has `2^(m−ℓ)`
coefficients and each of the `Q` queries runs a full-length MSM against it, so that term
is far larger than the coset folds. Getting the attribution right is what identified the
batching below as worthwhile.

#### Batching check 3

Check 3 compares `Q` pairs of values. Both sides collapse into one equation, and the two
sides batch by **structurally opposite** mechanisms:

| side | what is shared | what is combined | effect |
|---|---|---|---|
| reduced codeword | the point vector `Reduced` | the `eq` **scalar** vectors, summed with `γ^j` | `Q·2^(m−ℓ)` → `2^(m−ℓ)` group ops — asymptotic |
| opened cosets | the scalar vector `eq(r)` | the **points**, concatenated | same point count, one length-`Q·2^ℓ` Pippenger instead of `Q` length-`2^ℓ` MSMs — constant factor |

The codeword side wins asymptotically because the points are fixed and only scalars vary,
so `Q` MSMs become one. The coset side cannot win that way — every query has different
points — but a single long MSM lets Pippenger bucket properly, where `Q` separate
length-8 MSMs are far too short for bucketing to pay. The combined check is

    ⟨concat(leaf_1..leaf_Q), γ^j ⊗ eq(r)⟩  ==  ⟨Reduced, Σ_j γ^j·eq(curve_j)⟩

with the same `γ^j` ladder on both sides, computed once — deriving it twice would be two
places for the sides to drift apart.

Measured, `BenchmarkFoldVerify`, `-benchtime=3x`:

| m/ℓ | per-query | batched | speedup |
|---|---|---|---|
| 8/1 | 19.9ms | 1.60ms | **12.4×** |
| 10/2 | 26.2ms | 2.41ms | **10.9×** |
| 12/3 | 38.2ms | 3.98ms | **9.6×** |

Against the original full-encode verifier at m = 12 that is **901ms → 3.98ms, 226×**. The
verifier is now roughly 75× faster than its own prover rather than 15× slower.

Batching does **not** remove the `Q·2^(m−ℓ)` plaintext term from the proof itself —
`Reduced` is still sent in full. Recursing instead of sending it in plain is WHIR proper,
and is what would take the verifier to polylog; see 13.14.

### 13.7 Mutation testing the folding phase

Sixteen mutations were applied across the per-query and batched versions. Two real gaps
were found; both are now closed, and each was confirmed by re-running the mutation. Three
survivors turned out to be equivalent mutants, one of which was initially misclassified as
a third gap — see "The unweighted-sum survivor" below.

**Gap 1 — the check that makes step 13 sound was untested.** Covered in 13.3: deleting
check 3 left the suite green. The lesson is that a soundness test can pass for the
wrong reason, and only mutation reveals which reason.

**Gap 2 — the verifier could check fewer queries than it sampled.** Making the verifier
sample `Q−1` indices left the suite green. The reason is subtle and worth recording:
`sampleQueryIndices` draws sequentially, so sampling `Q−1` returns exactly the first
`Q−1` of the honest `Q` list. A truncated verifier loop therefore agrees with the
honest prover on every query it looks at. The existing `len(proof.Queries) != cfg.Queries`
guard does not help — that bounds what the prover **sends**, and this is about what the
verifier **reads**. Every other negative test tampered with query `[0]`, which any
truncation still checks.

`TestFoldChecksEveryQueryNotJustTheFirst` corrupts each query position in turn,
including the last, and now fails the mutation. The number of queries actually checked
is the soundness parameter, and losing one silently costs bits no honest-path test can
see.

**Two equivalent mutants**, recorded rather than papered over:

- Encoding at `q.Index` instead of the locally sampled `idx`. The preceding
  `q.Index != idx` guard makes these provably the same value, so no test can
  distinguish them. `idx` is still the better code, because it does not depend on a
  guard several lines above staying where it is.
- Deleting the `cfg.CosetSize()` length check. A leaf is hashed whole, so a leaf of the
  wrong length gives a different digest and `VerifyMerkleProof` rejects it first —
  verified directly. The check is defence in depth that names the malformed opening,
  not a soundness gate; `TestFoldRejectsAShortCoset`'s godoc says so explicitly, since a
  test whose name implies it pins a check it does not pin is worse than no test.

Mutations correctly caught: skipping the Merkle check (5 tests), reversing the `eq`
order (3), dropping the reduced-claim check, dropping the round-sum check, dropping a
round, swapping two queries, tampering with the reduced polynomial, and — confirming
the transcript threading is load-bearing rather than cosmetic — having the verifier use
an unchained transcript.

**The unweighted-sum survivor, and why it is not a gap.** Setting every `γ` power to 1 —
turning the batched combination into a plain unweighted sum — leaves the suite green. An
unweighted sum normally *is* unsound: overshoot one query by δ, undershoot another by δ,
and the totals agree while both queries are wrong. So this was first recorded as a real
gap, and that was wrong. The cancelling attack is unconstructible here, for two
independent reasons:

1. **The cosets cannot host it.** A leaf is hashed whole, so any tampered coset fails
   `VerifyMerkleProof` before the batched equation is evaluated.
2. **`Reduced` cannot host it either**, even though it is sent in plain and bound by no
   root. It is absorbed into the transcript **before** the query indices are sampled. A
   perturbation `d` must satisfy `⟨d, Σ_j eq(curve_j)⟩ = 0` to survive the unweighted sum —
   but changing `Reduced` reshuffles the indices `j`, and therefore the very vectors `d`
   must be orthogonal to. The attacker needs a fixed point of the hash.

Reason 2 was established by construction, not by argument. `d` supported on three
coordinates and orthogonal to both `eqCur` (so check 2 stays silent) and `Σ_j eq(curve_j)`
exists and was built — the 3×3 cross product of the two constraint rows. Applying it made
the verifier sample `[426 459 108 105]` instead of the indices the prover had opened, and
the index guard rejected before the equation ran.

So `γ` is **defence in depth, and the absorb-before-sample ordering is what is
load-bearing**. That makes the ordering the thing worth pinning, and
`TestFoldReducedIsAbsorbedBeforeQueriesAreSampled` pins it: it fails if `Reduced` is
absorbed after `sampleQueryIndices`. If someone ever moves that absorption — to tidy the
transcript, or to let the prover stream — the unweighted-sum mutation stops being
equivalent and becomes a real break, and `γ` becomes the only thing standing in the way.

Four tests in this work passed for the wrong reason before being fixed, every one of them
because `VerifyMerkleProof` rejects a tampered leaf before the check under test runs. That
is the dominant failure mode of negative testing in this package, and the reason each
negative test's godoc now names which check does the rejecting.


### 13.8 Transcript threading, and why not a fresh transcript

`ProveGroupEval`/`VerifyGroupEval` built their transcript as a local and dropped it, and
`csp.Transcript.fsState` is unexported, so the folding phase could not continue the same
Fiat–Shamir chain. Both now have `*WithTranscript` variants that accept a
`*csp.Transcript` and mutate it in place; `Absorb` already mutates, so this is the
natural shape. The original functions became thin wrappers, so **no existing call site
changed**.

The rejected alternative was a fresh WHIR transcript absorbing the sum-check's public
outputs. Its soundness would depend on that absorb list being *complete*, and an
omission is a silent failure every honest test still passes — the same shape as the
`evalTranscriptHeader` gap found in step 12's mutation pass (section 12.9). Threading
gives one unbroken chain with nothing to enumerate.

One ordering detail matters: the prover absorbs **every reduced coefficient before
sampling query indices**. Sampling first would let the prover see which cosets it had
to fix up.

### 13.9 The query count lives in the commitment, not the proof

A soundness hole I introduced and caught while wiring the verifier: the first version
derived the query count as `len(proof.Fold.Queries)`. That lets the prover choose its own
security level — send one query, have the verifier accept it as the full set, and the
proof has a few bits of soundness while verifying cleanly.

`CosetCommitment` therefore carries `Fold FoldConfig`, and the verifier reads
`c.Cosets.Fold`. The count is a security parameter, and a security parameter the prover
chooses is not one. `TestEvalGroupRejectsAReducedQueryCount` pins it.

The same reasoning drives the **anti-downgrade check in both directions**: if
`c.Cosets != nil` a fold proof is *required*, and if `c.Cosets == nil` a fold proof is
*rejected*. Without the first, a prover strips the folding phase and gets the old
unsound behaviour from a commitment that promised better; without the second, a fold
proof appears to add assurance against a root that never committed to cosets.

### 13.10 The field path's size constraints, and which are real

Two independent constraints, which is why they are worth separating. Since step 6 made
the matrix split a parameter (13.13), only the second is a property of the *scheme* —
the first is a property of the **balanced split**, and moving the cut removes it.

**Parity.** Folding attaches to leg 1, which runs over the row variables — so the
constraint "`m` even" from the folding spec applies to `rowVars = M − M1`, not to `m`.
Under the balanced split `M1 = m/2` that makes the foldable sizes exactly
`m ≡ 0 or 3 (mod 4)`:

| `m mod 4` | `rowVars = m − m/2` | foldable? |
|---|---|---|
| 0 | `m/2`, even | yes — 4, 8, 12, … |
| 3 | `(m+1)/2`, even | yes — 3, 7, 11, … |
| 1 | `(m+1)/2`, odd | no — 5, 9, 13, … |
| 2 | `m/2`, odd | no — 6, 10, 14, … |

So the familiar "`m` must be a multiple of 4" is only half the rule, and the odd sizes
3, 7, 11 were never blocked by parity at all — they are blocked by drawability below.
An assertion written while adding `split_test.go` claimed "foldable iff `m % 4 == 0`"
and failed at `m = 3`; the two constraints are easy to conflate because on the sizes
anyone actually uses they coincide.

With the split free, the condition becomes one on `M1` rather than on `m`, and every
`m > 2` has a foldable cut: `m = 10` at `M1 = 4` has a row half of 6, and `m = 18` at
`M1 = 8` (the Rust reference's own value) has 10.

**Drawability.** The `Q` consistency queries are *distinct* indices into the folded
domain, which holds `2^(rowVars − ℓ + logRate)` cosets. At m = 4, `rowVars = 2` gives 16
cosets, and the default `Q = 43` cannot be drawn from them. So the smallest usable
field-path size is **m = 8**, not m = 4.

The second constraint was found by the PCS facade (section 13.12) and is a real defect
it exposed, not a limitation of the facade: `DefaultFoldConfig(2)` was returning
`Queries = 43` happily, and the failure surfaced from inside `proveFold` as
"cannot draw 43 distinct indices from 16" — *after* the commitment had been built and the
folding rounds absorbed into the transcript. `FoldConfig.Validate` now checks
`Queries ≤ NumCosets(m)`, so the configuration is rejected where it is chosen rather than
where it is used. m = 2 is the only even count affected on the group path, since that path
sizes its domain by `m` itself and already has 64 cosets at m = 4.

Both boundaries are pinned by `TestFieldFoldRequiresMDivisibleByFour`, which asserts on
the *reason* for each rejection rather than only on the sentinel — both return
`ErrInvalidFoldConfig`, so a test checking the sentinel alone would not notice the two
swapping over. `TestDefaultFoldConfigHasAFloor` pins the m = 2 boundary and that the
check is on drawability rather than on `m`: at `Q = 16`, `rowVars = 2` configures fine.

### 13.11 API

    type SoundnessRegime int   // Capacity (conjectured) | Johnson (provable)

    type FoldConfig struct { Ell, LogRate, Queries int; Regime SoundnessRegime }
    func DefaultFoldConfig(m int) FoldConfig
    func DefaultEll(m, logRate, q int) int
    func QueryCount(logRate int, regime SoundnessRegime, lambda int) int
    func (c FoldConfig) Validate(m int) error
    func (c FoldConfig) CosetSize() int

    type CosetCommitment struct { Root []byte; NumVars, Ell, LogDomain int; Fold FoldConfig }
    type CosetOpeningHint struct { ... }
    func EncodeCosets(p sumcheck.GroupPoly, dom *Domain, ell int) ([][]bls12381.G1Affine, *Domain, error)
    func CommitCosets(p sumcheck.GroupPoly, dom *Domain, ell int) (*CosetCommitment, *CosetOpeningHint, error)
    func (h *CosetOpeningHint) OpenCoset(y int) ([]bls12381.G1Affine, *MerkleProof, error)

    type CosetOpening struct { Index int; Leaf []bls12381.G1Affine; Path *MerkleProof }
    type FoldProof struct {
        Rounds  [][3]bls12381.G1Affine
        Reduced sumcheck.GroupPoly
        Queries []*CosetOpening
    }

    func CommitGroupWithFold(G sumcheck.GroupPoly, dom *Domain, k int, cfg FoldConfig) (*Commitment, *GroupOpeningHint, error)
    func CommitFieldWithFold(f sumcheck.FieldPoly, gens []bls12381.G1Affine, dom *Domain, k int, cfg FoldConfig) (*Commitment, *FieldOpeningHint, error)
    func CommitFieldWithFoldAt(f sumcheck.FieldPoly, gens []bls12381.G1Affine, dom *Domain, k int, cfg FoldConfig, split Split) (*Commitment, *FieldOpeningHint, error)

    func EncodeGroupOracleAt(p sumcheck.GroupPoly, dom *Domain, i int) (bls12381.G1Affine, error)
    func VerifyBatch(root []byte, leaves [][]bls12381.G1Affine, proof *BatchProof) bool

    func ProveGroupEvalWithTranscript(tr *csp.Transcript, ...) (...)
    func VerifyGroupEvalWithTranscript(tr *csp.Transcript, ...) (...)

`EvalProof` and `GroupEvalProof` each gain `Fold *FoldProof`. `CommitGroupWithFold` and
`CommitFieldWithFold` are the only commitment constructors in the public API: the plain
`commitGroup`/`commitField` stages, which produce a commitment whose `Cosets` is nil and
therefore reduce a claim without closing it, are **unexported**. Folding is not a mode —
there is no setting in which a caller wants it off, and every non-test caller of those
stages was always the corresponding `WithFold` constructor. What survives as a runtime
check is the case unexporting cannot reach: a nil-`Cosets` commitment arriving from the
wire or from an older version, which the facade's verifier constructors refuse.

### 13.12 The PCS facade

`pcs.go` exposes the scheme in the shape an argument system wants it: setup, statement,
witness, prover, verifier. It adds **no cryptography** — every line delegates to the
primitives above — and exists because assembling them correctly takes four decisions
whose failures are silent.

    type FieldSetup struct { /* numVars, split, fold, gens, dom, curve */ }
    func NewFieldSetup(numVars int, gens []bls12381.G1Affine, curve *mathlib.Curve, cfg FoldConfig) (*FieldSetup, error)
    func NewFieldSetupWithSplit(split Split, gens []bls12381.G1Affine, curve *mathlib.Curve, cfg FoldConfig) (*FieldSetup, error)
    func (s *FieldSetup) NumVars() int
    func (s *FieldSetup) Split() Split
    func (s *FieldSetup) FoldConfig() FoldConfig

    type FieldStatement struct { Alpha []fr.Element }
    type FieldWitness   struct { Poly sumcheck.FieldPoly }

    func NewFieldProver(setup *FieldSetup, st FieldStatement, w FieldWitness) (*FieldProver, error)
    func (p *FieldProver) Commitment() *Commitment
    func (p *FieldProver) Prove() (*EvalProof, fr.Element, error)

    func NewFieldVerifier(setup *FieldSetup, st FieldStatement, com *Commitment) (*FieldVerifier, error)
    func (v *FieldVerifier) Verify(proof *EvalProof, sigma fr.Element) int
    func (v *FieldVerifier) VerifyErr(proof *EvalProof, sigma fr.Element) error

The group path is the same with `GroupSetup`/`GroupStatement`/`GroupWitness`,
`NewGroupSetup(numVars, curve, cfg)` (no generators — the group commitment is tier 2
alone), and `Prove() (*GroupEvalProof, bls12381.G1Affine, error)`.

**The four decisions it hides.**

1. **The two paths need different domain sizes.** The group path encodes all `m`
   variables and needs `2^(m + logRate)`; the field path folds only leg 1 and needs
   `2^(rowVars + logRate)`. Passing `m` on the field path oversizes the domain by
   `2^(m - rowVars) = 2^(m/2)` — 16x at `m = 8`, **256x** at `m = 16` — and all of it is
   paid in the commit FFT that dominates `NewFieldProver`. Not "twice", which is the
   natural guess from the usual halving and was what this section originally claimed.
2. **A commitment must carry its coset oracle.** Folding is not a mode that can be
   switched off: the stages producing a nil-`Cosets` commitment are unexported, so the
   only way to hold one is to receive it from outside (deserialized, or from an older
   version). The facade's verifier constructors refuse exactly that.
3. **`Alpha` has `m` coordinates, not `Commitment.NumVars`,** which counts only the row
   half of the field matrix.
4. **Generators are converted once.** `NewGenerators` caches a mathlib conversion worth
   15–18% of a prove and the bulk of a verify; building it per call is a silent ~6× on
   the verifier.

**Two guarantees, in opposite directions.** A prover from this API always commits *with*
folding, and a verifier from this API *refuses* a commitment whose `Cosets` is nil. The
second is the one the `0/1` return cannot express, so it is caught at construction:
accepting such a commitment would make `Verify` report 1 for a proof that establishes
nothing. `TestPCSProverAlwaysFolds` and `TestPCSVerifierRejectsUnfoldedCommitment` pin
them; the round-trip tests alone cannot, because an unfolded proof verifies happily
against its own unfolded commitment.

**`Verify` returns `int`, `VerifyErr` returns `error`.** `Verify`'s `0` deliberately
collapses "the proof is invalid" and "you called it wrong", which is right for a caller
that wants only the digit and wrong for one debugging an integration.
`TestPCSVerifyErrSeparatesMisuseFromRejection` pins that a nil proof reports `ErrNilProof`
while a forged one reports a coset failure.

**What `Verify` does not establish.** It does not establish that the commitment is to any
particular polynomial — that is what a commitment is *for*, and a verifier that never saw
the witness cannot check it. A caller must obtain the commitment from a source it trusts
or bind it into a larger transcript. Passing the prover's own `Commitment()` straight into
the verifier, as the tests do, exercises the protocol and proves nothing about provenance.

The scheme is **not** zero-knowledge: `Reduced` is sent in plain, so a proof reveals
partial information about the witness. Deferred by design, as below.

**Mutation testing the facade.** Ten mutations over `pcs.go` and `foldconfig.go`; eight
were caught, and the two survivors were both on the `rowVars`/`numVars` axis in
`NewFieldSetup` — the same confusion decision 1 above exists to prevent. They turned out
to be different in kind, which is the useful part.

*Validating the fold config against `numVars` instead of `rowVars` is an equivalent
mutant.* `DefaultEll` returns `1` at every size the field path admits, and `Validate`'s
two `m`-dependent constraints — `Ell <= m/2` and `Queries <= NumCosets(m)` — are both
*looser* at the larger parameter. So `Validate(numVars)` accepts everything
`Validate(rowVars)` does, and differs only for a hand-supplied `Ell` in
`(rowVars/2, numVars/2]`. Recorded here so it is not later "fixed" with a test that
cannot exist; the shipped code still validates against `rowVars`, because that is what
the fold phase runs over and it makes the error name the right parameter.

*Oversizing the domain was a real gap, and it is a **performance** defect, not a
soundness one.* This is why no correctness test saw it: an oversized domain still
encodes, commits, proves and verifies, because `EncodeFieldOracle` consumes the first
`2^(rowVars+logRate)` points and ignores the rest, and the domain size is never absorbed
into the transcript. Probed directly — a prover on a `2^11` domain at `m = 8` produces a
proof that a verifier holding the correct `2^7` domain accepts, with no error at all. A
cost that every functional test is blind to needs a structural assertion, so
`TestPCSSetupSizesTheDomainByTheFoldedHalf` asserts `dom.LogSize` against
`rowVars + LogRate` on the field path and against `m + LogRate` on the group path, the
latter so a "fix" that unifies the two paths fails too. A benchmark would have measured
the regression but only a human reading the numbers would have noticed it.

### 13.13 The outer matrix split as a parameter

The field construction reads `f` as a `2^RowVars x 2^M1` matrix. `M1` — the number of
**column** variables — decides how the work divides between the two legs:

| | smaller `M1` | larger `M1` |
|---|---|---|
| leg 2 (CSP, linear) | cheaper — fewer variables, shorter row MSMs | dearer |
| generators needed | `2^M1`, fewer | more |
| leg 1 / domain | larger row half, so a bigger FFT and Merkle tree | smaller |

It was hardcoded to `m/2` until step 6. That is one point on the curve, and the Rust
reference treats it as a tuned free parameter, shipping asymmetric values per size
(`m=18 → M1=8`, `m=22 → M1=9`, `m=26 → M1=11`).

    type Split struct { M, M1 int }
    func DefaultMatrixSplit(m int) Split        // the balanced cut, M1 = m/2
    func (s Split) RowVars() int                // M - M1: what the fold runs over
    func (s Split) ColVars() int                // M1
    func (s Split) Rows() int                   // 2^RowVars
    func (s Split) Cols() int                   // 2^M1, the generator count
    func (s Split) Validate() error             // commit-time contract
    func (s Split) ValidateForFold() error      // Validate + an EVEN row half

**Two contracts, deliberately.** `Validate` is what committing needs: the halves must
multiply back to `2^M`. `ValidateForFold` adds the even-row-half rule, because the coset
layout halves the row half exactly. These belong to different phases — `commitFieldAt`
calls the first, `CommitFieldWithFoldAt` the second — and collapsing them is a real
hazard, not a hypothetical one: a draft of `Split` put the fold rule in `Validate` and
broke every odd-`m` and `m = 2` test in the package at once, because those sizes commit
and open perfectly well through the non-folding stages.

**The split is on the wire.** `Commitment.ColVars` carries `M1`. This closes the
ambiguity `checkShape` used to document: `NumVars` is `log2` of the *row* count, so it
pins down `RowVars` and nothing else, and every row count is consistent with many `M1`.
Before the field existed the verifier had to take the total variable count from `alpha`
and divide it at the balanced cut, and could not detect a prover that had cut elsewhere.
`ColVars == 0` means "not stated" — a group commitment, or a field commitment from
before the field — and falls back to the balanced split, so older commitments verify
exactly as they did.

**Why a round trip is nearly worthless as the test here.** `eq` factorizes over *any*
split, so a prover and verifier that both divide `alpha` at the wrong point produce a
proof that verifies against itself perfectly — for a different polynomial than the one
committed. `Verify() == 1` cannot see it. `TestFieldPCSSplitMakesOddSizesUsable`
therefore checks `sigma` against `sumcheck.FieldPoly.EvaluatePoint`, the package's own
reference evaluator, which knows nothing about matrices. Mutating `splitAlphaAt` to swap
the halves passes verification and fails only that assertion — confirming both that the
test works and that the silent-failure mode is real.

Six mutations were run against the threading, all caught: swapping the halves; the
prover re-deriving the split instead of using the committed one; the verifier dividing
`alpha` at the balanced cut; `checkShape` ignoring `ColVars`; the commitment omitting
`ColVars`; and the facade dropping the setup's split when committing.

**Not yet done.** `DefaultEll` and the drawability floor are still computed against
`RowVars` without regard to how the split was chosen (13.10), and no benchmark has
established whether `m/2` is optimal for *our* cost model. It will not match Rust's
`m/2 − 2`: that reference also folds the generator oracle (its `l2`), which keeps a
larger column half cheap, whereas here every column variable is full linear CSP cost.
Revisit the default when leg 2 folding lands, not before.

### 13.14 What is still open

Deferred by design, unchanged from section 12.8: zero-knowledge; `Setup`; batched `Eval`
at several points; serialization; and the `O(n^(1/4))` variant, which needs a second
folding layer over the *generator* oracle and is not what `k` controls.

One thing the batching in 13.6 does **not** fix: the verifier is still linear in
`2^(m−ℓ)`, because `Reduced` is sent in plain and the verifier must touch every
coefficient of it. Batching removed the factor of `Q`, not the term. Sending `Reduced` is
the deliberate stopping point of this step — the claim is closed and sound, at one round
of folding. Recursing instead of sending it in plain is WHIR proper: fold again over the
reduced oracle rather than revealing it, repeat until the polynomial is small enough to
send, and the verifier becomes polylogarithmic. That is the next structural step, not a
tuning parameter.

## 14. References

- Titan paper — `eprint_version/` in the `titan` project; `group-sum-check.tex`
  covers the group oracle encoding and the efficient group sum-check.
- Rust reference implementation — the `titan-implementation` project
  (`src/utils.rs` for `multilinear_fft`, `src/group_sumcheck.rs` for the group
  sum-check).
- Arnon, Chiesa, Fenzi, Yogev, *WHIR: Reed–Solomon Proximity Testing with
  Super-Fast Verification* — the IOPP Titan adapts.
- Attema, Cramer, *Compressed Sigma-Protocol Theory* — the CSP used to close the
  evaluation argument.
- [Sum-Check Protocol](sumcheck.md) — the polynomial types and folding convention
  this package builds on.
