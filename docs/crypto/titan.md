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
12. [References](#12-references)

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
no soundness at all. Until WHIR lands, this is the caller's responsibility.

## 7. Merkle Commitment and the Two Tiers

Titan commits a field multilinear in two tiers, and the inner tier is by itself a
commitment to a *group* multilinear. That is the whole reason the scheme was chosen
here: **one commitment mechanism, two entry points**.

| | Mechanism | Assumption | What it binds |
|---|---|---|---|
| Tier 1 | Pedersen MSM per matrix row | discrete log | row coefficients to `G_j` |
| Tier 2 | Merkle root over the RS codeword | random oracle | `G` to a queryable oracle |

```
CommitGroup(G)  = tier 2              a group polynomial commitment
CommitField(f)  = tier 1 then tier 2  a field polynomial commitment
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
claimed `v`. That needs the WHIR folding rounds plus the group sum-check of
section 6, and is the next step. `Commit` and `Eval` are separate for that reason,
and "commitment" should not be read as "PCS complete".

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
// The caller MUST still close the reduction: see section 6.5.
```

`sigma` is returned rather than taken as an argument, since it is determined by `f`
and `alpha`. `ell` is a pure performance knob — the claim proved is the same for every
value — but it is bound into the transcript, so both sides must agree on it.


### 8.1 Commitment

`CommitGroup` is the group polynomial commitment; `CommitField` is the field one and
runs both tiers. Both return a `*Commitment` for the verifier and an opening hint
that is **prover state and must not be sent**.

```go
dom, err := titan.NewDomain(11)                  // |L| = 2^11
if err != nil {
    return errors.Wrap(err, "failed to build evaluation domain")
}

// Group polynomial commitment: tier 2 only.
c, hint, err := titan.CommitGroup(groupPoly, dom, 0)   // k = 0, one point per leaf
if err != nil {
    return errors.Wrap(err, "failed to commit the group polynomial")
}

// Field polynomial commitment: tier 1 (Pedersen rows) then tier 2.
c, fhint, err := titan.CommitField(fieldPoly, gens, dom, 0)
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

`gens` comes from the caller: `CommitField` performs no trusted setup, and generator
provenance is a separate question this package does not answer. At least `cols`
generators are required (`ErrInsufficientGenerators`).

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

| `m` | `CommitField` |
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

Statement coverage is **93.4%** overall, race-clean.

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

## 12. References

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
