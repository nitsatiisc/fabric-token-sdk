// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

// This contract adds support for verifying zero knowledge proofs based on BN254 curve
// in fabric-token-sdk inside evm environment.
contract ZKATVerifier {
    // Seperator
    string public constant SEP = "||";
    // BN254 scalar field order (group order r)
    uint256 public constant GROUP_ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // BN254 base field prime p (for on-curve check y^2 == x^3 + 3 mod p)
    uint256 public constant BASE_FIELD = 21888242871839275222246405745257275088696311157297823662689037894645226208583;


    struct G1Point { uint256 x; uint256 y; }

    // Solidity mimics of the IPA datastructures in token-sdk

    struct IPAVerifier {
        // inner product
        uint256 innerProduct;
        // Generator Q in affine
        G1Point Q;
        // left generators
        G1Point[] leftGenerators;
        // right generators
        G1Point[] rightGenerators;
        // commitment
        G1Point commitment;
        // rounds
        uint256 rounds;
    }

    struct IPAProof {
        // final folded left vector
        uint256 left;
        // final folded right vector
        uint256 right;
        // left messages during protocol rounds
        G1Point[] L;
        // right messages during protocol rounds
        G1Point[] R;
    }

    struct RangeVerifier {
        // commitment to the value
        G1Point comV;
        // generators for commitment
        G1Point g;
        G1Point h;
        // generators for vector commitments
        G1Point[] leftGenerators;
        G1Point[] rightGenerators;
        // generator for commitment to vector blinders
        G1Point P;
        // generator to be passed on to IPA
        G1Point Q;
        // number of rounds
        uint rounds;
        // number of bits in range
        uint nr;
    }

    struct RangeProof {
        // commitment to bit, bit - 1 vectors
        G1Point C;
        // commitment to blinders for above vectors
        G1Point D;
        // commitment to coeffs of polynomial t(X)
        G1Point T1;
        G1Point T2;
        // Blinding for value of inner product
        uint256 tau;
        // Correction to derive inner product commitment for IPA
        uint256 delta;
        // innerproduct for IPA
        uint256 innerProduct;
        // IPA proof
        IPAProof ipaProof;
    }

    // Collect temporary variables in a struct to prevent
    // too many local variables error.
    struct tempVars {
        uint256 x;
        uint256 xprime;
        uint256 xinv;
        uint256 xsq;
        uint256 xinvsq;
        uint    n;
        G1Point Qprime;
        G1Point Cprime;
        G1Point X;
        G1Point tempLeft;
        G1Point tempRight;
        G1Point Cleft;
        G1Point Cright;
    }

    struct tempVarsRp {
        uint256 y;
        uint256 yinv;
        uint256 z;
        uint256 x;
        uint256 xsq;
        uint256 zsq;
        uint256 zcube;
        uint256 negz;
        uint256 f;
        uint256[] powers_of_y;
        uint256[] powers_of_two;
        G1Point lhs;
        G1Point rhs;
        G1Point ipaComm;
    }
    // This function verifies proof for inner product v for vectors A and B.
    // IPAVerifier specifies size of the vectors, generators for left, right vectors and inner product and the commitment.
    // IPAProof contains the messages from the prover.
    function verifyIPA(IPAVerifier memory stmt, IPAProof memory proof) public view returns (bool) {
        require(proof.L.length == stmt.rounds, "Size of L != rounds");
        require(proof.R.length == stmt.rounds, "Size of R != rounds");
        tempVars memory temp;

        // compute initial challenge x by hashing generators, commitment and inner product.
        bytes memory rBytes = packPoints(stmt.rightGenerators);
        bytes memory lBytes = packPoints(stmt.leftGenerators);
        bytes memory array = abi.encodePacked(rBytes, lBytes, stmt.Q.x, stmt.Q.y, stmt.commitment.x, stmt.commitment.y);
        bytes memory raw = abi.encodePacked(array,stmt.innerProduct);
        bytes memory hashBytes = abi.encodePacked(sha256(raw));
        temp.x = hashtoZr(hashBytes);
        temp.xprime = mulmod(temp.x, stmt.innerProduct, GROUP_ORDER);
        temp.Qprime = ecMul(stmt.Q, temp.xprime);
        G1Point memory C = ecAdd(stmt.commitment, temp.Qprime);
        temp.X = ecMul(stmt.Q, temp.x);

        // copy the generators for reduction rounds
        G1Point[] memory leftGen = new G1Point[](stmt.leftGenerators.length);
        G1Point[] memory rightGen = new G1Point[](stmt.rightGenerators.length);
        for(uint256 i=0; i < leftGen.length; i++) {
            leftGen[i] = stmt.leftGenerators[i];
            rightGen[i] = stmt.rightGenerators[i];
        }

        // reduce the instance size in each round
        temp.n = leftGen.length;
        for(uint i=0; i < stmt.rounds; i++) {
            // compute challenge by hashing i^th prover message.
            bytes memory cBytes = abi.encodePacked(proof.L[i].x, proof.L[i].y, proof.R[i].x, proof.R[i].y);
            hashBytes = abi.encodePacked(sha256(cBytes));
            temp.x = hashtoZr(hashBytes);
            temp.xinv = inverse(temp.x);
            require(mulmod(temp.x, temp.xinv, GROUP_ORDER)==uint256(1), "INVFAULT");
            temp.xsq = mulmod(temp.x, temp.x, GROUP_ORDER);
            temp.xinvsq = mulmod(temp.xinv, temp.xinv, GROUP_ORDER);
            temp.Cprime = ecMul(proof.L[i], temp.xsq);
            temp.Cright = ecMul(proof.R[i], temp.xinvsq);
            temp.Cprime = ecAdd(temp.Cprime, temp.Cright);
            temp.Cprime = ecAdd(temp.Cprime, C);
            C = temp.Cprime;

            // fold the generators
            temp.n = temp.n/2;
            for(uint j=0; j < temp.n; j++) {
                leftGen[j] = ecMul(leftGen[j], temp.xinv);
                temp.tempLeft = ecMul(leftGen[j+temp.n], temp.x);
                leftGen[j] = ecAdd(leftGen[j], temp.tempLeft);

                rightGen[j] = ecMul(rightGen[j], temp.x);
                temp.tempRight = ecMul(rightGen[j+temp.n], temp.xinv);
                rightGen[j] = ecAdd(rightGen[j], temp.tempRight);
            }
        }

        temp.Cprime = ecMul(leftGen[0], proof.left);
        temp.tempRight = ecMul(rightGen[0], proof.right);
        G1Point memory XPrime = ecMul(temp.X, mulmod(proof.left, proof.right, GROUP_ORDER));
        temp.Cprime = ecAdd(temp.Cprime, temp.tempRight);
        temp.Cprime = ecAdd(temp.Cprime, XPrime);
        require(temp.Cprime.x == C.x, "Invalid IPA Proof");
        require(temp.Cprime.y == C.y, "Invalid IPA Proof");
        return true;
    }



    // This function verifies the range proof.
    function verifyRange(RangeVerifier calldata stmt, RangeProof calldata proof) external view returns (bool) {
        tempVarsRp memory temp;
        // compute challenges y as H(C||D||comV)
        bytes memory hashBytes = abi.encodePacked(
        sha256(
        abi.encodePacked(proof.C.x, proof.C.y, proof.D.x, proof.D.y, stmt.comV.x, stmt.comV.y)
        ));
        temp.y = hashtoZr(hashBytes);
        temp.yinv = inverse(temp.y);
        hashBytes = abi.encodePacked(sha256(abi.encodePacked(temp.y)));

        temp.z = hashtoZr(hashBytes);
        temp.zsq = mulmod(temp.z, temp.z, GROUP_ORDER);
        temp.zcube = mulmod(temp.z, temp.zsq, GROUP_ORDER);
        temp.negz = (GROUP_ORDER - (temp.z % GROUP_ORDER)) % GROUP_ORDER;

        G1Point[] memory rightGenPrime = computeNewGenerators(stmt.rightGenerators, inverse(temp.y));
        temp.f = computeDelta(temp.y,temp.z, stmt.nr);

        // compute challenge x as H(T1||T2)
        hashBytes = abi.encodePacked(sha256(abi.encodePacked(proof.T1.x, proof.T1.y, proof.T2.x, proof.T2.y)));
        temp.x = hashtoZr(hashBytes);
        temp.xsq = mulmod(temp.x, temp.x, GROUP_ORDER);

        // compute vectors y^n and 2^n
        temp.powers_of_two = computePowerVector(uint256(2), stmt.nr);
        temp.powers_of_y = computePowerVector(temp.y, stmt.nr);

        temp.rhs = ecMul(stmt.comV, temp.zsq);
        temp.rhs = ecAdd(temp.rhs, ecMul(stmt.g, temp.f));
        temp.rhs = ecAdd(temp.rhs, ecMul(proof.T1, temp.x));
        temp.rhs = ecAdd(temp.rhs, ecMul(proof.T2, temp.xsq));

        temp.lhs = ecMul(stmt.g, proof.innerProduct);
        temp.lhs = ecAdd(temp.lhs, ecMul(stmt.h, proof.tau));

        require(temp.lhs.x == temp.rhs.x, "Invalid rangeproof");
        require(temp.lhs.y == temp.rhs.y, "Invalid rangeproof");

        // Compute commitment for IPA
        temp.ipaComm = proof.C;
        temp.ipaComm = ecAdd(temp.ipaComm, ecMul(proof.D, temp.x));
        for(uint i=0; i < stmt.nr; ++i) {
            temp.ipaComm = ecAdd(temp.ipaComm, ecMul(stmt.leftGenerators[i], temp.negz));
            uint256 exp1 = mulmod(temp.z, temp.powers_of_y[i], GROUP_ORDER);
            uint256 exp2 = mulmod(temp.zsq, temp.powers_of_two[i], GROUP_ORDER);
            exp1 = addmod(exp1, exp2, GROUP_ORDER);
            temp.ipaComm = ecAdd(temp.ipaComm, ecMul(rightGenPrime[i], exp1));
        }
        // apply final correction of P^{-\delta}
        uint256 negdelta = (GROUP_ORDER - (proof.delta % GROUP_ORDER)) % GROUP_ORDER;
        temp.ipaComm = ecAdd(temp.ipaComm, ecMul(stmt.P, negdelta));
        IPAVerifier memory ipaVerifier = IPAVerifier(
            proof.innerProduct,
            stmt.Q,
            stmt.leftGenerators,
            rightGenPrime,
            temp.ipaComm,
            stmt.rounds
        );

        require(verifyIPA(ipaVerifier,proof.ipaProof), "Invalid IPA Proof");
        return true;
    }



    // This is a small test function to verify a simple Schnorr proof of g^x = P.
    function verifyDlog(
            uint256 Gx, uint256 Gy,
            uint256 Px, uint256 Py,
            uint256 Tx, uint256 Ty,
            uint256 prfZ
      ) external view returns (bool) {

        G1Point memory G = G1Point(Gx, Gy);
        G1Point memory P = G1Point(Px, Py);
        G1Point memory t = G1Point(Tx, Ty);
        // compute challenge c = Hash(G||P||t)
        bytes memory cBytes = abi.encodePacked(sha256(abi.encodePacked(Gx,Gy,Px,Py,Tx,Ty)));
        uint256 c = hashtoZr(cBytes);
        G1Point memory lhs = ecMul(G, prfZ);    // lhs = z.G
        G1Point memory rhs = ecMul(P, c);       // rhs = c.P + t
        rhs = ecAdd(rhs, t);
        require(lhs.x == rhs.x, "lhs.x != rhs.x");
        require(lhs.y == rhs.y, "lhs.y != rhs.y");
        return true;
    }

    // ECMUL precompile (0x07). Input: 32B x,32B y,32B scalar Output: 32B x,32B y
    function ecMul(G1Point memory p, uint256 s) internal view returns (G1Point memory r) {
        // reduce scalar mod group order to be safe
        s = s % GROUP_ORDER;

        bytes memory input = abi.encodePacked(p.x, p.y, s);
        bytes memory out = new bytes(64); // 2 * 32 bytes
        bool success;
        assembly {
        // 0x07 = ECMUL
        // call staticcall(gas, to, inOffset, inSize, outOffset, outSize)
            success := staticcall(gas(), 0x07, add(input, 0x20), 0x60, add(out, 0x20), 0x40)
        }
        require(success, "ecmul precompile failed");
        r.x = toUint256(out, 0) % BASE_FIELD;
        r.y = toUint256(out, 32) % BASE_FIELD;
    }

    // ECADD precompile (0x06). Input: 32B x1, 32B y1, 32B x2, 32B y2 Output: 32B x3, 32B y3
    function ecAdd(G1Point memory p, G1Point memory q) internal view returns (G1Point memory r) {
        bytes memory input = abi.encodePacked(p.x, p.y, q.x, q.y);
        bytes memory out = new bytes(64);
        bool success;
        assembly {
            // 0x06 = ECADD
            success := staticcall(gas(), 0x06, add(input,0x20), 0x80, add(out,0x20), 0x40)
        }
        require(success, "ecadd precompile failed");
        r.x = toUint256(out, 0) % BASE_FIELD;
        r.y = toUint256(out, 32) % BASE_FIELD;
    }

    // Convenience routine to hash bytes to Zr element.
    function hashtoZr(bytes memory b) pure internal  returns (uint256) {
        uint256 r = toUint256(b,0);
        r = r % GROUP_ORDER;
        return r;
    }

    /// A test function to check scalar multiplication.
    function verifyMul(
        uint256 Ax, uint256 Ay,
        uint256 Bx, uint256 By,
        uint256 w
    ) external view returns (bool) {
        G1Point memory A = G1Point(Ax, Ay);
        G1Point memory B = G1Point(Bx, By);
        G1Point memory R = ecMul(A, w);
        return (R.x == B.x && R.y == B.y);
    }

    /// read 32-byte big-endian word from `b` at offset `offset` (0..32..).
    function toUint256(bytes memory b, uint256 offset) internal pure returns (uint256) {
        require(b.length >= offset + 32, "out of range");
        uint256 x;
        assembly {
            x := mload(add(add(b, 0x20), offset))
        }
        return x;
    }

    // Convenience routine to flatten G1 elements to bytes.
    function packPoints(G1Point[] memory points) public pure returns (bytes memory) {
        bytes memory out;
        for (uint i = 0; i < points.length; i++) {
            out = bytes.concat(out, abi.encodePacked(points[i].x, points[i].y));
        }
        return out;
    }

    // Convenience routine to compute fresh generators for range proof
    function computeNewGenerators(G1Point[] memory gens, uint256 y) public view returns (G1Point[] memory) {
        uint256 ypow = 1;
        G1Point[] memory gensPrime = new G1Point[](gens.length);
        for(uint i=0; i < gens.length; ++i) {
            gensPrime[i] = ecMul(gens[i], ypow);
            ypow = mulmod(ypow, y, GROUP_ORDER);
        }

        return gensPrime;
    }

    // compute function f(y,z)=(z-z^2)\sum{y} - z^3(2^n-1)
    function computeDelta(uint256 y, uint256 z, uint n) public view returns (uint256) {
        uint256 zsq = mulmod(z, z, GROUP_ORDER);
        uint256 zcube = mulmod(zsq, z, GROUP_ORDER);
        uint256 sumy = modExp(y, n, GROUP_ORDER) - 1;
        uint256 sum2 = modExp(2, n, GROUP_ORDER) - 1;
        sumy = mulmod(sumy, inverse(y-1), GROUP_ORDER);
        uint256 t1 = mulmod(z, z-1, GROUP_ORDER);
        t1 = mulmod(t1, sumy, GROUP_ORDER);
        uint256 t2 = mulmod(zcube, sum2, GROUP_ORDER);
        t2 = addmod(t1, t2, GROUP_ORDER);
        t2 = (GROUP_ORDER - (t2 % GROUP_ORDER)) % GROUP_ORDER;
        return t2;
    }

    // compute power vector
    function computePowerVector(uint256 y, uint n) public pure returns (uint256[] memory) {
        uint256[] memory powers = new uint256[](n);
        uint256 acc = uint256(1);
        for(uint i=0; i < n; i++) {
            powers[i] = acc;
            acc = mulmod(acc, y, GROUP_ORDER);
        }
        return powers;
    }


    // Performs (base ^ exponent) % modulus using the modexp precompile.
    // All arguments are uint256 and returned result is uint256.
    function modExp(
        uint256 base,
        uint256 exponent,
        uint256 modulus
    ) internal view returns (uint256 result) {
        require(modulus != 0, "modulus cannot be zero");

        // Each input length is 32 bytes (uint256)
        bytes memory input = abi.encodePacked(
            uint256(32),   // base length
            uint256(32),   // exponent length
            uint256(32),   // modulus length
            bytes32(base),
            bytes32(exponent),
            bytes32(modulus)
        );

        bytes memory output = new bytes(32);

        bool success;
        assembly {
        // call(modexp) = 0x05
            success := staticcall(
                gas(),
                0x05,
                add(input, 0x20),
                mload(input),
                add(output, 0x20),
                0x20
            )
        }
        require(success, "modexp failed");

        assembly {
            result := mload(add(output, 0x20))
        }
    }

    // Compute inverse of Zr element using precompile.
    function inverse(uint256 x) public view returns (uint256 inv) {
        uint256[6] memory input;
        input[0] = 0x20; // base length
        input[1] = 0x20; // exp length
        input[2] = 0x20; // mod length
        input[3] = x;
        input[4] = GROUP_ORDER - 2;
        input[5] = GROUP_ORDER;

        bytes memory output = new bytes(0x20);
        assembly {
            if iszero(staticcall(not(0), 0x05, input, 0xc0, add(output, 0x20), 0x20)) {
                revert(0, 0)
            }
        }
        inv = abi.decode(output, (uint256));
    }


}
