"""
Zero-Knowledge Range Proofs via Binary Bit-Decomposition & CDS 1-out-of-2 Sigma Protocols.
Proves 0 <= v < 2^k without revealing private value v.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Any, Dict, List, Optional, Tuple

from .models import PedersenCommitment, PedersenParameters, RangeProof
from .pedersen import PedersenEngine, get_default_parameters


class RangeProofEngine:
    """
    Zero-Knowledge Range Proof engine.
    Constructs and verifies proofs that a committed value satisfies 0 <= v < 2^max_bits.
    """

    def __init__(self, params: Optional[PedersenParameters] = None):
        self.params = params or get_default_parameters()
        self.pedersen = PedersenEngine(self.params)

    def _hash_challenge(self, data_parts: List[str]) -> int:
        joined = ":".join(data_parts).encode("utf-8")
        return int.from_bytes(hashlib.sha256(joined).digest(), "big") % self.params.q

    def prove_bit(self, b: int, r: int, C: int, bit_idx: int) -> Dict[str, str]:
        """
        CDS 1-out-of-2 NIZK proof that commitment C opens to 0 or 1.
        C = g^b * h^r mod p.
        """
        p, q, g, h = self.params.p, self.params.q, self.params.g, self.params.h
        g_inv = pow(g, -1, p)
        C_minus_g = (C * g_inv) % p

        if b == 0:
            # Real proof for branch 0 (C opens to 0 with private key r: C = h^r)
            # Simulated proof for branch 1 (C_minus_g opens to 0)
            w0 = secrets.randbelow(q - 1) + 1
            R0 = pow(h, w0, p)

            # Pick simulated challenge e1 and response s1
            e1 = secrets.randbelow(q - 1) + 1
            s1 = secrets.randbelow(q - 1) + 1
            # R1 = h^s1 * (C_minus_g)^(-e1) mod p
            R1 = (pow(h, s1, p) * pow(C_minus_g, -e1, p)) % p

            # Overall challenge e = H(C, R0, R1, bit_idx)
            e = self._hash_challenge([hex(C), hex(R0), hex(R1), str(bit_idx)])
            e0 = (e - e1) % q
            s0 = (w0 + e0 * r) % q

        elif b == 1:
            # Simulated proof for branch 0
            e0 = secrets.randbelow(q - 1) + 1
            s0 = secrets.randbelow(q - 1) + 1
            R0 = (pow(h, s0, p) * pow(C, -e0, p)) % p

            # Real proof for branch 1 (C_minus_g opens to 0 with private key r: C_minus_g = h^r)
            w1 = secrets.randbelow(q - 1) + 1
            R1 = pow(h, w1, p)

            e = self._hash_challenge([hex(C), hex(R0), hex(R1), str(bit_idx)])
            e1 = (e - e0) % q
            s1 = (w1 + e1 * r) % q
        else:
            raise ValueError(f"Bit must be 0 or 1, got {b}")

        return {
            "R0": hex(R0),
            "R1": hex(R1),
            "e0": hex(e0),
            "e1": hex(e1),
            "s0": hex(s0),
            "s1": hex(s1),
        }

    def verify_bit(self, C: int, proof: Dict[str, str], bit_idx: int) -> bool:
        """Verify CDS 1-out-of-2 proof for a single bit commitment."""
        p, q, g, h = self.params.p, self.params.q, self.params.g, self.params.h
        R0 = int(proof["R0"], 16)
        R1 = int(proof["R1"], 16)
        e0 = int(proof["e0"], 16)
        e1 = int(proof["e1"], 16)
        s0 = int(proof["s0"], 16)
        s1 = int(proof["s1"], 16)

        g_inv = pow(g, -1, p)
        C_minus_g = (C * g_inv) % p

        # Check total challenge consistency
        e = self._hash_challenge([hex(C), hex(R0), hex(R1), str(bit_idx)])
        if (e0 + e1) % q != e:
            return False

        # Check branch 0: h^s0 == R0 * C^e0 mod p
        left0 = pow(h, s0, p)
        right0 = (R0 * pow(C, e0, p)) % p
        if left0 != right0:
            return False

        # Check branch 1: h^s1 == R1 * (C_minus_g)^e1 mod p
        left1 = pow(h, s1, p)
        right1 = (R1 * pow(C_minus_g, e1, p)) % p
        if left1 != right1:
            return False

        return True

    def prove_range(self, value: int, max_bits: int = 16) -> RangeProof:
        """
        Generate zero-knowledge range proof that 0 <= value < 2^max_bits.
        Returns RangeProof containing bit commitments, bit proofs, and aggregate commitment.
        """
        if value < 0 or value >= (1 << max_bits):
            raise ValueError(f"Value {value} out of range [0, 2^{max_bits}-1]")

        p, q = self.params.p, self.params.q
        bits = [(value >> i) & 1 for i in range(max_bits)]

        bit_commitments = []
        bit_proofs = []
        r_bits = []

        total_r = 0
        total_C = 1

        for i, b in enumerate(bits):
            r_i = secrets.randbelow(q - 1) + 1
            r_bits.append(r_i)

            comm = self.pedersen.commit(value=b, blinding_factor=r_i)
            bit_commitments.append(comm.commitment)

            bp = self.prove_bit(b, r_i, comm.commitment, i)
            bit_proofs.append(bp)

            weight = 1 << i
            total_r = (total_r + r_i * weight) % q
            # Homomorphically scale: C_i^(2^i)
            scaled_C = pow(comm.commitment, weight, p)
            total_C = (total_C * scaled_C) % p

        return RangeProof(
            max_bits=max_bits,
            commitment=total_C,
            bit_commitments=bit_commitments,
            bit_proofs=bit_proofs,
        )

    def verify_range(self, proof: RangeProof) -> bool:
        """
        Verify that:
        1. Each bit commitment is validly in {0, 1}
        2. Homomorphic aggregation prod(C_i^(2^i)) == C mod p
        """
        p = self.params.p
        if len(proof.bit_commitments) != proof.max_bits:
            return False
        if len(proof.bit_proofs) != proof.max_bits:
            return False

        expected_C = 1
        for i in range(proof.max_bits):
            C_i = proof.bit_commitments[i]
            bp = proof.bit_proofs[i]

            if not self.verify_bit(C_i, bp, i):
                return False

            weight = 1 << i
            scaled_C = pow(C_i, weight, p)
            expected_C = (expected_C * scaled_C) % p

        return expected_C == proof.commitment
