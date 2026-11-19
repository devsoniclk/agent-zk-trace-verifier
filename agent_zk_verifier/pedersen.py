"""
Pedersen Commitment Engine with Additive Homomorphic Properties.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import List, Optional, Tuple

from .models import PedersenCommitment, PedersenParameters

# Standard RFC 3526 2048-bit Modular Exponential (MODP) Safe Prime: p = 2q + 1
# Order q is prime: q = (p - 1) // 2
RFC3526_2048_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)

RFC3526_2048_ORDER = (RFC3526_2048_PRIME - 1) // 2


def derive_generators(p: int, q: int) -> Tuple[int, int]:
    """
    Derives two verifiable, cryptographically independent generators g, h for
    the quadratic residue subgroup of order q in Z_p*.
    g = 2^2 mod p
    h = Hash(p || g)^2 mod p
    """
    g = pow(2, 2, p)
    
    # Nothing-up-my-sleeve independent generator h via SHA-512 domain separation
    seed = f"AgentZKVerifier:Pedersen:GeneratorH:{hex(p)}:{hex(g)}".encode("utf-8")
    h_int = int.from_bytes(hashlib.sha512(seed).digest() + hashlib.sha512(seed + b":extra").digest(), "big") % p
    if h_int == 0 or h_int == 1:
        h_int = 3
    h = pow(h_int, 2, p)
    if h == 1 or h == g:
        h = pow(5, 2, p)
    return g, h


DEFAULT_PARAMS: Optional[PedersenParameters] = None


def get_default_parameters() -> PedersenParameters:
    """Returns singleton default Pedersen parameters using RFC 3526 2048-bit group."""
    global DEFAULT_PARAMS
    if DEFAULT_PARAMS is None:
        p = RFC3526_2048_PRIME
        q = RFC3526_2048_ORDER
        g, h = derive_generators(p, q)
        DEFAULT_PARAMS = PedersenParameters(p=p, q=q, g=g, h=h)
    return DEFAULT_PARAMS


class PedersenEngine:
    """
    Pedersen Commitment scheme supporting additive and scalar homomorphic operations.
    Hiding: Information-theoretically hiding (for any commitment C, every value is possible).
    Binding: Computationally binding under Discrete Logarithm assumption in Z_p*.
    """

    def __init__(self, params: Optional[PedersenParameters] = None):
        self.params = params or get_default_parameters()

    def commit(self, value: int, blinding_factor: Optional[int] = None) -> PedersenCommitment:
        """
        Compute Pedersen commitment C = g^v * h^r mod p.
        Value must be non-negative, blinding factor r is uniformly chosen from Z_q*.
        """
        if blinding_factor is None:
            blinding_factor = secrets.randbelow(self.params.q - 1) + 1

        v_mod = value % self.params.q
        r_mod = blinding_factor % self.params.q

        gv = pow(self.params.g, v_mod, self.params.p)
        hr = pow(self.params.h, r_mod, self.params.p)
        commitment = (gv * hr) % self.params.p

        return PedersenCommitment(
            commitment=commitment,
            blinding_factor=blinding_factor,
            value=value,
        )

    def verify(self, commitment: int, value: int, blinding_factor: int) -> bool:
        """Verify that commitment C opens to (value, blinding_factor)."""
        expected = self.commit(value=value, blinding_factor=blinding_factor).commitment
        return commitment == expected

    def add(self, c1: PedersenCommitment, c2: PedersenCommitment) -> PedersenCommitment:
        """
        Homomorphic addition: C_sum = C1 * C2 mod p = g^(v1+v2) * h^(r1+r2) mod p.
        """
        c_sum = (c1.commitment * c2.commitment) % self.params.p
        r_sum = None
        if c1.blinding_factor is not None and c2.blinding_factor is not None:
            r_sum = (c1.blinding_factor + c2.blinding_factor) % self.params.q
        v_sum = None
        if c1.value is not None and c2.value is not None:
            v_sum = c1.value + c2.value

        return PedersenCommitment(
            commitment=c_sum,
            blinding_factor=r_sum,
            value=v_sum,
        )

    def add_commitments(self, commitments: List[int]) -> int:
        """Combine raw commitment integers homomorphically: C_tot = prod(C_i) mod p."""
        tot = 1
        for c in commitments:
            tot = (tot * c) % self.params.p
        return tot

    def scalar_mul(self, commitment: PedersenCommitment, scalar: int) -> PedersenCommitment:
        """
        Homomorphic scalar multiplication: C^k mod p = g^(k*v) * h^(k*r) mod p.
        """
        c_mul = pow(commitment.commitment, scalar % self.params.q, self.params.p)
        r_mul = None
        if commitment.blinding_factor is not None:
            r_mul = (commitment.blinding_factor * scalar) % self.params.q
        v_mul = None
        if commitment.value is not None:
            v_mul = commitment.value * scalar

        return PedersenCommitment(
            commitment=c_mul,
            blinding_factor=r_mul,
            value=v_mul,
        )
