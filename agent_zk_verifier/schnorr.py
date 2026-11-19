"""
Non-Interactive Zero-Knowledge (NIZK) Schnorr Sigma Protocol for Pedersen Commitments.
Fiat-Shamir transformed for non-interactive verifiable agent proofs.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Optional

from .models import PedersenCommitment, PedersenParameters, SchnorrProof
from .pedersen import get_default_parameters


class SchnorrProver:
    """
    Proves knowledge of opening (value v, blinding factor r) for commitment C = g^v * h^r mod p
    without disclosing either value or blinding factor.
    """

    def __init__(self, params: Optional[PedersenParameters] = None):
        self.params = params or get_default_parameters()

    def compute_challenge(self, commitment: int, R: int, context: str = "") -> int:
        """Deterministic Fiat-Shamir challenge hash scalar."""
        data = f"{self.params.p}:{self.params.q}:{self.params.g}:{self.params.h}:{commitment}:{R}:{context}".encode(
            "utf-8"
        )
        digest = hashlib.sha256(data).digest()
        return int.from_bytes(digest, "big") % self.params.q

    def prove(self, commitment: PedersenCommitment, context: str = "") -> SchnorrProof:
        """
        Generate NIZK proof of knowledge for commitment opening.
        Requires commitment.value and commitment.blinding_factor.
        """
        if commitment.value is None or commitment.blinding_factor is None:
            raise ValueError("Prover requires private value and blinding factor to create proof.")

        v = commitment.value % self.params.q
        r = commitment.blinding_factor % self.params.q

        # 1. Ephemeral nonces
        w_v = secrets.randbelow(self.params.q - 1) + 1
        w_r = secrets.randbelow(self.params.q - 1) + 1

        # 2. Announcement R = g^w_v * h^w_r mod p
        gw = pow(self.params.g, w_v, self.params.p)
        hw = pow(self.params.h, w_r, self.params.p)
        R = (gw * hw) % self.params.p

        # 3. Fiat-Shamir challenge
        e = self.compute_challenge(commitment.commitment, R, context)

        # 4. Responses
        s_v = (w_v + e * v) % self.params.q
        s_r = (w_r + e * r) % self.params.q

        return SchnorrProof(R=R, e=e, s_v=s_v, s_r=s_r)


class SchnorrVerifier:
    """Verifies Schnorr NIZK proofs of knowledge."""

    def __init__(self, params: Optional[PedersenParameters] = None):
        self.params = params or get_default_parameters()

    def verify(self, commitment: int, proof: SchnorrProof, context: str = "") -> bool:
        """
        Verifies:
        1. e == Hash(params, C, R, context)
        2. g^s_v * h^s_r == R * C^e mod p
        """
        # Range check on proof components
        if not (1 <= proof.R < self.params.p):
            return False
        if not (0 <= proof.e < self.params.q):
            return False
        if not (0 <= proof.s_v < self.params.q):
            return False
        if not (0 <= proof.s_r < self.params.q):
            return False

        # Recompute challenge
        expected_e = SchnorrProver(self.params).compute_challenge(commitment, proof.R, context)
        if expected_e != proof.e:
            return False

        # Verify equation: g^s_v * h^s_r = R * C^e mod p
        left = (pow(self.params.g, proof.s_v, self.params.p) * pow(self.params.h, proof.s_r, self.params.p)) % self.params.p
        right = (proof.R * pow(commitment, proof.e, self.params.p)) % self.params.p

        return left == right
