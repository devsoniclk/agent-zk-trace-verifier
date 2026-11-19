"""
Batch Verification and Recursive Aggregation for Multi-Agent Swarm Proofs.
"""

from __future__ import annotations

import time
from typing import List, Optional

from .models import (
    BatchVerificationResult,
    CompliancePolicy,
    ZKProofReceipt,
    ZKTraceProof,
)
from .pedersen import PedersenEngine, get_default_parameters
from .trace_verifier import AgentZKTraceVerifier


class BatchZKVerifier:
    """
    Orchestrates batch verification across autonomous agent fleet deliberations.
    Combines individual zero-knowledge receipts and homomorphically verifies
    swarm-wide aggregate resource expenditures.
    """

    def __init__(self, verifier: Optional[AgentZKTraceVerifier] = None):
        self.verifier = verifier or AgentZKTraceVerifier()
        self.params = get_default_parameters()
        self.pedersen = PedersenEngine(self.params)

    def verify_batch(
        self,
        proofs: List[ZKTraceProof],
        policy: Optional[CompliancePolicy] = None,
    ) -> BatchVerificationResult:
        """
        Verifies a collection of agent zero-knowledge proofs.
        """
        start_time = time.perf_counter()
        receipts: List[ZKProofReceipt] = []

        passed = 0
        failed = 0

        for proof in proofs:
            receipt = self.verifier.verify_proof(proof, policy)
            receipts.append(receipt)
            if receipt.is_valid:
                passed += 1
            else:
                failed += 1

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        all_valid = (failed == 0) and (len(proofs) > 0)

        return BatchVerificationResult(
            total_proofs=len(proofs),
            passed_count=passed,
            failed_count=failed,
            all_valid=all_valid,
            elapsed_ms=elapsed_ms,
            individual_receipts=receipts,
        )

    def aggregate_resource_commitments(
        self,
        proofs: List[ZKTraceProof],
    ) -> dict[str, str]:
        """
        Homomorphically combine token and cost commitments across the entire swarm:
        C_swarm = prod(C_i) mod p.
        """
        token_comms = [int(p.token_commitment, 16) for p in proofs]
        cost_comms = [int(p.cost_commitment, 16) for p in proofs]

        swarm_tokens = self.pedersen.add_commitments(token_comms)
        swarm_cost = self.pedersen.add_commitments(cost_comms)

        return {
            "swarm_token_commitment": hex(swarm_tokens),
            "swarm_cost_commitment": hex(swarm_cost),
            "proof_count": str(len(proofs)),
        }
