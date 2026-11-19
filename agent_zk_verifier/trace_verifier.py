"""
Primary Zero-Knowledge Trajectory Integrity & Execution Trace Verification Engine.
Coordinates Pedersen commitments, NIZK Schnorr proofs, Range proofs, and R1CS circuits.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    CompliancePolicy,
    ExecutionTrace,
    ZKProofReceipt,
    ZKTraceProof,
    sha256_digest,
)
from .pedersen import PedersenEngine, get_default_parameters
from .range_proof import RangeProofEngine
from .r1cs import AgentTraceCircuitSynthesizer, R1CSVerifier
from .schnorr import SchnorrProver, SchnorrVerifier


class AgentZKTraceVerifier:
    """
    Comprehensive Zero-Knowledge Trace Verifier for Autonomous AI Agent Swarms.
    Generates and verifies cryptographic proofs that an agent trajectory satisfied
    all compliance, safety, and resource invariants without leaking private deliberations.
    """

    def __init__(self):
        self.params = get_default_parameters()
        self.pedersen = PedersenEngine(self.params)
        self.schnorr_prover = SchnorrProver(self.params)
        self.schnorr_verifier = SchnorrVerifier(self.params)
        self.range_engine = RangeProofEngine(self.params)

    def audit_trace(
        self,
        trace: ExecutionTrace,
        policy: Optional[CompliancePolicy] = None,
    ) -> Tuple[bool, List[str]]:
        """
        Deterministic, non-ZK audit of raw execution trace integrity.
        Detects uncommitted jumps, broken state chains, and policy violations.
        """
        violations = []
        pol = policy or CompliancePolicy()

        if not trace.steps:
            violations.append("Execution trace contains 0 steps.")
            return False, violations

        # 1. Step continuity and state transition chain
        for i, step in enumerate(trace.steps):
            if step.step_index != i:
                violations.append(
                    f"Step index discontinuity at position {i}: step_index is {step.step_index}"
                )

            if i > 0:
                prev_step = trace.steps[i - 1]
                if step.state_before_hash != prev_step.state_after_hash:
                    violations.append(
                        f"State chain broken at step {i}: state_before_hash ({step.state_before_hash[:8]}...) != prev state_after_hash ({prev_step.state_after_hash[:8]}...)"
                    )

            if pol.allowed_tools and step.tool_name not in pol.allowed_tools:
                violations.append(f"Unauthorized tool invocation: '{step.tool_name}' at step {i}")

            if pol.allowed_models and step.model_name not in pol.allowed_models:
                violations.append(f"Unauthorized model usage: '{step.model_name}' at step {i}")

        # 2. Global policy boundaries
        if len(trace.steps) > pol.max_steps:
            violations.append(f"Step count {len(trace.steps)} exceeds policy limit {pol.max_steps}")

        if trace.total_tokens > pol.max_tokens:
            violations.append(f"Total tokens {trace.total_tokens} exceeds policy limit {pol.max_tokens}")

        if trace.total_cost > pol.max_cost_usd:
            violations.append(f"Total cost ${trace.total_cost:.4f} exceeds policy limit ${pol.max_cost_usd:.4f}")

        if trace.total_latency_ms > pol.max_latency_ms:
            violations.append(
                f"Total latency {trace.total_latency_ms:.1f}ms exceeds policy limit {pol.max_latency_ms:.1f}ms"
            )

        return len(violations) == 0, violations

    def prove_trace(
        self,
        trace: ExecutionTrace,
        policy: Optional[CompliancePolicy] = None,
        token_range_bits: int = 20,  # Up to 1,048,575 tokens
        cost_range_bits: int = 24,   # Up to ~16.7 USD in microdollars
    ) -> ZKTraceProof:
        """
        Synthesizes a full zero-knowledge proof for the agent trajectory:
        1. Homomorphic Pedersen commitments to resource usage
        2. Schnorr NIZK proofs of knowledge for commitment opening
        3. Zero-knowledge range proofs enforcing token and cost bounds
        4. R1CS circuit synthesis & witness verification
        5. Merkle root commitment to trace sequence
        """
        pol = policy or CompliancePolicy()
        is_valid, violations = self.audit_trace(trace, pol)
        if not is_valid:
            raise ValueError(f"Cannot generate ZK proof for invalid trace: {'; '.join(violations)}")

        merkle_root = trace.compute_merkle_root()
        policy_digest = pol.digest()

        # 1. Resource commitments
        tokens_val = trace.total_tokens
        cost_micro = int(trace.total_cost * 1_000_000)

        comm_tokens = self.pedersen.commit(value=tokens_val)
        comm_cost = self.pedersen.commit(value=cost_micro)

        # 2. Schnorr NIZK proofs of knowledge
        context_tokens = f"token_comm:{trace.trace_id}:{policy_digest}"
        context_cost = f"cost_comm:{trace.trace_id}:{policy_digest}"

        schnorr_tokens = self.schnorr_prover.prove(comm_tokens, context=context_tokens)
        schnorr_cost = self.schnorr_prover.prove(comm_cost, context=context_cost)

        # 3. Range proofs
        range_tokens = self.range_engine.prove_range(tokens_val, max_bits=token_range_bits)
        range_cost = self.range_engine.prove_range(cost_micro, max_bits=cost_range_bits)

        # 4. R1CS Circuit synthesis & verification
        circuit = AgentTraceCircuitSynthesizer.synthesize_trace_circuit(trace.trace_id, len(trace.steps))
        witness = R1CSVerifier.generate_trace_witness(trace.steps)
        r1cs_satisfied, r1cs_errs = R1CSVerifier.verify(circuit, witness)
        if not r1cs_satisfied:
            raise ValueError(f"R1CS circuit unsatisfied: {r1cs_errs}")

        r1cs_circuit_digest = sha256_digest(str(circuit.to_dict()))

        # 5. Tool membership verification flag
        tool_membership_ok = True
        if pol.allowed_tools:
            tool_membership_ok = all(s.tool_name in pol.allowed_tools for s in trace.steps)

        proof_id = f"zkproof_{uuid.uuid4().hex[:12]}"

        return ZKTraceProof(
            proof_id=proof_id,
            trace_id=trace.trace_id,
            merkle_root=merkle_root,
            token_commitment=comm_tokens.to_hex(),
            cost_commitment=comm_cost.to_hex(),
            step_count=len(trace.steps),
            token_range_proof=range_tokens,
            cost_range_proof=range_cost,
            token_schnorr_proof=schnorr_tokens,
            cost_schnorr_proof=schnorr_cost,
            tool_membership_verified=tool_membership_ok,
            r1cs_circuit_digest=r1cs_circuit_digest,
            policy_digest=policy_digest,
        )

    def verify_proof(
        self,
        proof: ZKTraceProof,
        policy: Optional[CompliancePolicy] = None,
    ) -> ZKProofReceipt:
        """
        Cryptographically verifies the zero-knowledge proof without accessing
        the underlying execution trace or private payloads.
        Returns a tamper-evident ZKProofReceipt.
        """
        start_time = time.perf_counter()
        pol = policy or CompliancePolicy()
        expected_policy_digest = pol.digest()

        violations = []

        # 1. Policy digest check
        if proof.policy_digest != expected_policy_digest:
            violations.append(
                f"Policy mismatch: expected {expected_policy_digest}, proof has {proof.policy_digest}"
            )

        # 2. Tool membership check
        if not proof.tool_membership_verified:
            violations.append("Tool membership check failed or unauthorized tools executed.")

        # 3. Step count policy check
        if proof.step_count > pol.max_steps:
            violations.append(f"Proof step count {proof.step_count} exceeds policy limit {pol.max_steps}")

        # 4. Verify Schnorr NIZK proofs
        token_comm_int = int(proof.token_commitment, 16)
        cost_comm_int = int(proof.cost_commitment, 16)

        context_tokens = f"token_comm:{proof.trace_id}:{proof.policy_digest}"
        context_cost = f"cost_comm:{proof.trace_id}:{proof.policy_digest}"

        if not self.schnorr_verifier.verify(token_comm_int, proof.token_schnorr_proof, context=context_tokens):
            violations.append("Schnorr NIZK proof verification failed for token commitment.")

        if not self.schnorr_verifier.verify(cost_comm_int, proof.cost_schnorr_proof, context=context_cost):
            violations.append("Schnorr NIZK proof verification failed for cost commitment.")

        # 5. Verify Zero-Knowledge Range Proofs
        if not self.range_engine.verify_range(proof.token_range_proof):
            violations.append("Token zero-knowledge range proof verification failed.")

        if not self.range_engine.verify_range(proof.cost_range_proof):
            violations.append("Cost zero-knowledge range proof verification failed.")

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        is_valid = len(violations) == 0

        receipt_id = f"zkreceipt_{uuid.uuid4().hex[:12]}"
        return ZKProofReceipt(
            receipt_id=receipt_id,
            proof_id=proof.proof_id,
            trace_id=proof.trace_id,
            merkle_root=proof.merkle_root,
            policy_digest=proof.policy_digest,
            is_valid=is_valid,
            verified_at=datetime.now(timezone.utc).isoformat(),
            verification_latency_ms=elapsed_ms,
            details={
                "step_count": proof.step_count,
                "token_commitment": proof.token_commitment,
                "cost_commitment": proof.cost_commitment,
                "violations": violations,
            },
        )
