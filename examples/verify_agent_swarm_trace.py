"""
Example: End-to-End Zero-Knowledge Verification of an Autonomous Agent Swarm Trajectory.
Demonstrates:
1. Trajectory generation with sequential state transitions
2. Homomorphic Pedersen commitments to resource bounds
3. Schnorr NIZK & Range Proof generation
4. R1CS arithmetic circuit verification
5. Multi-agent batch verification and homomorphic swarm aggregation
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent_zk_verifier import (
    AgentZKTraceVerifier,
    BatchZKVerifier,
    CompliancePolicy,
    ExecutionTrace,
    TraceStep,
)


def create_agent_trace(agent_id: str, step_count: int = 3) -> ExecutionTrace:
    steps = []
    state_curr = "0xstate_genesis"
    for i in range(step_count):
        state_next = f"0xstate_{agent_id}_{i+1}"
        step = TraceStep(
            step_id=f"step_{agent_id}_{i}",
            step_index=i,
            agent_id=agent_id,
            tool_name="web_search" if i == 0 else "code_interpreter",
            model_name="qwen-3.5",
            token_count=250 + i * 100,
            latency_ms=180.0,
            financial_cost=0.0012,
            input_hash=f"0xinput_{i}",
            output_hash=f"0xoutput_{i}",
            state_before_hash=state_curr,
            state_after_hash=state_next,
        )
        steps.append(step)
        state_curr = state_next

    return ExecutionTrace(
        trace_id=f"trace_{agent_id}",
        agent_id=agent_id,
        session_id="session_swarm_alpha",
        steps=steps,
        initial_state_hash="0xstate_genesis",
        final_state_hash=state_curr,
    )


def main():
    print("=== Agent ZK Trace Verifier: Swarm Trajectory Verification ===\n")
    verifier = AgentZKTraceVerifier()
    batch_verifier = BatchZKVerifier(verifier)

    policy = CompliancePolicy(
        max_steps=10,
        max_tokens=50_000,
        max_cost_usd=0.50,
        allowed_tools=["web_search", "code_interpreter"],
        allowed_models=["qwen-3.5"],
    )

    agents = ["agent_researcher", "agent_coder", "agent_auditor"]
    proofs = []

    for ag in agents:
        trace = create_agent_trace(ag, step_count=2)
        print(f"[*] Auditing and proving trajectory for {ag} (Tokens: {trace.total_tokens})...")
        proof = verifier.prove_trace(trace, policy, token_range_bits=12, cost_range_bits=14)
        receipt = verifier.verify_proof(proof, policy)
        print(f"    -> ZK Proof ID: {proof.proof_id}")
        print(f"    -> Merkle Root: {proof.merkle_root[:16]}...")
        print(f"    -> Verification Status: {'VALID' if receipt.is_valid else 'INVALID'}")
        print(f"    -> Latency: {receipt.verification_latency_ms:.2f} ms\n")
        proofs.append(proof)

    print("[*] Running Batch Swarm Verification & Resource Aggregation...")
    batch_res = batch_verifier.verify_batch(proofs, policy)
    agg = batch_verifier.aggregate_resource_commitments(proofs)

    print(f"[+] All {batch_res.total_proofs} swarm proofs verified: {batch_res.all_valid}")
    print(f"[+] Total batch verification time: {batch_res.elapsed_ms:.2f} ms")
    print(f"[+] Homomorphic Swarm Token Commitment: {agg['swarm_token_commitment'][:24]}...")
    print(f"[+] Homomorphic Swarm Cost Commitment:  {agg['swarm_cost_commitment'][:24]}...")


if __name__ == "__main__":
    main()
