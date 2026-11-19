"""
Example: Proving Policy Compliance Without Disclosing Secret Inputs or Tool Arguments.
Demonstrates:
- Private tool invocation with sensitive customer data
- Zero-knowledge proof that executed tools belong strictly to authorized whitelist
- Range proof that compute spending was under threshold
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent_zk_verifier import AgentZKTraceVerifier, CompliancePolicy, ExecutionTrace, TraceStep, sha256_digest


def main():
    print("=== Confidential Agent Policy Proof Demonstration ===\n")
    verifier = AgentZKTraceVerifier()

    # Secret user prompt and confidential database payload
    secret_prompt = "Confidential customer KYC financial records for corporate audit."
    secret_output = "Approved: risk score 0.02, verified identity."

    # The trace only records cryptographic hashes of private content
    step = TraceStep(
        step_id="step_kyc_0",
        step_index=0,
        agent_id="kyc_verifier_agent",
        tool_name="kyc_identity_check",
        model_name="gemma-4",
        token_count=350,
        latency_ms=120.0,
        financial_cost=0.0025,
        input_hash=sha256_digest(secret_prompt),
        output_hash=sha256_digest(secret_output),
        state_before_hash=sha256_digest("genesis_state"),
        state_after_hash=sha256_digest("kyc_verified_state"),
    )

    trace = ExecutionTrace(
        trace_id="trace_confidential_kyc",
        agent_id="kyc_verifier_agent",
        session_id="session_isolated_01",
        steps=[step],
        initial_state_hash=step.state_before_hash,
        final_state_hash=step.state_after_hash,
    )

    public_policy = CompliancePolicy(
        max_steps=5,
        max_tokens=10_000,
        max_cost_usd=0.10,
        allowed_tools=["kyc_identity_check", "sanctions_screener"],
        allowed_models=["gemma-4"],
    )

    print("[*] Synthesizing Zero-Knowledge Proof...")
    proof = verifier.prove_trace(trace, public_policy, token_range_bits=10, cost_range_bits=12)

    print("[*] Transmitting ZK Proof to third-party auditor (Zero secrets transmitted)...")
    print(f"    Public Proof ID: {proof.proof_id}")
    print(f"    Public Token Commitment: {proof.token_commitment[:24]}...")
    print(f"    Public Cost Commitment:  {proof.cost_commitment[:24]}...")
    print(f"    Policy Digest:           {proof.policy_digest[:24]}...\n")

    print("[*] Auditor Verifying Proof...")
    receipt = verifier.verify_proof(proof, public_policy)
    print(f"[+] Audit Result: {'VERIFIED AND CERTIFIED' if receipt.is_valid else 'REJECTED'}")
    print(f"[+] Verified in {receipt.verification_latency_ms:.2f} ms")


if __name__ == "__main__":
    main()
