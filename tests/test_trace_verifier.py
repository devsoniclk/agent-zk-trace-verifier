"""Tests for AgentZKTraceVerifier End-to-End Audit, Proving, and Verification."""

import pytest
from agent_zk_verifier.models import CompliancePolicy, ExecutionTrace, TraceStep
from agent_zk_verifier.trace_verifier import AgentZKTraceVerifier


def _create_sample_trace(step_count: int = 3) -> ExecutionTrace:
    steps = []
    for i in range(step_count):
        steps.append(
            TraceStep(
                step_id=f"step_{i}",
                step_index=i,
                agent_id="forge_agent",
                tool_name="web_search",
                model_name="qwen-3.5",
                token_count=100 + i * 20,
                latency_ms=150.0,
                financial_cost=0.0005,
                input_hash=f"in_hash_{i}",
                output_hash=f"out_hash_{i}",
                state_before_hash=f"state_hash_{i}",
                state_after_hash=f"state_hash_{i+1}",
            )
        )
    return ExecutionTrace(
        trace_id="trace_test_001",
        agent_id="forge_agent",
        session_id="session_001",
        steps=steps,
        initial_state_hash="state_hash_0",
        final_state_hash=f"state_hash_{step_count}",
    )


def test_audit_valid_trace():
    verifier = AgentZKTraceVerifier()
    trace = _create_sample_trace(3)
    policy = CompliancePolicy(allowed_tools=["web_search"], allowed_models=["qwen-3.5"])

    is_valid, violations = verifier.audit_trace(trace, policy)
    assert is_valid
    assert len(violations) == 0


def test_audit_broken_state_chain():
    verifier = AgentZKTraceVerifier()
    trace = _create_sample_trace(3)
    # Break state transition between step 0 and 1
    trace.steps[1].state_before_hash = "corrupted_state_hash"

    is_valid, violations = verifier.audit_trace(trace)
    assert not is_valid
    assert any("State chain broken" in v for v in violations)


def test_audit_unauthorized_tool():
    verifier = AgentZKTraceVerifier()
    trace = _create_sample_trace(2)
    trace.steps[1].tool_name = "unauthorized_malicious_tool"
    policy = CompliancePolicy(allowed_tools=["web_search"])

    is_valid, violations = verifier.audit_trace(trace, policy)
    assert not is_valid
    assert any("Unauthorized tool invocation" in v for v in violations)


def test_end_to_end_zk_proof_and_verification():
    verifier = AgentZKTraceVerifier()
    trace = _create_sample_trace(2)
    policy = CompliancePolicy(
        max_steps=10,
        max_tokens=100_000,
        max_cost_usd=1.0,
        allowed_tools=["web_search"],
    )

    # 1. Prover synthesizes zero-knowledge proof (using smaller range bits for fast testing)
    proof = verifier.prove_trace(trace, policy, token_range_bits=12, cost_range_bits=14)
    assert proof.trace_id == trace.trace_id
    assert proof.merkle_root == trace.compute_merkle_root()
    assert proof.tool_membership_verified

    # 2. Verifier checks proof
    receipt = verifier.verify_proof(proof, policy)
    assert receipt.is_valid
    assert receipt.trace_id == trace.trace_id
    assert receipt.verification_latency_ms > 0
    assert len(receipt.details["violations"]) == 0


def test_verify_proof_policy_mismatch_fails():
    verifier = AgentZKTraceVerifier()
    trace = _create_sample_trace(2)
    policy_a = CompliancePolicy(max_steps=10)
    policy_b = CompliancePolicy(max_steps=5)

    proof = verifier.prove_trace(trace, policy_a, token_range_bits=10, cost_range_bits=12)

    receipt = verifier.verify_proof(proof, policy_b)
    assert not receipt.is_valid
    assert any("Policy mismatch" in v for v in receipt.details["violations"])
