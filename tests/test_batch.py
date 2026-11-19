"""Tests for Multi-Agent Batch Verification and Resource Aggregation."""

import pytest
from agent_zk_verifier.batch import BatchZKVerifier
from agent_zk_verifier.models import CompliancePolicy, ExecutionTrace, TraceStep
from agent_zk_verifier.trace_verifier import AgentZKTraceVerifier


def _create_trace(trace_id: str, tokens: int = 100) -> ExecutionTrace:
    step = TraceStep(
        step_id=f"step_{trace_id}",
        step_index=0,
        agent_id=f"agent_{trace_id}",
        tool_name="tool_batch",
        model_name="model_batch",
        token_count=tokens,
        latency_ms=50.0,
        financial_cost=0.001,
        input_hash="inh",
        output_hash="outh",
        state_before_hash="sbh",
        state_after_hash="sah",
    )
    return ExecutionTrace(
        trace_id=trace_id,
        agent_id=f"agent_{trace_id}",
        session_id="session_batch",
        steps=[step],
        initial_state_hash="sbh",
        final_state_hash="sah",
    )


def test_batch_verification_all_pass():
    trace_verifier = AgentZKTraceVerifier()
    batch_verifier = BatchZKVerifier(trace_verifier)
    policy = CompliancePolicy(max_tokens=10_000, allowed_tools=["tool_batch"])

    traces = [_create_trace(f"trace_{i}", tokens=50 * (i + 1)) for i in range(3)]
    proofs = [trace_verifier.prove_trace(t, policy, token_range_bits=10, cost_range_bits=12) for t in traces]

    res = batch_verifier.verify_batch(proofs, policy)
    assert res.all_valid
    assert res.total_proofs == 3
    assert res.passed_count == 3
    assert res.failed_count == 0
    assert len(res.individual_receipts) == 3


def test_batch_resource_aggregation():
    trace_verifier = AgentZKTraceVerifier()
    batch_verifier = BatchZKVerifier(trace_verifier)
    policy = CompliancePolicy(max_tokens=10_000, allowed_tools=["tool_batch"])

    t1 = _create_trace("t1", 100)
    t2 = _create_trace("t2", 200)

    p1 = trace_verifier.prove_trace(t1, policy, token_range_bits=10, cost_range_bits=12)
    p2 = trace_verifier.prove_trace(t2, policy, token_range_bits=10, cost_range_bits=12)

    agg = batch_verifier.aggregate_resource_commitments([p1, p2])
    assert "swarm_token_commitment" in agg
    assert "swarm_cost_commitment" in agg
    assert agg["proof_count"] == "2"
