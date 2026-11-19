"""Tests for Core Data Models and Canonical Serialization."""

import pytest
from agent_zk_verifier.models import (
    CompliancePolicy,
    ExecutionTrace,
    PedersenParameters,
    RangeProof,
    SchnorrProof,
    TraceStep,
    ZKProofReceipt,
    ZKTraceProof,
    canonical_json,
    sha256_digest,
)


def test_canonical_json_sorting():
    d1 = {"z": 1, "a": 2, "m": {"b": 3, "a": 4}}
    d2 = {"a": 2, "z": 1, "m": {"a": 4, "b": 3}}
    assert canonical_json(d1) == canonical_json(d2)
    assert canonical_json(d1) == '{"a":2,"m":{"a":4,"b":3},"z":1}'


def test_sha256_digest():
    assert sha256_digest("hello") == sha256_digest(b"hello")
    assert len(sha256_digest("test")) == 64


def test_trace_step_digest_and_canonical():
    step = TraceStep(
        step_id="step_1",
        step_index=0,
        agent_id="agent_alpha",
        tool_name="web_search",
        model_name="qwen-3.5",
        token_count=150,
        latency_ms=250.5,
        financial_cost=0.0003,
        input_hash="hash_in_1",
        output_hash="hash_out_1",
        state_before_hash="state_0",
        state_after_hash="state_1",
        timestamp="2026-11-19T12:00:00Z",
    )
    d = step.canonical_dict()
    assert d["step_id"] == "step_1"
    assert d["token_count"] == 150
    assert len(step.digest()) == 64


def test_execution_trace_merkle_root_and_properties():
    steps = [
        TraceStep(
            step_id=f"step_{i}",
            step_index=i,
            agent_id="agent_alpha",
            tool_name="tool_a",
            model_name="model_m",
            token_count=100 * (i + 1),
            latency_ms=50.0,
            financial_cost=0.001,
            input_hash=f"in_{i}",
            output_hash=f"out_{i}",
            state_before_hash=f"st_{i}",
            state_after_hash=f"st_{i+1}",
        )
        for i in range(3)
    ]
    trace = ExecutionTrace(
        trace_id="trace_xyz",
        agent_id="agent_alpha",
        session_id="session_123",
        steps=steps,
        initial_state_hash="st_0",
        final_state_hash="st_3",
    )

    assert trace.total_tokens == 100 + 200 + 300
    assert trace.total_cost == pytest.approx(0.003)
    assert trace.total_latency_ms == pytest.approx(150.0)
    assert trace.distinct_tools == {"tool_a"}

    root = trace.compute_merkle_root()
    assert len(root) == 64

    # Test serialization roundtrip
    trace_dict = trace.to_dict()
    restored = ExecutionTrace.from_dict(trace_dict)
    assert restored.trace_id == trace.trace_id
    assert len(restored.steps) == 3
    assert restored.compute_merkle_root() == root


def test_empty_execution_trace_merkle_root():
    trace = ExecutionTrace(trace_id="empty", agent_id="a", session_id="s", steps=[])
    assert len(trace.compute_merkle_root()) == 64


def test_compliance_policy_digest():
    pol1 = CompliancePolicy(max_steps=50, max_tokens=100_000, allowed_tools=["t2", "t1"])
    pol2 = CompliancePolicy(max_steps=50, max_tokens=100_000, allowed_tools=["t1", "t2"])
    assert pol1.digest() == pol2.digest()


def test_pedersen_parameters_dict_roundtrip():
    params = PedersenParameters(p=23, q=11, g=4, h=9)
    d = params.to_dict()
    restored = PedersenParameters.from_dict(d)
    assert restored.p == 23
    assert restored.q == 11
    assert restored.g == 4
    assert restored.h == 9


def test_schnorr_and_range_proof_models():
    sp = SchnorrProof(R=10, e=20, s_v=30, s_r=40)
    sp_d = sp.to_dict()
    restored_sp = SchnorrProof.from_dict(sp_d)
    assert restored_sp.R == 10
    assert restored_sp.e == 20

    rp = RangeProof(
        max_bits=2,
        commitment=123,
        bit_commitments=[10, 20],
        bit_proofs=[{"R0": "0xa", "R1": "0xb", "e0": "0x1", "e1": "0x2", "s0": "0x3", "s1": "0x4"}],
    )
    rp_d = rp.to_dict()
    restored_rp = RangeProof.from_dict(rp_d)
    assert restored_rp.commitment == 123
    assert restored_rp.max_bits == 2
