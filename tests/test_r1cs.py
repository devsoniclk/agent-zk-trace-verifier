"""Tests for R1CS Circuit Synthesis, Witness Generation, and Verification."""

import pytest
from agent_zk_verifier.models import TraceStep
from agent_zk_verifier.r1cs import (
    AgentTraceCircuitSynthesizer,
    R1CSBuilder,
    R1CSVerifier,
)


def test_r1cs_builder_primitives():
    builder = R1CSBuilder(circuit_id="test_prim")
    builder.assert_constant("a", 5)
    builder.assert_constant("b", 10)
    builder.assert_sum("a", "b", "c")
    builder.assert_mul("c", "a", "d")  # 15 * 5 = 75

    circuit = builder.build()
    assert circuit.circuit_id == "test_prim"
    assert len(circuit.constraints) == 4

    witness = {"a": 5, "b": 10, "c": 15, "d": 75}
    satisfied, violations = R1CSVerifier.verify(circuit, witness)
    assert satisfied
    assert len(violations) == 0

    # Wrong witness
    bad_witness = {"a": 5, "b": 10, "c": 15, "d": 76}
    sat_bad, viol_bad = R1CSVerifier.verify(circuit, bad_witness)
    assert not sat_bad
    assert len(viol_bad) == 1


def test_r1cs_boolean_constraint():
    builder = R1CSBuilder(circuit_id="bool_test")
    builder.assert_boolean("bit")
    circuit = builder.build()

    # bit = 0 is valid
    assert R1CSVerifier.verify(circuit, {"bit": 0})[0]
    # bit = 1 is valid
    assert R1CSVerifier.verify(circuit, {"bit": 1})[0]
    # bit = 2 is invalid
    assert not R1CSVerifier.verify(circuit, {"bit": 2})[0]


def test_agent_trace_circuit_synthesis_and_witness():
    steps = [
        TraceStep(
            step_id=f"s_{i}",
            step_index=i,
            agent_id="agent_1",
            tool_name="tool_1",
            model_name="model_1",
            token_count=100 + i * 50,
            latency_ms=10.0,
            financial_cost=0.001,
            input_hash="inh",
            output_hash="outh",
            state_before_hash="sbh",
            state_after_hash="sah",
        )
        for i in range(3)
    ]

    circuit = AgentTraceCircuitSynthesizer.synthesize_trace_circuit("trace_123", len(steps))
    witness = R1CSVerifier.generate_trace_witness(steps)

    satisfied, violations = R1CSVerifier.verify(circuit, witness)
    assert satisfied
    assert len(violations) == 0

    # Tampering with token accumulator in witness
    tampered_witness = dict(witness)
    tampered_witness["total_tokens"] += 1
    tampered_sat, tampered_viol = R1CSVerifier.verify(circuit, tampered_witness)
    assert not tampered_sat
    assert len(tampered_viol) > 0
