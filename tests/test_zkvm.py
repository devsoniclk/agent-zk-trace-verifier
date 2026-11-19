"""Tests for zkVM Guest Execution Trace & Receipt Verification."""

import pytest
from agent_zk_verifier.models import ExecutionTrace, TraceStep
from agent_zk_verifier.zkvm import (
    DEFAULT_RISC0_IMAGE_ID,
    DEFAULT_SP1_VKEY,
    ZKVMExecutionReceipt,
    ZKVMVerifier,
)


def _make_trace() -> ExecutionTrace:
    steps = [
        TraceStep(
            step_id="step_0",
            step_index=0,
            agent_id="agent_1",
            tool_name="tool_1",
            model_name="model_1",
            token_count=120,
            latency_ms=10.0,
            financial_cost=0.001,
            input_hash="in_0",
            output_hash="out_0",
            state_before_hash="state_0",
            state_after_hash="state_1",
        )
    ]
    return ExecutionTrace(
        trace_id="trace_zkvm",
        agent_id="agent_1",
        session_id="session_zkvm",
        steps=steps,
        initial_state_hash="state_0",
        final_state_hash="state_1",
    )


def test_zkvm_receipt_generation_and_verification():
    trace = _make_trace()
    verifier = ZKVMVerifier()

    receipt = verifier.generate_receipt(trace, policy_digest="policy_abc123", system="risc0")
    assert receipt.system == "risc0"
    assert receipt.image_id == DEFAULT_RISC0_IMAGE_ID
    assert receipt.journal.total_tokens == 120

    is_valid, violations = verifier.verify_receipt(receipt, expected_policy_digest="policy_abc123")
    assert is_valid
    assert len(violations) == 0


def test_zkvm_receipt_serialization_roundtrip():
    trace = _make_trace()
    verifier = ZKVMVerifier()
    receipt = verifier.generate_receipt(trace, policy_digest="pol_hash", system="sp1")
    assert receipt.image_id == DEFAULT_SP1_VKEY

    d = receipt.to_dict()
    restored = ZKVMExecutionReceipt.from_dict(d)
    assert restored.system == receipt.system
    assert restored.seal == receipt.seal
    assert restored.journal.digest() == receipt.journal.digest()


def test_zkvm_receipt_tampered_seal():
    trace = _make_trace()
    verifier = ZKVMVerifier()
    receipt = verifier.generate_receipt(trace, policy_digest="pol_hash")

    receipt.seal = "bad_seal_0000000000000000000000000000000000000000000000000000000000"
    is_valid, violations = verifier.verify_receipt(receipt)
    assert not is_valid
    assert any("Invalid zkVM proof seal" in v for v in violations)


def test_zkvm_receipt_unauthorized_image_id():
    trace = _make_trace()
    verifier = ZKVMVerifier(authorized_image_ids=["0x1234"])
    receipt = verifier.generate_receipt(trace, policy_digest="pol_hash", image_id="0x9999")

    is_valid, violations = verifier.verify_receipt(receipt)
    assert not is_valid
    assert any("Unauthorized zkVM image ID" in v for v in violations)
