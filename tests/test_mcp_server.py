"""Tests for AgentZKMCPServer JSON-RPC Interface."""

import json
import pytest
from agent_zk_verifier.mcp_server import AgentZKMCPServer
from agent_zk_verifier.models import CompliancePolicy, ExecutionTrace, TraceStep
from agent_zk_verifier.trace_verifier import AgentZKTraceVerifier
from agent_zk_verifier.zkvm import ZKVMVerifier


def _make_trace_dict() -> dict:
    step = TraceStep(
        step_id="step_mcp_0",
        step_index=0,
        agent_id="agent_mcp",
        tool_name="read_file",
        model_name="gemma-4",
        token_count=150,
        latency_ms=20.0,
        financial_cost=0.0002,
        input_hash="hash_in",
        output_hash="hash_out",
        state_before_hash="state_0",
        state_after_hash="state_1",
    )
    trace = ExecutionTrace(
        trace_id="trace_mcp_test",
        agent_id="agent_mcp",
        session_id="session_mcp",
        steps=[step],
        initial_state_hash="state_0",
        final_state_hash="state_1",
    )
    return trace.to_dict()


def test_mcp_initialize():
    server = AgentZKMCPServer()
    resp = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert resp["id"] == 1
    assert resp["result"]["serverInfo"]["name"] == "agent-zk-trace-verifier"


def test_mcp_tools_list():
    server = AgentZKMCPServer()
    resp = server.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tools = resp["result"]["tools"]
    names = {t["name"] for t in tools}
    assert "audit_trajectory_integrity" in names
    assert "prove_trace_constraints" in names
    assert "verify_zk_proof" in names
    assert "verify_r1cs_circuit" in names
    assert "verify_zkvm_receipt" in names
    assert "aggregate_batch_proofs" in names


def test_mcp_all_tools():
    server = AgentZKMCPServer()
    trace_dict = _make_trace_dict()

    # 1. audit_trajectory_integrity
    audit_resp = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "audit_trajectory_integrity",
                "arguments": {"trace": trace_dict},
            },
        }
    )
    audit_data = json.loads(audit_resp["result"]["content"][0]["text"])
    assert audit_data["is_valid"] is True

    # 2. verify_r1cs_circuit
    r1cs_resp = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "verify_r1cs_circuit",
                "arguments": {"trace": trace_dict},
            },
        }
    )
    r1cs_data = json.loads(r1cs_resp["result"]["content"][0]["text"])
    assert r1cs_data["satisfied"] is True

    # 3. prove_trace_constraints & verify_zk_proof
    prove_resp = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "prove_trace_constraints",
                "arguments": {"trace": trace_dict},
            },
        }
    )
    proof_dict = json.loads(prove_resp["result"]["content"][0]["text"])
    assert "proof_id" in proof_dict

    verify_resp = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "verify_zk_proof",
                "arguments": {"proof": proof_dict},
            },
        }
    )
    receipt_dict = json.loads(verify_resp["result"]["content"][0]["text"])
    assert receipt_dict["is_valid"] is True

    # 4. aggregate_batch_proofs
    batch_resp = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "aggregate_batch_proofs",
                "arguments": {"proofs": [proof_dict]},
            },
        }
    )
    batch_data = json.loads(batch_resp["result"]["content"][0]["text"])
    assert batch_data["all_valid"] is True
    assert "aggregated_commitments" in batch_data

    # 5. verify_zkvm_receipt
    trace = ExecutionTrace.from_dict(trace_dict)
    zkvm = ZKVMVerifier()
    rec = zkvm.generate_receipt(trace, policy_digest="test_pol")
    zkvm_resp = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {
                "name": "verify_zkvm_receipt",
                "arguments": {
                    "receipt": rec.to_dict(),
                    "expected_policy_digest": "test_pol",
                },
            },
        }
    )
    zkvm_data = json.loads(zkvm_resp["result"]["content"][0]["text"])
    assert zkvm_data["receipt_valid"] is True


def test_mcp_unknown_tool():
    server = AgentZKMCPServer()
    resp = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {"name": "invalid_tool", "arguments": {}},
        }
    )
    assert "error" in resp
    assert resp["error"]["code"] == -32000


def test_mcp_unknown_method():
    server = AgentZKMCPServer()
    resp = server.handle_request({"jsonrpc": "2.0", "id": 99, "method": "nonexistent"})
    assert "error" in resp
    assert resp["error"]["code"] == -32601
