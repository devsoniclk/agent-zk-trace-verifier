"""Tests for Click/Rich CLI Commands."""

import json
from click.testing import CliRunner
from agent_zk_verifier.cli import main
from agent_zk_verifier.models import ExecutionTrace, TraceStep


def _write_trace_file(tmp_path, step_count=2):
    steps = [
        TraceStep(
            step_id=f"step_{i}",
            step_index=i,
            agent_id="cli_agent",
            tool_name="tool_cli",
            model_name="model_cli",
            token_count=100 + i * 20,
            latency_ms=10.0,
            financial_cost=0.001,
            input_hash=f"in_{i}",
            output_hash=f"out_{i}",
            state_before_hash=f"st_{i}",
            state_after_hash=f"st_{i+1}",
        )
        for i in range(step_count)
    ]
    trace = ExecutionTrace(
        trace_id="cli_trace_test",
        agent_id="cli_agent",
        session_id="cli_sess",
        steps=steps,
        initial_state_hash="st_0",
        final_state_hash=f"st_{step_count}",
    )
    p = tmp_path / "trace.json"
    with open(p, "w", encoding="utf-8") as f:
        json.dump(trace.to_dict(), f)
    return str(p)


def test_cli_audit_command(tmp_path):
    runner = CliRunner()
    trace_path = _write_trace_file(tmp_path)

    result = runner.invoke(main, ["audit", trace_path])
    assert result.exit_code == 0
    assert "Execution Trajectory Audit Summary" in result.output
    assert "PASS" in result.output


def test_cli_r1cs_command(tmp_path):
    runner = CliRunner()
    trace_path = _write_trace_file(tmp_path)

    result = runner.invoke(main, ["r1cs", trace_path])
    assert result.exit_code == 0
    assert "R1CS Circuit Synthesis & Verification" in result.output
    assert "YES" in result.output


def test_cli_prove_and_verify(tmp_path):
    runner = CliRunner()
    trace_path = _write_trace_file(tmp_path)
    proof_path = str(tmp_path / "proof.json")

    # Prove
    res_prove = runner.invoke(main, ["prove", trace_path, "-o", proof_path])
    assert res_prove.exit_code == 0
    assert "Zero-Knowledge Proof Generated Successfully!" in res_prove.output

    # Verify
    res_verify = runner.invoke(main, ["verify", proof_path])
    assert res_verify.exit_code == 0
    assert "ZK Proof Verification Succeeded!" in res_verify.output

    # Batch
    res_batch = runner.invoke(main, ["batch", proof_path])
    assert res_batch.exit_code == 0
    assert "Total Proofs" in res_batch.output
