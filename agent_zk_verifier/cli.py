"""
Click and Rich Command-Line Interface for Zero-Knowledge Trace Verifier.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .batch import BatchZKVerifier
from .mcp_server import AgentZKMCPServer
from .models import CompliancePolicy, ExecutionTrace, ZKTraceProof
from .pedersen import PedersenEngine, get_default_parameters
from .r1cs import AgentTraceCircuitSynthesizer, R1CSVerifier
from .trace_verifier import AgentZKTraceVerifier
from .zkvm import ZKVMExecutionReceipt, ZKVMVerifier

console = Console()


@click.group()
@click.version_option(version="0.1.0")
def main():
    """Agent ZK Trace Verifier: Zero-Knowledge Verification for Autonomous Agent Swarms."""
    pass


@main.command()
@click.argument("trace_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--policy", "-p", type=click.Path(exists=True, dir_okay=False), help="Path to policy JSON.")
def audit(trace_path: str, policy: Optional[str]):
    """Audit raw execution trace for step continuity, broken state hashes, and policy breaches."""
    with open(trace_path, "r", encoding="utf-8") as f:
        trace_data = json.load(f)
    trace = ExecutionTrace.from_dict(trace_data)

    pol = CompliancePolicy()
    if policy:
        with open(policy, "r", encoding="utf-8") as f:
            pol = CompliancePolicy(**json.load(f))

    verifier = AgentZKTraceVerifier()
    is_valid, violations = verifier.audit_trace(trace, pol)

    table = Table(title="Execution Trajectory Audit Summary")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Trace ID", trace.trace_id)
    table.add_row("Agent ID", trace.agent_id)
    table.add_row("Steps", str(len(trace.steps)))
    table.add_row("Total Tokens", f"{trace.total_tokens:,}")
    table.add_row("Total Cost ($)", f"${trace.total_cost:.4f}")
    table.add_row("Total Latency (ms)", f"{trace.total_latency_ms:.1f}")
    table.add_row("Merkle Root", trace.compute_merkle_root()[:16] + "...")
    table.add_row("Audit Status", "[bold green]PASS[/bold green]" if is_valid else "[bold red]FAIL[/bold red]")

    console.print(table)

    if not is_valid:
        console.print("[bold red]Violations Detected:[/bold red]")
        for v in violations:
            console.print(f"  [red]• {v}[/red]")
        sys.exit(1)
    else:
        console.print("[bold green]Trace satisfies all sequential continuity and policy invariants.[/bold green]")


@main.command()
@click.argument("trace_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--policy", "-p", type=click.Path(exists=True, dir_okay=False), help="Path to policy JSON.")
@click.option("--output", "-o", type=click.Path(dir_okay=False), default="zk_proof.json", help="Output proof path.")
def prove(trace_path: str, policy: Optional[str], output: str):
    """Generate a Zero-Knowledge Proof for an execution trajectory."""
    with open(trace_path, "r", encoding="utf-8") as f:
        trace_data = json.load(f)
    trace = ExecutionTrace.from_dict(trace_data)

    pol = CompliancePolicy()
    if policy:
        with open(policy, "r", encoding="utf-8") as f:
            pol = CompliancePolicy(**json.load(f))

    verifier = AgentZKTraceVerifier()
    with console.status("[bold cyan]Synthesizing Zero-Knowledge Proof (Pedersen, Schnorr, Range, R1CS)...[/bold cyan]"):
        proof = verifier.prove_trace(trace, pol)

    proof_dict = proof.to_dict()
    with open(output, "w", encoding="utf-8") as f:
        json.dump(proof_dict, f, indent=2)

    console.print(
        Panel.fit(
            f"[bold green]Zero-Knowledge Proof Generated Successfully![/bold green]\n"
            f"Proof ID: [cyan]{proof.proof_id}[/cyan]\n"
            f"Trace Merkle Root: [yellow]{proof.merkle_root}[/yellow]\n"
            f"Token Commitment: [magenta]{proof.token_commitment[:18]}...[/magenta]\n"
            f"Cost Commitment: [magenta]{proof.cost_commitment[:18]}...[/magenta]\n"
            f"Saved to: [bold]{output}[/bold]",
            title="ZK Proof Synthesis",
        )
    )


@main.command()
@click.argument("proof_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--policy", "-p", type=click.Path(exists=True, dir_okay=False), help="Path to policy JSON.")
def verify(proof_path: str, policy: Optional[str]):
    """Verify a Zero-Knowledge Proof against public constraints."""
    with open(proof_path, "r", encoding="utf-8") as f:
        proof_data = json.load(f)
    proof = ZKTraceProof.from_dict(proof_data)

    pol = CompliancePolicy()
    if policy:
        with open(policy, "r", encoding="utf-8") as f:
            pol = CompliancePolicy(**json.load(f))

    verifier = AgentZKTraceVerifier()
    with console.status("[bold cyan]Verifying Zero-Knowledge Proof...[/bold cyan]"):
        receipt = verifier.verify_proof(proof, pol)

    if receipt.is_valid:
        console.print(
            Panel.fit(
                f"[bold green]ZK Proof Verification Succeeded![/bold green]\n"
                f"Receipt ID: [cyan]{receipt.receipt_id}[/cyan]\n"
                f"Trace ID: [yellow]{receipt.trace_id}[/yellow]\n"
                f"Verification Latency: [magenta]{receipt.verification_latency_ms:.2f} ms[/magenta]",
                title="ZK Verification Receipt",
            )
        )
    else:
        console.print(
            Panel.fit(
                f"[bold red]ZK Proof Verification FAILED![/bold red]\n"
                f"Violations:\n"
                + "\n".join(f"  • {v}" for v in receipt.details.get("violations", [])),
                title="Verification Failure",
            )
        )
        sys.exit(1)


@main.command()
@click.argument("trace_path", type=click.Path(exists=True, dir_okay=False))
def r1cs(trace_path: str):
    """Synthesize and verify R1CS arithmetic circuit for execution trace."""
    with open(trace_path, "r", encoding="utf-8") as f:
        trace_data = json.load(f)
    trace = ExecutionTrace.from_dict(trace_data)

    circuit = AgentTraceCircuitSynthesizer.synthesize_trace_circuit(trace.trace_id, len(trace.steps))
    witness = R1CSVerifier.generate_trace_witness(trace.steps)
    satisfied, violations = R1CSVerifier.verify(circuit, witness)

    table = Table(title="R1CS Circuit Synthesis & Verification")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Circuit ID", circuit.circuit_id)
    table.add_row("Constraints", str(len(circuit.constraints)))
    table.add_row("Variables", str(len(circuit.variable_names)))
    table.add_row("Public Inputs", ", ".join(circuit.public_inputs))
    table.add_row("Satisfied", "[bold green]YES[/bold green]" if satisfied else "[bold red]NO[/bold red]")

    console.print(table)
    if not satisfied:
        for v in violations:
            console.print(f"  [red]• {v}[/red]")
        sys.exit(1)


@main.command()
@click.argument("proof_paths", nargs=-1, type=click.Path(exists=True, dir_okay=False))
def batch(proof_paths: List[str]):
    """Batch-verify multiple ZKTraceProof files and aggregate commitments."""
    if not proof_paths:
        console.print("[red]No proof files specified.[/red]")
        return

    proofs = []
    for p in proof_paths:
        with open(p, "r", encoding="utf-8") as f:
            proofs.append(ZKTraceProof.from_dict(json.load(f)))

    verifier = BatchZKVerifier()
    res = verifier.verify_batch(proofs)
    agg = verifier.aggregate_resource_commitments(proofs)

    table = Table(title="Batch Verification & Commitment Aggregation")
    table.add_column("Metric", style="cyan")
    table.add_column("Result", style="green")

    table.add_row("Total Proofs", str(res.total_proofs))
    table.add_row("Passed Proofs", str(res.passed_count))
    table.add_row("Failed Proofs", str(res.failed_count))
    table.add_row("Total Latency", f"{res.elapsed_ms:.2f} ms")
    table.add_row("All Valid", "[bold green]YES[/bold green]" if res.all_valid else "[bold red]NO[/bold red]")
    table.add_row("Swarm Token Comm", agg["swarm_token_commitment"][:18] + "...")
    table.add_row("Swarm Cost Comm", agg["swarm_cost_commitment"][:18] + "...")

    console.print(table)
    if not res.all_valid:
        sys.exit(1)


@main.command()
def serve():
    """Launch Model Context Protocol (MCP) stdio JSON-RPC 2.0 server."""
    server = AgentZKMCPServer()
    server.run_stdio()


if __name__ == "__main__":
    main()
