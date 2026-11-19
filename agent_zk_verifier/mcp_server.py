"""
Model Context Protocol (MCP) stdio JSON-RPC 2.0 Server for Zero-Knowledge Trace Verification.
Exposes cryptographic proof generation, constraint verification, and trajectory auditing.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, Optional

from .batch import BatchZKVerifier
from .models import CompliancePolicy, ExecutionTrace, ZKTraceProof
from .pedersen import PedersenEngine, get_default_parameters
from .r1cs import AgentTraceCircuitSynthesizer, R1CSVerifier
from .trace_verifier import AgentZKTraceVerifier
from .zkvm import ZKVMExecutionReceipt, ZKVMVerifier


class AgentZKMCPServer:
    """
    Lightweight, robust stdio JSON-RPC MCP Server compatible with Anthropic/OpenBot MCP specification.
    """

    def __init__(self):
        self.verifier = AgentZKTraceVerifier()
        self.batch_verifier = BatchZKVerifier(self.verifier)
        self.zkvm_verifier = ZKVMVerifier()
        self.pedersen = PedersenEngine(get_default_parameters())

    def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch JSON-RPC 2.0 requests to internal handlers."""
        method = request.get("method")
        params = request.get("params", {})
        req_id = request.get("id")

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "agent-zk-trace-verifier",
                        "version": "0.1.0",
                    },
                },
            }

        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": [
                        {
                            "name": "audit_trajectory_integrity",
                            "description": "Inspects and audits raw agent execution trajectory for step continuity, broken state hashes, and policy breaches.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "trace": {"type": "object", "description": "ExecutionTrace JSON object."},
                                    "policy": {"type": "object", "description": "Optional CompliancePolicy parameters."},
                                },
                                "required": ["trace"],
                            },
                        },
                        {
                            "name": "prove_trace_constraints",
                            "description": "Generates a zero-knowledge proof of trajectory compliance (Pedersen commitments, Schnorr NIZK, Range proofs, and R1CS satisfaction) without disclosing sensitive prompt/payload content.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "trace": {"type": "object", "description": "ExecutionTrace JSON object."},
                                    "policy": {"type": "object", "description": "Optional CompliancePolicy parameters."},
                                },
                                "required": ["trace"],
                            },
                        },
                        {
                            "name": "verify_zk_proof",
                            "description": "Cryptographically verifies a zero-knowledge trace proof against a public compliance policy and emits an immutable receipt.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "proof": {"type": "object", "description": "ZKTraceProof JSON object."},
                                    "policy": {"type": "object", "description": "Optional CompliancePolicy parameters."},
                                },
                                "required": ["proof"],
                            },
                        },
                        {
                            "name": "verify_r1cs_circuit",
                            "description": "Synthesizes and checks satisfaction of Rank-1 Constraint System (R1CS) arithmetic equations over the trajectory state transitions.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "trace": {"type": "object", "description": "ExecutionTrace JSON object."},
                                },
                                "required": ["trace"],
                            },
                        },
                        {
                            "name": "verify_zkvm_receipt",
                            "description": "Validates a zkVM execution receipt (RISC Zero or SP1) against expected policy digest and program image ID.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "receipt": {"type": "object", "description": "ZKVMExecutionReceipt JSON object."},
                                    "expected_policy_digest": {"type": "string"},
                                },
                                "required": ["receipt"],
                            },
                        },
                        {
                            "name": "aggregate_batch_proofs",
                            "description": "Batch verifies multiple agent swarm proofs and computes homomorphically aggregated resource commitments.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "proofs": {"type": "array", "items": {"type": "object"}},
                                    "policy": {"type": "object"},
                                },
                                "required": ["proofs"],
                            },
                        },
                    ]
                },
            }

        elif method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments", {})
            try:
                res_content = self.call_tool(tool_name, args)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(res_content, indent=2)}]},
                }
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32000, "message": str(e)},
                }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method '{method}' not found"},
        }

    def call_tool(self, name: str, args: Dict[str, Any]) -> Any:
        if name == "audit_trajectory_integrity":
            trace = ExecutionTrace.from_dict(args["trace"])
            pol_data = args.get("policy")
            policy = CompliancePolicy(**pol_data) if pol_data else CompliancePolicy()
            is_valid, violations = self.verifier.audit_trace(trace, policy)
            return {
                "trace_id": trace.trace_id,
                "is_valid": is_valid,
                "violations": violations,
                "merkle_root": trace.compute_merkle_root(),
                "step_count": len(trace.steps),
                "total_tokens": trace.total_tokens,
                "total_cost": trace.total_cost,
            }

        elif name == "prove_trace_constraints":
            trace = ExecutionTrace.from_dict(args["trace"])
            pol_data = args.get("policy")
            policy = CompliancePolicy(**pol_data) if pol_data else CompliancePolicy()
            proof = self.verifier.prove_trace(trace, policy)
            return proof.to_dict()

        elif name == "verify_zk_proof":
            proof = ZKTraceProof.from_dict(args["proof"])
            pol_data = args.get("policy")
            policy = CompliancePolicy(**pol_data) if pol_data else CompliancePolicy()
            receipt = self.verifier.verify_proof(proof, policy)
            return receipt.to_dict()

        elif name == "verify_r1cs_circuit":
            trace = ExecutionTrace.from_dict(args["trace"])
            circuit = AgentTraceCircuitSynthesizer.synthesize_trace_circuit(trace.trace_id, len(trace.steps))
            witness = R1CSVerifier.generate_trace_witness(trace.steps)
            satisfied, violations = R1CSVerifier.verify(circuit, witness)
            return {
                "circuit_id": circuit.circuit_id,
                "satisfied": satisfied,
                "num_constraints": len(circuit.constraints),
                "num_variables": len(circuit.variable_names),
                "violations": violations,
            }

        elif name == "verify_zkvm_receipt":
            receipt = ZKVMExecutionReceipt.from_dict(args["receipt"])
            expected_digest = args.get("expected_policy_digest")
            is_valid, violations = self.zkvm_verifier.verify_receipt(receipt, expected_digest)
            return {
                "receipt_valid": is_valid,
                "violations": violations,
                "system": receipt.system,
                "image_id": receipt.image_id,
                "journal_digest": receipt.journal.digest(),
            }

        elif name == "aggregate_batch_proofs":
            proofs = [ZKTraceProof.from_dict(p) for p in args["proofs"]]
            pol_data = args.get("policy")
            policy = CompliancePolicy(**pol_data) if pol_data else CompliancePolicy()
            batch_res = self.batch_verifier.verify_batch(proofs, policy)
            agg_commitments = self.batch_verifier.aggregate_resource_commitments(proofs)
            res = batch_res.to_dict()
            res["aggregated_commitments"] = agg_commitments
            return res

        else:
            raise ValueError(f"Unknown tool name: {name}")

    def run_stdio(self) -> None:
        """Run JSON-RPC loop over standard input and output."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
                resp = self.handle_request(req)
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
            except Exception as e:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {e}"},
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()
