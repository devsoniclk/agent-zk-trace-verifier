"""
Agent ZK Trace Verifier: Zero-Knowledge Trajectory Integrity & Execution Trace Verification for Autonomous AI Agent Swarms.
"""

from .batch import BatchZKVerifier
from .mcp_server import AgentZKMCPServer
from .models import (
    BatchVerificationResult,
    CompliancePolicy,
    ExecutionTrace,
    PedersenCommitment,
    PedersenParameters,
    R1CSCircuit,
    R1CSConstraint,
    RangeProof,
    SchnorrProof,
    TraceStep,
    ZKProofReceipt,
    ZKTraceProof,
    canonical_json,
    sha256_digest,
)
from .pedersen import PedersenEngine, get_default_parameters
from .range_proof import RangeProofEngine
from .r1cs import AgentTraceCircuitSynthesizer, R1CSBuilder, R1CSVerifier
from .schnorr import SchnorrProver, SchnorrVerifier
from .trace_verifier import AgentZKTraceVerifier
from .zkvm import ZKVMExecutionReceipt, ZKVMJournal, ZKVMVerifier

__version__ = "0.1.0"
__all__ = [
    "AgentZKTraceVerifier",
    "BatchZKVerifier",
    "AgentZKMCPServer",
    "PedersenEngine",
    "RangeProofEngine",
    "SchnorrProver",
    "SchnorrVerifier",
    "R1CSBuilder",
    "R1CSVerifier",
    "AgentTraceCircuitSynthesizer",
    "ZKVMVerifier",
    "ZKVMExecutionReceipt",
    "ZKVMJournal",
    "ExecutionTrace",
    "TraceStep",
    "CompliancePolicy",
    "ZKTraceProof",
    "ZKProofReceipt",
    "BatchVerificationResult",
    "PedersenCommitment",
    "PedersenParameters",
    "SchnorrProof",
    "RangeProof",
    "R1CSCircuit",
    "R1CSConstraint",
    "get_default_parameters",
    "canonical_json",
    "sha256_digest",
]
