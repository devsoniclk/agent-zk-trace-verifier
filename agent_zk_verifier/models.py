"""
Core Data Models for Zero-Knowledge Agent Trajectory and Execution Trace Verification.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set


def canonical_json(data: Any) -> str:
    """Deterministic, sorted JSON serialization (RFC 8785 compliant)."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_digest(data: str | bytes) -> str:
    """Compute standard SHA-256 hex digest."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


@dataclass
class TraceStep:
    """Individual execution step in an autonomous agent trajectory."""
    step_id: str
    step_index: int
    agent_id: str
    tool_name: str
    model_name: str
    token_count: int
    latency_ms: float
    financial_cost: float
    input_hash: str
    output_hash: str
    state_before_hash: str
    state_after_hash: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def canonical_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "step_index": self.step_index,
            "agent_id": self.agent_id,
            "tool_name": self.tool_name,
            "model_name": self.model_name,
            "token_count": self.token_count,
            "latency_ms": round(self.latency_ms, 3),
            "financial_cost": round(self.financial_cost, 6),
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "state_before_hash": self.state_before_hash,
            "state_after_hash": self.state_after_hash,
            "timestamp": self.timestamp,
        }

    def digest(self) -> str:
        """Deterministic hash of this execution step."""
        return sha256_digest(canonical_json(self.canonical_dict()))


@dataclass
class ExecutionTrace:
    """Complete execution trace for an autonomous agent deliberation trajectory."""
    trace_id: str
    agent_id: str
    session_id: str
    steps: List[TraceStep] = field(default_factory=list)
    initial_state_hash: str = ""
    final_state_hash: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def total_tokens(self) -> int:
        return sum(s.token_count for s in self.steps)

    @property
    def total_cost(self) -> float:
        return sum(s.financial_cost for s in self.steps)

    @property
    def total_latency_ms(self) -> float:
        return sum(s.latency_ms for s in self.steps)

    @property
    def distinct_tools(self) -> Set[str]:
        return {s.tool_name for s in self.steps}

    def compute_merkle_root(self) -> str:
        """Compute cryptographic Merkle root of all trace steps."""
        if not self.steps:
            return sha256_digest("empty_trace")
        
        leaf_hashes = [s.digest() for s in self.steps]
        current_layer = leaf_hashes
        
        while len(current_layer) > 1:
            next_layer = []
            for i in range(0, len(current_layer), 2):
                left = current_layer[i]
                right = current_layer[i + 1] if i + 1 < len(current_layer) else left
                combined = sha256_digest(left + right)
                next_layer.append(combined)
            current_layer = next_layer
            
        return current_layer[0]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "initial_state_hash": self.initial_state_hash,
            "final_state_hash": self.final_state_hash,
            "created_at": self.created_at,
            "merkle_root": self.compute_merkle_root(),
            "total_tokens": self.total_tokens,
            "total_cost": round(self.total_cost, 6),
            "total_latency_ms": round(self.total_latency_ms, 3),
            "step_count": len(self.steps),
            "steps": [s.canonical_dict() for s in self.steps],
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ExecutionTrace:
        steps = []
        for s in data.get("steps", []):
            steps.append(
                TraceStep(
                    step_id=s["step_id"],
                    step_index=s["step_index"],
                    agent_id=s["agent_id"],
                    tool_name=s["tool_name"],
                    model_name=s["model_name"],
                    token_count=int(s["token_count"]),
                    latency_ms=float(s["latency_ms"]),
                    financial_cost=float(s["financial_cost"]),
                    input_hash=s["input_hash"],
                    output_hash=s["output_hash"],
                    state_before_hash=s["state_before_hash"],
                    state_after_hash=s["state_after_hash"],
                    timestamp=s.get("timestamp", ""),
                )
            )
        return cls(
            trace_id=data["trace_id"],
            agent_id=data["agent_id"],
            session_id=data["session_id"],
            steps=steps,
            initial_state_hash=data.get("initial_state_hash", ""),
            final_state_hash=data.get("final_state_hash", ""),
            created_at=data.get("created_at", ""),
            metadata=data.get("metadata", {}),
        )


@dataclass
class PedersenParameters:
    """Public parameters for Pedersen commitment scheme."""
    p: int  # Safe prime modulus
    q: int  # Subgroup order: p = 2q + 1
    g: int  # Generator 1
    h: int  # Generator 2 (independent of g)

    def to_dict(self) -> Dict[str, str]:
        return {
            "p": hex(self.p),
            "q": hex(self.q),
            "g": hex(self.g),
            "h": hex(self.h),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, str]) -> PedersenParameters:
        return cls(
            p=int(d["p"], 16),
            q=int(d["q"], 16),
            g=int(d["g"], 16),
            h=int(d["h"], 16),
        )


@dataclass
class PedersenCommitment:
    """Cryptographic Pedersen commitment C = g^v * h^r mod p."""
    commitment: int
    blinding_factor: Optional[int] = None
    value: Optional[int] = None

    def to_hex(self) -> str:
        return hex(self.commitment)

    def to_dict(self, include_secrets: bool = False) -> Dict[str, Any]:
        res: Dict[str, Any] = {"commitment": hex(self.commitment)}
        if include_secrets:
            if self.blinding_factor is not None:
                res["blinding_factor"] = hex(self.blinding_factor)
            if self.value is not None:
                res["value"] = self.value
        return res


@dataclass
class SchnorrProof:
    """Non-interactive zero-knowledge proof of knowledge for discrete log / opening."""
    R: int  # Announce R = g^w1 * h^w2 mod p
    e: int  # Challenge scalar e = Hash(...)
    s_v: int  # Response for value
    s_r: int  # Response for blinding factor

    def to_dict(self) -> Dict[str, str]:
        return {
            "R": hex(self.R),
            "e": hex(self.e),
            "s_v": hex(self.s_v),
            "s_r": hex(self.s_r),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, str]) -> SchnorrProof:
        return cls(
            R=int(d["R"], 16),
            e=int(d["e"], 16),
            s_v=int(d["s_v"], 16),
            s_r=int(d["s_r"], 16),
        )


@dataclass
class RangeProof:
    """Zero-knowledge range proof demonstrating 0 <= v < 2^max_bits."""
    max_bits: int
    commitment: int
    bit_commitments: List[int]
    bit_proofs: List[Dict[str, str]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_bits": self.max_bits,
            "commitment": hex(self.commitment),
            "bit_commitments": [hex(c) for c in self.bit_commitments],
            "bit_proofs": self.bit_proofs,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> RangeProof:
        return cls(
            max_bits=d["max_bits"],
            commitment=int(d["commitment"], 16),
            bit_commitments=[int(c, 16) for c in d["bit_commitments"]],
            bit_proofs=d["bit_proofs"],
        )


@dataclass
class R1CSConstraint:
    """A single Rank-1 constraint: <A, z> * <B, z> = <C, z>."""
    a: Dict[str, int]
    b: Dict[str, int]
    c: Dict[str, int]

    def to_dict(self) -> Dict[str, Any]:
        return {"a": self.a, "b": self.b, "c": self.c}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> R1CSConstraint:
        return cls(a=d["a"], b=d["b"], c=d["c"])


@dataclass
class R1CSCircuit:
    """Synthesized arithmetic circuit for agent execution verification."""
    circuit_id: str
    variable_names: List[str]
    public_inputs: List[str]
    constraints: List[R1CSConstraint]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "circuit_id": self.circuit_id,
            "variable_names": self.variable_names,
            "public_inputs": self.public_inputs,
            "constraints": [c.to_dict() for c in self.constraints],
            "num_constraints": len(self.constraints),
            "num_variables": len(self.variable_names),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> R1CSCircuit:
        return cls(
            circuit_id=d["circuit_id"],
            variable_names=d["variable_names"],
            public_inputs=d["public_inputs"],
            constraints=[R1CSConstraint.from_dict(c) for c in d["constraints"]],
        )


@dataclass
class CompliancePolicy:
    """Public policy rules that an execution trajectory must satisfy."""
    max_steps: int = 100
    max_tokens: int = 1_000_000
    max_cost_usd: float = 10.0
    max_latency_ms: float = 60_000.0
    allowed_tools: Optional[List[str]] = None
    allowed_models: Optional[List[str]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_steps": self.max_steps,
            "max_tokens": self.max_tokens,
            "max_cost_usd": self.max_cost_usd,
            "max_latency_ms": self.max_latency_ms,
            "allowed_tools": sorted(self.allowed_tools) if self.allowed_tools else None,
            "allowed_models": sorted(self.allowed_models) if self.allowed_models else None,
        }

    def digest(self) -> str:
        return sha256_digest(canonical_json(self.to_dict()))


@dataclass
class ZKTraceProof:
    """Zero-knowledge proof verifying full execution trace compliance."""
    proof_id: str
    trace_id: str
    merkle_root: str
    token_commitment: str
    cost_commitment: str
    step_count: int
    token_range_proof: RangeProof
    cost_range_proof: RangeProof
    token_schnorr_proof: SchnorrProof
    cost_schnorr_proof: SchnorrProof
    tool_membership_verified: bool
    r1cs_circuit_digest: str
    policy_digest: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proof_id": self.proof_id,
            "trace_id": self.trace_id,
            "merkle_root": self.merkle_root,
            "token_commitment": self.token_commitment,
            "cost_commitment": self.cost_commitment,
            "step_count": self.step_count,
            "token_range_proof": self.token_range_proof.to_dict(),
            "cost_range_proof": self.cost_range_proof.to_dict(),
            "token_schnorr_proof": self.token_schnorr_proof.to_dict(),
            "cost_schnorr_proof": self.cost_schnorr_proof.to_dict(),
            "tool_membership_verified": self.tool_membership_verified,
            "r1cs_circuit_digest": self.r1cs_circuit_digest,
            "policy_digest": self.policy_digest,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> ZKTraceProof:
        return cls(
            proof_id=d["proof_id"],
            trace_id=d["trace_id"],
            merkle_root=d["merkle_root"],
            token_commitment=d["token_commitment"],
            cost_commitment=d["cost_commitment"],
            step_count=int(d["step_count"]),
            token_range_proof=RangeProof.from_dict(d["token_range_proof"]),
            cost_range_proof=RangeProof.from_dict(d["cost_range_proof"]),
            token_schnorr_proof=SchnorrProof.from_dict(d["token_schnorr_proof"]),
            cost_schnorr_proof=SchnorrProof.from_dict(d["cost_schnorr_proof"]),
            tool_membership_verified=bool(d["tool_membership_verified"]),
            r1cs_circuit_digest=d["r1cs_circuit_digest"],
            policy_digest=d["policy_digest"],
            created_at=d.get("created_at", ""),
        )


@dataclass
class ZKProofReceipt:
    """Verifiable receipt certifying that a ZKTraceProof was successfully verified."""
    receipt_id: str
    proof_id: str
    trace_id: str
    merkle_root: str
    policy_digest: str
    is_valid: bool
    verified_at: str
    verification_latency_ms: float
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "proof_id": self.proof_id,
            "trace_id": self.trace_id,
            "merkle_root": self.merkle_root,
            "policy_digest": self.policy_digest,
            "is_valid": self.is_valid,
            "verified_at": self.verified_at,
            "verification_latency_ms": round(self.verification_latency_ms, 3),
            "details": self.details,
        }


@dataclass
class BatchVerificationResult:
    """Result of batch verification across multiple autonomous agent proofs."""
    total_proofs: int
    passed_count: int
    failed_count: int
    all_valid: bool
    elapsed_ms: float
    individual_receipts: List[ZKProofReceipt]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_proofs": self.total_proofs,
            "passed_count": self.passed_count,
            "failed_count": self.failed_count,
            "all_valid": self.all_valid,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "individual_receipts": [r.to_dict() for r in self.individual_receipts],
        }
