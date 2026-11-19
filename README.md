# agent-zk-trace-verifier

> Zero-Knowledge Trajectory Integrity & Execution Trace Verification for Autonomous AI Agent Swarms.

`agent-zk-trace-verifier` enables autonomous multi-agent networks to prove compliance with execution policies, resource bounds, and state transition invariants without revealing confidential prompts, tool inputs, or private deliberation traces.

---

## Core Capabilities

1. **Deterministic Trajectory Representation & Merkle Roots**
   - Canonical RFC 8785 JSON representation of agent execution steps.
   - Cryptographic SHA-256 Merkle root computation over sequential deliberation traces.

2. **Homomorphic Pedersen Commitments**
   - Additive homomorphic properties for cumulative token and financial spend.
   - RFC 3526 2048-bit safe prime parameters with cryptographically independent generators.

3. **NIZK Schnorr & Zero-Knowledge Range Proofs**
   - Non-interactive zero-knowledge proof of commitment openings via Fiat-Shamir transformation.
   - CDS 1-out-of-2 sigma bit-decomposition range proofs bounding compute and spend ($0 \le v < 2^k$).

4. **Rank-1 Constraint System (R1CS) Synthesis**
   - Synthesizes arithmetic constraints ($Az \circ Bz = Cz$) enforcing sequential step continuity and token accumulation.

5. **zkVM Guest Journal & Receipt Verification**
   - Supports RISC Zero and Succinct SP1 verifiable computation receipts.

6. **Multi-Agent Batch Verification & Homomorphic Aggregation**
   - Verifies fleet-wide trajectories in batch and combines commitments across swarms.

7. **Fast MCP Server & Rich CLI**
   - Stdio JSON-RPC 2.0 interface exposing 6 tools.
   - Command-line interface with interactive Rich terminal reporting.

---

## Installation

```bash
pip install agent-zk-trace-verifier
```

For development:
```bash
git clone https://github.com/devsoniclk/agent-zk-trace-verifier.git
cd agent-zk-trace-verifier
pip install -e .[dev]
```

---

## Quickstart

### Python API

```python
from agent_zk_verifier import AgentZKTraceVerifier, CompliancePolicy, ExecutionTrace, TraceStep

verifier = AgentZKTraceVerifier()

# Define public verification policy
policy = CompliancePolicy(
    max_steps=10,
    max_tokens=100_000,
    max_cost_usd=1.00,
    allowed_tools=["web_search", "code_interpreter"],
)

# 1. Audit raw trajectory
is_valid, violations = verifier.audit_trace(trace, policy)

# 2. Generate Zero-Knowledge Proof (Hiding private inputs & intermediate outputs)
proof = verifier.prove_trace(trace, policy)

# 3. Third-party verifier validates proof without accessing sensitive data
receipt = verifier.verify_proof(proof, policy)
assert receipt.is_valid
```

### Command Line Interface

```bash
# Audit trajectory file
agent-zk audit trace.json --policy policy.json

# Synthesize Zero-Knowledge Proof
agent-zk prove trace.json -p policy.json -o proof.json

# Verify Zero-Knowledge Proof
agent-zk verify proof.json -p policy.json

# Batch verify multiple agent proofs
agent-zk batch proof1.json proof2.json proof3.json

# Launch MCP Server
agent-zk serve
```

---

## Test Suite

```bash
pytest --cov=agent_zk_verifier tests/
```

45/45 automated unit and integration tests passing with 92% coverage.

---

## License

MIT License. Copyright (c) 2026 Lakshitha Dananjaya.
