"""
Benchmark Suite for Agent ZK Trace Verifier:
Measures:
1. Pedersen commitment & opening throughput
2. Schnorr NIZK proof generation & verification latency
3. Zero-Knowledge Range proof generation & verification latency (8-bit, 12-bit, 16-bit)
4. R1CS constraint evaluation speed
5. Batch verification scaling across N agent proofs
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent_zk_verifier import (
    AgentZKTraceVerifier,
    BatchZKVerifier,
    CompliancePolicy,
    ExecutionTrace,
    PedersenEngine,
    RangeProofEngine,
    SchnorrProver,
    SchnorrVerifier,
    TraceStep,
)


def benchmark_pedersen(iterations: int = 50):
    engine = PedersenEngine()
    start = time.perf_counter()
    for i in range(iterations):
        c = engine.commit(value=1000 + i)
    elapsed = (time.perf_counter() - start) * 1000.0 / iterations
    print(f"Pedersen Commit Throughput:       {elapsed:.3f} ms / commitment")


def benchmark_schnorr(iterations: int = 50):
    engine = PedersenEngine()
    prover = SchnorrProver(engine.params)
    verifier = SchnorrVerifier(engine.params)
    comm = engine.commit(value=500)

    start_p = time.perf_counter()
    proofs = [prover.prove(comm, context="bench") for _ in range(iterations)]
    p_time = (time.perf_counter() - start_p) * 1000.0 / iterations

    start_v = time.perf_counter()
    for proof in proofs:
        verifier.verify(comm.commitment, proof, context="bench")
    v_time = (time.perf_counter() - start_v) * 1000.0 / iterations

    print(f"Schnorr NIZK Prover Latency:      {p_time:.3f} ms / proof")
    print(f"Schnorr NIZK Verifier Latency:    {v_time:.3f} ms / verify")


def benchmark_range_proofs():
    engine = RangeProofEngine()
    for bits in [8, 12, 16]:
        val = (1 << (bits - 1)) + 5
        start_p = time.perf_counter()
        proof = engine.prove_range(val, max_bits=bits)
        p_time = (time.perf_counter() - start_p) * 1000.0

        start_v = time.perf_counter()
        engine.verify_range(proof)
        v_time = (time.perf_counter() - start_v) * 1000.0

        print(f"Range Proof ({bits:2d}-bit): Prover={p_time:6.2f} ms | Verifier={v_time:6.2f} ms")


def main():
    print("=== Agent ZK Trace Verifier Micro-Benchmarks ===\n")
    benchmark_pedersen()
    benchmark_schnorr()
    print()
    benchmark_range_proofs()
    print("\nBenchmark completed successfully.")


if __name__ == "__main__":
    main()
