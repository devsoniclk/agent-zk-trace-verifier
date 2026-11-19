"""Tests for Zero-Knowledge Range Proofs."""

import pytest
from agent_zk_verifier.range_proof import RangeProofEngine


def test_bit_proof_branch_0():
    engine = RangeProofEngine()
    comm = engine.pedersen.commit(value=0)
    bp = engine.prove_bit(0, comm.blinding_factor, comm.commitment, 0)
    assert engine.verify_bit(comm.commitment, bp, 0)


def test_bit_proof_branch_1():
    engine = RangeProofEngine()
    comm = engine.pedersen.commit(value=1)
    bp = engine.prove_bit(1, comm.blinding_factor, comm.commitment, 1)
    assert engine.verify_bit(comm.commitment, bp, 1)


def test_bit_proof_tampered_fails():
    engine = RangeProofEngine()
    comm = engine.pedersen.commit(value=0)
    bp = engine.prove_bit(0, comm.blinding_factor, comm.commitment, 0)

    # Tamper with e0
    tampered_bp = dict(bp)
    tampered_bp["e0"] = hex(int(bp["e0"], 16) + 1)
    assert not engine.verify_bit(comm.commitment, tampered_bp, 0)


def test_range_proof_small_values():
    engine = RangeProofEngine()
    # 4 bits allows [0, 15]
    for val in [0, 1, 7, 15]:
        proof = engine.prove_range(val, max_bits=4)
        assert proof.max_bits == 4
        assert len(proof.bit_commitments) == 4
        assert engine.verify_range(proof)


def test_range_proof_out_of_bounds_raises():
    engine = RangeProofEngine()
    with pytest.raises(ValueError):
        engine.prove_range(16, max_bits=4)
    with pytest.raises(ValueError):
        engine.prove_range(-1, max_bits=4)


def test_range_proof_tampering():
    engine = RangeProofEngine()
    proof = engine.prove_range(5, max_bits=4)
    assert engine.verify_range(proof)

    # Tamper with total commitment
    tampered_proof = proof
    tampered_proof.commitment = (proof.commitment + 1) % engine.params.p
    assert not engine.verify_range(tampered_proof)
