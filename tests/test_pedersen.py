"""Tests for Pedersen Commitment Engine and Homomorphic Operations."""

import pytest
from agent_zk_verifier.pedersen import PedersenEngine, derive_generators, get_default_parameters


def test_default_parameters():
    params = get_default_parameters()
    assert params.p > 0
    assert params.q == (params.p - 1) // 2
    assert params.g != params.h
    assert params.g != 1
    assert params.h != 1


def test_derive_generators():
    # Test on small safe prime p = 23 (q = 11)
    p = 23
    q = 11
    g, h = derive_generators(p, q)
    assert g != 1
    assert h != 1
    assert g != h
    assert pow(g, q, p) == 1
    assert pow(h, q, p) == 1


def test_commit_and_verify():
    engine = PedersenEngine()
    comm = engine.commit(value=1000)
    assert comm.commitment > 0
    assert comm.blinding_factor is not None
    assert comm.value == 1000

    assert engine.verify(comm.commitment, 1000, comm.blinding_factor)
    assert not engine.verify(comm.commitment, 1001, comm.blinding_factor)
    assert not engine.verify(comm.commitment, 1000, comm.blinding_factor + 1)


def test_homomorphic_addition():
    engine = PedersenEngine()
    c1 = engine.commit(value=500)
    c2 = engine.commit(value=300)

    c_sum = engine.add(c1, c2)
    assert c_sum.value == 800
    assert engine.verify(c_sum.commitment, 800, c_sum.blinding_factor)

    # Test adding raw list of commitments
    tot_raw = engine.add_commitments([c1.commitment, c2.commitment])
    assert tot_raw == c_sum.commitment


def test_homomorphic_scalar_multiplication():
    engine = PedersenEngine()
    c = engine.commit(value=40)
    c_scaled = engine.scalar_mul(c, 5)

    assert c_scaled.value == 200
    assert engine.verify(c_scaled.commitment, 200, c_scaled.blinding_factor)
