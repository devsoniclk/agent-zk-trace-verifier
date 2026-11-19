"""Tests for Non-Interactive Schnorr NIZK Sigma Protocols."""

import pytest
from agent_zk_verifier.models import SchnorrProof
from agent_zk_verifier.pedersen import PedersenEngine
from agent_zk_verifier.schnorr import SchnorrProver, SchnorrVerifier


def test_schnorr_proof_validity():
    engine = PedersenEngine()
    prover = SchnorrProver(engine.params)
    verifier = SchnorrVerifier(engine.params)

    comm = engine.commit(value=12345)
    proof = prover.prove(comm, context="test_ctx")

    assert verifier.verify(comm.commitment, proof, context="test_ctx")


def test_schnorr_proof_context_binding():
    engine = PedersenEngine()
    prover = SchnorrProver(engine.params)
    verifier = SchnorrVerifier(engine.params)

    comm = engine.commit(value=999)
    proof = prover.prove(comm, context="ctx_A")

    # Verification fails if context differs
    assert not verifier.verify(comm.commitment, proof, context="ctx_B")


def test_schnorr_proof_tampering():
    engine = PedersenEngine()
    prover = SchnorrProver(engine.params)
    verifier = SchnorrVerifier(engine.params)

    comm = engine.commit(value=888)
    proof = prover.prove(comm, context="tamper_ctx")

    # Tamper with response s_v
    tampered_proof = SchnorrProof(
        R=proof.R,
        e=proof.e,
        s_v=(proof.s_v + 1) % engine.params.q,
        s_r=proof.s_r,
    )
    assert not verifier.verify(comm.commitment, tampered_proof, context="tamper_ctx")

    # Tamper with announcement R
    tampered_R = SchnorrProof(
        R=(proof.R + 1) % engine.params.p,
        e=proof.e,
        s_v=proof.s_v,
        s_r=proof.s_r,
    )
    assert not verifier.verify(comm.commitment, tampered_R, context="tamper_ctx")


def test_schnorr_prover_requires_secrets():
    engine = PedersenEngine()
    prover = SchnorrProver(engine.params)
    comm = engine.commit(value=10)
    comm.value = None

    with pytest.raises(ValueError):
        prover.prove(comm)
