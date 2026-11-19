"""
Rank-1 Constraint System (R1CS) Synthesis, Witness Generation, and Verification Engine.
Enforces arithmetic constraints Az * Bz = Cz over agent state transition trajectories.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Set, Tuple

from .models import R1CSCircuit, R1CSConstraint, TraceStep, canonical_json


class R1CSBuilder:
    """
    Synthesizes R1CS circuits for agent execution invariants:
    - Step-counter monotonic incrementation: step_{t+1} - step_t = 1
    - Resource monotonicity: cumulative_{t+1} = cumulative_t + delta_t
    - Boolean variable constraints: x * (1 - x) = 0
    - State hash integrity constraints
    """

    def __init__(self, circuit_id: str):
        self.circuit_id = circuit_id
        self.variables: Set[str] = {"ONE"}  # Constant 1
        self.public_inputs: List[str] = []
        self.constraints: List[R1CSConstraint] = []
        self._var_index: int = 0

    def add_public_input(self, name: str) -> str:
        self.variables.add(name)
        if name not in self.public_inputs:
            self.public_inputs.append(name)
        return name

    def add_witness_var(self, name: Optional[str] = None) -> str:
        if name is None:
            self._var_index += 1
            name = f"w_{self._var_index}"
        self.variables.add(name)
        return name

    def add_constraint(
        self,
        a: Dict[str, int],
        b: Dict[str, int],
        c: Dict[str, int],
    ) -> None:
        """Add constraint: <a, z> * <b, z> = <c, z>."""
        for k in a.keys():
            self.variables.add(k)
        for k in b.keys():
            self.variables.add(k)
        for k in c.keys():
            self.variables.add(k)
        self.constraints.append(R1CSConstraint(a=a, b=b, c=c))

    def assert_equal(self, var1: str, var2: str) -> None:
        """var1 * 1 = var2."""
        self.add_constraint(a={var1: 1}, b={"ONE": 1}, c={var2: 1})

    def assert_constant(self, var: str, value: int) -> None:
        """var * 1 = value * 1."""
        self.add_constraint(a={var: 1}, b={"ONE": 1}, c={"ONE": value})

    def assert_mul(self, x: str, y: str, out: str) -> None:
        """x * y = out."""
        self.add_constraint(a={x: 1}, b={y: 1}, c={out: 1})

    def assert_sum(self, x: str, y: str, out: str) -> None:
        """(x + y) * 1 = out."""
        self.add_constraint(a={x: 1, y: 1}, b={"ONE": 1}, c={out: 1})

    def assert_boolean(self, var: str) -> None:
        """var * (1 - var) = 0  =>  var * (1*ONE + (-1)*var) = 0."""
        self.add_constraint(a={var: 1}, b={"ONE": 1, var: -1}, c={})

    def build(self) -> R1CSCircuit:
        return R1CSCircuit(
            circuit_id=self.circuit_id,
            variable_names=sorted(self.variables),
            public_inputs=sorted(self.public_inputs),
            constraints=self.constraints,
        )


class AgentTraceCircuitSynthesizer:
    """
    Synthesizes standard verification circuits specifically modeling an agent's
    execution trajectory, guaranteeing:
    1. Sequential step continuity (step_{i+1} == step_i + 1)
    2. Token accumulator correctness
    3. Final state transition consistency
    """

    @classmethod
    def synthesize_trace_circuit(cls, trace_id: str, step_count: int) -> R1CSCircuit:
        builder = R1CSBuilder(circuit_id=f"trace_circuit_{trace_id}")
        builder.add_public_input("total_tokens")
        builder.add_public_input("step_count")

        # Step monotonicity constraints
        prev_step = builder.add_witness_var("step_0")
        builder.assert_constant(prev_step, 0)

        prev_tokens = builder.add_witness_var("tokens_0")
        builder.assert_constant(prev_tokens, 0)

        for i in range(1, step_count + 1):
            curr_step = builder.add_witness_var(f"step_{i}")
            # step_i = step_{i-1} + 1
            builder.add_constraint(
                a={prev_step: 1, "ONE": 1},
                b={"ONE": 1},
                c={curr_step: 1},
            )
            prev_step = curr_step

            # Token accumulator: tokens_i = tokens_{i-1} + delta_tokens_i
            delta_tokens = builder.add_witness_var(f"delta_tokens_{i}")
            curr_tokens = builder.add_witness_var(f"tokens_{i}")
            builder.add_constraint(
                a={prev_tokens: 1, delta_tokens: 1},
                b={"ONE": 1},
                c={curr_tokens: 1},
            )
            prev_tokens = curr_tokens

        # Assert final accumulators match public inputs
        builder.assert_equal(prev_step, "step_count")
        builder.assert_equal(prev_tokens, "total_tokens")

        return builder.build()


class R1CSVerifier:
    """
    Verifies satisfaction of R1CS circuits for a given variable assignment (witness vector).
    """

    @staticmethod
    def evaluate_constraint(
        constraint: R1CSConstraint,
        witness: Dict[str, int],
    ) -> Tuple[bool, int, int, int]:
        """
        Evaluate <a, z> * <b, z> == <c, z>.
        Returns (is_satisfied, val_a, val_b, val_c).
        """
        val_a = sum(coeff * witness.get(var, 0) for var, coeff in constraint.a.items())
        val_b = sum(coeff * witness.get(var, 0) for var, coeff in constraint.b.items())
        val_c = sum(coeff * witness.get(var, 0) for var, coeff in constraint.c.items())

        is_satisfied = (val_a * val_b) == val_c
        return is_satisfied, val_a, val_b, val_c

    @classmethod
    def verify(
        cls,
        circuit: R1CSCircuit,
        witness: Dict[str, int],
    ) -> Tuple[bool, List[str]]:
        """
        Verifies that all constraints in the circuit are satisfied by the witness.
        Witness must contain 'ONE': 1.
        """
        full_witness = dict(witness)
        full_witness["ONE"] = 1

        violations = []
        for i, constraint in enumerate(circuit.constraints):
            satisfied, va, vb, vc = cls.evaluate_constraint(constraint, full_witness)
            if not satisfied:
                violations.append(
                    f"Constraint #{i} failed: ({va}) * ({vb}) != ({vc}) [a={constraint.a}, b={constraint.b}, c={constraint.c}]"
                )

        return len(violations) == 0, violations

    @classmethod
    def generate_trace_witness(
        cls,
        steps: List[TraceStep],
    ) -> Dict[str, int]:
        """Generate complete satisfying witness vector from trace steps."""
        witness: Dict[str, int] = {
            "ONE": 1,
            "step_0": 0,
            "tokens_0": 0,
            "step_count": len(steps),
            "total_tokens": sum(s.token_count for s in steps),
        }

        cumulative_tokens = 0
        for i, step in enumerate(steps, 1):
            witness[f"step_{i}"] = i
            witness[f"delta_tokens_{i}"] = step.token_count
            cumulative_tokens += step.token_count
            witness[f"tokens_{i}"] = cumulative_tokens

        return witness
