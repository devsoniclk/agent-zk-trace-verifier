# Contributing to Agent Restaking AVS

Thank you for contributing to the Agent Restaking AVS Protocol.

## Development Setup

```bash
git clone https://github.com/devsoniclk/agent-p2p-gossip-mesh.git
cd agent-p2p-gossip-mesh
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Tests

We mandate 100% test passing and >95% code coverage for all PRs:

```bash
pytest -v --cov=agent_p2p_mesh --cov-report=term-missing
```

## Pull Request Guidelines

1. Ensure all tests pass.
2. Add comprehensive unit and integration tests for any new features.
3. Adhere to strict type annotations (`mypy`).
4. Follow conventional commit messages.
