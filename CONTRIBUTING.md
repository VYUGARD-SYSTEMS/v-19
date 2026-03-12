# Contributing to v-19 Scanner

Thanks for your interest in contributing to v-19.

## What We Accept

- **Scanner improvements** — better detection logic for AWS, Azure, GCP, Kubernetes
- **Bug fixes** — things that break on specific cloud configurations
- **New cloud support** — additional identity providers or platforms
- **Documentation** — better examples, clearer setup instructions
- **Tests** — increased coverage for scanner and risk classification code

## What's Out of Scope

The following are part of the Enterprise edition and not in this repo:

- Attack path chaining / graph traversal algorithms
- Financial exposure calculations
- Remediation code generation
- Compliance report generation

## Getting Started

```bash
git clone https://github.com/vyugard-systems/v-19.git
cd v-19
pip install -e ".[dev]"
pytest tests/
```

## Pull Request Process

1. Fork the repo and create a branch from `main`
2. Add tests for any new scanner logic
3. Run `pytest` and make sure everything passes
4. Submit a PR with a clear description of the change

## Code Style

- Python 3.9+ compatible
- Type hints on public methods
- Dataclasses for structured data
- No external dependencies beyond what's in `pyproject.toml` without discussion

## Reporting Security Issues

If you find a security vulnerability in the scanner code, please email security@vyugard.tech instead of opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
