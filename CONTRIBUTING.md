# Contributing to Supply Chain Sentinel

Thank you for your interest in contributing to Supply Chain Sentinel. This document provides guidelines and instructions for contributing to this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Environment Setup](#development-environment-setup)
- [Code Style Guidelines](#code-style-guidelines)
- [Submitting Pull Requests](#submitting-pull-requests)
- [Reporting Bugs](#reporting-bugs)
- [Feature Requests](#feature-requests)

---

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. We expect all contributors to act professionally and considerately in all interactions.

## How to Contribute

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally.
3. **Create a branch** for your changes (`git checkout -b feature/your-feature-name`).
4. **Make your changes** and commit with clear, descriptive messages.
5. **Push** your branch and open a Pull Request against `main`.

> **Note:** For security-sensitive contributions, please review our [Security Policy](SECURITY.md) before submitting.

## Development Environment Setup

### Prerequisites

| Requirement | Minimum Version |
|-------------|-----------------|
| Python      | 3.9+            |
| pip         | 21.0+           |
| Git         | 2.30+           |

### Installation

```bash
# Clone your fork
git clone https://github.com/<your-username>/supply-chain-sentinel.git
cd supply-chain-sentinel

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate           # Windows

# Install dependencies (including dev dependencies)
pip install -e ".[dev]"

# Verify the installation
python -m pytest --version
```

### Running Tests

```bash
# Run the full test suite
python -m pytest

# Run with coverage
python -m pytest --cov=supply_chain_sentinel --cov-report=term-missing

# Run a specific test module
python -m pytest tests/test_scanner.py -v
```

## Code Style Guidelines

- **Formatter:** All Python code must be formatted with [Black](https://github.com/psf/black) (line length 88).
- **Linter:** Code must pass [Ruff](https://github.com/astral-sh/ruff) with the project configuration.
- **Type Hints:** All public functions and methods must include type annotations.
- **Docstrings:** Use Google-style docstrings for all public modules, classes, and functions.
- **Imports:** Use `isort` for consistent import ordering (Black-compatible profile).

```bash
# Format code
black .

# Lint code
ruff check .

# Sort imports
isort .
```

### Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
feat: add SBOM parsing for CycloneDX format
fix: resolve false positive in dependency resolution
docs: update API reference for scanner module
test: add integration tests for vulnerability matcher
```

## Submitting Pull Requests

1. Ensure all tests pass and there are no linting errors.
2. Update documentation if your changes affect public APIs or user-facing behavior.
3. Add or update tests to cover your changes.
4. Fill out the [Pull Request template](.github/PULL_REQUEST_TEMPLATE.md) completely.
5. Request a review from at least one maintainer.

**Pull requests that do not pass CI checks will not be reviewed.**

### Review Process

- A maintainer will review your PR within 5 business days.
- Address all review comments before requesting a re-review.
- Once approved, a maintainer will merge your PR.

## Reporting Bugs

Use the [Bug Report](https://github.com/Vighnesh/supply-chain-sentinel/issues/new?template=bug_report.md) issue template. Include:

- A clear, descriptive title.
- Steps to reproduce the issue.
- Expected vs. actual behavior.
- Environment details (OS, Python version, package version).
- Relevant logs or screenshots.

> **Security vulnerabilities** must NOT be reported via public issues. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## Feature Requests

Use the [Feature Request](https://github.com/Vighnesh/supply-chain-sentinel/issues/new?template=feature_request.md) issue template. Include:

- A clear description of the problem you are trying to solve.
- Your proposed solution.
- Any alternatives you have considered.

---

Thank you for helping make Supply Chain Sentinel more secure and reliable.
