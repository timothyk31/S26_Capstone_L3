# Contributing to the Multi-Agent OpenSCAP Security Compliance System

Thank you for your interest in contributing! This document outlines how to propose changes, report issues, and collaborate on the project.

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Reporting Issues](#reporting-issues)
- [Submitting Pull Requests](#submitting-pull-requests)
- [Development Guidelines](#development-guidelines)
- [Testing](#testing)
- [Commit Message Guidelines](#commit-message-guidelines)
- [Community Expectations](#community-expectations)
- [Contact](#contact)

## Code of Conduct

By participating in this project, you agree to maintain a respectful, inclusive, and professional environment. Harassment, discrimination, or abusive behavior of any kind will not be tolerated. Please be kind, constructive, and assume good intent when interacting with other contributors.

## Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/S26_Capstone_L3.git
   cd S26_Capstone_L3
   ```
3. **Set up a virtual environment** and install dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
4. **Configure environment variables** in a `.env` file as described in the [README](README.md#environmental-variables).
5. **Create a branch** for your work:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## How to Contribute

There are many ways to contribute:

- Reporting bugs or unexpected behavior
- Proposing new features or enhancements
- Improving documentation
- Writing or improving tests
- Refactoring or optimizing existing code
- Reviewing open pull requests

## Reporting Issues

Before opening a new issue, please search existing issues to avoid duplicates. When filing an issue, include:

- A clear, descriptive title
- Steps to reproduce the problem
- Expected behavior vs. actual behavior
- Relevant logs, error messages, or screenshots
- Your environment (OS, Python version, target VM details)
- Any relevant configuration (sanitize API keys and credentials)

For security vulnerabilities, **do not open a public issue**. Please contact the maintainers directly (see [Contact](#contact)).

## Submitting Pull Requests

1. Ensure your branch is up to date with `main`:
   ```bash
   git fetch origin
   git rebase origin/main
   ```
2. Make focused, logically grouped commits.
3. Run the test suite and ensure all tests pass.
4. Update documentation (`README.md`, docstrings, etc.) when applicable.
5. Push your branch and open a pull request against the `main` branch.
6. Fill out the PR description with:
   - A summary of the changes
   - Motivation and context
   - Related issue numbers (e.g. `Closes #42`)
   - A test plan describing how you verified the changes
7. Be responsive to review feedback and willing to iterate.

PRs should be reasonably small and focused. Large, sprawling PRs are harder to review and more likely to stall.

## Development Guidelines

- **Python style:** Follow [PEP 8](https://peps.python.org/pep-0008/). Use descriptive variable and function names.
- **Type hints:** Add type annotations where they clarify intent, especially on public APIs and agent interfaces.
- **Pydantic models:** Prefer Pydantic schemas (see `schemas.py`) for structured data passed between agents.
- **Logging:** Use the existing logging patterns rather than `print()` statements in production code paths.
- **Secrets:** Never commit API keys, credentials, or private host information. Use `.env` and keep it out of version control.
- **Agent changes:** When modifying agent prompts or workflows, document the rationale and include before/after behavior in the PR.
- **Dependencies:** Only add new dependencies when necessary, and update `requirements.txt` accordingly.

## Testing

- Tests live in the `tests/` directory. See `tests/TEST_INDEX.md` for an overview.
- Run the full test suite:
  ```bash
  pytest
  ```
- Add tests for new features or bug fixes. Regression tests are especially appreciated.
- Integration tests that depend on live LLM calls should be marked and skippable without valid credentials.

## Commit Message Guidelines

Write clear, meaningful commit messages:

- Use the imperative mood in the subject line ("Add feature" not "Added feature").
- Keep the subject line under 72 characters.
- Provide additional context in the body when the change is non-trivial.
- Reference related issues where appropriate (e.g. `Fixes #123`).

Example:
```
Add retry logic to Remedy agent for transient API failures

The Remedy agent previously aborted on any LLM error. This change
retries up to 3 times with exponential backoff before failing the
finding, which significantly improves pipeline reliability.

Fixes #87
```

## Community Expectations

- Be respectful and constructive in discussions and reviews.
- Assume good intent and ask clarifying questions before pushing back.
- Credit the work of others; do not submit code you do not have the right to contribute.
- Follow the project's [LICENSE](LICENSE) — contributions are made under the same terms.

## Contact

For questions, proposals, or security disclosures, please reach out via the repository's issue tracker or contact the maintainers listed in the [README](README.md#contact-information).

Thank you for helping make this project better!
