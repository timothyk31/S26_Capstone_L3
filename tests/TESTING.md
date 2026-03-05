# Testing — Usage

Run tests from the **project root** (where `run_tests.py` lives).

## Setup

```bash
pip install -r requirements.txt
```

## Run tests

| Command | What it runs |
|--------|----------------|
| `python run_tests.py --fast` | Fast unit tests only (no slow / SSH / LLM) |
| `python run_tests.py --unit` | All unit tests |
| `python run_tests.py --integration` | Integration tests (mocked agents) |
| `python run_tests.py --api` | API tests (mocked external services) |
| `python run_tests.py --all` | Unit + integration + API |
| `python run_tests.py --coverage` | Full suite with coverage report (HTML in `htmlcov/`) |
| `python run_tests.py --specific tests/unit/test_schemas.py` | One file or path |
| `python run_tests.py --clean` | Remove `.pytest_cache`, `htmlcov`, etc. |

Use `python3` instead of `python` if that’s what your system has.

## Run pytest directly

```bash
pytest tests/unit -v
pytest tests/integration -v
pytest tests/ -m "unit and not slow"
```

Config: `tests/pytest.ini`. Tests use mocks only; no VM or real SSH/LLM required for the default suite.
