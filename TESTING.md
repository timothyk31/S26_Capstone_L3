# Testing Framework Documentation

## Overview

This project implements a comprehensive testing framework for the Multi-Agent OpenSCAP Security Compliance System. The framework includes unit tests, integration tests, and external API tests.

## Quick Start

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Run Tests
```bash
# Quick smoke test
python run_tests.py --fast

# Complete test suite
python run_tests.py --all

# With coverage reporting
python run_tests.py --coverage
```

## Test Structure

```
tests/
├── unit/                   # Unit tests (fast, no external deps)
│   ├── agents/            # Agent-specific tests
│   ├── helpers/           # Helper module tests
│   └── test_schemas.py    # Data model tests
├── integration/           # Integration tests (cross-component)
│   ├── test_agent_pipeline.py
│   └── test_error_handling.py
├── api/                   # External API tests
│   ├── test_openrouter_api.py
│   └── test_ssh_api.py
├── fixtures/              # Test data and factories
├── mocks/                 # Mock servers and services
└── conftest.py           # Global test configuration
```

## Test Categories

### Unit Tests (`@pytest.mark.unit`)
- **Purpose**: Test individual components in isolation
- **Speed**: Fast (< 1 second per test)
- **Dependencies**: No external services required
- **Coverage**: Core business logic, data models, algorithms

**Examples:**
```bash
pytest tests/unit -m "unit"                    # All unit tests
pytest tests/unit -m "unit and not slow"       # Fast unit tests only
pytest tests/unit/agents/test_triage_agent.py  # Specific agent tests
python run_tests.py --unit                     # Using test runner
```

### Integration Tests (`@pytest.mark.integration`)
- **Purpose**: Test component interactions and workflows
- **Speed**: Medium (1-10 seconds per test)
- **Dependencies**: Mocked external services
- **Coverage**: Pipeline flows, error handling, data consistency

**Examples:**
```bash
pytest tests/integration -m "integration"      # All integration tests
python run_tests.py --integration              # Using test runner
```

### External API Tests (`@pytest.mark.api`)
- **Purpose**: Test external service contracts and resilience
- **Speed**: Variable (depends on network/mocking)
- **Dependencies**: Mock or real external services
- **Coverage**: API contracts, network failures, rate limiting

**Examples:**
```bash
pytest tests/api -m "api"                      # All API tests
pytest tests/api -m "contract"                # Contract tests only
```

### Specialized Test Markers
- `@pytest.mark.slow`: Tests that take > 5 seconds
- `@pytest.mark.requires_ssh`: Tests needing SSH access
- `@pytest.mark.requires_llm`: Tests needing LLM API access
- `@pytest.mark.contract`: API contract validation tests
- `@pytest.mark.chaos`: Chaos engineering tests

## Running Tests

### Using run_tests.py (Recommended)

```bash
# Fast feedback loop
python run_tests.py --fast

# Specific test categories
python run_tests.py --unit
python run_tests.py --integration
python run_tests.py --api

# Complete test suite
python run_tests.py --all

# Coverage analysis
python run_tests.py --coverage

# Specific test files
python run_tests.py --specific tests/unit/test_schemas.py

# Security analysis
python run_tests.py --security

# Performance tests
python run_tests.py --performance

# Clean up artifacts
python run_tests.py --clean
```


### Using pytest directly

```bash
# Basic usage
pytest tests/unit -v

# With markers
pytest tests/ -m "unit and not slow"
pytest tests/ -m "integration and not requires_ssh"
pytest tests/ -m "api and contract"

# With coverage
pytest tests/ --cov=./ --cov-report=html

# Parallel execution
pytest tests/ -n auto

# Stop on first failure
pytest tests/ -x

# Verbose output with traceback
pytest tests/ -vv --tb=long
```

## Test Configuration

### Environment Variables

```bash
# For LLM API tests (optional)
export OPENROUTER_API_KEY="your-api-key"
export OPENROUTER_MODEL="meta-llama/llama-3.1-70b-instruct"
export OPENROUTER_BASE_URL="https://openrouter.ai/api/v1"

# For SSH tests (optional)
export TEST_SSH_HOST="your-test-host"
export TEST_SSH_USER="test-user"
export TEST_SSH_KEY="/path/to/ssh/key"
```

### Configuration Files

- `pytest.ini`: pytest configuration and markers
- `conftest.py`: Global fixtures and test setup

## Test Data and Fixtures

### Factories
The test framework uses factory patterns for creating consistent test data:

```python
from tests.fixtures.test_data_factory import (
    VulnerabilityFactory,
    TriageDecisionFactory,
    RemediationAttemptFactory
)

# Create test data
vuln = VulnerabilityFactory.create_ssh_timeout()
decision = TriageDecisionFactory.create_approve()
attempt = RemediationAttemptFactory.create_successful()
```

### Global Fixtures
Available in all tests via `conftest.py`:

- `temp_dir`: Temporary directory for file operations
- `sample_vulnerability`: Standard test vulnerability
- `mock_llm_client`: Mock LLM client
- `mock_command_executor`: Mock command executor
- `mock_ssh_connection`: Mock SSH connection

## Writing New Tests

### Unit Test Example

```python
import pytest
from unittest.mock import MagicMock, patch
from agents.triage_agent import TriageAgent
from tests.fixtures.test_data_factory import VulnerabilityFactory

@pytest.mark.unit
class TestTriageAgent:
    def setup_method(self):
        self.agent = TriageAgent()
    
    def test_safe_ssh_config_approval(self):
        vuln = VulnerabilityFactory.create_ssh_timeout()
        input_data = TriageInput(vulnerability=vuln)
        
        result = self.agent.process(input_data)
        
        assert result.should_remediate is True
        assert result.risk_level == "low"
```

### Integration Test Example

```python
import pytest
from unittest.mock import MagicMock
from workflow.pipeline_v2 import PipelineV2

@pytest.mark.integration
class TestPipelineIntegration:
    def test_end_to_end_success_flow(self):
        # Setup mocked agents
        mock_triage = MagicMock()
        mock_remedy = MagicMock()
        
        pipeline = PipelineV2(
            triage_agent=mock_triage,
            remedy_agent_v2=mock_remedy
        )
        
        # Configure mocks
        mock_triage.process.return_value = approval_decision
        mock_remedy.process.return_value = (successful_attempt, approval)
        
        # Execute and verify
        result = pipeline.run(vulnerability)
        assert result.final_status == "success"
```

### API Test Example

```python
import pytest
import responses
from helpers.llm_base import ToolCallingLLM

@pytest.mark.api
class TestOpenRouterAPI:
    @responses.activate
    @pytest.mark.contract
    def test_api_response_format(self):
        responses.add(
            responses.POST,
            "https://openrouter.ai/api/v1/chat/completions",
            json=expected_response,
            status=200
        )
        
        llm = ToolCallingLLM(...)
        result = llm.run("test message")
        
        assert result == "expected response"
```

## Mock Services

### Mock OpenRouter Server
For testing without real API calls:

```python
from tests.mocks.mock_openrouter import MockOpenRouterContext

with MockOpenRouterContext(port=8001) as server:
    # Configure custom responses
    server.configure_response("test-model", custom_response)
    
    # Run tests against mock server
    llm = ToolCallingLLM(base_url=server.get_url(), ...)
    result = llm.run("test")
```

## Local Testing Workflow

### Development Testing
```bash
# Daily development workflow
python run_tests.py --fast     # Quick feedback
python run_tests.py --all      # Before committing
python run_tests.py --security # Security check
```

## Coverage Reporting

### Generate Coverage Reports
```bash
# HTML report
python run_tests.py --coverage
# Open htmlcov/index.html

# Terminal report
pytest tests/ --cov=./ --cov-report=term

# XML report (for CI)
pytest tests/ --cov=./ --cov-report=xml
```

### Coverage Targets
- **Unit Tests**: > 90% line coverage
- **Integration Tests**: > 80% branch coverage
- **Critical Paths**: 100% coverage for security-critical code

## Performance Testing

### Benchmarking
```bash
# Run performance tests
python run_tests.py --performance

# With benchmarking
pytest tests/ --benchmark-only
```

### Load Testing
```bash
# Chaos engineering tests
pytest tests/ -m "chaos"

# Concurrent execution tests
pytest tests/ -n auto --dist loadfile
```

## Troubleshooting

### Common Issues

1. **Import Errors**
   ```bash
   # Ensure proper Python path
   export PYTHONPATH="${PYTHONPATH}:$(pwd)"
   ```

2. **Missing Dependencies**
   ```bash
   pip install -r requirements.txt
   python run_tests.py --no-deps-check  # Skip check
   ```

3. **SSH Test Failures**
   ```bash
   # Skip SSH tests
   pytest tests/ -m "not requires_ssh"
   ```

4. **LLM API Test Failures**
   ```bash
   # Skip LLM tests
   pytest tests/ -m "not requires_llm"
   
   # Or set up API key
   export OPENROUTER_API_KEY="your-key"
   ```

### Debug Mode
```bash
# Verbose debugging
pytest tests/ -vv --tb=long --capture=no

# Drop into debugger on failure
pytest tests/ --pdb

# Run single test with debugging
pytest tests/unit/test_schemas.py::TestVulnerabilitySchema::test_vulnerability_creation_minimal -vv
```

## Best Practices

### Test Design
1. **Independence**: Tests should not depend on each other
2. **Determinism**: Tests should produce consistent results
3. **Speed**: Unit tests should run in < 1 second
4. **Clarity**: Test names should describe what is being tested
5. **Coverage**: Aim for high coverage of critical paths

### Test Organization
1. **One class per component**: Group related tests in classes
2. **Descriptive names**: Use clear, descriptive test method names
3. **Setup/teardown**: Use fixtures for common test setup
4. **Markers**: Use pytest markers to categorize tests
5. **Documentation**: Include docstrings for complex test scenarios

### Mock Usage
1. **External services**: Always mock external APIs in unit tests
2. **File system**: Use temporary directories for file operations
3. **Time**: Use freezegun for time-dependent tests
4. **Network**: Use responses library for HTTP mocking
5. **Database**: Use in-memory databases for data tests

This testing framework provides comprehensive coverage while maintaining fast feedback loops for efficient development.