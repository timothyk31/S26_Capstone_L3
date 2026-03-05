#!/usr/bin/env python3
"""
Comprehensive test runner for the Multi-Agent OpenSCAP Testing Framework.

This script provides a convenient interface for running different types of tests
with proper configuration and environment validation.
"""

import argparse
import os
import sys
import subprocess
import time
from pathlib import Path
from typing import List, Optional


PYTEST_CONFIG = "pytest.ini"


class TestRunner:
    """Main test runner class."""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.test_dir = self.project_root / "tests"
        
    def run_command(self, cmd: List[str], capture_output: bool = False) -> subprocess.CompletedProcess:
        """Run a command and return the result."""
        print(f"Running: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                cwd=self.project_root,
                capture_output=capture_output,
                text=True,
                check=False
            )
            return result
        except subprocess.SubprocessError as e:
            print(f"Command failed: {e}")
            return subprocess.CompletedProcess(cmd, 1, "", str(e))
    
    def check_dependencies(self) -> bool:
        """Check if all test dependencies are installed."""
        print("Checking test dependencies...")
        
        required_packages = [
            "pytest", "pytest_mock", "pytest_cov", "responses", "factory"
        ]
        
        missing = []
        for package in required_packages:
            result = self.run_command([sys.executable, "-c", f"import {package.replace('-', '_')}"], capture_output=True)
            if result.returncode != 0:
                missing.append(package)
        
        if missing:
            print(f"Missing packages: {', '.join(missing)}")
            print("Install with: pip install -r requirements.txt")
            return False
        
        print("All test dependencies are available.")
        return True
    
    def validate_environment(self) -> bool:
        """Validate the test environment."""
        print("Validating test environment...")
        
        # Check Python version
        if sys.version_info < (3, 10):
            print(f"Python 3.10+ required, found {sys.version}")
            return False
        
        # Check test directory structure
        required_dirs = [
            self.test_dir / "unit",
            self.test_dir / "unit" / "agents",
            self.test_dir / "unit" / "workflow", 
            self.test_dir / "unit" / "helpers",
            self.test_dir / "integration", 
            self.test_dir / "api",
            self.test_dir / "fixtures"
        ]
        
        for dir_path in required_dirs:
            if not dir_path.exists():
                print(f"Missing test directory: {dir_path}")
                return False
        
        print("Environment validation passed.")
        return True
    
    def run_unit_tests(self, fast_only: bool = False, verbose: bool = False) -> int:
        """Run unit tests."""
        print("\n" + "="*50)
        print("RUNNING UNIT TESTS")
        print("="*50)
        
        cmd = ["python", "-m", "pytest", "-c", PYTEST_CONFIG, "tests/unit"]
        
        if fast_only:
            cmd.extend(["-m", "unit and not slow"])
        else:
            cmd.extend(["-m", "unit"])
        
        if verbose:
            cmd.append("-v")
        else:
            cmd.append("-q")
        
        cmd.extend(["--tb=short"])
        
        result = self.run_command(cmd)
        return result.returncode
    
    def run_integration_tests(self, verbose: bool = False) -> int:
        """Run integration tests."""
        print("\n" + "="*50)
        print("RUNNING INTEGRATION TESTS")
        print("="*50)
        
        cmd = [
            "python", "-m", "pytest", "-c", PYTEST_CONFIG, "tests/integration",
            "-m", "integration and not requires_ssh and not requires_llm"
        ]
        
        if verbose:
            cmd.append("-v")
        else:
            cmd.append("-q")
        
        cmd.extend(["--tb=short"])
        
        result = self.run_command(cmd)
        return result.returncode
    
    def run_api_tests(self, verbose: bool = False) -> int:
        """Run API tests."""
        print("\n" + "="*50)
        print("RUNNING API TESTS")
        print("="*50)
        
        cmd = [
            "python", "-m", "pytest", "-c", PYTEST_CONFIG, "tests/api",
            "-m", "api and not requires_ssh and not requires_llm"
        ]
        
        if verbose:
            cmd.append("-v")
        else:
            cmd.append("-q")
        
        cmd.extend(["--tb=short"])
        
        result = self.run_command(cmd)
        return result.returncode
    
    def run_coverage_test(self) -> int:
        """Run tests with coverage reporting."""
        print("\n" + "="*50)
        print("RUNNING COVERAGE ANALYSIS")
        print("="*50)
        
        cmd = [
            "python", "-m", "pytest", "-c", PYTEST_CONFIG, "tests/",
            "-m", "not requires_ssh and not requires_llm",
            "--cov=./",
            "--cov-report=html",
            "--cov-report=term",
            "--tb=short"
        ]
        
        result = self.run_command(cmd)
        
        if result.returncode == 0:
            print("\nCoverage report generated in htmlcov/index.html")
        
        return result.returncode
    
    def run_specific_test(self, test_path: str, verbose: bool = False) -> int:
        """Run a specific test file or test function."""
        print(f"\n" + "="*50)
        print(f"RUNNING SPECIFIC TEST: {test_path}")
        print("="*50)
        
        cmd = ["python", "-m", "pytest", "-c", PYTEST_CONFIG, test_path]
        
        if verbose:
            cmd.append("-v")
        
        cmd.extend(["--tb=short"])
        
        result = self.run_command(cmd)
        return result.returncode
    
    def run_security_scan(self) -> int:
        """Run security analysis."""
        print("\n" + "="*50)
        print("RUNNING SECURITY ANALYSIS")
        print("="*50)
        
        exit_code = 0
        
        # Run bandit security scan
        print("Running bandit security scan...")
        result = self.run_command([
            "python", "-m", "bandit", "-r", "agents/", "helpers/", "workflow/", 
            "-f", "json", "-o", "bandit-report.json"
        ])
        if result.returncode != 0:
            print("Bandit scan completed with warnings (see bandit-report.json)")
            exit_code = 1
        
        # Run safety check
        print("Checking dependencies for known vulnerabilities...")
        result = self.run_command(["python", "-m", "safety", "check"])
        if result.returncode != 0:
            print("Safety check found vulnerabilities")
            exit_code = 1
        
        return exit_code
    
    def run_performance_tests(self) -> int:
        """Run performance/benchmark tests."""
        print("\n" + "="*50)
        print("RUNNING PERFORMANCE TESTS")
        print("="*50)
        
        cmd = [
            "python", "-m", "pytest", "-c", PYTEST_CONFIG, "tests/",
            "-m", "slow",
            "--tb=short"
        ]
        
        result = self.run_command(cmd)
        return result.returncode
    
    def clean_artifacts(self) -> None:
        """Clean up test artifacts."""
        print("Cleaning up test artifacts...")
        
        artifacts = [
            ".pytest_cache",
            "tests/.pytest_cache",
            "__pycache__",
            ".coverage",
            "htmlcov",
            "coverage.xml",
            "bandit-report.json",
            "test-report.html"
        ]
        
        for artifact in artifacts:
            artifact_path = self.project_root / artifact
            if artifact_path.exists():
                if artifact_path.is_dir():
                    import shutil
                    shutil.rmtree(artifact_path)
                else:
                    artifact_path.unlink()
        
        # Clean Python cache files
        for pyc_file in self.project_root.rglob("*.pyc"):
            pyc_file.unlink()
        
        for pycache_dir in self.project_root.rglob("__pycache__"):
            import shutil
            shutil.rmtree(pycache_dir)
        
        print("Cleanup completed.")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Multi-Agent OpenSCAP Testing Framework Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_tests.py --fast              # Quick unit tests only
  python run_tests.py --unit              # All unit tests
  python run_tests.py --integration       # Integration tests
  python run_tests.py --api               # API contract tests
  python run_tests.py --all               # Complete test suite
  python run_tests.py --coverage          # Tests with coverage
  python run_tests.py --specific tests/unit/test_schemas.py  # Specific test
  python run_tests.py --security          # Security analysis
  python run_tests.py --performance       # Performance tests
  python run_tests.py --clean             # Clean up artifacts
        """
    )
    
    parser.add_argument("--fast", action="store_true", 
                       help="Run fast unit tests only")
    parser.add_argument("--unit", action="store_true",
                       help="Run all unit tests")
    parser.add_argument("--integration", action="store_true",
                       help="Run integration tests")
    parser.add_argument("--api", action="store_true",
                       help="Run API tests")
    parser.add_argument("--all", action="store_true",
                       help="Run complete test suite")
    parser.add_argument("--coverage", action="store_true",
                       help="Run tests with coverage reporting")
    parser.add_argument("--specific", type=str,
                       help="Run specific test file or function")
    parser.add_argument("--security", action="store_true",
                       help="Run security analysis")
    parser.add_argument("--performance", action="store_true",
                       help="Run performance/benchmark tests")
    parser.add_argument("--clean", action="store_true",
                       help="Clean up test artifacts")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Verbose output")
    parser.add_argument("--no-deps-check", action="store_true",
                       help="Skip dependency check")
    
    args = parser.parse_args()
    
    runner = TestRunner()
    
    # Clean up if requested
    if args.clean:
        runner.clean_artifacts()
        return 0
    
    # Validate environment
    if not args.no_deps_check:
        if not runner.validate_environment():
            return 1
        
        if not runner.check_dependencies():
            return 1
    
    exit_code = 0
    
    # Run tests based on arguments
    if args.fast:
        exit_code = runner.run_unit_tests(fast_only=True, verbose=args.verbose)
    elif args.unit:
        exit_code = runner.run_unit_tests(verbose=args.verbose)
    elif args.integration:
        exit_code = runner.run_integration_tests(verbose=args.verbose)
    elif args.api:
        exit_code = runner.run_api_tests(verbose=args.verbose)
    elif args.coverage:
        exit_code = runner.run_coverage_test()
    elif args.specific:
        exit_code = runner.run_specific_test(args.specific, verbose=args.verbose)
    elif args.security:
        exit_code = runner.run_security_scan()
    elif args.performance:
        exit_code = runner.run_performance_tests()
    elif args.all:
        # Run complete test suite
        print("Running complete test suite...")
        
        tests = [
            ("Unit Tests", lambda: runner.run_unit_tests(verbose=args.verbose)),
            ("Integration Tests", lambda: runner.run_integration_tests(verbose=args.verbose)),
            ("API Tests", lambda: runner.run_api_tests(verbose=args.verbose)),
        ]
        
        results = {}
        for test_name, test_func in tests:
            print(f"\n{'='*60}")
            print(f"STARTING: {test_name}")
            print('='*60)
            start_time = time.time()
            
            result = test_func()
            results[test_name] = result
            
            duration = time.time() - start_time
            status = "PASSED" if result == 0 else "FAILED"
            print(f"{test_name}: {status} ({duration:.2f}s)")
            
            if result != 0:
                exit_code = 1
        
        # Print summary
        print("\n" + "="*60)
        print("TEST SUMMARY")
        print("="*60)
        for test_name, result in results.items():
            status = "✓ PASSED" if result == 0 else "✗ FAILED"
            print(f"{test_name:<30} {status}")
        
        overall = "PASSED" if exit_code == 0 else "FAILED"
        print(f"\nOverall Result: {overall}")
    
    else:
        # Default: run fast unit tests
        print("No specific test type specified, running fast unit tests...")
        exit_code = runner.run_unit_tests(fast_only=True, verbose=args.verbose)
    
    return exit_code


if __name__ == "__main__":
    sys.exit(main())