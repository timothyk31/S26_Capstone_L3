# TODO: Implement Concurrent Manager (Manage 4 concurrent workflows)
#
# Purpose: Run multiple Pipeline instances concurrently (default 4, configurable)
# Per spec: "Ideally 4 findings at a time, all workflows share same VM resource"
#
# Key responsibilities:
# 1. Manage pool of concurrent pipelines (default 4)
# 2. Queue findings for distribution
# 3. Coordinate shared VM resource (single ShellCommandExecutor)
# 4. Handle graceful failure (one pipeline failure doesn't stop others)
# 5. Collect all FindingResults
# 6. Progress reporting for all concurrent workflows
#
# Concurrency options:
# - Option 1: ThreadPoolExecutor (simplest)
# - Option 2: asyncio (if agents support async)
# - Option 3: multiprocessing.Pool (overkill, SSH connections not picklable)
#
# Example:
# class ConcurrentManager:
#     def __init__(
#         self,
#         pipeline_factory: Callable[[], Pipeline],  # Creates new Pipeline instance
#         max_concurrent: int = 4,  # Per spec
#     ):
#         self.pipeline_factory = pipeline_factory
#         self.max_concurrent = max_concurrent
#
#     def run_all(self, vulnerabilities: List[Vulnerability]) -> List[FindingResult]:
#         """Run all vulnerabilities through pipeline with concurrency limit"""
#         results = []
#
#         with ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
#             # Submit all findings to pool
#             futures = {executor.submit(self._run_pipeline, vuln): vuln for vuln in vulnerabilities}
#
#             # Collect results as they complete
#             for future in as_completed(futures):
#                 vuln = futures[future]
#                 try:
#                     result = future.result()
#                     results.append(result)
#                 except Exception as e:
#                     # Log error, continue with other findings
#                     console.print(f"[red]Pipeline failed for {vuln.id}: {e}[/red]")
#
#         return results
#
#     def _run_pipeline(self, vulnerability: Vulnerability) -> FindingResult:
#         """Run single finding through pipeline"""
#         pipeline = self.pipeline_factory()
#         return pipeline.run(vulnerability)