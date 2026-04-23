# Test Index

## Integration Tests (8)

| Test | What it tests |
|---|---|
| test_success_path_persists_reports | Full success flow; triage + remedy JSON persisted to disk by AgentReportWriter |
| test_discarded_finding_skips_remedy | Triage `should_remediate=False` short-circuits — remedy never called |
| test_human_review_finding_skips_remedy | Triage `requires_human_review=True` returns early with correct final_status |
| test_triage_exception_falls_back_to_human_review | Triage raises → pipeline produces fallback decision and writes `error.json` |
| test_preset_triage_decision_skips_triage_agent | Caller-supplied `triage_decision` bypasses the triage agent entirely |
| test_previous_attempts_forwarded_to_remedy | `previous_attempts`, `review_feedback`, `previous_review_verdicts` plumbed into `RemedyInput` on retry |
| test_sequential_findings_mixed_outcomes | Multi-finding run (success/discard/rejected); reports only written for stages that ran |
| test_fresh_metrics_tracker_injected_per_finding | A new `LLMMetricsTracker` is created per run and propagated to all nested agents |

## Unit Tests (95)

### Schemas (8)

| Test | What it tests |
|---|---|
| test_approved_with_review_and_qa | `PreApprovalResult` with both review and QA approving |
| test_rejected_by_review | `PreApprovalResult` rejected at review stage, QA not run |
| test_rejected_by_qa | `PreApprovalResult` approved by review but rejected by QA |
| test_success_finding | `V2FindingResult` construction for a successful finding |
| test_discarded_finding | `V2FindingResult` for a discarded finding (no remediation/approval) |
| test_failed_finding | `V2FindingResult` for a failed remediation |
| test_empty_report | `V2AggregatedReport` with zero findings |
| test_report_with_results | `V2AggregatedReport` containing finding results |

### OpenSCAP Parsing (4)

| Test | What it tests |
|---|---|
| test_ids_are_rule_based | Parsed finding IDs derive from rule names (not generic counters) |
| test_rule_and_oval_id_preserved | `rule` and `oval_id` fields preserved from XCCDF input |
| test_json_output_matches | JSON export structure matches expected schema |
| test_pass_results_excluded | `pass` results filtered out; only fails/errors kept |

### QA Agent V2 (13)

| Test | What it tests |
|---|---|
| test_valid_json | `_parse_qa_result` parses well-formed JSON LLM response |
| test_json_wrapped_in_markdown | `_parse_qa_result` strips markdown code fences around JSON |
| test_invalid_json_returns_unsafe | Malformed JSON yields an unsafe QAResult fallback |
| test_missing_fields_use_defaults | Missing fields in LLM JSON fall back to schema defaults |
| test_non_list_side_effects_ignored | Non-list `side_effects` field is sanitized to empty list |
| test_contains_vulnerability_info | QA prompt includes vulnerability id/title/description |
| test_contains_plan_description | QA prompt includes the planned remediation commands |
| test_contains_review_info | QA prompt includes review verdict context |
| test_is_pre_execution_framing | Prompt is framed as pre-execution safety check (not post-hoc) |
| test_includes_llm_verdict_when_present | Prior LLM verdict (if any) appears in QA prompt |
| test_process_returns_qa_result | `process()` returns a valid `QAResult` on happy path |
| test_process_unsafe_verdict | `process()` returns `safe=False` when LLM says unsafe |
| test_process_llm_returns_garbage | `process()` gracefully handles non-JSON LLM output |

### Review Agent V2 (6)

| Test | What it tests |
|---|---|
| test_both_approve | Review approves → QA approves → final approved=True |
| test_review_rejects_qa_not_called | Review rejection short-circuits; QA is not invoked |
| test_review_approves_qa_rejects | Review approves but QA rejects → final not approved |
| test_review_error_auto_approves_then_qa_runs | Review exception auto-approves so QA still runs |
| test_qa_error_returns_not_approved | QA exception produces a not-approved `PreApprovalResult` |
| test_qa_receives_correct_input | QA receives correct `QAInput` built from review outcome |

### Remedy Agent V2 (10)

| Test | What it tests |
|---|---|
| test_full_success_path | Plan → Review+QA approve → commands applied end-to-end |
| test_approval_rejected | Review/QA reject the plan → no commands executed |
| test_session_error_returns_error_attempt | LLM session crash produces a populated error `RemediationAttempt` |
| test_duration_is_recorded | Overall attempt duration field is set on the result |
| test_step_durations_recorded | Per-step timings recorded in the attempt metrics |
| test_step_durations_no_review | Step timings still recorded when review step skipped |
| test_step_durations_on_session_error | Step timings recorded even when session errors out |
| test_review_input_constructed_correctly | `ReviewInput` built with vuln + attempt + triage context |
| test_review_plan_cap_forces_proceed ⚠️ | (failing) plan-rejection cap forces remedy to proceed |
| test_review_plan_cap_resets_on_approval ⚠️ | (failing) plan cap counter resets after an approval |

### Triage Agent (1)

| Test | What it tests |
|---|---|
| test_malformed_primary_model_logs_and_fallback_model_succeeds | Primary model malformed output → fallback model invoked and succeeds |

### File Locking (22)

| Test | What it tests |
|---|---|
| test_sed_inplace | `sed -i` path extraction |
| test_sed_inplace_with_backup | `sed -i.bak` path extraction |
| test_echo_redirect | `echo > path` path extraction |
| test_echo_append | `echo >> path` path extraction |
| test_tee | `tee path` path extraction |
| test_tee_append | `tee -a path` path extraction |
| test_cp | `cp` source/dest path extraction |
| test_mv | `mv` source/dest path extraction |
| test_chmod | `chmod` target path extraction |
| test_chown | `chown` target path extraction |
| test_cat_read | `cat path` recognised as read |
| test_grep_read | `grep … path` recognised as read |
| test_head_read | `head path` recognised as read |
| test_tail_read | `tail path` recognised as read |
| test_no_paths | Commands with no filesystem paths return empty |
| test_ignores_relative_paths | Only absolute paths are tracked |
| test_ignores_dev_paths | `/dev/*` paths are ignored |
| test_multiple_paths | Command touching multiple paths → all extracted |
| test_empty_command | Empty command string returns empty path list |
| test_session_context_manager | `session()` context manager opens and closes cleanly |
| test_acquire_inside_session | Locks acquired inside a session are tracked |
| test_acquire_outside_session_is_noop | Acquiring without an active session is a no-op |
| test_duplicate_path_not_double_locked | Same path requested twice acquires lock only once |
| test_release_on_session_exit | Locks auto-released when session exits |
| test_empty_paths_ignored | Empty-path acquire requests are ignored |
| test_sorted_acquisition_order | Locks acquired in sorted order to prevent deadlocks |
| test_two_threads_contend_on_same_path | Two threads serialize on the same path |
| test_different_paths_no_contention | Threads on different paths run in parallel |
| test_lock_timeout | Lock acquisition respects timeout |
| test_many_workers_same_file | Many workers on the same file serialize correctly |
| test_no_deadlock_with_sorted_acquisition | Sorted acquisition order prevents deadlock |
| test_lock_tracked_despite_print_failure | Lock state consistent even if logging raises |
| test_session_cleanup_releases_all_locks | Session teardown releases every held lock |
| test_session_with_no_acquires | Empty session opens and closes cleanly |
| test_multiple_sequential_sessions_same_thread | Sequential sessions in one thread don't leak state |
| test_thread_isolation | Each thread's session state is isolated |
| test_get_lock_returns_same_lock_for_same_path | Same path → same lock object (identity) |
| test_get_lock_different_paths_different_locks | Different paths → distinct lock objects |

### Scanner Matching (7)

| Test | What it tests |
|---|---|
| test_match_finding_fail | Scan result matches finding as `fail` |
| test_match_finding_pass | Scan result matches finding as `pass` |
| test_match_finding_empty_scan | Empty scan output returns no match |
| test_match_finding_by_oval_id | Matches finding by `oval_id` |
| test_match_finding_by_rule | Matches finding by `rule` name when oval_id missing |
| test_scan_full_profile_success | Full-profile scan succeeds end-to-end |
| test_scan_full_profile_failure_raises | Full-profile scan failure raises the expected exception |

### Pipeline V2 (8)

| Test | What it tests |
|---|---|
| test_single_attempt_returns_pending_scan | Single attempt returns `pending_scan` (scan happens externally) |
| test_triage_discards | Triage discard → final_status `discarded` |
| test_triage_human_review | Triage flags human review → final_status `requires_human_review` |
| test_triage_error_fallback | Triage exception → safe fallback decision |
| test_result_has_timestamp | Returned `V2FindingResult` has an ISO timestamp |
| test_run_with_triage_decision_skips_triage | Passing `triage_decision=` skips the triage agent |
| test_run_accepts_retry_context | Retry context (previous attempts/verdicts) accepted without error |
| test_remedy_error_returns_pending_scan | Remedy error still produces a `pending_scan` result |

---

**Totals:** 8 integration + 95 unit = 103 tests. ⚠️ = currently failing (pre-existing).
