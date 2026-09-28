# Python test accounting for PR #5

Counts are **100 = 71 shared + 29 working-tree-only** and
**77 = 71 shared + 6 PR-only**. The difference of 23 is a net count, not
a list of 23 omitted tests. The omitted working-tree tests are not all
publisher/runtime scope: 18 are browser/local-viewer/graph tests, 4 image-runtime
preparation tests, and 7 model-runtime tests.

No Python test present on the PR base (`1968db9`) is deleted, skipped or changed
by #5. The 77-test suite remains intact; the independent browser/runtime work
and its tests were not included in the node PR. This does **not** mean that #5
has the new browser behavior or its coverage. The node behavior is exercised
separately by its Rust HTTP tests.

The 100-test side is an owner-local, uncommitted working tree, not a public Git
revision. A public reader cannot reproduce that side from #5 alone; the named
snapshot is a reported local inventory, not independently reproducible evidence
of an unavailable tree. The 77-test PR side and its unchanged test files can be
verified against public base `1968db9`. No private source tree is bundled here.

With access to both checkouts, reproduce the comparison (discovery only):

```sh
python3 ops/compare_tests.py --left /path/to/full-working-tree \
  --right /path/to/pr-worktree
git diff 1968db9 -- "ops/test_*.py"
```

The checked snapshot is [python-test-inventory.json](python-test-inventory.json).
Names below are complete unittest IDs, not inferred from file counts.

## Working-tree-only tests (29)

- `test_browser.BrowserTests.test_complete_claim_body_is_only_the_node_response_and_escaped` — browser.
- `test_browser.BrowserTests.test_config_and_service_never_embed_credentials` — browser.
- `test_browser.BrowserTests.test_coordinates_and_ids_do_not_round` — browser.
- `test_browser.BrowserTests.test_empty_window_and_failed_reads_remain_distinct_over_http` — browser.
- `test_browser.BrowserTests.test_failed_media_and_png_stay_errors_over_http` — browser.
- `test_browser.BrowserTests.test_image_membership_is_checked_at_exact_entity_and_coordinate` — browser.
- `test_browser.BrowserTests.test_image_unbound_or_corrupt_is_refused` — browser.
- `test_browser.BrowserTests.test_localhost_server_refuses_cross_site_hosts_files_and_writes` — browser.
- `test_browser.BrowserTests.test_malformed_or_inconsistent_media_is_error_not_absence` — browser.
- `test_browser.BrowserTests.test_media_error_is_not_absence` — browser.
- `test_browser.BrowserTests.test_no_media_readings_and_unavailable_prose_are_explicit` — browser.
- `test_browser.BrowserTests.test_node_reads_and_images_keep_exact_ids_and_media_states` — browser.
- `test_browser.BrowserTests.test_read_scope_only_from_env_file` — browser.
- `test_browser.BrowserTests.test_redirects_cannot_forward_credential` — browser.
- `test_browser_local.ProposalViewerTests.test_prepared_images_and_tampering` — local candidate viewer.
- `test_browser_local.ProposalViewerTests.test_stale_application_receipt_rejected` — local candidate viewer.
- `test_browser_local.ProposalViewerTests.test_symlink_cannot_expose_outside_attempt` — local candidate viewer.
- `test_graphview.GraphTests.test_same_year_chain_uses_edge_direction_not_title_order` — graph rendering.
- `test_image_prepare.ImagePreparationTests.test_gpu_job_retains_budget_preserves_history_and_binds_returned_images` — image preparation runtime.
- `test_image_prepare.ImagePreparationTests.test_gpu_reservation_rounds_up_and_refuses_changed_price` — image preparation runtime.
- `test_image_prepare.ImagePreparationTests.test_image_preparation_refuses_edited_prompt_and_stale_body` — image preparation runtime.
- `test_image_prepare.ImagePreparationTests.test_image_route_detects_changed_runtime_expiry_and_unpinned_image` — image preparation runtime.
- `test_model_runtime.ModelTests.test_extension_preserves_base_and_requires_supported_connection` — model runtime.
- `test_model_runtime.ModelTests.test_media_prompts_are_model_authored_and_bound_to_every_entry` — model runtime.
- `test_model_runtime.ModelTests.test_optional_classification_is_model_authored_not_repaired` — model runtime.
- `test_model_runtime.RuntimeReceiptTests.test_attempt_result_schema_refuses_unknown_status_and_nonempty_terminal_result` — model runtime.
- `test_model_runtime.RuntimeReceiptTests.test_needs_evidence_completion_writes_terminal_receipt_and_stops` — model runtime.
- `test_model_runtime.RuntimeReceiptTests.test_new_attempt_after_evidence_gap_requires_new_evidence` — model runtime.
- `test_model_runtime.RuntimeReceiptTests.test_terminal_attempt_retry_never_calls_route_transport_or_budget` — model runtime.

## PR-only tests (6; retained from main)

- `test_model_runtime.ModelTests.test_viewer_escapes_content_and_has_no_write_action`
- `test_viewer.ViewerTests.test_connection_credentials_use_environment_not_argv`
- `test_viewer.ViewerTests.test_missing_credential_never_discovers_retired_host`
- `test_viewer.ViewerTests.test_nonlocal_viewer_database_is_refused`
- `test_viewer.ViewerTests.test_same_year_chain_uses_edge_direction_not_title_order`
- `test_viewer.ViewerTests.test_sources_and_prose_are_escaped_without_inventing_source_absence`

## Legacy coverage mapping

- The same-year graph ordering test moved from `test_viewer.ViewerTests` to
  `test_graphview.GraphTests` in the full working tree; its assertions match.
- Legacy proposal rendering and source/prose escaping overlap the new browser
  escaping/read-only tests, but are not name-equivalent or an exact six-for-six
  coverage replacement. #5 retains the legacy tests unchanged.
- Legacy database credential/environment and loopback tests exercise the retired
  database-backed viewer in the full working tree. The new browser has different
  HTTP/config/read-key tests. Do not relabel those as publisher/runtime tests or
  claim identical coverage from the arithmetic. The old implementation and
  its six tests are still present on #5.
