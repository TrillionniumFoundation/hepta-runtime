# Retention input-error text compatibility

The independent composition consumer rejected the second full Linux attempt:
eight of nine component gates passed, while the evidence gate remained open.
All 19 retained-bundle comparisons had equal parsed JSON. Nine validation
failures had different opaque `content.text` bytes because the native error
serializer used sorted object keys. The other ten retained-bundle responses
already matched byte for byte. The original failed receipt and its exit code 3
are retained; a passing Rust matrix does not override that result.

## Change and original oracle

The production change admits `invalid_request/get_evidence_bundle` to the
existing input-error ordering used by `inspect_elf_notes`. It does not change
validation, result contents, schema, transport budgets or the strict byte
comparison. An unexpected member at any admitted object level still rejects
the complete ordered projection and retains the existing full fallback text.

The nine original request and response strings are preserved in
`tests/fixtures/rea_retention_error_text_original_20261125.json`, SHA-256
`0d088fa25df3ef76a822523ce3dfe937e95db276a563d87bda381e673d9614fb`.
They come from the authenticated `rea-agents` 6.8.0 package, not the native
implementation. Each expected text is copied from the retained reference wire;
parsing it for assertions does not regenerate the expected string. These are
synthetic validation failures; retained success bodies and host paths are not
published in this fixture.

| Original case | Validation boundary |
| --- | --- |
| `complete_filters_rejected` | Filters with complete-bundle detail |
| `detail_null` | Null detail |
| `filters_null` | Null filter object |
| `bad_evidence_id` | Uppercase evidence digest |
| `short_target_digest` | Short target digest |
| `uppercase_profile_digest` | Uppercase profile digest |
| `empty_operation` | Empty operation filter |
| `empty_procedure` | Empty procedure filter |
| `unknown_filter_keys` | Two unknown fields in original insertion order |

The admitted object orders are `code, category, message, retryable,
remediation, recovery, details`; `remediation.action`; `recovery.kind,
operation`; `details.operation, issues`; and each issue's `path, reason,
message, expected, minimum, maximum`, limited to members actually present.
The regression also checks 45 unknown-member controls across the nine cases
and five object levels. Full MCP replay separately retains all 19 original
opaque expectations, including the ten previously passing successes.

## Qualification boundary

The new serializer is production code, so the previous full matrix and
five-producer receipts cannot qualify the new source or binary. The new cut
must pass its own complete matrix, all five original producers and the
independent nine-gate consumer. Scoped tests and input authentication are
recorded separately. This repair does not qualify any of the 229 operation
rows or 18 families, recover the historical 5,244-case corpus, or establish an
active-encoder cancellation observation. Those requirements remain explicit.
