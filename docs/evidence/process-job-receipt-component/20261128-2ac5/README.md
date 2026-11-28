# Durable JobReceipt component

The two production HIA sources in this change are exact copies of the JobReceipt policy and packer from Hepta commit \`c7e19fe852ca57b78c77441d3ad2969ac198860e\`. The source provenance file records their original paths, Git blob identities, whole-file SHA256 values, sizes and modes. The five original author, syscall and qualification files are retained beside that provenance without editing their contents.

This component publishes an already validated JobRecord in the original six-stage protocol. The HIA policy performs exclusive temporary creation, the complete write, file synchronization, close, rename and directory synchronization. It returns the original \`HIAJRW01\` acknowledgement only after the appropriate stage completes. A missing acknowledgement does not authorize replay, fallback or a claim that publication failed before taking effect.

## Actual qualification

On the Linux desktop host, the two captured HIA sources were compiled with the existing development B3 image \`bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0\`. The packer produced a 189,279-byte ELF, SHA256 \`3a79d790f1da2527c4ada9c62671b81685e366c6e6111e110ea47172e5d29284\`. The complete original template, relocation, policy extent and suffix were checked before executing it.

Nine ordinary methods from the full, unchanged original test file ran successfully, without skips and with their original five-second child limits:

- \`test_both_durable_publications_preserve_bytes_and_mode\`
- \`test_existing_temporary_is_not_overwritten_or_promoted\`
- \`test_rename_failure_is_not_success_or_replayed\`
- \`test_original_registry_size_boundary\`
- \`test_terminal_wire_publishes_the_existing_newline_terminated_files\`
- \`test_owner_wire_creates_both_exact_records_and_never_replaces_previous_intent\`
- \`test_owner_wire_stops_at_partial_publication_without_retry\`
- \`test_native_capture_preserves_isolated_extent_and_actual_io\`
- \`test_original_wait_holds_custody_and_returns_real_wait_status\`

Five malformed pack frames were rejected with the complete output buffer unchanged. The previously qualified process-record image also generated three actual records, including the maximum u128 timestamp and u64 fingerprint. Separate executions of the real publisher persisted \`pending\`, \`launched\` and \`launch_unknown\` records, each with exact byte readback, mode 0600, one link and the original phase-six acknowledgement.

The successful component run took 0.4898519 seconds internally and 0.668364 seconds in its controller. The full original 21-method module remains preserved. The claim here covers the explicitly listed nine methods; the other twelve methods, complete JobRecord reader, complete public process routes and matching final cold installation are separate qualifications.

## Preserved failures and explicit test preparation

The first transport preflight rejected a directory member in the input archive before extracting or running the component. The next run compiled both HIA images successfully but stopped before packaging because the older pinned development compiler distribution did not contain four checker helpers. Both failures are retained.

The successful successor explicitly loaded the four complete original checker function bodies from the captured original source: \`_binding_declaration\`, \`read_adapter_binding\`, \`verify_adapter\` and \`elf_header\`. Their complete ASTs and containing file are pinned in the preparation receipt. No original test-method body or expected result was changed.

The original inputs, failed and successful controllers, actual native products, full buffers, traces, source captures and five externally captured prerequisite files are in \`originals.tar.gz\`. Its 248 files and 46 directories contain 18,536,817 raw bytes. The complete archive is 3,240,124 bytes, SHA256 \`085fa4a1ad6681a3471554ae956fdde9b4941e4fffe0cebbf0a6951cd5853446\`. Every member's bytes and mode were independently checked on Linux and after transfer to the Mac. No original was removed.
