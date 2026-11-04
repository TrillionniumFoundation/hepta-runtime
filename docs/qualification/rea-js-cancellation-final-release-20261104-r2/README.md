# Final release real MCP cancellation evidence

This is one fixed five-second cancellation and same-owner recovery experiment against release SHA-256 4da25b9b865ef262878098d3d97b5e0c70f44bc83192d4abb4c8d1888fb0dd5d, the same binary used by the final normal MCP and Babel gates.

The unchanged harness first completed a normal MCP call. It then identified its original MCP owner's actual direct JavaScript parser child, opened a pidfd, sent SIGSTOP through that pidfd and confirmed the same child was stopped. This prevents natural parser completion from being mistaken for cancellation.

After a normal MCP notifications/cancelled message for that request, the original live parent terminated and reaped that child within 0.022742728 seconds, inside the unchanged five-second observation window. The pidfd became exit-ready, the child's /proc entry disappeared, and every owner task's children list was empty. The same owner completed a subsequent call. Harness fallback SIGKILL was false. Finally, the parent exited zero on stdin EOF and was reaped.

The original records bind owner PID 1316539 and worker PID 1316549/start-time 85922965. These are historical owned process identities, not currently actionable process targets. The proof is limited to this recorded fixture and Linux process lifecycle. It does not claim arbitrary future-drop synchronous reaping, all cancellation schedules, parent-death qualification, or complete REA parity.

The production worker's 20-second absolute deadline was not changed. The harness's five-second observation window and source were unchanged; harness SHA-256 is 7c7e504f2227846d6434ba1306454455aea1c3178799def379e5c37f1f54735d. No test retry occurred. The original process job ended succeeded/zero with complete durable logs.

The workspace qualification, fixtures, wire logs, stopped-worker record, observation samples, original job request/exit/witness and stdout/stderr are preserved byte for byte. Build provenance includes the original release qualification and complete before/after source and verification inventories. No runtime executable, state database or credential file is copied; excluded runtime paths and hashes remain explicit references in the manifest.

This archive records a passing finite final-release cancellation gate. It is not an assertion that every project integration or upstream parity gate has passed. The top-level manifest covers all included files except itself. Original JSON numbers and absolute historical paths are retained unchanged.
