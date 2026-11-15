# Exact MCP frame admission regression

A bounded raw request with malformed arguments must still receive final response
frame admission. The former argument-validity check bypassed the frame guard.
The independent negative control produced a 10,485,955-byte response for a
10,485,760-byte request, exceeding the frame ceiling by 195 bytes.

The original failing component run is red-v2.json/log (one selected test). The
fixed component run is green.json/log (33 passed tests). It covers legacy and
modern protocol forms and malformed null, Boolean, array and string arguments.
commit.json identifies the source fix; each run records its source hashes.

The component uses the repository frame and transport modules through Rust path
attributes. Its copied contract module changes only response_budget visibility
to compile the not-yet-wired 0b2 baseline. This is component evidence, not the
complete candidate build or dual-MCP operation qualification.

red.json/log and unavailable-floor-Cargo.lock retain the failed attempt to use an
unavailable offline rmcp version. That attempt selected zero tests and provides
no passing qualification. The successful component uses locked rmcp 3.4.1.

artifacts.sha256.json identifies the archived original files. Absolute paths in
original receipts name the execution location; archived paths do not rewrite the
execution history. Later complete-candidate runs are recorded separately.
