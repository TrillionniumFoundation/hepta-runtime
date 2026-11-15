//! Compile-time smoke test: the binary and a trusted native caller share one
//! policy-enforced backend. This test performs no external effects.

use hepta_runtime::mcp::runtime::jobs::ProcessRefParams;

#[test]
fn public_native_runtime_boundary_is_linkable_without_running_a_tool() {
    let job = ProcessRefParams {
        host: "configured-host".to_string(),
        job_id: "job:fixture".to_string(),
    };
    assert_eq!(job.host, "configured-host");
    assert_eq!(job.job_id, "job:fixture");

    // Compile-check the existing policy-enforced entry points without
    // initializing a runtime, loading credentials, or dispatching a process.
    let _ = hepta_runtime::mcp::runtime::init_runtime;
    let _ = hepta_runtime::mcp::runtime::start_job;
    let _ = hepta_runtime::mcp::runtime::status_job;
    let _ = hepta_runtime::mcp::runtime::wait_job;
    let _ = hepta_runtime::mcp::runtime::cancel_job;
    let _ = hepta_runtime::mcp::runtime::hardware_snapshot;
}
