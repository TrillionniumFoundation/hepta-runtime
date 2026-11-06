// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Hepta Runtime: explicit multi-host execution, durable jobs, PTY sessions,
//! policy enforcement, and read-only host inspection.

#[cfg(all(feature = "phase-cost-diagnostics", not(target_os = "linux")))]
compile_error!("phase-cost-diagnostics is an explicitly Linux-only diagnostic build");
#[cfg(all(feature = "phase-cost-diagnostics", target_os = "linux"))]
pub mod phase_cost;

// Default builds erase each diagnostic wrapper to its original expression.
// None of the default branches evaluate diagnostic inputs or inspect env.
macro_rules! phase_cost_sync {
	($phase:ident, $body:block) => {{
		#[cfg(all(feature = "phase-cost-diagnostics", target_os = "linux"))]
		let _phase_cost_span = $crate::mcp::runtime::phase_cost::sync_span(
			$crate::mcp::runtime::phase_cost::Phase::$phase,
		);
		$body
	}};
}
pub(crate) use phase_cost_sync;

macro_rules! phase_cost_future {
	($phase:ident, $future:expr) => {{
		#[cfg(all(feature = "phase-cost-diagnostics", target_os = "linux"))]
		{
			$crate::mcp::runtime::phase_cost::wall_future(
				$crate::mcp::runtime::phase_cost::Phase::$phase,
				$future,
			)
		}
		#[cfg(not(all(feature = "phase-cost-diagnostics", target_os = "linux")))]
		{
			$future
		}
	}};
}
pub(crate) use phase_cost_future;

#[cfg(target_os = "linux")]
macro_rules! phase_cost_wall {
	($phase:ident, $body:block) => {{
		#[cfg(feature = "phase-cost-diagnostics")]
		{
			let span = $crate::mcp::runtime::phase_cost::wall_span(
				$crate::mcp::runtime::phase_cost::Phase::$phase,
			);
			let value = $body;
			$crate::mcp::runtime::phase_cost::finish_span(span);
			value
		}
		#[cfg(not(feature = "phase-cost-diagnostics"))]
		$body
	}};
}
#[cfg(target_os = "linux")]
pub(crate) use phase_cost_wall;

macro_rules! phase_cost_request {
	($operation:expr, $host:expr, $body:block) => {{
		#[cfg(all(feature = "phase-cost-diagnostics", target_os = "linux"))]
		{
			let context = $crate::mcp::runtime::phase_cost::TraceContext::request($operation, $host);
			$crate::mcp::runtime::phase_cost::request_scope(context, async move $body).await
		}
		#[cfg(not(all(feature = "phase-cost-diagnostics", target_os = "linux")))]
		$body
	}};
}
pub(crate) use phase_cost_request;

#[cfg(target_os = "linux")]
macro_rules! phase_cost_context_future {
	($context:expr, $future:expr) => {{
		#[cfg(feature = "phase-cost-diagnostics")]
		{
			$crate::mcp::runtime::phase_cost::in_context($context, $future)
		}
		#[cfg(not(feature = "phase-cost-diagnostics"))]
		{
			$future
		}
	}};
}
#[cfg(target_os = "linux")]
pub(crate) use phase_cost_context_future;

macro_rules! phase_cost_context {
	($context:expr, $body:block) => {{
		#[cfg(all(feature = "phase-cost-diagnostics", target_os = "linux"))]
		{
			$crate::mcp::runtime::phase_cost::with_context($context, || $body)
		}
		#[cfg(not(all(feature = "phase-cost-diagnostics", target_os = "linux")))]
		$body
	}};
}
pub(crate) use phase_cost_context;

pub mod binary;
pub mod caller_scope;
pub mod checkpoint;
pub mod config;
pub mod documents;
pub mod effect_owner_fence;
pub mod effective_config;
pub mod execution;
pub mod health;
pub mod inspect;
pub mod jobs;
pub mod multi_read;
#[cfg(unix)]
mod namespace_version;
pub mod operator;
mod privileged_ledger;
pub mod pty;
pub mod request_async;
pub mod request_audit;
pub mod request_results;
pub mod search_jobs;
pub mod ssh;
pub mod stream;
pub mod terminal;

pub use config::{
	init_runtime, runtime_config, HostConfig, Platform, PrivilegedAction, RuntimeConfig,
};
pub use inspect::{hardware_snapshot, network_inspect, privileged_action, service_status};
pub use jobs::{cancel_job, list_jobs, read_job, start_job, status_job, wait_job};
pub use pty::{close_all_ptys, close_pty, list_ptys, read_pty, start_pty, write_pty};

// Private encrypted operation retention key capability.
pub mod operation_crypto;

pub mod operation_async;

/// Startup completes the existing durable store protocol before readiness.
/// No request identity is admitted and no handler runs during preparation.
pub async fn prepare_durable_stores() -> anyhow::Result<()> {
	let root = runtime_config()?.state_dir.clone();
	tokio::task::spawn_blocking(move || {
		request_audit::prepare_at(&root)?;
		request_results::prepare_at(&root)
	})
	.await
	.map_err(|_| anyhow::anyhow!("private runtime store preparation failed"))?
}

/// Stop request-scoped work when an embedding controller retires.
///
/// Freeze both asynchronous admission paths and the observation pool before
/// draining their original owners. Shell children and interactive PTYs belong
/// to this controller; durable host jobs remain queryable after it restarts.
pub async fn shutdown_request_scoped() {
	request_async::freeze_admission();
	ssh::freeze_direct_transport();
	ssh::freeze_observation_pool();
	operation_async::freeze_admission();
	tokio::join!(request_async::shutdown(), operation_async::shutdown());
	crate::mcp::fs::shell::kill_all_shell_children();
	pty::close_all_ptys().await;
}
