// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Hepta Runtime: explicit multi-host execution, durable jobs, PTY sessions,
//! policy enforcement, and read-only host inspection.

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
	ssh::freeze_observation_pool();
	operation_async::freeze_admission();
	tokio::join!(request_async::shutdown(), operation_async::shutdown());
	crate::mcp::fs::shell::kill_all_shell_children();
	pty::close_all_ptys().await;
}
