// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Fixed, authenticated reachability probes for administrator-configured hosts.
use anyhow::Result;
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

use super::config::{runtime_config, HostConfig, RuntimeConfig};

const PROBE_RESPONSE: &[u8] = b"hepta-host-health-v1\n";
const PROBE_COMMAND: &str = "printf 'hepta-host-health-v1\\n'";
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PROBE_BYTES: usize = 256;

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostHealthParams {
	/// Exact host name returned by host_list. No network address or SSH target is accepted.
	pub host: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProbeStatus {
	Healthy,
	Timeout,
	SshFailed,
	TransportError,
	InvalidResponse,
}

fn configured_host<'a>(config: &'a RuntimeConfig, name: &str) -> Result<&'a HostConfig> {
	config
		.hosts
		.get(name)
		.ok_or_else(|| anyhow::anyhow!("unknown host; call host_list for configured names"))
}

fn probe_command(host: &HostConfig) -> Command {
	let mut command = Command::new("ssh");
	command.args([
		"-T",
		"-o",
		"BatchMode=yes",
		"-o",
		"ConnectTimeout=8",
		"-o",
		"StrictHostKeyChecking=yes",
		"-o",
		"ForwardAgent=no",
		"-o",
		"ClearAllForwardings=yes",
		"-o",
		"PermitLocalCommand=no",
		"-o",
		"RemoteCommand=none",
		"-o",
		"RequestTTY=no",
		"--",
	]);
	command.arg(&host.ssh_target).arg(PROBE_COMMAND);
	command
}

async fn probe(mut command: Command, timeout: Duration) -> ProbeStatus {
	// Neither SSH diagnostics nor a host's login banner may reveal credentials,
	// destinations or unbounded data through this read-only health surface.
	command
		.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::null())
		.kill_on_drop(true);
	let Ok(mut child) = command.spawn() else {
		return ProbeStatus::TransportError;
	};
	let Some(stdout) = child.stdout.take() else {
		let _ = child.start_kill();
		let _ = child.wait().await;
		return ProbeStatus::TransportError;
	};
	let operation = async {
		let read = async {
			let mut data = Vec::new();
			stdout
				.take((MAX_PROBE_BYTES + 1) as u64)
				.read_to_end(&mut data)
				.await?;
			Ok::<_, std::io::Error>(data)
		};
		tokio::try_join!(read, child.wait())
	};
	let status = match tokio::time::timeout(timeout, operation).await {
		Ok(Ok((_, status))) if !status.success() => ProbeStatus::SshFailed,
		Ok(Ok((data, _))) if data == PROBE_RESPONSE => ProbeStatus::Healthy,
		Ok(Ok(_)) => ProbeStatus::InvalidResponse,
		Ok(Err(_)) => ProbeStatus::TransportError,
		Err(_) => ProbeStatus::Timeout,
	};
	if matches!(status, ProbeStatus::Timeout | ProbeStatus::TransportError) {
		let _ = child.start_kill();
		let _ = child.wait().await;
	}
	status
}

pub async fn host_health(params: HostHealthParams) -> Result<String> {
	let config = runtime_config()?;
	let host = configured_host(config, &params.host)?;
	let started = Instant::now();
	let status = probe(probe_command(host), PROBE_TIMEOUT).await;
	let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
	let healthy = status == ProbeStatus::Healthy;
	// The fixed command proves an authenticated roundtrip without granting an
	// executable, arguments, destination or policy change to the tool caller.
	Ok(serde_json::to_string_pretty(&json!({
		"schema": "hepta-host-health-v1",
		"host": params.host,
		"platform": host.platform,
		"transport": "ssh",
		"status": status,
		"reachable": healthy,
		"authenticated": healthy,
		"ssh_roundtrip_ms": elapsed_ms,
		"timeout_ms": PROBE_TIMEOUT.as_millis(),
		"measurement": "SSH invocation roundtrip including connection setup or reuse, authentication, remote shell startup and fixed response; not ICMP RTT.",
		"diagnostics_redacted": true,
	}))?)
}

#[cfg(test)]
#[path = "health_tests.rs"]
mod tests;
