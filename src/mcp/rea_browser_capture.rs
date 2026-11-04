// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//! Fixed two-phase orchestration and evidence publication after owned cleanup.

use super::cdp::Cdp;
use super::fixture::Fixtures;
use super::input::{self, Admission, ENTRY, MAX_HAR, PROBE, SCHEMA};
use super::process::{check_cancelled, remove_profile, OwnedChrome, Signals};
use super::BrowserCaptureArgs;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

fn progress(value: Value) -> Result<()> {
	let mut stdout = std::io::stdout().lock();
	serde_json::to_writer(&mut stdout, &value)?;
	stdout.write_all(b"\n")?;
	stdout.flush()?;
	Ok(())
}

struct Captured {
	hars: Vec<Vec<u8>>,
	receipt: Value,
}

pub(super) fn run(args: BrowserCaptureArgs) -> Result<()> {
	let _signals = Signals::install()?;
	let admitted = input::admit(&args)?;
	check_cancelled()?;
	let native_sha256 = executable_identity()?;
	let profile = admitted
		.parent
		.create_child(&format!(".hepta-private-capture-{}", input::random_name()?))?;
	let mut chrome: Option<OwnedChrome> = None;
	let mut fixtures: Option<Fixtures> = None;
	let captured = (|| -> Result<Captured> {
		let chrome_profile = profile.create_child("profile")?;
		fixtures = Some(Fixtures::start(
			admitted.snapshots.clone(),
			&admitted.manifest.requests,
		)?);
		let servers = fixtures.as_ref().context("owned fixtures missing")?;
		servers.control_probe()?;
		let (owner, stream) = OwnedChrome::launch(&chrome_profile)?;
		let pid = owner.pid;
		chrome = Some(owner);
		progress(
			json!({"phase":"browser_started","implementation":"native-rust","browser_pid":pid,"browser_pgid":pid,"profile":chrome_profile.path,"origin":servers.origin,"probe_origin":servers.probe_origin,"automatic_retry":false}),
		)?;
		let mut allowed = BTreeSet::from([format!("{}{ENTRY}", servers.origin)]);
		for snapshot in &admitted.snapshots {
			allowed.insert(format!("{}{}", servers.origin, snapshot.resource.url_path));
		}
		let mut cdp = Cdp::new(
			stream,
			Instant::now() + Duration::from_secs(admitted.manifest.timeout_seconds),
			allowed,
		);
		let browser = cdp.call("Browser.getVersion", json!({}))?;
		progress(json!({"phase":"browser_connected","cdp":cdp.stats(),"automatic_retry":false}))?;
		let target = cdp.call("Target.createTarget", json!({"url":"about:blank"}))?;
		let target = target
			.get("targetId")
			.and_then(Value::as_str)
			.context("Chrome target identity missing")?;
		let attached = cdp.call(
			"Target.attachToTarget",
			json!({"targetId":target,"flatten":true}),
		)?;
		cdp.session = Some(
			attached
				.get("sessionId")
				.and_then(Value::as_str)
				.context("Chrome session identity missing")?
				.to_owned(),
		);
		cdp.call("Page.enable", json!({}))?;
		cdp.call(
			"Network.enable",
			json!({"maxTotalBufferSize":2 * 1024 * 1024,"maxResourceBufferSize":128 * 1024}),
		)?;
		cdp.call("Network.setCacheDisabled", json!({"cacheDisabled":true}))?;
		cdp.call("Network.setBypassServiceWorker", json!({"bypass":true}))?;
		cdp.call(
			"Fetch.enable",
			json!({"patterns":[{"urlPattern":"*","requestStage":"Request"}]}),
		)?;
		progress(
			json!({"phase":"capture_target_ready","cdp":cdp.stats(),"automatic_retry":false}),
		)?;
		let mut bootstrap: Option<String> = None;
		let mut hars = Vec::new();
		let mut coverage = serde_json::Map::new();
		for (index, phase) in ["before", "after"].iter().enumerate() {
			check_cancelled()?;
			if let Some(old) = bootstrap.take() {
				cdp.call(
					"Page.removeScriptToEvaluateOnNewDocument",
					json!({"identifier":old}),
				)?;
			}
			let script = format!(
				"window.__heptaCaptureGeneration={};",
				serde_json::to_string(phase)?
			);
			let added = cdp.call(
				"Page.addScriptToEvaluateOnNewDocument",
				json!({"source":script}),
			)?;
			bootstrap = Some(
				added
					.get("identifier")
					.and_then(Value::as_str)
					.context("Chrome bootstrap identity missing")?
					.into(),
			);
			servers.set_phase(index);
			cdp.begin_phase(phase)?;
			let url = format!("{}{ENTRY}", servers.origin);
			let navigated = cdp.call("Page.navigate", json!({"url":url}))?;
			if navigated.get("errorText").is_some() {
				bail!("fixed fixture navigation failed");
			}
			progress(
				json!({"phase":"capture_navigated","capture_phase":phase,"cdp":cdp.stats(),"automatic_retry":false}),
			)?;
			let ready = format!("document.URL==={} && window.__heptaCaptureGeneration==={} && typeof window.__heptaCaptureDone==='object'", serde_json::to_string(&url)?, serde_json::to_string(phase)?);
			loop {
				let value = cdp.call(
					"Runtime.evaluate",
					json!({"expression":ready,"returnByValue":true}),
				)?;
				if value.pointer("/result/value").and_then(Value::as_bool) == Some(true) {
					break;
				}
				std::thread::sleep(Duration::from_millis(20));
			}
			let done = cdp.call(
				"Runtime.evaluate",
				json!({"expression":"window.__heptaCaptureDone","awaitPromise":true,"returnByValue":true}),
			)?;
			let result = done
				.pointer("/result/value")
				.context("fixed fixture result missing")?;
			if result.get("generation").and_then(Value::as_str) != Some(phase)
				|| result.get("blocked").and_then(Value::as_bool) != Some(true)
				|| result
					.get("results")
					.and_then(Value::as_array)
					.map(Vec::len) != Some(admitted.manifest.requests.len())
			{
				bail!("fixed fixture generation, completion, or denial witness mismatch");
			}
			// The resolved JS promise is not an event barrier. Retain repeated URL
			// occurrences and wait for CDP terminals plus every request-gate ack.
			let expected_urls: Vec<_> = std::iter::once(format!("{}{ENTRY}", servers.origin))
				.chain(
					admitted
						.manifest
						.requests
						.iter()
						.map(|path| format!("{}{path}", servers.origin)),
				)
				.chain(std::iter::once(format!("{}{PROBE}", servers.probe_origin)))
				.collect();
			cdp.settle_requests(&expected_urls)?;
			let (har, phase_coverage) = cdp.har()?;
			let bytes = serde_json::to_vec(&har)?;
			if bytes.len() > MAX_HAR {
				bail!("HAR publication exceeds byte budget");
			}
			hars.push(bytes);
			coverage.insert((*phase).into(), phase_coverage);
			progress(
				json!({"phase":"capture_phase_complete","capture_phase":phase,"automatic_retry":false}),
			)?;
		}
		// Keep observing the original target session through pipe closure. The
		// original child owner still confirms group termination below.
		let close_acknowledged = cdp.close_browser()?;
		cdp.require_settled()?;
		let stats = cdp.stats();
		let denied = cdp.denied.clone();
		let probe_url = format!("{}{PROBE}", servers.probe_origin);
		for phase in ["before", "after"] {
			if !cdp
				.denied
				.iter()
				.any(|row| row["phase"] == phase && row["url"] == probe_url)
			{
				bail!("missing phase-specific request gate denial witness");
			}
		}
		let receipt = json!({
			"schema":SCHEMA,"implementation":"native-rust","native_worker_sha256":native_sha256,"runtime_version":env!("CARGO_PKG_VERSION"),
			"manifest_sha256":admitted.manifest_sha256,"sources":source_pins(&admitted),"requests":admitted.manifest.requests,
			"browser_version":browser,"origin":servers.origin,"probe_origin":servers.probe_origin,"cdp":stats,
			"phase_coverage":coverage,"denied_urls":denied,"browser_close_acknowledged":close_acknowledged,
			"request_owner":"existing-native-process-job","automatic_retry":false,
			"process_level_network_isolation":false,"changed_session_descendants_covered":false,
			"coverage":{
				"source_scripts_executed":false,"generated_fixture_script_executed":true,
				"input_page_dom_inspected":false,"arbitrary_page_execution_supported":false,
				"websocket_blocking_qualified":false,"popup_navigation_blocking_qualified":false,
				"page_origin_gate":true,"process_level_network_isolation":false,"same_origin_before_after":true,
				"raw_http_wire_equivalence":false,"general_browser_state_replay":false,
				"changed_session_descendants_covered":false
			}
		});
		Ok(Captured { hars, receipt })
	})();
	// Cleanup is unconditional and takes priority over a successful capture or a
	// cancellation. A retained leader reserves its original group through final reap.
	let process_cleanup = if let Some(owner) = chrome.as_mut() {
		owner.cleanup()
	} else {
		Ok(())
	};
	let fixture_cleanup = if let Some(servers) = fixtures.as_mut() {
		servers.shutdown()
	} else {
		Ok(())
	};
	process_cleanup.context("private Chrome cleanup unconfirmed; original job requires inspection, automatic_retry=false")?;
	fixture_cleanup?;
	remove_profile(&admitted.parent, &profile)?;
	let mut captured = captured?;
	check_cancelled()?;
	// Snapshot and validate counters only after both the browser owner cleanup
	// and every fixture thread have completed; late requests remain observable.
	let servers = fixtures
		.as_ref()
		.context("owned fixtures missing after cleanup")?;
	let mut loopback = servers.receipt()?;
	loopback["origin"] = json!(servers.origin);
	loopback["negative_probe_origin"] = json!(servers.probe_origin);
	loopback["negative_probe_control_requests"] =
		loopback["positive_control_requests_received"].clone();
	loopback["negative_probe_browser_requests"] =
		loopback["browser_probe_requests_received"].clone();
	captured.receipt["loopback"] = loopback;
	captured.receipt["private_chrome_closed"] = json!(true);
	captured.receipt["private_profile_removed"] = json!(true);
	captured.receipt["original_process_group_no_live_members"] = json!(true);
	captured.receipt["loopback_servers_stopped"] = json!(true);
	let output = admitted.parent.create_child(&admitted.output_name)?;
	let mut artifacts = serde_json::Map::new();
	for (phase, bytes) in ["before", "after"].iter().zip(&captured.hars) {
		let name = format!("{phase}.har");
		output.publish(&name, bytes, MAX_HAR)?;
		artifacts.insert(
			(*phase).into(),
			json!({"path":output.path.join(&name),"bytes":bytes.len(),"sha256":input::sha256(bytes)}),
		);
	}
	captured.receipt["artifacts"] = json!(artifacts);
	// A visible receipt cannot attest its own later directory fsync. The original
	// job and post-sync complete event provide that confirmation.
	captured.receipt["publication"] = json!({
		"create_only":true,"har_files_fsynced":true,"har_directory_fsynced":true,
		"receipt_published_last":true,
		"receipt_directory_fsync_confirmation":"original_job_succeeded_with_complete_event"
	});
	let receipt = serde_json::to_vec(&captured.receipt)?;
	output.verify_location()?;
	output.publish("capture-receipt.json", &receipt, 64 * 1024)?;
	// Signals only set an atomic flag during publication. The receipt proves the
	// files exist; the durable job may still report cancelled, never auto-retry it.
	check_cancelled()?;
	progress(
		json!({"phase":"complete","implementation":"native-rust","output_directory":output.path,"receipt_path":output.path.join("capture-receipt.json"),"receipt_sha256":input::sha256(&receipt),"receipt_directory_fsynced":true,"artifacts":artifacts,"private_chrome_closed":true,"private_profile_removed":true,"automatic_retry":false}),
	)?;
	Ok(())
}

fn source_pins(admitted: &Admission) -> Vec<Value> {
	admitted.snapshots.iter().map(|snapshot| json!({
		"url_path":snapshot.resource.url_path,"mime_type":snapshot.resource.mime_type,
		"before":{"file":snapshot.resource.before.file,"sha256":snapshot.resource.before.sha256,"bytes":snapshot.before.len()},
		"after":{"file":snapshot.resource.after.as_ref().unwrap_or(&snapshot.resource.before).file,"sha256":snapshot.resource.after.as_ref().unwrap_or(&snapshot.resource.before).sha256,"bytes":snapshot.after.len()},
		"delivery":snapshot.resource.delivery,"delay_ms":snapshot.resource.delay_ms
	})).collect()
}

fn executable_identity() -> Result<String> {
	let mut file = File::open("/proc/self/exe")?;
	let before = file.metadata()?;
	if !before.is_file() || before.len() > 512 * 1024 * 1024 {
		bail!("native capture executable exceeds identity budget");
	}
	let mut hasher = Sha256::new();
	let mut total = 0u64;
	let mut buffer = [0u8; 64 * 1024];
	loop {
		check_cancelled()?;
		let count = file.read(&mut buffer)?;
		if count == 0 {
			break;
		}
		total += count as u64;
		if total > 512 * 1024 * 1024 {
			bail!("native executable changed during identity read");
		}
		hasher.update(&buffer[..count]);
	}
	crate::mcp::rea_files::ensure_unchanged(&before, &file.metadata()?)?;
	if total != before.len() {
		bail!("native executable identity read was incomplete");
	}
	Ok(hasher
		.finalize()
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect())
}
