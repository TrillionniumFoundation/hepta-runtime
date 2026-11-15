// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Saturated ordinary traffic cannot consume the existing-job cancellation reserve.
use super::*;

fn submit_cancellation(
	owner: &Owner,
	fixture: &Fixture,
	target: &str,
	slot: usize,
) -> JoinHandle<Result<Output>> {
	let owner = owner.0.clone();
	let command = fixture.command(slot);
	let target = target.to_owned();
	tokio::spawn(async move {
		owner
			.capture_cancellation(
				&target,
				command,
				format!("input-{slot}").as_bytes(),
				Instant::now() + Duration::from_secs(10),
			)
			.await
	})
}

async fn hold_normal_admission(owner: &Owner) -> OwnedSemaphorePermit {
	owner
		.0
		.admission
		.clone()
		.acquire_many_owned(MAX_ADMITTED as u32)
		.await
		.unwrap()
}

#[tokio::test]
async fn full_normal_sixteen_refuses_ordinary_but_original_cancel_can_submit_once() {
	let owner = Owner::new();
	let fixture = Fixture::new();
	let mut normal: Vec<_> = (0..8)
		.map(|slot| submit(&owner, &fixture, &format!("target-{}", slot / 2), slot))
		.collect();
	until(|| (0..8).all(|slot| fixture.ready(slot).exists())).await;
	for slot in 8..16 {
		normal.push(submit(&owner, &fixture, "target-0", slot));
	}
	until(|| owner.0.admission.available_permits() == 0).await;
	assert_eq!(owner.0.global.available_permits(), 0);
	assert_eq!(owner.0.target("target-0").unwrap().available_permits(), 0);
	let refused = owner
		.0
		.capture(
			"target-0",
			fixture.command(90),
			b"ordinary seventeenth must not borrow cancellation capacity",
			Instant::now() + Duration::from_secs(5),
		)
		.await
		.unwrap_err();
	assert!(refused.to_string().contains("admitted capacity exhausted"));
	assert!(!fixture.ready(90).exists());

	let cancellation = submit_cancellation(&owner, &fixture, "target-0", 100);
	until(|| fixture.ready(100).exists()).await;
	assert_eq!(owner.0.core.children.lock().unwrap().len(), 9);
	assert_eq!(owner.0.core.hooks.spawned.load(Ordering::Acquire), 9);
	assert_eq!(owner.0.global.available_permits(), 0);
	assert_eq!(owner.0.admission.available_permits(), 0);
	assert_eq!(owner.0.cancel_global.available_permits(), 0);
	assert_eq!(
		owner.0.cancel_admission.available_permits(),
		MAX_CANCEL_ADMITTED - 1
	);
	fixture.release(100);
	finish_call(cancellation, 100).await;
	assert_eq!(owner.0.global.available_permits(), 0);
	assert_eq!(owner.0.admission.available_permits(), 0);
	assert_eq!(
		owner.0.cancel_global.available_permits(),
		CANCEL_CONNECTIONS
	);
	for slot in 0..16 {
		fixture.release(slot);
	}
	for (slot, task) in normal.into_iter().enumerate() {
		finish_call(task, slot).await;
	}
	assert_eq!(fixture.event_peak(), 9);
	assert_eq!(owner.0.core.hooks.spawned.load(Ordering::Acquire), 17);
	owner.finish().await;
}

#[tokio::test]
async fn unsaturated_six_host_cancellations_keep_parallel_ordinary_capacity() {
	let owner = Owner::new();
	let fixture = Fixture::new();
	let calls: Vec<_> = (0..6)
		.map(|slot| submit_cancellation(&owner, &fixture, &format!("host-{slot}"), slot))
		.collect();
	until(|| (0..6).all(|slot| fixture.ready(slot).exists())).await;
	assert_eq!(owner.0.global.available_permits(), GLOBAL_CONNECTIONS - 6);
	assert_eq!(owner.0.admission.available_permits(), MAX_ADMITTED - 6);
	assert_eq!(
		owner.0.cancel_global.available_permits(),
		CANCEL_CONNECTIONS
	);
	assert_eq!(
		owner.0.cancel_admission.available_permits(),
		MAX_CANCEL_ADMITTED
	);
	for slot in 0..6 {
		fixture.release(slot);
	}
	for (slot, task) in calls.into_iter().enumerate() {
		finish_call(task, slot).await;
	}
	assert_eq!(fixture.event_peak(), 6);
	owner.finish().await;
}

#[tokio::test]
async fn partial_ordinary_host_or_global_permits_drop_before_using_reserve() {
	for held_host in [true, false] {
		let owner = Owner::new();
		let fixture = Fixture::new();
		let host = owner.0.target("same").unwrap();
		let held = if held_host {
			host.clone()
				.acquire_many_owned(HOST_CONNECTIONS as u32)
				.await
				.unwrap()
		} else {
			owner
				.0
				.global
				.clone()
				.acquire_many_owned(GLOBAL_CONNECTIONS as u32)
				.await
				.unwrap()
		};
		let call = submit_cancellation(&owner, &fixture, "same", 0);
		until(|| fixture.ready(0).exists()).await;
		assert_eq!(owner.0.admission.available_permits(), MAX_ADMITTED);
		assert_eq!(
			host.available_permits(),
			if held_host { 0 } else { HOST_CONNECTIONS }
		);
		assert_eq!(
			owner.0.global.available_permits(),
			if held_host { GLOBAL_CONNECTIONS } else { 0 }
		);
		assert_eq!(owner.0.cancel_global.available_permits(), 0);
		fixture.release(0);
		finish_call(call, 0).await;
		drop(held);
		owner.finish().await;
	}
}

#[tokio::test]
async fn reserve_bounds_eight_admissions_one_child_and_dropped_waiters_never_spawn() {
	let owner = Owner::new();
	let fixture = Fixture::new();
	let normal = hold_normal_admission(&owner).await;
	let active = submit_cancellation(&owner, &fixture, "same", 0);
	until(|| fixture.ready(0).exists()).await;
	let queued: Vec<_> = (1..MAX_CANCEL_ADMITTED)
		.map(|slot| submit_cancellation(&owner, &fixture, "same", slot))
		.collect();
	until(|| owner.0.cancel_admission.available_permits() == 0).await;
	assert_eq!(owner.0.core.children.lock().unwrap().len(), 1);
	let error = owner
		.0
		.capture_cancellation(
			"same",
			fixture.command(90),
			b"refused",
			Instant::now() + Duration::from_secs(2),
		)
		.await
		.unwrap_err();
	assert!(error
		.to_string()
		.contains("cancellation capacity exhausted"));
	assert!(!fixture.ready(90).exists());
	for call in queued {
		call.abort();
		assert!(call.await.unwrap_err().is_cancelled());
	}
	assert_eq!(
		owner.0.cancel_admission.available_permits(),
		MAX_CANCEL_ADMITTED - 1
	);
	fixture.release(0);
	finish_call(active, 0).await;
	assert!((1..MAX_CANCEL_ADMITTED).all(|slot| !fixture.ready(slot).exists()));
	assert_eq!(owner.0.core.hooks.spawned.load(Ordering::Acquire), 1);
	drop(normal);
	owner.finish().await;
}

#[tokio::test]
async fn reserved_caller_drop_keeps_capacity_until_reap_and_queued_deadline_never_submits() {
	let owner = Owner::new();
	let fixture = Fixture::new();
	let normal = hold_normal_admission(&owner).await;
	let gate = Arc::new(Gate::default());
	let _release = ReleaseGate(gate.clone());
	*owner.0.core.hooks.child.lock().unwrap() = Some(ChildHooks {
		before_reap: Mutex::new(Some(gate.clone())),
		unconfirmed_wait: false,
	});
	let call = submit_cancellation(&owner, &fixture, "same", 0);
	until(|| fixture.ready(0).exists()).await;
	call.abort();
	assert!(call.await.unwrap_err().is_cancelled());
	until(|| gate.reached.load(Ordering::Acquire)).await;
	assert_eq!(owner.0.cancel_global.available_permits(), 0);
	assert_eq!(
		owner.0.cancel_admission.available_permits(),
		MAX_CANCEL_ADMITTED - 1
	);
	assert_eq!(owner.0.core.children.lock().unwrap().len(), 1);
	let error = owner
		.0
		.capture_cancellation(
			"same",
			fixture.command(1),
			b"expired",
			Instant::now() + Duration::from_millis(30),
		)
		.await
		.unwrap_err();
	assert!(error
		.to_string()
		.contains("cancellation admission deadline"));
	assert!(!fixture.ready(1).exists());
	assert_eq!(
		owner.0.cancel_admission.available_permits(),
		MAX_CANCEL_ADMITTED - 1
	);
	gate.release();
	drop(normal);
	idle(&owner).await;
	assert_eq!(owner.0.core.hooks.spawned.load(Ordering::Acquire), 1);
	owner.finish().await;
}

#[tokio::test]
async fn freeze_stops_reserved_child_and_unsubmitted_reserve_waiters() {
	let owner = Owner::new();
	let fixture = Fixture::new();
	let normal = hold_normal_admission(&owner).await;
	let active = submit_cancellation(&owner, &fixture, "same", 0);
	until(|| fixture.ready(0).exists()).await;
	let queued = submit_cancellation(&owner, &fixture, "same", 1);
	until(|| owner.0.cancel_admission.available_permits() == MAX_CANCEL_ADMITTED - 2).await;
	owner.0.core.freeze();
	assert!(active.await.unwrap().is_err());
	assert!(queued.await.unwrap().is_err());
	assert!(!fixture.ready(1).exists());
	assert_eq!(owner.0.core.hooks.spawned.load(Ordering::Acquire), 1);
	drop(normal);
	owner.finish().await;
}

#[tokio::test]
async fn unconfirmed_reserved_reap_quarantines_capacity_and_freezes_both_routes() {
	let owner = Owner::new();
	let fixture = Fixture::new();
	let normal = hold_normal_admission(&owner).await;
	fixture.release(0);
	*owner.0.core.hooks.child.lock().unwrap() = Some(ChildHooks {
		before_reap: Mutex::new(None),
		unconfirmed_wait: true,
	});
	assert!(owner
		.0
		.capture_cancellation(
			"same",
			fixture.command(0),
			b"",
			Instant::now() + Duration::from_secs(5)
		)
		.await
		.is_err());
	assert!(owner.0.shutdown().await.is_err());
	assert_eq!(owner.0.cancel_global.available_permits(), 0);
	assert_eq!(
		owner.0.cancel_admission.available_permits(),
		MAX_CANCEL_ADMITTED - 1
	);
	assert_eq!(owner.0.core.children.lock().unwrap().len(), 1);
	drop(normal);
	assert!(owner
		.0
		.capture(
			"same",
			fixture.command(1),
			b"",
			Instant::now() + Duration::from_secs(1)
		)
		.await
		.is_err());
	assert!(owner
		.0
		.capture_cancellation(
			"same",
			fixture.command(2),
			b"",
			Instant::now() + Duration::from_secs(1)
		)
		.await
		.is_err());
	assert!(!fixture.ready(1).exists() && !fixture.ready(2).exists());
	assert_eq!(owner.0.core.hooks.spawned.load(Ordering::Acquire), 1);
	// As in the ordinary unconfirmed-wait fixture, reveal only the already-reaped
	// original Child to clean up the test; persistent owner failure stays failed.
	let original = owner
		.0
		.core
		.children
		.lock()
		.unwrap()
		.values()
		.next()
		.unwrap()
		.clone();
	original.state.lock().await.wait_failed = false;
	original.stop_and_reap().await.unwrap();
	owner.0.core.release(&original).await.unwrap();
	drop(original);
	assert_eq!(
		owner.0.cancel_global.available_permits(),
		CANCEL_CONNECTIONS
	);
	assert_eq!(
		owner.0.cancel_admission.available_permits(),
		MAX_CANCEL_ADMITTED
	);
	assert!(owner.0.shutdown().await.is_err());
}

#[test]
fn public_start_reuse_and_cancel_keep_internal_reservation_selection() {
	const CHILD: &str = "HEPTA_CANCEL_RESERVE_ROUTE_CHILD";
	if std::env::var_os(CHILD).is_none() {
		let output = std::process::Command::new(std::env::current_exe().unwrap())
			.args([
				"mcp::runtime::ssh::direct::tests::cancellation_tests::public_start_reuse_and_cancel_keep_internal_reservation_selection",
				"--exact", "--test-threads=1",
			])
			.env(CHILD, "1")
			.output()
			.unwrap();
		assert!(
			output.status.success(),
			"{}\n{}",
			String::from_utf8_lossy(&output.stdout),
			String::from_utf8_lossy(&output.stderr)
		);
		return;
	}
	// Process-global policy/PATH are changed only in this single-test child.
	// This executable records a JSON request locally; no network is contacted.
	use crate::mcp::runtime::{config, jobs};
	use serde_json::{json, Value};
	let root = tempfile::Builder::new()
		.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
		.unwrap();
	std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
	let trace = root.path().join("requests.jsonl");
	let ssh = root.path().join("ssh");
	std::fs::write(&ssh, r#"#!/usr/bin/python3
import json, os, sys
q = json.load(sys.stdin)
kind = q.get('op') or ('start' if 'executable' in q else 'cancel' if 'grace_seconds' in q else 'status')
with open(os.environ['HEPTA_CANCEL_RESERVE_ROUTE_TRACE'], 'a', encoding='utf-8') as stream:
    stream.write(json.dumps({'kind': kind, 'request': q}) + '\n')
if kind == 'start':
    answer = {'ok': True, 'job_id': q['job_id'], 'backend': 'systemd_system' if 'op' in q else 'detached', 'launcher_pid': os.getpid(), 'status': {'job_id': q['job_id']}}
elif kind == 'cancel':
    answer = {'job_id': q['job_id'], 'result': 'already_exited'}
else:
    answer = {'job_id': q['job_id'], 'state': 'running'}
print(json.dumps(answer))
"#).unwrap();
	std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700)).unwrap();
	std::env::set_var("PATH", root.path());
	std::env::set_var("HEPTA_CANCEL_RESERVE_ROUTE_TRACE", &trace);
	for key in [
		"HEPTA_EFFECT_OWNER_FENCE_DIR",
		"HEPTA_EFFECT_OWNER_SELF",
		"HEPTA_EFFECT_OWNER_FENCE_REQUIRED",
		"HEPTA_RUNTIME_OBSERVATION_POOL",
	] {
		std::env::remove_var(key);
	}
	config::init_runtime(serde_json::from_value(json!({
		"state_dir": root.path().join("state"),
		"hosts": {
			"operator": {"ssh_target":"local-recorder.invalid", "platform":"linux", "execution_mode":"operator", "remote_state_dir":"/fixture-operator", "allow_execute":true, "allow_job_network":true},
			"isolated": {"ssh_target":"local-recorder.invalid", "platform":"linux", "execution_mode":"isolated", "remote_state_dir":"/fixture-isolated", "allow_execute":true}
		}
	})).unwrap()).unwrap();
	let rows = || -> Vec<Value> {
		std::fs::read_to_string(&trace)
			.unwrap_or_default()
			.lines()
			.map(|line| serde_json::from_str(line).unwrap())
			.collect()
	};
	let request = |host: &str, key: &str| -> jobs::ProcessStartParams {
		serde_json::from_value(
			json!({"host":host,"executable":"/usr/bin/true","idempotency_key":key}),
		)
		.unwrap()
	};
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.unwrap();
	runtime.block_on(async {
		let guard = start().unwrap();
		let proxy = guard.0.clone();
		for host in ["operator", "isolated"] {
			let original_request = request(host, "original");
			let initial: Value =
				serde_json::from_str(&jobs::start_job(original_request.clone()).await.unwrap())
					.unwrap();
			assert_eq!(initial["job"]["launch_state"], "launched");
			let job_id = initial["job"]["id"].as_str().unwrap();
			let receipt = root
				.path()
				.join("state/jobs")
				.join(format!("{job_id}.json"));
			let original_bytes = std::fs::read(&receipt).unwrap();
			let held = proxy
				.admission
				.clone()
				.acquire_many_owned(MAX_ADMITTED as u32)
				.await
				.unwrap();
			let before = rows().len();
			let new: Value = serde_json::from_str(
				&jobs::start_job(request(host, "new-under-load"))
					.await
					.unwrap(),
			)
			.unwrap();
			assert_eq!(new["launch"]["state"], "launch_unknown");
			assert_eq!(new["launch"]["automatic_retry"], false);
			let reused: Value =
				serde_json::from_str(&jobs::start_job(original_request).await.unwrap()).unwrap();
			assert_eq!(reused["reused"], true);
			assert_eq!(reused["retried_launch"], false);
			assert_eq!(reused["status"]["state"], "status_unavailable");
			assert_eq!(rows().len(), before);
			assert_eq!(
				proxy.cancel_admission.available_permits(),
				MAX_CANCEL_ADMITTED
			);
			let cancelled: Value = serde_json::from_str(
				&jobs::cancel_job(jobs::ProcessCancelParams {
					host: host.into(),
					job_id: job_id.into(),
					grace_seconds: Some(0),
				})
				.await
				.unwrap(),
			)
			.unwrap();
			assert_eq!(cancelled["job_id"], job_id);
			assert_eq!(cancelled["result"], "already_exited");
			assert_eq!(cancelled["termination_confirmed"], false);
			assert_eq!(cancelled["automatic_retry"], false);
			assert_eq!(cancelled["audit_recorded"], true);
			assert_eq!(rows().len(), before + 1);
			assert_eq!(rows()[before]["kind"], "cancel");
			assert_eq!(rows()[before]["request"]["job_id"], job_id);
			assert_eq!(proxy.admission.available_permits(), 0);
			assert_eq!(std::fs::read(receipt).unwrap(), original_bytes);
			assert_eq!(
				proxy.cancel_admission.available_permits(),
				MAX_CANCEL_ADMITTED
			);
			assert_eq!(proxy.cancel_global.available_permits(), CANCEL_CONNECTIONS);
			drop(held);
		}
		assert_eq!(
			rows().iter().filter(|row| row["kind"] == "start").count(),
			2
		);
		assert_eq!(
			rows().iter().filter(|row| row["kind"] == "cancel").count(),
			2
		);
		guard.shutdown().await.unwrap();
	});
}
