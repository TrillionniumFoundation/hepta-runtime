// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Lost acknowledgements retain the authorized persistent terminal identity.
use super::*;

#[tokio::test]
async fn terminal_starts_serialize_only_the_same_identity() {
	let locks = TerminalStartLocks::default();
	let slow = locks.get("dpty-slow-host").unwrap();
	let held = slow.lock().await;
	let same = locks.get("dpty-slow-host").unwrap();
	assert!(Arc::ptr_eq(&slow, &same));
	assert!(same.try_lock().is_err());
	let healthy = locks.get("dpty-healthy-host").unwrap();
	assert!(healthy.try_lock().is_ok());
	// A cancelled waiter releases its reference; later requests retain the same lock.
	{
		let waiting = same.clone().lock_owned();
		tokio::pin!(waiting);
		assert!(
			std::future::poll_fn(|cx| std::task::Poll::Ready(
				std::future::Future::poll(waiting.as_mut(), cx).is_pending()
			))
			.await
		);
	}
	drop(held);
	assert!(same.try_lock().is_ok());
}

#[test]
fn terminal_start_lock_registry_reclaims_dormant_ids_without_splitting_live_ids() {
	let locks = TerminalStartLocks::default();
	let active = locks.get("dpty-active").unwrap();
	for serial in 0..4096 {
		drop(locks.get(&format!("dpty-{serial}")).unwrap());
	}
	assert!(locks.locks.lock().unwrap().len() <= 1024);
	assert!(Arc::ptr_eq(&active, &locks.get("dpty-active").unwrap()));
}

#[test]
fn terminal_start_lock_registry_reclaims_burst_on_hot_lookup_and_shrinks_capacity() {
	let locks = TerminalStartLocks::default();
	let hot = locks.get("dpty-hot").unwrap();
	let burst: Vec<_> = (0..4096)
		.map(|serial| locks.get(&format!("dpty-burst-{serial}")).unwrap())
		.collect();
	let peak_capacity = locks.locks.lock().unwrap().capacity();
	assert!(peak_capacity > START_LOCK_CLEANUP_THRESHOLD * 4);
	drop(burst);
	assert!(Arc::ptr_eq(&hot, &locks.get("dpty-hot").unwrap()));
	let retained = locks.locks.lock().unwrap();
	assert_eq!(retained.len(), 1);
	assert!(retained.capacity() <= START_LOCK_CLEANUP_THRESHOLD * 4);
	assert!(retained.capacity() < peak_capacity);
}

#[tokio::test]
async fn terminal_start_lock_registry_keeps_owned_waiter_during_cleanup_and_cancel() {
	let locks = TerminalStartLocks::default();
	let initial = locks.get("dpty-owned-waiter").unwrap();
	let identity = Arc::as_ptr(&initial);
	let held = initial.lock_owned().await;
	let surviving;
	{
		let waiting = locks.get("dpty-owned-waiter").unwrap().lock_owned();
		tokio::pin!(waiting);
		assert!(
			std::future::poll_fn(|cx| std::task::Poll::Ready(
				std::future::Future::poll(waiting.as_mut(), cx).is_pending()
			))
			.await
		);
		// Only the queued owned future retains this lock during the cleanup below.
		drop(held);
		for serial in 0..START_LOCK_CLEANUP_THRESHOLD {
			drop(locks.get(&format!("dpty-cleanup-{serial}")).unwrap());
		}
		surviving = locks.get("dpty-owned-waiter").unwrap();
		assert_eq!(identity, Arc::as_ptr(&surviving));
		assert!(surviving.try_lock().is_err());
	}
	// Cancelling the queued future releases its reserved permit for the next call.
	assert!(surviving.try_lock().is_ok());
	assert!(Arc::ptr_eq(
		&surviving,
		&locks.get("dpty-owned-waiter").unwrap()
	));
}

fn record() -> TerminalRecord {
	TerminalRecord {
		session_id: "dpty-existing".into(),
		host: "target-host".into(),
		ssh_target: "pinned-target".into(),
		remote_state_dir: "/private/state".into(),
		job_dir: "/private/state/terminals/dpty-existing".into(),
		request: json!({"env":{"SECRET":"credential"}}),
	}
}

#[test]
fn terminal_transport_failure_retains_same_session_for_every_effect() {
	for operation in ["start", "write", "close"] {
		let result = retain_terminal_outcome(
			&record(),
			operation,
			Err(anyhow::anyhow!("SECRET ssh lost acknowledgement")),
			Some(7),
		);
		assert_eq!(result["session_id"], "dpty-existing");
		assert_eq!(result["host"], "target-host");
		assert_eq!(result["outcome"], "unknown");
		assert_eq!(result["automatic_retry"], false);
		assert_eq!(result["persistent_across_runtime_restart"], true);
		assert!(result.get("bytes_written").is_none());
		assert!(!result.to_string().contains("SECRET"));
		assert!(!result.to_string().contains("credential"));
		if operation == "close" {
			assert_eq!(result["termination_confirmed"], false);
		}
	}
}

#[test]
fn terminal_invalid_acknowledgements_never_claim_delivered_input_or_termination() {
	for (operation, values) in [
		(
			"start",
			vec![
				Value::Null,
				json!([]),
				json!({"reused":false,"status":{"state":"invented","output_complete":true}}),
			],
		),
		(
			"write",
			vec![
				json!({"bytes_written":8,"complete":true,"reused":false}),
				json!({"bytes_written":3,"complete":true,"reused":false}),
				json!({"bytes_written":7,"complete":true}),
			],
		),
		(
			"close",
			vec![
				json!({"result":"terminated"}),
				json!({"result":"close_requested","error":"SECRET"}),
			],
		),
	] {
		for ack in values {
			let result = retain_terminal_outcome(&record(), operation, Ok(ack), Some(7));
			assert_eq!(result["outcome"], "unknown", "invalid {operation} ack");
			assert_eq!(result["automatic_retry"], false);
			assert_eq!(result["session_id"], "dpty-existing");
			assert!(!result.to_string().contains("SECRET"));
		}
	}
}

#[test]
fn partial_terminal_write_ack_and_local_binding_survive_completion_audit_failure() {
	let ack = json!({"bytes_written":3,"complete":false,"reused":false,"host":"spoofed-host","session_id":"spoofed-session"});
	let result = retain_terminal_outcome(&record(), "write", Ok(ack), Some(7));
	let result = retain_pty_after_audit(result, Err(anyhow::anyhow!("SECRET audit sync failed")));
	assert_eq!(result["bytes_written"], 3);
	assert_eq!(result["complete"], false);
	assert_eq!(result["host"], "target-host");
	assert_eq!(result["session_id"], "dpty-existing");
	assert_eq!(result["automatic_retry"], false);
	assert_eq!(result["audit_recorded"], false);
	assert!(!result.to_string().contains("SECRET"));
}

#[test]
fn persistent_unknown_start_state_is_preserved_without_becoming_success() {
	for state in ["lost", "launch_unknown"] {
		let result = retain_terminal_outcome(
			&record(),
			"start",
			Ok(json!({"reused":true,"status":{"state":state,"output_complete":false}})),
			None,
		);
		assert_eq!(result["status"]["state"], state);
		assert_eq!(result["outcome"], "unknown");
		assert_eq!(result["automatic_retry"], false);
	}
	let result = retain_terminal_outcome(
		&record(),
		"start",
		Ok(json!({"reused":false,"status":{"state":"running","output_complete":false,"pid":123}})),
		None,
	);
	assert_eq!(result["status"]["pid"], 123);
	assert!(result.get("outcome").is_none());
}

#[test]
fn close_acknowledgement_never_infers_exit_from_absent_owner() {
	for (ack, confirmed) in [("close_requested", false), ("already_exited", false)] {
		let result = retain_terminal_outcome(&record(), "close", Ok(json!({"result":ack})), None);
		let result =
			retain_pty_after_audit(result, Err(anyhow::anyhow!("SECRET audit unavailable")));
		assert_eq!(result["result"], ack);
		assert_eq!(result["termination_confirmed"], confirmed);
		if ack == "already_exited" {
			assert_eq!(result["outcome"], "unknown");
		}
		assert_eq!(result["audit_recorded"], false);
		assert_eq!(result["automatic_retry"], false);
	}
}
