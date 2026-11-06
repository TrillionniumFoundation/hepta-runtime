// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! A cleanup witness cannot borrow another job or a still-live process group.

use super::*;
use serde_json::json;

fn cancelled() -> Value {
	json!({"job_id":"owned-job", "state":"cancelled", "exit_code":0,
		"timed_out":false, "cancelled":true, "launch_nonce":"a".repeat(32), "at_unix_ms":1,
		"terminal_publication_protocol":1, "terminal_publication_confirmed":true,
		"output_complete":true, "output_durable":true,
		"log_bytes":{"stdout":{"seen":0,"stored":0},"stderr":{"seen":0,"stored":0}},
		"log_truncated":{"stdout":false,"stderr":false}, "log_errors":{"stdout":null,"stderr":null},
		"log_synced":{"stdout":true,"stderr":true},
		"scratch_cleanup":{"schema":"hepta.rea.engine-scratch-cleanup.v1", "job_id":"owned-job",
			"launch_nonce":"a".repeat(32), "directory":"engine-scratch", "device":1,"inode":2,
			"state":"removed","removed":true,"durable":true,"worker_adopted":true,
			"original_process_group_stopped":true,"original_child_reaped":true}})
}

#[test]
fn engine_scratch_receipt_is_part_of_the_stable_original_terminal_proof() {
	let value = cancelled();
	let proof = terminal_proof(&value, "owned-job").unwrap().unwrap();
	assert_eq!(proof.state, "cancelled");
	assert_eq!(proof.exit_code, 0);
	assert_eq!(
		proof.scratch_cleanup,
		Some(value["scratch_cleanup"].clone())
	);
	let mut retained = value;
	retained["scratch_cleanup"]["state"] = json!("retained");
	retained["scratch_cleanup"]["removed"] = json!(false);
	retained["scratch_cleanup"]["durable"] = json!(false);
	assert_ne!(
		proof,
		terminal_proof(&retained, "owned-job").unwrap().unwrap()
	);
}

#[test]
fn engine_scratch_removal_cannot_be_claimed_without_original_group_and_wait() {
	for field in [
		"original_process_group_stopped",
		"original_child_reaped",
		"durable",
	] {
		let mut value = cancelled();
		value["scratch_cleanup"][field] = json!(false);
		assert!(terminal_proof(&value, "owned-job").is_err(), "{field}");
	}
	for field in ["job_id", "launch_nonce", "directory"] {
		let mut value = cancelled();
		value["scratch_cleanup"][field] = json!("another-owner");
		assert!(terminal_proof(&value, "owned-job").is_err(), "{field}");
	}
}

#[test]
fn retained_and_legacy_scratch_remain_queryable_without_fabricated_cleanup() {
	let mut value = cancelled();
	value["scratch_cleanup"]["state"] = json!("retained");
	for field in [
		"removed",
		"durable",
		"original_process_group_stopped",
		"original_child_reaped",
	] {
		value["scratch_cleanup"][field] = json!(false);
	}
	assert!(terminal_proof(&value, "owned-job").unwrap().is_some());
	value.as_object_mut().unwrap().remove("scratch_cleanup");
	assert!(terminal_proof(&value, "owned-job")
		.unwrap()
		.unwrap()
		.scratch_cleanup
		.is_none());
}
