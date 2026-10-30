// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Root-helper pure validation tests; no privileged side effects.
use super::*;
#[test]
fn strict_owned_ids() {
	assert!(safe_id("pty-ab12-77"));
	for s in ["", "..", "a/b", "a.service", "a;id"] {
		assert!(!safe_id(s));
	}
}
#[test]
fn unknown_root_actions_and_pid_fields_cannot_deserialize() {
	assert!(
		serde_json::from_value::<Request>(json!({"op":"cancel","job_id":"abc","pid":1})).is_err()
	);
}
#[test]
fn argv_and_stdin_bind_full_digest() {
	let mut q: Request =
		serde_json::from_value(json!({"op":"start","job_id":"abc","executable":"/bin/true"}))
			.unwrap();
	let d = digest(&q).unwrap();
	assert_eq!(d.len(), 64);
	q.stdin = Some("different".into());
	assert_ne!(d, digest(&q).unwrap());
}
#[test]
fn cwd_symlink_escape_is_rejected() {
	let root = tempfile::tempdir().unwrap();
	let other = tempfile::tempdir().unwrap();
	std::os::unix::fs::symlink(other.path(), root.path().join("escape")).unwrap();
	let p = Policy {
		workspace: root.path().to_owned(),
		allow_network: false,
		max_timeout_seconds: 60,
		max_cpu_percent: 25,
		max_memory_bytes: 134217728,
	};
	let mut q:Request=serde_json::from_value(json!({"op":"start","job_id":"abc","executable":"/usr/bin/true","cwd":root.path().join("escape")})).unwrap();
	assert!(validate(&mut q, &p).is_err());
}
#[test]
fn resources_are_capped_by_admin() {
	let root = tempfile::tempdir().unwrap();
	let p = Policy {
		workspace: root.path().to_owned(),
		allow_network: false,
		max_timeout_seconds: 60,
		max_cpu_percent: 25,
		max_memory_bytes: 134217728,
	};
	let mut q: Request = serde_json::from_value(
		json!({"op":"start","job_id":"abc","executable":"/usr/bin/true","cpu_quota_percent":26}),
	)
	.unwrap();
	assert!(validate(&mut q, &p).is_err());
	q.cpu_quota_percent = Some(20);
	assert!(validate(&mut q, &p).is_ok());
}

fn completed_fixture() -> (Record, Exit) {
	(
		Record {
			job_id: "fixture".into(),
			unit: "hepta-job-fixture.service".into(),
			request_digest: "digest".into(),
			boot_id: "previous-boot".into(),
			nonce: "owned-nonce".into(),
			invocation_id: Some("original-invocation".into()),
			launch_state: "launched".into(),
			created_unix_ms: 1,
			terminal_protocol: None,
		},
		Exit {
			job_id: "fixture".into(),
			nonce: "owned-nonce".into(),
			exit_code: 7,
			timed_out: false,
			cancelled: false,
			at_unix_ms: 2,
			terminal_protocol: None,
			output_complete: None,
			output_durable: None,
			capture: None,
		},
	)
}
#[test]
fn completed_result_preserves_exit_from_previous_boot() {
	let (r, e) = completed_fixture();
	let result = completed_result(
		&r,
		&ConfirmedExit {
			receipt: e,
			witnessed: false,
		},
	)
	.unwrap();
	assert_eq!(result["state"], "failed");
	assert_eq!(result["exit_code"], 7);
}
#[test]
fn completion_must_match_owned_nonce_and_job() {
	let (r, receipt) = completed_fixture();
	let mut e = ConfirmedExit {
		receipt,
		witnessed: false,
	};
	e.receipt.nonce = "foreign".into();
	assert!(completed_result(&r, &e).is_err());
	e.receipt.nonce = r.nonce.clone();
	e.receipt.job_id = "foreign".into();
	assert!(completed_result(&r, &e).is_err());
}

#[test]
fn versioned_status_without_terminal_receipt_never_invents_a_terminal_outcome() {
	for protocol in [TerminalProtocol::CapturedV1, TerminalProtocol::PtyV1] {
		for (active, present, launch) in [
			("failed", true, "launched"),
			("inactive", true, "launched"),
			("", false, "launched"),
			("active", true, "cancelled"),
		] {
			let root = tempfile::tempdir().unwrap();
			let (mut record, _) = completed_fixture();
			record.terminal_protocol = Some(protocol);
			record.launch_state = launch.into();
			let result = status_at(
				&mut record,
				root.path(),
				|| Ok("previous-boot".into()),
				|_| {
					Ok((
						BTreeMap::from([("ActiveState".into(), active.into())]),
						present,
					))
				},
			)
			.unwrap();
			assert_eq!(result["state"], "finalizing");
			assert_eq!(result["outcome"], "unknown");
			assert_eq!(result["reason"], "terminal_receipt_missing");
			assert_eq!(result["status_authoritative"], false);
			assert_eq!(result["automatic_retry"], false);
			assert_eq!(result["terminal_receipt_observed"], false);
			assert_eq!(result["terminal_publication"], "not_observed");
			assert_eq!(result["terminal_publication_confirmed"], false);
			assert!(result["exit_code"].is_null());
			assert!(result["output_complete"].is_null());
			assert!(result["output_durable"].is_null());
		}
	}
}

#[test]
fn status_preserves_live_observations_and_legacy_terminal_states() {
	for protocol in [None, Some(TerminalProtocol::CapturedV1)] {
		for active in ["active", "activating", "deactivating"] {
			let root = tempfile::tempdir().unwrap();
			let (mut record, _) = completed_fixture();
			record.terminal_protocol = protocol;
			let result = status_at(
				&mut record,
				root.path(),
				|| Ok("previous-boot".into()),
				|_| {
					Ok((
						BTreeMap::from([("ActiveState".into(), active.into())]),
						true,
					))
				},
			)
			.unwrap();
			assert_eq!(result["state"], "running");
			assert!(result["exit_code"].is_null());
		}
	}
	for (active, present, launch, expected) in [
		("failed", true, "launched", "failed"),
		("inactive", true, "launched", "lost"),
		("", false, "launched", "lost"),
		("active", true, "cancelled", "cancelled"),
	] {
		let root = tempfile::tempdir().unwrap();
		let (mut record, _) = completed_fixture();
		record.launch_state = launch.into();
		let result = status_at(
			&mut record,
			root.path(),
			|| Ok("previous-boot".into()),
			|_| {
				Ok((
					BTreeMap::from([("ActiveState".into(), active.into())]),
					present,
				))
			},
		)
		.unwrap();
		assert_eq!(result["state"], expected);
		assert!(result["outcome"].is_null());
	}
}

#[test]
fn status_rereads_terminal_publication_after_systemd_collection_or_probe_error() {
	for snapshot in ["failed", "not-found", "error", "running"] {
		let root = tempfile::tempdir().unwrap();
		let (mut record, _) = completed_fixture();
		record.terminal_protocol = Some(TerminalProtocol::PtyV1);
		let result = status_at(
			&mut record,
			root.path(),
			|| Ok("previous-boot".into()),
			|r| {
				let receipt = Exit::new(
					&r.job_id,
					r.nonce.clone(),
					0,
					false,
					false,
					TerminalProtocol::PtyV1,
					None,
				);
				publish_terminal(root.path(), &receipt)?;
				if snapshot == "error" {
					bail!("unit disappeared during observation");
				}
				Ok((
					BTreeMap::from([("ActiveState".into(), snapshot.into())]),
					snapshot != "not-found",
				))
			},
		)
		.unwrap();
		assert_eq!(result["state"], "succeeded");
		assert_eq!(result["exit_code"], 0);
		assert_eq!(result["terminal_publication_confirmed"], true);
		assert_eq!(result["automatic_retry"], false);
	}
}

#[test]
fn status_rereads_unwitnessed_publication_before_interpreting_unit_failure() {
	let root = tempfile::tempdir().unwrap();
	let (mut record, _) = completed_fixture();
	record.terminal_protocol = Some(TerminalProtocol::PtyV1);
	let result = status_at(
		&mut record,
		root.path(),
		|| Ok("previous-boot".into()),
		|r| {
			let receipt = Exit::new(
				&r.job_id,
				r.nonce.clone(),
				0,
				false,
				false,
				TerminalProtocol::PtyV1,
				None,
			);
			atomic(&root.path().join("exit.json"), &receipt)?;
			Ok((
				BTreeMap::from([("ActiveState".into(), "failed".into())]),
				true,
			))
		},
	)
	.unwrap();
	assert_eq!(result["state"], "finalizing");
	assert_eq!(result["outcome"], "unknown");
	assert_eq!(result["status_authoritative"], false);
	assert_eq!(result["automatic_retry"], false);
	assert_eq!(result["terminal_receipt_observed"], true);
	assert_eq!(result["terminal_publication_confirmed"], false);
}

#[test]
fn versioned_reboot_without_a_receipt_is_unknown_and_never_replayed() {
	let root = tempfile::tempdir().unwrap();
	let (mut record, _) = completed_fixture();
	record.terminal_protocol = Some(TerminalProtocol::CapturedV1);
	let result = status_at(
		&mut record,
		root.path(),
		|| Ok("next-boot".into()),
		|_| panic!("must not inspect a later boot's unit"),
	)
	.unwrap();
	assert_eq!(result["state"], "lost");
	assert_eq!(result["reason"], "target_reboot");
	assert_eq!(result["outcome"], "unknown");
	assert_eq!(result["status_authoritative"], false);
	assert_eq!(result["automatic_retry"], false);
	assert_eq!(result["terminal_receipt_observed"], false);
	assert_eq!(result["terminal_publication_confirmed"], false);
}

#[test]
fn terminal_publication_during_boot_probe_remains_valid_after_reboot() {
	let root = tempfile::tempdir().unwrap();
	let (mut record, _) = completed_fixture();
	record.terminal_protocol = Some(TerminalProtocol::PtyV1);
	let receipt = Exit::new(
		&record.job_id,
		record.nonce.clone(),
		0,
		false,
		false,
		TerminalProtocol::PtyV1,
		None,
	);
	let result = status_at(
		&mut record,
		root.path(),
		|| {
			publish_terminal(root.path(), &receipt)?;
			Ok("next-boot".into())
		},
		|_| panic!("must not inspect a later boot's unit"),
	)
	.unwrap();
	assert_eq!(result["state"], "succeeded");
	assert_eq!(result["terminal_publication_confirmed"], true);
	assert_eq!(result["automatic_retry"], false);
}

#[test]
fn probe_failure_without_a_terminal_receipt_stays_an_error() {
	let root = tempfile::tempdir().unwrap();
	let (mut record, _) = completed_fixture();
	record.terminal_protocol = Some(TerminalProtocol::PtyV1);
	let error = status_at(
		&mut record,
		root.path(),
		|| Ok("previous-boot".into()),
		|_| bail!("unit incarnation changed: refusing operation"),
	)
	.unwrap_err();
	assert!(error.to_string().contains("unit incarnation changed"));
}

#[test]
fn cancellation_ack_cannot_overwrite_a_witnessed_original_exit() {
	for (code, cancelled, expected) in [
		(0, false, "succeeded"),
		(7, false, "failed"),
		(0, true, "cancelled"),
	] {
		let root = tempfile::tempdir().unwrap();
		let (mut record, _) = completed_fixture();
		record.terminal_protocol = Some(TerminalProtocol::PtyV1);
		let receipt = Exit::new(
			&record.job_id,
			record.nonce.clone(),
			code,
			false,
			cancelled,
			TerminalProtocol::PtyV1,
			None,
		);
		publish_terminal(root.path(), &receipt).unwrap();
		// A stop acknowledgment after the supervisor published this original
		// terminal result cannot alter what actually happened to the command.
		record.launch_state = "cancelled".into();
		let result = status_at(
			&mut record,
			root.path(),
			|| panic!("terminal result precedes boot probe"),
			|_| panic!("terminal result precedes unit probe"),
		)
		.unwrap();
		assert_eq!(result["state"], expected);
		assert_eq!(result["exit_code"], code);
		assert_eq!(result["cancelled"], cancelled);
		assert_eq!(result["terminal_publication_confirmed"], true);
	}
	let (mut record, receipt) = completed_fixture();
	record.launch_state = "cancelled".into();
	assert_eq!(
		completed_result(
			&record,
			&ConfirmedExit {
				receipt,
				witnessed: false
			}
		)
		.unwrap()["state"],
		"cancelled"
	);
}

#[test]
fn json_fifo_rejected_without_waiting_for_a_writer() {
	let root = tempfile::tempdir().unwrap();
	let path = root.path().join("fifo");
	let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
	assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
	assert!(json_file::<Value>(&path).is_err());
}

fn quiet_command(script: &str) -> Command {
	let mut command = Command::new("python3");
	command
		.args(["-I", "-S", "-c", script])
		.stdin(Stdio::null());
	command
}

fn capture_fixture(script: &str, directory: &Path) -> Supervision {
	let mut command = quiet_command(script);
	let (child, capture) = spawn_supervised(&mut command, directory, false).unwrap();
	finish_supervision(child, capture, Duration::from_secs(10), || false).unwrap()
}

fn capture_receipt(outcome: Supervision) -> (Record, Exit) {
	let (mut record, _) = completed_fixture();
	record.terminal_protocol = Some(TerminalProtocol::CapturedV1);
	let receipt = Exit::new(
		&record.job_id,
		record.nonce.clone(),
		outcome
			.status
			.code()
			.unwrap_or(128 + outcome.status.signal().unwrap_or(0)),
		outcome.timed_out,
		outcome.cancelled,
		TerminalProtocol::CapturedV1,
		outcome.capture,
	);
	(record, receipt)
}

fn persist_capture(directory: &Path, outcome: Supervision) -> (Record, Exit) {
	let (record, receipt) = capture_receipt(outcome);
	publish_terminal(directory, &receipt).unwrap();
	let receipt: Exit = json_file(&directory.join("exit.json")).unwrap();
	(record, receipt)
}

#[test]
fn legacy_completion_and_pty_never_invent_output_completeness() {
	let (record, _) = completed_fixture();
	let old: Exit = serde_json::from_value(json!({
		"job_id":record.job_id,"nonce":record.nonce,"exit_code":0,
		"timed_out":false,"cancelled":false,"at_unix_ms":2,
	}))
	.unwrap();
	let root = tempfile::tempdir().unwrap();
	fs::write(root.path().join("stdout.log"), b"old output").unwrap();
	atomic(&root.path().join("exit.json"), &old).unwrap();
	let status = completion_at(&record, root.path()).unwrap().unwrap();
	assert_eq!(status["state"], "succeeded");
	assert_eq!(status["terminal_publication"], "legacy_unknown");
	assert!(status["output_complete"].is_null());
	assert!(status["output_durable"].is_null());
	assert!(status["capture"].is_null());
	let output = read_output_at(&record, root.path(), 0, 0, 16384).unwrap();
	assert_eq!(output["stdout"]["eof"], true);
	assert_eq!(output["terminal_receipt_observed"], true);
	assert!(output["output_complete"].is_null());
	assert!(output["output_durable"].is_null());
	let mut record = record;
	record.terminal_protocol = Some(TerminalProtocol::PtyV1);
	let pty = Exit::new(
		&record.job_id,
		record.nonce.clone(),
		0,
		false,
		false,
		TerminalProtocol::PtyV1,
		None,
	);
	publish_terminal(root.path(), &pty).unwrap();
	let status = completion_at(&record, root.path()).unwrap().unwrap();
	assert_eq!(status["state"], "succeeded");
	assert_eq!(status["terminal_publication_confirmed"], true);
	assert!(status["output_complete"].is_null());
	assert!(status["output_durable"].is_null());
	assert!(status["capture"].is_null());
	assert!(supervisor_capture_result(&pty).is_ok());
}

#[test]
fn original_pipes_are_fully_synced_before_the_terminal_capture_receipt() {
	let root = tempfile::tempdir().unwrap();
	let outcome = capture_fixture(
		"import os;os.write(1,b'original\\x00stdout\\xff');os.write(2,b'original stderr')",
		root.path(),
	);
	assert!(outcome.status.success());
	let (record, receipt) = persist_capture(root.path(), outcome);
	assert_eq!(receipt.output_complete, Some(true));
	assert_eq!(receipt.output_durable, Some(true));
	assert_eq!(
		fs::read(root.path().join("stdout.log")).unwrap(),
		b"original\x00stdout\xff"
	);
	assert_eq!(
		fs::read(root.path().join("stderr.log")).unwrap(),
		b"original stderr"
	);
	let status = completion_at(&record, root.path()).unwrap().unwrap();
	assert_eq!(status["state"], "succeeded");
	for name in ["stdout", "stderr"] {
		assert_eq!(status["capture"][name]["eof"], true);
		assert_eq!(status["capture"][name]["synced"], true);
		assert_eq!(status["capture"][name]["truncated"], false);
	}
	let first = read_output_at(&record, root.path(), 0, 0, 3).unwrap();
	assert_eq!(first["stdout"]["next_offset"], 3);
	assert_eq!(first["stdout"]["bytes_hex"], "6f7269");
	assert_eq!(first["output_complete"], true);
	assert_eq!(first["output_durable"], true);
	assert!(read_output_at(&record, root.path(), 1_000, 0, 16384).is_err());
}

#[test]
fn cap_plus_one_retains_the_bound_and_reports_lost_output_in_status_and_reads() {
	let root = tempfile::tempdir().unwrap();
	let outcome = capture_fixture(
		r#"import os
os.write(2,b'stderr remains fair')
for _ in range(2048):
    view=memoryview(b'x'*8192)
    while view:
        view=view[os.write(1,view):]
os.write(1,b'!')
"#,
		root.path(),
	);
	assert!(outcome.status.success());
	let (record, receipt) = persist_capture(root.path(), outcome);
	let capture = receipt.capture.as_ref().unwrap();
	assert_eq!(capture.stdout.seen, LOG_MAX + 1);
	assert_eq!(capture.stdout.saved, LOG_MAX);
	assert!(capture.stdout.eof && capture.stdout.truncated && capture.stdout.synced);
	assert!(capture.stderr.complete() && capture.stderr.synced);
	assert_eq!(
		fs::metadata(root.path().join("stdout.log")).unwrap().len(),
		LOG_MAX
	);
	let status = completion_at(&record, root.path()).unwrap().unwrap();
	assert_eq!(status["state"], "failed");
	assert_eq!(status["exit_code"], 0);
	assert_eq!(status["output_complete"], false);
	assert_eq!(status["output_durable"], false);
	assert!(supervisor_capture_result(&receipt).is_err());
	let tail = read_output_at(&record, root.path(), LOG_MAX, 0, 16384).unwrap();
	assert_eq!(tail["stdout"]["eof"], true);
	assert_eq!(tail["stdout"]["bytes_hex"], "");
	assert_eq!(tail["capture"]["stdout"]["truncated"], true);
	assert_eq!(tail["output_complete"], false);
	assert_eq!(tail["output_durable"], false);
}

#[test]
fn a_delayed_inherited_writer_cannot_change_logs_after_terminal_publication() {
	let root = tempfile::tempdir().unwrap();
	let (out_reader, out_writer) = capture_pipe().unwrap();
	let (err_reader, err_writer) = capture_pipe().unwrap();
	let capture = Capture {
		streams: [
			CaptureStream::new(
				out_reader,
				File::create(root.path().join("stdout.log")).unwrap(),
			),
			CaptureStream::new(
				err_reader,
				File::create(root.path().join("stderr.log")).unwrap(),
			),
		],
	};
	// A separately owned fixture child inherits this exact output pipe. Its
	// write is gated until AFTER the original leader's terminal publication.
	// Both actual children have RAII custody, including assertion failures.
	let mut delayed = quiet_command(
		r#"import os,pathlib,sys,time
root=pathlib.Path(sys.argv[1]);until=time.monotonic()+5
while not (root/'release').exists():
    if time.monotonic()>=until:raise RuntimeError('fixture was not released')
    time.sleep(.005)
try:os.write(1,b'late output must not be retained')
except BrokenPipeError:(root/'observed').write_text('closed')
else:(root/'observed').write_text('late write succeeded')
"#,
	);
	delayed
		.arg(root.path())
		.stdout(Stdio::from(out_writer.try_clone().unwrap()))
		.stderr(Stdio::null());
	let delayed_child = delayed.spawn().unwrap();
	drop(delayed);
	let mut delayed = OriginalChild {
		child: delayed_child,
		reaped: false,
	};
	let mut leader = quiet_command("import os;os.write(1,b'original prefix')");
	leader
		.stdout(Stdio::from(out_writer))
		.stderr(Stdio::from(err_writer));
	let original = OriginalChild {
		child: leader.spawn().unwrap(),
		reaped: false,
	};
	drop(leader);
	let outcome =
		finish_supervision(original, Some(capture), Duration::from_secs(5), || false).unwrap();
	assert!(outcome.status.success());
	let (record, receipt) = persist_capture(root.path(), outcome);
	let stream = &receipt.capture.as_ref().unwrap().stdout;
	assert!(stream.drain_timeout && !stream.eof && stream.synced);
	assert_eq!(stream.seen, b"original prefix".len() as u64);
	let before = fs::read(root.path().join("stdout.log")).unwrap();
	assert_eq!(before, b"original prefix");
	assert_eq!(
		completion_at(&record, root.path()).unwrap().unwrap()["state"],
		"failed"
	);
	fs::write(root.path().join("release"), b"release").unwrap();
	let until = Instant::now() + Duration::from_secs(3);
	loop {
		if let Some(status) = delayed.try_wait().unwrap() {
			assert!(status.success());
			break;
		}
		assert!(
			Instant::now() < until,
			"original delayed writer failed to settle"
		);
		std::thread::sleep(Duration::from_millis(5));
	}
	assert_eq!(
		fs::read_to_string(root.path().join("observed")).unwrap(),
		"closed"
	);
	assert_eq!(fs::read(root.path().join("stdout.log")).unwrap(), before);
	let output = read_output_at(&record, root.path(), before.len() as u64, 0, 16384).unwrap();
	assert_eq!(output["stdout"]["eof"], true);
	assert_eq!(output["output_complete"], false);
}

#[test]
fn real_sink_write_failure_is_retained_without_stopping_other_stream_capture() {
	let root = tempfile::tempdir().unwrap();
	let mut command =
		quiet_command("import os;os.write(1,b'cannot persist');os.write(2,b'original stderr')");
	let (child, capture) = spawn_supervised(&mut command, root.path(), false).unwrap();
	let mut capture = capture.unwrap();
	capture.streams[0].writer = File::open(root.path().join("stdout.log")).unwrap();
	let outcome =
		finish_supervision(child, Some(capture), Duration::from_secs(5), || false).unwrap();
	assert!(outcome.status.success());
	let (record, receipt) = persist_capture(root.path(), outcome);
	let capture = receipt.capture.as_ref().unwrap();
	assert!(capture.stdout.write_error.is_some());
	assert_eq!(capture.stdout.seen, b"cannot persist".len() as u64);
	assert_eq!(capture.stdout.saved, 0);
	assert!(capture.stdout.eof && capture.stderr.complete());
	assert_eq!(
		fs::read(root.path().join("stderr.log")).unwrap(),
		b"original stderr"
	);
	let status = completion_at(&record, root.path()).unwrap().unwrap();
	assert_eq!(status["state"], "failed");
	assert_eq!(status["exit_code"], 0);
	assert_eq!(status["output_complete"], false);
}

#[cfg(target_os = "linux")]
#[test]
fn actual_fsync_failure_cannot_produce_a_successful_complete_receipt() {
	let root = tempfile::tempdir().unwrap();
	let mut command = quiet_command("import os;os.write(1,b'fsync must fail')");
	let (child, capture) = spawn_supervised(&mut command, root.path(), false).unwrap();
	let mut capture = capture.unwrap();
	// Linux accepts writes to this original descriptor but rejects fsync with
	// EINVAL. This exercises the real barrier error, without an error callback.
	capture.streams[0].writer = OpenOptions::new().write(true).open("/dev/null").unwrap();
	let outcome =
		finish_supervision(child, Some(capture), Duration::from_secs(5), || false).unwrap();
	assert!(outcome.status.success());
	let (record, receipt) = persist_capture(root.path(), outcome);
	let capture = receipt.capture.as_ref().unwrap();
	assert!(capture.stdout.eof && capture.stdout.read_error.is_none());
	assert!(capture.stdout.write_error.is_none());
	assert!(capture.stdout.sync_error.is_some() && !capture.stdout.synced);
	assert_eq!(capture.stdout.seen, capture.stdout.saved);
	assert_eq!(
		completion_at(&record, root.path()).unwrap().unwrap()["state"],
		"failed"
	);
	assert_eq!(receipt.output_complete, Some(false));
	assert_eq!(receipt.output_durable, Some(false));
}

#[test]
fn nonblocking_empty_pipe_then_hangup_preserves_bytes_and_exact_eof() {
	let root = tempfile::tempdir().unwrap();
	let (reader, mut writer) = capture_pipe().unwrap();
	let mut stream = CaptureStream::new(reader, File::create(root.path().join("log")).unwrap());
	stream.read_ready();
	assert!(stream.reader.is_some() && stream.report.read_error.is_none());
	assert_eq!(stream.report.seen, 0);
	writer.write_all(b"original tail").unwrap();
	drop(writer);
	stream.read_ready();
	let report = stream.finish();
	assert!(report.complete() && report.synced);
	assert_eq!(report.seen, b"original tail".len() as u64);
	assert_eq!(fs::read(root.path().join("log")).unwrap(), b"original tail");
}

#[cfg(target_os = "linux")]
#[test]
fn actual_read_error_is_retained_without_claiming_pipe_eof() {
	let root = tempfile::tempdir().unwrap();
	let mut stream = CaptureStream::new(
		File::open(root.path()).unwrap(),
		File::create(root.path().join("log")).unwrap(),
	);
	stream.read_ready();
	let report = stream.finish();
	assert!(report.read_error.is_some());
	assert!(!report.eof && !report.complete());
	assert_eq!(report.seen, 0);
}

#[test]
fn unsafe_or_existing_log_refuses_before_the_original_child_is_spawned() {
	use std::os::unix::process::CommandExt;
	for second in [false, true] {
		let root = tempfile::tempdir().unwrap();
		let protected = root
			.path()
			.join(if second { "stderr.log" } else { "stdout.log" });
		fs::write(&protected, b"retained original").unwrap();
		let marker = root.path().join("business-ran");
		let mut command =
			quiet_command("import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('effect')");
		command.arg(&marker);
		let attempted = tempfile::tempfile().unwrap();
		let fd = attempted.as_raw_fd();
		unsafe {
			command.pre_exec(move || {
				if libc::write(fd, b"x".as_ptr().cast(), 1) != 1 {
					libc::_exit(125);
				}
				Ok(())
			});
		}
		assert!(spawn_supervised(&mut command, root.path(), false).is_err());
		assert_eq!(attempted.metadata().unwrap().len(), 0);
		assert!(!marker.exists());
		assert_eq!(fs::read(protected).unwrap(), b"retained original");
	}
	let root = tempfile::tempdir().unwrap();
	let target = root.path().join("original");
	fs::write(&target, b"not a capture log").unwrap();
	std::os::unix::fs::symlink(&target, root.path().join("stdout.log")).unwrap();
	let mut command = quiet_command("raise RuntimeError('must never spawn')");
	assert!(spawn_supervised(&mut command, root.path(), false).is_err());
	assert_eq!(fs::read(target).unwrap(), b"not a capture log");
}

#[test]
fn timeout_and_cancellation_reap_the_original_child_and_keep_capture_evidence() {
	for cancel in [false, true] {
		let root = tempfile::tempdir().unwrap();
		let mut command = quiet_command("import time;time.sleep(30)");
		let (child, capture) = spawn_supervised(&mut command, root.path(), false).unwrap();
		let timeout = if cancel {
			Duration::from_secs(30)
		} else {
			Duration::from_millis(50)
		};
		let outcome = finish_supervision(child, capture, timeout, || cancel).unwrap();
		assert!(!outcome.status.success());
		assert_eq!(outcome.timed_out, !cancel);
		assert_eq!(outcome.cancelled, cancel);
		assert!(outcome.capture.unwrap().durable());
	}
}

#[test]
fn read_and_status_refuse_foreign_or_inconsistent_terminal_capture_evidence() {
	let root = tempfile::tempdir().unwrap();
	let outcome = capture_fixture("print('original')", root.path());
	let (record, mut receipt) = persist_capture(root.path(), outcome);
	receipt.nonce = "foreign".into();
	atomic(&root.path().join("exit.json"), &receipt).unwrap();
	assert!(completion_at(&record, root.path()).is_err());
	assert!(read_output_at(&record, root.path(), 0, 0, 16384).is_err());
	receipt.nonce = record.nonce.clone();
	receipt.capture.as_mut().unwrap().stdout.truncated = true;
	atomic(&root.path().join("exit.json"), &receipt).unwrap();
	let status = completion_at(&record, root.path()).unwrap().unwrap();
	assert_eq!(status["state"], "finalizing");
	assert!(status["output_complete"].is_null());
	let output = read_output_at(&record, root.path(), 0, 0, 16384).unwrap();
	assert_eq!(output["terminal_publication"], "publication_pending");
	assert!(output["output_complete"].is_null());
}

fn assert_publication_pending(record: &Record, directory: &Path) {
	let status = completion_at(record, directory).unwrap().unwrap();
	let output = read_output_at(record, directory, 0, 0, 16384).unwrap();
	for value in [&status, &output] {
		assert_eq!(value["state"], "finalizing");
		assert_eq!(value["outcome"], "unknown");
		assert_eq!(value["automatic_retry"], false);
		assert_eq!(value["status_authoritative"], false);
		assert_eq!(value["terminal_receipt_observed"], true);
		assert_eq!(value["terminal_publication"], "publication_pending");
		assert_eq!(value["terminal_publication_confirmed"], false);
		assert!(value["output_complete"].is_null());
		assert!(value["output_durable"].is_null());
		assert!(value["capture"].is_null());
	}
}

#[cfg(target_os = "linux")]
#[test]
fn actual_exit_directory_sync_failure_leaves_visible_exit_unconfirmed() {
	let root = tempfile::tempdir().unwrap();
	let outcome = capture_fixture("print('original bytes before barrier')", root.path());
	let (record, receipt) = capture_receipt(outcome);
	let parent = File::open(root.path()).unwrap();
	let rejected_barrier = File::open("/dev/null").unwrap();
	// The production publisher executes the actual file sync and rename, then
	// encounters a real fsync(EINVAL). There is no injected error return.
	let error = publish_terminal_with_parents(root.path(), &receipt, &rejected_barrier, &parent)
		.unwrap_err();
	assert_eq!(
		error
			.downcast_ref::<std::io::Error>()
			.and_then(|error| error.raw_os_error()),
		Some(libc::EINVAL)
	);
	let visible: Exit = json_file(&root.path().join("exit.json")).unwrap();
	assert_eq!(visible.output_durable, Some(true));
	assert!(!root.path().join("exit.witness").exists());
	assert_publication_pending(&record, root.path());
	let output = read_output_at(&record, root.path(), 0, 0, 16384).unwrap();
	assert_eq!(output["stdout"]["text"], "original bytes before barrier\n");
}

#[test]
fn actual_witness_publication_failure_cannot_promote_visible_exit() {
	let root = tempfile::tempdir().unwrap();
	let outcome = capture_fixture("print('retained before witness')", root.path());
	let (record, receipt) = capture_receipt(outcome);
	let obstructed = root.path().join("exit.witness");
	fs::create_dir(&obstructed).unwrap();
	assert!(publish_terminal(root.path(), &receipt).is_err());
	assert!(root.path().join("exit.json").is_file());
	assert!(obstructed.is_dir());
	assert_publication_pending(&record, root.path());
	assert_eq!(
		fs::read(root.path().join("stdout.log")).unwrap(),
		b"retained before witness\n"
	);
}

#[cfg(target_os = "linux")]
#[test]
fn visible_witness_proves_prior_exit_barrier_not_its_own_directory_sync() {
	let root = tempfile::tempdir().unwrap();
	let outcome = capture_fixture("print('preceding barrier succeeded')", root.path());
	let (record, receipt) = capture_receipt(outcome);
	let parent = File::open(root.path()).unwrap();
	let rejected_barrier = File::open("/dev/null").unwrap();
	assert!(
		publish_terminal_with_parents(root.path(), &receipt, &parent, &rejected_barrier).is_err()
	);
	let witness: TerminalWitness = json_file(&root.path().join("exit.witness")).unwrap();
	assert_eq!(
		witness.exit_sha256,
		bytes_digest(&fs::read(root.path().join("exit.json")).unwrap())
	);
	let status = completion_at(&record, root.path()).unwrap().unwrap();
	assert_eq!(status["state"], "succeeded");
	assert_eq!(status["terminal_publication_confirmed"], true);
	assert_eq!(status["output_durable"], true);
	// Losing that unconfirmed witness after a crash is conservative unknown;
	// the reader never reconstructs it from Exit or systemd's exit state.
	fs::remove_file(root.path().join("exit.witness")).unwrap();
	assert_publication_pending(&record, root.path());
}

#[test]
fn witness_binds_exact_exit_bytes_identity_protocol_and_new_record_marker() {
	let root = tempfile::tempdir().unwrap();
	let outcome = capture_fixture(
		"print('same semantic JSON is not the same receipt')",
		root.path(),
	);
	let (record, receipt) = persist_capture(root.path(), outcome);
	let exit_path = root.path().join("exit.json");
	let witness_path = root.path().join("exit.witness");
	let original_exit = fs::read(&exit_path).unwrap();
	let original_witness = fs::read(&witness_path).unwrap();
	for (field, changed) in [
		("job_id", "foreign-job"),
		("nonce", "foreign-incarnation"),
		("terminal_protocol", "pty_v1"),
		("exit_sha256", "foreign-bytes"),
	] {
		let mut value: Value = serde_json::from_slice(&original_witness).unwrap();
		value[field] = json!(changed);
		atomic(&witness_path, &value).unwrap();
		assert_publication_pending(&record, root.path());
	}
	fs::write(&witness_path, &original_witness).unwrap();
	let mut same_json = original_exit.clone();
	same_json.extend_from_slice(b" \n");
	fs::write(&exit_path, same_json).unwrap();
	assert_publication_pending(&record, root.path());
	fs::write(&exit_path, &original_exit).unwrap();
	assert_eq!(
		completion_at(&record, root.path()).unwrap().unwrap()["state"],
		"succeeded"
	);
	let mut missing_capture = serde_json::to_value(&receipt).unwrap();
	for field in ["capture", "output_complete", "output_durable"] {
		missing_capture.as_object_mut().unwrap().remove(field);
	}
	atomic(&exit_path, &missing_capture).unwrap();
	assert_publication_pending(&record, root.path());
	missing_capture
		.as_object_mut()
		.unwrap()
		.remove("terminal_protocol");
	atomic(&exit_path, &missing_capture).unwrap();
	assert_publication_pending(&record, root.path());
	assert_eq!(
		completion_at(&record, root.path()).unwrap().unwrap()["reason"],
		"terminal_protocol_mismatch"
	);
	let mut other_mode = record.clone();
	other_mode.terminal_protocol = Some(TerminalProtocol::PtyV1);
	fs::write(&exit_path, &original_exit).unwrap();
	assert_publication_pending(&other_mode, root.path());
	// A legacy Record can observe an upgraded supervisor's new, witnessed
	// receipt. The missing record marker never suppresses witness checking.
	let mut old_record = record.clone();
	old_record.terminal_protocol = None;
	assert_eq!(
		completion_at(&old_record, root.path()).unwrap().unwrap()["output_complete"],
		true
	);
	fs::remove_file(&witness_path).unwrap();
	assert_publication_pending(&old_record, root.path());
}

#[test]
fn confirmed_capture_reads_reject_deleted_truncated_or_appended_logs() {
	for name in ["stdout.log", "stderr.log"] {
		for mutation in ["delete", "truncate", "append"] {
			let root = tempfile::tempdir().unwrap();
			let outcome = capture_fixture(
				"import os;os.write(1,b'original stdout');os.write(2,b'original stderr')",
				root.path(),
			);
			let (record, _) = persist_capture(root.path(), outcome);
			assert_eq!(
				read_output_at(&record, root.path(), 0, 0, 16384).unwrap()["output_complete"],
				true
			);
			let path = root.path().join(name);
			match mutation {
				"delete" => fs::remove_file(&path).unwrap(),
				"truncate" => OpenOptions::new()
					.write(true)
					.open(&path)
					.unwrap()
					.set_len(1)
					.unwrap(),
				"append" => OpenOptions::new()
					.append(true)
					.open(&path)
					.unwrap()
					.write_all(b"foreign tail")
					.unwrap(),
				_ => unreachable!(),
			}
			assert!(
				read_output_at(&record, root.path(), 0, 0, 16384).is_err(),
				"{name} {mutation}"
			);
		}
	}
	let root = tempfile::tempdir().unwrap();
	let outcome = capture_fixture("pass", root.path());
	let (record, _) = persist_capture(root.path(), outcome);
	fs::remove_file(root.path().join("stdout.log")).unwrap();
	assert!(read_output_at(&record, root.path(), 0, 0, 16384).is_err());
}

#[test]
fn legacy_specs_upgrade_but_declared_capture_and_pty_modes_cannot_change() {
	let (record, _) = completed_fixture();
	let old_record: Record =
		serde_json::from_value(serde_json::to_value(&record).unwrap()).unwrap();
	assert!(old_record.terminal_protocol.is_none());
	let old_spec: Spec = serde_json::from_value(json!({
		"request":{"op":"start","job_id":record.job_id,"executable":"/bin/true"},
		"nonce":record.nonce,"boot_id":record.boot_id,"workspace":"/workspace",
	}))
	.unwrap();
	assert!(old_spec.terminal_protocol.is_none());
	for interactive in [false, true] {
		let protocol = TerminalProtocol::for_interactive(interactive);
		assert_eq!(
			TerminalProtocol::for_spec(old_spec.terminal_protocol, interactive).unwrap(),
			protocol
		);
		assert_eq!(
			TerminalProtocol::for_spec(Some(protocol), interactive).unwrap(),
			protocol
		);
		assert!(TerminalProtocol::for_spec(Some(protocol), !interactive).is_err());
	}
}

#[test]
fn setup_failure_has_explicit_capture_evidence_and_never_looks_like_legacy() {
	let root = tempfile::tempdir().unwrap();
	fs::write(root.path().join("stdout.log"), b"retained original").unwrap();
	let mut command = quiet_command("raise RuntimeError('must not spawn')");
	let error = match spawn_supervised(&mut command, root.path(), false) {
		Ok(_) => panic!("existing log must refuse before workload spawn"),
		Err(error) => error,
	};
	let (mut record, _) = completed_fixture();
	record.terminal_protocol = Some(TerminalProtocol::CapturedV1);
	let receipt = Exit::new(
		&record.job_id,
		record.nonce.clone(),
		127,
		false,
		false,
		TerminalProtocol::CapturedV1,
		Some(OutputCapture::not_started(&format!("{error:#}"))),
	);
	publish_terminal(root.path(), &receipt).unwrap();
	let status = completion_at(&record, root.path()).unwrap().unwrap();
	assert_eq!(status["state"], "failed");
	assert_eq!(status["exit_code"], 127);
	assert_eq!(status["output_complete"], false);
	assert_eq!(status["output_durable"], false);
	assert!(status["capture"]["stdout"]["read_error"]
		.as_str()
		.unwrap()
		.contains("before workload spawn"));
	assert_eq!(
		fs::read(root.path().join("stdout.log")).unwrap(),
		b"retained original"
	);
}

#[test]
fn confirmed_capture_pages_preserve_all_bytes_and_standard_digest_wire_format() {
	// Independent SHA-256 vectors keep the durable identity format canonical.
	assert_eq!(
		bytes_digest(b""),
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	);
	assert_eq!(
		bytes_digest(b"abc"),
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	);
	let root = tempfile::tempdir().unwrap();
	let outcome = capture_fixture(
		r#"import os
view=memoryview(bytes(range(256))*65)
while view:
    view=view[os.write(1,view):]
os.write(2,bytes([0,128,255]))
"#,
		root.path(),
	);
	assert!(outcome.status.success());
	let (record, receipt) = persist_capture(root.path(), outcome);
	assert_eq!(receipt.output_complete, Some(true));
	assert_eq!(receipt.output_durable, Some(true));
	let expected: Vec<u8> = (0..65).flat_map(|_| 0..=u8::MAX).collect();
	let first = read_output_at(&record, root.path(), 0, 0, u64::MAX).unwrap();
	assert_eq!(first["stdout"]["next_offset"], 16384);
	assert_eq!(first["stdout"]["eof"], false);
	assert_eq!(first["stderr"]["bytes_hex"], "0080ff");
	assert_eq!(first["terminal_publication_confirmed"], true);
	let last = read_output_at(&record, root.path(), 16384, 3, u64::MAX).unwrap();
	assert_eq!(last["stdout"]["next_offset"], expected.len());
	assert_eq!(last["stdout"]["eof"], true);
	assert_eq!(last["stderr"]["bytes_hex"], "");
	let mut decoded = Vec::new();
	for (page, expected_page) in [(&first, &expected[..16384]), (&last, &expected[16384..])] {
		let hex = page["stdout"]["bytes_hex"].as_str().unwrap();
		assert_eq!(hex.len(), expected_page.len() * 2);
		assert!(hex
			.bytes()
			.all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
		decoded.extend(
			hex.as_bytes()
				.chunks_exact(2)
				.map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()),
		);
		assert_eq!(
			page["stdout"]["text"],
			String::from_utf8_lossy(expected_page).as_ref()
		);
	}
	assert_eq!(decoded, expected);
}

fn pending_launch_namespace_fixture(parent: &Path) -> (PathBuf, Vec<u8>, Vec<u8>) {
	let registry = parent.join("job-registry");
	let directory = registry.join("fixture");
	fs::create_dir_all(&directory).unwrap();
	let (mut record, _) = completed_fixture();
	record.launch_state = "pending".into();
	record.invocation_id = None;
	record.terminal_protocol = Some(TerminalProtocol::CapturedV1);
	let request = serde_json::from_value(json!({
		"op":"start","job_id":record.job_id,"executable":"/usr/bin/true"
	}))
	.unwrap();
	let spec = Spec {
		request,
		nonce: record.nonce.clone(),
		boot_id: record.boot_id.clone(),
		workspace: parent.to_string_lossy().into_owned(),
		terminal_protocol: record.terminal_protocol,
	};
	atomic(&directory.join("spec.json"), &spec).unwrap();
	atomic(&directory.join("record.json"), &record).unwrap();
	let spec = fs::read(directory.join("spec.json")).unwrap();
	let record = fs::read(directory.join("record.json")).unwrap();
	(registry, spec, record)
}

#[test]
fn fresh_launch_namespace_sync_precedes_both_submission_modes() {
	for spawn in [false, true] {
		let root = tempfile::tempdir().unwrap();
		let (registry, spec, record) = pending_launch_namespace_fixture(root.path());
		let directory = registry.join("fixture");
		let marker = root.path().join("submitted");
		let mut command =
			quiet_command("import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('once')");
		command.arg(&marker);
		let status = dispatch_after_launch_namespace_sync(&registry, || {
			assert_eq!(fs::read(directory.join("spec.json"))?, spec);
			assert_eq!(fs::read(directory.join("record.json"))?, record);
			if spawn {
				Ok(command.spawn()?.wait()?)
			} else {
				Ok(command.output()?.status)
			}
		})
		.unwrap();
		assert!(status.success());
		assert_eq!(fs::read_to_string(marker).unwrap(), "once");
		let retained: Record = json_file(&directory.join("record.json")).unwrap();
		assert_eq!(retained.launch_state, "pending");
		assert_eq!(retained.invocation_id, None);
	}
}

#[cfg(target_os = "linux")]
#[test]
fn actual_launch_namespace_sync_failures_preserve_pending_inputs_without_spawn() {
	use std::os::unix::process::CommandExt;
	for fail_parent in [false, true] {
		for spawn in [false, true] {
			let root = tempfile::tempdir().unwrap();
			let (registry_path, spec, record) = pending_launch_namespace_fixture(root.path());
			let directory = registry_path.join("fixture");
			let registry = File::open(&registry_path).unwrap();
			let parent = File::open(root.path()).unwrap();
			// Linux returns a real fsync(EINVAL) for this descriptor. The same
			// production gate must reject either barrier before either submit API.
			let rejected = File::open("/dev/null").unwrap();
			let (registry, parent) = if fail_parent {
				(&registry, &rejected)
			} else {
				(&rejected, &parent)
			};
			let marker = root.path().join("business-ran");
			let mut command =
				quiet_command("import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('effect')");
			command.arg(&marker);
			let attempted = tempfile::tempfile().unwrap();
			let fd = attempted.as_raw_fd();
			unsafe {
				command.pre_exec(move || {
					if libc::write(fd, b"x".as_ptr().cast(), 1) != 1 {
						libc::_exit(125);
					}
					Ok(())
				});
			}
			let error = dispatch_after_launch_namespace_sync_with_parents(registry, parent, || {
				if spawn {
					Ok(command.spawn()?.wait()?)
				} else {
					Ok(command.output()?.status)
				}
			})
			.unwrap_err();
			assert_eq!(
				error
					.downcast_ref::<std::io::Error>()
					.and_then(|error| error.raw_os_error()),
				Some(libc::EINVAL)
			);
			assert_eq!(
				error.to_string(),
				if fail_parent {
					"sync job registry parent before dispatch"
				} else {
					"sync job registry before dispatch"
				}
			);
			assert_eq!(attempted.metadata().unwrap().len(), 0);
			assert!(!marker.exists());
			assert_eq!(fs::read(directory.join("spec.json")).unwrap(), spec);
			assert_eq!(fs::read(directory.join("record.json")).unwrap(), record);
			let retained: Record = json_file(&directory.join("record.json")).unwrap();
			assert_eq!(retained.launch_state, "pending");
			assert_eq!(retained.invocation_id, None);
		}
	}
}
