// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Regression tests for ssh.
use super::*;
use std::collections::BTreeMap;

#[test]
fn fixed_observation_command_caches_match_uncached_bytes_and_share_storage() {
	let file = file_observation_command().unwrap();
	let status = job_observation_command(ObservationScript::Status).unwrap();
	let read = job_observation_command(ObservationScript::Read).unwrap();
	assert_eq!(
		file,
		python_json_command("python3", super::super::binary::observation_source()).unwrap()
	);
	assert_eq!(
		status,
		python_json_command(
			"python3",
			&super::super::jobs::observation_script(ObservationScript::Status).unwrap()
		)
		.unwrap()
	);
	assert_eq!(
		read,
		python_json_command(
			"python3",
			&super::super::jobs::observation_script(ObservationScript::Read).unwrap()
		)
		.unwrap()
	);
	assert_ne!(status, read);
	let expected = (
		file.as_ptr() as usize,
		status.as_ptr() as usize,
		read.as_ptr() as usize,
	);
	let workers: Vec<_> = (0..8)
		.map(|_| {
			std::thread::spawn(|| {
				(
					file_observation_command().unwrap().as_ptr() as usize,
					job_observation_command(ObservationScript::Status)
						.unwrap()
						.as_ptr() as usize,
					job_observation_command(ObservationScript::Read)
						.unwrap()
						.as_ptr() as usize,
				)
			})
		})
		.collect();
	for worker in workers {
		assert_eq!(worker.join().unwrap(), expected);
	}
}

fn observation_command_copies(marker: &str) -> Vec<(String, Vec<u8>)> {
	let (file, file_input) = prepare_file_observation(FileObservation::Info {
		root: "/synthetic",
		path: marker,
	})
	.unwrap();
	let (status, status_input, _, _) = prepare_observation(JobObservation::PythonStatus {
		job_id: marker,
		job_dir: "/synthetic/jobs/original",
		unit: "original-unit",
		request_digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		wait_seconds: 0,
	})
	.unwrap();
	let (read, read_input, _, _) = prepare_observation(JobObservation::PythonRead {
		job_id: marker,
		job_dir: "/synthetic/jobs/original",
		unit: "original-unit",
		request_digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		stdout_offset: 13,
		stderr_offset: 29,
		limit: 16384,
	})
	.unwrap();
	vec![
		(file, file_input),
		(status, status_input),
		(read, read_input),
	]
}

#[test]
fn cached_command_copies_keep_request_data_separate_and_cannot_poison_later_calls() {
	let first_marker = "FIRST_DATA_NEVER_CODE\n'\"";
	let second_marker = "SECOND_DATA_NEVER_CODE\n'\"";
	let mut first = observation_command_copies(first_marker);
	let expected_commands: Vec<_> = first.iter().map(|(command, _)| command.clone()).collect();
	for (command, input) in &mut first {
		assert!(!command.contains("FIRST_DATA_NEVER_CODE"));
		let value: serde_json::Value = serde_json::from_slice(input).unwrap();
		assert_eq!(
			value.get("path").or_else(|| value.get("job_id")).unwrap(),
			first_marker
		);
		command.clear();
		command.push_str("caller-owned copy changed");
		input.fill(0);
	}
	for ((command, input), expected) in observation_command_copies(second_marker)
		.into_iter()
		.zip(expected_commands)
	{
		assert_eq!(command, expected);
		assert!(!command.contains("SECOND_DATA_NEVER_CODE"));
		let value: serde_json::Value = serde_json::from_slice(&input).unwrap();
		assert_eq!(
			value.get("path").or_else(|| value.get("job_id")).unwrap(),
			second_marker
		);
		assert!(!String::from_utf8(input)
			.unwrap()
			.contains("FIRST_DATA_NEVER_CODE"));
	}
}

#[test]
fn quotes_shell_data() {
	assert_eq!(shell_quote("a b"), "'a b'");
	assert_eq!(shell_quote("a'b"), "'a'\"'\"'b'");
}

#[test]
fn builds_argv_without_model_side_quoting() {
	let cmd = build_exec_command(
		"/bin/printf",
		&["%s".into(), "a b'c".into()],
		Some("/tmp/a b"),
		&BTreeMap::new(),
		24,
		80,
	)
	.unwrap();
	assert!(cmd.contains("'/tmp/a b'"));
	assert!(cmd.contains("'a b'\"'\"'c'"));
}

#[test]
fn python_interpreter_is_fixed_or_absolute_safe_and_shell_quoted() {
	assert_eq!(
		python_json_command("python3", "print('ok')").unwrap(),
		"'python3' -c 'print('\"'\"'ok'\"'\"')'"
	);
	let interpreter = "/opt/venv's python/bin/python3";
	assert_eq!(
		python_json_command(interpreter, "print(1)").unwrap(),
		format!("{} -c 'print(1)'", shell_quote(interpreter))
	);
	for invalid in [
		"",
		"python",
		"venv/bin/python3",
		"/opt/../bin/python3",
		"/opt/python\n3",
		"/opt/python\t3",
		"/opt/python\0",
	] {
		assert!(
			python_json_command(invalid, "print(1)").is_err(),
			"{invalid:?}"
		);
	}
	assert!(python_json_command(&format!("/{}", "x".repeat(4096)), "").is_err());
}
