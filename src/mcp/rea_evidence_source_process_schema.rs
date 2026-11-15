// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Process-capture shape checks in the frozen Zod declaration order.

use super::*;

pub(super) fn capture(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	let Some(map) = v.object(value, path) else {
		return;
	};
	manifest(map.get("manifest"), &child(path, "manifest"), v);
	normalization(map.get("normalization"), &child(path, "normalization"), v);
	for (key, item) in [
		(
			"frames",
			frame as fn(Option<&Value>, &[Value], &mut Validation<'_>),
		),
		("rendered_frames", rendered),
		("interaction_events", interaction),
	] {
		array(map.get(key), &child(path, key), v, item);
	}
	exit(map.get("exit"), &child(path, "exit"), v);
	settlement(map.get("settlement"), &child(path, "settlement"), v);
	for (key, item) in [
		(
			"process_samples",
			sample as fn(Option<&Value>, &[Value], &mut Validation<'_>),
		),
		("filesystem_checkpoints", checkpoint),
		("event_journal", journal),
		("files_before", file_state),
		("files_after", file_state),
		("filesystem_effects", effect),
	] {
		array(map.get(key), &child(path, key), v, item);
	}
	boolean(map.get("truncated"), &child(path, "truncated"), v);
	coverage::details(
		map.get("truncation_details"),
		&child(path, "truncation_details"),
		v,
	);
	v.strings(
		map.get("limitations"),
		&child(path, "limitations"),
		false,
		false,
	);
	array(
		map.get("residual_unknowns"),
		&child(path, "residual_unknowns"),
		v,
		residual,
	);
	cleanup(map.get("cleanup"), &child(path, "cleanup"), v);
	v.process_unknown(
		map,
		&[
			"manifest",
			"normalization",
			"frames",
			"rendered_frames",
			"interaction_events",
			"exit",
			"settlement",
			"process_samples",
			"filesystem_checkpoints",
			"event_journal",
			"files_before",
			"files_after",
			"filesystem_effects",
			"truncated",
			"truncation_details",
			"limitations",
			"residual_unknowns",
			"cleanup",
		],
		path,
	);
}

fn record(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	let Some(map) = value.and_then(Value::as_object) else {
		v.invalid_type(value, path, "record");
		return;
	};
	for (key, value) in map {
		if key != "__proto__" {
			v.json_value(Some(value), &child(path, key.as_str()), false);
		}
	}
}

fn manifest(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	let Some(map) = v.object(value, path) else {
		return;
	};
	strings(
		map,
		&[
			"rea_version",
			"provider_version",
			"platform",
			"architecture",
		],
		path,
		true,
		v,
	);
	v.choice(
		map.get("pty_backend"),
		&child(path, "pty_backend"),
		&["node-pty"],
	);
	for key in ["started_at", "completed_at"] {
		let p = child(path, key);
		if v.string(map.get(key), &p, false)
			.is_some_and(|text| !iso_datetime(text))
		{
			v.add(&p, "Invalid ISO datetime".into(),
				vec![json!({"path":p,"reason":"invalid_format","expected":"datetime","message":"Invalid ISO datetime"})], false);
		}
	}
	for key in ["scenario", "comparison_contract"] {
		record(map.get(key), &child(path, key), v);
	}
	for key in ["full_scenario_sha256", "comparison_contract_sha256"] {
		v.digest(map.get(key), &child(path, key), "");
	}
	for key in ["selected_executable_sha256", "executable_sha256"] {
		if map.get(key) != Some(&Value::Null) {
			v.digest(map.get(key), &child(path, key), "");
		}
	}
	let p = child(path, "executable_identity");
	if let Some(identity) = v.object(map.get("executable_identity"), &p) {
		v.choice(
			identity.get("state"),
			&child(&p, "state"),
			&["path_metadata_unchanged", "unknown"],
		);
		if identity.get("reason") != Some(&Value::Null) {
			v.string(identity.get("reason"), &child(&p, "reason"), false);
		}
		v.process_unknown(identity, &["state", "reason"], &p);
	}
	v.digest(
		map.get("normalization_sha256"),
		&child(path, "normalization_sha256"),
		"",
	);
	v.process_unknown(
		map,
		&[
			"rea_version",
			"provider_version",
			"platform",
			"architecture",
			"pty_backend",
			"started_at",
			"completed_at",
			"scenario",
			"comparison_contract",
			"full_scenario_sha256",
			"comparison_contract_sha256",
			"selected_executable_sha256",
			"executable_sha256",
			"executable_identity",
			"normalization_sha256",
		],
		path,
	);
}

fn iso_datetime(value: &str) -> bool {
	let Some((date, time)) = value.split_once('T') else {
		return false;
	};
	let Some(time) = time.strip_suffix('Z') else {
		return false;
	};
	if date.len() != 10 || !date.is_ascii() {
		return false;
	}
	let parts: Vec<_> = date.split('-').collect();
	if parts.len() != 3
		|| parts[0].len() != 4
		|| parts[1].len() != 2
		|| parts[2].len() != 2
		|| parts
			.iter()
			.any(|part| !part.bytes().all(|b| b.is_ascii_digit()))
	{
		return false;
	}
	let (Ok(year), Ok(month), Ok(day)) = (
		parts[0].parse::<u32>(),
		parts[1].parse::<u32>(),
		parts[2].parse::<u32>(),
	) else {
		return false;
	};
	let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
	let days = match month {
		1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
		4 | 6 | 9 | 11 => 30,
		2 if leap => 29,
		2 => 28,
		_ => return false,
	};
	if day == 0 || day > days {
		return false;
	}
	let parts: Vec<_> = time.split(':').collect();
	if !(2..=3).contains(&parts.len()) {
		return false;
	}
	let valid = |part: &str, max| {
		part.len() == 2
			&& part.bytes().all(|b| b.is_ascii_digit())
			&& part.parse::<u32>().is_ok_and(|n| n <= max)
	};
	if !valid(parts[0], 23) || !valid(parts[1], 59) {
		return false;
	}
	if parts.len() == 2 {
		return true;
	}
	if let Some((second, fraction)) = parts[2].split_once('.') {
		valid(second, 59) && !fraction.is_empty() && fraction.bytes().all(|b| b.is_ascii_digit())
	} else {
		valid(parts[2], 59)
	}
}

fn normalization(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	let Some(map) = v.object(value, path) else {
		return;
	};
	for key in ["paths", "pids", "ports"] {
		boolean(map.get(key), &child(path, key), v);
	}
	safe_positive(map.get("time_bucket_ms"), &child(path, "time_bucket_ms"), v);
	array(map.get("patterns"), &child(path, "patterns"), v, pattern);
}

fn pattern(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	if let Some(map) = v.object(value, path) {
		strings(map, &["pattern", "replacement"], path, false, v);
	}
}

fn frame(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	let Some(map) = v.object(value, path) else {
		return;
	};
	integers(map, &["sequence", "at_ms"], path, false, v);
	v.string(map.get("data"), &child(path, "data"), false);
	if let Some(value) = map.get("raw_data") {
		v.string(Some(value), &child(path, "raw_data"), false);
	}
}

fn rendered(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	let Some(map) = v.object(value, path) else {
		return;
	};
	integers(map, &["sequence", "at_ms"], path, false, v);
	integers(map, &["columns", "rows"], path, true, v);
	integers(map, &["cursor_x", "cursor_y"], path, false, v);
	v.choice(
		map.get("active_buffer"),
		&child(path, "active_buffer"),
		&["normal", "alternate"],
	);
	v.strings(map.get("lines"), &child(path, "lines"), false, false);
	v.string(
		map.get("serialized_state"),
		&child(path, "serialized_state"),
		false,
	);
}

fn interaction(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	let Some(map) = v.object(value, path) else {
		return;
	};
	integers(
		map,
		&["sequence", "scheduled_at_ms", "dispatched_at_ms"],
		path,
		false,
		v,
	);
	v.choice(
		map.get("type"),
		&child(path, "type"),
		&["input", "resize", "signal"],
	);
	v.string(map.get("data"), &child(path, "data"), false);
	v.choice(
		map.get("outcome"),
		&child(path, "outcome"),
		&["dispatched", "target_exited", "failed"],
	);
}

fn exit(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	let Some(map) = v.object(value, path) else {
		return;
	};
	for key in ["code", "signal"] {
		if map.get(key) != Some(&Value::Null) {
			integer(map.get(key), &child(path, key), None, v);
		}
	}
	v.choice(
		map.get("reason"),
		&child(path, "reason"),
		&["exited", "timeout", "idle_timeout"],
	);
	if let Some(value) = map.get("finalization") {
		finalization(Some(value), &child(path, "finalization"), v);
	}
}

fn finalization(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	let start = v.issues.len();
	let Some(map) = v.object(value, path) else {
		return;
	};
	safe_positive(map.get("requested_ms"), &child(path, "requested_ms"), v);
	for key in ["elapsed_ms", "exit_code"] {
		if map.get(key) != Some(&Value::Null) {
			integer(map.get(key), &child(path, key), Some(false), v);
		}
	}
	let p = child(path, "signals");
	array(map.get("signals"), &p, v, finalization_signal);
	if map
		.get("signals")
		.and_then(Value::as_array)
		.is_some_and(Vec::is_empty)
	{
		v.minimum(&p, 1, "array");
	}
	v.process_unknown(
		map,
		&["requested_ms", "elapsed_ms", "exit_code", "signals"],
		path,
	);
	if v.aborted_from(start) {
		return;
	}
	if map.get("exit_code") != Some(&Value::Null) && map.get("elapsed_ms") == Some(&Value::Null) {
		v.custom(
			&child(path, "exit_code"),
			"finalization exit_code requires an observed exit",
			false,
		);
	}
	for (index, attempt) in rows(&map["signals"]).iter().enumerate() {
		if attempt.get("reason").is_some() && attempt["delivery"] != "unverified" {
			v.custom(
				&child(&child(&p, index), "reason"),
				"finalization reason is only allowed for an unverified delivery",
				false,
			);
		}
	}
}

fn finalization_signal(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	let Some(map) = v.object(value, path) else {
		return;
	};
	v.choice(
		map.get("signal"),
		&child(path, "signal"),
		&["SIGTERM", "SIGKILL"],
	);
	integer(
		map.get("sent_at_ms"),
		&child(path, "sent_at_ms"),
		Some(false),
		v,
	);
	v.choice(
		map.get("delivery"),
		&child(path, "delivery"),
		&["signaled", "gone", "identity-changed", "unverified"],
	);
	if let Some(value) = map.get("reason") {
		v.string(Some(value), &child(path, "reason"), true);
	}
	v.process_unknown(map, &["signal", "sent_at_ms", "delivery", "reason"], path);
}

fn settlement(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	let Some(map) = v.object(value, path) else {
		return;
	};
	if !v.discriminator(
		map.get("state"),
		&child(path, "state"),
		&["quiesced", "alive_at_deadline", "unverifiable"],
	) {
		return;
	}
	integer(
		map.get("elapsed_ms"),
		&child(path, "elapsed_ms"),
		Some(false),
		v,
	);
	let allowed: &[&str] = if map["state"] == "quiesced" {
		&["not_required"]
	} else {
		&["cleaned", "failed"]
	};
	v.choice(
		map.get("cleanup_outcome"),
		&child(path, "cleanup_outcome"),
		allowed,
	);
}

fn sample(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	let Some(map) = v.object(value, path) else {
		return;
	};
	integer(map.get("at_ms"), &child(path, "at_ms"), Some(false), v);
	integer(map.get("pid"), &child(path, "pid"), Some(true), v);
	integer(
		map.get("parent_pid"),
		&child(path, "parent_pid"),
		Some(false),
		v,
	);
	v.string(map.get("command"), &child(path, "command"), false);
	for (key, positive) in [("process_group_id", true), ("session_id", false)] {
		if map.get(key) != Some(&Value::Null) {
			integer(map.get(key), &child(path, key), Some(positive), v);
		}
	}
}

fn checkpoint(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	let Some(map) = v.object(value, path) else {
		return;
	};
	v.choice(
		map.get("name"),
		&child(path, "name"),
		&["before", "after_settlement"],
	);
	integer(map.get("at_ms"), &child(path, "at_ms"), Some(false), v);
	array(map.get("files"), &child(path, "files"), v, file_state);
	array(map.get("effects"), &child(path, "effects"), v, effect);
	boolean(map.get("truncated"), &child(path, "truncated"), v);
}

fn journal(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	let Some(map) = v.object(value, path) else {
		return;
	};
	integer(
		map.get("capture_order"),
		&child(path, "capture_order"),
		Some(false),
		v,
	);
	v.choice(
		map.get("collection"),
		&child(path, "collection"),
		COLLECTIONS,
	);
	integer(map.get("index"), &child(path, "index"), Some(false), v);
}

fn file_state(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	let Some(map) = v.object(value, path) else {
		return;
	};
	if !v.discriminator(
		map.get("type"),
		&child(path, "type"),
		&["file", "symlink", "directory", "other"],
	) {
		return;
	}
	v.string(map.get("path"), &child(path, "path"), false);
	integers(map, &["mode", "size"], path, false, v);
	if map["type"] == "file" {
		if map.get("sha256") != Some(&Value::Null) {
			v.digest(map.get("sha256"), &child(path, "sha256"), "");
		}
	} else {
		null(map.get("sha256"), &child(path, "sha256"), v);
	}
	if map["type"] == "symlink" {
		v.string(
			map.get("symlink_target"),
			&child(path, "symlink_target"),
			false,
		);
	} else {
		null(map.get("symlink_target"), &child(path, "symlink_target"), v);
	}
}

fn effect(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	let Some(map) = v.object(value, path) else {
		return;
	};
	if !v.discriminator(
		map.get("status"),
		&child(path, "status"),
		&["created", "deleted", "modified", "unchanged", "unknown"],
	) {
		return;
	}
	v.string(map.get("path"), &child(path, "path"), false);
	for (key, absent) in [("before", "created"), ("after", "deleted")] {
		if map["status"] == absent {
			null(map.get(key), &child(path, key), v);
		} else if map["status"] != "unknown" || map.get(key) != Some(&Value::Null) {
			file_state(map.get(key), &child(path, key), v);
		}
	}
	if map["status"] == "unknown" {
		v.string(map.get("reason"), &child(path, "reason"), true);
	}
}

fn residual(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	let Some(map) = v.object(value, path) else {
		return;
	};
	v.choice(
		map.get("scope"),
		&child(path, "scope"),
		&[
			"terminal",
			"interaction",
			"exit",
			"process",
			"filesystem",
			"cleanup",
			"network",
			"environment",
		],
	);
	v.string(map.get("reason"), &child(path, "reason"), false);
}

fn cleanup(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	let Some(map) = v.object(value, path) else {
		return;
	};
	v.choice(
		map.get("owned_process_group"),
		&child(path, "owned_process_group"),
		&["verified"],
	);
	v.choice(
		map.get("temporary_root"),
		&child(path, "temporary_root"),
		&["removed"],
	);
	if let Some(value) = map.get("unverified_processes") {
		array(
			Some(value),
			&child(path, "unverified_processes"),
			v,
			unverified,
		);
	}
}

fn unverified(value: Option<&Value>, path: &[Value], v: &mut Validation<'_>) {
	let Some(map) = v.object(value, path) else {
		return;
	};
	integer(map.get("pid"), &child(path, "pid"), Some(true), v);
	v.string(map.get("reason"), &child(path, "reason"), false);
	v.process_unknown(map, &["pid", "reason"], path);
}
