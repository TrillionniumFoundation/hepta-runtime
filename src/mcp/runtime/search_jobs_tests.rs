// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Adversarial validation and durable receipt tests for the search lifecycle.
use super::*;

fn params() -> SearchStartParams {
	serde_json::from_value(
		json!({"host":"main","root":"/tmp/workspace","query":"needle","kind":"content"}),
	)
	.unwrap()
}

fn record() -> SearchRecord {
	SearchRecord {
		id: "1".repeat(64),
		owner: "2".repeat(64),
		instance: "3".repeat(64),
		host: "main".into(),
		ssh_target: "localhost".into(),
		remote_state_dir: "/tmp/state".into(),
		created_unix_ms: 1,
		state: "running".into(),
		reason: None,
		request: params(),
	}
}

#[test]
fn identities_are_opaque_unique_and_caller_cannot_supply_owner() {
	let one = new_owner_id().unwrap();
	let two = new_owner_id().unwrap();
	assert!(valid_id(&one));
	assert_ne!(one, two);
	assert!(!valid_id("../owner"));
	assert!(!valid_id(&"A".repeat(64)));
	assert!(
		serde_json::from_value::<SearchRefParams>(json!({"search_id":one,"owner":two})).is_err()
	);
	assert!(serde_json::from_value::<SearchStartParams>(
		json!({"host":"main","root":"/tmp","query":"x","kind":"content","owner":"spoof"})
	)
	.is_err());
}

#[test]
fn validation_bounds_every_caller_resource() {
	let base = params();
	assert!(validate_start(&base).is_ok());
	let mut p = base.clone();
	p.query = "x".repeat(513);
	assert!(validate_start(&p).is_err());
	p = base.clone();
	p.query = "bad\nquery".into();
	assert!(validate_start(&p).is_err());
	p = base.clone();
	p.root = "/tmp/../outside".into();
	assert!(validate_start(&p).is_err());
	p = base.clone();
	p.root = "relative".into();
	assert!(validate_start(&p).is_err());
	p = base.clone();
	p.max_results = Some(1001);
	assert!(validate_start(&p).is_err());
	p = base.clone();
	p.max_entries = Some(10001);
	assert!(validate_start(&p).is_err());
	p = base.clone();
	p.max_bytes = Some(64 * 1024 * 1024 + 1);
	assert!(validate_start(&p).is_err());
	p = base.clone();
	p.timeout_seconds = Some(31);
	assert!(validate_start(&p).is_err());
	p = base;
	p.max_results = Some(0);
	assert!(validate_start(&p).is_err());
	assert!(page_limit(Some(0)).is_err());
	assert!(page_limit(Some(33)).is_err());
}

#[test]
fn explicit_search_modes_and_filters_preserve_omitted_literal_defaults() {
	let defaults = params();
	assert!(defaults.query_mode.is_none());
	assert!(defaults.literal_search.is_none());
	assert!(!defaults.ignore_case);
	assert!(!defaults.early_termination);
	assert!(defaults.context_lines.is_none());
	let mut p = defaults.clone();
	p.query_mode = Some(SearchQueryMode::Regex);
	p.literal_search = Some(false);
	p.ignore_case = true;
	p.context_lines = Some(10);
	p.file_pattern = Some("*.rs|*.py".into());
	p.exclude_patterns = vec!["vendor".into(), "target/*".into()];
	assert!(validate_start(&p).is_ok());
	p.literal_search = Some(true);
	assert!(validate_start(&p).is_err());
	p.literal_search = None;
	p.query_mode = Some(SearchQueryMode::Glob);
	assert!(validate_start(&p).is_err());
	p.kind = SearchKind::Files;
	assert!(validate_start(&p).is_ok());
	p.context_lines = Some(11);
	assert!(validate_start(&p).is_err());
	p.context_lines = None;
	p.file_pattern = Some("[z-a]".into());
	assert!(validate_start(&p).is_err());
	p.file_pattern = None;
	p.exclude_patterns = vec!["x".into(); 33];
	assert!(validate_start(&p).is_err());
	p.exclude_patterns = vec!["bad\npattern".into()];
	assert!(validate_start(&p).is_err());
	assert!(serde_json::from_value::<SearchStartParams>(json!({
		"host":"main","root":"/tmp","query":"x","kind":"content","ignore_case":1
	}))
	.is_err());
}

#[test]
fn compiled_globs_match_ripgrep_order_braces_anchors_escapes_and_byte_case_folding() {
	use std::io::Write;
	use std::process::{Command, Stdio};
	let temporary = tempfile::tempdir().unwrap();
	let paths = [
		"a.txt",
		"secret.txt",
		"KEEP.TXT",
		"dir/a.txt",
		"dir/deep/b.txt",
		"dir/secret.txt",
		"src/a.js",
		"src/b.ts",
		"src/deep/c.js",
		"names/star*.txt",
		"names/q?.txt",
		"!bang.txt",
		"unicode/Å.txt",
		"unicode/å.txt",
		"unicode/中.txt",
		"a1.txt",
		"a2.txt",
		"new\nline.txt",
	];
	for path in paths {
		let full = temporary.path().join(path);
		std::fs::create_dir_all(full.parent().unwrap()).unwrap();
		std::fs::write(full, "needle").unwrap();
	}
	let patterns = [
		"*.txt|!secret.txt",
		"*.txt|!secret.txt|secret.txt",
		"src/*.{js,ts}",
		"src/**/{a,b,c}.js",
		"*.txt|!dir/|dir/a.txt",
		"/a.txt",
		"a[12].txt",
		r"names/star\*.txt",
		r"names/q\?.txt",
		r"\!bang.txt",
		"#comment|*.js",
		"*.{txt,js}|!src/**|src/a.js",
		"dir/",
		"unicode/Å.txt",
		"*.txt| | !secret.txt",
	];
	let mut requests = Vec::new();
	let mut expected = Vec::new();
	let mut labels = Vec::new();
	for insensitive in [false, true] {
		for pattern in patterns {
			let mut p = params();
			p.kind = SearchKind::Files;
			p.query = "*".into();
			p.query_mode = Some(SearchQueryMode::Glob);
			p.file_pattern = Some(pattern.into());
			p.ignore_case = insensitive;
			let program = compile_glob_program(&p).unwrap();
			let mut value = serde_json::to_value(&p).unwrap();
			value["glob_program"] = serde_json::to_value(program).unwrap();
			value["context_lines"] = json!(0);
			requests.push(value);
			labels.push(format!(
				"file_pattern={pattern:?}, ignore_case={insensitive}"
			));
			let mut command = Command::new("rg");
			command.current_dir(temporary.path()).args([
				"--files",
				"--hidden",
				"--no-ignore",
				"--no-config",
				"--null",
			]);
			for glob in pattern
				.split('|')
				.map(str::trim)
				.filter(|part| !part.is_empty())
			{
				command
					.arg(if insensitive { "--iglob" } else { "--glob" })
					.arg(glob);
			}
			let output = command.arg(".").output().unwrap();
			assert!(
				output.status.code().is_some_and(|code| code <= 1),
				"{}",
				String::from_utf8_lossy(&output.stderr)
			);
			let mut names: Vec<_> = output
				.stdout
				.split(|byte| *byte == 0)
				.filter(|name| !name.is_empty())
				.map(|name| {
					String::from_utf8(name.to_vec())
						.unwrap()
						.trim_start_matches("./")
						.to_string()
				})
				.collect();
			names.sort();
			expected.push(names);
		}
	}
	for (query, excludes) in [
		("src/*.{js,ts}", vec![]),
		("src/**", vec![]),
		(r"names/q\?.txt", vec![]),
		("unicode/?.txt", vec![]),
		("unicode/??.txt", vec![]),
		("a[!2].txt", vec![]),
		("*", vec!["*.txt", "!a.txt"]),
		("*", vec!["dir/", "!dir/a.txt"]),
		("*", vec!["dir/*", "!dir/a.txt"]),
	] {
		let mut p = params();
		p.kind = SearchKind::Files;
		p.query = query.into();
		p.query_mode = Some(SearchQueryMode::Glob);
		p.exclude_patterns = excludes.iter().map(|value| value.to_string()).collect();
		let mut value = serde_json::to_value(&p).unwrap();
		value["glob_program"] = serde_json::to_value(compile_glob_program(&p).unwrap()).unwrap();
		value["context_lines"] = json!(0);
		requests.push(value);
		labels.push(format!("query={query:?}, excludes={excludes:?}"));
		let mut command = Command::new("rg");
		command.current_dir(temporary.path()).args([
			"--files",
			"--hidden",
			"--no-ignore",
			"--no-config",
			"--null",
			"--glob",
			query,
		]);
		for exclusion in excludes {
			command.arg("--glob").arg(
				exclusion
					.strip_prefix('!')
					.map_or_else(|| format!("!{exclusion}"), str::to_string),
			);
		}
		let output = command.arg(".").output().unwrap();
		assert!(
			output.status.code().is_some_and(|code| code <= 1),
			"{}",
			String::from_utf8_lossy(&output.stderr)
		);
		let mut names: Vec<_> = output
			.stdout
			.split(|byte| *byte == 0)
			.filter(|name| !name.is_empty())
			.map(|name| {
				String::from_utf8(name.to_vec())
					.unwrap()
					.trim_start_matches("./")
					.to_string()
			})
			.collect();
		names.sort();
		expected.push(names);
	}
	let source = format!("__name__='search_glob_test'\n{}\nq=json.load(sys.stdin)\nout=[]\nfor request in q['requests']:\n matches,included,excluded,_=options(request)\n selected=[]\n for path in q['paths']:\n  parents=path.split('/')[:-1]\n  denied=any(excluded('/'.join(parents[:i]),True) for i in range(1,len(parents)+1))\n  if not denied and included(path) and not excluded(path) and matches(path):selected.append(path)\n out.append(sorted(selected))\nprint(json.dumps(out))", include_str!("search_worker.py"));
	let mut child = Command::new("python3")
		.args(["-c", &source])
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.unwrap();
	child
		.stdin
		.take()
		.unwrap()
		.write_all(&serde_json::to_vec(&json!({"requests":requests,"paths":paths})).unwrap())
		.unwrap();
	let output = child.wait_with_output().unwrap();
	assert!(
		output.status.success(),
		"{}",
		String::from_utf8_lossy(&output.stderr)
	);
	let actual: Vec<Vec<String>> = serde_json::from_slice(&output.stdout).unwrap();
	assert_eq!(actual.len(), expected.len());
	for (index, (actual, expected)) in actual.iter().zip(&expected).enumerate() {
		assert_eq!(actual, expected, "case {index}, {}", labels[index]);
	}
}

#[test]
fn administrator_search_interpreter_mapping_rejects_malformed_unknown_and_unsafe_paths() {
	let config: RuntimeConfig = serde_json::from_value(json!({"hosts":{
		"main":{"ssh_target":"localhost","remote_state_dir":"/tmp/state"},
		"other":{"ssh_target":"remote","remote_state_dir":"/tmp/state"}
	}}))
	.unwrap();
	assert!(parse_search_interpreters(None, &config).unwrap().is_empty());
	let mapping =
		parse_search_interpreters(Some(r#"{"main":"/opt/document env/bin/python3"}"#), &config)
			.unwrap();
	assert_eq!(
		mapping.get("main").unwrap(),
		"/opt/document env/bin/python3"
	);
	assert!(!mapping.contains_key("other"));
	for invalid in [
		"invalid JSON",
		"[]",
		"null",
		r#"{"main":null}"#,
		r#"{"unknown":"/usr/bin/python3"}"#,
		r#"{"main":"python3"}"#,
		r#"{"main":"relative/python3"}"#,
		r#"{"main":"/opt/../python3"}"#,
		r#"{"main":"/opt/python\n3"}"#,
		r#"{"main":"/opt/python\t3"}"#,
	] {
		assert!(
			parse_search_interpreters(Some(invalid), &config).is_err(),
			"{invalid:?}"
		);
	}
	assert!(parse_search_interpreters(Some(&" ".repeat(64 * 1024 + 1)), &config).is_err());
	assert!(serde_json::from_value::<SearchStartParams>(json!({
		"host":"main","root":"/tmp","query":"x","kind":"content", "interpreter":"/bin/sh"
	}))
	.is_err());
}

#[test]
fn unfinished_restart_receipt_is_interrupted_without_pid_reattachment() {
	let mut r = record();
	let old = r.instance.clone();
	assert!(!reconcile(&mut r, &old));
	assert!(reconcile(&mut r, &"4".repeat(64)));
	assert_eq!(r.state, "interrupted");
	assert_eq!(
		r.reason.as_deref(),
		Some("controller_restarted_no_session_resume")
	);
	assert!(!reconcile(&mut r, &"5".repeat(64)));
	let mut terminal = record();
	terminal.state = "completed".into();
	assert!(!reconcile(&mut terminal, &"4".repeat(64)));
	assert_eq!(terminal.state, "completed");
}

#[test]
fn abandoned_native_completed_receipt_frees_active_quota_without_exposing_its_owner() {
	let mut r = record();
	assert!(!apply_native_terminal(&mut r, &json!({"state":"running"})));
	assert!(!apply_native_terminal(
		&mut r,
		&json!({"state":"untrusted"})
	));
	assert!(apply_native_terminal(
		&mut r,
		&json!({"state":"completed","reason":null})
	));
	assert!(TERMINAL.contains(&r.state.as_str()));
	assert_eq!(r.owner, "2".repeat(64));
	assert!(!apply_native_terminal(
		&mut r,
		&json!({"state":"interrupted"})
	));
	assert_eq!(r.state, "completed");
}

#[test]
fn outer_mcp_string_escaping_counts_against_fixed_wire_budget() {
	let payload = "\\\"".repeat(MAX_PAGE_BYTES / 5);
	let value = json!({"payload":payload});
	let raw = serde_json::to_string(&value).unwrap();
	assert!(raw.len() < MAX_PAGE_BYTES);
	assert!(wire_size(&raw).unwrap() > MAX_PAGE_BYTES);
	assert!(response(value).is_err());
}

#[tokio::test]
async fn private_receipt_denies_other_session_without_path_details() {
	let temporary = tempfile::tempdir().unwrap();
	let r = record();
	save(temporary.path(), &r).await.unwrap();
	let error = owned(temporary.path(), &"9".repeat(64), &r.id)
		.await
		.unwrap_err()
		.to_string();
	assert_eq!(error, "search unavailable to this session");
	assert!(!error.contains("workspace"));
	assert!(!error.contains("localhost"));
	let error = owned(temporary.path(), &r.owner, &"9".repeat(64))
		.await
		.unwrap_err()
		.to_string();
	assert_eq!(error, "search unavailable to this session");
}

#[tokio::test]
async fn receipts_refuse_symlink_special_files_and_unbounded_serialized_responses() {
	let temporary = tempfile::tempdir().unwrap();
	let r = record();
	save(temporary.path(), &r).await.unwrap();
	let path = temporary.path().join(format!("{}.json", r.id));
	let got = read_record(&path).await.unwrap();
	assert_eq!(got.id, r.id);
	#[cfg(unix)]
	{
		use std::os::unix::fs::symlink;
		let link = temporary.path().join("link.json");
		symlink(&path, &link).unwrap();
		assert!(read_record(&link).await.is_err());
	}
	assert!(response(json!({"payload":"x".repeat(MAX_PAGE_BYTES)})).is_err());
	let empty = serde_json::to_string(&json!({"payload":""})).unwrap();
	let exact_payload = MAX_PAGE_BYTES - wire_size(&empty).unwrap();
	let boundary = json!({"payload":"x".repeat(exact_payload)});
	assert_eq!(
		wire_size(&serde_json::to_string(&boundary).unwrap()).unwrap(),
		MAX_PAGE_BYTES
	);
	assert!(response(boundary).is_ok());
	assert!(response(json!({"payload":"x".repeat(exact_payload + 1)})).is_err());
}

#[tokio::test]
async fn aggregate_filter_state_cannot_publish_an_unreadable_receipt() {
	let temporary = tempfile::tempdir().unwrap();
	let mut r = record();
	r.request.exclude_patterns = vec!["\t".repeat(512); 32];
	assert!(validate_start(&r.request).is_ok());
	assert!(save(temporary.path(), &r).await.is_err());
	assert!(tokio::fs::read_dir(temporary.path())
		.await
		.unwrap()
		.next_entry()
		.await
		.unwrap()
		.is_none());
}

fn effect_ack(record: &SearchRecord, action: &str, state: &str) -> Value {
	let mut value = json!({"search_id":record.id,"action":action,"backend":"native_search_worker","state":state});
	if action == "start" {
		value["snapshot_ready"] = json!(false);
	} else {
		value["stop_requested"] = json!(!TERMINAL.contains(&state));
	}
	value
}

#[tokio::test]
async fn failed_search_intent_never_polls_start_or_stop_dispatch() {
	use std::sync::atomic::{AtomicUsize, Ordering};
	let root = tempfile::tempdir().unwrap();
	let blocked = root.path().join("not-a-directory");
	tokio::fs::write(&blocked, b"must remain untouched")
		.await
		.unwrap();
	let calls = AtomicUsize::new(0);
	let r = record();
	let start = dispatch_search_start(&blocked, r.clone(), async {
		calls.fetch_add(1, Ordering::SeqCst);
		Ok(effect_ack(&r, "start", "running"))
	})
	.await
	.unwrap_err()
	.to_string();
	assert!(start.contains("no start request dispatched"));
	let stop = dispatch_search_stop(&blocked, r.clone(), async {
		calls.fetch_add(1, Ordering::SeqCst);
		Ok(effect_ack(&r, "stop", "running"))
	})
	.await
	.unwrap_err()
	.to_string();
	assert!(stop.contains("no stop request dispatched"));
	assert_eq!(calls.load(Ordering::SeqCst), 0);
	assert_eq!(
		tokio::fs::read(&blocked).await.unwrap(),
		b"must remain untouched"
	);
}

#[tokio::test]
async fn acknowledged_start_save_failure_returns_existing_identity_and_real_observation() {
	let root = tempfile::tempdir().unwrap();
	let directory = root.path().join("state");
	tokio::fs::create_dir(&directory).await.unwrap();
	let retained = root.path().join("retained-intent");
	let marker = root.path().join("accepted-start");
	let mut r = record();
	r.state = "launching".into();
	let ack = effect_ack(&r, "start", "running");
	let result = dispatch_search_start(&directory, r.clone(), async {
		tokio::fs::write(&marker, b"one start accepted")
			.await
			.unwrap();
		tokio::fs::rename(&directory, &retained).await.unwrap();
		tokio::fs::write(&directory, b"publication blocked after effect")
			.await
			.unwrap();
		Ok(ack)
	})
	.await
	.unwrap();
	let value: Value = serde_json::from_str(&result).unwrap();
	assert_eq!(value["search"]["search_id"], r.id);
	assert_eq!(value["search"]["state"], "running");
	assert_eq!(value["observed_state"], "running");
	assert_eq!(value["effect_outcome"], "start_acknowledged");
	assert_eq!(value["automatic_retry"], false);
	assert_eq!(value["metadata_durability_confirmed"], false);
	assert_eq!(
		read_record(&retained.join(format!("{}.json", r.id)))
			.await
			.unwrap()
			.state,
		"launching"
	);
	assert_eq!(
		tokio::fs::read(marker).await.unwrap(),
		b"one start accepted"
	);
}

#[tokio::test]
async fn lost_start_ack_is_structured_unknown_without_relaunch() {
	use std::sync::atomic::{AtomicUsize, Ordering};
	let root = tempfile::tempdir().unwrap();
	let mut r = record();
	r.state = "launching".into();
	let calls = AtomicUsize::new(0);
	let result = dispatch_search_start(root.path(), r.clone(), async {
		calls.fetch_add(1, Ordering::SeqCst);
		Err(anyhow!("SECRET lost start ACK"))
	})
	.await
	.unwrap();
	let value: Value = serde_json::from_str(&result).unwrap();
	assert_eq!(calls.load(Ordering::SeqCst), 1);
	assert_eq!(value["search"]["search_id"], r.id);
	assert_eq!(value["effect_outcome"], "start_unknown");
	assert_eq!(value["outcome"], "unknown");
	assert_eq!(value["automatic_retry"], false);
	assert_eq!(value["metadata_durability_confirmed"], true);
	assert!(!result.contains("SECRET"));
	assert_eq!(
		read_record(&root.path().join(format!("{}.json", r.id)))
			.await
			.unwrap()
			.state,
		"launch_uncertain"
	);
}

#[tokio::test]
async fn delivered_cancel_with_lost_ack_retains_same_identity_and_unconfirmed_outcome() {
	let root = tempfile::tempdir().unwrap();
	let r = record();
	let marker = root.path().join("delivered-cancel");
	let result = dispatch_search_stop(root.path(), r.clone(), async {
		tokio::fs::write(&marker, b"one cancellation marker accepted")
			.await
			.unwrap();
		Err(anyhow!("SECRET acknowledgement lost after cancel"))
	})
	.await
	.unwrap();
	let value: Value = serde_json::from_str(&result).unwrap();
	assert_eq!(value["search"]["search_id"], r.id);
	assert_eq!(value["effect_outcome"], "cancel_unknown");
	assert_eq!(value["outcome"], "unknown");
	assert_eq!(value["observed_state"], "running");
	assert_eq!(value["termination_confirmed"], false);
	assert_eq!(value["automatic_retry"], false);
	assert!(value.get("stop_requested").is_none());
	assert!(!result.contains("SECRET"));
	assert_eq!(
		tokio::fs::read(marker).await.unwrap(),
		b"one cancellation marker accepted"
	);
}

#[tokio::test]
async fn terminal_stop_ack_survives_save_failure_without_becoming_termination_proof() {
	let root = tempfile::tempdir().unwrap();
	let directory = root.path().join("state");
	tokio::fs::create_dir(&directory).await.unwrap();
	let retained = root.path().join("retained-intent");
	let r = record();
	let ack = effect_ack(&r, "stop", "cancelled");
	let result = dispatch_search_stop(&directory, r.clone(), async {
		tokio::fs::rename(&directory, &retained).await.unwrap();
		tokio::fs::write(&directory, b"publication blocked after ACK")
			.await
			.unwrap();
		Ok(ack)
	})
	.await
	.unwrap();
	let value: Value = serde_json::from_str(&result).unwrap();
	assert_eq!(value["search"]["search_id"], r.id);
	assert_eq!(value["search"]["state"], "cancelled");
	assert_eq!(value["observed_state"], "cancelled");
	assert_eq!(value["stop_requested"], false);
	assert_eq!(value["metadata_durability_confirmed"], false);
	assert_eq!(value["termination_confirmed"], false);
	assert_eq!(value["automatic_retry"], false);
	assert_eq!(
		read_record(&retained.join(format!("{}.json", r.id)))
			.await
			.unwrap()
			.state,
		"running"
	);
}

#[tokio::test]
async fn post_rename_directory_sync_failure_preserves_observation_and_unconfirmed_durability() {
	let root = tempfile::tempdir().unwrap();
	let mut r = record();
	let ack = effect_ack(&r, "start", "running");
	let observed = retain_start_effect(&mut r, Ok(ack));
	let persistence = save_with_directory_sync(root.path(), &r, async {
		Err(anyhow!("SECRET directory fsync failed"))
	})
	.await;
	assert!(persistence.is_err());
	assert_eq!(
		read_record(&root.path().join(format!("{}.json", r.id)))
			.await
			.unwrap()
			.state,
		"running"
	);
	let result = retain_search_effect_result(&r, observed, persistence);
	let value: Value = serde_json::from_str(&result).unwrap();
	assert_eq!(value["search"]["search_id"], r.id);
	assert_eq!(value["observed_state"], "running");
	assert_eq!(value["metadata_durability_confirmed"], false);
	assert_eq!(value["automatic_retry"], false);
	assert!(!result.contains("SECRET"));
}

#[test]
fn effect_ack_identity_backend_action_and_flags_must_match() {
	let r = record();
	let mut invalid_starts = vec![
		Value::Null,
		json!([]),
		json!({"state":"running","snapshot_ready":false}),
	];
	let mut invalid_stops = vec![
		Value::Null,
		json!({"state":"cancelled","stop_requested":false}),
	];
	for key in ["search_id", "action", "backend"] {
		let mut a = effect_ack(&r, "start", "running");
		a[key] = json!("mismatched");
		invalid_starts.push(a);
		let mut a = effect_ack(&r, "stop", "running");
		a[key] = json!("mismatched");
		invalid_stops.push(a);
	}
	let mut a = effect_ack(&r, "start", "running");
	a["error"] = json!("SECRET contradictory acknowledgement");
	invalid_starts.push(a);
	let mut a = effect_ack(&r, "stop", "running");
	a["error"] = json!("SECRET contradictory acknowledgement");
	invalid_stops.push(a);
	let mut a = effect_ack(&r, "start", "running");
	a["snapshot_ready"] = json!(true);
	invalid_starts.push(a);
	let mut a = effect_ack(&r, "stop", "running");
	a["stop_requested"] = json!(false);
	invalid_stops.push(a);
	let mut a = effect_ack(&r, "stop", "cancelled");
	a["stop_requested"] = json!(true);
	invalid_stops.push(a);
	for native in invalid_starts {
		let mut r = r.clone();
		let value = retain_start_effect(&mut r, Ok(native));
		assert_eq!(value["effect_outcome"], "start_unknown");
		assert_eq!(r.state, "launch_uncertain");
	}
	for native in invalid_stops {
		let mut r = r.clone();
		let value = retain_stop_effect(&mut r, Ok(native));
		assert_eq!(value["effect_outcome"], "cancel_unknown");
		assert_eq!(value["termination_confirmed"], false);
		assert_eq!(r.state, "running");
	}
}

#[test]
fn oversized_effect_response_retains_identity_under_actual_mcp_envelope_cap() {
	let r = record();
	let observed = json!({"effect_outcome":"cancel_requested","observed_state":"running","stop_requested":true,"termination_confirmed":false,"excess":"\\\"".repeat(64*1024)});
	let result =
		retain_search_effect_result(&r, observed, Err(anyhow!("SECRET persistence failure")));
	let value: Value = serde_json::from_str(&result).unwrap();
	assert_eq!(value["search"]["search_id"], r.id);
	assert_eq!(value["effect_outcome"], "cancel_requested");
	assert_eq!(value["stop_requested"], true);
	assert_eq!(value["metadata_durability_confirmed"], false);
	assert_eq!(value["automatic_retry"], false);
	assert!(wire_size(&result).unwrap() < 64 * 1024);
	assert!(!result.contains("SECRET"));
}
