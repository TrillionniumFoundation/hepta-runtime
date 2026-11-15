// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Complete root-string schema witnesses remain negative, owned file evidence.
//! Original observations are real Node/REA MCP frames; native resource and
//! cleanup fault tests below are independent lifecycle checks, not mock oracles.

use super::*;

const FIXTURE: &[u8] =
	include_bytes!("../../tests/fixtures/rea_evidence_root_string/original-controls.json");

fn fixture() -> Value {
	serde_json::from_slice(FIXTURE).unwrap()
}

fn unhex(text: &str) -> Vec<u8> {
	assert_eq!(text.len() % 2, 0);
	(0..text.len())
		.step_by(2)
		.map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
		.collect()
}

fn digest(bytes: &[u8]) -> String {
	Sha256::digest(bytes)
		.into_iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}

fn native_parse(
	bytes: &[u8],
	limits: NativeJsonLimits,
	small: bool,
) -> (Result<Parsed>, Rc<RefCell<State>>) {
	let state = Rc::new(RefCell::new(State::new(
		CancellationToken::new(),
		limits,
		small,
	)));
	let result = parse_reader(
		io::Cursor::new(bytes),
		bytes.len() as u64,
		Rc::clone(&state),
	);
	(result, state)
}

fn load(path: &Path, root: &Path, limits: NativeJsonLimits) -> Result<OwnedJson> {
	read_blocking(
		path.to_str().unwrap(),
		&[root.to_owned()],
		CancellationToken::new(),
		limits,
	)
}

#[test]
fn original_controls_bind_real_node_mcp_bytes_and_terminal_provenance() {
	assert_eq!(
		digest(FIXTURE),
		"53fa6eace4cc9e9d8870e81f7c68f0eb382d9a42db17c97d18b97e090658acce"
	);
	let reference = fixture();
	assert_eq!(reference["passed"], true);
	assert_eq!(reference["candidate_executed"], false);
	assert_eq!(reference["automatic_retry"], false);
	assert_eq!(reference["reference_before"], reference["reference_after"]);
	assert_eq!(reference["reference_before"]["file_count"], 2398);
	assert_eq!(
		reference["reference_before"]["tarball_sha256"],
		"8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb"
	);
	assert_eq!(reference["node"], reference["node_after"]);
	assert_eq!(reference["producer"], reference["producer_after"]);
	assert_eq!(reference["helpers_before"], reference["helpers_after"]);
	assert_eq!(reference["original_close"]["returncode"], 0);
	assert_eq!(reference["original_close"]["owner_pidfd_exited"], true);
	assert_eq!(reference["original_close"]["process_group_gone"], true);
	assert_eq!(reference["original_close"]["forced_cleanup"], json!([]));
	let node_bytes =
		include_bytes!("../../tests/fixtures/rea_evidence_root_string/node-probe.stdout");
	assert_eq!(digest(node_bytes), reference["node_probe_stdout"]["sha256"]);
	let node: Value = serde_json::from_slice(node_bytes).unwrap();
	assert_eq!(node["node"], "v22.23.4");
	assert_eq!(node["cases"].as_array().unwrap().len(), 21);
	let provenance: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_evidence_root_string/provenance.json"
	))
	.unwrap();
	assert_eq!(
		provenance["successful_run"]["terminal"]["state"],
		"succeeded"
	);
	assert_eq!(provenance["successful_run"]["terminal"]["exit_code"], 0);
	assert_eq!(
		provenance["successful_run"]["terminal"]["output_complete"],
		true
	);
	assert_eq!(
		provenance["successful_run"]["terminal"]["output_durable"],
		true
	);
	assert_eq!(
		provenance["successful_run"]["terminal"]["automatic_retry"],
		false
	);
	assert_eq!(
		provenance["first_failed_preflight"]["terminal"]["exit_code"],
		1
	);
	assert_eq!(
		provenance["first_failed_preflight"]["node_or_mcp_started"],
		false
	);
	assert_eq!(
		digest(include_bytes!(
			"../../tests/fixtures/rea_evidence_root_string/producer-r2.py"
		)),
		reference["producer"]["sha256"]
	);
	assert_eq!(
		digest(include_bytes!(
			"../../tests/fixtures/rea_evidence_root_string/original-116-valid-json-control-12.json"
		)),
		"67aafb48282c3b8e538f05d58fa5f2dc5b137ab5faf746807d445068051362a0"
	);
	let prior: Value = serde_json::from_slice(&unhex(
		provenance["prior_original_116"]["response_wire_hex"]
			.as_str()
			.unwrap(),
	))
	.unwrap();
	let lone = &reference["cases"][0];
	assert_eq!(
		lone["input_sha256"],
		provenance["prior_original_116"]["input_sha256"]
	);
	let current: Value =
		serde_json::from_str(lone["original_response_raw"].as_str().unwrap()).unwrap();
	assert_eq!(prior["result"]["content"], current["result"]["content"]);
	for case in reference["cases"].as_array().unwrap() {
		let bytes = unhex(case["input_hex"].as_str().unwrap());
		assert_eq!(bytes.len() as u64, case["input_bytes"].as_u64().unwrap());
		assert_eq!(digest(&bytes), case["input_sha256"]);
		let request = case["original_request_raw"].as_str().unwrap();
		let response = case["original_response_raw"].as_str().unwrap();
		assert_eq!(digest(request.as_bytes()), case["original_request_sha256"]);
		assert_eq!(
			digest(response.as_bytes()),
			case["original_response_sha256"]
		);
		let request: Value = serde_json::from_str(request).unwrap();
		let response: Value = serde_json::from_str(response).unwrap();
		assert_eq!(request["params"]["name"], "import_evidence_bundle");
		assert_eq!(request["id"], response["id"]);
		assert_eq!(response["result"]["isError"], true);
		assert_eq!(case["original_session_unchanged"], true);
		assert_eq!(
			node["cases"]
				.as_array()
				.unwrap()
				.iter()
				.find(|row| row["id"] == case["id"])
				.unwrap(),
			&case["node"]
		);
	}
}

#[test]
fn real_original_controls_preserve_values_errors_and_owned_root_string_proofs() {
	let reference = fixture();
	let directory = tempfile::tempdir().unwrap();
	let mut counts = [0; 5];
	for case in reference["cases"].as_array().unwrap() {
		let id = case["id"].as_str().unwrap();
		let bytes = unhex(case["input_hex"].as_str().unwrap());
		let path = directory.path().join(format!("{id}.json"));
		std::fs::write(&path, &bytes).unwrap();
		let result = load(&path, directory.path(), NativeJsonLimits::default());
		match case["expected_native"].as_str().unwrap() {
			"witness" => {
				let Err(FileReadError::RootString(proof)) = result else {
					panic!("{id}: expected owned negative proof, got {result:?}");
				};
				assert_eq!(proof.selected_path, path.to_str().unwrap());
				assert_eq!(proof.input_bytes, bytes.len() as u64);
				assert_eq!(proof.sha256, case["input_sha256"]);
				assert_eq!(case["node"]["json_parse"], true);
				assert_eq!(case["node"]["root_kind"], "string");
				counts[0] += 1;
			}
			"value" => {
				let value = result.unwrap().value;
				if let Some(units) = case["node"]["utf16_units"].as_array() {
					let actual: Vec<u16> = value.as_str().unwrap().encode_utf16().collect();
					let expected: Vec<u16> =
						units.iter().map(|v| v.as_u64().unwrap() as u16).collect();
					assert_eq!(actual, expected, "{id}");
				} else {
					assert_eq!(value, true, "{id}");
				}
				counts[1] += 1;
			}
			"invalid-json" => {
				let Err(FileReadError::InvalidJson {
					message,
					user_message,
				}) = result
				else {
					panic!("{id}: expected syntax failure, got {result:?}");
				};
				assert_eq!(message, case["node"]["message"], "{id}");
				assert!(user_message.is_none(), "{id}");
				counts[2] += 1;
			}
			"invalid-utf8" => {
				assert!(
					matches!(result,
						Err(FileReadError::InvalidJson { message, user_message })
						if message == UTF8_MESSAGE && user_message.as_deref() == Some(UTF8_MESSAGE)
					),
					"{id}"
				);
				counts[3] += 1;
			}
			"gap" => {
				assert!(
					matches!(result, Err(FileReadError::NativeProfileGap { .. })),
					"{id}: {result:?}"
				);
				counts[4] += 1;
			}
			other => panic!("unknown expected profile: {other}"),
		}
	}
	assert_eq!(counts, [6, 5, 5, 2, 3]);
}

#[test]
fn observer_proof_requires_the_entire_grammar_and_survives_every_split() {
	for case in fixture()["cases"].as_array().unwrap() {
		if case["node"]["utf8"] != true {
			continue;
		}
		let bytes = unhex(case["input_hex"].as_str().unwrap());
		let expected = case["node"]["json_parse"] == true && case["node"]["root_kind"] == "string";
		for split in 0..=bytes.len() {
			let mut observer = json_eof::Tracker::new();
			observer.accept(&bytes[..split]);
			observer.accept(&bytes[split..]);
			assert_eq!(
				observer.complete_root_string(),
				expected,
				"{} split {split}",
				case["id"]
			);
		}
	}
	for bytes in [
		b"".as_slice(),
		b" ",
		b"\"",
		b"\"\\",
		b"\"\\u",
		b"\"\\uD8",
		b"\"\\uD800",
		b"{}",
		b"[]",
	] {
		let mut observer = json_eof::Tracker::new();
		observer.accept(bytes);
		assert!(!observer.complete_root_string(), "{bytes:?}");
	}
	let mut too_deep = vec![b'['; 123];
	too_deep.extend_from_slice(br#""\uD800""#);
	too_deep.extend(std::iter::repeat_n(b']', 123));
	let mut observer = json_eof::Tracker::new();
	observer.accept(&too_deep);
	assert!(!observer.complete_root_string());
	assert!(std::mem::size_of::<json_eof::Tracker>() < 4096);
}

#[test]
fn generic_parser_and_checkpoint_parser_do_not_manufacture_a_value_or_owned_proof() {
	for case in fixture()["cases"].as_array().unwrap() {
		if case["expected_native"] != "witness" {
			continue;
		}
		let bytes = unhex(case["input_hex"].as_str().unwrap());
		let (result, state) = native_parse(&bytes, NativeJsonLimits::default(), true);
		assert!(
			matches!(
				result,
				Err(FileReadError::NativeProfileGap {
					feature: "json-diagnostic-or-value-representation",
					..
				})
			),
			"{}: {result:?}",
			case["id"]
		);
		let state = state.borrow();
		assert!(state.eof && state.complete_root_string);
		assert_eq!(state.input_bytes, bytes.len() as u64);
		assert_eq!(state.digest(), case["input_sha256"]);
		assert!(matches!(
			parse_checkpoint_json(&bytes, &CancellationToken::new()),
			Err(FileReadError::NativeProfileGap { .. })
		));
	}
}

#[test]
fn native_configuration_token_and_materialization_budgets_precede_root_string_proof() {
	let directory = tempfile::tempdir().unwrap();
	let path = directory.path().join("lone.json");
	let bytes = br#""\uD800""#;
	std::fs::write(&path, bytes).unwrap();
	for limits in [
		NativeJsonLimits {
			max_depth: 0,
			..Default::default()
		},
		NativeJsonLimits {
			max_depth: 121,
			..Default::default()
		},
		NativeJsonLimits {
			max_token_bytes: 0,
			..Default::default()
		},
		NativeJsonLimits {
			max_materialized_bytes: 0,
			..Default::default()
		},
	] {
		assert!(matches!(
			load(&path, directory.path(), limits),
			Err(FileReadError::NativeProfileGap {
				feature: "native-json-limit-configuration",
				..
			})
		));
	}
	assert!(matches!(
		load(
			&path,
			directory.path(),
			NativeJsonLimits {
				max_token_bytes: 7,
				..Default::default()
			}
		),
		Err(FileReadError::NativeProfileGap {
			feature: "native-json-token-budget",
			..
		})
	));
	// Root Seed charges 128. The checked whole source safely bounds the
	// skipped string visit: 128 + 64 + 2*8 = 208, including quotes/whitespace.
	for maximum in [1, 127, 128, 207] {
		assert!(
			matches!(
				load(
					&path,
					directory.path(),
					NativeJsonLimits {
						max_materialized_bytes: maximum,
						..Default::default()
					}
				),
				Err(FileReadError::NativeProfileGap {
					feature: "native-json-materialization-budget",
					..
				})
			),
			"{maximum}"
		);
	}
	assert!(matches!(
		load(
			&path,
			directory.path(),
			NativeJsonLimits {
				max_materialized_bytes: 208,
				..Default::default()
			}
		),
		Err(FileReadError::RootString(_))
	));
	let deep = format!("{}\"\\uD800\"{}", "[".repeat(4), "]".repeat(4));
	std::fs::write(&path, deep).unwrap();
	assert!(matches!(
		load(
			&path,
			directory.path(),
			NativeJsonLimits {
				max_depth: 1,
				..Default::default()
			}
		),
		Err(FileReadError::NativeProfileGap {
			feature: "native-json-depth-budget",
			..
		})
	));
}

#[test]
fn native_small_file_scope_includes_its_boundary_and_excludes_larger_root_strings() {
	let directory = tempfile::tempdir().unwrap();
	let path = directory.path().join("threshold.json");
	let mut bytes = br#""\uD800""#.to_vec();
	bytes.resize(NATIVE_JSON_THRESHOLD as usize, b' ');
	std::fs::write(&path, &bytes).unwrap();
	assert!(matches!(
		load(&path, directory.path(), NativeJsonLimits::default()),
		Err(FileReadError::RootString(_))
	));
	bytes.push(b' ');
	std::fs::write(&path, &bytes).unwrap();
	assert!(matches!(
		load(&path, directory.path(), NativeJsonLimits::default()),
		Err(FileReadError::NativeProfileGap {
			feature: "json-diagnostic-or-value-representation",
			..
		})
	));
}

#[test]
fn complete_read_fence_requires_physical_eof_exact_length_and_stable_digests() {
	let bytes = br#""\uD800""#;
	let (_, state) = native_parse(bytes, NativeJsonLimits::default(), true);
	let expected = digest(bytes);
	assert!(ensure_complete_read(&state.borrow(), bytes.len() as u64, Some(&expected)).is_ok());
	let other = digest(br#""\uDC00""#);
	for (length, first_digest) in [
		(bytes.len() as u64 + 1, &expected),
		(bytes.len() as u64, &other),
	] {
		assert!(matches!(
			ensure_complete_read(&state.borrow(), length, Some(first_digest)),
			Err(FileReadError::File {
				errno: Some(libc::ESTALE),
				..
			})
		));
	}
	state.borrow_mut().eof = false;
	assert!(matches!(
		ensure_complete_read(&state.borrow(), bytes.len() as u64, Some(&expected)),
		Err(FileReadError::File {
			errno: Some(libc::ESTALE),
			..
		})
	));
}

#[test]
fn no_root_candidate_survives_real_descriptor_or_named_source_changes() {
	for change in ["write", "grow", "truncate", "replace"] {
		let directory = tempfile::tempdir().unwrap();
		let path = directory.path().join("mutated.json");
		std::fs::write(&path, br#""\uD800""#).unwrap();
		let stop = CancellationToken::new();
		let roots = [directory.path().to_owned()];
		let (mut file, before) = open_confined(&path, &roots, &stop).unwrap();
		match change {
			"write" => std::fs::write(&path, br#""\uDC00""#).unwrap(),
			"grow" => std::fs::write(&path, br#""\uD800"  "#).unwrap(),
			"truncate" => std::fs::write(&path, b"").unwrap(),
			"replace" => {
				std::fs::rename(&path, directory.path().join("old.json")).unwrap();
				std::fs::write(&path, br#""\uD800""#).unwrap();
			}
			_ => unreachable!(),
		}
		let mut candidate = None;
		let result = read_admitted(
			&mut file,
			&before,
			path.to_str().unwrap(),
			&roots,
			&stop,
			NativeJsonLimits::default(),
			&mut candidate,
		);
		assert!(candidate.is_none(), "{change}");
		assert!(
			matches!(
				close_result(file, result),
				Err(FileReadError::File {
					reason: FileReason::Io,
					errno: Some(libc::ESTALE)
				})
			),
			"{change}"
		);
	}
}

#[test]
fn source_is_really_closed_before_a_late_cancellation_can_be_promoted() {
	for cancel in [false, true] {
		let directory = tempfile::tempdir().unwrap();
		let path = directory.path().join("close.json");
		std::fs::write(&path, br#""\uD800""#).unwrap();
		let stop = CancellationToken::new();
		let roots = [directory.path().to_owned()];
		let (mut file, before) = open_confined(&path, &roots, &stop).unwrap();
		let mut candidate = None;
		let result = read_admitted(
			&mut file,
			&before,
			path.to_str().unwrap(),
			&roots,
			&stop,
			NativeJsonLimits::default(),
			&mut candidate,
		);
		assert!(matches!(
			&result,
			Err(FileReadError::NativeProfileGap { .. })
		));
		assert!(candidate.is_some());
		let closed = close_result(file, result);
		assert!(matches!(
			&closed,
			Err(FileReadError::NativeProfileGap { .. })
		));
		if cancel {
			stop.cancel();
		}
		let result = finish_after_close(closed, candidate, &stop);
		if cancel {
			assert!(matches!(result, Err(FileReadError::Cancelled)));
		} else {
			assert!(matches!(result, Err(FileReadError::RootString(_))));
		}
	}
}

#[test]
fn native_cleanup_fault_keeps_the_primary_gap_and_never_uses_its_candidate() {
	let directory = tempfile::tempdir().unwrap();
	let path = directory.path().join("cleanup.json");
	std::fs::write(&path, br#""\uD800""#).unwrap();
	let stop = CancellationToken::new();
	let roots = [directory.path().to_owned()];
	let (mut file, before) = open_confined(&path, &roots, &stop).unwrap();
	let mut candidate = None;
	let result = read_admitted(
		&mut file,
		&before,
		path.to_str().unwrap(),
		&roots,
		&stop,
		NativeJsonLimits::default(),
		&mut candidate,
	);
	let closed = close_result(file, result);
	assert!(candidate.is_some());
	// Synthetic native fault after an actual close. This checks projection
	// priority; it is not evidence of an original REA or kernel close failure.
	let fault = FileReadError::Cleanup {
		errno: Some(libc::EIO),
		primary: Some(Box::new(closed.unwrap_err())),
		native_cleanup_incomplete: true,
	};
	stop.cancel();
	let result = finish_after_close(Err(fault), candidate, &stop);
	let Err(FileReadError::Cleanup {
		primary: Some(primary),
		native_cleanup_incomplete: true,
		..
	}) = result
	else {
		panic!("cleanup was replaced: {result:?}");
	};
	assert!(matches!(
		*primary,
		FileReadError::NativeProfileGap {
			feature: "json-diagnostic-or-value-representation",
			..
		}
	));
}

#[test]
fn root_string_observation_does_not_hide_late_io_or_cancellation() {
	struct LateFailure {
		bytes: io::Cursor<&'static [u8]>,
		cancel: Option<CancellationToken>,
	}
	impl Read for LateFailure {
		fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
			let count = self.bytes.read(output)?;
			if count != 0 {
				return Ok(count);
			}
			if let Some(cancel) = &self.cancel {
				cancel.cancel();
				Ok(0)
			} else {
				Err(io::Error::from_raw_os_error(libc::EIO))
			}
		}
	}
	for cancel in [false, true] {
		let stop = CancellationToken::new();
		let state = Rc::new(RefCell::new(State::new(
			stop.clone(),
			NativeJsonLimits::default(),
			true,
		)));
		let reader = LateFailure {
			bytes: io::Cursor::new(br#""\uD800""#),
			cancel: cancel.then(|| stop.clone()),
		};
		let result = parse_reader(reader, 8, Rc::clone(&state));
		if cancel {
			assert!(matches!(result, Err(FileReadError::Cancelled)));
		} else {
			assert!(matches!(
				result,
				Err(FileReadError::File {
					errno: Some(libc::EIO),
					..
				})
			));
		}
		assert!(!state.borrow().eof);
		assert!(!state.borrow().complete_root_string);
	}
}
