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

//! Real confined files, frozen producer outcomes and blocking-owner lifecycle.

use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::sync::{
	atomic::{AtomicBool, Ordering},
	Arc,
};

fn runtime() -> tokio::runtime::Runtime {
	tokio::runtime::Builder::new_multi_thread()
		.worker_threads(2)
		.enable_all()
		.build()
		.unwrap()
}
fn temporary() -> tempfile::TempDir {
	// Socket qualification uses an owned short pathname within the actual
	// AF_UNIX limit, independent of a CI runner's potentially long TMPDIR.
	tempfile::Builder::new()
		.prefix("rea-json-")
		.tempdir_in("/tmp")
		.unwrap()
}
fn reference() -> Value {
	serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_evidence_file/reference-r2.json"
	))
	.unwrap()
}
fn unhex(text: &str) -> Vec<u8> {
	assert_eq!(text.len() % 2, 0);
	(0..text.len())
		.step_by(2)
		.map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
		.collect()
}
fn source_bytes(case: &Value) -> Vec<u8> {
	if let Some(hex) = case.get("hex").and_then(Value::as_str) {
		return unhex(hex);
	}
	match case["name"].as_str().unwrap() {
		"bare-record" => {
			include_bytes!("../../tests/fixtures/rea_evidence_file/bare-record.json").to_vec()
		}
		"canonical-bundle" => {
			include_bytes!("../../tests/fixtures/rea_evidence_file/canonical-bundle.json").to_vec()
		}
		"over-eight-mib" => {
			let generator = &case["generator"];
			let mut bytes = generator["prefix"].as_str().unwrap().as_bytes().to_vec();
			bytes.resize(
				bytes.len() + generator["repeat_count"].as_u64().unwrap() as usize,
				b'x',
			);
			bytes.extend_from_slice(generator["suffix"].as_str().unwrap().as_bytes());
			bytes
		}
		name => panic!("missing source bytes for {name}"),
	}
}
fn bytes_hash(bytes: &[u8]) -> String {
	Sha256::digest(bytes)
		.into_iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}
struct HashSink(Sha256);
impl io::Write for HashSink {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		self.0.update(bytes);
		Ok(bytes.len())
	}
	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}
fn json_hash(value: &Value) -> String {
	let mut sink = HashSink(Sha256::new());
	serde_json::to_writer(&mut sink, value).unwrap();
	sink.0
		.finalize()
		.into_iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}
fn load(path: &Path, root: &Path, limits: NativeJsonLimits) -> Result<OwnedJson> {
	runtime().block_on(read_json(
		path.to_string_lossy().into_owned(),
		vec![root.to_owned()],
		CancellationToken::new(),
		(),
		limits,
	))
}

#[test]
fn original_19_file_outcomes_keep_14_exact_cases_and_five_profile_gaps() {
	let reference = reference();
	assert_eq!(reference["cases"].as_array().unwrap().len(), 19);
	let owned = temporary();
	let mut exact = 0;
	let mut gaps = 0;
	for case in reference["cases"].as_array().unwrap() {
		let name = case["name"].as_str().unwrap();
		let path = owned.path().join(format!("{name}.json"));
		let mut socket = None;
		match case["kind"].as_str().unwrap() {
			"file" => {
				let bytes = source_bytes(case);
				assert_eq!(
					bytes.len() as u64,
					case["bytes"].as_u64().unwrap(),
					"{name}"
				);
				assert_eq!(bytes_hash(&bytes), case["sha256"], "{name}");
				std::fs::write(&path, bytes).unwrap();
			}
			"directory" => std::fs::create_dir(&path).unwrap(),
			"missing" => {}
			"symlink" => symlink(owned.path().join("bare-record.json"), &path).unwrap(),
			"fifo" => {
				use std::os::unix::ffi::OsStrExt;
				let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
				assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
			}
			"socket" => socket = Some(std::os::unix::net::UnixListener::bind(&path).unwrap()),
			kind => panic!("unexpected source kind {kind}"),
		}
		let result = load(&path, owned.path(), NativeJsonLimits::default());
		if matches!(
			name,
			"invalid-object" | "unpaired-surrogate" | "number-overflow" | "depth-121" | "symlink"
		) {
			assert!(
				matches!(result, Err(FileReadError::NativeProfileGap { .. })),
				"{name}: {result:?}"
			);
			gaps += 1;
			continue;
		}
		let expected = &case["expected"];
		if expected["ok"] == true {
			let parsed = result.unwrap_or_else(|e| panic!("{name}: {e:?}"));
			assert_eq!(parsed.input_bytes, case["bytes"].as_u64().unwrap());
			assert_eq!(parsed.sha256, case["sha256"]);
			assert_eq!(parsed.selected_path, path.to_string_lossy());
			if let Some(text) = expected.get("json_text").and_then(Value::as_str) {
				let original: Value = serde_json::from_str(text).unwrap();
				assert_eq!(parsed.value, original, "{name}");
			} else {
				assert!(
					parsed.input_bytes > 8 * 1024 * 1024,
					"the original threshold is not a file cap"
				);
				assert_eq!(json_hash(&parsed.value), expected["json_sha256"], "{name}");
			}
			for row in expected["object_order"].as_array().unwrap() {
				let actual = parsed
					.object_order
					.keys(row["path"].as_array().unwrap())
					.unwrap();
				assert_eq!(json!(actual), row["keys"], "{name}: {}", row["path"]);
			}
			if matches!(name, "bare-record" | "canonical-bundle") {
				let order = parsed.object_order;
				let resolver = |path: &[Value]| order.keys(path);
				let authenticated =
					super::super::rea_evidence_source::authenticate_file_with_order(
						parsed.value,
						&parsed.selected_path,
						None,
						Some(&resolver),
					)
					.unwrap();
				assert!(authenticated["evidence_id"]
					.as_str()
					.unwrap()
					.starts_with("ev_"));
			}
		} else {
			let error = result.unwrap_err();
			match error {
				FileReadError::File { reason, .. } => {
					assert_eq!(reason.as_str(), expected["typed_error"]["reason"], "{name}")
				}
				FileReadError::InvalidJson {
					message,
					user_message,
				} => {
					assert_eq!(expected["typed_error"]["reason"], "invalid-json", "{name}");
					assert_eq!(
						json!([{ "path":[],"reason":"invalid_format","expected":"JSON","message":message }]),
						expected["typed_error"]["contentIssues"],
						"{name}"
					);
					assert_eq!(
						json!(user_message),
						expected["typed_error"]
							.get("userMessage")
							.cloned()
							.unwrap_or(Value::Null),
						"{name}"
					);
				}
				error => panic!("{name}: unexpected {error:?}"),
			}
		}
		exact += 1;
		drop(socket);
	}
	assert_eq!((exact, gaps), (14, 5));
}

#[test]
fn duplicate_subtrees_and_javascript_property_order_are_exact() {
	let owned = temporary();
	let path = owned.path().join("order.json");
	std::fs::write(&path,br#"{"x":{"old":1},"4294967295":0,"10":0,"2":0,"01":0,"0":0,"x":0,"array":[{"z":1,"a":2,"z":3}]}"#).unwrap();
	let parsed = load(&path, owned.path(), NativeJsonLimits::default()).unwrap();
	assert_eq!(
		parsed.object_order.keys(&[]).unwrap(),
		["0", "2", "10", "x", "4294967295", "01", "array"]
	);
	assert!(parsed.object_order.keys(&[json!("x")]).is_none());
	assert_eq!(
		parsed
			.object_order
			.keys(&[json!("array"), json!(0)])
			.unwrap(),
		["z", "a"]
	);
	assert_eq!(parsed.value["array"][0], json!({"z":3,"a":2}));
}

#[test]
fn scalar_numbers_are_rounded_to_javascript_semantics() {
	let owned = temporary();
	let path = owned.path().join("numbers.json");
	std::fs::write(
		&path,
		b"[1.0,-0,1e0,9007199254740993,9223372036854775807,-9223372036854775809]",
	)
	.unwrap();
	let parsed = load(&path, owned.path(), NativeJsonLimits::default()).unwrap();
	assert_eq!(parsed.value[0].as_u64(), Some(1));
	assert_eq!(parsed.value[1].as_u64(), Some(0));
	assert_eq!(parsed.value[2].as_u64(), Some(1));
	assert_eq!(parsed.value[3].as_u64(), Some(9_007_199_254_740_992));
	assert_eq!(parsed.value[4].as_u64(), Some(9_223_372_036_854_775_808));
	assert_eq!(parsed.value[5].as_i64(), Some(i64::MIN));
}

#[test]
fn utf8_scalar_spans_real_chunk_boundary_and_invalid_sequences_are_rejected() {
	let owned = temporary();
	let path = owned.path().join("boundary.json");
	let mut bytes = b"{\"s\":\"".to_vec();
	bytes.resize(CHUNK - 1, b'x');
	bytes.extend_from_slice("€😀\"}".as_bytes());
	std::fs::write(&path, &bytes).unwrap();
	let parsed = load(&path, owned.path(), NativeJsonLimits::default()).unwrap();
	assert!(parsed.value["s"].as_str().unwrap().ends_with("€😀"));
	for invalid in [
		vec![0xc0, 0x80],
		vec![0xed, 0xa0, 0x80],
		vec![0xf4, 0x90, 0x80, 0x80],
		vec![0xe2, 0x82],
	] {
		let mut bytes = b"\"".to_vec();
		bytes.extend(invalid);
		bytes.push(b'"');
		std::fs::write(&path, bytes).unwrap();
		assert!(
			matches!(load(&path,owned.path(),NativeJsonLimits::default()),Err(FileReadError::InvalidJson{message,..}) if message==UTF8_MESSAGE)
		);
	}
}

#[test]
fn actual_descriptor_fences_reject_writes_growth_truncation_and_name_replacement() {
	for change in ["write", "grow", "truncate", "replace"] {
		let owned = temporary();
		let path = owned.path().join("source.json");
		std::fs::write(&path, b"{\"original\":1}").unwrap();
		let cancellation = CancellationToken::new();
		let roots = vec![owned.path().to_owned()];
		let (mut file, before) = open_confined(&path, &roots, &cancellation).unwrap();
		match change {
			"write" => std::fs::write(&path, b"{\"original\":2}").unwrap(),
			"grow" => std::fs::write(&path, b"{\"original\":1234}").unwrap(),
			"truncate" => std::fs::write(&path, b"{}").unwrap(),
			"replace" => {
				std::fs::rename(&path, owned.path().join("old.json")).unwrap();
				std::fs::write(&path, b"{\"replacement\":3}").unwrap();
			}
			_ => unreachable!(),
		}
		assert!(
			rea_files::ensure_unchanged(&before, &file.metadata().unwrap()).is_err(),
			"real metadata changed: {change}"
		);
		let result = read_admitted(
			&mut file,
			&before,
			path.to_str().unwrap(),
			&roots,
			&cancellation,
			NativeJsonLimits::default(),
		);
		assert!(
			matches!(
				close_result(file, result),
				Err(FileReadError::File {
					reason: FileReason::Io,
					..
				})
			),
			"{change}"
		);
	}
}

#[test]
fn native_admission_limits_and_confinement_are_reported_as_native_facts() {
	let owned = temporary();
	let outside = temporary();
	let path = owned.path().join("source.json");
	std::fs::write(&path, b"{\"value\":\"01234567890123456789\"}").unwrap();
	let token = NativeJsonLimits {
		max_token_bytes: 16,
		..Default::default()
	};
	assert!(matches!(
		load(&path, owned.path(), token),
		Err(FileReadError::NativeProfileGap {
			feature: "native-json-token-budget",
			..
		})
	));
	let materialized = NativeJsonLimits {
		max_materialized_bytes: 128,
		..Default::default()
	};
	assert!(matches!(
		load(&path, owned.path(), materialized),
		Err(FileReadError::NativeProfileGap {
			feature: "native-json-materialization-budget",
			..
		})
	));
	assert!(matches!(
		load(&path, outside.path(), NativeJsonLimits::default()),
		Err(FileReadError::NativeProfileGap {
			feature: "controller-workspace-admission",
			..
		})
	));
	symlink(outside.path(), owned.path().join("linked-parent")).unwrap();
	std::fs::write(outside.path().join("secret.json"), b"{}").unwrap();
	assert!(matches!(
		load(
			&owned.path().join("linked-parent/secret.json"),
			owned.path(),
			NativeJsonLimits::default()
		),
		Err(FileReadError::NativeProfileGap {
			feature: "controller-workspace-admission",
			..
		})
	));
}

#[test]
fn cancellation_and_dropped_waiter_keep_the_actual_permit_until_owner_exit() {
	struct Guard {
		permit: Option<tokio::sync::OwnedSemaphorePermit>,
		released: Option<tokio::sync::oneshot::Sender<()>>,
	}
	impl Drop for Guard {
		fn drop(&mut self) {
			drop(self.permit.take());
			if let Some(tx) = self.released.take() {
				let _ = tx.send(());
			}
		}
	}
	runtime().block_on(async {
		let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
		let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();
		let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
		let (release_tx, release_rx) = std::sync::mpsc::channel();
		let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
		let observed = Arc::new(AtomicBool::new(false));
		let inside = Arc::clone(&observed);
		let task = tokio::spawn(owned_task(
			CancellationToken::new(),
			Guard {
				permit: Some(permit),
				released: Some(finished_tx),
			},
			move |stop| {
				entered_tx.send(()).unwrap();
				release_rx.recv().unwrap();
				inside.store(stop.is_cancelled(), Ordering::SeqCst);
				Err(FileReadError::Cancelled)
			},
		));
		entered_rx.await.unwrap();
		task.abort();
		assert!(task.await.unwrap_err().is_cancelled());
		assert_eq!(
			semaphore.available_permits(),
			0,
			"detached blocking owner still owns admission"
		);
		release_tx.send(()).unwrap();
		tokio::time::timeout(std::time::Duration::from_secs(5), finished_rx)
			.await
			.unwrap()
			.unwrap();
		assert_eq!(semaphore.available_permits(), 1);
		assert!(observed.load(Ordering::SeqCst));
		let stop = CancellationToken::new();
		stop.cancel();
		let empty = temporary();
		assert!(matches!(
			read_json(
				empty
					.path()
					.join("absent.json")
					.to_string_lossy()
					.into_owned(),
				vec![empty.path().into()],
				stop,
				(),
				Default::default()
			)
			.await,
			Err(FileReadError::Cancelled)
		));
	});
}

#[test]
fn file_errno_contract_and_cleanup_facts_are_typed() {
	for (errno, reason) in [
		(libc::ENOENT, FileReason::Missing),
		(libc::ENOTDIR, FileReason::Missing),
		(libc::ENAMETOOLONG, FileReason::PathLimit),
		(libc::EACCES, FileReason::Io),
		(libc::EPERM, FileReason::Io),
	] {
		let error = physical(io::Error::from_raw_os_error(errno));
		assert!(
			matches!(error,FileReadError::File{reason:actual,errno:Some(code)} if actual==reason&&code==errno)
		);
	}
	let owned = temporary();
	let path = owned.path().join("permissions.json");
	std::fs::write(&path, b"{}").unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
	if unsafe { libc::geteuid() } != 0 {
		assert!(matches!(
			load(&path, owned.path(), Default::default()),
			Err(FileReadError::File {
				reason: FileReason::Io,
				errno: Some(libc::EACCES)
			})
		));
	}
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	let long = owned.path().join("x".repeat(256));
	assert!(matches!(
		load(&long, owned.path(), Default::default()),
		Err(FileReadError::File {
			reason: FileReason::PathLimit,
			..
		})
	));
	let error = FileReadError::Cleanup {
		errno: Some(libc::EIO),
		primary: Some(Box::new(FileReadError::Cancelled)),
		native_cleanup_incomplete: true,
	};
	let value = serde_json::to_value(error).unwrap();
	assert_eq!(value["native_cleanup_incomplete"], true);
	assert_eq!(value["primary"]["kind"], "cancelled");
}

#[test]
fn original_alias_paths_preserve_error_spelling_directory_requirement_and_selection() {
	let reference: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_evidence_file/alias-reference-r1.json"
	))
	.unwrap();
	assert_eq!(reference["cases"].as_array().unwrap().len(), 7);
	let owned = temporary();
	std::fs::write(
		owned.path().join("bare.json"),
		include_bytes!("../../tests/fixtures/rea_evidence_file/bare-record.json"),
	)
	.unwrap();
	std::fs::write(owned.path().join("empty.json"), []).unwrap();
	std::fs::create_dir(owned.path().join("directory")).unwrap();
	for case in reference["cases"].as_array().unwrap() {
		assert_eq!(
			normalized_error_path(case["path"].as_str().unwrap()).unwrap(),
			case["normalized_path"],
			"the exact original error path"
		);
		let name = case["name"].as_str().unwrap();
		let suffix = match name {
			"missing-alias" => "absent.json",
			"empty-alias" => "empty.json",
			"bare-source-alias" | "bare-selector-alias" => "bare.json",
			"file-trailing-slash" => "bare.json//",
			"file-trailing-dot" => "bare.json/.",
			"directory-alias" => "directory//.",
			_ => panic!("unexpected original alias case {name}"),
		};
		let raw = format!("{}//./{suffix}", owned.path().display());
		let actual = runtime().block_on(read_json(
			raw.clone(),
			vec![owned.path().to_owned()],
			CancellationToken::new(),
			(),
			Default::default(),
		));
		if matches!(name, "bare-source-alias" | "bare-selector-alias") {
			let parsed = actual.unwrap();
			assert_eq!(parsed.selected_path, raw, "selector keeps caller spelling");
			if name == "bare-source-alias" {
				assert_eq!(parsed.value["evidence_id"], case["expected"]["evidence_id"]);
			} else {
				let order = parsed.object_order;
				let resolver = |path: &[Value]| order.keys(path);
				let error = super::super::rea_evidence_source::authenticate_file_with_order(
					parsed.value,
					&parsed.selected_path,
					case["evidence_id"].as_str(),
					Some(&resolver),
				)
				.unwrap_err();
				let super::super::rea_evidence_source::SourceError::Selection { message } = error
				else {
					panic!("wrong selector outcome {error:?}");
				};
				assert_eq!(
					message,
					case["expected"]["projected"]["message"]
						.as_str()
						.unwrap()
						.replace(case["path"].as_str().unwrap(), &raw)
				);
			}
		} else {
			match actual.unwrap_err() {
				FileReadError::File { reason, .. } => {
					assert_eq!(
						reason.as_str(),
						case["expected"]["typed_error"]["reason"],
						"{name}"
					);
				}
				FileReadError::InvalidJson {
					message,
					user_message,
				} => {
					assert_eq!(
						json!([{"path":[],"reason":"invalid_format","expected":"JSON","message":message}]),
						case["expected"]["typed_error"]["contentIssues"]
					);
					assert_eq!(user_message, None);
				}
				error => panic!("unexpected alias error {name}: {error:?}"),
			}
		}
	}
	for (raw, normalized) in [
		("/", "/"),
		("///./", "/"),
		("/a//./b/.", "/a/b/"),
		("/a//b///", "/a/b/"),
		("/a/.../b", "/a/.../b"),
	] {
		assert_eq!(normalized_error_path(raw).unwrap(), normalized);
	}
	for raw in ["relative.json", "/a/../b.json", "/a/\0b"] {
		assert!(matches!(
			normalized_error_path(raw),
			Err(FileReadError::NativeProfileGap { .. })
		));
	}
	symlink(
		owned.path().join("bare.json"),
		owned.path().join("link.json"),
	)
	.unwrap();
	for suffix in ["link.json/", "link.json/."] {
		let raw = format!("{}/{}", owned.path().display(), suffix);
		assert!(
			matches!(
				runtime().block_on(read_json(
					raw,
					vec![owned.path().into()],
					CancellationToken::new(),
					(),
					Default::default()
				)),
				Err(FileReadError::NativeProfileGap {
					feature: "controller-workspace-admission",
					..
				})
			),
			"a trailing directory requirement must not follow a symlink"
		);
	}
}

#[test]
fn frozen_eof_reference_errors_match_all_sixteen_inputs() {
	let reference: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_evidence_file/eof-reference-r1.json"
	))
	.unwrap();
	assert_eq!(
		reference["node_sha256"],
		"94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90"
	);
	let cases = reference["cases"].as_array().unwrap();
	assert_eq!(cases.len(), 16);
	let owned = temporary();
	let mut exact = 0;
	for (index, case) in cases.iter().enumerate() {
		let input = case["input"].as_str().unwrap();
		let expected = case["message"].as_str().unwrap();
		// Reader chunk boundaries cannot change the syntax state or position.
		for split in 0..=input.len() {
			let mut tracker = json_eof::Tracker::new();
			tracker.accept(&input.as_bytes()[..split]);
			tracker.accept(&input.as_bytes()[split..]);
			assert_eq!(tracker.finish().as_deref(), Some(expected), "{input:?}");
		}
		let path = owned.path().join(format!("eof-{index}.json"));
		std::fs::write(&path, input).unwrap();
		let outcome = load(&path, owned.path(), NativeJsonLimits::default());
		match outcome {
			Err(FileReadError::InvalidJson {
				message,
				user_message,
			}) => {
				assert_eq!(message, expected, "{input:?}");
				assert!(user_message.is_none());
			}
			other => panic!("{input:?}: {other:?}"),
		}
		exact += 1;
	}
	assert_eq!(exact, 16);
}

#[test]
fn eof_diagnostics_do_not_reclassify_non_eof_or_representation_errors() {
	let owned = temporary();
	let inputs = [
		"[1,]",
		"{\"a\":}",
		"\"\\q",
		"\"\\u0q",
		"\"abc\n",
		"1e ",
		"01",
		"tru ",
		"[]x",
		"\"\\uD800\"",
		"1e400",
	];
	for (index, input) in inputs.iter().enumerate() {
		let path = owned.path().join(format!("non-eof-{index}.json"));
		std::fs::write(&path, input).unwrap();
		let outcome = load(&path, owned.path(), NativeJsonLimits::default());
		assert!(
			matches!(outcome, Err(FileReadError::NativeProfileGap { .. })),
			"{input:?}: {outcome:?}"
		);
	}
}

#[test]
fn eof_diagnostics_do_not_change_the_large_file_parser_profile() {
	let input = b"{\"a\":1";
	let state = Rc::new(RefCell::new(State::new(
		CancellationToken::new(),
		NativeJsonLimits::default(),
		false,
	)));
	let outcome = parse_reader(io::Cursor::new(input), input.len() as u64, state);
	assert!(matches!(
		outcome,
		Err(FileReadError::NativeProfileGap {
			feature: "json-diagnostic-or-value-representation",
			..
		})
	));
}
