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

//! Atomic export, ownership, cancellation and retained-cleanup regressions.

use super::*;
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::sync::atomic::AtomicBool;
use std::sync::{Condvar, Mutex as StdMutex};
use tempfile::TempDir;

const EMPTY: &[u8] = br#"{"artifacts":[],"captures":[],"environments":[],"providers":[],"records":[],"scenarios":[],"unknowns":[]}"#;

async fn admission() -> Arc<AdmissionPermit> {
	Arc::new(
		super::super::runtime::effect_owner_fence::admit_new_effect()
			.await
			.unwrap(),
	)
}

#[allow(clippy::too_many_arguments)]
async fn run_owned(
	input: Input,
	roots: Vec<PathBuf>,
	cancellation: CancellationToken,
	admission: Arc<AdmissionPermit>,
	registry: Arc<ExportRegistry>,
	records: usize,
	unknowns: usize,
	encoder: Encoder,
	hooks: Hooks,
) -> Outcome {
	super::run_owned(
		input,
		roots,
		cancellation,
		admission,
		registry,
		records,
		unknowns,
		encoder,
		hooks,
		Arc::new(tokio::sync::Mutex::new(())),
	)
	.await
}

fn encoder(bytes: Vec<u8>) -> Encoder {
	Box::new(move |writer| {
		writer.write_all(&bytes)?;
		Ok(())
	})
}

fn selected(path: &Path, overwrite: bool) -> Input {
	Input::parse(&json!({"path":path.to_str().unwrap(),"overwrite":overwrite})).unwrap()
}

async fn write(path: &Path, root: &Path, overwrite: bool) -> Outcome {
	run_owned(
		selected(path, overwrite),
		vec![root.to_owned()],
		CancellationToken::new(),
		admission().await,
		Arc::new(ExportRegistry::default()),
		0,
		0,
		encoder(EMPTY.to_vec()),
		Hooks::default(),
	)
	.await
}

fn stages(root: &Path) -> Vec<PathBuf> {
	fs::read_dir(root)
		.unwrap()
		.map(|entry| entry.unwrap().path())
		.filter(|path| {
			path.file_name()
				.unwrap()
				.to_string_lossy()
				.starts_with(".rea-write-")
		})
		.collect()
}

fn error(outcome: Outcome, code: &str, reason: &str) -> Failure {
	let failure = outcome.unwrap_err();
	assert_eq!(failure.0["code"], code);
	assert_eq!(failure.0["details"]["reason"], reason);
	failure
}

fn hook(callback: impl Fn(Phase, &Path) -> io::Result<()> + Send + Sync + 'static) -> Hooks {
	Hooks {
		callback: Some(Arc::new(callback)),
	}
}

#[test]
fn strict_input_and_posix_path_selection() {
	let input = Input::parse(&json!({"path":"//workspace/./a//evidence.json"})).unwrap();
	assert_eq!(input.path, "/workspace/a/evidence.json");
	assert!(!input.overwrite);
	assert_eq!(
		Input::parse(&json!({"path":"/a/b/..//c"})).unwrap().path,
		"/a/b/../c"
	);
	assert_eq!(Input::parse(&json!({"path":"/a/."})).unwrap().path, "/a/");
	for raw in [
		json!(null),
		json!({}),
		json!({"path":null}),
		json!({"path":""}),
		json!({"path":"relative"}),
		json!({"path":"/a\0b"}),
		json!({"path":"/a","overwrite":null}),
		json!({"path":"/a","overwrite":1}),
		json!({"path":"/a","extra":true}),
	] {
		assert_eq!(Input::parse(&raw).unwrap_err().0["code"], "invalid_request");
	}
}

#[test]
fn frozen_export_schema_has_session_result_wrapper() {
	let input: Value = serde_json::from_str(include_str!(
		"rea_contract_schemas/export_evidence_bundle.input.json"
	))
	.unwrap();
	let output: Value = serde_json::from_str(include_str!(
		"rea_contract_schemas/export_evidence_bundle.output.json"
	))
	.unwrap();
	assert_eq!(input["properties"]["overwrite"]["default"], false);
	assert_eq!(output["required"], json!(["result"]));
	assert_eq!(output["$id"],"urn:rea:tool-output:sha256:8f25c6189cc54a6a9705844d3b51f53abe7d85c22aebe665040d2fade659c4ed");
	assert_eq!(&*input_schema(), input.as_object().unwrap());
	assert_eq!(&*output_schema(), output.as_object().unwrap());
}

#[test]
fn raw_top_level_unknown_keys_retain_actual_object_keys_order() {
	let raw = json!({"path":"/fixture","a":1,"z":2,"2":3,"10":4});
	let order = ["2", "10", "z", "path", "a"].map(str::to_owned);
	let failure = validate(&raw, Some(&order)).unwrap_err();
	assert_eq!(
		failure.0["details"]["issues"],
		json!([
			{"path":["2"],"reason":"unknown_argument"},{"path":["10"],"reason":"unknown_argument"},
			{"path":["z"],"reason":"unknown_argument"},{"path":["a"],"reason":"unknown_argument"}
		])
	);
}

#[tokio::test]
async fn complete_private_atomic_export_and_target_free_wire() {
	let temp = TempDir::new().unwrap();
	let path = temp.path().join("bundle.json");
	let receipt = write(&path, temp.path(), false).await.unwrap();
	assert_eq!(fs::read(&path).unwrap(), EMPTY);
	assert_eq!(receipt.bytes, EMPTY.len() as u64);
	assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
	assert_eq!(fs::metadata(&path).unwrap().nlink(), 1);
	assert!(stages(temp.path()).is_empty());
	let result = wire(Ok(receipt));
	assert!(result.meta.is_none());
	assert!(result.is_error.is_none());
	assert_eq!(result.structured_content.unwrap()["result"]["records"], 0);
	assert!(wire(Err(file_failure(path.to_str().unwrap(), "exists")))
		.meta
		.is_none());
}

#[tokio::test]
async fn no_replace_retains_existing_inode_and_bytes() {
	let temp = TempDir::new().unwrap();
	let path = temp.path().join("bundle.json");
	fs::write(&path, b"original").unwrap();
	let inode = fs::metadata(&path).unwrap().ino();
	error(
		write(&path, temp.path(), false).await,
		"invalid_request",
		"exists",
	);
	assert_eq!(fs::read(&path).unwrap(), b"original");
	assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
	assert!(stages(temp.path()).is_empty());
}

#[tokio::test]
async fn overwrite_replaces_name_without_mutating_existing_hardlink() {
	let temp = TempDir::new().unwrap();
	let path = temp.path().join("bundle.json");
	let alias = temp.path().join("old-link");
	fs::write(&path, b"original").unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
	fs::hard_link(&path, &alias).unwrap();
	let old = fs::metadata(&path).unwrap().ino();
	write(&path, temp.path(), true).await.unwrap();
	assert_eq!(fs::read(&alias).unwrap(), b"original");
	assert_eq!(fs::read(&path).unwrap(), EMPTY);
	assert_ne!(fs::metadata(&path).unwrap().ino(), old);
	assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
}

#[tokio::test]
async fn final_symlink_and_directory_obey_overwrite_precedence() {
	let temp = TempDir::new().unwrap();
	let outside = TempDir::new().unwrap();
	let target = outside.path().join("target");
	fs::write(&target, b"untouched").unwrap();
	let path = temp.path().join("link");
	symlink(&target, &path).unwrap();
	error(
		write(&path, temp.path(), false).await,
		"invalid_request",
		"exists",
	);
	error(
		write(&path, temp.path(), true).await,
		"invalid_request",
		"not-file",
	);
	assert_eq!(fs::read(&target).unwrap(), b"untouched");
	assert!(fs::symlink_metadata(&path).unwrap().is_symlink());
	let directory = temp.path().join("directory");
	fs::create_dir(&directory).unwrap();
	error(
		write(&directory, temp.path(), false).await,
		"invalid_request",
		"exists",
	);
	error(
		write(&directory, temp.path(), true).await,
		"invalid_request",
		"not-file",
	);
}

#[tokio::test]
async fn missing_parent_and_trailing_directory_are_explicit() {
	let temp = TempDir::new().unwrap();
	error(
		write(&temp.path().join("absent/out.json"), temp.path(), false).await,
		"invalid_request",
		"missing",
	);
	let path = PathBuf::from(format!("{}/out/", temp.path().display()));
	error(
		write(&path, temp.path(), false).await,
		"invalid_request",
		"not-file",
	);
	assert!(stages(temp.path()).is_empty());
}

#[tokio::test]
async fn workspace_policy_never_follows_parent_symlink_or_parent_component() {
	let root = TempDir::new().unwrap();
	let outside = TempDir::new().unwrap();
	symlink(outside.path(), root.path().join("link")).unwrap();
	for path in [
		root.path().join("link/out.json"),
		root.path().join("../out.json"),
		outside.path().join("out.json"),
	] {
		assert_eq!(
			write(&path, root.path(), false).await.unwrap_err().0["details"]["boundary"],
			"filesystem-write-policy"
		);
	}
	assert!(!outside.path().join("out.json").exists());
	let failure = run_owned(
		selected(&root.path().join("out.json"), false),
		vec![],
		CancellationToken::new(),
		admission().await,
		Arc::new(ExportRegistry::default()),
		0,
		0,
		encoder(EMPTY.to_vec()),
		Hooks::default(),
	)
	.await
	.unwrap_err();
	assert_eq!(failure.0["details"]["boundary"], "filesystem-write-policy");
}

#[tokio::test]
async fn already_cancelled_does_not_touch_existing_destination() {
	let temp = TempDir::new().unwrap();
	let path = temp.path().join("bundle.json");
	fs::write(&path, b"original").unwrap();
	let cancel = CancellationToken::new();
	cancel.cancel();
	let outcome = run_owned(
		selected(&path, true),
		vec![temp.path().to_owned()],
		cancel,
		admission().await,
		Arc::new(ExportRegistry::default()),
		0,
		0,
		encoder(EMPTY.to_vec()),
		Hooks::default(),
	)
	.await;
	assert_eq!(outcome.unwrap_err().0["code"], "cancelled");
	assert_eq!(fs::read(&path).unwrap(), b"original");
	assert!(stages(temp.path()).is_empty());
}

#[tokio::test]
async fn active_writer_cancellation_is_terminal_not_write_all_eintr_spin() {
	let temp = TempDir::new().unwrap();
	let path = temp.path().join("bundle.json");
	let token = CancellationToken::new();
	let cancel = token.clone();
	let encode: Encoder = Box::new(move |writer| {
		writer.write_all(b"prefix")?;
		cancel.cancel();
		writer.write_all(b"suffix")?;
		Ok(())
	});
	let outcome = tokio::time::timeout(
		std::time::Duration::from_secs(5),
		run_owned(
			selected(&path, false),
			vec![temp.path().to_owned()],
			token,
			admission().await,
			Arc::new(ExportRegistry::default()),
			0,
			0,
			encode,
			Hooks::default(),
		),
	)
	.await
	.unwrap();
	assert_eq!(outcome.unwrap_err().0["code"], "cancelled");
	assert!(!path.exists());
	assert!(stages(temp.path()).is_empty());
}

#[tokio::test]
async fn cancellation_at_commit_boundary_has_truthful_outcome() {
	let temp = TempDir::new().unwrap();
	for phase in [Phase::BeforePublish, Phase::Published] {
		let path = temp.path().join(format!("{phase:?}.json"));
		let token = CancellationToken::new();
		let trigger = token.clone();
		let hooks = hook(move |at, _| {
			if at == phase {
				trigger.cancel();
			}
			Ok(())
		});
		let outcome = run_owned(
			selected(&path, false),
			vec![temp.path().to_owned()],
			token,
			admission().await,
			Arc::new(ExportRegistry::default()),
			0,
			0,
			encoder(EMPTY.to_vec()),
			hooks,
		)
		.await;
		if phase == Phase::BeforePublish {
			assert_eq!(outcome.unwrap_err().0["code"], "cancelled");
			assert!(!path.exists());
		} else {
			assert_eq!(outcome.unwrap().bytes, EMPTY.len() as u64);
			assert_eq!(fs::read(&path).unwrap(), EMPTY);
		}
	}
	assert!(stages(temp.path()).is_empty());
}

#[tokio::test]
async fn encoder_failure_and_sync_failure_preserve_old_output() {
	let temp = TempDir::new().unwrap();
	for fail_sync in [false, true] {
		let path = temp.path().join(format!("{fail_sync}.json"));
		fs::write(&path, b"old").unwrap();
		let encode: Encoder = if fail_sync {
			encoder(EMPTY.to_vec())
		} else {
			Box::new(|writer| {
				writer.write_all(b"partial")?;
				Err(io::Error::from_raw_os_error(libc::ENOSPC).into())
			})
		};
		let hooks = hook(move |at, _| {
			if fail_sync && at == Phase::BeforeSync {
				Err(io::Error::from_raw_os_error(libc::ENOSPC))
			} else {
				Ok(())
			}
		});
		error(
			run_owned(
				selected(&path, true),
				vec![temp.path().to_owned()],
				CancellationToken::new(),
				admission().await,
				Arc::new(ExportRegistry::default()),
				0,
				0,
				encode,
				hooks,
			)
			.await,
			"execution_failure",
			"io",
		);
		assert_eq!(fs::read(&path).unwrap(), b"old");
		assert!(stages(temp.path()).is_empty());
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_no_replace_never_truncates_winner() {
	let temp = TempDir::new().unwrap();
	let path = temp.path().join("bundle.json");
	let registry = Arc::new(ExportRegistry::default());
	let first = run_owned(
		selected(&path, false),
		vec![temp.path().to_owned()],
		CancellationToken::new(),
		admission().await,
		Arc::clone(&registry),
		0,
		0,
		encoder(EMPTY.to_vec()),
		Hooks::default(),
	);
	let second = run_owned(
		selected(&path, false),
		vec![temp.path().to_owned()],
		CancellationToken::new(),
		admission().await,
		registry,
		0,
		0,
		encoder(b"different".to_vec()),
		Hooks::default(),
	);
	let (first, second) = tokio::join!(first, second);
	assert_ne!(first.is_ok(), second.is_ok());
	let expected = if first.is_ok() { EMPTY } else { b"different" };
	assert_eq!(fs::read(&path).unwrap(), expected);
	let failed = if first.is_err() { first } else { second };
	error(failed, "invalid_request", "exists");
	assert!(stages(temp.path()).is_empty());
}

struct Gate {
	reached: StdMutex<Option<tokio::sync::oneshot::Sender<()>>>,
	release: StdMutex<bool>,
	wake: Condvar,
}
impl Gate {
	fn new() -> (Arc<Self>, tokio::sync::oneshot::Receiver<()>) {
		let (tx, rx) = tokio::sync::oneshot::channel();
		(
			Arc::new(Self {
				reached: StdMutex::new(Some(tx)),
				release: StdMutex::new(false),
				wake: Condvar::new(),
			}),
			rx,
		)
	}
	fn hold(&self) {
		if let Some(tx) = self.reached.lock().unwrap().take() {
			tx.send(()).unwrap();
		}
		let mut released = self.release.lock().unwrap();
		while !*released {
			released = self.wake.wait(released).unwrap();
		}
	}
	fn open(&self) {
		*self.release.lock().unwrap() = true;
		self.wake.notify_all();
	}
}

async fn completed(registry: &ExportRegistry) -> Vec<Value> {
	tokio::time::timeout(std::time::Duration::from_secs(5), async {
		loop {
			let values = registry.take_completed();
			if !values.is_empty() {
				break values;
			}
			tokio::time::sleep(std::time::Duration::from_millis(5)).await;
		}
	})
	.await
	.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abort_before_publication_keeps_admission_until_owned_cleanup() {
	let temp = TempDir::new().unwrap();
	let path = temp.path().join("bundle.json");
	let registry = Arc::new(ExportRegistry::default());
	let permit = admission().await;
	let weak = Arc::downgrade(&permit);
	let (gate, reached) = Gate::new();
	let held = Arc::clone(&gate);
	let hooks = hook(move |at, _| {
		if at == Phase::BeforePublish {
			held.hold();
		}
		Ok(())
	});
	let task = tokio::spawn(run_owned(
		selected(&path, false),
		vec![temp.path().to_owned()],
		CancellationToken::new(),
		permit,
		Arc::clone(&registry),
		0,
		0,
		encoder(EMPTY.to_vec()),
		hooks,
	));
	reached.await.unwrap();
	task.abort();
	assert!(task.await.unwrap_err().is_cancelled());
	assert!(weak.upgrade().is_some());
	gate.open();
	let retained = completed(&registry).await;
	assert_eq!(retained[0]["outcome"]["error"]["code"], "cancelled");
	assert!(!path.exists());
	assert!(stages(temp.path()).is_empty());
	tokio::time::timeout(std::time::Duration::from_secs(5), async {
		while weak.upgrade().is_some() {
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abort_after_publication_retains_completed_receipt() {
	let temp = TempDir::new().unwrap();
	let path = temp.path().join("bundle.json");
	let registry = Arc::new(ExportRegistry::default());
	let (gate, reached) = Gate::new();
	let held = Arc::clone(&gate);
	let hooks = hook(move |at, _| {
		if at == Phase::Published {
			held.hold();
		}
		Ok(())
	});
	let task = tokio::spawn(run_owned(
		selected(&path, false),
		vec![temp.path().to_owned()],
		CancellationToken::new(),
		admission().await,
		Arc::clone(&registry),
		0,
		0,
		encoder(EMPTY.to_vec()),
		hooks,
	));
	reached.await.unwrap();
	task.abort();
	assert!(task.await.unwrap_err().is_cancelled());
	assert_eq!(fs::read(&path).unwrap(), EMPTY);
	gate.open();
	let retained = completed(&registry).await;
	assert_eq!(retained[0]["outcome"]["result"]["bytes"], EMPTY.len());
	assert!(stages(temp.path()).is_empty());
}

#[tokio::test]
async fn real_unlink_failure_retains_published_bytes_owner_and_admission_until_retry() {
	assert_ne!(
		unsafe { libc::geteuid() },
		0,
		"This permission-failure test requires the ordinary unprivileged qualification user"
	);
	let temp = TempDir::new().unwrap();
	let path = temp.path().join("bundle.json");
	let registry = Arc::new(ExportRegistry::default());
	let permit = admission().await;
	let weak = Arc::downgrade(&permit);
	let inject = Arc::new(AtomicBool::new(true));
	let active = Arc::clone(&inject);
	let hooks = hook(move |at, path| {
		if at == Phase::BeforeUnlink && active.load(Ordering::Relaxed) {
			fs::set_permissions(path, fs::Permissions::from_mode(0o500))?;
		}
		Ok(())
	});
	let failure = run_owned(
		selected(&path, false),
		vec![temp.path().to_owned()],
		CancellationToken::new(),
		permit,
		Arc::clone(&registry),
		0,
		0,
		encoder(EMPTY.to_vec()),
		hooks,
	)
	.await
	.unwrap_err();
	assert_eq!(failure.0["code"], "cleanup_incomplete");
	assert_eq!(failure.0["details"]["published"], true);
	assert_eq!(failure.0["details"]["bytes"], EMPTY.len());
	assert_eq!(fs::read(&path).unwrap(), EMPTY);
	assert!(weak.upgrade().is_some());
	assert_eq!(registry.pending().len(), 1);
	let new = temp.path().join("new.json");
	let blocked = run_owned(
		selected(&new, false),
		vec![temp.path().to_owned()],
		CancellationToken::new(),
		admission().await,
		Arc::clone(&registry),
		0,
		0,
		encoder(EMPTY.to_vec()),
		Hooks::default(),
	)
	.await
	.unwrap_err();
	assert_eq!(blocked.0["code"], "cleanup_incomplete");
	assert!(!new.exists());
	assert_eq!(stages(temp.path()).len(), 1);
	// The test's injection must be disabled before retrying the exact owner.
	inject.store(false, Ordering::Relaxed);
	for stage in stages(temp.path()) {
		fs::set_permissions(stage, fs::Permissions::from_mode(0o700)).unwrap();
	}
	Arc::clone(&registry).retry_cleanup().await.unwrap();
	assert!(registry.pending().is_empty());
	assert!(stages(temp.path()).is_empty());
	assert!(weak.upgrade().is_none());
}

#[tokio::test]
async fn overwritten_publication_and_real_rmdir_failure_are_both_reported() {
	assert_ne!(unsafe { libc::geteuid() }, 0);
	let temp = TempDir::new().unwrap();
	let path = temp.path().join("bundle.json");
	fs::write(&path, b"old").unwrap();
	let registry = Arc::new(ExportRegistry::default());
	let root = temp.path().to_owned();
	let mode = fs::metadata(&root).unwrap().mode() & 0o777;
	let inject = Arc::new(AtomicBool::new(true));
	let active = Arc::clone(&inject);
	let hooks = hook(move |at, _| {
		if at == Phase::BeforeRmdir && active.load(Ordering::Relaxed) {
			fs::set_permissions(&root, fs::Permissions::from_mode(0o500))?;
		}
		Ok(())
	});
	let failure = run_owned(
		selected(&path, true),
		vec![temp.path().to_owned()],
		CancellationToken::new(),
		admission().await,
		Arc::clone(&registry),
		0,
		0,
		encoder(EMPTY.to_vec()),
		hooks,
	)
	.await
	.unwrap_err();
	assert_eq!(failure.0["code"], "cleanup_incomplete");
	assert_eq!(failure.0["details"]["published"], true);
	assert_eq!(fs::read(&path).unwrap(), EMPTY);
	inject.store(false, Ordering::Relaxed);
	fs::set_permissions(temp.path(), fs::Permissions::from_mode(mode)).unwrap();
	Arc::clone(&registry).retry_cleanup().await.unwrap();
	assert!(stages(temp.path()).is_empty());
}

#[tokio::test]
async fn foreign_staged_inode_is_never_removed() {
	let temp = TempDir::new().unwrap();
	let path = temp.path().join("bundle.json");
	let registry = Arc::new(ExportRegistry::default());
	let hooks = hook(|at, path| {
		if at == Phase::BeforePublish {
			fs::rename(path.join("content"), path.join("original"))?;
			fs::write(path.join("content"), b"foreign")?;
		}
		Ok(())
	});
	let failure = run_owned(
		selected(&path, false),
		vec![temp.path().to_owned()],
		CancellationToken::new(),
		admission().await,
		Arc::clone(&registry),
		0,
		0,
		encoder(EMPTY.to_vec()),
		hooks,
	)
	.await
	.unwrap_err();
	assert_eq!(failure.0["code"], "cleanup_incomplete");
	assert!(!path.exists());
	let stage = stages(temp.path()).pop().unwrap();
	assert_eq!(fs::read(stage.join("content")).unwrap(), b"foreign");
	assert!(Arc::clone(&registry).retry_cleanup().await.is_err());
	assert_eq!(fs::read(stage.join("content")).unwrap(), b"foreign");
	fs::remove_file(stage.join("content")).unwrap();
	fs::rename(stage.join("original"), stage.join("content")).unwrap();
	Arc::clone(&registry).retry_cleanup().await.unwrap();
	assert!(stages(temp.path()).is_empty());
}

#[tokio::test]
async fn destination_created_during_encoding_wins_no_replace_race() {
	let temp = TempDir::new().unwrap();
	let path = temp.path().join("bundle.json");
	let destination = path.clone();
	let encode: Encoder = Box::new(move |writer| {
		writer.write_all(EMPTY)?;
		fs::write(&destination, b"concurrent")?;
		Ok(())
	});
	error(
		run_owned(
			selected(&path, false),
			vec![temp.path().to_owned()],
			CancellationToken::new(),
			admission().await,
			Arc::new(ExportRegistry::default()),
			0,
			0,
			encode,
			Hooks::default(),
		)
		.await,
		"invalid_request",
		"exists",
	);
	assert_eq!(fs::read(&path).unwrap(), b"concurrent");
	assert!(stages(temp.path()).is_empty());
}

#[tokio::test]
async fn oversized_writer_slice_is_written_in_bounded_chunks_without_loss() {
	let temp = TempDir::new().unwrap();
	let path = temp.path().join("large.json");
	let bytes = vec![b'x'; 3 * WRITE_CHUNK + 13];
	let expected = bytes.clone();
	let receipt = run_owned(
		selected(&path, false),
		vec![temp.path().to_owned()],
		CancellationToken::new(),
		admission().await,
		Arc::new(ExportRegistry::default()),
		7,
		3,
		encoder(bytes),
		Hooks::default(),
	)
	.await
	.unwrap();
	assert_eq!(receipt.bytes, expected.len() as u64);
	assert_eq!(receipt.records, 7);
	assert_eq!(receipt.unknowns, 3);
	assert_eq!(fs::read(&path).unwrap(), expected);
}

#[tokio::test]
async fn pending_cleanup_keeps_session_owner_alive_after_last_external_handle_drops() {
	assert_ne!(unsafe { libc::geteuid() }, 0);
	let temp = TempDir::new().unwrap();
	let path = temp.path().join("bundle.json");
	let registry = Arc::new(ExportRegistry::default());
	let registry_weak = Arc::downgrade(&registry);
	let permit = admission().await;
	let permit_weak = Arc::downgrade(&permit);
	let inject = Arc::new(AtomicBool::new(true));
	let active = Arc::clone(&inject);
	let hooks = hook(move |at, path| {
		if at == Phase::BeforeUnlink && active.load(Ordering::Relaxed) {
			fs::set_permissions(path, fs::Permissions::from_mode(0o500))?;
		}
		Ok(())
	});
	let result = run_owned(
		selected(&path, false),
		vec![temp.path().to_owned()],
		CancellationToken::new(),
		permit,
		Arc::clone(&registry),
		0,
		0,
		encoder(EMPTY.to_vec()),
		hooks,
	)
	.await;
	assert_eq!(result.unwrap_err().0["code"], "cleanup_incomplete");
	drop(registry);
	assert!(permit_weak.upgrade().is_some());
	let retained = registry_weak.upgrade().unwrap();
	assert_eq!(retained.pending().len(), 1);
	// Debug must not recurse through the fail-closed self-hold.
	assert!(format!("{retained:?}").contains("retains_owner_lifetime: true"));
	inject.store(false, Ordering::Relaxed);
	for stage in stages(temp.path()) {
		fs::set_permissions(stage, fs::Permissions::from_mode(0o700)).unwrap();
	}
	Arc::clone(&retained).retry_cleanup().await.unwrap();
	drop(retained);
	assert!(permit_weak.upgrade().is_none());
	assert!(registry_weak.upgrade().is_none());
}

#[tokio::test]
async fn cancellation_with_cleanup_failure_keeps_the_original_cancellation() {
	assert_ne!(unsafe { libc::geteuid() }, 0);
	let temp = TempDir::new().unwrap();
	let path = temp.path().join("bundle.json");
	let registry = Arc::new(ExportRegistry::default());
	let token = CancellationToken::new();
	let cancel = token.clone();
	let inject = Arc::new(AtomicBool::new(true));
	let active = Arc::clone(&inject);
	let hooks = hook(move |at, path| {
		if at == Phase::BeforeWrite {
			cancel.cancel();
		}
		if at == Phase::BeforeUnlink && active.load(Ordering::Relaxed) {
			fs::set_permissions(path, fs::Permissions::from_mode(0o500))?;
		}
		Ok(())
	});
	let result = run_owned(
		selected(&path, false),
		vec![temp.path().to_owned()],
		token,
		admission().await,
		Arc::clone(&registry),
		0,
		0,
		encoder(EMPTY.to_vec()),
		hooks,
	)
	.await
	.unwrap_err();
	assert_eq!(result.0["code"], "cleanup_incomplete");
	assert_eq!(result.0["category"], "cancelled");
	assert_eq!(result.0["details"]["execution_failure"], "cancelled");
	assert!(result.0["details"].get("published").is_none());
	assert!(!path.exists());
	inject.store(false, Ordering::Relaxed);
	for stage in stages(temp.path()) {
		fs::set_permissions(stage, fs::Permissions::from_mode(0o700)).unwrap();
	}
	Arc::clone(&registry).retry_cleanup().await.unwrap();
	assert!(registry.pending().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publication_hook_and_shared_file_lock_outlive_handler_abort() {
	let temp = TempDir::new().unwrap();
	let path = temp.path().join("bundle.json");
	let changes = Arc::new(StdMutex::new(Vec::new()));
	let observed = Arc::clone(&changes);
	let registry = Arc::new(ExportRegistry::new(Arc::new(move |path| {
		observed.lock().unwrap().push(path.to_path_buf())
	})));
	let file_lock = Arc::new(tokio::sync::Mutex::new(()));
	let (gate, reached) = Gate::new();
	let held = Arc::clone(&gate);
	let hooks = hook(move |at, _| {
		if at == Phase::Published {
			held.hold();
		}
		Ok(())
	});
	let task = tokio::spawn(super::run_owned(
		selected(&path, false),
		vec![temp.path().to_owned()],
		CancellationToken::new(),
		admission().await,
		Arc::clone(&registry),
		0,
		0,
		encoder(EMPTY.to_vec()),
		hooks,
		Arc::clone(&file_lock),
	));
	reached.await.unwrap();
	assert_eq!(*changes.lock().unwrap(), vec![path.clone()]);
	assert!(file_lock.try_lock().is_err());
	task.abort();
	assert!(task.await.unwrap_err().is_cancelled());
	assert!(file_lock.try_lock().is_err());
	gate.open();
	let outcome = completed(&registry).await;
	assert_eq!(outcome[0]["outcome"]["result"]["bytes"], EMPTY.len());
	tokio::time::timeout(std::time::Duration::from_secs(5), async {
		while file_lock.try_lock().is_err() {
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
	assert_eq!(*changes.lock().unwrap(), vec![path]);
}

#[tokio::test]
async fn pending_same_path_lock_is_released_before_retry_acquires_it_again() {
	assert_ne!(unsafe { libc::geteuid() }, 0);
	let temp = TempDir::new().unwrap();
	let path = temp.path().join("bundle.json");
	let count = Arc::new(AtomicU64::new(0));
	let hits = Arc::clone(&count);
	let registry = Arc::new(ExportRegistry::new(Arc::new(move |_| {
		hits.fetch_add(1, Ordering::Relaxed);
	})));
	let file_lock = Arc::new(tokio::sync::Mutex::new(()));
	let inject = Arc::new(AtomicBool::new(true));
	let active = Arc::clone(&inject);
	let hooks = hook(move |at, path| {
		if at == Phase::BeforeUnlink && active.load(Ordering::Relaxed) {
			fs::set_permissions(path, fs::Permissions::from_mode(0o500))?;
		}
		Ok(())
	});
	let failed = super::run_owned(
		selected(&path, false),
		vec![temp.path().to_owned()],
		CancellationToken::new(),
		admission().await,
		Arc::clone(&registry),
		0,
		0,
		encoder(EMPTY.to_vec()),
		hooks,
		Arc::clone(&file_lock),
	)
	.await
	.unwrap_err();
	assert_eq!(failed.0["details"]["published"], true);
	assert_eq!(count.load(Ordering::Relaxed), 1);
	assert!(file_lock.try_lock().is_err());
	inject.store(false, Ordering::Relaxed);
	for stage in stages(temp.path()) {
		fs::set_permissions(stage, fs::Permissions::from_mode(0o700)).unwrap();
	}
	let next = tokio::time::timeout(
		std::time::Duration::from_secs(5),
		super::run_owned(
			selected(&path, true),
			vec![temp.path().to_owned()],
			CancellationToken::new(),
			admission().await,
			Arc::clone(&registry),
			0,
			0,
			encoder(EMPTY.to_vec()),
			Hooks::default(),
			Arc::clone(&file_lock),
		),
	)
	.await
	.unwrap()
	.unwrap();
	assert_eq!(next.bytes, EMPTY.len() as u64);
	assert_eq!(count.load(Ordering::Relaxed), 2);
	assert!(file_lock.try_lock().is_ok());
	assert!(registry.pending().is_empty());
	assert!(stages(temp.path()).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_while_waiting_for_another_writer_does_not_leak_admission() {
	let temp = TempDir::new().unwrap();
	let path = temp.path().join("bundle.json");
	let registry = Arc::new(ExportRegistry::default());
	let file_lock = Arc::new(tokio::sync::Mutex::new(()));
	let _other_writer = file_lock.lock().await;
	let token = CancellationToken::new();
	let trigger = token.clone();
	let permit = admission().await;
	let weak = Arc::downgrade(&permit);
	let task = tokio::spawn(super::run_owned(
		selected(&path, false),
		vec![temp.path().to_owned()],
		token,
		permit,
		Arc::clone(&registry),
		0,
		0,
		encoder(EMPTY.to_vec()),
		Hooks::default(),
		Arc::clone(&file_lock),
	));
	tokio::time::timeout(std::time::Duration::from_secs(5), async {
		while registry.state().active != 1 {
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
	trigger.cancel();
	let failure = tokio::time::timeout(std::time::Duration::from_secs(5), task)
		.await
		.unwrap()
		.unwrap()
		.unwrap_err();
	assert_eq!(failure.0["code"], "cancelled");
	assert!(weak.upgrade().is_none());
	assert!(!path.exists());
	assert!(stages(temp.path()).is_empty());
	tokio::time::timeout(
		std::time::Duration::from_secs(5),
		Arc::clone(&registry).close(),
	)
	.await
	.unwrap()
	.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_waits_for_active_and_queued_owners_and_closes_new_admission() {
	let temp = TempDir::new().unwrap();
	let path = temp.path().join("first.json");
	let second_path = temp.path().join("second.json");
	let registry = Arc::new(ExportRegistry::default());
	let (gate, reached) = Gate::new();
	let held = Arc::clone(&gate);
	let hooks = hook(move |at, _| {
		if at == Phase::Published {
			held.hold();
		}
		Ok(())
	});
	let first = tokio::spawn(run_owned(
		selected(&path, false),
		vec![temp.path().to_owned()],
		CancellationToken::new(),
		admission().await,
		Arc::clone(&registry),
		0,
		0,
		encoder(EMPTY.to_vec()),
		hooks,
	));
	reached.await.unwrap();
	let second = tokio::spawn(run_owned(
		selected(&second_path, false),
		vec![temp.path().to_owned()],
		CancellationToken::new(),
		admission().await,
		Arc::clone(&registry),
		0,
		0,
		encoder(EMPTY.to_vec()),
		Hooks::default(),
	));
	tokio::time::timeout(std::time::Duration::from_secs(5), async {
		while registry.state().active != 2 {
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
	let closing = tokio::spawn(Arc::clone(&registry).close());
	tokio::time::timeout(std::time::Duration::from_secs(5), async {
		while !registry.state().closed {
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
	assert!(!closing.is_finished());
	let refused = temp.path().join("refused.json");
	error(
		run_owned(
			selected(&refused, false),
			vec![temp.path().to_owned()],
			CancellationToken::new(),
			admission().await,
			Arc::clone(&registry),
			0,
			0,
			encoder(EMPTY.to_vec()),
			Hooks::default(),
		)
		.await,
		"execution_failure",
		"io",
	);
	assert!(!refused.exists());
	gate.open();
	first.await.unwrap().unwrap();
	second.await.unwrap().unwrap();
	tokio::time::timeout(std::time::Duration::from_secs(5), closing)
		.await
		.unwrap()
		.unwrap()
		.unwrap();
	assert_eq!(fs::read(&path).unwrap(), EMPTY);
	assert_eq!(fs::read(&second_path).unwrap(), EMPTY);
	assert!(registry.pending().is_empty());
	assert!(stages(temp.path()).is_empty());
	assert_eq!(registry.state().active, 0);
}

#[tokio::test]
async fn close_reports_unreleased_cleanup_without_undoing_publication() {
	assert_ne!(unsafe { libc::geteuid() }, 0);
	let temp = TempDir::new().unwrap();
	let path = temp.path().join("bundle.json");
	let registry = Arc::new(ExportRegistry::default());
	let file_lock = Arc::new(tokio::sync::Mutex::new(()));
	let inject = Arc::new(AtomicBool::new(true));
	let active = Arc::clone(&inject);
	let hooks = hook(move |at, path| {
		if at == Phase::BeforeUnlink && active.load(Ordering::Relaxed) {
			fs::set_permissions(path, fs::Permissions::from_mode(0o500))?;
		}
		Ok(())
	});
	let result = super::run_owned(
		selected(&path, false),
		vec![temp.path().to_owned()],
		CancellationToken::new(),
		admission().await,
		Arc::clone(&registry),
		0,
		0,
		encoder(EMPTY.to_vec()),
		hooks,
		Arc::clone(&file_lock),
	)
	.await
	.unwrap_err();
	assert_eq!(result.0["code"], "cleanup_incomplete");
	let close = Arc::clone(&registry).close().await.unwrap_err();
	assert_eq!(close.0["details"]["published"], true);
	assert!(file_lock.try_lock().is_err());
	assert_eq!(fs::read(&path).unwrap(), EMPTY);
	inject.store(false, Ordering::Relaxed);
	for stage in stages(temp.path()) {
		fs::set_permissions(stage, fs::Permissions::from_mode(0o700)).unwrap();
	}
	Arc::clone(&registry).close().await.unwrap();
	assert!(file_lock.try_lock().is_ok());
	assert!(registry.pending().is_empty());
	assert_eq!(fs::read(&path).unwrap(), EMPTY);
}

#[test]
fn frozen_export_receipt_keeps_path_before_bytes_in_both_wire_representations() {
	let result = wire(Ok(Receipt {
		path: "/tmp/complete.json".into(),
		bytes: 31,
		records: 2,
		unknowns: 3,
	}));
	let expected =
		r#"{"result":{"path":"/tmp/complete.json","bytes":31,"records":2,"unknowns":3}}"#;
	assert_eq!(result.content[0].as_text().unwrap().text, expected);
	assert!(result.meta.is_none());
	assert_eq!(
		result.structured_content.as_ref().unwrap(),
		&serde_json::from_str::<Value>(expected).unwrap()
	);
	#[derive(serde::Deserialize)]
	struct Encoded {
		#[serde(rename = "structuredContent")]
		structured: Box<serde_json::value::RawValue>,
	}
	let bytes =
		serde_json::to_vec(&super::super::rea_structured_wire::WireToolResult(&result)).unwrap();
	let encoded: Encoded = serde_json::from_slice(&bytes).unwrap();
	assert_eq!(encoded.structured.get(), expected);
}
