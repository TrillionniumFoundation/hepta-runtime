// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Explicit subprocess bridge to the real canonical owner; never adopts a model.

use super::*;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

#[path = "../../qualification/weight_recovery_runtime_20261122/src/engine.rs"]
mod recovery;

fn save(path: &Path, value: &Value) -> Result<()> {
	let mut f = OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.custom_flags(libc::O_NOFOLLOW)
		.open(path)?;
	f.write_all(&serde_json::to_vec(value)?)?;
	f.sync_all()?;
	File::open(
		path.parent()
			.ok_or_else(|| anyhow!("result parent missing"))?,
	)?
	.sync_all()?;
	Ok(())
}

use std::fs::File;

struct StopAt {
	root: PathBuf,
	cut: String,
}
impl recovery::Checkpoint for StopAt {
	fn reached(&mut self, name: &str) -> Result<()> {
		if self.cut == name {
			save(
				&self.root.join("CUT_REACHED.json"),
				&json!({"phase":name,"pid":std::process::id()}),
			)?;
			loop {
				std::thread::park_timeout(Duration::from_secs(1));
			}
		}
		Ok(())
	}
}

/// Hooks are scoped to this ignored worker's explicitly supplied isolated store.
/// They park only after both immutable stage files have been fsynced.
pub(super) fn before_rename(from: &Path, to: &Path) -> Result<()> {
	let Ok(root) = std::env::var("HEPTA_RECOVERY_TEST_ROOT") else {
		return Ok(());
	};
	let root = PathBuf::from(root);
	if to.parent() != Some(root.join("owner-state/weight-artifacts-v1").as_path())
		|| !from
			.file_name()
			.is_some_and(|s| s.to_string_lossy().starts_with(".pending-"))
		|| !to
			.file_name()
			.is_some_and(|s| s.to_string_lossy().starts_with("wa1_"))
	{
		return Ok(());
	}
	let manifest: Value = serde_json::from_slice(&std::fs::read(from.join("manifest.json"))?)?;
	let phase = if manifest["kind"] == "patch" {
		"publish_before_rename"
	} else {
		"restore_before_rename"
	};
	let mut stop = StopAt {
		root,
		cut: std::env::var("HEPTA_RECOVERY_TEST_CUT").unwrap_or_default(),
	};
	recovery::Checkpoint::reached(&mut stop, phase)
}

struct NativeOwner {
	runtime: tokio::runtime::Runtime,
	root: PathBuf,
	source: PathBuf,
	state: PathBuf,
}
impl NativeOwner {
	fn record(&self, operation: &str, result: &Value) -> Result<()> {
		let p = self.root.join("OWNER_CALLS.jsonl");
		let mut file = OpenOptions::new()
			.create(true)
			.append(true)
			.mode(0o600)
			.custom_flags(libc::O_NOFOLLOW)
			.open(p)?;
		file.write_all(&serde_json::to_vec(
			&json!({"operation":operation,"receipt":result,"pid":std::process::id()}),
		)?)?;
		file.write_all(b"\n")?;
		file.sync_all()?;
		Ok(())
	}
	fn receipt(&self, result: &Value) -> Result<recovery::OwnerReceipt> {
		if result["production_eligible"] != false || result["source_modified"] != false {
			bail!("canonical owner exceeded research scope");
		}
		let text = |key: &str| -> Result<String> {
			Ok(result[key]
				.as_str()
				.ok_or_else(|| anyhow!("receipt field {key}"))?
				.into())
		};
		Ok(recovery::OwnerReceipt {
			artifact_id: text("artifact_id")?,
			source_sha256: text("source_sha256")?,
			content_sha256: text("sha256")?,
			kind: text("kind")?,
		})
	}
}
impl recovery::ArtifactOwner for NativeOwner {
	fn publish(&mut self, intent: &recovery::Intent) -> Result<recovery::OwnerReceipt> {
		let p: PatchTensorParams = serde_json::from_value(intent.owner_request.clone())?;
		if Path::new(&p.path) != self.source || p.expected_sha256 != intent.source_sha256 {
			bail!("request does not bind this isolated source");
		}
		let result = self.runtime.block_on(apply_with_roots(
			p,
			std::slice::from_ref(&self.root),
			&self.state,
			None,
			None,
		))?;
		self.record("publish", &result)?;
		self.receipt(&result)
	}
	fn inspect(&mut self, receipt: &recovery::OwnerReceipt) -> Result<()> {
		self.runtime.block_on(async {
			let (mut file, before, commitment) =
				open_pinned_artifact(&receipt.artifact_id, &self.state).await?;
			if commitment != receipt.content_sha256
				|| file_hash(&mut file, before.len()).await? != commitment
			{
				bail!("canonical pinned artifact content differs");
			}
			unchanged(&before, &file.metadata().await?)
		})
	}
	fn restore(
		&mut self,
		_: &recovery::Intent,
		candidate: &recovery::OwnerReceipt,
	) -> Result<recovery::OwnerReceipt> {
		let result = self
			.runtime
			.block_on(restore_with_state(&candidate.artifact_id, &self.state))?;
		self.record("restore", &result)?;
		self.receipt(&result)
	}
	fn verify_original(&mut self, intent: &recovery::Intent) -> Result<()> {
		if recovery::digest(&std::fs::read(&self.source)?) != intent.source_sha256 {
			bail!("original source changed");
		}
		Ok(())
	}
}

struct NativeLinearEvaluator {
	state: PathBuf,
	reject: bool,
	calls: usize,
}
impl recovery::Evaluator for NativeLinearEvaluator {
	fn evaluate(
		&mut self,
		intent: &recovery::Intent,
		candidate: &recovery::OwnerReceipt,
	) -> Result<recovery::Evaluation> {
		self.calls += 1;
		let data = std::fs::read(
			self.state
				.join("weight-artifacts-v1")
				.join(&candidate.artifact_id)
				.join("model.safetensors"),
		)?;
		if recovery::digest(&data) != candidate.content_sha256 || data.len() < 8 {
			bail!("candidate bytes differ");
		}
		let header = u64::from_le_bytes(data[..8].try_into()?) as usize;
		let offset = 8usize
			.checked_add(header)
			.ok_or_else(|| anyhow!("header overflow"))?;
		if data.len() != offset + 32 {
			bail!("bounded F64 fixture layout differs");
		}
		let mut score = 0.0;
		for (i, bytes) in data[offset..].chunks_exact(8).enumerate() {
			let x = f64::from_le_bytes(bytes.try_into()?);
			if !x.is_finite() {
				bail!("nonfinite candidate");
			}
			score += (i + 1) as f64 * x;
		}
		let result = json!({"score":score,"expected":22.0,"rejected_control":self.reject,"model_sha256":candidate.content_sha256});
		Ok(recovery::Evaluation {
			candidate_sha256: candidate.content_sha256.clone(),
			task_sha256: intent.task_sha256.clone(),
			law_sha256: intent.law_sha256.clone(),
			evaluator_sha256: intent.evaluator_sha256.clone(),
			passed: score == 22.0 && !self.reject,
			result_sha256: recovery::digest(&serde_json::to_vec(&result)?),
		})
	}
}

fn fixture() -> Result<(Vec<u8>, Vec<u8>)> {
	let mut header = br#"{"readout4":{"dtype":"F64","shape":[4],"data_offsets":[0,32]}}"#.to_vec();
	while !header.len().is_multiple_of(8) {
		header.push(b' ');
	}
	let mut original = (header.len() as u64).to_le_bytes().to_vec();
	original.extend(header);
	for x in [0.0f64, 1.0, 2.0, 3.0] {
		original.extend(x.to_le_bytes());
	}
	let mut candidate = original.clone();
	let n = candidate.len();
	candidate[n - 24..n - 16].copy_from_slice(&4.0f64.to_le_bytes());
	candidate[n - 8..].copy_from_slice(&2.0f64.to_le_bytes());
	Ok((original, candidate))
}

#[test]
#[ignore = "explicit isolated canonical-owner process harness required"]
fn canonical_f64_crash_recovery_worker() -> Result<()> {
	let root = PathBuf::from(std::env::var("HEPTA_RECOVERY_TEST_ROOT")?);
	let mode = std::env::var("HEPTA_RECOVERY_TEST_MODE")?;
	if !root.is_absolute() || !matches!(mode.as_str(), "start" | "recover") {
		bail!("explicit isolated mode required");
	}
	if mode == "start" {
		std::fs::DirBuilder::new().mode(0o700).create(&root)?;
	}
	let (original, candidate) = fixture()?;
	let source = root.join("original.safetensors");
	let state = root.join("owner-state");
	if mode == "start" {
		let mut f = OpenOptions::new()
			.write(true)
			.create_new(true)
			.mode(0o600)
			.open(&source)?;
		f.write_all(&original)?;
		f.sync_all()?;
		File::open(&root)?.sync_all()?;
	}
	let params = PatchTensorParams {
		path: source.to_string_lossy().into_owned(),
		expected_sha256: recovery::digest(&original),
		tensor_name: "readout4".into(),
		edits: vec![
			ExactElementEdit {
				index: 1,
				expected_hex: hex(&1.0f64.to_le_bytes()),
				replacement_hex: hex(&4.0f64.to_le_bytes()),
			},
			ExactElementEdit {
				index: 3,
				expected_hex: hex(&3.0f64.to_le_bytes()),
				replacement_hex: hex(&2.0f64.to_le_bytes()),
			},
		],
	};
	let request = serde_json::to_value(params)?;
	let intent = recovery::Intent {
		schema: "hepta.weight.recovery-intent.v1".into(),
		source_sha256: recovery::digest(&original),
		candidate_sha256: recovery::digest(&candidate),
		law_sha256: recovery::digest(b"finite deterministic linear fixture law v1"),
		task_sha256: recovery::digest(b"sum (i+1)*w_i equals 22"),
		evaluator_sha256: recovery::digest(include_bytes!("weight_artifact_recovery_tests.rs")),
		owner_request_sha256: recovery::digest(&serde_json::to_vec(&request)?),
		owner_request: request,
	};
	if mode == "start" {
		save(&root.join("INTENT.json"), &serde_json::to_value(&intent)?)?;
	} else if serde_json::from_slice::<recovery::Intent>(&std::fs::read(root.join("INTENT.json"))?)?
		!= intent
	{
		bail!("persisted intent differs");
	}
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()?;
	let mut owner = NativeOwner {
		runtime,
		root: root.clone(),
		source,
		state: state.clone(),
	};
	let mut evaluator = NativeLinearEvaluator {
		state,
		reject: std::env::var("HEPTA_RECOVERY_TEST_REJECT").as_deref() == Ok("true"),
		calls: 0,
	};
	let mut checkpoint = StopAt {
		root: root.clone(),
		cut: std::env::var("HEPTA_RECOVERY_TEST_CUT").unwrap_or_default(),
	};
	let record = if mode == "start" {
		recovery::execute(
			&root.join("journal"),
			intent.clone(),
			&mut owner,
			&mut evaluator,
			&mut checkpoint,
		)?
	} else {
		recovery::recover(&root.join("journal"), &intent, &mut owner, &mut checkpoint)?
	};
	let name = std::env::var("HEPTA_RECOVERY_TEST_RESULT")?;
	if name.contains('/') || name.contains('\\') || !name.ends_with(".json") {
		bail!("result basename required");
	}
	save(
		&root.join(name),
		&json!({"schema":"hepta.weight.canonical-recovery-worker.v1","pid":std::process::id(),"mode":mode,
		"record":record,"evaluator_calls_this_process":evaluator.calls,"production_adoption":false,"source_unchanged":std::fs::read(root.join("original.safetensors"))?==original}),
	)?;
	Ok(())
}
