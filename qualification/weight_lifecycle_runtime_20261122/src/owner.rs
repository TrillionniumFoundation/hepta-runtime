// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Adapter to the same runtime canonical patch/restore API, without another store.

use crate::inputs;
use anyhow::{anyhow, bail, Result};
use hepta_runtime::mcp::{runtime, weight_artifact, weight_tensor::PatchTensorParams};
use hepta_semantic_source_adapter_study::{digest, unique_json};
use hepta_weight_recovery_study as recovery;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub struct NativeOwner {
	pub runtime: tokio::runtime::Runtime,
	pub root: PathBuf,
	pub state: PathBuf,
	pub source: PathBuf,
	pub calls: Vec<Value>,
	pub operations: Vec<Value>,
	pub inspected_model_bytes: u64,
}

pub(crate) fn local_owner_config(root: &Path) -> Result<runtime::RuntimeConfig> {
	// The existing runtime schema requires a host descriptor. This localhost
	// descriptor grants no remote capability and initialization opens no SSH link.
	let config: runtime::RuntimeConfig = serde_json::from_value(json!({
		"state_dir":root.join("owner-state"),"controller_workspace_roots":[root],
		"hosts":{"disabled_localhost":{"ssh_target":"localhost",
			"remote_state_dir":root.join("disabled-remote-state"),
			"execution_mode":"isolated","platform":"linux",
			"allow_execute":false,"allow_pty":false,"allow_write":false,
			"allow_job_network":false,"allow_detached_fallback":false,
			"allowed_read_path_prefixes":[],"allowed_write_path_prefixes":[]}}
	}))?;
	config.validate()?;
	Ok(config)
}

impl NativeOwner {
	pub fn new(root: &Path) -> Result<Self> {
		inputs::private_dir(root)?;
		let state = root.join("owner-state");
		let config = local_owner_config(root)?;
		runtime::init_runtime(config)?;
		let rt = tokio::runtime::Builder::new_multi_thread()
			.worker_threads(1)
			.enable_all()
			.build()?;
		Ok(Self {
			runtime: rt,
			root: root.into(),
			state,
			source: root.join("source.safetensors"),
			calls: Vec::new(),
			operations: Vec::new(),
			inspected_model_bytes: 0,
		})
	}

	fn measured(
		&mut self,
		operation: &str,
		result: &Result<String>,
		stamp: crate::meter::Stamp,
	) -> Result<()> {
		let row = json!({"operation":operation,"succeeded":result.is_ok(),"measurement":stamp.finish(operation)?,
			"error":result.as_ref().err().map(|e| e.to_string()),"pid":std::process::id()});
		inputs::save_json(
			&self.root.join(format!(
				"owner-operation-{}-{}.json",
				std::process::id(),
				self.operations.len()
			)),
			&row,
		)?;
		self.operations.push(row);
		Ok(())
	}

	fn receipt(&mut self, operation: &str, result: Value) -> Result<recovery::OwnerReceipt> {
		if result["production_eligible"] != false || result["source_modified"] != false {
			bail!("canonical owner exceeded research scope");
		}
		let field = |key: &str| -> Result<String> {
			result[key]
				.as_str()
				.map(str::to_owned)
				.ok_or_else(|| anyhow!("owner field {key} missing"))
		};
		let receipt = recovery::OwnerReceipt {
			artifact_id: field("artifact_id")?,
			source_sha256: field("source_sha256")?,
			content_sha256: field("sha256")?,
			kind: field("kind")?,
		};
		let ordinal = self.calls.len();
		let row = json!({"operation":operation,"receipt":result,"pid":std::process::id(),
			"bytes_copied_and_hashed_scope":"canonical owner processes complete checkpoint; patch bytes alone are not I/O cost"});
		inputs::save_json(
			&self
				.root
				.join(format!("owner-call-{}-{ordinal}.json", std::process::id())),
			&row,
		)?;
		self.calls.push(row);
		Ok(receipt)
	}

	pub fn artifact_path(&self, receipt: &recovery::OwnerReceipt) -> Result<PathBuf> {
		if !receipt
			.artifact_id
			.strip_prefix("wa1_")
			.is_some_and(hepta_weight_program_study::snapshot::valid_digest)
		{
			bail!("single-tensor canonical artifact identity required");
		}
		Ok(self
			.state
			.join("weight-artifacts-v1")
			.join(&receipt.artifact_id)
			.join("model.safetensors"))
	}
}

impl recovery::ArtifactOwner for NativeOwner {
	fn publish(&mut self, intent: &recovery::Intent) -> Result<recovery::OwnerReceipt> {
		let params: PatchTensorParams = serde_json::from_value(intent.owner_request.clone())?;
		if Path::new(&params.path) != self.source || params.expected_sha256 != intent.source_sha256
		{
			bail!("publication request does not bind the isolated original");
		}
		let stamp = crate::meter::Stamp::start()?;
		let result = self.runtime.block_on(weight_artifact::patch(params));
		self.measured("publish", &result, stamp)?;
		let output = result?;
		self.receipt("publish", unique_json(output.as_bytes())?)
	}

	fn inspect(&mut self, receipt: &recovery::OwnerReceipt) -> Result<()> {
		let path = self.artifact_path(receipt)?;
		let parent = path
			.parent()
			.ok_or_else(|| anyhow!("artifact directory missing"))?;
		inputs::private_dir(parent)?;
		let bytes = inputs::read(&path, inputs::MAX_INPUT)?;
		self.inspected_model_bytes += bytes.len() as u64;
		if digest(&bytes) != receipt.content_sha256 {
			bail!("canonical artifact content differs");
		}
		let mut manifest = unique_json(&inputs::read(
			&parent.join("manifest.json"),
			inputs::MAX_INPUT,
		)?)?;
		if manifest["artifact_id"] != receipt.artifact_id
			|| manifest["kind"] != receipt.kind
			|| manifest["source_sha256"] != receipt.source_sha256
			|| manifest["target_sha256"] != receipt.content_sha256
		{
			bail!("canonical artifact manifest differs from receipt");
		}
		manifest
			.as_object_mut()
			.ok_or_else(|| anyhow!("artifact manifest object required"))?
			.remove("artifact_id");
		if format!("wa1_{}", digest(&serde_json::to_vec(&manifest)?)) != receipt.artifact_id {
			bail!("canonical artifact manifest identity differs");
		}
		Ok(())
	}

	fn restore(
		&mut self,
		_: &recovery::Intent,
		candidate: &recovery::OwnerReceipt,
	) -> Result<recovery::OwnerReceipt> {
		let stamp = crate::meter::Stamp::start()?;
		let result =
			self.runtime
				.block_on(weight_artifact::restore(weight_artifact::RestoreParams {
					artifact_id: candidate.artifact_id.clone(),
				}));
		self.measured("restore", &result, stamp)?;
		let output = result?;
		self.receipt("restore", unique_json(output.as_bytes())?)
	}

	fn verify_original(&mut self, intent: &recovery::Intent) -> Result<()> {
		crate::evaluation::verify_latest_evidence(&self.root, intent)?;
		let bytes = inputs::read(&self.source, inputs::MAX_INPUT)?;
		self.inspected_model_bytes += bytes.len() as u64;
		if digest(&bytes) != intent.source_sha256 {
			bail!("isolated source changed");
		}
		Ok(())
	}
}
