// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Whole-model cohort artifacts in the existing immutable weight owner.
//!
//! One pinned checkpoint, one exact global budget and one atomic directory
//! publication cover every member. The original 1024-element request cap and
//! shared artifact quota remain in force. No production incumbent is owned here.

use super::*;
use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const MAX_MEMBERS: usize = 32;
const MAX_EDITS: usize = 1024;
const JOURNAL_LIMIT: usize = 128;
static WORKERS: OnceLock<Arc<Semaphore>> = OnceLock::new();

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Identity {
	pub code_sha256: String,
	pub tensor_map_sha256: String,
	/// Includes evaluation data, split, freshness, time and unit commitments.
	pub data_manifest_sha256: String,
	pub objective_sha256: String,
	/// Includes generator/table dependencies and their immutable identities.
	pub dependency_manifest_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "policy", rename_all = "snake_case", deny_unknown_fields)]
pub enum TrainingContract {
	/// This candidate may not be resumed for training through this contract.
	InferenceOnly,
	/// A new stateless SGD/PGD run. No old optimizer checkpoint may be loaded.
	StatelessFresh {
		algorithm: StatelessAlgorithm,
		trainer_code_sha256: String,
		training_protocol_sha256: String,
	},
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StatelessAlgorithm {
	GradientDescent,
	ProjectedGradientDescent,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Member {
	pub tensor_name: String,
	pub edits: Vec<ExactElementEdit>,
	pub maximum_update_l2_norm: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchParams {
	/// Stable caller key: exactly 64 lowercase hexadecimal characters.
	pub request_id: String,
	pub path: String,
	pub expected_sha256: String,
	pub identity: Identity,
	/// At most 32 unique tensors and 1024 edited elements across the cohort.
	pub members: Vec<Member>,
	pub maximum_update_l2_norm: f64,
	/// Mandatory. Stateful continuation and implicit momentum reuse are rejected.
	pub training: TrainingContract,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RestoreCohortParams {
	pub request_id: String,
	pub artifact_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CohortManifest {
	schema: String,
	artifact_id: String,
	request: PatchParams,
	source_size_bytes: u64,
	target_sha256: String,
	patches: Vec<TensorPatch>,
	global_budget: Value,
	member_budgets: Vec<Value>,
	parent_artifact_id: Option<String>,
	restored_source_sha256: Option<String>,
	changed_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Intent {
	schema: String,
	request_digest: String,
	artifact_id: String,
	manifest_sha256: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Boundary {
	None,
	Intent,
	Staged,
	Published,
	Completed,
}

async fn boundary(current: Boundary, requested: Boundary) -> Result<()> {
	#[cfg(test)]
	{
		let name = match current {
			Boundary::Intent => "intent",
			Boundary::Staged => "staged",
			Boundary::Published => "published",
			Boundary::Completed => "completed",
			Boundary::None => "none",
		};
		if std::env::var("HEPTA_TEST_COHORT_PHASE").as_deref() == Ok(name) {
			let marker = std::env::var("HEPTA_TEST_COHORT_MARKER")?;
			tokio::fs::write(marker, name).await?;
			loop {
				tokio::time::sleep(Duration::from_millis(20)).await;
			}
		}
	}
	if current == requested {
		bail!("injected cohort interruption");
	}
	Ok(())
}

pub(super) fn valid_id(id: &str) -> bool {
	id.strip_prefix("wc1_")
		.is_some_and(super::super::weight_config::valid_sha256)
}

fn digest(bytes: &[u8]) -> String {
	hex(&Sha256::digest(bytes))
}

fn manifest_id(manifest: &CohortManifest) -> Result<String> {
	let mut value = serde_json::to_value(manifest)?;
	value
		.as_object_mut()
		.ok_or_else(|| anyhow!("cohort manifest must be an object"))?
		.remove("artifact_id");
	Ok(format!("wc1_{}", digest(&serde_json::to_vec(&value)?)))
}

fn validate(params: &mut PatchParams) -> Result<()> {
	let valid = super::super::weight_config::valid_sha256;
	let identity = &params.identity;
	if [
		&params.request_id,
		&params.expected_sha256,
		&identity.code_sha256,
		&identity.tensor_map_sha256,
		&identity.data_manifest_sha256,
		&identity.objective_sha256,
		&identity.dependency_manifest_sha256,
	]
	.iter()
	.any(|value| !valid(value))
	{
		bail!("cohort requires exact request, checkpoint and identity commitments");
	}
	if let TrainingContract::StatelessFresh {
		trainer_code_sha256,
		training_protocol_sha256,
		..
	} = &params.training
	{
		if !valid(trainer_code_sha256) || !valid(training_protocol_sha256) {
			bail!("stateless continuation requires trainer and training protocol commitments");
		}
	}
	if params.members.is_empty() || params.members.len() > MAX_MEMBERS {
		bail!("cohort requires 1 to 32 unique tensor members");
	}
	super::super::weight_norm::validate_radius(params.maximum_update_l2_norm)?;
	params
		.members
		.sort_by(|left, right| left.tensor_name.cmp(&right.tensor_name));
	let mut names = BTreeSet::new();
	let mut count = 0usize;
	for member in &mut params.members {
		if member.tensor_name.is_empty()
			|| member.tensor_name.len() > 4096
			|| !names.insert(member.tensor_name.clone())
		{
			bail!("cohort tensor names must be unique; tensor sharding is not admitted");
		}
		if member.edits.is_empty() || member.edits.len() > MAX_EDITS {
			bail!("cohort member edit count must remain within 1..1024");
		}
		count = count
			.checked_add(member.edits.len())
			.ok_or_else(|| anyhow!("edit count overflow"))?;
		if count > MAX_EDITS {
			bail!("cohort total exceeds the existing 1024-element request cap");
		}
		member.edits.sort_by_key(|edit| edit.index);
		if member
			.edits
			.iter()
			.any(|edit| edit.expected_hex.len() > 8 || edit.replacement_hex.len() > 8)
		{
			bail!("cohort element bytes exceed the native tensor bound");
		}
		super::super::weight_norm::validate_radius(member.maximum_update_l2_norm)?;
	}
	if serde_json::to_vec(params)?.len() as u64 > MAX_MANIFEST_BYTES / 2 {
		bail!("cohort request exceeds the bounded manifest budget");
	}
	Ok(())
}

// All finite F16 and BF16 values have exact F32 representations.
fn represented_value(dtype: &str, value: &str) -> Result<f32> {
	let bytes = weight_tensor::unhex(value)?;
	let result = match dtype {
		"F32" => f32::from_le_bytes(bytes.try_into().map_err(|_| anyhow!("invalid F32 bytes"))?),
		"BF16" => {
			let bits = u16::from_le_bytes(
				bytes
					.try_into()
					.map_err(|_| anyhow!("invalid BF16 bytes"))?,
			);
			f32::from_bits(u32::from(bits) << 16)
		}
		"F16" => {
			let bits =
				u16::from_le_bytes(bytes.try_into().map_err(|_| anyhow!("invalid F16 bytes"))?);
			let sign = u32::from(bits & 0x8000) << 16;
			let exponent = u32::from((bits >> 10) & 31);
			let mantissa = u32::from(bits & 1023);
			if exponent == 0 {
				let magnitude = (mantissa as f32) * 2_f32.powi(-24);
				if sign == 0 {
					magnitude
				} else {
					-magnitude
				}
			} else {
				if exponent == 31 {
					bail!("nonfinite F16 value");
				}
				f32::from_bits(sign | ((exponent + 112) << 23) | (mantissa << 13))
			}
		}
		_ => bail!("cohort supports only native F32/F16/BF16 tensor bytes"),
	};
	if !result.is_finite() {
		bail!("cohort budget rejects nonfinite values");
	}
	Ok(result)
}

fn combined_changes(patches: &[TensorPatch]) -> Result<Vec<ByteChange>> {
	let mut changes: Vec<_> = patches
		.iter()
		.flat_map(|patch| patch.changes.iter().cloned())
		.collect();
	changes.sort_by_key(|change| change.file_offset);
	for pair in changes.windows(2) {
		let end = pair[0]
			.file_offset
			.checked_add((pair[0].expected_hex.len() / 2) as u64)
			.ok_or_else(|| anyhow!("cohort byte range overflow"))?;
		if end > pair[1].file_offset {
			bail!("cohort members overlap in checkpoint storage");
		}
	}
	Ok(changes)
}

async fn read_exact_record(path: &Path, root: &Path, expected: &[u8]) -> Result<()> {
	let bytes =
		super::super::rea_files::read_private_bounded(path, &[root.to_owned()], MAX_MANIFEST_BYTES)
			.await?;
	if bytes != expected {
		bail!("cohort immutable record conflicts with this request");
	}
	Ok(())
}

async fn write_record(directory: &Path, name: &str, bytes: &[u8]) -> Result<()> {
	let destination = directory.join(name);
	if tokio::fs::symlink_metadata(&destination).await.is_ok() {
		return read_exact_record(&destination, directory, bytes).await;
	}
	// A partial temporary record cannot authorize any publication. Only the
	// atomically renamed and fsynced intent is an admitted operation.
	let temporary = directory.join(format!(".pending-{name}"));
	if let Ok(metadata) = tokio::fs::symlink_metadata(&temporary).await {
		if !metadata.is_file() || metadata.file_type().is_symlink() {
			bail!("invalid cohort journal temporary entry");
		}
		#[cfg(unix)]
		{
			use std::os::unix::fs::MetadataExt;
			if metadata.nlink() != 1
				|| metadata.uid() != unsafe { libc::geteuid() }
				|| metadata.mode() & 0o777 != 0o600
			{
				bail!("cohort journal temporary record must be private and singly linked");
			}
		}
		tokio::fs::remove_file(&temporary).await?;
	}
	let mut file = create_private(&temporary).await?;
	file.write_all(bytes).await?;
	file.sync_all().await?;
	drop(file);
	rename_exclusive(&temporary, &destination).await?;
	tokio::fs::File::open(directory).await?.sync_all().await?;
	read_exact_record(&destination, directory, bytes).await
}

async fn journal_directory(state: &Path, request_id: &str) -> Result<PathBuf> {
	let root = state.join("weight-cohort-journal-v1");
	private_directory(&root).await?;
	let destination = root.join(request_id);
	if tokio::fs::symlink_metadata(&destination).await.is_err() {
		let mut entries = tokio::fs::read_dir(&root).await?;
		let mut count = 0usize;
		while let Some(entry) = entries.next_entry().await? {
			verify_private_directory(&entry.path()).await?;
			count += 1;
			if count >= JOURNAL_LIMIT {
				bail!("cohort journal admission budget exhausted");
			}
		}
	}
	private_directory(&destination).await?;
	tokio::fs::File::open(&root).await?.sync_all().await?;
	tokio::fs::File::open(state).await?.sync_all().await?;
	Ok(destination)
}

async fn read_cohort(root: &Path, id: &str) -> Result<CohortManifest> {
	if !valid_id(id) {
		bail!("invalid native cohort artifact identity");
	}
	verify_private_directory(&root.join(id)).await?;
	let bytes = super::super::rea_files::read_private_bounded(
		&root.join(id).join("manifest.json"),
		&[root.to_owned()],
		MAX_MANIFEST_BYTES,
	)
	.await?;
	let mut manifest: CohortManifest =
		serde_json::from_value(super::super::rea_evidence::parse_unique_json(&bytes)?)?;
	if manifest.schema != "hepta.weight.native-cohort.v1"
		|| manifest.artifact_id != id
		|| manifest_id(&manifest)? != id
		|| manifest.source_size_bytes > MAX_MODEL_BYTES
	{
		bail!("cohort manifest identity is inconsistent");
	}
	validate(&mut manifest.request)?;
	let model = root.join(id).join("model.safetensors");
	let (mut file, before) =
		super::super::rea_files::open_confined(&model, &[root.to_owned()]).await?;
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		if before.nlink() != 1
			|| before.uid() != unsafe { libc::geteuid() }
			|| before.mode() & 0o777 != 0o600
		{
			bail!("retained cohort must be private, owned and singly linked");
		}
	}
	if before.len() != manifest.source_size_bytes
		|| file_hash(&mut file, before.len()).await? != manifest.target_sha256
	{
		bail!("cohort model failed complete readback verification");
	}
	unchanged(&before, &file.metadata().await?)?;
	Ok(manifest)
}

async fn reset_stage(
	stage: &Path,
	manifest_bytes: &[u8],
	root: &Path,
	incoming: u64,
) -> Result<()> {
	if tokio::fs::symlink_metadata(stage).await.is_ok() {
		verify_private_directory(stage).await?;
		let mut entries = tokio::fs::read_dir(stage).await?;
		while let Some(entry) = entries.next_entry().await? {
			let name = entry.file_name();
			if name != "manifest.json"
				&& name != "model.safetensors"
				&& name != ".pending-manifest.json"
			{
				bail!("interrupted cohort stage contains an unowned entry");
			}
			let meta = tokio::fs::symlink_metadata(entry.path()).await?;
			if !meta.is_file() || meta.file_type().is_symlink() {
				bail!("invalid interrupted cohort stage member");
			}
			#[cfg(unix)]
			{
				use std::os::unix::fs::MetadataExt;
				if meta.nlink() != 1
					|| meta.mode() & 0o777 != 0o600
					|| meta.uid() != unsafe { libc::geteuid() }
				{
					bail!("interrupted cohort stage must contain private single-link files");
				}
			}
		}
		if tokio::fs::try_exists(stage.join("manifest.json")).await? {
			read_exact_record(&stage.join("manifest.json"), stage, manifest_bytes).await?;
		}
		tokio::fs::remove_dir_all(stage).await?;
	}
	quota(root, incoming).await?;
	private_directory(stage).await?;
	write_record(stage, "manifest.json", manifest_bytes).await
}

async fn apply_with_roots(
	mut params: PatchParams,
	roots: &[PathBuf],
	state: &Path,
	parent: Option<String>,
	restored_sha: Option<String>,
	interrupt: Boundary,
) -> Result<Value> {
	if !cfg!(target_os = "linux") {
		bail!("native cohort publication requires Linux");
	}
	validate(&mut params)?;
	let (mut source, before) =
		super::super::rea_files::open_confined(Path::new(&params.path), roots).await?;
	if before.len() > MAX_MODEL_BYTES {
		bail!("cohort source exceeds the native 2 GiB cap");
	}
	let mut patches = Vec::new();
	let mut pairs = Vec::new();
	let mut member_budgets = Vec::new();
	for member in &params.members {
		let report =
			super::super::rea_model::inspect_tensor_descriptor(&mut source, &member.tensor_name)
				.await?;
		let patch = weight_tensor::prepare(
			&PatchTensorParams {
				path: params.path.clone(),
				expected_sha256: params.expected_sha256.clone(),
				tensor_name: member.tensor_name.clone(),
				edits: member.edits.clone(),
			},
			&report,
		)?;
		let local = patch
			.changes
			.iter()
			.map(|change| {
				Ok((
					represented_value(&patch.dtype, &change.expected_hex)?,
					represented_value(&patch.dtype, &change.replacement_hex)?,
				))
			})
			.collect::<Result<Vec<_>>>()?;
		let budget = super::super::weight_norm::check_pairs(
			local.iter().copied(),
			member.maximum_update_l2_norm,
		)?;
		if !budget.within_budget {
			bail!("cohort member exceeds its exact update budget");
		}
		member_budgets.push(serde_json::to_value(budget)?);
		pairs.extend(local);
		patches.push(patch);
	}
	let global = super::super::weight_norm::check_pairs(pairs, params.maximum_update_l2_norm)?;
	if !global.within_budget {
		bail!("cohort exceeds its single exact global update budget");
	}
	let changes = combined_changes(&patches)?;
	let (source_sha, target_sha, changed) =
		transform_changes(&mut source, None, &changes, before.len()).await?;
	unchanged(&before, &source.metadata().await?)?;
	if source_sha != params.expected_sha256
		|| restored_sha.as_ref().is_some_and(|sha| sha != &target_sha)
	{
		bail!("cohort base compare failed or inverse failed original checkpoint identity");
	}
	let mut manifest = CohortManifest {
		schema: "hepta.weight.native-cohort.v1".into(),
		artifact_id: String::new(),
		request: params,
		source_size_bytes: before.len(),
		target_sha256: target_sha,
		patches,
		global_budget: serde_json::to_value(global)?,
		member_budgets,
		parent_artifact_id: parent,
		restored_source_sha256: restored_sha,
		changed_bytes: changed,
	};
	manifest.artifact_id = manifest_id(&manifest)?;
	let manifest_bytes = serde_json::to_vec(&manifest)?;
	if manifest_bytes.len() as u64 > MAX_MANIFEST_BYTES {
		bail!("cohort manifest exceeds the unchanged native 512 KiB cap");
	}
	let root = store_root(state).await?;
	let _lock = lock_store(&root).await?;
	unchanged(&before, &source.metadata().await?)?;
	let journal = journal_directory(state, &manifest.request.request_id).await?;
	let implementation = digest(
		&[
			include_bytes!("weight_artifact_cohort.rs").as_slice(),
			include_bytes!("weight_artifact.rs").as_slice(),
			include_bytes!("weight_tensor.rs").as_slice(),
			include_bytes!("weight_norm.rs").as_slice(),
		]
		.concat(),
	);
	let intent = Intent {
		schema: "hepta.weight.cohort-intent.v1".into(),
		request_digest: digest(&serde_json::to_vec(
			&json!({"request":manifest.request,"roots":roots,"state":state,"implementation":implementation,"parent":manifest.parent_artifact_id,"restored_sha":manifest.restored_source_sha256}),
		)?),
		artifact_id: manifest.artifact_id.clone(),
		manifest_sha256: digest(&manifest_bytes),
	};
	let intent_bytes = serde_json::to_vec(&intent)?;
	write_record(&journal, "intent.json", &intent_bytes).await?;
	boundary(Boundary::Intent, interrupt).await?;
	let completed = tokio::fs::symlink_metadata(journal.join("outcome.json"))
		.await
		.is_ok();
	let destination = root.join(&manifest.artifact_id);
	let reused = tokio::fs::symlink_metadata(&destination).await.is_ok();
	if completed && !reused {
		bail!("published cohort is missing; journal forbids replay of completed publication");
	}
	if reused {
		let saved = read_cohort(&root, &manifest.artifact_id).await?;
		if serde_json::to_vec(&saved)? != manifest_bytes {
			bail!("retained cohort differs from admitted intent");
		}
	} else {
		let stage = root.join(format!(".pending-cohort-{}", manifest.artifact_id));
		// The only resettable stage is named by this retained intent under the
		// same owner lock. Pending directories still consume the shared quota.
		reset_stage(
			&stage,
			&manifest_bytes,
			&root,
			before.len() + MAX_MANIFEST_BYTES,
		)
		.await?;
		let mut output = create_private(&stage.join("model.safetensors")).await?;
		let (source_sha, target_sha, changed) =
			transform_changes(&mut source, Some(&mut output), &changes, before.len()).await?;
		unchanged(&before, &source.metadata().await?)?;
		if source_sha != manifest.request.expected_sha256
			|| target_sha != manifest.target_sha256
			|| changed != manifest.changed_bytes
		{
			bail!("cohort source changed during the transaction; no group was published");
		}
		output.sync_all().await?;
		drop(output);
		tokio::fs::File::open(&stage).await?.sync_all().await?;
		boundary(Boundary::Staged, interrupt).await?;
		rename_exclusive(&stage, &destination).await?;
		tokio::fs::File::open(&root).await?.sync_all().await?;
	}
	tokio::fs::File::open(&root).await?.sync_all().await?;
	boundary(Boundary::Published, interrupt).await?;
	let saved = read_cohort(&root, &manifest.artifact_id).await?;
	if serde_json::to_vec(&saved)? != manifest_bytes {
		bail!("cohort post-publication readback disagrees");
	}
	let outcome = serde_json::to_vec(
		&json!({"schema":"hepta.weight.cohort-outcome.v1","intent":intent,"target_sha256":saved.target_sha256,"all_members_verified":true}),
	)?;
	write_record(&journal, "outcome.json", &outcome).await?;
	boundary(Boundary::Completed, interrupt).await?;
	unchanged(&before, &source.metadata().await?)?;
	Ok(
		json!({"schema":"hepta.weight.native-cohort-receipt.v1","artifact_id":saved.artifact_id,
		"artifact_path":destination.join("model.safetensors"),"manifest_path":destination.join("manifest.json"),
		"journal_path":journal,"source_sha256":saved.request.expected_sha256,"sha256":saved.target_sha256,
		"changed_bytes":saved.changed_bytes,"members":saved.patches.len(),"global_budget":saved.global_budget,
		"training_contract":saved.request.training,"training_owner_verification_required":true,
		"optimizer_state_migrated":false,"all_members_verified":true,"reused":reused,
		"recovered_publication":reused && !completed,"source_modified":false,
		"incumbent_pointer_modified":false,"production_eligible":false,"behavior_evaluated":false}),
	)
}

pub(super) async fn open_pinned(
	id: &str,
	state: &Path,
) -> Result<(tokio::fs::File, std::fs::Metadata, String)> {
	let root = state.join("weight-artifacts-v1");
	verify_private_directory(&root).await?;
	let saved = read_cohort(&root, id).await?;
	let (file, metadata) =
		super::super::rea_files::open_confined(&root.join(id).join("model.safetensors"), &[root])
			.await?;
	Ok((file, metadata, saved.target_sha256))
}

// The spawned transaction owns BOTH the concurrency permit and the effect
// fence. Dropping/timing out the RPC join cannot drop either guard while an
// uncancellable renameat2 worker can still execute. No abort handle is exposed.
async fn retained_transaction<G, F>(guard: G, operation: F) -> Result<Value>
where
	G: Send + 'static,
	F: std::future::Future<Output = Result<Value>> + Send + 'static,
{
	tokio::spawn(async move {
		let _guard = guard;
		operation.await
	})
	.await
	.context("cohort owner task failed; reconcile the same request")?
}

async fn owner_guards() -> Result<(
	OwnedSemaphorePermit,
	super::super::runtime::effect_owner_fence::AdmissionPermit,
)> {
	let slot = WORKERS
		.get_or_init(|| Arc::new(Semaphore::new(4)))
		.clone()
		.acquire_owned()
		.await?;
	let owner = super::super::runtime::effect_owner_fence::admit_new_effect().await?;
	Ok((slot, owner))
}

pub async fn patch(params: PatchParams) -> Result<String> {
	let config = super::super::runtime::runtime_config()?;
	let roots = config.controller_workspace_roots.clone();
	let state = config.state_dir.clone();
	let guards = owner_guards().await?;
	let operation =
		async move { apply_with_roots(params, &roots, &state, None, None, Boundary::None).await };
	let result = tokio::time::timeout(Duration::from_secs(300), retained_transaction(guards, operation))
		.await.context("cohort response deadline exceeded; the admitted owner task may still finish; reconcile only the same request identity")??;
	Ok(serde_json::to_string(&result)?)
}

async fn restore_with_state(params: RestoreCohortParams, state: &Path) -> Result<Value> {
	let root = store_root(state).await?;
	let saved = read_cohort(&root, &params.artifact_id).await?;
	if saved.parent_artifact_id.is_some() {
		bail!("a restored cohort cannot be restored again");
	}
	let mut request = saved.request;
	request.request_id = params.request_id;
	request.path = root
		.join(&params.artifact_id)
		.join("model.safetensors")
		.to_string_lossy()
		.into_owned();
	let original_sha = request.expected_sha256.clone();
	request.expected_sha256 = saved.target_sha256;
	request.training = TrainingContract::InferenceOnly;
	for member in &mut request.members {
		for edit in &mut member.edits {
			std::mem::swap(&mut edit.expected_hex, &mut edit.replacement_hex);
		}
	}
	apply_with_roots(
		request,
		&[root],
		state,
		Some(params.artifact_id),
		Some(original_sha),
		Boundary::None,
	)
	.await
}

pub async fn restore(params: RestoreCohortParams) -> Result<String> {
	let state = super::super::runtime::runtime_config()?.state_dir.clone();
	let guards = owner_guards().await?;
	let operation = async move { restore_with_state(params, &state).await };
	let result = tokio::time::timeout(Duration::from_secs(300), retained_transaction(guards, operation))
		.await.context("cohort restore response deadline exceeded; the owner task may still finish; reconcile only the same request identity")??;
	Ok(serde_json::to_string(&result)?)
}

#[cfg(test)]
pub(super) fn before_rename_test_hook(from: &Path, to: &Path) -> Result<()> {
	let Ok(root) = std::env::var("HEPTA_TEST_COHORT_RENAME_ROOT") else {
		return Ok(());
	};
	if to.parent() != Some(Path::new(&root))
		|| !to
			.file_name()
			.is_some_and(|name| valid_id(&name.to_string_lossy()))
		|| !from
			.file_name()
			.is_some_and(|name| name.to_string_lossy().starts_with(".pending-cohort-"))
	{
		return Ok(());
	}
	std::fs::write(
		std::env::var("HEPTA_TEST_COHORT_RENAME_MARKER")?,
		b"rename worker entered",
	)?;
	let release = PathBuf::from(std::env::var("HEPTA_TEST_COHORT_RENAME_RELEASE")?);
	let deadline = std::time::Instant::now() + Duration::from_secs(15);
	while !release.exists() {
		if std::time::Instant::now() >= deadline {
			bail!("test rename release deadline exceeded");
		}
		std::thread::sleep(Duration::from_millis(2));
	}
	Ok(())
}

#[cfg(all(test, target_os = "linux"))]
#[path = "weight_artifact_cohort_tests.rs"]
mod tests;
