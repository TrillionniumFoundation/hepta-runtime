// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DurableState {
	Unknown,
	Completed,
	Failed,
}
mod record_schema {
	use super::DurableState;
	use serde::{Deserialize, Serialize};

	// Serde derives its default Visitor diagnostic from the Rust identifier,
	// not serde(rename). Keep the original name for both string specializations.
	#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
	#[serde(deny_unknown_fields)]
	pub(super) struct Record<S> {
		pub(super) request_id: S,
		pub(super) owner: S,
		pub(super) tool_name: S,
		pub(super) state: DurableState,
		pub(super) accepted_unix_ms: u128,
		pub(super) elapsed_ms: Option<u64>,
	}
}
type RecordFields<S> = record_schema::Record<S>;
type Record = record_schema::Record<String>;
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArchiveAnchor {
	root_device: u64,
	root_inode: u64,
	archive_device: u64,
	archive_inode: u64,
}
type Identity = [u64; 2];
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ShardAnchor {
	format: u32,
	root: Identity,
	legacy: Identity,
	archive: Identity,
	// Entry i binds the directory named as the two lowercase hex digits of i.
	shards: Vec<Identity>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InitIntent {
	format: u32,
	root: Identity,
	legacy: Identity,
	archive: Option<Identity>,
	shards: Vec<Identity>,
}
