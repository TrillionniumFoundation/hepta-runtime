// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ResultState {
	Unknown,
	Stored,
	Overflow,
	RefusedDto,
	NotCompleted,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Record {
	request_id: String,
	owner: String,
	tool_name: String,
	accepted_unix_ms: u128,
	policy_binding: String,
	state: ResultState,
	payload_base64: Option<String>,
	payload_bytes: Option<usize>,
	payload_sha256: Option<String>,
}
#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DirectoryIdentity {
	device: u64,
	inode: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArchiveAnchor {
	schema: u8,
	root: DirectoryIdentity,
	legacy: DirectoryIdentity,
	store: DirectoryIdentity,
	archive: DirectoryIdentity,
	shards: Vec<DirectoryIdentity>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArchiveMarker {
	schema: u8,
	anchor_sha256: String,
}
