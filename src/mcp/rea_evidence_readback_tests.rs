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

//! Readback regressions against authenticated frozen Evidence and canonical exports.

use super::*;
use serde_json::Value;

fn records() -> Vec<Value> {
	let fixtures: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_evidence_creation.json"
	))
	.unwrap();
	let mut records = BTreeMap::new();
	for case in fixtures["cases"].as_array().unwrap() {
		if let Some(id) = case["expected"]["evidence_id"].as_str() {
			records.insert(id.to_owned(), case["expected"].clone());
		}
	}
	records.into_values().collect()
}

fn params(id: Option<&str>, offset: usize, length: usize) -> ReadParams {
	ReadParams {
		snapshot_id: id.map(str::to_owned),
		offset,
		length,
	}
}

fn payload(result: CallToolResult) -> Value {
	assert_ne!(result.is_error, Some(true), "{result:?}");
	result.structured_content.unwrap()["result"].clone()
}

fn decode(text: &str) -> Vec<u8> {
	assert_eq!(text.len() % 2, 0);
	text.as_bytes()
		.as_chunks::<2>()
		.0
		.iter()
		.map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect()
}

#[tokio::test]
async fn pages_reconstruct_the_complete_canonical_export_and_replay_exactly() {
	let session = EvidenceSession::default();
	for record in records().into_iter().take(2) {
		session.record(record).unwrap();
	}
	let mut exported = Vec::new();
	session
		.snapshot()
		.unwrap()
		.write_canonical(&mut exported)
		.unwrap();
	let registry = ReadbackRegistry::default();
	let token = CancellationToken::new();
	let first = payload(
		registry
			.read(params(None, 0, 137), &session, token.clone())
			.await,
	);
	let id = first["snapshot_id"].as_str().unwrap();
	assert_eq!(first["sha256"], hexadecimal(&Sha256::digest(&exported)));
	assert_eq!(first["total_bytes"], exported.len());
	assert_eq!(first["persistence"], "session-only");
	let replay = payload(
		registry
			.read(params(Some(id), 0, 137), &session, token.clone())
			.await,
	);
	assert_eq!(replay, first);
	let mut page = first.clone();
	let mut bytes = Vec::new();
	loop {
		assert_eq!(page["offset"], bytes.len());
		assert_eq!(page["snapshot_id"], id);
		let chunk = decode(page["bytes_hex"].as_str().unwrap());
		assert_eq!(page["chunk_sha256"], hexadecimal(&Sha256::digest(&chunk)));
		bytes.extend(chunk);
		if page["eof"] == true {
			assert!(page["next_offset"].is_null());
			break;
		}
		let offset = page["next_offset"].as_u64().unwrap() as usize;
		page = payload(
			registry
				.read(params(Some(id), offset, 137), &session, token.clone())
				.await,
		);
	}
	assert_eq!(bytes, exported);
	let eof = payload(
		registry
			.read(params(Some(id), bytes.len(), 1), &session, token)
			.await,
	);
	assert_eq!(eof["bytes_hex"], "");
	assert_eq!(eof["eof"], true);
}

#[tokio::test]
async fn frozen_cursor_survives_new_records_and_is_never_inherited_by_another_session() {
	let session = EvidenceSession::default();
	let fixtures = records();
	assert!(fixtures.len() >= 2);
	session.record(fixtures[0].clone()).unwrap();
	let registry = ReadbackRegistry::default();
	let token = CancellationToken::new();
	let old = payload(
		registry
			.read(params(None, 0, MAX_PAGE_BYTES), &session, token.clone())
			.await,
	);
	let id = old["snapshot_id"].as_str().unwrap();
	session.record(fixtures[1].clone()).unwrap();
	let replay = payload(
		registry
			.read(params(Some(id), 0, MAX_PAGE_BYTES), &session, token.clone())
			.await,
	);
	assert_eq!(old, replay);
	let new = payload(
		registry
			.read(params(None, 0, MAX_PAGE_BYTES), &session, token.clone())
			.await,
	);
	assert_ne!(old["snapshot_id"], new["snapshot_id"]);
	assert_eq!(old["records"], 1);
	assert_eq!(new["records"], 2);
	let other = ReadbackRegistry::default();
	assert_eq!(
		other
			.read(params(Some(id), 0, 1), &session, token.clone())
			.await
			.is_error,
		Some(true)
	);
	let closed = payload(registry.close(CloseParams {
		snapshot_id: id.to_owned(),
	}));
	assert_eq!(closed["released"], true);
	assert_eq!(
		registry
			.read(params(Some(id), 0, 1), &session, token)
			.await
			.is_error,
		Some(true)
	);
	assert_eq!(
		payload(registry.close(CloseParams {
			snapshot_id: id.to_owned()
		}))["released"],
		false
	);
	assert_eq!(session.snapshot().unwrap().record_count(), 2);
}

#[tokio::test]
async fn limits_bad_cursors_and_cancellation_publish_no_partial_snapshot() {
	let session = EvidenceSession::default();
	let registry = ReadbackRegistry::default();
	let invalid_close = registry.close(CloseParams {
		snapshot_id: "ebs1_BAD".to_owned(),
	});
	assert_eq!(invalid_close.is_error, Some(true));
	let invalid_close: Value =
		serde_json::from_str(&invalid_close.content[0].as_text().unwrap().text).unwrap();
	assert_eq!(
		invalid_close["error"]["details"]["operation"],
		"close_evidence_snapshot"
	);
	for request in [
		params(None, 1, 1),
		params(None, 0, 0),
		params(None, 0, MAX_PAGE_BYTES + 1),
		params(Some("ebs1_BAD"), 0, 1),
		params(Some(&format!("ebs1_{}", "0".repeat(64))), 0, 1),
	] {
		assert_eq!(
			registry
				.read(request, &session, CancellationToken::new())
				.await
				.is_error,
			Some(true)
		);
	}
	let token = CancellationToken::new();
	token.cancel();
	assert_eq!(
		registry
			.read(params(None, 0, 1), &session, token)
			.await
			.is_error,
		Some(true)
	);
	assert!(registry.state.lock().unwrap().snapshots.is_empty());
	let bounded = ReadbackRegistry {
		limits: Limits {
			snapshot_bytes: 16,
			total_bytes: 32,
			snapshots: 1,
		},
		..Default::default()
	};
	assert_eq!(
		bounded
			.read(params(None, 0, 1), &session, CancellationToken::new())
			.await
			.is_error,
		Some(true)
	);
	assert_eq!(bounded.state.lock().unwrap().bytes, 0);
	assert!(bounded.state.lock().unwrap().snapshots.is_empty());
	assert_eq!(bounded.state.lock().unwrap().pending_encoders, 0);
	assert_eq!(bounded.state.lock().unwrap().pending_bytes, 0);
}

#[tokio::test]
async fn count_limit_refuses_without_evicting_and_release_restores_capacity() {
	let session = EvidenceSession::default();
	let registry = ReadbackRegistry {
		limits: Limits {
			snapshots: 1,
			..Limits::default()
		},
		..Default::default()
	};
	let token = CancellationToken::new();
	let first = payload(
		registry
			.read(params(None, 0, 1), &session, token.clone())
			.await,
	);
	let id = first["snapshot_id"].as_str().unwrap();
	session.record(records()[0].clone()).unwrap();
	assert_eq!(
		registry
			.read(params(None, 0, 1), &session, token.clone())
			.await
			.is_error,
		Some(true)
	);
	assert_eq!(
		payload(
			registry
				.read(params(Some(id), 0, 1), &session, token.clone())
				.await
		),
		first
	);
	assert_eq!(
		registry
			.read(
				params(
					Some(id),
					first["total_bytes"].as_u64().unwrap() as usize + 1,
					1
				),
				&session,
				token.clone()
			)
			.await
			.is_error,
		Some(true)
	);
	registry.close(CloseParams {
		snapshot_id: id.to_owned(),
	});
	let second = payload(registry.read(params(None, 0, 1), &session, token).await);
	assert_eq!(second["records"], 1);
	assert_ne!(first["snapshot_id"], second["snapshot_id"]);
}

#[tokio::test]
async fn concurrent_encoders_share_payload_budget_without_a_count_gate() {
	let session = Arc::new(EvidenceSession::default());
	let registry = Arc::new(ReadbackRegistry::default());
	let reservations: Vec<_> = (0..32)
		.map(|_| registry.reserve_encoding().unwrap())
		.collect();
	assert_eq!(registry.state.lock().unwrap().pending_encoders, 32);
	let token = CancellationToken::new();
	let first = payload(
		registry
			.read(params(None, 0, 1), &session, token.clone())
			.await,
	);
	let id = first["snapshot_id"].as_str().unwrap();
	assert_eq!(
		payload(registry.read(params(Some(id), 0, 1), &session, token).await),
		first
	);
	drop(reservations);
	let mut requests = tokio::task::JoinSet::new();
	for _ in 0..32 {
		let registry = Arc::clone(&registry);
		let session = Arc::clone(&session);
		requests.spawn(async move {
			payload(
				registry
					.read(params(None, 0, 1), &session, CancellationToken::new())
					.await,
			)
		});
	}
	while let Some(reply) = requests.join_next().await {
		assert_eq!(reply.unwrap(), first);
	}
	let state = registry.state.lock().unwrap();
	assert_eq!(state.snapshots.len(), 1);
	assert_eq!(state.pending_encoders, 0);
	assert_eq!(state.pending_bytes, 0);
}

#[test]
fn pending_encoding_charges_aggregate_bytes_and_releases_only_its_own_charge() {
	let registry = ReadbackRegistry {
		limits: Limits {
			snapshot_bytes: 32,
			total_bytes: 32,
			snapshots: 4,
		},
		..Default::default()
	};
	let mut first = registry.reserve_encoding().unwrap();
	let mut second = registry.reserve_encoding().unwrap();
	assert!(first.charge(20).unwrap());
	assert!(second.charge(12).unwrap());
	assert!(!second.charge(1).unwrap());
	assert_eq!(registry.state.lock().unwrap().pending_bytes, 32);
	drop(first);
	assert_eq!(registry.state.lock().unwrap().pending_bytes, 12);
	assert!(second.charge(20).unwrap());
	drop(second);
	assert_eq!(registry.state.lock().unwrap().pending_bytes, 0);
	assert_eq!(registry.state.lock().unwrap().pending_encoders, 0);
}

#[tokio::test]
async fn aborted_encoder_waiter_keeps_accounting_until_the_blocking_owner_finishes() {
	let registry = ReadbackRegistry::default();
	let mut reservation = registry.reserve_encoding().unwrap();
	assert!(reservation.charge(32).unwrap());
	let (started_tx, started_rx) = tokio::sync::oneshot::channel();
	let (release_tx, release_rx) = std::sync::mpsc::channel();
	let (done_tx, done_rx) = tokio::sync::oneshot::channel();
	let waiter = tokio::spawn(async move {
		tokio::task::spawn_blocking(move || {
			started_tx.send(()).unwrap();
			release_rx.recv().unwrap();
			drop(reservation);
			done_tx.send(()).unwrap();
		})
		.await
		.unwrap();
	});
	started_rx.await.unwrap();
	waiter.abort();
	assert!(waiter.await.unwrap_err().is_cancelled());
	assert_eq!(registry.state.lock().unwrap().pending_encoders, 1);
	assert_eq!(registry.state.lock().unwrap().pending_bytes, 32);
	release_tx.send(()).unwrap();
	done_rx.await.unwrap();
	assert_eq!(registry.state.lock().unwrap().pending_encoders, 0);
	assert_eq!(registry.state.lock().unwrap().pending_bytes, 0);
}

#[test]
fn bounded_writer_stops_after_cancellation_without_accepting_more_bytes() {
	let token = CancellationToken::new();
	let mut writer = BoundedWriter {
		bytes: Vec::new(),
		hash: Sha256::new(),
		limit: 16,
		cancellation: token.clone(),
		limit_exceeded: false,
		reservation: None,
	};
	writer.write_all(b"prefix").unwrap();
	token.cancel();
	assert!(writer.write_all(b"suffix").is_err());
	assert_eq!(writer.bytes, b"prefix");
	assert!(!writer.limit_exceeded);
}
