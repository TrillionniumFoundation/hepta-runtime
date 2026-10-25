// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Real owner projections over one redb transaction and a validated pending view.
use super::*;
use std::os::unix::fs::OpenOptionsExt;

fn record(owner: &str, tool: &str, time: u128, state: DurableState) -> Record {
	Record {
		request_id: new_id().unwrap(),
		owner: owner.to_owned(),
		tool_name: tool.to_owned(),
		state,
		accepted_unix_ms: time,
		elapsed_ms: (state != DurableState::Unknown).then_some(1),
	}
}

fn database(root: &Path) -> Database {
	let file = std::fs::OpenOptions::new()
		.read(true)
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(root.join("usage-projection.redb"))
		.unwrap();
	open_database(file, Instant::now() + Duration::from_secs(10))
		.unwrap()
		.0
}

// No background index worker is started. The disposable database is built from
// these freshly created originals; all handles leave before TempDir cleanup.
#[test]
fn one_validated_view_has_exact_private_counts_for_four_owners() {
	let root = tempfile::Builder::new()
		.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
		.unwrap();
	let _guard = store_lock().unwrap();
	let hot = open_store(root.path()).unwrap();
	let archive = hot_snapshot(root.path(), &hot).unwrap().1;
	let owners: Vec<_> = (0..4).map(|index| format!("{index:064x}")).collect();
	let records = [
		record(&owners[0], "host_list", 10, DurableState::Completed),
		record(&owners[0], "file_info", 11, DurableState::Unknown),
		record(&owners[1], "file_info", 20, DurableState::Failed),
		record(&owners[2], "host_list", 30, DurableState::Unknown),
	];
	let mut entries = Vec::new();
	for record in &records {
		save_archive_with_sync(&archive, record, false, true).unwrap();
		entries.push(Entry {
			record: record.clone(),
			stamp: stamp(&archive, &format!("{}.json", record.request_id)).unwrap(),
		});
	}
	let active = Arc::new(AtomicBool::new(true));
	active_registry()
		.unwrap()
		.insert(records[3].request_id.clone(), Arc::downgrade(&active));
	let database = database(root.path());
	apply(&database, entries, None, true).unwrap();
	let deadline = Instant::now() + QUERY_BUDGET;
	let view = PendingView::default();
	content::verify_members(&database, &archive, &view, deadline).unwrap();
	let observed = usage_from_view(&database, &view, &owners, deadline).unwrap();
	assert!(!observed.large);
	let values: Vec<_> = observed.values.into_iter().map(Result::unwrap).collect();
	assert_eq!(values[0]["total_requests"], 2);
	assert_eq!(values[0]["completed"], 1);
	assert_eq!(values[0]["unknown"], 1);
	assert_eq!(values[0]["active"], 0);
	assert_eq!(
		values[0]["tool_counts"],
		json!({"file_info":1,"host_list":1})
	);
	assert_eq!(values[0]["first_accepted_unix_ms"], 10);
	assert_eq!(values[0]["last_accepted_unix_ms"], 11);
	assert_eq!(values[1]["total_requests"], 1);
	assert_eq!(values[1]["failed"], 1);
	assert_eq!(values[1]["tool_counts"], json!({"file_info":1}));
	assert_eq!(values[2]["active"], 1);
	assert_eq!(values[2]["unknown"], 0);
	assert_eq!(values[2]["tool_counts"], json!({"host_list":1}));
	assert_eq!(values[3]["total_requests"], 0);
	assert_eq!(values[3]["tool_counts"], json!({}));
	assert!(values[3]["first_accepted_unix_ms"].is_null());
	assert!(values[3]["last_accepted_unix_ms"].is_null());
	for value in values {
		assert_eq!(value["scope"], "same_verified_credential_or_native_session");
		assert_eq!(value["contains_parameters_or_output"], false);
	}
}

#[test]
fn legitimate_completion_and_addition_share_the_same_readonly_pending_view() {
	let root = tempfile::Builder::new()
		.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
		.unwrap();
	let _guard = store_lock().unwrap();
	let hot = open_store(root.path()).unwrap();
	let archive = hot_snapshot(root.path(), &hot).unwrap().1;
	let owners = ["a".repeat(64), "b".repeat(64), "c".repeat(64)];
	let original = record(&owners[0], "host_list", 10, DurableState::Unknown);
	save_archive_with_sync(&archive, &original, false, true).unwrap();
	let first = Entry {
		record: original.clone(),
		stamp: stamp(&archive, &format!("{}.json", original.request_id)).unwrap(),
	};
	let database = database(root.path());
	apply(&database, [first.clone()], None, true).unwrap();
	let mut completed = original.clone();
	completed.state = DurableState::Completed;
	completed.elapsed_ms = Some(5);
	save_archive_with_sync(&archive, &completed, true, true).unwrap();
	let added = record(&owners[1], "file_info", 20, DurableState::Unknown);
	save_archive_with_sync(&archive, &added, false, true).unwrap();
	let mut pending = BTreeMap::new();
	for record in [completed, added] {
		let entry = Entry {
			stamp: stamp(&archive, &format!("{}.json", record.request_id)).unwrap(),
			record,
		};
		pending.insert(id(&entry.record.request_id).unwrap(), entry);
	}
	let before_count = database
		.begin_read()
		.unwrap()
		.open_table(ROWS)
		.unwrap()
		.len()
		.unwrap();
	let deadline = Instant::now() + QUERY_BUDGET;
	let view = PendingView::new(&database, &pending, deadline).unwrap();
	content::verify_members(&database, &archive, &view, deadline).unwrap();
	let values: Vec<_> = usage_from_view(&database, &view, &owners, deadline)
		.unwrap()
		.values
		.into_iter()
		.map(Result::unwrap)
		.collect();
	assert_eq!(values[0]["completed"], 1);
	assert_eq!(values[0]["unknown"], 0);
	assert_eq!(values[0]["total_requests"], 1);
	assert_eq!(values[1]["unknown"], 1);
	assert_eq!(values[1]["total_requests"], 1);
	assert_eq!(values[1]["first_accepted_unix_ms"], 20);
	assert_eq!(values[2]["total_requests"], 0);
	assert_eq!(pending.len(), 2);
	let transaction = database.begin_read().unwrap();
	let rows = transaction.open_table(ROWS).unwrap();
	assert_eq!(rows.len().unwrap(), before_count);
	let unchanged = codec::decode(
		rows.get(id(&original.request_id).unwrap().as_slice())
			.unwrap()
			.unwrap()
			.value(),
	)
	.unwrap();
	assert!(unchanged.record == first.record);
	assert!(unchanged.stamp == first.stamp);
}

#[test]
fn a_real_owner_wire_budget_error_stays_local_in_the_shared_projection_transaction() {
	// This derived-table fixture tests projection bounds only; it is not a
	// complete archive or an input to read_snapshot/content validation.
	let root = tempfile::tempdir().unwrap();
	let database = database(root.path());
	let owners = ["a".repeat(64), "b".repeat(64)];
	let transaction = database.begin_write().unwrap();
	{
		transaction.open_table(ROWS).unwrap();
		transaction.open_table(ORDER).unwrap();
		let mut counts = transaction.open_table(COUNTS).unwrap();
		let mut prefix = id(&owners[0]).unwrap().to_vec();
		prefix.push(b't');
		for number in 0..600u16 {
			let mut key = prefix.clone();
			key.extend_from_slice("t".repeat(62).as_bytes());
			key.push(b'a' + (number / 26) as u8);
			key.push(b'a' + (number % 26) as u8);
			counts.insert(key.as_slice(), 1u64).unwrap();
		}
	}
	transaction.commit().unwrap();
	let mut values = usage_from_view(
		&database,
		&PendingView::default(),
		&owners,
		Instant::now() + QUERY_BUDGET,
	)
	.unwrap()
	.values
	.into_iter();
	assert!(values
		.next()
		.unwrap()
		.unwrap_err()
		.to_string()
		.contains("wire budget"));
	let healthy = values.next().unwrap().unwrap();
	assert_eq!(healthy["total_requests"], 0);
	assert_eq!(healthy["tool_counts"], json!({}));
	assert!(values.next().is_none());
}
