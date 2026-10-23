use super::{JobRecord, read_records_from, start_lock};
use std::sync::Arc;

fn fixture_record(id: &str) -> JobRecord {
	JobRecord {
		id: id.to_owned(),
		host: "test-host".to_owned(),
		ssh_target: "test@example.invalid".to_owned(),
		unit: format!("hepta-runtime-job-{id}"),
		remote_job_dir: format!("/tmp/hepta/jobs/{id}"),
		executable: "/bin/true".to_owned(),
		args: vec![],
		cwd: None,
		env_keys: vec![],
		created_unix_ms: 1,
		idempotency_key: Some("once".to_owned()),
		request_fingerprint: 42,
		launch_state: "launched".to_owned(),
		launch_error: None,
	}
}

#[test]
fn inventory_retains_valid_records_and_ignores_uncommitted_temp_names() {
	let dir = tempfile::tempdir().unwrap();
	let record = fixture_record("valid-1");
	std::fs::write(
		dir.path().join("valid-1.json"),
		serde_json::to_vec(&record).unwrap(),
	)
	.unwrap();
	std::fs::write(dir.path().join("other.json.tmp.123"), b"partial").unwrap();
	let records = read_records_from(dir.path()).unwrap();
	assert_eq!(records.len(), 1);
	assert_eq!(records[0].id, "valid-1");
	assert_eq!(records[0].idempotency_key.as_deref(), Some("once"));
}

#[test]
fn inventory_fails_closed_on_corrupt_record_instead_of_replaying() {
	let dir = tempfile::tempdir().unwrap();
	let record = fixture_record("valid-1");
	std::fs::write(
		dir.path().join("valid-1.json"),
		serde_json::to_vec(&record).unwrap(),
	)
	.unwrap();
	std::fs::write(dir.path().join("damaged.json"), b"{unreadable").unwrap();
	assert!(read_records_from(dir.path()).is_err());
}

#[test]
fn inventory_rejects_record_identity_substitution() {
	let dir = tempfile::tempdir().unwrap();
	let record = fixture_record("original");
	std::fs::write(
		dir.path().join("different.json"),
		serde_json::to_vec(&record).unwrap(),
	)
	.unwrap();
	assert!(read_records_from(dir.path()).is_err());
}

#[cfg(unix)]
#[test]
fn inventory_rejects_symlinked_record() {
	use std::os::unix::fs::symlink;
	let dir = tempfile::tempdir().unwrap();
	let record = fixture_record("real");
	let target = dir.path().join("real.json");
	std::fs::write(&target, serde_json::to_vec(&record).unwrap()).unwrap();
	symlink(&target, dir.path().join("alias.json")).unwrap();
	assert!(read_records_from(dir.path()).is_err());
}

#[test]
fn start_lock_shares_a_host_but_not_distinct_hosts() {
	let one = start_lock("integration-host-a").unwrap();
	let same = start_lock("integration-host-a").unwrap();
	let other = start_lock("integration-host-b").unwrap();
	assert!(Arc::ptr_eq(&one, &same));
	assert!(!Arc::ptr_eq(&one, &other));
}

#[tokio::test]
async fn start_lock_does_not_serialize_unrelated_hosts() {
	let one = start_lock("locked-host-a").unwrap();
	let other = start_lock("unlocked-host-b").unwrap();
	let _held = one.lock().await;
	assert!(start_lock("locked-host-a").unwrap().try_lock().is_err());
	assert!(other.try_lock().is_ok());
}
