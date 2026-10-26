// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Isolated cohort barriers, resource bounds, failure and exact-scope fixtures.
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

fn root() -> tempfile::TempDir {
	tempfile::Builder::new()
		.permissions(std::fs::Permissions::from_mode(0o700))
		.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
		.unwrap()
}
fn begin(root: &Path, owner: char, tool: &str, target: Option<String>) -> Work {
	Work::Begin(Begin {
		root: root.into(),
		owner: owner.to_string().repeat(64),
		tool: tool.into(),
		target,
	})
}
fn admissions(root: &Path, count: usize) -> Vec<Work> {
	(0..count)
		.map(|_| begin(root, 'a', "host_list", None))
		.collect()
}
fn barrier(directory: &File, _: Barrier) -> Result<()> {
	directory.sync_all()?;
	Ok(())
}
fn tickets(values: Vec<Result<Outcome>>) -> Vec<RequestTicket> {
	values
		.into_iter()
		.map(|value| match value.unwrap() {
			Outcome::Begun(ticket) => ticket,
			Outcome::Finished => panic!("expected an admission"),
		})
		.collect()
}
fn names(root: &Path, name: &str) -> usize {
	std::fs::read_dir(root.join(name)).unwrap().count()
}

fn fixed_ticket(directory: &File, archive: &Archive, prefix: u8, suffix: u64) -> RequestTicket {
	let record = Record {
		request_id: format!("{prefix:02x}{suffix:062x}"),
		owner: "a".repeat(64),
		tool_name: "host_list".into(),
		state: DurableState::Unknown,
		accepted_unix_ms: 100 + suffix as u128,
		elapsed_ms: None,
	};
	save_archive_with_sync(archive, &record, false, true).unwrap();
	save(directory, &record, false).unwrap();
	RequestTicket {
		directory: directory.try_clone().unwrap(),
		archive: archive.try_clone().unwrap(),
		hot_present: true,
		record,
		started: Instant::now(),
		active: Arc::new(AtomicBool::new(true)),
		_read_pin: None,
	}
}

#[test]
fn mixed_cohort_syncs_every_physical_archive_directory_before_hot_and_ack() {
	let root = root();
	let (archive, prepared) = {
		let _guard = store_lock().unwrap();
		let directory = open_store(root.path()).unwrap();
		let archive = open_archive(root.path()).unwrap();
		let legacy = fixed_ticket(&directory, &archive, 0x10, 1);
		archive.initialize_shards().unwrap();
		let first = fixed_ticket(&directory, &archive, 0x00, 2);
		let last = fixed_ticket(&directory, &archive, 0xff, 3);
		(archive, vec![legacy, first, last])
	};
	let expected: HashSet<_> = prepared
		.iter()
		.map(|ticket| {
			directory_identity(
				archive
					.directory_for_existing(&format!("{}.json", ticket.request_id()))
					.unwrap(),
			)
			.unwrap()
		})
		.collect();
	assert_eq!(expected.len(), 3);
	let active: Vec<_> = prepared
		.iter()
		.map(|ticket| ticket.active.clone())
		.collect();
	let mut observed = HashSet::new();
	let mut hot = 0;
	let works = prepared
		.into_iter()
		.map(|ticket| Work::Finish(root.path().into(), ticket, AuditCompletion::Completed))
		.collect();
	let result = execute(works, &mut |directory, phase| {
		assert!(active.iter().all(|value| value.load(Ordering::Acquire)));
		if phase == Barrier::Archive {
			assert_eq!(hot, 0);
			assert!(observed.insert(directory_identity(directory)?));
		} else {
			assert_eq!(observed, expected);
			hot += 1;
		}
		barrier(directory, phase)
	})
	.unwrap();
	assert_eq!(observed, expected);
	assert_eq!(hot, 1);
	assert!(result
		.into_iter()
		.all(|value| matches!(value, Ok(Outcome::Finished))));
	assert!(active.iter().all(|value| !value.load(Ordering::Acquire)));
}

#[test]
fn failed_shard_barrier_drains_other_directories_and_refuses_every_completion() {
	let root = root();
	let (archive, prepared) = {
		let _guard = store_lock().unwrap();
		let directory = open_store(root.path()).unwrap();
		let archive = open_archive(root.path()).unwrap();
		archive.initialize_shards().unwrap();
		let first = fixed_ticket(&directory, &archive, 0x00, 11);
		let last = fixed_ticket(&directory, &archive, 0xff, 12);
		(archive, vec![first, last])
	};
	let ids: Vec<_> = prepared
		.iter()
		.map(|ticket| ticket.request_id().to_owned())
		.collect();
	let active: Vec<_> = prepared
		.iter()
		.map(|ticket| ticket.active.clone())
		.collect();
	let mut synced = HashSet::new();
	let works = prepared
		.into_iter()
		.map(|ticket| Work::Finish(root.path().into(), ticket, AuditCompletion::Completed))
		.collect();
	assert!(execute(works, &mut |directory, phase| {
		assert!(phase == Barrier::Archive);
		let inserted = synced.insert(directory_identity(directory)?);
		assert!(inserted);
		if synced.len() == 1 {
			return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
		}
		barrier(directory, phase)
	})
	.is_err());
	assert_eq!(synced.len(), 2);
	assert!(active.iter().all(|value| value.load(Ordering::Acquire)));
	let hot = open_store(root.path()).unwrap();
	for id in ids {
		assert!(read_record(&hot, &format!("{id}.json")).unwrap().state == DurableState::Unknown);
		assert!(
			archive.read_record(&format!("{id}.json")).unwrap().state == DurableState::Completed
		);
	}
}

#[test]
fn duplicate_internal_completion_tickets_keep_the_first_terminal_original() {
	let root = root();
	let first = tickets(execute(admissions(root.path(), 1), &mut barrier).unwrap())
		.pop()
		.unwrap();
	let second = RequestTicket {
		directory: first.directory.try_clone().unwrap(),
		archive: first.archive.try_clone().unwrap(),
		hot_present: first.hot_present,
		record: first.record.clone(),
		started: first.started,
		active: first.active.clone(),
		_read_pin: None,
	};
	let id = first.record.request_id.clone();
	let values = execute(
		vec![
			Work::Finish(root.path().into(), first, AuditCompletion::Completed),
			Work::Finish(root.path().into(), second, AuditCompletion::Failed),
		],
		&mut barrier,
	)
	.unwrap();
	assert!(values[0].is_ok() && values[1].is_err());
	let archive = open_archive(root.path()).unwrap();
	let record = archive.read_record(&format!("{id}.json")).unwrap();
	assert!(record.state == DurableState::Completed);
	let hot = open_store(root.path()).unwrap();
	assert!(read_record(&hot, &format!("{id}.json")).unwrap() == record);
}

#[test]
fn one_file_sync_failure_preserves_errno_and_other_admissions_in_each_publication_phase() {
	for failed_phase in [Barrier::Archive, Barrier::Hot] {
		let root = root();
		let mut existing = tickets(execute(admissions(root.path(), 1), &mut barrier).unwrap());
		let existing = existing.pop().unwrap();
		let existing_id = existing.request_id().to_owned();
		assert!(execute(
			vec![Work::Finish(
				root.path().into(),
				existing,
				AuditCompletion::Completed
			)],
			&mut barrier
		)
		.unwrap()
		.into_iter()
		.all(|result| result.is_ok()));
		let existing_path = root
			.path()
			.join(ARCHIVE_NAME)
			.join(format!("{existing_id}.json"));
		let existing_bytes = std::fs::read(&existing_path).unwrap();
		let mut calls = 0;
		let mut refused = None;
		let mut barriers = Vec::new();
		let values = execute_with_staging(
			admissions(root.path(), 8),
			&mut |directory, phase| {
				barriers.push(phase);
				barrier(directory, phase)
			},
			&mut |records| {
				calls += 1;
				let inject = (calls == 1 && failed_phase == Barrier::Archive)
					|| (calls == 2 && failed_phase == Barrier::Hot);
				if !inject {
					return stage::save_many(records);
				}
				refused = Some(records[3].1.clone());
				stage::save_many_with_barrier(
					records,
					Arc::new(|file: &File| {
						file.sync_all()?;
						Ok(())
					}),
					&|files, operation| {
						files
							.iter()
							.enumerate()
							.map(|(slot, file)| {
								if slot == 3 {
									Err(anyhow::Error::new(std::io::Error::from_raw_os_error(
										libc::EIO,
									))
									.context("injected single audit file barrier"))
								} else {
									operation(file)
								}
							})
							.collect()
					},
				)
			},
		)
		.unwrap();
		assert_eq!(calls, 2);
		assert!(barriers == vec![Barrier::Archive, Barrier::Hot]);
		assert_eq!(values.len(), 8);
		let refused = refused.unwrap();
		let mut accepted = Vec::new();
		for (slot, value) in values.into_iter().enumerate() {
			if slot == 3 {
				let Err(error) = value else {
					panic!("failed file must not receive a dispatch ticket");
				};
				assert_eq!(
					error
						.chain()
						.find_map(|error| error.downcast_ref::<std::io::Error>())
						.and_then(std::io::Error::raw_os_error),
					Some(libc::EIO)
				);
			} else {
				let Ok(Outcome::Begun(ticket)) = value else {
					panic!("independent admission refused");
				};
				assert!(is_dispatch_active(ticket.request_id()).unwrap());
				accepted.push(ticket);
			}
		}
		assert_eq!(accepted.len(), 7);
		assert!(!is_dispatch_active(&refused.request_id).unwrap());
		assert!(!root
			.path()
			.join(STORE_NAME)
			.join(format!("{}.json", refused.request_id))
			.exists());
		let archived = root
			.path()
			.join(ARCHIVE_NAME)
			.join(format!("{}.json", refused.request_id));
		if failed_phase == Barrier::Archive {
			assert!(!archived.exists());
		} else {
			assert_eq!(
				std::fs::read(archived).unwrap(),
				serde_json::to_vec(&refused).unwrap()
			);
			assert!(refused.state == DurableState::Unknown);
		}
		assert_eq!(names(root.path(), STORE_NAME), 8);
		assert_eq!(
			names(root.path(), ARCHIVE_NAME),
			if failed_phase == Barrier::Archive {
				8
			} else {
				9
			}
		);
		for folder in [STORE_NAME, ARCHIVE_NAME] {
			assert!(std::fs::read_dir(root.path().join(folder))
				.unwrap()
				.all(|entry| {
					!entry
						.unwrap()
						.file_name()
						.to_string_lossy()
						.ends_with(".tmp")
				}));
		}
		let completed = execute(
			accepted
				.into_iter()
				.map(|ticket| Work::Finish(root.path().into(), ticket, AuditCompletion::Completed))
				.collect(),
			&mut barrier,
		)
		.unwrap();
		assert!(completed.into_iter().all(|value| value.is_ok()));
		assert_eq!(std::fs::read(existing_path).unwrap(), existing_bytes);
	}
}

#[test]
fn cohort_crash_child() {
	let Some(root) = std::env::var_os("HEPTA_TEST_COHORT_CRASH_ROOT") else {
		return;
	};
	let root = PathBuf::from(root);
	let phase = std::env::var("HEPTA_TEST_COHORT_CRASH_PHASE").unwrap();
	let output = execute(admissions(&root, 8), &mut |directory, barrier| {
		if phase == "before_archive_sync" && barrier == Barrier::Archive {
			unsafe { libc::_exit(86) };
		}
		directory.sync_all()?;
		if (phase == "after_archive_sync" && barrier == Barrier::Archive)
			|| (phase == "after_hot_sync" && barrier == Barrier::Hot)
		{
			unsafe { libc::_exit(86) };
		}
		Ok(())
	});
	// This is a fixture dispatch sentinel: a process which crashes before the
	// acknowledgement must never reach even this local, non-effectful handler.
	if output.is_ok() {
		std::fs::write(root.join("handler-dispatched"), b"unexpected").unwrap();
	}
	panic!("crash fixture failed to terminate at its selected barrier");
}

#[test]
fn process_crash_before_ack_preserves_unknown_ids_and_never_replays() {
	for phase in [
		"before_archive_sync",
		"after_archive_sync",
		"after_hot_sync",
	] {
		let root = root();
		let mut child = std::process::Command::new(std::env::current_exe().unwrap())
			.args([
				"mcp::runtime::request_audit::batch::tests::cohort_crash_child",
				"--exact",
				"--test-threads=1",
			])
			.env("HEPTA_TEST_COHORT_CRASH_ROOT", root.path())
			.env("HEPTA_TEST_COHORT_CRASH_PHASE", phase)
			.stdout(std::process::Stdio::null())
			.stderr(std::process::Stdio::null())
			.spawn()
			.unwrap();
		let deadline = Instant::now() + Duration::from_secs(60);
		let status = loop {
			if let Some(status) = child.try_wait().unwrap() {
				break status;
			}
			if Instant::now() >= deadline {
				child.kill().unwrap();
				child.wait().unwrap();
				panic!("crash fixture did not reach its barrier");
			}
			std::thread::sleep(Duration::from_millis(10));
		};
		assert_eq!(status.code(), Some(86));
		assert!(!root.path().join("handler-dispatched").exists());
		let mut original = std::collections::BTreeMap::new();
		for item in std::fs::read_dir(root.path().join(ARCHIVE_NAME)).unwrap() {
			let path = item.unwrap().path();
			let bytes = std::fs::read(&path).unwrap();
			let record: Record = serde_json::from_slice(&bytes).unwrap();
			assert!(record.state == DurableState::Unknown && record.elapsed_ms.is_none());
			assert!(!is_dispatch_active(&record.request_id).unwrap());
			original.insert(path, bytes);
		}
		assert_eq!(original.len(), 8);
		assert_eq!(
			names(root.path(), STORE_NAME),
			if phase == "after_hot_sync" { 8 } else { 0 }
		);
		prepare_at(root.path()).unwrap();
		let history: Value = serde_json::from_str(
			&archive_history_at(
				root.path(),
				&"a".repeat(64),
				RequestHistoryParams {
					after_id: None,
					limit: Some(32),
				},
			)
			.unwrap(),
		)
		.unwrap();
		assert_eq!(history["requests"].as_array().unwrap().len(), 8);
		assert!(history["requests"]
			.as_array()
			.unwrap()
			.iter()
			.all(|record| record["state"] == "unknown"));
		for (path, bytes) in original {
			assert_eq!(std::fs::read(path).unwrap(), bytes);
		}
		assert!(!root.path().join("handler-dispatched").exists());
	}
}

#[test]
fn cohort_admission_has_one_archive_then_one_hot_barrier_without_early_active_markers() {
	let root = root();
	let mut stages = Vec::new();
	let values = execute(admissions(root.path(), 8), &mut |directory, phase| {
		stages.push(phase);
		assert_eq!(names(root.path(), ARCHIVE_NAME), 8);
		if phase == Barrier::Archive {
			assert_eq!(names(root.path(), STORE_NAME), 0);
			for name in std::fs::read_dir(root.path().join(ARCHIVE_NAME))? {
				let record: Record = serde_json::from_slice(&std::fs::read(name?.path())?)?;
				assert!(!is_dispatch_active(&record.request_id)?);
			}
		} else {
			assert_eq!(names(root.path(), STORE_NAME), 8);
		}
		directory.sync_all()?;
		Ok(())
	})
	.unwrap();
	assert!(stages == vec![Barrier::Archive, Barrier::Hot]);
	let tickets = tickets(values);
	for ticket in tickets {
		assert!(is_dispatch_active(ticket.request_id()).unwrap());
		assert_eq!(
			std::fs::metadata(
				root.path()
					.join(STORE_NAME)
					.join(format!("{}.json", ticket.request_id()))
			)
			.unwrap()
			.permissions()
			.mode() & 0o777,
			0o600
		);
	}
}

#[test]
fn cohort_completion_updates_every_cached_member_after_both_barriers() {
	let root = root();
	let admitted = tickets(execute(admissions(root.path(), 8), &mut barrier).unwrap());
	let ids: Vec<_> = admitted.iter().map(|t| t.request_id().to_owned()).collect();
	let work = admitted
		.into_iter()
		.map(|t| Work::Finish(root.path().into(), t, AuditCompletion::Completed))
		.collect();
	let mut stages = Vec::new();
	let output = execute(work, &mut |directory, phase| {
		stages.push(phase);
		if phase == Barrier::Archive {
			for id in &ids {
				let hot: Record = serde_json::from_slice(&std::fs::read(
					root.path().join(STORE_NAME).join(format!("{id}.json")),
				)?)?;
				assert!(hot.state == DurableState::Unknown);
			}
		}
		directory.sync_all()?;
		Ok(())
	})
	.unwrap();
	assert!(stages == vec![Barrier::Archive, Barrier::Hot]);
	assert!(output
		.into_iter()
		.all(|r| matches!(r, Ok(Outcome::Finished))));
	let _guard = store_lock().unwrap();
	let dir = open_store(root.path()).unwrap();
	let (cached, _) = hot_snapshot(root.path(), &dir).unwrap();
	assert_eq!(cached.len(), 8);
	assert!(cached
		.iter()
		.all(|r| r.state == DurableState::Completed && r.elapsed_ms.is_some()));
	assert!(ids.iter().all(|id| !is_dispatch_active(id).unwrap()));
}

#[test]
fn single_completion_updates_only_its_cached_member_after_both_barriers() {
	let root = root();
	let mut admitted = tickets(execute(admissions(root.path(), 8), &mut barrier).unwrap());
	let ticket = admitted.pop().unwrap();
	let id = ticket.request_id().to_owned();
	let active = ticket.active.clone();
	// A single completion must not reread or rewrite an unrelated unsafe leaf.
	let peer = root
		.path()
		.join(STORE_NAME)
		.join(format!("{}.json", admitted[0].request_id()));
	let peer_bytes = std::fs::read(&peer).unwrap();
	std::fs::set_permissions(&peer, std::fs::Permissions::from_mode(0o700)).unwrap();
	let mut stages = Vec::new();
	let output = execute(
		vec![Work::Finish(
			root.path().into(),
			ticket,
			AuditCompletion::Completed,
		)],
		&mut |directory, phase| {
			assert!(active.load(Ordering::Acquire));
			stages.push(phase);
			directory.sync_all()?;
			Ok(())
		},
	)
	.unwrap();
	assert!(matches!(
		output.into_iter().next().unwrap(),
		Ok(Outcome::Finished)
	));
	assert!(stages == vec![Barrier::Archive, Barrier::Hot]);
	assert!(!active.load(Ordering::Acquire));
	assert_eq!(std::fs::read(&peer).unwrap(), peer_bytes);
	assert_eq!(
		std::fs::metadata(&peer).unwrap().permissions().mode() & 0o777,
		0o700
	);
	let _guard = store_lock().unwrap();
	let directory = open_store(root.path()).unwrap();
	let (cached, _) = hot_snapshot(root.path(), &directory).unwrap();
	assert_eq!(cached.len(), 8);
	assert_eq!(
		cached
			.iter()
			.filter(|record| record.state == DurableState::Completed)
			.count(),
		1
	);
	assert!(
		cached
			.iter()
			.find(|record| record.request_id == id)
			.unwrap()
			.state == DurableState::Completed
	);
}

#[test]
fn single_completion_refuses_replaced_hot_directory_before_changing_archive() {
	let root = root();
	let ticket = tickets(execute(admissions(root.path(), 1), &mut barrier).unwrap())
		.pop()
		.unwrap();
	let archive = root
		.path()
		.join(ARCHIVE_NAME)
		.join(format!("{}.json", ticket.request_id()));
	let before = std::fs::read(&archive).unwrap();
	std::fs::rename(
		root.path().join(STORE_NAME),
		root.path().join("original-hot"),
	)
	.unwrap();
	std::fs::create_dir(root.path().join(STORE_NAME)).unwrap();
	std::fs::set_permissions(
		root.path().join(STORE_NAME),
		std::fs::Permissions::from_mode(0o700),
	)
	.unwrap();
	let mut reached = false;
	let output = execute(
		vec![Work::Finish(
			root.path().into(),
			ticket,
			AuditCompletion::Completed,
		)],
		&mut |_, _| {
			reached = true;
			Ok(())
		},
	)
	.unwrap();
	assert!(output[0].is_err());
	assert!(!reached);
	assert_eq!(std::fs::read(archive).unwrap(), before);
	assert_eq!(names(root.path(), STORE_NAME), 0);
}

#[test]
fn single_completion_does_not_acknowledge_a_failed_durability_barrier() {
	for failed in [Barrier::Archive, Barrier::Hot] {
		let root = root();
		let ticket = tickets(execute(admissions(root.path(), 1), &mut barrier).unwrap())
			.pop()
			.unwrap();
		let active = ticket.active.clone();
		let output = execute(
			vec![Work::Finish(
				root.path().into(),
				ticket,
				AuditCompletion::Completed,
			)],
			&mut |directory, phase| {
				if phase == failed {
					bail!("isolated single completion barrier failure");
				}
				barrier(directory, phase)
			},
		)
		.unwrap();
		assert!(output[0].is_err());
		assert!(active.load(Ordering::Acquire));
	}
}

#[test]
fn failed_archive_or_hot_barrier_never_returns_a_dispatch_ticket() {
	for failed in [Barrier::Archive, Barrier::Hot] {
		let root = root();
		let result = execute(admissions(root.path(), 4), &mut |directory, phase| {
			if phase == failed {
				bail!("fixture barrier failure");
			}
			barrier(directory, phase)
		});
		assert!(result.is_err());
		assert_eq!(names(root.path(), ARCHIVE_NAME), 4);
		assert_eq!(
			names(root.path(), STORE_NAME),
			if failed == Barrier::Archive { 0 } else { 4 }
		);
		for item in std::fs::read_dir(root.path().join(ARCHIVE_NAME)).unwrap() {
			let record: Record =
				serde_json::from_slice(&std::fs::read(item.unwrap().path()).unwrap()).unwrap();
			assert!(record.state == DurableState::Unknown && record.elapsed_ms.is_none());
			assert!(!is_dispatch_active(&record.request_id).unwrap());
		}
	}
}

#[test]
fn cross_owner_read_refuses_individually_without_poisoning_valid_admission() {
	let root = root();
	let first = tickets(execute(admissions(root.path(), 1), &mut barrier).unwrap())
		.pop()
		.unwrap();
	let id = first.request_id().to_owned();
	let result = execute(
		vec![
			begin(root.path(), 'b', "request_result", Some(id.clone())),
			begin(root.path(), 'a', "host_list", None),
		],
		&mut barrier,
	)
	.unwrap();
	assert!(result[0].is_err());
	assert!(result[1].is_ok());
	assert!(!read_pins().unwrap().contains_key(&id));
	assert!(is_dispatch_active(&id).unwrap());
}

#[test]
fn mixed_roots_and_oversized_cohorts_refuse_before_storage_changes() {
	let one = root();
	let two = root();
	assert!(execute(
		vec![
			begin(one.path(), 'a', "host_list", None),
			begin(two.path(), 'a', "host_list", None)
		],
		&mut barrier
	)
	.is_err());
	assert!(execute(admissions(one.path(), MAX_BATCH + 1), &mut barrier).is_err());
	assert_eq!(std::fs::read_dir(one.path()).unwrap().count(), 0);
	assert_eq!(std::fs::read_dir(two.path()).unwrap().count(), 0);
}

#[test]
fn replaced_archive_after_barrier_refuses_without_writing_the_replacement() {
	let root = root();
	let result = execute(admissions(root.path(), 2), &mut |directory, phase| {
		directory.sync_all()?;
		if phase == Barrier::Archive {
			std::fs::rename(
				root.path().join(ARCHIVE_NAME),
				root.path().join("original-archive"),
			)?;
			std::fs::create_dir(root.path().join(ARCHIVE_NAME))?;
			std::fs::set_permissions(
				root.path().join(ARCHIVE_NAME),
				std::fs::Permissions::from_mode(0o700),
			)?;
		}
		Ok(())
	});
	assert!(result.is_err());
	assert_eq!(names(root.path(), ARCHIVE_NAME), 0);
	assert_eq!(names(root.path(), "original-archive"), 2);
}

fn job(work: Work) -> Job {
	let (reply, _) = mpsc::channel();
	Job { work, reply }
}
#[test]
fn queue_bound_refuses_before_any_dispatch_or_storage_write() {
	let root = root();
	let queue = Arc::new(Queue::default());
	{
		let mut q = queue.pending.lock().unwrap();
		for work in admissions(root.path(), MAX_QUEUED) {
			q.jobs.push_back(job(work));
		}
	}
	let coordinator = Coordinator {
		queue,
		processor: Arc::new(|_| panic!("full queue must not execute")),
		worker: None,
	};
	assert!(coordinator
		.begin(root.path().into(), "a".repeat(64), "host_list".into(), None)
		.is_err());
	assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
	assert_eq!(
		coordinator.queue.pending.lock().unwrap().jobs.len(),
		MAX_QUEUED
	);
}

#[test]
fn queue_preserves_fifo_cohort_kind_root_and_batch_bound() {
	let one = root();
	let two = root();
	let queue = Queue::default();
	{
		let mut q = queue.pending.lock().unwrap();
		for work in admissions(one.path(), 33) {
			q.jobs.push_back(job(work));
		}
		q.jobs
			.push_back(job(begin(two.path(), 'a', "host_list", None)));
		for work in admissions(one.path(), 36) {
			q.jobs.push_back(job(work));
		}
	}
	assert_eq!(queue.take().unwrap().unwrap().len(), 32);
	queue.completed();
	assert_eq!(queue.take().unwrap().unwrap().len(), 1);
	queue.completed();
	let other = queue.take().unwrap().unwrap();
	assert_eq!(other.len(), 1);
	assert_eq!(other[0].work.key().0, two.path());
	queue.completed();
	assert_eq!(queue.take().unwrap().unwrap().len(), 32);
	queue.completed();
	assert_eq!(queue.take().unwrap().unwrap().len(), 4);
	queue.completed();
	queue.close();
	assert!(queue.take().unwrap().is_none());
}

#[test]
fn idle_caller_owns_processor_until_ack_and_backlog_keeps_fifo() {
	let first = root();
	let second = root();
	let third = root();
	let (entered, wait_entered) = mpsc::channel();
	let (resume, wait_resume) = mpsc::channel();
	let wait_resume = Mutex::new(wait_resume);
	let seen = Arc::new(Mutex::new(Vec::new()));
	let observed = seen.clone();
	let coordinator = Arc::new(
		Coordinator::with_processor(Arc::new(move |works| {
			let mut seen = observed.lock().unwrap();
			let initial = seen.is_empty();
			for work in &works {
				seen.push((work.key().0.to_owned(), std::thread::current().id()));
			}
			drop(seen);
			if initial {
				entered.send(()).unwrap();
				wait_resume.lock().unwrap().recv().unwrap();
			}
			works.into_iter().map(|_| Ok(Outcome::Finished)).collect()
		}))
		.unwrap(),
	);
	let caller = coordinator.clone();
	let path = first.path().to_owned();
	let active = std::thread::spawn(move || {
		let identity = std::thread::current().id();
		assert!(matches!(
			caller.submit(begin(&path, 'a', "host_list", None)),
			Ok(Outcome::Finished)
		));
		identity
	});
	wait_entered.recv_timeout(Duration::from_secs(60)).unwrap();
	let mut replies = Vec::new();
	{
		let mut pending = coordinator.queue.pending.lock().unwrap();
		assert!(pending.running);
		for root in [second.path(), third.path()] {
			let (reply, receive) = mpsc::channel();
			pending.jobs.push_back(Job {
				work: begin(root, 'a', "host_list", None),
				reply,
			});
			replies.push(receive);
		}
	}
	coordinator.queue.ready.notify_one();
	assert_eq!(seen.lock().unwrap().len(), 1);
	assert!(replies
		.iter()
		.all(|reply| matches!(reply.try_recv(), Err(mpsc::TryRecvError::Empty))));
	resume.send(()).unwrap();
	let first_thread = active.join().unwrap();
	for reply in replies {
		assert!(matches!(
			reply.recv_timeout(Duration::from_secs(60)).unwrap(),
			Ok(Outcome::Finished)
		));
	}
	let seen = seen.lock().unwrap();
	assert_eq!(
		seen.iter()
			.map(|value| value.0.as_path())
			.collect::<Vec<_>>(),
		vec![first.path(), second.path(), third.path()]
	);
	assert_eq!(seen[0].1, first_thread);
	assert_ne!(seen[1].1, first_thread);
}

#[test]
fn inline_processor_panic_closes_and_wakes_all_queued_waiters() {
	let root = root();
	let path = root.path().to_owned();
	let (entered, wait_entered) = mpsc::channel();
	let (resume, wait_resume) = mpsc::channel();
	let wait_resume = Mutex::new(wait_resume);
	let coordinator = Arc::new(
		Coordinator::with_processor(Arc::new(move |_| {
			entered.send(()).unwrap();
			wait_resume.lock().unwrap().recv().unwrap();
			panic!("isolated inline fixture");
		}))
		.unwrap(),
	);
	let caller = coordinator.clone();
	let active = std::thread::spawn(move || caller.submit(begin(&path, 'a', "host_list", None)));
	wait_entered.recv_timeout(Duration::from_secs(60)).unwrap();
	let mut waiters = Vec::new();
	{
		let mut pending = coordinator.queue.pending.lock().unwrap();
		for work in admissions(root.path(), MAX_QUEUED) {
			let (reply, receive) = mpsc::channel();
			pending.jobs.push_back(Job { work, reply });
			waiters.push(receive);
		}
	}
	assert!(coordinator
		.submit(begin(root.path(), 'a', "host_list", None))
		.is_err());
	resume.send(()).unwrap();
	assert!(active.join().unwrap().is_err());
	assert!(waiters.into_iter().all(|waiter| waiter
		.recv_timeout(Duration::from_secs(60))
		.unwrap()
		.is_err()));
	assert!(!coordinator.is_ready());
	assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn worker_panic_refuses_waiter_and_future_admission_instead_of_hanging() {
	let root = root();
	let coordinator =
		Coordinator::with_processor(Arc::new(|_| panic!("isolated worker fixture"))).unwrap();
	assert!(coordinator
		.begin(root.path().into(), "a".repeat(64), "host_list".into(), None)
		.is_err());
	assert!(coordinator
		.begin(root.path().into(), "a".repeat(64), "host_list".into(), None)
		.is_err());
	assert!(!coordinator.is_ready());
	assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn lost_reply_never_replays_and_leaves_exact_unknown_identity() {
	let root = root();
	let (done, wait) = mpsc::channel();
	let coordinator = Coordinator::with_processor(Arc::new(move |works| {
		let result = execute(works, &mut barrier).unwrap();
		let _ = done.send(());
		result
	}))
	.unwrap();
	{
		let mut q = coordinator.queue.pending.lock().unwrap();
		q.jobs
			.push_back(job(begin(root.path(), 'a', "host_list", None)));
	}
	coordinator.queue.ready.notify_one();
	wait.recv_timeout(Duration::from_secs(60)).unwrap();
	drop(coordinator);
	assert_eq!(names(root.path(), ARCHIVE_NAME), 1);
	for entry in std::fs::read_dir(root.path().join(ARCHIVE_NAME)).unwrap() {
		let r: Record =
			serde_json::from_slice(&std::fs::read(entry.unwrap().path()).unwrap()).unwrap();
		assert!(r.state == DurableState::Unknown);
		assert!(!is_dispatch_active(&r.request_id).unwrap());
	}
}

#[test]
fn active_capacity_and_lookup_pins_survive_cohort_eviction() {
	let root = root();
	let mut active = Vec::new();
	for _ in 0..MAX_OWNER / MAX_BATCH {
		active.extend(tickets(
			execute(admissions(root.path(), MAX_BATCH), &mut barrier).unwrap(),
		));
	}
	assert_eq!(active.len(), MAX_OWNER);
	let archived_only = tickets(execute(admissions(root.path(), 8), &mut barrier).unwrap());
	assert!(archived_only.iter().all(|t| !t.hot_present));
	assert_eq!(names(root.path(), STORE_NAME), MAX_OWNER);
	let oldest = {
		let _guard = store_lock().unwrap();
		entries(&open_store(root.path()).unwrap()).unwrap()[0]
			.request_id
			.clone()
	};
	drop(active);
	drop(archived_only);
	let mut work = vec![begin(
		root.path(),
		'a',
		"request_result",
		Some(oldest.clone()),
	)];
	work.extend(admissions(root.path(), 15));
	let readers = tickets(execute(work, &mut barrier).unwrap());
	assert!(root
		.path()
		.join(STORE_NAME)
		.join(format!("{oldest}.json"))
		.exists());
	assert!(is_active(&oldest).unwrap());
	assert_eq!(names(root.path(), STORE_NAME), MAX_OWNER);
	drop(readers);
	let _ = tickets(execute(admissions(root.path(), 1), &mut barrier).unwrap());
	assert!(!root
		.path()
		.join(STORE_NAME)
		.join(format!("{oldest}.json"))
		.exists());
	assert!(observation_at(root.path(), &"a".repeat(64), &oldest).is_ok());
}

#[test]
fn handler_cannot_run_while_hot_durability_acknowledgement_is_parked() {
	use std::sync::atomic::AtomicUsize;
	let root = root();
	let path = root.path().to_owned();
	let (entered, wait_entered) = mpsc::channel();
	let (resume, wait_resume) = mpsc::channel();
	let wait_resume = Arc::new(Mutex::new(wait_resume));
	let coordinator = Arc::new(
		Coordinator::with_processor(Arc::new(move |works| {
			execute(works, &mut |directory, phase| {
				if phase == Barrier::Hot {
					entered.send(())?;
					wait_resume
						.lock()
						.map_err(|_| anyhow!("fixture gate"))?
						.recv()?;
				}
				directory.sync_all()?;
				Ok(())
			})
			.unwrap()
		}))
		.unwrap(),
	);
	let effects = Arc::new(AtomicUsize::new(0));
	let counter = effects.clone();
	let worker = coordinator.clone();
	let handler = std::thread::spawn(move || {
		let ticket = worker
			.begin(path, "a".repeat(64), "binary_write".into(), None)
			.unwrap();
		counter.fetch_add(1, Ordering::SeqCst);
		ticket
	});
	let reached = wait_entered.recv_timeout(Duration::from_secs(60));
	let before = effects.load(Ordering::SeqCst);
	let resumed = resume.send(());
	let finished = handler.join();
	reached.unwrap();
	resumed.unwrap();
	let ticket = finished.unwrap();
	assert_eq!(before, 0);
	assert_eq!(effects.load(Ordering::SeqCst), 1);
	assert!(is_dispatch_active(ticket.request_id()).unwrap());
}

#[test]
fn one_unsafe_hot_leaf_does_not_rewrite_it_or_reject_other_completion() {
	let root = root();
	let admitted = tickets(execute(admissions(root.path(), 2), &mut barrier).unwrap());
	let path = root
		.path()
		.join(STORE_NAME)
		.join(format!("{}.json", admitted[0].request_id()));
	let original = std::fs::read(&path).unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
	let work = admitted
		.into_iter()
		.map(|t| Work::Finish(root.path().into(), t, AuditCompletion::Completed))
		.collect();
	let result = execute(work, &mut barrier).unwrap();
	assert!(result[0].is_err());
	assert!(result[1].is_ok());
	assert_eq!(std::fs::read(&path).unwrap(), original);
	assert_eq!(
		std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
		0o700
	);
}

#[test]
fn abandoned_owned_hot_snapshot_recovers_all_existing_receipts() {
	let root = root();
	let admitted = tickets(execute(admissions(root.path(), 8), &mut barrier).unwrap());
	let identities: std::collections::BTreeSet<_> =
		admitted.iter().map(|t| t.request_id().to_owned()).collect();
	let work = admitted
		.into_iter()
		.map(|ticket| Work::Finish(root.path().into(), ticket, AuditCompletion::Completed))
		.collect();
	assert!(execute(work, &mut barrier)
		.unwrap()
		.into_iter()
		.all(|v| v.is_ok()));
	let _guard = store_lock().unwrap();
	let base = audit_root(root.path()).unwrap();
	let directory = open_named_store_at(&base, STORE_NAME).unwrap();
	let archive = open_archive_at(&base).unwrap();
	let moved = hot_snapshot_at(&directory, &archive, true).unwrap();
	assert_eq!(moved.len(), 8);
	drop(moved);
	// Model an error before the caller can restore its owned snapshot.
	let recovered = hot_snapshot_at(&directory, &archive, false).unwrap();
	assert_eq!(
		recovered
			.iter()
			.map(|r| r.request_id.clone())
			.collect::<std::collections::BTreeSet<_>>(),
		identities
	);
	assert!(recovered.iter().all(|r| r.state == DurableState::Completed));
}

#[test]
fn root_replacement_during_cohort_refuses_and_preserves_the_replacement() {
	let parent = root();
	let state = parent.path().join("state");
	let displaced = parent.path().join("original-state");
	std::fs::create_dir(&state).unwrap();
	std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
	let result = execute(admissions(&state, 2), &mut |directory, phase| {
		directory.sync_all()?;
		if phase == Barrier::Archive {
			std::fs::rename(&state, &displaced)?;
			std::fs::create_dir(&state)?;
			std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))?;
			std::fs::write(state.join("unrelated"), b"replacement stays unchanged")?;
		}
		Ok(())
	});
	assert!(result.is_err());
	assert_eq!(
		std::fs::read(state.join("unrelated")).unwrap(),
		b"replacement stays unchanged"
	);
	assert_eq!(std::fs::read_dir(&state).unwrap().count(), 1);
	assert_eq!(names(&displaced, ARCHIVE_NAME), 2);
	for entry in std::fs::read_dir(displaced.join(ARCHIVE_NAME)).unwrap() {
		let record: Record =
			serde_json::from_slice(&std::fs::read(entry.unwrap().path()).unwrap()).unwrap();
		assert!(record.state == DurableState::Unknown);
		assert!(!is_dispatch_active(&record.request_id).unwrap());
	}
}

#[test]
fn mixed_admission_and_completion_share_barriers_without_early_ack_markers() {
	let root = root();
	let mut old = tickets(execute(admissions(root.path(), 2), &mut barrier).unwrap());
	let completed = old.pop().unwrap();
	let id = completed.request_id().to_owned();
	let active = completed.active.clone();
	let mut stages = Vec::new();
	let values = execute(
		vec![
			begin(root.path(), 'b', "host_list", None),
			Work::Finish(root.path().into(), completed, AuditCompletion::Completed),
			begin(root.path(), 'a', "host_health", None),
		],
		&mut |directory, phase| {
			stages.push(phase);
			assert!(active.load(Ordering::Acquire));
			assert_eq!(names(root.path(), ARCHIVE_NAME), 4);
			assert_eq!(
				names(root.path(), STORE_NAME),
				if phase == Barrier::Archive { 2 } else { 4 }
			);
			for member in std::fs::read_dir(root.path().join(ARCHIVE_NAME))? {
				let record: Record = serde_json::from_slice(&std::fs::read(member?.path())?)?;
				if record.owner == "b".repeat(64) || record.tool_name == "host_health" {
					assert!(!is_dispatch_active(&record.request_id)?);
				}
			}
			let hot: Record = serde_json::from_slice(&std::fs::read(
				root.path().join(STORE_NAME).join(format!("{id}.json")),
			)?)?;
			assert!(
				hot.state
					== if phase == Barrier::Archive {
						DurableState::Unknown
					} else {
						DurableState::Completed
					}
			);
			directory.sync_all()?;
			Ok(())
		},
	)
	.unwrap();
	assert!(stages == vec![Barrier::Archive, Barrier::Hot]);
	assert!(!active.load(Ordering::Acquire));
	let mut values = values.into_iter();
	let Outcome::Begun(first) = values.next().unwrap().unwrap() else {
		panic!("FIFO first admission");
	};
	assert!(matches!(values.next().unwrap().unwrap(), Outcome::Finished));
	let Outcome::Begun(last) = values.next().unwrap().unwrap() else {
		panic!("FIFO last admission");
	};
	assert_eq!(first.record.owner, "b".repeat(64));
	assert_eq!(last.record.owner, "a".repeat(64));
	assert!(is_dispatch_active(first.request_id()).unwrap());
	assert!(is_dispatch_active(last.request_id()).unwrap());
	let _guard = store_lock().unwrap();
	let directory = open_store(root.path()).unwrap();
	let (records, _) = hot_snapshot(root.path(), &directory).unwrap();
	assert_eq!(records.len(), 4);
	assert!(records.iter().find(|r| r.request_id == id).unwrap().state == DurableState::Completed);
}

#[test]
fn mixed_cohort_barrier_failure_refuses_every_ack_and_retains_active_completion() {
	for failed in [Barrier::Archive, Barrier::Hot] {
		let root = root();
		let old = tickets(execute(admissions(root.path(), 1), &mut barrier).unwrap())
			.pop()
			.unwrap();
		let id = old.request_id().to_owned();
		let active = old.active.clone();
		let result = execute(
			vec![
				Work::Finish(root.path().into(), old, AuditCompletion::Completed),
				begin(root.path(), 'b', "host_list", None),
			],
			&mut |directory, phase| {
				directory.sync_all()?;
				if phase == failed {
					bail!("isolated mixed barrier failure");
				}
				Ok(())
			},
		);
		assert!(result.is_err());
		assert!(active.load(Ordering::Acquire));
		assert!(is_dispatch_active(&id).unwrap());
		for member in std::fs::read_dir(root.path().join(ARCHIVE_NAME)).unwrap() {
			let record: Record =
				serde_json::from_slice(&std::fs::read(member.unwrap().path()).unwrap()).unwrap();
			if record.request_id != id {
				assert!(!is_dispatch_active(&record.request_id).unwrap());
			}
		}
	}
}

#[test]
fn invalid_admission_keeps_mixed_cohort_results_bound_to_their_fifo_slots() {
	let root = root();
	let old = tickets(execute(admissions(root.path(), 1), &mut barrier).unwrap())
		.pop()
		.unwrap();
	let active = old.active.clone();
	let values = execute(
		vec![
			begin(root.path(), 'b', "host_list", None),
			begin(root.path(), 'z', "host_list", None),
			Work::Finish(root.path().into(), old, AuditCompletion::Completed),
		],
		&mut barrier,
	)
	.unwrap();
	let mut values = values.into_iter();
	assert!(matches!(values.next().unwrap(), Ok(Outcome::Begun(_))));
	assert!(values.next().unwrap().is_err());
	assert!(matches!(values.next().unwrap(), Ok(Outcome::Finished)));
	assert!(!active.load(Ordering::Acquire));
	assert_eq!(names(root.path(), ARCHIVE_NAME), 2);
}

#[test]
fn same_root_interleaved_queue_coalesces_without_overtaking_another_root() {
	let one = root();
	let two = root();
	let old = tickets(execute(admissions(one.path(), 1), &mut barrier).unwrap())
		.pop()
		.unwrap();
	let queue = Queue::default();
	{
		let mut pending = queue.pending.lock().unwrap();
		for work in [
			begin(one.path(), 'a', "host_list", None),
			Work::Finish(one.path().into(), old, AuditCompletion::Completed),
			begin(one.path(), 'b', "host_list", None),
			begin(two.path(), 'a', "host_list", None),
			begin(one.path(), 'a', "host_list", None),
		] {
			pending.jobs.push_back(job(work));
		}
	}
	let first = queue.take().unwrap().unwrap();
	assert_eq!(
		first.iter().map(|job| job.work.key().1).collect::<Vec<_>>(),
		vec![true, false, true]
	);
	assert!(first.iter().all(|job| job.work.key().0 == one.path()));
	queue.completed();
	let second = queue.take().unwrap().unwrap();
	assert_eq!(second.len(), 1);
	assert_eq!(second[0].work.key().0, two.path());
	queue.completed();
	let third = queue.take().unwrap().unwrap();
	assert_eq!(third.len(), 1);
	assert_eq!(third[0].work.key().0, one.path());
	queue.close();
}

#[test]
fn mixed_cohort_crash_child() {
	let Some(root) = std::env::var_os("HEPTA_TEST_MIXED_COHORT_ROOT") else {
		return;
	};
	let root = PathBuf::from(root);
	let phase = std::env::var("HEPTA_TEST_MIXED_COHORT_PHASE").unwrap();
	let old = tickets(execute(admissions(&root, 1), &mut barrier).unwrap())
		.pop()
		.unwrap();
	let result = execute(
		vec![
			begin(&root, 'b', "host_list", None),
			Work::Finish(root.clone(), old, AuditCompletion::Completed),
			begin(&root, 'b', "host_health", None),
		],
		&mut |directory, barrier| {
			directory.sync_all()?;
			if (phase == "archive" && barrier == Barrier::Archive)
				|| (phase == "hot" && barrier == Barrier::Hot)
			{
				unsafe { libc::_exit(87) };
			}
			Ok(())
		},
	);
	if result.is_ok() {
		std::fs::write(root.join("mixed-dispatched"), b"unexpected").unwrap();
	}
	panic!("mixed crash fixture did not stop");
}

#[test]
fn mixed_cohort_process_crash_never_dispatches_or_changes_originals_on_recovery() {
	for phase in ["archive", "hot"] {
		let root = root();
		let mut child = std::process::Command::new(std::env::current_exe().unwrap())
			.args([
				"mcp::runtime::request_audit::batch::tests::mixed_cohort_crash_child",
				"--exact",
				"--test-threads=1",
			])
			.env("HEPTA_TEST_MIXED_COHORT_ROOT", root.path())
			.env("HEPTA_TEST_MIXED_COHORT_PHASE", phase)
			.stdout(std::process::Stdio::null())
			.stderr(std::process::Stdio::null())
			.spawn()
			.unwrap();
		let deadline = Instant::now() + Duration::from_secs(60);
		let status = loop {
			if let Some(status) = child.try_wait().unwrap() {
				break status;
			}
			if Instant::now() >= deadline {
				child.kill().unwrap();
				child.wait().unwrap();
				panic!("mixed crash child timeout");
			}
			std::thread::sleep(Duration::from_millis(10));
		};
		assert_eq!(status.code(), Some(87));
		assert!(!root.path().join("mixed-dispatched").exists());
		let mut original = Vec::new();
		for member in std::fs::read_dir(root.path().join(ARCHIVE_NAME)).unwrap() {
			let path = member.unwrap().path();
			let bytes = std::fs::read(&path).unwrap();
			let record: Record = serde_json::from_slice(&bytes).unwrap();
			assert!(!is_dispatch_active(&record.request_id).unwrap());
			assert!(
				record.state
					== if record.owner == "a".repeat(64) {
						DurableState::Completed
					} else {
						DurableState::Unknown
					}
			);
			original.push((path, bytes));
		}
		assert_eq!(original.len(), 3);
		assert_eq!(
			names(root.path(), STORE_NAME),
			if phase == "archive" { 1 } else { 3 }
		);
		prepare_at(root.path()).unwrap();
		for (path, bytes) in original {
			assert_eq!(std::fs::read(path).unwrap(), bytes);
		}
		assert!(!root.path().join("mixed-dispatched").exists());
	}
}
