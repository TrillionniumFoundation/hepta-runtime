// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bounded original-read ownership, error propagation and terminal-fence ordering.
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::AtomicUsize;

fn budget() -> Instant {
	Instant::now() + Duration::from_secs(10)
}

#[derive(Default)]
struct Gate {
	open: Mutex<bool>,
	wake: Condvar,
}

impl Gate {
	fn release(&self) {
		*self.open.lock().unwrap() = true;
		self.wake.notify_all();
	}
	fn wait(&self) {
		let (open, _) = self
			.wake
			.wait_timeout_while(self.open.lock().unwrap(), Duration::from_secs(10), |open| {
				!*open
			})
			.unwrap();
		assert!(*open, "original-worker test gate was not released");
	}
}

// Construct before spawning a test coordinator, so assertion/spawn failures
// release every synthetic wait before the surrounding scope/runtime joins.
struct ReleaseGates(Vec<Arc<Gate>>);

impl Drop for ReleaseGates {
	fn drop(&mut self) {
		for gate in &self.0 {
			gate.release();
		}
	}
}

struct Fixture {
	root: tempfile::TempDir,
	archive: Archive,
	entries: Vec<Entry>,
}

impl Fixture {
	fn new(sharded: bool, count: usize) -> Self {
		let root = tempfile::Builder::new()
			.permissions(std::fs::Permissions::from_mode(0o700))
			.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
			.unwrap();
		let _guard = store_lock().unwrap();
		let archive = open_archive(root.path()).unwrap();
		if sharded {
			archive.initialize_shards().unwrap();
		}
		let mut entries = Vec::new();
		for number in 0..count {
			let record = Record {
				request_id: format!("{number:064x}"),
				owner: "a".repeat(64),
				tool_name: "host_list".into(),
				state: DurableState::Completed,
				accepted_unix_ms: 100_000 + number as u128,
				elapsed_ms: Some(1),
			};
			let filename = format!("{}.json", record.request_id);
			let directory = archive.directory_for_write(&filename, false).unwrap();
			save_raw_with_sync(directory, &record, false, true).unwrap();
			entries.push(Entry {
				stamp: stamp(&archive, &filename).unwrap(),
				record,
			});
		}
		Self {
			root,
			archive,
			entries,
		}
	}
	fn submit<'scope, 'env: 'scope>(
		&'env self,
		workers: &mut OriginalWorkers<'scope, 'env>,
		number: usize,
	) -> Result<()> {
		let entry = self.entries[number].clone();
		let filename = format!("{}.json", entry.record.request_id);
		let directory = self.archive.directory_for_existing(&filename)?;
		workers.submit(&self.archive, directory, &filename, entry)
	}
	fn database(&self, entries: impl IntoIterator<Item = Entry>) -> Database {
		let file = open_at(
			self.archive.root(),
			CACHE_NAME,
			libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
			0o600,
		)
		.unwrap();
		let database = database(file, budget()).unwrap();
		apply(&database, entries, None, true).unwrap();
		database
	}
	fn original_bytes(&self) -> Vec<Vec<u8>> {
		self.entries
			.iter()
			.map(|entry| {
				let name = format!("{}.json", entry.record.request_id);
				let directory = self.archive.directory_for_existing(&name).unwrap();
				let mut file = open_at(directory, &name, libc::O_RDONLY, 0).unwrap();
				let mut bytes = Vec::new();
				file.read_to_end(&mut bytes).unwrap();
				bytes
			})
			.collect()
	}
}

fn parallel_check(
	fixture: &Fixture,
	database: &Database,
	view: &PendingView,
	count: u64,
) -> Result<()> {
	let transaction = database.begin_read()?;
	let rows = transaction.open_table(ROWS)?;
	let order = transaction.open_table(ORDER)?;
	let guard = store_lock()?;
	// A small synthetic fixture calls the actual parallel kernel explicitly;
	// this is not the production large-archive selector or a performance trial.
	verify_members_parallel(
		&fixture.archive,
		(&rows, &order),
		view,
		count,
		budget(),
		&guard,
	)
}

#[derive(Debug)]
struct OriginalFailure;

impl std::fmt::Display for OriginalFailure {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter.write_str("original synthetic failure")
	}
}
impl std::error::Error for OriginalFailure {}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExitCase {
	ProducerError,
	OriginalError,
	ProducerPanic,
	OriginalPanic,
	BothPanic,
	Deadline,
}

fn held_children_exit(case: ExitCase) {
	let fixture = Fixture::new(false, 2);
	let started: [Arc<Gate>; 2] = std::array::from_fn(|_| Arc::new(Gate::default()));
	let release: [Arc<Gate>; 2] = std::array::from_fn(|_| Arc::new(Gate::default()));
	let trigger = Arc::new(Gate::default());
	let leaving = Arc::new(Gate::default());
	let exited = AtomicUsize::new(0);
	let (send_done, receive_done) = std::sync::mpsc::channel();
	let deadline = if case == ExitCase::Deadline {
		Instant::now() + Duration::from_secs(2)
	} else {
		budget()
	};
	std::thread::scope(|outer| {
		let _release = ReleaseGates(vec![
			release[0].clone(),
			release[1].clone(),
			trigger.clone(),
		]);
		outer.spawn(|| {
			// A test-local mutex proves poisoning without corrupting the shared
			// production STORE_LOCK for the rest of the qualification suite.
			let protected = Mutex::new(());
			let cancelled = AtomicBool::new(false);
			let perform = |task: OriginalTask<'_>| {
				let number = task.number as usize;
				started[number].release();
				release[number].wait();
				if number == 0 && case == ExitCase::OriginalError {
					return Err(
						anyhow::Error::new(OriginalFailure).context("original read context")
					);
				}
				if number == 0 && matches!(case, ExitCase::OriginalPanic | ExitCase::BothPanic) {
					std::panic::panic_any("original child panic");
				}
				verify_original_task(task)
			};
			let hook = |event| {
				if matches!(event, OriginalWorkerEvent::Exiting(_)) {
					exited.fetch_add(1, Ordering::SeqCst);
				}
			};
			let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
				let _guard = protected.lock().unwrap();
				std::thread::scope(|scope| {
					let mut workers = OriginalWorkers::new(&cancelled, deadline);
					workers.hook = Some(&hook);
					workers.start(scope, &perform)?;
					fixture.submit(&mut workers, 0)?;
					fixture.submit(&mut workers, 1)?;
					trigger.wait();
					leaving.release();
					match case {
						ExitCase::ProducerError => {
							Err(anyhow::Error::new(OriginalFailure).context("producer context"))
						}
						ExitCase::ProducerPanic | ExitCase::BothPanic => {
							std::panic::panic_any("coordinator panic")
						}
						_ => workers.finish(2),
					}
				})
			}));
			send_done
				.send((
					result,
					protected.is_poisoned(),
					exited.load(Ordering::SeqCst),
				))
				.unwrap();
		});
		started[0].wait();
		started[1].wait();
		if case == ExitCase::Deadline {
			std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
		}
		trigger.release();
		leaving.wait();
		if matches!(
			case,
			ExitCase::OriginalError | ExitCase::OriginalPanic | ExitCase::BothPanic
		) {
			release[0].release();
		}
		assert!(matches!(
			receive_done.recv_timeout(Duration::from_millis(25)),
			Err(std::sync::mpsc::RecvTimeoutError::Timeout)
		));
		release[0].release();
		release[1].release();
		let (outcome, poisoned, exited) =
			receive_done.recv_timeout(Duration::from_secs(10)).unwrap();
		assert_eq!(exited, 2);
		match case {
			ExitCase::ProducerPanic | ExitCase::OriginalPanic | ExitCase::BothPanic => {
				let payload = outcome.expect_err("the original panic must propagate after joins");
				let expected = if case == ExitCase::OriginalPanic {
					"original child panic"
				} else {
					"coordinator panic"
				};
				assert_eq!(payload.downcast_ref::<&str>(), Some(&expected));
				assert!(poisoned);
			}
			_ => {
				let error = outcome.unwrap().unwrap_err();
				assert!(!poisoned);
				if case != ExitCase::Deadline {
					assert!(error.is::<OriginalFailure>());
					assert_eq!(error.root_cause().to_string(), "original synthetic failure");
				}
			}
		}
	});
}

#[test]
fn original_workers_preserve_producer_error_until_held_children_have_joined() {
	held_children_exit(ExitCase::ProducerError);
}

#[test]
fn original_workers_preserve_read_error_chain_until_other_child_has_joined() {
	held_children_exit(ExitCase::OriginalError);
}

#[test]
fn original_workers_finish_cleanup_during_existing_coordinator_unwind() {
	held_children_exit(ExitCase::ProducerPanic);
}

#[test]
fn original_worker_panic_resumes_through_the_coordinator_lock_after_all_joins() {
	held_children_exit(ExitCase::OriginalPanic);
}

#[test]
fn original_workers_do_not_resume_a_second_panic_during_coordinator_unwind() {
	held_children_exit(ExitCase::BothPanic);
}

#[test]
fn original_workers_expired_budget_does_not_detach_held_children() {
	held_children_exit(ExitCase::Deadline);
}

#[test]
fn original_worker_second_spawn_failure_joins_the_first_waiting_thread() {
	let entered = Arc::new(Gate::default());
	let exiting = Arc::new(Gate::default());
	let release = Arc::new(Gate::default());
	let (send_done, receive_done) = std::sync::mpsc::channel();
	std::thread::scope(|outer| {
		let _release = ReleaseGates(vec![release.clone(), entered.clone()]);
		outer.spawn(|| {
			let cancelled = AtomicBool::new(false);
			let perform =
				|_task: OriginalTask<'_>| -> Result<()> { panic!("no task was submitted") };
			let hook = |event| match event {
				OriginalWorkerEvent::Started(0) => entered.release(),
				OriginalWorkerEvent::BeforeSpawn(1) => entered.wait(),
				OriginalWorkerEvent::Exiting(0) => {
					exiting.release();
					release.wait();
				}
				_ => {}
			};
			let result = std::thread::scope(|scope| {
				let mut workers = OriginalWorkers::new(&cancelled, budget());
				workers.hook = Some(&hook);
				workers.fail_spawn_at = Some(1);
				workers.start(scope, &perform)
			});
			send_done.send(result).unwrap();
		});
		exiting.wait();
		assert!(matches!(
			receive_done.recv_timeout(Duration::from_millis(25)),
			Err(std::sync::mpsc::RecvTimeoutError::Timeout)
		));
		release.release();
		let error = receive_done
			.recv_timeout(Duration::from_secs(10))
			.unwrap()
			.unwrap_err();
		assert!(error.is::<std::io::Error>());
		assert!(error
			.to_string()
			.contains("synthetic original worker spawn failure"));
	});
}

#[test]
fn original_workers_bound_submitted_unconsumed_work_to_one_per_lane() {
	let fixture = Fixture::new(false, 4);
	let release: [Arc<Gate>; 2] = std::array::from_fn(|_| Arc::new(Gate::default()));
	let submitting_third = Arc::new(Gate::default());
	let (send_started, receive_started) = std::sync::mpsc::channel();
	let (send_done, receive_done) = std::sync::mpsc::channel();
	std::thread::scope(|outer| {
		let _release = ReleaseGates(release.to_vec());
		outer.spawn(|| {
			let cancelled = AtomicBool::new(false);
			let perform = |task: OriginalTask<'_>| {
				send_started.send(task.number).unwrap();
				if task.number < 2 {
					release[task.number as usize].wait();
				}
				verify_original_task(task)
			};
			let result = std::thread::scope(|scope| {
				let mut workers = OriginalWorkers::new(&cancelled, budget());
				workers.start(scope, &perform)?;
				fixture.submit(&mut workers, 0)?;
				fixture.submit(&mut workers, 1)?;
				submitting_third.release();
				fixture.submit(&mut workers, 2)?;
				fixture.submit(&mut workers, 3)?;
				workers.finish(4)
			});
			send_done.send(result).unwrap();
		});
		let first = receive_started
			.recv_timeout(Duration::from_secs(10))
			.unwrap();
		let second = receive_started
			.recv_timeout(Duration::from_secs(10))
			.unwrap();
		assert_eq!(BTreeSet::from([first, second]), BTreeSet::from([0, 1]));
		submitting_third.wait();
		assert!(matches!(
			receive_started.recv_timeout(Duration::from_millis(25)),
			Err(std::sync::mpsc::RecvTimeoutError::Timeout)
		));
		release[0].release();
		assert_eq!(
			receive_started
				.recv_timeout(Duration::from_secs(10))
				.unwrap(),
			2
		);
		release[1].release();
		assert_eq!(
			receive_started
				.recv_timeout(Duration::from_secs(10))
				.unwrap(),
			3
		);
		receive_done
			.recv_timeout(Duration::from_secs(10))
			.unwrap()
			.unwrap();
	});
}

#[test]
fn parallel_original_join_keeps_one_db_view_with_pending_replacement_and_addition() {
	let fixture = Fixture::new(false, 3);
	let mut initial = fixture.entries[..2].to_vec();
	initial[0].record.state = DurableState::Unknown;
	initial[0].record.elapsed_ms = None;
	let database = fixture.database(initial);
	let pending = BTreeMap::from([
		(
			id(&fixture.entries[0].record.request_id).unwrap(),
			fixture.entries[0].clone(),
		),
		(
			id(&fixture.entries[2].record.request_id).unwrap(),
			fixture.entries[2].clone(),
		),
	]);
	let view = PendingView::new(&database, &pending, budget()).unwrap();
	let originals = fixture.original_bytes();
	let cache = std::fs::read(fixture.root.path().join(CACHE_NAME)).unwrap();
	parallel_check(&fixture, &database, &view, 3).unwrap();
	assert_eq!(fixture.original_bytes(), originals);
	assert_eq!(
		std::fs::read(fixture.root.path().join(CACHE_NAME)).unwrap(),
		cache
	);
	assert_eq!(
		database
			.begin_read()
			.unwrap()
			.open_table(ROWS)
			.unwrap()
			.len()
			.unwrap(),
		2
	);
	assert_eq!(view.entries.len(), 2);
}

#[test]
fn parallel_original_join_refuses_complete_record_disagreement_and_missing_coverage() {
	let fixture = Fixture::new(false, 2);
	let originals = fixture.original_bytes();
	let mut different = fixture.entries.clone();
	different[1].record.accepted_unix_ms += 1;
	let database = fixture.database(different);
	let error = parallel_check(&fixture, &database, &PendingView::default(), 2).unwrap_err();
	assert!(error.to_string().contains("full record content changed"));
	assert_eq!(fixture.original_bytes(), originals);

	let exact = Fixture::new(false, 2);
	let database = exact.database(exact.entries.clone());
	let error = parallel_check(&exact, &database, &PendingView::default(), 3).unwrap_err();
	assert!(error.to_string().contains("view coverage changed"));
}

#[test]
fn strict_walk_finishes_child_work_before_full_terminal_fences_in_both_layouts() {
	for sharded in [false, true] {
		let fixture = Fixture::new(sharded, 1);
		let cancelled = AtomicBool::new(false);
		let exited = AtomicUsize::new(0);
		let hook = |event| {
			if matches!(event, OriginalWorkerEvent::Exiting(_)) {
				exited.fetch_add(1, Ordering::SeqCst);
			}
		};
		let result = std::thread::scope(|scope| {
			let mut workers = OriginalWorkers::new(&cancelled, budget());
			workers.hook = Some(&hook);
			workers.start(scope, &verify_original_task)?;
			fixture.archive.walk_with_finish(
				&mut workers,
				|workers, directory, filename, _| {
					workers.submit(
						&fixture.archive,
						directory,
						filename,
						fixture.entries[0].clone(),
					)
				},
				|workers| {
					workers.finish(1)?;
					assert_eq!(exited.load(Ordering::SeqCst), 2);
					// A new synthetic namespace entry after all jobs have joined
					// must still be seen by the original full terminal fence.
					let path = if sharded {
						fixture
							.root
							.path()
							.join(archive_store::SHARD_ROOT)
							.join("zz")
					} else {
						fixture.root.path().join(archive_store::SHARD_INTENT)
					};
					std::fs::write(path, b"synthetic terminal namespace change")?;
					Ok(())
				},
			)
		});
		assert!(result.is_err());
		assert_eq!(exited.load(Ordering::SeqCst), 2);
	}
}

#[test]
fn strict_walk_with_finish_still_rejects_cross_namespace_duplicates_before_finish() {
	let fixture = Fixture::new(true, 1);
	save_raw_with_sync(
		fixture.archive.legacy(),
		&fixture.entries[0].record,
		false,
		true,
	)
	.unwrap();
	let mut finished = false;
	let result = fixture.archive.walk_with_finish(
		&mut finished,
		|_, _, _, _| Ok(()),
		|finished| {
			*finished = true;
			Ok(())
		},
	);
	assert!(result
		.unwrap_err()
		.to_string()
		.contains("duplicate request archive identity"));
	assert!(!finished);
}

#[test]
fn async_metadata_timeout_retains_its_permit_until_original_children_join() {
	let fixture = Arc::new(Fixture::new(false, 1));
	let started = Arc::new(Gate::default());
	let release = Arc::new(Gate::default());
	let slots = Arc::new(tokio::sync::Semaphore::new(MAX_METADATA_QUERIES));
	let runtime = tokio::runtime::Builder::new_multi_thread()
		.worker_threads(2)
		.enable_all()
		.build()
		.unwrap();
	// Must drop before runtime: an assertion failure cannot leave a blocking
	// child held while Runtime::drop waits for the original blocking closure.
	let _release = ReleaseGates(vec![release.clone()]);
	runtime.block_on(async {
		let reserved = slots.clone().acquire_many_owned(7).await.unwrap();
		let query_fixture = fixture.clone();
		let query_started = started.clone();
		let query_release = release.clone();
		let query_slots = slots.clone();
		let task = tokio::spawn(async move {
			run_metadata_query(
				Instant::now() + Duration::from_secs(2),
				query_slots,
				move |deadline| {
					let cancelled = AtomicBool::new(false);
					let perform = |task: OriginalTask<'_>| {
						query_started.release();
						query_release.wait();
						verify_original_task(task)
					};
					std::thread::scope(|scope| {
						let mut workers = OriginalWorkers::new(&cancelled, deadline);
						workers.start(scope, &perform)?;
						query_fixture.submit(&mut workers, 0)?;
						workers.finish(1)
					})
				},
			)
			.await
		});
		tokio::task::spawn_blocking(move || started.wait())
			.await
			.unwrap();
		let error = task.await.unwrap().unwrap_err();
		assert!(error.is::<MetadataQueryDeadline>());
		assert_eq!(slots.available_permits(), 0);
		release.release();
		let drained = tokio::time::timeout(Duration::from_secs(10), slots.clone().acquire_owned())
			.await
			.unwrap()
			.unwrap();
		drop(drained);
		drop(reserved);
		assert_eq!(slots.available_permits(), MAX_METADATA_QUERIES);
	});
}
