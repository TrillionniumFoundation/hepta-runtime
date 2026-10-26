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
		Self::with_ids(sharded, (0..count).map(|number| format!("{number:064x}")))
	}
	fn with_ids(sharded: bool, ids: impl IntoIterator<Item = String>) -> Self {
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
		for (number, request_id) in ids.into_iter().enumerate() {
			let record = Record {
				request_id,
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
		workers.ready_for_record()?;
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
	let count = ORIGINAL_READ_WORKERS * ORIGINAL_READ_BATCH;
	let fixture = Fixture::new(false, count);
	let started: [Arc<Gate>; 2] = std::array::from_fn(|_| Arc::new(Gate::default()));
	let release: [Arc<Gate>; 2] = std::array::from_fn(|_| Arc::new(Gate::default()));
	let trigger = Arc::new(Gate::default());
	let leaving = Arc::new(Gate::default());
	let cancelling = Arc::new(Gate::default());
	let exited = AtomicUsize::new(0);
	let performed = Mutex::new(Vec::new());
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
				performed.lock().unwrap().push(number);
				if number.is_multiple_of(ORIGINAL_READ_BATCH) {
					let lane = number / ORIGINAL_READ_BATCH;
					started[lane].release();
					release[lane].wait();
				}
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
			let hook = |event| match event {
				OriginalWorkerEvent::Exiting(_) => {
					exited.fetch_add(1, Ordering::SeqCst);
				}
				OriginalWorkerEvent::CancellationStarted => cancelling.release(),
				_ => {}
			};
			let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
				let _guard = protected.lock().unwrap();
				std::thread::scope(|scope| {
					let mut workers = OriginalWorkers::new(&cancelled, deadline);
					workers.hook = Some(&hook);
					workers.start(scope, &perform)?;
					for number in 0..count {
						fixture.submit(&mut workers, number)?;
					}
					trigger.wait();
					leaving.release();
					match case {
						ExitCase::ProducerError => {
							Err(anyhow::Error::new(OriginalFailure).context("producer context"))
						}
						ExitCase::ProducerPanic | ExitCase::BothPanic => {
							std::panic::panic_any("coordinator panic")
						}
						_ => workers.finish(count as u64),
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
		cancelling.wait();
		assert!(matches!(
			receive_done.recv_timeout(Duration::from_millis(25)),
			Err(std::sync::mpsc::RecvTimeoutError::Timeout)
		));
		release[0].release();
		release[1].release();
		let (outcome, poisoned, exited) =
			receive_done.recv_timeout(Duration::from_secs(10)).unwrap();
		assert_eq!(exited, 2);
		assert_eq!(
			performed
				.lock()
				.unwrap()
				.iter()
				.copied()
				.collect::<BTreeSet<_>>(),
			BTreeSet::from([0, ORIGINAL_READ_BATCH]),
			"cancellation/deadline must stop both original batch suffixes"
		);
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
	let full = ORIGINAL_READ_WORKERS * ORIGINAL_READ_BATCH;
	let fixture = Fixture::new(false, full + 2);
	let release: [Arc<Gate>; 2] = std::array::from_fn(|_| Arc::new(Gate::default()));
	let submitting_next = Arc::new(Gate::default());
	let (send_started, receive_started) = std::sync::mpsc::channel();
	let (send_done, receive_done) = std::sync::mpsc::channel();
	std::thread::scope(|outer| {
		let _release = ReleaseGates(release.to_vec());
		outer.spawn(|| {
			let cancelled = AtomicBool::new(false);
			let perform = |task: OriginalTask<'_>| {
				send_started.send(task.number).unwrap();
				if task.number == 0 || task.number == ORIGINAL_READ_BATCH as u64 {
					release[task.number as usize / ORIGINAL_READ_BATCH].wait();
				}
				verify_original_task(task)
			};
			let result = std::thread::scope(|scope| {
				let mut workers = OriginalWorkers::new(&cancelled, budget());
				workers.start(scope, &perform)?;
				for number in 0..full {
					fixture.submit(&mut workers, number)?;
				}
				assert_eq!(workers.submitted, full as u64);
				assert_eq!(workers.verified, 0);
				for (lane, state) in workers.lanes.iter().enumerate() {
					assert!(state.pending.is_empty());
					assert_eq!(
						state.outstanding,
						Some((
							(lane * ORIGINAL_READ_BATCH) as u64,
							ORIGINAL_READ_BATCH as u64
						))
					);
				}
				submitting_next.release();
				fixture.submit(&mut workers, full)?;
				fixture.submit(&mut workers, full + 1)?;
				workers.finish((full + 2) as u64)
			});
			send_done.send(result).unwrap();
		});
		let first = receive_started
			.recv_timeout(Duration::from_secs(10))
			.unwrap();
		let second = receive_started
			.recv_timeout(Duration::from_secs(10))
			.unwrap();
		assert_eq!(
			BTreeSet::from([first, second]),
			BTreeSet::from([0, ORIGINAL_READ_BATCH as u64])
		);
		submitting_next.wait();
		assert!(matches!(
			receive_started.recv_timeout(Duration::from_millis(25)),
			Err(std::sync::mpsc::RecvTimeoutError::Timeout)
		));
		// The next batch may use lane 0 only after every one of its original
		// 32 records completes. Lane 1 remains held throughout this step.
		release[0].release();
		let after_first: BTreeSet<_> = (0..ORIGINAL_READ_BATCH + 1)
			.map(|_| {
				receive_started
					.recv_timeout(Duration::from_secs(10))
					.unwrap()
			})
			.collect();
		let expected: BTreeSet<_> = (1..ORIGINAL_READ_BATCH as u64)
			.chain([full as u64, full as u64 + 1])
			.collect();
		assert_eq!(after_first, expected);
		assert!(matches!(
			receive_done.recv_timeout(Duration::from_millis(25)),
			Err(std::sync::mpsc::RecvTimeoutError::Timeout)
		));
		release[1].release();
		let rest: BTreeSet<_> = (1..ORIGINAL_READ_BATCH)
			.map(|_| {
				receive_started
					.recv_timeout(Duration::from_secs(10))
					.unwrap()
			})
			.collect();
		assert_eq!(
			rest,
			((ORIGINAL_READ_BATCH + 1) as u64..full as u64).collect()
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
		let count = ORIGINAL_READ_BATCH + 1;
		let fixture = Fixture::new(sharded, count);
		let expected: BTreeMap<_, _> = fixture
			.entries
			.iter()
			.map(|entry| (format!("{}.json", entry.record.request_id), entry.clone()))
			.collect();
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
					workers.ready_for_record()?;
					workers.submit(
						&fixture.archive,
						directory,
						filename,
						expected.get(filename).unwrap().clone(),
					)
				},
				|workers| {
					workers.finish(count as u64)?;
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

#[test]
fn parallel_page_observation_rechecks_warm_off_page_originals() {
	let count = ORIGINAL_READ_BATCH + 1;
	let fixture = Fixture::new(false, count);
	let database = fixture.database(fixture.entries.clone());
	let view = PendingView::default();
	let selected = {
		let _guard = store_lock().unwrap();
		let transaction = database.begin_read().unwrap();
		let rows = transaction.open_table(ROWS).unwrap();
		let order = transaction.open_table(ORDER).unwrap();
		let counts = transaction.open_table(COUNTS).unwrap();
		let (selected, total) = page_from_view(
			&rows,
			&order,
			&counts,
			&fixture.archive,
			&view,
			&fixture.entries[0].record.owner,
			None,
			1,
			budget(),
		)
		.unwrap();
		assert_eq!(total, count as u64);
		// Exclude both the returned page and its extra lookahead record.
		assert_eq!(selected.len(), 2);
		selected
	};
	let victim = fixture
		.entries
		.iter()
		.find(|entry| {
			selected
				.iter()
				.all(|record| record.request_id != entry.record.request_id)
		})
		.unwrap();
	// Use the real two-reader kernel on a small synthetic archive. This tests
	// fresh complete observations, not the production large-row selector.
	parallel_check(&fixture, &database, &view, count as u64).unwrap();
	let mut changed = victim.record.clone();
	changed.elapsed_ms = Some(changed.elapsed_ms.unwrap() + 1);
	let path = fixture
		.root
		.path()
		.join(ARCHIVE_NAME)
		.join(format!("{}.json", changed.request_id));
	std::fs::write(path, serde_json::to_vec(&changed).unwrap()).unwrap();
	let originals_before_refusal = fixture.original_bytes();
	let cache_before_refusal = std::fs::read(fixture.root.path().join(CACHE_NAME)).unwrap();
	assert!(parallel_check(&fixture, &database, &view, count as u64).is_err());
	assert_eq!(fixture.original_bytes(), originals_before_refusal);
	assert_eq!(
		std::fs::read(fixture.root.path().join(CACHE_NAME)).unwrap(),
		cache_before_refusal
	);
}

fn original_batch(
	fixture: &Fixture,
	first: usize,
	count: usize,
	deadline: Instant,
) -> OriginalBatch<'_> {
	let tasks = (first..first + count)
		.map(|number| {
			let expected = fixture.entries[number].clone();
			let filename = format!("{}.json", expected.record.request_id);
			let directory = fixture.archive.directory_for_existing(&filename).unwrap();
			OriginalTask {
				number: number as u64,
				archive: &fixture.archive,
				directory,
				filename,
				expected,
				deadline,
			}
		})
		.collect();
	OriginalBatch {
		first: first as u64,
		tasks,
	}
}

#[test]
fn original_worker_batches_cover_exact_boundaries_and_partial_tails() {
	let fixture = Fixture::new(false, 129);
	let originals = fixture.original_bytes();
	for count in [0usize, 1, 2, 31, 32, 33, 63, 64, 65, 66, 127, 128, 129] {
		let cancelled = AtomicBool::new(false);
		let performed = Mutex::new(Vec::new());
		let batches = Mutex::new(Vec::new());
		let perform = |task: OriginalTask<'_>| {
			performed.lock().unwrap().push(task.number);
			verify_original_task(task)
		};
		let hook = |event| {
			if let OriginalWorkerEvent::BatchSubmitted(lane, first, count) = event {
				batches.lock().unwrap().push((lane, first, count));
			}
		};
		std::thread::scope(|scope| {
			let mut workers = OriginalWorkers::new(&cancelled, budget());
			workers.hook = Some(&hook);
			workers.start(scope, &perform).unwrap();
			for number in 0..count {
				fixture.submit(&mut workers, number).unwrap();
				let retained: u64 = workers
					.lanes
					.iter()
					.map(|lane| {
						assert!(lane.pending.is_empty() || lane.outstanding.is_none());
						lane.pending.len() as u64 + lane.outstanding.map_or(0, |(_, length)| length)
					})
					.sum();
				assert!(retained <= (ORIGINAL_READ_BATCH * ORIGINAL_READ_WORKERS) as u64);
				assert_eq!(retained, workers.submitted - workers.verified);
			}
			workers.finish(count as u64).unwrap();
			assert_eq!(workers.submitted, count as u64);
			assert_eq!(workers.verified, count as u64);
			assert!(workers.lanes.iter().all(|lane| lane.pending.is_empty()
				&& lane.outstanding.is_none()
				&& lane.thread.is_none()));
		});
		let mut actual = performed.into_inner().unwrap();
		actual.sort_unstable();
		assert_eq!(actual, (0..count as u64).collect::<Vec<_>>());
		let expected: Vec<_> = (0..count)
			.step_by(ORIGINAL_READ_BATCH)
			.map(|first| {
				(
					(first / ORIGINAL_READ_BATCH) % ORIGINAL_READ_WORKERS,
					first as u64,
					(count - first).min(ORIGINAL_READ_BATCH) as u64,
				)
			})
			.collect();
		assert_eq!(batches.into_inner().unwrap(), expected);
	}
	assert_eq!(fixture.original_bytes(), originals);
}

#[test]
fn original_worker_batch_failures_preserve_original_chain_and_join_other_lane() {
	for fail_at in [0usize, 15, 31] {
		let count = ORIGINAL_READ_BATCH * ORIGINAL_READ_WORKERS;
		let fixture = Fixture::new(false, count);
		let other_started = Arc::new(Gate::default());
		let release_other = Arc::new(Gate::default());
		let cancelling = Arc::new(Gate::default());
		let performed = Mutex::new(Vec::new());
		let exited = AtomicUsize::new(0);
		let (send_done, receive_done) = std::sync::mpsc::channel();
		std::thread::scope(|outer| {
			let _release = ReleaseGates(vec![other_started.clone(), release_other.clone()]);
			outer.spawn(|| {
				let cancelled = AtomicBool::new(false);
				let perform = |task: OriginalTask<'_>| {
					let number = task.number as usize;
					performed.lock().unwrap().push(number);
					if number == 0 {
						other_started.wait();
					}
					if number == ORIGINAL_READ_BATCH {
						other_started.release();
						release_other.wait();
					}
					if number == fail_at {
						return Err(anyhow::Error::new(OriginalFailure)
							.context("batched original read context"));
					}
					verify_original_task(task)
				};
				let hook = |event| match event {
					OriginalWorkerEvent::CancellationStarted => cancelling.release(),
					OriginalWorkerEvent::Exiting(_) => {
						exited.fetch_add(1, Ordering::SeqCst);
					}
					_ => {}
				};
				let result = std::thread::scope(|scope| {
					let mut workers = OriginalWorkers::new(&cancelled, budget());
					workers.hook = Some(&hook);
					workers.start(scope, &perform)?;
					for number in 0..count {
						fixture.submit(&mut workers, number)?;
					}
					workers.finish(count as u64)
				});
				send_done.send(result).unwrap();
			});
			cancelling.wait();
			assert!(matches!(
				receive_done.recv_timeout(Duration::from_millis(25)),
				Err(std::sync::mpsc::RecvTimeoutError::Timeout)
			));
			release_other.release();
			let error = receive_done
				.recv_timeout(Duration::from_secs(10))
				.unwrap()
				.unwrap_err();
			assert!(error.is::<OriginalFailure>());
			assert_eq!(error.to_string(), "batched original read context");
			assert_eq!(error.root_cause().to_string(), "original synthetic failure");
			assert_eq!(exited.load(Ordering::SeqCst), ORIGINAL_READ_WORKERS);
		});
		let mut actual = performed.into_inner().unwrap();
		actual.sort_unstable();
		let expected: Vec<_> = (0..=fail_at).chain([ORIGINAL_READ_BATCH]).collect();
		assert_eq!(actual, expected, "no failing batch suffix may run");
	}
}

#[test]
fn original_worker_batch_cancellation_discards_partial_tail_and_running_suffix() {
	let fixture = Fixture::new(false, ORIGINAL_READ_WORKERS * ORIGINAL_READ_BATCH - 1);
	let started = Arc::new(Gate::default());
	let release = Arc::new(Gate::default());
	let cancelling = Arc::new(Gate::default());
	let performed = Mutex::new(Vec::new());
	let batches = Mutex::new(Vec::new());
	let exited = AtomicUsize::new(0);
	let (send_done, receive_done) = std::sync::mpsc::channel();
	std::thread::scope(|outer| {
		let _release = ReleaseGates(vec![started.clone(), release.clone()]);
		outer.spawn(|| {
			let cancelled = AtomicBool::new(false);
			let perform = |task: OriginalTask<'_>| {
				performed.lock().unwrap().push(task.number);
				assert_eq!(
					task.number, 0,
					"neither the queued suffix nor the pending tail may run"
				);
				started.release();
				release.wait();
				verify_original_task(task)
			};
			let hook = |event| match event {
				OriginalWorkerEvent::BatchSubmitted(lane, first, count) => {
					batches.lock().unwrap().push((lane, first, count));
				}
				OriginalWorkerEvent::CancellationStarted => cancelling.release(),
				OriginalWorkerEvent::Exiting(_) => {
					exited.fetch_add(1, Ordering::SeqCst);
				}
				_ => {}
			};
			let result: Result<()> = std::thread::scope(|scope| {
				let mut workers = OriginalWorkers::new(&cancelled, budget());
				workers.hook = Some(&hook);
				workers.start(scope, &perform)?;
				for number in 0..fixture.entries.len() {
					fixture.submit(&mut workers, number)?;
				}
				assert_eq!(
					workers.lanes[0].outstanding,
					Some((0, ORIGINAL_READ_BATCH as u64))
				);
				assert_eq!(workers.lanes[1].pending.len(), ORIGINAL_READ_BATCH - 1);
				assert!(workers.lanes[1].outstanding.is_none());
				started.wait();
				Err(anyhow::Error::new(OriginalFailure).context("producer left a partial batch"))
			});
			send_done.send(result).unwrap();
		});
		cancelling.wait();
		assert!(matches!(
			receive_done.recv_timeout(Duration::from_millis(25)),
			Err(std::sync::mpsc::RecvTimeoutError::Timeout)
		));
		release.release();
		let error = receive_done
			.recv_timeout(Duration::from_secs(10))
			.unwrap()
			.unwrap_err();
		assert!(error.is::<OriginalFailure>());
		assert_eq!(error.to_string(), "producer left a partial batch");
		assert_eq!(exited.load(Ordering::SeqCst), ORIGINAL_READ_WORKERS);
	});
	assert_eq!(*performed.lock().unwrap(), vec![0]);
	assert_eq!(
		*batches.lock().unwrap(),
		vec![(0, 0, ORIGINAL_READ_BATCH as u64)]
	);
}

#[test]
fn original_worker_batch_reply_identity_and_complete_coverage_are_required() {
	for (first, count, verified, text) in [
		(1, 32, 32, "task identity changed"),
		(0, 0, 0, "task identity changed"),
		(0, 31, 31, "task identity changed"),
		(0, 33, 33, "task identity changed"),
		(0, 32, 31, "completion changed"),
		(0, 32, 33, "completion changed"),
	] {
		let cancelled = AtomicBool::new(false);
		let (send, receive) = std::sync::mpsc::sync_channel(1);
		send.send(OriginalReply {
			first,
			count,
			verified,
			result: Ok(()),
		})
		.unwrap();
		let mut workers = OriginalWorkers::new(&cancelled, budget());
		workers.submitted = ORIGINAL_READ_BATCH as u64;
		workers.lanes[0].receive = Some(receive);
		workers.lanes[0].outstanding = Some((0, ORIGINAL_READ_BATCH as u64));
		assert!(workers.receive(0).unwrap_err().to_string().contains(text));
		assert_eq!(workers.verified, 0);
		assert_eq!(workers.lanes[0].verified, 0);
	}
	// A real read error after a successful prefix must survive the smaller
	// verified count; it is not a fabricated coverage error or full success.
	let cancelled = AtomicBool::new(false);
	let (send, receive) = std::sync::mpsc::sync_channel(1);
	let mut workers = OriginalWorkers::new(&cancelled, budget());
	workers.lanes[0].receive = Some(receive);
	workers.lanes[0].outstanding = Some((0, ORIGINAL_READ_BATCH as u64));
	send.send(OriginalReply {
		first: 0,
		count: ORIGINAL_READ_BATCH as u64,
		verified: 15,
		result: Err(anyhow::Error::new(OriginalFailure).context("partial original batch")),
	})
	.unwrap();
	let error = workers.receive(0).unwrap_err();
	assert!(error.is::<OriginalFailure>());
	assert_eq!(error.root_cause().to_string(), "original synthetic failure");
	assert_eq!(workers.verified, 0);
	drop(workers);
	// A duplicate old reply cannot be accepted for the next generation of the
	// same lane, even though its count and successful prefix are well formed.
	let cancelled = AtomicBool::new(false);
	let (send, receive) = std::sync::mpsc::sync_channel(1);
	let mut workers = OriginalWorkers::new(&cancelled, budget());
	workers.submitted = 65;
	workers.lanes[0].receive = Some(receive);
	workers.lanes[0].outstanding = Some((0, ORIGINAL_READ_BATCH as u64));
	send.send(OriginalReply {
		first: 0,
		count: ORIGINAL_READ_BATCH as u64,
		verified: ORIGINAL_READ_BATCH as u64,
		result: Ok(()),
	})
	.unwrap();
	workers.receive(0).unwrap();
	workers.lanes[0].outstanding = Some((64, 1));
	send.send(OriginalReply {
		first: 0,
		count: ORIGINAL_READ_BATCH as u64,
		verified: ORIGINAL_READ_BATCH as u64,
		result: Ok(()),
	})
	.unwrap();
	assert!(workers
		.receive(0)
		.unwrap_err()
		.to_string()
		.contains("task identity changed"));
	assert_eq!(workers.verified, ORIGINAL_READ_BATCH as u64);
}

#[test]
fn original_worker_batches_refuse_invalid_task_sequences_and_extended_deadlines() {
	let fixture = Fixture::new(false, ORIGINAL_READ_BATCH + 1);
	for (case, count, expected_prefix, text) in [
		(0, 0, 0, "batch coverage changed"),
		(1, 33, 0, "batch coverage changed"),
		(2, 2, 0, "batch coverage changed"),
		(3, 2, 1, "task identity changed"),
		(4, 2, 1, "task identity changed"),
	] {
		let deadline = budget();
		let cancelled = AtomicBool::new(false);
		let performed = AtomicUsize::new(0);
		let mut batch = original_batch(&fixture, 0, count, deadline);
		match case {
			2 => batch.first = u64::MAX - 1,
			3 => batch.tasks[1].number = 7,
			4 => batch.tasks[1].deadline = deadline + Duration::from_secs(1),
			_ => {}
		}
		let perform = |task: OriginalTask<'_>| {
			performed.fetch_add(1, Ordering::SeqCst);
			verify_original_task(task)
		};
		let reply = perform_original_batch(batch, &cancelled, deadline, &perform);
		assert_eq!(reply.count, count as u64);
		assert_eq!(reply.verified, expected_prefix as u64);
		assert_eq!(performed.load(Ordering::SeqCst), expected_prefix);
		assert!(reply.result.unwrap_err().to_string().contains(text));
	}
	let deadline = budget();
	let cancelled = AtomicBool::new(true);
	let perform = |_task: OriginalTask<'_>| -> Result<()> {
		panic!("an already cancelled batch must not start its first original read")
	};
	let reply = perform_original_batch(
		original_batch(&fixture, 0, 2, deadline),
		&cancelled,
		deadline,
		&perform,
	);
	assert_eq!(reply.verified, 0);
	assert!(reply
		.result
		.unwrap_err()
		.to_string()
		.contains("worker cancelled"));
}

#[test]
fn original_worker_batches_keep_each_original_directory_across_shard_boundaries() {
	let count = ORIGINAL_READ_WORKERS * ORIGINAL_READ_BATCH + 1;
	let ids = (0..count).map(|number| {
		let prefix = if number < ORIGINAL_READ_BATCH - 1 {
			"00"
		} else {
			"01"
		};
		format!("{prefix}{number:062x}")
	});
	let fixture = Fixture::with_ids(true, ids);
	let database = fixture.database(fixture.entries.clone());
	let originals = fixture.original_bytes();
	let cache = std::fs::read(fixture.root.path().join(CACHE_NAME)).unwrap();
	// Two full batches and the last record exercise the real complete walk,
	// original readers, DB identity join and all terminal namespace fences.
	parallel_check(&fixture, &database, &PendingView::default(), count as u64).unwrap();
	assert_eq!(fixture.original_bytes(), originals);
	assert_eq!(
		std::fs::read(fixture.root.path().join(CACHE_NAME)).unwrap(),
		cache
	);
	// Explicitly cross the directory boundary inside one batch, independent
	// of directory enumeration order; the same filename under a wrong shard
	// descriptor must be refused, never silently read through a batch-wide fd.
	let deadline = budget();
	let cancelled = AtomicBool::new(false);
	let good = perform_original_batch(
		original_batch(&fixture, 0, ORIGINAL_READ_BATCH, deadline),
		&cancelled,
		deadline,
		&verify_original_task,
	);
	assert_eq!(good.verified, ORIGINAL_READ_BATCH as u64);
	good.result.unwrap();
	let mut wrong = original_batch(&fixture, 0, ORIGINAL_READ_BATCH, deadline);
	let first_directory = wrong.tasks[0].directory;
	wrong.tasks[ORIGINAL_READ_BATCH - 1].directory = first_directory;
	let bad = perform_original_batch(wrong, &cancelled, deadline, &verify_original_task);
	assert!(bad.result.is_err());
	assert_eq!(bad.verified, (ORIGINAL_READ_BATCH - 1) as u64);
	assert_eq!(fixture.original_bytes(), originals);
	assert_eq!(
		std::fs::read(fixture.root.path().join(CACHE_NAME)).unwrap(),
		cache
	);
}
