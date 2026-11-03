// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Final entry stays with the independent owner and its original child.

use super::*;

struct EntryGuard {
	live: Arc<AtomicBool>,
	// A host guard is required to be Send, not Sync.
	_not_sync: std::cell::Cell<()>,
}

impl EntryGuard {
	fn new(live: Arc<AtomicBool>) -> Self {
		live.store(true, Ordering::Release);
		Self {
			live,
			_not_sync: std::cell::Cell::new(()),
		}
	}
}

impl Drop for EntryGuard {
	fn drop(&mut self) {
		self.live.store(false, Ordering::Release);
	}
}

#[tokio::test]
async fn queued_cancellation_and_expiry_never_consume_final_entry() {
	let owner = Owner::new();
	let fixture = Fixture::new();
	let entered = Arc::new(AtomicU64::new(0));
	for expired in [false, true] {
		let deadline = if expired {
			Instant::now() - Duration::from_millis(1)
		} else {
			Instant::now() + Duration::from_secs(5)
		};
		let (mut request, cancel, receive) =
			queued_request(&owner, &fixture, usize::from(expired), deadline).await;
		let count = entered.clone();
		request.entry = Some(Box::new(move || {
			count.fetch_add(1, Ordering::AcqRel);
			Ok(Box::new(()))
		}));
		if !expired {
			cancel.cancel();
		}
		assert!(owner.0.sender.try_send(request).is_ok());
		assert!(reply(receive).await.is_err());
	}
	assert_eq!(entered.load(Ordering::Acquire), 0);
	assert_eq!(owner.0.core.hooks.spawned.load(Ordering::Acquire), 0);
	assert!(!fixture.ready(0).exists() && !fixture.ready(1).exists());
	owner.finish().await;
}

#[tokio::test]
async fn denied_entry_never_spawns_and_failed_spawn_releases_its_guard() {
	let owner = Owner::new();
	let fixture = Fixture::new();
	let error = owner
		.0
		.capture_with_entry(
			"host",
			fixture.command(0),
			b"",
			Instant::now() + Duration::from_secs(5),
			|| -> Result<()> { bail!("revoked at final physical entry") },
		)
		.await
		.unwrap_err();
	assert!(error
		.to_string()
		.contains("revoked at final physical entry"));
	assert!(!fixture.ready(0).exists());
	let live = Arc::new(AtomicBool::new(false));
	let guard_live = live.clone();
	let mut command = Command::new("/hepta-test-missing-ssh-executable");
	pipes(&mut command);
	assert!(owner
		.0
		.capture_with_entry(
			"host",
			command,
			b"",
			Instant::now() + Duration::from_secs(5),
			move || Ok(EntryGuard::new(guard_live)),
		)
		.await
		.is_err());
	assert!(!live.load(Ordering::Acquire));
	assert_eq!(owner.0.core.hooks.spawned.load(Ordering::Acquire), 0);
	owner.finish().await;
}

#[tokio::test]
async fn cancelled_caller_cannot_release_entry_guard_before_original_child_reap() {
	let owner = Owner::new();
	let fixture = Fixture::new();
	let gate = Arc::new(Gate::default());
	let _release = ReleaseGate(gate.clone());
	*owner.0.core.hooks.child.lock().unwrap() = Some(ChildHooks {
		before_reap: Mutex::new(Some(gate.clone())),
		unconfirmed_wait: false,
	});
	let live = Arc::new(AtomicBool::new(false));
	let guard_live = live.clone();
	let entered = Arc::new(AtomicU64::new(0));
	let count = entered.clone();
	let proxy = owner.0.clone();
	let command = fixture.command(0);
	let call = tokio::spawn(async move {
		proxy
			.capture_with_entry(
				"host",
				command,
				b"input-0",
				Instant::now() + Duration::from_secs(5),
				move || {
					count.fetch_add(1, Ordering::AcqRel);
					Ok(EntryGuard::new(guard_live))
				},
			)
			.await
	});
	until(|| fixture.ready(0).exists()).await;
	assert!(live.load(Ordering::Acquire));
	call.abort();
	assert!(call.await.unwrap_err().is_cancelled());
	until(|| gate.reached.load(Ordering::Acquire)).await;
	assert!(
		live.load(Ordering::Acquire),
		"entry guard must survive the cancelled caller"
	);
	assert_eq!(entered.load(Ordering::Acquire), 1);
	assert_eq!(owner.0.global.available_permits(), GLOBAL_CONNECTIONS - 1);
	gate.release();
	idle(&owner).await;
	assert!(!live.load(Ordering::Acquire));
	assert_eq!(owner.0.core.hooks.spawned.load(Ordering::Acquire), 1);
	owner.finish().await;
}
