// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! The real pool owner's exit cannot discard an uncertain child ledger.
use super::*;

pub(super) async fn run(path: &Path, fail_cleanup: bool) {
	// Use start's actual dedicated thread and joining path. Holding a test's
	// own Core through shutdown would conceal the lifetime regression.
	let guard = start(path).await.unwrap();
	let proxy = guard.0.clone();
	let core = proxy.custody.lock().unwrap().as_ref().unwrap().clone();
	assert_ne!(core.owner_tid, unsafe { libc::syscall(libc::SYS_gettid) });
	let root = core.root.path.clone();
	let weak_core = Arc::downgrade(&core);
	let global = Arc::new(Semaphore::new(MAX_SESSIONS));
	let host = Arc::new(Semaphore::new(HOST_SESSIONS));
	let child = Command::new("python3")
		.args(["-I", "-S", "-c", "import sys; sys.stdin.buffer.read()"])
		.stdin(Stdio::piped())
		.stdout(Stdio::null())
		.stderr(Stdio::null())
		.kill_on_drop(true)
		.spawn()
		.unwrap();
	let pid = child.id().unwrap();
	// This local pipe-blocked fixture is an original Child, not a fabricated
	// PID. Transfer its sole strong owner and all three budgets to the real
	// pool ledger; no SSH server or external process is signalled by the test.
	let id = core.sequence.fetch_add(1, Ordering::Relaxed);
	let owned = Arc::new(OwnedChild {
		id,
		pid,
		pidfd: None,
		identity: OnceLock::new(),
		approved: AtomicBool::new(false),
		child: AsyncMutex::new(child),
		_permits: vec![
			Arc::new(proxy.admission.clone().try_acquire_owned().unwrap()),
			Arc::new(global.clone().try_acquire_owned().unwrap()),
			Arc::new(host.clone().try_acquire_owned().unwrap()),
		],
	});
	let weak_child = Arc::downgrade(&owned);
	assert!(core.children.lock().await.insert(id, owned).is_none());
	if fail_cleanup {
		// The actual shutdown returns before reaping on a poisoned supervisor
		// ledger. A caught fixture panic exercises that existing error path.
		let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
			let _held = core.background.lock().unwrap();
			panic!("controlled pool owner cleanup poison");
		}));
		assert!(poisoned.is_err());
	}
	drop(core);
	// At this point the fixture retains only Weak<Core>/Weak<OwnedChild>.
	// Neither can make a failed thread's otherwise abandoned ledger survive.
	let result = timeout(Duration::from_secs(5), guard.shutdown())
		.await
		.unwrap();
	assert!(proxy.thread.lock().unwrap().is_none());
	assert!(!proxy.healthy.load(Ordering::Acquire));
	assert!(proxy.stop.is_cancelled());
	if fail_cleanup {
		let error = result.unwrap_err();
		assert!(
			error.to_string().contains("supervisor unavailable"),
			"{error:#}"
		);
		assert_eq!(proxy.admission.available_permits(), MAX_ADMITTED - 1);
		assert_eq!(global.available_permits(), MAX_SESSIONS - 1);
		assert_eq!(host.available_permits(), HOST_SESSIONS - 1);
		let core = weak_core
			.upgrade()
			.expect("failed owner lost its original ledger");
		let owned = weak_child
			.upgrade()
			.expect("failed owner discarded its original child");
		assert!(Arc::ptr_eq(
			proxy.custody.lock().unwrap().as_ref().unwrap(),
			&core,
		));
		assert!(Arc::ptr_eq(
			core.children.lock().await.get(&id).unwrap(),
			&owned,
		));
		assert!(owned.child.lock().await.try_wait().unwrap().is_none());
		assert!(root.exists());
		assert!(capture(
			"fixture",
			"NEVER_DISPATCH".into(),
			vec![],
			Duration::from_secs(1),
		)
		.await
		.is_err());
		assert!(
			start(path).await.is_err(),
			"failed owner must not be replaced"
		);
		// Explicit fixture cleanup of its own child only, after the assertions.
		// Production exposes no retry/replacement or custody-clearing API.
		core.background.clear_poison();
		core.stop_child(&owned, Duration::ZERO).await.unwrap();
		core.release(&owned).await.unwrap();
		drop(owned);
		let cleanup = core.shutdown().await;
		core.validation.finish_shutdown(cleanup).await.unwrap();
		drop(proxy.custody.lock().unwrap().take());
		drop(core);
	} else {
		result.unwrap();
		assert!(proxy.custody.lock().unwrap().is_none());
	}
	assert!(weak_core.upgrade().is_none());
	assert!(weak_child.upgrade().is_none());
	assert!(!root.exists());
	assert!(!PathBuf::from(format!("/proc/{pid}")).exists());
	assert_eq!(proxy.admission.available_permits(), MAX_ADMITTED);
	assert_eq!(global.available_permits(), MAX_SESSIONS);
	assert_eq!(host.available_permits(), HOST_SESSIONS);
}
