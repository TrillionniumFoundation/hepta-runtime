// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Original-child retirement must not stop unrelated host admission.
use super::*;

async fn wait_until(mut ready: impl FnMut() -> bool) {
	timeout(Duration::from_secs(5), async {
		while !ready() {
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
}

// This regression uses only pre-change actor/entry/child interfaces. The
// original inline maintenance waits on the held Child and misses the cold
// dispatch deadline; no timing-dependent real network outage is required.
async fn slow_retirement(core: &Arc<Core>) {
	let (master, generation, _listener) = retired_generation(core, Duration::ZERO).await;
	let old = core
		.entry(
			"fixture",
			&CancellationToken::new(),
			Instant::now() + Duration::from_secs(10),
		)
		.await
		.unwrap();
	let host_permit = old.permits.clone().acquire_owned().await.unwrap();
	let original_child = master.owned.child.lock().await;
	let (sender, receiver) = mpsc::channel(QUEUE);
	let global = Arc::new(Semaphore::new(MAX_SESSIONS));
	let task_core = core.clone();
	let task_global = global.clone();
	let mut actor = tokio::task::spawn_local(async move {
		task_core
			.run_with_dispatch(receiver, task_global, |core, request, permit| async move {
				let _permit = permit;
				assert_eq!(request.host, "cold");
				let result = core
					.entry("fixture", &request.cancel, request.deadline)
					.await
					.and_then(|binding| {
						assert_eq!(binding.permits.available_permits(), HOST_SESSIONS - 1);
						Err(anyhow!("controlled cold-host dispatch completed"))
					});
				let _ = request.reply.send(result);
			})
			.await
	});
	wait_until(|| !master.accepting.load(Ordering::Acquire)).await;
	let (reply, receive) = oneshot::channel();
	sender
		.send(Request {
			host: "cold".into(),
			command: "controlled-dispatch".into(),
			input: vec![],
			deadline: Instant::now() + Duration::from_secs(3),
			cancel: CancellationToken::new(),
			reply,
			admission: test_admission(),
		})
		.await
		.unwrap();
	let dispatched = timeout(Duration::from_secs(2), receive).await;
	core.stop.cancel();
	// Shutdown must stay pending while the exact original cleanup is blocked.
	let stopped =
		std::future::poll_fn(|cx| std::task::Poll::Ready(std::pin::Pin::new(&mut actor).poll(cx)))
			.await;
	assert!(
		stopped.is_pending(),
		"actor escaped its original retirement"
	);
	assert_eq!(old.permits.available_permits(), HOST_SESSIONS - 1);
	drop(original_child);
	timeout(Duration::from_secs(5), actor)
		.await
		.unwrap()
		.unwrap()
		.unwrap();
	{
		let entries = core.masters.lock().await;
		let retained = entries.get("fixture").unwrap();
		assert_eq!(retained.generation, generation);
		assert!(Arc::ptr_eq(&retained.permits, &old.permits));
	}
	assert!(core.children.lock().await.is_empty());
	assert!(!master.socket.exists());
	assert_eq!(global.available_permits(), MAX_SESSIONS);
	drop(host_permit);
	core.maintain().await.unwrap();
	assert!(core.masters.lock().await.is_empty());
	drop(sender);
	let error = match dispatched {
		Ok(Ok(Err(error))) => error,
		_ => panic!("slow original master retirement blocked another host's actor dispatch"),
	};
	assert!(error
		.to_string()
		.contains("controlled cold-host dispatch completed"));
}

async fn concurrent_renewal(core: &Arc<Core>) {
	let (master, generation, _listener) = retired_generation(core, Duration::ZERO).await;
	let cancel = CancellationToken::new();
	let deadline = Instant::now() + Duration::from_secs(10);
	let old = core.entry("fixture", &cancel, deadline).await.unwrap();
	let original_child = master.owned.child.lock().await;
	let maintenance_core = core.clone();
	let maintenance = tokio::task::spawn_local(async move { maintenance_core.maintain().await });
	wait_until(|| !master.accepting.load(Ordering::Acquire)).await;
	core.renew("fixture", generation, &master, deadline, &cancel)
		.await
		.unwrap();
	let mut renewed = core.entry("fixture", &cancel, deadline).await.unwrap();
	assert_ne!(renewed.generation, generation);
	assert!(Arc::ptr_eq(&renewed.permits, &old.permits));
	core.stop.cancel();
	drop(original_child);
	timeout(Duration::from_secs(5), maintenance)
		.await
		.unwrap()
		.unwrap()
		.unwrap();
	assert!(renewal_error(&mut renewed.ready)
		.await
		.contains("stopped before new master"));
	{
		let entries = core.masters.lock().await;
		let current = entries.get("fixture").unwrap();
		assert_eq!(current.generation, renewed.generation);
		assert!(current.ready.same_channel(&renewed.ready));
		assert!(Arc::ptr_eq(&current.permits, &old.permits));
	}
	assert!(matches!(&*master.retirement.lock().await, Some(Ok(()))));
	assert!(core.children.lock().await.is_empty());
	assert!(!master.socket.exists());
}

async fn persistent_cleanup_failure(core: &Arc<Core>) {
	let (master, _, _listener) = retired_generation(core, Duration::ZERO).await;
	std::fs::remove_file(&master.socket).unwrap();
	let _replacement = tokio::net::UnixListener::bind(&master.socket).unwrap();
	std::fs::set_permissions(&master.socket, std::fs::Permissions::from_mode(0o600)).unwrap();
	let replacement = profile::socket_stamp(&master.socket).unwrap();
	assert_ne!(replacement, master.stamp);
	let (_sender, receiver) = mpsc::channel(QUEUE);
	let task_core = core.clone();
	let actor = tokio::task::spawn_local(async move {
		task_core
			.run_with_dispatch(
				receiver,
				Arc::new(Semaphore::new(MAX_SESSIONS)),
				|_, _, _| async { panic!("no request was submitted") },
			)
			.await
	});
	let error = timeout(Duration::from_secs(5), actor)
		.await
		.unwrap()
		.unwrap()
		.unwrap_err();
	assert!(
		error.to_string().contains("cleanup identity uncertain"),
		"{error:#}"
	);
	assert!(core.stop.is_cancelled());
	assert!(matches!(&*master.retirement.lock().await, Some(Err(_))));
	let repeat = core.retire_master(&master).await.unwrap_err();
	assert!(repeat.to_string().contains("original retirement failed"));
	assert_eq!(profile::socket_stamp(&master.socket).unwrap(), replacement);
	assert!(core
		.entry(
			"cold",
			&CancellationToken::new(),
			Instant::now() + Duration::from_secs(1),
		)
		.await
		.is_err());
	// The fixture alone owns this replacement; production retained and refused it.
	std::fs::remove_file(&master.socket).unwrap();
}

async fn maintenance_panic(core: &Arc<Core>) {
	let (_sender, receiver) = mpsc::channel(QUEUE);
	let task_core = core.clone();
	let actor = tokio::task::spawn_local(async move {
		task_core
			.run_with_maintenance(
				receiver,
				Arc::new(Semaphore::new(MAX_SESSIONS)),
				|_, _, _| async { panic!("no request was submitted") },
				|_| async { panic!("injected maintenance owner panic") },
			)
			.await
	});
	let error = timeout(Duration::from_secs(5), actor)
		.await
		.unwrap()
		.unwrap()
		.unwrap_err();
	assert!(
		error.to_string().contains("maintenance supervisor failed"),
		"{error:#}"
	);
	assert!(core.stop.is_cancelled());
	assert!(core
		.entry(
			"cold",
			&CancellationToken::new(),
			Instant::now() + Duration::from_secs(1),
		)
		.await
		.is_err());
}

#[test]
fn isolated_master_retirement_preserves_other_hosts_and_cleanup_custody() {
	for kind in ["slow", "renewal", "failure", "panic"] {
		let mut child = std::process::Command::new(std::env::current_exe().unwrap())
			.args([
				"--exact",
				"mcp::runtime::ssh::observation_pool::tests::maintenance::isolated_helper",
				"--ignored",
				"--nocapture",
			])
			.env("HEPTA_RETIREMENT_TEST_FIXTURE", kind)
			.stdin(Stdio::null())
			.stdout(Stdio::null())
			.stderr(Stdio::inherit())
			.spawn()
			.unwrap();
		let deadline = std::time::Instant::now() + Duration::from_secs(30);
		loop {
			if let Some(status) = child.try_wait().unwrap() {
				assert!(status.success(), "retirement fixture {kind}: {status}");
				break;
			}
			if std::time::Instant::now() >= deadline {
				child.kill().unwrap();
				let _ = child.wait();
				panic!("retirement fixture {kind} exceeded its original deadline");
			}
			std::thread::sleep(Duration::from_millis(20));
		}
	}
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "private subprocess fixture; invoked by the bounded parent test"]
async fn isolated_helper() {
	let kind = std::env::var("HEPTA_RETIREMENT_TEST_FIXTURE").unwrap();
	let (_root, path, agent, _) = fixture_with_cold_host(true).await;
	let core = core(&path).await;
	tokio::task::LocalSet::new()
		.run_until(async {
			match kind.as_str() {
				"slow" => slow_retirement(&core).await,
				"renewal" => concurrent_renewal(&core).await,
				"failure" => persistent_cleanup_failure(&core).await,
				"panic" => maintenance_panic(&core).await,
				_ => panic!("unsupported retirement fixture"),
			}
			core.shutdown().await.unwrap();
		})
		.await;
	assert!(core.children.lock().await.is_empty());
	assert!(core.masters.lock().await.is_empty());
	assert!(!core.root.path.exists());
	agent.abort();
	let _ = agent.await;
}
