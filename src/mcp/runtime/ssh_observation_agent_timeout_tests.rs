// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Isolated fixtures for missing lookup authority, never cached acceptance.
use super::*;

#[tokio::test(flavor = "current_thread")]
async fn unrelated_timeouts_and_identical_error_text_are_not_lookup_deadlines() {
	let elapsed = timeout(Duration::ZERO, std::future::pending::<()>())
		.await
		.unwrap_err();
	for error in [
		anyhow!("observation SSH agent deadline"),
		anyhow!(std::io::Error::new(
			std::io::ErrorKind::TimedOut,
			"observation SSH agent deadline",
		)),
		anyhow!(elapsed).context("observation SSH agent deadline"),
	] {
		assert!(!error.is::<profile::AgentLookupDeadline>());
	}
}

async fn lookup_closed(control: &Arc<AgentControl>, expected: usize) {
	timeout(Duration::from_secs(3), async {
		while control.deadline_closed.load(Ordering::Acquire) < expected {
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
	assert_eq!(control.deadline_closed.load(Ordering::Acquire), expected);
}

fn arm_next_lookup(control: &Arc<AgentControl>, offset: usize) -> usize {
	let before = control.requests.load(Ordering::Acquire);
	control
		.deadline_request
		.store(before + offset, Ordering::Release);
	before
}

pub(super) async fn startup(path: &Path, control: &Arc<AgentControl>, kind: &str) {
	let selected = match kind {
		"agent-startup-unbound-timeout" => 1,
		"agent-startup-bound-timeout" => 2,
		"agent-startup-final-timeout" => 3,
		_ => panic!("unsupported startup lookup fixture"),
	};
	control.deadline_request.store(selected, Ordering::Release);
	let error = timeout(Duration::from_secs(12), start(path))
		.await
		.unwrap()
		.err()
		.expect("missing initial authority must refuse the whole pool");
	assert!(error.to_string().contains("observation SSH agent deadline"));
	lookup_closed(control, 1).await;
	let pool = POOL.get().unwrap();
	assert!(!pool.healthy.load(Ordering::Acquire));
	assert!(pool.stop.is_cancelled());
	assert!(pool.thread.lock().unwrap().is_none());
	assert_eq!(pool.admission.available_permits(), MAX_ADMITTED);
	assert_eq!(control.requests.load(Ordering::Acquire), selected);
	assert!(capture(
		"fixture",
		"NEVER_DISPATCH".into(),
		vec![],
		Duration::from_secs(1),
	)
	.await
	.is_err());
	assert_eq!(control.requests.load(Ordering::Acquire), selected);
}

async fn request_phase(core: &Arc<Core>, control: &Arc<AgentControl>, prelease: bool) {
	// The terminal ssh -G generation reaches the real prelease check but must
	// never be presented as an authenticated master or reach slave creation.
	let retired = if prelease {
		Some(retired_generation(core, Duration::from_secs(10)).await)
	} else {
		None
	};
	let offset = if prelease { 2 } else { 1 };
	let before = arm_next_lookup(control, offset);
	let sequence = core.sequence.load(Ordering::Acquire);
	let global = Arc::new(Semaphore::new(MAX_SESSIONS));
	let admissions = Arc::new(Semaphore::new(MAX_ADMITTED));
	let (reply, receive) = oneshot::channel();
	let request = Request {
		host: "fixture".into(),
		command: "NEVER_DISPATCH".into(),
		input: vec![],
		deadline: Instant::now() + Duration::from_millis(500),
		cancel: CancellationToken::new(),
		reply,
		admission: Arc::new(admissions.clone().try_acquire_owned().unwrap()),
	};
	let initial = global.clone().try_acquire_owned().unwrap();
	timeout(
		Duration::from_secs(3),
		core.clone().execute(request, initial, global.clone()),
	)
	.await
	.unwrap();
	let error = receive.await.unwrap().err().unwrap();
	assert!(error.is::<profile::AgentLookupDeadline>(), "{error:#}");
	assert!(error
		.context("caller context preserves the exact failure type")
		.is::<profile::AgentLookupDeadline>());
	lookup_closed(control, 1).await;
	assert!(!core.stop.is_cancelled());
	assert_eq!(control.requests.load(Ordering::Acquire), before + offset);
	assert_eq!(core.sequence.load(Ordering::Acquire), sequence);
	assert_eq!(global.available_permits(), MAX_SESSIONS);
	assert_eq!(admissions.available_permits(), MAX_ADMITTED);
	if let Some((master, generation, _)) = &retired {
		let entries = core.masters.lock().await;
		let entry = entries.get("fixture").unwrap();
		assert_eq!(entry.generation, *generation);
		assert_eq!(entry.permits.available_permits(), HOST_SESSIONS);
		assert_eq!(master.active.load(Ordering::Acquire), 0);
		assert!(master.accepting.load(Ordering::Acquire));
		assert_eq!(core.children.lock().await.len(), 1);
	} else {
		assert!(core.masters.lock().await.is_empty());
		assert!(core.children.lock().await.is_empty());
	}
	core.verify_request_profile(Instant::now() + Duration::from_secs(3))
		.await
		.unwrap();
	assert_eq!(
		control.requests.load(Ordering::Acquire),
		before + offset + 1
	);
	assert!(!core.stop.is_cancelled());
}

async fn postresponse(core: &Arc<Core>, agent: &Arc<AgentControl>) {
	let global = Arc::new(Semaphore::new(MAX_SESSIONS));
	let admissions = Arc::new(Semaphore::new(MAX_ADMITTED));
	let host = Arc::new(Semaphore::new(HOST_SESSIONS));
	let release = Arc::new(Semaphore::new(0));
	let (completed_send, mut completed) = mpsc::channel(MAX_SESSIONS);
	let control = Arc::new(PostverifyControl {
		global: global.clone(),
		host: host.clone(),
		completed: completed_send,
		release: release.clone(),
	});
	let (sender, receiver) = mpsc::channel(QUEUE);
	let actor = tokio::task::spawn_local(core.clone().run_with_dispatch(
		receiver,
		global.clone(),
		move |core, request, initial| postverify_dispatch(core, request, initial, control.clone()),
	));
	let before = agent.requests.load(Ordering::Acquire);
	let first = enqueue_fair_request(
		&sender,
		&admissions,
		"fixture",
		"must-discard-completed-output",
		Instant::now() + Duration::from_secs(15),
	);
	assert_eq!(phase_notice(&mut completed).await, first.command);
	assert_eq!(agent.requests.load(Ordering::Acquire), before + 2);
	assert!(core.children.lock().await.is_empty());
	assert_eq!(host.available_permits(), HOST_SESSIONS);
	assert_eq!(global.available_permits(), MAX_SESSIONS - 1);
	assert_eq!(admissions.available_permits(), MAX_ADMITTED - 1);
	arm_next_lookup(agent, 1);
	release.add_permits(1);
	let error = timeout(Duration::from_secs(5), first.reply)
		.await
		.unwrap()
		.unwrap()
		.err()
		.expect("captured bytes cannot survive a missing response authority check");
	assert!(error.is::<profile::AgentLookupDeadline>(), "{error:#}");
	lookup_closed(agent, 1).await;
	assert_eq!(agent.requests.load(Ordering::Acquire), before + 3);
	assert_eq!(global.available_permits(), MAX_SESSIONS);
	assert_eq!(admissions.available_permits(), MAX_ADMITTED);
	assert!(core.children.lock().await.is_empty());
	assert!(!core.stop.is_cancelled());
	assert!(!actor.is_finished());
	// A distinct later request performs initial, prelease and postresponse
	// checks again. It runs a new real, owned ssh -G child; it is not a replay
	// or an authenticated-mux integration fixture.
	let second = enqueue_fair_request(
		&sender,
		&admissions,
		"fixture",
		"separate-request-with-fresh-checks",
		Instant::now() + Duration::from_secs(15),
	);
	assert_eq!(phase_notice(&mut completed).await, second.command);
	release.add_permits(1);
	let output = timeout(Duration::from_secs(5), second.reply)
		.await
		.unwrap()
		.unwrap()
		.unwrap();
	assert_eq!(agent.requests.load(Ordering::Acquire), before + 6);
	assert!(output.status.success());
	assert!(!output.stdout.is_empty());
	assert_eq!(host.available_permits(), HOST_SESSIONS);
	assert_eq!(global.available_permits(), MAX_SESSIONS - 1);
	assert_eq!(admissions.available_permits(), MAX_ADMITTED - 1);
	assert!(!core.stop.is_cancelled());
	drop(output);
	assert_eq!(global.available_permits(), MAX_SESSIONS);
	assert_eq!(admissions.available_permits(), MAX_ADMITTED);
	core.stop.cancel();
	timeout(Duration::from_secs(3), actor)
		.await
		.unwrap()
		.unwrap()
		.unwrap();
}

async fn failed_master(core: &Arc<Core>, control: &Arc<AgentControl>) {
	let before = arm_next_lookup(control, 1);
	let cancel = CancellationToken::new();
	let mut failed = core
		.entry("fixture", &cancel, Instant::now() + Duration::from_secs(1))
		.await
		.unwrap();
	let held = failed.permits.clone().try_acquire_owned().unwrap();
	assert!(renewal_error(&mut failed.ready)
		.await
		.contains("observation SSH agent deadline"));
	lookup_closed(control, 1).await;
	assert!(core.stop.is_cancelled());
	assert!(core.children.lock().await.is_empty());
	assert_eq!(std::fs::read_dir(&core.root.path).unwrap().count(), 0);
	assert_eq!(control.requests.load(Ordering::Acquire), before + 1);
	let sequence = core.sequence.load(Ordering::Acquire);
	core.maintain().await.unwrap();
	{
		let entries = core.masters.lock().await;
		let still_failed = entries.get("fixture").unwrap();
		assert_eq!(still_failed.generation, failed.generation);
		assert!(still_failed.ready.same_channel(&failed.ready));
		assert!(Arc::ptr_eq(&still_failed.permits, &failed.permits));
		assert_eq!(still_failed.permits.available_permits(), HOST_SESSIONS - 1);
		assert!(still_failed.draining.is_none());
		assert!(matches!(&*still_failed.ready.borrow(), Some(Err(_))));
	}
	assert!(core
		.entry("fixture", &cancel, Instant::now() + Duration::from_secs(1))
		.await
		.is_err());
	assert_eq!(core.sequence.load(Ordering::Acquire), sequence);
	assert_eq!(control.requests.load(Ordering::Acquire), before + 1);
	drop(held);
	core.maintain().await.unwrap();
	assert!(core.masters.lock().await.is_empty());
	// Lifecycle failure stays fatal even after clean retirement; no stale RPC
	// or later caller can silently turn this failure into another generation.
	assert!(core
		.entry("fixture", &cancel, Instant::now() + Duration::from_secs(1))
		.await
		.is_err());
	assert!(matches!(&*failed.ready.borrow(), Some(Err(_))));
	assert_eq!(control.requests.load(Ordering::Acquire), before + 1);
	assert_eq!(core.sequence.load(Ordering::Acquire), sequence);
	assert!(core.children.lock().await.is_empty());
	assert!(core.stop.is_cancelled());
}

async fn failed_renewal(core: &Arc<Core>, control: &Arc<AgentControl>) {
	let (old, generation, _listener) = retired_generation(core, Duration::from_secs(10)).await;
	let cancel = CancellationToken::new();
	let deadline = Instant::now() + Duration::from_secs(15);
	let stale = core.entry("fixture", &cancel, deadline).await.unwrap();
	let held = stale.permits.clone().try_acquire_owned().unwrap();
	let before = arm_next_lookup(control, 1);
	core.renew("fixture", generation, &old, deadline, &cancel)
		.await
		.unwrap();
	let mut failed = core.entry("fixture", &cancel, deadline).await.unwrap();
	assert_ne!(failed.generation, generation);
	assert!(Arc::ptr_eq(&failed.permits, &stale.permits));
	assert!(renewal_error(&mut failed.ready)
		.await
		.contains("observation SSH agent deadline"));
	lookup_closed(control, 1).await;
	assert!(!old.accepting.load(Ordering::Acquire));
	assert_eq!(old.active.load(Ordering::Acquire), 0);
	assert!(!old.socket.exists());
	assert!(core.children.lock().await.is_empty());
	assert!(core.stop.is_cancelled());
	assert_eq!(control.requests.load(Ordering::Acquire), before + 1);
	{
		let entries = core.masters.lock().await;
		let current = entries.get("fixture").unwrap();
		assert_eq!(current.generation, failed.generation);
		assert!(current.draining.is_none());
		assert!(Arc::ptr_eq(&current.permits, &stale.permits));
		assert_eq!(current.permits.available_permits(), HOST_SESSIONS - 1);
		assert!(matches!(&*current.ready.borrow(), Some(Err(_))));
	}
	let sequence = core.sequence.load(Ordering::Acquire);
	assert!(core
		.renew("fixture", generation, &old, deadline, &cancel)
		.await
		.is_err());
	assert_eq!(core.sequence.load(Ordering::Acquire), sequence);
	assert_eq!(control.requests.load(Ordering::Acquire), before + 1);
	core.maintain().await.unwrap();
	assert!(core.masters.lock().await.contains_key("fixture"));
	drop(held);
	core.maintain().await.unwrap();
	assert!(core.masters.lock().await.is_empty());
	assert!(matches!(&*failed.ready.borrow(), Some(Err(_))));
	assert!(core.entry("fixture", &cancel, deadline).await.is_err());
	assert!(core
		.renew("fixture", generation, &old, deadline, &cancel)
		.await
		.is_err());
	assert_eq!(core.sequence.load(Ordering::Acquire), sequence);
	assert_eq!(control.requests.load(Ordering::Acquire), before + 1);
}

async fn later_authority_failure(core: &Arc<Core>, control: &Arc<AgentControl>, kind: &str) {
	let bound = core.agent.get().unwrap().clone();
	let before = arm_next_lookup(control, 1);
	let first = core
		.verify_request_profile(Instant::now() + Duration::from_millis(500))
		.await
		.unwrap_err();
	assert!(first.is::<profile::AgentLookupDeadline>());
	lookup_closed(control, 1).await;
	assert!(!core.stop.is_cancelled());
	let agent_requests = match kind {
		"agent-timeout-then-key-change" => {
			control.response_fault.store(1, Ordering::Release);
			1
		}
		"agent-timeout-then-frame-error" => {
			control.response_fault.store(2, Ordering::Release);
			1
		}
		"agent-timeout-then-io-error" => {
			control.response_fault.store(3, Ordering::Release);
			1
		}
		"agent-timeout-then-socket-change" => {
			std::fs::remove_file(&core.profile.agent).unwrap();
			private_write(&core.profile.agent, b"not a socket");
			0
		}
		"agent-timeout-then-file-change" => {
			private_write(
				&core.profile.known_hosts,
				b"changed after missing authority\n",
			);
			0
		}
		"agent-timeout-then-environment-change" => {
			std::env::set_var("SSH_AUTH_SOCK", core.root.path.join("undeclared-agent"));
			0
		}
		_ => panic!("unsupported later authority failure fixture"),
	};
	let error = core
		.verify_request_profile(Instant::now() + Duration::from_secs(3))
		.await
		.unwrap_err();
	assert!(!error.is::<profile::AgentLookupDeadline>(), "{error:#}");
	assert!(core.stop.is_cancelled());
	assert_eq!(core.agent.get(), Some(&bound));
	assert_eq!(
		control.requests.load(Ordering::Acquire),
		before + 1 + agent_requests,
	);
	assert!(core.children.lock().await.is_empty());
	assert!(core.masters.lock().await.is_empty());
}

pub(super) async fn run(core: &Arc<Core>, control: &Arc<AgentControl>, kind: &str) {
	match kind {
		"agent-initial-timeout" => request_phase(core, control, false).await,
		"agent-prelease-timeout" => request_phase(core, control, true).await,
		"agent-postresponse-timeout" => {
			tokio::task::LocalSet::new()
				.run_until(postresponse(core, control))
				.await;
		}
		"agent-master-timeout" => failed_master(core, control).await,
		"agent-renewal-timeout" => failed_renewal(core, control).await,
		"agent-renewal-cleanup-error" => {
			let before = arm_next_lookup(control, 1);
			renewal_fixture(core, "renew-cleanup").await;
			assert!(core.stop.is_cancelled());
			assert_eq!(control.requests.load(Ordering::Acquire), before);
			assert_eq!(control.deadline_closed.load(Ordering::Acquire), 0);
		}
		kind if kind.starts_with("agent-timeout-then-") => {
			later_authority_failure(core, control, kind).await;
		}
		_ => panic!("unsupported lookup deadline fixture"),
	}
}
