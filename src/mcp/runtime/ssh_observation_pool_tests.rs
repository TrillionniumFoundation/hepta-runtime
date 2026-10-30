// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Isolated observation scheduling, ownership and recovery fixtures.
use super::*;
use serde_json::json;
use std::future::Future;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;

#[path = "ssh_observation_agent_timeout_tests.rs"]
mod agent_timeout;

#[path = "ssh_observation_socket_publication_tests.rs"]
mod socket_publication;

#[path = "ssh_file_observation_pool_tests.rs"]
mod file_observations;

#[path = "ssh_observation_maintenance_tests.rs"]
mod maintenance;

// Direct lifecycle fixtures own a private admission; actor capacity fixtures
// below instead share the actual sixteen-permit admission pool.
fn test_admission() -> Arc<OwnedSemaphorePermit> {
	Arc::new(
		Arc::new(Semaphore::new(MAX_ADMITTED))
			.try_acquire_owned()
			.unwrap(),
	)
}

fn proxy_admission_fixture() -> (Arc<Proxy>, mpsc::Receiver<Request>) {
	let (sender, receiver) = mpsc::channel(QUEUE);
	let proxy = Arc::new(Proxy {
		sender,
		admission: Arc::new(Semaphore::new(MAX_ADMITTED)),
		stop: CancellationToken::new(),
		healthy: AtomicBool::new(true),
		thread: Mutex::new(None),
	});
	(proxy, receiver)
}

async fn proxy_submission(
	proxy: Arc<Proxy>,
	command: String,
	deadline: Instant,
	cancel: CancellationToken,
) -> Result<oneshot::Receiver<Result<Captured>>> {
	let (reply, receive) = oneshot::channel();
	let input = command.as_bytes().to_vec();
	proxy
		.enqueue("fixture", command, input, deadline, cancel, reply)
		.await?;
	Ok(receive)
}

async fn fill_proxy_channel(
	proxy: &Arc<Proxy>,
	deadline: Instant,
) -> Vec<oneshot::Receiver<Result<Captured>>> {
	let mut replies = Vec::new();
	for index in 0..QUEUE {
		replies.push(
			proxy_submission(
				proxy.clone(),
				format!("queued-{index}"),
				deadline,
				CancellationToken::new(),
			)
			.await
			.unwrap(),
		);
	}
	assert_eq!(proxy.sender.capacity(), 0);
	assert_eq!(proxy.admission.available_permits(), MAX_ADMITTED - QUEUE);
	replies
}

async fn assert_proxy_submission_pending<F: Future>(mut task: std::pin::Pin<&mut F>) {
	std::future::poll_fn(|context| {
		assert!(task.as_mut().poll(context).is_pending());
		std::task::Poll::Ready(())
	})
	.await;
}

#[tokio::test(flavor = "current_thread")]
async fn queued_proxy_waiters_keep_sixteen_identities_and_send_each_request_once() {
	let (proxy, mut receiver) = proxy_admission_fixture();
	let deadline = Instant::now() + Duration::from_secs(30);
	let mut replies = fill_proxy_channel(&proxy, deadline).await;
	let mut waiters = Vec::new();
	for index in 0..MAX_ADMITTED - QUEUE {
		let mut task = Box::pin(proxy_submission(
			proxy.clone(),
			format!("waiting-{index}"),
			deadline,
			CancellationToken::new(),
		));
		assert_proxy_submission_pending(task.as_mut()).await;
		waiters.push(task);
	}
	assert_eq!(receiver.len(), QUEUE);
	assert_eq!(proxy.sender.capacity(), 0);
	assert_eq!(proxy.admission.available_permits(), 0);
	// All sixteen are real queued or reserve-waiting requests. The next call
	// must fail in its first poll without creating another channel waiter.
	let mut excess = Box::pin(proxy_submission(
		proxy.clone(),
		"seventeenth".to_owned(),
		deadline,
		CancellationToken::new(),
	));
	std::future::poll_fn(|context| {
		match excess.as_mut().poll(context) {
			std::task::Poll::Ready(Err(error)) => {
				assert!(error.to_string().contains("pool capacity unavailable"));
			}
			_ => panic!("the seventeenth identity must be refused immediately"),
		}
		std::task::Poll::Ready(())
	})
	.await;
	assert_eq!(proxy.admission.available_permits(), 0);
	let mut requests = Vec::new();
	for (index, waiter) in waiters.into_iter().enumerate() {
		let request = receiver.try_recv().unwrap();
		assert_eq!(request.command, format!("queued-{index}"));
		// Keep the received identity alive as an actor/child would. Draining
		// the channel cannot create a seventeenth accepted identity.
		requests.push(request);
		replies.push(
			timeout(Duration::from_secs(5), waiter)
				.await
				.unwrap()
				.unwrap(),
		);
		assert_eq!(receiver.len(), QUEUE);
		assert_eq!(proxy.sender.capacity(), 0);
		assert_eq!(proxy.admission.available_permits(), 0);
	}
	for index in 0..MAX_ADMITTED - QUEUE {
		let request = receiver.try_recv().unwrap();
		assert_eq!(request.command, format!("waiting-{index}"));
		requests.push(request);
	}
	assert!(matches!(
		receiver.try_recv(),
		Err(mpsc::error::TryRecvError::Empty)
	));
	assert_eq!(requests.len(), MAX_ADMITTED);
	for request in &requests {
		assert_eq!(request.host, "fixture");
		assert_eq!(request.input.as_slice(), request.command.as_bytes());
		assert_eq!(
			request.deadline, deadline,
			"queue waiting cannot extend the deadline"
		);
		assert!(!request.cancel.is_cancelled());
	}
	drop(requests);
	for reply in replies {
		assert!(reply.await.is_err());
	}
	assert_eq!(proxy.sender.capacity(), QUEUE);
	assert_eq!(proxy.admission.available_permits(), MAX_ADMITTED);
}

#[tokio::test(flavor = "current_thread")]
async fn queued_proxy_waiters_release_identity_on_cancel_deadline_stop_and_close() {
	for reason in ["cancel", "deadline", "stop", "close"] {
		let (proxy, mut receiver) = proxy_admission_fixture();
		let queued_deadline = Instant::now() + Duration::from_secs(30);
		let replies = fill_proxy_channel(&proxy, queued_deadline).await;
		let deadline = if reason == "deadline" {
			Instant::now() + Duration::from_secs(1)
		} else {
			queued_deadline
		};
		let cancel = CancellationToken::new();
		let mut task = Box::pin(proxy_submission(
			proxy.clone(),
			"must-not-send".to_owned(),
			deadline,
			cancel.clone(),
		));
		assert_proxy_submission_pending(task.as_mut()).await;
		assert_eq!(
			proxy.admission.available_permits(),
			MAX_ADMITTED - QUEUE - 1
		);
		match reason {
			"cancel" => cancel.cancel(),
			"stop" => proxy.stop.cancel(),
			"close" => receiver.close(),
			"deadline" => {}
			_ => unreachable!(),
		}
		let error = timeout(Duration::from_secs(5), task)
			.await
			.unwrap()
			.err()
			.unwrap();
		assert!(error.to_string().contains(match reason {
			"cancel" => "cancelled before queue",
			"deadline" => "queue admission deadline",
			"stop" => "stopped before queue",
			"close" => "queue closed",
			_ => unreachable!(),
		}));
		assert_eq!(receiver.len(), QUEUE);
		assert_eq!(proxy.admission.available_permits(), MAX_ADMITTED - QUEUE);
		for index in 0..QUEUE {
			let request = receiver.try_recv().unwrap();
			assert_eq!(request.command, format!("queued-{index}"));
		}
		for reply in replies {
			assert!(reply.await.is_err());
		}
		assert_eq!(proxy.admission.available_permits(), MAX_ADMITTED);
		assert_eq!(proxy.stop.is_cancelled(), reason == "stop");
	}
}

#[tokio::test(flavor = "current_thread")]
async fn queued_proxy_rechecks_submission_fences_after_capacity_wakes() {
	for reason in ["cancel", "deadline", "stop", "unhealthy", "close"] {
		let (proxy, mut receiver) = proxy_admission_fixture();
		let queued_deadline = Instant::now() + Duration::from_secs(30);
		let replies = fill_proxy_channel(&proxy, queued_deadline).await;
		let deadline = if reason == "deadline" {
			Instant::now() + Duration::from_secs(1)
		} else {
			queued_deadline
		};
		let cancel = CancellationToken::new();
		let mut task = Box::pin(proxy_submission(
			proxy.clone(),
			"must-not-send".to_owned(),
			deadline,
			cancel.clone(),
		));
		assert_proxy_submission_pending(task.as_mut()).await;
		let held = receiver.try_recv().unwrap();
		// The waiter now has channel capacity, but cannot be polled between
		// this wake and the new fence. In the unhealthy case neither select
		// cancellation arm is ready, so only the post-reserve check can refuse.
		match reason {
			"cancel" => cancel.cancel(),
			"stop" => proxy.stop.cancel(),
			"unhealthy" => proxy.healthy.store(false, Ordering::Release),
			"close" => receiver.close(),
			"deadline" => tokio::time::sleep_until(deadline).await,
			_ => unreachable!(),
		}
		assert!(timeout(Duration::from_secs(5), task)
			.await
			.unwrap()
			.is_err());
		assert_eq!(
			receiver.len(),
			QUEUE - 1,
			"a wake cannot bypass a submission fence"
		);
		assert_eq!(proxy.admission.available_permits(), MAX_ADMITTED - QUEUE);
		if reason == "unhealthy" {
			assert!(!proxy.stop.is_cancelled());
			assert!(!cancel.is_cancelled());
		}
		drop(held);
		for index in 1..QUEUE {
			let request = receiver.try_recv().unwrap();
			assert_eq!(request.command, format!("queued-{index}"));
		}
		for reply in replies {
			assert!(reply.await.is_err());
		}
		assert_eq!(proxy.admission.available_permits(), MAX_ADMITTED);
	}
}

#[tokio::test(flavor = "current_thread")]
async fn queued_proxy_future_drop_and_receiver_drop_return_their_own_identities() {
	let (proxy, receiver) = proxy_admission_fixture();
	let deadline = Instant::now() + Duration::from_secs(30);
	let replies = fill_proxy_channel(&proxy, deadline).await;
	let unpolled = proxy_submission(
		proxy.clone(),
		"unpolled".to_owned(),
		deadline,
		CancellationToken::new(),
	);
	drop(unpolled);
	assert_eq!(proxy.admission.available_permits(), MAX_ADMITTED - QUEUE);
	let cancel = CancellationToken::new();
	let mut abandoned = Box::pin(async {
		// Match capture's cancellation guard while its enqueue is suspended.
		let _guard = CancelOnDrop(cancel.clone());
		proxy_submission(
			proxy.clone(),
			"abandoned".to_owned(),
			deadline,
			cancel.clone(),
		)
		.await
	});
	assert_proxy_submission_pending(abandoned.as_mut()).await;
	assert_eq!(
		proxy.admission.available_permits(),
		MAX_ADMITTED - QUEUE - 1
	);
	drop(abandoned);
	assert!(cancel.is_cancelled());
	assert_eq!(proxy.admission.available_permits(), MAX_ADMITTED - QUEUE);
	assert_eq!(receiver.len(), QUEUE);
	let mut waiting = Box::pin(proxy_submission(
		proxy.clone(),
		"receiver-dropped".to_owned(),
		deadline,
		CancellationToken::new(),
	));
	assert_proxy_submission_pending(waiting.as_mut()).await;
	drop(receiver);
	// Dropping the receiver releases only its eight queued identities. The
	// ninth still belongs to the suspended submission until it sees closure.
	assert_eq!(proxy.admission.available_permits(), MAX_ADMITTED - 1);
	assert!(timeout(Duration::from_secs(5), waiting)
		.await
		.unwrap()
		.is_err());
	assert_eq!(proxy.admission.available_permits(), MAX_ADMITTED);
	for reply in replies {
		assert!(reply.await.is_err());
	}
	assert!(!proxy.stop.is_cancelled());
}

#[test]
fn control_paths_reserve_the_real_unix_temporary_socket_boundary() {
	let root = tempfile::Builder::new()
		.prefix("hr-socket-")
		.tempdir_in("/tmp")
		.unwrap();
	for multibyte in [false, true] {
		for (length, accepted) in [
			(CONTROL_SOCKET_PATH_BYTES, true),
			(CONTROL_SOCKET_PATH_BYTES + 1, false),
		] {
			let tail = if multibyte { "é" } else { "m" };
			let name_bytes = length - root.path().as_os_str().as_encoded_bytes().len() - 1;
			let socket = root
				.path()
				.join(format!("{}{tail}", "s".repeat(name_bytes - tail.len())));
			assert_eq!(socket.as_os_str().as_encoded_bytes().len(), length);
			// Both final names fit: only OpenSSH's actual temporary name crosses
			// the boundary. Bind real sockets instead of testing strings alone.
			let _final_listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
			let mut temporary = socket.as_os_str().to_os_string();
			temporary.push(".0123456789abcdef");
			let temporary = PathBuf::from(temporary);
			assert_eq!(
				temporary.as_os_str().as_encoded_bytes().len(),
				if accepted { 107 } else { 108 }
			);
			let temporary_listener = std::os::unix::net::UnixListener::bind(&temporary);
			assert_eq!(temporary_listener.is_ok(), accepted);
			assert_eq!(check_control_socket_path(&socket).is_ok(), accepted);
		}
	}
}

#[tokio::test]
async fn completed_output_keeps_global_capacity_until_original_caller_finishes() {
	let permits = Arc::new(Semaphore::new(1));
	let budget = Arc::new(permits.clone().acquire_owned().await.unwrap());
	let output = Captured {
		output: Output {
			status: ExitStatus::from_raw(0),
			stdout: b"{}".to_vec(),
			stderr: vec![],
		},
		_budget: budget.clone(),
		_admission: test_admission(),
	};
	let (send, receive) = oneshot::channel();
	assert!(send.send(output).is_ok());
	drop(budget);
	assert_eq!(permits.available_permits(), 0);
	let output = receive.await.unwrap();
	assert_eq!(
		serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
		json!({})
	);
	assert_eq!(permits.available_permits(), 0);
	drop(output);
	assert_eq!(permits.available_permits(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn completed_reply_supervisors_do_not_consume_replacement_slots() {
	let permits = Arc::new(Semaphore::new(MAX_SESSIONS));
	let returned = Arc::new(AtomicUsize::new(0));
	let mut work = JoinSet::new();
	let mut replies = Vec::new();
	for _ in 0..MAX_SESSIONS {
		let permit = permits.clone().acquire_owned().await.unwrap();
		let returned = returned.clone();
		let (send, receive) = oneshot::channel();
		work.spawn(async move {
			let output = Captured {
				output: Output {
					status: ExitStatus::from_raw(0),
					stdout: b"{}".to_vec(),
					stderr: vec![],
				},
				_budget: Arc::new(permit),
				_admission: test_admission(),
			};
			assert!(send.send(output).is_ok());
			// Match execute: reply send through return contains no await/yield.
			returned.fetch_add(1, Ordering::SeqCst);
		});
		replies.push(receive);
	}
	for reply in replies {
		let output = timeout(Duration::from_secs(5), reply)
			.await
			.unwrap()
			.unwrap();
		assert_eq!(
			serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
			json!({})
		);
		drop(output);
	}
	// The owner-thread actor cannot run during a worker's synchronous return.
	assert_eq!(returned.load(Ordering::SeqCst), MAX_SESSIONS);
	assert_eq!(permits.available_permits(), MAX_SESSIONS);
	// The old len-only admission path would reject this exact state.
	assert_eq!(work.len(), MAX_SESSIONS);
	Core::reap_completed_requests(&mut work).unwrap();
	assert!(work.is_empty());
	assert!(permits.try_acquire_owned().is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn reaping_supervisors_does_not_release_unparsed_output_budget() {
	let permits = Arc::new(Semaphore::new(MAX_SESSIONS));
	let mut work = JoinSet::new();
	let mut replies = Vec::new();
	for _ in 0..MAX_SESSIONS {
		let permit = permits.clone().acquire_owned().await.unwrap();
		let (send, receive) = oneshot::channel();
		work.spawn(async move {
			assert!(send
				.send(Captured {
					output: Output {
						status: ExitStatus::from_raw(0),
						stdout: b"{}".to_vec(),
						stderr: vec![],
					},
					_budget: Arc::new(permit),
					_admission: test_admission(),
				})
				.is_ok());
		});
		replies.push(receive);
	}
	let mut outputs = Vec::new();
	for reply in replies {
		outputs.push(
			timeout(Duration::from_secs(5), reply)
				.await
				.unwrap()
				.unwrap(),
		);
	}
	assert_eq!(work.len(), MAX_SESSIONS);
	Core::reap_completed_requests(&mut work).unwrap();
	assert!(work.is_empty());
	assert_eq!(permits.available_permits(), 0);
	assert!(permits.clone().try_acquire_owned().is_err());
	drop(outputs.pop());
	let replacement = permits.clone().try_acquire_owned().unwrap();
	assert_eq!(permits.available_permits(), 0);
	drop(replacement);
	drop(outputs);
	assert_eq!(permits.available_permits(), MAX_SESSIONS);
}

#[tokio::test(flavor = "current_thread")]
async fn admission_reap_preserves_mixed_and_full_live_supervisor_bounds() {
	let permits = Arc::new(Semaphore::new(MAX_SESSIONS));
	let stop = CancellationToken::new();
	let mut work = JoinSet::new();
	let mut started = Vec::new();
	for index in 0..MAX_SESSIONS {
		let permit = permits.clone().acquire_owned().await.unwrap();
		let stop = stop.clone();
		let (send, receive) = oneshot::channel();
		work.spawn(async move {
			let _permit = permit;
			assert!(send.send(()).is_ok());
			if index < MAX_SESSIONS / 2 {
				stop.cancelled().await;
			}
		});
		started.push(receive);
	}
	for ready in started {
		timeout(Duration::from_secs(5), ready)
			.await
			.unwrap()
			.unwrap();
	}
	assert_eq!(work.len(), MAX_SESSIONS);
	Core::reap_completed_requests(&mut work).unwrap();
	assert_eq!(work.len(), MAX_SESSIONS / 2);
	assert_eq!(permits.available_permits(), MAX_SESSIONS / 2);
	let mut replacements = Vec::new();
	for _ in 0..MAX_SESSIONS / 2 {
		let permit = permits.clone().try_acquire_owned().unwrap();
		let stop = stop.clone();
		let (send, receive) = oneshot::channel();
		work.spawn(async move {
			let _permit = permit;
			assert!(send.send(()).is_ok());
			stop.cancelled().await;
		});
		replacements.push(receive);
	}
	for ready in replacements {
		timeout(Duration::from_secs(5), ready)
			.await
			.unwrap()
			.unwrap();
	}
	Core::reap_completed_requests(&mut work).unwrap();
	assert_eq!(work.len(), MAX_SESSIONS);
	assert!(permits.clone().try_acquire_owned().is_err());
	stop.cancel();
	while let Some(result) = work.join_next().await {
		result.unwrap();
	}
	assert_eq!(permits.available_permits(), MAX_SESSIONS);
}

#[tokio::test(flavor = "current_thread")]
async fn admission_reap_propagates_panicked_and_cancelled_supervisors() {
	for cancel in [false, true] {
		let mut work = JoinSet::new();
		let (send, receive) = oneshot::channel();
		let task = work.spawn(async move {
			assert!(send.send(()).is_ok());
			if cancel {
				std::future::pending::<()>().await;
			} else {
				panic!("bounded admission fixture panic");
			}
		});
		timeout(Duration::from_secs(5), receive)
			.await
			.unwrap()
			.unwrap();
		if cancel {
			task.abort();
		}
		timeout(Duration::from_secs(5), async {
			while !task.is_finished() {
				tokio::task::yield_now().await;
			}
		})
		.await
		.unwrap();
		let error = Core::reap_completed_requests(&mut work).unwrap_err();
		assert!(error
			.to_string()
			.contains("observation request supervisor failed"));
		assert!(work.is_empty());
	}
}

#[tokio::test(flavor = "current_thread")]
async fn unpolled_supervisor_abort_stops_before_any_body_can_run() {
	let stop = CancellationToken::new();
	let guard = StopUnlessCompleted {
		stop: stop.clone(),
		completed: false,
	};
	let (entered, receive) = oneshot::channel();
	let mut work = JoinSet::new();
	let task = work.spawn(async move {
		entered.send(()).unwrap();
		std::future::pending::<()>().await;
		guard.complete();
	});
	task.abort();
	assert!(work.join_next().await.unwrap().is_err());
	assert!(receive.await.is_err());
	assert!(stop.is_cancelled());
}

fn private_write(path: &Path, bytes: &[u8]) {
	std::fs::write(path, bytes).unwrap();
	std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

struct AgentControl {
	stall: AtomicBool,
	entered: tokio::sync::Notify,
	requests: AtomicUsize,
	// A single selected lookup withholds its response until the original
	// caller closes that exact stream. It neither accepts a retry nor changes
	// the socket/peer/key identity used by later successful lookups.
	deadline_request: AtomicUsize,
	deadline_closed: AtomicUsize,
	// Fixture-only complete response faults: 1 key change, 2 malformed frame,
	// 3 an unexplained connection close. Zero preserves the original response.
	response_fault: AtomicUsize,
}

async fn fixture() -> (
	tempfile::TempDir,
	PathBuf,
	tokio::task::JoinHandle<()>,
	Arc<AgentControl>,
) {
	fixture_with_cold_host(false).await
}

async fn fixture_with_cold_host(
	cold: bool,
) -> (
	tempfile::TempDir,
	PathBuf,
	tokio::task::JoinHandle<()>,
	Arc<AgentControl>,
) {
	fixture_with_file_policy(cold, false).await
}

async fn fixture_with_file_policy(
	cold: bool,
	files: bool,
) -> (
	tempfile::TempDir,
	PathBuf,
	tokio::task::JoinHandle<()>,
	Arc<AgentControl>,
) {
	let root = tempfile::tempdir().unwrap();
	std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
	let state = root.path().join("state");
	std::fs::create_dir(&state).unwrap();
	std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
	let mut spec = json!({"state_dir":state,"hosts":{"fixture":{
		"ssh_target":"hepta-observation-fixture","platform":"linux","remote_state_dir":"/private/jobs-fixture",
		"allow_execute":false,"allow_pty":false,"allow_write":false}}});
	if cold {
		spec["hosts"]["cold"] = spec["hosts"]["fixture"].clone();
		spec["hosts"]["cold"]["ssh_target"] = json!("hepta-observation-cold-fixture");
	}
	if files {
		spec["hosts"]["fixture"]["execution_mode"] = json!("operator");
		spec["hosts"]["fixture"]["allowed_read_path_prefixes"] =
			json!(["/allowed", "/allowed/nested"]);
	}
	let runtime = serde_json::from_value(spec).unwrap();
	crate::mcp::runtime::config::init_runtime(runtime).unwrap();
	let known = root.path().join("known_hosts");
	private_write(&known, b"");
	let config = root.path().join("ssh_config");
	private_write(&config, format!("Host hepta-observation-fixture hepta-observation-cold-fixture\n HostName 127.0.0.1\n Port 9\n User nobody\n BatchMode yes\n ForwardAgent no\n StrictHostKeyChecking yes\n UserKnownHostsFile {}\n GlobalKnownHostsFile /dev/null\n", known.display()).as_bytes());
	let agent = root.path().join("agent");
	let listener = tokio::net::UnixListener::bind(&agent).unwrap();
	std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o775)).unwrap();
	// This is an isolated subprocess, never a concurrent mutation of another
	// test's environment, config singleton, credential or runtime store.
	std::env::set_var("SSH_AUTH_SOCK", &agent);
	let control = Arc::new(AgentControl {
		stall: AtomicBool::new(false),
		entered: tokio::sync::Notify::new(),
		requests: AtomicUsize::new(0),
		deadline_request: AtomicUsize::new(0),
		deadline_closed: AtomicUsize::new(0),
		response_fault: AtomicUsize::new(0),
	});
	let server_control = control.clone();
	let server = tokio::spawn(async move {
		loop {
			let Ok((mut stream, _)) = listener.accept().await else {
				return;
			};
			let mut request = [0; 5];
			if stream.read_exact(&mut request).await.is_err() {
				continue;
			}
			assert_eq!(request, [0, 0, 0, 1, 11]);
			let request_number = server_control.requests.fetch_add(1, Ordering::Release) + 1;
			if server_control.stall.load(Ordering::Acquire) {
				server_control.entered.notify_one();
				std::future::pending::<()>().await;
			}
			if server_control.deadline_request.load(Ordering::Acquire) == request_number {
				server_control.entered.notify_one();
				let mut unexpected = [0; 1];
				let closed = timeout(Duration::from_secs(8), stream.read(&mut unexpected))
					.await
					.expect("expired lookup must drop its original agent stream");
				assert!(matches!(closed, Ok(0)), "{closed:?}");
				server_control
					.deadline_closed
					.fetch_add(1, Ordering::Release);
				continue;
			}
			let fault = server_control.response_fault.load(Ordering::Acquire);
			if fault == 3 {
				continue;
			}
			let key: &[u8] = if fault == 1 {
				b"different-public-key-fixture"
			} else {
				b"bounded-public-key-fixture"
			};
			let mut response = vec![12, 0, 0, 0, 1];
			response.extend_from_slice(&(key.len() as u32).to_be_bytes());
			response.extend_from_slice(key);
			response.extend_from_slice(&0u32.to_be_bytes());
			if fault == 2 {
				response[0] = 5;
			}
			if stream
				.write_all(&(response.len() as u32).to_be_bytes())
				.await
				.is_ok()
			{
				let _ = stream.write_all(&response).await;
			}
		}
	});
	let path = root.path().join("profile.json");
	let hex = |path: &str| {
		profile::digest(&std::fs::read(path).unwrap())
			.iter()
			.map(|v| format!("{v:02x}"))
			.collect::<String>()
	};
	private_write(&path, &serde_json::to_vec(&json!({"schema":"hepta-observation-ssh-pool/v1",
		"allow_bounded_cached_authentication":true,"ssh_config":config,"ssh_config_sha256":hex(config.to_str().unwrap()),
		"known_hosts":known,"known_hosts_sha256":hex(known.to_str().unwrap()),
		"ssh_sha256":hex("/usr/bin/ssh"),"false_sha256":hex("/usr/bin/false"),"shell_sha256":hex("/bin/sh"),
		"agent_socket":agent,"socket_parent":root.path()})).unwrap());
	(root, path, server, control)
}

async fn core(path: &Path) -> Arc<Core> {
	let profile = Arc::new(Profile::load(path).unwrap());
	let root = PrivateRoot::create(&profile).unwrap();
	let core = Arc::new(Core {
		profile,
		validation: validation::Workers::new(),
		root,
		stop: CancellationToken::new(),
		agent: OnceLock::new(),
		children: AsyncMutex::new(BTreeMap::new()),
		masters: AsyncMutex::new(BTreeMap::new()),
		background: Mutex::new(JoinSet::new()),
		maintenance_changed: Notify::new(),
		sequence: AtomicU64::new(1),
		owner_tid: unsafe { libc::syscall(libc::SYS_gettid) },
	});
	core.initialize().await.unwrap();
	core
}

// A fixture-only retired generation: the owned child really executed the
// pinned ssh -G and was waited. The listener pins cleanup identity; it is not
// an authenticated master and must never pass the real SO_PEERCRED lease gate.
async fn retired_generation(
	core: &Arc<Core>,
	remaining: Duration,
) -> (Arc<Master>, u64, tokio::net::UnixListener) {
	let name = core.sequence.fetch_add(1, Ordering::Relaxed);
	let socket = core.root.path.join(format!("retired-fixture-{name}"));
	let args = core
		.arguments("fixture", Mode::Master, &socket, true)
		.unwrap();
	let mut command = core.command(&args);
	command
		.stdin(Stdio::null())
		.stdout(Stdio::null())
		.stderr(Stdio::null());
	let owned = core
		.spawn(
			&args,
			command,
			vec![],
			Instant::now() + Duration::from_secs(3),
			&CancellationToken::new(),
		)
		.await
		.unwrap();
	assert!(timeout(Duration::from_secs(3), owned.wait())
		.await
		.unwrap()
		.unwrap()
		.success());
	assert!(owned.terminal().await.unwrap());
	let listener = tokio::net::UnixListener::bind(&socket).unwrap();
	std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
	let stamp = profile::socket_stamp(&socket).unwrap();
	let master = Arc::new(Master {
		owned,
		socket,
		stamp,
		created: Instant::now() - AGE + remaining,
		last_use: Mutex::new(Instant::now()),
		active: AtomicUsize::new(0),
		accepting: AtomicBool::new(true),
		retirement: AsyncMutex::new(None),
	});
	let generation = core.sequence.fetch_add(1, Ordering::Relaxed);
	let (send, receive) = watch::channel(Some(Ok(master.clone())));
	core.masters.lock().await.insert(
		"fixture".into(),
		Entry {
			ready: receive,
			permits: Arc::new(Semaphore::new(HOST_SESSIONS)),
			generation,
			ready_deadline: Instant::now() + START + REAP,
			draining: None,
		},
	);
	drop(send);
	(master, generation, listener)
}

async fn renewal_error(ready: &mut watch::Receiver<Ready>) -> String {
	timeout(Duration::from_secs(3), async {
		loop {
			let value = { ready.borrow().clone() };
			if let Some(value) = value {
				return match value {
					Err(error) => error,
					Ok(_) => panic!("fixture must stop before a new master can connect"),
				};
			}
			ready
				.changed()
				.await
				.expect("renewal owner must publish an outcome");
		}
	})
	.await
	.unwrap()
}

async fn renewal_fixture(core: &Arc<Core>, kind: &str) {
	let (old, generation, _listener) = retired_generation(core, Duration::from_secs(10)).await;
	let cancel = CancellationToken::new();
	let deadline = Instant::now() + Duration::from_secs(15);
	let stale = core.entry("fixture", &cancel, deadline).await.unwrap();
	match kind {
		"renew-singleflight" => {
			old.active.store(1, Ordering::Release);
			core.renew("fixture", generation, &old, deadline, &cancel)
				.await
				.unwrap();
			let mut installed = core.entry("fixture", &cancel, deadline).await.unwrap();
			assert_ne!(installed.generation, generation);
			assert!(!old.accepting.load(Ordering::Acquire));
			assert!(Arc::ptr_eq(&installed.permits, &stale.permits));
			assert!(installed
				.draining
				.as_ref()
				.is_some_and(|value| Arc::ptr_eq(value, &old)));
			let (first, second) = tokio::join!(
				core.renew("fixture", generation, &old, deadline, &cancel),
				core.renew("fixture", generation, &old, deadline, &cancel)
			);
			first.unwrap();
			second.unwrap();
			let latest = core.entry("fixture", &cancel, deadline).await.unwrap();
			assert_eq!(latest.generation, installed.generation);
			assert_eq!(latest.ready_deadline, installed.ready_deadline);
			assert!(latest.ready.same_channel(&installed.ready));
			assert!(Arc::ptr_eq(&latest.permits, &installed.permits));
			assert_eq!(core.masters.lock().await.len(), 1);
			assert_eq!(core.background.lock().unwrap().len(), 1);
			assert_eq!(core.children.lock().await.len(), 1);
			assert!(matches!(&*stale.ready.borrow(), Some(Ok(value)) if Arc::ptr_eq(value, &old)));
			core.stop.cancel();
			old.active.store(0, Ordering::Release);
			assert!(renewal_error(&mut installed.ready)
				.await
				.contains("stopped before new master"));
			assert!(core.children.lock().await.is_empty());
			assert!(!old.socket.exists());
		}
		"renew-refused" => {
			let sequence = core.sequence.load(Ordering::Acquire);
			let cancelled = CancellationToken::new();
			cancelled.cancel();
			assert!(core
				.renew("fixture", generation, &old, deadline, &cancelled)
				.await
				.is_err());
			assert!(core
				.renew(
					"fixture",
					generation,
					&old,
					Instant::now() - Duration::from_millis(1),
					&cancel
				)
				.await
				.is_err());
			assert!(core.entry("fixture", &cancelled, deadline).await.is_err());
			assert!(core
				.entry(
					"fixture",
					&cancel,
					Instant::now() - Duration::from_millis(1)
				)
				.await
				.is_err());
			let latest = core.entry("fixture", &cancel, deadline).await.unwrap();
			assert_eq!(latest.generation, generation);
			assert_eq!(latest.ready_deadline, stale.ready_deadline);
			assert!(latest.ready.same_channel(&stale.ready));
			assert!(latest.draining.is_none());
			assert!(old.accepting.load(Ordering::Acquire));
			assert_eq!(core.sequence.load(Ordering::Acquire), sequence);
			assert_eq!(core.background.lock().unwrap().len(), 0);
			assert_eq!(core.children.lock().await.len(), 1);
			assert!(!core.stop.is_cancelled());
		}
		"renew-cleanup" => {
			std::fs::remove_file(&old.socket).unwrap();
			let _replacement = tokio::net::UnixListener::bind(&old.socket).unwrap();
			std::fs::set_permissions(&old.socket, std::fs::Permissions::from_mode(0o600)).unwrap();
			let replacement = profile::socket_stamp(&old.socket).unwrap();
			assert_ne!(replacement, old.stamp);
			core.renew("fixture", generation, &old, deadline, &cancel)
				.await
				.unwrap();
			let mut ready = {
				core.masters
					.lock()
					.await
					.get("fixture")
					.unwrap()
					.ready
					.clone()
			};
			let error = renewal_error(&mut ready).await;
			assert!(error.contains("cleanup identity uncertain"), "{error}");
			assert!(core.stop.is_cancelled());
			assert!(!old.accepting.load(Ordering::Acquire));
			assert!(core.children.lock().await.is_empty());
			assert_eq!(profile::socket_stamp(&old.socket).unwrap(), replacement);
			assert!(core.maintain().await.is_err());
			let entries = core.masters.lock().await;
			let held = entries.get("fixture").unwrap();
			assert!(held
				.draining
				.as_ref()
				.is_some_and(|value| Arc::ptr_eq(value, &old)));
			assert!(matches!(&*held.ready.borrow(), Some(Err(_))));
			drop(entries);
			// Only the fixture removes its independently pinned replacement. The
			// production cleanup refused it and retained the old draining proof.
			assert_eq!(profile::socket_stamp(&old.socket).unwrap(), replacement);
			std::fs::remove_file(&old.socket).unwrap();
		}
		"renew-deadline" => {
			old.active.store(1, Ordering::Release);
			let request_cancel = CancellationToken::new();
			let (reply, _) = oneshot::channel();
			let request = Request {
				host: "fixture".into(),
				command: "NEVER_DISPATCH".into(),
				input: vec![],
				deadline,
				cancel: request_cancel.clone(),
				reply,
				admission: test_admission(),
			};
			assert!(request.deadline > old.created + AGE);
			let permits = Arc::new(Semaphore::new(1));
			let permit = permits.clone().acquire_owned().await.unwrap();
			let task_core = core.clone();
			let global = permits.clone();
			let task =
				tokio::spawn(
					async move { task_core.execute_inner(&request, permit, global).await },
				);
			timeout(Duration::from_secs(3), async {
				while old.accepting.load(Ordering::Acquire) {
					tokio::task::yield_now().await;
				}
			})
			.await
			.unwrap();
			let mut installed = core.entry("fixture", &cancel, deadline).await.unwrap();
			assert_ne!(installed.generation, generation);
			assert!(installed
				.draining
				.as_ref()
				.is_some_and(|value| Arc::ptr_eq(value, &old)));
			assert_eq!(
				permits.available_permits(),
				1,
				"renewal waiting must return global capacity"
			);
			assert_eq!(
				core.children.lock().await.len(),
				1,
				"no slave or new master before drain"
			);
			request_cancel.cancel();
			let error = match timeout(Duration::from_secs(1), task)
				.await
				.unwrap()
				.unwrap()
			{
				Err(error) => error,
				Ok(_) => panic!("cancelled synthetic lease cannot deliver a result"),
			};
			assert!(error.to_string().contains("cancelled"), "{error:#}");
			assert!(!error.to_string().contains("lifetime cannot cover"));
			assert_eq!(permits.available_permits(), 1);
			core.stop.cancel();
			old.active.store(0, Ordering::Release);
			assert!(renewal_error(&mut installed.ready)
				.await
				.contains("stopped before new master"));
			assert!(core.children.lock().await.is_empty());
		}
		"renew-maintain" => {
			core.maintain().await.unwrap();
			assert!(!old.accepting.load(Ordering::Acquire));
			assert!(core.masters.lock().await.is_empty());
			assert!(core.children.lock().await.is_empty());
			assert!(!old.socket.exists());
			let sequence = core.sequence.load(Ordering::Acquire);
			core.renew("fixture", generation, &old, deadline, &cancel)
				.await
				.unwrap();
			assert_eq!(core.sequence.load(Ordering::Acquire), sequence);
			assert!(core.masters.lock().await.is_empty());
			assert_eq!(core.background.lock().unwrap().len(), 0);
			assert!(matches!(&*stale.ready.borrow(), Some(Ok(value)) if Arc::ptr_eq(value, &old)));
		}
		"renew-retirement" => {
			// A terminal master does not release the old session budget.
			old.active.store(1, Ordering::Release);
			assert_eq!(stale.permits.available_permits(), HOST_SESSIONS);
			core.maintain().await.unwrap();
			assert!(!old.accepting.load(Ordering::Acquire));
			assert!(core.children.lock().await.is_empty());
			assert!(!old.socket.exists());
			let held = core.entry("fixture", &cancel, deadline).await.unwrap();
			assert_eq!(held.generation, generation);
			assert!(Arc::ptr_eq(&held.permits, &stale.permits));
			let permit = stale.permits.clone().acquire_owned().await.unwrap();
			old.active.store(0, Ordering::Release);
			core.maintain().await.unwrap();
			let held = core.entry("fixture", &cancel, deadline).await.unwrap();
			assert_eq!(held.generation, generation);
			assert!(Arc::ptr_eq(&held.permits, &stale.permits));
			assert_eq!(held.permits.available_permits(), HOST_SESSIONS - 1);
			drop(permit);
			core.maintain().await.unwrap();
			assert!(core.masters.lock().await.is_empty());
			assert_eq!(core.background.lock().unwrap().len(), 0);
			// Error-ready generations retain their outstanding permits too.
			let permit = stale.permits.clone().acquire_owned().await.unwrap();
			let (send, receive) =
				watch::channel(Some(Err("synthetic failed generation".to_owned())));
			let failed_generation = core.sequence.fetch_add(1, Ordering::Relaxed);
			core.masters.lock().await.insert(
				"fixture".into(),
				Entry {
					ready: receive,
					permits: stale.permits.clone(),
					generation: failed_generation,
					ready_deadline: deadline,
					draining: None,
				},
			);
			drop(send);
			core.maintain().await.unwrap();
			let held = core.entry("fixture", &cancel, deadline).await.unwrap();
			assert_eq!(held.generation, failed_generation);
			assert!(Arc::ptr_eq(&held.permits, &stale.permits));
			assert!(matches!(&*held.ready.borrow(), Some(Err(_))));
			drop(permit);
			core.maintain().await.unwrap();
			assert!(core.masters.lock().await.is_empty());
			assert_eq!(core.background.lock().unwrap().len(), 0);
		}
		_ => panic!("unsupported renewal fixture"),
	}
}

async fn queued_admission_fixture(core: &Arc<Core>, kind: &str, agent: &Arc<AgentControl>) {
	let permits = Arc::new(Semaphore::new(MAX_SESSIONS));
	let admissions = Arc::new(Semaphore::new(MAX_ADMITTED));
	let mut retained = Vec::new();
	for _ in 0..MAX_SESSIONS {
		retained.push(Captured {
			output: Output {
				status: ExitStatus::from_raw(0),
				stdout: b"{}".to_vec(),
				stderr: vec![],
			},
			_budget: Arc::new(permits.clone().acquire_owned().await.unwrap()),
			_admission: Arc::new(admissions.clone().try_acquire_owned().unwrap()),
		});
	}
	let (sender, receiver) = mpsc::channel(QUEUE);
	let mut replies = Vec::new();
	let mut cancellations = Vec::new();
	let initially_queued = if kind == "queue-stop" {
		QUEUE - 1
	} else {
		QUEUE
	};
	for _ in 0..initially_queued {
		let (reply, receive) = oneshot::channel();
		let cancel = CancellationToken::new();
		let request = Request {
			host: "fixture".into(),
			command: "NEVER_DISPATCH".into(),
			input: vec![],
			deadline: Instant::now() + Duration::from_secs(40),
			cancel: cancel.clone(),
			reply,
			admission: Arc::new(admissions.clone().try_acquire_owned().unwrap()),
		};
		assert!(sender.try_send(request).is_ok());
		replies.push(Some(receive));
		cancellations.push(cancel);
	}
	let mut actor = Box::pin(core.clone().run_with_capacity(receiver, permits.clone()));
	// Poll the real actor while every output permit is retained. Moving all
	// channel entries into pending must not admit a seventeenth request.
	std::future::poll_fn(|cx| {
		assert!(actor.as_mut().poll(cx).is_pending());
		std::task::Poll::Ready(())
	})
	.await;
	assert_eq!(sender.capacity(), QUEUE);
	assert_eq!(permits.available_permits(), 0);
	assert_eq!(admissions.available_permits(), QUEUE - initially_queued);
	for reply in &mut replies {
		assert!(matches!(
			reply.as_mut().unwrap().try_recv(),
			Err(oneshot::error::TryRecvError::Empty)
		));
	}
	if kind == "queue-stop" {
		// The actor is not polled between enqueue and cancellation: seven
		// requests are pending and one remains in the channel when stop fires.
		let waiting = enqueue_fair_request(
			&sender,
			&admissions,
			"fixture",
			"NEVER_DISPATCH",
			Instant::now() + Duration::from_secs(40),
		);
		replies.push(Some(waiting.reply));
		assert_eq!(sender.capacity(), QUEUE - 1);
	}
	assert_eq!(admissions.available_permits(), 0);
	assert!(admissions.clone().try_acquire_owned().is_err());
	if kind == "queue-stop" {
		core.stop.cancel();
		timeout(Duration::from_secs(3), actor)
			.await
			.unwrap()
			.unwrap();
		for reply in replies.into_iter().flatten() {
			let error = reply.await.unwrap().err().unwrap();
			assert!(error.to_string().contains("pool stopped before admission"));
		}
		assert_eq!(permits.available_permits(), 0);
	} else {
		for (index, cancel) in cancellations.iter().enumerate() {
			if !(kind == "queue-admission" && index == 0 || kind == "queue-capacity" && index == 2)
			{
				cancel.cancel();
			}
		}
		if kind == "queue-capacity" {
			// Exercise cancellation and a caller that disappeared while waiting,
			// without creating any SSH task. Fairness fixtures also cover expiry.
			drop(replies[2].take());
		} else {
			agent.stall.store(true, Ordering::Release);
		}
		// Return exactly one parsed-output budget. The actor must admit from
		// the original queue, not reject or allocate a larger pool.
		drop(retained.pop());
		let observe = async {
			if kind == "queue-admission" {
				agent.entered.notified().await;
				assert_eq!(permits.available_permits(), 0);
				assert!(core.masters.lock().await.is_empty());
				assert!(core.children.lock().await.is_empty());
				cancellations[0].cancel();
			}
			for (index, reply) in replies.into_iter().enumerate() {
				let Some(reply) = reply else { continue };
				let error = reply.await.unwrap().err().unwrap();
				let expected = if kind == "queue-admission" && index == 0 {
					"cancelled during admission profile check"
				} else {
					"cancelled before admission"
				};
				assert!(error.to_string().contains(expected), "{error:#}");
			}
			core.stop.cancel();
		};
		let (_, result) = timeout(Duration::from_secs(5), async {
			tokio::join!(observe, actor)
		})
		.await
		.unwrap();
		result.unwrap();
		assert_eq!(permits.available_permits(), 1);
	}
	drop(retained);
	assert_eq!(permits.available_permits(), MAX_SESSIONS);
	assert_eq!(admissions.available_permits(), MAX_ADMITTED);
	assert!(core.masters.lock().await.is_empty());
	assert!(core.children.lock().await.is_empty());
}

struct FairRequest {
	reply: oneshot::Receiver<Result<Captured>>,
	cancel: CancellationToken,
	command: String,
}

fn enqueue_fair_request(
	sender: &mpsc::Sender<Request>,
	admissions: &Arc<Semaphore>,
	host: &str,
	command: &str,
	deadline: Instant,
) -> FairRequest {
	let (reply, receive) = oneshot::channel();
	let cancel = CancellationToken::new();
	let request = Request {
		host: host.into(),
		command: command.into(),
		input: vec![],
		deadline,
		cancel: cancel.clone(),
		reply,
		admission: Arc::new(admissions.clone().try_acquire_owned().unwrap()),
	};
	assert!(sender.try_send(request).is_ok());
	FairRequest {
		reply: receive,
		cancel,
		command: command.into(),
	}
}

fn fair_output(budget: OwnedSemaphorePermit, admission: Arc<OwnedSemaphorePermit>) -> Captured {
	Captured {
		output: Output {
			status: ExitStatus::from_raw(0),
			stdout: b"{}".to_vec(),
			stderr: vec![],
		},
		_budget: Arc::new(budget),
		_admission: admission,
	}
}

struct ControlledDispatch {
	global: Arc<Semaphore>,
	hosts: BTreeMap<String, Arc<Semaphore>>,
	started: mpsc::Sender<(String, String)>,
	preflight: mpsc::Sender<String>,
	budget_waiting: mpsc::Sender<String>,
	preflight_gate: Option<Arc<Semaphore>>,
	release: Arc<Semaphore>,
}

async fn controlled_dispatch(
	core: Arc<Core>,
	request: Request,
	initial: OwnedSemaphorePermit,
	control: Arc<ControlledDispatch>,
) {
	let result = async {
		core.admission_profile(&request, initial).await?;
		assert!(control.preflight.try_send(request.command.clone()).is_ok());
		if let Some(gate) = &control.preflight_gate {
			tokio::select! {
				value = gate.clone().acquire_owned() => value.unwrap().forget(),
				_ = request.cancel.cancelled() => bail!("controlled request cancelled"),
				_ = core.stop.cancelled() => bail!("controlled pool stopped"),
				_ = tokio::time::sleep_until(request.deadline) => bail!("controlled deadline"),
			};
		}
		let host = tokio::select! {
			value = control.hosts[&request.host].clone().acquire_owned() => value.unwrap(),
			_ = request.cancel.cancelled() => bail!("controlled request cancelled"),
			_ = core.stop.cancelled() => bail!("controlled pool stopped"),
			_ = tokio::time::sleep_until(request.deadline) => bail!("controlled deadline"),
		};
		assert!(control
			.budget_waiting
			.try_send(request.command.clone())
			.is_ok());
		let budget = core
			.request_budget(&request, control.global.clone())
			.await?;
		assert!(control
			.started
			.try_send((request.host.clone(), request.command.clone()))
			.is_ok());
		tokio::select! {
			value = control.release.clone().acquire_owned() => value.unwrap().forget(),
			_ = request.cancel.cancelled() => bail!("controlled request cancelled"),
			_ = core.stop.cancelled() => bail!("controlled pool stopped"),
			_ = tokio::time::sleep_until(request.deadline) => bail!("controlled deadline"),
		};
		assert_ne!(request.command, "PANIC", "controlled supervisor panic");
		drop(host);
		Ok(Captured {
			output: Output {
				status: ExitStatus::from_raw(0),
				stdout: b"{}".to_vec(),
				stderr: vec![],
			},
			_budget: budget,
			_admission: request.admission.clone(),
		})
	}
	.await;
	let _ = request.reply.send(result);
}

async fn phase_notice(notices: &mut mpsc::Receiver<String>) -> String {
	timeout(Duration::from_secs(5), notices.recv())
		.await
		.unwrap()
		.unwrap()
}

async fn drained(sender: &mpsc::Sender<Request>) {
	timeout(Duration::from_secs(3), async {
		while sender.capacity() != QUEUE {
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
}

async fn started_host(started: &mut mpsc::Receiver<(String, String)>, host: &str) -> String {
	let (actual, command) = timeout(Duration::from_secs(3), started.recv())
		.await
		.unwrap()
		.unwrap();
	assert_eq!(actual, host);
	command
}

// These fixtures exercise the production actor with controlled work, so no
// network timing is used as evidence of scheduling or of resource bounds.
async fn fairness_fixture(core: &Arc<Core>, kind: &str) {
	let permits = Arc::new(Semaphore::new(MAX_SESSIONS));
	let admissions = Arc::new(Semaphore::new(MAX_ADMITTED));
	let (sender, receiver) = mpsc::channel(QUEUE);
	let (started_send, mut started) = mpsc::channel(MAX_ADMITTED);
	let (preflight_send, mut preflight) = mpsc::channel(MAX_ADMITTED + 1);
	let (budget_send, mut budget_waiting) = mpsc::channel(MAX_ADMITTED + 1);
	let release = Arc::new(Semaphore::new(0));
	let preflight_gate = matches!(
		kind,
		"fair-panic" | "fair-budget-cancel" | "fair-budget-deadline"
	)
	.then(|| Arc::new(Semaphore::new(0)));
	let control = Arc::new(ControlledDispatch {
		global: permits.clone(),
		hosts: core
			.profile
			.hosts
			.keys()
			.map(|host| (host.clone(), Arc::new(Semaphore::new(HOST_SESSIONS))))
			.collect(),
		started: started_send,
		preflight: preflight_send,
		budget_waiting: budget_send,
		preflight_gate: preflight_gate.clone(),
		release: release.clone(),
	});
	let actor = tokio::task::spawn_local(core.clone().run_with_dispatch(
		receiver,
		permits.clone(),
		move |core, request, permit| controlled_dispatch(core, request, permit, control.clone()),
	));
	let deadline = Instant::now() + Duration::from_secs(40);
	let mut requests = Vec::new();
	let mut retained = Vec::new();
	match kind {
		"fair-hot-cold" | "fair-capacity" => {
			for index in 0..QUEUE {
				requests.push(enqueue_fair_request(
					&sender,
					&admissions,
					"fixture",
					&format!("hot-{index}"),
					deadline,
				));
			}
			let first = started_host(&mut started, "fixture").await;
			let second = started_host(&mut started, "fixture").await;
			assert_ne!(first, second);
			for _ in 0..QUEUE {
				phase_notice(&mut preflight).await;
			}
			drained(&sender).await;
			assert_eq!(permits.available_permits(), MAX_SESSIONS - HOST_SESSIONS);
			if kind == "fair-hot-cold" {
				for index in 0..HOST_SESSIONS {
					requests.push(enqueue_fair_request(
						&sender,
						&admissions,
						"cold",
						&format!("cold-{index}"),
						deadline,
					));
				}
				// Both cold tasks start while all eight earlier hot requests are
				// unfinished. Hot host waiters hold no global budget.
				let mut cold = [
					started_host(&mut started, "cold").await,
					started_host(&mut started, "cold").await,
				];
				cold.sort();
				assert_eq!(cold, ["cold-0", "cold-1"]);
				assert_eq!(
					permits.available_permits(),
					MAX_SESSIONS - 2 * HOST_SESSIONS
				);
				assert_eq!(admissions.available_permits(), MAX_ADMITTED - 10);
			} else {
				// The channel still has capacity eight. Drain the first batch
				// before proving the unchanged pure-hot admission bound of 16.
				for index in QUEUE..MAX_ADMITTED {
					requests.push(enqueue_fair_request(
						&sender,
						&admissions,
						"fixture",
						&format!("hot-{index}"),
						deadline,
					));
				}
				drained(&sender).await;
				for _ in QUEUE..MAX_ADMITTED {
					phase_notice(&mut preflight).await;
				}
				assert_eq!(admissions.available_permits(), 0);
				assert!(admissions.clone().try_acquire_owned().is_err());
				assert_eq!(permits.available_permits(), MAX_SESSIONS - HOST_SESSIONS);
				let index = requests
					.iter()
					.position(|request| request.command != first && request.command != second)
					.unwrap();
				let cancelled = requests.remove(index);
				cancelled.cancel.cancel();
				assert!(timeout(Duration::from_secs(3), cancelled.reply)
					.await
					.unwrap()
					.unwrap()
					.is_err());
				assert_eq!(admissions.available_permits(), 1);
				requests.push(enqueue_fair_request(
					&sender,
					&admissions,
					"fixture",
					"replacement",
					deadline,
				));
				drained(&sender).await;
				assert_eq!(phase_notice(&mut preflight).await, "replacement");
				assert_eq!(admissions.available_permits(), 0);
			}
			assert!(started.try_recv().is_err());
		}
		"fair-retained" => {
			release.add_permits(MAX_SESSIONS);
			for index in 0..MAX_SESSIONS {
				requests.push(enqueue_fair_request(
					&sender,
					&admissions,
					"fixture",
					&format!("output-{index}"),
					deadline,
				));
			}
			for request in requests.drain(..) {
				retained.push(
					timeout(Duration::from_secs(3), request.reply)
						.await
						.unwrap()
						.unwrap()
						.unwrap(),
				);
			}
			let mut executed = Vec::new();
			for _ in 0..MAX_SESSIONS {
				executed.push(started_host(&mut started, "fixture").await);
				phase_notice(&mut preflight).await;
			}
			executed.sort();
			assert_eq!(
				executed,
				(0..MAX_SESSIONS)
					.map(|index| format!("output-{index}"))
					.collect::<Vec<_>>()
			);
			assert_eq!(permits.available_permits(), 0);
			assert_eq!(admissions.available_permits(), QUEUE);
			for index in 0..QUEUE {
				requests.push(enqueue_fair_request(
					&sender,
					&admissions,
					"fixture",
					&format!("pending-{index}"),
					deadline,
				));
			}
			drained(&sender).await;
			// Captured outputs count toward the same 16: eight retained plus
			// eight pending cannot turn into eight retained plus 16 pending.
			assert_eq!(admissions.available_permits(), 0);
			assert!(admissions.clone().try_acquire_owned().is_err());
			assert!(started.try_recv().is_err());
			release.add_permits(1);
			drop(retained.pop());
			let executed = started_host(&mut started, "fixture").await;
			let index = requests
				.iter()
				.position(|request| request.command == executed)
				.unwrap();
			let next = requests.remove(index);
			retained.push(
				timeout(Duration::from_secs(3), next.reply)
					.await
					.unwrap()
					.unwrap()
					.unwrap(),
			);
			assert_eq!(permits.available_permits(), 0);
			assert_eq!(admissions.available_permits(), 1);
			requests.push(enqueue_fair_request(
				&sender,
				&admissions,
				"fixture",
				"new-pending",
				deadline,
			));
			drained(&sender).await;
			assert_eq!(admissions.available_permits(), 0);
			assert!(started.try_recv().is_err());
		}
		"fair-cancel-deadline" => {
			for _ in 0..MAX_SESSIONS {
				retained.push(fair_output(
					permits.clone().try_acquire_owned().unwrap(),
					Arc::new(admissions.clone().try_acquire_owned().unwrap()),
				));
			}
			let cancelled =
				enqueue_fair_request(&sender, &admissions, "fixture", "cancelled", deadline);
			let expired = enqueue_fair_request(
				&sender,
				&admissions,
				"fixture",
				"expired",
				Instant::now() - Duration::from_millis(1),
			);
			let closed = enqueue_fair_request(&sender, &admissions, "fixture", "closed", deadline);
			let unknown =
				enqueue_fair_request(&sender, &admissions, "outside-profile", "unknown", deadline);
			requests.push(enqueue_fair_request(
				&sender,
				&admissions,
				"cold",
				"still-pending",
				deadline,
			));
			drained(&sender).await;
			cancelled.cancel.cancel();
			drop(closed);
			// Introduce the future deadline only after the earlier queue is
			// drained. With no intervening await, this assertion has no race
			// against the actor or a slow three-second drain timeout.
			let mut expiring = enqueue_fair_request(
				&sender,
				&admissions,
				"fixture",
				"expiring",
				Instant::now() + Duration::from_secs(1),
			);
			assert!(matches!(
				expiring.reply.try_recv(),
				Err(oneshot::error::TryRecvError::Empty)
			));
			for request in [cancelled, expired, expiring] {
				let error = timeout(Duration::from_secs(3), request.reply)
					.await
					.unwrap()
					.unwrap()
					.err()
					.unwrap();
				assert!(error.to_string().contains("cancelled before admission"));
			}
			let error = unknown.reply.await.unwrap().err().unwrap();
			assert!(error.to_string().contains("outside observation profile"));
			assert_eq!(
				admissions.available_permits(),
				MAX_ADMITTED - MAX_SESSIONS - 1
			);
			assert_eq!(permits.available_permits(), 0);
			assert!(started.try_recv().is_err());
		}
		"fair-panic" | "fair-budget-cancel" | "fair-budget-deadline" => {
			for _ in 0..MAX_SESSIONS - 1 {
				retained.push(fair_output(
					permits.clone().try_acquire_owned().unwrap(),
					Arc::new(admissions.clone().try_acquire_owned().unwrap()),
				));
			}
			let command = if kind == "fair-panic" {
				"PANIC"
			} else {
				"HOLD"
			};
			let held = enqueue_fair_request(&sender, &admissions, "fixture", command, deadline);
			assert_eq!(phase_notice(&mut preflight).await, command);
			let waiting_deadline = if kind == "fair-budget-deadline" {
				Instant::now() + Duration::from_secs(10)
			} else {
				deadline
			};
			let replacement = enqueue_fair_request(
				&sender,
				&admissions,
				"cold",
				"MUST_NOT_START",
				waiting_deadline,
			);
			assert_eq!(phase_notice(&mut preflight).await, "MUST_NOT_START");
			// Both supervisors already exist. Let the first own the only global
			// budget, then prove the second has entered the same budget wait.
			let gate = preflight_gate.as_ref().unwrap();
			gate.add_permits(1);
			assert_eq!(started_host(&mut started, "fixture").await, command);
			assert_eq!(phase_notice(&mut budget_waiting).await, command);
			gate.add_permits(1);
			assert_eq!(phase_notice(&mut budget_waiting).await, "MUST_NOT_START");
			assert_eq!(permits.available_permits(), 0);
			if kind != "fair-panic" {
				if kind == "fair-budget-cancel" {
					replacement.cancel.cancel();
				}
				let error = timeout(Duration::from_secs(12), replacement.reply)
					.await
					.unwrap()
					.unwrap()
					.err()
					.unwrap();
				assert!(error.to_string().contains("global capacity"));
				assert_eq!(permits.available_permits(), 0);
				assert_eq!(
					admissions.available_permits(),
					MAX_ADMITTED - retained.len() - 1
				);
				assert!(started.try_recv().is_err());
				assert!(!core.stop.is_cancelled());
				core.stop.cancel();
				timeout(Duration::from_secs(3), actor)
					.await
					.unwrap()
					.unwrap()
					.unwrap();
				assert!(held.reply.await.unwrap().is_err());
				assert_eq!(
					admissions.available_permits(),
					MAX_ADMITTED - retained.len()
				);
				drop(retained);
				assert_eq!(permits.available_permits(), MAX_SESSIONS);
				assert_eq!(admissions.available_permits(), MAX_ADMITTED);
				return;
			}
			release.add_permits(1);
			// The guard synchronously stops the pool before the awakened peer
			// can cross request_budget, independently of when the actor reaps.
			let error = timeout(Duration::from_secs(3), actor)
				.await
				.unwrap()
				.unwrap()
				.unwrap_err();
			assert!(error.to_string().contains("supervisor failed"));
			assert!(core.stop.is_cancelled());
			assert!(held.reply.await.is_err());
			let error = replacement.reply.await.unwrap().err().unwrap();
			assert!(error.to_string().contains("global capacity"));
			assert!(started.try_recv().is_err());
			assert_eq!(permits.available_permits(), 1);
			assert_eq!(
				admissions.available_permits(),
				MAX_ADMITTED - retained.len()
			);
			drop(retained);
			assert_eq!(permits.available_permits(), MAX_SESSIONS);
			assert_eq!(admissions.available_permits(), MAX_ADMITTED);
			return;
		}
		_ => panic!("unsupported fairness fixture"),
	}
	core.stop.cancel();
	timeout(Duration::from_secs(3), actor)
		.await
		.unwrap()
		.unwrap()
		.unwrap();
	for request in requests {
		assert!(request.reply.await.unwrap().is_err());
	}
	// Stopping the actor never refunds output held by the original caller.
	assert_eq!(permits.available_permits(), MAX_SESSIONS - retained.len());
	assert_eq!(
		admissions.available_permits(),
		MAX_ADMITTED - retained.len()
	);
	drop(retained);
	assert_eq!(permits.available_permits(), MAX_SESSIONS);
	assert_eq!(admissions.available_permits(), MAX_ADMITTED);
	assert!(core.masters.lock().await.is_empty());
	assert!(core.children.lock().await.is_empty());
}

async fn owned_admission_fixture(core: &Arc<Core>) {
	let permits = Arc::new(Semaphore::new(MAX_SESSIONS));
	let admissions = Arc::new(Semaphore::new(MAX_ADMITTED));
	let host = Arc::new(Semaphore::new(HOST_SESSIONS));
	let admission = Arc::new(admissions.clone().try_acquire_owned().unwrap());
	let budget = Arc::new(permits.clone().try_acquire_owned().unwrap());
	let (reply, _receive) = oneshot::channel();
	let request = Request {
		host: "fixture".into(),
		command: "NEVER_EXECUTE".into(),
		input: vec![],
		deadline: Instant::now() + Duration::from_secs(5),
		cancel: CancellationToken::new(),
		reply,
		admission: admission.clone(),
	};
	let socket = core.root.path.join("owned-budget");
	let listener = tokio::net::UnixListener::bind(&socket).unwrap();
	std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
	let mut args = core
		.arguments("fixture", Mode::Slave, &socket, false)
		.unwrap();
	args.push(request.command.clone());
	let mut command = core.command(&args);
	command
		.stdin(Stdio::null())
		.stdout(Stdio::null())
		.stderr(Stdio::null());
	let owned = core
		.spawn(
			&args,
			command,
			vec![
				budget.clone(),
				Arc::new(host.clone().try_acquire_owned().unwrap()),
				admission.clone(),
			],
			request.deadline,
			&request.cancel,
		)
		.await
		.unwrap();
	let (_stream, _) = timeout(Duration::from_secs(3), listener.accept())
		.await
		.unwrap()
		.unwrap();
	drop(request);
	drop(admission);
	drop(budget);
	// A caller/supervisor can disappear, but its exact unreaped child keeps
	// all three permits. Refusing premature release also freezes dispatch.
	assert!(core.release(&owned).await.is_err());
	assert!(core.stop.is_cancelled());
	assert_eq!(core.children.lock().await.len(), 1);
	assert_eq!(permits.available_permits(), MAX_SESSIONS - 1);
	assert_eq!(admissions.available_permits(), MAX_ADMITTED - 1);
	assert_eq!(host.available_permits(), HOST_SESSIONS - 1);
	core.stop_child(&owned, Duration::ZERO).await.unwrap();
	core.release(&owned).await.unwrap();
	assert_eq!(admissions.available_permits(), MAX_ADMITTED - 1);
	drop(owned);
	assert_eq!(permits.available_permits(), MAX_SESSIONS);
	assert_eq!(admissions.available_permits(), MAX_ADMITTED);
	assert_eq!(host.available_permits(), HOST_SESSIONS);
	std::fs::remove_file(socket).unwrap();
}

async fn fair_renewal_fixture(core: &Arc<Core>) {
	let (old, generation, _listener) = retired_generation(core, Duration::from_secs(20)).await;
	old.active.store(1, Ordering::Release);
	let permits = Arc::new(Semaphore::new(MAX_SESSIONS));
	let admissions = Arc::new(Semaphore::new(MAX_ADMITTED));
	let (sender, receiver) = mpsc::channel(QUEUE);
	let (started_send, mut started) = mpsc::channel(MAX_ADMITTED);
	let request_global = permits.clone();
	let actor = tokio::task::spawn_local(core.clone().run_with_dispatch(
		receiver,
		permits.clone(),
		move |core, request, permit| {
			assert!(started_send
				.try_send((request.host.clone(), request.command.clone()))
				.is_ok());
			let global = request_global.clone();
			async move {
				if request.host == "cold" {
					let output = fair_output(permit, request.admission.clone());
					assert!(request.reply.send(Ok(output)).is_ok());
				} else {
					core.execute(request, permit, global).await;
				}
			}
		},
	));
	let deadline = Instant::now() + Duration::from_secs(40);
	let first = enqueue_fair_request(&sender, &admissions, "fixture", "renew-first", deadline);
	let second = enqueue_fair_request(&sender, &admissions, "fixture", "renew-second", deadline);
	let waiting = enqueue_fair_request(
		&sender,
		&admissions,
		"fixture",
		"waiting-for-renewal",
		deadline,
	);
	assert_eq!(started_host(&mut started, "fixture").await, "renew-first");
	assert_eq!(started_host(&mut started, "fixture").await, "renew-second");
	assert_eq!(
		started_host(&mut started, "fixture").await,
		"waiting-for-renewal"
	);
	timeout(Duration::from_secs(3), async {
		loop {
			let changed = core
				.masters
				.lock()
				.await
				.get("fixture")
				.is_some_and(|entry| entry.generation != generation && entry.draining.is_some());
			if changed && permits.available_permits() == MAX_SESSIONS {
				break;
			}
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
	let cold = enqueue_fair_request(
		&sender,
		&admissions,
		"cold",
		"cold-during-renewal",
		deadline,
	);
	assert_eq!(
		started_host(&mut started, "cold").await,
		"cold-during-renewal"
	);
	let output = cold.reply.await.unwrap().unwrap();
	assert!(started.try_recv().is_err());
	assert_eq!(permits.available_permits(), MAX_SESSIONS - 1);
	assert_eq!(admissions.available_permits(), MAX_ADMITTED - 4);
	waiting.cancel.cancel();
	assert!(timeout(Duration::from_secs(3), waiting.reply)
		.await
		.unwrap()
		.unwrap()
		.is_err());
	core.stop.cancel();
	old.active.store(0, Ordering::Release);
	timeout(Duration::from_secs(5), actor)
		.await
		.unwrap()
		.unwrap()
		.unwrap();
	assert!(first.reply.await.unwrap().is_err());
	assert!(second.reply.await.unwrap().is_err());
	assert!(started.try_recv().is_err());
	drop(output);
	assert_eq!(permits.available_permits(), MAX_SESSIONS);
	assert_eq!(admissions.available_permits(), MAX_ADMITTED);
}

async fn phased_preflight_fixture(core: &Arc<Core>, agent: &Arc<AgentControl>) {
	let permits = Arc::new(Semaphore::new(MAX_SESSIONS));
	let admissions = Arc::new(Semaphore::new(MAX_ADMITTED));
	let host = Arc::new(Semaphore::new(HOST_SESSIONS));
	let occupied = host
		.clone()
		.acquire_many_owned(HOST_SESSIONS as u32)
		.await
		.unwrap();
	let (_ready, receive_ready) = watch::channel(None);
	core.masters.lock().await.insert(
		"fixture".into(),
		Entry {
			ready: receive_ready,
			permits: host.clone(),
			generation: core.sequence.fetch_add(1, Ordering::Relaxed),
			ready_deadline: Instant::now() + Duration::from_secs(40),
			draining: None,
		},
	);
	let before = agent.requests.load(Ordering::Acquire);
	let (sender, receiver) = mpsc::channel(QUEUE);
	let actor = tokio::task::spawn_local(core.clone().run_with_capacity(receiver, permits.clone()));
	let mut requests = Vec::new();
	for index in 0..MAX_SESSIONS {
		requests.push(enqueue_fair_request(
			&sender,
			&admissions,
			"fixture",
			&format!("preflight-{index}"),
			Instant::now() + Duration::from_secs(40),
		));
	}
	// Run the actual execute path. All eight real agent/profile checks finish
	// while the original host semaphore is occupied and no SSH child exists.
	timeout(Duration::from_secs(5), async {
		loop {
			let checked = agent.requests.load(Ordering::Acquire) - before;
			assert!(checked <= MAX_SESSIONS);
			if checked == MAX_SESSIONS && permits.available_permits() == MAX_SESSIONS {
				break;
			}
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
	assert_eq!(host.available_permits(), 0);
	assert_eq!(admissions.available_permits(), MAX_ADMITTED - MAX_SESSIONS);
	assert!(core.children.lock().await.is_empty());
	for request in &requests {
		request.cancel.cancel();
	}
	for request in requests {
		assert!(timeout(Duration::from_secs(3), request.reply)
			.await
			.unwrap()
			.unwrap()
			.is_err());
	}
	assert!(!core.stop.is_cancelled());
	core.stop.cancel();
	timeout(Duration::from_secs(3), actor)
		.await
		.unwrap()
		.unwrap()
		.unwrap();
	drop(occupied);
	assert_eq!(host.available_permits(), HOST_SESSIONS);
	assert_eq!(permits.available_permits(), MAX_SESSIONS);
	assert_eq!(admissions.available_permits(), MAX_ADMITTED);
}

struct PostverifyControl {
	global: Arc<Semaphore>,
	host: Arc<Semaphore>,
	completed: mpsc::Sender<String>,
	release: Arc<Semaphore>,
}

async fn postverify_dispatch(
	core: Arc<Core>,
	request: Request,
	initial: OwnedSemaphorePermit,
	control: Arc<PostverifyControl>,
) {
	let result = async {
		core.admission_profile(&request, initial).await?;
		let host = tokio::select! {
			value = control.host.clone().acquire_owned() => value.unwrap(),
			_ = core.stop.cancelled() => bail!("postverify fixture stopped"),
			_ = request.cancel.cancelled() => bail!("postverify fixture cancelled"),
			_ = tokio::time::sleep_until(request.deadline) => bail!("postverify fixture deadline"),
		};
		let budget = core
			.request_budget(&request, control.global.clone())
			.await?;
		core.verify_request_profile(request.deadline).await?;
		let args = core.arguments(
			"fixture",
			Mode::Slave,
			&core.root.path.join("phase-effective"),
			true,
		)?;
		// This is a real pinned, descriptor-owned ssh -G child. Its real wait,
		// release and output capture determine when the host permit is free.
		let output = core
			.captured(
				args,
				&[],
				request.deadline,
				&request.cancel,
				vec![budget.clone(), Arc::new(host), request.admission.clone()],
			)
			.await?;
		assert!(output.status.success());
		assert!(!output.stdout.is_empty());
		assert!(control.completed.try_send(request.command.clone()).is_ok());
		tokio::select! {
			value = control.release.clone().acquire_owned() => value.unwrap().forget(),
			_ = core.stop.cancelled() => bail!("postverify fixture stopped"),
			_ = request.cancel.cancelled() => bail!("postverify fixture cancelled"),
			_ = tokio::time::sleep_until(request.deadline) => bail!("postverify fixture deadline"),
		};
		core.verify_request_profile(request.deadline).await?;
		Ok(Captured {
			output,
			_budget: budget,
			_admission: request.admission.clone(),
		})
	}
	.await;
	let _ = request.reply.send(result);
}

async fn phased_postverify_fixture(core: &Arc<Core>) {
	let permits = Arc::new(Semaphore::new(MAX_SESSIONS));
	let admissions = Arc::new(Semaphore::new(MAX_ADMITTED));
	let host = Arc::new(Semaphore::new(HOST_SESSIONS));
	let release = Arc::new(Semaphore::new(0));
	let (completed_send, mut completed) = mpsc::channel(MAX_SESSIONS);
	let control = Arc::new(PostverifyControl {
		global: permits.clone(),
		host: host.clone(),
		completed: completed_send,
		release: release.clone(),
	});
	let (sender, receiver) = mpsc::channel(QUEUE);
	let actor = tokio::task::spawn_local(core.clone().run_with_dispatch(
		receiver,
		permits.clone(),
		move |core, request, permit| postverify_dispatch(core, request, permit, control.clone()),
	));
	let mut requests = Vec::new();
	let count = HOST_SESSIONS * 2;
	for index in 0..count {
		requests.push(enqueue_fair_request(
			&sender,
			&admissions,
			"fixture",
			&format!("postverify-{index}"),
			Instant::now() + Duration::from_secs(40),
		));
	}
	let mut finished = Vec::new();
	for _ in 0..count {
		finished.push(phase_notice(&mut completed).await);
	}
	finished.sort();
	assert_eq!(
		finished,
		(0..count)
			.map(|index| format!("postverify-{index}"))
			.collect::<Vec<_>>()
	);
	// Four children have been captured and reaped while all four response
	// checks are blocked. Host2 is free; four output budgets remain charged.
	assert_eq!(host.available_permits(), HOST_SESSIONS);
	assert_eq!(permits.available_permits(), MAX_SESSIONS - count);
	assert_eq!(admissions.available_permits(), MAX_ADMITTED - count);
	assert!(core.children.lock().await.is_empty());
	for request in &mut requests {
		assert!(matches!(
			request.reply.try_recv(),
			Err(oneshot::error::TryRecvError::Empty)
		));
	}
	release.add_permits(count);
	let mut outputs = Vec::new();
	for request in requests {
		outputs.push(
			timeout(Duration::from_secs(5), request.reply)
				.await
				.unwrap()
				.unwrap()
				.unwrap(),
		);
	}
	core.stop.cancel();
	timeout(Duration::from_secs(3), actor)
		.await
		.unwrap()
		.unwrap()
		.unwrap();
	assert_eq!(permits.available_permits(), MAX_SESSIONS - count);
	assert_eq!(admissions.available_permits(), MAX_ADMITTED - count);
	drop(outputs);
	assert_eq!(permits.available_permits(), MAX_SESSIONS);
	assert_eq!(admissions.available_permits(), MAX_ADMITTED);
}

async fn validation_early_shutdown_drain_fixture(core: &Arc<Core>, poison_lock: bool) {
	let marker = core.root.path.join("validation-drain-fixture");
	private_write(&marker, b"validation authority remains alive");
	let reads = Arc::new(AtomicUsize::new(0));
	let mut releases = Vec::new();
	// Occupy both real validation slots. Aborting the async callers must leave
	// the blocking closures and their permits alive across failed cleanup.
	for _ in 0..2 {
		let (entered, receive) = oneshot::channel();
		let (release, wait) = std::sync::mpsc::channel();
		let worker_core = core.clone();
		let worker_marker = marker.clone();
		let worker_reads = reads.clone();
		let caller = tokio::spawn(async move {
			worker_core
				.validation
				.run(
					&worker_core.stop,
					Instant::now() + Duration::from_secs(10),
					move || {
						let _ = entered.send(());
						wait.recv_timeout(Duration::from_secs(8))
							.context("test validation closure was not released")?;
						let bytes = std::fs::read(&worker_marker)?;
						if bytes != b"validation authority remains alive" {
							bail!("test validation authority changed before closure completion");
						}
						worker_reads.fetch_add(1, Ordering::SeqCst);
						Ok(())
					},
				)
				.await
		});
		timeout(Duration::from_secs(2), receive)
			.await
			.unwrap()
			.unwrap();
		caller.abort();
		assert!(caller.await.unwrap_err().is_cancelled());
		releases.push(release);
	}
	let refused_reads = Arc::new(AtomicUsize::new(0));
	let queued_core = core.clone();
	let queued_marker = marker.clone();
	let queued_reads = refused_reads.clone();
	let (waiting, admitted) = oneshot::channel();
	let queued = tokio::spawn(async move {
		let _ = waiting.send(());
		queued_core
			.validation
			.run(
				&queued_core.stop,
				Instant::now() + Duration::from_secs(10),
				move || {
					queued_reads.fetch_add(1, Ordering::SeqCst);
					std::fs::read(queued_marker)?;
					Ok(())
				},
			)
			.await
	});
	admitted.await.unwrap();
	assert!(!queued.is_finished());
	if poison_lock {
		let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
			let _held = core.background.lock().unwrap();
			panic!("controlled observation supervisor lock poison");
		}));
		assert!(poisoned.is_err());
	} else {
		core.background(async { bail!("controlled observation supervisor cleanup failure") })
			.unwrap();
	}
	// These are actual early Core::shutdown errors, before its successful-path
	// validation drain. Neither error establishes that the detached work ended.
	let cleanup = timeout(Duration::from_secs(2), core.shutdown())
		.await
		.unwrap();
	let error = cleanup.as_ref().unwrap_err();
	assert_eq!(
		error.to_string(),
		if poison_lock {
			"observation supervisor unavailable"
		} else {
			"observation child cleanup incomplete; reconciliation required"
		}
	);
	let original_error = error.root_cause() as *const _;
	assert!(core.stop.is_cancelled());
	assert!(timeout(Duration::from_secs(2), queued)
		.await
		.unwrap()
		.unwrap()
		.is_err());
	let new_marker = marker.clone();
	let new_reads = refused_reads.clone();
	assert!(core
		.validation
		.run(
			&core.stop,
			Instant::now() + Duration::from_secs(2),
			move || {
				new_reads.fetch_add(1, Ordering::SeqCst);
				std::fs::read(new_marker)?;
				Ok(())
			},
		)
		.await
		.is_err());
	assert_eq!(refused_reads.load(Ordering::SeqCst), 0);
	let finished = core.validation.finish_shutdown(cleanup);
	tokio::pin!(finished);
	// Poll the actual barrier: no wall-clock delay is used to establish that
	// it is pending while either real closure still owns its permit.
	assert!(
		std::future::poll_fn(|cx| std::task::Poll::Ready(finished.as_mut().poll(cx)))
			.await
			.is_pending()
	);
	assert!(marker.exists());
	releases.pop().unwrap().send(()).unwrap();
	timeout(Duration::from_secs(2), async {
		while reads.load(Ordering::SeqCst) != 1 {
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
	assert!(
		std::future::poll_fn(|cx| std::task::Poll::Ready(finished.as_mut().poll(cx)))
			.await
			.is_pending()
	);
	releases.pop().unwrap().send(()).unwrap();
	let error = timeout(Duration::from_secs(2), finished)
		.await
		.unwrap()
		.unwrap_err();
	assert!(std::ptr::eq(error.root_cause(), original_error));
	assert_eq!(reads.load(Ordering::SeqCst), 2);
	assert_eq!(refused_reads.load(Ordering::SeqCst), 0);
	assert!(marker.exists());
	// Only this fixture clears its deliberate poison and removes its own file;
	// the outer fixture then performs ordinary Core cleanup and root assertions.
	if poison_lock {
		core.background.clear_poison();
	}
	std::fs::remove_file(marker).unwrap();
}

#[test]
fn isolated_actual_ssh_guard_cancellation_and_ownership_fixtures() {
	for kind in [
		"off",
		"startup",
		"missing",
		"cancel",
		"profile",
		"wrong-thread",
		"admission-cancel",
		"spawn-cancel",
		"proof-failure",
		"validation-cleanup-error-drain",
		"validation-lock-error-drain",
		"renew-singleflight",
		"renew-refused",
		"renew-cleanup",
		"renew-deadline",
		"renew-maintain",
		"renew-retirement",
		"queue-capacity",
		"queue-stop",
		"queue-admission",
		"fair-hot-cold",
		"fair-capacity",
		"fair-retained",
		"fair-cancel-deadline",
		"fair-panic",
		"fair-budget-cancel",
		"fair-budget-deadline",
		"fair-owned-child",
		"fair-renewal",
		"fair-preflight",
		"fair-postverify",
		"socket-parent-bound",
		"agent-startup-unbound-timeout",
		"agent-startup-bound-timeout",
		"agent-startup-final-timeout",
		"agent-initial-timeout",
		"agent-prelease-timeout",
		"agent-postresponse-timeout",
		"agent-master-timeout",
		"agent-renewal-timeout",
		"agent-renewal-cleanup-error",
		"agent-timeout-then-key-change",
		"agent-timeout-then-frame-error",
		"agent-timeout-then-io-error",
		"agent-timeout-then-socket-change",
		"agent-timeout-then-file-change",
		"agent-timeout-then-environment-change",
	] {
		let mut child = std::process::Command::new(std::env::current_exe().unwrap())
			.args([
				"--exact",
				"mcp::runtime::ssh::observation_pool::tests::isolated_helper",
				"--ignored",
				"--nocapture",
			])
			.env("HEPTA_A15_TEST_FIXTURE", kind)
			.stdin(Stdio::null())
			.stdout(Stdio::null())
			.stderr(Stdio::inherit())
			.spawn()
			.unwrap();
		let deadline = std::time::Instant::now() + Duration::from_secs(45);
		let status = loop {
			if let Some(status) = child.try_wait().unwrap() {
				break status;
			}
			if std::time::Instant::now() >= deadline {
				child.kill().unwrap();
				child.wait().unwrap();
				panic!("isolated fixture deadline: {kind}");
			}
			std::thread::sleep(Duration::from_millis(20));
		};
		assert!(status.success(), "isolated fixture failed: {kind}");
	}
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "launched only by the bounded isolated subprocess test"]
async fn isolated_helper() {
	let kind = std::env::var("HEPTA_A15_TEST_FIXTURE").expect("isolated fixture required");
	let (root, path, agent, agent_control) = if kind.starts_with("fair-") {
		fixture_with_cold_host(true).await
	} else {
		fixture().await
	};
	if kind == "external-peer" {
		external_peer_helper(&path).await;
	} else if kind.starts_with("agent-startup-") {
		agent_timeout::startup(&path, &agent_control, &kind).await;
	} else if kind == "socket-parent-bound" {
		let name_bytes = format!("hp-o-{}-{}", std::process::id(), "0".repeat(32)).len();
		// Two separators plus m-1 add five bytes after the parent and root name.
		let parent_bytes = CONTROL_SOCKET_PATH_BYTES + 1 - name_bytes - 5;
		let leaf_bytes = parent_bytes - root.path().as_os_str().as_encoded_bytes().len() - 1;
		let parent = root.path().join("p".repeat(leaf_bytes));
		std::fs::create_dir(&parent).unwrap();
		std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
		let mut spec: serde_json::Value =
			serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
		spec["socket_parent"] = json!(parent);
		private_write(&path, &serde_json::to_vec(&spec).unwrap());
		let profile = Profile::load(&path).unwrap();
		let error = PrivateRoot::create(&profile).err().unwrap();
		assert!(error.to_string().contains("OpenSSH temporary publication"));
		assert_eq!(std::fs::read_dir(&parent).unwrap().count(), 0);
	} else if kind == "off" {
		let threads = std::fs::read_dir("/proc/self/task").unwrap().count();
		let descriptors = std::fs::read_dir("/proc/self/fd").unwrap().count();
		assert!(!requested());
		assert!(super::super::start_observation_pool(None, false)
			.await
			.unwrap()
			.is_none());
		assert!(!requested());
		assert_eq!(
			threads,
			std::fs::read_dir("/proc/self/task").unwrap().count()
		);
		assert_eq!(
			descriptors,
			std::fs::read_dir("/proc/self/fd").unwrap().count()
		);
	} else if kind == "startup" {
		// ControlMaster=yes is already explicit: a following -M toggles to ask.
		let argument_core = core(&path).await;
		let args = argument_core
			.arguments(
				"fixture",
				Mode::Master,
				&root.path().join("argv-only"),
				false,
			)
			.unwrap();
		assert!(!args.iter().any(|arg| arg == "-M"));
		assert!(args
			.windows(2)
			.any(|pair| pair[0] == "-o" && pair[1] == "ControlMaster=yes"));
		assert!(args.iter().any(|arg| arg == "-N"));
		assert!(args.iter().any(|arg| arg == "-n"));
		argument_core.stop.cancel();
		argument_core.shutdown().await.unwrap();
		drop(argument_core);
		let guard = start(&path).await.unwrap();
		assert!(requested());
		assert!(!guard.0.stop.is_cancelled());
		let error = match capture(
			"fixture",
			"x".repeat(super::super::MAX_OBSERVATION_BYTES + 1),
			vec![],
			Duration::from_secs(1),
		)
		.await
		{
			Err(error) => error,
			Ok(_) => panic!("oversized payload must be refused before enqueue"),
		};
		assert!(
			error
				.to_string()
				.contains("observation_pool_payload_unsupported"),
			"{error:#}"
		);
		for entry in std::fs::read_dir(root.path()).unwrap() {
			let entry = entry.unwrap();
			if entry.file_name().to_string_lossy().starts_with("hp-o-") {
				assert_eq!(std::fs::read_dir(entry.path()).unwrap().count(), 0);
			}
		}
		guard.shutdown().await.unwrap();
		assert!(requested());
		assert!(capture(
			"fixture",
			"NEVER_DISPATCH".into(),
			vec![],
			Duration::from_secs(1)
		)
		.await
		.is_err());
	} else {
		let core = core(&path).await;
		match kind.as_str() {
			"validation-cleanup-error-drain" | "validation-lock-error-drain" => {
				validation_early_shutdown_drain_fixture(
					&core,
					kind == "validation-lock-error-drain",
				)
				.await;
			}
			kind if kind.starts_with("agent-") => {
				agent_timeout::run(&core, &agent_control, kind).await;
			}
			"fair-hot-cold"
			| "fair-capacity"
			| "fair-retained"
			| "fair-cancel-deadline"
			| "fair-panic"
			| "fair-budget-cancel"
			| "fair-budget-deadline" => {
				// The real actor is intentionally not Send: all maintenance and
				// child ownership stay on this same current-thread runtime.
				tokio::task::LocalSet::new()
					.run_until(fairness_fixture(&core, &kind))
					.await;
			}
			"fair-owned-child" => owned_admission_fixture(&core).await,
			"fair-renewal" => {
				tokio::task::LocalSet::new()
					.run_until(fair_renewal_fixture(&core))
					.await;
			}
			"fair-preflight" => {
				tokio::task::LocalSet::new()
					.run_until(phased_preflight_fixture(&core, &agent_control))
					.await;
			}
			"fair-postverify" => {
				tokio::task::LocalSet::new()
					.run_until(phased_postverify_fixture(&core))
					.await;
			}
			"queue-capacity" | "queue-stop" | "queue-admission" => {
				queued_admission_fixture(&core, &kind, &agent_control).await;
			}
			"renew-singleflight" | "renew-refused" | "renew-cleanup" | "renew-deadline"
			| "renew-maintain" | "renew-retirement" => renewal_fixture(&core, &kind).await,
			"admission-cancel" => {
				agent_control.stall.store(true, Ordering::Release);
				let cancel = CancellationToken::new();
				let (reply, _) = oneshot::channel();
				let request = Request {
					host: "fixture".into(),
					command: "NEVER_DISPATCH".into(),
					input: vec![],
					deadline: Instant::now() + Duration::from_secs(40),
					cancel: cancel.clone(),
					reply,
					admission: test_admission(),
				};
				let permits = Arc::new(Semaphore::new(1));
				let permit = permits.clone().acquire_owned().await.unwrap();
				let task_core = core.clone();
				let global = permits.clone();
				let task =
					tokio::spawn(
						async move { task_core.execute_inner(&request, permit, global).await },
					);
				timeout(Duration::from_secs(1), agent_control.entered.notified())
					.await
					.unwrap();
				cancel.cancel();
				assert!(timeout(Duration::from_millis(250), task)
					.await
					.unwrap()
					.unwrap()
					.is_err());
				assert_eq!(permits.available_permits(), 1);
				assert!(core.masters.lock().await.is_empty());
				assert!(core.children.lock().await.is_empty());
				assert!(!core.stop.is_cancelled());
			}
			"spawn-cancel" => {
				let args = core
					.arguments(
						"fixture",
						Mode::Slave,
						&core.root.path.join("missing"),
						false,
					)
					.unwrap();
				let cancel = CancellationToken::new();
				cancel.cancel();
				assert!(core
					.captured(
						args.clone(),
						&[],
						Instant::now() + Duration::from_secs(1),
						&cancel,
						vec![]
					)
					.await
					.is_err());
				assert!(core
					.captured(
						args,
						&[],
						Instant::now() - Duration::from_millis(1),
						&CancellationToken::new(),
						vec![]
					)
					.await
					.is_err());
				assert!(core.children.lock().await.is_empty());
			}
			"proof-failure" => {
				let socket = core.root.path.join("unproven");
				let _listener = tokio::net::UnixListener::bind(&socket).unwrap();
				std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
				let mut args = core
					.arguments("fixture", Mode::Slave, &socket, false)
					.unwrap();
				args.push("printf SHOULD_NEVER_EXECUTE".into());
				let command = core.command(&args);
				let mut wrong_identity = args;
				wrong_identity.push("NOT_THE_EXECUTED_ARGV".into());
				assert!(core
					.spawn(
						&wrong_identity,
						command,
						vec![],
						Instant::now() + Duration::from_secs(2),
						&CancellationToken::new()
					)
					.await
					.is_err());
				assert!(core.stop.is_cancelled());
				assert!(core.children.lock().await.is_empty());
				std::fs::remove_file(socket).unwrap();
			}
			"missing" => {
				let socket = core.root.path.join("missing");
				let mut args = core
					.arguments("fixture", Mode::Slave, &socket, false)
					.unwrap();
				args.push("printf SHOULD_NEVER_EXECUTE".into());
				let output = core
					.captured(
						args,
						&[],
						Instant::now() + Duration::from_secs(5),
						&CancellationToken::new(),
						vec![],
					)
					.await
					.unwrap();
				assert!(!output.status.success());
				assert!(output.stdout.is_empty());
				assert!(core.children.lock().await.is_empty());
			}
			"cancel" => {
				let socket = core.root.path.join("blocked");
				let listener = tokio::net::UnixListener::bind(&socket).unwrap();
				std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
				let (ready, waiting) = oneshot::channel();
				let fake = tokio::spawn(async move {
					let (stream, _) = listener.accept().await.unwrap();
					let _ = ready.send(());
					std::future::pending::<()>().await;
					drop(stream);
				});
				let mut args = core
					.arguments("fixture", Mode::Slave, &socket, false)
					.unwrap();
				args.push("printf SHOULD_NEVER_EXECUTE".into());
				let permits = Arc::new(Semaphore::new(1));
				let permit = permits.clone().acquire_owned().await.unwrap();
				let cancel = CancellationToken::new();
				let task_cancel = cancel.clone();
				let task_core = core.clone();
				let task = tokio::spawn(async move {
					task_core
						.captured(
							args,
							&[],
							Instant::now() + Duration::from_secs(5),
							&task_cancel,
							vec![Arc::new(permit)],
						)
						.await
				});
				timeout(Duration::from_secs(2), waiting)
					.await
					.unwrap()
					.unwrap();
				assert_eq!(permits.available_permits(), 0);
				assert_eq!(core.children.lock().await.len(), 1);
				cancel.cancel();
				assert!(task.await.unwrap().is_err());
				assert!(core.children.lock().await.is_empty());
				assert_eq!(permits.available_permits(), 1);
				fake.abort();
				let _ = fake.await;
				std::fs::remove_file(socket).unwrap();
			}
			"profile" => {
				private_write(&core.profile.known_hosts, b"changed in place\n");
				assert!(core
					.verify_profile(Instant::now() + Duration::from_secs(1))
					.await
					.is_err());
				assert!(core.stop.is_cancelled());
				assert!(core.children.lock().await.is_empty());
			}
			"wrong-thread" => {
				let other = core.clone();
				let thread = std::thread::spawn(move || {
					let runtime = tokio::runtime::Builder::new_current_thread()
						.enable_all()
						.build()
						.unwrap();
					runtime.block_on(async {
						let args = other
							.arguments(
								"fixture",
								Mode::Slave,
								&other.root.path.join("missing"),
								false,
							)
							.unwrap();
						other
							.captured(
								args,
								&[],
								Instant::now() + Duration::from_secs(1),
								&CancellationToken::new(),
								vec![],
							)
							.await
					})
				});
				assert!(thread.join().unwrap().is_err());
				assert!(core.children.lock().await.is_empty());
			}
			_ => panic!("unsupported isolated fixture"),
		}
		core.shutdown().await.unwrap();
	}
	agent.abort();
	let _ = agent.await;
	assert!(!std::fs::read_dir(root.path()).unwrap().any(|entry| entry
		.unwrap()
		.file_name()
		.to_string_lossy()
		.starts_with("hp-o-")));
}

// Explicit external-driver fixture only; deliberately absent from the normal
// bounded parent loop. The external peer must stay alive holding all mux
// descriptors while that driver kills only this helper process.
async fn external_peer_helper(path: &Path) {
	use sha2::{Digest, Sha256};
	use std::io::Write;
	let socket = PathBuf::from(
		std::env::var_os("HEPTA_A15_EXTERNAL_SOCKET").expect("external socket required"),
	);
	profile::absolute(&socket).unwrap();
	let socket_parent = socket.parent().unwrap().to_owned();
	let socket_parent_file = profile::open_absolute(&socket_parent, true).unwrap();
	let socket_parent_stamp = profile::private_directory(&socket_parent).unwrap();
	assert!(socket_parent_stamp.same_directory(&Stamp::of(&socket_parent_file.metadata().unwrap())));
	let parent: u32 = std::env::var("HEPTA_A15_EXTERNAL_PARENT")
		.unwrap()
		.parse()
		.unwrap();
	assert_eq!(unsafe { libc::getppid() } as u32, parent);
	let nonce = std::env::var("HEPTA_A15_EXTERNAL_NONCE").unwrap();
	assert!(
		nonce.len() == 64
			&& nonce
				.bytes()
				.all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
	);
	let stamp = profile::socket_stamp(&socket).unwrap();
	let probe = timeout(Duration::from_secs(3), UnixStream::connect(&socket))
		.await
		.unwrap()
		.unwrap();
	let peer = profile::peer(&probe).unwrap();
	assert_eq!(
		(peer.0 as u32, peer.1),
		(parent, unsafe { libc::geteuid() })
	);
	assert_eq!(profile::socket_stamp(&socket).unwrap(), stamp);
	assert!(
		socket_parent_stamp.same_directory(&profile::private_directory(&socket_parent).unwrap())
	);
	drop(probe);
	let path = path.to_owned();
	let (ready, receive) = oneshot::channel();
	let owner = std::thread::Builder::new().name("hepta-external-pdeath-fixture".into()).spawn(move || {
		let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
		runtime.block_on(async move {
			let core = core(&path).await;
			let owner_tid = unsafe { libc::syscall(libc::SYS_gettid) };
			assert_ne!(owner_tid as u32, std::process::id());
			assert_eq!(core.owner_tid, owner_tid);
			assert_eq!(profile::socket_stamp(&socket).unwrap(), stamp);
			assert!(socket_parent_stamp.same_directory(&profile::private_directory(&socket_parent).unwrap()));
			assert!(socket_parent_stamp.same_directory(&Stamp::of(&socket_parent_file.metadata().unwrap())));
			let mut args = core.arguments("fixture", Mode::Slave, &socket, false).unwrap();
			args.push("NEVER_DISPATCH".into());
			let mut command = core.command(&args);
			command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
			let started = Instant::now();
			let owned = core.spawn(&args, command, vec![], started + Duration::from_secs(5), &CancellationToken::new()).await.unwrap();
			owned.verify_live().await.unwrap();
			let identity = process_identity(owned.pid).unwrap();
			let argv_hash = Sha256::digest(&identity.argv).iter().map(|v| format!("{v:02x}")).collect::<String>();
			assert_eq!(profile::socket_stamp(&socket).unwrap(), stamp);
			assert!(socket_parent_stamp.same_directory(&profile::private_directory(&socket_parent).unwrap()));
			assert!(socket_parent_stamp.same_directory(&Stamp::of(&socket_parent_file.metadata().unwrap())));
			let value = json!({"schema":"hepta-external-pdeath-helper/v1","nonce":nonce,
				"helper_pid":std::process::id(),"parent_pid":parent,"owner_tid":owner_tid,"ssh_pid":owned.pid,
				"ssh_birth":identity.birth,"ssh_uid":identity.uid,"ssh_exe":std::fs::read_link(format!("/proc/{}/exe",owned.pid)).unwrap(),
				"ssh_exe_device":identity.dev,"ssh_exe_inode":identity.ino,"ssh_argv_sha256":argv_hash,"ssh_argv":args,
				"profile_path":path,"socket_path":socket,"socket_device":stamp.dev,"socket_inode":stamp.ino,
				"socket_uid":stamp.uid,"socket_mode":stamp.mode,"backstop_seconds":30,
				"milliseconds_since_spawn":started.elapsed().as_millis()});
			let _ = ready.send(value);
			// The driver must kill this process within5s of dual readiness. This
			// thirty-second failure backstop cannot count as PDEATH evidence.
			tokio::time::sleep_until(started + Duration::from_secs(30)).await;
			core.stop.cancel();
			core.shutdown().await.unwrap();
		});
	}).unwrap();
	let value = timeout(Duration::from_secs(10), receive)
		.await
		.unwrap()
		.unwrap();
	println!(
		"HEPTA_A15_EXTERNAL_READY {}",
		serde_json::to_string(&value).unwrap()
	);
	std::io::stdout().flush().unwrap();
	// Joining only; the main runtime keeps the independent fake-agent healthy.
	tokio::task::spawn_blocking(move || owner.join())
		.await
		.unwrap()
		.unwrap();
	panic!("external helper reached its cleanup backstop without a parent-death proof");
}
