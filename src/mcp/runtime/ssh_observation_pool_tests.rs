// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Isolated observation scheduling, ownership and recovery fixtures.
use super::*;
use serde_json::json;
use std::future::Future;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use tokio::sync::Semaphore;

#[path = "ssh_observation_agent_timeout_tests.rs"]
mod agent_timeout;

#[path = "ssh_observation_socket_publication_tests.rs"]
mod socket_publication;

#[path = "ssh_file_observation_pool_tests.rs"]
mod file_observations;

#[path = "ssh_observation_maintenance_tests.rs"]
mod maintenance;

#[path = "ssh_observation_owner_custody_tests.rs"]
mod owner_custody;

fn proxy_admission_fixture() -> (Arc<Proxy>, mpsc::UnboundedReceiver<Request>) {
	let (sender, receiver) = mpsc::unbounded_channel();
	let proxy = Arc::new(Proxy {
		sender,
		stop: CancellationToken::new(),
		healthy: AtomicBool::new(true),
		thread: Mutex::new(None),
		custody: Mutex::new(None),
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
	for index in 0..32 {
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
	replies
}

#[tokio::test(flavor = "current_thread")]
async fn proxy_accepts_beyond_old_queue_and_admission_caps_once_per_identity() {
	let (proxy, mut receiver) = proxy_admission_fixture();
	let deadline = Instant::now() + Duration::from_secs(30);
	let replies = fill_proxy_channel(&proxy, deadline).await;
	assert_eq!(receiver.len(), 32);
	for index in 0..32 {
		let request = receiver.try_recv().unwrap();
		assert_eq!(request.command, format!("queued-{index}"));
		assert_eq!(request.host, "fixture");
		assert_eq!(request.input.as_slice(), request.command.as_bytes());
		assert_eq!(request.deadline, deadline);
		assert!(!request.cancel.is_cancelled());
	}
	assert!(matches!(
		receiver.try_recv(),
		Err(mpsc::error::TryRecvError::Empty)
	));
	for reply in replies {
		assert!(reply.await.is_err());
	}
}

#[tokio::test(flavor = "current_thread")]
async fn proxy_checks_cancel_deadline_stop_health_and_closed_queue_before_submission() {
	for reason in ["cancel", "deadline", "stop", "unhealthy", "close"] {
		let (proxy, mut receiver) = proxy_admission_fixture();
		let deadline = Instant::now() + Duration::from_secs(30);
		let replies = fill_proxy_channel(&proxy, deadline).await;
		let cancel = CancellationToken::new();
		match reason {
			"cancel" => cancel.cancel(),
			"stop" => proxy.stop.cancel(),
			"unhealthy" => proxy.healthy.store(false, Ordering::Release),
			"close" => receiver.close(),
			"deadline" => {}
			_ => unreachable!(),
		}
		let deadline = if reason == "deadline" {
			Instant::now()
		} else {
			deadline
		};
		let error = proxy_submission(proxy.clone(), "must-not-send".into(), deadline, cancel)
			.await
			.err()
			.unwrap();
		assert!(error.to_string().contains("before queue submission"));
		assert_eq!(receiver.len(), 32);
		drop(receiver);
		for reply in replies {
			assert!(reply.await.is_err());
		}
		assert_eq!(proxy.stop.is_cancelled(), reason == "stop");
	}
}

#[tokio::test(flavor = "current_thread")]
async fn proxy_future_and_receiver_drop_never_create_or_replay_requests() {
	let (proxy, receiver) = proxy_admission_fixture();
	let deadline = Instant::now() + Duration::from_secs(30);
	let replies = fill_proxy_channel(&proxy, deadline).await;
	let unpolled = proxy_submission(
		proxy.clone(),
		"unpolled".into(),
		deadline,
		CancellationToken::new(),
	);
	drop(unpolled);
	assert_eq!(receiver.len(), 32);
	drop(receiver);
	assert!(proxy_submission(
		proxy.clone(),
		"receiver-dropped".into(),
		deadline,
		CancellationToken::new()
	)
	.await
	.is_err());
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

#[tokio::test(flavor = "current_thread")]
async fn completed_supervisors_leave_all_original_outputs_owned_by_callers() {
	let mut work = JoinSet::new();
	let mut replies = Vec::new();
	for _ in 0..32 {
		let (send, receive) = oneshot::channel();
		work.spawn(async move {
			assert!(send.send(fair_output()).is_ok());
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
	Core::reap_completed_requests(&mut work).unwrap();
	assert!(work.is_empty());
	for output in outputs {
		assert_eq!(
			serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
			json!({})
		);
	}
}

#[tokio::test(flavor = "current_thread")]
async fn reap_propagates_panicked_and_cancelled_supervisors() {
	for cancel in [false, true] {
		let mut work = JoinSet::new();
		let (send, receive) = oneshot::channel();
		let task = work.spawn(async move {
			assert!(send.send(()).is_ok());
			if cancel {
				std::future::pending::<()>().await;
			} else {
				panic!("request supervisor fixture panic");
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
	if std::env::var("HEPTA_A15_TEST_FIXTURE").as_deref() == Ok("many-hosts") {
		for index in 1..12 {
			spec["hosts"][format!("fixture-{index}")] = spec["hosts"]["fixture"].clone();
		}
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
			activity: Arc::new(Activity::default()),
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
			assert!(Arc::ptr_eq(&installed.activity, &stale.activity));
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
			assert!(Arc::ptr_eq(&latest.activity, &installed.activity));
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
			};
			assert!(request.deadline > old.created + AGE);
			let task_core = core.clone();
			let task = tokio::spawn(async move { task_core.execute_inner(&request).await });
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
			// A terminal master does not retire original activity leases.
			old.active.store(1, Ordering::Release);
			assert_eq!(stale.activity.active(), 0);
			core.maintain().await.unwrap();
			assert!(!old.accepting.load(Ordering::Acquire));
			assert!(core.children.lock().await.is_empty());
			assert!(!old.socket.exists());
			let held = core.entry("fixture", &cancel, deadline).await.unwrap();
			assert_eq!(held.generation, generation);
			assert!(Arc::ptr_eq(&held.activity, &stale.activity));
			let permit = stale.activity.lease().unwrap();
			old.active.store(0, Ordering::Release);
			core.maintain().await.unwrap();
			let held = core.entry("fixture", &cancel, deadline).await.unwrap();
			assert_eq!(held.generation, generation);
			assert!(Arc::ptr_eq(&held.activity, &stale.activity));
			assert_eq!(held.activity.active(), 1);
			drop(permit);
			core.maintain().await.unwrap();
			assert!(core.masters.lock().await.is_empty());
			assert_eq!(core.background.lock().unwrap().len(), 0);
			// Error-ready generations retain their outstanding activity too.
			let permit = stale.activity.lease().unwrap();
			let (send, receive) =
				watch::channel(Some(Err("synthetic failed generation".to_owned())));
			let failed_generation = core.sequence.fetch_add(1, Ordering::Relaxed);
			core.masters.lock().await.insert(
				"fixture".into(),
				Entry {
					ready: receive,
					activity: stale.activity.clone(),
					generation: failed_generation,
					ready_deadline: deadline,
					draining: None,
				},
			);
			drop(send);
			core.maintain().await.unwrap();
			let held = core.entry("fixture", &cancel, deadline).await.unwrap();
			assert_eq!(held.generation, failed_generation);
			assert!(Arc::ptr_eq(&held.activity, &stale.activity));
			assert!(matches!(&*held.ready.borrow(), Some(Err(_))));
			drop(permit);
			core.maintain().await.unwrap();
			assert!(core.masters.lock().await.is_empty());
			assert_eq!(core.background.lock().unwrap().len(), 0);
		}
		_ => panic!("unsupported renewal fixture"),
	}
}

struct FairRequest {
	reply: oneshot::Receiver<Result<Captured>>,
	cancel: CancellationToken,
	command: String,
}

fn enqueue_fair_request(
	sender: &mpsc::UnboundedSender<Request>,
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
	};
	assert!(sender.send(request).is_ok());
	FairRequest {
		reply: receive,
		cancel,
		command: command.into(),
	}
}

fn fair_output() -> Captured {
	Captured {
		output: Output {
			status: ExitStatus::from_raw(0),
			stdout: b"{}".to_vec(),
			stderr: vec![],
		},
	}
}

async fn phase_notice(notices: &mut mpsc::Receiver<String>) -> String {
	timeout(Duration::from_secs(5), notices.recv())
		.await
		.unwrap()
		.unwrap()
}

async fn started_host(started: &mut mpsc::Receiver<(String, String)>, host: &str) -> String {
	let (actual, command) = timeout(Duration::from_secs(3), started.recv())
		.await
		.unwrap()
		.unwrap();
	assert_eq!(actual, host);
	command
}

// The real actor runs controlled work so all starts can be observed before any
// completes, independently of network connection or authentication timing.
async fn unbounded_dispatch_fixture(core: &Arc<Core>, kind: &str) {
	let (sender, receiver) = mpsc::unbounded_channel();
	let (started_send, mut started) = mpsc::channel(64);
	let release = Arc::new(Semaphore::new(0));
	let task_release = release.clone();
	let actor = tokio::task::spawn_local(core.clone().run_with_dispatch(
		receiver,
		move |core, request| {
			let started = started_send.clone();
			let release = task_release.clone();
			async move {
				let result = async {
					core.admission_profile(&request).await?;
					assert!(started
						.try_send((request.host.clone(), request.command.clone()))
						.is_ok());
					tokio::select! {
						permit = release.acquire() => permit.unwrap().forget(),
						_ = request.cancel.cancelled() => bail!("controlled request cancelled"),
						_ = core.stop.cancelled() => bail!("controlled pool stopped"),
						_ = tokio::time::sleep_until(request.deadline) => bail!("controlled deadline"),
					}
					assert_ne!(request.command, "PANIC", "controlled supervisor panic");
					Ok(fair_output())
				}
				.await;
				let _ = request.reply.send(result);
			}
		},
	));
	let deadline = Instant::now() + Duration::from_secs(30);
	let mut requests = Vec::new();
	for index in 0..32 {
		requests.push(enqueue_fair_request(
			&sender,
			"fixture",
			&format!("held-{index}"),
			deadline,
		));
	}
	if kind == "fair-stopped" {
		core.stop.cancel();
		for request in requests {
			assert!(!matches!(request.reply.await, Ok(Ok(_))));
		}
		timeout(Duration::from_secs(5), actor)
			.await
			.unwrap()
			.unwrap()
			.unwrap();
		assert!(started.try_recv().is_err());
		assert!(core.children.lock().await.is_empty());
		return;
	}
	let mut names = std::collections::BTreeSet::new();
	for _ in 0..32 {
		names.insert(started_host(&mut started, "fixture").await);
	}
	assert_eq!(names.len(), 32);
	let cold = enqueue_fair_request(
		&sender,
		"cold",
		if kind == "fair-panic" {
			"PANIC"
		} else {
			"cold"
		},
		deadline,
	);
	assert_eq!(started_host(&mut started, "cold").await, cold.command);
	requests.push(cold);
	if kind == "fair-cancel-deadline" {
		let timed = enqueue_fair_request(
			&sender,
			"cold",
			"running-deadline",
			Instant::now() + Duration::from_secs(1),
		);
		assert_eq!(started_host(&mut started, "cold").await, timed.command);
		assert!(timeout(Duration::from_secs(3), timed.reply)
			.await
			.unwrap()
			.unwrap()
			.is_err());
		for request in &requests {
			request.cancel.cancel();
		}
		for request in requests {
			assert!(request.reply.await.unwrap().is_err());
		}
		let expired = enqueue_fair_request(&sender, "fixture", "expired", Instant::now());
		assert!(expired.reply.await.unwrap().is_err());
		let cancelled =
			enqueue_fair_request(&sender, "fixture", "cancelled-before-start", deadline);
		cancelled.cancel.cancel();
		assert!(cancelled.reply.await.unwrap().is_err());
		let closed = enqueue_fair_request(&sender, "fixture", "closed-before-start", deadline);
		drop(closed.reply);
		let unknown = enqueue_fair_request(&sender, "outside-profile", "unknown", deadline);
		assert!(unknown.reply.await.unwrap().is_err());
		assert!(started.try_recv().is_err());
	} else {
		release.add_permits(requests.len());
		if kind == "fair-panic" {
			for request in requests {
				let _ = request.reply.await;
			}
			assert!(timeout(Duration::from_secs(5), actor)
				.await
				.unwrap()
				.unwrap()
				.is_err());
			assert!(core.stop.is_cancelled());
			return;
		}
		let mut outputs = Vec::new();
		for request in requests {
			outputs.push(request.reply.await.unwrap().unwrap());
		}
		// Keeping every prior output cannot obstruct another original request.
		let later = enqueue_fair_request(&sender, "fixture", "after-retained-outputs", deadline);
		assert_eq!(started_host(&mut started, "fixture").await, later.command);
		release.add_permits(1);
		outputs.push(later.reply.await.unwrap().unwrap());
		assert_eq!(outputs.len(), 34);
	}
	assert!(core.children.lock().await.is_empty());
	core.stop.cancel();
	timeout(Duration::from_secs(5), actor)
		.await
		.unwrap()
		.unwrap()
		.unwrap();
}

async fn owned_admission_fixture(core: &Arc<Core>) {
	let host = Arc::new(Activity::default());
	let (reply, _receive) = oneshot::channel();
	let request = Request {
		host: "fixture".into(),
		command: "NEVER_EXECUTE".into(),
		input: vec![],
		deadline: Instant::now() + Duration::from_secs(5),
		cancel: CancellationToken::new(),
		reply,
	};
	let socket = core.root.path.join("owned-lifetime");
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
			vec![Arc::new(host.lease().unwrap())],
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
	// The exact unreaped child retains master activity after the caller leaves.
	// Refusing premature release freezes dispatch until custody is reconciled.
	assert!(core.release(&owned).await.is_err());
	assert!(core.stop.is_cancelled());
	assert_eq!(core.children.lock().await.len(), 1);
	assert_eq!(host.active(), 1);
	core.stop_child(&owned, Duration::ZERO).await.unwrap();
	core.release(&owned).await.unwrap();
	assert_eq!(host.active(), 1);
	drop(owned);
	assert_eq!(host.active(), 0);
	std::fs::remove_file(socket).unwrap();
}

async fn fair_renewal_fixture(core: &Arc<Core>) {
	let (old, generation, _listener) = retired_generation(core, Duration::from_secs(20)).await;
	old.active.store(1, Ordering::Release);
	let (sender, receiver) = mpsc::unbounded_channel();
	let (started_send, mut started) = mpsc::channel(64);
	let actor = tokio::task::spawn_local(core.clone().run_with_dispatch(
		receiver,
		move |core, request| {
			assert!(started_send
				.try_send((request.host.clone(), request.command.clone()))
				.is_ok());
			async move {
				if request.host == "cold" {
					let output = fair_output();
					assert!(request.reply.send(Ok(output)).is_ok());
				} else {
					core.execute(request).await;
				}
			}
		},
	));
	let deadline = Instant::now() + Duration::from_secs(40);
	let first = enqueue_fair_request(&sender, "fixture", "renew-first", deadline);
	let second = enqueue_fair_request(&sender, "fixture", "renew-second", deadline);
	let waiting = enqueue_fair_request(&sender, "fixture", "waiting-for-renewal", deadline);
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
			if changed {
				break;
			}
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
	let cold = enqueue_fair_request(&sender, "cold", "cold-during-renewal", deadline);
	assert_eq!(
		started_host(&mut started, "cold").await,
		"cold-during-renewal"
	);
	let output = cold.reply.await.unwrap().unwrap();
	assert!(started.try_recv().is_err());
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
}

async fn phased_preflight_fixture(core: &Arc<Core>, agent: &Arc<AgentControl>) {
	let host = Arc::new(Activity::default());
	let (_ready, receive_ready) = watch::channel(None);
	core.masters.lock().await.insert(
		"fixture".into(),
		Entry {
			ready: receive_ready,
			activity: host.clone(),
			generation: core.sequence.fetch_add(1, Ordering::Relaxed),
			ready_deadline: Instant::now() + Duration::from_secs(40),
			draining: None,
		},
	);
	let before = agent.requests.load(Ordering::Acquire);
	let (sender, receiver) = mpsc::unbounded_channel();
	let actor = tokio::task::spawn_local(core.clone().run(receiver));
	let mut requests = Vec::new();
	for index in 0..32 {
		requests.push(enqueue_fair_request(
			&sender,
			"fixture",
			&format!("preflight-{index}"),
			Instant::now() + Duration::from_secs(40),
		));
	}
	// Every request completes its initial authority check and independently
	// waits on the same master initialization, with no child dispatched early.
	timeout(Duration::from_secs(8), async {
		loop {
			let checked = agent.requests.load(Ordering::Acquire) - before;
			assert!(checked <= 32);
			if checked == 32 && host.active() == 32 {
				break;
			}
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
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
	assert_eq!(host.active(), 0);
	assert!(!core.stop.is_cancelled());
	core.stop.cancel();
	timeout(Duration::from_secs(3), actor)
		.await
		.unwrap()
		.unwrap()
		.unwrap();
}

struct PostverifyControl {
	host: Arc<Activity>,
	completed: mpsc::Sender<String>,
	release: Arc<Semaphore>,
}

async fn postverify_dispatch(core: Arc<Core>, request: Request, control: Arc<PostverifyControl>) {
	let result = async {
		core.admission_profile(&request).await?;
		let host = Arc::new(control.host.lease()?);
		core.verify_request_profile(request.deadline).await?;
		let args = core.arguments(
			"fixture",
			Mode::Slave,
			&core.root.path.join("phase-effective"),
			true,
		)?;
		// A real pinned, descriptor-owned ssh -G child must be captured and
		// reaped before its lifetime lease ends or any output can be delivered.
		let output = core
			.captured(args, &[], request.deadline, &request.cancel, vec![host])
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
		Ok(Captured { output })
	}
	.await;
	let _ = request.reply.send(result);
}

async fn phased_postverify_fixture(core: &Arc<Core>) {
	let host = Arc::new(Activity::default());
	let release = Arc::new(Semaphore::new(0));
	let (completed_send, mut completed) = mpsc::channel(64);
	let control = Arc::new(PostverifyControl {
		host: host.clone(),
		completed: completed_send,
		release: release.clone(),
	});
	let (sender, receiver) = mpsc::unbounded_channel();
	let actor = tokio::task::spawn_local(
		core.clone()
			.run_with_dispatch(receiver, move |core, request| {
				postverify_dispatch(core, request, control.clone())
			}),
	);
	let mut requests = Vec::new();
	let count = 24;
	for index in 0..count {
		requests.push(enqueue_fair_request(
			&sender,
			"fixture",
			&format!("postverify-{index}"),
			Instant::now() + Duration::from_secs(40),
		));
	}
	let mut finished = std::collections::BTreeSet::new();
	for _ in 0..count {
		finished.insert(phase_notice(&mut completed).await);
	}
	assert_eq!(
		finished,
		(0..count)
			.map(|index| format!("postverify-{index}"))
			.collect()
	);
	// All children are reaped while every response still awaits a fresh
	// authority check. No output becomes visible before that check finishes.
	assert_eq!(host.active(), 0);
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
	assert_eq!(outputs.len(), count);
	assert_eq!(host.active(), 0);
}

async fn validation_early_shutdown_drain_fixture(core: &Arc<Core>, poison_lock: bool) {
	let marker = core.root.path.join("validation-drain-fixture");
	private_write(&marker, b"validation authority remains alive");
	let reads = Arc::new(AtomicUsize::new(0));
	let mut releases = Vec::new();
	// Hold two original validations. Aborting the async callers must leave
	// the blocking closures and their activity leases alive across failed cleanup.
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
	// Existing retained work cannot prevent a separate full validation.
	core.validation
		.run(&core.stop, Instant::now() + Duration::from_secs(2), || {
			Ok(())
		})
		.await
		.unwrap();
	let refused_reads = Arc::new(AtomicUsize::new(0));
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
	// it is pending while either original closure remains active.
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
		"many-hosts",
		"owner-custody-success",
		"owner-custody-failure",
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
		"fair-hot-cold",
		"fair-stopped",
		"fair-cancel-deadline",
		"fair-panic",
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
	} else if kind.starts_with("owner-custody-") {
		owner_custody::run(&path, kind == "owner-custody-failure").await;
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
			"many-hosts" => {
				assert_eq!(core.profile.hosts.len(), 12);
				let cancel = CancellationToken::new();
				for host in core.profile.hosts.keys() {
					core.entry(host, &cancel, Instant::now() + Duration::from_secs(5))
						.await
						.unwrap();
				}
				assert_eq!(core.masters.lock().await.len(), 12);
				for _ in 0..40 {
					let stop = core.stop.clone();
					core.background(async move {
						stop.cancelled().await;
						Ok(())
					})
					.unwrap();
				}
				assert_eq!(core.background.lock().unwrap().len(), 52);
				core.stop.cancel();
			}
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
			"fair-hot-cold" | "fair-stopped" | "fair-cancel-deadline" | "fair-panic" => {
				tokio::task::LocalSet::new()
					.run_until(unbounded_dispatch_fixture(&core, &kind))
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
				};
				let task_core = core.clone();
				let task = tokio::spawn(async move { task_core.execute_inner(&request).await });
				timeout(Duration::from_secs(1), agent_control.entered.notified())
					.await
					.unwrap();
				cancel.cancel();
				assert!(timeout(Duration::from_millis(250), task)
					.await
					.unwrap()
					.unwrap()
					.is_err());
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
				let activity = Arc::new(Activity::default());
				let lease = activity.lease().unwrap();
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
							vec![Arc::new(lease)],
						)
						.await
				});
				timeout(Duration::from_secs(2), waiting)
					.await
					.unwrap()
					.unwrap();
				assert_eq!(activity.active(), 1);
				assert_eq!(core.children.lock().await.len(), 1);
				cancel.cancel();
				assert!(task.await.unwrap().is_err());
				assert!(core.children.lock().await.is_empty());
				assert_eq!(activity.active(), 0);
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
