// Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
use super::*;
use serde_json::json;
use std::future::Future;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;

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

fn private_write(path: &Path, bytes: &[u8]) {
	std::fs::write(path, bytes).unwrap();
	std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

struct AgentControl {
	stall: AtomicBool,
	entered: tokio::sync::Notify,
}

async fn fixture() -> (
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
	let runtime = serde_json::from_value(json!({"state_dir":state,"hosts":{"fixture":{
		"ssh_target":"hepta-observation-fixture","platform":"linux","remote_state_dir":"/private/jobs-fixture",
		"allow_execute":false,"allow_pty":false,"allow_write":false}}})).unwrap();
	crate::mcp::runtime::config::init_runtime(runtime).unwrap();
	let known = root.path().join("known_hosts");
	private_write(&known, b"");
	let config = root.path().join("ssh_config");
	private_write(&config, format!("Host hepta-observation-fixture\n HostName 127.0.0.1\n Port 9\n User nobody\n BatchMode yes\n ForwardAgent no\n StrictHostKeyChecking yes\n UserKnownHostsFile {}\n GlobalKnownHostsFile /dev/null\n", known.display()).as_bytes());
	let agent = root.path().join("agent");
	let listener = tokio::net::UnixListener::bind(&agent).unwrap();
	std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o775)).unwrap();
	// This is an isolated subprocess, never a concurrent mutation of another
	// test's environment, config singleton, credential or runtime store.
	std::env::set_var("SSH_AUTH_SOCK", &agent);
	let control = Arc::new(AgentControl {
		stall: AtomicBool::new(false),
		entered: tokio::sync::Notify::new(),
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
			if server_control.stall.load(Ordering::Acquire) {
				server_control.entered.notify_one();
				std::future::pending::<()>().await;
			}
			let key = b"bounded-public-key-fixture";
			let mut response = vec![12, 0, 0, 0, 1];
			response.extend_from_slice(&(key.len() as u32).to_be_bytes());
			response.extend_from_slice(key);
			response.extend_from_slice(&0u32.to_be_bytes());
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
		root,
		stop: CancellationToken::new(),
		agent: OnceLock::new(),
		children: AsyncMutex::new(BTreeMap::new()),
		masters: AsyncMutex::new(BTreeMap::new()),
		background: Mutex::new(JoinSet::new()),
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
			};
			assert!(request.deadline > old.created + AGE);
			let permits = Arc::new(Semaphore::new(1));
			let permit = permits.clone().acquire_owned().await.unwrap();
			let task_core = core.clone();
			let task = tokio::spawn(async move { task_core.execute_inner(&request, permit).await });
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
	let mut retained = Vec::new();
	for _ in 0..MAX_SESSIONS {
		retained.push(Captured {
			output: Output {
				status: ExitStatus::from_raw(0),
				stdout: b"{}".to_vec(),
				stderr: vec![],
			},
			_budget: Arc::new(permits.clone().acquire_owned().await.unwrap()),
		});
	}
	let (sender, receiver) = mpsc::channel(QUEUE);
	let mut replies = Vec::new();
	let mut cancellations = Vec::new();
	for index in 0..QUEUE {
		let (reply, receive) = oneshot::channel();
		let cancel = CancellationToken::new();
		let request = Request {
			host: "fixture".into(),
			command: "NEVER_DISPATCH".into(),
			input: vec![],
			deadline: if kind == "queue-capacity" && index == 1 {
				Instant::now() - Duration::from_millis(1)
			} else {
				Instant::now() + Duration::from_secs(40)
			},
			cancel: cancel.clone(),
			reply,
		};
		assert!(sender.try_send(request).is_ok());
		replies.push(Some(receive));
		cancellations.push(cancel);
	}
	let mut actor = Box::pin(core.clone().run_with_capacity(receiver, permits.clone()));
	// Poll the real actor while every output permit is retained. There is no
	// sleep-based ordering: its first suspension must leave the queue intact.
	std::future::poll_fn(|cx| {
		assert!(actor.as_mut().poll(cx).is_pending());
		std::task::Poll::Ready(())
	})
	.await;
	assert_eq!(sender.capacity(), 0);
	assert_eq!(permits.available_permits(), 0);
	for reply in &mut replies {
		assert!(matches!(
			reply.as_mut().unwrap().try_recv(),
			Err(oneshot::error::TryRecvError::Empty)
		));
	}
	let (reply, _) = oneshot::channel();
	assert!(matches!(
		sender.try_send(Request {
			host: "fixture".into(),
			command: "NEVER_DISPATCH".into(),
			input: vec![],
			deadline: Instant::now() + Duration::from_secs(40),
			cancel: CancellationToken::new(),
			reply,
		}),
		Err(mpsc::error::TrySendError::Full(_))
	));
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
			if !(kind == "queue-admission" && index == 0)
				&& !(kind == "queue-capacity" && (index == 1 || index == 2))
			{
				cancel.cancel();
			}
		}
		if kind == "queue-capacity" {
			// Independently exercise cancellation, expired deadline and a caller
			// that disappeared while waiting, without creating any SSH task.
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
	assert!(core.masters.lock().await.is_empty());
	assert!(core.children.lock().await.is_empty());
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
		"renew-singleflight",
		"renew-refused",
		"renew-cleanup",
		"renew-deadline",
		"renew-maintain",
		"renew-retirement",
		"queue-capacity",
		"queue-stop",
		"queue-admission",
		"socket-parent-bound",
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
	let (root, path, agent, agent_control) = fixture().await;
	if kind == "external-peer" {
		external_peer_helper(&path).await;
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
		assert!(super::super::start_observation_pool(None)
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
				};
				let permits = Arc::new(Semaphore::new(1));
				let permit = permits.clone().acquire_owned().await.unwrap();
				let task_core = core.clone();
				let task =
					tokio::spawn(async move { task_core.execute_inner(&request, permit).await });
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
