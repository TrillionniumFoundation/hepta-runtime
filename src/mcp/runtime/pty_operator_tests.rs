// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Historical pruning never removes or caps active PTY owners.
use super::*;

#[test]
fn active_sessions_survive_beyond_both_old_thresholds() {
	let mut sessions = HashMap::new();
	for index in 0..512 {
		let id = format!("pty-fixture-{index}");
		sessions.insert(
			id.clone(),
			PtySession {
				stop: CancellationToken::new(),
				id,
				host: "fixture".into(),
				pid: 0,
				created_unix_ms: 0,
				stdin: Arc::new(AsyncMutex::new(None)),
				output: Arc::new(Mutex::new(RingBuffer::new())),
				status: Arc::new(Mutex::new(PtyStatus {
					state: if index == 511 {
						PtyState::Exited
					} else {
						PtyState::Running
					},
					exit_code: None,
					detail: None,
				})),
			},
		);
	}
	prune_closed_sessions(&mut sessions);
	assert_eq!(sessions.len(), 511);
	assert!(!sessions.contains_key("pty-fixture-511"));
	assert!(sessions
		.values()
		.all(|session| matches!(session.status.lock().unwrap().state, PtyState::Running)));
}
