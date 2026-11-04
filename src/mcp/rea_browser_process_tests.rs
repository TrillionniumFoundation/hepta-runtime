// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::*;

fn finite_child(script: &str) -> OwnedChrome {
	let mut command = Command::new("/bin/sh");
	command
		.args(["-c", script])
		.stdin(Stdio::null())
		.stdout(Stdio::null())
		.stderr(Stdio::null());
	// SAFETY: the child performs only the async-signal-safe setsid syscall.
	unsafe {
		command.pre_exec(|| {
			if libc::setsid() < 0 {
				return Err(std::io::Error::last_os_error());
			}
			Ok(())
		});
	}
	let child = command.spawn().unwrap();
	let pid = child.id() as i32;
	OwnedChrome {
		child,
		pid,
		reaped: false,
		lost: false,
	}
}

#[test]
fn exited_leader_retains_custody_until_its_live_descendant_is_cleaned() {
	let mut owner = finite_child("trap '' HUP; sleep 30 & exit 7");
	let deadline = Instant::now() + Duration::from_secs(3);
	loop {
		if let Some(status) = owner.observe_exit().unwrap() {
			assert_eq!(status, 7);
			break;
		}
		assert!(Instant::now() < deadline);
		std::thread::sleep(Duration::from_millis(5));
	}
	assert!(!live_group_members(owner.pid, deadline).unwrap().is_empty());
	assert!(!owner.reaped);
	owner.cleanup().unwrap();
	assert!(owner.reaped);
	assert!(
		live_group_members(owner.pid, Instant::now() + Duration::from_secs(3))
			.unwrap()
			.is_empty()
	);
	owner.cleanup().unwrap();
}

#[test]
fn foreign_reaping_refuses_numeric_process_group_cleanup() {
	let mut owner = finite_child("exit 0");
	assert!(owner.child.wait().unwrap().success());
	assert!(owner.observe_exit().is_err());
	assert!(owner.lost);
	assert!(owner.cleanup().is_err());
}

#[test]
fn descriptor_profile_cleanup_unlinks_symlinks_without_following_them() {
	let temp = tempfile::tempdir().unwrap();
	let parent = Directory::open_absolute(temp.path().to_str().unwrap()).unwrap();
	std::fs::create_dir(temp.path().join("outside")).unwrap();
	std::fs::write(temp.path().join("outside/sentinel"), b"preserve").unwrap();
	let profile = parent.create_child("owned-profile").unwrap();
	let nested = profile.create_child("nested").unwrap();
	nested.publish("data", b"owned", 64).unwrap();
	std::os::unix::fs::symlink(
		temp.path().join("outside"),
		profile.path.join("external-link"),
	)
	.unwrap();
	remove_profile(&parent, &profile).unwrap();
	assert!(!profile.path.exists());
	assert_eq!(
		std::fs::read(temp.path().join("outside/sentinel")).unwrap(),
		b"preserve"
	);
}
