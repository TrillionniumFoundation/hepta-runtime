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
//! Original child custody, profile cleanup, and launcher environment confinement.

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

#[test]
fn launcher_environment_writes_and_cleanup_stay_in_the_owned_profile() {
	let temp = tempfile::tempdir().unwrap();
	let parent = Directory::open_absolute(temp.path().to_str().unwrap()).unwrap();
	let outside = parent.create_child("outside").unwrap();
	outside.publish("sentinel", b"preserve", 64).unwrap();
	let profile = parent.create_child("owned-profile").unwrap();
	let variables = ["HOME", "XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"];
	let ambient: Vec<_> = variables.iter().map(std::env::var_os).collect();
	let mut command = Command::new("/bin/sh");
	for variable in variables {
		command.env(variable, &outside.path);
	}
	let environment = private_environment(&mut command, &profile).unwrap();
	// Exercise the vendor launcher's XDG write and all four child destinations
	// with a real finite child, without launching or claiming a Chrome result.
	let status = command
		.args([
			"-ec",
			r#"xdg_app_dir="${XDG_DATA_HOME:-$HOME/.local/share/applications}"
mkdir -p "$xdg_app_dir"
[ -f "$xdg_app_dir/mimeapps.list" ] || touch "$xdg_app_dir/mimeapps.list"
for directory in "$HOME" "$XDG_DATA_HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME"; do
	printf 'owned' > "$directory/child-write"
done"#,
		])
		.status()
		.unwrap();
	assert!(status.success());
	verify_environment(&profile, &environment).unwrap();
	assert_eq!(
		variables.iter().map(std::env::var_os).collect::<Vec<_>>(),
		ambient
	);
	for directory in &environment {
		assert_eq!(directory.file.metadata().unwrap().mode() & 0o777, 0o700);
		assert_eq!(
			std::fs::read(directory.path.join("child-write")).unwrap(),
			b"owned"
		);
	}
	assert!(profile.path.join("xdg-data/mimeapps.list").is_file());
	assert_eq!(std::fs::read_dir(&outside.path).unwrap().count(), 1);
	remove_profile(&parent, &profile).unwrap();
	assert!(!profile.path.exists());
	assert_eq!(
		std::fs::read(outside.path.join("sentinel")).unwrap(),
		b"preserve"
	);
}

#[test]
fn private_environment_refuses_existing_symlink_before_child_launch() {
	let temp = tempfile::tempdir().unwrap();
	let parent = Directory::open_absolute(temp.path().to_str().unwrap()).unwrap();
	let outside = parent.create_child("outside").unwrap();
	outside.publish("sentinel", b"preserve", 64).unwrap();
	let profile = parent.create_child("owned-profile").unwrap();
	std::os::unix::fs::symlink(&outside.path, profile.path.join("xdg-data")).unwrap();
	let mut command = Command::new("/bin/sh");
	assert!(private_environment(&mut command, &profile).is_err());
	remove_profile(&parent, &profile).unwrap();
	assert!(!profile.path.exists());
	assert_eq!(std::fs::read_dir(&outside.path).unwrap().count(), 1);
	assert_eq!(
		std::fs::read(outside.path.join("sentinel")).unwrap(),
		b"preserve"
	);
}

#[test]
fn private_environment_location_check_detects_directory_replacement() {
	let temp = tempfile::tempdir().unwrap();
	let parent = Directory::open_absolute(temp.path().to_str().unwrap()).unwrap();
	let profile = parent.create_child("owned-profile").unwrap();
	let mut command = Command::new("/bin/sh");
	let environment = private_environment(&mut command, &profile).unwrap();
	let moved = temp.path().join("moved-home");
	std::fs::rename(&environment[0].path, &moved).unwrap();
	std::fs::create_dir(&environment[0].path).unwrap();
	assert!(verify_environment(&profile, &environment).is_err());
	assert!(moved.is_dir());
}

#[test]
fn failed_post_spawn_validation_keeps_custody_and_unknown_cleanup_retains_profile() {
	let temp = tempfile::tempdir().unwrap();
	let parent = Directory::open_absolute(temp.path().to_str().unwrap()).unwrap();
	let profile = parent.create_child("owned-profile").unwrap();
	profile.publish("sentinel", b"retain", 64).unwrap();
	let mut command = Command::new("/bin/sh");
	command.args(["-c", "exit 0"]);
	// SAFETY: the child performs only the async-signal-safe setsid syscall.
	unsafe {
		command.pre_exec(|| {
			if libc::setsid() < 0 {
				return Err(std::io::Error::last_os_error());
			}
			Ok(())
		});
	}
	let environment = private_environment(&mut command, &profile).unwrap();
	std::fs::rename(&environment[0].path, temp.path().join("moved-home")).unwrap();
	std::fs::create_dir(&environment[0].path).unwrap();
	let mut custody = None;
	assert!(spawn_in_custody(&mut command, &mut custody, &profile, &environment).is_err());
	// Reap through the child handle to produce the real ECHILD path, rather than
	// synthesizing a cleanup status. The capture cleanup must not remove files.
	assert!(custody.as_mut().unwrap().child.wait().unwrap().success());
	assert!(
		super::super::capture::cleanup_capture(&parent, &profile, &mut custody, &mut None).is_err()
	);
	assert!(custody.as_ref().unwrap().lost);
	profile.verify_location().unwrap();
	assert_eq!(
		std::fs::read(profile.path.join("sentinel")).unwrap(),
		b"retain"
	);
}
