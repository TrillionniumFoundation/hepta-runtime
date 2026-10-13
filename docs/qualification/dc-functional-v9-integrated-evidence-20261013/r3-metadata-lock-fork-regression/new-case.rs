
#[cfg(target_os = "linux")]
#[test]
fn metadata_lock_drop_unlocks_while_a_forked_child_holds_the_descriptor() {
	use std::os::fd::{AsRawFd, FromRawFd};
	let root = private_root();
	let (dir, lease) = locked_store(root.path()).unwrap();
	let mut ready = [0; 2];
	assert_eq!(unsafe { libc::pipe2(ready.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
	let read_end = unsafe { File::from_raw_fd(ready[0]) };
	let write_end = unsafe { File::from_raw_fd(ready[1]) };
	let pid = unsafe { libc::fork() };
	assert!(pid >= 0);
	if pid == 0 {
		// Only async-signal-safe libc calls after fork; no Rust allocation or drops.
		unsafe {
			libc::close(read_end.as_raw_fd());
			let byte = [1u8];
			if libc::write(write_end.as_raw_fd(), byte.as_ptr().cast(), 1) != 1 {
				libc::_exit(2);
			}
			loop {
				libc::pause();
			}
		}
	}
	struct OwnedChild(libc::pid_t);
	impl Drop for OwnedChild {
		fn drop(&mut self) {
			unsafe {
				libc::kill(self.0, libc::SIGKILL);
				while libc::waitpid(self.0, std::ptr::null_mut(), 0) < 0 {
					if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
						break;
					}
				}
			}
		}
	}
	let child = OwnedChild(pid);
	drop(write_end);
	let mut poll = libc::pollfd { fd: read_end.as_raw_fd(), events: libc::POLLIN, revents: 0 };
	assert_eq!(unsafe { libc::poll(&mut poll, 1, 5000) }, 1);
	let mut byte = [0u8];
	assert_eq!(unsafe { libc::read(read_end.as_raw_fd(), byte.as_mut_ptr().cast(), 1) }, 1);
	assert_eq!(byte, [1]);
	assert_eq!(unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) }, 0);
	drop(lease);
	let (same_dir, next_lease) = locked_store(root.path()).unwrap();
	use std::os::unix::fs::MetadataExt;
	assert_eq!(dir.metadata().unwrap().ino(), same_dir.metadata().unwrap().ino());
	// The child has not exec'd or exited, so CLOEXEC alone cannot release this lock.
	assert_eq!(unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) }, 0);
	drop(next_lease);
	drop(child);
}
