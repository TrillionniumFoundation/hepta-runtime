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

//! Post-read, thread-synchronized Linux seccomp denylist for the Rust parser.
//! This is defense in depth, NOT a complete OS/user/network namespace sandbox.

use anyhow::Result;

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn tighten_after_read() -> Result<()> {
	use anyhow::{bail, Context};
	const LOAD_W_ABS: u16 = 0x20;
	const JEQ_K: u16 = 0x15;
	const JSET_K: u16 = 0x45;
	const RET_K: u16 = 0x06;
	const ALLOW: u32 = 0x7fff_0000;
	const KILL: u32 = 0x8000_0000;
	const REFUSE: u32 = 0x0005_0000 | libc::EPERM as u32;
	#[cfg(target_arch = "x86_64")]
	const ARCH: u32 = 0xc000_003e;
	#[cfg(target_arch = "aarch64")]
	const ARCH: u32 = 0xc000_00b7;

	fn stmt(code: u16, k: u32) -> libc::sock_filter {
		libc::sock_filter { code, jt: 0, jf: 0, k }
	}
	fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
		libc::sock_filter { code, jt, jf, k }
	}
	let mut refused: Vec<libc::c_long> = vec![
		libc::SYS_openat, libc::SYS_openat2,
		libc::SYS_socket, libc::SYS_socketpair, libc::SYS_connect, libc::SYS_bind,
		libc::SYS_listen, libc::SYS_accept, libc::SYS_accept4,
		libc::SYS_sendto, libc::SYS_recvfrom, libc::SYS_sendmsg, libc::SYS_recvmsg,
		libc::SYS_execve, libc::SYS_execveat, libc::SYS_clone, libc::SYS_clone3,
		libc::SYS_ptrace, libc::SYS_io_uring_setup, libc::SYS_io_uring_enter,
		libc::SYS_io_uring_register, libc::SYS_pidfd_getfd,
		libc::SYS_process_vm_readv, libc::SYS_process_vm_writev,
	];
	#[cfg(target_arch = "x86_64")]
	refused.extend([libc::SYS_open, libc::SYS_creat, libc::SYS_fork, libc::SYS_vfork]);
	refused.sort_unstable();
	refused.dedup();

	let mut filter = vec![
		stmt(LOAD_W_ABS, 4), // seccomp_data.arch
		jump(JEQ_K, ARCH, 1, 0),
		stmt(RET_K, KILL),
		stmt(LOAD_W_ABS, 0), // seccomp_data.nr
	];
	#[cfg(target_arch = "x86_64")]
	{
		// x32 shares the x86-64 audit architecture; reject its ABI bit.
		filter.push(jump(JSET_K, 0x4000_0000, 0, 1));
		filter.push(stmt(RET_K, KILL));
	}
	for number in refused {
		filter.push(jump(JEQ_K, number as u32, 0, 1));
		filter.push(stmt(RET_K, REFUSE));
	}
	filter.push(stmt(RET_K, ALLOW));
	let mut rule = libc::sock_fprog {
		len: u16::try_from(filter.len()).context("REA seccomp program exceeds limit")?,
		filter: filter.as_mut_ptr(),
	};
	if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
		return Err(std::io::Error::last_os_error())
			.context("cannot set no_new_privs for REA worker");
	}
	// Flag 1 = SECCOMP_FILTER_FLAG_TSYNC; synchronize every runtime thread.
	// Operation 1 = SECCOMP_SET_MODE_FILTER, from linux/seccomp.h.
	let rc = unsafe { libc::syscall(libc::SYS_seccomp, 1, 1, &raw mut rule) };
	if rc > 0 {
		bail!("REA seccomp filter synchronization failed for thread {rc}");
	}
	if rc < 0 {
		return Err(std::io::Error::last_os_error())
			.context("cannot install process-wide REA worker seccomp filter");
	}
	Ok(())
}

#[cfg(all(target_os = "linux", not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
pub fn tighten_after_read() -> Result<()> {
	anyhow::bail!("Linux REA worker architecture has no qualified seccomp filter");
}

#[cfg(not(target_os = "linux"))]
pub fn tighten_after_read() -> Result<()> {
	// macOS is resource-limited only; production sandbox qualification open.
	Ok(())
}

#[cfg(target_os = "linux")]
pub fn verify_file_network_denial() -> Result<()> {
	let file = std::fs::File::open("/etc/passwd")
		.expect_err("REA seccomp must refuse file opens");
	if file.raw_os_error() != Some(libc::EPERM) {
		anyhow::bail!("REA file probe did not receive EPERM");
	}
	let net = std::net::TcpStream::connect("127.0.0.1:9")
		.expect_err("REA seccomp must refuse network sockets");
	if net.raw_os_error() != Some(libc::EPERM) {
		anyhow::bail!("REA network probe did not receive EPERM");
	}
	Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn verify_file_network_denial() -> Result<()> {
	anyhow::bail!("REA worker security probe requires Linux seccomp");
}
