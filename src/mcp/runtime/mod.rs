//! Hepta Runtime: explicit multi-host execution, durable jobs, PTY sessions,
//! policy enforcement, and read-only host inspection.

pub mod config;
pub mod inspect;
pub mod jobs;
mod privileged_ledger;
pub mod pty;
pub mod ssh;

pub use config::{
	init_runtime, runtime_config, HostConfig, Platform, PrivilegedAction, RuntimeConfig,
};
pub use inspect::{hardware_snapshot, network_inspect, privileged_action, service_status};
pub use jobs::{cancel_job, list_jobs, read_job, start_job, status_job, wait_job};
pub use pty::{close_all_ptys, close_pty, list_ptys, read_pty, start_pty, write_pty};

// Digest text is persisted as lowercase, fixed-width hexadecimal identity.
// Encode bytes explicitly: sha2 0.11's output array does not implement LowerHex.
fn sha256_hex(digest: &[u8]) -> String {
	const HEX: &[u8; 16] = b"0123456789abcdef";
	let mut encoded = String::with_capacity(digest.len() * 2);
	for &byte in digest {
		encoded.push(HEX[(byte >> 4) as usize] as char);
		encoded.push(HEX[(byte & 0x0f) as usize] as char);
	}
	encoded
}

#[cfg(test)]
#[test]
fn sha256_hex_preserves_all_nibbles() {
	assert_eq!(sha256_hex(&[0x00, 0x10, 0x2f, 0xa5, 0xff]), "00102fa5ff");
}
