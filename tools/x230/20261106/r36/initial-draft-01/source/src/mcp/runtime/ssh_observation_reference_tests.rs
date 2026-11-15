// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
//! Differential checks for bounded executable references and complete fresh reads.

use super::*;
use std::cell::Cell;
use std::os::unix::fs::{symlink, PermissionsExt};

fn pin_hex(bytes: &[u8]) -> String {
	digest(bytes)
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}

fn pin_pair(bytes: &[u8], maximum: usize) -> (tempfile::TempDir, PinnedFile, PinnedFile) {
	let root = tempfile::tempdir().unwrap();
	let path = root.path().join("reference-pin");
	std::fs::write(&path, bytes).unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	let (mut reference, loaded) =
		PinnedFile::load(&path, Some(&pin_hex(bytes)), maximum, true, false).unwrap();
	assert!(reference.reference.is_none());
	// Production opts in only for fixed public executables. A private test file permits
	// differential mutation tests without touching a system executable.
	let mut reference_budget = MAX_EXECUTABLE_REFERENCE_BYTES;
	reference.reference = bounded_executable_reference(loaded, &mut reference_budget);
	let mut sha = reference.clone();
	sha.reference = None;
	(root, sha, reference)
}

fn rebase_stamp(pin: &mut PinnedFile) {
	// Test-only rebasing isolates byte validation from the independent stamp
	// fence. Production never changes its initial stamp, digest or reference.
	pin.stamp = Stamp::of(&std::fs::metadata(&pin.path).unwrap());
	pin.verify_identity().unwrap();
}

fn observed_verify(
	pin: &PinnedFile,
	check: impl Fn(usize) -> Result<()>,
) -> (std::result::Result<(), String>, usize) {
	let calls = Cell::new(0);
	let result = pin
		.verify_checked(&|| {
			calls.set(calls.get() + 1);
			check(calls.get())
		})
		.map_err(|error| error.to_string());
	(result, calls.get())
}

fn observed_verify_buffer(
	pin: &PinnedFile,
	buffer: &mut [u8; VERIFY_BUFFER_BYTES],
	check: impl Fn(usize) -> Result<()>,
) -> (std::result::Result<(), String>, usize) {
	let calls = Cell::new(0);
	let result = pin
		.verify_checked_with_buffer(
			&|| {
				calls.set(calls.get() + 1);
				check(calls.get())
			},
			buffer,
		)
		.map_err(|error| error.to_string());
	(result, calls.get())
}

#[test]
fn shared_verification_buffer_ignores_stale_tail_across_modes_and_lengths() {
	let fixtures: Vec<_> = [
		vec![37; VERIFY_BUFFER_BYTES * 3 + 7],
		vec![61; 13],
		Vec::new(),
		vec![67; VERIFY_BUFFER_BYTES + 1],
		vec![71; 1],
		Vec::new(),
	]
	.into_iter()
	.map(|bytes| pin_pair(&bytes, bytes.len()))
	.collect();
	for reference_first in [false, true] {
		// Keep the preceding file's tail, including across empty reads.
		let mut buffer = [0xa5; VERIFY_BUFFER_BYTES];
		for (index, (_root, sha, reference)) in fixtures.iter().enumerate() {
			let pin = if (index % 2 == 0) == reference_first {
				reference
			} else {
				sha
			};
			let fresh = observed_verify(pin, |_| Ok(()));
			assert!(fresh.0.is_ok());
			let shared = observed_verify_buffer(pin, &mut buffer, |_| Ok(()));
			assert_eq!(shared, fresh, "file {index}, reference first: {reference_first}");
		}
	}
}

#[test]
fn shared_verification_buffer_keeps_mismatch_cancellation_precedence() {
	let seed = vec![91; VERIFY_BUFFER_BYTES * 2 + 5];
	let (_seed_root, seed_sha, _) = pin_pair(&seed, seed.len());
	let mut buffer = [0xa5; VERIFY_BUFFER_BYTES];
	observed_verify_buffer(&seed_sha, &mut buffer, |_| Ok(())).0.unwrap();

	let mut bytes = vec![43; VERIFY_BUFFER_BYTES + 7];
	let (_root, mut sha, mut reference) = pin_pair(&bytes, bytes.len());
	let (accepted, complete_checks) = observed_verify(&sha, |_| Ok(()));
	accepted.unwrap();
	bytes[0] ^= 1;
	std::fs::write(&sha.path, &bytes).unwrap();
	rebase_stamp(&mut sha);
	rebase_stamp(&mut reference);
	for pin in [&sha, &reference] {
		let fresh = observed_verify(pin, |_| Ok(()));
		let shared = observed_verify_buffer(pin, &mut buffer, |_| Ok(()));
		assert_eq!(shared, fresh);
		assert_eq!(shared.0.unwrap_err(), "observation profile changed");
		assert_eq!(shared.1 + 1, complete_checks);
		for cancel_at in 1..complete_checks {
			let (result, calls) = observed_verify_buffer(pin, &mut buffer, |index| {
				if index == cancel_at {
					bail!("injected validation cancellation");
				}
				Ok(())
			});
			assert_eq!(result.unwrap_err(), "injected validation cancellation");
			assert_eq!(calls, cancel_at);
		}
	}
}

#[test]
fn reference_and_sha_agree_on_first_last_and_multi_chunk_changes() {
	for length in [
		0,
		1,
		VERIFY_BUFFER_BYTES - 1,
		VERIFY_BUFFER_BYTES,
		VERIFY_BUFFER_BYTES + 1,
		VERIFY_BUFFER_BYTES * 3 + 7,
	] {
		let mut bytes: Vec<_> = (0..length).map(|index| (index % 251) as u8).collect();
		let (_root, mut sha, mut reference) = pin_pair(&bytes, length);
		assert_eq!(
			observed_verify(&sha, |_| Ok(())),
			observed_verify(&reference, |_| Ok(()))
		);
		reference.verify().unwrap();
		if length == 0 {
			continue;
		}
		let mut positions = vec![0, length / 2, length - 1];
		positions.sort_unstable();
		positions.dedup();
		for position in positions {
			bytes[position] ^= 1;
			std::fs::write(&sha.path, &bytes).unwrap();
			rebase_stamp(&mut sha);
			rebase_stamp(&mut reference);
			let hashed = observed_verify(&sha, |_| Ok(()));
			let compared = observed_verify(&reference, |_| Ok(()));
			assert_eq!(hashed, compared, "length {length}, byte {position}");
			assert_eq!(compared.0.unwrap_err(), "observation profile changed");
			bytes[position] ^= 1;
			std::fs::write(&sha.path, &bytes).unwrap();
			rebase_stamp(&mut sha);
			rebase_stamp(&mut reference);
			sha.verify().unwrap();
			reference.verify().unwrap();
		}
	}
}

#[test]
fn reference_budget_preserves_initial_pins_and_sha_fallback() {
	for length in [
		MAX_EXECUTABLE_REFERENCE_BYTES - 1,
		MAX_EXECUTABLE_REFERENCE_BYTES,
		MAX_EXECUTABLE_REFERENCE_BYTES + 1,
	] {
		let mut bytes = vec![37; length];
		let (_root, mut sha, mut reference) = pin_pair(&bytes, length);
		assert_eq!(
			reference.reference.is_some(),
			length <= MAX_EXECUTABLE_REFERENCE_BYTES
		);
		assert_eq!(sha.digest, reference.digest);
		sha.verify().unwrap();
		reference.verify().unwrap();
		let error = PinnedFile::load(&sha.path, Some(&"0".repeat(64)), length, true, false)
			.err()
			.unwrap();
		assert_eq!(error.to_string(), "observation profile byte pin mismatch");
		bytes[length - 1] ^= 1;
		std::fs::write(&sha.path, &bytes).unwrap();
		rebase_stamp(&mut sha);
		rebase_stamp(&mut reference);
		assert_eq!(
			observed_verify(&sha, |_| Ok(())),
			observed_verify(&reference, |_| Ok(()))
		);
		assert!(reference.verify().is_err());
	}
}

#[test]
fn executable_references_share_one_budget_without_spending_on_rejected_files() {
	let mut remaining = MAX_EXECUTABLE_REFERENCE_BYTES;
	let first =
		bounded_executable_reference(vec![59; MAX_EXECUTABLE_REFERENCE_BYTES - 8], &mut remaining)
			.unwrap();
	assert_eq!(remaining, 8);
	assert!(bounded_executable_reference(vec![61; 9], &mut remaining).is_none());
	assert_eq!(remaining, 8);
	let second = bounded_executable_reference(vec![67; 7], &mut remaining).unwrap();
	assert_eq!(remaining, 1);
	let third = bounded_executable_reference(vec![71; 1], &mut remaining).unwrap();
	assert_eq!(remaining, 0);
	assert_eq!(
		first.len() + second.len() + third.len(),
		MAX_EXECUTABLE_REFERENCE_BYTES
	);
	assert!(bounded_executable_reference(vec![73; 1], &mut remaining).is_none());
	assert_eq!(remaining, 0);
}

#[test]
fn references_share_owned_bytes_without_following_later_file_writes() {
	let bytes = vec![19; VERIFY_BUFFER_BYTES + 7];
	let (_root, sha, reference) = pin_pair(&bytes, bytes.len());
	let mut clone = reference.clone();
	assert!(sha.reference.is_none());
	assert!(Arc::ptr_eq(
		reference.reference.as_ref().unwrap(),
		clone.reference.as_ref().unwrap()
	));
	std::fs::write(&clone.path, vec![20; bytes.len()]).unwrap();
	rebase_stamp(&mut clone);
	assert_eq!(reference.reference.as_deref().unwrap(), bytes.as_slice());
	assert_eq!(
		clone.verify().unwrap_err().to_string(),
		"observation profile changed"
	);
}

#[test]
fn reference_length_must_match_the_complete_stream() {
	for length in [0, VERIFY_BUFFER_BYTES + 7] {
		let bytes = vec![41; length];
		let (_root, sha, mut reference) = pin_pair(&bytes, length);
		sha.verify().unwrap();
		let mut wrong = [bytes.clone(), bytes.clone()];
		let _ = wrong[0].pop();
		wrong[1].push(41);
		for expected in wrong {
			if expected.len() == length {
				continue;
			}
			let mut reference_budget = MAX_EXECUTABLE_REFERENCE_BYTES;
			reference.reference = bounded_executable_reference(expected, &mut reference_budget);
			assert_eq!(
				reference.verify().unwrap_err().to_string(),
				"observation profile changed"
			);
		}
	}
}

#[test]
fn first_chunk_mismatch_keeps_later_checks_and_cancellation_precedence() {
	let mut bytes = vec![43; VERIFY_BUFFER_BYTES * 3 + 7];
	let (_root, mut sha, mut reference) = pin_pair(&bytes, bytes.len());
	let (accepted, complete_checks) = observed_verify(&sha, |_| Ok(()));
	accepted.unwrap();
	bytes[0] ^= 1;
	std::fs::write(&sha.path, &bytes).unwrap();
	rebase_stamp(&mut sha);
	rebase_stamp(&mut reference);
	let hashed = observed_verify(&sha, |_| Ok(()));
	let compared = observed_verify(&reference, |_| Ok(()));
	assert_eq!(hashed, compared);
	assert_eq!(compared.0.unwrap_err(), "observation profile changed");
	// Only the successful final check is absent. A first-chunk difference must
	// not skip any later read boundary or the checks around verify_read.
	assert_eq!(compared.1 + 1, complete_checks);
	for cancel_at in 1..complete_checks {
		for pin in [&sha, &reference] {
			let stop = tokio_util::sync::CancellationToken::new();
			let (result, calls) = observed_verify(pin, |index| {
				if index == cancel_at {
					stop.cancel();
				}
				if stop.is_cancelled() {
					bail!("injected validation cancellation");
				}
				Ok(())
			});
			assert_eq!(result.unwrap_err(), "injected validation cancellation");
			assert_eq!(calls, cancel_at);
		}
	}
}

fn mutate_boundary(root: &Path, path: &Path, bytes: &[u8], mutation: &str) {
	match mutation {
		"shorter" | "longer" => {
			let length = if mutation == "shorter" {
				bytes.len() - 1
			} else {
				bytes.len() + 1
			};
			std::fs::OpenOptions::new()
				.write(true)
				.open(path)
				.unwrap()
				.set_len(length as u64)
				.unwrap();
		}
		"replacement" | "symlink" => {
			let original = root.join("original");
			std::fs::rename(path, &original).unwrap();
			if mutation == "replacement" {
				std::fs::write(path, bytes).unwrap();
				std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
			} else {
				symlink(original, path).unwrap();
			}
		}
		"permissions" => {
			std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
		}
		"hardlink" => std::fs::hard_link(path, root.join("alias")).unwrap(),
		_ => unreachable!(),
	}
}

#[test]
fn reference_and_sha_keep_length_path_and_metadata_error_precedence() {
	for mutation in [
		"shorter",
		"longer",
		"replacement",
		"symlink",
		"permissions",
		"hardlink",
	] {
		for before_open in [true, false] {
			let mut results = Vec::new();
			for use_reference in [false, true] {
				let mut bytes = vec![47; VERIFY_BUFFER_BYTES * 3 + 7];
				let (root, sha, reference) = pin_pair(&bytes, bytes.len() + 1);
				let mut pin = if use_reference { reference } else { sha };
				let (accepted, complete_checks) = observed_verify(&pin, |_| Ok(()));
				accepted.unwrap();
				bytes[0] ^= 1;
				std::fs::write(&pin.path, &bytes).unwrap();
				rebase_stamp(&mut pin);
				if before_open {
					mutate_boundary(root.path(), &pin.path, &bytes, mutation);
				}
				let result = observed_verify(&pin, |index| {
					// This is after the complete read and before verify_read;
					// the earlier content difference must not hide this change.
					if !before_open && index == complete_checks - 2 {
						mutate_boundary(root.path(), &pin.path, &bytes, mutation);
					}
					Ok(())
				});
				assert!(result.0.is_err());
				if !before_open {
					assert_ne!(
						result.0.as_ref().unwrap_err(),
						"observation profile changed"
					);
					assert_eq!(result.1, complete_checks - 2);
				}
				results.push(result);
			}
			if mutation == "symlink" && !before_open {
				// Independent fixtures can cross different ctime ticks: the
				// descriptor stamp may reject first, or the fresh no-follow open
				// may return ELOOP. Both occur at the original verify_read fence.
				let no_follow = std::io::Error::from_raw_os_error(libc::ELOOP).to_string();
				for (result, _) in &results {
					let error = result.as_ref().unwrap_err();
					assert!(error == "observation profile input changed" || error == &no_follow);
				}
				assert_eq!(results[0].1, results[1].1);
			} else {
				assert_eq!(
					results[0], results[1],
					"{mutation}, before open: {before_open}"
				);
			}
		}
	}
}

#[tokio::test(flavor = "current_thread")]
async fn reference_owner_still_freezes_on_content_change_after_worker_acceptance() {
	use super::super::validation::Workers;
	use std::time::Duration;

	let mut bytes = vec![53; VERIFY_BUFFER_BYTES * 3 + 7];
	let (_root, _sha, mut reference) = pin_pair(&bytes, bytes.len());
	let checked = reference.clone();
	let stop = tokio_util::sync::CancellationToken::new();
	let workers = Workers::new();
	let ticket = workers
		.run_retained(
			&stop,
			Instant::now() + Duration::from_secs(8),
			move |ticket| checked.verify_checked(&|| ticket.check_current()),
		)
		.await
		.unwrap();
	*bytes.last_mut().unwrap() ^= 1;
	std::fs::write(&reference.path, &bytes).unwrap();
	rebase_stamp(&mut reference);
	let error = ticket
		.finish(|ticket| reference.verify_checked(&|| ticket.check_current()))
		.unwrap_err();
	assert_eq!(error.to_string(), "observation profile changed");
	assert!(stop.is_cancelled());
	workers.drain().await.unwrap();
}

fn clock_ns(clock: libc::clockid_t) -> u64 {
	let mut value = libc::timespec {
		tv_sec: 0,
		tv_nsec: 0,
	};
	assert_eq!(unsafe { libc::clock_gettime(clock, &mut value) }, 0);
	value.tv_sec as u64 * 1_000_000_000 + value.tv_nsec as u64
}

#[test]
#[ignore = "isolated real SSH complete-read ABBA microbenchmark; not end-to-end RPC throughput"]
fn ssh_reference_complete_read_abba_microbenchmark() {
	use std::time::Duration;

	const ITERATIONS: usize = 128;
	const BLOCKS: usize = 3;
	let path = Path::new("/usr/bin/ssh");
	let maximum = 16 * 1024 * 1024;
	let expected = pin_hex(&read_file(path, maximum, false, true).unwrap().1);
	let (mut reference, bytes) =
		PinnedFile::load(path, Some(&expected), maximum, false, true).unwrap();
	let length = bytes.len();
	let mut reference_budget = MAX_EXECUTABLE_REFERENCE_BYTES;
	reference.reference = bounded_executable_reference(bytes, &mut reference_budget);
	assert!(
		reference.reference.is_some(),
		"SSH executable exceeds the reference budget"
	);
	let mut sha = reference.clone();
	sha.reference = None;
	let stop = tokio_util::sync::CancellationToken::new();
	let deadline = Instant::now() + Duration::from_secs(120);
	let check_current = || {
		if stop.is_cancelled() || Instant::now() >= deadline {
			bail!("observation validation cancelled or expired before authority acceptance");
		}
		Ok(())
	};
	for _ in 0..8 {
		sha.verify_checked(&check_current).unwrap();
		reference.verify_checked(&check_current).unwrap();
	}
	println!(
		"SSH_REFERENCE_ABBA {}",
		serde_json::json!({
			"kind": "setup",
			"path": path,
			"sha256": expected,
			"bytes": length,
			"reference_limit_bytes": MAX_EXECUTABLE_REFERENCE_BYTES,
			"read_buffer_bytes": VERIFY_BUFFER_BYTES,
			"iterations_per_arm": ITERATIONS,
			"blocks": BLOCKS,
			"warmup_per_arm": 8,
			"order": ["sha", "reference", "reference", "sha"],
			"scope": "same pinned file; complete fresh verify_checked; mechanism CPU/wall only",
			"rss_comparable": false,
			"rss_note": "both pins coexist in one process; reference bytes remain resident in both arms",
		})
	);
	for block in 0..BLOCKS {
		for (position, (arm, pin)) in [
			("sha", &sha),
			("reference", &reference),
			("reference", &reference),
			("sha", &sha),
		]
		.into_iter()
		.enumerate()
		{
			let wall_start = clock_ns(libc::CLOCK_MONOTONIC);
			let process_start = clock_ns(libc::CLOCK_PROCESS_CPUTIME_ID);
			let thread_start = clock_ns(libc::CLOCK_THREAD_CPUTIME_ID);
			for _ in 0..ITERATIONS {
				pin.verify_checked(&check_current).unwrap();
			}
			let thread_end = clock_ns(libc::CLOCK_THREAD_CPUTIME_ID);
			let process_end = clock_ns(libc::CLOCK_PROCESS_CPUTIME_ID);
			let wall_end = clock_ns(libc::CLOCK_MONOTONIC);
			println!(
				"SSH_REFERENCE_ABBA {}",
				serde_json::json!({
					"kind": "sample",
					"block": block,
					"position": position,
					"arm": arm,
					"iterations": ITERATIONS,
					"wall_start_ns": wall_start,
					"wall_end_ns": wall_end,
					"wall_ns": wall_end - wall_start,
					"thread_cpu_start_ns": thread_start,
					"thread_cpu_end_ns": thread_end,
					"thread_cpu_ns": thread_end - thread_start,
					"process_cpu_start_ns": process_start,
					"process_cpu_end_ns": process_end,
					"process_cpu_ns": process_end - process_start,
				})
			);
		}
	}
	sha.verify_checked(&check_current).unwrap();
	reference.verify_checked(&check_current).unwrap();
}
