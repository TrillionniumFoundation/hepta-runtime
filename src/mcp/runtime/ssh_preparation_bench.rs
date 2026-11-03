// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Opt-in component measurement; excludes SSH and end-to-end RPC throughput.
use super::*;
use std::hint::black_box;
use std::sync::{Arc, Barrier};
use std::time::Instant;

fn prepare(cached: bool, kind: u8) -> String {
	if cached {
		match kind {
			0 => file_observation_command().unwrap().to_owned(),
			1 => job_observation_command(ObservationScript::Status)
				.unwrap()
				.to_owned(),
			_ => job_observation_command(ObservationScript::Read)
				.unwrap()
				.to_owned(),
		}
	} else {
		match kind {
			0 => {
				python_json_command("python3", super::super::binary::observation_source()).unwrap()
			}
			1 => python_json_command(
				"python3",
				&super::super::jobs::observation_script(ObservationScript::Status).unwrap(),
			)
			.unwrap(),
			_ => python_json_command(
				"python3",
				&super::super::jobs::observation_script(ObservationScript::Read).unwrap(),
			)
			.unwrap(),
		}
	}
}

#[test]
#[ignore = "explicit component ABBA measurement, not a timing assertion"]
fn fixed_observation_preparation_abba() {
	const ITERATIONS: usize = 2000;
	for (kind, label) in [(0, "file"), (1, "status"), (2, "read")] {
		let reference = prepare(false, kind);
		assert_eq!(reference, prepare(true, kind));
		for workers in [1usize, 4, 8] {
			for (round, cached) in [false, true, true, false].into_iter().enumerate() {
				let barrier = Arc::new(Barrier::new(workers + 1));
				let threads: Vec<_> = (0..workers)
					.map(|_| {
						let barrier = barrier.clone();
						std::thread::spawn(move || {
							barrier.wait();
							let mut bytes = 0usize;
							for _ in 0..ITERATIONS {
								bytes +=
									black_box(prepare(black_box(cached), black_box(kind))).len();
							}
							bytes
						})
					})
					.collect();
				let started = Instant::now();
				barrier.wait();
				let bytes: usize = threads
					.into_iter()
					.map(|thread| thread.join().unwrap())
					.sum();
				let nanos = started.elapsed().as_nanos();
				assert_eq!(bytes, reference.len() * workers * ITERATIONS);
				println!(
					"{}",
					serde_json::json!({
						"schema": "hepta-ssh-preparation-component/v1",
						"component": label,
						"workers": workers,
						"round": round,
						"arm": if cached { "cached" } else { "uncached" },
						"operations": workers * ITERATIONS,
						"wall_ns": nanos,
						"command_bytes": reference.len(),
						"scope": "fixed command construction including owned copy; excludes transport"
					})
				);
			}
		}
	}
}
