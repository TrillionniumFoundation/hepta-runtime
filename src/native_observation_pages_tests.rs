// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Terminal paging preserves exact bytes and identities under bounded concurrency.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

use super::{collect, ProcessReadParams, PAGE_BYTES, PAGE_WINDOW};

fn fixture_page(params: &ProcessReadParams, stdout: &[u8], stderr: &[u8]) -> Value {
	let part = |bytes: &[u8], offset: u64| {
		let offset = offset as usize;
		let end = (offset + params.limit.unwrap() as usize).min(bytes.len());
		let hex: String = bytes[offset..end]
			.iter()
			.map(|byte| format!("{byte:02x}"))
			.collect();
		json!({
			"offset": offset,
			"next_offset": end,
			"size": bytes.len(),
			"eof": end == bytes.len(),
			"bytes_hex": hex,
			// Lossy text is deliberately unrelated to the authoritative byte stream.
			"text": "presentation is not the original bytes"
		})
	};
	json!({
		"job_id": params.job_id,
		"stdout": part(stdout, params.stdout_offset.unwrap()),
		"stderr": part(stderr, params.stderr_offset.unwrap()),
	})
}

struct ActiveRead(Arc<AtomicUsize>);

impl Drop for ActiveRead {
	fn drop(&mut self) {
		self.0.fetch_sub(1, Ordering::SeqCst);
	}
}

#[tokio::test]
async fn binary_megabyte_output_is_complete_with_four_read_futures_at_most() {
	let stdout = Arc::new((0..1_179_648).map(|i| (i % 256) as u8).collect::<Vec<_>>());
	let stderr = Arc::new(vec![255; PAGE_BYTES as usize + 19]);
	let active = Arc::new(AtomicUsize::new(0));
	let peak = Arc::new(AtomicUsize::new(0));
	let calls = Arc::new(AtomicUsize::new(0));
	let result = collect(
		"original-host",
		"original-job",
		stdout.len() as u64,
		stderr.len() as u64,
		stdout.len() + stderr.len(),
		|params| {
			let (stdout, stderr, active, peak, calls) = (
				stdout.clone(),
				stderr.clone(),
				active.clone(),
				peak.clone(),
				calls.clone(),
			);
			async move {
				assert_eq!(params.host, "original-host");
				assert_eq!(params.job_id, "original-job");
				assert_eq!(params.limit, Some(PAGE_BYTES));
				let count = active.fetch_add(1, Ordering::SeqCst) + 1;
				peak.fetch_max(count, Ordering::SeqCst);
				calls.fetch_add(1, Ordering::SeqCst);
				let _active = ActiveRead(active);
				tokio::task::yield_now().await;
				Ok(fixture_page(&params, &stdout, &stderr).to_string())
			}
		},
	)
	.await
	.unwrap();
	assert_eq!(result.stdout, *stdout);
	assert_eq!(result.stderr, *stderr);
	assert_eq!(result.page_reads, 72);
	assert_eq!(result.read_windows, 18);
	assert_eq!(calls.load(Ordering::SeqCst), 72);
	assert_eq!(peak.load(Ordering::SeqCst), PAGE_WINDOW);
	assert_eq!(active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn pages_finish_out_of_order_but_preserve_original_stream_order() {
	let stdout = Arc::new(
		(0..PAGE_BYTES * 4)
			.map(|i| (i / PAGE_BYTES) as u8)
			.collect::<Vec<_>>(),
	);
	let finished = Arc::new(Mutex::new(Vec::new()));
	let result = collect(
		"host",
		"job",
		stdout.len() as u64,
		0,
		stdout.len(),
		|params| {
			let stdout = stdout.clone();
			let finished = finished.clone();
			async move {
				let index = params.stdout_offset.unwrap() / PAGE_BYTES;
				for _ in index..4 {
					tokio::task::yield_now().await;
				}
				finished.lock().unwrap().push(index);
				Ok(fixture_page(&params, &stdout, &[]).to_string())
			}
		},
	)
	.await
	.unwrap();
	assert_eq!(result.stdout, *stdout);
	assert_ne!(*finished.lock().unwrap(), vec![0, 1, 2, 3]);
}

#[tokio::test]
async fn oversized_or_overflowed_output_is_refused_before_any_read() {
	let calls = AtomicUsize::new(0);
	for (out, err, budget) in [(2, 3, 4), (u64::MAX, 1, usize::MAX), (0, 0, 0)] {
		let result = collect("host", "job", out, err, budget, |_| {
			calls.fetch_add(1, Ordering::SeqCst);
			async { anyhow::bail!("must not read") }
		})
		.await;
		assert!(result.is_err());
	}
	assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn empty_terminal_streams_still_require_a_bound_empty_page() {
	let result = collect("host", "job", 0, 0, 1, |params| async move {
		Ok(fixture_page(&params, &[], &[]).to_string())
	})
	.await
	.unwrap();
	assert!(result.stdout.is_empty() && result.stderr.is_empty());
	assert_eq!((result.page_reads, result.read_windows), (1, 1));
}

#[tokio::test]
async fn corrupted_identity_length_cursor_and_bytes_are_rejected_without_retry() {
	for corruption in ["job", "size", "cursor", "bytes", "eof", "short"] {
		let calls = AtomicUsize::new(0);
		let result = collect("host", "job", 8, 0, 8, |params| {
			calls.fetch_add(1, Ordering::SeqCst);
			async move {
				let mut page = fixture_page(&params, b"original", &[]);
				match corruption {
					"job" => page["job_id"] = json!("replacement"),
					"size" => page["stdout"]["size"] = json!(9),
					"cursor" => page["stdout"]["offset"] = json!(1),
					"bytes" => page["stdout"]["bytes_hex"] = json!("zz"),
					"eof" => page["stdout"]["eof"] = json!(false),
					"short" => {
						page["stdout"]["bytes_hex"] = json!("6f");
						page["stdout"]["next_offset"] = json!(1);
						page["stdout"]["eof"] = json!(false);
					}
					_ => unreachable!(),
				}
				Ok(page.to_string())
			}
		})
		.await;
		assert!(result.is_err(), "accepted {corruption}");
		assert_eq!(calls.load(Ordering::SeqCst), 1, "retried {corruption}");
	}
}

#[tokio::test]
async fn cancelled_observation_drops_the_entire_window_without_detached_reads() {
	let active = Arc::new(AtomicUsize::new(0));
	let calls = Arc::new(AtomicUsize::new(0));
	let future = collect(
		"host",
		"job",
		PAGE_BYTES * 72,
		0,
		PAGE_BYTES as usize * 72,
		|_| {
			let active = active.clone();
			let calls = calls.clone();
			async move {
				active.fetch_add(1, Ordering::SeqCst);
				calls.fetch_add(1, Ordering::SeqCst);
				let _active = ActiveRead(active);
				std::future::pending::<anyhow::Result<String>>().await
			}
		},
	);
	assert!(tokio::time::timeout(Duration::from_millis(20), future)
		.await
		.is_err());
	assert_eq!(calls.load(Ordering::SeqCst), PAGE_WINDOW);
	assert_eq!(active.load(Ordering::SeqCst), 0);
}
