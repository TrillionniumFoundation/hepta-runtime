// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bounded concurrent reads of an already terminal job's immutable log pages.

use std::future::Future;
use std::time::Instant;

use anyhow::{anyhow, Result};
use serde_json::Value;

use super::diagnostic::{Cause, Failure, PageFailure, Stage};
use super::wire::{decode_page, require_job_id};
use super::ProcessReadParams;

const PAGE_BYTES: u64 = 16 * 1024;
const PAGE_WINDOW: usize = 4;

pub(super) struct TerminalStreams {
	pub stdout: Vec<u8>,
	pub stderr: Vec<u8>,
	pub page_reads: usize,
	pub read_windows: usize,
}

struct PageRequest {
	params: ProcessReadParams,
	stdout_size: u64,
	stderr_size: u64,
	window: usize,
	index: usize,
}

struct TerminalPage {
	stdout_offset: u64,
	stderr_offset: u64,
	stdout: Vec<u8>,
	stderr: Vec<u8>,
}

async fn read_page<R, F>(request: Option<PageRequest>, read: &R) -> Result<Option<TerminalPage>>
where
	R: Fn(ProcessReadParams) -> F + Sync,
	F: Future<Output = Result<String>> + Send,
{
	let Some(request) = request else {
		return Ok(None);
	};
	let stdout_offset = request.params.stdout_offset.unwrap_or(0);
	let stderr_offset = request.params.stderr_offset.unwrap_or(0);
	let limit = request.params.limit.unwrap_or(PAGE_BYTES);
	let job_id = request.params.job_id.clone();
	let started = Instant::now();
	let fault = |stage, cause, source| {
		let mut failure = Failure::new(stage, cause, source);
		failure.pages.push(PageFailure {
			stage,
			cause,
			window: request.window,
			index: request.index,
			stdout_offset,
			stderr_offset,
			limit,
			elapsed: started.elapsed(),
		});
		anyhow::Error::new(failure)
	};
	let raw = read(request.params)
		.await
		.map_err(|error| fault(Stage::PageTransport, Cause::transport(&error), error))?;
	let page: Value = serde_json::from_str(&raw)
		.map_err(|error| fault(Stage::PageDecode, Cause::InvalidJson, error.into()))?;
	require_job_id(&page, &job_id)
		.map_err(|error| fault(Stage::PageBinding, Cause::BindingMismatch, error))?;
	let stdout = decode_page(&page["stdout"], stdout_offset, request.stdout_size, limit)
		.map_err(|error| fault(Stage::PageIntegrity, Cause::InvalidPage, error))?;
	let stderr = decode_page(&page["stderr"], stderr_offset, request.stderr_size, limit)
		.map_err(|error| fault(Stage::PageIntegrity, Cause::InvalidPage, error))?;
	// Terminal sizes are frozen by the caller's original publication witness.
	// Reject a short page instead of skipping bytes at the next fixed offset.
	let stdout_end = stdout_offset + limit.min(request.stdout_size - stdout_offset);
	let stderr_end = stderr_offset + limit.min(request.stderr_size - stderr_offset);
	if stdout.next_offset != stdout_end
		|| stderr.next_offset != stderr_end
		|| stdout.eof != (stdout_end == request.stdout_size)
		|| stderr.eof != (stderr_end == request.stderr_size)
	{
		return Err(fault(
			Stage::PageIntegrity,
			Cause::InvalidPage,
			anyhow!("terminal runtime page did not contain its complete bounded range"),
		));
	}
	Ok(Some(TerminalPage {
		stdout_offset,
		stderr_offset,
		stdout: stdout.bytes,
		stderr: stderr.bytes,
	}))
}

/// Read-only futures are polled together and retained by this caller. Dropping
/// this future drops the whole window; no detached tasks or new jobs are created.
pub(super) async fn collect<R, F>(
	host: &str,
	job_id: &str,
	stdout_size: u64,
	stderr_size: u64,
	max_output_bytes: usize,
	read: R,
) -> Result<TerminalStreams>
where
	R: Fn(ProcessReadParams) -> F + Sync,
	F: Future<Output = Result<String>> + Send,
{
	let started = Instant::now();
	let fault = |cause, source| {
		let mut failure = Failure::new(Stage::OutputBudget, cause, source);
		failure.elapsed = started.elapsed();
		failure.output_read = failure.elapsed;
		anyhow::Error::new(failure)
	};
	let total = stdout_size.checked_add(stderr_size).ok_or_else(|| {
		fault(
			Cause::RetentionBudget,
			anyhow!("runtime output length overflow"),
		)
	})?;
	if max_output_bytes == 0 || u128::from(total) > max_output_bytes as u128 {
		return Err(fault(
			Cause::RetentionBudget,
			anyhow!("original runtime output exceeds the admitted retention budget"),
		));
	}
	let stdout_len = usize::try_from(stdout_size)
		.map_err(|error| fault(Cause::RetentionBudget, error.into()))?;
	let stderr_len = usize::try_from(stderr_size)
		.map_err(|error| fault(Cause::RetentionBudget, error.into()))?;
	let mut result = TerminalStreams {
		stdout: Vec::new(),
		stderr: Vec::new(),
		page_reads: 0,
		read_windows: 0,
	};
	result
		.stdout
		.try_reserve_exact(stdout_len)
		.map_err(|error| fault(Cause::Allocation, error.into()))?;
	result
		.stderr
		.try_reserve_exact(stderr_len)
		.map_err(|error| fault(Cause::Allocation, error.into()))?;
	let page_limit = PAGE_BYTES.min(
		u64::try_from(max_output_bytes)
			.map_err(|error| fault(Cause::RetentionBudget, error.into()))?,
	);
	let page_count = usize::try_from(stdout_size.max(stderr_size).div_ceil(page_limit).max(1))
		.map_err(|error| fault(Cause::RetentionBudget, error.into()))?;
	for first in (0..page_count).step_by(PAGE_WINDOW) {
		let requests: [Option<PageRequest>; PAGE_WINDOW] = std::array::from_fn(|slot| {
			let index = first.checked_add(slot)?;
			if index >= page_count {
				return None;
			}
			// index is below ceil(maximum stream size / page_limit), so this
			// offset cannot exceed the original bounded stream length.
			let offset = index as u64 * page_limit;
			Some(PageRequest {
				params: ProcessReadParams {
					host: host.to_owned(),
					job_id: job_id.to_owned(),
					stdout_offset: Some(offset.min(stdout_size)),
					stderr_offset: Some(offset.min(stderr_size)),
					limit: Some(page_limit),
				},
				stdout_size,
				stderr_size,
				window: result.read_windows + 1,
				index,
			})
		});
		let [a, b, c, d] = requests;
		let pages = tokio::join!(
			read_page(a, &read),
			read_page(b, &read),
			read_page(c, &read),
			read_page(d, &read),
		);
		result.read_windows += 1;
		let pages = [pages.0, pages.1, pages.2, pages.3];
		let validated = result.page_reads
			+ pages
				.iter()
				.filter(|page| matches!(page, Ok(Some(_))))
				.count();
		// join! already waited for every original read. Preserve each failed
		// page's static diagnosis and all attempted costs, including later slots.
		let failures: Vec<PageFailure> = pages
			.iter()
			.filter_map(|page| page.as_ref().err())
			.filter_map(|error| error.downcast_ref::<Failure>())
			.flat_map(|failure| failure.pages.iter().cloned())
			.collect();
		for page in pages {
			let page = page.map_err(|mut error| {
				if let Some(failure) = error.downcast_mut::<Failure>() {
					failure.elapsed = started.elapsed();
					failure.output_read = failure.elapsed;
					failure.page_reads_attempted = (first + PAGE_WINDOW).min(page_count);
					failure.validated_page_reads = validated;
					failure.read_windows = result.read_windows;
					failure.retained_stdout_bytes = result.stdout.len();
					failure.retained_stderr_bytes = result.stderr.len();
					failure.pages = failures.clone();
				}
				error
			})?;
			let Some(page) = page else {
				continue;
			};
			if page.stdout_offset != result.stdout.len() as u64
				|| page.stderr_offset != result.stderr.len() as u64
			{
				let mut failure = Failure::new(
					Stage::PageIntegrity,
					Cause::InvalidPage,
					anyhow!("runtime output window is not contiguous with the original streams"),
				);
				failure.elapsed = started.elapsed();
				failure.output_read = failure.elapsed;
				failure.page_reads_attempted = (first + PAGE_WINDOW).min(page_count);
				failure.validated_page_reads = validated;
				failure.read_windows = result.read_windows;
				failure.retained_stdout_bytes = result.stdout.len();
				failure.retained_stderr_bytes = result.stderr.len();
				return Err(failure.into());
			}
			result.stdout.extend_from_slice(&page.stdout);
			result.stderr.extend_from_slice(&page.stderr);
			result.page_reads += 1;
		}
	}
	if result.stdout.len() != stdout_len || result.stderr.len() != stderr_len {
		let mut failure = Failure::new(
			Stage::PageIntegrity,
			Cause::InvalidPage,
			anyhow!("runtime output does not match the original terminal lengths"),
		);
		failure.elapsed = started.elapsed();
		failure.output_read = failure.elapsed;
		failure.page_reads_attempted = result.page_reads;
		failure.validated_page_reads = result.page_reads;
		failure.read_windows = result.read_windows;
		failure.retained_stdout_bytes = result.stdout.len();
		failure.retained_stderr_bytes = result.stderr.len();
		return Err(failure.into());
	}
	Ok(result)
}

#[cfg(test)]
#[path = "native_observation_pages_tests.rs"]
mod tests;
