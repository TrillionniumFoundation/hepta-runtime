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
//! Actual target plan futures, blocking pool ownership and exact Duration conversion.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
include!(concat!(env!("OUT_DIR"), "/module.rs"));

fn clock_ns() -> Result<u64> {
	let mut value = libc::timespec { tv_sec: 0, tv_nsec: 0 };
	let code = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) };
	if code != 0 || value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
		bail!("invalid actual monotonic clock");
	}
	u64::try_from(value.tv_sec)?
		.checked_mul(1_000_000_000)
		.and_then(|v| v.checked_add(value.tv_nsec as u64))
		.ok_or_else(|| anyhow!("monotonic clock overflow"))
}

fn word(value: &Value, key: &str) -> Result<u64> {
	value.get(key).and_then(Value::as_u64).ok_or_else(|| anyhow!("missing u64 {key}"))
}

fn parameters(value: &Value) -> Result<original::BellmanPlanParams> {
	let rows = value.get("states").and_then(Value::as_array).ok_or_else(|| anyhow!("missing states"))?;
	let mut states = Vec::with_capacity(rows.len());
	for row in rows {
		let raw = row.as_array().ok_or_else(|| anyhow!("state is not an array"))?;
		if raw.len() != 6 { bail!("wrong action count in owned fixture"); }
		let mut actions = Vec::with_capacity(6);
		for action in raw {
			let parsed = if action.is_null() {
				None
			} else {
				match action.get("kind").and_then(Value::as_str) {
					Some("terminal") => Some(original::BellmanAction::Terminal {
						value: f64::from_bits(word(action, "value_bits")?),
					}),
					Some("continue") => {
						let raw_branches = action.get("branches").and_then(Value::as_array)
							.ok_or_else(|| anyhow!("missing branches"))?;
						let mut branches = Vec::with_capacity(raw_branches.len());
						for branch in raw_branches {
							branches.push(original::BellmanBranch {
								probability: f64::from_bits(word(branch, "probability_bits")?),
								successor: u32::try_from(word(branch, "successor")?)?,
								reward: f64::from_bits(word(branch, "reward_bits")?),
								fee: f64::from_bits(word(branch, "fee_bits")?),
							});
						}
						Some(original::BellmanAction::Continue { branches })
					}
					_ => bail!("unknown owned fixture action"),
				}
			};
			actions.push(parsed);
		}
		states.push(original::BellmanState {
			actions: actions.try_into().map_err(|_| anyhow!("owned action conversion"))?,
		});
	}
	Ok(original::BellmanPlanParams { states })
}

fn simple(value: f64) -> original::BellmanPlanParams {
	original::BellmanPlanParams { states: vec![original::BellmanState {
		actions: [Some(original::BellmanAction::Terminal { value }), None, None, None, None, None],
	}] }
}

fn output(value: &Value) -> Result<()> {
	let mut stdout = std::io::stdout().lock();
	serde_json::to_writer(&mut stdout, value)?;
	stdout.write_all(b"\n")?;
	stdout.flush()?;
	Ok(())
}

fn runtime() -> Result<tokio::runtime::Runtime> {
	Ok(tokio::runtime::Builder::new_current_thread().max_blocking_threads(2).enable_all().build()?)
}

fn ordinary(input: &str) -> Result<()> {
	let runtime = runtime()?;
	for (index, line) in input.lines().enumerate() {
		let value: Value = serde_json::from_str(line)?;
		let params = parameters(&value)?;
		let before = clock_ns()?;
		let available_before = original::observed_available_permits();
		let result = runtime.block_on(original::plan(params));
		let after = clock_ns()?;
		let (kind, text) = match result { Ok(value) => (0, value), Err(error) => (1, format!("{error:#}")) };
		output(&json!({"index": index, "name": value.get("name"), "kind": kind, "text": text,
			"before_ns": before, "after_ns": after, "available_before": available_before,
			"available_after": original::observed_available_permits()}))?;
	}
	Ok(())
}

type Gate = Arc<(Mutex<bool>, Condvar)>;

fn release(gate: &Gate) -> Result<()> {
	*gate.0.lock().map_err(|_| anyhow!("owned fixture gate poisoned"))? = true;
	gate.1.notify_all();
	Ok(())
}

async fn occupy_pool() -> Result<(Vec<Gate>, Vec<tokio::task::JoinHandle<Result<()>>>, Vec<i64>)> {
	let (started_tx, started_rx) = std::sync::mpsc::channel();
	let mut gates = Vec::new();
	let mut workers = Vec::new();
	for _ in 0..2 {
		let gate = Arc::new((Mutex::new(false), Condvar::new()));
		gates.push(gate.clone());
		let sender = started_tx.clone();
		workers.push(tokio::task::spawn_blocking(move || {
			sender.send(unsafe { libc::syscall(libc::SYS_gettid) as i64 })?;
			let mut ready = gate.0.lock().map_err(|_| anyhow!("owned fixture gate poisoned"))?;
			while !*ready { ready = gate.1.wait(ready).map_err(|_| anyhow!("owned fixture wait poisoned"))?; }
			Ok(())
		}));
	}
	let ids = vec![started_rx.recv()?, started_rx.recv()?];
	if ids[0] <= 0 || ids[0] == ids[1] { bail!("blocking workers were not independently started"); }
	Ok((gates, workers, ids))
}

async fn permits(expected: usize) {
	while original::observed_available_permits() != expected { tokio::task::yield_now().await; }
}

async fn lifecycle() -> Result<Value> {
	let (gates, blockers, ids) = occupy_pool().await?;
	let a = tokio::spawn(original::plan(simple(1.0)));
	let b = tokio::spawn(original::plan(simple(2.0)));
	permits(0).await;
	let third_before = original::plan(simple(99.0)).await.err().ok_or_else(|| anyhow!("third plan admitted"))?;
	a.abort();
	let cancelled = a.await.err().ok_or_else(|| anyhow!("caller was not cancelled"))?;
	if !cancelled.is_cancelled() { bail!("caller cancellation was not observed"); }
	let after_cancel = original::observed_available_permits();
	let third_after = original::plan(simple(99.0)).await.err().ok_or_else(|| anyhow!("cancel released worker permit"))?;
	for gate in &gates { release(gate)?; }
	for blocker in blockers { blocker.await.context("joining owned fixture blocker")??; }
	let result = b.await.context("joining surviving original caller")??;
	permits(2).await;
	Ok(json!({"blocking_thread_ids": ids, "queued_permits": 0, "after_cancel_permits": after_cancel,
		"third_before": format!("{third_before:#}"), "third_after": format!("{third_after:#}"),
		"cancelled": true, "surviving_result": result, "drained_permits": original::observed_available_permits()}))
}

async fn retained() -> Result<Value> {
	let mut pending = Vec::new();
	for index in 0..40 {
		let caller = tokio::spawn(original::plan(simple(index as f64 + 0.25)));
		while !caller.is_finished() { tokio::task::yield_now().await; }
		if original::observed_available_permits() != 2 { bail!("ready result retained a permit"); }
		pending.push((index, caller));
	}
	let ready_count = pending.len();
	let mut results = Vec::new();
	for (index, caller) in pending.into_iter().rev() {
		results.push(json!({"index": index, "text": caller.await.context("joining retained result")??}));
	}
	Ok(json!({"ready_count": ready_count, "results": results, "final_permits": original::observed_available_permits()}))
}

async fn queued_hold() -> Result<Value> {
	let (gates, blockers, ids) = occupy_pool().await?;
	let caller = tokio::spawn(original::plan(simple(7.0)));
	permits(1).await;
	let before = clock_ns()?;
	std::thread::sleep(Duration::from_millis(30_025));
	let after = clock_ns()?;
	let held_permits = original::observed_available_permits();
	for gate in &gates { release(gate)?; }
	for blocker in blockers { blocker.await??; }
	let result = caller.await??;
	Ok(json!({"blocking_thread_ids": ids, "before_ns": before, "after_ns": after,
		"held_permits": held_permits, "result": result, "final_permits": original::observed_available_permits()}))
}

fn main() -> Result<()> {
	let mode = std::env::args().nth(1).ok_or_else(|| anyhow!("missing owned qualification mode"))?;
	let mut input = String::new();
	std::io::stdin().read_to_string(&mut input)?;
	match mode.as_str() {
		"ordinary" => ordinary(&input)?,
		"writer-trace" => for (index, line) in input.lines().enumerate() {
			output(&json!({"index": index, "trace": original::trace_canonical_writer(line)?}))?;
		},
		"duration" => for line in input.lines() {
			let ns: u64 = serde_json::from_str(line)?;
			let value = Duration::new(ns / 1_000_000_000, (ns % 1_000_000_000) as u32).as_secs_f64();
			output(&json!({"nanoseconds": ns, "bits": value.to_bits()}))?;
		},
		"lifecycle" => output(&runtime()?.block_on(lifecycle())?)?,
		"retained" => output(&runtime()?.block_on(retained())?)?,
		"queue-hold" => output(&runtime()?.block_on(queued_hold())?)?,
		"core-deadline" => output(&original::observed_deadline_hold(false)?)?,
		"writer-deadline" => output(&original::observed_deadline_hold(true)?)?,
		_ => bail!("unknown qualification mode"),
	}
	eprintln!("{{\"pid\":{},\"parent_pid\":{},\"pgid\":{}}}", std::process::id(), unsafe { libc::getppid() }, unsafe { libc::getpgrp() });
	Ok(())
}
