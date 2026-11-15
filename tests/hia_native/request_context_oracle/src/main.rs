// Copyright 2026 Muvon Un Limited
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

//! Original-source oracle: included production function bodies are unchanged.
//! Framing, private observations and scheduling controls are test-only code.

use serde_json::{json, Value};
use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
use std::io::{self, BufRead, Read, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

mod mcp {
	pub mod fs {
		pub mod delta {
			include!("../fixtures/original_view_cache.rs");
			pub fn oracle_get(c: &ViewCache, key: &str) -> Option<String> {
				c.get(key)
			}
			pub fn oracle_set(c: &ViewCache, key: &str, value: &str) {
				c.set(key.to_owned(), value.to_owned());
			}
		}
	}
	pub mod request_ctx {
		include!("../fixtures/original_request_ctx.rs");
		// Original has no PEEK API: clone-and-dedup is observation-only.
		pub fn oracle_snapshot() -> Vec<String> {
			CTX.try_with(|ctx| {
				let hints = ctx.hints.borrow().clone();
				let mut seen = std::collections::HashSet::new();
				hints
					.into_iter()
					.filter(|h| seen.insert(h.clone()))
					.collect()
			})
			.unwrap_or_default()
		}
	}
}
use mcp::fs::delta::{oracle_get, oracle_set, ViewCache};
use mcp::request_ctx;
include!("../fixtures/original_append_hints.rs");

mod composer {
	mod request_ctx {
		use std::cell::RefCell;
		thread_local! { pub static DRAINED: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) }; }
		pub fn drain_hints() -> Vec<String> {
			DRAINED.with(|v| std::mem::take(&mut *v.borrow_mut()))
		}
	}
	include!("../fixtures/original_append_hints.rs");
	pub fn render(base: String, drained: Vec<String>) -> String {
		request_ctx::DRAINED.with(|v| *v.borrow_mut() = drained);
		append_hints(base)
	}
}

fn hex(bytes: &[u8]) -> String {
	const DIGITS: &[u8; 16] = b"0123456789abcdef";
	let mut out = String::with_capacity(bytes.len() * 2);
	for b in bytes {
		out.push(DIGITS[(b >> 4) as usize] as char);
		out.push(DIGITS[(b & 15) as usize] as char);
	}
	out
}
fn request(op: u64, payload: &[u8]) -> Vec<u8> {
	let mut out = b"HRCXQ001".to_vec();
	out.extend(op.to_le_bytes());
	out.extend((payload.len() as u64).to_le_bytes());
	out.extend(0u64.to_le_bytes());
	out.extend(payload);
	out
}
fn reply(tag: u64, scalar: u64, payload: &[u8]) -> Vec<u8> {
	let mut out = b"HRCXR001".to_vec();
	out.extend(tag.to_le_bytes());
	out.extend(scalar.to_le_bytes());
	out.extend((payload.len() as u64).to_le_bytes());
	out.extend(payload);
	out
}
fn list_reply(items: &[String]) -> Vec<u8> {
	let mut payload = Vec::new();
	for item in items {
		payload.extend((item.len() as u64).to_le_bytes());
		payload.extend(item.as_bytes());
	}
	reply(1, items.len() as u64, &payload)
}
fn record(
	log: &mut Vec<Value>,
	index: usize,
	operation: &str,
	op: u64,
	payload: &[u8],
	result: Vec<u8>,
) {
	log.push(json!({"index":index,"operation":operation,"input_hex":hex(&request(op,payload)),"output_hex":hex(&result)}));
}
fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
	value
		.get(key)
		.and_then(Value::as_str)
		.ok_or_else(|| format!("missing string {key}"))
}
#[derive(Clone, Copy)]
enum Stop {
	End,
	Exit(usize),
	Destroy(usize),
}

fn eval<'a>(
	events: &'a [Value],
	index: &'a mut usize,
	caches: &'a HashMap<u64, Arc<ViewCache>>,
	log: &'a mut Vec<Value>,
	depth: usize,
) -> Pin<Box<dyn Future<Output = Result<Stop, String>> + Send + 'a>> {
	Box::pin(async move {
		while *index < events.len() {
			let position = *index;
			let event = &events[position];
			*index += 1;
			let op = string(event, "op")?;
			match op {
				"init" => {
					if depth != 0 {
						return Err("init inside scope".to_owned());
					};
					record(log, position, op, 1, &[], reply(0, 0, &[]));
				}
				"enter" => {
					let alias = event
						.get("cache")
						.and_then(Value::as_u64)
						.ok_or("missing cache alias")?;
					let cache = caches.get(&alias).ok_or("unbound cache alias")?.clone();
					let pointer = Arc::as_ptr(&cache) as usize;
					let end = request_ctx::with_request_context(cache, async {
						assert_eq!(
							request_ctx::with_view_cache(|c| c as *const ViewCache as usize),
							Some(pointer)
						);
						record(log, position, op, 2, &alias.to_le_bytes(), reply(0, 0, &[]));
						eval(events, index, caches, log, depth + 1).await
					})
					.await?;
					match end {
						Stop::Exit(at) => record(log, at, "exit", 3, &[], reply(0, 0, &[])),
						Stop::Destroy(at) if depth == 0 => {
							record(log, at, "destroy", 8, &[], reply(0, 0, &[]))
						}
						Stop::Destroy(at) => return Ok(Stop::Destroy(at)),
						Stop::End => return Err("scope missing exit/destroy".to_owned()),
					}
				}
				"exit" => {
					if depth == 0 {
						return Err("exit outside scope".to_owned());
					};
					return Ok(Stop::Exit(position));
				}
				"push" => {
					let h = string(event, "hint")?;
					request_ctx::push_hint(h);
					record(log, position, op, 4, h.as_bytes(), reply(0, 0, &[]));
				}
				"drain" => record(
					log,
					position,
					op,
					5,
					&[],
					list_reply(&request_ctx::drain_hints()),
				),
				"peek" => record(
					log,
					position,
					op,
					6,
					&[],
					list_reply(&request_ctx::oracle_snapshot()),
				),
				"cache" => {
					let pointer = request_ctx::with_view_cache(|c| c as *const ViewCache as usize);
					let alias = pointer.map(|ptr| {
						*caches
							.iter()
							.find(|(_, c)| Arc::as_ptr(c) as usize == ptr)
							.expect("bound test cache")
							.0
					});
					let out = match alias {
						Some(a) => reply(3, 1, &a.to_le_bytes()),
						None => reply(3, 0, &[]),
					};
					record(log, position, op, 7, &[], out);
				}
				"destroy" => {
					if depth != 0 {
						return Ok(Stop::Destroy(position));
					};
					record(log, position, op, 8, &[], reply(0, 0, &[]));
				}
				_ => return Err(format!("unknown test event {op}")),
			}
			tokio::task::yield_now().await;
		}
		Ok(Stop::End)
	})
}

struct CatchPanic<F: Future> {
	inner: Pin<Box<F>>,
}
impl<F: Future> Future for CatchPanic<F> {
	type Output = Result<F::Output, Box<dyn Any + Send>>;
	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
			self.get_mut().inner.as_mut().poll(cx)
		})) {
			Ok(Poll::Ready(v)) => Poll::Ready(Ok(v)),
			Ok(Poll::Pending) => Poll::Pending,
			Err(e) => Poll::Ready(Err(e)),
		}
	}
}

async fn scenarios() -> Value {
	let mut rows = Vec::new();
	let cache = Arc::new(ViewCache::default());
	let pointer = Arc::as_ptr(&cache) as usize;
	let mut called = false;
	assert_eq!(
		request_ctx::with_view_cache(|_| {
			called = true;
			17
		}),
		None
	);
	assert!(!called);
	request_ctx::push_hint("outside");
	assert!(request_ctx::drain_hints().is_empty());
	assert_eq!(append_hints("base".to_owned()), "base");
	rows.push(json!({"case":"outside-scope-and-closure-not-called","ok":true}));

	let outer = request_ctx::with_request_context(cache.clone(), async {
		request_ctx::push_hint("outer");
		request_ctx::with_view_cache(|c| oracle_set(c, "key", "shared"));
		let other = Arc::new(ViewCache::default());
		let other_ptr = Arc::as_ptr(&other) as usize;
		let inner = request_ctx::with_request_context(other, async {
			assert_eq!(
				request_ctx::with_view_cache(|c| c as *const ViewCache as usize),
				Some(other_ptr)
			);
			assert_eq!(
				request_ctx::with_view_cache(|c| oracle_get(c, "key")),
				Some(None)
			);
			request_ctx::push_hint("inner");
			tokio::task::yield_now().await;
			request_ctx::drain_hints()
		})
		.await;
		assert_eq!(inner, vec!["inner"]);
		assert_eq!(
			request_ctx::with_view_cache(|c| c as *const ViewCache as usize),
			Some(pointer)
		);
		assert_eq!(
			request_ctx::with_view_cache(|c| oracle_get(c, "key")),
			Some(Some("shared".to_owned()))
		);
		request_ctx::push_hint("outer");
		request_ctx::drain_hints()
	})
	.await;
	assert_eq!(outer, vec!["outer"]);
	assert!(request_ctx::drain_hints().is_empty());
	rows.push(json!({"case":"nested-different-cache-restores-parent","ok":true}));

	let shared = request_ctx::with_request_context(cache.clone(), async {
		assert!(request_ctx::drain_hints().is_empty());
		request_ctx::with_view_cache(|c| oracle_get(c, "key"))
	})
	.await;
	assert_eq!(shared, Some(Some("shared".to_owned())));
	rows.push(json!({"case":"same-session-cache-persists-hints-fresh","ok":true}));

	let dedup = request_ctx::with_request_context(cache.clone(), async {
		for h in ["", "é", "e\u{301}", "a\0b", "\r\n", "é", "", "⚠️ ", "a\0b"] {
			request_ctx::push_hint(h);
		}
		let first = request_ctx::drain_hints();
		assert_eq!(first, vec!["", "é", "e\u{301}", "a\0b", "\r\n", "⚠️ "]);
		assert!(request_ctx::drain_hints().is_empty());
		request_ctx::push_hint("é");
		assert_eq!(request_ctx::drain_hints(), vec!["é"]);
		first
	})
	.await;
	rows.push(
		json!({"case":"exact-utf8-first-occurrence-and-drain-clear","ok":true,"hints":dedup}),
	);

	request_ctx::with_request_context(cache.clone(), async {
		request_ctx::push_hint("parent");
		let child = tokio::spawn(async {
			request_ctx::push_hint("unscoped-child");
			(
				request_ctx::drain_hints(),
				request_ctx::with_view_cache(|_| 17),
			)
		})
		.await
		.unwrap();
		assert_eq!(child, (Vec::<String>::new(), None));
		assert_eq!(request_ctx::drain_hints(), vec!["parent"]);
	})
	.await;
	rows.push(json!({"case":"spawned-task-does-not-inherit-parent-context","ok":true}));

	let barrier = Arc::new(tokio::sync::Barrier::new(3));
	let mut handles = Vec::new();
	for name in ["left", "right"] {
		let c = cache.clone();
		let b = barrier.clone();
		handles.push(tokio::spawn(request_ctx::with_request_context(
			c,
			async move {
				request_ctx::push_hint(name);
				b.wait().await;
				for _ in 0..32 {
					request_ctx::push_hint(name);
					tokio::task::yield_now().await;
				}
				request_ctx::with_view_cache(|c| oracle_set(c, name, name));
				let hints = request_ctx::drain_hints();
				assert_eq!(hints, vec![name]);
				hints
			},
		)));
	}
	barrier.wait().await;
	let left = handles.remove(0).await.unwrap();
	let right = handles.remove(0).await.unwrap();
	assert_eq!(oracle_get(&cache, "left"), Some("left".to_owned()));
	assert_eq!(oracle_get(&cache, "right"), Some("right".to_owned()));
	rows.push(json!({"case":"real-tokio-task-interleaving-shared-cache-isolated-hints","ok":true,"yield_count":64,"left":left,"right":right}));

	let mut handles = Vec::new();
	for name in ["session-a", "session-b"] {
		handles.push(tokio::spawn(request_ctx::with_request_context(
			Arc::new(ViewCache::default()),
			async move {
				request_ctx::with_view_cache(|c| oracle_set(c, "same-key", name));
				request_ctx::push_hint(name);
				tokio::task::yield_now().await;
				assert_eq!(
					request_ctx::with_view_cache(|c| oracle_get(c, "same-key")),
					Some(Some(name.to_owned()))
				);
				request_ctx::drain_hints()
			},
		)));
	}
	assert_eq!(handles.remove(0).await.unwrap(), vec!["session-a"]);
	assert_eq!(handles.remove(0).await.unwrap(), vec!["session-b"]);
	rows.push(json!({"case":"different-session-cache-and-hints-isolated","ok":true}));

	let joined = request_ctx::with_request_context(cache.clone(), async {
		request_ctx::push_hint("parent-join");
		let a = request_ctx::with_request_context(Arc::new(ViewCache::default()), async {
			request_ctx::push_hint("join-a");
			tokio::task::yield_now().await;
			request_ctx::drain_hints()
		});
		let b = request_ctx::with_request_context(Arc::new(ViewCache::default()), async {
			request_ctx::push_hint("join-b");
			tokio::task::yield_now().await;
			request_ctx::drain_hints()
		});
		let (a, b) = tokio::join!(a, b);
		assert_eq!(a, vec!["join-a"]);
		assert_eq!(b, vec!["join-b"]);
		assert_eq!(request_ctx::drain_hints(), vec!["parent-join"]);
		(a, b)
	})
	.await;
	rows.push(
		json!({"case":"same-task-join-futures-own-distinct-contexts","ok":true,"children":joined}),
	);

	let failed: Result<u64, &str> = request_ctx::with_request_context(cache.clone(), async {
		request_ctx::push_hint("failed-call");
		Err("original-error")
	})
	.await;
	assert_eq!(failed, Err("original-error"));
	assert!(
		request_ctx::with_request_context(cache.clone(), async { request_ctx::drain_hints() })
			.await
			.is_empty()
	);
	rows.push(json!({"case":"error-output-preserved-failed-hints-dropped","ok":true}));

	let restored = request_ctx::with_request_context(cache.clone(), async {
		request_ctx::push_hint("parent-before-panic");
		let inner = request_ctx::with_request_context(Arc::new(ViewCache::default()), async {
			request_ctx::push_hint("panicked-child");
			tokio::task::yield_now().await;
			panic!("expected original-scope panic");
		});
		assert!(CatchPanic {
			inner: Box::pin(inner)
		}
		.await
		.is_err());
		assert_eq!(
			request_ctx::with_view_cache(|c| c as *const ViewCache as usize),
			Some(pointer)
		);
		request_ctx::drain_hints()
	})
	.await;
	assert_eq!(restored, vec!["parent-before-panic"]);
	rows.push(json!({"case":"caught-nested-panic-restores-parent","ok":true}));

	let cancel_cache = Arc::new(ViewCache::default());
	let (tx, rx) = tokio::sync::oneshot::channel();
	let handle = tokio::spawn(request_ctx::with_request_context(
		cancel_cache.clone(),
		async move {
			request_ctx::push_hint("aborted-task");
			tx.send(()).unwrap();
			std::future::pending::<()>().await;
		},
	));
	rx.await.unwrap();
	handle.abort();
	assert!(handle.await.unwrap_err().is_cancelled());
	assert_eq!(Arc::strong_count(&cancel_cache), 1);
	assert!(
		request_ctx::with_request_context(cancel_cache, async { request_ctx::drain_hints() })
			.await
			.is_empty()
	);
	rows.push(
		json!({"case":"abort-real-pending-task-drops-context-and-cache-reference","ok":true}),
	);

	let dropped = request_ctx::with_request_context(cache.clone(), async {
		request_ctx::push_hint("parent-before-drop");
		let nested = Arc::new(ViewCache::default());
		let mut future = Box::pin(request_ctx::with_request_context(nested.clone(), async {
			request_ctx::push_hint("pending-child");
			std::future::pending::<()>().await;
		}));
		std::future::poll_fn(|cx| {
			assert!(future.as_mut().poll(cx).is_pending());
			Poll::Ready(())
		})
		.await;
		assert_eq!(
			request_ctx::with_view_cache(|c| c as *const ViewCache as usize),
			Some(pointer)
		);
		drop(future);
		assert_eq!(Arc::strong_count(&nested), 1);
		request_ctx::drain_hints()
	})
	.await;
	assert_eq!(dropped, vec!["parent-before-drop"]);
	rows.push(json!({"case":"drop-partially-polled-nested-scope-restores-parent","ok":true}));

	let text = request_ctx::with_request_context(cache, async {
		request_ctx::push_hint("hint");
		request_ctx::push_hint("hint");
		request_ctx::push_hint("");
		let first = append_hints("base\r\n\0尾".to_owned());
		let second = append_hints(first.clone());
		assert_eq!(first, "base\r\n\0尾\n\n⚠️ hint\n⚠️ \n");
		assert_eq!(first, second);
		first
	})
	.await;
	rows.push(json!({"case":"original-composer-after-original-drain","ok":true,"output":text}));
	json!({"schema":"hepta.runtime.request-context.original-scenarios.v1","ok":true,
        "case_count":rows.len(),"cases":rows,"runtime":"actual tokio 1.53.1, 2 workers",
        "native_scheduler_executed":false,"native_cutover_qualified":false})
}

async fn dispatch(input: Value) -> Result<Value, String> {
	match string(&input, "op")? {
		"trace" => {
			let events = input
				.get("events")
				.and_then(Value::as_array)
				.ok_or("missing events")?;
			let mut caches = HashMap::new();
			for event in events {
				if event.get("op").and_then(Value::as_str) == Some("enter") {
					let alias = event
						.get("cache")
						.and_then(Value::as_u64)
						.ok_or("missing cache alias")?;
					caches
						.entry(alias)
						.or_insert_with(|| Arc::new(ViewCache::default()));
				}
			}
			let mut index = 0;
			let mut log = Vec::new();
			if !matches!(
				eval(events, &mut index, &caches, &mut log, 0).await?,
				Stop::End
			) {
				return Err("unclosed top-level trace".to_owned());
			}
			assert!(request_ctx::drain_hints().is_empty());
			Ok(
				json!({"schema":"hepta.runtime.request-context.original-trace.v1","id":input.get("id"),
                "steps":log,"peek_is_test_only_clone_observation":true,"cache_aliases_are_private_observers":true}),
			)
		}
		"append_only" => {
			let hints = input
				.get("hints")
				.and_then(Value::as_array)
				.ok_or("missing hints")?
				.iter()
				.map(|v| {
					v.as_str()
						.map(str::to_owned)
						.ok_or("non-string hint".to_owned())
				})
				.collect::<Result<Vec<_>, _>>()?;
			let out = composer::render(string(&input, "base")?.to_owned(), hints);
			Ok(
				json!({"schema":"hepta.runtime.response-hints.original.v1","id":input.get("id"),
                "output_hex":hex(out.as_bytes()),"output":out}),
			)
		}
		"scenarios" => Ok(scenarios().await),
		_ => Err("unknown oracle operation".to_owned()),
	}
}

fn word(data: &[u8], at: usize) -> u64 {
	u64::from_le_bytes(data[at..at + 8].try_into().unwrap())
}

fn append_corpus(input: &str, output: &str) -> Result<Value, Box<dyn std::error::Error>> {
	let mut file = std::fs::File::open(input)?;
	let mut out = io::BufWriter::new(
		std::fs::OpenOptions::new()
			.write(true)
			.create_new(true)
			.open(output)?,
	);
	let mut count = 0u64;
	let mut total = 0u64;
	loop {
		let mut header = [0u8; 16];
		let first = file.read(&mut header[..1])?;
		if first == 0 {
			break;
		};
		file.read_exact(&mut header[1..])?;
		let length: usize = word(&header, 0).try_into()?;
		let capacity = word(&header, 8);
		let mut wire = vec![0u8; length];
		file.read_exact(&mut wire)?;
		assert_eq!(&wire[..8], b"HRHAQ001");
		assert_eq!(word(&wire, 24), 0);
		let base_len: usize = word(&wire, 8).try_into()?;
		let drain_len: usize = word(&wire, 16).try_into()?;
		assert_eq!(wire.len(), 32 + base_len + drain_len);
		let base = std::str::from_utf8(&wire[32..32 + base_len])?.to_owned();
		let drain = &wire[32 + base_len..];
		assert_eq!(&drain[..8], b"HRCXR001");
		assert_eq!(word(drain, 8), 1);
		let hints_count = word(drain, 16);
		assert_eq!(word(drain, 24) as usize, drain.len() - 32);
		let mut hints = Vec::new();
		let mut position = 32;
		for _ in 0..hints_count {
			let len: usize = word(drain, position).try_into()?;
			position += 8;
			hints.push(std::str::from_utf8(&drain[position..position + len])?.to_owned());
			position += len;
		}
		assert_eq!(position, drain.len());
		let actual = composer::render(base, hints);
		assert!(actual.len() as u64 <= capacity);
		out.write_all(&(actual.len() as u64).to_le_bytes())?;
		out.write_all(&(actual.len() as u64).to_le_bytes())?;
		out.write_all(actual.as_bytes())?;
		count += 1;
		total += actual.len() as u64;
	}
	out.flush()?;
	Ok(
		json!({"schema":"hepta.runtime.response-hints.original-corpus.v1","case_count":count,"output_bytes":total,
        "original_append_function_executed":true,"dedup_applied_by_composer":false}),
	)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let args = std::env::args().collect::<Vec<_>>();
	if args.len() == 4 && args[1] == "--append-corpus" {
		println!("{}", append_corpus(&args[2], &args[3])?);
		return Ok(());
	}
	if args.len() != 1 {
		return Err("usage: oracle [--append-corpus INPUT OUTPUT]".into());
	}
	let runtime = tokio::runtime::Builder::new_multi_thread()
		.worker_threads(2)
		.enable_all()
		.build()?;
	let stdin = io::stdin();
	let mut stdout = io::BufWriter::new(io::stdout().lock());
	for line in stdin.lock().lines() {
		let input: Value = serde_json::from_str(&line?)?;
		let result = runtime
			.block_on(dispatch(input))
			.map_err(io::Error::other)?;
		serde_json::to_writer(&mut stdout, &result)?;
		writeln!(stdout)?;
		stdout.flush()?;
	}
	Ok(())
}
