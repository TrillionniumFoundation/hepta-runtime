// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
//! Test-only adapters drive unchanged original request context and cache owners.
//! Each actor is a real original Tokio scoped future, polled on the same task.

use serde_json::{json, Value};
use std::collections::HashMap;
use std::future::Future;
use std::io::{self, BufRead, Write};
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, Waker};

mod mcp {
	pub mod fs {
		pub mod delta {
			include!("../fixtures/original_view_cache.rs");
			pub fn get(cache: &ViewCache, key: &str) -> Option<String> {
				cache.get(key)
			}
			pub fn set(cache: &ViewCache, key: &str, value: &str) {
				cache.set(key.to_owned(), value.to_owned());
			}
			pub fn forget(cache: &ViewCache, key: &str) {
				cache.forget(key);
			}
			pub fn subtree(cache: &ViewCache, key: &str) {
				cache.forget_subtree(key);
			}
		}
	}
	pub mod request_ctx {
		include!("../fixtures/original_request_ctx.rs");
	}
}
use mcp::fs::delta::{self, ViewCache};
use mcp::request_ctx;

fn hex(raw: &[u8]) -> String {
	const DIGITS: &[u8; 16] = b"0123456789abcdef";
	let mut result = String::with_capacity(raw.len() * 2);
	for value in raw {
		result.push(DIGITS[(value >> 4) as usize] as char);
		result.push(DIGITS[(value & 15) as usize] as char);
	}
	result
}

fn unhex(text: &str) -> Vec<u8> {
	assert_eq!(text.len() % 2, 0);
	text.as_bytes()
		.chunks_exact(2)
		.map(|pair| {
			let digit = |v: u8| match v {
				b'0'..=b'9' => v - b'0',
				b'a'..=b'f' => v - b'a' + 10,
				_ => panic!("hex"),
			};
			(digit(pair[0]) << 4) | digit(pair[1])
		})
		.collect()
}

fn word(raw: &[u8], offset: usize) -> u64 {
	u64::from_le_bytes(raw[offset..offset + 8].try_into().unwrap())
}

fn cache_reply(value: Option<String>) -> Vec<u8> {
	let mut out = b"HVCAR001".to_vec();
	out.extend(u64::from(value.is_some()).to_le_bytes());
	out.extend((value.as_ref().map_or(0, |v| v.len()) as u64).to_le_bytes());
	out.extend(0u64.to_le_bytes());
	if let Some(value) = value {
		out.extend(value.as_bytes());
	}
	out
}

fn hints_reply(values: Vec<String>) -> Vec<u8> {
	let mut payload = Vec::new();
	for value in &values {
		payload.extend((value.len() as u64).to_le_bytes());
		payload.extend(value.as_bytes());
	}
	let mut out = b"HRCXR001".to_vec();
	out.extend(1u64.to_le_bytes());
	out.extend((values.len() as u64).to_le_bytes());
	out.extend((payload.len() as u64).to_le_bytes());
	out.extend(payload);
	out
}

fn cache_call(cache: &ViewCache, raw: &[u8]) -> Vec<u8> {
	assert!(raw.len() >= 48 && &raw[..8] == b"HVCACH01");
	let operation = word(raw, 8);
	let key_len = word(raw, 24) as usize;
	let a_len = word(raw, 32) as usize;
	let b_len = word(raw, 40) as usize;
	assert_eq!(raw.len(), 48 + key_len + a_len + b_len);
	let key = std::str::from_utf8(&raw[48..48 + key_len]).unwrap();
	let a = std::str::from_utf8(&raw[48 + key_len..48 + key_len + a_len]).unwrap();
	if word(raw, 16) == 2 {
		return cache_reply(None);
	}
	match operation {
		1 => cache_reply(delta::get(cache, key)),
		2 => {
			delta::set(cache, key, a);
			cache_reply(None)
		}
		3 => {
			delta::forget(cache, key);
			cache_reply(None)
		}
		4 => {
			delta::subtree(cache, key);
			cache_reply(None)
		}
		5 => {
			cache.forget_all();
			cache_reply(None)
		}
		_ => panic!("operation outside this focused original replay domain"),
	}
}

enum Command {
	Access(usize),
	Push(String),
	Drain,
	Cache(Vec<u8>),
	Finish(bool),
	Panic,
}
struct Message {
	command: Command,
	reply: std::sync::mpsc::Sender<Value>,
}
struct Actor {
	future: Pin<Box<dyn Future<Output = Result<(), String>> + Send>>,
	sender: tokio::sync::mpsc::UnboundedSender<Message>,
	identity: usize,
	lease: u64,
}

impl Actor {
	fn new(cache: Arc<ViewCache>, lease: u64) -> Self {
		let identity = Arc::as_ptr(&cache) as usize;
		let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<Message>();
		let future = request_ctx::with_request_context(cache, async move {
			while let Some(message) = receiver.recv().await {
				let value = match message.command {
					Command::Access(expected) => {
						let identity = request_ctx::with_view_cache(|cache| {
							cache as *const ViewCache as usize
						});
						json!({"present":identity.is_some(),"identity_matches":identity == Some(expected)})
					}
					Command::Push(hint) => {
						request_ctx::push_hint(&hint);
						json!({"unit":true})
					}
					Command::Drain => {
						json!({"payload_hex":hex(&hints_reply(request_ctx::drain_hints()))})
					}
					Command::Cache(wire) => {
						let body = request_ctx::with_view_cache(|cache| cache_call(cache, &wire))
							.unwrap_or_else(|| cache_reply(None));
						json!({"payload_hex":hex(&body)})
					}
					Command::Finish(error) => {
						message.reply.send(json!({"active":false})).unwrap();
						return if error {
							Err("original executor error".to_owned())
						} else {
							Ok(())
						};
					}
					Command::Panic => panic!("intentional original scoped-future panic"),
				};
				message.reply.send(value).unwrap();
			}
			Ok(())
		});
		Self {
			future: Box::pin(future),
			sender,
			identity,
			lease,
		}
	}
	fn poll(&mut self) -> Poll<Result<(), String>> {
		let result = self
			.future
			.as_mut()
			.poll(&mut Context::from_waker(Waker::noop()));
		assert!(
			request_ctx::with_view_cache(|_| ()).is_none(),
			"task-local leaked outside poll"
		);
		assert!(
			request_ctx::drain_hints().is_empty(),
			"hints leaked outside poll"
		);
		result
	}
	fn command(&mut self, command: Command, end: bool) -> Value {
		let (reply, receiver) = std::sync::mpsc::channel();
		self.sender.send(Message { command, reply }).unwrap();
		let result = self.poll();
		assert_eq!(result.is_ready(), end);
		receiver.try_recv().unwrap()
	}
	fn panic_and_drop(&mut self) {
		let (reply, _receiver) = std::sync::mpsc::channel();
		self.sender
			.send(Message {
				command: Command::Panic,
				reply,
			})
			.unwrap();
		assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.poll())).is_err());
		assert!(request_ctx::with_view_cache(|_| ()).is_none());
		assert!(request_ctx::drain_hints().is_empty());
	}
}

fn number(value: &Value, key: &str) -> u64 {
	value[key].as_u64().unwrap()
}
fn text<'a>(value: &'a Value, key: &str) -> &'a str {
	value[key].as_str().unwrap()
}

fn trace(input: &Value) -> Value {
	let mut owned: HashMap<u64, Arc<ViewCache>> = HashMap::new();
	let mut labels: HashMap<u64, Weak<ViewCache>> = HashMap::new();
	let mut actors: HashMap<u64, Actor> = HashMap::new();
	let mut cache: Weak<ViewCache> = Weak::new();
	let mut observations = Vec::new();
	let mut actual_polls = 0usize;
	for event in input["events"].as_array().unwrap() {
		let op = text(event, "op");
		let value = match op {
			"create" => {
				assert!(cache.upgrade().is_none() && owned.is_empty() && actors.is_empty());
				let value = Arc::new(ViewCache::default());
				cache = Arc::downgrade(&value);
				labels.clear();
				labels.insert(number(event, "alias"), cache.clone());
				owned.insert(number(event, "alias"), value);
				json!({"strong_count":cache.strong_count(),"alive":cache.strong_count()!=0})
			}
			"clone" => {
				let value = labels[&number(event, "source")].upgrade().unwrap();
				assert!(labels
					.insert(number(event, "alias"), Arc::downgrade(&value))
					.is_none());
				owned.insert(number(event, "alias"), value);
				json!({"strong_count":cache.strong_count(),"alive":cache.strong_count()!=0})
			}
			"release" => {
				let alias = number(event, "source");
				assert!(labels.remove(&alias).is_some());
				drop(owned.remove(&alias).unwrap());
				json!({"strong_count":cache.strong_count(),"alive":cache.strong_count()!=0})
			}
			"inspect" => {
				assert!(labels.contains_key(&number(event, "source")));
				json!({"strong_count":cache.strong_count(),"alive":cache.strong_count()!=0})
			}
			"owned_cache" => {
				let body = {
					let value = labels[&number(event, "source")].upgrade().unwrap();
					cache_call(&value, &unhex(text(event, "wire_hex")))
				};
				json!({"strong_count":cache.strong_count(),"payload_hex":hex(&body)})
			}
			"open" => {
				let value = labels[&number(event, "source")].upgrade().unwrap();
				let alias = number(event, "alias");
				assert!(labels.insert(alias, Arc::downgrade(&value)).is_none());
				let mut actor = Actor::new(value, alias);
				assert!(actor.poll().is_pending());
				actual_polls += 1;
				assert!(actors.insert(number(event, "actor"), actor).is_none());
				json!({"active":true})
			}
			"close" => {
				let mut actor = actors.remove(&number(event, "actor")).unwrap();
				let value = actor.command(Command::Finish(event["error"].as_bool().unwrap()), true);
				actual_polls += 1;
				labels.remove(&actor.lease).unwrap();
				drop(actor);
				value
			}
			"cancel" => {
				let mut actor = actors.remove(&number(event, "actor")).unwrap();
				if number(event, "reason") == 4 {
					actor.panic_and_drop();
					actual_polls += 1;
				}
				labels.remove(&actor.lease).unwrap();
				drop(actor);
				json!({"active":false})
			}
			"late_retire" => {
				assert!(!actors.contains_key(&number(event, "actor")));
				json!({"active":false})
			}
			"yield" | "resume" => {
				assert!(actors
					.get_mut(&number(event, "actor"))
					.unwrap()
					.poll()
					.is_pending());
				actual_polls += 1;
				json!({"pending":true,"outside_absent":true})
			}
			"access" | "push" | "drain" | "cache" => {
				if event["bound"].as_bool().unwrap() {
					let actor = actors.get_mut(&number(event, "actor")).unwrap();
					let command = match op {
						"access" => Command::Access(actor.identity),
						"push" => Command::Push(text(event, "hint").to_owned()),
						"drain" => Command::Drain,
						_ => Command::Cache(unhex(text(event, "wire_hex"))),
					};
					actual_polls += 1;
					actor.command(command, false)
				} else {
					assert!(request_ctx::with_view_cache(|_| ()).is_none());
					match op {
						"access" => json!({"present":false,"identity_matches":false}),
						"push" => {
							request_ctx::push_hint(text(event, "hint"));
							json!({"unit":true})
						}
						"drain" => {
							json!({"payload_hex":hex(&hints_reply(request_ctx::drain_hints()))})
						}
						_ => {
							let wire = unhex(text(event, "wire_hex"));
							let body = request_ctx::with_view_cache(|c| cache_call(c, &wire))
								.unwrap_or_else(|| cache_reply(None));
							json!({"payload_hex":hex(&body)})
						}
					}
				}
			}
			_ => panic!("unknown event"),
		};
		assert!(request_ctx::with_view_cache(|_| ()).is_none());
		observations.push(json!({"ordinal":number(event,"ordinal"),"value":value}));
	}
	assert!(actors.is_empty() && owned.is_empty());
	assert_eq!(cache.strong_count(), 0);
	assert!(cache.upgrade().is_none());
	json!({"trace":input["trace"],"observations":observations,"actual_scoped_future_polls":actual_polls,
		"final_cache_dropped":true,"all_outside_poll_access_absent":true})
}

async fn actual_tokio_probes() -> Value {
	let root = Arc::new(ViewCache::default());
	let weak = Arc::downgrade(&root);
	let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
	let scope = tokio::spawn(request_ctx::with_request_context(
		root.clone(),
		async move {
			request_ctx::push_hint("cancelled actual Tokio task");
			let absent = tokio::spawn(async {
				let absent = request_ctx::with_view_cache(|_| ()).is_none();
				request_ctx::push_hint("spawned hint discarded");
				absent && request_ctx::drain_hints().is_empty()
			})
			.await
			.unwrap();
			assert!(absent);
			ready_tx.send(()).unwrap();
			std::future::pending::<()>().await;
		},
	));
	ready_rx.await.unwrap();
	assert_eq!(weak.strong_count(), 2);
	scope.abort();
	assert!(scope.await.unwrap_err().is_cancelled());
	assert_eq!(weak.strong_count(), 1);
	request_ctx::with_request_context(root.clone(), async {
		assert!(request_ctx::drain_hints().is_empty());
	})
	.await;
	drop(root);
	assert_eq!(weak.strong_count(), 0);
	assert!(weak.upgrade().is_none());

	let root = Arc::new(ViewCache::default());
	let weak = Arc::downgrade(&root);
	delta::set(&root, "key", "committed before publication");
	let publication = root.clone();
	let (worker_tx, worker_rx) = tokio::sync::oneshot::channel();
	let (release_tx, release_rx) = tokio::sync::oneshot::channel();
	let scope = tokio::spawn(request_ctx::with_request_context(
		root.clone(),
		async move {
			request_ctx::push_hint("request-owned abandoned hint");
			let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
			let worker = tokio::spawn(async move {
				assert!(request_ctx::with_view_cache(|_| ()).is_none());
				ready_tx.send(()).unwrap();
				release_rx.await.unwrap();
				assert_eq!(
					delta::get(&publication, "key").as_deref(),
					Some("committed before publication")
				);
				publication.forget_all();
				assert!(delta::get(&publication, "key").is_none());
			});
			ready_rx.await.unwrap();
			worker_tx.send(worker).unwrap();
			std::future::pending::<()>().await;
		},
	));
	let worker = worker_rx.await.unwrap();
	assert_eq!(weak.strong_count(), 3);
	scope.abort();
	assert!(scope.await.unwrap_err().is_cancelled());
	assert_eq!(weak.strong_count(), 2);
	drop(root);
	assert_eq!(weak.strong_count(), 1);
	assert!(!worker.is_finished());
	release_tx.send(()).unwrap();
	worker.await.unwrap();
	assert_eq!(weak.strong_count(), 0);
	assert!(weak.upgrade().is_none());

	let root = Arc::new(ViewCache::default());
	let weak = Arc::downgrade(&root);
	let panicking = tokio::spawn(request_ctx::with_request_context(root.clone(), async {
		request_ctx::push_hint("panic drops original scoped context");
		panic!("intentional actual Tokio panic");
	}));
	assert!(panicking.await.unwrap_err().is_panic());
	assert_eq!(weak.strong_count(), 1);
	assert!(request_ctx::with_view_cache(|_| ()).is_none());
	assert!(request_ctx::drain_hints().is_empty());
	drop(root);
	assert!(weak.upgrade().is_none());
	json!({"actual_tokio_abort_join_cancelled":true,"actual_spawn_does_not_inherit":true,
		"cancelled_hints_discarded":true,"owned_worker_survives_request_cancel_and_session_drop":true,
		"worker_only_releases_own_arc":true,"actual_owned_forget_all_after_cancel":true,
		"actual_tokio_panic_join":true,"final_weak_upgrade_none":true,
		"stdio_async_writer_implemented":false})
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
	let previous = std::panic::take_hook();
	std::panic::set_hook(Box::new(|_| {}));
	let input: Vec<Value> = io::stdin()
		.lock()
		.lines()
		.map(|line| serde_json::from_str(&line.unwrap()).unwrap())
		.collect();
	let mut stdout = io::BufWriter::new(io::stdout().lock());
	for value in &input {
		serde_json::to_writer(&mut stdout, &trace(value)).unwrap();
		stdout.write_all(b"\n").unwrap();
	}
	let probes = actual_tokio_probes().await;
	serde_json::to_writer(
		&mut stdout,
		&json!({"probe":"actual-tokio-lifetime","result":probes}),
	)
	.unwrap();
	stdout.write_all(b"\n").unwrap();
	stdout.flush().unwrap();
	std::panic::set_hook(previous);
}
