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
//! Two finite owned loopback fixtures. User sources are served only as fetch data.

use super::input::{Snapshot, CONTROL, ENTRY, PROBE};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Default)]
struct State {
	stop: AtomicBool,
	phase: AtomicUsize,
	counts: Mutex<BTreeMap<String, usize>>,
	error: Mutex<Option<String>>,
}

pub(super) struct Fixtures {
	state: Arc<State>,
	threads: Vec<JoinHandle<()>>,
	pub origin: String,
	pub probe_origin: String,
	probe_address: SocketAddr,
}

impl Fixtures {
	pub fn start(snapshots: Vec<Snapshot>, requests: &[String]) -> Result<Self> {
		let listener = TcpListener::bind("127.0.0.1:0")?;
		let probe = TcpListener::bind("127.0.0.1:0")?;
		listener.set_nonblocking(true)?;
		probe.set_nonblocking(true)?;
		let origin = format!("http://{}", listener.local_addr()?);
		let probe_address = probe.local_addr()?;
		let probe_origin = format!("http://{probe_address}");
		let html = format!(r#"<!doctype html><html><head><meta charset="utf-8"><title>Hepta fixed local capture</title><link rel="icon" href="data:,"></head><body><script>
window.__heptaCaptureDone=(async()=>{{const generation=window.__heptaCaptureGeneration;const results=[];
for(const path of {}){{try{{const r=await fetch(path,{{cache:"no-store",credentials:"omit"}});await r.arrayBuffer();results.push({{path,ok:true}})}}catch(e){{results.push({{path,ok:false}})}}}}
let blocked=false;try{{await fetch({},{{mode:"no-cors",cache:"no-store",credentials:"omit"}})}}catch(e){{blocked=true}}
return {{generation,results,blocked}}}})();</script></body></html>"#, serde_json::to_string(requests)?, serde_json::to_string(&format!("{probe_origin}{PROBE}"))?).into_bytes();
		let state = Arc::new(State::default());
		let mut result = Self {
			state,
			threads: Vec::new(),
			origin,
			probe_origin,
			probe_address,
		};
		for (kind, server) in [("source", listener), ("probe", probe)] {
			let state = result.state.clone();
			let snapshots = snapshots.clone();
			let html = html.clone();
			let handle = std::thread::Builder::new()
				.name(format!("rea-capture-{kind}"))
				.spawn(move || {
					let outcome = serve(server, kind, &state, &snapshots, &html);
					if let Err(error) = outcome {
						if let Ok(mut slot) = state.error.lock() {
							*slot = Some(format!("{error:#}").chars().take(1024).collect());
						}
						state.stop.store(true, Ordering::Relaxed);
					}
				})?;
			result.threads.push(handle);
		}
		Ok(result)
	}

	pub fn set_phase(&self, phase: usize) {
		self.state.phase.store(phase, Ordering::SeqCst);
	}

	pub fn control_probe(&self) -> Result<()> {
		let mut stream = TcpStream::connect_timeout(&self.probe_address, Duration::from_secs(2))?;
		stream.set_read_timeout(Some(Duration::from_secs(2)))?;
		stream.set_write_timeout(Some(Duration::from_secs(2)))?;
		write!(
			stream,
			"GET {CONTROL} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
			self.probe_address
		)?;
		let mut bytes = Vec::new();
		Read::by_ref(&mut stream)
			.take(4097)
			.read_to_end(&mut bytes)?;
		if bytes.len() > 4096
			|| !bytes.starts_with(b"HTTP/1.1 200 ")
			|| !bytes.ends_with(b"owned-loopback-probe")
		{
			bail!("loopback denial positive control failed");
		}
		Ok(())
	}

	pub fn receipt(&self) -> Result<Value> {
		if !self.threads.is_empty() {
			bail!("owned loopback receipt requested before fixture shutdown");
		}
		if let Some(error) = self
			.state
			.error
			.lock()
			.map_err(|_| anyhow::anyhow!("fixture error lock poisoned"))?
			.as_ref()
		{
			bail!("owned loopback fixture failed: {error}");
		}
		let counts = self
			.state
			.counts
			.lock()
			.map_err(|_| anyhow::anyhow!("fixture count lock poisoned"))?;
		let probe_requests: usize = counts
			.iter()
			.filter(|(key, _)| key.starts_with("probe:") && key.ends_with(PROBE))
			.map(|(_, value)| value)
			.sum();
		let control_requests: usize = counts
			.iter()
			.filter(|(key, _)| key.starts_with("probe:") && key.ends_with(CONTROL))
			.map(|(_, value)| value)
			.sum();
		if probe_requests != 0 || control_requests != 1 {
			bail!("browser denial is not independently established by the owned probe");
		}
		Ok(
			json!({"counts": *counts, "browser_probe_requests_received": probe_requests, "positive_control_requests_received": control_requests}),
		)
	}

	pub fn shutdown(&mut self) -> Result<()> {
		self.state.stop.store(true, Ordering::Relaxed);
		let mut failed = false;
		for handle in self.threads.drain(..) {
			failed |= handle.join().is_err();
		}
		if failed {
			bail!("owned loopback fixture cleanup unconfirmed");
		}
		Ok(())
	}
}

impl Drop for Fixtures {
	fn drop(&mut self) {
		let _ = self.shutdown();
	}
}

fn serve(
	listener: TcpListener,
	kind: &str,
	state: &State,
	snapshots: &[Snapshot],
	html: &[u8],
) -> Result<()> {
	let mut accepted = 0usize;
	while !state.stop.load(Ordering::Relaxed) {
		let (mut stream, _) = match listener.accept() {
			Ok(value) => value,
			Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
				std::thread::sleep(Duration::from_millis(10));
				continue;
			}
			Err(error) => return Err(error.into()),
		};
		accepted += 1;
		if accepted > 128 {
			bail!("owned loopback request budget exceeded");
		}
		stream.set_read_timeout(Some(Duration::from_millis(100)))?;
		stream.set_write_timeout(Some(Duration::from_millis(200)))?;
		let deadline = Instant::now() + Duration::from_secs(2);
		let mut request = Vec::new();
		loop {
			if state.stop.load(Ordering::Relaxed) {
				return Ok(());
			}
			if Instant::now() >= deadline || request.len() >= 8192 {
				break;
			}
			let mut buffer = [0u8; 1024];
			match stream.read(&mut buffer) {
				Ok(0) => break,
				Ok(count) => {
					request.extend_from_slice(&buffer[..count]);
					if request.windows(4).any(|w| w == b"\r\n\r\n") {
						break;
					}
				}
				Err(error)
					if matches!(
						error.kind(),
						std::io::ErrorKind::WouldBlock
							| std::io::ErrorKind::TimedOut
							| std::io::ErrorKind::Interrupted
					) =>
				{
					continue
				}
				Err(_) => break,
			}
		}
		if request.is_empty() {
			continue;
		}
		if request.len() > 8192 {
			bail!("owned loopback header budget exceeded");
		}
		let text = std::str::from_utf8(&request).context("invalid loopback request bytes")?;
		let first = text.lines().next().context("empty loopback request")?;
		let parts: Vec<_> = first.split_whitespace().collect();
		if parts.len() != 3 || parts[0] != "GET" || !parts[2].starts_with("HTTP/1.") {
			bail!("fixed loopback fixture accepts bounded GET only");
		}
		let path = parts[1];
		let phase = state.phase.load(Ordering::SeqCst);
		let phase_name = if phase == 0 { "before" } else { "after" };
		let key = format!("{kind}:{phase_name}:{path}");
		let mut counts = state
			.counts
			.lock()
			.map_err(|_| anyhow::anyhow!("fixture count lock poisoned"))?;
		if counts.len() >= 80 && !counts.contains_key(&key) {
			bail!("loopback observation budget exceeded");
		}
		*counts.entry(key).or_default() += 1;
		drop(counts);
		let mut status = "200 OK";
		let mut mime = "text/plain";
		let mut truncated = false;
		let bytes: &[u8] = if kind == "probe" {
			b"owned-loopback-probe"
		} else if path == ENTRY {
			mime = "text/html; charset=utf-8";
			html
		} else if let Some(snapshot) = snapshots.iter().find(|s| s.resource.url_path == path) {
			mime = &snapshot.resource.mime_type;
			truncated = snapshot.resource.delivery == "truncated";
			let until = Instant::now() + Duration::from_millis(snapshot.resource.delay_ms);
			while Instant::now() < until && !state.stop.load(Ordering::Relaxed) {
				std::thread::sleep(Duration::from_millis(10));
			}
			if phase == 0 {
				&snapshot.before
			} else {
				&snapshot.after
			}
		} else {
			status = "404 Not Found";
			b"unknown fixed fixture resource"
		};
		let headers = format!("HTTP/1.1 {status}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", bytes.len() + usize::from(truncated));
		// A browser cancellation can close its socket while the fixture is writing.
		// Such transport failures are represented by CDP loadingFailed, not invented bodies.
		let _ = stream
			.write_all(headers.as_bytes())
			.and_then(|_| stream.write_all(bytes));
	}
	Ok(())
}
