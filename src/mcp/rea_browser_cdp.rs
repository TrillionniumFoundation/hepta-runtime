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
//! Bounded NUL-delimited CDP transport, request gate and response observations.

use super::input::{sha256, MAX_BODY, MAX_TOTAL_BODY};
use super::process::check_cancelled;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::Instant;

const MAX_MESSAGES: usize = 2048;
const MAX_MESSAGE: usize = 256 * 1024;
const MAX_RECEIVED: usize = 8 * 1024 * 1024;

#[derive(Clone)]
struct Observation {
	id: String,
	request: Value,
	response: Option<Value>,
	start: f64,
	wall: f64,
	end: Option<f64>,
	finished: bool,
	failed: Option<String>,
}

#[derive(Debug)]
struct ProtocolError(String);
impl std::fmt::Display for ProtocolError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(&self.0)
	}
}
impl std::error::Error for ProtocolError {}

#[derive(Debug)]
struct CleanPipeClosed;
impl std::fmt::Display for CleanPipeClosed {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("owned Chrome CDP pipe closed before response")
	}
}
impl std::error::Error for CleanPipeClosed {}

pub(super) struct Cdp {
	stream: UnixStream,
	deadline: Instant,
	buffer: Vec<u8>,
	next_id: u64,
	ignored: BTreeSet<u64>,
	pub session: Option<String>,
	pub phase: String,
	allowed: BTreeSet<String>,
	pub denied: Vec<Value>,
	rows: Vec<Observation>,
	messages: usize,
	received: usize,
	body_bytes: usize,
	phase_settled: bool,
}

impl Cdp {
	pub fn new(stream: UnixStream, deadline: Instant, allowed: BTreeSet<String>) -> Self {
		Self {
			stream,
			deadline,
			buffer: Vec::new(),
			next_id: 1,
			ignored: BTreeSet::new(),
			session: None,
			phase: String::new(),
			allowed,
			denied: Vec::new(),
			rows: Vec::new(),
			messages: 0,
			received: 0,
			body_bytes: 0,
			phase_settled: false,
		}
	}

	fn wait_ready(&self, events: i16) -> Result<()> {
		check_cancelled()?;
		if Instant::now() >= self.deadline {
			bail!("fixed browser capture deadline exceeded");
		}
		let remaining = self
			.deadline
			.saturating_duration_since(Instant::now())
			.as_millis()
			.min(100) as i32;
		let mut poll = libc::pollfd {
			fd: self.stream.as_raw_fd(),
			events,
			revents: 0,
		};
		// SAFETY: one valid pollfd, with a finite cancellation observation interval.
		let result = unsafe { libc::poll(&mut poll, 1, remaining) };
		if result < 0 {
			let error = std::io::Error::last_os_error();
			if error.kind() != std::io::ErrorKind::Interrupted {
				return Err(error.into());
			}
		}
		Ok(())
	}

	pub fn send(&mut self, method: &str, params: Value) -> Result<u64> {
		self.send_to(method, params, self.session.clone())
	}

	// Command routing is separate from the target session whose events are observed.
	fn send_to(&mut self, method: &str, params: Value, session: Option<String>) -> Result<u64> {
		check_cancelled()?;
		let id = self.next_id;
		self.next_id += 1;
		if id > 2048 {
			bail!("CDP command budget exceeded");
		}
		let mut command = json!({"id":id,"method":method,"params":params});
		if let Some(session) = session {
			command["sessionId"] = Value::String(session);
		}
		let mut bytes = serde_json::to_vec(&command)?;
		if bytes.len() > MAX_MESSAGE {
			bail!("CDP command byte budget exceeded");
		}
		bytes.push(0);
		let mut offset = 0;
		while offset < bytes.len() {
			self.wait_ready(libc::POLLOUT)?;
			match self.stream.write(&bytes[offset..]) {
				Ok(0) => bail!("owned Chrome CDP pipe closed during command"),
				Ok(count) => offset += count,
				Err(error)
					if matches!(
						error.kind(),
						std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
					) =>
				{
					continue
				}
				Err(error) => return Err(error).context("owned Chrome CDP write failed"),
			}
		}
		Ok(id)
	}

	fn next_message(&mut self) -> Result<Value> {
		loop {
			check_cancelled()?;
			if let Some(end) = self.buffer.iter().position(|b| *b == 0) {
				if end > MAX_MESSAGE {
					bail!("CDP message byte budget exceeded");
				}
				let value = serde_json::from_slice(&self.buffer[..end])
					.context("invalid CDP JSON message")?;
				self.buffer.drain(..=end);
				self.messages += 1;
				if self.messages > MAX_MESSAGES {
					bail!("CDP event/response count exceeded");
				}
				return Ok(value);
			}
			if self.buffer.len() > MAX_MESSAGE {
				bail!("unterminated CDP message byte budget exceeded");
			}
			self.wait_ready(libc::POLLIN)?;
			let mut bytes = [0u8; 8192];
			match self.stream.read(&mut bytes) {
				Ok(0) if self.buffer.is_empty() => return Err(CleanPipeClosed.into()),
				Ok(0) => bail!("owned Chrome CDP pipe closed with an incomplete message"),
				Ok(count) => {
					self.received += count;
					if self.received > MAX_RECEIVED {
						bail!("CDP total received byte budget exceeded");
					}
					self.buffer.extend_from_slice(&bytes[..count]);
				}
				Err(error)
					if matches!(
						error.kind(),
						std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
					) =>
				{
					continue
				}
				Err(error) => return Err(error).context("owned Chrome CDP read failed"),
			}
		}
	}

	pub fn call(&mut self, method: &str, params: Value) -> Result<Value> {
		let id = self.send(method, params)?;
		loop {
			let message = self
				.next_message()
				.with_context(|| format!("waiting for CDP command {method}"))?;
			if let Some(result) = self.handle_message(&message, Some(id))? {
				return Ok(result);
			}
		}
	}

	/// Drain through clean pipe closure on the original capture deadline. Chrome
	/// may close without acknowledging Browser.close, but protocol, request-gate,
	/// cancellation and budget errors must never become an unacknowledged success.
	pub fn close_browser(&mut self) -> Result<bool> {
		self.require_settled()?;
		let id = self
			.send_to("Browser.close", json!({}), None)
			.context("sending browser-level close command")?;
		let mut acknowledged = false;
		loop {
			check_cancelled()?;
			if Instant::now() >= self.deadline {
				bail!("fixed browser capture deadline exceeded while closing browser");
			}
			match self.next_message() {
				Ok(message) => {
					if self
						.handle_message(&message, (!acknowledged).then_some(id))?
						.is_some()
					{
						acknowledged = true;
					}
				}
				Err(error) if error.downcast_ref::<CleanPipeClosed>().is_some() => {
					check_cancelled()?;
					if Instant::now() >= self.deadline {
						bail!("fixed browser capture deadline exceeded while closing browser");
					}
					self.require_settled()?;
					return Ok(acknowledged);
				}
				Err(error) => return Err(error).context("draining browser close observations"),
			}
		}
	}

	/// Share response identity/error checks between commands and the phase drain.
	fn handle_message(&mut self, message: &Value, awaited: Option<u64>) -> Result<Option<Value>> {
		if let Some(reply_id) = message.get("id") {
			let reply_id = reply_id.as_u64().context("invalid CDP response identity")?;
			let gate = self.ignored.remove(&reply_id);
			if Some(reply_id) != awaited && !gate {
				bail!("unexpected CDP command response identity");
			}
			if let Some(error) = message.get("error") {
				if message.get("result").is_some() {
					bail!("CDP response contains both result and error");
				}
				let description = error
					.get("message")
					.and_then(Value::as_str)
					.context("invalid CDP error response")?
					.chars()
					.take(512)
					.collect::<String>();
				if gate {
					bail!("CDP request gate acknowledgement failed: {description}");
				}
				return Err(ProtocolError(description).into());
			}
			let result = message
				.get("result")
				.filter(|value| value.is_object())
				.context("CDP response lacks an object result")?;
			if Some(reply_id) == awaited {
				return Ok(Some(result.clone()));
			}
		} else {
			self.event(message)?;
		}
		Ok(None)
	}

	/// Wait for every selected URL occurrence and its terminal loading event.
	/// A resolved page promise is not a CDP event barrier. No new deadline is set.
	pub fn settle_requests(&mut self, expected_urls: &[String]) -> Result<()> {
		if expected_urls.is_empty() || expected_urls.len() > 64 {
			bail!("fixed browser request occurrence bound refused");
		}
		let mut expected = BTreeMap::new();
		for url in expected_urls {
			if url.len() > 4096 {
				bail!("expected browser request URL exceeds bound");
			}
			*expected.entry(url.as_str()).or_insert(0usize) += 1;
		}
		self.phase_settled = false;
		loop {
			check_cancelled()?;
			if Instant::now() >= self.deadline {
				bail!("fixed browser capture deadline exceeded while settling request occurrences");
			}
			let mut observed = BTreeMap::new();
			let mut terminal = true;
			for row in &self.rows {
				let url = row
					.request
					.get("url")
					.and_then(Value::as_str)
					.context("observed browser request URL missing")?;
				let count = observed.entry(url).or_insert(0usize);
				*count += 1;
				if *count > expected.get(url).copied().unwrap_or(0) {
					bail!("unexpected browser request occurrence while settling fixed capture");
				}
				if row.finished && row.failed.is_some() {
					bail!("contradictory terminal browser loading events");
				}
				terminal &= row.finished || row.failed.is_some();
			}
			if observed == expected && terminal && self.ignored.is_empty() {
				self.phase_settled = true;
				return Ok(());
			}
			let message = self
				.next_message()
				.context("waiting for fixed browser request terminals and gate acknowledgements")?;
			self.handle_message(&message, None)?;
		}
	}

	pub fn require_settled(&self) -> Result<()> {
		if !self.phase_settled || !self.ignored.is_empty() {
			bail!("browser phase is unsettled or has unconfirmed request gate acknowledgements");
		}
		Ok(())
	}

	fn event(&mut self, message: &Value) -> Result<()> {
		let Some(method) = message.get("method").and_then(Value::as_str) else {
			bail!("CDP message lacks response ID or method");
		};
		let params = message
			.get("params")
			.filter(|value| value.is_object())
			.context("CDP event lacks object params")?;
		if message.get("sessionId").and_then(Value::as_str) != self.session.as_deref() {
			return Ok(());
		}
		if method == "Fetch.requestPaused" {
			self.phase_settled = false;
			let url = params
				.pointer("/request/url")
				.and_then(Value::as_str)
				.context("paused request has no URL")?;
			let method = params
				.pointer("/request/method")
				.and_then(Value::as_str)
				.context("paused request has no method")?;
			let request_id = params
				.get("requestId")
				.and_then(Value::as_str)
				.context("paused request has no identity")?;
			if url.len() > 4096 || request_id.len() > 256 {
				bail!("paused request identity exceeds bound");
			}
			let id = if method == "GET" && self.allowed.contains(url) {
				self.send("Fetch.continueRequest", json!({"requestId":request_id}))?
			} else {
				if self.denied.len() >= 64 {
					bail!("denied browser request observation budget exceeded");
				}
				self.denied
					.push(json!({"phase":self.phase,"url":url,"method":method}));
				self.send(
					"Fetch.failRequest",
					json!({"requestId":request_id,"errorReason":"AccessDenied"}),
				)?
			};
			self.ignored.insert(id);
			return Ok(());
		}
		if !method.starts_with("Network.") {
			return Ok(());
		}
		let Some(id) = params.get("requestId").and_then(Value::as_str) else {
			return Ok(());
		};
		if id.len() > 256 {
			bail!("network request identity exceeds bound");
		}
		if method == "Network.requestWillBeSent" {
			let request = params.get("request").context("network request missing")?;
			let url = request
				.get("url")
				.and_then(Value::as_str)
				.context("network URL missing")?;
			if url.starts_with("data:") {
				return Ok(());
			}
			self.phase_settled = false;
			if self.rows.len() >= 64
				|| url.len() > 4096
				|| request.get("method").and_then(Value::as_str) != Some("GET")
				|| self.rows.iter().any(|row| row.id == id)
			{
				bail!("network request/redirect exceeds fixed capture contract");
			}
			self.rows.push(Observation {
				id: id.into(),
				request: request.clone(),
				response: None,
				start: finite(params, "timestamp")?,
				wall: finite(params, "wallTime")?,
				end: None,
				finished: false,
				failed: None,
			});
		} else if let Some(row) = self.rows.iter_mut().find(|row| row.id == id) {
			match method {
				"Network.responseReceived" => {
					self.phase_settled = false;
					row.response = Some(
						params
							.get("response")
							.context("network response missing")?
							.clone(),
					)
				}
				"Network.loadingFinished" => {
					self.phase_settled = false;
					row.finished = true;
					row.end = Some(finite(params, "timestamp")?);
				}
				"Network.loadingFailed" => {
					self.phase_settled = false;
					row.end = Some(finite(params, "timestamp")?);
					row.failed = Some(
						params
							.get("errorText")
							.and_then(Value::as_str)
							.unwrap_or("loading failed")
							.chars()
							.take(256)
							.collect(),
					);
				}
				_ => (),
			}
		}
		Ok(())
	}

	pub fn begin_phase(&mut self, phase: &str) -> Result<()> {
		if !self.phase.is_empty() {
			self.require_settled()?;
		}
		self.phase = phase.into();
		self.rows.clear();
		self.phase_settled = false;
		Ok(())
	}

	pub fn har(&mut self) -> Result<(Value, Value)> {
		self.require_settled()?;
		let rows = self.rows.clone();
		let mut entries = Vec::new();
		let mut states = BTreeMap::new();
		for row in &rows {
			let response = row.response.clone().unwrap_or_else(|| json!({}));
			let mut content =
				json!({"mimeType":response.get("mimeType").and_then(Value::as_str).unwrap_or("")});
			let mut state = "missing";
			let mut reason = row.failed.clone().unwrap_or_else(|| {
				"response body not available in the bounded capture window".into()
			});
			let mut representation = None;
			let mut decoded = None;
			if row.finished {
				match self.call("Network.getResponseBody", json!({"requestId":row.id})) {
					Ok(body) => {
						let text = body
							.get("body")
							.and_then(Value::as_str)
							.context("CDP response body must be a string")?;
						let encoded = body
							.get("base64Encoded")
							.and_then(Value::as_bool)
							.context("CDP response body encoding must be boolean")?;
						if text.len() > MAX_BODY * 2 {
							bail!("encoded response body exceeds budget");
						}
						let bytes = if encoded {
							decode_base64(text)?
						} else {
							text.as_bytes().to_vec()
						};
						if bytes.len() > MAX_BODY {
							bail!("decoded response body exceeds budget");
						}
						self.body_bytes += bytes.len();
						if self.body_bytes > MAX_TOTAL_BODY {
							bail!("combined response body budget exceeded");
						}
						content["text"] = json!(text);
						content["size"] = json!(bytes.len());
						if encoded {
							content["encoding"] = json!("base64");
						}
						state = if bytes.is_empty() {
							"empty"
						} else if encoded {
							"base64"
						} else {
							"complete"
						};
						reason.clear();
						representation = Some(sha256(text.as_bytes()));
						decoded = Some(sha256(&bytes));
					}
					Err(error) if error.downcast_ref::<ProtocolError>().is_some() => {
						reason = format!("CDP body unavailable: {error}");
					}
					Err(error) => return Err(error),
				}
			}
			*states.entry(state).or_insert(0usize) += 1;
			let missing = if state == "missing" {
				json!(reason)
			} else {
				Value::Null
			};
			let headers = headers(response.get("headers"))?;
			let status = response
				.get("status")
				.and_then(Value::as_f64)
				.unwrap_or(0.0);
			if !status.is_finite() || !(0.0..=599.0).contains(&status) || status.fract() != 0.0 {
				bail!("invalid observed HTTP status");
			}
			entries.push(json!({
				"startedDateTime":wall_time(row.wall)?, "time":((row.end.unwrap_or(row.start) - row.start).max(0.0) * 1000.0),
				"request":{"method":"GET","url":row.request["url"],"httpVersion":"HTTP/1.1","cookies":[],"headers":self::headers(row.request.get("headers"))?,"queryString":[],"headersSize":-1,"bodySize":0},
				"response":{"status":status as u16,"statusText":response.get("statusText").and_then(Value::as_str).unwrap_or(""),"httpVersion":response.get("protocol").and_then(Value::as_str).unwrap_or(""),"cookies":[],"headers":headers,"content":content,"redirectURL":"","headersSize":-1,"bodySize":-1},
				"cache":{},"timings":{"send":0,"wait":0,"receive":0},
				"_hepta":{"body_state":state,"body_missing_reason":missing,"representation_sha256":representation,"decoded_representation_sha256":decoded,"network_loading_complete":row.finished,"raw_wire_body_identity":false}
			}));
		}
		if rows.len() != self.rows.len() {
			bail!("late browser requests arrived during body collection");
		}
		self.require_settled()?;
		let coverage = json!({"entry_count":entries.len(),"body_states":states,"every_response_body_recorded":!states.contains_key("missing")});
		Ok((
			json!({"log":{"version":"1.2","creator":{"name":"Hepta fixed local browser capture","version":"1"},"entries":entries}}),
			coverage,
		))
	}

	pub fn stats(&self) -> Value {
		json!({"transport":"native-cdp-pipe-asciiz","messages_received":self.messages,"bytes_received":self.received,"commands_sent":self.next_id - 1,"decoded_body_bytes":self.body_bytes,"max_messages":MAX_MESSAGES,"max_message_bytes":MAX_MESSAGE,"max_received_bytes":MAX_RECEIVED})
	}
}

fn finite(value: &Value, field: &str) -> Result<f64> {
	let value = value
		.get(field)
		.and_then(Value::as_f64)
		.context("CDP timestamp missing")?;
	if !value.is_finite() || value < 0.0 {
		bail!("invalid CDP timestamp");
	}
	Ok(value)
}

fn headers(value: Option<&Value>) -> Result<Vec<Value>> {
	let Some(headers) = value.and_then(Value::as_object) else {
		return Ok(Vec::new());
	};
	if headers.len() > 128 {
		bail!("HAR header count exceeds bound");
	}
	let mut result = Vec::new();
	for (name, value) in headers {
		let value = value.as_str().context("CDP header value must be string")?;
		if name.len() > 256 || value.len() > 8192 {
			bail!("HAR header bytes exceed bound");
		}
		result.push(json!({"name":name,"value":value}));
	}
	result.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
	Ok(result)
}

fn wall_time(seconds: f64) -> Result<String> {
	if !(0.0..=253_402_300_799.0).contains(&seconds) {
		bail!("HAR wall clock is out of range");
	}
	let seconds_int = seconds.floor() as libc::time_t;
	let mut result: libc::tm = unsafe { std::mem::zeroed() };
	// SAFETY: both pointers refer to valid initialized objects; gmtime_r has no global state.
	if unsafe { libc::gmtime_r(&seconds_int, &mut result) }.is_null() {
		bail!("HAR UTC timestamp conversion failed");
	}
	Ok(format!(
		"{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
		result.tm_year + 1900,
		result.tm_mon + 1,
		result.tm_mday,
		result.tm_hour,
		result.tm_min,
		result.tm_sec,
		((seconds - seconds.floor()) * 1000.0).floor() as u32
	))
}

pub(super) fn decode_base64(text: &str) -> Result<Vec<u8>> {
	let input = text.as_bytes();
	if !input.len().is_multiple_of(4) {
		bail!("invalid base64 response length");
	}
	let mut output = Vec::with_capacity(input.len() / 4 * 3);
	for (index, group) in input.chunks_exact(4).enumerate() {
		let last = (index + 1) * 4 == input.len();
		let digit = |b| -> Result<u8> {
			match b {
				b'A'..=b'Z' => Ok(b - b'A'),
				b'a'..=b'z' => Ok(b - b'a' + 26),
				b'0'..=b'9' => Ok(b - b'0' + 52),
				b'+' => Ok(62),
				b'/' => Ok(63),
				_ => bail!("invalid base64 response alphabet"),
			}
		};
		let a = digit(group[0])?;
		let b = digit(group[1])?;
		output.push((a << 2) | (b >> 4));
		if group[2] == b'=' {
			if !last || group[3] != b'=' || b & 15 != 0 {
				bail!("invalid base64 response padding");
			}
			continue;
		}
		let c = digit(group[2])?;
		output.push((b << 4) | (c >> 2));
		if group[3] == b'=' {
			if !last || c & 3 != 0 {
				bail!("invalid base64 response padding");
			}
			continue;
		}
		output.push((c << 6) | digit(group[3])?);
	}
	Ok(output)
}
