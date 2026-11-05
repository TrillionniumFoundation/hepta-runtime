// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0

//! Preserve the frozen REA argument boundary without changing serde_json's map
//! representation or the transport used by other runtime tools.
//!
//! The SDK keeps framing, protocol parsing, responses and cancellation. A reader
//! copies at most one bounded raw line, never reads beyond that line into the
//! SDK's buffer, and hands its observations to that request's private Extensions.
//! There is no request-ID registry and no client-controlled metadata channel.

use std::{
	collections::HashSet,
	fmt,
	future::Future,
	io,
	pin::Pin,
	sync::{Arc, Mutex},
	task::{Context, Poll},
};

use rmcp::{
	model::{
		CallToolRequest, CallToolRequestParams, ClientRequest, ErrorData, GetExtensions,
		JsonRpcMessage,
	},
	service::{RxJsonRpcMessage, TxJsonRpcMessage},
	transport::{async_rw::AsyncRwTransport, Transport},
	RoleServer,
};
use serde::{
	de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor},
	Deserialize,
};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, BufReader, ReadBuf};

/// REA 6.8.0's actual Node STDIO default receive-buffer limit. This bounds the
/// adapter's extra raw copy; the original SDK's non-REA behavior is unchanged.
const MAX_CAPTURE_BYTES: usize = 10 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
	Missing,
	Null,
	Boolean,
	Number,
	String,
	Array,
	Object,
}

#[derive(Clone, Debug)]
struct OrderNode {
	kind: Kind,
	keys: Vec<String>,
	child: Option<Box<OrderNode>>,
	view: Option<Box<OrderNode>>,
	source: Option<Box<OrderNode>>,
}

impl OrderNode {
	fn scalar(kind: Kind) -> Self {
		Self {
			kind,
			keys: Vec::new(),
			child: None,
			view: None,
			source: None,
		}
	}
}

/// Only this module can construct these facts. Wire `_meta` cannot forge them.
/// The server must check `protocol_error()` before invoking the REA operation.
#[derive(Clone, Debug)]
pub(crate) struct ReaRawArguments {
	arguments: OrderNode,
	failure: Option<ErrorData>,
}

impl ReaRawArguments {
	/// Successful capture and JSON decoding prove that the complete request,
	/// including its ID, fit the raw frame limit. Argument shape is a separate
	/// decision: a non-object argument still needs a bounded protocol refusal.
	pub(crate) fn has_bounded_frame(&self) -> bool {
		self.failure.is_none()
	}

	/// JavaScript Object.keys order for arguments (`[]`), filters, static view or Evidence source.
	pub(crate) fn object_keys(&self, path: &[&str]) -> Option<&[String]> {
		let node = match path {
			[] => &self.arguments,
			["filters"] => self.arguments.child.as_deref()?,
			["view"] => self.arguments.view.as_deref()?,
			["source"] => self.arguments.source.as_deref()?,
			_ => return None,
		};
		(node.kind == Kind::Object).then_some(node.keys.as_slice())
	}

	/// The actual REA SDK rejects a present non-object arguments value at the
	/// JSON-RPC layer, including null (which rmcp otherwise treats as omitted).
	pub(crate) fn protocol_error(&self) -> Option<ErrorData> {
		if let Some(error) = &self.failure {
			return Some(error.clone());
		}
		let received = match self.arguments.kind {
			Kind::Missing | Kind::Object => return None,
			Kind::Null => "null",
			Kind::Boolean => "boolean",
			Kind::Number => "number",
			Kind::String => "string",
			Kind::Array => "array",
		};
		Some(ErrorData::invalid_params(
			format!(
				"Invalid tools/call request: [\n  {{\n    \"expected\": \"record\",\n    \"code\": \"invalid_type\",\n    \"path\": [\n      \"params\",\n      \"arguments\"\n    ],\n    \"message\": \"Invalid input: expected record, received {received}\"\n  }}\n]"
			),
			None,
		))
	}

	fn failed(message: &'static str) -> Self {
		Self {
			arguments: OrderNode::scalar(Kind::Missing),
			failure: Some(ErrorData::invalid_request(message, None)),
		}
	}

	fn from_line(line: CapturedLine) -> Self {
		let CapturedLine::Bytes(bytes) = line else {
			return Self::failed(
				"REA tools/call request exceeds the 10485760-byte raw argument boundary.",
			);
		};
		let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes);
		let mut decoder = serde_json::Deserializer::from_slice(bytes);
		let parsed = OrderScanner(0).deserialize(&mut decoder).and_then(|node| {
			decoder.end()?;
			Ok(node)
		});
		match parsed {
			Ok(root) => Self {
				arguments: root
					.child
					.and_then(|params| params.child)
					.map(|node| *node)
					.unwrap_or_else(|| OrderNode::scalar(Kind::Missing)),
				failure: None,
			},
			Err(_) => Self::failed(
				"REA raw argument boundary could not authenticate the received JSON frame.",
			),
		}
	}
}

// Retain only the four relevant object levels. Unrelated values are consumed by
// serde's JSON parser as IgnoredAny, including nested arrays and unknown objects.
struct OrderScanner(u8);

impl<'de> DeserializeSeed<'de> for OrderScanner {
	type Value = OrderNode;
	fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
		decoder.deserialize_any(self)
	}
}

impl<'de> Visitor<'de> for OrderScanner {
	type Value = OrderNode;
	fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("a JSON value")
	}
	fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
		Ok(OrderNode::scalar(Kind::Null))
	}
	fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
		self.visit_unit()
	}
	fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
		Ok(OrderNode::scalar(Kind::Boolean))
	}
	fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
		Ok(OrderNode::scalar(Kind::Number))
	}
	fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
		Ok(OrderNode::scalar(Kind::Number))
	}
	fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
		Ok(OrderNode::scalar(Kind::Number))
	}
	fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Self::Value, E> {
		Ok(OrderNode::scalar(Kind::String))
	}
	fn visit_string<E: serde::de::Error>(self, _: String) -> Result<Self::Value, E> {
		self.visit_str("")
	}
	fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
		while seq.next_element::<IgnoredAny>()?.is_some() {}
		Ok(OrderNode::scalar(Kind::Array))
	}
	fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
		let mut node = OrderNode::scalar(Kind::Object);
		let mut seen = HashSet::new();
		let next = match self.0 {
			0 => Some("params"),
			1 => Some("arguments"),
			2 => Some("filters"),
			_ => None,
		};
		while let Some(key) = map.next_key::<String>()? {
			if self.0 >= 2 && seen.insert(key.clone()) {
				node.keys.push(key.clone());
			}
			if next == Some(key.as_str()) {
				// JSON.parse retains a property's first position but its last value.
				node.child = Some(Box::new(map.next_value_seed(OrderScanner(self.0 + 1))?));
			} else if self.0 == 2 && key == "source" {
				node.source = Some(Box::new(map.next_value_seed(OrderScanner(3))?));
			} else if self.0 == 2 && key == "view" {
				node.view = Some(Box::new(map.next_value_seed(OrderScanner(3))?));
			} else {
				map.next_value::<IgnoredAny>()?;
			}
		}
		// Canonical array-index properties precede other string properties, in
		// numeric order. 2^32-1, leading zeros and -0 are ordinary string keys.
		node.keys
			.sort_by_key(|key| array_index(key).map_or((1, 0), |i| (0, i)));
		Ok(node)
	}
}

fn array_index(key: &str) -> Option<u32> {
	let value = key.parse::<u32>().ok()?;
	(value != u32::MAX && value.to_string() == key).then_some(value)
}

enum CapturedLine {
	Bytes(Vec<u8>),
	OverBudget,
}

type FrameSlot = Arc<Mutex<Option<CapturedLine>>>;

struct CapturingReader<R> {
	reader: BufReader<R>,
	partial: Vec<u8>,
	over_budget: bool,
	limit: usize,
	frame: FrameSlot,
}

impl<R> CapturingReader<R> {
	fn finish(&mut self) {
		let frame = if self.over_budget {
			CapturedLine::OverBudget
		} else {
			CapturedLine::Bytes(std::mem::take(&mut self.partial))
		};
		self.over_budget = false;
		*self.frame.lock().unwrap_or_else(|e| e.into_inner()) = Some(frame);
	}
}

impl<R: AsyncRead + Unpin> AsyncRead for CapturingReader<R> {
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		out: &mut ReadBuf<'_>,
	) -> Poll<io::Result<()>> {
		if out.remaining() == 0 {
			return Poll::Ready(Ok(()));
		}
		let this = &mut *self;
		let available = match Pin::new(&mut this.reader).poll_fill_buf(cx) {
			Poll::Pending => return Poll::Pending,
			Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
			Poll::Ready(Ok(available)) => available,
		};
		if available.is_empty() {
			if !this.partial.is_empty() || this.over_budget {
				this.finish();
			}
			return Poll::Ready(Ok(()));
		}
		// Never hand the SDK a byte from the next frame. Its read_until can now
		// return exactly the frame occupying the one slot, even after read-ahead.
		let count = available
			.iter()
			.position(|&b| b == b'\n')
			.map_or(available.len(), |i| i + 1)
			.min(out.remaining());
		let bytes = &available[..count];
		let complete = bytes.last() == Some(&b'\n');
		if !this.over_budget {
			if count > this.limit.saturating_sub(this.partial.len()) {
				this.over_budget = true;
				this.partial = Vec::new();
			} else {
				this.partial.extend_from_slice(bytes);
			}
		}
		out.put_slice(bytes);
		Pin::new(&mut this.reader).consume(count);
		if complete {
			this.finish();
		}
		Poll::Ready(Ok(()))
	}
}

/// STDIO adapter for explicitly selected frozen REA contracts. Other tool names and all
/// notifications, responses, parsing errors and outbound writes retain SDK behavior.
pub struct ReaMcpTransport<R: AsyncRead + Unpin, W: AsyncWrite> {
	inner: AsyncRwTransport<RoleServer, CapturingReader<R>, W>,
	frame: FrameSlot,
}

impl<R, W> ReaMcpTransport<R, W>
where
	R: AsyncRead + Send + Unpin,
	W: AsyncWrite + Send + Unpin + 'static,
{
	pub fn new(read: R, write: W) -> Self {
		Self::with_capture_budget(read, write, MAX_CAPTURE_BYTES)
	}

	fn with_capture_budget(read: R, write: W, limit: usize) -> Self {
		let frame = Arc::new(Mutex::new(None));
		Self {
			inner: AsyncRwTransport::new_server(
				CapturingReader {
					reader: BufReader::new(read),
					partial: Vec::new(),
					over_budget: false,
					limit,
					frame: Arc::clone(&frame),
				},
				write,
			),
			frame,
		}
	}
}

fn selected(name: &str) -> bool {
	matches!(
		name,
		"rea_inspect_elf_notes"
			| "rea_get_evidence_bundle"
			| "rea_inspect_apk_signature_evidence"
			| "rea_inspect_analysis_view"
			| "rea_export_evidence_bundle"
	)
}

fn attach(message: &mut RxJsonRpcMessage<RoleServer>, frame: Option<CapturedLine>) {
	let JsonRpcMessage::Request(message) = message else {
		return;
	};
	let eligible = match &message.request {
		ClientRequest::CallToolRequest(call) => selected(call.params.name.as_ref()),
		ClientRequest::CustomRequest(call) if call.method == "tools/call" => call
			.params
			.as_ref()
			.and_then(|params| params.get("name"))
			.and_then(serde_json::Value::as_str)
			.is_some_and(selected),
		_ => false,
	};
	if !eligible {
		return;
	}
	let raw = frame.map(ReaRawArguments::from_line).unwrap_or_else(|| {
		ReaRawArguments::failed(
			"REA raw argument boundary is unavailable for the received JSON frame.",
		)
	});
	if let ClientRequest::CustomRequest(custom) = &mut message.request {
		// The base SDK has already parsed the frame, but the adapter must not
		// allocate a second unbounded argument/metadata tree. Leave over-budget
		// fallbacks on the SDK rejection path, carrying the private failure for
		// an optional narrow custom-request handler to report directly.
		if raw.failure.is_some() {
			custom.extensions.insert(raw);
			return;
		}
		// rmcp's custom-method fallback otherwise changes an invalid tools/call
		// into -32601. Only repair the recognized non-object arguments shape;
		// other malformed protocol fields remain the SDK's responsibility.
		let Some(params) = custom.params.as_mut() else {
			return;
		};
		let Some(arguments) = params.get_mut("arguments") else {
			return;
		};
		if arguments.is_object() {
			return;
		}
		let original_arguments =
			std::mem::replace(arguments, serde_json::Value::Object(Default::default()));
		// Validate the remaining SDK fields while borrowing the existing tree.
		// The rejected argument can be a large string or array: move, never clone.
		let parsed = CallToolRequestParams::deserialize(&*params);
		if let Some(arguments) = params.get_mut("arguments") {
			*arguments = original_arguments;
		}
		let Ok(params) = parsed else {
			return;
		};
		let mut replacement = CallToolRequest::new(params);
		replacement.extensions = std::mem::take(&mut custom.extensions);
		message.request = ClientRequest::CallToolRequest(replacement);
	}
	message.request.extensions_mut().insert(raw);
}

impl<R, W> Transport<RoleServer> for ReaMcpTransport<R, W>
where
	R: AsyncRead + Send + Unpin,
	W: AsyncWrite + Send + Unpin + 'static,
{
	type Error = io::Error;
	fn send(
		&mut self,
		item: TxJsonRpcMessage<RoleServer>,
	) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
		self.inner.send(item)
	}
	async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
		let message = self.inner.receive().await;
		let frame = self.frame.lock().unwrap_or_else(|e| e.into_inner()).take();
		message.map(|mut message| {
			attach(&mut message, frame);
			message
		})
	}
	async fn close(&mut self) -> Result<(), Self::Error> {
		self.frame.lock().unwrap_or_else(|e| e.into_inner()).take();
		self.inner.close().await
	}
}

#[cfg(test)]
#[path = "rea_mcp_transport_tests.rs"]
mod tests;
