// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Keep the original producer's object order in both MCP representations.
//! The SDK's Value uses sorted maps. Only an admitted REA success whose unique
//! JSON text equals its complete structured value can reuse that text on wire.
//! No request identifier, metadata, or unrelated message is rewritten.

use rmcp::model::{CallToolResult, ServerResult};
use serde::{ser::SerializeMap, Deserialize, Serialize, Serializer};
use serde_json::{value::RawValue, Value};
use std::{
	io,
	pin::Pin,
	task::{Context, Poll},
};
use tokio::io::AsyncWrite;

fn supported(value: &Value) -> bool {
	if matches!(
		value.get("operation").and_then(Value::as_str),
		Some("inspect_elf_notes" | "inspect_apk_signature" | "inspect_analysis_view")
	) {
		return true;
	}
	let Some(bundle) = value.get("result").and_then(Value::as_object) else {
		return false;
	};
	if bundle.get("kind").and_then(Value::as_str) == Some("evidence-bundle-summary") {
		return true;
	}
	const KEYS: [&str; 7] = [
		"artifacts",
		"providers",
		"environments",
		"scenarios",
		"captures",
		"unknowns",
		"records",
	];
	bundle.len() == KEYS.len()
		&& KEYS
			.iter()
			.all(|key| bundle.get(*key).is_some_and(Value::is_array))
}

fn ordered_text(result: &CallToolResult) -> Option<&str> {
	if result.is_error == Some(true) {
		return None;
	}
	let structured = result.structured_content.as_ref()?;
	if !supported(structured) {
		return None;
	}
	let [content] = result.content.as_slice() else {
		return None;
	};
	let text = content.as_text()?.text.as_str();
	// Reject duplicate members and mismatches instead of using one
	// representation to conceal an invalid second representation.
	let parsed = super::rea_evidence::parse_unique_json(text.as_bytes()).ok()?;
	(parsed == *structured).then_some(text)
}

/// The final-frame guard uses exactly the representation the writer emits.
/// All optional SDK fields retain their values and presence rules.
pub(super) struct WireToolResult<'a>(pub(super) &'a CallToolResult);

pub(super) struct WireServerResult<'a>(pub(super) &'a ServerResult);

impl Serialize for WireServerResult<'_> {
	fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		match self.0 {
			ServerResult::CallToolResult(result) => WireToolResult(result).serialize(serializer),
			other => other.serialize(serializer),
		}
	}
}

impl Serialize for WireToolResult<'_> {
	fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		let Some(text) = ordered_text(self.0) else {
			return self.0.serialize(serializer);
		};
		let raw: &RawValue = serde_json::from_str(text).map_err(serde::ser::Error::custom)?;
		let mut map = serializer.serialize_map(None)?;
		if let Some(kind) = &self.0.result_type {
			map.serialize_entry("resultType", kind)?;
		}
		map.serialize_entry("content", &self.0.content)?;
		map.serialize_entry("structuredContent", raw)?;
		if let Some(error) = self.0.is_error {
			map.serialize_entry("isError", &error)?;
		}
		if let Some(meta) = &self.0.meta {
			map.serialize_entry("_meta", meta)?;
		}
		map.end()
	}
}

#[derive(Deserialize)]
struct Frame<'a> {
	#[serde(borrow)]
	result: Option<&'a RawValue>,
}

#[derive(Deserialize)]
struct StructuredField<'a> {
	#[serde(rename = "structuredContent", borrow)]
	structured: Option<&'a RawValue>,
}

fn rewrite(frame: &mut Vec<u8>, limit: usize) -> io::Result<()> {
	let replacement = (|| {
		let envelope: Frame<'_> = serde_json::from_slice(frame).ok()?;
		let result = envelope.result?;
		let field: StructuredField<'_> = serde_json::from_str(result.get()).ok()?;
		let structured = field.structured?;
		let result: CallToolResult = serde_json::from_str(result.get()).ok()?;
		let text = ordered_text(&result)?;
		if text == structured.get() {
			return None;
		}
		let start = (structured.get().as_ptr() as usize).checked_sub(frame.as_ptr() as usize)?;
		let end = start.checked_add(structured.get().len())?;
		if frame.get(start..end)? != structured.get().as_bytes() {
			return None;
		}
		Some((start..end, text.to_owned()))
	})();
	let Some((range, text)) = replacement else {
		return Ok(());
	};
	let size = frame
		.len()
		.checked_sub(range.len())
		.and_then(|size| size.checked_add(text.len()))
		.ok_or_else(|| io::Error::other("REA structured frame size overflow"))?;
	if size > limit {
		return Err(io::Error::other(
			"REA structured frame exceeded its final measured budget",
		));
	}
	frame
		.try_reserve(size.saturating_sub(frame.len()))
		.map_err(io::Error::other)?;
	frame.splice(range, text.bytes());
	Ok(())
}

/// One bounded JSON-RPC line is collected only until its first newline.
/// Larger unrelated SDK lines pass through without a second unbounded copy.
/// Accepted bytes stay owned across a cancelled send and are drained before
/// another message can write, preserving the SDK writer's framing lock.
pub(crate) struct StructuredWriter<W> {
	inner: W,
	line: Vec<u8>,
	pending: Vec<u8>,
	written: usize,
	passthrough: bool,
	limit: usize,
}

impl<W> StructuredWriter<W> {
	pub(crate) fn new(inner: W) -> Self {
		Self::with_limit(
			inner,
			super::rea_contract::response_budget().unwrap_or(super::rea_contract::RESPONSE_BYTES),
		)
	}

	fn with_limit(inner: W, limit: usize) -> Self {
		Self {
			inner,
			line: Vec::new(),
			pending: Vec::new(),
			written: 0,
			passthrough: false,
			limit,
		}
	}
}

impl<W: AsyncWrite + Unpin> StructuredWriter<W> {
	fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		while self.written < self.pending.len() {
			let count =
				match Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.written..]) {
					Poll::Pending => return Poll::Pending,
					Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
					Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
					Poll::Ready(Ok(count)) => count,
				};
			self.written += count;
		}
		self.pending.clear();
		self.written = 0;
		if self.line.is_empty() {
			std::mem::swap(&mut self.pending, &mut self.line);
		}
		Poll::Ready(Ok(()))
	}
}

impl<W: AsyncWrite + Unpin> AsyncWrite for StructuredWriter<W> {
	fn poll_write(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		bytes: &[u8],
	) -> Poll<io::Result<usize>> {
		let this = self.get_mut();
		if bytes.is_empty() {
			return Poll::Ready(Ok(0));
		}
		loop {
			match this.drain(cx) {
				Poll::Pending => return Poll::Pending,
				Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
				Poll::Ready(Ok(())) => {}
			}
			let count = bytes
				.iter()
				.position(|byte| *byte == b'\n')
				.map_or(bytes.len(), |index| index + 1);
			if this.passthrough {
				return match Pin::new(&mut this.inner).poll_write(cx, &bytes[..count]) {
					Poll::Ready(Ok(written)) => {
						if written == count && bytes[count - 1] == b'\n' {
							this.passthrough = false;
						}
						Poll::Ready(Ok(written))
					}
					other => other,
				};
			}
			if count > this.limit.saturating_sub(this.line.len()) {
				this.pending = std::mem::take(&mut this.line);
				this.passthrough = true;
				continue;
			}
			if let Err(error) = this.line.try_reserve(count) {
				return Poll::Ready(Err(io::Error::other(error)));
			}
			this.line.extend_from_slice(&bytes[..count]);
			if bytes[count - 1] == b'\n' {
				this.pending = std::mem::take(&mut this.line);
				if let Err(error) = rewrite(&mut this.pending, this.limit) {
					this.pending.clear();
					return Poll::Ready(Err(error));
				}
			}
			return Poll::Ready(Ok(count));
		}
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		let this = self.get_mut();
		match this.drain(cx) {
			Poll::Pending => return Poll::Pending,
			Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
			Poll::Ready(Ok(())) => {}
		}
		if !this.line.is_empty() {
			// An explicit flush of an incomplete line commits its original bytes;
			// no later fragment is allowed to rewrite already emitted content.
			this.pending = std::mem::take(&mut this.line);
			this.passthrough = true;
			match this.drain(cx) {
				Poll::Pending => return Poll::Pending,
				Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
				Poll::Ready(Ok(())) => {}
			}
		}
		Pin::new(&mut this.inner).poll_flush(cx)
	}

	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		match self.as_mut().poll_flush(cx) {
			Poll::Ready(Ok(())) => Pin::new(&mut self.get_mut().inner).poll_shutdown(cx),
			other => other,
		}
	}
}

#[cfg(test)]
#[path = "rea_structured_wire_tests.rs"]
mod tests;
