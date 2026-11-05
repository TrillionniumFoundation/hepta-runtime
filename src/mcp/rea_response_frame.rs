// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Final native STDIO frame accounting after the complete SDK service boundary.
//!
//! The original REA chunk budget is separate. This guard includes the actual
//! SDK result discriminator, runtime metadata, exact request ID and newline.
//! It also covers SDK protocol errors produced before `ServerHandler::call_tool`.
//! Only the five explicitly named tools with successful private raw admission
//! are covered. Other requests and transports without that admission pass through.

use super::rea_contract::{self, Failure};
use super::rea_mcp_transport::ReaRawArguments;
use rmcp::model::{
	CallToolResult, ClientNotification, ClientRequest, ErrorData, JsonRpcResponse,
	JsonRpcVersion2_0, ProtocolVersion, RequestId, ServerConfig, ServerResult,
};
use rmcp::service::{NotificationContext, RequestContext, Service};
use rmcp::RoleServer;
use serde::Serialize;
use serde_json::{json, Value};
use std::borrow::Cow;
use std::io::{self, Write};

/// Place this outside the SDK's `ServerHandler` to `Service` adapter.
///
/// Capturing the private admission facts before moving the request into the SDK
/// avoids a request-ID registry and includes protocol refusals, final runtime
/// audit/retention acknowledgements, and SDK legacy-version normalization.
#[derive(Clone)]
pub struct ReaFramedService<S> {
	inner: S,
}

impl<S> ReaFramedService<S> {
	pub fn new(inner: S) -> Self {
		Self { inner }
	}
}

impl<S: Service<RoleServer>> Service<RoleServer> for ReaFramedService<S> {
	async fn handle_request(
		&self,
		request: ClientRequest,
		context: RequestContext<RoleServer>,
	) -> Result<ServerResult, ErrorData> {
		let frame = match &request {
			ClientRequest::CallToolRequest(call) => {
				FrameContext::for_request(call.params.name.as_ref(), &context)
			}
			_ => None,
		};
		let result = self.inner.handle_request(request, context).await;
		match frame {
			Some(frame) => frame.finish(result),
			None => result,
		}
	}

	async fn handle_notification(
		&self,
		notification: ClientNotification,
		context: NotificationContext<RoleServer>,
	) -> Result<(), ErrorData> {
		self.inner.handle_notification(notification, context).await
	}

	fn get_info(&self) -> ServerConfig {
		self.inner.get_info()
	}

	fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
		self.inner.supported_protocol_versions()
	}
}

struct FrameContext {
	operation: &'static str,
	id: RequestId,
	modern: bool,
	limit: usize,
}

struct Counter {
	bytes: usize,
	limit: usize,
	exceeded: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum CountFailure {
	Overflow(usize),
	Encoding,
}

impl Write for Counter {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		self.bytes = self.bytes.saturating_add(bytes.len());
		if self.bytes > self.limit {
			self.exceeded = true;
			return Err(io::Error::other("Native MCP frame exceeds response budget"));
		}
		Ok(bytes.len())
	}

	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

/// The borrowed equivalent of SDK `JsonRpcError`, whose error field is owned.
/// Using a borrow avoids cloning an arbitrarily large original error's data.
/// All guarded requests have a known ID, so its SDK `Option` is always `Some`.
#[derive(Serialize)]
struct ErrorFrame<'a> {
	jsonrpc: JsonRpcVersion2_0,
	id: Option<&'a RequestId>,
	error: &'a ErrorData,
}

impl FrameContext {
	fn for_request(name: &str, context: &RequestContext<RoleServer>) -> Option<Self> {
		let operation = match name {
			"rea_inspect_elf_notes" => "inspect_elf_notes",
			"rea_inspect_apk_signature_evidence" => "inspect_apk_signature",
			"rea_inspect_analysis_view" => "inspect_analysis_view",
			"rea_get_evidence_bundle" => "get_evidence_bundle",
			"rea_export_evidence_bundle" => "export_evidence_bundle",
			_ => return None,
		};
		// These facts can only be constructed by the bounded raw STDIO reader.
		// The proof covers the entire admitted tools/call line, including ID.
		if context
			.extensions
			.get::<ReaRawArguments>()?
			.protocol_error()
			.is_some()
		{
			return None;
		}
		Some(Self {
			operation,
			id: context.id.clone(),
			modern: context
				.protocol_version()
				.is_some_and(|version| version >= ProtocolVersion::V_2026_07_28),
			limit: rea_contract::response_budget().unwrap_or(rea_contract::RESPONSE_BYTES),
		})
	}

	fn count<T: Serialize>(&self, value: &T) -> Result<usize, CountFailure> {
		let mut counter = Counter {
			bytes: 1, // AsyncRwTransport's terminating LF.
			limit: self.limit,
			exceeded: false,
		};
		match serde_json::to_writer(&mut counter, value) {
			Ok(()) => Ok(counter.bytes),
			Err(_) if counter.exceeded => Err(CountFailure::Overflow(counter.bytes)),
			Err(_) => Err(CountFailure::Encoding),
		}
	}

	fn count_result(&self, result: &ServerResult) -> Result<usize, CountFailure> {
		self.count(&JsonRpcResponse {
			jsonrpc: JsonRpcVersion2_0,
			id: self.id.clone(),
			result,
		})
	}

	fn count_error(&self, error: &ErrorData) -> Result<usize, CountFailure> {
		self.count(&ErrorFrame {
			jsonrpc: JsonRpcVersion2_0,
			id: Some(&self.id),
			error,
		})
	}

	fn normalize_replacement(&self, result: &mut CallToolResult) {
		// The SDK already normalized the original response. A new replacement
		// is made after that boundary, so apply the identical legacy rule here.
		if !self.modern
			&& result
				.result_type
				.as_ref()
				.is_some_and(|kind| kind.is_complete())
		{
			result.result_type = None;
		}
	}

	fn minimal_error(&self, message: &'static str) -> Result<ServerResult, ErrorData> {
		let error = ErrorData::internal_error(message, None);
		if self.count_error(&error).is_ok() {
			return Err(error);
		}
		let minimal = ErrorData::internal_error("", None);
		// An admitted SDK RequestId is i64 or a valid Unicode string. Re-encoding
		// it cannot exceed its valid input token. This same-ID error has fewer
		// fixed bytes than the shortest recognized tools/call envelope. The raw
		// input ceiling is 10 MiB and every valid response budget is >= 10 MiB.
		// Therefore the minimal frame always fits on this private-admission
		// path. If an internal change breaks that proof, fail before returning
		// a serializable frame; never silently emit an over-budget fallback.
		assert!(
			self.count_error(&minimal).is_ok(),
			"REA private frame admission invariant violated"
		);
		Err(minimal)
	}

	fn finish_error(&self, error: ErrorData) -> Result<ServerResult, ErrorData> {
		match self.count_error(&error) {
			Ok(_) => Err(error),
			Err(CountFailure::Encoding) => {
				self.minimal_error("Native response serialization failed")
			}
			Err(CountFailure::Overflow(_)) => {
				self.minimal_error("Response exceeds the configured frame budget")
			}
		}
	}

	fn oversized_complete(
		&self,
		mut complete: CallToolResult,
		lower_bound: usize,
	) -> Result<ServerResult, ErrorData> {
		let mut limits = json!({"boundary":"native-mcp-frame","max_frame_bytes":self.limit,
            "frame_bytes_at_least":lower_bound,"includes_request_id":true,"includes_newline":true});
		if let Some(id) = complete
			.structured_content
			.as_ref()
			.and_then(|value| value.get("evidence_id"))
			.and_then(Value::as_str)
			.filter(|id| {
				id.len() == 67
					&& id.starts_with("ev_")
					&& id.as_bytes()[3..]
						.iter()
						.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
			}) {
			limits["evidence_id"] = json!(id);
			limits["evidence_reference"] = json!({"kind":"retained-evidence","evidence_id":id});
		}
		let metadata = complete.meta.take();
		drop(complete);
		let mut refusal = Failure::resource(
            self.operation,
            "transport",
            "The complete native MCP frame exceeds its configured byte budget. The completed result was not truncated.",
            limits,
            false,
            "Use a shorter request identifier and retrieve or export the retained Evidence.",
        )
        .wire();
		// Move the already finalized metadata, including any runtime identity
		// or audit acknowledgement. Content-free exports remain metadata-free
		// when the original result was; no target provenance is invented.
		refusal.meta = metadata;
		self.normalize_replacement(&mut refusal);
		let result = ServerResult::CallToolResult(refusal);
		match self.count_result(&result) {
			Ok(_) => Ok(result),
			Err(CountFailure::Encoding) => {
				self.minimal_error("Native response serialization failed")
			}
			Err(CountFailure::Overflow(_)) => {
				self.minimal_error("Response exceeds the configured frame budget")
			}
		}
	}

	fn finish(&self, result: Result<ServerResult, ErrorData>) -> Result<ServerResult, ErrorData> {
		match result {
			Ok(ServerResult::CallToolResult(complete)) => {
				let result = ServerResult::CallToolResult(complete);
				match self.count_result(&result) {
					Ok(_) => Ok(result),
					Err(CountFailure::Encoding) => {
						self.minimal_error("Native response serialization failed")
					}
					Err(CountFailure::Overflow(bytes)) => {
						let ServerResult::CallToolResult(complete) = result else {
							unreachable!("matched complete result")
						};
						self.oversized_complete(complete, bytes)
					}
				}
			}
			// These five contracts are synchronous complete tools. Task,
			// input-required and every other unexpected result variant must
			// become a bounded protocol error, not escape accounting.
			Ok(_) => self.finish_error(ErrorData::internal_error(
				"Selected REA tools require a complete synchronous tool result",
				None,
			)),
			Err(error) => self.finish_error(error),
		}
	}
}

#[cfg(test)]
#[path = "rea_response_frame_tests.rs"]
mod tests;
