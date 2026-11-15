// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Exact original result metadata functions and SDK projection transport.
use rmcp::model::{CallToolResponse, CallToolResult, CreateTaskResult, ErrorData, MetaObject};
use serde_json::{json, Value};
use std::io::{BufRead, Write};
mod json_size;
use json_size::serialized_json_size;
pub const ID_META: &str = "io.hepta.runtime/request-v8";
pub const ACK_META: &str = "io.hepta.runtime/retention-v8";
pub fn eligible(tool: &str) -> bool {
	matches!(tool, "host_list" | "host_health" | "effective_config")
}
fn identity_value(id: &str) -> Value {
	json!({"request_id":id,"automatic_retry":false,"delivery_proven":false})
}
pub fn exposes_identity(tool: &str) -> bool {
	eligible(tool)
		|| matches!(
			tool,
			"request_status" | "request_result" | "request_start" | "request_cancel"
		)
}
pub fn reserve_final_wire(result: &mut Result<CallToolResponse, ErrorData>, tool: &str, id: &str) {
	let cap = match tool {
		"effective_config" => 256 * 1024,
		"request_status" | "request_result" | "request_start" | "request_cancel" => 64 * 1024,
		_ => return,
	};
	let mut candidate = result.clone();
	attach_ack(&mut candidate, "durability_unknown_not_dispatched", false);
	let too_large = match candidate {
		Ok(CallToolResponse::Complete(ref value)) => {
			serialized_json_size(value).map_or(true, |size| size > cap)
		}
		_ => false,
	};
	if too_large {
		*result = Err(ErrorData::internal_error(
			"read-only original result exceeds final wire budget; original result was not retained",
			None,
		));
		attach_identity(result, id);
	}
}
pub fn attach_identity(result: &mut Result<CallToolResponse, ErrorData>, id: &str) {
	let mut marker = identity_value(id);
	match result {
		Ok(CallToolResponse::Complete(value)) => {
			let meta = value.meta.get_or_insert_with(MetaObject::new);
			if let Some(original) = meta.remove(ID_META) {
				marker["original_metadata"] = original;
			}
			meta.insert(ID_META.into(), marker);
		}
		Err(error) => {
			let original = error.data.take();
			let mut data = match original {
				Some(Value::Object(mut value)) => {
					if let Some(prior) = value.remove(ID_META) {
						marker["original_metadata"] = prior;
					}
					Value::Object(value)
				}
				Some(value) => json!({"original_error_data":value}),
				None => json!({}),
			};
			data[ID_META] = marker;
			error.data = Some(data);
		}
		_ => {}
	}
}
pub fn attach_ack(
	result: &mut Result<CallToolResponse, ErrorData>,
	state: &str,
	audit_durable: bool,
) {
	let ack = json!({"result_state":state,"audit_completion_durable":audit_durable,
		"semantics":"native_generated_result_before_retention_ack_and_transport_normalization; delivery unproven","automatic_retry":false});
	match result {
		Ok(CallToolResponse::Complete(value)) => {
			let meta = value.meta.get_or_insert_with(MetaObject::new);
			let mut ack = ack;
			if let Some(original) = meta.remove(ACK_META) {
				ack["original_metadata"] = original;
			}
			meta.insert(ACK_META.into(), ack);
		}
		Err(error) => {
			let mut ack = ack;
			let mut data = match error.data.take() {
				Some(Value::Object(mut value)) => {
					if let Some(original) = value.remove(ACK_META) {
						ack["original_metadata"] = original;
					}
					Value::Object(value)
				}
				Some(value) => json!({"original_error_data":value}),
				None => json!({}),
			};
			data[ACK_META] = ack;
			error.data = Some(data);
		}
		_ => {}
	}
}
pub enum AuditCompletion {
	/// Successful dispatch response, not confirmed delivery or business success.
	Completed,
	/// Dispatch rejection/failure, never proof that a side effect did not occur.
	Failed,
	/// Completion or possible side effects cannot be reliably classified.
	Unknown,
}

struct Cancellation(bool);
impl Cancellation {
	fn is_cancelled(&self) -> bool {
		self.0
	}
}
// Preserve the two original match blocks byte for byte.
#[rustfmt::skip]
fn decisions(result: &Result<CallToolResponse, ErrorData>, cancelled: Cancellation, visible: bool, readonly: bool) -> (u64, bool) {
			let completion = match &result {
				_ if cancelled.is_cancelled() => AuditCompletion::Unknown,
				Ok(CallToolResponse::Complete(value)) if !value.is_error.unwrap_or(false) => {
					AuditCompletion::Completed
				}
				_ if !visible || readonly => AuditCompletion::Failed,
				_ => AuditCompletion::Unknown,
			}
;
				let response = match &result {
					Ok(CallToolResponse::Complete(value))
						if !cancelled.is_cancelled() && !value.is_error.unwrap_or(false) =>
					{
						Some(value.clone())
					}
					_ => None,
				}
;
(match completion { AuditCompletion::Completed => 1, AuditCompletion::Failed => 2, AuditCompletion::Unknown => 3 }, response.is_some())
}

fn body(result: &Result<CallToolResponse, ErrorData>) -> (u64, Value) {
	match result {
		Ok(CallToolResponse::Complete(value)) => (1, serde_json::to_value(value).unwrap()),
		Err(error) => (2, serde_json::to_value(error).unwrap()),
		Ok(CallToolResponse::Task(value)) => (3, serde_json::to_value(value).unwrap()),
		Ok(_) => panic!("SDK response variant is outside this fixed typed reference corpus"),
	}
}

fn observe(input: Value) -> Value {
	let tag = input["tag"].as_u64().unwrap();
	let op = input["op"].as_u64().unwrap();
	let tool = input["tool"].as_str().unwrap();
	let id = input["request_id"].as_str().unwrap();
	let state = input["state"].as_str().unwrap();
	let audit = input["audit_durable"].as_bool().unwrap();
	let mut result = match tag {
		1 => {
			let mut value =
				serde_json::from_value::<CallToolResult>(input["body"].clone()).unwrap();
			if let Some(structured) = input["body"].as_object().unwrap().get("structuredContent") {
				value.structured_content = Some(structured.clone());
			}
			Ok(CallToolResponse::Complete(value))
		}
		2 => {
			let mut error: ErrorData = serde_json::from_value(input["body"].clone()).unwrap();
			// A typed ErrorData can contain Some(Value::Null). Its serialized
			// representation differs from None, although Option deserialization
			// alone collapses the two. The fixture preserves that typed choice.
			if let Some(value) = input["body"].as_object().unwrap().get("data") {
				error.data = Some(value.clone());
			}
			Err(error)
		}
		3 => Ok(CallToolResponse::Task(
			serde_json::from_value::<CreateTaskResult>(input["body"].clone()).unwrap(),
		)),
		_ => panic!("typed reference tag"),
	};
	let (_, before) = body(&result);
	match op {
		1 => attach_identity(&mut result, id),
		2 => reserve_final_wire(&mut result, tool, id),
		3 => attach_ack(&mut result, state, audit),
		4 => (),
		_ => panic!("typed reference operation"),
	}
	let (after_tag, after) = body(&result);
	let typed_size = match &result {
		Ok(CallToolResponse::Complete(value)) => serde_json::to_vec(value).unwrap().len(),
		Err(value) => serde_json::to_vec(value).unwrap().len(),
		Ok(CallToolResponse::Task(value)) => serde_json::to_vec(value).unwrap().len(),
		Ok(_) => panic!("SDK response variant is outside this fixed typed reference corpus"),
	};
	let (completion, candidate) = decisions(
		&result,
		Cancellation(input["cancelled"].as_bool().unwrap()),
		input["visible"].as_bool().unwrap(),
		input["readonly"].as_bool().unwrap(),
	);
	json!({
		"input_body":serde_json::to_string(&before).unwrap(),
		"output_body":serde_json::to_string(&after).unwrap(),
		"output_typed_bytes":typed_size,
		"tag":after_tag,
		"eligible":eligible(tool),
		"expose":exposes_identity(tool),
		"completion":completion,
		"retention_candidate":eligible(tool) && candidate,
		"budget_refused":op == 2 && tag == 1 && after_tag == 2
	})
}

fn main() {
	let stdin = std::io::stdin();
	let mut out = std::io::BufWriter::new(std::io::stdout().lock());
	for line in stdin.lock().lines() {
		let input: Value = serde_json::from_str(&line.unwrap()).unwrap();
		serde_json::to_writer(&mut out, &observe(input)).unwrap();
		out.write_all(b"\n").unwrap();
		out.flush().unwrap();
	}
}
