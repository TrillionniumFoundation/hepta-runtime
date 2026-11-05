use super::*;
use std::{io::Cursor, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

fn call_line(name: &str, arguments: &str, id: u32) -> String {
	format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tools/call\",\"params\":{{\"name\":\"{name}\",\"arguments\":{arguments}}}}}\n")
}

async fn decode(line: String) -> RxJsonRpcMessage<RoleServer> {
	let mut transport = ReaMcpTransport::new(Cursor::new(line.into_bytes()), tokio::io::sink());
	transport.receive().await.expect("complete request")
}

fn raw(message: &RxJsonRpcMessage<RoleServer>) -> &ReaRawArguments {
	let JsonRpcMessage::Request(request) = message else {
		panic!("request expected")
	};
	request
		.request
		.extensions()
		.get::<ReaRawArguments>()
		.expect("private raw extension")
}

#[tokio::test]
async fn preserves_original_keys_and_last_duplicate_values() {
	let message = decode(call_line(
		"rea_get_evidence_bundle",
		r#"{"zzz":1,"filters":{"zzz":1,"aaa":2,"zzz":3},"aaa":2,"zzz":3}"#,
		1,
	))
	.await;
	assert_eq!(
		raw(&message).object_keys(&[]).unwrap(),
		["zzz", "filters", "aaa"]
	);
	assert_eq!(
		raw(&message).object_keys(&["filters"]).unwrap(),
		["zzz", "aaa"]
	);
	assert!(raw(&message).protocol_error().is_none());
	let value = serde_json::to_value(&message).unwrap();
	assert_eq!(value["params"]["arguments"]["zzz"], 3);
	assert_eq!(value["params"]["arguments"]["filters"]["zzz"], 3);
}

#[tokio::test]
async fn javascript_array_indices_precede_other_keys_in_numeric_order() {
	let message = decode(call_line(
		"rea_inspect_elf_notes",
		r#"{"zzz":0,"10":0,"2":0,"01":0,"4294967295":0,"4294967294":0,"0":0,"-0":0,"aaa":0,"2":1}"#,
		1,
	))
	.await;
	assert_eq!(
		raw(&message).object_keys(&[]).unwrap(),
		[
			"0",
			"2",
			"10",
			"4294967294",
			"zzz",
			"01",
			"4294967295",
			"-0",
			"aaa"
		]
	);
}

#[tokio::test]
async fn duplicate_filters_keeps_its_last_object_order() {
	let message = decode(call_line(
		"rea_get_evidence_bundle",
		r#"{"filters":{"old":1},"detail":"summary","filters":{"z":1,"a":2}}"#,
		3,
	))
	.await;
	assert_eq!(
		raw(&message).object_keys(&[]).unwrap(),
		["filters", "detail"]
	);
	assert_eq!(raw(&message).object_keys(&["filters"]).unwrap(), ["z", "a"]);
}

#[tokio::test]
async fn non_object_arguments_are_typed_calls_with_exact_rpc_rejections() {
	for (arguments, received) in [
		("null", "null"),
		("[]", "array"),
		(r#""text""#, "string"),
		("true", "boolean"),
		("1.5", "number"),
	] {
		let message = decode(call_line("rea_inspect_elf_notes", arguments, 4)).await;
		let JsonRpcMessage::Request(request) = &message else {
			panic!("request")
		};
		assert!(matches!(request.request, ClientRequest::CallToolRequest(_)));
		let error = serde_json::to_value(raw(&message).protocol_error().unwrap()).unwrap();
		assert_eq!(error["code"], -32602);
		assert_eq!(error["message"], format!(
			"Invalid tools/call request: [\n  {{\n    \"expected\": \"record\",\n    \"code\": \"invalid_type\",\n    \"path\": [\n      \"params\",\n      \"arguments\"\n    ],\n    \"message\": \"Invalid input: expected record, received {received}\"\n  }}\n]"));
		assert!(error.get("data").is_none());
	}
}

#[tokio::test]
async fn omitted_arguments_remain_omitted_and_distinct_from_null() {
	let message = decode("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"rea_get_evidence_bundle\"}}\n".into()).await;
	assert!(raw(&message).protocol_error().is_none());
	assert!(raw(&message).object_keys(&[]).is_none());
	assert!(serde_json::to_value(message).unwrap()["params"]
		.get("arguments")
		.is_none());
}

#[tokio::test]
async fn non_rea_and_unmapped_rea_tools_keep_original_sdk_values_and_variants() {
	for name in [
		"view",
		"rea_verify_evidence",
		"rea_inspect_elf_notes_suffix",
		"inspect_elf_notes",
	] {
		for arguments in [r#"{"z":1,"a":2}"#, "null", "[]"] {
			let line = call_line(name, arguments, 7);
			let expected: RxJsonRpcMessage<RoleServer> = serde_json::from_str(&line).unwrap();
			let actual = decode(line).await;
			assert_eq!(
				serde_json::to_value(&actual).unwrap(),
				serde_json::to_value(&expected).unwrap()
			);
			let JsonRpcMessage::Request(request) = actual else {
				panic!("request")
			};
			assert!(request
				.request
				.extensions()
				.get::<ReaRawArguments>()
				.is_none());
			assert_eq!(
				matches!(request.request, ClientRequest::CustomRequest(_)),
				arguments == "[]"
			);
		}
	}
}

#[tokio::test]
async fn client_meta_cannot_forge_the_private_raw_extension() {
	let message = decode("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"rea_get_evidence_bundle\",\"_meta\":{\"ReaRawArguments\":{\"keys\":[\"a\",\"z\"]}},\"arguments\":{\"z\":1,\"a\":2}}}\n".into()).await;
	assert_eq!(raw(&message).object_keys(&[]).unwrap(), ["z", "a"]);
}

#[tokio::test]
async fn frames_with_reused_ids_never_share_keys() {
	let lines = [
		call_line("rea_inspect_elf_notes", r#"{"z":1,"a":2}"#, 1),
		call_line("view", "[]", 1),
		call_line("rea_get_evidence_bundle", r#"{"b":1,"a":2}"#, 1),
	]
	.concat();
	let mut transport = ReaMcpTransport::new(Cursor::new(lines.into_bytes()), tokio::io::sink());
	let first = transport.receive().await.unwrap();
	assert_eq!(raw(&first).object_keys(&[]).unwrap(), ["z", "a"]);
	let second = transport.receive().await.unwrap();
	let JsonRpcMessage::Request(second) = second else {
		panic!("request")
	};
	assert!(second
		.request
		.extensions()
		.get::<ReaRawArguments>()
		.is_none());
	let third = transport.receive().await.unwrap();
	assert_eq!(raw(&third).object_keys(&[]).unwrap(), ["b", "a"]);
	assert!(transport.receive().await.is_none());
	assert!(transport.frame.lock().unwrap().is_none());
}

#[tokio::test]
async fn invalid_json_and_protocol_error_do_not_poison_the_next_frame() {
	let lines = format!(
		"not JSON\n{{\"oops\":1}}\n{}",
		call_line("rea_inspect_elf_notes", r#"{"z":1,"a":2}"#, 9)
	);
	let mut transport = ReaMcpTransport::new(Cursor::new(lines.into_bytes()), tokio::io::sink());
	let message = transport.receive().await.unwrap();
	assert_eq!(raw(&message).object_keys(&[]).unwrap(), ["z", "a"]);
}

#[tokio::test]
async fn cancelling_a_receive_keeps_partial_line_and_outbound_send_available() {
	let (server, mut client) = tokio::io::duplex(1024);
	let (read, write) = tokio::io::split(server);
	let mut transport = ReaMcpTransport::new(read, write);
	client.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"rea_inspect_elf_notes\",\"arguments\":{\"z\":1,").await.unwrap();
	assert!(
		tokio::time::timeout(Duration::from_millis(25), transport.receive())
			.await
			.is_err()
	);
	transport
		.send(JsonRpcMessage::error(
			ErrorData::internal_error("concurrent reply", None),
			None,
		))
		.await
		.unwrap();
	client.write_all(b"\"a\":2}}}\n").await.unwrap();
	let message = transport.receive().await.unwrap();
	assert_eq!(raw(&message).object_keys(&[]).unwrap(), ["z", "a"]);
	let mut response = String::new();
	BufReader::new(&mut client)
		.read_line(&mut response)
		.await
		.unwrap();
	assert_eq!(
		serde_json::from_str::<serde_json::Value>(&response).unwrap()["error"]["message"],
		"concurrent reply"
	);
}

#[tokio::test]
async fn sdk_bom_crlf_and_final_line_at_eof_keep_their_behavior() {
	for (prefix, suffix) in [("\u{feff}", "\r\n"), ("", "")] {
		let line = call_line("rea_get_evidence_bundle", r#"{"z":1,"a":2}"#, 1);
		let message = decode(format!("{prefix}{}{suffix}", line.trim_end())).await;
		assert_eq!(raw(&message).object_keys(&[]).unwrap(), ["z", "a"]);
	}
}

#[tokio::test]
async fn oversized_raw_copy_fails_closed_only_for_selected_tools() {
	for name in ["rea_inspect_elf_notes", "view"] {
		let line = call_line(name, r#"{"z":1,"a":2}"#, 1);
		let mut transport = ReaMcpTransport::with_capture_budget(
			Cursor::new(line.into_bytes()),
			tokio::io::sink(),
			16,
		);
		let message = transport.receive().await.unwrap();
		let JsonRpcMessage::Request(request) = &message else {
			panic!("request")
		};
		if selected(name) {
			assert!(raw(&message)
				.protocol_error()
				.unwrap()
				.message
				.contains("10485760-byte"));
			assert!(raw(&message).object_keys(&[]).is_none());
		} else {
			assert!(request
				.request
				.extensions()
				.get::<ReaRawArguments>()
				.is_none());
		}
	}
}

#[tokio::test]
async fn malformed_non_argument_fields_are_not_repaired() {
	let line = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"rea_inspect_elf_notes\",\"arguments\":[],\"_meta\":[]}}\n";
	let expected: RxJsonRpcMessage<RoleServer> = serde_json::from_str(line).unwrap();
	let message = decode(line.into()).await;
	assert_eq!(
		serde_json::to_value(message).unwrap(),
		serde_json::to_value(expected).unwrap()
	);
}

#[tokio::test]
async fn transport_drop_releases_its_frame_slot_without_external_cleanup() {
	let transport = ReaMcpTransport::new(Cursor::new(Vec::<u8>::new()), tokio::io::sink());
	let weak = Arc::downgrade(&transport.frame);
	drop(transport);
	assert!(weak.upgrade().is_none());
}

#[tokio::test]
async fn actual_rmcp_context_receives_private_facts_and_returns_rpc_error() {
	use rmcp::{
		model::{CallToolResponse, CallToolResult},
		service::RequestContext,
		ServerHandler, ServiceExt,
	};
	#[derive(Clone)]
	struct Handler(Arc<Mutex<Vec<Vec<String>>>>);
	impl ServerHandler for Handler {
		async fn call_tool(
			&self,
			_request: CallToolRequestParams,
			context: RequestContext<RoleServer>,
		) -> Result<CallToolResponse, ErrorData> {
			let raw = context
				.extensions
				.get::<ReaRawArguments>()
				.expect("transport facts moved to context");
			if let Some(error) = raw.protocol_error() {
				return Err(error);
			}
			self.0
				.lock()
				.unwrap()
				.push(raw.object_keys(&[]).unwrap().to_vec());
			Ok(CallToolResult::success(Vec::new()).into())
		}
	}
	let seen = Arc::new(Mutex::new(Vec::new()));
	let (server, client) = tokio::io::duplex(8192);
	let (read, write) = tokio::io::split(server);
	let handler = Handler(Arc::clone(&seen));
	let owner = tokio::spawn(async move {
		let service = handler
			.serve(ReaMcpTransport::new(read, write))
			.await
			.unwrap();
		service.waiting().await.unwrap();
	});
	let (read, mut write) = tokio::io::split(client);
	let mut read = BufReader::new(read);
	write.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"raw-boundary-test\",\"version\":\"1\"}}}\n").await.unwrap();
	let mut reply = String::new();
	read.read_line(&mut reply).await.unwrap();
	assert!(serde_json::from_str::<serde_json::Value>(&reply)
		.unwrap()
		.get("result")
		.is_some());
	write
		.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
		.await
		.unwrap();
	write
		.write_all(call_line("rea_inspect_elf_notes", "null", 1).as_bytes())
		.await
		.unwrap();
	reply.clear();
	read.read_line(&mut reply).await.unwrap();
	assert_eq!(
		serde_json::from_str::<serde_json::Value>(&reply).unwrap()["error"]["code"],
		-32602
	);
	assert!(seen.lock().unwrap().is_empty());
	write
		.write_all(call_line("rea_inspect_elf_notes", r#"{"z":1,"a":2}"#, 2).as_bytes())
		.await
		.unwrap();
	reply.clear();
	read.read_line(&mut reply).await.unwrap();
	assert!(serde_json::from_str::<serde_json::Value>(&reply)
		.unwrap()
		.get("result")
		.is_some());
	assert_eq!(
		seen.lock().unwrap().as_slice(),
		&[vec!["z".to_string(), "a".to_string()]]
	);
	write.shutdown().await.unwrap();
	drop(write);
	drop(read);
	tokio::time::timeout(Duration::from_secs(5), owner)
		.await
		.unwrap()
		.unwrap();
}
