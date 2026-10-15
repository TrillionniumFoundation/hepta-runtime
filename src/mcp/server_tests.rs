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

//! End-to-end delivery tests for background-job completion, over a real
//! in-memory MCP connection (duplex transport, full rmcp client + server).
//!
//! Covers both delivery paths a client can end up on:
//! - the 2026-07-28 contract path: a `subscriptions/listen` stream carries the
//!   update, and no unsolicited duplicate is sent;
//! - the legacy fallback: with no listen stream, the unsolicited
//!   `resources/updated` push is delivered to the client handler — what
//!   pre-2026-07-28 clients receive.

use std::sync::Arc;
use std::time::Duration;

use rmcp::model::{
	CacheScope, CallToolRequestParams, ClientCapabilities, ClientConfig, ContentBlock,
	Implementation, ProtocolVersion, ReadResourceRequestParams, SubscribeRequestParams,
	SubscriptionFilter,
};
use rmcp::service::{ClientLifecycleMode, ClientServiceExt, NotificationContext, RunningService};
use rmcp::{ClientHandler, RoleClient, ServiceExt};
use serde_json::json;
use tokio::sync::Mutex;

use super::OctofsServer;

/// Minimal client that records unsolicited `resources/updated` pushes and Claude
/// Code channel messages.
#[derive(Clone, Debug)]
struct RecordingClient {
	unsolicited: Arc<Mutex<Vec<String>>>,
	channel: Arc<Mutex<Vec<serde_json::Value>>>,
	protocol_version: ProtocolVersion,
}

impl ClientHandler for RecordingClient {
	fn get_info(&self) -> ClientConfig {
		ClientConfig::new(
			ClientCapabilities::default(),
			Implementation::new("octofs-test-client", "0.0.0"),
		)
		.with_protocol_version(self.protocol_version.clone())
	}

	async fn on_resource_updated(
		&self,
		params: rmcp::model::ResourceUpdatedNotificationParam,
		_context: NotificationContext<RoleClient>,
	) {
		self.unsolicited.lock().await.push(params.uri);
	}

	async fn on_custom_notification(
		&self,
		notification: rmcp::model::CustomNotification,
		_context: NotificationContext<RoleClient>,
	) {
		if notification.method == "notifications/claude/channel" {
			self.channel
				.lock()
				.await
				.push(notification.params.unwrap_or_default());
		}
	}
}

/// Connect a client with the requested protocol lifecycle to a fresh server
/// instance over an in-memory duplex transport.
///
/// The returned JoinHandle keeps the server task — and its RunningService —
/// alive for the test's lifetime: dropping a RunningService cancels the
/// connection, and `serve()` blocks until the handshake completes, so it must
/// run concurrently with the client.
async fn connect_with_lifecycle(
	protocol_version: ProtocolVersion,
	lifecycle: ClientLifecycleMode,
) -> (
	RunningService<RoleClient, RecordingClient>,
	tokio::task::JoinHandle<()>,
	Arc<Mutex<Vec<String>>>,
) {
	let (client_io, server_io) = tokio::io::duplex(4096);
	let server_task = tokio::spawn(async move {
		// A per-test temp root keeps identical background commands from sibling
		// tests independent. The TempDir lives inside this task, so it is cleaned
		// up only after the connection closes.
		let root = tempfile::tempdir().expect("temp session root");
		let server = OctofsServer::with_root(root.path().to_path_buf())
			.serve(server_io)
			.await
			.expect("serve server");
		server.waiting().await.expect("server connection closed");
	});
	let unsolicited = Arc::new(Mutex::new(Vec::new()));
	let client = tokio::time::timeout(
		Duration::from_secs(5),
		RecordingClient {
			unsolicited: unsolicited.clone(),
			channel: Arc::new(Mutex::new(Vec::new())),
			protocol_version,
		}
		.serve_with_lifecycle(client_io, lifecycle),
	)
	.await
	.expect("client handshake within 5s")
	.expect("serve client");
	(client, server_task, unsolicited)
}

async fn connect() -> (
	RunningService<RoleClient, RecordingClient>,
	tokio::task::JoinHandle<()>,
	Arc<Mutex<Vec<String>>>,
) {
	connect_with_lifecycle(
		ProtocolVersion::V_2026_07_28,
		ClientLifecycleMode::Auto {
			preferred_versions: vec![ProtocolVersion::V_2026_07_28],
			legacy_version: None,
		},
	)
	.await
}

async fn connect_legacy() -> (
	RunningService<RoleClient, RecordingClient>,
	tokio::task::JoinHandle<()>,
	Arc<Mutex<Vec<String>>>,
) {
	connect_with_lifecycle(
		ProtocolVersion::V_2025_11_25,
		ClientLifecycleMode::Initialize,
	)
	.await
}

/// Start a ~2s job and return the resource link advertised when the test-only
/// foreground window automatically promotes it.
/// Each platform uses its native bounded-wait command; the POSIX loop keeps
/// `sleep` inside the shell guard's documented leniency.
async fn start_job(client: &RunningService<RoleClient, RecordingClient>) -> String {
	let command = if cfg!(target_os = "windows") {
		"ping -n 3 127.0.0.1"
	} else {
		"for i in 1 2; do sleep 1; done"
	};
	let serde_json::Value::Object(arguments) = json!({"command": command}) else {
		unreachable!("literal object argument")
	};
	let params = CallToolRequestParams::new("shell").with_arguments(arguments);
	let result = client.call_tool(params).await.expect("call shell");
	result
		.content
		.iter()
		.find_map(|block| match block {
			ContentBlock::ResourceLink(link) => Some(link.uri.clone()),
			_ => None,
		})
		.unwrap_or_else(|| {
			panic!(
				"promoted shell advertises a resource link; got is_error={:?} content={:?}",
				result.is_error, result.content
			)
		})
}

async fn wait_for_job_exit(uri: &str) {
	let id = crate::mcp::fs::background::job_id_from_uri(uri).expect("job URI");
	let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
	loop {
		if matches!(
			crate::mcp::fs::background::status(id),
			Some(crate::mcp::fs::background::JobStatus::Exited(_))
		) {
			return;
		}
		assert!(
			tokio::time::Instant::now() < deadline,
			"background job {uri} never finished"
		);
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
}

async fn wait_for_unsolicited(unsolicited: &Arc<Mutex<Vec<String>>>, uri: &str) {
	let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
	loop {
		if unsolicited
			.lock()
			.await
			.iter()
			.any(|notified| notified == uri)
		{
			return;
		}
		assert!(
			tokio::time::Instant::now() < deadline,
			"unsolicited push for {uri} never arrived"
		);
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn job_completion_is_delivered_on_the_listen_stream() {
	let (client, _server_task, unsolicited) = connect().await;
	let uri = start_job(&client).await;

	let mut filter = SubscriptionFilter::new();
	filter.resource_subscriptions = Some(vec![uri.clone()]);
	let mut subscription =
		tokio::time::timeout(Duration::from_secs(5), client.peer().listen(filter))
			.await
			.expect("listen establishes")
			.expect("listen succeeds");
	assert!(
		subscription
			.acknowledged()
			.resource_subscriptions
			.as_ref()
			.is_some_and(|uris| uris.contains(&uri)),
		"server must acknowledge the requested URI"
	);

	let notification = tokio::time::timeout(Duration::from_secs(15), subscription.next())
		.await
		.expect("update arrives on the stream")
		.expect("stream alive")
		.expect("valid notification");
	match notification {
		rmcp::model::ServerNotification::ResourceUpdatedNotification(update) => {
			assert_eq!(update.params.uri, uri);
		}
		other => panic!("expected a resource update, got {other:?}"),
	}
	assert!(
		unsolicited.lock().await.is_empty(),
		"stream delivery must not duplicate as an unsolicited push"
	);
	subscription.cancel().await.expect("cancel subscription");
}

#[tokio::test(flavor = "multi_thread")]
async fn job_completion_falls_back_to_unsolicited_push_without_a_stream() {
	let (client, _server_task, unsolicited) = connect().await;
	let uri = start_job(&client).await;

	// No listen stream — the server must fall back to the unsolicited push
	// that pre-2026-07-28 clients rely on.
	wait_for_unsolicited(&unsolicited, &uri).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn finished_job_is_replayed_to_a_late_listen_stream() {
	let (client, _server_task, _unsolicited) = connect().await;
	let uri = start_job(&client).await;
	wait_for_job_exit(&uri).await;

	let mut filter = SubscriptionFilter::new();
	filter.resource_subscriptions = Some(vec![uri.clone()]);
	let mut subscription =
		tokio::time::timeout(Duration::from_secs(5), client.peer().listen(filter))
			.await
			.expect("late listen establishes")
			.expect("late listen succeeds");
	let notification = tokio::time::timeout(Duration::from_secs(5), subscription.next())
		.await
		.expect("finished job is replayed")
		.expect("stream alive")
		.expect("valid notification");
	match notification {
		rmcp::model::ServerNotification::ResourceUpdatedNotification(update) => {
			assert_eq!(update.params.uri, uri);
		}
		other => panic!("expected a resource update, got {other:?}"),
	}
	subscription.cancel().await.expect("cancel subscription");
}

#[tokio::test(flavor = "multi_thread")]
#[allow(deprecated)]
async fn finished_job_is_replayed_to_a_late_legacy_subscription() {
	let (client, _server_task, unsolicited) = connect_legacy().await;
	let uri = start_job(&client).await;
	wait_for_job_exit(&uri).await;
	// Drain the original completion push first. Otherwise it could arrive after
	// `clear` and make the replay assertion pass without the subscribe handler.
	wait_for_unsolicited(&unsolicited, &uri).await;
	unsolicited.lock().await.clear();

	client
		.subscribe(SubscribeRequestParams::new(uri.clone()))
		.await
		.expect("legacy subscription succeeds");
	wait_for_unsolicited(&unsolicited, &uri).await;
}

/// Claude Code wakes its model only on channel messages, so on a pre-2026-07-28
/// connection a job's exit also goes out as one, carrying the job resource text.
#[tokio::test(flavor = "multi_thread")]
async fn job_completion_is_pushed_as_a_claude_channel_message_on_legacy_connections() {
	let (client, _server_task, unsolicited) = connect_legacy().await;
	let info = client.peer_info().expect("server info");
	assert!(
		info.capabilities
			.experimental
			.as_ref()
			.is_some_and(|experimental| experimental.contains_key("claude/channel")),
		"the claude/channel capability must be advertised"
	);
	let uri = start_job(&client).await;
	wait_for_unsolicited(&unsolicited, &uri).await;

	let id = crate::mcp::fs::background::job_id_from_uri(&uri).expect("job URI");
	let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
	let message = loop {
		if let Some(message) = client.service().channel.lock().await.first().cloned() {
			break message;
		}
		assert!(
			tokio::time::Instant::now() < deadline,
			"channel message for {uri} never arrived"
		);
		tokio::time::sleep(Duration::from_millis(100)).await;
	};
	assert_eq!(message["meta"]["job"], id, "{message}");
	let content = message["content"].as_str().expect("text content");
	assert!(content.starts_with(&format!("job {id}\n")), "{content}");
	assert!(content.contains("status: exited with code 0"), "{content}");
}

/// 2026-07-28 carries no unsolicited notifications and Claude Code drops channels
/// on such a connection, so none is sent there.
#[tokio::test(flavor = "multi_thread")]
async fn no_claude_channel_message_on_2026_07_28_connections() {
	let (client, _server_task, unsolicited) = connect().await;
	let uri = start_job(&client).await;
	wait_for_unsolicited(&unsolicited, &uri).await;
	// The channel message would follow the resources/updated push from the same task.
	tokio::time::sleep(Duration::from_millis(500)).await;
	assert!(client.service().channel.lock().await.is_empty());
}

/// 2026-07-28 requires `ttlMs` and `cacheScope` on list and read results. A
/// strict client (Claude Code's `server/discover` runtime) rejects results
/// without them and never loads octofs's tools.
#[tokio::test(flavor = "multi_thread")]
async fn results_carry_cache_hints_on_2026_07_28() {
	let (client, _server_task, _unsolicited) = connect().await;

	let tools = client.list_tools(None).await.expect("list tools");
	assert_eq!(tools.ttl_ms, Some(0));
	assert_eq!(tools.cache_scope, Some(CacheScope::Public));

	let uri = start_job(&client).await;
	let resources = client.list_resources(None).await.expect("list resources");
	assert_eq!(resources.ttl_ms, Some(0));
	assert_eq!(resources.cache_scope, Some(CacheScope::Private));

	let read = client
		.read_resource(ReadResourceRequestParams::new(uri))
		.await
		.expect("read job resource");
	assert_eq!(read.ttl_ms, Some(0));
	assert_eq!(read.cache_scope, Some(CacheScope::Private));
}

/// The hints don't exist before 2026-07-28, so legacy results stay unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn legacy_results_carry_no_cache_hints() {
	let (client, _server_task, _unsolicited) = connect_legacy().await;

	let tools = client.list_tools(None).await.expect("list tools");
	assert_eq!(tools.ttl_ms, None);
	assert_eq!(tools.cache_scope, None);

	let uri = start_job(&client).await;
	let resources = client.list_resources(None).await.expect("list resources");
	assert_eq!(resources.ttl_ms, None);
	assert_eq!(resources.cache_scope, None);

	let read = client
		.read_resource(ReadResourceRequestParams::new(uri))
		.await
		.expect("read job resource");
	assert_eq!(read.ttl_ms, None);
	assert_eq!(read.cache_scope, None);
}

/// A job link reads through `view` exactly as through `resources/read`: models try
/// `view` on it first, and a client's resource reader may be deferred.
#[tokio::test(flavor = "multi_thread")]
async fn view_reads_a_job_link_like_resources_read() {
	let (client, _server_task, _unsolicited) = connect_legacy().await;
	let uri = start_job(&client).await;
	wait_for_job_exit(&uri).await;

	let read = client
		.read_resource(ReadResourceRequestParams::new(uri.clone()))
		.await
		.expect("read job resource");
	let expected = match &read.contents[0] {
		rmcp::model::ResourceContents::TextResourceContents { text, .. } => text.clone(),
		other => panic!("job resource is text, got {other:?}"),
	};
	assert!(
		expected.contains("status: exited with code 0"),
		"{expected}"
	);

	let view = |path: String| {
		let serde_json::Value::Object(arguments) = json!({ "path": path }) else {
			unreachable!("literal object argument")
		};
		client.call_tool(CallToolRequestParams::new("view").with_arguments(arguments))
	};
	let result = view(uri.clone()).await.expect("call view");
	assert_ne!(result.is_error, Some(true), "{:?}", result.content);
	let text = result
		.content
		.iter()
		.find_map(|block| match block {
			ContentBlock::Text(text) => Some(text.text.clone()),
			_ => None,
		})
		.expect("text result");
	assert_eq!(text, expected);

	let missing = view("octofs://jobs/0-0".to_string())
		.await
		.expect("call view");
	assert_eq!(missing.is_error, Some(true), "unknown job id is an error");
}

// A model that names one edit in a shape the schema did not anticipate is still
// naming one edit; these coercions keep that from costing a round-trip.
#[test]
fn batch_edit_accepts_content_as_a_list_of_lines() {
	let params: super::BatchEditParams = serde_json::from_value(serde_json::json!({
		"path": "src/lib.rs",
		"operations": [{
			"operation": "replace",
			"start": "7:56",
			"end": "7:56",
			"content": ["use a::B;", "use c::D;"],
		}],
	}))
	.expect("list content is joined");
	assert_eq!(params.operations[0].content, "use a::B;\nuse c::D;");
}

#[test]
fn batch_edit_hoists_a_path_carried_on_every_operation() {
	let params: super::BatchEditParams = serde_json::from_value(serde_json::json!({
		"operations": [
			{"operation": "replace", "start": "7:56", "content": "a", "path": "src/lib.rs"},
			{"operation": "insert", "start": 0, "content": "b", "path": "src/lib.rs"},
		],
	}))
	.expect("a single agreed path is the target");
	assert_eq!(params.path, "src/lib.rs");
	assert_eq!(params.operations.len(), 2);
}

#[test]
fn batch_edit_rejects_operations_naming_different_files() {
	let err = serde_json::from_value::<super::BatchEditParams>(serde_json::json!({
		"operations": [
			{"operation": "replace", "start": "7:56", "content": "a", "path": "src/one.rs"},
			{"operation": "replace", "start": "9:aa", "content": "b", "path": "src/two.rs"},
		],
	}))
	.expect_err("no single target is named");
	assert!(err.to_string().contains("single file"), "got: {err}");
}

#[test]
fn generator_noise_is_stripped_but_parameters_named_like_it_survive() {
	let serde_json::Value::Object(mut schema) = serde_json::json!({
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type": "object",
		"properties": {
			"context": {"type": "integer", "format": "uint", "minimum": 0, "default": null},
			"mode": {"type": "string", "default": "fast"},
			"format": {"type": "string", "default": null},
			"start": {"anyOf": [{"type": "string"}, {"type": "integer", "format": "int64"}]},
		},
		"$defs": {"Op": {"type": "integer", "format": "int64"}},
	}) else {
		unreachable!("literal object")
	};
	super::strip_generator_noise(&mut schema);
	assert_eq!(
		serde_json::Value::Object(schema),
		serde_json::json!({
			"type": "object",
			"properties": {
				"context": {"type": "integer", "minimum": 0},
				"mode": {"type": "string", "default": "fast"},
				"format": {"type": "string"},
				"start": {"anyOf": [{"type": "string"}, {"type": "integer"}]},
			},
			"$defs": {"Op": {"type": "integer"}},
		})
	);
}

/// The served tool list carries no generator noise and keeps every parameter.
#[tokio::test(flavor = "multi_thread")]
async fn served_tool_schemas_carry_no_generator_noise() {
	let (client, _server_task, _unsolicited) = connect_legacy().await;
	let tools = client.list_tools(None).await.expect("list tools");
	assert_eq!(tools.tools.len(), 10);
	for name in [
		"directory_create",
		"file_move",
		"directory_move",
		"text_file_write",
	] {
		assert!(
			tools.tools.iter().any(|t| t.name == name),
			"registered explicit {name}"
		);
	}

	for tool in &tools.tools {
		let schema = serde_json::to_string(tool.input_schema.as_ref()).expect("schema json");
		assert!(
			!schema.contains("\"$schema\"")
				&& !schema.contains("\"format\"")
				&& !schema.contains("\"default\":null"),
			"{}: {schema}",
			tool.name
		);
	}
	let view = tools
		.tools
		.iter()
		.find(|tool| tool.name == "view")
		.expect("view tool");
	let properties = view.input_schema["properties"]
		.as_object()
		.expect("view properties");
	for name in [
		"path",
		"start",
		"end",
		"pattern",
		"content",
		"regex",
		"max_depth",
		"context",
		"full",
	] {
		assert!(properties.contains_key(name), "view keeps `{name}`");
	}
}

async fn call_runtime_tool_text(
	client: &RunningService<RoleClient, RecordingClient>,
	name: &str,
	arguments: serde_json::Value,
) -> (bool, String) {
	let serde_json::Value::Object(arguments) = arguments else {
		panic!("runtime tool arguments must be an object");
	};
	let result = client
		.call_tool(CallToolRequestParams::new(name.to_string()).with_arguments(arguments))
		.await
		.unwrap_or_else(|error| panic!("call {name}: {error}"));
	let text = result
		.content
		.iter()
		.find_map(|block| match block {
			ContentBlock::Text(text) => Some(text.text.clone()),
			_ => None,
		})
		.unwrap_or_default();
	(result.is_error == Some(true), text)
}

/// Destructive remote integration test. It is ignored by default and must run
/// under the dedicated controller identity with a reviewed runtime config.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires dedicated hepta-runtime SSH identities and HEPTA_RUNTIME_TEST_CONFIG"]
#[serial_test::serial]
async fn runtime_remote_execution_recovery_and_policy_e2e() {
	let config_path = std::env::var("HEPTA_RUNTIME_TEST_CONFIG")
		.expect("HEPTA_RUNTIME_TEST_CONFIG points to reviewed JSON policy");
	let config = crate::mcp::runtime::RuntimeConfig::load(std::path::Path::new(&config_path))
		.expect("load runtime test config");
	crate::mcp::runtime::init_runtime(config).expect("initialize runtime once");
	let (client, _server_task, _unsolicited) = connect().await;

	let tools = client.list_tools(None).await.expect("list runtime tools");
	assert!(
		!tools.tools.iter().any(|tool| tool.name == "shell"),
		"legacy shell must not be advertised in runtime mode"
	);
	for name in [
		"host_list",
		"process_start",
		"process_status",
		"process_read",
		"process_wait",
		"process_cancel",
		"pty_start",
		"hardware_snapshot",
		"service_status",
		"network_inspect",
	] {
		assert!(
			tools.tools.iter().any(|tool| tool.name == name),
			"missing {name}"
		);
	}

	let key = format!("e2e-{}", std::process::id());
	let start_args = json!({
		"host": "pocket4",
		"executable": "/usr/bin/python3",
		"args": ["-c", "import time; print('begin', flush=True); time.sleep(2); print('done', flush=True)"],
		"cwd": "/var/lib/hepta-runtime/workspaces",
		"idempotency_key": key,
		"nice": 19,
		"cpu_quota_percent": 25,
		"memory_max_bytes": 134217728
	});
	let (failed, started_text) =
		call_runtime_tool_text(&client, "process_start", start_args.clone()).await;
	assert!(!failed, "process_start: {started_text}");
	let started: serde_json::Value = serde_json::from_str(&started_text).expect("start JSON");
	let job_id = started["job"]["id"].as_str().expect("job id").to_string();
	assert_eq!(started["reused"], false);

	let (failed, reused_text) = call_runtime_tool_text(&client, "process_start", start_args).await;
	assert!(!failed, "idempotent process_start: {reused_text}");
	let reused: serde_json::Value = serde_json::from_str(&reused_text).expect("reuse JSON");
	assert_eq!(reused["reused"], true);
	assert_eq!(reused["job"]["id"], job_id);

	let (failed, waited_text) = call_runtime_tool_text(
		&client,
		"process_wait",
		json!({"host":"pocket4", "job_id":job_id, "timeout_seconds":10}),
	)
	.await;
	assert!(!failed, "process_wait: {waited_text}");
	let waited: serde_json::Value = serde_json::from_str(&waited_text).expect("wait JSON");
	assert_eq!(waited["state"], "succeeded", "{waited_text}");

	let (failed, output_text) = call_runtime_tool_text(
		&client,
		"process_read",
		json!({"host":"pocket4", "job_id":job_id, "stdout_offset":0, "stderr_offset":0, "limit":65536}),
	)
	.await;
	assert!(!failed, "process_read: {output_text}");
	let output: serde_json::Value = serde_json::from_str(&output_text).expect("read JSON");
	let stdout = output["stdout"]["text"].as_str().unwrap_or_default();
	assert!(
		stdout.contains("begin") && stdout.contains("done"),
		"{output_text}"
	);

	let cancel_key = format!("e2e-cancel-{}", std::process::id());
	let (failed, long_text) = call_runtime_tool_text(
		&client,
		"process_start",
		json!({
			"host":"pocket4",
			"executable":"/usr/bin/python3",
			"args":["-c", "import time; print('cancel-me', flush=True); time.sleep(60)"],
			"cwd":"/var/lib/hepta-runtime/workspaces",
			"idempotency_key":cancel_key,
			"nice":19,
			"cpu_quota_percent":10,
			"memory_max_bytes":134217728
		}),
	)
	.await;
	assert!(!failed, "long process_start: {long_text}");
	let long: serde_json::Value = serde_json::from_str(&long_text).expect("long JSON");
	let long_id = long["job"]["id"].as_str().expect("long job id");
	tokio::time::sleep(Duration::from_millis(400)).await;
	let (failed, cancel_text) = call_runtime_tool_text(
		&client,
		"process_cancel",
		json!({"host":"pocket4", "job_id":long_id, "grace_seconds":5}),
	)
	.await;
	assert!(!failed, "process_cancel: {cancel_text}");
	let (failed, cancelled_text) = call_runtime_tool_text(
		&client,
		"process_wait",
		json!({"host":"pocket4", "job_id":long_id, "timeout_seconds":8}),
	)
	.await;
	assert!(!failed, "wait cancelled: {cancelled_text}");
	let cancelled: serde_json::Value =
		serde_json::from_str(&cancelled_text).expect("cancelled JSON");
	assert!(
		matches!(
			cancelled["state"].as_str(),
			Some("cancelled" | "failed" | "completed_unknown")
		),
		"{cancelled_text}"
	);

	let net_key = format!("e2e-network-{}", std::process::id());
	let (failed, net_start_text) = call_runtime_tool_text(
		&client,
		"process_start",
		json!({
			"host":"pocket4",
			"executable":"/usr/bin/python3",
			"args":["-c", "import socket; socket.socket(socket.AF_INET, socket.SOCK_STREAM)"],
			"cwd":"/var/lib/hepta-runtime/workspaces",
			"idempotency_key":net_key
		}),
	)
	.await;
	assert!(!failed, "network sandbox launch: {net_start_text}");
	let net_started: serde_json::Value =
		serde_json::from_str(&net_start_text).expect("network start JSON");
	let net_id = net_started["job"]["id"].as_str().expect("network job id");
	let (failed, net_wait_text) = call_runtime_tool_text(
		&client,
		"process_wait",
		json!({"host":"pocket4", "job_id":net_id, "timeout_seconds":8}),
	)
	.await;
	assert!(!failed, "network sandbox wait: {net_wait_text}");
	let net_wait: serde_json::Value =
		serde_json::from_str(&net_wait_text).expect("network wait JSON");
	assert_eq!(
		net_wait["state"], "failed",
		"AF_INET must be blocked: {net_wait_text}"
	);

	let (denied, denied_text) = call_runtime_tool_text(
		&client,
		"process_start",
		json!({
			"host":"pocket4",
			"executable":"/bin/bash",
			"args":["-c", "true"],
			"cwd":"/var/lib/hepta-runtime/workspaces"
		}),
	)
	.await;
	assert!(denied, "shell launch must be denied: {denied_text}");

	let (denied, direct_shell) =
		call_runtime_tool_text(&client, "shell", json!({"command":"ssh hepta-rog id"})).await;
	assert!(denied, "legacy shell bypass must be denied: {direct_shell}");

	let (denied, local_secret) = call_runtime_tool_text(
		&client,
		"view",
		json!({"path":"/var/lib/hepta-runtime/.ssh/id_ed25519"}),
	)
	.await;
	assert!(
		denied,
		"controller secret path must be denied: {local_secret}"
	);
	let (denied, remote_protected) = call_runtime_tool_text(
		&client,
		"view",
		json!({"path":"ssh://hepta-pocket4/home/alex/Jts/jts.ini"}),
	)
	.await;
	assert!(
		denied,
		"protected remote path must be denied: {remote_protected}"
	);

	for host in ["pocket4", "rog"] {
		let (failed, snapshot) =
			call_runtime_tool_text(&client, "hardware_snapshot", json!({"host":host})).await;
		assert!(
			!failed && snapshot.contains("hostname"),
			"snapshot {host}: {snapshot}"
		);
	}
	let (failed, services) = call_runtime_tool_text(
		&client,
		"service_status",
		json!({"host":"pocket4", "services":["actions.runner.TrillionniumFoundation.pocket4.service"]}),
	)
	.await;
	assert!(
		!failed && services.contains("ActiveState"),
		"service_status: {services}"
	);
	let (failed, network) =
		call_runtime_tool_text(&client, "network_inspect", json!({"host":"pocket4"})).await;
	assert!(
		!failed && network.contains("addresses"),
		"network_inspect: {network}"
	);

	let (failed, pty_text) = call_runtime_tool_text(
		&client,
		"pty_start",
		json!({
			"host":"pocket4",
			"executable":"/usr/bin/python3",
			"args":["-i", "-q"],
			"cwd":"/var/lib/hepta-runtime/workspaces"
		}),
	)
	.await;
	assert!(!failed, "pty_start: {pty_text}");
	let pty: serde_json::Value = serde_json::from_str(&pty_text).expect("PTY JSON");
	let session_id = pty["session_id"].as_str().expect("session id");
	tokio::time::sleep(Duration::from_millis(400)).await;
	let (failed, written) = call_runtime_tool_text(
		&client,
		"pty_write",
		json!({"host":"pocket4", "session_id":session_id, "data":"print('PTY_OK')\n"}),
	)
	.await;
	assert!(!failed, "pty_write: {written}");
	tokio::time::sleep(Duration::from_millis(500)).await;
	let (failed, pty_output) = call_runtime_tool_text(
		&client,
		"pty_read",
		json!({"host":"pocket4", "session_id":session_id, "offset":0, "limit":65536}),
	)
	.await;
	assert!(
		!failed && pty_output.contains("PTY_OK"),
		"pty_read: {pty_output}"
	);
	let (failed, closed) = call_runtime_tool_text(
		&client,
		"pty_close",
		json!({"host":"pocket4", "session_id":session_id}),
	)
	.await;
	assert!(!failed, "pty_close: {closed}");
}

/// Phase one of the controller-restart test. Run this ignored test as the
/// dedicated controller account, let the process exit, then run phase two in a
/// fresh test process. The remote systemd unit must outlive this MCP server.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "manual phase one for durable controller restart validation"]
#[serial_test::serial]
async fn runtime_restart_phase_one_starts_remote_job() {
	let config_path = std::env::var("HEPTA_RUNTIME_TEST_CONFIG")
		.expect("HEPTA_RUNTIME_TEST_CONFIG points to reviewed JSON policy");
	let config = crate::mcp::runtime::RuntimeConfig::load(std::path::Path::new(&config_path))
		.expect("load runtime test config");
	crate::mcp::runtime::init_runtime(config).expect("initialize runtime once");
	let (client, _server_task, _unsolicited) = connect().await;
	let key = format!("restart-e2e-{}", std::process::id());
	let (failed, text) = call_runtime_tool_text(
		&client,
		"process_start",
		json!({
			"host":"pocket4",
			"executable":"/usr/bin/python3",
			"args":["-c", "import time; print('restart-begin', flush=True); time.sleep(8); print('restart-done', flush=True)"],
			"cwd":"/var/lib/hepta-runtime/workspaces",
			"idempotency_key":key,
			"nice":19,
			"cpu_quota_percent":10,
			"memory_max_bytes":134217728
		}),
	)
	.await;
	assert!(!failed, "process_start: {text}");
	let value: serde_json::Value = serde_json::from_str(&text).expect("start JSON");
	let id = value["job"]["id"].as_str().expect("job id");
	std::fs::write(
		"/var/lib/hepta-runtime/state/restart-e2e-job-id",
		format!("{id}\n"),
	)
	.expect("persist restart test job id");
	let (failed, status) = call_runtime_tool_text(
		&client,
		"process_status",
		json!({"host":"pocket4", "job_id":id}),
	)
	.await;
	assert!(
		!failed && status.contains("running"),
		"job must be running: {status}"
	);
}

/// Phase two is intentionally a separate OS process from phase one.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "manual phase two for durable controller restart validation"]
#[serial_test::serial]
async fn runtime_restart_phase_two_recovers_remote_job() {
	let config_path = std::env::var("HEPTA_RUNTIME_TEST_CONFIG")
		.expect("HEPTA_RUNTIME_TEST_CONFIG points to reviewed JSON policy");
	let config = crate::mcp::runtime::RuntimeConfig::load(std::path::Path::new(&config_path))
		.expect("load runtime test config");
	crate::mcp::runtime::init_runtime(config).expect("initialize runtime once");
	let id = std::fs::read_to_string("/var/lib/hepta-runtime/state/restart-e2e-job-id")
		.expect("phase one job id")
		.trim()
		.to_string();
	let (client, _server_task, _unsolicited) = connect().await;
	let (failed, status) = call_runtime_tool_text(
		&client,
		"process_wait",
		json!({"host":"pocket4", "job_id":id, "timeout_seconds":20}),
	)
	.await;
	assert!(!failed, "recover wait: {status}");
	let status_json: serde_json::Value = serde_json::from_str(&status).expect("status JSON");
	assert_eq!(status_json["state"], "succeeded", "{status}");
	let (failed, output) = call_runtime_tool_text(
		&client,
		"process_read",
		json!({"host":"pocket4", "job_id":id, "stdout_offset":0, "stderr_offset":0, "limit":65536}),
	)
	.await;
	assert!(!failed, "recover read: {output}");
	assert!(
		output.contains("restart-begin") && output.contains("restart-done"),
		"{output}"
	);
}
/// Cross-platform backend integration: systemd user unit on Linux and detached supervisor on macOS.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires dedicated x230 and mac hepta-runtime SSH identities"]
#[serial_test::serial]
async fn runtime_linux_and_macos_backends_e2e() {
	let config_path = std::env::var("HEPTA_RUNTIME_TEST_CONFIG")
		.expect("HEPTA_RUNTIME_TEST_CONFIG points to reviewed JSON policy");
	let config = crate::mcp::runtime::RuntimeConfig::load(std::path::Path::new(&config_path))
		.expect("load runtime test config");
	crate::mcp::runtime::init_runtime(config).expect("initialize runtime once");
	let (client, _server_task, _unsolicited) = connect().await;

	for (host, cwd, backend) in [
		("x230", "/var/lib/hepta-runtime/workspaces", "systemd"),
		("mac", "/Users/hepta-runtime/workspaces", "detached"),
	] {
		let key = format!("cross-platform-{host}-{}", std::process::id());
		let (failed, started_text) = call_runtime_tool_text(
			&client,
			"process_start",
			json!({
				"host":host,
				"executable":"/usr/bin/python3",
				"args":["-c", "import time; print('cross-begin', flush=True); time.sleep(1); print('cross-done', flush=True)"],
				"cwd":cwd,
				"idempotency_key":key,
				"nice":19,
				"memory_max_bytes":134217728
			}),
		).await;
		assert!(!failed, "{host} process_start: {started_text}");
		let started: serde_json::Value = serde_json::from_str(&started_text).expect("start JSON");
		assert_eq!(started["launch"]["backend"], backend, "{started_text}");
		let job_id = started["job"]["id"].as_str().expect("job id");
		let (failed, waited_text) = call_runtime_tool_text(
			&client,
			"process_wait",
			json!({"host":host,"job_id":job_id,"timeout_seconds":15}),
		)
		.await;
		assert!(!failed, "{host} wait: {waited_text}");
		let waited: serde_json::Value = serde_json::from_str(&waited_text).expect("wait JSON");
		assert_eq!(waited["state"], "succeeded", "{waited_text}");
		let (failed, output) = call_runtime_tool_text(
			&client,
			"process_read",
			json!({"host":host,"job_id":job_id,"stdout_offset":0,"stderr_offset":0,"limit":65536}),
		)
		.await;
		assert!(!failed, "{host} read: {output}");
		assert!(
			output.contains("cross-begin") && output.contains("cross-done"),
			"{output}"
		);

		let (failed, snapshot) =
			call_runtime_tool_text(&client, "hardware_snapshot", json!({"host":host})).await;
		assert!(
			!failed && snapshot.contains("hostname"),
			"snapshot {host}: {snapshot}"
		);
	}

	let (failed, long_text) = call_runtime_tool_text(
		&client,
		"process_start",
		json!({
			"host":"mac",
			"executable":"/usr/bin/python3",
			"args":["-c", "import time; print('mac-cancel', flush=True); time.sleep(60)"],
			"cwd":"/Users/hepta-runtime/workspaces",
			"idempotency_key":format!("mac-cancel-{}", std::process::id())
		}),
	)
	.await;
	assert!(!failed, "mac cancel launch: {long_text}");
	let long: serde_json::Value = serde_json::from_str(&long_text).expect("mac long JSON");
	let id = long["job"]["id"].as_str().expect("mac long id");
	tokio::time::sleep(Duration::from_millis(500)).await;
	let (failed, cancel) = call_runtime_tool_text(
		&client,
		"process_cancel",
		json!({"host":"mac","job_id":id,"grace_seconds":3}),
	)
	.await;
	assert!(!failed, "mac cancel: {cancel}");
	let (failed, waited) = call_runtime_tool_text(
		&client,
		"process_wait",
		json!({"host":"mac","job_id":id,"timeout_seconds":8}),
	)
	.await;
	assert!(!failed, "mac cancel wait: {waited}");
	let value: serde_json::Value = serde_json::from_str(&waited).expect("mac wait JSON");
	assert!(
		matches!(value["state"].as_str(), Some("cancelled" | "failed")),
		"{waited}"
	);
}
