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

//! MCP server handlers, session state, and tool parameter schemas.

use std::sync::{Arc, RwLock};

use rmcp::{
	handler::server::{wrapper::Parameters, ServerHandler},
	model::{
		CacheScope, CallToolResult, ContentBlock, CustomNotification, ExperimentalCapabilities,
		Implementation, JsonObject, ListResourcesResult, ListToolsResult, PaginatedRequestParams,
		ProtocolVersion, ReadResourceRequestParams, ReadResourceResponse, ReadResourceResult,
		RequestId, Resource, ResourceContents, ServerCapabilities, ServerConfig,
		ServerNotification, SubscribeRequestParams, SubscriptionFilter, UnsubscribeRequestParams,
	},
	schemars,
	service::{Peer, RequestContext, SubscriptionContext, SubscriptionSink},
	tool, tool_handler, tool_router, ErrorData, RoleServer,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use super::fs;
use super::request_ctx;
use super::runtime;
use super::McpToolCall;

/// Per-session working directory state.
/// Each server instance has its own workdir, isolated from other sessions.
#[derive(Debug)]
pub struct SessionWorkdir {
	/// The session root directory (set at session creation, never changes).
	pub root: PathBuf,
	/// The current working directory (can be changed via workdir tool).
	pub current: RwLock<Option<PathBuf>>,
}

impl SessionWorkdir {
	pub fn new(root: PathBuf) -> Self {
		Self {
			root,
			current: RwLock::new(None),
		}
	}

	/// Get the current working directory, or the root if not set.
	pub fn get_current(&self) -> PathBuf {
		self.current
			.read()
			.ok()
			.and_then(|guard| guard.clone())
			.unwrap_or_else(|| self.root.clone())
	}

	/// Set the current working directory.
	pub fn set_current(&self, path: PathBuf) {
		if let Ok(mut guard) = self.current.write() {
			*guard = Some(path);
		}
	}

	/// Reset to the session root.
	pub fn reset(&self) {
		if let Ok(mut guard) = self.current.write() {
			*guard = None;
		}
	}
}

/// Active `subscriptions/listen` streams opened by this session's client.
///
/// Sinks are registered when a client listens and removed when the stream
/// ends (client cancellation, transport close, or graceful teardown).
/// Background-job completion is delivered through matching sinks — the
/// 2026-07-28 contract path — and falls back to an unsolicited push for
/// clients that never opened a stream (see the `shell` tool's notifier).
#[derive(Debug, Default)]
struct SubscriptionRegistry {
	/// The guard is never held across an `.await`: sinks are cloned out first.
	sinks: std::sync::Mutex<Vec<SubscriptionSink>>,
}

impl SubscriptionRegistry {
	fn register(&self, sink: SubscriptionSink) {
		if let Ok(mut sinks) = self.sinks.lock() {
			sinks.push(sink);
		}
	}

	fn unregister(&self, id: &RequestId) {
		if let Ok(mut sinks) = self.sinks.lock() {
			sinks.retain(|sink| sink.id() != id);
		}
	}

	/// Sinks whose accepted filter covers `uri`, cloned out so no lock is held
	/// while sending.
	fn sinks_for(&self, uri: &str) -> Vec<SubscriptionSink> {
		self.sinks
			.lock()
			.map(|sinks| {
				sinks
					.iter()
					.filter(|sink| {
						sink.accepted()
							.resource_subscriptions
							.as_ref()
							.is_some_and(|uris| uris.iter().any(|u| u == uri))
					})
					.cloned()
					.collect()
			})
			.unwrap_or_default()
	}
}

fn background_job_finished(uri: &str) -> bool {
	fs::background::job_id_from_uri(uri)
		.and_then(fs::background::status)
		.is_some_and(|status| matches!(status, fs::background::JobStatus::Exited(_)))
}

/// Deliver a completion to every matching live subscription. Failed sinks are
/// removed immediately so they cannot suppress the legacy peer fallback.
async fn notify_subscriptions(subscriptions: &SubscriptionRegistry, uri: &str) -> bool {
	let mut delivered = false;
	for sink in subscriptions.sinks_for(uri) {
		let id = sink.id().clone();
		match sink.notify_resource_updated(uri).await {
			Ok(()) => delivered = true,
			Err(error) => {
				debug!("subscription delivery for {uri} failed: {error}");
				subscriptions.unregister(&id);
			}
		}
	}
	delivered
}

async fn notify_peer_resource_updated(peer: &Peer<RoleServer>, uri: &str) {
	if let Err(error) = peer
		.notify_resource_updated(rmcp::model::ResourceUpdatedNotificationParam::new(uri))
		.await
	{
		warn!(
			"background job notification for {uri} could not be delivered: {error}; \
			 completion remains available through the job resource"
		);
	}
}

/// Claude Code ignores `resources/updated` for the model (it only evicts its read
/// cache), so a job's exit would never wake the session. Its one server-to-model
/// push is a channel: a server declaring the `claude/channel` experimental
/// capability sends `notifications/claude/channel`, and Claude Code injects the
/// content as `<channel source="octofs" job="…">` into the session, starting a turn.
/// It accepts channels only from servers the user enabled (`--channels`, or
/// `--dangerously-load-development-channels server:<name>` for a local server), in
/// interactive sessions, on pre-2026-07-28 connections; other clients ignore it.
const CLAUDE_CHANNEL_CAPABILITY: &str = "claude/channel";
const RUNTIME_TOOL_NAMES: &[&str] = &[
	"process_checkpoint",
	"pdf_security",
	"binary_patch_inode",
	"document_render",
	"worksheet_recalculate",
	"worksheet_edit",
	"pdf_edit",
	"file_info",
	"binary_read",
	"binary_write",
	"binary_upload",
	"document_read",
	"image_read",
	"document_write",
	"document_edit",
	"shell_start",
	"host_processes",
	"host_signal",
	"sudo_start",
	"host_list",
	"process_start",
	"process_status",
	"process_read",
	"process_wait",
	"process_cancel",
	"process_list",
	"pty_start",
	"pty_read",
	"pty_write",
	"pty_close",
	"pty_list",
	"hardware_snapshot",
	"service_status",
	"network_inspect",
	"privileged_action",
];
const CLAUDE_CHANNEL_NOTIFICATION: &str = "notifications/claude/channel";

/// Push a finished job to Claude Code as a channel message carrying what
/// `resources/read` returns for it: the exit code and the output tail.
async fn notify_claude_channel(peer: &Peer<RoleServer>, uri: &str) {
	let Some(id) = fs::background::job_id_from_uri(uri) else {
		return;
	};
	let Some(body) = fs::background::resource_text(id) else {
		return;
	};
	let params = serde_json::json!({ "content": body, "meta": { "job": id } });
	let notification = CustomNotification::new(CLAUDE_CHANNEL_NOTIFICATION, Some(params));
	if let Err(error) = peer
		.send_notification(ServerNotification::CustomNotification(notification))
		.await
	{
		warn!("background job channel message for {uri} could not be delivered: {error}");
	}
}

/// Before 2026-07-28 a server may push notifications nobody subscribed to; the
/// 2026-07-28 revision routes every notification through a listen stream, and
/// Claude Code drops channels on such a connection.
fn allows_unsolicited_notifications(context: &RequestContext<RoleServer>) -> bool {
	!context
		.protocol_version()
		.is_some_and(|version| version >= ProtocolVersion::V_2026_07_28)
}

/// How often a running foreground `shell` command reports liveness. Well below
/// any sane client idle timeout so a single missed beat cannot cancel the call.
const SHELL_HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// MCP server with per-session working directory isolation.
#[derive(Debug, Clone)]
pub struct OctofsServer {
	/// Per-session working directory state.
	workdir: Arc<SessionWorkdir>,
	/// Whether the session context (workdir) has been applied from client
	/// capabilities. Applied once on the first tool call so a later `workdir`
	/// tool change is not overwritten by subsequent requests.
	session_applied: Arc<std::sync::atomic::AtomicBool>,
	/// Listen streams opened by this client, for contract-clean delivery of
	/// background-job completion notifications.
	subscriptions: Arc<SubscriptionRegistry>,
	/// Last full content served per file, so repeat whole-file views can
	/// return only what changed.
	view_cache: Arc<fs::delta::ViewCache>,
}

impl OctofsServer {
	/// Create a new server instance with the given session root directory.
	pub fn new() -> Self {
		Self::with_root(super::get_session_root_directory())
	}

	/// Create a server instance rooted at an explicit directory. HTTP sessions
	/// each build their own instance this way; tests use it to isolate the
	/// per-cwd background-job guard from sibling tests.
	pub fn with_root(root: PathBuf) -> Self {
		Self {
			workdir: Arc::new(SessionWorkdir::new(root)),
			session_applied: Arc::new(std::sync::atomic::AtomicBool::new(false)),
			subscriptions: Arc::new(SubscriptionRegistry::default()),
			view_cache: Arc::new(fs::delta::ViewCache::default()),
		}
	}

	/// Apply the octomind session context from client capabilities
	/// (`experimental.session.workdir`) on the first tool call.
	///
	/// Works for both protocol eras: modern clients (2026-07-28) carry
	/// capabilities in every request's `_meta`, legacy clients set them during
	/// the `initialize` handshake — `RequestContext::client_capabilities()`
	/// resolves both.
	fn ensure_session_workdir(&self, context: &RequestContext<RoleServer>) {
		if self
			.session_applied
			.swap(true, std::sync::atomic::Ordering::SeqCst)
		{
			return;
		}
		let Some(capabilities) = context.client_capabilities() else {
			return;
		};
		let Some(experimental) = &capabilities.experimental else {
			return;
		};
		if let Some(session_obj) = experimental.get("session") {
			if let Some(workdir_str) = session_obj.get("workdir").and_then(|v| v.as_str()) {
				let path = std::path::PathBuf::from(workdir_str);
				let policy_allows = runtime::config::maybe_runtime_config().is_none()
					|| runtime::config::check_local_path(&path).is_ok();
				if path.is_absolute() && path.is_dir() && policy_allows {
					self.workdir.set_current(path.clone());
					debug!("Session workdir set from capabilities: {}", path.display());
				} else {
					debug!(
						"Session workdir '{}' is not an absolute directory path, ignoring",
						workdir_str
					);
				}
			}
		}
	}
}

impl Default for OctofsServer {
	fn default() -> Self {
		Self::new()
	}
}

use std::path::PathBuf;

fn enforce_runtime_path_spec(
	path_spec: &str,
	workdir: &std::path::Path,
	write: bool,
) -> Result<(), String> {
	if runtime::config::maybe_runtime_config().is_none() {
		return Ok(());
	}
	if path_spec.starts_with("octofs://") {
		return Err("Octofs background resources are disabled in runtime mode".to_string());
	}
	for raw in path_spec.split('|') {
		let raw = raw.trim();
		if raw.is_empty() {
			return Err("path must not contain an empty root".to_string());
		}
		match fs::remote::resolve_path_source(raw, workdir) {
			fs::PathSource::Local(path) => {
				runtime::config::check_local_path(&path).map_err(|error| error.to_string())?;
			}
			fs::PathSource::Remote {
				host,
				path,
				user_explicit,
				port_explicit,
				..
			} => {
				runtime::config::check_remote_path(
					&host,
					&path,
					user_explicit,
					port_explicit,
					write,
				)
				.map_err(|error| error.to_string())?;
			}
		}
	}
	Ok(())
}

#[tool_router]
impl OctofsServer {
	#[tool(
		title = "View",
		annotations(
			read_only_hint = true,
			destructive_hint = false,
			idempotent_hint = true,
			open_world_hint = false
		),
		description = "Read files, list directories, search content. Lines render as \
			`N:hh|content`; copy `N:hh` verbatim — it is the line id edit tools target. Listings \
			are recursive and gitignore-aware, one `path\tNL\t~Nt` (lines, ~tokens) per file. \
			Re-viewing a whole file returns only the hunks changed since your last view (or an \
			unchanged marker); ranged reads always return the requested lines. Reuse returned \
			content: read a complete block in one call, combine adjacent windows, never re-read \
			overlapping ranges or narrow one just to pick edit targets; re-read only when the file \
			may have changed or output was truncated."
	)]
	async fn view(
		&self,
		context: RequestContext<RoleServer>,
		Parameters(params): Parameters<ViewParams>,
	) -> Result<String, String> {
		self.ensure_session_workdir(&context);
		let workdir = self.workdir.get_current();
		enforce_runtime_path_spec(&params.path, &workdir, false)?;
		let call = McpToolCall {
			tool_name: "view".to_string(),
			parameters: serde_json::to_value(&params).unwrap_or_default(),
			tool_id: String::new(),
			workdir,
		};
		request_ctx::with_request_context(self.view_cache.clone(), async move {
			let result = fs::execute_view(&call).await.map_err(|e| e.to_string())?;
			Ok(append_hints(result))
		})
		.await
	}

	#[tool(
		title = "Text Editor",
		annotations(
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = false
		),
		description = "File operations. create: new file only — fails if it exists, parent \
			directories are made. str_replace: raw file text (real newlines, no `N:hh|` \
			prefixes); old_text must match exactly once, or set replace_all: true — on no or \
			multiple matches the error lists candidate line ids for batch_edit. delete: remove a \
			file (not a directory). undo_edit: revert the last edit to `path` (10 levels, delete \
			included). Prefer batch_edit when you already hold line ids."
	)]
	async fn text_editor(
		&self,
		context: RequestContext<RoleServer>,
		Parameters(params): Parameters<TextEditorParams>,
	) -> Result<String, String> {
		self.ensure_session_workdir(&context);
		let workdir = self.workdir.get_current();
		enforce_runtime_path_spec(&params.path, &workdir, true)?;
		let call = McpToolCall {
			tool_name: "text_editor".to_string(),
			parameters: serde_json::to_value(&params).unwrap_or_default(),
			tool_id: String::new(),
			workdir,
		};
		request_ctx::with_request_context(self.view_cache.clone(), async move {
			let result = fs::execute_text_editor(&call)
				.await
				.map_err(|e| e.to_string())?;
			Ok(append_hints(result))
		})
		.await
	}

	#[tool(
		title = "Batch Edit",
		annotations(
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = false
		),
		description = "Apply insert/replace operations (max 50) to one file atomically. Targets \
			are line ids (\"12:a3\") from view or edit output, verified before anything is written; \
			a stale id fails with the current content. All targets refer to the original file and \
			must not overlap. The result diff carries fresh ids for follow-up edits — no re-view \
			needed; removed lines, and the middle of a long added block, show as an id range, and \
			a trailing `shift:` line says how later \
			original line numbers moved. Insert anchors 0 (file start) and -1 (end) are plain \
			integers. Content is raw text without id prefixes."
	)]
	async fn batch_edit(
		&self,
		context: RequestContext<RoleServer>,
		Parameters(params): Parameters<BatchEditParams>,
	) -> Result<String, String> {
		self.ensure_session_workdir(&context);
		let workdir = self.workdir.get_current();
		enforce_runtime_path_spec(&params.path, &workdir, true)?;
		let call = McpToolCall {
			tool_name: "batch_edit".to_string(),
			parameters: serde_json::to_value(&params).unwrap_or_default(),
			tool_id: String::new(),
			workdir,
		};
		request_ctx::with_request_context(self.view_cache.clone(), async move {
			let result = fs::execute_batch_edit(&call)
				.await
				.map_err(|e| e.to_string())?;
			Ok(append_hints(result))
		})
		.await
	}

	#[tool(
		title = "Extract Lines",
		annotations(
			read_only_hint = false,
			destructive_hint = false,
			idempotent_hint = false,
			open_world_hint = false
		),
		description = "Copy a line range from one file and append it into another without \
			retyping it — moving code between files, splitting modules. The source is left \
			untouched; to move, follow with a batch_edit that removes the range."
	)]
	async fn extract_lines(
		&self,
		context: RequestContext<RoleServer>,
		Parameters(params): Parameters<ExtractLinesParams>,
	) -> Result<String, String> {
		self.ensure_session_workdir(&context);
		let workdir = self.workdir.get_current();
		enforce_runtime_path_spec(&params.from_path, &workdir, false)?;
		enforce_runtime_path_spec(&params.append_path, &workdir, true)?;
		let call = McpToolCall {
			tool_name: "extract_lines".to_string(),
			parameters: serde_json::to_value(&params).unwrap_or_default(),
			tool_id: String::new(),
			workdir,
		};
		request_ctx::with_request_context(self.view_cache.clone(), async move {
			let result = fs::execute_extract_lines(&call)
				.await
				.map_err(|e| e.to_string())?;
			Ok(append_hints(result))
		})
		.await
	}

	#[tool(
		title = "Shell",
		annotations(
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = true
		),
		description = "Run a shell command: builds, tests, git, project CLIs. `sh -c` (`cmd /C` \
			on Windows) in the current workdir, local machine only, no stdin or TTY — never run \
			interactive commands or prefix `cd` to the workdir (`cd <other> && …` is fine one-off; \
			`workdir` switches permanently; a remote ssh:// workdir disables shell). Use `view` to \
			read, list and search files (cat/grep/ls except as a later pipe stage, `sed -i` and \
			echo/cat writes into the workdir are rejected). Output is terminal-clean \
			(ANSI and progress redraws stripped, repeated lines collapsed with a count; pipe \
			through `od -c` or `xxd` for exact bytes); a non-zero exit returns as an error with \
			the output. A command still running after ~10s moves to the background and returns a \
			job resource; you are notified with the exit code and output tail when it exits. Do \
			NOT poll, sleep, re-run or `ps` it — start the next independent step or end your turn. \
			Distinct commands run concurrently; an identical command in the same directory is \
			rejected while it runs."
	)]
	async fn shell(
		&self,
		context: RequestContext<RoleServer>,
		Parameters(params): Parameters<ShellParams>,
	) -> Result<CallToolResult, String> {
		if runtime::config::maybe_runtime_config().is_some() {
			return Err(
				"the unrestricted local shell tool is disabled in runtime mode; use process_start or an exact privileged_action"
					.to_string(),
			);
		}
		self.ensure_session_workdir(&context);
		let workdir = self.workdir.get_current();
		let call = McpToolCall {
			tool_name: "shell".to_string(),
			parameters: serde_json::to_value(&params).unwrap_or_default(),
			tool_id: String::new(),
			workdir,
		};
		// Heartbeat while a command is inside the foreground window, so the MCP
		// idle timeout does not cancel a call that is silent by nature. Anything
		// still running at the boundary is returned as a background resource, so
		// there is no held-open call or polling after promotion.
		let progress_token = context.meta.get_progress_token();
		let peer = context.peer.clone();
		// A background job outlives this call; when it exits, emit
		// `resources/updated` for its resource URI so the client can read the
		// output. Two delivery paths, by what the client set up: 2026-07-28
		// clients that opened a `subscriptions/listen` stream get the
		// notification on it (tagged with their subscription id by the sink);
		// everyone else gets the unsolicited push the pre-2026-07-28 spec
		// allowed. On pre-2026-07-28 connections the exit also goes out as a Claude
		// Code channel message, the only push that reaches its model. The peer and
		// registry handles are captured here and hidden behind an opaque callback so
		// the fs layer stays protocol-free.
		let completion_peer = context.peer.clone();
		let subscriptions = self.subscriptions.clone();
		let push_channel = allows_unsolicited_notifications(&context);
		let notifier: fs::shell::BackgroundNotify = Box::new(move |uri| {
			tokio::spawn(async move {
				if !notify_subscriptions(&subscriptions, &uri).await {
					notify_peer_resource_updated(&completion_peer, &uri).await;
				}
				if push_channel {
					notify_claude_channel(&completion_peer, &uri).await;
				}
			});
		});
		// The resource link carries the command as its name, so a client can
		// describe the job ("make reldebug … still running") without re-deriving
		// it — e.g. when preserving pending jobs across a context compaction.
		let job_label: String = params.command.trim().chars().take(80).collect();
		let exec = request_ctx::with_request_context(self.view_cache.clone(), async move {
			let outcome = fs::execute_shell_command(&call, Some(notifier))
				.await
				.map_err(|e| e.to_string())?;
			let mut content = vec![ContentBlock::text(append_hints(outcome.text))];
			if let Some(uri) = outcome.resource_uri {
				// A ResourceLink is the protocol-native "watch this" signal: the
				// client follows it generically, with no octofs-specific
				// knowledge, so shell can be served by any MCP server.
				let name = if job_label.is_empty() {
					"background shell job".to_string()
				} else {
					format!("shell: {job_label}")
				};
				content.push(ContentBlock::resource_link(Resource::new(uri, name)));
			}
			Ok::<_, String>(CallToolResult::success(content))
		});
		tokio::pin!(exec);
		let mut beats = 0.0_f64;
		loop {
			tokio::select! {
				biased;
				done = &mut exec => return done,
				_ = tokio::time::sleep(SHELL_HEARTBEAT_INTERVAL) => {
					let Some(token) = progress_token.clone() else { continue };
					beats += 1.0;
					let _ = peer
						.notify_progress(
							rmcp::model::ProgressNotificationParam::new(token, beats)
								.with_message("command still running"),
						)
						.await;
				}
			}
		}
	}

	#[tool(
		title = "Shell Start",
		annotations(
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = true
		),
		description = "Run a shell command on an administrator-configured operator host with the SSH account authority. Durable job identity, logs and idempotency use process_status/read/wait/cancel. Never retry uncertain execution with a new key. Isolated hosts deny this tool."
	)]
	async fn shell_start(
		&self,
		Parameters(params): Parameters<runtime::operator::ShellStartParams>,
	) -> Result<String, String> {
		runtime::operator::shell_start(params)
			.await
			.map_err(|error| error.to_string())
	}

	#[tool(
		title = "Host Processes",
		annotations(
			read_only_hint = true,
			destructive_hint = false,
			idempotent_hint = true,
			open_world_hint = true
		),
		description = "List actual host processes with bounded PID pagination and start identities, not only runtime jobs. Operator hosts only. Command arguments are omitted to avoid exposing secrets."
	)]
	async fn host_processes(
		&self,
		Parameters(params): Parameters<runtime::operator::HostProcessesParams>,
	) -> Result<String, String> {
		runtime::operator::host_processes(params)
			.await
			.map_err(|error| error.to_string())
	}

	#[tool(
		title = "Host Signal",
		annotations(
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = true
		),
		description = "Signal one positive target-host PID, including processes not created by this runtime. Operator hosts only; existing OS permissions and sudoers apply. Prefer expected_identity from host_processes. Result confirms signal delivery, not process termination. Never blindly retry uncertain delivery."
	)]
	async fn host_signal(
		&self,
		Parameters(params): Parameters<runtime::operator::HostSignalParams>,
	) -> Result<String, String> {
		runtime::operator::host_signal(params)
			.await
			.map_err(|error| error.to_string())
	}

	#[tool(
		title = "Sudo Start",
		annotations(
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = true
		),
		description = "Start a temporary arbitrary sudo command through an operator-host SSH PTY, using only that login account existing sudoers/PAM rights. Does not grant permissions or install NOPASSWD. Use pty_read/write/close. Never put passwords in arguments; input is not persisted by the runtime audit but may be retained by the MCP client."
	)]
	async fn sudo_start(
		&self,
		Parameters(params): Parameters<runtime::operator::SudoStartParams>,
	) -> Result<String, String> {
		runtime::operator::sudo_start(params)
			.await
			.map_err(|error| error.to_string())
	}

	#[tool(
		title = "Host List",
		annotations(
			read_only_hint = true,
			destructive_hint = false,
			idempotent_hint = true,
			open_world_hint = false
		),
		description = "List configured runtime host names and their capability flags. SSH destinations and credentials are never accepted from tool input."
	)]
	async fn host_list(
		&self,
		Parameters(_params): Parameters<runtime::inspect::HostListParams>,
	) -> Result<String, String> {
		runtime::inspect::host_list().map_err(|error| error.to_string())
	}

	#[tool(
		title = "Process Start",
		annotations(
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = true
		),
		description = "Start an explicit executable and argv on one configured host. No shell syntax is parsed. Jobs have durable metadata and logs, survive MCP reconnects, support idempotency keys, and may be resource-limited."
	)]
	async fn process_start(
		&self,
		Parameters(params): Parameters<runtime::jobs::ProcessStartParams>,
	) -> Result<String, String> {
		runtime::jobs::start_job(params)
			.await
			.map_err(|error| error.to_string())
	}

	#[tool(
		title = "Process Status",
		annotations(
			read_only_hint = true,
			destructive_hint = false,
			idempotent_hint = true,
			open_world_hint = true
		),
		description = "Read the authoritative state of a durable process created by this runtime. A job id is always bound to its original configured host."
	)]
	async fn process_status(
		&self,
		Parameters(params): Parameters<runtime::jobs::ProcessRefParams>,
	) -> Result<String, String> {
		runtime::jobs::status_job(params)
			.await
			.map_err(|error| error.to_string())
	}

	#[tool(
		title = "Process Read",
		annotations(
			read_only_hint = true,
			destructive_hint = false,
			idempotent_hint = true,
			open_world_hint = true
		),
		description = "Read bounded stdout and stderr ranges from a durable process using independent byte offsets. The response returns next offsets for lossless pagination."
	)]
	async fn process_read(
		&self,
		Parameters(params): Parameters<runtime::jobs::ProcessReadParams>,
	) -> Result<String, String> {
		runtime::jobs::read_job(params)
			.await
			.map_err(|error| error.to_string())
	}

	#[tool(
		title = "Process Wait",
		annotations(
			read_only_hint = true,
			destructive_hint = false,
			idempotent_hint = true,
			open_world_hint = true
		),
		description = "Wait up to 30 seconds for a durable process state change, then return its current state. This never starts or duplicates a job."
	)]
	async fn process_wait(
		&self,
		Parameters(params): Parameters<runtime::jobs::ProcessWaitParams>,
	) -> Result<String, String> {
		runtime::jobs::wait_job(params)
			.await
			.map_err(|error| error.to_string())
	}

	#[tool(
		title = "Process Cancel",
		annotations(
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = true,
			open_world_hint = true
		),
		description = "Cancel only a durable process created by this runtime. Ownership is verified from stored unit/job metadata; arbitrary PID signalling is not exposed."
	)]
	async fn process_cancel(
		&self,
		Parameters(params): Parameters<runtime::jobs::ProcessCancelParams>,
	) -> Result<String, String> {
		runtime::jobs::cancel_job(params)
			.await
			.map_err(|error| error.to_string())
	}

	#[tool(
		title = "Process List",
		annotations(
			read_only_hint = true,
			destructive_hint = false,
			idempotent_hint = true,
			open_world_hint = false
		),
		description = "List locally persisted durable job identities, optionally restricted to one configured host. Use process_status for live state."
	)]
	async fn process_list(
		&self,
		Parameters(params): Parameters<runtime::jobs::ProcessListParams>,
	) -> Result<String, String> {
		runtime::jobs::list_jobs(params).map_err(|error| error.to_string())
	}

	#[tool(
		title = "document_read",
		annotations(
			read_only_hint = true,
			destructive_hint = false,
			idempotent_hint = true,
			open_world_hint = false
		),
		description = "Read PDF pages, DOCX outline/XML, XLS stored results and XLSX worksheet ranges on the controller or an explicit configured operator host. Native remote transfers verify versions and SHA256. Optional PDF render returns native MCP images. No URL fetching, decryption, macros or recalculation."
	)]
	async fn document_read(
		&self,
		Parameters(params): Parameters<runtime::documents::DocumentReadParams>,
	) -> Result<CallToolResult, String> {
		runtime::documents::read(params, false)
			.await
			.map_err(|e| e.to_string())
	}

	#[tool(
		title = "image_read",
		annotations(
			read_only_hint = true,
			destructive_hint = false,
			idempotent_hint = true,
			open_world_hint = false
		),
		description = "Read a raster image on the controller or an explicit configured operator host as native MCP image content, with original SHA256 and dimensions. Preview is resized; use binary_read for lossless original bytes."
	)]
	async fn image_read(
		&self,
		Parameters(params): Parameters<runtime::documents::DocumentReadParams>,
	) -> Result<CallToolResult, String> {
		runtime::documents::read(params, true)
			.await
			.map_err(|e| e.to_string())
	}

	#[tool(
		title = "document_write",
		annotations(
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = false
		),
		description = "Create or replace PDF/DOCX from basic markdown, or XLSX from sheet row arrays, locally or on a configured operator host. Requires expected_sha256 or absent for create-only; no executable HTML, URL fetching or formula calculation."
	)]
	async fn document_write(
		&self,
		Parameters(params): Parameters<runtime::documents::DocumentWriteParams>,
	) -> Result<CallToolResult, String> {
		runtime::documents::write(params)
			.await
			.map_err(|e| e.to_string())
	}

	#[tool(
		title = "document_edit",
		annotations(
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = false
		),
		description = "Apply a fingerprint-checked exact XML replacement to a local or configured-operator-host DOCX body/header/footer. Preserve unselected package payloads. Reject invalid XML, stale versions and unexpected match counts. No shell operation."
	)]
	async fn document_edit(
		&self,
		Parameters(params): Parameters<runtime::documents::DocumentEditParams>,
	) -> Result<CallToolResult, String> {
		runtime::documents::edit(params)
			.await
			.map_err(|e| e.to_string())
	}

	#[tool(
		title = "file_info",
		annotations(
			read_only_hint = true,
			destructive_hint = false,
			idempotent_hint = true,
			open_world_hint = true
		),
		description = "Return a regular target file size, immutable-read version token, POSIX mode and full SHA256. Explicit configured operator host; rejects symlinks and special files."
	)]
	async fn file_info(
		&self,
		Parameters(params): Parameters<runtime::binary::FileInfoParams>,
	) -> Result<String, String> {
		runtime::binary::info(params)
			.await
			.map_err(|e| e.to_string())
	}

	#[tool(
		title = "binary_read",
		annotations(
			read_only_hint = true,
			destructive_hint = false,
			idempotent_hint = true,
			open_world_hint = true
		),
		description = "Read bounded base64 file bytes with independent chunk SHA256 and next_offset. Pin expected_version from the first chunk. No 1 MiB total file limit."
	)]
	async fn binary_read(
		&self,
		Parameters(params): Parameters<runtime::binary::BinaryReadParams>,
	) -> Result<String, String> {
		runtime::binary::read(params)
			.await
			.map_err(|e| e.to_string())
	}

	#[tool(
		title = "binary_write",
		annotations(
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = true
		),
		description = "Atomically publish at most 1 MiB of decoded base64 under the target account. expected_version is mandatory; absent is create-only. Preserves supported descriptor-bound ownership/mode, xattrs and ACLs with verification; rejects hard-link splits and special execution flags before publication."
	)]
	async fn binary_write(
		&self,
		Parameters(params): Parameters<runtime::binary::BinaryWriteParams>,
	) -> Result<String, String> {
		runtime::binary::write(params)
			.await
			.map_err(|e| e.to_string())
	}

	#[tool(
		title = "binary_upload",
		annotations(
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = true
		),
		description = "Stage binary files in bounded chunks and commit only after total size and SHA256 verification. Retries are bound to upload ID and offsets; destination is unchanged until commit. Commit replay verifies the published destination; abort never deletes committed output. This does not lock out noncooperating writers."
	)]
	async fn binary_upload(
		&self,
		Parameters(params): Parameters<runtime::binary::BinaryUploadParams>,
	) -> Result<String, String> {
		runtime::binary::upload(params)
			.await
			.map_err(|e| e.to_string())
	}

	#[tool(
		title = "PDF Page Edit",
		annotations(
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = true
		),
		description = "Insert/delete PDF pages into a distinct output file, preserving the source. Source/output fingerprints are required; inserted PDF sources also need SHA256. Supports local or explicitly configured operator-host paths. Page deletion is not secure redaction; signed/encrypted PDFs are rejected."
	)]
	async fn pdf_edit(
		&self,
		Parameters(params): Parameters<runtime::documents::PdfEditParams>,
	) -> Result<rmcp::model::CallToolResult, String> {
		runtime::documents::edit_pdf(params)
			.await
			.map_err(|e| e.to_string())
	}

	#[tool(
		title = "Worksheet Range Edit",
		annotations(
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = true
		),
		description = "Edit a bounded XLSX/XLSM cell range with source SHA256 validation. Preserves unselected OOXML package payloads and cell styles; invalidates formula caches and requests recalculation on open. Does NOT calculate formulas. Signed workbooks, merged sheets and shared/array formula edits are refused. Supports local and explicit operator-host files."
	)]
	async fn worksheet_edit(
		&self,
		Parameters(params): Parameters<runtime::documents::WorksheetEditParams>,
	) -> Result<rmcp::model::CallToolResult, String> {
		runtime::documents::edit_worksheet(params)
			.await
			.map_err(|e| e.to_string())
	}

	#[tool(
		title = "Rich Document PDF Render",
		annotations(
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = true
		),
		description = "Render HTML/CSS, Markdown or inline SVG to PDF locally or on a configured operator host. Assets require declared names, paths and SHA256 and are referenced as asset:name. No implicit file/HTTP requests, scripts or external resources. Return render warnings and actual page count; no pixel-identity claim to a browser."
	)]
	async fn document_render(
		&self,
		Parameters(params): Parameters<runtime::documents::DocumentRenderParams>,
	) -> Result<rmcp::model::CallToolResult, String> {
		runtime::documents::render_rich(params)
			.await
			.map_err(|e| e.to_string())
	}
	#[tool(
		title = "Worksheet Formula Recalculate",
		annotations(
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = true
		),
		description = "Compute supported XLSX/XLSM dependencies offline, including static global/local names, shared formulas, bounded declared fixed arrays and 1904 calendar serials. Preserve source formula encoding and unmodified OOXML payloads; require current SHA256. Reject circular/dynamic/external/relative-name/unsupported constructs before publication. Returns calculated caches and explicit error cells, not Microsoft Excel engine identity."
	)]
	async fn worksheet_recalculate(
		&self,
		Parameters(params): Parameters<runtime::documents::WorksheetRecalculateParams>,
	) -> Result<rmcp::model::CallToolResult, String> {
		runtime::documents::recalculate(params)
			.await
			.map_err(|e| e.to_string())
	}

	#[tool(
		title = "Recoverable Inode Patch",
		annotations(
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = true
		),
		description = "Linux-only explicit same-size patch of at most 64 KiB, preserving inode/hard links/open-file identity. Requires expected version/hash, transaction ID and acknowledgement of NON-ATOMIC visibility. Durable private receipts support status/recovery. Optional special mode-bit preservation uses existing owner rights only. Not a transactional snapshot for concurrent readers; capabilities/immutable flags are refused."
	)]
	async fn binary_patch_inode(
		&self,
		Parameters(params): Parameters<runtime::binary::InodePatchParams>,
	) -> Result<String, String> {
		runtime::binary::patch_inode(params)
			.await
			.map_err(|e| e.to_string())
	}

	#[tool(
		title = "PDF Protection and Signature Integrity",
		annotations(
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = true
		),
		description = "Inspect PDF detached-CMS byte-range integrity, create AES-256 encrypted or owner-authorized decrypted copies, or append an explicitly acknowledged unsigned metadata revision. Source/output SHA256 required. Passwords are private owned files on the chosen host, never raw parameters. Original files remain unchanged. Optional trust_store_file plus SHA256 validates the chain only against caller-supplied public roots. validate_policy additionally checks DocMDP/FieldMDP revision differences offline. fill_form_copy creates a distinct incremental text-form output only with explicit roots, allow_unsigned_revision and verified form-filling permission; locked fields or invalid revisions are refused. Revocation, trusted signing time and certificate-purpose policy remain unevaluated. Existing signatures do not sign a new revision."
	)]
	async fn pdf_security(
		&self,
		Parameters(params): Parameters<runtime::documents::PdfSecurityParams>,
	) -> Result<rmcp::model::CallToolResult, String> {
		runtime::documents::secure_pdf(params)
			.await
			.map_err(|e| e.to_string())
	}

	#[tool(
		title = "Process Checkpoint Lifecycle",
		annotations(
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = true
		),
		description = "Same-boot single-process Linux CRIU snapshots, only on administrator-pinned operator hosts. Inspect returns exact identity and resource limits. Dump stops/exits the original only after a validated private snapshot. Restore returns restored_stopped, never claims the program is running. A separate resume requires exact restored identity and acknowledge_resume. Old requests never silently relaunch; status exposes uncertain states. Internal pipes/unchanged files only; external sockets/terminals/GPU/multi-process state not supported. Uses existing sudo authority; no images or secrets returned."
	)]
	async fn process_checkpoint(
		&self,
		Parameters(params): Parameters<runtime::checkpoint::CheckpointParams>,
	) -> Result<String, String> {
		runtime::checkpoint::execute(params)
			.await
			.map_err(|e| e.to_string())
	}

	#[tool(
		title = "PTY Start",
		annotations(
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = true
		),
		description = "Start a real terminal on a configured host. Operator terminals are owned by a target-account daemon, retain a full disk archive and survive controller restarts. Use an idempotency_key to reconcile uncertain launches. Target reboot does not resume a running program. Isolated-host terminals remain controller-scoped."
	)]
	async fn pty_start(
		&self,
		Parameters(params): Parameters<runtime::pty::PtyStartParams>,
	) -> Result<String, String> {
		runtime::pty::start_pty(params)
			.await
			.map_err(|error| error.to_string())
	}

	#[tool(
		title = "PTY Read",
		annotations(
			read_only_hint = true,
			destructive_hint = false,
			idempotent_hint = true,
			open_world_hint = false
		),
		description = "Read bounded PTY output using byte cursors. By default text pages preserve complete UTF-8 characters (a tiny limit may extend up to 3 bytes); utf8_pending means an incomplete live character needs more input. Set raw_bytes=true for exact byte pages and decode bytes_hex for binary output. text_is_lossy labels invalid text; output_complete is false on capture errors. The ring reports dropped prefixes."
	)]
	async fn pty_read(
		&self,
		Parameters(params): Parameters<runtime::pty::PtyReadParams>,
	) -> Result<String, String> {
		runtime::pty::read_pty_async(params)
			.await
			.map_err(|error| error.to_string())
	}

	#[tool(
		title = "PTY Write",
		annotations(
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = true
		),
		description = "Write exact UTF-8 bytes, including control characters, to a PTY session created by this runtime."
	)]
	async fn pty_write(
		&self,
		Parameters(params): Parameters<runtime::pty::PtyWriteParams>,
	) -> Result<String, String> {
		runtime::pty::write_pty(params)
			.await
			.map_err(|error| error.to_string())
	}

	#[tool(
		title = "PTY Close",
		annotations(
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = true,
			open_world_hint = true
		),
		description = "Close a runtime-created terminal. Operator mode asks its target owner to terminate the terminal child group and retains the complete archive. This does not guarantee containment of privileged or deliberately detached descendants."
	)]
	async fn pty_close(
		&self,
		Parameters(params): Parameters<runtime::pty::PtyRefParams>,
	) -> Result<String, String> {
		runtime::pty::close_pty(params)
			.await
			.map_err(|error| error.to_string())
	}

	#[tool(
		title = "PTY List",
		annotations(
			read_only_hint = true,
			destructive_hint = false,
			idempotent_hint = true,
			open_world_hint = false
		),
		description = "List interactive PTY sessions owned by this runtime process, optionally restricted to one configured host."
	)]
	async fn pty_list(
		&self,
		Parameters(params): Parameters<runtime::pty::PtyListParams>,
	) -> Result<String, String> {
		runtime::pty::list_ptys_async(params)
			.await
			.map_err(|error| error.to_string())
	}

	#[tool(
		title = "Hardware Snapshot",
		annotations(
			read_only_hint = true,
			destructive_hint = false,
			idempotent_hint = true,
			open_world_hint = true
		),
		description = "Return a typed, read-only hardware snapshot from a configured host: DMI/CPU/memory, hwmon temperatures and power, GPU state, power supplies and limits, NPU devices, and USB4/Thunderbolt peers."
	)]
	async fn hardware_snapshot(
		&self,
		Parameters(params): Parameters<runtime::inspect::HostParams>,
	) -> Result<String, String> {
		runtime::inspect::hardware_snapshot(params)
			.await
			.map_err(|error| error.to_string())
	}

	#[tool(
		title = "Service Status",
		annotations(
			read_only_hint = true,
			destructive_hint = false,
			idempotent_hint = true,
			open_world_hint = true
		),
		description = "Read exact systemd unit or launchd label status from a configured host. This tool never starts, stops, enables, or disables services."
	)]
	async fn service_status(
		&self,
		Parameters(params): Parameters<runtime::inspect::ServiceStatusParams>,
	) -> Result<String, String> {
		runtime::inspect::service_status(params)
			.await
			.map_err(|error| error.to_string())
	}

	#[tool(
		title = "Network Inspect",
		annotations(
			read_only_hint = true,
			destructive_hint = false,
			idempotent_hint = true,
			open_world_hint = true
		),
		description = "Read links, addresses, routes, listeners, and USB4/Thunderbolt peers from a configured host without changing network state."
	)]
	async fn network_inspect(
		&self,
		Parameters(params): Parameters<runtime::inspect::HostParams>,
	) -> Result<String, String> {
		runtime::inspect::network_inspect(params)
			.await
			.map_err(|error| error.to_string())
	}

	#[tool(
		title = "Privileged Action",
		annotations(
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = true
		),
		description = "Run one exact, administrator-configured sudo action on a configured host. Arbitrary sudo commands, executable paths, services, and PIDs are never accepted from tool input."
	)]
	async fn privileged_action(
		&self,
		Parameters(params): Parameters<runtime::inspect::PrivilegedActionParams>,
	) -> Result<String, String> {
		runtime::inspect::privileged_action(params)
			.await
			.map_err(|error| error.to_string())
	}

	#[tool(
		title = "Working Directory",
		annotations(
			read_only_hint = false,
			destructive_hint = false,
			idempotent_hint = true,
			open_world_hint = false
		),
		description = "Switch the working directory for later calls (`path`) or revert to the \
			session root (`reset: true`). Every tool resolves relative paths against it; do not \
			call it just to check the directory. A remote (ssh://) workdir disables `shell`."
	)]
	async fn workdir(
		&self,
		context: RequestContext<RoleServer>,
		Parameters(params): Parameters<WorkdirParams>,
	) -> Result<String, String> {
		self.ensure_session_workdir(&context);
		let workdir = self.workdir.get_current();
		if !params.reset.unwrap_or(false) {
			if let Some(path) = params.path.as_deref() {
				enforce_runtime_path_spec(path, &workdir, false)?;
			}
		}
		let call = McpToolCall {
			tool_name: "workdir".to_string(),
			parameters: serde_json::to_value(&params).unwrap_or_default(),
			tool_id: String::new(),
			workdir,
		};
		let result = fs::execute_workdir_command(&call)
			.await
			.map_err(|e| e.to_string())?;

		// Update session workdir state based on the structured result
		match &result {
			fs::WorkdirResult::Set { current, .. } => {
				self.workdir.set_current(current.clone());
			}
			fs::WorkdirResult::Reset => {
				self.workdir.reset();
			}
			fs::WorkdirResult::Get { .. } => {}
		}

		Ok(result.to_json_string())
	}
}

/// Collapse `"type": [T, "null"]` to `T` and `anyOf: [X, {"type": "null"}]` to
/// `X` throughout a tool schema, merging the surviving branch into the parent
/// so field-level keys (description) win.
///
/// schemars emits those nullable forms for every `Option<T>` parameter. Serving
/// stacks build their tool-call grammar from `"type"` and some read it as a
/// plain string: given the array form they fall through to the string branch and
/// constrain the model to emit the argument as text — `"3"` instead of `3` —
/// which rmcp then rejects while deserializing parameters. Measured on Alibaba
/// Model Studio's Qwen path and on CoreWeave; the same weights on Parasail,
/// Chutes and DeepInfra are unaffected.
///
/// Lossless: optionality is carried by `required`. Genuine multi-branch unions
/// (the `string | integer` line endpoints) have nothing to collapse to and are
/// left alone — `parse_endpoint` accepts either form anyway.
fn strip_null_variants(value: &mut serde_json::Value) {
	match value {
		serde_json::Value::Object(obj) => {
			for nested in obj.values_mut() {
				strip_null_variants(nested);
			}

			let collapsed_type =
				obj.get_mut("type")
					.and_then(|t| t.as_array_mut())
					.and_then(|types| {
						types.retain(|t| t.as_str() != Some("null"));
						(types.len() == 1).then(|| types[0].clone())
					});
			if let Some(single) = collapsed_type {
				obj.insert("type".to_string(), single);
			}

			for key in ["anyOf", "oneOf"] {
				let only = obj
					.get_mut(key)
					.and_then(|v| v.as_array_mut())
					.and_then(|variants| {
						variants.retain(|v| v.get("type").and_then(|t| t.as_str()) != Some("null"));
						(variants.len() == 1).then(|| variants[0].clone())
					});
				if let Some(serde_json::Value::Object(only)) = only {
					obj.remove(key);
					for (k, v) in only {
						obj.entry(k).or_insert(v);
					}
				}
			}
		}
		serde_json::Value::Array(items) => {
			for item in items.iter_mut() {
				strip_null_variants(item);
			}
		}
		_ => {}
	}
}

/// schemars emits keys no model acts on: `$schema`, the `format` of every integer
/// (`int64`, `uint` — `minimum` already bounds the unsigned ones) and `default: null`
/// on every optional field. Always-loaded tool definitions ride on every request, so
/// they are dropped. Keyword-aware: under `properties`/`$defs` the keys are names,
/// so a parameter called `format` or `default` survives.
fn strip_generator_noise(schema: &mut serde_json::Map<String, serde_json::Value>) {
	schema.remove("$schema");
	schema.remove("format");
	if schema
		.get("default")
		.is_some_and(serde_json::Value::is_null)
	{
		schema.remove("default");
	}
	for (key, value) in schema.iter_mut() {
		match (key.as_str(), value) {
			("properties" | "$defs", serde_json::Value::Object(named)) => {
				for sub in named.values_mut() {
					if let serde_json::Value::Object(sub) = sub {
						strip_generator_noise(sub);
					}
				}
			}
			(_, serde_json::Value::Object(sub)) => strip_generator_noise(sub),
			(_, serde_json::Value::Array(items)) => {
				for item in items {
					if let serde_json::Value::Object(sub) = item {
						strip_generator_noise(sub);
					}
				}
			}
			_ => {}
		}
	}
}

/// 2026-07-28 makes `ttlMs` and `cacheScope` required on list and read results;
/// older protocol versions don't define them. rmcp's generated `list_tools` sets
/// them, so the overrides below must too — a strict 2026-07-28 client (Claude
/// Code's `server/discover` runtime) rejects the result and loads no tools at all.
fn supports_cache_hints(context: &RequestContext<RoleServer>) -> bool {
	context
		.protocol_version()
		.is_some_and(|version| version >= ProtocolVersion::V_2026_07_28)
}

#[tool_handler(router = Self::tool_router())]
impl ServerHandler for OctofsServer {
	fn get_info(&self) -> ServerConfig {
		ServerConfig::new(
			// Resources (read/list) advertise automatically promoted shell jobs
			// as handles. `subscribe` is advertised because resource updates are
			// deliverable both ways: on a `subscriptions/listen` stream (the
			// 2026-07-28 contract path, see `listen` below) and as the
			// unsolicited push legacy clients expect (the `shell` notifier's
			// fallback path). `claude/channel` lets Claude Code sessions that
			// enabled octofs as a channel receive job exits (see
			// `notify_claude_channel`).
			ServerCapabilities::builder()
				.enable_experimental_with(ExperimentalCapabilities::from([(
					CLAUDE_CHANNEL_CAPABILITY.to_string(),
					JsonObject::new(),
				)]))
				.enable_tools()
				.enable_resources()
				.enable_resources_subscribe()
				.build(),
		)
		.with_server_info(Implementation::from_build_env())
		.with_protocol_version(ProtocolVersion::V_2026_07_28)
		.with_instructions(
			"Filesystem tools. File lines render as `N:hh|content`; `N:hh` is the line id edit \
				 tools target, and edit results are diffs with fresh ids, so edits chain without \
				 re-viewing files. Reuse returned content and ids; read complete relevant blocks, \
				 then act on them. Each response costs a round trip: first decide what you need \
				 next, then request every call that doesn't depend on another's result in that one \
				 response."
				.to_string(),
		)
	}

	async fn list_tools(
		&self,
		_request: Option<PaginatedRequestParams>,
		context: RequestContext<RoleServer>,
	) -> Result<ListToolsResult, ErrorData> {
		let runtime_enabled = runtime::config::maybe_runtime_config().is_some();
		let tools = Self::tool_router()
			.list_all()
			.into_iter()
			.filter(|tool| {
				if runtime_enabled {
					tool.name.as_ref() != "shell"
				} else {
					!RUNTIME_TOOL_NAMES.contains(&tool.name.as_ref())
				}
			})
			.map(|mut tool| {
				let mut schema = tool.input_schema.as_ref().clone();
				for value in schema.values_mut() {
					strip_null_variants(value);
				}
				strip_generator_noise(&mut schema);
				tool.input_schema = Arc::new(schema);
				tool
			})
			.collect();
		let result = ListToolsResult::with_all_items(tools);
		if !supports_cache_hints(&context) {
			return Ok(result);
		}
		// ttl 0 matches rmcp's generated handler; the list is identical for every caller.
		Ok(result.with_ttl_ms(0).with_cache_scope(CacheScope::Public))
	}

	// Background shell jobs are surfaced as resources: each promoted command is
	// `octofs://jobs/<id>`, readable for its status and output tail. On exit the
	// job's wait task emits `resources/updated` for that URI (see the `shell`
	// handler's notifier), so a client learns a build finished without polling.
	async fn list_resources(
		&self,
		_request: Option<PaginatedRequestParams>,
		context: RequestContext<RoleServer>,
	) -> Result<ListResourcesResult, ErrorData> {
		let resources = fs::background::list()
			.into_iter()
			.map(|job| {
				let state = match job.status() {
					fs::background::JobStatus::Running => "running",
					fs::background::JobStatus::Exited(_) => "finished",
				};
				Resource::new(
					fs::background::resource_uri(&job.id),
					format!("background shell job ({state}): {}", job.command),
				)
			})
			.collect();
		let result = ListResourcesResult::with_all_items(resources);
		if !supports_cache_hints(&context) {
			return Ok(result);
		}
		// Jobs come and go and belong to this session: never fresh, never shared.
		Ok(result.with_ttl_ms(0).with_cache_scope(CacheScope::Private))
	}

	async fn read_resource(
		&self,
		request: ReadResourceRequestParams,
		context: RequestContext<RoleServer>,
	) -> Result<ReadResourceResponse, ErrorData> {
		let uri = request.uri;
		let id = fs::background::job_id_from_uri(&uri)
			.ok_or_else(|| ErrorData::resource_not_found(format!("Not a job URI: {uri}"), None))?;
		let body = fs::background::resource_text(id).ok_or_else(|| {
			ErrorData::resource_not_found(format!("No such background job: {uri}"), None)
		})?;
		let result = ReadResourceResult::new(vec![ResourceContents::text(body, uri)]);
		if !supports_cache_hints(&context) {
			return Ok(result.into());
		}
		// A running job's tail changes between reads, and it is this session's job.
		Ok(result
			.with_ttl_ms(0)
			.with_cache_scope(CacheScope::Private)
			.into())
	}

	// 2026-07-28 change notifications are opt-in: the client opens a
	// `subscriptions/listen` stream filtered to what it wants, and the SDK
	// acknowledges the accepted subset before `listen` runs. Accept whatever
	// the client asked for — the SDK intersects it with the capabilities
	// advertised in `get_info` (resources.subscribe gates URI subscriptions).
	fn accepted_subscription_filter(
		&self,
		requested: &SubscriptionFilter,
	) -> Option<SubscriptionFilter> {
		Some(requested.clone())
	}

	// Keep the sink registered for the life of the stream so background-job
	// completion can be delivered on it. `cancelled` resolves on client
	// cancellation, transport close, or graceful teardown — however the
	// stream ends, the sink is removed. A sink whose stream died between
	// registration and delivery self-reports as closed on send.
	async fn listen(&self, context: SubscriptionContext) -> Result<(), ErrorData> {
		let sink = context.sink().clone();
		let id = sink.id().clone();
		let uris = sink
			.accepted()
			.resource_subscriptions
			.clone()
			.unwrap_or_default();
		self.subscriptions.register(sink.clone());

		// Registration happens before this check. If the job exits concurrently,
		// either its completion path sees this sink or this replay sees the exited
		// state (possibly both, which is safe for a change notification).
		for uri in uris.into_iter().filter(|uri| background_job_finished(uri)) {
			if let Err(error) = sink.notify_resource_updated(uri.clone()).await {
				debug!("late subscription replay for {uri} failed: {error}");
				self.subscriptions.unregister(&id);
				notify_peer_resource_updated(&context.request_context().peer, &uri).await;
			}
		}
		context.cancelled().await;
		self.subscriptions.unregister(&id);
		Ok(())
	}

	// Legacy (pre-2026-07-28) clients that see `subscribe` advertised may run
	// the `resources/subscribe` handshake. Normal delivery is the unsolicited
	// push sent on job exit. If that happened before this subscription arrived,
	// replay it now from the retained job state.
	async fn subscribe(
		&self,
		request: SubscribeRequestParams,
		context: RequestContext<RoleServer>,
	) -> Result<(), ErrorData> {
		if background_job_finished(&request.uri) {
			notify_peer_resource_updated(&context.peer, &request.uri).await;
		}
		Ok(())
	}

	async fn unsubscribe(
		&self,
		_request: UnsubscribeRequestParams,
		_context: RequestContext<RoleServer>,
	) -> Result<(), ErrorData> {
		Ok(())
	}

	// The default `initialize` (legacy clients) and `discover` (2026-07-28
	// clients) implementations handle version negotiation; the session
	// workdir from client capabilities is applied per-request in
	// `ensure_session_workdir`, which covers both eras.
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod server_tests;

/// Drain this request's hints and append them to the tool result.
/// Called after tool execution (inside the request scope) to surface guidance to the LLM.
fn append_hints(mut result: String) -> String {
	let hints = request_ctx::drain_hints();
	if !hints.is_empty() {
		result.push_str("\n\n");
		for hint in hints {
			result.push_str("⚠️ ");
			result.push_str(&hint);
			result.push('\n');
		}
	}
	result
}
// ── Tool parameter schemas ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ViewParams {
	/// File or directory. `a|b` searches several roots with `content` (max 32); several
	/// files take parallel view calls. Remote: ssh://[user@]host[:port]/path (host may be an
	/// ~/.ssh/config alias; `ssh://host` or `ssh://host/~/dir` is the login home).
	pub path: String,
	/// First line (inclusive): line id or integer (negative counts from the end, -1 = last).
	/// Default: line 1.
	#[serde(default)]
	#[schemars(schema_with = "line_endpoint_schema")]
	pub start: Option<serde_json::Value>,
	/// Last line (inclusive): line id or integer (negative counts from the end). Default: end
	/// of file; omit both `start` and `end` for the whole file.
	#[serde(default)]
	#[schemars(schema_with = "line_endpoint_schema")]
	pub end: Option<serde_json::Value>,
	/// Ripgrep -g globs bounding listings and searches: without `/` a name at any depth,
	/// with `/` the relative path; `*`, `**`, `?`, `[abc]`, `{rs,toml}`, leading `!`; `|`
	/// joins ordered globs (later wins), e.g. `**/*.rs|!target/**`. Applied after
	/// gitignore/hidden filtering; one line, max 4096 bytes, 64 globs.
	#[serde(default)]
	pub pattern: Option<String>,
	/// Locate code: searches the whole file/tree (`start`/`end` ignored) for a literal
	/// substring, or a Rust regex with `regex: true` (`(?i)` case-insensitive; alternation for
	/// related terms).
	#[serde(default)]
	pub content: Option<String>,
	/// Treat `content` as a regex. Default: false.
	#[serde(default)]
	pub regex: Option<bool>,
	/// Directory depth bound. Default: unlimited, except a bare remote listing (no
	/// `pattern`/`content`) stops at the root entries. Searches walk the whole tree.
	#[serde(default)]
	pub max_depth: Option<usize>,
	/// Include dotfiles and dot-directories.
	#[serde(default)]
	pub include_hidden: Option<bool>,
	/// Lines around each `content` match. Default: 0.
	#[serde(default)]
	pub context: Option<usize>,
	/// Force the complete file when re-viewing a whole file (normally only changed hunks),
	/// e.g. after losing earlier context. No effect on ranges or searches; output limits
	/// unchanged.
	#[serde(default)]
	pub full: Option<bool>,
}

/// JSON schema for a single line endpoint (`start`/`end`/`append_line`/op `start`/`end`).
///
/// One shape everywhere: a line id string "N:hh" copied from view output (verified
/// against the file before edits), or a plain integer line number where positions are
/// allowed (view ranges, insert anchors 0/-1). `anyOf` (not `oneOf`) is used because
/// it has strictly wider cross-stack support.
fn line_endpoint_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
	let schema = serde_json::json!({
		"description": "Line id \"N:hh\" from view/edit output, or an integer line number (negative counts from the end). Edit targets require ids.",
		"anyOf": [
			{ "type": "string" },
			{ "type": "integer", "format": "int64" }
		],
		"examples": ["12:a3", -1]
	});
	serde_json::from_value(schema).expect("static schema is valid JSON")
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TextEditorCommand {
	Create,
	StrReplace,
	Delete,
	UndoEdit,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct TextEditorParams {
	/// Operation to perform.
	pub command: TextEditorCommand,
	/// File path (ssh://user@host:port/path for remote).
	pub path: String,
	/// Content for `create`.
	#[serde(default)]
	pub content: Option<String>,
	/// `str_replace`: exact text to find (required).
	#[serde(default)]
	pub old_text: Option<String>,
	/// `str_replace`: replacement text (required).
	#[serde(default)]
	pub new_text: Option<String>,
	/// `str_replace`: replace every occurrence (rename-style). Default: false.
	#[serde(default)]
	pub replace_all: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BatchEditOperationType {
	Insert,
	Replace,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct BatchEditOperation {
	/// `insert` (after `start`) or `replace` (`start`..`end`).
	pub operation: BatchEditOperationType,
	/// Line id in the ORIGINAL file: first line to replace, or the anchor to insert after
	/// (for `insert` also the integers 0 = file start, -1 = after the last line).
	#[schemars(schema_with = "line_endpoint_schema")]
	pub start: serde_json::Value,
	/// `replace` only: last line to replace (inclusive), as a line id. Default: `start`.
	#[serde(default)]
	#[schemars(schema_with = "line_endpoint_schema")]
	pub end: Option<serde_json::Value>,
	/// Raw text to insert or replace with, no line-id prefixes.
	#[serde(deserialize_with = "string_or_lines")]
	pub content: String,
}

/// Accept content as a string or as a list of lines. A list names exactly one
/// block of text, so joining it beats rejecting the call and being re-sent the
/// same edit as a string.
fn string_or_lines<'de, D>(deserializer: D) -> Result<String, D::Error>
where
	D: serde::Deserializer<'de>,
{
	match serde_json::Value::deserialize(deserializer)? {
		serde_json::Value::String(s) => Ok(s),
		serde_json::Value::Array(items) => items
			.iter()
			.map(|item| match item {
				serde_json::Value::String(s) => Ok(s.as_str()),
				other => Err(serde::de::Error::custom(format!(
					"content list must hold strings, found {other}"
				))),
			})
			.collect::<Result<Vec<_>, _>>()
			.map(|lines| lines.join("\n")),
		other => Err(serde::de::Error::custom(format!(
			"content must be a string or a list of lines, found {other}"
		))),
	}
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct BatchEditParams {
	/// File to edit (ssh://user@host:port/path for remote).
	pub path: String,
	/// Operations on this one file (max 50).
	#[schemars(length(max = 50))]
	pub operations: Vec<BatchEditOperation>,
}

/// The tool edits one file, so callers sometimes carry `path` on each operation
/// instead of at the top level. When every operation names the same file that is
/// the file to edit, so it is hoisted rather than refused; disagreeing paths stay
/// an error because no single target is named.
impl<'de> Deserialize<'de> for BatchEditParams {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		#[derive(Deserialize)]
		struct Raw {
			#[serde(default)]
			path: Option<String>,
			operations: Vec<serde_json::Value>,
		}

		let mut raw = Raw::deserialize(deserializer)?;
		let mut per_op: Vec<String> = Vec::new();
		for op in &mut raw.operations {
			if let Some(obj) = op.as_object_mut() {
				if let Some(serde_json::Value::String(p)) = obj.remove("path") {
					per_op.push(p);
				}
			}
		}

		let path = match raw.path {
			Some(p) => p,
			None => {
				let mut unique: Vec<&String> = Vec::new();
				for p in &per_op {
					if !unique.contains(&p) {
						unique.push(p);
					}
				}
				match unique.as_slice() {
					[only] => (*only).clone(),
					[] => return Err(serde::de::Error::missing_field("path")),
					_ => return Err(serde::de::Error::custom(
						"batch_edit edits a single file, but the operations name different paths; \
							 issue one batch_edit per file",
					)),
				}
			}
		};

		let operations = raw
			.operations
			.into_iter()
			.map(serde_json::from_value::<BatchEditOperation>)
			.collect::<Result<Vec<_>, _>>()
			.map_err(serde::de::Error::custom)?;

		Ok(BatchEditParams { path, operations })
	}
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ExtractLinesParams {
	/// Source file (ssh://user@host:port/path for remote).
	pub from_path: String,
	/// First line to copy (inclusive): integer or line id (verified against the source).
	#[schemars(schema_with = "line_endpoint_schema")]
	pub from_start: serde_json::Value,
	/// Last line to copy (inclusive): integer or line id. Default: `from_start`.
	#[serde(default)]
	#[schemars(schema_with = "line_endpoint_schema")]
	pub from_end: Option<serde_json::Value>,
	/// Target file the lines are appended to (ssh://user@host:port/path for remote).
	pub append_path: String,
	/// Where to append in the target: 0 = beginning, -1 = end, N = after line N, or a line
	/// id (verified against the target).
	#[schemars(schema_with = "line_endpoint_schema")]
	pub append_line: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ShellParams {
	/// Command line for `sh -c`; use non-interactive flags (`-y`, `--no-pager`, `CI=1`) for
	/// anything that might prompt.
	pub command: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct WorkdirParams {
	/// Directory to switch into, absolute or relative to the current workdir; required unless
	/// `reset`. Not `"."` (a no-op). Remote: ssh://user@host:port/path; `ssh://host` or
	/// `ssh://host/~/dir` is the login home.
	#[serde(default)]
	pub path: Option<String>,
	/// Revert to the session root.
	#[serde(default)]
	pub reset: Option<bool>,
}

// ── Server implementation ───────────────────────────────────────────────────────
