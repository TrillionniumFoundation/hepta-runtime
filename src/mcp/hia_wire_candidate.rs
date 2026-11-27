// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Pinned native HIA wire admission while MCP retains request and effect ownership.

use std::{
	env,
	fs::{self, File, Permissions},
	io::{self, Read, Write},
	os::{
		fd::{AsRawFd, FromRawFd},
		unix::fs::PermissionsExt,
	},
	path::PathBuf,
	process::Stdio,
	sync::{Arc, Mutex, OnceLock},
	time::Duration,
};

use anyhow::{ensure, Context, Result};
use axum::{
	body::{Body, Bytes},
	extract::Request,
	http::{request::Parts, Method},
};
use http_body::{Body as HttpBody, Frame, SizeHint};
use rmcp::model::{CallToolRequestParams, RequestId};
use tokio::{process::Command, time::timeout};

#[derive(Clone)]
pub(super) struct Admitted(pub(super) bool);
const PATH: &str = "HIA_LOCAL_MCP_WIRE_IMAGE";
const SHA: &str = "HIA_LOCAL_MCP_WIRE_SHA256";
const BINARY_MAX: usize = 1 << 20;
const WIRE_MAX: usize = 8 << 20;
const SEALS: libc::c_int =
	libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;

pub(super) fn image_selected(path: &str, pin: &str) -> bool {
	super::hia_controller_release::selected(path)
		|| env::var_os(path).is_some()
		|| env::var_os(pin).is_some()
}

pub(super) fn selected() -> bool {
	image_selected(PATH, SHA)
}

pub(super) fn sealed(name: &std::ffi::CStr, bytes: &[u8], executable: bool) -> io::Result<File> {
	// Linux returns a fresh owned descriptor on success.
	let fd =
		unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
	if fd < 0 {
		return Err(io::Error::last_os_error());
	}
	let mut file = unsafe { File::from_raw_fd(fd) };
	file.write_all(bytes)?;
	file.set_permissions(Permissions::from_mode(if executable {
		0o500
	} else {
		0o400
	}))?;
	if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, SEALS) } != 0 {
		return Err(io::Error::last_os_error());
	}
	Ok(file)
}

pub(super) fn admit_executable(path_key: &str, pin_key: &str) -> Result<File> {
	if let Some(source) = super::hia_controller_release::image(path_key) {
		return Ok(source?);
	}
	let path = PathBuf::from(env::var_os(path_key).context("missing HIA wire image")?);
	ensure!(path.is_absolute(), "HIA wire image must be absolute");
	let expected = env::var(pin_key).context("missing HIA wire digest")?;
	let mut contents = Vec::new();
	fs::File::open(path)?
		.take((BINARY_MAX + 1) as u64)
		.read_to_end(&mut contents)?;
	ensure!(
		!contents.is_empty()
			&& contents.len() <= BINARY_MAX
			&& super::hia_contract::sha256(&contents) == expected,
		"invalid HIA wire image identity"
	);
	Ok(sealed(c"hia-mcp-wire-executable", &contents, true)?)
}

fn frame_word(bytes: &[u8], at: usize) -> Result<u64> {
	let end = at
		.checked_add(8)
		.context("HIA frame word offset overflow")?;
	let word = bytes.get(at..end).context("truncated HIA frame word")?;
	Ok(u64::from_le_bytes(
		word.try_into().context("invalid HIA frame word extent")?,
	))
}

struct WireObservation<'a> {
	raw: &'a [u8],
	descriptor: Vec<u8>,
}

impl<'a> WireObservation<'a> {
	fn word(&self, at: usize) -> Result<u64> {
		frame_word(&self.descriptor, at)
	}

	fn span(&self, at: usize) -> Option<&'a [u8]> {
		let start = usize::try_from(self.word(at).ok()?).ok()?;
		let size = usize::try_from(self.word(at.checked_add(8)?).ok()?).ok()?;
		self.raw.get(start..start.checked_add(size)?)
	}

	fn require_id(&self, request_id: &RequestId) -> Result<()> {
		let id = self.span(32).context("invalid HIA request ID span")?;
		let native_id: RequestId = serde_json::from_slice(id)?;
		ensure!(&native_id == request_id, "HIA native ID does not match SDK");
		Ok(())
	}
}

async fn observe_wire(raw: &[u8]) -> Result<WireObservation<'_>> {
	static IMAGE: OnceLock<Result<File, String>> = OnceLock::new();
	let image = IMAGE
		.get_or_init(|| admit_executable(PATH, SHA).map_err(|error| error.to_string()))
		.as_ref()
		.map_err(|error| anyhow::anyhow!("{error}"))?;
	// The newline belongs to stdio framing and is excluded from the wire cap.
	let raw = raw.strip_suffix(b"\n").unwrap_or(raw);
	ensure!(
		(2..=WIRE_MAX).contains(&raw.len()),
		"HIA wire size out of bounds"
	);
	let input = sealed(c"hia-mcp-wire-frame", raw, false)?;
	let executable = format!("/proc/self/fd/{}", image.as_raw_fd());
	let mut command = Command::new(executable);
	command
		.env_clear()
		.kill_on_drop(true)
		.stdin(Stdio::from(input));
	let out = timeout(Duration::from_secs(3), command.output()).await??;
	ensure!(
		out.status.success() && out.stderr.is_empty() && out.stdout.len() == 96,
		"HIA wire admission refused"
	);
	let wire = WireObservation {
		raw,
		descriptor: out.stdout,
	};
	ensure!(
		wire.word(0)? == 88 && &wire.descriptor[8..16] == b"HIAMCP01" && wire.word(88)? == 0,
		"invalid HIA wire descriptor"
	);
	Ok(wire)
}

pub(super) async fn observe(
	raw: &[u8],
	call: &CallToolRequestParams,
	request_id: &RequestId,
) -> Result<()> {
	let wire = observe_wire(raw).await?;
	ensure!(
		wire.word(16)? == 5,
		"HIA native wire did not select the tool route"
	);
	let ordinal = wire.word(64)?;
	ensure!(
		ordinal > 0
			&& super::hia_contract::TOOLS.get((ordinal - 1) as usize) == Some(&call.name.as_ref()),
		"HIA native tool name does not match SDK"
	);
	wire.require_id(request_id)?;
	let arg_wire = wire.span(72).context("invalid HIA argument span")?;
	let native_args = if arg_wire.is_empty() {
		None
	} else {
		Some(serde_json::from_slice(arg_wire)?)
	};
	ensure!(
		native_args == call.arguments,
		"HIA native arguments do not match SDK"
	);
	tracing::info!(tool = %call.name, bytes = wire.raw.len(), "Native HIA wire admission accepted");
	Ok(())
}

#[derive(Clone)]
pub(super) struct ResourceWireAdmitted(pub(super) bool);

pub(super) async fn observe_resource(raw: &[u8], uri: &str, request_id: &RequestId) -> Result<()> {
	let wire = observe_wire(raw).await?;
	ensure!(
		wire.word(16)? == 8 && wire.word(64)? == 0,
		"HIA native wire did not select the resource-read route"
	);
	wire.require_id(request_id)?;
	let raw_uri = wire.span(72).context("invalid HIA resource URI span")?;
	let native_uri: String = serde_json::from_slice(raw_uri)?;
	ensure!(
		native_uri == uri,
		"HIA native resource URI does not match SDK"
	);
	tracing::info!(
		bytes = wire.raw.len(),
		"Native HIA admitted the original MCP resource URI"
	);
	Ok(())
}

// rmcp consumes the HTTP stream before dispatch, but preserves request Parts.
// Copy only its data frames and leave SDK framing, header order and limits intact.
#[derive(Clone)]
struct HttpRequestWire(Arc<Mutex<Option<Vec<u8>>>>);

struct CapturingBody {
	body: Body,
	wire: HttpRequestWire,
}

impl HttpBody for CapturingBody {
	type Data = Bytes;
	type Error = axum::Error;

	fn poll_frame(
		mut self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<Option<std::result::Result<Frame<Bytes>, Self::Error>>> {
		let next = std::pin::Pin::new(&mut self.body).poll_frame(cx);
		if let std::task::Poll::Ready(Some(Ok(frame))) = &next {
			if let (Some(chunk), Ok(mut wire)) = (frame.data_ref(), self.wire.0.lock()) {
				if let Some(current) = wire.as_mut() {
					if chunk.len() <= WIRE_MAX - current.len() {
						current.extend_from_slice(chunk);
					} else {
						*wire = None;
					}
				}
			}
		}
		next
	}

	fn is_end_stream(&self) -> bool {
		self.body.is_end_stream()
	}

	fn size_hint(&self) -> SizeHint {
		self.body.size_hint()
	}
}

/// Preserve authenticated POST bytes for selected HIA tool and resource routes.
pub fn capture_hia_resource_http(request: Request) -> Request {
	if !(selected() || super::hia_controller_release::resource_ingress_selected())
		|| request.method() != Method::POST
	{
		return request;
	}
	let (mut parts, body) = request.into_parts();
	let wire = HttpRequestWire(Arc::new(Mutex::new(Some(Vec::new()))));
	parts.extensions.insert(wire.clone());
	Request::from_parts(parts, Body::new(CapturingBody { body, wire }))
}

fn take_http_wire(parts: &Parts) -> Result<Vec<u8>> {
	let captured = parts
		.extensions
		.get::<HttpRequestWire>()
		.context("missing HTTP request capture")?;
	captured
		.0
		.lock()
		.ok()
		.and_then(|mut state| state.take())
		.context("HTTP request capture unavailable")
}

pub(super) async fn observe_http_tool(
	parts: &Parts,
	call: &CallToolRequestParams,
	request_id: &RequestId,
) -> Result<()> {
	let raw = take_http_wire(parts)?;
	observe(&raw, call, request_id).await?;
	tracing::info!("Native HIA admitted the authenticated HTTP tool request");
	Ok(())
}

pub(super) async fn observe_http_resource(
	parts: &Parts,
	uri: &str,
	request_id: &RequestId,
) -> Result<()> {
	let raw = take_http_wire(parts)?;
	observe_resource(&raw, uri, request_id).await?;
	tracing::info!("Native HIA admitted the authenticated HTTP resource URI");
	Ok(())
}

const REPLY_PATH: &str = "HIA_LOCAL_MCP_REPLY_IMAGE";
const REPLY_SHA: &str = "HIA_LOCAL_MCP_REPLY_SHA256";

#[derive(serde::Deserialize)]
struct ReplyEnvelope<'a> {
	#[serde(borrow)]
	id: Option<&'a serde_json::value::RawValue>,
	#[serde(borrow)]
	result: Option<&'a serde_json::value::RawValue>,
}

#[derive(serde::Deserialize)]
struct ReplyResult<'a> {
	#[serde(borrow, rename = "structuredContent")]
	structured: Option<&'a serde_json::value::RawValue>,
}

#[derive(serde::Deserialize)]
struct ReplyHiaResult<'a> {
	#[serde(borrow)]
	contract_version: Option<&'a str>,
}

fn hia_reply(raw: &[u8]) -> Option<(&str, &str)> {
	let response: ReplyEnvelope<'_> = serde_json::from_slice(raw).ok()?;
	let result = response.result?.get();
	let response_type: ReplyResult<'_> = serde_json::from_str(result).ok()?;
	let marker: ReplyHiaResult<'_> = serde_json::from_str(response_type.structured?.get()).ok()?;
	if marker.contract_version? == super::hia_contract::CONTRACT_VERSION {
		Some((response.id?.get(), result))
	} else {
		None
	}
}

fn render_hia_reply(id: &str, result: &str, limit: usize) -> Result<Vec<u8>> {
	static IMAGE: OnceLock<Result<File, String>> = OnceLock::new();
	let image = IMAGE
		.get_or_init(|| admit_executable(REPLY_PATH, REPLY_SHA).map_err(|error| error.to_string()))
		.as_ref()
		.map_err(|error| anyhow::anyhow!("{error}"))?;
	let frame = format!(r#"{{"id":{id},"result":{result}}}"#);
	ensure!(frame.len() <= WIRE_MAX, "HIA reply exceeds frame bound");
	let input = sealed(c"hia-mcp-reply-frame", frame.as_bytes(), false)?;
	let exe = format!("/proc/self/fd/{}", image.as_raw_fd());
	let out = std::process::Command::new(exe)
		.env_clear()
		.stdin(Stdio::from(input))
		.output()?;
	ensure!(
		out.status.success() && out.stderr.is_empty() && out.stdout.len() >= 8,
		"HIA reply writer refused"
	);
	let count = usize::try_from(frame_word(&out.stdout, 0)?)?;
	ensure!(
		count <= limit
			&& count > 2
			&& out.stdout.len() - 8 == count
			&& out.stdout.last() == Some(&b'\n'),
		"invalid HIA reply result"
	);
	tracing::info!(bytes = count, "Native HIA wire response emitted");
	Ok(out.stdout[8..].to_vec())
}

pub(super) fn rewrite_reply(frame: &mut Vec<u8>, limit: usize) -> io::Result<()> {
	if !image_selected(REPLY_PATH, REPLY_SHA) {
		return Ok(());
	}
	let Some((id, result)) = hia_reply(frame) else {
		return Ok(());
	};
	*frame = render_hia_reply(id, result, limit).map_err(io::Error::other)?;
	Ok(())
}

const TERMINAL_PATH: &str = "HIA_LOCAL_MCP_TERMINAL_IMAGE";
const TERMINAL_SHA: &str = "HIA_LOCAL_MCP_TERMINAL_SHA256";

pub(super) fn terminal_selected() -> bool {
	image_selected(TERMINAL_PATH, TERMINAL_SHA)
}

pub(super) async fn admit_terminal(
	expected: &serde_json::Value,
	report: &[u8],
	exit_code: i32,
) -> Result<serde_json::Value> {
	static IMAGE: OnceLock<Result<File, String>> = OnceLock::new();
	let image = IMAGE
		.get_or_init(|| {
			admit_executable(TERMINAL_PATH, TERMINAL_SHA).map_err(|error| error.to_string())
		})
		.as_ref()
		.map_err(|error| anyhow::anyhow!("{error}"))?;
	let mut frame = br#"{"expected":"#.to_vec();
	serde_json::to_writer(&mut frame, expected)?;
	write!(frame, r#","exit_code":{exit_code},"report":"#)?;
	frame.extend_from_slice(report);
	frame.push(b'}');
	ensure!(
		frame.len() <= WIRE_MAX,
		"HIA terminal envelope exceeds wire bound"
	);
	let input = sealed(c"hia-mcp-terminal-frame", &frame, false)?;
	let executable = format!("/proc/self/fd/{}", image.as_raw_fd());
	let mut command = Command::new(executable);
	command
		.env_clear()
		.kill_on_drop(true)
		.stdin(Stdio::from(input));
	let out = timeout(Duration::from_secs(3), command.output()).await??;
	ensure!(
		out.status.success() && out.stderr.is_empty() && out.stdout.len() >= 8,
		"HIA terminal report refused"
	);
	let size = usize::try_from(frame_word(&out.stdout, 0)?)?;
	ensure!(
		size <= report.len() && size > 2 && out.stdout.len() - 8 == size,
		"HIA terminal report invalid or not bound to the original response"
	);
	let body = serde_json::from_slice(&out.stdout[8..])?;
	tracing::info!(bytes = size, "Native HIA worker report admission accepted");
	Ok(body)
}

const REQUEST_SCHEMA: (&str, &str) = (
	"HIA_LOCAL_MCP_INPUT_SCHEMA_IMAGE",
	"HIA_LOCAL_MCP_INPUT_SCHEMA_SHA256",
);
const RESPONSE_SCHEMA: (&str, &str) = (
	"HIA_LOCAL_MCP_RESPONSE_SCHEMA_IMAGE",
	"HIA_LOCAL_MCP_RESPONSE_SCHEMA_SHA256",
);
const PROOF_SCHEMA: (&str, &str) = (
	"HIA_LOCAL_MCP_PROOF_SCHEMA_IMAGE",
	"HIA_LOCAL_MCP_PROOF_SCHEMA_SHA256",
);

pub(super) enum SchemaSide {
	Request,
	Response,
}

struct SchemaImages {
	request: File,
	response: File,
	proof: File,
}

pub(super) fn schema_selected() -> bool {
	[REQUEST_SCHEMA, RESPONSE_SCHEMA, PROOF_SCHEMA]
		.into_iter()
		.any(|(path, pin)| image_selected(path, pin))
}

fn schema_images() -> Result<&'static SchemaImages> {
	static IMAGES: OnceLock<Result<SchemaImages, String>> = OnceLock::new();
	IMAGES
		.get_or_init(|| {
			let load = || -> Result<SchemaImages> {
				Ok(SchemaImages {
					request: admit_executable(REQUEST_SCHEMA.0, REQUEST_SCHEMA.1)?,
					response: admit_executable(RESPONSE_SCHEMA.0, RESPONSE_SCHEMA.1)?,
					proof: admit_executable(PROOF_SCHEMA.0, PROOF_SCHEMA.1)?,
				})
			};
			load().map_err(|error| error.to_string())
		})
		.as_ref()
		.map_err(|error| anyhow::anyhow!("{error}"))
}

pub(super) async fn observe_schema(
	side: SchemaSide,
	tool: &str,
	catalog_sha256: &str,
	value: &serde_json::Value,
) -> Result<()> {
	// Pin all three images before any effect, including for the synthetic
	// resource route, which keeps its separate URI input contract.
	let images = schema_images()?;
	let (image, direction) = match side {
		SchemaSide::Request if tool == "hia_resource_read" => return Ok(()),
		SchemaSide::Request => (&images.request, "input"),
		SchemaSide::Response if tool == "hia_verify" => (&images.proof, "proof"),
		SchemaSide::Response => (&images.response, "response"),
	};
	let ordinary_tool = if tool == "hia_resource_read" {
		"hia_read"
	} else {
		tool
	};
	let index = super::hia_contract::TOOLS
		.iter()
		.position(|known| *known == ordinary_tool)
		.context("unknown HIA schema tool")?;
	ensure!(
		catalog_sha256.len() == 64,
		"invalid HIA schema catalog digest extent"
	);
	let mut frame = ((index as u64) + 1).to_le_bytes().to_vec();
	frame.extend_from_slice(catalog_sha256.as_bytes());
	serde_json::to_writer(&mut frame, value)?;
	ensure!(
		frame.len() <= super::hia_contract::MAX_WORKER_BYTES + 72,
		"HIA schema payload exceeds retained wire bound"
	);
	let input = sealed(c"hia-mcp-schema-frame", &frame, false)?;
	let executable = format!("/proc/self/fd/{}", image.as_raw_fd());
	let mut command = Command::new(executable);
	command
		.env_clear()
		.kill_on_drop(true)
		.stdin(Stdio::from(input));
	let out = timeout(Duration::from_secs(3), command.output()).await??;
	ensure!(
		out.status.success() && out.stderr.is_empty() && out.stdout.as_slice() == [0; 8],
		"Native HIA schema refused the selected tool {direction}"
	);
	tracing::info!(%tool, direction, "Native HIA schema admitted MCP value");
	Ok(())
}

const NEGOTIATE_PATH: &str = "HIA_LOCAL_MCP_NEGOTIATION_IMAGE";
const NEGOTIATE_SHA: &str = "HIA_LOCAL_MCP_NEGOTIATION_SHA256";

#[derive(Clone)]
pub(super) struct LegacyChoice(pub(super) Option<rmcp::model::ProtocolVersion>);

pub(super) fn negotiation_selected() -> bool {
	image_selected(NEGOTIATE_PATH, NEGOTIATE_SHA)
}

pub(super) async fn negotiate_legacy(raw: &[u8]) -> Result<rmcp::model::ProtocolVersion> {
	use rmcp::model::ProtocolVersion;
	static IMAGE: OnceLock<Result<File, String>> = OnceLock::new();
	let image = IMAGE
		.get_or_init(|| {
			admit_executable(NEGOTIATE_PATH, NEGOTIATE_SHA).map_err(|error| error.to_string())
		})
		.as_ref()
		.map_err(|error| anyhow::anyhow!("{error}"))?;
	let raw = raw.strip_suffix(b"\n").unwrap_or(raw);
	ensure!(
		(2..=WIRE_MAX).contains(&raw.len()),
		"HIA negotiation exceeds wire bound"
	);
	let input = sealed(c"hia-mcp-negotiation-frame", raw, false)?;
	let exe = format!("/proc/self/fd/{}", image.as_raw_fd());
	let mut command = Command::new(exe);
	command
		.env_clear()
		.kill_on_drop(true)
		.stdin(Stdio::from(input));
	let out = timeout(Duration::from_secs(3), command.output()).await??;
	ensure!(
		out.status.success() && out.stdout.len() == 120 && out.stderr.is_empty(),
		"HIA negotiation refused"
	);
	let word = |at| frame_word(&out.stdout, at);
	ensure!(
		word(0)? == 112 && &out.stdout[8..16] == b"HIAMCP01" && word(16)? == 1 && word(96)? == 1,
		"HIA did not admit legacy initialization"
	);
	let version = match word(112)? {
		1 => ProtocolVersion::V_2024_11_05,
		2 => ProtocolVersion::V_2025_03_26,
		3 => ProtocolVersion::V_2025_06_18,
		4 => ProtocolVersion::V_2025_11_25,
		_ => anyhow::bail!("invalid HIA legacy version"),
	};
	tracing::info!(%version,"Native HIA selected legacy MCP version");
	Ok(version)
}

const CATALOG_EXE: &str = "HIA_LOCAL_MCP_CATALOG_IMAGE";
const CATALOG_EXE_PIN: &str = "HIA_LOCAL_MCP_CATALOG_SHA256";
const CATALOG_DATA: &str = "HIA_LOCAL_MCP_CATALOG_DATA";

#[derive(serde::Deserialize)]
struct CatalogResult {
	tools: Vec<rmcp::model::Tool>,
}

fn read_catalog() -> Result<std::collections::BTreeMap<String, rmcp::model::Tool>> {
	let executable = admit_executable(CATALOG_EXE, CATALOG_EXE_PIN)?;
	let source = if let Some(catalog) = super::hia_controller_release::catalog() {
		std::borrow::Cow::Borrowed(catalog)
	} else {
		let data_path =
			PathBuf::from(env::var_os(CATALOG_DATA).context("missing installed HIA catalog")?);
		ensure!(data_path.is_absolute(), "HIA catalog path must be absolute");
		let mut source = Vec::new();
		let expected = super::hia_contract::CATALOG_BYTES;
		File::open(data_path)?
			.take((expected.len() + 1) as u64)
			.read_to_end(&mut source)?;
		ensure!(
			source == expected,
			"installed HIA catalog does not match provider pin"
		);
		std::borrow::Cow::Owned(source)
	};
	let input = sealed(c"hia-mcp-catalog-frame", &source, false)?;
	let exe = format!("/proc/self/fd/{}", executable.as_raw_fd());
	let out = std::process::Command::new(exe)
		.env_clear()
		.stdin(Stdio::from(input))
		.output()?;
	ensure!(
		out.status.success() && out.stderr.is_empty() && out.stdout.len() >= 8,
		"HIA catalog projection failed"
	);
	let count = usize::try_from(frame_word(&out.stdout, 0)?)?;
	ensure!(
		count == out.stdout.len() - 8 && count <= WIRE_MAX,
		"invalid HIA catalog size"
	);
	let result: CatalogResult = serde_json::from_slice(&out.stdout[8..])?;
	let mut tools = std::collections::BTreeMap::new();
	for tool in result.tools {
		ensure!(
			tools.insert(tool.name.to_string(), tool).is_none(),
			"duplicate native HIA tool"
		);
	}
	ensure!(
		tools.len() == super::hia_contract::TOOLS.len()
			&& super::hia_contract::TOOLS
				.iter()
				.all(|name| tools.contains_key(*name)),
		"incomplete native HIA tools"
	);
	tracing::info!(count = tools.len(), "Native HIA tool catalog published");
	Ok(tools)
}

pub(super) fn catalog(
) -> Result<Option<&'static std::collections::BTreeMap<String, rmcp::model::Tool>>> {
	if !image_selected(CATALOG_EXE, CATALOG_EXE_PIN) && env::var_os(CATALOG_DATA).is_none() {
		return Ok(None);
	}
	static TOOLS: OnceLock<Result<std::collections::BTreeMap<String, rmcp::model::Tool>, String>> =
		OnceLock::new();
	TOOLS
		.get_or_init(|| read_catalog().map_err(|error| error.to_string()))
		.as_ref()
		.map(Some)
		.map_err(|error| anyhow::anyhow!("{error}"))
}

const URI_EXE: &str = "HIA_LOCAL_MCP_URI_IMAGE";
const URI_PIN: &str = "HIA_LOCAL_MCP_URI_SHA256";

pub(super) async fn valid_uri(uri: &str) -> Result<Option<bool>> {
	if !image_selected(URI_EXE, URI_PIN) {
		return Ok(None);
	}
	static IMAGE: OnceLock<Result<File, String>> = OnceLock::new();
	let image = IMAGE
		.get_or_init(|| admit_executable(URI_EXE, URI_PIN).map_err(|error| error.to_string()))
		.as_ref()
		.map_err(|error| anyhow::anyhow!("{error}"))?;
	if uri.len() > 208 {
		return Ok(Some(false));
	}
	let input = sealed(c"hia-mcp-resource-uri", uri.as_bytes(), false)?;
	let exe = format!("/proc/self/fd/{}", image.as_raw_fd());
	let mut command = Command::new(exe);
	command
		.env_clear()
		.kill_on_drop(true)
		.stdin(Stdio::from(input));
	let out = timeout(Duration::from_secs(3), command.output()).await??;
	ensure!(
		out.status.success() && out.stderr.is_empty() && out.stdout.len() >= 8,
		"HIA URI classification failed"
	);
	let word = |at| frame_word(&out.stdout, at);
	if word(0)? == 0xfffffff0 && out.stdout.len() == 8 {
		tracing::info!("Native HIA denied resource URI syntax");
		return Ok(Some(false));
	}
	ensure!(
		out.stdout.len() == 32
			&& word(0)? == 24
			&& &out.stdout[8..16] == b"HIAMURI1"
			&& word(16)? == uri.len() as u64
			&& word(24)?.checked_add(16) == Some(word(16)?),
		"invalid HIA resource URI descriptor"
	);
	tracing::info!("Native HIA admitted resource URI syntax");
	Ok(Some(true))
}

#[cfg(test)]
#[path = "hia_wire_candidate_tests.rs"]
mod hia_wire_candidate_tests;
