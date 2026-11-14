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
//! Execute the unchanged original auth middleware, token loader and owner APIs.
use anyhow::{anyhow, Context, Result};
use axum::{
	body::Body,
	extract::State,
	http::{HeaderName, HeaderValue, Request, StatusCode},
	response::{IntoResponse, Response},
	routing::post,
	Router,
};
use serde_json::{json, Value};
use std::{
	collections::HashMap,
	io::{BufRead, Write},
	os::unix::fs::{OpenOptionsExt, PermissionsExt},
	path::{Path, PathBuf},
	sync::{
		atomic::{AtomicUsize, Ordering},
		Arc,
	},
};
use tower::ServiceExt;

include!(concat!(env!("OUT_DIR"), "/original_authority_reference.rs"));

const INVALID: u32 = 0xffffffff;
const AUTH_REQUIRED: u32 = 0xffffffed;
const FORBIDDEN: u32 = 0xffffffdf;
const UNAUTHORIZED: u32 = 0xffffffde;
const MISSING_EXTENSION: u32 = 0xffffffdd;
const OWNER_ENTROPY: u32 = 0xffffffdc;
const AUTH_CHANGED: u32 = 0xffffffdb;
const CRYPTO_UNAVAILABLE: u32 = 0xffffffda;
const BINDING_INPUT: u32 = 0xffffffd9;

fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|value| format!("{value:02x}")).collect()
}

fn unhex(value: &str) -> Result<Vec<u8>> {
	if value.len() % 2 != 0
		|| !value
			.bytes()
			.all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
	{
		return Err(anyhow!("noncanonical corpus hex"));
	}
	(0..value.len())
		.step_by(2)
		.map(|at| Ok(u8::from_str_radix(&value[at..at + 2], 16)?))
		.collect()
}

fn field<'a>(row: &'a Value, name: &str) -> Result<&'a str> {
	row[name]
		.as_str()
		.ok_or_else(|| anyhow!("missing string field {name}"))
}

fn number(row: &Value, name: &str) -> Result<u64> {
	row[name]
		.as_u64()
		.ok_or_else(|| anyhow!("missing unsigned field {name}"))
}

fn mapped(error: &anyhow::Error) -> Result<u32> {
	Ok(match error.to_string().as_str() {
		"runtime HTTP mode requires --auth-token-file" => AUTH_REQUIRED,
		"private runtime token file unavailable" => 0xfffffffd,
		"runtime token requires an account-owned single-link 0600 regular file" => 0xfffffffc,
		"runtime token changed while reading" => 0xfffffffb,
		"runtime token must contain 32..4096 printable non-whitespace ASCII bytes" => 0xfffffffa,
		"authenticated operator scope unavailable; dispatch refused" => MISSING_EXTENSION,
		"native session entropy unavailable" => OWNER_ENTROPY,
		"session credential authority changed; dispatch refused" => AUTH_CHANGED,
		"trusted operation crypto authority unavailable" => CRYPTO_UNAVAILABLE,
		"cryptographic binding input unavailable" => BINDING_INPUT,
		_ => {
			if let Some(code) = error
				.downcast_ref::<std::io::Error>()
				.and_then(|error| error.raw_os_error())
			{
				if (1..=4095).contains(&code) {
					return Ok(0xffffd000 | code as u32);
				}
			}
			return Err(anyhow!("unclassified original error: {error}"));
		}
	})
}

fn reply(code: u32, bytes: &[u8]) -> Response {
	let mut result = Vec::from(code.to_le_bytes());
	result.extend_from_slice(bytes);
	(StatusCode::OK, result).into_response()
}

#[derive(Clone)]
struct Dispatch {
	mode: u64,
	op: u64,
	payload: Arc<Vec<u8>>,
	binding: Arc<mcp::runtime::caller_scope::SessionOwnerBinding>,
	fallback: Option<String>,
	stdio_crypto: Option<Arc<mcp::runtime::operation_crypto::ResultCryptoScope>>,
	peer: rmcp::Peer<rmcp::RoleServer>,
	route_calls: Arc<AtomicUsize>,
	resolve_calls: Arc<AtomicUsize>,
	crypto_calls: Arc<AtomicUsize>,
}

async fn dispatch(State(state): State<Dispatch>, request: axum::extract::Request) -> Response {
	state.route_calls.fetch_add(1, Ordering::Relaxed);
	if state.op == 0 {
		return reply(0, &[]);
	}
	if state.op > 2 {
		return reply(INVALID, &[]);
	}
	let (parts, _) = request.into_parts();
	let mut context =
		rmcp::service::RequestContext::new(rmcp::model::RequestId::Number(0), state.peer.clone());
	if state.mode != 1 {
		context.extensions.insert(parts);
	}
	state.resolve_calls.fetch_add(1, Ordering::Relaxed);
	let result: Result<Vec<u8>> = if state.op == 1 {
		state
			.binding
			.resolve(&context, state.fallback.as_deref())
			.map(|owner| vec![mcp::runtime::caller_scope::fixture_authenticated(&owner) as u8])
	} else {
		state.crypto_calls.fetch_add(1, Ordering::Relaxed);
		state
			.binding
			.resolve_operation_crypto(
				&context,
				state.fallback.as_deref(),
				state.stdio_crypto.as_ref(),
			)
			.and_then(|(_, crypto)| {
				crypto
					.request_binding(&state.payload)
					.map(|text| text.into_bytes())
					.map_err(Into::into)
			})
	};
	match result {
		Ok(bytes) => reply(0, &bytes),
		Err(error) => reply(
			mapped(&error).expect("all admitted original errors are classified"),
			&[],
		),
	}
}

struct App {
	mode: u64,
	auth: Option<HttpAuth>,
	original_auth_scope: Option<mcp::runtime::caller_scope::AuthenticatedOperatorScope>,
	binding: Arc<mcp::runtime::caller_scope::SessionOwnerBinding>,
	fallback: Option<String>,
	stdio_crypto: Option<Arc<mcp::runtime::operation_crypto::ResultCryptoScope>>,
	entropy: mcp::runtime::operation_crypto::AuthorityFixtureEntropy,
	owner_failure: bool,
	owner_calls: usize,
	stdio_calls: usize,
}

impl App {
	fn session(&mut self) {
		// These two original owners retain the original server's initialization order.
		self.fallback = if self.owner_failure {
			None
		} else {
			self.owner_calls += 1;
			mcp::runtime::owner_reference::new_owner_id().ok()
		};
		self.binding = Arc::new(mcp::runtime::caller_scope::SessionOwnerBinding::default());
		self.stdio_calls += 1;
		self.stdio_crypto = self.entropy.stdio();
	}

	async fn request(
		&self,
		row: &Value,
		peer: &rmcp::Peer<rmcp::RoleServer>,
		counts: &Counts,
	) -> Result<(u32, Vec<u8>)> {
		let op = number(row, "request_op")?;
		let payload = unhex(field(row, "payload_hex")?)?;
		let state = Dispatch {
			mode: self.mode,
			op,
			payload: Arc::new(payload),
			binding: self.binding.clone(),
			fallback: self.fallback.clone(),
			stdio_crypto: self.stdio_crypto.clone(),
			peer: peer.clone(),
			route_calls: counts.route_calls.clone(),
			resolve_calls: counts.resolve_calls.clone(),
			crypto_calls: counts.crypto_calls.clone(),
		};
		let mut router = Router::new().route("/", post(dispatch)).with_state(state);
		if let Some(auth) = &self.auth {
			router = router.layer(axum::middleware::from_fn_with_state(
				auth.clone(),
				require_http_auth,
			));
		}
		let mut request = Request::builder()
			.method("POST")
			.uri("/")
			.body(Body::empty())?;
		for pair in row["headers"]
			.as_array()
			.ok_or_else(|| anyhow!("headers must be array"))?
		{
			let pair = pair
				.as_array()
				.ok_or_else(|| anyhow!("header must be pair"))?;
			if pair.len() != 2 {
				return Err(anyhow!("header pair size"));
			}
			let name = unhex(pair[0].as_str().ok_or_else(|| anyhow!("header name"))?)?;
			let value = unhex(pair[1].as_str().ok_or_else(|| anyhow!("header value"))?)?;
			request.headers_mut().append(
				HeaderName::from_bytes(&name)?,
				HeaderValue::from_bytes(&value)?,
			);
		}
		let response = router.oneshot(request).await?;
		let status = response.status();
		let bytes = axum::body::to_bytes(response.into_body(), 2 << 20).await?;
		if status == StatusCode::FORBIDDEN {
			return Ok((FORBIDDEN, vec![]));
		}
		if status == StatusCode::UNAUTHORIZED {
			return Ok((UNAUTHORIZED, vec![]));
		}
		if status != StatusCode::OK || bytes.len() < 4 {
			return Err(anyhow!("unexpected original middleware response"));
		}
		Ok((
			u32::from_le_bytes(bytes[..4].try_into()?),
			bytes[4..].to_vec(),
		))
	}
}

#[derive(Default)]
struct Counts {
	rows: usize,
	starts: usize,
	reconnects: usize,
	requests: usize,
	shutdowns: usize,
	trusted_extension_fixture_transfers: usize,
	load_auth_calls: usize,
	owner_calls: usize,
	stdio_calls: usize,
	entropy_calls: u64,
	route_calls: Arc<AtomicUsize>,
	resolve_calls: Arc<AtomicUsize>,
	crypto_calls: Arc<AtomicUsize>,
}

struct NullServer;
impl rmcp::ServerHandler for NullServer {}

fn probe(args: &[std::ffi::OsString]) -> Result<bool> {
	let result = match args {
		[_, command, path] if command == "--token-probe" => Some(
			mcp::runtime::caller_scope::read_private_token(Path::new(path))
				.map_err(|error| mapped(&error).unwrap()),
		),
		[_, command] if command == "--stdio-owner-probe" => Some(
			mcp::runtime::owner_reference::new_owner_id()
				.map(|text| unhex(&text).unwrap())
				.map_err(|_| 0xfffffff9),
		),
		[_] => None,
		_ => return Err(anyhow!("invalid oracle arguments")),
	};
	if let Some(result) = result {
		let mut stdout = std::io::stdout().lock();
		match result {
			Ok(bytes) => {
				stdout.write_all(&(bytes.len() as u32).to_le_bytes())?;
				stdout.write_all(&bytes)?;
			}
			Err(code) => stdout.write_all(&code.to_le_bytes())?,
		}
		return Ok(true);
	}
	Ok(false)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
	let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
	if probe(&args)? {
		return Ok(());
	}
	let stamp = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)?
		.as_nanos();
	let root: PathBuf = std::env::temp_dir().join(format!(
		"hia-authority-reference-{}-{stamp}",
		std::process::id()
	));
	std::fs::create_dir(&root)?;
	std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
	let (transport, _unused_peer) = tokio::io::duplex(4096);
	let mut running =
		rmcp::service::serve_directly::<rmcp::RoleServer, _, _, _, _>(NullServer, transport, None);
	let peer = running.peer().clone();
	let mut apps: HashMap<u64, App> = HashMap::new();
	let mut counts = Counts::default();
	let mut observations = Vec::new();
	for line in std::io::stdin().lock().lines() {
		let line = line?;
		let row: Value = serde_json::from_str(&line)?;
		counts.rows += 1;
		let id = number(&row, "context")?;
		let result = match field(&row, "operation")? {
			"start" => {
				if apps.contains_key(&id) {
					return Err(anyhow!("duplicate context"));
				}
				counts.starts += 1;
				let mode = number(&row, "mode")?;
				if !(1..=4).contains(&mode) {
					return Err(anyhow!("invalid corpus mode"));
				}
				let path = root.join(format!("token-{id}"));
				if mode == 2 && !row["missing_file"].as_bool().unwrap_or(false) {
					let bytes = unhex(field(&row, "token_file_hex")?)?;
					let mut file = std::fs::OpenOptions::new()
						.write(true)
						.create_new(true)
						.mode(0o600)
						.open(&path)?;
					file.write_all(&bytes)?;
					file.set_permissions(std::fs::Permissions::from_mode(
						number(&row, "file_mode")? as u32,
					))?;
				}
				let auth = if mode == 1 {
					Ok(None)
				} else {
					counts.load_auth_calls += 1;
					load_http_auth(
						if mode == 2 { Some(&path) } else { None },
						mode == 2 || mode == 4,
					)
				};
				match auth {
					Err(error) => (mapped(&error)?, Vec::new()),
					Ok(auth) => {
						let original_auth_scope = auth.as_ref().map(|auth| auth.scope.clone());
						let mut app = App {
							mode,
							auth,
							original_auth_scope,
							binding: Arc::new(Default::default()),
							fallback: None,
							stdio_crypto: None,
							entropy: mcp::runtime::operation_crypto::AuthorityFixtureEntropy::new(
								number(&row, "entropy_seed")?,
								number(&row, "entropy_fail")?,
							),
							owner_failure: row["owner_failure"]
								.as_bool()
								.ok_or_else(|| anyhow!("owner failure fixture field"))?,
							owner_calls: 0,
							stdio_calls: 0,
						};
						app.session();
						apps.insert(id, app);
						(0, Vec::new())
					}
				}
			}
			"request" => {
				counts.requests += 1;
				apps.get(&id)
					.ok_or_else(|| anyhow!("unknown active context"))?
					.request(&row, &peer, &counts)
					.await?
			}
			"replace_verified_extension" => {
				if row["adapter_only"] != true {
					return Err(anyhow!(
						"trusted fixture control must be separately declared"
					));
				}
				let source = apps
					.get(&number(&row, "source_context")?)
					.and_then(|app| app.auth.as_ref())
					.ok_or_else(|| {
						anyhow!("source credential has not passed original file verification")
					})?
					.scope
					.clone();
				let destination = apps
					.get_mut(&id)
					.and_then(|app| app.auth.as_mut())
					.ok_or_else(|| anyhow!("destination credential is not active"))?;
				destination.scope = source;
				counts.trusted_extension_fixture_transfers += 1;
				(0, Vec::new())
			}
			"restore_verified_extension" => {
				if row["adapter_only"] != true {
					return Err(anyhow!(
						"trusted fixture control must be separately declared"
					));
				}
				let app = apps
					.get_mut(&id)
					.ok_or_else(|| anyhow!("unknown restore context"))?;
				app.auth
					.as_mut()
					.ok_or_else(|| anyhow!("credential missing"))?
					.scope = app.original_auth_scope
					.clone()
					.ok_or_else(|| anyhow!("original verified scope missing"))?;
				counts.trusted_extension_fixture_transfers += 1;
				(0, Vec::new())
			}
			"reconnect" => {
				counts.reconnects += 1;
				let app = apps
					.get_mut(&id)
					.ok_or_else(|| anyhow!("unknown reconnect context"))?;
				if app.mode == 1 {
					return Err(anyhow!("stdio cannot reconnect in this profile"));
				}
				app.session();
				(0, Vec::new())
			}
			"shutdown" => {
				counts.shutdowns += 1;
				let app = apps
					.remove(&id)
					.ok_or_else(|| anyhow!("unknown shutdown context"))?;
				counts.owner_calls += app.owner_calls;
				counts.stdio_calls += app.stdio_calls;
				counts.entropy_calls += app.entropy.calls();
				(0, Vec::new())
			}
			_ => return Err(anyhow!("unknown corpus operation")),
		};
		let expected_code = number(&row, "code")?;
		let expected_bytes = unhex(field(&row, "output_hex")?)?;
		if result.0 as u64 != expected_code || result.1 != expected_bytes {
			return Err(anyhow!(
				"original mismatch at row {}: code {:08x}, expected {:08x}",
				counts.rows,
				result.0,
				expected_code
			));
		}
		observations.extend_from_slice(&result.0.to_le_bytes());
		observations.extend_from_slice(&(result.1.len() as u64).to_le_bytes());
		observations.extend_from_slice(&result.1);
	}
	for app in apps.values() {
		counts.owner_calls += app.owner_calls;
		counts.stdio_calls += app.stdio_calls;
		counts.entropy_calls += app.entropy.calls();
	}
	apps.clear();
	running
		.close()
		.await
		.context("closing qualification-only peer")?;
	std::fs::remove_dir_all(&root)?;
	use sha2::Digest;
	println!(
		"{}",
		json!({"status":"PASS", "rows":counts.rows, "starts":counts.starts,
		"reconnects":counts.reconnects, "requests":counts.requests, "shutdowns":counts.shutdowns,
		"adapter_only_rows":counts.trusted_extension_fixture_transfers,
		"original_load_http_auth_calls":counts.load_auth_calls, "original_new_owner_id_calls":counts.owner_calls,
		"original_stdio_with_fixture_calls":counts.stdio_calls, "synthetic_entropy_fills":counts.entropy_calls,
		"actual_router_dispatch_calls":counts.route_calls.load(Ordering::Relaxed),
		"original_resolve_calls":counts.resolve_calls.load(Ordering::Relaxed),
		"original_resolve_operation_crypto_calls":counts.crypto_calls.load(Ordering::Relaxed),
		"output_sha256":hex(&sha2::Sha256::digest(&observations)), "native_cases_added_by_replay":0,
		"original_middleware_executed":true, "whole_runtime_replaced":false})
	);
	Ok(())
}
