// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Credential-authenticated metadata scope; never a ChatGPT user or conversation identity.
use anyhow::{anyhow, bail, Result};
use rmcp::{service::RequestContext, RoleServer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Mutex};

/// Only the verified HTTP middleware constructs this non-serialized extension.
#[derive(Clone)]
pub struct AuthenticatedOperatorScope {
	owner: String,
}
impl std::fmt::Debug for AuthenticatedOperatorScope {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("AuthenticatedOperatorScope([redacted])")
	}
}
impl AuthenticatedOperatorScope {
	pub fn from_verified_token(token: &[u8]) -> Self {
		let mut digest = Sha256::new();
		digest.update(b"hepta-runtime/private-operator-credential/v1\0");
		digest.update(token);
		Self {
			owner: digest
				.finalize()
				.iter()
				.map(|byte| format!("{byte:02x}"))
				.collect(),
		}
	}
}

#[derive(Clone, PartialEq, Eq)]
pub struct OwnerScope {
	owner: String,
	authenticated: bool,
}
impl std::fmt::Debug for OwnerScope {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("OwnerScope")
			.field("authenticated", &self.authenticated)
			.finish_non_exhaustive()
	}
}
impl OwnerScope {
	pub fn owner(&self) -> &str {
		&self.owner
	}
	pub fn annotate(&self, text: String, search: bool) -> Result<String> {
		let mut result: Value = serde_json::from_str(&text)?;
		let object = result
			.as_object_mut()
			.ok_or_else(|| anyhow!("metadata response unavailable"))?;
		object.insert("ownership_scope".into(), self.kind().into());
		object.insert(
			"authenticated_chatgpt_caller_isolation".into(),
			false.into(),
		);
		object.insert(
			"credential_metadata_resume".into(),
			self.authenticated.into(),
		);
		if search {
			// Transport sessions and unfinished target programs are never restored or replayed.
			object.insert(
				"metadata_resume_after_restart".into(),
				self.authenticated.into(),
			);
			object.insert("session_resume_after_restart".into(), false.into());
			object.insert(
				"unfinished_search_after_controller_restart".into(),
				"interrupted_without_relaunch".into(),
			);
		} else {
			object.insert("session_scope".into(), self.kind().into());
			object.insert("cross_session_resume".into(), self.authenticated.into());
			if let Some(retention) = object.get_mut("retention").and_then(Value::as_object_mut) {
				if let Some(limit) = retention.remove("per_session") {
					retention.insert("per_owner".into(), limit);
				}
			}
		}
		let text = serde_json::to_string(&result)?;
		let wire =
			rmcp::model::CallToolResult::success(vec![rmcp::model::ContentBlock::text(&text)]);
		if serde_json::to_vec(&wire)?.len() > 64 * 1024 {
			bail!("scoped metadata wire response exceeds 64 KiB; reduce result page limit");
		}
		Ok(text)
	}
	/// Annotation failure after a search effect must preserve its reconciliation identity.
	pub fn annotate_search_effect(&self, text: String) -> String {
		if let Ok(scoped) = self.annotate(text.clone(), true) {
			return scoped;
		}
		tracing::warn!("search scope annotation unavailable; existing identity retained");
		let Ok(original) = serde_json::from_str::<Value>(&text) else {
			return text;
		};
		let Some(id) = original
			.pointer("/search/search_id")
			.and_then(Value::as_str)
			.filter(|id| {
				id.len() == 64
					&& id
						.bytes()
						.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
			})
		else {
			return text;
		};
		let mut search = json!({"search_id":id});
		for (key, max) in [("host", 64), ("state", 64), ("reason", 512)] {
			if let Some(value) = original
				.get("search")
				.and_then(|search| search.get(key))
				.and_then(Value::as_str)
				.filter(|value| value.len() <= max)
			{
				search[key] = json!(value);
			}
		}
		let mut result = json!({"search":search,"automatic_retry":false,
			"ownership_scope":self.kind(),"authenticated_chatgpt_caller_isolation":false,
			"scope_annotation_status":"unavailable_after_effect_identity_retained",
			"recovery":"reconcile the existing search_id; do not relaunch an uncertain search"});
		for key in ["stop_requested", "already_terminal"] {
			if let Some(value) = original.get(key).and_then(Value::as_bool) {
				result[key] = json!(value);
			}
		}
		serde_json::to_string(&result).unwrap_or(text)
	}
	fn kind(&self) -> &'static str {
		if self.authenticated {
			"authenticated_private_operator_credential"
		} else {
			"native_mcp_session_only"
		}
	}
}

/// A session cannot change credential authority after its first admitted tool call.
#[derive(Default)]
pub struct SessionOwnerBinding(Mutex<Option<OwnerScope>>);
impl std::fmt::Debug for SessionOwnerBinding {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("SessionOwnerBinding([redacted])")
	}
}
impl SessionOwnerBinding {
	pub fn resolve(
		&self,
		context: &RequestContext<RoleServer>,
		fallback: Option<&str>,
	) -> Result<OwnerScope> {
		self.resolve_parts(
			context.extensions.get::<axum::http::request::Parts>(),
			fallback,
		)
	}
	fn resolve_parts(
		&self,
		parts: Option<&axum::http::request::Parts>,
		fallback: Option<&str>,
	) -> Result<OwnerScope> {
		let scope = if let Some(parts) = parts {
			let verified = parts
				.extensions
				.get::<AuthenticatedOperatorScope>()
				.ok_or_else(|| {
					anyhow!("authenticated operator scope unavailable; dispatch refused")
				})?;
			OwnerScope {
				owner: verified.owner.clone(),
				authenticated: true,
			}
		} else {
			let owner = fallback
				.filter(|value| {
					value.len() == 64
						&& value
							.bytes()
							.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
				})
				.ok_or_else(|| anyhow!("native session entropy unavailable"))?;
			OwnerScope {
				owner: owner.into(),
				authenticated: false,
			}
		};
		let mut binding = self
			.0
			.lock()
			.map_err(|_| anyhow!("session authority unavailable"))?;
		if let Some(bound) = binding.as_ref() {
			if bound != &scope {
				bail!("session credential authority changed; dispatch refused");
			}
		} else {
			*binding = Some(scope.clone());
		}
		Ok(scope)
	}
}

/// Open once, without following the final symlink or blocking on a special file.
#[cfg(unix)]
pub fn read_private_token(path: &Path) -> Result<Vec<u8>> {
	use std::{
		fs::OpenOptions,
		io::Read,
		os::unix::fs::{MetadataExt, OpenOptionsExt},
	};
	let mut file = OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
		.open(path)
		.map_err(|_| anyhow!("private runtime token file unavailable"))?;
	let before = file.metadata()?;
	if !before.is_file()
		|| before.uid() != unsafe { libc::geteuid() }
		|| before.mode() & 0o7777 != 0o600
		|| before.nlink() != 1
	{
		bail!("runtime token requires an account-owned single-link 0600 regular file");
	}
	let mut token = Vec::new();
	file.by_ref().take(4098).read_to_end(&mut token)?;
	let after = file.metadata()?;
	if before.uid() != after.uid()
		|| after.mode() & 0o7777 != 0o600
		|| after.nlink() != 1
		|| before.len() != after.len()
		|| before.mtime() != after.mtime()
		|| before.mtime_nsec() != after.mtime_nsec()
		|| before.ctime() != after.ctime()
		|| before.ctime_nsec() != after.ctime_nsec()
	{
		bail!("runtime token changed while reading");
	}
	if token.last() == Some(&b'\n') {
		token.pop();
	}
	if !(32..=4096).contains(&token.len()) || token.iter().any(|b| !(33..=126).contains(b)) {
		bail!("runtime token must contain 32..4096 printable non-whitespace ASCII bytes");
	}
	Ok(token)
}
#[cfg(not(unix))]
pub fn read_private_token(_path: &Path) -> Result<Vec<u8>> {
	bail!("private runtime token requires Unix descriptor support");
}

#[cfg(all(test, unix))]
#[path = "caller_scope_tests.rs"]
mod tests;
