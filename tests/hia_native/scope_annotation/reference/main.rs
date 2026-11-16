// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Private source-extracted comparison fixture. No runtime implementation.
use anyhow::{anyhow, bail, Result};
use serde_json::Value;
use std::io::{self, Read, Write};

#[derive(Clone, PartialEq, Eq)]
pub struct OwnerScope {
	owner: String,
	authenticated: bool,
}
impl OwnerScope {
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
	fn kind(&self) -> &'static str {
		if self.authenticated {
			"authenticated_private_operator_credential"
		} else {
			"native_mcp_session_only"
		}
	}
	fn observe_serialized_prefix(&self, text: String, search: bool) -> Result<(String, Vec<u8>)> {
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
		let bytes = serde_json::to_vec(&wire)?;
		Ok((text, bytes))
	}
}

fn word(raw: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(raw[at..at+8].try_into().unwrap())
}
fn number(raw: &mut Vec<u8>, value: u64) { raw.extend_from_slice(&value.to_le_bytes()); }
fn observed(raw: &[u8]) -> Vec<u8> {
    assert!(raw.len() >= 48 && raw.len() <= (8 << 20) + 48);
    assert_eq!(&raw[..8], b"HSCANQ01");
    assert_eq!(word(raw, 8), 1);
    assert!(word(raw, 16) <= 1 && word(raw, 24) <= 1);
    assert_eq!(word(raw, 32) as usize, raw.len() - 48);
    assert_eq!(word(raw, 40), 0);
    let text = std::str::from_utf8(&raw[48..]).unwrap().to_owned();
    let scope = OwnerScope { owner: String::new(), authenticated: word(raw, 16) == 1 };
    let search = word(raw, 24) == 1;
    // Primary execution: the entire original method above is unchanged.
    let primary = scope.annotate(text.clone(), search);
    // A second, explicitly separate source-prefix observer retains the full
    // actual constructor serialization even when the primary budget rejects.
    let prefix = scope.observe_serialized_prefix(text, search);
    let (kind, category, answer, annotation, wire) = match (primary, prefix) {
        (Ok(actual), Ok((annotation, wire))) => {
            assert_eq!(actual, annotation);
            assert!(wire.len() <= 65536);
            (0u64, 0u64, actual, annotation, wire)
        },
        (Err(error), Ok((annotation, wire))) => {
            let text = error.to_string();
            assert_eq!(text, "scoped metadata wire response exceeds 64 KiB; reduce result page limit");
            assert!(wire.len() > 65536);
            (1, 3, text, annotation, wire)
        },
        (Err(error), Err(prefix_error)) => {
            let text = error.to_string();
            assert_eq!(text, prefix_error.to_string());
            let category = if text == "metadata response unavailable" { 2 } else { 1 };
            (1, category, text, String::new(), Vec::new())
        },
        _ => panic!("unchanged primary and exact-prefix observer disagree"),
    };
    let mut response = b"HSCANR01".to_vec();
    for value in [kind, answer.len() as u64, wire.len() as u64, category, annotation.len() as u64, 0, 0] {
        number(&mut response, value);
    }
    response.extend_from_slice(answer.as_bytes());
    let mut result = b"HSCASR01".to_vec();
    for value in [response.len() as u64, annotation.len() as u64, wire.len() as u64] { number(&mut result, value); }
    result.extend(response);
    result.extend_from_slice(annotation.as_bytes());
    result.extend(wire);
    result
}

fn main() {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut head = [0u8; 8];
        let count = input.read(&mut head[..1]).unwrap();
        if count == 0 { break; }
        input.read_exact(&mut head[1..]).unwrap();
        let size = u64::from_le_bytes(head) as usize;
        assert!((48..=(8 << 20) + 48).contains(&size));
        let mut raw = vec![0u8; size];
        input.read_exact(&mut raw).unwrap();
        let result = observed(&raw);
        output.write_all(&(result.len() as u64).to_le_bytes()).unwrap();
        output.write_all(&result).unwrap();
    }
    output.flush().unwrap();
}
