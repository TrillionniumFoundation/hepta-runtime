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
// SPDX-License-Identifier: Apache-2.0
//! Actual source-extracted OwnerScope comparison fixture and complete observations.
//! The two target methods are byte-for-byte unchanged. The separate prefix
//! observer and tracing subscriber record their returned data and warning.
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

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

#[derive(Clone, Default)]
struct WarningCapture(Arc<Mutex<Vec<String>>>);

impl tracing::Subscriber for WarningCapture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool { true }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Visitor(Option<String>);
        impl tracing::field::Visit for Visitor {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                assert_eq!(field.name(), "message");
                assert!(self.0.is_none());
                self.0 = Some(format!("{value:?}"));
            }
        }
        assert_eq!(*event.metadata().level(), tracing::Level::WARN);
        let mut visitor = Visitor(None);
        event.record(&mut visitor);
        self.0.lock().unwrap().push(visitor.0.unwrap());
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

fn word(raw: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(raw[at..at + 8].try_into().unwrap())
}

fn number(raw: &mut Vec<u8>, value: u64) {
    raw.extend_from_slice(&value.to_le_bytes());
}

fn observed(raw: &[u8]) -> Vec<u8> {
    assert!(raw.len() >= 48);
    assert_eq!(&raw[..8], b"HSCANS02");
    let operation = word(raw, 8);
    assert!(operation == 1 || operation == 2);
    assert!(word(raw, 16) <= 1 && word(raw, 24) <= 1);
    assert!(operation != 2 || word(raw, 24) == 1);
    assert_eq!(word(raw, 32) as usize, raw.len() - 48);
    assert_eq!(word(raw, 40), 0);
    let text = std::str::from_utf8(&raw[48..]).unwrap().to_owned();
    let scope = OwnerScope { owner: String::new(), authenticated: word(raw, 16) == 1 };
    let search = word(raw, 24) == 1;
    let warning_capture = WarningCapture::default();
    // This is the actual unchanged effect method, including its own annotate
    // call, second parse, field filters, warning and original-text recovery.
    let effect = if operation == 2 {
        Some(tracing::subscriber::with_default(warning_capture.clone(), || {
            scope.annotate_search_effect(text.clone())
        }))
    } else {
        None
    };
    // Independently retain annotate's complete primary result and the entire
    // original serialization prefix, including a rejected over-budget wire.
    let primary = scope.annotate(text.clone(), search);
    let failed = primary.is_err();
    let prefix = scope.observe_serialized_prefix(text.clone(), search);
    let (annotate_kind, category, annotate_answer, annotation, wire) = match (primary, prefix) {
        (Ok(actual), Ok((annotation, wire))) => {
            assert_eq!(actual, annotation);
            assert!(wire.len() <= 65536);
            (0u64, 0u64, actual, annotation, wire)
        }
        (Err(error), Ok((annotation, wire))) => {
            let error = error.to_string();
            assert_eq!(error, "scoped metadata wire response exceeds 64 KiB; reduce result page limit");
            assert!(wire.len() > 65536);
            (1, 3, error, annotation, wire)
        }
        (Err(error), Err(prefix_error)) => {
            let error = error.to_string();
            assert_eq!(error, prefix_error.to_string());
            let category = if error == "metadata response unavailable" { 2 } else { 1 };
            (1, category, error, String::new(), Vec::new())
        }
        _ => panic!("unchanged primary and separate original-prefix observer disagree"),
    };
    let warnings = warning_capture.0.lock().unwrap();
    assert_eq!(warnings.len(), usize::from(operation == 2 && failed));
    let warning = warnings.first().cloned().unwrap_or_default();
    if !warning.is_empty() {
        assert_eq!(warning, "search scope annotation unavailable; existing identity retained");
    }
    let (kind, answer, fallback) = if let Some(answer) = effect {
        let fallback = if !failed { 0 } else if answer == text { 2 } else { 1 };
        (0, answer, fallback)
    } else {
        (annotate_kind, annotate_answer, 0)
    };
    let mut response = b"HSCAR002".to_vec();
    for value in [kind, answer.len() as u64, wire.len() as u64, category,
                  annotation.len() as u64, fallback, warnings.len() as u64] {
        number(&mut response, value);
    }
    response.extend_from_slice(answer.as_bytes());
    let mut result = b"HSCASR02".to_vec();
    for value in [response.len() as u64, annotation.len() as u64, wire.len() as u64, warning.len() as u64] {
        number(&mut result, value);
    }
    result.extend(response);
    result.extend_from_slice(annotation.as_bytes());
    result.extend(wire);
    result.extend_from_slice(warning.as_bytes());
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
        let size = usize::try_from(u64::from_le_bytes(head)).unwrap();
        assert!(size >= 48);
        let mut raw = vec![0u8; size];
        input.read_exact(&mut raw).unwrap();
        let result = observed(&raw);
        output.write_all(&(result.len() as u64).to_le_bytes()).unwrap();
        output.write_all(&result).unwrap();
    }
    output.flush().unwrap();
}
