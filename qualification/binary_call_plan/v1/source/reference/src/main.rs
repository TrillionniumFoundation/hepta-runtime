// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
static POOL: AtomicBool = AtomicBool::new(false);
static EVENTS: Mutex<Vec<Value>> = Mutex::new(Vec::new());
use std::sync::Mutex;
mod mcp {
    pub mod weight_config {
        pub type WeightWorkerProfile = serde_json::Value;
        pub fn validate_profiles(config: &crate::runtime::config::RuntimeConfig) -> anyhow::Result<()> {
            anyhow::ensure!(config.weight_workers.is_empty(), "excluded weight profile boundary");
            Ok(())
        }
    }
    pub mod rea_provider {
        pub type ReaStaticProfile = serde_json::Value;
        pub fn validate_profiles(config: &crate::runtime::config::RuntimeConfig) -> anyhow::Result<()> {
            anyhow::ensure!(config.rea_static_profiles.is_empty(), "excluded analyzer profile boundary");
            Ok(())
        }
    }
    pub mod hia_provider {
        pub type HiaWorkerProfile = serde_json::Value;
        pub fn validate_profile(config: &crate::runtime::config::RuntimeConfig) -> anyhow::Result<()> {
            anyhow::ensure!(config.hia_worker.is_none(), "excluded HIA provider profile boundary");
            Ok(())
        }
    }
}
mod runtime {
    pub mod config { include!("config.rs"); }
    pub mod binary { include!("binary.rs"); }
    pub mod jobs {
        pub fn audit(event: &str, host: &str, path: &str, detail: &serde_json::Value) -> anyhow::Result<()> {
            crate::EVENTS.lock().unwrap().push(serde_json::json!({
                "kind":"audit","event":event,"host":host,"path":path,"detail":detail
            }));
            Ok(())
        }
    }
    pub mod ssh {
        pub fn file_observation_pool_requested() -> bool {
            crate::POOL.load(std::sync::atomic::Ordering::Relaxed)
        }
        pub enum FileObservation<'a> {
            Info { root: &'a str, path: &'a str },
            Read { root: &'a str, path: &'a str, offset: Option<u64>,
                   limit: u64, expected_version: Option<&'a str> },
        }
        pub async fn run_file_observation(host: &str, request: FileObservation<'_>)
            -> anyhow::Result<serde_json::Value> {
            let query = match request {
                FileObservation::Info { root, path } =>
                    serde_json::json!({"op":"info","root":root,"path":path}),
                FileObservation::Read { root, path, offset, limit, expected_version } =>
                    serde_json::json!({"op":"read","root":root,"path":path,"offset":offset,
                                      "limit":limit,"expected_version":expected_version}),
            };
            crate::EVENTS.lock().unwrap().push(serde_json::json!({
                "kind":"observation","host":host,"query":query
            }));
            Ok(query)
        }

        pub async fn run_python_json(host: &super::config::HostConfig, source: &str,
            query: &serde_json::Value, duration: std::time::Duration) -> anyhow::Result<serde_json::Value> {
            crate::EVENTS.lock().unwrap().push(serde_json::json!({
                "kind":"rpc","ssh_target":host.ssh_target,"source":source,
                "query":query,"duration_seconds":duration.as_secs()
            }));
            Ok(query.clone())
        }
    }
    pub fn ready<F: std::future::Future>(future: F) -> F::Output {
        let mut pinned = std::pin::pin!(future);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        match pinned.as_mut().poll(&mut context) {
            std::task::Poll::Ready(value) => value,
            std::task::Poll::Pending => panic!("private ready post-admission boundary became pending"),
        }
    }
}
fn word(out: &mut [u8], at: usize, value: u64) {
    out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn hex(raw: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut result = String::with_capacity(raw.len() * 2);
    for byte in raw {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}
fn result_frame(kind: u64, params: &Value) -> Vec<u8> {
    let mut out = vec![0; 256];
    out[..8].copy_from_slice(b"HBPRR001");
    word(&mut out, 16, kind);
    let action = match (kind, params["action"].as_str()) {
        (4, Some("chunk")) | (5, Some("apply")) => 1,
        (4, Some("commit")) | (5, Some("status")) => 2,
        (4, Some("abort")) | (5, Some("recover")) => 3,
        (_, None) => 0,
        _ => panic!("typed action is not one of the unchanged enum variants"),
    };
    word(&mut out, 24, action);
    let options: &[(u64, &str)] = match kind {
        1 | 3 => &[],
        2 => &[(9, "offset"), (10, "limit"), (4, "expected_version")],
        4 => &[(9, "offset"), (3, "data_base64"), (4, "expected_version"), (11, "size"), (6, "sha256")],
        5 => &[(9, "offset"), (4, "expected_version"), (8, "expected_sha256"), (3, "data_base64")],
        _ => panic!("private kind"),
    };
    let present = options.iter().fold(0u64, |bits, (id, key)| {
        if params[*key].is_null() { bits } else { bits | (1u64 << *id) }
    });
    word(&mut out, 32, present);
    let flags = u64::from(params["acknowledge_non_atomic"].as_bool().unwrap_or(false))
        | (u64::from(params["preserve_special_bits"].as_bool().unwrap_or(false)) << 1);
    word(&mut out, 40, flags);
    for (at, key) in [(48, "offset"), (56, "limit"), (64, "size")] {
        word(&mut out, at, params[key].as_u64().unwrap_or(0));
    }
    for (index, key) in ["host", "path", "data_base64", "expected_version", "upload_id",
                         "sha256", "transaction_id", "expected_sha256"].iter().enumerate() {
        let bytes = params[*key].as_str().unwrap_or("").as_bytes();
        word(&mut out, 88 + index * 8, bytes.len() as u64);
        out.extend_from_slice(bytes);
    }
    out
}
fn error_frame(kind: u64, message: &str) -> Vec<u8> {
    let mut out = vec![0; 256];
    out[..8].copy_from_slice(b"HBPRR001");
    word(&mut out, 8, 1);
    word(&mut out, 16, kind);
    word(&mut out, 72, message.len() as u64);
    out.extend_from_slice(message.as_bytes());
    out
}

fn main() -> Result<()> {
    use runtime::binary::*;
    let mut raw = Vec::new();
    std::io::stdin().read_to_end(&mut raw)?;
    let group: Value = serde_json::from_slice(&raw)?;
    runtime::config::install_fixture(group["config"].clone())?;
    let mut rows = Vec::new();
    for row in group["cases"].as_array().context("cases")? {
        let kind = row["kind"].as_u64().context("kind")?;
        POOL.store(row["pool"].as_bool().context("pool")?, Ordering::Relaxed);
        anyhow::ensure!(EVENTS.lock().unwrap().is_empty(), "unconsumed prior effect boundary");
        let map: serde_json::Map<String, Value> =
            serde_json::from_str(row["raw_json"].as_str().context("raw_json")?)?;
        let value = Value::Object(map);
        let canonical = serde_json::to_string(&value)?;
        macro_rules! execute {
            ($ty:ty, $body:path) => {{
                match serde_json::from_value::<$ty>(value) {
                    Err(error) => json!({"canonical":canonical,"typed_ok":false,
                        "typed_frame":hex(&error_frame(kind,&error.to_string())),
                        "error":error.to_string(),"events":[]}),
                    Ok(params) => {
                        let normalized = serde_json::to_value(&params)?;
                        let frame = result_frame(kind, &normalized);
                        let result = runtime::ready($body(params));
                        let events = std::mem::take(&mut *EVENTS.lock().unwrap());
                        let body = match result {
                            Ok(text) => json!({"ok":text}),
                            Err(error) => json!({"error":error.to_string()}),
                        };
                        json!({"canonical":canonical,"typed_ok":true,"typed_frame":hex(&frame),
                            "normalized":normalized,"body":body,"events":events})
                    },
                }
            }}
        }
        let result = match kind {
            1 => execute!(FileInfoParams,runtime::binary::info),
            2 => execute!(BinaryReadParams,runtime::binary::read),
            3 => execute!(BinaryWriteParams,runtime::binary::write),
            4 => execute!(BinaryUploadParams,runtime::binary::upload),
            5 => execute!(InodePatchParams,runtime::binary::patch_inode),
            _ => anyhow::bail!("private fixture kind"),
        };
        rows.push(json!({"case_id":row["case_id"],"kind":kind,"name":row["name"],"result":result}));
    }
    std::io::stdout().write_all(&serde_json::to_vec(&rows)?)?;
    std::io::stdout().write_all(b"\n")?;
    Ok(())
}
