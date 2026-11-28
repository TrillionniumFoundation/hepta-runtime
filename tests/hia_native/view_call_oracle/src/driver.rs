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

// Test-only actual filesystem scheduling and observation. Original function
// bodies and the Tokio task-local context are assembled unchanged above.
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex};
use serde_json::{json, Value};

#[derive(Default)]
struct Observation {
    case: Value,
    inputs: Vec<Vec<u8>>,
    outputs: Vec<Vec<u8>>,
    counts: HashMap<String, u64>,
    events: Vec<Value>,
    fired: Vec<usize>,
    rendered: Option<Value>,
    before_cancel: Option<Value>,
}

static OBS: LazyLock<Mutex<Observation>> = LazyLock::new(Default::default);

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value.as_bytes().chunks_exact(2).map(|pair| {
        let text = std::str::from_utf8(pair).unwrap();
        u8::from_str_radix(text, 16).unwrap()
    }).collect()
}

fn path(value: &Value) -> PathBuf {
    let raw = decode_hex(value.as_str().unwrap());
    let result = PathBuf::from(std::ffi::OsString::from_vec(raw));
    assert!(!result.is_absolute());
    assert!(!result.components().any(|component| matches!(component, std::path::Component::ParentDir)));
    result
}

fn trace_blob(raw: &[u8]) -> usize {
    let mut obs = OBS.lock().unwrap();
    obs.outputs.push(raw.to_vec());
    obs.outputs.len() - 1
}

fn raw_path() -> Option<PathBuf> {
    let obs = OBS.lock().unwrap();
    obs.case["raw_path"].as_bool().unwrap().then(|| path(&obs.case["path_hex"]))
}

fn record_render(result: &anyhow::Result<String>) {
    let record = match result {
        Ok(text) => json!({"ok": true, "blob": trace_blob(text.as_bytes()), "bytes": text.len()}),
        Err(error) => json!({"ok": false, "error": error.to_string()}),
    };
    OBS.lock().unwrap().rendered = Some(record);
}

async fn actions(actions: &[Value]) {
    for action in actions {
        let target = path(&action["path_hex"]);
        match action["kind"].as_str().unwrap() {
            "write" => {
                let bytes = OBS.lock().unwrap().inputs[action["blob"].as_u64().unwrap() as usize].clone();
                if let Some(parent) = target.parent() {
                    tokio::fs::create_dir_all(parent).await.unwrap();
                }
                tokio::fs::write(&target, bytes).await.unwrap();
            }
            "remove" => tokio::fs::remove_file(&target).await.unwrap(),
            "mkdir" => tokio::fs::create_dir_all(&target).await.unwrap(),
            "symlink" => tokio::fs::symlink(path(&action["target_hex"]), &target).await.unwrap(),
            "hardlink" => tokio::fs::hard_link(path(&action["target_hex"]), &target).await.unwrap(),
            _ => panic!("unregistered filesystem fixture action"),
        }
    }
}

async fn hooks(event: &str, occurrence: u64, when: &str) {
    let pending = {
        let obs = OBS.lock().unwrap();
        obs.case["hooks"].as_array().unwrap().iter().enumerate()
            .filter(|(_, row)| row["event"] == event && row["occurrence"] == occurrence && row["when"] == when)
            .map(|(index, row)| (index, row["actions"].as_array().unwrap().clone())).collect::<Vec<_>>()
    };
    for (index, list) in pending {
        actions(&list).await;
        let mut obs = OBS.lock().unwrap();
        assert!(!obs.fired.contains(&index));
        obs.fired.push(index);
        obs.events.push(json!({"kind": "mutation", "hook": index, "event": event,
                               "occurrence": occurrence, "when": when}));
    }
}

async fn before(event: &str) -> u64 {
    let occurrence = {
        let mut obs = OBS.lock().unwrap();
        let count = obs.counts.entry(event.into()).or_default();
        *count += 1;
        *count
    };
    hooks(event, occurrence, "before").await;
    occurrence
}

async fn after(event: &str, occurrence: u64, result: Value) {
    OBS.lock().unwrap().events.push(json!({"kind": "io", "event": event,
                                         "occurrence": occurrence, "result": result}));
    hooks(event, occurrence, "after").await;
}

fn probe(cache: &mcp::fs::delta::ViewCache, names: &[Value]) -> Value {
    let mut out = Vec::new();
    for name in names {
        let source = mcp::fs::PathSource::Local(path(name));
        let cached = mcp::fs::delta::inspect(cache, &source);
        out.push(json!({"path_hex": name, "present": cached.is_some(),
                        "blob": cached.as_ref().map(|text| trace_blob(text.as_bytes())),
                        "bytes": cached.as_ref().map_or(0, String::len)}));
    }
    json!(out)
}

fn word(input: &mut impl Read) -> u64 {
    let mut raw = [0u8; 8];
    input.read_exact(&mut raw).unwrap();
    u64::from_le_bytes(raw)
}

fn bytes(input: &mut impl Read, size: u64) -> Vec<u8> {
    let mut result = vec![0u8; usize::try_from(size).unwrap()];
    input.read_exact(&mut result).unwrap();
    result
}

fn write_record(output: &mut impl Write, metadata: &Value, blobs: &[Vec<u8>]) {
    let raw = serde_json::to_vec(metadata).unwrap();
    output.write_all(&(raw.len() as u64).to_le_bytes()).unwrap();
    output.write_all(&(blobs.len() as u64).to_le_bytes()).unwrap();
    output.write_all(&raw).unwrap();
    for blob in blobs {
        output.write_all(&(blob.len() as u64).to_le_bytes()).unwrap();
        output.write_all(blob).unwrap();
    }
}

async fn execute_case(case: Value, inputs: Vec<Vec<u8>>, cache: Arc<mcp::fs::delta::ViewCache>) -> (Value, Vec<Vec<u8>>) {
    *OBS.lock().unwrap() = Observation { case: case.clone(), inputs, ..Default::default() };
    actions(case["setup"].as_array().unwrap()).await;
    if case["reset_cache"].as_bool().unwrap() { cache.forget_all(); }
    let probes = case["cache_probes"].as_array().unwrap();
    let before_cache = probe(&cache, probes);
    let mut parameters = case["params"].clone();
    if !case["raw_path"].as_bool().unwrap() {
        parameters["path"] = json!(String::from_utf8(decode_hex(case["path_hex"].as_str().unwrap())).unwrap());
    }
    let call = mcp::McpToolCall { parameters, workdir: PathBuf::new() };
    let context = case["context"].as_bool().unwrap();
    let cancel = case["cancel_after_render"].as_bool().unwrap();
    let (sender, receiver) = tokio::sync::oneshot::channel::<()>();
    let request_cache = cache.clone();
    let task = tokio::spawn(async move {
        let future = async move {
            let result = mcp::fs::core::execute_view(&call).await;
            let hints = request_ctx::inspect_hints();
            if cancel {
                let row = match &result {
                    Ok(text) => json!({"ok": true, "blob": trace_blob(text.as_bytes()), "bytes": text.len(), "hints": hints}),
                    Err(error) => json!({"ok": false, "error": error.to_string(), "hints": hints}),
                };
                OBS.lock().unwrap().before_cancel = Some(row);
                sender.send(()).unwrap();
                std::future::pending::<()>().await;
            }
            let (ok, body) = match result {
                Ok(text) => (true, append_hints(text)),
                Err(error) => (false, error.to_string()),
            };
            let remaining = request_ctx::inspect_hints();
            json!({"ok": ok, "blob": trace_blob(body.as_bytes()), "bytes": body.len(),
                   "hints": hints, "hints_remaining": remaining})
        };
        if context { request_ctx::with_request_context(request_cache, future).await }
        else { future.await }
    });
    let outcome = if cancel {
        receiver.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        json!({"cancelled": true, "publication_bytes": 0})
    } else { task.await.unwrap() };
    assert!(request_ctx::drain_hints().is_empty());
    let after_cache = probe(&cache, probes);
    let mut obs = OBS.lock().unwrap();
    assert_eq!(obs.fired.len(), case["hooks"].as_array().unwrap().len(), "every scheduled actual I/O mutation must execute");
    let metadata = json!({"case_id": case["case_id"], "name": case["name"],
                          "session": case["session"], "outcome": outcome,
                          "rendered": obs.rendered, "before_cancel": obs.before_cancel,
                          "cache_before": before_cache, "cache_after": after_cache,
                          "io_counts": obs.counts, "events": obs.events,
                          "fired_hooks": obs.fired, "outside_scope_hints_empty": true});
    (metadata, std::mem::take(&mut obs.outputs))
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let root = std::env::args_os().nth(1).map(PathBuf::from).expect("fresh fixture root argument");
    assert!(!root.exists(), "fixture root must be fresh");
    tokio::fs::create_dir_all(&root).await.unwrap();
    let root = tokio::fs::canonicalize(root).await.unwrap();
    let mut input = io::BufReader::new(io::stdin().lock());
    let mut output = io::BufWriter::new(io::stdout().lock());
    assert_eq!(bytes(&mut input, 8), b"HVCOI001");
    let count = word(&mut input);
    output.write_all(b"HVCOO001").unwrap();
    output.write_all(&count.to_le_bytes()).unwrap();
    let mut sessions: HashMap<u64, Arc<mcp::fs::delta::ViewCache>> = HashMap::new();
    for _ in 0..count {
        let metadata_size = word(&mut input);
        let blob_count = word(&mut input);
        let metadata: Value = serde_json::from_slice(&bytes(&mut input, metadata_size)).unwrap();
        let mut blobs = Vec::new();
        for _ in 0..blob_count { let size = word(&mut input); blobs.push(bytes(&mut input, size)); }
        let session = metadata["session"].as_u64().unwrap();
        let directory = root.join(format!("session-{session}"));
        tokio::fs::create_dir_all(&directory).await.unwrap();
        std::env::set_current_dir(&directory).unwrap();
        let cache = sessions.entry(session).or_default().clone();
        let (metadata, blobs) = execute_case(metadata, blobs, cache).await;
        write_record(&mut output, &metadata, &blobs);
    }
    let mut trailing = [0u8; 1];
    assert_eq!(input.read(&mut trailing).unwrap(), 0, "trailing corpus bytes");
    output.flush().unwrap();
}
