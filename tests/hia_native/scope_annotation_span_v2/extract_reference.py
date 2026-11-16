"""Extract both unchanged OwnerScope methods and a separate wire observer."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parent
TARGET_COMMIT = "d3d75c30719db966b004756f610007a7c723729e"
TARGET_SHA = "1db8a3f4235339d8a7aef6e247ddc8f42f4791a26efe4dd298490421b8ca1d9a"
TARGET_BLOB = "ea360b7627695d212fd4fbe9f7e71d1dc8858591"
LOCK_SHA = "1509860cac0e7f26e6a845edfec1c87ae3bd92380ecaa357457e5263e861d631"
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
CARGO = (ROOT / "reference/Cargo.toml").read_bytes()
PREFIX = b'''// Copyright 2026 Muvon Un Limited
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

'''


def extract(raw):
    assert SHA(raw) == TARGET_SHA
    assert hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == TARGET_BLOB
    start = raw.index(b"#[derive(Clone, PartialEq, Eq)]\npub struct OwnerScope {")
    pieces = {"struct": (start, raw.index(b"\n}\n", start) + 3)}
    for name, marker in (("annotate", b"\tpub fn annotate("),
                         ("annotate_search_effect", b"\tpub fn annotate_search_effect("),
                         ("kind", b"\tfn kind(")):
        start = raw.index(marker)
        pieces[name] = (start, raw.index(b"\n\t}\n", start) + 4)
    members = {name: raw[start:end] for name, (start, end) in pieces.items()}
    signature = b"\tpub fn annotate(&self, text: String, search: bool) -> Result<String> {\n"
    annotate = members["annotate"]
    assert annotate.startswith(signature)
    budget = annotate.index(b"\t\tif serde_json::to_vec(&wire)?.len() > 64 * 1024 {")
    prefix = annotate[len(signature):budget]
    observer = (b"\tfn observe_serialized_prefix(&self, text: String, search: bool) -> Result<(String, Vec<u8>)> {\n"
                + prefix + b"\t\tlet bytes = serde_json::to_vec(&wire)?;\n\t\tOk((text, bytes))\n\t}\n")
    source = (PREFIX + members["struct"] + b"impl OwnerScope {\n" + members["annotate"]
              + members["annotate_search_effect"] + members["kind"] + observer + b"}\n"
              + (ROOT / "reference/observer.rs.txt").read_bytes())
    records = {name: dict(start=start, end=end, bytes=end-start, sha256=SHA(raw[start:end]))
               for name, (start, end) in pieces.items()}
    records["observer_original_prefix"] = dict(start=pieces["annotate"][0] + len(signature),
        end=pieces["annotate"][0] + budget, bytes=len(prefix), sha256=SHA(prefix),
        unchanged_entire_method=False, exact_original_statements=True)
    return source, records


if __name__ == "__main__":
    source, records = extract((ROOT / "reference/target/src/mcp/runtime/caller_scope.rs").read_bytes())
    (ROOT / "reference/main.rs").write_bytes(source)
    record = dict(schema="hepta.scope-annotation-span.original-extraction.v2", target_commit=TARGET_COMMIT,
        target_sha256=TARGET_SHA, target_git_blob=TARGET_BLOB, target_lock_sha256=LOCK_SHA,
        source_sha256=SHA(source), cargo_sha256=SHA(CARGO), extracted=records,
        primary_methods_unchanged=True, warning_recorded_from_actual_tracing=True,
        prefix_observer_separate=True, original_execution_qualified=False)
    (ROOT / "reference/extraction.json").write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
    print(json.dumps(record, sort_keys=True))
