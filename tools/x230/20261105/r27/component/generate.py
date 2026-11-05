#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Embed exact source items in bench.rs; retain source and excerpt SHA-256s."""
import argparse
import hashlib
import json
from pathlib import Path
import re


DIRECTORY = Path(__file__).resolve().parent
ITEMS = [
    ("limit", rb"(?m)^const MAX_OBSERVATION_BYTES:[^\r\n]*(?:\r?\n|$)", False),
    ("validate", rb"(?m)^fn validate_observation_bytes\(", True),
    ("script", rb"(?m)^pub\(super\) enum ObservationScript\s*\{", True),
    ("observation", rb"(?m)^pub\(super\) enum JobObservation<'a>\s*\{", True),
    ("prepare", rb"(?m)^fn prepare_observation\(", True),
]
PAYLOAD = (
    "payload",
    rb"(?m)^#\[derive\(Serialize\)\]\r?\n#\[serde\(untagged\)\]\r?\nenum JobObservationPayload<'a>\s*\{",
    True,
)
ADAPTER = b"""
// Both modules use the same fixed stub and the same fixture adapter.
fn job_observation_command(_script: ObservationScript) -> Result<&'static str> {
    Ok(super::PYTHON_COMMAND_STUB)
}

pub(super) const LIMIT: usize = MAX_OBSERVATION_BYTES;

#[inline(never)]
pub(super) fn prepare(case: &super::Case) -> Result<super::Prepared> {
    let value = match case.kind {
        super::Kind::PythonStatus => JobObservation::PythonStatus {
            job_id: &case.job_id,
            job_dir: &case.job_dir,
            unit: &case.unit,
            request_digest: &case.request_digest,
            wait_seconds: case.wait_seconds,
        },
        super::Kind::PythonRead => JobObservation::PythonRead {
            job_id: &case.job_id,
            job_dir: &case.job_dir,
            unit: &case.unit,
            request_digest: &case.request_digest,
            stdout_offset: case.stdout_offset,
            stderr_offset: case.stderr_offset,
            limit: case.limit,
        },
        super::Kind::SystemStatus => JobObservation::SystemStatus { job_id: &case.job_id },
        super::Kind::SystemRead => JobObservation::SystemRead {
            job_id: &case.job_id,
            stdout_offset: case.stdout_offset,
            stderr_offset: case.stderr_offset,
            limit: case.limit,
        },
    };
    prepare_observation(value)
}
"""


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def extract(source, specification):
    name, pattern, block = specification
    matches = list(re.finditer(pattern, source))
    if len(matches) != 1:
        raise ValueError(f"{name}: expected one source item, found {len(matches)}")
    start, end = matches[0].span()
    if block:
        # These known top-level items end at the first column-zero closing brace.
        # Nested blocks are indented; no extracted item contains raw string code.
        closing = re.search(rb"(?m)^\}(?:\r?\n|$)", source[end:])
        if closing is None:
            raise ValueError(f"{name}: missing top-level closing brace")
        end += closing.end()
    excerpt = source[start:end]
    return excerpt, {
        "name": name,
        "sha256": sha256(excerpt),
        "bytes": len(excerpt),
        "first_line": source[:start].count(b"\n") + 1,
        "last_line": source[:end].count(b"\n"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path,
                        default=DIRECTORY.parent / "base/src/mcp/runtime/ssh.rs")
    parser.add_argument("--candidate", type=Path,
                        default=DIRECTORY.parent / "candidate/src/mcp/runtime/ssh.rs")
    parser.add_argument("--output", type=Path, default=DIRECTORY / "bench.rs")
    args = parser.parse_args()
    modules, records, originals = [], {}, {}
    for label, path in [("baseline", args.baseline), ("candidate", args.candidate)]:
        source = path.read_bytes()  # No newline normalization or source rewriting.
        source.decode("utf-8")
        specifications = ITEMS[:-1] + ([PAYLOAD] if label == "candidate" else []) + ITEMS[-1:]
        parts, hashes, original = [], [], {}
        for specification in specifications:
            excerpt, information = extract(source, specification)
            parts.append(excerpt)
            hashes.append(information)
            original[information["name"]] = excerpt
        imports = b"use anyhow::{bail, Result};\nuse std::time::Duration;\n"
        if label == "candidate":
            imports += b"use serde::Serialize;\n"
        module = b"mod " + label.encode() + b" {\n" + imports + b"\n".join(parts) + ADAPTER + b"}\n"
        # Re-extract from the completed module and verify every original byte/hash.
        for specification, information in zip(specifications, hashes):
            embedded, _ = extract(module, specification)
            assert embedded == original[information["name"]]
            assert sha256(embedded) == information["sha256"]
        modules.append(module)
        records[label] = {"file": str(path.resolve()), "sha256": sha256(source), "items": hashes}
        originals[label] = original
    for name in ("limit", "validate", "script", "observation"):
        if originals["baseline"][name] != originals["candidate"][name]:
            raise ValueError(f"shared source item differs: {name}")
    provenance = json.dumps({"kind": "source", "sources": records}, separators=(",", ":"))
    delimiter = "#"
    while '"' + delimiter in provenance:
        delimiter += "#"
    constant = f'const SOURCE_METADATA: &str = r{delimiter}"{provenance}"{delimiter};\n'.encode()
    block = b"// BEGIN_EXTRACTED_SOURCE\n" + constant + b"\n".join(modules) + b"// END_EXTRACTED_SOURCE\n"
    template = (DIRECTORY / "bench.rs").read_bytes()
    pattern = rb"(?ms)^// BEGIN_EXTRACTED_SOURCE\r?\n.*?^// END_EXTRACTED_SOURCE\r?\n"
    output, count = re.subn(pattern, lambda _: block, template)
    if count != 1:
        raise ValueError("bench.rs must contain exactly one extraction region")
    args.output.write_bytes(output)
    print(json.dumps({"generated": str(args.output.resolve()), "sha256": sha256(output),
                      "sources": records}, indent=2))


if __name__ == "__main__":
    main()
