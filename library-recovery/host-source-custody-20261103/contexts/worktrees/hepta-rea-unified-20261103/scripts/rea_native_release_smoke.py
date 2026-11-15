#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Check the shipped Rust descriptor workers without loading a large payload."""

import argparse
import hashlib
import json
import subprocess
import tempfile
import zipfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    with binary.open("rb") as source:
        binary_sha256 = hashlib.file_digest(source, "sha256").hexdigest()
    checks = []

    def invoke(name, command, path, request, expected_success=True, writable=False):
        with path.open("r+b" if writable else "rb") as source:
            result = subprocess.run(
                [str(binary), command, "--request", json.dumps(request)],
                stdin=source,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={},
                cwd="/",
                timeout=35,
                check=False,
            )
        (output / f"{name}.stdout").write_bytes(result.stdout)
        (output / f"{name}.stderr").write_bytes(result.stderr)
        assert (result.returncode == 0) == expected_success, (
            name, result.returncode, result.stderr.decode(errors="replace")
        )
        if expected_success:
            assert not result.stderr, (name, result.stderr)
            assert len(result.stdout) <= 1024 * 1024 + 1
            record = json.loads(result.stdout)
        else:
            assert not result.stdout, (name, "partial success output")
            assert result.stderr, (name, "missing refusal")
            record = None
        checks.append({"name": name, "exit_code": result.returncode,
                       "expected_success": expected_success, "passed": True})
        return record

    with tempfile.TemporaryDirectory(prefix="hepta-release-artifacts-") as temporary:
        root = Path(temporary)
        model = root / "sparse.safetensors"
        size = 4 * 1024 * 1024 * 1024
        header = json.dumps(
            {"w": {"dtype": "U8", "shape": [size], "data_offsets": [0, size]}},
            separators=(",", ":"),
        ).encode()
        with model.open("wb") as source:
            source.write(len(header).to_bytes(8, "little"))
            source.write(header)
            source.truncate(8 + len(header) + size)
            source.seek(-2, 2)
            source.write(bytes.fromhex("abcd"))
        request = {"operation": "inspect", "collection": "tensors", "offset": 0, "limit": 1}
        record = invoke("model-four-gib", "rea-model-worker", model, request)
        assert record["result"]["rows"][0]["byte_length"] == size
        record = invoke("model-tail-range", "rea-model-worker", model,
                        {"operation": "read", "tensor_name": "w", "offset": size - 2, "length": 2})
        assert record["result"]["bytes_hex"] == "abcd"
        invoke("model-writable-fd", "rea-model-worker", model, request,
               expected_success=False, writable=True)
        malformed = root / "malformed.safetensors"
        malformed.write_bytes((2 ** 64 - 1).to_bytes(8, "little"))
        invoke("model-malformed", "rea-model-worker", malformed, request,
               expected_success=False)

        archive = root / "inert-structure.apk"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as writer:
            writer.writestr("AndroidManifest.xml", b"inert, not a real manifest")
            writer.writestr("classes.dex", b"inert, not executable DEX")
            writer.writestr("lib/arm64-v8a/libfixture.so", b"inert, not a shared library")
            writer.writestr("META-INF/CERT.RSA", b"inert, not a signature")
        archive_request = {"filter": "native_library", "offset": 0, "limit": 1}
        record = invoke("archive-role-index", "rea-archive-worker", archive, archive_request)
        assert record["result"]["rows"][0]["name"] == "lib/arm64-v8a/libfixture.so"
        assert record["result"]["rows"][0]["content_verified"] is False
        assert record["coverage"]["signatures"] == "not_verified"
        invoke("archive-writable-fd", "rea-archive-worker", archive, archive_request,
               expected_success=False, writable=True)
        truncated = root / "truncated.zip"
        truncated.write_bytes(archive.read_bytes()[:-1])
        invoke("archive-truncated", "rea-archive-worker", truncated, archive_request,
               expected_success=False)

    summary = {
        "schema": "hepta.native-release-smoke.v1",
        "binary_sha256": binary_sha256,
        "binary_bytes": binary.stat().st_size,
        "model_payload_bytes": size,
        "worker_address_space_limit_bytes": 768 * 1024 * 1024,
        "checks": checks,
        "passed": True,
        "scope": "Descriptor parsing and range access; no full model hash, ZIP contents or signature qualification.",
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
