# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Reject damaged source, compiler receipts and complete native result corpora."""
from pathlib import Path
import argparse
import gzip
import json
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import hia_native_result_qualification as q
from result_value_registry import encoded, regular, require, sha, source_pins


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "build", "native", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    root, native = args.repo.resolve(strict=True), args.native.resolve(strict=True)
    bundle_path = args.build.resolve(strict=True)
    baseline = q.inspect_native_outputs(root, bundle_path, native)
    sources = source_pins(root)
    bundle = baseline["build"]["bundle"]
    module = Path(bundle["modules"]["binary32"]["path"]).parent
    requests = native / "binary32/original/requests.bin.gz"
    receipt = native / "binary32/original/receipt.json"
    result32 = native / "binary32/result.json"
    typed = native / "typed/result.json"
    request = native / "request/result.json"
    rows = []
    begin = time.monotonic()

    def rejected(label, changes, verify):
        old = {path: regular(path) for path in changes}
        try:
            for path, raw in changes.items():
                path.write_bytes(raw)
            try:
                verify()
            except (ValueError, AssertionError, KeyError, TypeError, EOFError, OSError) as error:
                rows.append(dict(label=label, rejected=True, error_type=type(error).__name__))
            else:
                raise AssertionError("damaged result evidence accepted: " + label)
        finally:
            for path, raw in old.items():
                path.write_bytes(raw)
        require(all(regular(path) == raw for path, raw in old.items()), "control restoration changed bytes")
        q.verify_build(root, bundle_path)

    def changed(path, edit):
        value = json.loads(regular(path))
        edit(value)
        return encoded(value)

    build = lambda: q.verify_build(root, bundle_path)
    full = lambda: q.inspect_native_outputs(root, bundle_path, native)
    fixture = lambda: q.fixture_receipts(root, native / "binary32", "binary32", q.object_at(result32))
    source = root / "tests/hia_native/result_value_cases.py"
    rejected("source-custody", {source: regular(source) + b"\n# damaged control\n"}, build)
    image = module / "module.image.bin"
    rejected("native-image", {image: bytes([regular(image)[0] ^ 1]) + regular(image)[1:]}, build)
    rejected("missing-child", {bundle_path: changed(bundle_path, lambda value: value["modules"].pop("value"))}, build)
    rejected("empty-compiler-observer", {module / "module.stdout.log": b"{}\n"}, build)
    complete = module / "module.output.bin"
    raw = regular(complete)
    rejected("compiler-output", {complete: raw[:100] + bytes([raw[100] ^ 1]) + raw[101:]}, build)
    path = module / "module.receipt.json"
    rejected("compiler-status", {path: changed(path, lambda value: value.update(status="trapped"))}, build)
    rejected("truncated-request", {requests: regular(requests)[:-8]}, fixture)
    raw = gzip.decompress(regular(requests))
    damaged = bytes([raw[0] ^ 1]) + raw[1:]
    packed = gzip.compress(damaged, mtime=0)
    replacement = changed(receipt, lambda value: value.update(input=dict(bytes=len(damaged), sha256=sha(damaged),
        compressed_bytes=len(packed), compressed_sha256=sha(packed))))
    rejected("rehash-changed-original-input", {requests: packed, receipt: replacement}, fixture)
    output32 = native / "binary32/native.stdout.jsonl.gz"
    raw = gzip.decompress(regular(output32)); damaged = b"1" + raw[1:]
    rejected("rehash-changed-native-output", {output32: gzip.compress(damaged, mtime=0),
        result32: changed(result32, lambda value: value.update(output_sha256=sha(damaged), output_bytes=len(damaged)))}, full)
    rejected("typed-case-count", {typed: changed(typed, lambda value: value.update(compared_cases=5248))}, full)
    rejected("last-metadata-result", {request: changed(request,
        lambda value: value["cases"][-1].update(output_sha256="0" * 64))}, full)
    rejected("typed-child-not-executed", {request: changed(request,
        lambda value: value.update(actual_typed_child_calls=0))}, full)
    output = native / "typed/native-results.bin.gz"
    rejected("typed-output-truncated", {output: regular(output)[:-8]}, full)
    rejected("retained-input-is-not-fresh-rust", {result32: changed(result32,
        lambda value: value.update(actual_original_cases=541693))}, full)
    path = root / "tests/hia_native/result_value_fixtures/manifest.json"
    rejected("fixture-manifest", {path: changed(path,
        lambda value: value["domains"]["request"]["cases"].update(cases=1))}, build)
    rejected("removed-native-control", {typed: changed(typed, lambda value: value["controls"].pop())}, full)
    require(len(rows) == 16 and q.inspect_native_outputs(root, bundle_path, native) == baseline
        and source_pins(root) == sources, "complete native evidence did not recover")
    result = dict(schema="hepta.result-values.native-evidence-controls.v1", status="PASS",
        rejections=len(rows), restorations=len(rows) + 1, full_native_admissions=2, controls=rows,
        native_executions_added_by_evidence_admission=0, sources_unchanged=True,
        elapsed_seconds=time.monotonic() - begin)
    args.output.write_bytes(encoded(result))
    print(json.dumps(result))


if __name__ == "__main__":
    main()
