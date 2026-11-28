"""Pure source-only preflight; never runs HIA, Rust, a compiler, or a subprocess."""
from pathlib import Path
import argparse
import ast
import hashlib
import sys
ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
from common import encoded, loads, pin, read, require, source
from transport_cases import SPECS, sequence
from protocol import cases


def run():
    identity = source()
    manifest = loads(read(ROOT / "SOURCE.json"))
    count = 0
    for name in manifest["files"]:
        if name.endswith(".py"):
            compile(read(ROOT / name), str(ROOT / name), "exec")
            count += 1
    reuse = loads(read(ROOT / "SOURCE_REUSE.json"))
    require(reuse["source_commit"] == "c4a4857148765d214ad3760dde9e127ebcabfada" and
            reuse["handoff_commit"] == "581b8e4d31dc9a7bb2e63ca8f8e2b79eea04989b",
            "exact complete reused qualification source")
    for name, expected in reuse["files"].items():
        raw = read(ROOT / name)
        require(pin(raw) == {key: expected[key] for key in ("bytes", "sha256")} and
                hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == expected["git_blob"],
                "whole unchanged reused source: " + name)
    composition = loads(read(ROOT / "native/audit_record_callable.composition.json"))
    require(pin(read(ROOT / "authoring/audit_record_callable.S")) == composition["adapter_source"] and
            pin(read(ROOT / "native/audit_record_callable.hepta")) == composition["packer_source"],
            "exact source-author CI output and current adapter")
    domain = cases(ROOT)
    require(len(domain) == 219 and sum(len(row["steps"]) for row in domain) == 459 and
            len(SPECS) == 45 and sum(len(sequence(spec)) for spec in SPECS) == 180,
            "full immutable filesystem and additive native-transport domains")
    before = read(ROOT / "read_original.py").decode()
    original = before[before.index("def original_trace("):before.index("\ndef verify(")]
    after = read(ROOT / "native_trace.py").decode()
    native = after[after.index("def native_trace("):]
    reconstructed = native.replace("def native_trace(", "def original_trace(", 1).replace(
        "AUDIT_PUMP_BEGIN", "AUDIT_ORIGINAL_BEGIN").replace("AUDIT_PUMP_END", "AUDIT_ORIGINAL_END")
    require(original == reconstructed, "complete exact original trace parser with only native marker spelling")
    provenance = loads(read(ROOT / "NATIVE_TRACE_PROVENANCE.json"))
    require(pin(original.encode()) == {k: provenance["original_function"][k] for k in ("bytes", "sha256")} and
            pin(native.encode()) == {k: provenance["native_function"][k] for k in ("bytes", "sha256")},
            "complete original/native parser provenance")
    # The private C callback only observes. It does not import an effect dispatcher.
    node = ast.parse(read(ROOT / "observe_callable.py"))
    imports = {alias.name for value in ast.walk(node) if isinstance(value, ast.Import) for alias in value.names}
    imports |= {value.module for value in ast.walk(node) if isinstance(value, ast.ImportFrom)}
    require("effects" not in imports and "native_process" not in imports, "no semantic Python effect dispatcher")
    result = dict(status="SOURCE_PREFLIGHT_PASS", source_manifest_sha256=identity,
                  python_files=count, cases=219, operations=459, transport_refusals=45,
                  native_or_rust_executions=0)
    print(encoded(result).decode(), end="")


if __name__ == "__main__":
    run()
