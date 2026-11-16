#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Direct bridge regression: ordinary error replies, real allocation and cleanup.

The metadata child and metadata cache slot are explicit unit fixtures. This does
not qualify ResultIntent, HIA packing, the SDK, or the complete public lifecycle.
No syscall interception, fault injection, or remote host operation is used.
"""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from public_lifecycle_registry import graph
import argparse, hashlib, json, re, shutil, subprocess, traceback

FIXED = "a5bd9c31a51fdd773dc27dad8d5142adf3a13a7b7c50874eb5ccbebe07f08de0"
H = lambda b: hashlib.sha256(b).hexdigest()
ENC = lambda v: (json.dumps(v, sort_keys=True, indent=2) + "\n").encode()

def block(text, begin, end):
    matches = list(re.finditer(r"(?m)^" + re.escape(begin), text))
    assert len(matches) == 1, begin
    start = matches[0].start()
    stop = re.search(r"(?m)^" + re.escape(end), text[matches[0].end():])
    assert stop is not None, end
    return text[start:matches[0].end() + stop.start()]

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    out = a.output.absolute()
    out.mkdir(parents=True, exist_ok=False)
    profile = graph(ROOT)
    a.fixed_bridge = ROOT / profile["metadata_source"]
    a.frozen_adapter = ROOT / profile["adapter_source"]
    template_path = Path(__file__).with_name("public_lifecycle") / "metadata_unit.S.in"
    inputs = {str(x.resolve()): x.read_bytes() for x in
              (a.fixed_bridge, a.frozen_adapter, template_path, Path(__file__), ROOT / "native/public_lifecycle_graph.json")}
    fixed, adapter = (inputs[str(x.resolve())] for x in (a.fixed_bridge, a.frozen_adapter))
    report = dict(schema="hepta.eligible.metadata-immediate-unit.v1", status="RUNNING",
                  inputs={p: dict(bytes=len(b), sha256=H(b)) for p, b in inputs.items()},
                  processes=[], syscall_interception=False, fault_injection=False,
                  new_original_rust_processes=0, actual_result_intent_calls=0,
                  public_lifecycle_qualified=False, production_activated=False,
                  whole_runtime_replaced=False)
    def save():
        (out / "result.json").write_bytes(ENC(report))
    def run(label, argv):
        r = subprocess.run(argv, cwd=out, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=30)
        (out / (label + ".stdout")).write_bytes(r.stdout)
        (out / (label + ".stderr")).write_bytes(r.stderr)
        report["processes"].append(dict(
            name=label, argv=argv, cwd=str(out), exit_code=r.returncode,
            timeout_seconds=30, executable_sha256=H(Path(argv[0]).read_bytes()),
            stdout=dict(bytes=len(r.stdout), sha256=H(r.stdout)),
            stderr=dict(bytes=len(r.stderr), sha256=H(r.stderr))))
        save()
        assert r.returncode == 0, (label, r.returncode, r.stderr)
        return r.stdout
    save()
    try:
        assert H(fixed) == FIXED and H(adapter) == profile["adapter_source_sha256"]
        before = b"    mov edi, tk_CV_BYTES\n"
        after = b"    mov edi, OFFSET FLAT:tk_CV_BYTES\n"
        assert fixed.count(after) == 1 and before not in fixed
        source, original = fixed.decode(), adapter.decode()
        metadata = source[source.index("ex_metadata_call:\n"):]
        config_drop = block(source, "ex_intent_config_drop:\n", "# Called after the fixed Ticket")
        allocation = block(original, "tk_allocate_guarded:\n", "tk_read_exact:\n")
        allocation = re.sub(r"\ballocate_guarded\b", "tk_allocate_guarded", allocation)
        allocation = re.sub(r"\btk_memory_fail\b", "fatal", allocation)
        conversion = block(original, "tk_intent_conversion_drop:\n", "# The metadata annotator")
        assert original.count(".equ tk_CV_BYTES, 817889280") == 1
        text = inputs[str(template_path.resolve())].decode()
        for name, body in dict(METADATA_CALL=metadata, CONFIG_DROP=config_drop,
                               ALLOCATION=allocation, CONVERSION_DROP=conversion).items():
            marker = "@" + name + "@"
            assert text.count(marker) == 1, marker
            text = text.replace(marker, body)
        (out / "unit.S").write_text(text)
        assembler, linker, objcopy = (shutil.which(x) for x in ("as", "ld", "objcopy"))
        assert assembler and linker and objcopy, "assembler tools unavailable"
        probe = ".intel_syntax noprefix\n.text\n" + after.decode()
        probe += "ret\n.equ tk_CV_BYTES, 817889280\n"
        (out / "fixed.S").write_text(probe)
        run("encoding-as", [assembler, "--64", str(out / "fixed.S"), "-o", str(out / "fixed.o")])
        run("encoding-flat", [objcopy, "-O", "binary", "--only-section=.text",
                              str(out / "fixed.o"), str(out / "fixed.bin")])
        assert (out / "fixed.bin").read_bytes().hex() == "bf0000c030c3"
        run("unit-as", [assembler, "--64", str(out / "unit.S"), "-o", str(out / "unit.o")])
        run("unit-link", [linker, "--build-id=none", "-m", "elf_x86_64",
                          "-o", str(out / "unit.elf"), str(out / "unit.o")])
        assert run("unit-execute", [str(out / "unit.elf")]) == b"METADATA_BRIDGE_UNIT_PASS\n"
        for path, raw in inputs.items():
            assert Path(path).read_bytes() == raw, path
        report.update(status="PASS_DIRECT_BRIDGE_UNIT_ONLY", direct_bridge_calls=3,
                      direct_child_error_replies=1, subsequent_direct_success_replies=2,
                      real_guarded_allocations=2, real_conversion_drop_calls=3,
                      retired_allocation_queries=2,
                      metadata_child="explicit synthetic direct-return fixture",
                      full_public_regression="separate normal and original suites")
    except BaseException as error:
        report.update(status="FAIL", error=repr(error), traceback=traceback.format_exc())
        save()
        raise
    save()
    print(json.dumps({key: report[key] for key in (
        "status", "direct_bridge_calls", "real_guarded_allocations",
        "actual_result_intent_calls", "full_public_regression")}, sort_keys=True))

if __name__ == "__main__":
    main()
