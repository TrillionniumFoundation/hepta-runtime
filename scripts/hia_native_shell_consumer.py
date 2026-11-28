"""Rebuild the two host-linked shell members on their actual consumer.

The cold prepared build remains immutable. This separately sealed closure
recompiles the same HIA bytes with the same admitted B3, requires identical
objects/images/bundle, and links against the consumer's exact libc and loader.
It confers no semantic qualification: all original shell suites still execute.

Collection reads retained bytes only. Live allocator/loader admission remains
mandatory at every actual outcome/foreground execution boundary.
"""
from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat

import hia_native_build as nb
import hia_native_shell_foreground_build as foreground
import hia_native_shell_outcome_build as outcome

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = "consumer-shell-build"
MANIFEST = DIRECTORY + "/consumer.json"
SCHEMA = "hepta.runtime.shell-consumer-build.v1"
MEMBERS = {
    "shell_outcome": ("shell-outcome", "native/shell_outcome.hepta"),
    "shell_foreground": ("shell-foreground", "native/shell_foreground_controller.hepta"),
}
SOURCES = (
    "scripts/hia_native_shell_consumer.py", "scripts/hia_native_pipeline.py",
    "scripts/qualify_hia_runtime_native.py",
    "scripts/hia_native_shell_outcome_build.py",
    "scripts/hia_native_shell_foreground_build.py",
    "tests/hia_native/shell_foreground_io.py",
)
SCOPE = {
    "whole_runtime_replaced": False, "production_activated": False,
    "production_shell_execution_qualified": False,
    "old_stack_removal_qualified": False,
    "matching_source_full_cold_qualified_by_consumer": False,
    "semantic_qualification_granted_by_consumer_build": False,
}


def need(value, message):
    if not value:
        raise ValueError(message)


def relative(name):
    need(type(name) is str and name and "\\" not in name and "\0" not in name
         and not PurePosixPath(name).is_absolute()
         and all(p not in ("", ".", "..") for p in name.split("/")),
         "consumer artifact path is not owned and relative")
    return Path(name)


def owned(root, name):
    path = Path(root) / relative(name)
    need(path.resolve(strict=True) == path.absolute()
         and stat.S_ISREG(path.lstat().st_mode) and path.stat().st_uid == os.getuid(),
         "consumer artifact is not an owned ordinary file")
    return path


def pin(path):
    path = Path(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and path.resolve(strict=True) == path.absolute()
         and before.st_uid == os.getuid(), "consumer evidence file is not owned and ordinary")
    raw = path.read_bytes()
    after = path.stat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(identity(before) == identity(after), "consumer evidence changed while reading")
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
            "mode": stat.S_IMODE(before.st_mode)}


def read_json(path):
    return foreground.strict_json(owned(Path(path).parent, Path(path).name).read_bytes())


def files(root, exclude=()):
    root = Path(root)
    need(root.resolve(strict=True) == root.absolute() and not root.is_symlink(),
         "consumer inventory root is not an owned directory")
    result = {}
    for base, dirs, names in os.walk(root, followlinks=False):
        for name in dirs:
            p = Path(base) / name
            need(stat.S_ISDIR(p.lstat().st_mode) and p.stat().st_uid == os.getuid()
                 and p.resolve(strict=True) == p.absolute(), "consumer inventory directory differs")
        for name in sorted(names):
            p = Path(base) / name
            n = p.relative_to(root).as_posix()
            if n not in exclude:
                result[n] = pin(p)
    return dict(sorted(result.items()))


def source_pins(root, prepared):
    pins = {name: pin(owned(root, name))["sha256"] for name in SOURCES}
    need(all(prepared["source_sha256"].get(name) == sha for name, sha in pins.items()),
         "consumer source is not bound by the prepared source closure")
    return pins


def original_modules(output, prepared):
    selected = {}
    for key, (name, source) in MEMBERS.items():
        row = prepared["modules"][key]
        need(set(row) == {"manifest", "sha256", "source", "builder"}
             and row["manifest"] == "build/" + name + "/manifest.json"
             and row["source"] == source and row["builder"] == key,
             "consumer may rebuild only the two exact prepared host-linked members")
        need(pin(owned(output, row["manifest"]))["sha256"] == row["sha256"],
             "original prepared shell manifest differs")
        selected[key] = copy.deepcopy(row)
    return selected


def bound_modules(data, original):
    result = {}
    for key, (name, _) in MEMBERS.items():
        row = copy.deepcopy(original[key])
        row["manifest"] = DIRECTORY + "/" + name + "/manifest.json"
        row["sha256"] = pin(owned(data, row["manifest"]))["sha256"]
        result[key] = row
    return result


def unchanged_images(output, data, prepared, original, current):
    old = {key: read_json(owned(output, row["manifest"])) for key, row in original.items()}
    new = {key: read_json(owned(data, row["manifest"])) for key, row in current.items()}
    compiler = prepared["compiler_image_sha256"]
    need(all(v.get("compiler_sha256") == compiler for v in (*old.values(), *new.values())),
         "consumer compiler differs from the prepared compiler")
    result = {}

    def same(label, before, after):
        a, b = before.read_bytes(), after.read_bytes()
        need(a == b, "consumer changed prepared HIA or mechanical bytes: " + label)
        result[label] = {"bytes": len(a), "sha256": hashlib.sha256(a).hexdigest()}

    for label in ("B1", "B2", "B3"):
        a = owned(output, "build/bootstrap/" + label + ".image.bin")
        b = owned(data, DIRECTORY + "/bootstrap/" + label + ".image.bin")
        same("compiler." + label, a, b)
        need(result["compiler." + label]["sha256"] == compiler, "consumer bootstrap generation differs")
    oa = Path(original["shell_outcome"]["manifest"]).parent
    ob = Path(current["shell_outcome"]["manifest"]).parent
    same("outcome.object", owned(output, (oa / relative(old["shell_outcome"]["object"])).as_posix()),
         owned(data, (ob / relative(new["shell_outcome"]["object"])).as_posix()))
    fa = Path(original["shell_foreground"]["manifest"]).parent
    fb = Path(current["shell_foreground"]["manifest"]).parent
    for name in ("bundle.o", "adapter.o", "adapter.text.bin", "outcome.o"):
        same("foreground." + name, owned(output, (fa / name).as_posix()),
             owned(data, (fb / name).as_posix()))
    for name in ("controller", "packer"):
        a = owned(output, (fa.parent / relative(old["shell_foreground"][name + "_manifest"])).as_posix())
        b = owned(data, (fb.parent / relative(new["shell_foreground"][name + "_manifest"])).as_posix())
        am, bm = read_json(a), read_json(b)
        need(am == bm and am.get("compiler_sha256") == compiler,
             "consumer changed generated HIA metadata: " + name)
        same("foreground." + name, owned(a.parent, am["image"]), owned(b.parent, bm["image"]))
    for label, key in (("process", "shell_process"), ("output", "shell_output_io")):
        row = prepared["modules"][key]
        path = owned(output, row["manifest"])
        need(pin(path)["sha256"] == row["sha256"], "prepared static shell component differs")
        for metadata in (old["shell_foreground"], new["shell_foreground"]):
            need(metadata[label + "_manifest"] == str(path)
                 and metadata[label + "_manifest_sha256"] == row["sha256"],
                 "consumer substituted a static process/output owner")
    for metadata, row in ((old["shell_foreground"], original["shell_outcome"]),
                          (new["shell_foreground"], current["shell_outcome"])):
        need(metadata["outcome_manifest"] == str(Path(output) / row["manifest"])
             and metadata["outcome_manifest_sha256"] == row["sha256"],
             "consumer foreground is not bound to its exact outcome owner")
    host = {}
    for phase, metadata in (("prepared", old), ("consumer", new)):
        om, fm = metadata["shell_outcome"], metadata["shell_foreground"]
        host[phase] = {"allocator": om["allocator"], "interpreter": fm["interpreter"],
                       "outcome_linker": om["linker"]}
    return result, host


def read(output, prepared, binding, expected, *, source_root=ROOT, data_root=None, full=False):
    """Read a declaration before transport, then full owners at their exact origin."""
    output, root = Path(output).absolute(), Path(source_root).absolute()
    data = output if data_root is None else Path(data_root).absolute()
    need(type(expected) is str and re.fullmatch("[0-9a-f]{64}", expected),
         "consumer prepared seal identity is malformed")
    need(type(binding) is dict and set(binding) == {"manifest", "sha256"}
         and binding["manifest"] == MANIFEST, "consumer manifest path or binding differs")
    path = owned(data, MANIFEST)
    need(pin(path)["sha256"] == binding["sha256"], "consumer manifest bytes differ")
    receipt = read_json(path)
    need(owned(output, "prepared-report.json").read_bytes() == nb.json_bytes(prepared),
         "consumer input report is not the immutable prepared snapshot")
    fields = {"schema", "status", "recorded_output", "prepared_sha256",
              "prepared_report_sha256", "compiler_image_sha256", "compiler_bootstrap_sha256",
              "sources", "prepared_modules", "consumer_modules", "bootstrap_files",
              "unchanged_images", "host_dependencies", "files", *SCOPE}
    need(set(receipt) == fields and receipt["schema"] == SCHEMA
         and receipt["status"] == "CONSUMER_BUILD_READY"
         and receipt["recorded_output"] == str(output)
         and receipt["prepared_sha256"] == expected
         and pin(owned(output, "native-build.json"))["sha256"] == expected
         and receipt["prepared_report_sha256"] == pin(owned(output, "prepared-report.json"))["sha256"]
         and all(receipt[name] is value for name, value in SCOPE.items()),
         "consumer build identity, origin, prepared seal or scope differs")
    need(receipt["sources"] == source_pins(root, prepared), "consumer exact source pins differ")
    original = original_modules(output, prepared)
    current = bound_modules(data, original)
    need(receipt["prepared_modules"] == original and receipt["consumer_modules"] == current,
         "consumer changed its exact module substitution")
    boot = files(output / "build/bootstrap")
    need(receipt["bootstrap_files"] == boot == files(data / DIRECTORY / "bootstrap")
         and receipt["compiler_bootstrap_sha256"] == prepared["compiler_bootstrap_sha256"]
         == pin(owned(output, "build/bootstrap/bootstrap.json"))["sha256"]
         and receipt["compiler_image_sha256"] == prepared["compiler_image_sha256"],
         "consumer changed the admitted compiler bootstrap")
    need(receipt["files"] == files(data / DIRECTORY, {"consumer.json"}),
         "consumer build omitted or changed a retained file")
    images, host = unchanged_images(output, data, prepared, original, current)
    need(receipt["unchanged_images"] == images and receipt["host_dependencies"] == host,
         "consumer object/image or exact host dependency binding differs")
    reviews = None
    if full:
        need(data == output, "complete consumer readers require the exact recorded output")
        reviews = {}
        for phase, rows in (("prepared", original), ("consumer", current)):
            reviews[phase] = {
                "outcome": outcome.read_evidence(output / rows["shell_outcome"]["manifest"], source_root=root),
                "foreground": foreground.read_evidence(output / rows["shell_foreground"]["manifest"], source_root=root),
            }
    return {"schema": SCHEMA + ".read", "status": "PASS", "modules": current,
            "unchanged_images": images, "host_dependencies": host, "complete_builds": reviews,
            "manifest_sha256": binding["sha256"], **SCOPE}


def admit_report(output, prepared, report, expected, *, source_root=ROOT, data_root=None, full=False):
    proof = read(output, prepared, report["shell_consumer_build"], expected,
                 source_root=source_root, data_root=data_root, full=full)
    modules = copy.deepcopy(report["modules"])
    need(set(modules) == set(prepared["modules"]), "consumer changed the complete module registry")
    for key, row in proof["modules"].items():
        need(modules[key] == row, "shell report did not select the qualified consumer member")
        modules[key] = prepared["modules"][key]
    need(modules == prepared["modules"], "consumer substituted another prepared module")
    return proof


def build(output, hepta, prepared, expected, *, source_root=ROOT):
    output, root = Path(output).absolute(), Path(source_root).absolute()
    need(type(expected) is str and re.fullmatch("[0-9a-f]{64}", expected)
         and pin(owned(output, "native-build.json"))["sha256"] == expected
         and owned(output, "prepared-report.json").read_bytes() == nb.json_bytes(prepared),
         "consumer requires the unchanged admitted prepared seal and report")
    original = original_modules(output, prepared)
    before = source_pins(root, prepared)
    for key, reader in (("shell_outcome", outcome.read_evidence),
                        ("shell_foreground", foreground.read_evidence)):
        reader(output / original[key]["manifest"], source_root=root)
    folder = output / DIRECTORY
    folder.mkdir(mode=0o700, exist_ok=False)
    bootstrap = files(output / "build/bootstrap")
    shutil.copytree(output / "build/bootstrap", folder / "bootstrap")
    need(files(folder / "bootstrap") == bootstrap, "consumer bootstrap transport differs")
    compiler = nb.NativeBuild(hepta, folder)
    need(pin(compiler.bootstrap())["sha256"] == prepared["compiler_image_sha256"],
         "consumer is not using the admitted B3")
    new_outcome = outcome.build_shell_outcome(hepta, folder, source_root=root)
    foreground.build_shell_foreground(hepta, folder, source_root=root,
        process_manifest=output / prepared["modules"]["shell_process"]["manifest"],
        output_manifest=output / prepared["modules"]["shell_output_io"]["manifest"],
        outcome_manifest=new_outcome)
    compiler._recheck()
    need(source_pins(root, prepared) == before, "consumer source changed while building")
    current = bound_modules(output, original)
    images, host = unchanged_images(output, output, prepared, original, current)
    receipt = {"schema": SCHEMA, "status": "CONSUMER_BUILD_READY", "recorded_output": str(output),
        "prepared_sha256": expected,
        "prepared_report_sha256": pin(owned(output, "prepared-report.json"))["sha256"],
        "compiler_image_sha256": prepared["compiler_image_sha256"],
        "compiler_bootstrap_sha256": prepared["compiler_bootstrap_sha256"],
        "sources": before, "prepared_modules": original, "consumer_modules": current,
        "bootstrap_files": bootstrap, "unchanged_images": images, "host_dependencies": host,
        "files": files(folder), **SCOPE}
    nb.write_new(output / MANIFEST, nb.json_bytes(receipt))
    binding = {"manifest": MANIFEST, "sha256": pin(output / MANIFEST)["sha256"]}
    read(output, prepared, binding, expected, source_root=root, full=True)
    return binding
