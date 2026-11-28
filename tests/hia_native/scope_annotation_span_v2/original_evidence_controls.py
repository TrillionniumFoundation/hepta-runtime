"""Independent retained-original admission controls. Never execute a binary."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time

sys.dont_write_bytecode = True
NAMES = ("target-identity", "build-executed-inflation", "compiled-source", "fixture-lock",
    "executed-binary", "registry-archive", "output-byte", "process-omitted",
    "replay-deadline", "replay-command", "compiler-flags", "registry-set")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.runtime.resolve(strict=True)
    capture = args.capture.resolve(strict=True)
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(root))
    import original_reader as q
    report = dict(schema="hepta.scope-annotation.original-reader-controls.v1", status="IN_PROGRESS",
        controls=[], relocations=[], native_processes_executed=0, original_processes_executed=0,
        execution=dict(pid=os.getpid(), parent_pid=os.getppid(), cwd=str(Path.cwd().resolve())))
    save = lambda: (output/"result.json").write_bytes(q.encoded(report))
    started = time.monotonic(); save()

    def reader(folder):
        return q.original_evidence(folder/"original", folder/"native", source_root=root)

    baseline = reader(capture)
    files = {"native/observed.bin.gz", "original/build.json", "original/lock-subset.json",
        "original/reference-environment.json", "original/reference-project/main.rs",
        "original/reference-project/Cargo.toml", "original/reference-project/Cargo.lock",
        "original/scope-annotation-original", "original/processes/processes.json"}
    files.update("original/"+name for name in baseline["registry_artifact_sha256"])
    processes = q.parse(q.read(capture/"original/processes/processes.json"))
    for process in processes:
        for field in ("stdin", "stdout", "stderr"):
            if process[field] is not None:
                files.add("original/processes/"+process[field]["file"])
    identities = {name: q.file_pin(capture/name) for name in sorted(files)}

    def copy(destination):
        destination.mkdir(parents=True, exist_ok=False)
        for name in sorted(files):
            path = destination/name
            path.parent.mkdir(parents=True, exist_ok=True)
            with q.opened(capture/name) as source, path.open("xb") as target:
                shutil.copyfileobj(source, target, 1 << 20)
            q.require(q.file_pin(path) == identities[name], "physical original copy differs")

    one, two = output/"copies/one", output/"copies/two"
    copy(one); copy(two)
    try:
        for folder in (one, two):
            q.require(reader(folder) == baseline, "relocated original evidence differs")
            report["relocations"].append(dict(name=folder.name, status="PASS", files=len(files),
                same_complete_source_and_artifact_identity=True, processes_executed=0))
        save()

        def edit(raw, fn):
            value = q.parse(raw); fn(value); return q.encoded(value)

        def refuse(name, changes):
            saved = {path: q.read(one/path, 256 << 20) for path in changes}
            try:
                for path, change in changes.items():
                    (one/path).write_bytes(change(saved[path]))
                try:
                    reader(one)
                except (ValueError, AssertionError, KeyError, EOFError, OSError, UnicodeDecodeError) as error:
                    report["controls"].append(dict(name=name, status="REFUSED", error_type=type(error).__name__,
                        reason=str(error)[:240])); save()
                else:
                    raise AssertionError("original reader accepted mutation: "+name)
            finally:
                for path, raw in saved.items():
                    (one/path).write_bytes(raw)

        build = "original/build.json"
        refuse("target-identity", {build: lambda b: edit(b, lambda v: v.update(target_commit="0"*40))})
        refuse("build-executed-inflation", {build: lambda b: edit(b, lambda v: v.update(actual_target_sdk_executed=True))})
        refuse("compiled-source", {"original/reference-project/main.rs": lambda b: b+b"\n"})
        refuse("fixture-lock", {"original/reference-project/Cargo.lock": lambda b: b+b"\n"})
        flip = lambda b: bytes([b[0]^1])+b[1:]
        refuse("executed-binary", {"original/scope-annotation-original": flip})
        archive = "original/"+sorted(baseline["registry_artifact_sha256"])[0]
        refuse("registry-archive", {archive: flip})
        refuse("output-byte", {"original/processes/original-replay.stdout": flip})
        process = "original/processes/processes.json"
        refuse("process-omitted", {process: lambda b: edit(b, lambda v: v.pop())})
        refuse("replay-deadline", {process: lambda b: edit(b, lambda v: v[-1].update(timeout_seconds=181))})
        refuse("replay-command", {process: lambda b: edit(b, lambda v: v[-1]["argv"].append("--unbound"))})
        def flags(value):
            value["explicit_reference_environment"]["CARGO_ENCODED_RUSTFLAGS"] = "--cfg=unbound"
            value["cargo_encoded_rustflags_override"] = "--cfg=unbound"
        refuse("compiler-flags", {
            "original/reference-environment.json": lambda b: edit(b, flags),
            build: lambda b: edit(b, lambda v: flags(v["environment"]))})
        refuse("registry-set", {"original/lock-subset.json": lambda b: edit(b,
            lambda v: v["registry_source_verification"].pop())})
        q.require(tuple(row["name"] for row in report["controls"]) == NAMES, "original reader controls incomplete")
        q.require(all(q.file_pin(one/name) == identities[name] and q.file_pin(two/name) == identities[name]
                      for name in files), "original evidence copies were not restored")
        q.require(reader(one) == baseline, "post-refusal original evidence differs")
        report.update(status="ORIGINAL_READER_CONTROLS_PASS", admitted_files=identities)
    finally:
        report["elapsed_seconds"] = time.monotonic()-started; save()
    shutil.rmtree(one); shutil.rmtree(two)
    print(json.dumps(dict(status=report["status"], controls=len(NAMES), relocations=2,
        native_processes_executed=0, original_processes_executed=0, elapsed_seconds=report["elapsed_seconds"]), sort_keys=True))


if __name__ == "__main__":
    main()
