"""Complete main qualification with the execution and previous read roots absent."""
from pathlib import Path
import argparse
import json
import os
import shutil
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))
import hia_native_batch_public_pipeline as p


def identity(path):
    value = path.lstat()
    p.need(stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode)
           and value.st_uid == os.getuid(), "owned actual directory required")
    return {"device": value.st_dev, "inode": value.st_ino, "mode": value.st_mode,
            "uid": value.st_uid, "gid": value.st_gid}


def absent(paths):
    for path in paths:
        p.need(not os.path.lexists(path), "execution or earlier read root is present: " + str(path))


def copied_inventory(source, output, base):
    table = {}
    for name, digest in base["source_sha256"].items():
        value = p.pin(source / name)
        p.exact(value["sha256"], digest, "complete independently copied source")
        table["source/" + name] = value
    for row in base["artifacts"]:
        name = row["path"]
        value = p.pin(output / name)
        p.exact(value, {key: row[key] for key in ("bytes", "sha256")}, "complete independently copied artifact")
        table["output/" + name] = value
    return table


def read_child(args):
    output = args.output.absolute()
    report, baseline = p.object_at(args.reference), p.object_at(args.baseline)
    _, old_root, old_output, _ = p.roots(ROOT, output)
    expected = [str(old_root), str(old_output)]
    if args.index == 2:
        expected.append(str(args.reference.parent / "read-1"))
    p.exact([str(path) for path in args.absent], expected, "exact independent absent roots")
    p.need(ROOT != old_root and output != old_output, "readback cannot reuse either execution root")
    before = copied_inventory(ROOT, output, baseline)
    absent(args.absent)
    active = True

    def audit(event, values):
        if not active:
            return
        if (event.startswith("subprocess.") or event.startswith("os.exec")
                or event.startswith("os.spawn") or event in ("os.system", "ctypes.dlopen", "ctypes.dlsym", "mmap.__new__")):
            raise RuntimeError("readback attempted executable activity: " + event)
        if event == "open":
            target, mode, flags = values
            if isinstance(target, (str, bytes)):
                path = Path(os.fsdecode(target)).absolute()
                p.need(not any(path == old or old in path.parents for old in args.absent),
                       "readback attempted an absent execution origin")
            p.need(not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND),
                   "retained qualification attempted a filesystem write")

    sys.addaudithook(audit)
    started = time.monotonic_ns()
    value = p.retained_base(ROOT, output, report)
    p.exact(value, baseline, "whole main qualification with absent execution roots")
    p.exact(copied_inventory(ROOT, output, baseline), before, "all copied inputs unchanged during pure read")
    absent(args.absent)
    finished = time.monotonic_ns()
    active = False
    p.write_new(args.result, value)
    summary = {"schema": "hepta.runtime.batch-public-main-absent-read.v1", "status": "PASS",
               "index": args.index, "pid": os.getpid(), "command": sys.argv, "cwd": os.getcwd(),
               "started_monotonic_ns": started, "finished_monotonic_ns": finished,
               "complete_evidence": p.pin(args.result), "copy_inventory_sha256": p.sha(p.canonical(before)),
               "actual_absent_paths": expected, "entire_object_equal": True,
               "native_execution_forbidden": True, "filesystem_writes_forbidden": True,
               "new_native_calls": 0, "new_original_processes": 0}
    p.write_new(args.result.with_name("READ.json"), summary)
    print(json.dumps(summary, sort_keys=True))


def main_parent(args):
    source, output = ROOT, args.output.absolute()
    prepared, old_root, old_output, _ = p.roots(source, output)
    p.exact([str(source), str(output)], [str(old_root), str(old_output)], "actual main readback parent roots")
    p.need(source != output and source not in output.parents and output not in source.parents,
           "actual source and output roots must be disjoint")
    reference = p.object_at(args.reference)
    baseline = p.retained_base(source, output, reference)
    p.exact(baseline, p.object_at(args.baseline), "complete base before physical root absence")
    workspace = output.with_name(output.name + "-batch-public-readbacks")
    p.need(workspace != source and source not in workspace.parents and workspace not in source.parents,
           "readback workspace must be outside the source tree")
    workspace.mkdir(mode=0o700, exist_ok=False)
    p.write_new(workspace / "REFERENCE.json", reference)
    p.write_new(workspace / "BASELINE.json", baseline)
    inventory = copied_inventory(source, output, baseline)
    p.write_new(workspace / "COPY-PINS.json", inventory)
    def copy_inputs(index, source_origin, output_origin):
        directory = workspace / ("read-" + str(index))
        directory.mkdir(exist_ok=False)
        for name, expected in inventory.items():
            relative = Path(name)
            origin = (source_origin if relative.parts[0] == "source" else output_origin).joinpath(*relative.parts[1:])
            target = directory / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(origin, target)
            p.exact(p.pin(target), expected, "complete physical readback copy")
    copy_inputs(1, source, output)
    moved = []
    original_identities = {str(path): identity(path) for path in (source, output)}
    p.write_new(workspace / "ROOTS-BEFORE.json", original_identities)
    read_processes, retired = [], []
    try:
        for path in (source, output):
            held = path.with_name(path.name + "-held-by-batch-public-readback")
            p.need(not os.path.lexists(held), "exclusive root hold is required")
            path.rename(held)
            p.exact(identity(held), original_identities[str(path)], "same root inode while absent")
            moved.append((path, held))
        absent((source, output))
        for index in (1, 2):
            directory = workspace / ("read-" + str(index))
            missing = [source, output]
            if index == 2:
                first = workspace / "read-1"
                absent((first,))
                held = dict(moved)
                copy_inputs(index, held[source], held[output])
                missing.append(first)
            absent(missing)
            command = [prepared["python"], "-I", "-B", str(directory / "source" / p.READBACK_DRIVER),
                       "--read", "--index", str(index), "--output", str(directory / "output"),
                       "--reference", str(workspace / "REFERENCE.json"), "--baseline", str(workspace / "BASELINE.json"),
                       "--result", str(workspace / ("result-" + str(index)) / "EVIDENCE.json")]
            for path in missing:
                command.extend(["--absent", str(path)])
            process = p.process(command, directory / "source", workspace / ("process-" + str(index)))
            result = p.object_at(workspace / ("result-" + str(index)) / "READ.json")
            p.exact(p.object_at(workspace / ("result-" + str(index)) / "EVIDENCE.json"), baseline,
                    "complete physical absent-root result")
            p.exact(p.object_at(workspace / ("process-" + str(index)) / "stdout.bin"), result,
                    "whole actual readback stdout")
            absent(missing)
            read_processes.append({"process": process, "result": result})
            p.exact(copied_inventory(directory / "source", directory / "output", baseline), inventory,
                    "complete derived readback bytes before retirement")
            shutil.rmtree(directory)
            absent((directory,))
            retired.append(str(directory))
    finally:
        for path, held in reversed(moved):
            p.need(not os.path.lexists(path), "original root was unexpectedly recreated")
            held.rename(path)
            p.exact(identity(path), original_identities[str(path)], "same original inode restored")
    after = {str(path): identity(path) for path in (source, output)}
    p.exact(after, original_identities, "all original root identities after both reads")
    p.exact(copied_inventory(source, output, baseline), inventory, "all original bytes unchanged after both reads")
    p.exact(retired, [str(workspace / ("read-" + str(index))) for index in (1, 2)],
            "each independently verified copy retired before its successor")
    result = {"schema": "hepta.runtime.batch-public-main-readbacks.v1", "status": "PASS",
              "workspace": str(workspace), "execution_source_root": str(source),
              "execution_output_root": str(output), "reference": p.pin(workspace / "REFERENCE.json"),
              "baseline": p.pin(workspace / "BASELINE.json"), "copy_pins": p.pin(workspace / "COPY-PINS.json"),
              "root_identities_before": original_identities, "root_identities_after": after,
              "read_processes": read_processes, "retired_copy_roots": retired,
              "actual_absent_root_reads": 2, "new_native_calls": 0, "new_original_processes": 0}
    p.write_new(workspace / "RESULT.json", result)
    destination = output / p.FOLDER / "readbacks"
    p.need(not destination.exists(), "retained readback destination exists")
    workspace.rename(destination)
    summary = {"schema": result["schema"], "status": "PASS", "actual_absent_root_reads": 2,
               "complete_evidence": p.pin(destination / "RESULT.json"),
               "new_native_calls": 0, "new_original_processes": 0,
               "errors": 0, "failures": 0, "skipped": 0}
    p.write_new(destination / "SUMMARY.json", summary)
    print(json.dumps(summary, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--read", action="store_true")
    parser.add_argument("--index", type=int, choices=(1, 2))
    for name in ("output", "reference", "baseline"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--result", type=Path)
    parser.add_argument("--absent", type=Path, action="append", default=[])
    args = parser.parse_args()
    if args.read:
        p.need(args.result is not None and args.index is not None, "complete readback child arguments")
        read_child(args)
    else:
        p.need(not args.absent and args.result is None and args.index is None, "parent readback arguments")
        main_parent(args)


if __name__ == "__main__":
    main()
