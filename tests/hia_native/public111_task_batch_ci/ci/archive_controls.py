"""Exercise the normal Cargo hard-link export boundary without executing captures."""
from pathlib import Path
from types import ModuleType, SimpleNamespace
import argparse, contextlib, hashlib, io, json, os, stat, sys, tarfile
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import pin, put, require
OLD_SHA256 = "b4dc493e79b52265a03965d8c7cb2a704ce9eae1f154f8146d1840b331f63a9c"

def snapshot(root):
    result = {}
    for path in [root, *sorted(root.rglob("*"))]:
        s = path.lstat()
        row = {"device":s.st_dev, "inode":s.st_ino, "nlink":s.st_nlink, "mode":s.st_mode,
               "size":s.st_size, "mtime_ns":s.st_mtime_ns, "ctime_ns":s.st_ctime_ns}
        if stat.S_ISREG(s.st_mode):
            row.update(pin(path))
        else:
            require(stat.S_ISDIR(s.st_mode), "control input kind")
        result[path.relative_to(root).as_posix()] = row
    return result

def module(raw, path, name):
    value = ModuleType(name)
    value.__file__ = str(path)
    exec(compile(raw, str(path), "exec", dont_inherit=True), value.__dict__)
    return value

def run(archive_source, output):
    archive_source = Path(archive_source).resolve(strict=True)
    output = Path(output).resolve()
    require(not output.exists(), "new archive-control output required")
    output.mkdir(parents=True)
    raw = archive_source.read_bytes()
    before_text = b"format=tarfile.PAX_FORMAT,dereference=False"
    after_text = b"format=tarfile.PAX_FORMAT,dereference=True"
    require(raw.count(after_text) == 1 and before_text not in raw, "one precise export change")
    baseline = raw.replace(after_text, before_text)
    require(hashlib.sha256(baseline).hexdigest() == OLD_SHA256, "unchanged complete failed exporter")
    (output/"archive-before.py").write_bytes(baseline)
    (output/"archive-after.py").write_bytes(raw)
    old = module(baseline, archive_source, "archive_before_control")
    new = module(raw, archive_source, "archive_after_control")
    capture, package = output/"input-capture", output/"input-package"
    (capture/"bin").mkdir(parents=True)
    (capture/"empty-directory").mkdir()
    package.mkdir()
    payload = (b"ordinary retained build data\x00\n" * 257)
    (capture/"bin/tool").write_bytes(payload)
    os.chmod(capture/"bin/tool", 0o755)
    os.link(capture/"bin/tool", capture/"bin/build-script-build")
    os.link(capture/"bin/tool", capture/"bin/build_script_build-hash")
    (capture/"independent-copy").write_bytes(payload)
    (capture/"empty-file").write_bytes(b"")
    os.chmod(capture/"empty-directory", 0o750)
    (package/"PACKAGE.json").write_bytes(b'{"fixture":"archive-byte-control"}\n')
    roots = {"capture":capture, "package":package}
    before = {name:snapshot(path) for name,path in roots.items()}
    shared = [capture/"bin"/name for name in ("tool","build-script-build","build_script_build-hash")]
    require(len({p.stat().st_ino for p in shared}) == 1 and all(p.stat().st_nlink == 3 for p in shared),
            "actual three-name source hard link")
    require((capture/"independent-copy").stat().st_ino != shared[0].stat().st_ino, "independent equal bytes")
    common = dict(capture=capture, package=package, manifest_sha256=pin(package/"PACKAGE.json")["sha256"],
                  label="archive-controls", driver_prefix=None)
    old_failure = None
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            old.pack(SimpleNamespace(**common, output=output/"old-export"))
    except ValueError as error:
        old_failure = str(error)
    require(old_failure == "archive contains a nonregular object", "exact preserved exporter failure")
    old_links = []
    with tarfile.open(output/"old-export/capture.tar.gz", "r:gz") as tar:
        for member in tar:
            if member.islnk():
                old_links.append({"name":member.name, "target":member.linkname})
    require(len(old_links) == 2, "actual prior-export hard-link records")
    require({name:snapshot(path) for name,path in roots.items()} == before, "old export changed input")
    with contextlib.redirect_stdout(io.StringIO()):
        new.pack(SimpleNamespace(**common, output=output/"new-export"))
        new.extract(SimpleNamespace(archive=output/"new-export/capture.tar.gz",
                    receipt=output/"new-export/archive.json", output=output/"extracted"))
    require({name:snapshot(path) for name,path in roots.items()} == before, "export/readback changed input")
    regular = []
    with tarfile.open(output/"new-export/capture.tar.gz", "r:gz") as tar:
        for member in tar:
            require(member.isfile() and not member.islnk() and not member.issym(), "complete regular member")
            regular.append(member.name)
    for name,row in before["capture"].items():
        if name == ".":
            continue
        path = output/"extracted"/name
        require(stat.S_IMODE(path.stat().st_mode) == stat.S_IMODE(row["mode"]), "restored mode")
        if stat.S_ISREG(row["mode"]):
            require(pin(path) == {k:row[k] for k in ("bytes","sha256")}, "full source bytes retained")
            require(path.stat().st_nlink == 1, "portable output contains independent regular copies")
        else:
            require(path.is_dir(), "complete empty-directory restoration")
    require(len({(output/"extracted"/"bin"/p.name).stat().st_ino for p in shared}) == 3,
            "regular materialization after complete bytes readback")
    report = {"status":"NORMAL_HARDLINK_COMPLETE_ARCHIVE_CONTROL_PASS",
        "old_exporter":pin(output/"archive-before.py"), "new_exporter":pin(output/"archive-after.py"),
        "old_failure":old_failure, "old_archive":pin(output/"old-export/capture.tar.gz"),
        "old_link_members":old_links, "new_archive":pin(output/"new-export/capture.tar.gz"),
        "new_receipt":json.loads((output/"new-export/archive.json").read_bytes()),
        "regular_members":len(regular), "input_before":before,
        "input_after":{name:snapshot(path) for name,path in roots.items()},
        "source_bytes_modes_inodes_mtimes_ctimes_unchanged":True,
        "native_executions":0, "rust_executions":0, "captured_code_executions":0}
    put(output/"CONTROL.json", report)
    return report

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.archive_source, args.output), sort_keys=True))
if __name__ == "__main__":
    main()
