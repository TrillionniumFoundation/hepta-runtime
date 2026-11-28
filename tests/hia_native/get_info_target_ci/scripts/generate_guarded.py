"""Run source derivation with an audited input allowlist and no child execution.

This checks the generator's actual file reads. It is a regression guard for this
source-owned build, not a sandbox for arbitrary hostile Python.
"""
from pathlib import Path
import argparse, ast, copy, hashlib, json, os, re, sys, tomllib
sys.dont_write_bytecode = True
def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "primary", "hepta", "output"):
        p.add_argument("--" + name, required=True, type=Path)
    a = p.parse_args()
    source, primary, hepta = (getattr(a, name).resolve(strict=True) for name in ("source", "primary", "hepta"))
    output = a.output.absolute()
    if output.exists(): raise ValueError("fresh generated source output required")
    roots = {"package": source, "primary": primary, "hepta": hepta,
             "stdlib": Path(sys.base_prefix).resolve(), "generated": output}
    reads, writes, denied = set(), set(), []
    def identify(path, write=False):
        value = Path(os.fsdecode(path)).absolute().resolve()
        if write:
            if value == output or value.is_relative_to(output):
                return ("generated", value.relative_to(output).as_posix())
            denied.append({"operation": "write", "path": str(value)})
            raise PermissionError("generator may write only its new output")
        for key, root in roots.items():
            if value == root or value.is_relative_to(root):
                return (key, value.relative_to(root).as_posix())
        denied.append({"operation": "read", "path": str(value)})
        raise PermissionError("generator may read only primary source, package, compiler and standard library")
    def audit(event, args):
        if event == "open":
            path, mode, flags = args
            if isinstance(path, (str, bytes, os.PathLike)):
                write = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
                key = identify(path, write)
                (writes if write else reads).add(key)
        elif event in {"os.mkdir", "os.remove", "os.rmdir", "os.chmod", "os.utime"}:
            identify(args[0], True)
        elif event in {"os.rename", "os.link", "os.symlink"}:
            identify(args[0], True); identify(args[1], True)
        elif event.startswith(("subprocess.", "ctypes.", "mmap.")) or event in {"os.system", "os.exec", "os.posix_spawn", "os.fork"}:
            denied.append({"operation": event})
            raise PermissionError("authoring process may not launch or execute native code")
    sys.addaudithook(audit)
    sys.path.insert(0, str(source / "scripts"))
    from author_get_info import generate
    result = generate(source, primary, hepta, output)
    report = dict(schema="hepta.current-get-info.author-read-audit.v1",
        status="PASS", reads=[dict(root=k, path=p) for k,p in sorted(reads)],
        writes=[dict(root=k, path=p) for k,p in sorted(writes)], denied=denied,
        expected_reference_zip_or_profile_outputs_accessed=False,
        primary_only_derivation=True, child_or_native_execution=False,
        source_sha256=result["source_sha256"])
    (output / "AUTHOR_READS.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("status", "source_sha256", "primary_only_derivation")}, sort_keys=True))
if __name__ == "__main__": main()
