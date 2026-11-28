"""Exact new anchored-reference/native argv and unexpanded per-process budgets."""
from pathlib import Path
import json
TRACE="openat,newfstatat,fstat,statx,geteuid,read,pread64,write,writev,close"
def commands(m):
    root=Path(m["source_root"]);out=Path(m["producer_root"]);rust=Path(m["rust_bin"]);python=m["python"]
    ref=out/"reference";config=["--config",'source.crates-io.replace-with="fixed-vendor"',"--config","source.fixed-vendor.directory="+json.dumps(str(out/"vendor"))]
    rows=[
        ("source-check",[python,"-I","-B",root/"source_check.py"],root,60),
        ("toolchain",[rust/"rustc","--version","--verbose"],root,60),
        ("cargo-version",[rust/"cargo","--version","--verbose"],root,60),
        ("strace-version",["/usr/bin/strace","--version"],root,60),
        ("native-build",[python,"-I","-B",root/"build_callable.py","--hepta",m["compiler_root"],"--output",out/"build"],root,900),
        ("rust-fetch",[rust/"cargo","fetch","--locked","--manifest-path",ref/"Cargo.toml"],ref,180),
        ("rust-vendor",[rust/"cargo","vendor","--locked","--offline","--versioned-dirs","--manifest-path",ref/"Cargo.toml",out/"vendor"],ref,180),
        ("rust-build",[rust/"cargo","build","--frozen","--verbose","--target","x86_64-unknown-linux-gnu","--manifest-path",ref/"Cargo.toml",*config],ref,900),
        ("native-observed",[python,"-I","-B",root/"native_callable.py","--build",out/"build","--output",out/"native-observed","--fixture",m["owned_fixture"],"--observer","on"],root,60),
        ("native-observer-off",["/usr/bin/strace","-qq","-f","-s","65536","-xx","-o",out/"native-observer-off.strace","-e","trace="+TRACE,
            python,"-I","-B",root/"native_callable.py","--build",out/"build","--output",out/"native-observer-off","--fixture",m["owned_fixture"],"--observer","off"],root,60),
        ("original",["/usr/bin/strace","-qq","-f","-s","65536","-xx","-o",out/"original.strace","-e","trace="+TRACE,
            python,"-I","-B",root/"original_process.py","--binary",out/"original.elf","--output",out/"original","--fixture",m["owned_fixture"]],root,60),
        ("native-controls",[python,"-I","-B",root/"transport_controls.py","--build",out/"build","--output",out/"transport-controls","--fixture",m["control_fixture"]],root,180),
        ("owner-controls",[python,"-I","-B",root/"hia_controls.py","--build",out/"build","--observed",out/"native-observed","--output",out/"owner-controls"],root,180)]
    return [dict(name=n,argv=[str(v) for v in args],cwd=str(cwd),timeout=budget) for n,args,cwd,budget in rows]
