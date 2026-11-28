"""Exact owned source/build/replay argv and unchanged per-process budgets."""
from pathlib import Path
import json
from protocol import domain
TRACE="openat,newfstatat,fstat,statx,geteuid,getrandom,poll,read,pread64,write,writev,fsync,linkat,unlinkat,close"
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
    ]
    for group in domain(root)["groups"]:
        for mode in ("observed","off"):
            name="native-"+mode+"-"+group
            cmd=[python,"-I","-B",root/"native_callable.py","--build",out/"build","--output",out/name,
                 "--fixture",m["owned_fixture"],"--group",group,"--observer","on" if mode=="observed" else "off"]
            if mode=="off":cmd=["/usr/bin/strace","-qq","-f","-s","65536","-xx","-o",out/(name+".strace"),"-e","trace="+TRACE,*cmd]
            rows.append((name,cmd,root,60))
        name="original-"+group
        rows.append((name,["/usr/bin/strace","-qq","-f","-s","65536","-xx","-o",out/(name+".strace"),"-e","trace="+TRACE,
            python,"-I","-B",root/"original_process.py","--binary",out/"original.elf","--output",out/name,
            "--fixture",m["owned_fixture"],"--group",group],root,60))
    return [dict(name=n,argv=[str(v) for v in argv],cwd=str(cwd),timeout=budget) for n,argv,cwd,budget in rows]
