"""Exact original budgets and one actual traced owned group per fixed domain."""
from pathlib import Path
import json
from protocol import domain
TRACE="openat,fcntl,dup2,dup3,close,getdents64,write,writev,exit_group,prctl,newfstatat,fstat,statx"
def commands(m):
    root=Path(m["source_root"]);out=Path(m["producer_root"]);rust=Path(m["rust_bin"]);python=m["python"]
    ref=out/"reference";config=["--config",'source.crates-io.replace-with="fixed-vendor"',
        "--config","source.fixed-vendor.directory="+json.dumps(str(out/"vendor"))]
    rows=[
        ("source-check",[python,"-I","-B",root/"source_check.py"],root,60),
        ("toolchain",[rust/"rustc","--version","--verbose"],root,60),
        ("cargo-version",[rust/"cargo","--version","--verbose"],root,60),
        ("strace-version",["/usr/bin/strace","--version"],root,60),
        ("native-build",[python,"-I","-B",root/"build_callable.py","--hepta",m["compiler_root"],"--output",out/"build"],root,900),
        ("native-build-readback",[python,"-I","-B",root/"read_build_cli.py","--build",out/"build"],root,180),
        ("rust-fetch",[rust/"cargo","fetch","--locked","--manifest-path",ref/"Cargo.toml"],ref,180),
        ("rust-vendor",[rust/"cargo","vendor","--locked","--offline","--versioned-dirs","--manifest-path",ref/"Cargo.toml",out/"vendor"],ref,180),
        ("rust-build",[rust/"cargo","build","--frozen","--verbose","--target","x86_64-unknown-linux-gnu","--manifest-path",ref/"Cargo.toml",*config],ref,900),
    ]
    for group in domain(root)["groups"]:
        name="paired-"+group
        argv=["/usr/bin/strace","-qq","-f","-s","65536","-xx","-v","-o",out/(name+".strace"),
            "-e","trace="+TRACE,python,"-I","-B",root/"run_pairs.py","--build",out/"build",
            "--binary",out/"original.elf","--output",out/name,"--fixture",Path(m["owned_fixture"])/group,"--group",group]
        rows.append((name,argv,root,60))
    return [dict(name=n,argv=[str(x)for x in argv],cwd=str(cwd),timeout=budget)for n,argv,cwd,budget in rows]
