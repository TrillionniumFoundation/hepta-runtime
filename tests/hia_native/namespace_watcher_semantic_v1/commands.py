"""Every source-defined group has one unchanged 60-second whole-process deadline."""
from pathlib import Path
import json
from protocol import domain
TRACE="inotify_init1,inotify_add_watch,inotify_rm_watch,read,openat,fcntl,dup2,dup3,close,write,writev,exit_group,newfstatat,fstat,statx,prlimit64,setrlimit"
READ_FDS=",".join(str(x)for x in range(32,320))
def commands(m):
    root=Path(m["source_root"]);out=Path(m["producer_root"]);rust=Path(m["rust_bin"]);python=m["python"]
    ref=out/"reference";config=["--config",'source.crates-io.replace-with="fixed-vendor"',
        "--config","source.fixed-vendor.directory="+json.dumps(str(out/"vendor"))]
    rows=[
        ("source-check",[python,"-I","-B",root/"source_check.py"],root,60),
        ("toolchain",[rust/"rustc","--version","--verbose"],root,60),
        ("cargo-version",[rust/"cargo","--version","--verbose"],root,60),
        ("strace-version",["/usr/bin/strace","--version"],root,60),
        ("native-build-readback",[python,"-I","-B",root/"read_build_cli.py","--retained",m["retained_root"]],root,180),
        ("rust-fetch",[rust/"cargo","fetch","--locked","--manifest-path",ref/"Cargo.toml"],ref,180),
        ("rust-vendor",[rust/"cargo","vendor","--locked","--offline","--versioned-dirs","--manifest-path",ref/"Cargo.toml",out/"vendor"],ref,180),
        ("rust-build",[rust/"cargo","build","--frozen","--verbose","--target","x86_64-unknown-linux-gnu","--manifest-path",ref/"Cargo.toml",*config],ref,900),
    ]
    for group in domain(root)["groups"]:
        name="paired-"+group
        # Complete kernel read payloads from exactly the real, privately reserved
        # event descriptor pool. All source/log I/O retains raw arguments and returns.
        argv=["/usr/bin/strace","-qq","-f","-s","65536","-xx","-v","-o",out/(name+".strace"),
            "-e","trace="+TRACE,"-e","raw=read,write,writev","-e","read="+READ_FDS,
            python,"-I","-B",root/"run_pairs.py","--retained",m["retained_root"],
            "--binary",out/"original.elf","--output",out/name,"--fixture",Path(m["owned_fixture"])/group,"--group",group]
        rows.append((name,argv,root,60))
    return [dict(name=n,argv=[str(x)for x in argv],cwd=str(cwd),timeout=budget)for n,argv,cwd,budget in rows]
