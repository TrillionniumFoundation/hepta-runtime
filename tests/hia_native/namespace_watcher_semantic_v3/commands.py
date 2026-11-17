"""Every source-defined group has one unchanged 60-second whole-process deadline."""
from pathlib import Path
import json
from protocol import domain
from trace_scope import TRACE,READ_FDS
def commands(m):
    root=Path(m["source_root"]);out=Path(m["producer_root"]);rust=Path(m["rust_bin"]);python=m["python"]
    ref=out/"reference";config=["--config",'source.crates-io.replace-with="fixed-vendor"',
        "--config","source.fixed-vendor.directory="+json.dumps(str(out/"vendor"))]
    rows=[
        ("source-check",[python,"-I","-B",root/"source_check.py"],root,60),
        ("toolchain",[rust/"rustc","--version","--verbose"],root,60),
        ("cargo-version",[rust/"cargo","--version","--verbose"],root,60),
        ("strace-version",["/usr/bin/strace","--kill-on-exit","--version"],root,60),
        ("trace-process-controls",[python,"-I","-B",root/"trace_controls.py","--output",out/"trace-controls"],root,60),
        ("native-build-readback",[python,"-I","-B",root/"read_build_cli.py","--retained",m["retained_root"]],root,180),
        ("rust-fetch",[rust/"cargo","fetch","--locked","--manifest-path",ref/"Cargo.toml"],ref,180),
        ("rust-vendor",[rust/"cargo","vendor","--locked","--offline","--versioned-dirs","--manifest-path",ref/"Cargo.toml",out/"vendor"],ref,180),
        ("rust-build",[rust/"cargo","build","--frozen","--verbose","--target","x86_64-unknown-linux-gnu","--manifest-path",ref/"Cargo.toml",*config],ref,900),
    ]
    for group in domain(root)["groups"]:
        name="paired-"+group
        # Every application gets the same complete trace and kernel payload set.
        # The unchanged full filesystem observer does not run under ptrace.
        argv=[python,"-I","-B",root/"run_pairs.py","--retained",m["retained_root"],
            "--binary",out/"original.elf","--output",out/name,"--fixture",Path(m["owned_fixture"])/group,"--group",group]
        rows.append((name,argv,root,60))
    return [dict(name=n,argv=[str(x)for x in argv],cwd=str(cwd),timeout=budget)for n,argv,cwd,budget in rows]
