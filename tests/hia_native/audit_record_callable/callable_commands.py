"""Exact native producer argv and unchanged per-process budgets."""
from pathlib import Path

TRACE = "openat,newfstatat,fstat,statx,geteuid,read,write,writev,fsync,close,linkat,unlinkat,renameat,fcntl,getdents64"


def commands(metadata):
    root = Path(metadata["source_root"])
    output = Path(metadata["producer_root"])
    python = metadata["python"]
    rows = [
        ("strace-version", ["/usr/bin/strace", "--version"], 60),
        ("native-build", [python, "-I", "-B", root / "build_callable.py", "--hepta", metadata["compiler_root"],
                          "--output", output / "build"], 900),
        ("native-observed", [python, "-I", "-B", root / "native_callable.py", "--build", output / "build",
                             "--output", output / "native-observed", "--fixture", metadata["owned_fixture"],
                             "--observer", "on"], 180),
        ("native-observer-off", ["/usr/bin/strace", "-qq", "-f", "-s", "65536", "-xx",
            "-o", output / "native-observer-off.strace", "-e", "trace=" + TRACE,
            python, "-I", "-B", root / "native_callable.py", "--build", output / "build",
            "--output", output / "native-observer-off", "--fixture", metadata["owned_fixture"],
            "--observer", "off"], 180),
        ("native-controls", [python, "-I", "-B", root / "transport_controls.py", "--build", output / "build",
                             "--output", output / "transport-controls", "--fixture", metadata["control_fixture"]], 180),
    ]
    return [dict(name=name, argv=[str(x) for x in argv], cwd=str(root), timeout=timeout)
            for name, argv, timeout in rows]
