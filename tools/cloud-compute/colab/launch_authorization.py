#!/usr/bin/env python3
"""Open the safe OAuth helper in the ROG user's existing GNOME desktop.

The authorization code stays in that graphical terminal and is never accepted
by this launcher. Exit 0 acknowledges opening a terminal, not authorization.
Read the safe status file to observe the actual outcome.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import subprocess


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--status-file", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    release = args.release.expanduser().absolute()
    status = args.status_file.expanduser().absolute()
    status.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    st = status.parent.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise RuntimeError("AUTH_STATUS_DIRECTORY_NOT_PRIVATE")
    python = release / "venv/bin/python"
    helper = release / "authorize_colab.py"
    if not python.is_file() or not helper.is_file():
        raise RuntimeError("AUTH_HELPER_NOT_INSTALLED")
    runtime = Path("/run/user") / str(os.getuid())
    if not (runtime / "bus").exists():
        raise RuntimeError("DESKTOP_SESSION_BUS_UNAVAILABLE")
    env = dict(os.environ)
    env["XDG_RUNTIME_DIR"] = str(runtime)
    env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=" + str(runtime / "bus")
    result = subprocess.run(
        ["/usr/bin/systemctl", "--user", "show-environment"],
        env=env, capture_output=True, text=True, timeout=10,
    )
    allowed = {"DISPLAY", "WAYLAND_DISPLAY", "XDG_SESSION_TYPE", "XDG_CURRENT_DESKTOP"}
    for line in result.stdout.splitlines():
        key, sep, value = line.partition("=")
        if sep and key in allowed:
            env[key] = value
    if not env.get("DISPLAY") and not env.get("WAYLAND_DISPLAY"):
        raise RuntimeError("DESKTOP_DISPLAY_UNAVAILABLE")
    command = [
        "/usr/bin/gnome-terminal", "--title=Hepta Colab 授权", "--",
        str(python), str(helper), "--loopback", "--open-browser", "--status-file", str(status),
    ]
    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise RuntimeError("AUTH_TERMINAL_LAUNCH_FAILED")
    print(json.dumps({
        "status": "authorization_terminal_open_requested",
        "status_file": str(status),
        "authorization_confirmed": False,
    }))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"status": "blocked", "error_type": type(exc).__name__,
                          "error_code": str(exc) if isinstance(exc, RuntimeError) else "AUTH_LAUNCH_ERROR"}))
        raise SystemExit(2)
