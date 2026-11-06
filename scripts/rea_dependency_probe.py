#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# Licensed under the Apache License, Version 2.0.
"""Observe provider discovery inputs without starting a provider or an ADB daemon.

Paths are discovery hints, not provider, license or behavioral qualification.
The optional ADB query reads only an already running loopback server. It sends
host:devices-l and never selects a device, runs a command or attaches to it.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import itertools
import json
from pathlib import Path
import platform
import re
import shutil
import socket


COMMANDS = (
    "node npm java cc python3 jadx ghidra analyzeHeadless gdb lldb rizin radare2 "
    "Cutter cutter objdump readelf adb frida frida-ls-devices tshark capinfos "
    "sigrok-cli binwalk unblob apktool wasm2wat wasm-validate jeb jeb_linux.sh "
    "ida idat idat64 hopper google-chrome chromium chromium-browser"
).split()
ENGINE_NAME = re.compile(
    r"(?:^|[-_ .])(?:ghidra|jadx|jeb|ida|idat|hopper|frida|android|chrome|"
    r"chromium|binwalk|unblob|sigrok|wireshark|wabt|apktool)(?:$|[-_ .0-9])",
    re.IGNORECASE,
)
MAX_DIRECTORY_ENTRIES = 1024
MAX_ADB_RESPONSE_BYTES = 65536


def directory_observation(root):
    record = {"root": str(root), "status": "unobserved", "candidates": []}
    try:
        children = list(itertools.islice(root.iterdir(), MAX_DIRECTORY_ENTRIES + 1))
        record.update(status="observed", truncated=len(children) > MAX_DIRECTORY_ENTRIES)
        for path in children[:MAX_DIRECTORY_ENTRIES]:
            if ENGINE_NAME.search(path.name):
                record["candidates"].append({"name": path.name, "directory": path.is_dir()})
        record["candidates"].sort(key=lambda value: value["name"])
    except OSError as error:
        record["reason"] = type(error).__name__
    return record


def existing_adb_server():
    record = {"status": "not_observed", "scope": "existing loopback server only"}
    try:
        with socket.create_connection(("127.0.0.1", 5037), timeout=2) as connection:
            request = b"host:devices-l"
            connection.sendall(("%04x" % len(request)).encode() + request)

            def read_exact(length):
                data = b""
                while len(data) < length:
                    part = connection.recv(length - len(data))
                    if not part:
                        raise ValueError("short ADB response")
                    data += part
                return data

            status = read_exact(4)
            if status != b"OKAY":
                return {**record, "status": "protocol_refusal", "status_bytes": status.hex()}
            size = int(read_exact(4), 16)
            if size > MAX_ADB_RESPONSE_BYTES:
                raise ValueError("oversized ADB response")
            devices = []
            for row in read_exact(size).decode("utf-8", "replace").splitlines():
                fields = row.split()
                if fields:
                    devices.append({"serial_sha256": hashlib.sha256(fields[0].encode()).hexdigest(),
                                    "state": fields[1] if len(fields) > 1 else "unknown",
                                    "reported_fields": fields[2:]})
            record.update(status="observed", device_count=len(devices), devices=devices)
    except (OSError, ValueError) as error:
        record["reason"] = type(error).__name__
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--existing-adb", action="store_true",
                        help="query an existing loopback ADB server; never start one")
    args = parser.parse_args()
    roots = [Path("/opt"), Path("/Applications"), Path("/usr/local/bin"),
             Path("/opt/homebrew/bin"), Path.home() / ".local/bin",
             Path.home() / "tools", Path.home() / "work"]
    result = {"schema": "hepta.rea.dependency-observation.v1",
              "observed_at": datetime.now(timezone.utc).isoformat(),
              "platform": platform.system(), "architecture": platform.machine(),
              "commands_on_process_path": {name: shutil.which(name) for name in COMMANDS},
              "bounded_directories": [directory_observation(root) for root in roots],
              "adb_existing_server": existing_adb_server() if args.existing_adb
                  else {"status": "not_requested"},
              "qualification": "DISCOVERY_ONLY",
              "limitations": ["Configured aliases are not proven to be distinct physical hosts",
                              "No PATH/directory match does not establish installation absence",
                              "No provider launch, license inspection, device command or attachment",
                              "Device discovery does not establish permission for instrumentation"],
              "limits": {"directory_entries_per_root": MAX_DIRECTORY_ENTRIES,
                         "adb_response_bytes": MAX_ADB_RESPONSE_BYTES}}
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
