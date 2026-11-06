#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Exact extracted original benchmark helpers; definitions only until called."""
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import struct
HOSTS = {"ai395", "mac", "main", "pocket4", "rog", "x230"}


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_file(path, maximum=16 * 1024 * 1024):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
             "input must be a single-link regular file: " + str(path))
        need(before.st_size <= maximum, "input exceeds size bound")
        with os.fdopen(os.dup(fd), "rb") as stream:
            data = stream.read(maximum + 1)
        need(len(data) == before.st_size and identity(before) == identity(os.fstat(fd))
             == identity(path.lstat()), "input changed while reading")
        return data
    finally:
        os.close(fd)


def create_file(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def agent_identity(path):
    before = Path(path).lstat()
    need(stat.S_ISSOCK(before.st_mode) and before.st_uid == os.getuid(),
         "current SSH agent socket must be account-owned")
    def exact(stream, count):
        chunks = bytearray()
        while len(chunks) < count:
            chunk = stream.recv(count - len(chunks))
            need(chunk, "SSH agent closed during identity observation")
            chunks.extend(chunk)
        return bytes(chunks)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(5)
        stream.connect(path)
        peer = struct.unpack("3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        need(peer[1] == os.getuid(), "SSH agent peer UID differs")
        stream.sendall(b"\0\0\0\1\x0b")
        length = struct.unpack(">I", exact(stream, 4))[0]
        need(5 <= length <= 65536, "SSH agent identity frame is out of bounds")
        data = exact(stream, length)
        need(data[0] == 12 and 1 <= int.from_bytes(data[1:5], "big") <= 64,
             "current SSH agent has no bounded usable key list")
    after = Path(path).lstat()
    need(identity(before) == identity(after), "SSH agent socket changed")
    return {"socket_identity": identity(before), "peer": peer,
            "identity_frame_sha256": digest(data)}


def fresh_profile(template_path, output, socket_parent, agent):
    old_raw = read_file(template_path, 262144)
    old = json.loads(old_raw)
    need(old["schema"] == "hepta-observation-ssh-pool/v1"
         and old["allow_bounded_cached_authentication"] is True, "unsupported profile template")
    raw_config = read_file(old["ssh_config"], 262144)
    raw_known = read_file(old["known_hosts"], 262144)
    need(digest(raw_config) == old["ssh_config_sha256"]
         and digest(raw_known) == old["known_hosts_sha256"], "historical SSH inputs changed")
    output.mkdir(mode=0o700)
    config, known = output / "ssh_config", output / "known_hosts"
    rewritten, replacements = [], 0
    for line in raw_config.decode().splitlines():
        fields = line.split()
        if fields and fields[0].lower() == "userknownhostsfile":
            need(len(fields) == 2 and fields[1] == old["known_hosts"],
                 "unrecognized known-hosts reference")
            line = " UserKnownHostsFile " + str(known)
            replacements += 1
        rewritten.append(line)
    need(replacements >= 1, "explicit known-hosts reference missing")
    create_file(config, ("\n".join(rewritten) + "\n").encode())
    create_file(known, raw_known)
    parent = Path(socket_parent)
    pin = parent.lstat()
    need(parent.resolve() == parent and stat.S_ISDIR(pin.st_mode)
         and pin.st_uid == os.getuid() and stat.S_IMODE(pin.st_mode) == 0o700,
         "socket parent must be an existing private direct directory")
    # Native checks its final socket path, but OpenSSH first binds a temporary
    # path with a dot plus 16 random characters. Reserve that suffix too, plus
    # a ten-digit PID and six-digit pool sequence for this bounded experiment.
    # A short direct private parent such as /home/qian/hx230-opt-20261023 fits;
    # a symlink or a shorter unverified alias is not an acceptable substitute.
    pool_component = len("/hp-o-") + 10 + 1 + 32
    control_component = len("/m-") + 6
    openssh_temporary_suffix = 1 + 16
    socket_bytes_with_nul = (len(os.fsencode(parent)) + pool_component
                             + control_component + openssh_temporary_suffix + 1)
    need(socket_bytes_with_nul <= 108,
         "socket parent exceeds conservative OpenSSH temporary-path budget; use a shorter private directory")
    spec = {"schema": "hepta-observation-ssh-pool/v1",
            "allow_bounded_cached_authentication": True,
            "ssh_config": str(config), "ssh_config_sha256": digest(read_file(config)),
            "known_hosts": str(known), "known_hosts_sha256": digest(raw_known),
            "ssh_sha256": digest(read_file("/usr/bin/ssh")),
            "false_sha256": digest(read_file("/usr/bin/false")),
            "shell_sha256": digest(read_file(Path("/bin/sh").resolve(strict=True))),
            "agent_socket": agent, "socket_parent": str(parent)}
    path = output / "profile.json"
    create_file(path, canonical(spec))
    return path, {"template_sha256": digest(old_raw), "new_profile_sha256": digest(read_file(path)),
                  "historical_agent_not_reused": True, "current_agent_bound": True}


def load_topology(path, profile_template):
    """Bind alias meaning to this exact pinned profile, never to another controller."""
    raw = read_file(path, 65536)
    value = json.loads(raw)
    need(value.get("schema") == "hepta-x230-benchmark-topology/v1"
         and value.get("profile_template_sha256") == digest(read_file(profile_template, 262144))
         and set(value.get("hosts", {})) == HOSTS, "topology is not bound to this profile/alias set")
    for host, item in value["hosts"].items():
        need(item.get("platform") in {"linux", "macos"}
             and isinstance(item.get("machine_group"), str) and 0 < len(item["machine_group"]) <= 256
             and not any(character in item["machine_group"] for character in "\r\n\0"),
             "invalid explicit platform/machine group: " + host)
        need(all(other["platform"] == item["platform"] for other in value["hosts"].values()
                 if other.get("machine_group") == item["machine_group"]),
             "one machine group has inconsistent platforms")
    receipt = {"file": "topology.json", "bytes": len(raw), "sha256": digest(raw),
               "profile_template_sha256": value["profile_template_sha256"], "hosts": value["hosts"],
               "alias_count": len(HOSTS),
               "physical_machine_groups": len({item["machine_group"] for item in value["hosts"].values()})}
    return raw, receipt

