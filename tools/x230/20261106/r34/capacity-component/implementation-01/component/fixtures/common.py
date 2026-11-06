# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
# Textually included in the three fixed component helpers. No import-time effect.
import hashlib
import json
import os
import re
import stat
import sys
import time

HOSTS = ("ai395", "mac", "main", "pocket4", "rog", "x230")
GATE_TTL = 30
WORKLOAD_TTL = 90


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def identity(info):
    return [info.st_dev, info.st_ino, info.st_uid, info.st_mode]


def stamp(info):
    return identity(info) + [info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def component(name):
    need(isinstance(name, str) and name not in ("", ".", "..")
         and "/" not in name and "\x00" not in name, "invalid descriptor-relative component")
    return name


def directory_at(parent, name):
    return os.open(component(name), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                   dir_fd=parent)


def absolute_directory(path):
    need(isinstance(path, str) and path.startswith("/") and path != "/", "absolute private directory required")
    parts = path.split("/")[1:]
    need(all(part not in ("", ".", "..") for part in parts), "noncanonical directory path")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts:
            child = directory_at(fd, part)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        need(info.st_uid == os.geteuid() and not stat.S_IMODE(info.st_mode) & 0o022,
             "foreign or writable fixture parent")
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_at(parent, name, limit=65536, optional=False):
    try:
        fd = os.open(component(name), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=parent)
    except FileNotFoundError:
        if optional:
            return None
        raise
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
             and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
             and 0 <= before.st_size <= limit, "unsafe or oversized private file: " + name)
        with os.fdopen(os.dup(fd), "rb") as stream:
            raw = stream.read(limit + 1)
        need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(fd))
             == stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)),
             "private file changed while read: " + name)
        return raw
    finally:
        os.close(fd)


def write_once(parent, name, raw):
    need(isinstance(raw, bytes) and len(raw) <= 65536, "oversized private publication")
    fd = os.open(component(name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=parent)
    try:
        with os.fdopen(os.dup(fd), "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        info = os.fstat(fd)
        need(info.st_uid == os.geteuid() and info.st_nlink == 1
             and stat.S_IMODE(info.st_mode) == 0o600
             and stamp(info) == stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)),
             "private publication identity changed")
    finally:
        os.close(fd)
    os.fsync(parent)


def validate_ticket(ticket):
    need(set(ticket) == {"nonce", "host", "victim", "base", "name", "fixture_identity",
                         "source_job_id", "source_record_sha256", "expected_platform"}, "unexpected fixture ticket fields")
    need(ticket["host"] in HOSTS and ticket["victim"] in ("x230", "mac"), "unfrozen fixture host role")
    need(re.fullmatch(r"[0-9a-f]{24}", ticket["nonce"]) is not None, "invalid fixture nonce")
    need(ticket["name"] == "r34-capacity-" + ticket["nonce"] + "-" + ticket["host"], "fixture name mismatch")
    need(re.fullmatch(r"[0-9a-f]+-[0-9a-f]+-[0-9a-f]+", ticket["source_job_id"]) is not None,
         "missing source provenance job identity")
    need(re.fullmatch(r"[0-9a-f]{64}", ticket["source_record_sha256"]) is not None,
         "missing source provenance record hash")
    need(ticket["expected_platform"] in ("linux", "darwin") and sys.platform == ticket["expected_platform"],
         "remote platform differs from frozen topology")


def origin(ticket, info):
    return {"schema": "hepta-r34-capacity-fixture/v1", **ticket, "fixture_identity": identity(info)}


def open_fixture(ticket, prepare=False):
    validate_ticket(ticket)
    base = absolute_directory(ticket["base"])
    fixture = None
    try:
        if prepare:
            need(ticket["fixture_identity"] is None, "fresh fixture already has an identity")
            os.mkdir(ticket["name"], mode=0o700, dir_fd=base)
        fixture = directory_at(base, ticket["name"])
        info = os.fstat(fixture)
        need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, "fixture owner/mode differs")
        expected = origin(ticket, info)
        if prepare:
            write_once(fixture, "origin.json", canonical(expected))
            os.fsync(base)
        else:
            need(ticket["fixture_identity"] == identity(info), "fixture directory identity changed")
            need(read_at(fixture, "origin.json", 8192) == canonical(expected), "fixture origin differs")
        return base, fixture, expected
    except BaseException:
        if fixture is not None:
            os.close(fixture)
        os.close(base)
        raise


def still_named(ticket, base, fixture):
    need(identity(os.fstat(fixture)) == ticket["fixture_identity"]
         == identity(os.stat(ticket["name"], dir_fd=base, follow_symlinks=False)), "fixture path changed")
    fresh_base = absolute_directory(ticket["base"])
    try:
        fresh = directory_at(fresh_base, ticket["name"])
        try:
            need(identity(os.fstat(fresh)) == ticket["fixture_identity"], "fresh fixture reopen differs")
        finally:
            os.close(fresh)
    finally:
        os.close(fresh_base)


def gate_count(ticket):
    peer = "ai395" if ticket["victim"] == "x230" else "main"
    return 2 if ticket["host"] in (ticket["victim"], peer) else 1


def release_value(ticket, kind):
    return {"schema": "hepta-r34-capacity-release/v1", "nonce": ticket["nonce"],
            "host": ticket["host"], "victim": ticket["victim"], "kind": kind,
            "fixture_identity": ticket["fixture_identity"]}


def released(ticket, fixture, kind):
    raw = read_at(fixture, kind + "-release.json", 8192, optional=True)
    if raw is None:
        return False
    need(raw == canonical(release_value(ticket, kind)), "release receipt differs")
    return True


def own_process_identity():
    result = {"pid": os.getpid(), "uid": os.geteuid(), "platform": sys.platform}
    if sys.platform == "linux":
        with open("/proc/self/stat", "r", encoding="ascii") as stream:
            tail = stream.read(4096).rsplit(")", 1)[1].split()
        result["start_ticks"] = int(tail[19])
    else:
        result["start_ticks"] = None
        result["birth_scope"] = "original runtime child receipt and account/start-time checks remain authoritative"
    return result


def stdin_payload():
    raw = sys.stdin.buffer.read(65537)
    need(len(raw) <= 65536, "component payload exceeds 64 KiB")
    return json.loads(raw)
