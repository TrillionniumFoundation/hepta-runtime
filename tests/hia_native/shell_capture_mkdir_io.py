"""Real Linux qualification for the private blocking HIA mkdir leaf.

The producer prepares owned paths and invokes the sealed native executable.
The reader reconstructs every syscall, guarded native entry and retired tree;
it never executes the implementation or turns a reported PASS into evidence.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path
import selectors

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
SCOPE = {
    "production_activated": False,
    "tokio_async_cancellation_qualified": False,
    "global_statx_atomic_cache_qualified": False,
    "capture_preparation_qualified": False,
    "registry_publication_qualified": False,
    "whole_runtime_replaced": False,
    "old_stack_removal_qualified": False,
}
SOURCE_NAMES = (
    "native/shell_capture_mkdir.hepta", "native/shell_capture_mkdir_abi.md",
    "native/shell_capture_mkdir_packer.hepta", "native/shell_capture_mkdir_layout.json",
    "native/shell_capture_mkdir_fixture.md", "scripts/shell_capture_mkdir_adapter.S",
    "scripts/hia_native_shell_capture_mkdir_build.py", "tests/hia_native/shell_capture_mkdir_io.py",
)
PENDING, CAPACITY, INVALID = 0xfffffffd, 0xfffffffe, 0xffffffff
MASK = (1 << 64) - 1
CASE_FILES = (
    "spec.json", "input.bin", "stdin.bin", "stdout.bin", "stderr.bin",
    "execution.json", "observation.json", "before.json", "after.json",
    "effects.bin", "entries.bin", "retirement.json",
)


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, "duplicate JSON key")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("JSON constant")))


def ordinary(path):
    path = Path(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "nonordinary evidence: " + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        need((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), "file changed during open")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read()
        after = os.fstat(fd)
        need((after.st_size, after.st_mtime_ns, after.st_ctime_ns) ==
             (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns), "file changed during read")
        return raw
    finally:
        os.close(fd)


def pin(raw):
    return {"bytes": len(raw), "sha256": sha(raw)}


def write_new(path, raw):
    path = Path(path)
    with path.open("xb") as stream:
        stream.write(raw)


def read_json(path):
    return strict_json(ordinary(path))


def plain_directory(path):
    need(stat.S_ISDIR(Path(path).lstat().st_mode), "evidence directory is not an ordinary directory")


def case_specs():
    """Shared immutable input/setup definitions; no import-time filesystem work."""
    def directory(path, mode=0o755):
        return {"path_hex": path.hex(), "kind": "directory", "mode": mode}
    def file(path):
        return {"path_hex": path.hex(), "kind": "file", "mode": 0o640,
                "payload_hex": b"existing\x00file\n".hex()}
    def link(path, target):
        return {"path_hex": path.hex(), "kind": "symlink", "mode": 0o777,
                "target_hex": target.hex()}
    def case(name, path, setup=(), seed=0, umask=0o022, absolute=False):
        return {"name": name, "path_hex": path.hex(), "setup": list(setup),
                "cache_seed": seed, "umask": umask, "absolute_under_work": absolute,
                "original_fresh_cache_comparable": seed == 0}
    return (
        case("empty", b""),
        case("root", b"/"),
        case("repeated_root", b"///./"),
        case("dot", b"."),
        case("new_leaf", b"leaf"),
        case("existing_directory", b"existing", [directory(b"existing")]),
        case("existing_file", b"existing-file", [file(b"existing-file")]),
        case("missing_ancestors", b"a/b/c"),
        case("existing_ancestor", b"existing/a/b", [directory(b"existing")]),
        case("repeated_slashes", b"a///b//c/"),
        case("dot_components", b"./a/./b/."),
        case("dotdot_existing", b"existing/../new/leaf", [directory(b"existing")]),
        case("dotdot_missing", b"a/../leaf"),
        case("dotdot_final", b"new/.."),
        case("dot_suffix", b"new/./"),
        case("absolute", b"absolute/a", absolute=True),
        case("non_utf8", b"\xffraw/\x80child"),
        case("embedded_nul", b"before/inside\0after"),
        case("symlink_to_directory", b"dirlink/a/b", [directory(b"target"), link(b"dirlink", b"target")]),
        case("symlink_leaf_directory", b"dirlink", [directory(b"target"), link(b"dirlink", b"target")]),
        case("symlink_to_file", b"filelink", [file(b"target-file"), link(b"filelink", b"target-file")]),
        case("dangling_symlink", b"dangling/a", [link(b"dangling", b"missing")]),
        case("symlink_loop", b"loop/a", [link(b"loop", b"loop")]),
        case("symlink_leaf_loop", b"loop", [link(b"loop", b"loop")]),
        case("intermediate_file", b"existing-file/a", [file(b"existing-file")]),
        case("file_trailing_slash", b"existing-file/", [file(b"existing-file")]),
        case("permission_denied", b"denied/a", [directory(b"denied", 0o500)]),
        case("component_too_long", b"x" * 256),
        case("path_too_long", b"a/" * 2048 + b"leaf"),
        case("umask", b"masked/a", umask=0o027),
        case("metadata_seed_present", b"existing", [directory(b"existing")], seed=1),
        case("metadata_seed_unavailable", b"existing", [directory(b"existing")], seed=2),
        case("create_seed_unavailable", b"new", seed=2),
    )


def path_for(spec, work):
    raw = bytes.fromhex(spec["path_hex"])
    return os.fsencode(work) + b"/" + raw if spec["absolute_under_work"] else raw


def input_for(spec, work):
    raw = path_for(spec, work)
    return b"HSHMKQ01" + struct.pack("<7Q", 1, spec["cache_seed"], len(raw), 0, 0, 0, 0) + raw


def rust_parent(raw):
    """Independent Unix reduction of Rust 1.95 Components::next_back/as_path.

    Prefixes do not exist on Unix. The original leading root/current-dir state
    remains while the back iterator consumes components and trims empty/dot
    suffixes. No pathlib normalization or UTF-8 decoding is used.
    """
    root = raw.startswith(b"/")
    cur = not root and (raw == b"." or raw.startswith(b"./"))
    boundary = int(root or cur)
    rest = raw
    found = False
    while len(rest) > boundary:
        split = rest.rfind(b"/", boundary)
        if split < 0:
            component, rest = rest[boundary:], rest[:boundary]
        else:
            component, rest = rest[split + 1:], rest[:split]
        if component not in (b"", b"."):
            found = True
            break
    if not found:
        return b"" if cur else None
    while len(rest) > boundary:
        split = rest.rfind(b"/", boundary)
        if split < 0:
            component, shortened = rest[boundary:], rest[:boundary]
        else:
            component, shortened = rest[split + 1:], rest[:split]
        if component not in (b"", b"."):
            break
        rest = shortened
    return rest


def stat_identity(value):
    return {"device": value.st_dev, "inode": value.st_ino,
            "mode": value.st_mode, "uid": value.st_uid, "gid": value.st_gid,
            "nlink": value.st_nlink, "size": value.st_size,
            "mtime_ns": value.st_mtime_ns, "ctime_ns": value.st_ctime_ns}


def tree_snapshot(work):
    root = os.fsencode(work)
    rows = []
    def visit(relative):
        path = root + (b"/" + relative if relative else b"")
        st = os.lstat(path)
        row = {"path_hex": relative.hex(), "stat": stat_identity(st)}
        if stat.S_ISDIR(st.st_mode):
            row["kind"] = "directory"
            with os.scandir(path) as entries:
                children = sorted(entry.name for entry in entries)
            rows.append(row)
            for name in children:
                visit(relative + b"/" + name if relative else name)
        elif stat.S_ISREG(st.st_mode):
            need(st.st_nlink == 1, "fixture file has unexpected hard links")
            payload = ordinary(os.fsdecode(path))
            row.update(kind="file", payload_hex=payload.hex(), payload=pin(payload))
            rows.append(row)
        elif stat.S_ISLNK(st.st_mode):
            row.update(kind="symlink", target_hex=os.readlink(path).hex())
            rows.append(row)
        else:
            raise ValueError("unregistered special fixture")
    visit(b"")
    return rows


def identity_equal(actual, expected, *, stable=False):
    keys = ("device", "inode", "mode", "uid", "gid") if stable else tuple(expected)
    return all(actual.get(key) == expected[key] for key in keys)


def setup_case(work, spec):
    work.mkdir(mode=0o700)
    os.chmod(work, 0o700)
    root = os.fsencode(work)
    for row in spec["setup"]:
        relative = bytes.fromhex(row["path_hex"])
        need(relative and not relative.startswith(b"/") and b".." not in relative.split(b"/"), "unsafe setup")
        path = root + b"/" + relative
        if row["kind"] == "directory":
            os.mkdir(path, row["mode"])
            os.chmod(path, row["mode"])
        elif row["kind"] == "file":
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, row["mode"])
            try:
                payload = bytes.fromhex(row["payload_hex"])
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(payload)
                os.fchmod(fd, row["mode"])
            finally:
                os.close(fd)
        else:
            os.symlink(bytes.fromhex(row["target_hex"]), path)


def decode_result(raw):
    need(len(raw) == 32 and raw[:8] == b"HSHMKR01", "result header")
    kind, value, cache = struct.unpack_from("<3Q", raw, 8)
    need(kind in (0, 1, 2) and cache in (0, 1, 2), "result kind/cache")
    need((kind == 1 and 1 <= value <= 4095) or (kind != 1 and value == 0), "result value")
    return {"kind": kind, "value": value, "cache": cache}


def decode_effects(raw):
    position, records = 0, []
    while position + 8 <= len(raw) and raw[position:position + 8] == b"HSHMKTR1":
        need(position + 192 <= len(raw), "truncated effect header")
        h = struct.unpack_from("<12Q", raw, position)
        slot = raw[position + 96:position + 192]
        size = 192 + h[9] + h[10]
        need(size <= len(raw) - position and h[11] == 0, "effect extent/reserved")
        records.append({"header": h, "slot": slot,
                        "path": raw[position + 192:position + 192 + h[9]],
                        "metadata": raw[position + 192 + h[9]:position + size]})
        position += size
    need(len(raw) - position == 128 and raw[position:position + 8] == b"HSHMKAU1", "missing effect footer")
    return records, struct.unpack_from("<16Q", raw, position)


def decode_entries(raw):
    position, records = 0, []
    while position + 8 <= len(raw) and raw[position:position + 8] == b"HSHMKEN1":
        need(position + 96 <= len(raw), "truncated entry header")
        h = struct.unpack_from("<12Q", raw, position)
        need(h[10:] == (0, 0) and h[6] == 64, "entry capacity/reserved")
        size = 96 + h[5] + h[6] + h[7] + 96
        need(size <= len(raw) - position, "entry extent")
        at = position + 96
        arrays = []
        for capacity in h[5:8]:
            arrays.append(raw[at:at + capacity + 32])
            at += capacity + 32
        records.append({"header": h, "arrays": arrays})
        position += size
    need(len(raw) - position == 128 and raw[position:position + 8] == b"HSHMKAU1", "missing entry footer")
    return records, struct.unpack_from("<16Q", raw, position)


def replay_policy(path, seed, operations):
    """Replay the original two loops against complete actual kernel returns."""
    cursor, cache = 0, seed
    def take(action, selected):
        nonlocal cursor
        need(cursor < len(operations), "missing semantic effect")
        value = operations[cursor]
        cursor += 1
        need(value["action"] == action and value["path"] == selected, "effect violates original path/order")
        return value
    def is_dir(selected):
        nonlocal cache
        if cache != 2:
            value = take(2, selected)
            if value["errno"] == 0:
                cache = 1
                return value["mode"] & 0o170000 == 0o040000
            if cache == 1:
                return False
            probe = take(3, b"")
            if probe["errno"] == 14:
                cache = 1
                return False
            cache = 2
        value = take(4, selected)
        return value["errno"] == 0 and value["mode"] & 0o170000 == 0o040000
    def complete(kind, value):
        need(cursor == len(operations), "extraneous filesystem effects")
        return {"kind": kind, "value": value, "cache": cache}
    if path == b"" or rust_parent(path) is None:
        return complete(0, 0)
    if b"\0" in path:
        return complete(2, 0)
    current, pending = path, []
    while current != b"" and rust_parent(current) is not None:
        call = take(1, current)
        error = call["errno"]
        if error == 0:
            break
        if error == 2:
            pending.append(current)
            current = rust_parent(current)
            continue
        if error == 17 and is_dir(current):
            break
        return complete(1, error)
    for current in reversed(pending):
        error = take(1, current)["errno"]
        if error and not (error == 17 and is_dir(current)):
            return complete(1, error)
    return complete(0, 0)


def validate_tree(rows):
    need(type(rows) is list and rows and rows[0].get("path_hex") == "", "tree root")
    result = {}
    for row in rows:
        need(type(row) is dict and type(row.get("path_hex")) is str, "tree row")
        path = bytes.fromhex(row["path_hex"])
        need(path.hex() == row["path_hex"] and path not in result, "duplicate/noncanonical tree path")
        need(not path.startswith(b"/") and b"\0" not in path
             and (not path or all(c not in (b"", b".", b"..") for c in path.split(b"/"))), "tree escape")
        value = row.get("stat")
        need(type(value) is dict and set(value) == {"device", "inode", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns"}, "tree identity fields")
        need(all(type(x) is int and x >= 0 for x in value.values()) and value["inode"] > 0, "tree identity numbers")
        kind = row.get("kind")
        expected_type = {"directory": stat.S_IFDIR, "file": stat.S_IFREG, "symlink": stat.S_IFLNK}.get(kind)
        need(expected_type is not None and stat.S_IFMT(value["mode"]) == expected_type, "tree type/mode")
        if kind == "file":
            payload = bytes.fromhex(row["payload_hex"])
            need(row.get("payload") == pin(payload) and value["size"] == len(payload) and value["nlink"] == 1, "tree payload")
            need(set(row) == {"path_hex", "stat", "kind", "payload_hex", "payload"}, "file row fields")
        elif kind == "symlink":
            target = bytes.fromhex(row["target_hex"])
            need(target and b"\0" not in target and value["size"] == len(target), "tree symlink target")
            need(set(row) == {"path_hex", "stat", "kind", "target_hex"}, "link row fields")
        else:
            need(set(row) == {"path_hex", "stat", "kind"}, "directory row fields")
        if path:
            parent = path.rsplit(b"/", 1)[0] if b"/" in path else b""
            need(parent in result and result[parent]["kind"] == "directory", "tree parent/preorder")
        result[path] = row
    need(result[b""]["kind"] == "directory", "fixture root not directory")
    return result


def verify_setup(rows, spec):
    tree = validate_tree(rows)
    need(set(tree) == {b""} | {bytes.fromhex(r["path_hex"]) for r in spec["setup"]}, "initial fixture inventory")
    need(stat.S_IMODE(tree[b""]["stat"]["mode"]) == 0o700, "initial root mode")
    for expected in spec["setup"]:
        actual = tree[bytes.fromhex(expected["path_hex"])]
        need(actual["kind"] == expected["kind"] and stat.S_IMODE(actual["stat"]["mode"]) == expected["mode"], "setup kind/mode")
        for key in ("payload_hex", "target_hex"):
            if key in expected:
                need(actual.get(key) == expected[key], "setup payload/target")
    return tree


def virtual_path(raw, work, tree):
    root = os.fsencode(work)
    if raw.startswith(b"/"):
        need(raw.startswith(root + b"/"), "effect outside owned work tree")
        raw = raw[len(root) + 1:]
    queue, components, followed = raw.split(b"/"), [], 0
    while queue:
        item = queue.pop(0)
        if item in (b"", b"."):
            continue
        if item == b"..":
            need(components, "fixture parent escape")
            components.pop()
            continue
        candidate = b"/".join(components + [item])
        row = tree.get(candidate)
        if row and row["kind"] == "symlink":
            followed += 1
            need(followed <= 40, "successful syscall traversed a symlink loop")
            target = bytes.fromhex(row["target_hex"])
            need(not target.startswith(b"/"), "fixture contains an external symlink")
            queue = target.split(b"/") + queue
        else:
            components.append(item)
    return b"/".join(components)


def verify_filesystem(before_rows, after_rows, spec, work, operations):
    before = verify_setup(before_rows, spec)
    after = validate_tree(after_rows)
    expected = copy.deepcopy(before)
    created = []
    for operation in operations:
        if operation["errno"] != 0:
            continue
        if operation["action"] == 1:
            selected = virtual_path(operation["path"], work, expected)
            need(selected not in expected and selected in after, "successful mkdir did not create an owned directory")
            expected[selected] = after[selected]
            created.append(selected)
            need(after[selected]["kind"] == "directory" and
                 stat.S_IMODE(after[selected]["stat"]["mode"]) == 0o777 & ~spec["umask"], "created directory mode/umask")
        elif operation["action"] in (2, 4):
            selected = virtual_path(operation["path"], work, expected)
            need(selected in expected, "metadata target missing in actual tree")
            row = expected[selected]
            need(operation["mode"] == row["stat"]["mode"], "metadata mode differs from retained inode")
            data = operation["metadata"]
            if operation["action"] == 2:
                inode = struct.unpack_from("<Q", data, 32)[0]
                device = os.makedev(*struct.unpack_from("<II", data, 136))
            else:
                device, inode = struct.unpack_from("<QQ", data)
            need((device, inode) == (row["stat"]["device"], row["stat"]["inode"]), "metadata inode differs from fixture")
    need(set(after) == set(expected), "unexplained final fixture entries")
    for path, row in before.items():
        actual = after[path]
        need(actual["kind"] == row["kind"] and identity_equal(actual["stat"], row["stat"], stable=row["kind"] == "directory"), "existing fixture identity changed")
        for key in ("payload_hex", "target_hex", "payload"):
            need(actual.get(key) == row.get(key), "existing file/link content changed")
    return {"initial_entries": len(before), "final_entries": len(after),
            "created_directories": len(created), "created_paths_hex": [p.hex() for p in created]}


def verify_execution(folder, spec, native_manifest, metadata, wire):
    receipt = read_json(folder / "execution.json")
    observation = read_json(folder / "observation.json")
    stdout, stderr = ordinary(folder / "stdout.bin"), ordinary(folder / "stderr.bin")
    work = folder / "work"
    elf = native_manifest.parent / metadata["elf"]
    need(receipt.get("schema") == "hepta.runtime.shell-capture-mkdir-execution.v1", "execution schema")
    need(receipt.get("case_directory") == str(folder) and receipt.get("name") == spec["name"], "execution case path")
    need(receipt.get("argv") == [str(elf), "--mkdir-fixture", str(folder)], "actual argv")
    need(receipt.get("cwd") == str(work) and receipt.get("umask") == spec["umask"], "actual cwd/umask")
    need(receipt.get("environment") == {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TMPDIR": str(folder.parent.parent / "temporary")}, "actual environment")
    need(receipt.get("native_manifest") == {"path": str(native_manifest), **pin(ordinary(native_manifest))}
         and receipt.get("executable_before") == pin(ordinary(elf))
         and receipt.get("executable_after") == receipt["executable_before"], "actual native executable binding")
    need(receipt.get("exit_code") == 0 and receipt.get("timed_out") is False and receipt.get("exception") is None, "actual subprocess failed")
    need(receipt.get("deadline_ms") == 30000 and type(receipt.get("pid")) is int and receipt["pid"] > 1, "execution deadline/pid")
    start, finish = receipt.get("started_ns"), receipt.get("finished_ns")
    need(type(start) is int and type(finish) is int and 0 < start <= finish
         and receipt.get("duration_ns") == finish - start and finish - start <= 30_000_000_000, "execution timing")
    capacity = 512 + 10 * (len(wire) - 64 + 1)
    stdin = struct.pack("<QQ", len(wire), capacity) + wire
    need(ordinary(folder / "stdin.bin") == stdin and receipt.get("stdin") == pin(stdin), "complete actual stdin")
    need(receipt.get("stdout") == pin(stdout) and receipt.get("stderr") == pin(stderr) and stderr == b"", "actual process streams")
    need(len(stdout) == 112 and stdout[:8] == b"HSHMKRD1", "complete stdout framing")
    ready = struct.unpack_from("<8Q", stdout)
    need(ready[1] == receipt["pid"] and ready[2] == ready[1] and ready[3] > 2 and ready[4] > 2
         and ready[3] != ready[4] and ready[5:] == (1, 0, 0), "ready process/descriptor identity")
    need(struct.unpack_from("<QQ", stdout, 64) == (32, 32), "final stdout frame")
    need(observation.get("pid") == receipt["pid"] and observation.get("executable_hex") == os.fsencode(elf).hex()
         and observation.get("cwd_hex") == os.fsencode(work).hex(), "live ready observation")
    process_stat = bytes.fromhex(observation["proc_stat_hex"])
    need(int(process_stat.split(b" ", 1)[0]) == receipt["pid"], "proc observation pid")
    fields = process_stat.rsplit(b")", 1)[1].split()
    need(len(fields) >= 20 and int(fields[1]) == receipt["producer_pid"]
         and int(fields[19]) == observation["starttime"] > 0, "ready custody identity")
    need(start <= observation.get("observed_ns", 0) <= finish, "observation outside real process")
    for fd, name in ((ready[3], "effects.bin"), (ready[4], "entries.bin")):
        observed = observation["fds"][name]
        need(observed["fd"] == fd and observed["target_hex"] == os.fsencode(folder / name).hex(), "ready owned trace descriptor")
        end = receipt["trace_file_stats"][name]
        need(identity_equal(end, observed["stat"], stable=True) and stat.S_ISREG(end["mode"])
             and end["nlink"] == 1 and stat.S_IMODE(end["mode"]) == 0o600
             and observed["stat"]["size"] == 0 and end["size"] == len(ordinary(folder / name)), "trace descriptor inode/extent")
    need(receipt.get("uid") == read_json(folder / "before.json")[0]["stat"]["uid"], "fixture uid")
    if spec["name"] == "permission_denied":
        need(receipt["uid"] != 0, "permission case requires an unprivileged owner")
    return receipt, ready, stdout[80:], capacity


def verify_native_arrays(folder, wire, capacity, receipt, ready, result):
    traces, footer = decode_effects(ordinary(folder / "effects.bin"))
    entries, entry_footer = decode_entries(ordinary(folder / "entries.bin"))
    need(footer == entry_footer and footer[1] == receipt["pid"] and footer[6:8] == (0, 0)
         and footer[8:13] == (32, 32, len(wire), capacity, 64)
         and footer[13:15] == ready[3:5] and footer[15] == 0, "complete matching audit footers")
    need(len(traces) % 2 == 0 and len(entries) % 2 == 0, "unpaired trace/entry")
    count = len(traces) // 2
    need(footer[2] == len(entries) // 2 == count + 1 and footer[3:6] == (count, count, count), "audit counts")
    operations = []
    for index in range(count):
        issue, done = traces[2 * index:2 * index + 2]
        ih, dh = issue["header"], done["header"]
        si, sd = struct.unpack("<12Q", issue["slot"]), struct.unpack("<12Q", done["slot"])
        need(ih[1:5] == (index + 1, 0, receipt["pid"], receipt["pid"])
             and dh[1:5] == (index + 1, 1, receipt["pid"], receipt["pid"]), "effect pair identity/order")
        need(issue["slot"][:8] == b"HSHMKFX1" and si[1] == index + 1 and si[2] in (1, 2, 3, 4)
             and si[6:] == (0,) * 6 and sd[:6] == si[:6] and sd[6] == 1 and sd[10:] == (0, 0), "private slot issuance/completion")
        action = si[2]
        need(si[5] == {1: 511, 2: 4095, 3: 4095, 4: 0}[action], "kernel fixed argument")
        need(ih[5] == dh[5] == {1: 83, 2: 332, 3: 332, 4: 262}[action], "actual syscall number")
        need(ih[6:9] == (0, 0, 0) and not issue["metadata"] and issue["path"] == done["path"], "issue payload/result")
        need(dh[6:9] == sd[7:10], "raw syscall completion differs from owner mailbox")
        error, mode = dh[7:9]
        need((error == 0 and dh[6] == 0) or (1 <= error <= 4095 and dh[6] == (-error & MASK) and mode == 0), "raw errno conversion")
        if action == 3:
            need(si[3:5] == (0, 0) and issue["path"] == b"", "NULL availability probe")
        else:
            need(len(issue["path"]) == si[4] and b"\0" not in issue["path"], "actual C-string path")
        data = done["metadata"]
        need(len(data) == {1: 0, 2: 256, 3: 0, 4: 144}[action], "complete syscall metadata bytes")
        if error == 0:
            observed_mode = struct.unpack_from("<H", data, 28)[0] if action == 2 else struct.unpack_from("<I", data, 24)[0] if action == 4 else 0
            need(mode == observed_mode, "original metadata mode")
        operations.append({"action": action, "path": done["path"], "errno": error, "mode": mode,
                           "raw": dh[6], "metadata": data})
    previous = None
    last_time = receipt["started_ns"]
    guards = ((0xc1, 0xc2), (0xa5, 0xa6), (0x5a, 0x5b))
    for index in range(count + 1):
        before, after = entries[2 * index:2 * index + 2]
        for phase, record in enumerate((before, after)):
            h = record["header"]
            need(h[1:8] == (index + 1, phase, receipt["pid"], receipt["pid"], len(wire), 64, capacity), "native entry identity/extent")
            need(last_time <= h[9] <= receipt["finished_ns"], "actual native entry timing")
            last_time = h[9]
            for array, size, pair in zip(record["arrays"], (len(wire), 64, capacity), guards):
                need(len(array) == size + 32 and array[:16] == bytes([pair[0]]) * 16 and array[-16:] == bytes([pair[1]]) * 16, "native memory guards")
        b = [a[16:-16] for a in before["arrays"]]
        a = [a[16:-16] for a in after["arrays"]]
        need(before["header"][8] == 0 and a[0] == b[0], "native input immutability")
        expected_input = wire if index == 0 else wire[:8] + struct.pack("<QQ", 2, 0) + wire[24:]
        need(b[0] == expected_input, "fixed continuation input")
        if previous is None:
            need(b[1] == b"\xa7" * 64 and b[2] == b"\x5c" * capacity, "initial borrowed contents")
        else:
            expected_work = bytearray(previous[2])
            expected_work[96:192] = traces[2 * index - 1]["slot"]
            need(b[1] == previous[1] and b[2] == expected_work, "bridge wrote outside actual completion")
        returned = after["header"][8]
        if index < count:
            need(returned == PENDING and a[1] == b[1], "pending native output changed")
            issue = traces[2 * index]
            need(a[2][96:192] == issue["slot"], "issued effect differs from actual HIA entry")
            fields = struct.unpack("<12Q", issue["slot"])
            if fields[2] != 3:
                offset, length = fields[3:5]
                need(offset == 513 + len(wire) - 64, "canonical HIA path borrow")
                need(offset + length < capacity and a[2][offset:offset + length + 1] == issue["path"] + b"\0", "actual HIA path borrow")
        else:
            need(returned == 32 and a[1][:32] == result and a[1][32:] == b"\xa7" * 32, "actual complete result/tail")
        previous = a
    return operations, {"native_entries": count + 1, "native_arrays": (count + 1) * 6,
                        "syscalls": count, "syscall_records": count * 2,
                        "actual_null_statx_probes": sum(o["action"] == 3 for o in operations),
                        "actual_stat64_calls": sum(o["action"] == 4 for o in operations)}


def ordered_retirement(rows):
    return sorted(rows, key=lambda row: (bytes.fromhex(row["path_hex"]).count(b"/"), len(bytes.fromhex(row["path_hex"])), row["path_hex"]), reverse=True)


def retire_case(folder, after_rows, validation):
    work = folder / "work"
    need(tree_snapshot(work) == after_rows, "fixture changed before retirement")
    rows = validate_tree(after_rows)
    deletion = []
    for row in ordered_retirement(after_rows):
        relative = bytes.fromhex(row["path_hex"])
        path = os.fsencode(work) + (b"/" + relative if relative else b"")
        current = stat_identity(os.lstat(path))
        need(identity_equal(current, row["stat"], stable=row["kind"] == "directory"), "fixture identity changed before deletion")
        if row["kind"] == "directory":
            with os.scandir(path) as entries:
                need(not list(entries), "refusing to delete nonempty or unknown directory")
            os.rmdir(path)
        else:
            os.unlink(path)
        absent = not os.path.lexists(path)
        need(absent, "retired fixture path remains")
        deletion.append({"path_hex": row["path_hex"], "kind": row["kind"],
                         "observed_before": current, "absent_after": True})
    receipt = {"schema": "hepta.runtime.shell-capture-mkdir-retirement.v1", "status": "PASS",
               "recorded_directory": str(folder), "owned_root": str(work),
               "sealed_tree": after_rows, "sealed_tree_sha256": sha(json_bytes(after_rows)),
               "validation_sha256": sha(json_bytes(validation)), "deletions": deletion,
               "root_absent_after": not os.path.lexists(work), **SCOPE}
    write_new(folder / "retirement.json", json_bytes(receipt))


def verify_retirement(folder, after_rows, validation):
    value = read_json(folder / "retirement.json")
    need(value.get("schema") == "hepta.runtime.shell-capture-mkdir-retirement.v1" and value.get("status") == "PASS"
         and value.get("recorded_directory") == str(folder) and value.get("owned_root") == str(folder / "work"), "retirement identity")
    need(value.get("sealed_tree") == after_rows and value.get("sealed_tree_sha256") == sha(json_bytes(after_rows))
         and value.get("validation_sha256") == sha(json_bytes(validation)), "retirement sealed bytes")
    need(value.get("root_absent_after") is True and not os.path.lexists(folder / "work"), "retired root has reappeared")
    expected = ordered_retirement(after_rows)
    actual = value.get("deletions")
    need(type(actual) is list and len(actual) == len(expected), "retirement complete deletion set")
    for event, row in zip(actual, expected):
        need(type(event) is dict and set(event) == {"path_hex", "kind", "observed_before", "absent_after"}
             and event["path_hex"] == row["path_hex"] and event["kind"] == row["kind"]
             and event["absent_after"] is True
             and identity_equal(event["observed_before"], row["stat"], stable=row["kind"] == "directory"), "retirement identity/type ordering")
    need(all(value.get(k) is v for k, v in SCOPE.items()), "retirement overstates scope")


def source_pins():
    return {name: pin(ordinary(ROOT / name)) for name in SOURCE_NAMES}


def load_native(native_manifest):
    native_manifest = Path(native_manifest).absolute()
    sys.path.insert(0, str(ROOT / "scripts"))
    from hia_native_shell_capture_mkdir_build import read_evidence
    checked = read_evidence(native_manifest, source_root=ROOT)
    need(checked.get("status") == "PASS", "native build strong reader")
    metadata = read_json(native_manifest)
    return native_manifest, metadata, checked


def _read_case(folder, native_manifest, metadata, *, require_retired=True):
    folder = Path(folder).absolute()
    plain_directory(folder)
    spec = read_json(folder / "spec.json")
    registered = {s["name"]: s for s in case_specs()}
    need(spec.get("name") in registered and spec == registered[spec["name"]], "case differs from registered input")
    need(folder.name == spec["name"], "case directory/name")
    wire = input_for(spec, folder / "work")
    need(ordinary(folder / "input.bin") == wire, "owner input bytes")
    receipt, ready, result, capacity = verify_execution(folder, spec, native_manifest, metadata, wire)
    operations, counts = verify_native_arrays(folder, wire, capacity, receipt, ready, result)
    projected = replay_policy(path_for(spec, folder / "work"), spec["cache_seed"], operations)
    need(decode_result(result) == projected, "native result differs from original blocking algorithm")
    before, after = read_json(folder / "before.json"), read_json(folder / "after.json")
    filesystem = verify_filesystem(before, after, spec, folder / "work", operations)
    for row in after:
        if row["path_hex"] in filesystem["created_paths_hex"]:
            need((row["stat"]["uid"], row["stat"]["gid"]) == (receipt["uid"], receipt["gid"]), "created directory ownership")
    validation = {"schema": "hepta.runtime.shell-capture-mkdir-case.v1", "status": "PASS",
                  "name": spec["name"], "result": projected, "counts": counts,
                  "filesystem": filesystem, "actual_kernel_syscalls": True,
                  "original_fresh_cache_comparable": spec["original_fresh_cache_comparable"], **SCOPE}
    if require_retired:
        verify_retirement(folder, after, validation)
    else:
        need(tree_snapshot(folder / "work") == after, "live final tree changed")
    return {"validation": validation, "wire": wire, "result_bytes": result,
            "path": path_for(spec, folder / "work"), "operations": operations,
            "before": before, "after": after, "spec": spec}


def read_case(folder, native_manifest):
    manifest, metadata, _ = load_native(native_manifest)
    return _read_case(folder, manifest, metadata)


def core_file_names(names):
    return ["source-snapshots/" + name for name in SOURCE_NAMES] + [
        "cases/" + name + "/" + leaf for name in names for leaf in CASE_FILES]


def _read_corpus(folder, native_manifest, *, require_full=True, require_controls=True):
    folder = Path(folder).absolute()
    for path in (folder, folder / "cases", folder / "source-snapshots", folder / "temporary"):
        plain_directory(path)
    manifest, metadata, build = load_native(native_manifest)
    report = read_json(folder / "report.json")
    need(report.get("schema") == "hepta.runtime.shell-capture-mkdir-os-report.v1"
         and report.get("status") == "PASS" and report.get("recorded_directory") == str(folder), "corpus identity")
    need(report.get("native_manifest") == {"path": str(manifest), **pin(ordinary(manifest))}, "corpus native manifest")
    names = report.get("case_names")
    registered = [s["name"] for s in case_specs()]
    need(type(names) is list and names and len(set(names)) == len(names)
         and all(n in registered for n in names), "registered case inventory")
    if require_full:
        need(names == registered and report.get("complete_registered_corpus") is True, "incomplete registered corpus")
    else:
        need(names == [n for n in registered if n in names]
             and report.get("complete_registered_corpus") is (names == registered), "subset order/claim")
    need(set(os.listdir(folder / "cases")) == set(names), "case directory set")
    expected_sources = source_pins()
    need(report.get("sources") == expected_sources, "current producer/source identity")
    for name in SOURCE_NAMES:
        path = folder / "source-snapshots" / name
        for parent in path.parents:
            if parent == folder:
                break
            plain_directory(parent)
        raw = ordinary(path)
        need(pin(raw) == expected_sources[name] and raw == ordinary(ROOT / name), "sealed source bytes")
    files = report.get("files")
    need(type(files) is dict and set(files) == set(core_file_names(names)), "full retained file inventory")
    for name in files:
        need(pin(ordinary(folder / name)) == files[name], "retained file bytes changed: " + name)
    cases, counts = [], {}
    for name in names:
        current = folder / "cases" / name
        need(set(os.listdir(current)) == set(CASE_FILES), "unexpected case evidence member")
        checked = _read_case(current, manifest, metadata)
        value = checked["validation"]
        cases.append(value)
        for key, amount in value["counts"].items():
            counts[key] = counts.get(key, 0) + amount
    counts.update(cases=len(names), retired_fixtures=len(names),
                  original_fresh_cache_cases=sum(c["original_fresh_cache_comparable"] for c in cases),
                  kernel_errno_injected=0)
    need(report.get("cases") == cases and report.get("counts") == counts, "reported cases/counts differ from raw evidence")
    need(all(report.get(key) is value for key, value in SCOPE.items()), "corpus overstates scope")
    controls = None
    if require_controls:
        controls = read_controls(folder, manifest)
        need(report.get("physical_controls") == controls, "physical control qualification")
    return {"schema": "hepta.runtime.shell-capture-mkdir-os-evidence.v1", "status": "PASS",
            "recorded_directory": str(folder), "native_manifest": report["native_manifest"],
            "complete_registered_corpus": names == registered, "counts": counts,
            "cases": cases, "retired_fixtures": len(names), "source_files": len(SOURCE_NAMES),
            "strong_native_build": build, "physical_controls": controls,
            "verification": "current-source-and-recorded-path", **SCOPE}


def read_evidence(folder, native_manifest, *, require_full=True):
    return _read_corpus(folder, native_manifest, require_full=require_full, require_controls=True)


def read_ready(process, deadline):
    data = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while len(data) < 64:
            remaining = (deadline - time.monotonic_ns()) / 1e9
            need(remaining > 0 and selector.select(remaining), "ready deadline expired")
            chunk = os.read(process.stdout.fileno(), 64 - len(data))
            need(chunk, "native fixture exited before ready")
            data.extend(chunk)
    return bytes(data)


def observe_ready(process, raw, folder, elf, started):
    need(len(raw) == 64 and raw[:8] == b"HSHMKRD1", "actual ready magic")
    ready = struct.unpack("<8Q", raw)
    need(ready[1:3] == (process.pid, process.pid), "actual ready pid")
    base = Path("/proc") / str(process.pid)
    process_stat = (base / "stat").read_bytes()
    fields = process_stat.rsplit(b")", 1)[1].split()
    need(int(fields[1]) == os.getpid(), "ready process no longer owned")
    fds = {}
    for fd, name in ((ready[3], "effects.bin"), (ready[4], "entries.bin")):
        link = os.fsencode(base / "fd" / str(fd))
        target = os.readlink(link)
        value = os.stat(link)
        need(target == os.fsencode(folder / name) and stat.S_ISREG(value.st_mode), "trace FD does not name owned evidence")
        fds[name] = {"fd": fd, "target_hex": target.hex(), "stat": stat_identity(value)}
    return {"pid": process.pid, "proc_stat_hex": process_stat.hex(),
            "starttime": int(fields[19]), "observed_ns": time.monotonic_ns(),
            "executable_hex": os.readlink(os.fsencode(base / "exe")).hex(),
            "cwd_hex": os.readlink(os.fsencode(base / "cwd")).hex(), "fds": fds}


def run_case(folder, spec, manifest, metadata):
    folder.mkdir(mode=0o700)
    work = folder / "work"
    setup_case(work, spec)
    before = tree_snapshot(work)
    wire = input_for(spec, work)
    capacity = 512 + 10 * (len(wire) - 64 + 1)
    stdin = struct.pack("<QQ", len(wire), capacity) + wire
    write_new(folder / "spec.json", json_bytes(spec))
    write_new(folder / "before.json", json_bytes(before))
    write_new(folder / "input.bin", wire)
    write_new(folder / "stdin.bin", stdin)
    elf = manifest.parent / metadata["elf"]
    argv = [str(elf), "--mkdir-fixture", str(folder)]
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TMPDIR": str(folder.parent.parent / "temporary")}
    executable_before = pin(ordinary(elf))
    process = None
    started = time.monotonic_ns()
    deadline = started + 30_000_000_000
    ready, tail, stderr = b"", b"", b""
    observation, exception, timed_out = {}, None, False
    try:
        process = subprocess.Popen(argv, cwd=work, env=env, umask=spec["umask"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True, bufsize=0)
        ready = read_ready(process, deadline)
        observation = observe_ready(process, ready, folder, elf, started)
        remaining = (deadline - time.monotonic_ns()) / 1e9
        need(remaining > 0, "deadline before request")
        tail, stderr = process.communicate(stdin, timeout=remaining)
    except Exception as error:
        exception = {"type": type(error).__name__, "message": str(error)}
        timed_out = isinstance(error, subprocess.TimeoutExpired)
        if process is not None:
            if process.poll() is None:
                process.kill()
            tail, stderr = process.communicate(timeout=5)
    finished = time.monotonic_ns()
    stdout = ready + tail
    after = tree_snapshot(work)
    write_new(folder / "stdout.bin", stdout)
    write_new(folder / "stderr.bin", stderr)
    write_new(folder / "observation.json", json_bytes(observation))
    write_new(folder / "after.json", json_bytes(after))
    receipt = {"schema": "hepta.runtime.shell-capture-mkdir-execution.v1", "name": spec["name"],
               "case_directory": str(folder), "argv": argv, "cwd": str(work), "environment": env,
               "umask": spec["umask"], "uid": os.geteuid(), "gid": os.getegid(), "producer_pid": os.getpid(),
               "pid": process.pid if process else None, "started_ns": started, "finished_ns": finished,
               "duration_ns": finished - started, "deadline_ms": 30000,
               "exit_code": process.returncode if process else None, "timed_out": timed_out, "exception": exception,
               "native_manifest": {"path": str(manifest), **pin(ordinary(manifest))},
               "executable_before": executable_before, "executable_after": pin(ordinary(elf)),
               "stdin": pin(stdin), "stdout": pin(stdout), "stderr": pin(stderr),
               "trace_file_stats": {n: stat_identity((folder / n).lstat()) for n in ("effects.bin", "entries.bin") if (folder / n).exists()}}
    write_new(folder / "execution.json", json_bytes(receipt))
    try:
        checked = _read_case(folder, manifest, metadata, require_retired=False)
    except Exception as error:
        failed = {"status": "FAIL", "type": type(error).__name__, "message": str(error)}
        write_new(folder / "failure.json", json_bytes(failed))
        retire_case(folder, after, failed)
        raise
    retire_case(folder, after, checked["validation"])
    return _read_case(folder, manifest, metadata)["validation"]


CONTROL_NAMES = (
    "missing_case", "duplicate_case", "input_path", "native_result", "effect_pid",
    "effect_action", "effect_errno", "metadata_mode", "entry_guard", "bridge_extra_write",
    "path_borrow_offset", "missing_footer", "retired_payload", "source_snapshot",
)
CONTROL_ERRORS = {
    "missing_case": "incomplete registered corpus",
    "duplicate_case": "registered case inventory",
    "input_path": "owner input bytes",
    "native_result": "actual complete result/tail",
    "effect_pid": "effect pair identity/order",
    "effect_action": "complete syscall metadata bytes",
    "effect_errno": "bridge wrote outside actual completion",
    "metadata_mode": "bridge wrote outside actual completion",
    "entry_guard": "native memory guards",
    "bridge_extra_write": "bridge wrote outside actual completion",
    "path_borrow_offset": "canonical HIA path borrow",
    "missing_footer": "missing effect footer",
    "retired_payload": "existing file/link content changed",
    "source_snapshot": "sealed source bytes",
}


def control_recipe(name, baseline):
    need(name in CONTROL_NAMES, "unknown physical control")
    data = dict(baseline)
    report = strict_json(data["report.json"])
    def qword(path, offset, value):
        changed = bytearray(data[path])
        struct.pack_into("<Q", changed, offset, value)
        data[path] = bytes(changed)
    if name == "missing_case":
        report["case_names"].pop()
    elif name == "duplicate_case":
        report["case_names"].append(report["case_names"][0])
    elif name == "input_path":
        path = "cases/new_leaf/input.bin"
        data[path] = data[path][:-1] + b"X"
        path = "cases/new_leaf/stdin.bin"
        data[path] = data[path][:-1] + b"X"
    elif name == "native_result":
        path = "cases/new_leaf/stdout.bin"
        qword(path, 88, 1)
        qword(path, 96, 2)
    elif name in ("effect_pid", "effect_action", "effect_errno"):
        path = "cases/new_leaf/effects.bin"
        records, _ = decode_effects(data[path])
        completion = 192 + len(records[0]["path"])
        if name == "effect_pid":
            for at in (0, completion):
                qword(path, at + 24, records[0]["header"][3] + 10000)
        elif name == "effect_action":
            for at in (0, completion):
                qword(path, at + 96 + 16, 4)
                qword(path, at + 96 + 40, 0)
                qword(path, at + 40, 262)
        else:
            qword(path, completion + 48, -5 & MASK)
            qword(path, completion + 56, 5)
            qword(path, completion + 96 + 56, -5 & MASK)
            qword(path, completion + 96 + 64, 5)
    elif name == "metadata_mode":
        path = "cases/existing_directory/effects.bin"
        records, _ = decode_effects(data[path])
        position = 0
        for row in records:
            slot = struct.unpack("<12Q", row["slot"])
            if slot[2] == 2 and row["header"][2] == 1:
                mode = stat.S_IFREG | 0o644
                qword(path, position + 64, mode)
                qword(path, position + 96 + 72, mode)
                changed = bytearray(data[path])
                struct.pack_into("<H", changed, position + 192 + len(row["path"]) + 28, mode)
                data[path] = bytes(changed)
                break
            position += 192 + len(row["path"]) + len(row["metadata"])
        else:
            raise ValueError("registered metadata control lacks actual statx")
    elif name in ("entry_guard", "bridge_extra_write"):
        path = "cases/new_leaf/entries.bin"
        records, _ = decode_entries(data[path])
        size = 96 + sum(len(a) for a in records[0]["arrays"])
        offset = size + 96 if name == "entry_guard" else 2 * size + 96 + len(records[0]["arrays"][0]) + len(records[0]["arrays"][1]) + 16 + 300
        changed = bytearray(data[path]); changed[offset] ^= 1; data[path] = bytes(changed)
    elif name == "path_borrow_offset":
        path = "cases/new_leaf/effects.bin"
        records, _ = decode_effects(data[path])
        position = 0
        for row in records:
            qword(path, position + 96 + 24, 512)
            position += 192 + len(row["path"]) + len(row["metadata"])
        path = "cases/new_leaf/entries.bin"
        records, _ = decode_entries(data[path])
        position = 0
        for row in records:
            work = row["arrays"][2][16:-16]
            if work[96:104] == b"HSHMKFX1":
                qword(path, position + 96 + len(row["arrays"][0]) + len(row["arrays"][1]) + 16 + 96 + 24, 512)
            position += 96 + sum(len(a) for a in row["arrays"])
    elif name == "missing_footer":
        path = "cases/new_leaf/effects.bin"
        data[path] = data[path][:-128]
    elif name == "retired_payload":
        path = "cases/existing_file/after.json"
        rows = strict_json(data[path])
        row = next(r for r in rows if r["kind"] == "file")
        payload = bytes.fromhex(row["payload_hex"])
        payload = bytes([payload[0] ^ 1]) + payload[1:]
        row["payload_hex"], row["payload"] = payload.hex(), pin(payload)
        data[path] = json_bytes(rows)
        path = "cases/existing_file/retirement.json"
        receipt = strict_json(data[path])
        receipt["sealed_tree"], receipt["sealed_tree_sha256"] = rows, sha(json_bytes(rows))
        data[path] = json_bytes(receipt)
    elif name == "source_snapshot":
        path = "source-snapshots/native/shell_capture_mkdir.hepta"
        data[path] = b"X" + data[path][1:]
    for case in report["case_names"]:
        path = "cases/" + case + "/execution.json"
        receipt = strict_json(data[path])
        for field in ("stdin", "stdout", "stderr"):
            receipt[field] = pin(data["cases/" + case + "/" + field + ".bin"])
        for leaf in ("effects.bin", "entries.bin"):
            receipt["trace_file_stats"][leaf]["size"] = len(data["cases/" + case + "/" + leaf])
        data[path] = json_bytes(receipt)
    for path in report["files"]:
        report["files"][path] = pin(data[path])
    data["report.json"] = json_bytes(report)
    changed = {p: raw for p, raw in data.items() if raw != baseline[p]}
    need(changed, "control did not change physical bytes")
    return changed


def reader_process(folder, corpus, manifest, mode="--verify-core"):
    python = Path(sys.executable).resolve(strict=True)
    source = Path(__file__).absolute()
    argv = [str(python), str(source), "--native-manifest", str(manifest), mode, str(corpus)]
    tool, producer = pin(ordinary(python)), pin(ordinary(source))
    paths = core_file_names([s["name"] for s in case_specs()]) + ["report.json"]
    evidence_before = {p: pin(ordinary(corpus / p)) for p in paths}
    started = time.monotonic_ns()
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": str(corpus / "temporary")}
    process = subprocess.Popen(argv, cwd=ROOT, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        stdout, stderr = process.communicate(timeout=5)
    finished = time.monotonic_ns()
    write_new(folder / "stdout.bin", stdout)
    write_new(folder / "stderr.bin", stderr)
    receipt = {"schema": "hepta.runtime.shell-capture-mkdir-reader-process.v1", "argv": argv,
               "cwd": str(ROOT), "environment": env, "pid": process.pid, "started_ns": started, "finished_ns": finished,
               "duration_ns": finished - started, "deadline_ms": 30000, "timed_out": timed_out,
               "exit_code": process.returncode, "stdout": pin(stdout), "stderr": pin(stderr),
               "python_before": tool, "python_after": pin(ordinary(python)),
               "source_before": producer, "source_after": pin(ordinary(source)),
               "evidence_before": evidence_before, "evidence_after": {p: pin(ordinary(corpus / p)) for p in paths}}
    write_new(folder / "execution.json", json_bytes(receipt))
    return receipt, stdout, stderr


def replace_ordinary(path, raw, expected=None):
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "mutation target is not ordinary")
    if expected is not None:
        need((before.st_dev, before.st_ino, before.st_mode) == (expected["device"], expected["inode"], expected["mode"]), "refusing to replace changed mutation target")
    fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        need((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), "mutation target changed")
        os.ftruncate(fd, 0)
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            need(written > 0, "mutation write failed")
            view = view[written:]
        after = os.fstat(fd)
        need((after.st_dev, after.st_ino, after.st_mode) == (before.st_dev, before.st_ino, before.st_mode), "mutation changed file identity")
    finally:
        os.close(fd)
    return {"device": before.st_dev, "inode": before.st_ino, "mode": before.st_mode}


def run_controls(corpus, manifest):
    controls = corpus / "controls"
    controls.mkdir(mode=0o700)
    raw_report = ordinary(corpus / "report.json")
    report = strict_json(raw_report)
    baseline = {name: ordinary(corpus / name) for name in core_file_names(report["case_names"])}
    baseline["report.json"] = raw_report
    identities = {p: {"device": (s := (corpus / p).lstat()).st_dev, "inode": s.st_ino, "mode": s.st_mode} for p in baseline}
    write_new(controls / "baseline-report.json", raw_report)
    all_rows = []
    for name in CONTROL_NAMES:
        target = controls / name
        target.mkdir()
        changed = control_recipe(name, baseline)
        mutations = []
        try:
            for index, path in enumerate(sorted(changed)):
                need(ordinary(corpus / path) == baseline[path], "baseline changed before mutation")
                identity = replace_ordinary(corpus / path, changed[path], identities[path])
                observed = ordinary(corpus / path)
                need(observed == changed[path], "physical mutation readback")
                prefix = f"{index:02d}"
                write_new(target / (prefix + ".before.bin"), baseline[path])
                write_new(target / (prefix + ".after.bin"), observed)
                mutations.append({"path": path, "prefix": prefix, "before": pin(baseline[path]),
                                  "after": pin(observed), "identity": identity})
            receipt, stdout, stderr = reader_process(target, corpus, manifest)
            rejected = strict_json(stdout)
            need(receipt["exit_code"] == 2 and not receipt["timed_out"] and stderr == b""
                 and rejected == {"status": "REJECTED", "error_type": "ValueError", "error": CONTROL_ERRORS[name]},
                 "physical mutation was not rejected at its named semantic gate: " + name)
        finally:
            for path in changed:
                replace_ordinary(corpus / path, baseline[path], identities[path])
            need(all(ordinary(corpus / path) == baseline[path] for path in changed), "baseline restoration failed")
        row = {"name": name, "mutations": mutations, "restored": True,
               "reader": {"execution": pin(ordinary(target / "execution.json")),
                          "stdout": pin(ordinary(target / "stdout.bin")), "stderr": pin(ordinary(target / "stderr.bin"))}}
        write_new(target / "control.json", json_bytes(row))
        all_rows.append(row)
    positive = controls / "restored-positive"
    positive.mkdir()
    receipt, stdout, stderr = reader_process(positive, corpus, manifest)
    need(receipt["exit_code"] == 0 and not receipt["timed_out"] and stderr == b""
         and strict_json(stdout).get("status") == "PASS", "restored independent positive failed")
    summary = {"schema": "hepta.runtime.shell-capture-mkdir-controls.v1", "status": "PASS",
               "control_names": list(CONTROL_NAMES), "controls": all_rows,
               "baseline_report": pin(raw_report), "restored_positive": {
                   n: pin(ordinary(positive / n)) for n in ("execution.json", "stdout.bin", "stderr.bin")}, **SCOPE}
    write_new(controls / "report.json", json_bytes(summary))
    return read_controls(corpus, manifest)


def verify_reader_process(folder, corpus, manifest, inputs, expected_exit, expected_error=None):
    receipt = read_json(folder / "execution.json")
    python = Path(sys.executable).resolve(strict=True)
    source = Path(__file__).absolute()
    need(receipt.get("schema") == "hepta.runtime.shell-capture-mkdir-reader-process.v1"
         and receipt.get("argv") == [str(python), str(source), "--native-manifest", str(manifest), "--verify-core", str(corpus)]
         and receipt.get("cwd") == str(ROOT), "actual reader command")
    need(receipt.get("environment") == {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": str(corpus / "temporary")}, "reader environment")
    need(receipt.get("python_before") == receipt.get("python_after") == pin(ordinary(python))
         and receipt.get("source_before") == receipt.get("source_after") == pin(ordinary(source)), "actual reader implementation/tool")
    need(receipt.get("evidence_before") == receipt.get("evidence_after") == {p: pin(raw) for p, raw in inputs.items()}, "reader actual input bytes")
    need(receipt.get("exit_code") == expected_exit and receipt.get("timed_out") is False
         and receipt.get("deadline_ms") == 30000 and type(receipt.get("pid")) is int and receipt["pid"] > 1, "actual reader process outcome")
    start, finish = receipt.get("started_ns"), receipt.get("finished_ns")
    need(type(start) is int and type(finish) is int and 0 < start <= finish
         and receipt.get("duration_ns") == finish - start <= 30_000_000_000, "reader deadline timing")
    stdout, stderr = ordinary(folder / "stdout.bin"), ordinary(folder / "stderr.bin")
    need(receipt.get("stdout") == pin(stdout) and receipt.get("stderr") == pin(stderr) and stderr == b"", "reader complete streams")
    result = strict_json(stdout)
    need(result.get("status") == ("PASS" if expected_exit == 0 else "REJECTED"), "reader raw stdout status")
    if expected_exit:
        need(expected_error is not None and result == {"status": "REJECTED", "error_type": "ValueError", "error": expected_error},
             "reader rejection reason differs from the named semantic gate")


def read_controls(corpus, manifest):
    corpus = Path(corpus).absolute()
    manifest = Path(manifest).absolute()
    controls = corpus / "controls"
    plain_directory(controls)
    summary = read_json(controls / "report.json")
    need(summary.get("schema") == "hepta.runtime.shell-capture-mkdir-controls.v1" and summary.get("status") == "PASS"
         and summary.get("control_names") == list(CONTROL_NAMES)
         and all(summary.get(k) is v for k, v in SCOPE.items()), "control registry/scope")
    current_report = read_json(corpus / "report.json")
    baseline_report = ordinary(controls / "baseline-report.json")
    expected_report = dict(current_report)
    expected_report["physical_controls"] = None
    need(baseline_report == json_bytes(expected_report) and summary.get("baseline_report") == pin(baseline_report), "control baseline report")
    baseline = {p: ordinary(corpus / p) for p in core_file_names([s["name"] for s in case_specs()])}
    baseline["report.json"] = baseline_report
    rows = summary.get("controls")
    need(type(rows) is list and len(rows) == len(CONTROL_NAMES), "complete control inventory")
    need(set(os.listdir(controls)) == set(CONTROL_NAMES) | {"baseline-report.json", "report.json", "restored-positive"}, "extra control package")
    for name, row in zip(CONTROL_NAMES, rows):
        folder = controls / name
        plain_directory(folder)
        need(row == read_json(folder / "control.json") and row.get("name") == name and row.get("restored") is True, "control identity")
        expected = control_recipe(name, baseline)
        mutations = row.get("mutations")
        need(type(mutations) is list and [m.get("path") for m in mutations] == sorted(expected), "named mutation changed a different file set")
        expected_files = {"control.json", "execution.json", "stdout.bin", "stderr.bin"}
        for index, mutation in enumerate(mutations):
            path, prefix = mutation["path"], f"{index:02d}"
            need(mutation.get("prefix") == prefix and mutation.get("before") == pin(baseline[path])
                 and mutation.get("after") == pin(expected[path]), "named mutation byte recipe")
            need(ordinary(folder / (prefix + ".before.bin")) == baseline[path]
                 and ordinary(folder / (prefix + ".after.bin")) == expected[path], "physical control payload differs from recipe")
            identity = mutation.get("identity")
            need(type(identity) is dict and set(identity) == {"device", "inode", "mode"}
                 and all(type(v) is int and v >= 0 for v in identity.values())
                 and identity["inode"] > 0 and stat.S_ISREG(identity["mode"]), "physical mutation identity")
            expected_files |= {prefix + ".before.bin", prefix + ".after.bin"}
        need(set(os.listdir(folder)) == expected_files, "control retained files")
        inputs = dict(baseline); inputs.update(expected)
        verify_reader_process(folder, corpus, manifest, inputs, 2, CONTROL_ERRORS[name])
        need(row.get("reader") == {"execution": pin(ordinary(folder / "execution.json")),
                                  "stdout": pin(ordinary(folder / "stdout.bin")), "stderr": pin(ordinary(folder / "stderr.bin"))}, "control reader pins")
    positive = controls / "restored-positive"
    plain_directory(positive)
    need(set(os.listdir(positive)) == {"execution.json", "stdout.bin", "stderr.bin"}, "positive retained files")
    verify_reader_process(positive, corpus, manifest, baseline, 0)
    need(summary.get("restored_positive") == {n: pin(ordinary(positive / n)) for n in ("execution.json", "stdout.bin", "stderr.bin")}, "restored positive pins")
    return {"status": "PASS", "physical_mutations_reconstructed": True,
            "physical_negative_controls": len(CONTROL_NAMES), "reader_processes": len(CONTROL_NAMES) + 1,
            "all_baseline_bytes_restored": True, "report_sha256": sha(ordinary(controls / "report.json"))}


def run(output, native_manifest):
    output = Path(output).absolute()
    manifest, metadata, _ = load_native(native_manifest)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    (output / "cases").mkdir()
    (output / "temporary").mkdir(mode=0o700)
    sources = source_pins()
    for name in SOURCE_NAMES:
        target = output / "source-snapshots" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        write_new(target, ordinary(ROOT / name))
    cases, counts = [], {}
    for spec in case_specs():
        result = run_case(output / "cases" / spec["name"], spec, manifest, metadata)
        cases.append(result)
        for key, amount in result["counts"].items():
            counts[key] = counts.get(key, 0) + amount
        print(json.dumps({"name": spec["name"], "status": "PASS", "result": result["result"]}, sort_keys=True), flush=True)
    names = [s["name"] for s in case_specs()]
    counts.update(cases=len(names), retired_fixtures=len(names),
                  original_fresh_cache_cases=sum(s["original_fresh_cache_comparable"] for s in case_specs()),
                  kernel_errno_injected=0)
    report = {"schema": "hepta.runtime.shell-capture-mkdir-os-report.v1", "status": "PASS",
              "recorded_directory": str(output), "complete_registered_corpus": True,
              "native_manifest": {"path": str(manifest), **pin(ordinary(manifest))},
              "sources": sources, "case_names": names, "cases": cases, "counts": counts,
              "files": {p: pin(ordinary(output / p)) for p in core_file_names(names)},
              "physical_controls": None, **SCOPE}
    need(source_pins() == sources, "source changed during actual OS qualification")
    write_new(output / "report.json", json_bytes(report))
    _read_corpus(output, manifest, require_controls=False)
    report["physical_controls"] = run_controls(output, manifest)
    replace_ordinary(output / "report.json", json_bytes(report))
    result = read_evidence(output, manifest)
    write_new(output / "readback.json", json_bytes(result))
    return result


def audit_read_only(folder, manifest):
    # Imports and immutable native-build admission happen before the audit gate;
    # the complete public read_evidence invocation runs inside the gate.
    load_native(manifest)
    import ctypes
    enabled, probes, forbidden = True, False, []
    observed = [0]
    def hook(event, args):
        if not enabled:
            return
        observed[0] += 1
        bad = event.startswith(("subprocess.", "socket.", "ctypes.")) or event in {
            "os.system", "os.fork", "os.forkpty", "os.posix_spawn", "os.exec", "os.kill",
            "os.mkdir", "os.remove", "os.rmdir", "os.rename", "os.link", "os.symlink",
            "os.chmod", "os.chown", "os.truncate", "os.utime", "os.setxattr", "os.removexattr",
        }
        if event == "open":
            path, mode, flags = args
            bad = bool(type(mode) is str and any(c in mode for c in "wax+")) or bool(type(flags) is int and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
            if isinstance(path, (str, bytes, os.PathLike)):
                bad |= os.fsencode(path).startswith(b"/proc/")
        if bad:
            forbidden.append({"event": event, "probe": probes})
            raise PermissionError("read-only audit blocked " + event)
    sys.addaudithook(hook)
    try:
        value = read_evidence(folder, manifest)
        need(not forbidden, "reader attempted a forbidden action")
        probes = True
        for call in (
            lambda: subprocess.run(["/bin/true"], check=True),
            lambda: open(Path(folder) / "forbidden-write", "wb"),
            lambda: open("/proc/self/stat", "rb"),
            lambda: ctypes.CDLL(None),
        ):
            try:
                call()
            except PermissionError:
                pass
            else:
                raise ValueError("audit negative probe was not blocked")
        need(len(forbidden) == 4 and all(x["probe"] for x in forbidden), "audit probe inventory")
    finally:
        enabled = False
    return {"schema": "hepta.runtime.shell-capture-mkdir-read-audit.v1", "status": "PASS",
            "reader_status": value["status"], "reader_forbidden_actions": 0,
            "blocked_negative_probes": 4, "observed_events": observed[0],
            "imports_preloaded": True, "report_sha256": sha(ordinary(Path(folder) / "report.json")), **SCOPE}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-manifest", type=Path, required=True)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--output", type=Path)
    modes.add_argument("--verify", type=Path)
    modes.add_argument("--verify-core", type=Path, help=argparse.SUPPRESS)
    modes.add_argument("--verify-case", type=Path)
    modes.add_argument("--audit-read-only", type=Path)
    args = parser.parse_args()
    try:
        if args.output:
            result = run(args.output, args.native_manifest)
        elif args.verify_core:
            result = _read_corpus(args.verify_core, args.native_manifest, require_controls=False)
        elif args.verify_case:
            result = read_case(args.verify_case, args.native_manifest)["validation"]
        elif args.audit_read_only:
            result = audit_read_only(args.audit_read_only, args.native_manifest)
        else:
            result = read_evidence(args.verify, args.native_manifest)
    except Exception as error:
        print(json.dumps({"status": "REJECTED", "error_type": type(error).__name__, "error": str(error)}, sort_keys=True), flush=True)
        raise SystemExit(2)
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
