"""Retain and retire only the public qualification's owned filesystem trees.

Native artifact transport contains regular evidence files, never live FIFOs or
symlinks. A normal original-comparison phase may reconstruct the admitted tree
at its exact execution path. Pure readers never reconstruct it. A reconstructed
inode is new; only the original replay's before/after rename preserves that
new inode. The archive retains source inode identifiers solely as provenance.
"""
from __future__ import annotations

from contextlib import contextmanager
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct

from hia_native_runtime_mcp_evidence import compact, decode, exact, require, sha

MAGIC = b"HMPFX001"
NATIVE = ("runtime-mcp/files",)
ORIGINAL = ("runtime-mcp-original/over64-files", "workdir-original/fixtures")
PROFILES = {
    "native": (NATIVE, "runtime-mcp/retired-fixtures"),
    "original": (ORIGINAL, "runtime-mcp-original/retired-fixtures"),
}
RESTORE = "runtime-mcp-original-fixture-restore.json"
HEX = re.compile(r"(?:[0-9a-f]{2})*\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode()


def file_pin(path):
    with Path(path).open("rb") as source:
        return dict(bytes=os.fstat(source.fileno()).st_size,
                    sha256=hashlib.file_digest(source, "sha256").hexdigest())


def root_path(output):
    output = Path(output).absolute()
    require(output.resolve(strict=True) == output and not output.is_symlink(),
            "public fixture output root crosses a symlink")
    info = output.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(),
            "public fixture output root is not an owned directory")
    return output


def name_bytes(name, roots):
    require(type(name) is str and HEX.fullmatch(name) and name,
            "public fixture path is not lossless lowercase hex")
    raw = bytes.fromhex(name)
    require(not raw.startswith(b"/") and b"\0" not in raw
            and all(part not in (b"", b".", b"..") for part in raw.split(b"/")),
            "public fixture path is not a contained relative name")
    require(any(raw == root.encode() or raw.startswith(root.encode() + b"/") for root in roots),
            "public fixture path escaped its fixed owner")
    return raw


@contextmanager
def parent_fd(output, relative):
    parts = os.fsencode(relative).split(b"/")
    require(all(part not in (b"", b".", b"..") for part in parts),
            "public fixture descriptor path is not canonical")
    fd = os.open(output, FLAGS)
    try:
        require(os.fstat(fd).st_uid == os.getuid(), "public fixture output descriptor is unowned")
        for part in parts[:-1]:
            child = os.open(part, FLAGS, dir_fd=fd)
            try:
                require(os.fstat(child).st_uid == os.getuid(), "public fixture ancestor is unowned")
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
        yield fd, parts[-1]
    finally:
        os.close(fd)


def inode(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink


def attributes(fd, name):
    # The already-open parent fixes traversal. The final component is lstat'ed
    # before and after each no-follow attribute operation.
    path = b"/proc/self/fd/" + str(fd).encode() + b"/" + name
    before = os.stat(name, dir_fd=fd, follow_symlinks=False)
    result = {os.fsencode(key).hex(): os.getxattr(path, key, follow_symlinks=False).hex()
              for key in sorted(os.listxattr(path, follow_symlinks=False), key=os.fsencode)}
    exact(inode(os.stat(name, dir_fd=fd, follow_symlinks=False)), inode(before),
          "public fixture changed during attribute capture")
    return result


def snapshot(output, roots):
    output = root_path(output)
    entries = []

    def visit(fd, name, relative):
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) <= 0o777,
                "public fixture has an unowned entry or special permission bits")
        entry = dict(path_hex=relative.hex(), mode=stat.S_IMODE(info.st_mode),
                     uid=info.st_uid, gid=info.st_gid, source_device=info.st_dev,
                     source_inode=info.st_ino, nlink=info.st_nlink, xattrs=attributes(fd, name))
        name_bytes(entry["path_hex"], roots)
        if stat.S_ISDIR(info.st_mode):
            entry["kind"] = "directory"
            entries.append(entry)
            child = os.open(name, FLAGS, dir_fd=fd)
            try:
                exact(inode(os.fstat(child)), inode(info), "public fixture directory changed")
                for component in sorted(map(os.fsencode, os.listdir(child))):
                    visit(child, component, relative + b"/" + component)
            finally:
                os.close(child)
        elif stat.S_ISREG(info.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            with os.fdopen(child, "rb") as source:
                exact(inode(os.fstat(source.fileno())), inode(info), "public fixture file changed")
                entry.update(kind="file", bytes=info.st_size,
                             sha256=hashlib.file_digest(source, "sha256").hexdigest())
                after = os.fstat(source.fileno())
                exact((inode(after), after.st_size), (inode(info), info.st_size),
                      "public fixture file changed during full-byte capture")
            entries.append(entry)
        elif stat.S_ISLNK(info.st_mode):
            entry.update(kind="symlink", target_hex=os.readlink(name, dir_fd=fd).hex())
            entries.append(entry)
        elif stat.S_ISFIFO(info.st_mode):
            entry["kind"] = "fifo"
            entries.append(entry)
        else:
            raise ValueError("public fixture refuses device/socket/unknown special entries")
        exact(inode(os.stat(name, dir_fd=fd, follow_symlinks=False)), inode(info),
              "public fixture entry changed during capture")

    for root in roots:
        with parent_fd(output, root) as (fd, name):
            require(stat.S_ISDIR(os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode),
                    "public fixture root is not a directory")
            visit(fd, name, root.encode())
    entries.sort(key=lambda row: row["path_hex"])
    groups = {}
    for entry in entries:
        if entry["kind"] == "file":
            groups.setdefault((entry["source_device"], entry["source_inode"]), []).append(entry)
    for group in groups.values():
        for entry in group:
            exact(entry["nlink"], len(group), "public fixture hardlink leaves the complete owned trees")
            entry["link_group"] = group[0]["path_hex"]
    validate_entries(entries, roots)
    return entries


def validate_entries(entries, roots):
    require(type(entries) is list and entries, "public fixture entries are missing")
    require(all(type(row) is dict for row in entries), "public fixture entry is not an object")
    paths = [row.get("path_hex") for row in entries]
    require(all(type(path) is str for path in paths), "public fixture path is not text")
    exact(paths, sorted(set(paths)), "public fixture entries are unordered or duplicated")
    table = {row["path_hex"]: row for row in entries}
    base = {"path_hex", "kind", "mode", "uid", "gid", "source_device", "source_inode", "nlink", "xattrs"}
    groups = {}
    for row in entries:
        raw = name_bytes(row["path_hex"], roots)
        fields = set(base)
        kind = row.get("kind")
        if kind == "file":
            fields.update(("bytes", "sha256", "link_group"))
            require(type(row.get("bytes")) is int and 0 <= row["bytes"] < 2**64
                    and type(row.get("sha256")) is str and SHA.fullmatch(row["sha256"]),
                    "public fixture file extent/digest differs")
            name_bytes(row.get("link_group"), roots)
            groups.setdefault(row["link_group"], []).append(row)
        elif kind == "symlink":
            fields.add("target_hex")
            target = row.get("target_hex")
            require(type(target) is str and target and HEX.fullmatch(target) and b"\0" not in bytes.fromhex(target),
                    "public fixture symlink target differs")
        else:
            require(kind in ("directory", "fifo"), "public fixture entry kind differs")
        exact(sorted(row), sorted(fields), "public fixture entry fields differ")
        for key in ("mode", "uid", "gid", "source_device", "source_inode", "nlink"):
            require(type(row[key]) is int and 0 <= row[key] < 2**64,
                    "public fixture integer metadata differs: " + key)
        require(row["mode"] <= 0o777 and row["nlink"] > 0, "public fixture permission/link metadata differs")
        if kind in ("symlink", "fifo"):
            exact(row["nlink"], 1, "public fixture non-file alias is unsupported")
        require(type(row["xattrs"]) is dict, "public fixture attributes are not an object")
        for key, value in row["xattrs"].items():
            require(type(key) is str and key and HEX.fullmatch(key) and b"\0" not in bytes.fromhex(key)
                    and type(value) is str and HEX.fullmatch(value), "public fixture attribute is not lossless")
        if raw not in {root.encode() for root in roots}:
            parent = raw.rsplit(b"/", 1)[0].hex()
            require(parent in table and table[parent]["kind"] == "directory", "public fixture parent is missing")
    for root in roots:
        require(root.encode().hex() in table and table[root.encode().hex()]["kind"] == "directory",
                "public fixture root is missing")
    identities = {}
    for primary, rows in groups.items():
        exact(primary, min(row["path_hex"] for row in rows), "public fixture hardlink primary differs")
        require(primary in table and table[primary]["kind"] == "file", "public fixture hardlink primary is absent")
        anchor = table[primary]
        identity = (anchor["source_device"], anchor["source_inode"])
        require(identity not in identities, "public fixture inode split across hardlink groups")
        identities[identity] = primary
        for row in rows:
            exact(row["nlink"], len(rows), "public fixture hardlink group is not closed")
            exact({key: value for key, value in row.items() if key != "path_hex"},
                  {key: value for key, value in anchor.items() if key != "path_hex"},
                  "public fixture hardlink metadata/content differs")


def logical(entries):
    """A cross-runner reconstruction has fresh inode/device identifiers."""
    return [{key: value for key, value in row.items()
             if key not in ("source_device", "source_inode") and not (key == "nlink" and row["kind"] == "directory")}
            for row in entries]


def exact_read(stream, size):
    raw = stream.read(size)
    require(len(raw) == size, "public fixture archive is truncated")
    return raw


def artifact(output, name):
    path = output / name
    require(path.resolve(strict=True) == path.absolute() and not path.is_symlink(),
            "public fixture evidence path crosses a symlink")
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid(),
            "public fixture evidence is not an owned regular file")
    return path


def dump_new(output, name, value):
    with parent_fd(output, name) as (fd, leaf):
        raw = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                      0o600, dir_fd=fd)
        with os.fdopen(raw, "wb") as stream:
            stream.write(encoded(value))
            stream.flush()
            os.fsync(stream.fileno())


def absent(output, roots):
    for root in roots:
        with parent_fd(output, root) as (fd, leaf):
            try:
                os.stat(leaf, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError("retired public fixture root reappeared: " + root)


def read_archive(output, entries, roots, name, expected, consume=None):
    validate_entries(entries, roots)
    exact(sorted(expected), ["bytes", "sha256"], "public fixture archive pin fields differ")
    require(type(expected["bytes"]) is int and expected["bytes"] >= 0
            and type(expected["sha256"]) is str and SHA.fullmatch(expected["sha256"]),
            "public fixture archive pin differs")
    path = artifact(output, name)
    exact(file_pin(path), expected, "complete public fixture archive differs")
    files = [(index, row) for index, row in enumerate(entries) if row["kind"] == "file"]
    total = 0
    with gzip.open(path, "rb") as stream:
        exact(exact_read(stream, 8), MAGIC, "public fixture archive magic differs")
        exact(struct.unpack("<Q", exact_read(stream, 8))[0], len(files), "public fixture archive file count differs")
        for index, row in files:
            exact(struct.unpack("<2Q", exact_read(stream, 16)), (index, row["bytes"]),
                  "public fixture archive frame differs")
            digest = hashlib.sha256()
            remaining = row["bytes"]
            if consume is not None:
                consume(row, None)
            while remaining:
                block = exact_read(stream, min(remaining, 1 << 20))
                digest.update(block)
                remaining -= len(block)
                total += len(block)
                if consume is not None:
                    consume(row, block)
            exact(digest.hexdigest(), row["sha256"], "complete public fixture file bytes differ")
            if consume is not None:
                consume(row, b"")
        exact(stream.read(1), b"", "trailing public fixture archive bytes")
    return dict(entries=len(entries), files=len(files), retained_file_bytes=total,
                directories=sum(row["kind"] == "directory" for row in entries),
                symlinks=sum(row["kind"] == "symlink" for row in entries),
                fifos=sum(row["kind"] == "fifo" for row in entries),
                hardlink_groups=len({row["link_group"] for row in entries if row["kind"] == "file"}),
                xattrs=sum(len(row["xattrs"]) for row in entries))


def remove_roots(output, roots, entries):
    require(shutil.rmtree.avoids_symlink_attacks, "descriptor-relative fixture retirement is unavailable")
    table = {row["path_hex"]: row for row in entries}
    for root in roots:
        with parent_fd(output, root) as (fd, leaf):
            info = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
            expected = table[root.encode().hex()]
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(),
                    "public fixture retirement root is not owned")
            exact((info.st_dev, info.st_ino), (expected["source_device"], expected["source_inode"]),
                  "public fixture retirement root identity changed")
            shutil.rmtree(leaf, dir_fd=fd)


def create_archive(output, roots, entries, name):
    with parent_fd(output, name) as (fd, leaf):
        descriptor = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=fd)
        with os.fdopen(descriptor, "wb") as destination:
            with gzip.GzipFile(filename="", fileobj=destination, mode="wb", mtime=0) as stream:
                stream.write(MAGIC)
                stream.write(struct.pack("<Q", sum(row["kind"] == "file" for row in entries)))
                for index, row in enumerate(entries):
                    if row["kind"] != "file":
                        continue
                    stream.write(struct.pack("<2Q", index, row["bytes"]))
                    with parent_fd(output, name_bytes(row["path_hex"], roots)) as (parent, child):
                        source_fd = os.open(child, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                        with os.fdopen(source_fd, "rb") as source:
                            info = os.fstat(source.fileno())
                            exact((info.st_dev, info.st_ino, info.st_size),
                                  (row["source_device"], row["source_inode"], row["bytes"]),
                                  "public fixture file changed before archive copy")
                            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid(),
                                    "public fixture archive input is not an owned file")
                            shutil.copyfileobj(source, stream, 1 << 20)
            destination.flush()
            os.fsync(destination.fileno())


def retired(output, profile, evidence, origin, *, create=False):
    """Return an identical object before/after transport; no read path restores."""
    output = root_path(output)
    require(profile in PROFILES, "unknown public fixture retirement profile")
    roots, prefix = PROFILES[profile]
    require(type(origin) is str and Path(origin).is_absolute() and str(Path(origin)) == origin
            and ".." not in Path(origin).parts, "public fixture origin is not canonical")
    expected = dict(schema="hepta.runtime.public-fixture-retirement.v1", status="PASS", profile=profile,
                    fixture_directories=list(roots), execution_output_root=origin,
                    complete_evidence_sha256=sha(encoded(evidence)), semantic_invocations_added=0,
                    source_inode_identifiers_are_provenance=True, reconstructed_original_inodes=False)
    receipt_name, archive_name = prefix + ".json", prefix + ".bin.gz"
    receipt = output / receipt_name
    if not receipt.exists():
        require(not receipt.is_symlink() and create, "complete public fixture retirement receipt is missing")
        exact(str(output), origin, "fixture retirement creation must use the actual execution output root")
        entries = snapshot(output, roots)
        create_archive(output, roots, entries, archive_name)
        archive_pin = file_pin(artifact(output, archive_name))
        read_archive(output, entries, roots, archive_name, archive_pin)
        exact(snapshot(output, roots), entries, "public fixtures changed before retirement")
        remove_roots(output, roots, entries)
        dump_new(output, receipt_name, dict(expected, entries=entries, archive=archive_pin))
    value = decode(artifact(output, receipt_name).read_bytes())
    require(type(value) is dict, "public fixture retirement receipt is not an object")
    exact(sorted(value), sorted(set(expected) | {"entries", "archive"}), "public fixture retirement fields differ")
    exact({key: value[key] for key in expected}, expected, "public fixture retirement binding differs")
    counts = read_archive(output, value["entries"], roots, archive_name, value["archive"])
    absent(output, roots)
    return dict(expected, **counts, artifact_sha256={receipt_name: file_pin(artifact(output, receipt_name))["sha256"],
                                                    archive_name: value["archive"]["sha256"]})


def replace_journal(output, value):
    temporary = RESTORE + ".pending"
    dump_new(output, temporary, value)
    with parent_fd(output, RESTORE) as (fd, name):
        try:
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            info = None
        require(info is None or (stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()),
                "public fixture restore journal owner changed")
        os.replace(os.fsencode(temporary), name, src_dir_fd=fd, dst_dir_fd=fd)


def metadata(output, row, *, roots=NATIVE):
    relative = name_bytes(row["path_hex"], roots)
    with parent_fd(output, relative) as (fd, name):
        before = os.stat(name, dir_fd=fd, follow_symlinks=False)
        require(before.st_uid == row["uid"] == os.getuid(), "reconstructed fixture uid differs")
        require(row["gid"] in {os.getegid(), *os.getgroups()}, "reconstructed fixture gid is not owned")
        if before.st_gid != row["gid"]:
            os.chown(name, -1, row["gid"], dir_fd=fd, follow_symlinks=False)
        path = b"/proc/self/fd/" + str(fd).encode() + b"/" + name
        wanted = {bytes.fromhex(key): bytes.fromhex(value) for key, value in row["xattrs"].items()}
        present = {os.fsencode(key) for key in os.listxattr(path, follow_symlinks=False)}
        for key in present - wanted.keys():
            os.removexattr(path, key, follow_symlinks=False)
        for key, value in wanted.items():
            os.setxattr(path, key, value, follow_symlinks=False)
        if row["kind"] != "symlink":
            os.chmod(name, row["mode"], dir_fd=fd, follow_symlinks=False)
        else:
            exact(row["mode"], 0o777, "reconstructed symlink permission mode differs")
        after = os.stat(name, dir_fd=fd, follow_symlinks=False)
        exact((after.st_dev, after.st_ino, stat.S_IFMT(after.st_mode)),
              (before.st_dev, before.st_ino, stat.S_IFMT(before.st_mode)),
              "reconstructed fixture identity changed while applying metadata")


def populate(output, entries, archive, expected, created, *, roots=NATIVE):
    # Open only descriptor-relative children. No archived symlink is traversed.
    directories = sorted((row for row in entries if row["kind"] == "directory"),
                         key=lambda row: (bytes.fromhex(row["path_hex"]).count(b"/"), row["path_hex"]))
    for row in directories:
        relative = name_bytes(row["path_hex"], roots)
        with parent_fd(output, relative) as (fd, name):
            os.mkdir(name, mode=0o700, dir_fd=fd)
            if relative in {root.encode() for root in roots}:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                created.append(dict(path_hex=relative.hex(), source_device=info.st_dev, source_inode=info.st_ino))
    opened = None

    def consume(row, block):
        nonlocal opened
        if row["link_group"] != row["path_hex"]:
            return
        if block is None:
            require(opened is None, "reconstructed fixture file overlap")
            with parent_fd(output, name_bytes(row["path_hex"], roots)) as (fd, name):
                child = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                0o600, dir_fd=fd)
            opened = os.fdopen(child, "wb")
        elif block:
            opened.write(block)
        else:
            opened.flush()
            os.fsync(opened.fileno())
            opened.close()
            opened = None
    try:
        read_archive(output, entries, roots, archive, expected, consume)
    finally:
        if opened is not None:
            opened.close()
    for row in entries:
        kind = row["kind"]
        if kind == "directory" or (kind == "file" and row["link_group"] == row["path_hex"]):
            continue
        with parent_fd(output, name_bytes(row["path_hex"], roots)) as (fd, name):
            if kind == "file":
                with parent_fd(output, name_bytes(row["link_group"], roots)) as (source_fd, source_name):
                    info = os.stat(source_name, dir_fd=source_fd, follow_symlinks=False)
                    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid(),
                            "reconstructed hardlink target is not an owned regular file")
                    os.link(source_name, name, src_dir_fd=source_fd, dst_dir_fd=fd, follow_symlinks=False)
            elif kind == "symlink":
                os.symlink(bytes.fromhex(row["target_hex"]), name, dir_fd=fd)
            else:
                exact(kind, "fifo", "reconstructed fixture kind differs")
                os.mkfifo(name, 0o600, dir_fd=fd)
    # Keep directories traversable until all content and metadata are in place.
    for row in sorted(entries, key=lambda row: (row["kind"] == "directory",
                                               -bytes.fromhex(row["path_hex"]).count(b"/"), row["path_hex"])):
        metadata(output, row, roots=roots)


@contextmanager
def restored_native(output, admitted, evidence, origin):
    """Only normal comparison execution may enter this ownership scope."""
    output = root_path(output)
    exact(str(output), origin, "original replay requires this exact admitted native execution origin")
    exact(retired(output, "native", evidence, origin), admitted,
          "native fixture retirement changed before reconstruction")
    require(not (output / RESTORE).exists() and not (output / RESTORE).is_symlink(),
            "a previous public fixture reconstruction already exists")
    value = decode(artifact(output, "runtime-mcp/retired-fixtures.json").read_bytes())
    created = []
    state = dict(schema="hepta.runtime.public-original-fixture-reconstruction.v1", status="RUNNING",
                 execution_output_root=origin, source_retirement_sha256=sha(encoded(admitted)),
                 fixture_directories=list(NATIVE), source_inodes_recreated=False,
                 complete_bytes_modes_xattrs_and_link_groups_reconstructed=False,
                 this_replay_before_after_inode_identity_preserved=False,
                 reconstruction_retired=False, error=None)
    replace_journal(output, state)
    before = None
    problem = None
    try:
        populate(output, value["entries"], "runtime-mcp/retired-fixtures.bin.gz", value["archive"], created)
        before = snapshot(output, NATIVE)
        exact(logical(before), logical(value["entries"]), "reconstructed complete public fixture state differs")
        dump_new(output, RESTORE + ".before.json", before)
        state.update(complete_bytes_modes_xattrs_and_link_groups_reconstructed=True,
                     restored_entries_sha256=sha(encoded(before)))
        replace_journal(output, state)
        yield before
    except BaseException as error:
        problem = error
        state["error"] = dict(type=type(error).__name__, message=str(error))
        raise
    finally:
        try:
            if before is not None:
                after = snapshot(output, NATIVE)
                dump_new(output, RESTORE + ".after.json", after)
                exact(after, before, "original replay failed to preserve this reconstruction's inode and complete state")
                state["this_replay_before_after_inode_identity_preserved"] = True
                remove_roots(output, NATIVE, after)
                absent(output, NATIVE)
                state["reconstruction_retired"] = True
                state["status"] = "PASS" if problem is None else "FAIL"
            elif created:
                remove_roots(output, NATIVE, created)
                absent(output, NATIVE)
                state.update(reconstruction_retired=True, status="FAIL")
            else:
                state["status"] = "FAIL"
        except BaseException as error:
            state.update(status="FAIL", cleanup_error=dict(type=type(error).__name__, message=str(error)))
            raise
        finally:
            replace_journal(output, state)


def retained_reconstruction(output, admitted, origin):
    """Pure read admission; old absolute origins are never opened or restored."""
    output = root_path(output)
    state = decode(artifact(output, RESTORE).read_bytes())
    expected = dict(schema="hepta.runtime.public-original-fixture-reconstruction.v1", status="PASS",
                    execution_output_root=origin, source_retirement_sha256=sha(encoded(admitted)),
                    fixture_directories=list(NATIVE), source_inodes_recreated=False,
                    complete_bytes_modes_xattrs_and_link_groups_reconstructed=True,
                    this_replay_before_after_inode_identity_preserved=True,
                    reconstruction_retired=True, error=None)
    exact(sorted(state), sorted(set(expected) | {"restored_entries_sha256"}), "public reconstruction receipt fields differ")
    exact({key: state[key] for key in expected}, expected, "public reconstruction receipt differs")
    before = decode(artifact(output, RESTORE + ".before.json").read_bytes())
    after = decode(artifact(output, RESTORE + ".after.json").read_bytes())
    value = decode(artifact(output, "runtime-mcp/retired-fixtures.json").read_bytes())
    validate_entries(before, NATIVE)
    validate_entries(after, NATIVE)
    exact(logical(before), logical(value["entries"]), "retained reconstruction differs from complete native archive")
    exact(before, after, "retained replay changed a reconstructed inode or complete state")
    exact(state["restored_entries_sha256"], sha(encoded(before)), "retained reconstruction state digest differs")
    absent(output, NATIVE)
    return dict(state, artifact_sha256={name: file_pin(artifact(output, name))["sha256"]
                                       for name in (RESTORE, RESTORE + ".before.json", RESTORE + ".after.json")})
