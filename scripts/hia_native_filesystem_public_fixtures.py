"""Archive only the SDK capture's owned tree across the two actual stages.

Pure readers validate full retained bytes and never restore an execution path.
The original replay uses the same absolute path in a separate real tree; the
reconstructed native tree is held by rename and restored with its own inode
identities intact. A failed replay leaves both trees for diagnosis.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import stat

import hia_native_runtime_mcp_fixtures as archive
from hia_native_filesystem_public_reference_source import canonical, decode, need, pin, regular

ROOTS = ("filesystem-public/native/fixtures",)
NATIVE_RECEIPT = "filesystem-public/native-fixtures.json"
NATIVE_ARCHIVE = "filesystem-public/native-fixtures.bin.gz"
ORIGINAL_RECEIPT = "filesystem-public/original-fixtures.json"
ORIGINAL_ARCHIVE = "filesystem-public/original-fixtures.bin.gz"
RESTORE = "filesystem-public/fixture-reconstruction.json"
HELD = "filesystem-public/native/fixtures-held-for-original"


def read(output, name):
    return regular(output, name).read_bytes()


def object_at(output, name):
    return decode(read(output, name))


def exact(left, right, label):
    need(canonical(left) == canonical(right), label)


def final_native_entries(output, entries, origin):
    """Bind all observed final trees to their complete actual last snapshots."""
    archive.validate_entries(entries, ROOTS)
    table = {bytes.fromhex(row["path_hex"]): row for row in entries}
    host = object_at(output, "filesystem-public/native/HOST.json")
    base = table[ROOTS[0].encode()]
    exact([base["source_device"], base["source_inode"], base["uid"]],
          host["fixture_identity"], "native fixture root identity before retirement")
    corpus = object_at(output, "filesystem-public/native/INPUTS.json")
    scenes = [scene for group in corpus["groups"] for scene in group["scenarios"]]
    for scene in scenes:
        layer = "public" if len(scene["sessions"]) == 1 else "observed"
        name = "filesystem-public/native/%s/scenario-%03d/records.jsonl" % (layer, scene["scenario_id"])
        rows = [decode(line) for line in read(output, name).splitlines()]
        last = rows[-1]
        need(last["kind"] == "scenario_end" and last["scenario_id"] == scene["scenario_id"],
             "complete final native scenario snapshot")
        exact([tree["root_hex"] for tree in last["filesystem"]], scene["observed_roots"],
              "final native observed roots")
        for tree in last["filesystem"]:
            raw_root = bytes.fromhex(tree["root_hex"])
            origin_raw = os.fsencode(origin) + b"/"
            need(raw_root.startswith(origin_raw), "observed fixture root escaped actual output")
            prefix = raw_root[len(origin_raw):]
            expected = set()
            for node in tree["nodes"]:
                suffix = bytes.fromhex(node["relative_hex"])
                path = prefix + (b"/" + suffix if suffix else b"")
                if "errno" in node:
                    exact(node, {"relative_hex": "", "errno": 2}, "retained absent fixture root")
                    need(path not in table, "absent native root reappeared")
                    continue
                expected.add(path)
                need(path in table, "final native fixture entry missing")
                actual = table[path]
                mode = node["mode"]
                kinds = {stat.S_IFDIR: "directory", stat.S_IFREG: "file", stat.S_IFLNK: "symlink", stat.S_IFIFO: "fifo"}
                need(stat.S_IFMT(mode) in kinds, "unowned final fixture object kind")
                exact([actual["kind"], actual["mode"], actual["uid"], actual["gid"],
                       actual["source_device"], actual["source_inode"], actual["nlink"]],
                      [kinds[stat.S_IFMT(mode)], stat.S_IMODE(mode), node["uid"], node["gid"],
                       node["device"], node["inode"], node["links"]], "complete final native metadata")
                if actual["kind"] == "file":
                    need("content_hex" in node and "read_errno" not in node, "complete final native file content")
                    exact({key: actual[key] for key in ("bytes", "sha256")}, pin(bytes.fromhex(node["content_hex"])),
                          "complete archived native file bytes")
                elif actual["kind"] == "symlink":
                    exact(actual["target_hex"], node["target_hex"], "raw archived symbolic-link target")
            present = {path for path in table if path == prefix or path.startswith(prefix + b"/")}
            exact(sorted(path.hex() for path in present), sorted(path.hex() for path in expected),
                  "complete final native fixture subtree")


def retirement(root, output, binding, *, create=False):
    output = archive.root_path(output)
    origin = binding["execution_output_root"]
    expected = {"schema": "hepta.runtime.filesystem-public-native-fixtures.v1", "status": "PASS",
                "execution_output_root": origin, "fixture_directories": list(ROOTS),
                "complete_native_evidence_sha256": pin(canonical(binding))["sha256"],
                "semantic_invocations_added": 0, "source_inodes_recreated": False}
    receipt = output / NATIVE_RECEIPT
    if not receipt.exists():
        need(create and not receipt.is_symlink() and str(output) == origin,
             "native fixture retirement must use its actual owned execution root")
        report = object_at(output, "filesystem-public/native/NATIVE.json")
        need(report["all_processes_terminated"] is True, "native process still owns fixture")
        entries = archive.snapshot(output, ROOTS)
        final_native_entries(output, entries, origin)
        archive.create_archive(output, ROOTS, entries, NATIVE_ARCHIVE)
        archive_pin = archive.file_pin(regular(output, NATIVE_ARCHIVE))
        archive.read_archive(output, entries, ROOTS, NATIVE_ARCHIVE, archive_pin)
        exact(archive.snapshot(output, ROOTS), entries, "native fixture changed during archival")
        archive.remove_roots(output, ROOTS, entries)
        archive.dump_new(output, NATIVE_RECEIPT, dict(expected, entries=entries, archive=archive_pin))
    value = object_at(output, NATIVE_RECEIPT)
    exact(sorted(value), sorted([*expected, "entries", "archive"]), "native retirement complete fields")
    exact({key: value[key] for key in expected}, expected, "native retirement evidence binding")
    final_native_entries(output, value["entries"], origin)
    counts = archive.read_archive(output, value["entries"], ROOTS, NATIVE_ARCHIVE, value["archive"])
    archive.absent(output, ROOTS)
    return dict(expected, **counts, artifact_sha256={name: archive.file_pin(regular(output, name))["sha256"]
                                                    for name in (NATIVE_RECEIPT, NATIVE_ARCHIVE)})


def journal(output, value):
    path = output / RESTORE
    temporary = output / (RESTORE + ".pending")
    need(not temporary.exists() and not temporary.is_symlink(), "unclaimed fixture journal update")
    if path.exists():
        need(regular(output, RESTORE).stat().st_uid == os.getuid(), "fixture journal owner differs")
    with temporary.open("xb") as stream:
        stream.write(canonical(value))
    os.replace(temporary, path)


@contextmanager
def original_fixture(root, output, binding, admitted):
    output = archive.root_path(output)
    exact(str(output), binding["execution_output_root"], "original requires the actual native path")
    exact(retirement(root, output, binding), admitted, "admitted native fixture before reconstruction")
    need(not (output / RESTORE).exists() and not (output / RESTORE).is_symlink(), "fixture reconstruction already attempted")
    archive.absent(output, (*ROOTS, HELD))
    original = object_at(output, NATIVE_RECEIPT)
    created = []
    archive.populate(output, original["entries"], NATIVE_ARCHIVE, original["archive"], created, roots=ROOTS)
    before = archive.snapshot(output, ROOTS)
    exact(archive.logical(before), archive.logical(original["entries"]), "complete reconstructed native fixture")
    archive.dump_new(output, RESTORE + ".before.json", before)
    path, held = output / ROOTS[0], output / HELD
    identity = archive.inode(path.lstat())
    state = dict(schema="hepta.runtime.filesystem-public-original-fixture.v1", status="RUNNING",
                 execution_output_root=str(output), source_retirement_sha256=pin(canonical(admitted))["sha256"],
                 fixture_directories=list(ROOTS), held_directory=HELD,
                 reconstructed_original_inodes=False, reconstructed_native_inode_preserved=False,
                 original_fixture_retired=False, reconstructed_native_fixture_retired=False,
                 before_sha256=pin(canonical(before))["sha256"], error=None)
    journal(output, state)
    path.rename(held)
    exact(list(archive.inode(held.lstat())), list(identity), "held native root identity")
    path.mkdir(mode=0o700)
    replay_identity = archive.inode(path.lstat())
    try:
        yield path
        # The caller has already admitted all original process completions and
        # complete bytes. Snapshot and archive its separate real effect tree.
        exact(list(archive.inode(path.lstat())[:5]), list(replay_identity[:5]), "original owned root identity")
        entries = archive.snapshot(output, ROOTS)
        archive.create_archive(output, ROOTS, entries, ORIGINAL_ARCHIVE)
        archive_pin = archive.file_pin(regular(output, ORIGINAL_ARCHIVE))
        archive.read_archive(output, entries, ROOTS, ORIGINAL_ARCHIVE, archive_pin)
        exact(archive.snapshot(output, ROOTS), entries, "original fixture changed during archival")
        archive.dump_new(output, ORIGINAL_RECEIPT, dict(
            schema="hepta.runtime.filesystem-public-original-fixtures.v1", status="PASS",
            execution_output_root=str(output), fixture_directories=list(ROOTS),
            original_report=pin(read(output, "filesystem-public/original/ORIGINAL.json")),
            entries=entries, archive=archive_pin, semantic_invocations_added=0))
        archive.remove_roots(output, ROOTS, entries)
        exact(list(archive.inode(held.lstat())), list(identity), "held native root changed during original execution")
        held.rename(path)
        after = archive.snapshot(output, ROOTS)
        exact(after, before, "same reconstructed native inodes and bytes after original replay")
        archive.dump_new(output, RESTORE + ".after.json", after)
        archive.remove_roots(output, ROOTS, after)
        archive.absent(output, (*ROOTS, HELD))
        state.update(status="PASS", reconstructed_native_inode_preserved=True,
                     original_fixture_retired=True, reconstructed_native_fixture_retired=True)
        journal(output, state)
    except BaseException as error:
        # No unknown live process is raced by cleanup. Both owned trees and
        # every original stream remain available after an incomplete replay.
        state.update(status="FAIL", error={"type": type(error).__name__, "message": str(error)})
        journal(output, state)
        raise


def retained_original(output, binding, admitted):
    output = archive.root_path(output)
    state = object_at(output, RESTORE)
    before = object_at(output, RESTORE + ".before.json")
    after = object_at(output, RESTORE + ".after.json")
    native = object_at(output, NATIVE_RECEIPT)
    expected = dict(schema="hepta.runtime.filesystem-public-original-fixture.v1", status="PASS",
                    execution_output_root=binding["execution_output_root"],
                    source_retirement_sha256=pin(canonical(admitted))["sha256"],
                    fixture_directories=list(ROOTS), held_directory=HELD,
                    reconstructed_original_inodes=False, reconstructed_native_inode_preserved=True,
                    original_fixture_retired=True, reconstructed_native_fixture_retired=True,
                    before_sha256=pin(canonical(before))["sha256"], error=None)
    exact(state, expected, "complete retained fixture reconstruction")
    archive.validate_entries(before, ROOTS)
    archive.validate_entries(after, ROOTS)
    exact(before, after, "retained native reconstruction identity")
    exact(archive.logical(before), archive.logical(native["entries"]), "reconstruction differs from native archive")
    original = object_at(output, ORIGINAL_RECEIPT)
    exact(sorted(original), sorted(("schema", "status", "execution_output_root", "fixture_directories",
                                   "original_report", "entries", "archive", "semantic_invocations_added")),
          "original fixture receipt fields")
    exact({key: original[key] for key in ("schema", "status", "execution_output_root", "fixture_directories",
                                        "original_report", "semantic_invocations_added")},
          dict(schema="hepta.runtime.filesystem-public-original-fixtures.v1", status="PASS",
               execution_output_root=binding["execution_output_root"], fixture_directories=list(ROOTS),
               original_report=pin(read(output, "filesystem-public/original/ORIGINAL.json")), semantic_invocations_added=0),
          "original fixture complete execution binding")
    counts = archive.read_archive(output, original["entries"], ROOTS, ORIGINAL_ARCHIVE, original["archive"])
    archive.absent(output, (*ROOTS, HELD))
    names = (RESTORE, RESTORE + ".before.json", RESTORE + ".after.json", ORIGINAL_RECEIPT, ORIGINAL_ARCHIVE)
    return dict(state, original_archive=counts,
                artifact_sha256={name: archive.file_pin(regular(output, name))["sha256"] for name in names})
