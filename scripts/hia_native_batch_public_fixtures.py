"""Retain complete public Batch effect trees between the actual CI stages.

Only original execution reconstructs a fixture. Pure readers inspect the full
archives while all effect directories remain absent.
"""
from pathlib import Path
import os
import stat

import hia_native_runtime_mcp_fixtures as archive
from hia_native_batch_call_fixtures import capture, permission_evidence

FOLDER = "batch-public"
NATIVE = FOLDER + "/native/files"
HELD = FOLDER + "/native/files.native-retained-for-original-v1"
ORIGINAL = FOLDER + "/original/original-files-retired"
RECONSTRUCTION = FOLDER + "/fixture-reconstruction.json"
need, exact = archive.require, archive.exact


def absent(output, roots):
    """Prove absence below an owned root without following any path component."""
    output = archive.root_path(output)
    for root in roots:
        raw = os.fsencode(root)
        parts = raw.split(b"/")
        need(not raw.startswith(b"/") and b"\0" not in raw
             and all(part not in (b"", b".", b"..") for part in parts),
             "unsafe relative fixture path")
        fd = os.open(output, archive.FLAGS)
        try:
            need(os.fstat(fd).st_uid == os.getuid(), "fixture root has a different owner")
            for part in parts[:-1]:
                try:
                    child = os.open(part, archive.FLAGS, dir_fd=fd)
                except FileNotFoundError:
                    try:
                        os.stat(part, dir_fd=fd, follow_symlinks=False)
                    except FileNotFoundError:
                        break
                    raise ValueError("fixture ancestor changed while checking absence")
                try:
                    need(os.fstat(child).st_uid == os.getuid(),
                         "fixture ancestor has a different owner")
                except BaseException:
                    os.close(child)
                    raise
                os.close(fd)
                fd = child
            else:
                try:
                    os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise ValueError("retired public fixture root reappeared: " + root)
        finally:
            os.close(fd)


def object_at(output, name):
    return archive.decode(archive.artifact(output, name).read_bytes())


def mapped_entries(entries, old, new):
    left, right = os.fsencode(old), os.fsencode(new)
    result = []
    for item in entries:
        row = dict(item)
        for key in ("path_hex", "link_group"):
            if key not in row:
                continue
            path = bytes.fromhex(row[key])
            need(path == left or path.startswith(left + b"/"), "fixture entry escaped its root")
            row[key] = (right + path[len(left):]).hex()
        result.append(row)
    return result


def observed_entries(output, entries, origin, *, original=False):
    retained = ORIGINAL if original else NATIVE
    archive.validate_entries(entries, (retained,))
    table = {bytes.fromhex(row["path_hex"]): row for row in entries}
    native_origin = os.fsencode(str(Path(origin) / NATIVE))
    data = object_at(output, FOLDER + "/native/INPUTS.json")
    scenes = sorted((s for g in data["groups"] for s in g["scenarios"]),
                    key=lambda scene: scene["scenario_id"])
    seen = {os.fsencode(retained)}
    for action in data["common_setup"]:
        raw = bytes.fromhex(action["path_hex"])
        need(raw == native_origin or raw.startswith(native_origin + b"/"),
             "common setup escaped actual native fixture")
        path = os.fsencode(retained) + raw[len(native_origin):]
        if path in table:
            need(action["kind"] == "mkdir" and table[path]["kind"] == "directory",
                 "common setup entry is not its declared directory")
            seen.add(path)
    folder = FOLDER + ("/original" if original else "/native")
    kinds = {stat.S_IFREG: "file", stat.S_IFDIR: "directory",
             stat.S_IFLNK: "symlink", stat.S_IFIFO: "fifo"}
    observations = []
    for scene in scenes:
        row = object_at(output, folder + "/scenario-%03d/RESULT.json" % scene["scenario_id"])
        observations.append((row["final_files"], scene["observed_roots"]))
    final_name = folder + "/FINAL-FIXTURES.json"
    capture = object_at(output, folder + "/RESULT.json")
    exact(capture["final_fixtures"], {"path": str(Path(origin) / final_name),
          **archive.file_pin(archive.artifact(output, final_name))},
          "actual producer committed complete final fixture bytes")
    final = object_at(output, final_name)
    observations.append((final["trees"], [native_origin.hex()]))
    for trees, expected_roots in observations:
        exact([tree["root_hex"] for tree in trees], expected_roots, "all final observed roots")
        for tree in trees:
            raw_root = bytes.fromhex(tree["root_hex"])
            need(raw_root == native_origin or raw_root.startswith(native_origin + b"/"),
                 "observed root escaped actual fixture")
            prefix = os.fsencode(retained) + raw_root[len(native_origin):]
            expected = set()
            for node in tree["nodes"]:
                suffix = bytes.fromhex(node["relative_hex"])
                need(not suffix or (not suffix.startswith(b"/") and b"\0" not in suffix
                     and all(part not in (b"", b".", b"..") for part in suffix.split(b"/"))),
                     "complete canonical observed relative name")
                path = prefix + (b"/" + suffix if suffix else b"")
                if "errno" in node:
                    exact(node, {"relative_hex": "", "errno": 2}, "complete absent fixture root")
                    need(path not in table, "absent final root reappeared")
                    continue
                need(path in table, "final observed fixture node is missing")
                need(path not in expected, "duplicate final observed fixture node")
                expected.add(path)
                seen.add(path)
                actual = table[path]
                mode = node["mode"]
                need(stat.S_IFMT(mode) in kinds, "unsupported observed fixture node")
                exact([actual[k] for k in ("kind", "mode", "uid", "gid", "source_device", "source_inode", "nlink")],
                      [kinds[stat.S_IFMT(mode)], stat.S_IMODE(mode), node["uid"], node["gid"],
                       node["device"], node["inode"], node["links"]],
                      "complete final inode and permission observation")
                if actual["kind"] == "file":
                    need("content_hex" in node and "read_errno" not in node, "complete last file bytes required")
                    raw = bytes.fromhex(node["content_hex"])
                    exact(node["size"], len(raw), "complete observed regular file length")
                    exact({k: actual[k] for k in ("bytes", "sha256")},
                          {"bytes": len(raw), "sha256": archive.sha(raw)}, "complete last file bytes")
                elif actual["kind"] == "symlink":
                    exact(actual["target_hex"], node["target_hex"], "complete raw symlink target")
                elif actual["kind"] == "directory":
                    need("readdir_errno" not in node, "complete observed directory entries")
            present = {p for p in table if p == prefix or p.startswith(prefix + b"/")}
            exact(sorted(p.hex() for p in present), sorted(p.hex() for p in expected), "complete observed subtree")
    exact(sorted(p.hex() for p in table), sorted(p.hex() for p in seen),
          "every archived entry belongs to the complete final observed fixture")


def retain(output, origin, binding, *, stage, roots, validate, create=False):
    output = archive.root_path(output)
    prefix = FOLDER + "/" + stage + "-fixtures"
    receipt, compressed, permissions = prefix + ".json", prefix + ".bin.gz", prefix + ".permissions.json"
    expected = {"schema": "hepta.runtime.batch-public-fixture-retirement.v1", "status": "PASS",
                "stage": stage, "execution_output_root": origin, "fixture_directories": list(roots),
                "complete_evidence_sha256": archive.sha(archive.encoded(binding)),
                "semantic_invocations_added": 0, "source_inode_identifiers_are_provenance": True}
    if not (output / receipt).exists():
        need(create and str(output) == origin, "retirement requires the actual owned execution root")
        entries, pin, _ = capture(output, roots, prefix)
        validate(entries)
        permission_evidence(output, permissions, roots, entries)
        archive.remove_roots(output, roots, entries)
        archive.dump_new(output, receipt, dict(expected, entries=entries, archive=pin,
                         permissions=archive.file_pin(archive.artifact(output, permissions))))
    value = object_at(output, receipt)
    exact(sorted(value), sorted([*expected, "entries", "archive", "permissions"]), "complete retirement fields")
    exact({k: value[k] for k in expected}, expected, "retirement bound to the complete evidence")
    validate(value["entries"])
    exact(archive.file_pin(archive.artifact(output, permissions)), value["permissions"], "complete permission journal")
    permission_evidence(output, permissions, roots, value["entries"])
    counts = archive.read_archive(output, value["entries"], roots, compressed, value["archive"])
    absent(output, roots)
    return dict(expected, **counts, artifact_sha256={
        n: archive.file_pin(archive.artifact(output, n))["sha256"] for n in (receipt, compressed, permissions)})


def native(output, origin, binding, *, create=False):
    return retain(output, origin, binding, stage="native", roots=(NATIVE,), create=create,
                  validate=lambda entries: observed_entries(output, entries, origin))


def restore(output, origin, binding, admitted):
    output = archive.root_path(output)
    exact(str(output), origin, "original replay requires the actual native output origin")
    exact(native(output, origin, binding), admitted, "native archive before reconstruction")
    need(not (output / RECONSTRUCTION).exists(), "fixture reconstruction was already attempted")
    absent(output, (NATIVE, HELD, ORIGINAL))
    value = object_at(output, FOLDER + "/native-fixtures.json")
    created = []
    archive.populate(output, value["entries"], FOLDER + "/native-fixtures.bin.gz",
                     value["archive"], created, roots=(NATIVE,))
    before = archive.snapshot(output, (NATIVE,))
    exact(archive.logical(before), archive.logical(value["entries"]),
          "reconstructed native bytes, modes and link relationships")
    archive.dump_new(output, RECONSTRUCTION, {
        "schema": "hepta.runtime.batch-public-fixture-reconstruction.v1", "status": "PASS",
        "execution_output_root": origin, "native_retirement_sha256": archive.sha(archive.encoded(admitted)),
        "entries": before, "original_inode_identifiers_recreated": False,
        "new_native_calls": 0, "new_original_processes": 0})


def original(output, origin, native_binding, native_retirement, original_binding, *, create=False):
    output = archive.root_path(output)
    reconstruction = object_at(output, RECONSTRUCTION)
    expected = {"schema": "hepta.runtime.batch-public-fixture-reconstruction.v1", "status": "PASS",
                "execution_output_root": origin,
                "native_retirement_sha256": archive.sha(archive.encoded(native_retirement)),
                "original_inode_identifiers_recreated": False, "new_native_calls": 0,
                "new_original_processes": 0}
    exact({k: v for k, v in reconstruction.items() if k != "entries"}, expected,
          "complete source-owned fixture reconstruction")
    native_value = object_at(output, FOLDER + "/native-fixtures.json")
    exact(archive.logical(reconstruction["entries"]), archive.logical(native_value["entries"]),
          "all reconstructed native content and relationships")
    rename = object_at(output, FOLDER + "/original/NATIVE-FIXTURE-RENAME.json")
    original_rename = object_at(output, FOLDER + "/original/ORIGINAL-FIXTURE-RETIREMENT.json")
    exact([rename["original"], rename["retained"], rename["origin_absent"]],
          [str(Path(origin) / NATIVE), str(Path(origin) / HELD), True], "actual native fixture rename")
    exact(rename["identity_before"], rename["identity_after"], "native root inode preserved by rename")
    exact([original_rename["original"], original_rename["retired"], original_rename["origin_absent"]],
          [str(Path(origin) / NATIVE), str(Path(origin) / ORIGINAL), True], "actual original fixture retirement")
    exact(original_rename["identity_before"], original_rename["identity_after"],
          "actual original root inode preserved by rename")

    def held(entries):
        exact(mapped_entries(entries, HELD, NATIVE), reconstruction["entries"],
              "reconstructed native tree kept with identical actual inodes")

    def published(entries):
        observed_entries(output, entries, origin, original=True)
        root = next(row for row in entries if row["path_hex"] == os.fsencode(ORIGINAL).hex())
        ident = original_rename["identity_before"]
        exact([root[k] for k in ("source_device", "source_inode", "uid", "gid", "mode")],
              [ident["device"], ident["inode"], ident["uid"], ident["gid"], stat.S_IMODE(ident["mode"])],
              "archived original root is the actual renamed root")

    restored = retain(output, origin, native_binding, stage="reconstructed-native", roots=(HELD,),
                      validate=held, create=create)
    published = retain(output, origin, original_binding, stage="original", roots=(ORIGINAL,),
                       validate=published, create=create)
    absent(output, (NATIVE, HELD, ORIGINAL))
    artifacts = {**restored["artifact_sha256"], **published["artifact_sha256"],
                 RECONSTRUCTION: archive.file_pin(archive.artifact(output, RECONSTRUCTION))["sha256"]}
    for name in ("NATIVE-FIXTURE-RENAME.json", "ORIGINAL-FIXTURE-RETIREMENT.json"):
        path = FOLDER + "/original/" + name
        artifacts[path] = archive.file_pin(archive.artifact(output, path))["sha256"]
    return {"schema": "hepta.runtime.batch-public-original-fixtures.v1", "status": "PASS",
            "reconstructed_native": restored, "original": published,
            "artifact_sha256": dict(sorted(artifacts.items())),
            "new_native_calls": 0, "new_original_processes": 0}
