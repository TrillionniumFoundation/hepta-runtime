#!/usr/bin/env python3
"""Create the fixed Mac transport only; no package code is imported or executed."""
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).parent
EXPECTED = json.loads((ROOT / "expected-payloads.json").read_bytes())
def sha(raw):
    return hashlib.sha256(raw).hexdigest()
def git_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
def canonical(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
payload_root = ROOT / "payload"
manifest = b"".join(p.read_bytes() for p in sorted((ROOT / "manifest-parts").glob("*.bin")))
assert len(manifest) == EXPECTED["seal-manifest.json"]["bytes"]
assert sha(manifest) == EXPECTED["seal-manifest.json"]["sha256"]
with (payload_root / "seal-manifest.json").open("xb") as stream:
    stream.write(manifest)
actual = {str(p.relative_to(payload_root)): p for p in payload_root.rglob("*") if p.is_file()}
assert set(actual) == set(EXPECTED) and len(actual) == 23
payload = {}
for name, path in sorted(actual.items()):
    raw = path.read_bytes()
    expected = EXPECTED[name]
    assert len(raw) == expected["bytes"] and sha(raw) == expected["sha256"]
    assert git_blob(raw) == expected["git_blob"]
    assert len(name.encode("ascii")) <= 100
    payload[name] = raw
seal = json.loads(manifest)
assert seal["sealed"] is True and seal["file_count"] == 21 and seal["payload_bytes"] == 371348
assert {row["staged_path"] for row in seal["files"]} == set(payload) - {"seal-manifest.json", "install_campaign.py"}
assert sum(map(len, payload.values())) == 709014
for row in seal["files"]:
    assert len(payload[row["staged_path"]]) == row["bytes"] and sha(payload[row["staged_path"]]) == row["sha256"]
assert payload["mac/d2_campaign.py"] == payload["x230/c1-tools-01/d2_campaign.py"]
tar_bytes = io.BytesIO()
with tarfile.open(fileobj=tar_bytes, mode="w", format=tarfile.USTAR_FORMAT) as archive:
    for name, raw in sorted(payload.items()):
        info = tarfile.TarInfo(name)
        info.size = len(raw)
        info.mode = 0o600
        info.uid = info.gid = info.mtime = 0
        info.uname = info.gname = ""
        archive.addfile(info, io.BytesIO(raw))
compressed = io.BytesIO()
with gzip.GzipFile(fileobj=compressed, mode="wb", filename="", mtime=0, compresslevel=9) as stream:
    stream.write(tar_bytes.getvalue())
archive_raw = compressed.getvalue()
assert len(archive_raw) <= 1024 * 1024 and len(tar_bytes.getvalue()) <= 2 * 1024 * 1024 + 65536
with tarfile.open(fileobj=io.BytesIO(archive_raw), mode="r:gz") as archive:
    members = archive.getmembers()
    assert len(members) == 23 and [m.name for m in members] == sorted(payload)
    for member in members:
        assert member.isfile() and member.mode == 0o600 and member.uid == member.gid == member.mtime == 0
        assert member.uname == member.gname == "" and not member.linkname
        assert archive.extractfile(member).read() == payload[member.name]
archive_name = "hepta-runtime-d2-c1-sealed-payloads-01.tar.gz"
for name, raw in (
    (archive_name, archive_raw),
    (archive_name + ".base64", base64.b64encode(archive_raw) + b"\n"),
):
    with (ROOT / name).open("xb") as stream:
        stream.write(raw)
metadata = {
    "schema": "hepta-d2-c1-mac-transport-build/v1",
    "package_code_executed": False,
    "filesystem_archive_extraction": False,
    "file_count": 23,
    "payload_bytes": 709014,
    "archive": {"name": archive_name, "bytes": len(archive_raw), "sha256": sha(archive_raw), "git_blob": git_blob(archive_raw)},
    "base64": {"bytes": len(base64.b64encode(archive_raw)) + 1, "sha256": sha(base64.b64encode(archive_raw) + b"\n"), "git_blob": git_blob(base64.b64encode(archive_raw) + b"\n")},
    "tar_uncompressed_bytes": len(tar_bytes.getvalue()),
    "all_members_exact_originals": True,
    "all_member_git_hashes_matched": True,
    "all_member_bytes_rechecked_in_memory": True,
    "omitted_optional_file": "operator-argv.json",
    "seal_manifest": EXPECTED["seal-manifest.json"],
    "payloads": EXPECTED,
}
with (ROOT / "transport-manifest.json").open("xb") as stream:
    stream.write(canonical(metadata))
print(json.dumps({key: value for key, value in metadata.items() if key != "payloads"}, sort_keys=True))
