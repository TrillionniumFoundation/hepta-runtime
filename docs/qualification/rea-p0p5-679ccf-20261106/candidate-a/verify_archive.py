#!/usr/bin/env python3
"""Verify every regular archive member against the publication index without extraction."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile

def verify(archive, index):
    expected = {row["archive_path"]: row for row in index["entries"] if row["disposition"] == "included"}
    assert len(expected) == sum(row["disposition"] == "included" for row in index["entries"])
    seen = set()
    total = 0
    with gzip.open(archive, "rb") as zipped:
        with tarfile.open(fileobj=zipped, mode="r|", ignore_zeros=True) as tar:
            for member in tar:
                name = member.name
                assert name not in seen and name in expected, "unexpected or duplicate tar member: " + name
                assert member.isfile() and not member.issym() and not member.islnk(), "nonregular tar member"
                assert not name.startswith("/") and ".." not in PurePosixPath(name).parts
                row = expected[name]
                assert member.size == row["bytes"], "member size mismatch: " + name
                digest = hashlib.sha256()
                count = 0
                with tar.extractfile(member) as stream:
                    for block in iter(lambda: stream.read(1048576), b""):
                        count += len(block)
                        digest.update(block)
                assert count == row["bytes"] and digest.hexdigest() == row["sha256"], "member bytes mismatch: " + name
                total += count
                seen.add(name)
        for block in iter(lambda: zipped.read(1048576), b""):
            assert not block.strip(b"\0"), "unexpected trailing gzip payload"
    assert seen == set(expected), "missing expected archive members"
    return {"member_count": len(seen), "uncompressed_member_bytes": total,
            "each_member_actual_bytes_and_sha256_checked": True,
            "member_set_complete_without_duplicates": True,
            "only_regular_members": True, "gzip_read_to_eof": True,
            "extracted_to_filesystem": False}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True)
    parser.add_argument("--index", required=True)
    args = parser.parse_args()
    result = verify(Path(args.archive), json.loads(Path(args.index).read_bytes()))
    print(json.dumps(result, sort_keys=True))

if __name__ == "__main__":
    main()
