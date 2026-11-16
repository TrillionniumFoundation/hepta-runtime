"""Retain complete focused evidence without rebuildable Cargo intermediates."""
import argparse
import json
import os
from pathlib import Path
import stat
import sys
import tarfile

sys.dont_write_bytecode = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.source_root.resolve(strict=True)
    capture = args.capture.absolute()
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(root/"scripts"))
    import hia_native_scope_annotation_qualification as q
    members = {"recipe-source/"+name: root/name for name in q.SOURCE_FILES}
    if capture.exists():
        for directory, subdirs, files in os.walk(capture, followlinks=False):
            parent = Path(directory)
            subdirs[:] = sorted(name for name in subdirs
                if (parent/name).relative_to(capture).as_posix() != "original/cargo-target")
            for name in subdirs:
                if (parent/name).is_symlink():
                    raise ValueError("unexpected evidence directory link")
            for name in sorted(files):
                path = parent/name
                relative = path.relative_to(capture).as_posix()
                if not stat.S_ISREG(path.lstat().st_mode):
                    raise ValueError("unexpected non-file in evidence: "+relative)
                members["capture/"+relative] = path
    manifest = {name: q.file_pin(path) for name, path in sorted(members.items())}
    archive = output/"scope-annotation-evidence.tar.gz"
    with tarfile.open(archive, "x:gz", compresslevel=1) as stream:
        for name, path in sorted(members.items()):
            with q.opened(path) as source:
                info = stream.gettarinfo(str(path), arcname=name)
                if not info.isfile():
                    raise ValueError("evidence changed kind during archive")
                stream.addfile(info, source)
            if q.file_pin(path) != manifest[name]:
                raise ValueError("evidence changed while archiving")
    receipt = dict(schema="hepta.scope-annotation.retained-archive.v1", members=manifest,
        archive=dict(file=archive.name, **q.file_pin(archive)),
        excluded_rebuildable_directory="original/cargo-target", qualification_inferred=False)
    (output/"manifest.json").write_bytes(q.encoded(receipt))
    print(json.dumps(dict(files=len(members), archive=receipt["archive"]), sort_keys=True))


if __name__ == "__main__":
    main()
