"""Inspect complete build evidence after relocation and controlled corruption."""
from pathlib import Path
import argparse
import json
import sys
import time

sys.dont_write_bytecode = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.source_root / "scripts"))
    import hia_native_filesystem_parity_build as build
    started = time.monotonic()
    args.output.mkdir(mode=0o700)
    source = args.source_root.resolve(strict=True)
    manifest = args.manifest.resolve(strict=True)
    bundle = manifest.parent
    evidence = build.inspect_bundle(manifest, source_root=source)
    original_pins = build.source_pins(source)
    files = ["manifest.json", "layout.json", "filesystem-parity.elf", *build.PACK_FILES]
    files.extend("bootstrap/" + name for name in build.BOOTSTRAP_FILES)
    for kind in ("owner", "packer"):
        name = "filesystem-parity" if kind == "owner" else "filesystem-parity-packer"
        files.extend(kind + "/" + entry for entry in (*build.COMPILE_FILES, name + ".hepta"))
    original_artifacts = {name: build.file_record(bundle / name) for name in files}

    def dump(path, value):
        build.write_new(path, build.json_bytes(value))

    def copy_files(src, dst, names):
        dst.mkdir(mode=0o700)
        for name in names:
            path = dst / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            build.write_new(path, build.read(src / name))

    relocated_source = args.output / "relocated-source"
    relocated_bundle = args.output / "relocated-bundle"
    copy_files(source, relocated_source, build.SOURCE_FILES)
    copy_files(bundle, relocated_bundle, files)
    relocated = build.inspect_bundle(relocated_bundle / "manifest.json", source_root=relocated_source)
    assert relocated == evidence
    controls = []

    def reject(name, relative, transform, *, in_source=False):
        path = (relocated_source if in_source else relocated_bundle) / relative
        raw = path.read_bytes()
        modified = transform(raw)
        assert modified != raw
        path.write_bytes(modified)
        try:
            try:
                build.inspect_bundle(relocated_bundle / "manifest.json", source_root=relocated_source)
            except (ValueError, OSError, KeyError, TypeError) as error:
                controls.append({"name": name, "path": relative, "bytes": len(modified),
                                 "sha256": build.sha(modified), "rejected": type(error).__name__, "message": str(error)})
            else:
                raise AssertionError("corrupt build was admitted: " + name)
        finally:
            path.write_bytes(raw)
        assert build.inspect_bundle(relocated_bundle / "manifest.json", source_root=relocated_source) == evidence

    def change_json(raw, key, value):
        parsed = json.loads(raw)
        parsed[key] = value
        return build.json_bytes(parsed)

    reject("complete-source", "native/filesystem_parity.hepta", lambda raw: raw + b"\n", in_source=True)
    reject("compiler-generation", "bootstrap/B2.image.bin", lambda raw: bytes([raw[0] ^ 1]) + raw[1:])
    reject("compiler-input", "owner/module.input.bin", lambda raw: raw[:-1] + bytes([raw[-1] ^ 1]))
    reject("compiler-output-tail", "owner/module.output.bin", lambda raw: raw[:-1] + bytes([raw[-1] ^ 1]))
    reject("compiler-stderr", "owner/module.stderr.log", lambda raw: b"unexpected\n")
    reject("packer-output-tail", "pack.output.bin", lambda raw: raw[:-1] + bytes([raw[-1] ^ 1]))
    reject("packed-elf", "filesystem-parity.elf", lambda raw: raw[:256] + bytes([raw[256] ^ 1]) + raw[257:])
    reject("mismatched-actual-stdout", "pack.stdout.log", lambda raw: change_json(raw, "core_u32", 80))
    reject("mismatched-complete-receipt", "pack.receipt.json", lambda raw: change_json(raw, "source_unchanged", False))
    reject("false-production-claim", "manifest.json", lambda raw: change_json(raw, "production_activated", True))
    reject("production-boolean-type", "manifest.json", lambda raw: change_json(raw, "production_activated", 0))
    reject("compile-scope-boolean-type", "owner/build.json", lambda raw: change_json(raw, "whole_runtime_replaced", 0))
    reject("duplicate-manifest-field", "manifest.json", lambda raw: b'{"production_activated":false,' + raw.lstrip()[1:])

    # Guard every reader access during a complete positive admission, so
    # retained historical absolute paths cannot fetch a producer artifact.
    raw_read = build.read
    audited = set()
    def relocated_only(path):
        path = Path(path).absolute()
        assert path.is_relative_to(relocated_source) or path.is_relative_to(relocated_bundle), path
        audited.add(str(path))
        return raw_read(path)
    build.read = relocated_only
    try:
        offline = build.inspect_bundle(relocated_bundle / "manifest.json", source_root=relocated_source)
        assert offline == evidence
    finally:
        build.read = raw_read
    assert build.source_pins(source) == original_pins
    assert {name: build.file_record(bundle / name) for name in files} == original_artifacts
    dump(args.output / "EVIDENCE.json", evidence)
    dump(args.output / "CONTROLS.json", controls)
    result = {"status": "PASS", "refusals": len(controls), "positive_reads": 3 + len(controls),
              "new_native_calls": 0, "new_rust_processes": 0, "relocated_without_reading_producer_paths": True,
              "audited_relocated_read_paths": len(audited),
              "source_files_unchanged": len(original_pins), "build_files_unchanged": len(original_artifacts),
              "evidence": build.file_record(args.output / "EVIDENCE.json"),
              "controls": build.file_record(args.output / "CONTROLS.json"),
              "elapsed_seconds": time.monotonic() - started,
              "public_filesystem_handlers_complete": False, "whole_runtime_replaced": False}
    dump(args.output / "RESULT.json", result)
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
