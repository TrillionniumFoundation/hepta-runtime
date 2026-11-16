"""Fresh HIA modules for constructor qualification; never invokes Rust."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import sys
import time

sys.dont_write_bytecode = True


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--hepta", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--bootstrap", type=Path)
    a = p.parse_args()
    source, output = a.source.resolve(), a.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(source / "scripts"))
    from hia_native_build import NativeBuild
    status = dict(schema="hepta.text-constructor-build.v2", status="RUNNING",
                  fresh_constructor_compile=True, fresh_typed_serializer_compile=True,
                  independent_cold_qualified=False, actual_rust_executed=False,
                  source=str(source), hepta=str(a.hepta.resolve()), modules={})
    def save():
        (output / "BUILD.json").write_text(json.dumps(status, sort_keys=True, indent=2)+"\n")
    save()
    start = time.monotonic()
    try:
        build = output / "build"
        if a.bootstrap:
            shutil.copytree(a.bootstrap.resolve(), build / "bootstrap")
            status["bootstrap_reused_from"] = str(a.bootstrap.resolve())
        builder = NativeBuild(a.hepta, build)
        for name, relative, profile in [
            ("text-result-constructor", "native/text_result_constructor.hepta", "history.v1"),
            ("retained-typed-result", "native/typed_result_json.hepta", "serde-json.v1"),
        ]:
            original = (source / relative).read_bytes()
            manifest = builder.compile(name, source / relative, standalone=None, buffer_profile=profile)
            raw = manifest.read_bytes()
            data = json.loads(raw)
            if data["source_sha256"] != sha(original):
                raise ValueError("fresh compile source pin differs")
            status["modules"][name] = dict(manifest=str(manifest.relative_to(output)),
                manifest_sha256=sha(raw), source_sha256=data["source_sha256"],
                image_sha256=data["image_sha256"], buffer_profile=profile)
            save()
        status["status"] = "HIA_COMPILE_PASS"
    except BaseException as exc:
        status.update(status="FAIL", error=repr(exc))
        raise
    finally:
        status["elapsed_seconds"] = time.monotonic()-start
        save()
    print(json.dumps(status, sort_keys=True))


if __name__ == "__main__":
    main()

