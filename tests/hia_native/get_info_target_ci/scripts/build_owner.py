"""Fresh HIA compile of only the previously generated fixed get_info source."""
from pathlib import Path
import argparse, hashlib, json, sys, time
sys.dont_write_bytecode = True
def sha(raw): return hashlib.sha256(raw).hexdigest()
def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "generated", "hepta", "output"):
        p.add_argument("--" + name, required=True, type=Path)
    a = p.parse_args()
    source, generated, hepta = (getattr(a, name).resolve(strict=True) for name in ("source", "generated", "hepta"))
    output = a.output.absolute(); output.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(source / "support"))
    from hia_native_build import NativeBuild
    original = (generated / "native/current_get_info.hepta").read_bytes()
    composition = json.loads((generated / "native/current_get_info.composition.json").read_bytes())
    assert sha(original) == composition["source_sha256"]
    report = dict(schema="hepta.current-get-info.native-build.v1", status="RUNNING",
        fresh_native_compile=True, bootstrap_reused=False, independent_cold_qualified=False,
        original_rust_executed=False, public_frontend_registered=False)
    def save(): (output / "BUILD.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    start = time.monotonic(); save()
    try:
        builder = NativeBuild(hepta, output / "build")
        manifest = builder.compile("current-get-info", generated / "native/current_get_info.hepta",
                                   standalone=None, buffer_profile="standard")
        raw = manifest.read_bytes(); data = json.loads(raw)
        assert data["source_sha256"] == sha(original)
        assert (generated / "native/current_get_info.hepta").read_bytes() == original
        report.update(status="HIA_COMPILE_PASS", source_sha256=data["source_sha256"],
            image_sha256=data["image_sha256"], manifest=manifest.relative_to(output).as_posix(),
            manifest_sha256=sha(raw), compiler_sha256=data["compiler_sha256"])
    except BaseException as error:
        report.update(status="FAIL", error=repr(error)); raise
    finally:
        report["elapsed_seconds"] = time.monotonic() - start; save()
    print(json.dumps(report, sort_keys=True))
if __name__ == "__main__": main()
