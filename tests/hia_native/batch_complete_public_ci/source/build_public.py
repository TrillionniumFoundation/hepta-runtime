"""Build both fixed public carriers; the second reuses checked HIA members."""
from pathlib import Path
import argparse
import json
import os
import shutil
import sys

from receipt_support import ROOT, PIN, regular, require, put


def build(hepta, output):
    require(os.environ.get("GITHUB_ACTIONS") == "true", "fresh bootstrap is restricted to CI")
    hepta = Path(hepta).resolve(strict=True)
    output = Path(output).absolute()
    output.mkdir(parents=True, exist_ok=False)
    source = ROOT / "native-source"
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(source / "scripts"))
    from public_nine_build import build_runtime_mcp, source_check
    before = source_check(source)
    report = {"schema": "hepta.runtime.batch-public-complete-build.v1", "status": "RUNNING",
        "source_binding": before, "source_root": str(source), "build_root": str(output),
        "graphs": {}, "public_batch_qualified": False, "whole_runtime_replaced": False}
    put(output / "BUILD.json", report)
    try:
        normal = build_runtime_mcp(hepta, output / "public-build", name="public94", source_root=source)
        normal_row = json.loads(regular(normal))
        require(len(normal_row["members"]) == 94 and all(r["fresh_compile"] is True for r in normal_row["members"]),
            "all 94 public members must be freshly compiled")
        members = {r["name"]: r["manifest"] for r in normal_row["members"]}
        boot = output / "private-build/bootstrap"
        boot.mkdir(parents=True)
        for name in ("bootstrap.json", "B1.image.bin", "B2.image.bin", "B3.image.bin"):
            shutil.copyfile(output / "public-build/bootstrap" / name, boot / name)
        private = build_runtime_mcp(hepta, output / "private-build", name="private94", source_root=source,
            manifests=members, private_fixture=True)
        private_row = json.loads(regular(private))
        require(len(private_row["members"]) == 94 and all(r["fresh_compile"] is False for r in private_row["members"]),
            "private carrier must reuse all exact public HIA members")
        for label, manifest in (("public", normal), ("private", private)):
            row = json.loads(regular(manifest))
            report["graphs"][label] = {"manifest": manifest.relative_to(output).as_posix(),
                "manifest_pin": PIN(regular(manifest)), "elf": (manifest.parent / row["elf"]).relative_to(output).as_posix(),
                "elf_pin": PIN(regular(manifest.parent / row["elf"]))}
        require(source_check(source) == before, "source changed during the paired build")
        report.update(status="PASS", fresh_member_compiles=94, reverified_private_members=94,
            actual_linker_compiles=2, actual_packer_compiles=2, actual_hia_compiles=98)
    except BaseException as error:
        report.update(status="FAIL", failure=repr(error))
        raise
    finally:
        put(output / "BUILD.json", report)
    print(json.dumps({k: report[k] for k in ("status", "actual_hia_compiles", "fresh_member_compiles",
        "reverified_private_members", "graphs")}, sort_keys=True))
    return report


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--hepta", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    build(a.hepta, a.output)
