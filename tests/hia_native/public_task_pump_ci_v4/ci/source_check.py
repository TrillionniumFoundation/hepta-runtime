"""Read the entire portable package and its immutable source boundaries."""
from pathlib import Path
import argparse
import json
import hashlib
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import pin, require, verify

def source(package, manifest_sha256, *, syntax=False):
    package = Path(package).resolve(strict=True)
    manifest = package / "PACKAGE.json"
    require(pin(manifest)["sha256"] == manifest_sha256, "package manifest identity differs")
    data = json.loads(manifest.read_bytes())
    expected = dict(data["files"])
    expected["PACKAGE.json"] = pin(manifest)
    actual = verify(package, expected)
    for name, row in data["files"].items():
        mode = row.get("mode", "100644")
        require(mode in ("100644", "100755") and bool((package/name).stat().st_mode & 0o111) == (mode == "100755"),
                "source executable mode differs: " + name)
    inputs = json.loads((package / "INPUTS.json").read_bytes())
    require(inputs["graph"]["files"] == 223 and inputs["port"]["files"] == 143
            and inputs["original"]["files"] == 31, "fixed source closure differs")
    require(pin(package/"graph/source/native/runtime_mcp_sources.json")["sha256"]
            == inputs["graph"]["source_binding_sha256"], "graph closure identity differs")
    require(pin(package/"port/PACKAGE.json")["sha256"] == inputs["port"]["package_sha256"],
            "packed worker/caller source identity differs")
    require(pin(package/"wire/reference/package-manifest.json")
            == inputs["original"]["package_manifest"], "original source identity differs")
    for row in inputs["existing_source_rows"]:
        require(actual[row["path"]] == {"bytes": row["bytes"], "sha256": row["sha256"]},
                "retained source differs: " + row["path"])
        raw = (package/row["path"]).read_bytes()
        require(hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest() == row["git_blob"],
                "retained Git object differs: " + row["path"])
    if syntax:
        require(set(data["new_python_sources"]) <= set(data["files"]), "new Python source inventory differs")
        for name in sorted(data["files"]):
            if not name.endswith(".py"):
                continue
            compile((package/name).read_bytes(), str(package/name), "exec", dont_inherit=True)
    return {"manifest": pin(manifest), "files": len(actual), "inputs": pin(package/"INPUTS.json"),
            "graph_source_binding": inputs["graph"]["source_binding_sha256"]}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    result = source(args.package, args.manifest_sha256, syntax=True)
    print(json.dumps({"status": "EXACT_SOURCE_CLOSURE_PASS", **result,
                      "native_executed": False, "rust_executed": False}, sort_keys=True))

if __name__ == "__main__":
    main()
