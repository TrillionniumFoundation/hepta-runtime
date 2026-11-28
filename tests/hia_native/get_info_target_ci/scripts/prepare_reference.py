"""Extract five primary source files; never decode expected get_info results."""
from pathlib import Path
import argparse, json, sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from reference_custody import inspect_zip
def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--reference-zip", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    proof, primary, rows = inspect_zip(a.reference_zip, observe=False)
    assert rows == [] and proof["observation_outputs_decoded"] is False
    output = a.output.absolute(); output.mkdir(parents=True, exist_ok=False)
    for name, raw in primary.items():
        path = output / name; path.write_bytes(raw); path.chmod(0o400)
    (output / "PRIMARY_CUSTODY.json").write_text(json.dumps(proof, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"status": "PRIMARY_SOURCE_CUSTODY_PASS", "files": len(primary),
                      "expected_results_decoded": False}, sort_keys=True))
if __name__ == "__main__": main()
