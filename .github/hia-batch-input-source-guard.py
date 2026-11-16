"""Verify the candidate changes only scheduling and complete partition placement."""
from pathlib import Path
import ast
import hashlib
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BASE = "db7593e6228e2c554369c634aaeb307eaafc923a"
EXPECTED = {
    "tests/hia_native/test_batch_plan_input.py": "bfa9970b9d856f4747ef4de083f341ed8b7e008f4d78dd0d082e668de319525a",
    "native/batch_plan_input_sources.json": "c56bac38e2a6e05635050ade8bbe6c7937f7f8c8a722f05ad779adc1ced7b12b",
    "scripts/hia_native_batch_plan_input_qualification.py": "e098c9f18fc83ae405251157417c11e1477af7566e27844d8acd12272adf3261",
    ".github/workflows/hia-runtime-native.yml": "125e8def7ff240222e438e533c60d5e83b4ad657ea2e772ffe6b499b3f01277c",
    "scripts/hia_native_pipeline.py": "22f17a9bf63f36d0d6870316f1f23d851e7e9581c10ff12c8cf0c74fbd776898",
    "tests/hia_native/test_native_pipeline.py": "5fc157cb36fc240bc16d36a7757295dad8d9474152f2fc6dffd2578728e817af",
}
def original(name):
    return subprocess.check_output(["git", "-C", str(ROOT), "show", BASE + ":" + name])
def method(tree, cls, name):
    owner = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == cls)
    return next(n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name == name)
def dump(value):
    if isinstance(value, list):
        return [ast.dump(n, include_attributes=False) for n in value]
    return ast.dump(value, include_attributes=False)

for name, expected in EXPECTED.items():
    assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest() == expected, name
name = "tests/hia_native/test_batch_plan_input.py"
old_source = original(name).decode()
new_source = (ROOT/name).read_text()
old, new = ast.parse(old_source), ast.parse(new_source)
old_case = method(old, "BatchPlanInputTests", "test_01_native_typed_and_editable_pipeline")
new_case = method(new, "BatchPlanInputTests", "run_cases")
old_loop = next(n for n in old_case.body if isinstance(n, ast.For))
new_loop = next(n for n in new_case.body if isinstance(n, ast.For))
assert dump(old_loop.body) == dump(new_loop.body)
assert dump(method(old, "Recorder", "complete")) == dump(method(new, "Transport", "complete"))
old_invoke = method(old, "Recorder", "invoke")
new_invoke = method(new, "Transport", "invoke")
assert dump(old_invoke.body) == dump(new_invoke.body[1:])
assert ast.unparse(new_invoke.body[0]) == "self.sink.check_capture()"
for label in ("test_02_invalid_frames_are_before_mutation", "test_03_output_boundary_and_workspace_reuse"):
    # Resolve by ordinal to preserve the existing source-owned method names.
    number = label[:7]
    old_owner = next(n for n in old.body if isinstance(n, ast.ClassDef) and n.name == "BatchPlanInputTests")
    new_owner = next(n for n in new.body if isinstance(n, ast.ClassDef) and n.name == "BatchPlanInputTests")
    before = next(n for n in old_owner.body if isinstance(n, ast.FunctionDef) and n.name.startswith(number))
    after = next(n for n in new_owner.body if isinstance(n, ast.FunctionDef) and n.name == before.name)
    assert ast.get_source_segment(old_source, before) == ast.get_source_segment(new_source, after)
profile = "native/batch_plan_input_sources.json"
expected_profile = json.loads(original(profile))
expected_profile[name] = EXPECTED[name]
assert json.loads((ROOT/profile).read_bytes()) == expected_profile
reader = "scripts/hia_native_batch_plan_input_qualification.py"
old_profile_sha = hashlib.sha256(original(profile)).hexdigest()
assert (ROOT/reader).read_bytes() == original(reader).replace(
    old_profile_sha.encode(), EXPECTED[profile].encode())
allowed = set(EXPECTED) | {
    ".github/hia-batch-input-focused.py",
    ".github/hia-batch-input-source-guard.py",
    ".github/workflows/hia-batch-input-candidate.yml",
}
changed = set(subprocess.check_output(
    ["git", "-C", str(ROOT), "diff", "--name-only", BASE, "HEAD"]).decode().splitlines())
assert changed == allowed, sorted(changed ^ allowed)
print(json.dumps({
    "status": "SOURCE_PRESERVATION_PASS",
    "candidate_files": EXPECTED,
    "original_case_body": "unchanged",
    "complete_continuations": "unchanged",
    "control_tests": "byte-identical",
    "semantic_evidence_reader": "only-source-profile-pin-changed",
    "native_or_original_executed": False,
}, sort_keys=True))
