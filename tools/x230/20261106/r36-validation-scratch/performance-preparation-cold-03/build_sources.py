#!/usr/bin/env python3
"""Pure source derivation for the R36 validation-scratch full acceptance plan."""
import ast
import hashlib
import json
import os
from pathlib import Path
import pprint
import re

HERE = Path(__file__).resolve().parent
REF = HERE / 'reference'
ROOT = '/home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02'
R35_ROOT = '/home/qian/hepta-runtime-optimization-20261106-r35'
PROFILE = '/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-observation-01/profile/profile.json'
PROFILE_SHA = 'ed680dc1613e4aea4de99336d21009c73e71554694edbe23f9dc3a433b586e89'
TOPOLOGY_SHA = 'c131f12bd145d53bd2c26d0917411a41e6e85d19a6273fc19d0ef3744d23658e'
CHANGED = {'src/mcp/runtime/ssh_observation_profile.rs',
           'src/mcp/runtime/ssh_observation_reference_tests.rs'}
PROPOSAL = 'R24 plus reference-only Context elimination and sweep-local lazy scratch; two frozen files only'
SCOPE = ('accepted R24 plus reference-only Context elimination and sweep-local lazy scratch; '
         'two frozen source/test files; validation-scratch PR108, separate from rejected audit-cache PR106')
LEDGER = []


def need(value, message):
    if not value:
        raise ValueError(message)


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def canonical(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def functions(text):
    return {n.name: n for n in ast.parse(text).body if isinstance(n, ast.FunctionDef)}


def segment(text, name):
    return ast.get_source_segment(text, functions(text)[name])


def assignment(text, name):
    nodes = [n for n in ast.parse(text).body if isinstance(n, ast.Assign)
             and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
             and n.targets[0].id == name]
    need(len(nodes) == 1, 'unique assignment required: ' + name)
    return nodes[0]


def assign(text, name, value):
    node = assignment(text, name)
    lines = text.splitlines(keepends=True)
    old = ''.join(lines[node.lineno-1:node.end_lineno])
    new = name + ' = ' + pprint.pformat(value, sort_dicts=True) + '\n'
    lines[node.lineno-1:node.end_lineno] = [new]
    LEDGER.append({'kind': 'assignment', 'name': name, 'old': old, 'new': new})
    return ''.join(lines)


def replace(text, old, new, count=1):
    need(text.count(old) == count, 'replacement occurrence differs: ' + old[:100])
    LEDGER.append({'kind': 'literal', 'old': old, 'new': new, 'count': count})
    return text.replace(old, new)


def namespace(text):
    return text.replace(R35_ROOT, ROOT).replace('r35', 'r36').replace('R35', 'R36')


def owner_namespace(text):
    mapping = {
        'CACHE_OWNER': 'R36_CACHE_OWNER', 'OWNER_PATHS': 'R36_OWNER_PATHS',
        'OWNER_JOBS': 'R36_OWNER_JOBS', 'ORIGINAL_MISSING_PATHS': 'R36_ORIGINAL_MISSING_PATHS',
        'STAGES': 'R36_QUALIFICATION_STAGES', 'BASELINE_COMMIT': 'R36_BASELINE_COMMIT',
        'CHANGED': 'R36_CHANGED_PATHS', 'native_terminal': 'r36_owner_native_terminal',
        'native_streams': 'r36_owner_native_streams', 'closed_stages': 'r36_owner_closed_stages',
        'validate_owner_documents': 'r36_validate_owner_documents',
        'validate_c1_owner': 'r36_validate_c1_owner', 'relative_identity': 'r36_relative_identity',
        'frozen_candidate': 'r36_frozen_candidate'}
    for old, new in mapping.items():
        text = re.sub(r'\b' + re.escape(old) + r'\b', new, text)
    # Preserve the original postflight JSON key; it is not a Python identifier.
    text = text.replace("post['r36_owner_native_terminal']", "post['native_terminal']")
    return text


SEAL_SOURCE = '''R36_PREPARATION_SEAL = None


def require_r36_preparation_seal():
    value = R36_PREPARATION_SEAL
    need(isinstance(value, dict)
         and value.get("schema") == "hepta-r36-scratch-parent-preparation-seal/v1"
         and value.get("runtime_root") == str(ROOT),
         "R36 validation-scratch parent is unsealed; actual preparation bindings required")
    paths = {"qualification_launcher": ROOT / "prepare_qualify.py",
             "qualification_input": ROOT / "qualification-input.json",
             "owner_closure_input": ROOT / "cache-owner-closure-inputs.json"}
    for label, path in paths.items():
        item = value[label]
        need(set(item) == {"path", "bytes", "sha256"} and item["path"] == str(path)
             and type(item["bytes"]) is int and item["bytes"] > 0
             and isinstance(item["sha256"], str) and HEX.fullmatch(item["sha256"]),
             "actual preparation identity is unresolved: " + label)
    need(isinstance(value["cargo_home"], str) and Path(value["cargo_home"]).is_absolute()
         and ".." not in Path(value["cargo_home"]).parts,
         "actual preparer's Cargo home binding required")
    return value


'''


OWNER_BIND_SOURCE = '''def bind_r36_chain_and_cache_owner(preparation, build_inputs, bind):
    """Rebind completed D2 evidence without reading or transferring a build cache."""
    seal = require_r36_preparation_seal()
    closure_id, raw = bind(ROOT / "cache-owner-closure-inputs.json",
                           seal["owner_closure_input"], retain=True)
    closure = json.loads(raw)
    need(build_inputs["owner_closure_input_sha256"] == closure_id["sha256"]
         and preparation["cache_owner_closure_input"] == closure_id,
         "R36 preparation binds another original cache-owner closure")
    need(closure["schema"] == "hepta-r36-d2-cache-owner-closure/v1"
         and closure["sealed"] is True and closure["required_missing_bindings"] == []
         and closure["owner_root"] == str(R36_CACHE_OWNER)
         and closure["build_mode"] == "cold-only" and closure["cache_path"] is None
         and closure["historical_cache_path"] == str(R36_CACHE_OWNER / "target-build")
         and closure["cold_target_path"] == str(ROOT / "target-build")
         and closure["cache_reused"] is False and closure["ownership_transfer_applicable"] is False
         and closure["historical_auditors_to_execute"] == 0
         and closure["candidate_adopted"] is False
         and closure["qualification_or_measurement_still_running"] is False
         and set(closure["inputs"]) == set(R36_OWNER_PATHS),
         "R36 completed cache-owner input set differs")
    for label, path in R36_OWNER_PATHS.items():
        need(closure["inputs"][label]["path"] == str(path),
             "R36 owner evidence path differs: " + label)
    need(set(closure["jobs"]) == set(R36_OWNER_JOBS) | {"c1_first_holder", "c1_recovery_holder"}
         and all(closure["jobs"][key] == value for key, value in R36_OWNER_JOBS.items()),
         "R36 cache-owner original jobs differ")
    documents = {}
    for label, pin in closure["inputs"].items():
        _, data = bind(pin["path"], pin, retain=True, maximum=8 * 1024 * 1024)
        documents[label] = json.loads(data)
    current = qualification_projection(source_inputs(R36_CACHE_OWNER / "source"))
    owner = r36_validate_owner_documents(documents, closure, current,
                                         build_inputs["qualification_harness_sha256"])
    need(preparation["cache_owner_closure"] == owner,
         "completed R36 preparation and rebound D2 owner evidence disagree")
    need(closure["original_missing_paths"] == [str(path) for path in R36_ORIGINAL_MISSING_PATHS]
         and all(not os.path.lexists(path) for path in R36_ORIGINAL_MISSING_PATHS),
         "the preserved original D2 failure acquired synthetic results")
    for pin in owner["retained_release_programs"].values():
        bind(pin["path"], pin, maximum=64 * 1024 * 1024)
    # The D2 originals are historical evidence. No old cache is accepted,
    # opened, transferred, or reconstructed by this cold-only consumer.
    return owner


'''


def make_owner(preparer):
    pieces = []
    for name in ('CACHE_OWNER', 'OWNER_JOBS', 'OWNER_PATHS', 'ORIGINAL_MISSING_PATHS'):
        pieces.append(owner_namespace(ast.get_source_segment(preparer, assignment(preparer, name))))
    for name in ('relative_identity', 'native_terminal', 'closed_stages', 'native_streams',
                 'validate_owner_documents', 'validate_c1_owner'):
        pieces.append(owner_namespace(segment(preparer, name)))
    candidate = owner_namespace(segment(preparer, 'frozen_candidate'))
    candidate = replace(candidate, 'def r36_frozen_candidate(manifest):',
        'def r36_frozen_candidate(manifest, bind):\n'
        '    def read_bound(identity, maximum=8 * 1024 * 1024):\n'
        '        return bind(identity["path"], identity, maximum=maximum, retain=True)[1]')
    pieces.append(candidate)
    return '\n\n\n'.join(pieces) + '\n\n\n' + OWNER_BIND_SOURCE


def make_binder(original):
    text = namespace(original)
    text = assign(text, 'R36_CHANGED_PATHS', CHANGED)
    text = assign(text, 'R36_ADOPTION_SCOPE', SCOPE)
    text = replace(text, 'R24 plus legacy-read JSON deferral and observation command move; three frozen files only', PROPOSAL)
    text = text.replace('three selected source and test files', 'two selected source and test files')
    text = text.replace('three-file R24 ablation', 'two-file R24 ablation')
    text = text.replace('three selected files', 'two selected files')
    text = text.replace('legacy-read JSON deferral and observation command ownership move on accepted R24',
                        'reference-only Context elimination and sweep-local lazy scratch on accepted R24')
    text = replace(text, '"--cargo-home", "/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02", "--jobs", "2"]',
                        '"--cargo-home", require_r36_preparation_seal()["cargo_home"], "--jobs", "2"]')
    text = replace(text, 'preparation.get("cache_transferred_by_rename") is True',
                        'preparation.get("build_mode") == "cold-only"\n'
                        '         and preparation.get("preparation_attempt") == "cold-02"\n'
                        '         and preparation.get("cache_reused") is False\n'
                        '         and preparation.get("ownership_transfer_applicable") is False\n'
                        '         and preparation.get("cache_transferred_by_rename") is False\n'
                        '         and preparation.get("new_empty_target_created") is True')
    text = replace(text, 'preparation.get("cache_to_transfer") == str(R36_CACHE_OWNER / "target-build")',
                        'preparation.get("cache_to_transfer") is None')
    text = replace(text, 'candidate_inputs["schema"] == "hepta-x230-r36-candidate/v1"',
                        'candidate_inputs["schema"] == "hepta-x230-r36-candidate-draft/v1"')
    text = replace(text, 'and candidate_inputs["patch_path"] == "candidate.patch"',
                        'and candidate_inputs["revision"] == "lazy-scratch-draft-03"')
    old = '''    need(input_id == {"path": str(fixed["qualification_input"]), "bytes": 3742,
         "sha256": "652541a8f461af9cc7dccd80b5989ffd6e151a8885dea4cc4675f2d054a8be63"},
         "frozen R36 qualification input differs")
    need(launcher_id == {"path": str(fixed["qualification_launcher"]), "bytes": 32838,
         "sha256": "6870655895432c8bd3ca266d00eb4a68b3150619352306c997a81ca0487130f4"},
         "frozen R36 preparation launcher differs")'''
    new = '''    seal = require_r36_preparation_seal()
    need(input_id == seal["qualification_input"], "frozen R36 qualification input differs")
    need(launcher_id == seal["qualification_launcher"], "frozen R36 preparation launcher differs")'''
    text = replace(text, old, new)
    text = replace(text, '    need(patch_id == frozen_patch and patch_id["sha256"] == candidate_inputs["patch_sha256"],',
                        '    need(patch_id == {key: frozen_patch[key] for key in ("path", "bytes", "sha256")}\n'
                        '         and patch_id["sha256"] == candidate_inputs["patch_sha256"],')
    text = replace(text, '         and preparation["candidate_patch"] == patch_id',
                        '         and preparation["candidate_patch"] == frozen_patch')
    text = replace(text, '    candidate_inputs, frozen_patch = r36_frozen_candidate(build_inputs, bind)',
                        '    candidate_inputs, frozen_patch = r36_frozen_candidate(build_inputs, bind)\n'
                        '    _, patch_raw = bind(fixed["candidate_patch"], patch_id, retain=True)\n'
                        '    patch_git = hashlib.sha1(b"blob " + str(len(patch_raw)).encode("ascii") + b"\\0" + patch_raw).hexdigest()\n'
                        '    need(frozen_patch["git_blob"] == patch_git == "273f9f72dd2e8da9d26cad55403cc09694bc96c3",\n'
                        '         "R36 original four-field patch identity differs")')
    text = replace(text, '    def document(path, expected=None):',
                        '    require_r36_preparation_seal()\n\n    def document(path, expected=None):')
    return SEAL_SOURCE + text


def make_parent(original, binder, owner):
    start = original.index('"""R35-specific receipt checks, inserted into the unchanged campaign parent.')
    end = original.index('def commands(out, attempt, baseline_runtime, baseline_sha, candidate_sha):')
    prefix, suffix = namespace(original[:start]), namespace(original[end:])
    prefix = replace(prefix,
        'PROFILE = Path("/home/qian/hepta-runtime-optimization-20261023/r11-native-observation-abba-20261103-02/profile/profile.json")',
        'PROFILE = Path(' + json.dumps(PROFILE) + ')')
    prefix = replace(prefix, 'TOPOLOGY = R16 / "benchmark-topology.json"',
                     'TOPOLOGY = ROOT / "measurement-fixtures-01/topology.json"')
    prefix = replace(prefix, 'FROZEN_JOBS = Path("/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01")',
                     'FROZEN_JOBS = ROOT / "measurement-fixtures-01/jobs"')
    prefix = replace(prefix, 'fe1e9551b5b8812ad6ed3da018c282b7261f7caeb2f49e4dcfefba7ff784ab08', PROFILE_SHA)
    prefix = replace(prefix, '8c0767d3318131a7d470d9cde8e327a59ce18adf022c8bc1b1d5a0fa9a865287', TOPOLOGY_SHA)
    suffix = replace(suffix, '"r36-cancel-recovery-"', '"s36-cancel-recovery-"')
    suffix = replace(suffix, '"h35"', '"hs36"')
    suffix = replace(suffix, 'def main():\n', 'def main():\n    require_r36_preparation_seal()\n')
    return prefix + binder + '\n\n' + owner + suffix


def make_installer(original):
    text = namespace(original)
    text = replace(text, 'OLD = Path("/home/qian/hepta-runtime-optimization-20261105-r29")',
                   'OLD = Path(' + json.dumps(R35_ROOT) + ')')
    text = replace(text, 'c62d10947f018cb12eb173ad663309c1a10dc75199773c567bcaf73e3284ea11',
                   'eec0348217f6c679d1f965004f1bd8ecded2886fc1c654d45a9ad6ea700391e4')
    text = replace(text, 'a377791a94e1327bdf3c7da98f30b379caafe6948295d81871f06287bf7c5ef0',
                   'eb50cd7ab0376c4b3dc768e8d184fdc23eeaa90c2ce5bdd4b9e9ac551448504e')
    text = replace(text, '    need(bundle["schema"] == "hepta-r36-parent-runner-bundle/v1" and bundle["runtime_root"] == str(ROOT)',
                   '    need(bundle.get("sealed") is True\n'
                   '         and bundle["schema"] == "hepta-r36-parent-runner-bundle/v1" and bundle["runtime_root"] == str(ROOT)')
    text = replace(text, '    parent.private_directory(HERE)\n',
                   '    parent.require_r36_preparation_seal()\n    parent.private_directory(HERE)\n')
    text = replace(text, '    lifecycle_manifest_path = LIFECYCLE / "lifecycle-tools-manifest-01.json"',
                   '''    fixture_root = ROOT / "measurement-fixtures-01"
    fixture_names = {"topology.json", *["jobs/" + name for name in bundle["frozen_job_names"]]}
    need(len(bundle["frozen_job_names"]) == 6 and len(fixture_names) == 7
         and set(bundle["fixture_inputs"]) == fixture_names,
         "seven frozen recovered fixture inputs required")
    for name, expected in sorted(bundle["fixture_inputs"].items()):
        relative = Path(name)
        need(not relative.is_absolute() and ".." not in relative.parts
             and (name == "topology.json" or (len(relative.parts) == 2 and relative.parts[0] == "jobs"
                  and relative.name.endswith(".json"))), "unsafe fixed fixture member")
        identity, data = parent.checked(HERE / "frozen-fixture-inputs" / relative,
                                        expected, maximum=65536, retain=True)
        bindings.append(identity)
        payloads[fixture_root / relative] = data
        copies.append({"source": identity, "destination": str(fixture_root / relative), "changed": False})
    need(hashlib.sha256(payloads[fixture_root / "topology.json"]).hexdigest() == parent.TOPOLOGY_SHA,
         "recovered topology differs from the fixed parent")
    lifecycle_manifest_path = LIFECYCLE / "lifecycle-tools-manifest-01.json"''')
    text = replace(text, '    need(not any(os.path.lexists(path) for path in [LIFECYCLE, receipt_path, *payloads,',
                   '    need(not any(os.path.lexists(path) for path in [LIFECYCLE, fixture_root, receipt_path, *payloads,')
    text = replace(text, '    parent.private_directory(LIFECYCLE, create_new=True)\n',
                   '    parent.private_directory(LIFECYCLE, create_new=True)\n'
                   '    parent.private_directory(fixture_root, create_new=True)\n'
                   '    parent.private_directory(fixture_root / "jobs", create_new=True)\n')
    return text


def write(path, raw):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    binder = make_binder((REF / 'r35_qualification_binding.py').read_text())
    owner = make_owner((REF / 'prepare_r36_qualify_cold02.py').read_text())
    original_parent = (REF / 'r35_campaign.py').read_text()
    parent = make_parent(original_parent, binder, owner)
    lifecycle = namespace((REF / 'r35_lifecycle_campaign.py').read_text())
    lifecycle = replace(lifecycle, 'Path("/home/qian/r36lc1")', 'Path("/home/qian/s36lc1")')
    lifecycle = replace(lifecycle, '    need(Path(parent.__file__).resolve() == HELPERS, "helper module path differs")',
                        '    need(Path(parent.__file__).resolve() == HELPERS, "helper module path differs")\n'
                        '    parent.require_r36_preparation_seal()')
    outputs = {'r36_campaign.py': parent, 'r36_lifecycle_campaign.py': lifecycle,
               'prepare_campaign_inputs.py': namespace((REF / 'prepare_campaign_inputs.py').read_text()),
               'prepare_lifecycle_inputs.py': namespace((REF / 'prepare_lifecycle_inputs.py').read_text()),
               'install_measurement_tools.py': make_installer((REF / 'install_measurement_tools.py').read_text())}
    for text in outputs.values():
        ast.parse(text)
    ast.parse(binder)
    ast.parse(owner)
    need('R35_CACHE_OWNER' not in parent and 'hepta-x230-r35-preparation' not in parent, 'old current-owner logic leaked')
    need('R36_PREPARATION_SEAL = None' in parent, 'future seal was filled')
    need('"hs36"' in parent and '"h35"' not in parent and '"h36"' not in parent, 'socket namespace differs')
    for path, text in outputs.items():
        write(HERE / 'generated' / path, text.encode())
    write(HERE / 'r36_qualification_binding.py', binder.encode())
    write(HERE / 'cache_owner_binding.py', owner.encode())
    write(HERE / 'source-edit-ledger.json', canonical({'schema': 'hepta-r36-scratch-source-edit-ledger/v1',
          'scope': 'pure local source derivation; no generated function imported or called', 'edits': LEDGER}))
    print(json.dumps({'generated': {name: identity(text.encode()) for name, text in outputs.items()},
                      'binder': identity(binder.encode()), 'owner': identity(owner.encode()),
                      'actual_qualification_pins': None, 'target_functions_executed': 0}, sort_keys=True))


if __name__ == '__main__':
    main()
