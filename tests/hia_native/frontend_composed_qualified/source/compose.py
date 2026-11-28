"""Reproduce the Authority91 -> Batch -> Bellman HIA source composition.

Only source authoring and parsing occur here. No native handler or Rust
reference is executed and the public catalog remains unchanged.
"""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
AUTHORITY = '9faea69f883e2d72ae839fc43b46f1ccfb2d5befd9687112f83fd38bf413493e'
HEPTA = 'd3e2c90173cf733e42b299d0c4274df4b593a12f'
pin = lambda raw: dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def run(command, output, label):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, timeout=60, cwd=output)
    (output / (label + '.stdout')).write_bytes(result.stdout)
    (output / (label + '.stderr')).write_bytes(result.stderr)
    assert result.returncode == 0 and result.stderr == b'', (label, result.returncode, result.stderr)
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hepta', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    hepta = args.hepta.resolve(strict=True)
    work = args.work.absolute()
    assert not work.exists()
    work.mkdir(parents=True)
    assert subprocess.check_output(['git', '-C', str(hepta), 'rev-parse', 'HEAD']).decode().strip() == HEPTA
    baseline = ROOT / 'baseline'
    assert pin((baseline / 'native/runtime_mcp.hepta').read_bytes())['sha256'] == AUTHORITY
    batch = run([sys.executable, '-I', '-B', str(ROOT / 'batch-authoring/author_frontend_dynamic.py'),
        '--baseline', str(baseline), '--baseline-sha256', AUTHORITY,
        '--hepta', str(hepta), '--output', str(work / 'batch')], work, 'batch-author')
    bellman = run([sys.executable, '-I', '-B', str(ROOT / 'authoring/author_frontend.py'),
        '--baseline', str(work / 'batch'), '--baseline-sha256', batch['source_sha256'],
        '--hepta', str(hepta), '--output', str(work / 'combined')], work, 'bellman-author')
    final = work / 'combined'
    batch_proof = json.loads((work / 'batch/native/runtime_mcp_batch_composition.json').read_bytes())
    comp = json.loads((final / 'native/runtime_mcp_composition.json').read_bytes())
    bellman_proof = comp['bellman_public_extension']
    before = json.loads((baseline / 'native/runtime_mcp_composition.json').read_bytes())
    assert batch_proof['entry_ast_byte_exact'] and batch_proof['prepared_request_inverse_ast_exact']
    assert batch_proof['fixed_child'] == 13 and batch_proof['global_gateway_slot'] == 47
    assert batch_proof['uses_existing_common_tool_completion_phase'] == 6
    assert batch_proof['uses_existing_growth_phase'] == 106
    assert bellman_proof['retained_entry_inverse_ast_exact']
    assert bellman_proof['fixed_child'] == 14 and bellman_proof['global_slot'] == 57
    assert bellman_proof['private_frontend_state'] == [1280, 1408]
    assert bellman_proof['phases'] == dict(allocate=15, caller=16, retire=17, pending=97)
    assert bellman_proof['pending_header_zero_fields'] == [16, 24, 32, 40, 56]
    assert comp['rebuilt_batch_extension'] == batch_proof
    assert comp['target_session_authority'] == before['target_session_authority']
    assert comp['supported_tool_names'] == before['supported_tool_names']
    assert len(comp['function_sha256']) == 84
    assert bellman['functions'] <= 128 and bellman['blocks'] <= 1536 and bellman['operations'] <= 8192
    sources = {name: (final / name).read_bytes() for name in (
        'native/runtime_mcp.hepta', 'native/runtime_mcp_composition.json',
        'native/runtime_mcp_bellman_composition.json')}
    sources['native/runtime_mcp_batch_composition.json'] = (work / 'batch/native/runtime_mcp_batch_composition.json').read_bytes()
    proof = dict(schema='hepta.runtime.authority-batch-bellman-frontend-source.v1',
        status='SOURCE_COMPOSITION_ONLY_NATIVE_AND_PUBLIC_QUALIFICATION_REQUIRED',
        composition_order=['authority91', 'batch', 'bellman'],
        authority_commit='68b0f1530602fccc063619ffe6e8fe57dc1e3ff5',
        batch_author_commit='789cfd59b61248846f4962ce5efba46d64633ed4',
        bellman_author_commit='7cb8f82ae5546cf995a020238cee5eb471acd80e',
        hepta_commit=HEPTA, authority_sha256=AUTHORITY,
        batch_source_sha256=batch['source_sha256'], source_sha256=bellman['source_sha256'],
        functions=bellman['functions'], blocks=bellman['blocks'], operations=bellman['operations'],
        source_files={name: pin(raw) for name, raw in sources.items()},
        batch=batch_proof, bellman=bellman_proof,
        catalog_names_unchanged=comp['supported_tool_names'],
        slots={'authority': 56, 'batch': 47, 'bellman': 57, 'sdk_request_registry_required': 58},
        phase_domains={'batch': [6, 106], 'authority': [13, 14, 113, 114],
            'bellman': [15, 16, 17, 97, 115, 116, 117]},
        batch_native_ci_status='v4 failed at the unchanged 180-second lane deadline; remediation independent',
        native_executions=0, rust_executions=0, public_graph_qualified=False,
        async_pending_registry_qualified=False, catalog_expanded=False,
        whole_runtime_replaced=False, old_stack_removal_qualified=False)
    sources['composition-source.json'] = (json.dumps(proof, sort_keys=True, indent=2) + '\n').encode()
    for name, raw in sources.items():
        target = ROOT / 'source' / name
        if args.check:
            assert target.read_bytes() == raw, name
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
    print(json.dumps({key: proof[key] for key in ['status', 'source_sha256', 'functions', 'blocks', 'operations',
        'native_executions', 'rust_executions', 'public_graph_qualified']}, sort_keys=True))


if __name__ == '__main__':
    main()
