"""Check the complete isolated adapter source without executing native code."""
from pathlib import Path
import argparse
import hashlib
import json
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SOURCE_SHA = '1c38b08d610c2440ae2e246bc06519f416591bbca590850f758ea8eef5848d4a'
HIA_SHA = 'fea1cccdbb11e41ba1ea60b6385d4c738697c20fc2f5e477ad78024abbe5a185'
CAPTURE_SHA = '711791d08c0e9b227d34defde626619c437a90c544171c6d94b03f235486485a'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=HERE / 'v1')
    args = parser.parse_args()
    folder = args.root.resolve(strict=True)
    source = folder / 'source'
    sys.path.insert(0, str(source / 'scripts'))
    import common
    identity = common.source_evidence(source)
    assert identity['manifest_sha256'] == SOURCE_SHA and len(identity['files']) == 38
    assert common.pin(source / 'native/binary_write_adapter.hepta')['sha256'] == HIA_SHA
    assert common.pin(source / 'parent-interface/SOURCE_MANIFEST.json')['sha256'] == 'a237011498e7da0ddad66e91f810bfd7e6f2753c200d7dd21ddd26d8f5257d90'
    assert common.pin(source / 'parent-interface/DOMAIN.json')['sha256'] == '0dc9c300dab0380e746ead00b3a8338db7abf9b8c15190208436377838999114'
    result = json.loads((folder / 'RESULTS.json').read_bytes())
    assert result['source_manifest']['sha256'] == SOURCE_SHA and result['actual_run']['sha256'] == CAPTURE_SHA
    assert result['source_files'] == 38 and result['reader_tests'] == 14 and result['full_processes'] == 27
    assert result['existing_product_files_changed'] == 0 and result['original_public_routes'] == 13
    q = result['qualification']
    assert q['status'] == 'COMPLETE_NATIVE_ADAPTER_DATA_PASS'
    assert q['actual_native_entries'] == 6715 and q['complete_native_bytes'] == 674302345
    assert q['counts'] == dict(actual_child_mismatch_controls=2,control_cases=53,interface_ready=254,
        interface_typed_null_rejections=2,lifecycle_controls=1,original_plan_inputs=433,
        original_typed_inputs=196,original_write_plan_inputs=59,original_write_ready=19,
        parent_interface_inputs=256,private_refusal_controls=50)
    for key in ('whole_runtime_replaced','public_binary_write_registered','parent_256_effect_domain_requalified',
                'old_body_101_requalified','production_carrier_installed','host_audit_ssh_lifecycle_qualified'):
        assert result[key] is False and q[key] is False
    assert q['parent_effects_executed'] == q['new_original_rust_executions'] == 0
    link = json.loads((folder / 'PARENT_INTERFACE_LINK.json').read_bytes())
    current = folder / 'parent-current'
    assert common.pin(current / 'SOURCE_MANIFEST.json')['sha256'] == 'b674d9c033dd43350a2d5f38039df469c8983149c0e568ab9c51ca614411d612'
    assert common.pin(current / 'ABI.md')['sha256'] == '46f76dbd1a3d939804a45e67e832e70d08c6aa24358658ad29c1da77a2117592'
    before = (source / 'parent-interface/ABI.md').read_text()
    after = (current / 'ABI.md').read_text()
    assert len(link['exact_abi_splices']) == 2
    forward = before
    for splice in link['exact_abi_splices']:
        assert splice['before'] and forward.count(splice['before']) == 1
        forward = forward.replace(splice['before'], splice['after'], 1)
    assert forward == after
    inverse = after
    for splice in reversed(link['exact_abi_splices']):
        assert splice['after'] and inverse.count(splice['after']) == 1
        inverse = inverse.replace(splice['after'], splice['before'], 1)
    assert inverse == before and link['parent_effects_qualified'] is False
    print(json.dumps(dict(status='EXACT_ISOLATED_ADAPTER_SOURCE_PASS',source_sha256=SOURCE_SHA,
        files=38,native_executions=0,compiler_executions=0,whole_runtime_replaced=False,
        public_binary_write_registered=False),sort_keys=True))


if __name__ == '__main__':
    main()
