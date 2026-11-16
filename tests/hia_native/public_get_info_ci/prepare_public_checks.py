"""Preserve the public90 corpus and make its intended current get_info delta explicit."""
import ast
import hashlib
import json
from pathlib import Path
import shutil

BASE=Path('/workspace/scratch/6780eb0cbcc3')
OLD=BASE/'integration-work/restored-ci/public80-rebased/evidence/recipe-source/drivers'
ROOT=BASE/'integration-work/public-get-info-v2'
OUT=ROOT/'drivers'
OUT.mkdir()
sha=lambda raw:hashlib.sha256(raw).hexdigest()


def replace(text, before, after):
    assert text.count(before)==1, before
    return text.replace(before,after)


for name in ('ordinary_public_helpers.py','ordinary_execution_input.py'):
    shutil.copyfile(OLD/name,OUT/name)
raw=(OLD/'qualify_native_constructor_public.py').read_bytes()
text=raw.decode()
text=replace(text,"('source', 'manifest', 'baseline-elf', 'output')","('source', 'manifest', 'baseline-elf', 'get-info-reference', 'output')")
text=replace(text,"md['physical_images'] == 80","md['physical_images'] == 81")
text=replace(text,"    candidate = manifest.parent / md['elf']", "    assert md['target_get_info_integrated'] is True and md['target_get_info_slot'] == 54\n    candidate = manifest.parent / md['elf']")
text=replace(text,"    out.mkdir(parents=True)", """    out.mkdir(parents=True)
    reference = args.get_info_reference.resolve(strict=True).read_bytes()
    assert len(reference) == 1236951 and sha(reference) == 'c9ff4c9282e406de911119c2287093165d3829c333be43da06ac14f75edf295d'
    original = json.loads(reference)
    assert original['target_commit'] == 'd3d75c30719db966b004756f610007a7c723729e'
    info = original['get_info_wire'].encode()
    assert sha(info) == '6d005e04c53f0a4ef515d4f61ea95e564cbe841a51b7752fe312fc4af86cbf41'
    expected_initialize = b'{"jsonrpc":"2.0","id":1,"result":' + info.replace(
        b'"protocolVersion":"2026-07-28"', b'"protocolVersion":"2025-11-25"', 1) + b'}'
    (out / 'current-get-info-original.stdout').write_bytes(reference)""")
before="""                    if compare:
                        if variant == 'eight':"""
after="""                    if label == 'initialize' and variant == 'nine':
                        assert raw == expected_initialize, ('current get_info plus retained default SDK negotiation', parsed)
                        counts['current_get_info_initialize_checks'] += 1
                    elif compare:
                        if variant == 'eight':"""
text=replace(text,before,after)
text=replace(text,"    save()\n    workflow =", "    report.update(current_get_info_reference_sha256=sha(reference), current_get_info_wire_sha256=sha(info),\n        initialize_behavior_change='current SDK identity3.9.0 and field order; negotiated protocol retained',\n        actual_current_sdk_handshake_compared=False, ordinary_cases_retained=90)\n    save()\n    workflow =")
(OUT/'qualify_public.py').write_text(text)

raw_reader=(OLD/'verify_native_constructor_public.py').read_bytes()
reader=raw_reader.decode()
reader=reader.replace("== 80", "== 81").replace("'physical_images': 80", "'physical_images': 81").replace("80 - fresh", "81 - fresh")
reader=reader.replace("== len(order) == 80", "== len(order) == 81")
reader=reader.replace("== 80 and len(set(order)) == 80", "== 81 and len(set(order)) == 81")
reader=reader.replace("len(set(order)) == 80", "len(set(order)) == 81")
reader=reader.replace("len(linked), 80,", "len(linked), 81,").replace("'<80Q'", "'<81Q'").replace("+ 80 * 8", "+ 81 * 8")
reader=replace(reader,"folder = build / 'build/public-nine-constructor'","folder = build / 'build/public-get-info'")
reader=replace(reader,"len(md['extra_table']) == 47", "len(md['extra_table']) == 55")
reader=replace(reader,"md['extra_table'][42:] == ['target_message', 'target_request', 'target_bridge', 'historical_protocol', 'text_constructor']",
    "md['extra_table'][42:47] == ['target_message', 'target_request', 'target_bridge', 'historical_protocol', 'text_constructor']\n    assert md['extra_table'][47:54] == [None] * 7 and md['extra_table'][54] == 'current_get_info'\n    assert md['target_get_info_integrated'] is True and md['target_get_info_slot'] == 54\n    assert md['target_get_info_source_sha256'] == 'e2c4829a305593938202a5bf00e6411c5f4ba095167ff6a0603882e32fc5c89c'")
reader=replace(reader,"    captured = {}", """    reference = hashed(loop / 'current-get-info-original.stdout', 'c9ff4c9282e406de911119c2287093165d3829c333be43da06ac14f75edf295d', 1236951)
    original = json.loads(reference)
    assert original['target_commit'] == 'd3d75c30719db966b004756f610007a7c723729e'
    info = original['get_info_wire'].encode()
    assert SHA(info) == '6d005e04c53f0a4ef515d4f61ea95e564cbe841a51b7752fe312fc4af86cbf41'
    expected_initialize = b'{"jsonrpc":"2.0","id":1,"result":' + info.replace(
        b'"protocolVersion":"2026-07-28"', b'"protocolVersion":"2025-11-25"', 1) + b'}'
    assert summary['current_get_info_reference_sha256'] == SHA(reference)
    assert summary['current_get_info_wire_sha256'] == SHA(info)
    assert summary['actual_current_sdk_handshake_compared'] is False
    captured = {}""")
reader=replace(reader,"""            assert row['response'] == after[label]['response'] and row['request'] == after[label]['request']
            counts['retained_complete_response_matches'] += 1""", """            assert row['request'] == after[label]['request']
            if label == 'initialize':
                assert after[label]['response'].encode() == expected_initialize
                assert json.loads(row['response'])['result']['serverInfo']['version'] == '3.4.1'
                counts['current_get_info_initialize_checks'] += 1
            else:
                assert row['response'] == after[label]['response']
                counts['retained_complete_response_matches'] += 1""")
reader=reader.replace("hepta.runtime.public-constructor-readonly-verification.v1","hepta.runtime.public-get-info-readonly-verification.v1")
(OUT/'verify_public.py').write_text(reader)

# The ordered workflow, all text mutations, and all request expressions stay
# source-identical. The changed comparison is explicit and has a current target
# method reference; it is not described as a fresh actual SDK handshake oracle.
proof=[]
before_tree=ast.parse(raw)
after_tree=ast.parse(text)
for name in ('workflow','text_steps'):
    def assignment(tree):
        found=[node for node in ast.walk(tree) if isinstance(node,ast.Assign)
            and any(isinstance(target,ast.Name) and target.id==name for target in node.targets)]
        assert len(found)==1
        return ast.dump(found[0],include_attributes=False).encode()
    before=assignment(before_tree);after=assignment(after_tree)
    assert before==after
    proof.append({'assignment':name,'ast_sha256':sha(before)})
def requests(tree):
    return [ast.dump(node,include_attributes=False) for node in ast.walk(tree) if isinstance(node,ast.Dict)
        and any(isinstance(key,ast.Constant) and key.value=='jsonrpc' for key in node.keys)]
assert requests(before_tree)==requests(after_tree)
document={'schema':'hepta.public-get-info.preserved-public-cases.v1','ordinary_processes':4,'ordinary_responses':90,
    'retained_complete_response_matches':32,'current_get_info_initialize_checks':1,
    'original_request_asts_unchanged':True,'original_workflow_and_text_steps_asts':proof,
    'source_sha256':sha((OUT/'qualify_public.py').read_bytes()),'prior_source_sha256':sha(raw),
    'reader_sha256':sha((OUT/'verify_public.py').read_bytes()),'prior_reader_sha256':sha(raw_reader),
    'actual_current_sdk_handshake_compared':False}
(OUT/'PUBLIC_CASES.json').write_text(json.dumps(document,sort_keys=True,indent=2)+'\n')
manifest=ROOT/'build/public-get-info/manifest.json';md=json.loads(manifest.read_bytes())
elf=manifest.parent/md['elf']
built={'schema':'hepta.runtime.public-get-info-development-build.v1','status':'NATIVE_BUILD_PASS',
    'manifest':str(manifest),'manifest_sha256':sha(manifest.read_bytes()),'elf':str(elf),
    'elf_bytes':elf.stat().st_size,'elf_sha256':md['elf_sha256'],'physical_images':81,
    'fresh_member_compiles':0,'checked_reused_members':81,'fresh_hia_link_and_pack':True,
    'bootstrap_reused':True,'independent_cold_qualified':False,'actual_target_rust_compared':False}
(ROOT/'BUILD.json').write_text(json.dumps(built,sort_keys=True,indent=2)+'\n')
print(json.dumps(document,sort_keys=True))
