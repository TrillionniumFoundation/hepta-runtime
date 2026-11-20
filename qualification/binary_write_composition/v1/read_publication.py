"""DATA-only check of published source, exact restored receipts and old holds."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,sys
ROOT=Path(__file__).resolve().parent
SOURCE='4b3ef39a1c93b9d786407310240b890008c5dc468b6db315bd5f03693de896d0'
READBACK='c2470b307aa3122559df27b13342099d0538f1538fc058c434693cdac1cda2dd'
QUALIFICATION='526cbaa1c94721ee9a93408937d45200da01a6c157c3160ec059743c2f057b66'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(path):
 with path.open('rb') as stream:return dict(bytes=path.stat().st_size,sha256=hashlib.file_digest(stream,'sha256').hexdigest())
def decode(path):return json.loads(path.read_bytes())
def source(root,expected):
 raw=(root/'SOURCE_MANIFEST.json').read_bytes();assert sha(raw)==expected
 rows=decode(root/'SOURCE_MANIFEST.json')['files'];assert len(rows)==len({x['path']for x in rows})
 assert {p.relative_to(root).as_posix()for p in root.rglob('*')if p.is_file()}=={x['path']for x in rows}|{'SOURCE_MANIFEST.json'}
 for row in rows:
  p=root/row['path'];assert not p.is_symlink() and p.stat().st_mode&0o777==0o644
  raw=p.read_bytes();assert len(raw)==row['bytes'] and sha(raw)==row['sha256']
  assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==row['git_blob']
 return {x['path']:x for x in rows}
def verify_parts(root,evidence,parts):
 assert parts['schema']=='hepta.runtime.binary-write-composition.git-parts.v1'
 assert parts['index']==pin(root/'EVIDENCE.json') and len(parts['parts'])==len(evidence['parts'])
 digest=hashlib.sha256();size=0
 for row,original in zip(parts['parts'],evidence['parts']):
  assert {k:v for k,v in row.items()if k!='path'}==original and row['offset']==size
  assert '/'not in row['path'] and row['path']not in('','.','..')
  p=root/row['path'];assert not p.is_symlink();raw=p.read_bytes()
  assert len(raw)==row['bytes'] and sha(raw)==row['sha256'];digest.update(raw);size+=len(raw)
 assert size==evidence['archive_bytes'] and digest.hexdigest()==evidence['archive_sha256']
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--restored',type=Path,required=True);a=p.parse_args()
 restored=a.restored.resolve(strict=True);r4=restored/'r4';result=decode(ROOT/'RESULTS.json')
 expected_false=('runtime_graph_modified','production_carrier_installed','host_audit_ssh_lifecycle_qualified',
  'dynamic_partial_release_qualified','dynamic_failed_result_allocation_qualified','public_binary_write_registered','whole_runtime_replaced')
 assert all(result[k]is False for k in expected_false)
 assert result['registered_native_public_tools']==13 and result['original_public_tool_target']==136
 assert result['base_commit']=='acd4d7aa766e8f74a7cfbd26b0d58f68cd5e5b39' and result['base_tree']=='aaa67939fa68736dc63318a1bb8304330f05a8bc'
 current=source(ROOT/'source',SOURCE);assert len(current)==139
 assert source(r4/'source',SOURCE)==current
 for name in current:assert (r4/'source'/name).read_bytes()==(ROOT/'source'/name).read_bytes()
 spec=importlib.util.spec_from_file_location('composition_source_publication',ROOT/'source/scripts/read_composition_source.py')
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 inheritance=module.read_source()
 assert inheritance['source']==result['source'] and inheritance['original_parent_inputs']==256
 assert len(inheritance['admitted_ids'])==254 and inheritance['typed_rejected_ids']==[217,244]
 assert len(inheritance['ordered_lane_partition']['original'])==992
 assert len(inheritance['ordered_lane_partition']['admitted'])==985
 assert len(inheritance['ordered_lane_partition']['typed_rejected'])==7 and inheritance['retries']==6
 evidence=decode(ROOT/'EVIDENCE.json');assert pin(ROOT/'EVIDENCE.json')==result['build_archive_index']
 assert evidence['mode']=='small' and evidence['complete_composition_capture_included']is False
 verify_parts(ROOT,evidence,decode(ROOT/'PARTS.json'))
 restored_record=decode(restored.parent/'RESTORED.json')
 assert restored_record['status']=='EXACT_ORDINARY_ARCHIVE_FILES_RESTORED' and restored_record['mode']=='small'
 assert restored_record['archive_sha256']==evidence['archive_sha256'] and restored_record['logical_files']==4659
 assert restored_record['logical_bytes']==427032999 and restored_record['semantic_origins_rewritten']is False
 assert restored_record['semantic_qualification_repeated']is False and restored_record['product_executions_added']==0
 qpath=r4/'qualification/QUALIFICATION.json';q=decode(qpath)
 assert pin(qpath)['sha256']==QUALIFICATION and (ROOT/'records/QUALIFICATION.json').read_bytes()==qpath.read_bytes()
 assert q['source']==q['source_after']==result['source'] and q['status']=='PASS_COMPLETE_PRIVATE_COMPOSITION'
 stages=['source','reader-controls','parent-reader-controls','adapter-reader-controls','build','link','build-data',
  'boundary','boundary-data','original-pure-capture','original-pure-data','full-capture','full-data']
 assert [x['name']for x in q['stages']]==stages
 for row in q['stages']:
  assert row['returncode']==0 and row['timed_out']is False and row['whole_group_gone']is True
  for stream in('stdout','stderr'):
   assert pin(r4/'qualification'/(row['name']+'.'+stream))==row['streams'][stream]
 for name,expected in q['receipts'].items():assert pin(r4/'qualification'/name)==expected
 reader=decode(r4/'qualification/READBACK.json')
 assert pin(r4/'qualification/READBACK.json')['sha256']==READBACK
 assert reader['status']=='READONLY_PASS' and reader['before']==reader['after']
 assert len(reader['probes'])==11 and all(x['rejected']for x in reader['probes'])
 assert reader['timeout_seconds']==600 and reader['elapsed_seconds']<600
 for key,value in result['complete_effect_evidence'].items():assert reader['evidence'][key]==value
 assert result['complete_effect_evidence']['complete_lane_runs']==985
 assert result['complete_effect_evidence']['original_complete_lane_runs']==992
 assert result['complete_effect_evidence']['typed_null_refusals']==2
 assert result['complete_effect_evidence']['actual_retry_controls']==6
 summary=decode(ROOT/'records/SUMMARY.json')
 assert summary['guard']['entries']==32529 and result['reader_guard']==summary['guard']
 assert result['pure_owner_evidence']==summary['pure_evidence']
 assert result['actual_boundaries']==summary['boundary_evidence']
 for name,expected in result['qualifying_receipts'].items():assert pin(ROOT/'records'/name)==expected
 for name,expected in result['preservation_receipts'].items():assert pin(ROOT/'records'/name)==expected
 complete=decode(ROOT/'COMPLETE_EVIDENCE.json')
 assert pin(ROOT/'COMPLETE_EVIDENCE.json')==result['complete_external_archive_index']
 assert complete['mode']=='complete' and complete['complete_composition_capture_included']is True
 assert complete['archive_bytes']==4762670388 and complete['archive_sha256']=='11ebf7037fb9d67810c9e64859902711e3a27e3286e28669067b6d70eebd3e79'
 archive_receipt=decode(ROOT/'records/COMPLETE_ARCHIVE_READBACK.json')
 assert archive_receipt['status']=='COMPLETE_ARCHIVE_AND_EVERY_RETAINED_SOURCE_BYTE_PASS'
 assert archive_receipt['evidence']==pin(ROOT/'COMPLETE_EVIDENCE.json') and archive_receipt['logical_files']==44937
 assert archive_receipt['objects']==33393 and archive_receipt['full_payload_bytes_read']is True
 assert archive_receipt['semantic_qualification_repeated']is False and archive_receipt['product_executions_added']==0
 history=decode(ROOT/'history/SOURCE_VERSIONS.json');old_sources={}
 for row in history['transitions']:
  before=source(restored/row['before']/'source',row['before_manifest_sha256'])
  after=source(restored/row['after']/'source',row['after_manifest_sha256'])
  changed={n:{'before':before.get(n),'after':after.get(n)}for n in sorted(set(before)|set(after))if before.get(n)!=after.get(n)}
  assert changed==row['whole_file_endpoints'] and not row['deleted']
  assert not any(n.endswith(('.hepta','.S'))for n in changed)
  assert pin(ROOT/'history'/row['patch']['path'])=={k:row['patch'][k]for k in('bytes','sha256')}
  old_sources[row['before']]=row['before_manifest_sha256'];old_sources[row['after']]=row['after_manifest_sha256']
 for version in('r2','r3'):
  old=decode(restored/version/'PROCESS.json');assert old['returncode']==1
  oldq=decode(restored/version/'qualification/QUALIFICATION.json');assert oldq['status']!='PASS_COMPLETE_PRIVATE_COMPOSITION'
 assert pin(restored/'r2/qualification/boundary-data.stderr')['sha256']=='b243aed1694027416074b9e463a30e7eb6cb9060535cdf27918fec8e79ca959e'
 assert pin(restored/'r3/qualification/full-capture.stderr')['sha256']=='b6c1bc9b8b2dd66f1c841ea8a0043a56cefb7b59320e21b6456e88d8deb8c585'
 assert pin(ROOT/'history/R3_CAPTURE_CHILD_STDERR.log')['sha256']=='e319d007939d96cb45d7c5a339bb54f0dd8cf0791ae6c007d5e0c2ff573e90d8'
 print(json.dumps(dict(status='PASS_PUBLICATION_SOURCE_RESTORED_BYTES_AND_ORIGINAL_RECEIPTS',source_files=139,
  original_pure_domains=[433,196,256],original_inputs=256,composition_inputs=254,typed_none_refusals=2,
  original_lanes=992,composition_lanes=985,typed_rejected_original_lanes=7,actual_cancel_controls=6,
  complete_archive_payload_read_by_this_check=False,semantic_qualification_repeated=False,product_executions_added=0,
  old_source_manifests=old_sources,public_binary_write_registered=False,whole_runtime_replaced=False),sort_keys=True))
if __name__=='__main__':main()
