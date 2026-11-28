"""Actual public MCP regex-search producer, with no original-result input.

The sole independent case generator supplies requests and real file setup.
This suite retains all native streams and checks their protocol/ownership.
A later admitted original-reference consumer compares 510 designated bodies.
Eight path-resolution controls use a different resolved-path context and are
not claimed as complete original-body equivalence. No Rust process runs here.
"""
from __future__ import annotations
import gzip,hashlib,importlib.util,json,os,struct,sys,time,traceback
from pathlib import Path
HERE=Path(__file__).resolve().parent
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
mcp=module('_regex_search_actual_mcp_transport',HERE/'test_runtime_mcp.py')
cases=module('_regex_search_public_original_inputs',HERE/'view_regex_search_oracle/cases.py')
sha=lambda raw:hashlib.sha256(raw).hexdigest()
def identity(path):
 size=0;h=hashlib.sha256()
 with path.open('rb') as source:
  while block:=source.read(1<<20):size+=len(block);h.update(block)
 return dict(bytes=size,sha256=h.hexdigest())
def selected(meta):
 return not meta['hooks'] and meta['context'] and not meta['cancel_after_render'] and not meta['raw_path']
def main():
 started=time.monotonic();output=Path(os.environ['HIA_VIEW_REGEX_SEARCH_PUBLIC_CAPTURE_DIR']).resolve();output.mkdir(parents=True,exist_ok=False)
 manifest=Path(os.environ['HIA_RUNTIME_MCP_MANIFEST']).resolve(strict=True)
 initial=mcp.source_identity()
 private_sources={str(path):identity(path) for path in (Path(__file__),Path(mcp.__file__),Path(cases.__file__))}
 mcp.MANIFEST=manifest;mcp.OUTPUT=output
 builder=module('_regex_search_actual_mcp_builder',HERE.parents[1]/'scripts/hia_native_runtime_mcp_build.py')
 bundle=json.loads(manifest.read_bytes())
 executable=manifest.parent/bundle['elf'];elf=executable.read_bytes()
 assert sha(elf)==bundle['elf_sha256'] and len(elf)==bundle['elf_bytes']
 assert [row['name'] for row in bundle['members']]==[item[0] for item in builder.MEMBERS]
 for row in bundle['members']:
  path=Path(row['manifest']);data=json.loads(path.read_bytes());image=(path.parent/data['image']).read_bytes()
  assert sha(path.read_bytes())==row['manifest_sha256'] and sha(image)==row['image_sha256']
  current=HERE.parents[1]/row['source']
  assert (path.parent/data['source']).read_bytes()==current.read_bytes()
  assert sha(current.read_bytes())==row['source_sha256'] and elf.count(image)==1
 for path,digest in bundle['boundary_sources'].items():
  assert sha((HERE.parents[1]/path).read_bytes())==digest
 mcp.NativeRuntime.exe=executable
 fixture_root=output.parent/'runtime-mcp/files/regex-search'
 fixture_root.mkdir(parents=True,exist_ok=False)
 rows=[];failures=[];selected_ids=None;totals={}
 try:
  for protocol in ['legacy','modern']:
   ids=[];session=None;previous=None;body_bytes=0;case_count=0
   input_hash=hashlib.sha256(cases.INPUT_MAGIC+struct.pack('<Q',271));input_bytes=16
   try:
    for case in cases.iter_cases():
     meta=case['metadata'];cid=meta['case_id']
     encoded=cases.blob_record(meta,case['blobs']);input_hash.update(encoded);input_bytes+=len(encoded);del encoded
     if not selected(meta):continue
     ids.append(cid);case_count+=1
     if meta['session']!=previous:
      if session is not None:session.finish()
      name=protocol+'-'+str(meta['session'])
      folder=fixture_root/name;folder.mkdir()
      session=mcp.Session(name,folder);previous=meta['session']
      if protocol=='legacy':
       initialized,_=session.ready()
       assert 'result' in initialized and initialized['id']==1
     mcp.setup_files(folder,case)
     arguments=dict(path=bytes.fromhex(meta['path_hex']).decode('utf-8'),**meta['params'])
     metadata={mcp.CAPS:{},mcp.VERSION:'2026-07-28'} if protocol=='modern' else None
     request=mcp.sdk.call(cid+2,arguments,metadata)
     reply,wire=session.call(request)
     assert set(reply)=={'jsonrpc','id','result'} and reply['jsonrpc']=='2.0' and reply['id']==cid+2
     result=reply['result']
     assert set(result)==({'content','isError','resultType'} if protocol=='modern' else {'content','isError'})
     assert type(result['isError']) is bool
     if protocol=='modern':assert result['resultType']=='complete'
     assert type(result['content']) is list and len(result['content'])==1
     content=result['content'][0];assert set(content)=={'type','text'} and content['type']=='text' and type(content['text']) is str
     body=content['text'].encode('utf-8')
     resolution_control=cid in (30043,30044,30045,30046)
     if resolution_control:
      raw_path=bytes.fromhex(meta['path_hex'])
      resolved=os.fsencode(folder)+b'/'+raw_path
      assert result['isError'] is True
      assert body==b'Path not found: '+raw_path+b' (resolved to '+resolved+b')'
     body_bytes+=len(body)
     prefix=output/'cases'/(protocol+'-'+str(cid))
     row=dict(case_id=cid,name=meta['name'],domain=meta['domain'],protocol=protocol,session=session.name,
      original_input=mcp.save(prefix.with_suffix('.input.bin.gz'),cases.encode_cases([case])),
      actual_request=mcp.save(prefix.with_suffix('.request.bin.gz'),mcp.compact(request)),
      actual_response=mcp.save(prefix.with_suffix('.response.bin.gz'),wire),
      actual_body=mcp.save(prefix.with_suffix('.body.bin.gz'),body),
      is_error=result['isError'],private_hooks_used=False,original_mcp_router_executed=False,
      comparison_domain='public_resolved_path_control' if resolution_control else 'complete_original_body',
      original_body_compared=False,original_body_designated=not resolution_control)
     rows.append(row)
     with (output/'public-cases.jsonl').open('ab') as stream:stream.write(mcp.compact(row)+b'\n')
    session.finish();session=None
    assert dict(bytes=input_bytes,sha256=input_hash.hexdigest())==dict(bytes=47423473,sha256='68c70b6a0cccdd157d29607562805db651293a969ea68c6d728f1016e47227da')
    assert case_count==259 and len(ids)==len(set(ids))==259
    if selected_ids is None:selected_ids=ids
    else:assert selected_ids==ids
    totals[protocol]=dict(cases=case_count,body_bytes=body_bytes,regex_search_cases=258,whole_preparation_cases=1,designated_original_body_cases=255,public_resolved_path_controls=4,original_body_comparisons_executed=0)
   finally:
    if session is not None:session.finish(error=True)
 except BaseException as error:
  failures.append(dict(error=repr(error),traceback=traceback.format_exc()))
  print(json.dumps(failures[-1]),file=sys.stderr,flush=True)
 try:
  assert len(rows)==518 and len(mcp.RECORDS)==508
  assert mcp.COUNTS['actual_elf_responses']==772
  assert mcp.source_identity()==initial
  assert {p:identity(Path(p)) for p in private_sources}==private_sources
 except BaseException as error:
  failures.append(dict(error=repr(error),traceback=traceback.format_exc()))
  print(json.dumps(failures[-1]),file=sys.stderr,flush=True)
 result=dict(schema='hepta.runtime.view-regex-search-public-native.v1',status='PASS' if not failures else 'FAIL',
  groups=1,failures=len(failures),errors=len(failures),skipped=0,elapsed_seconds=time.monotonic()-started,
  cases=len(rows),actual_elf_processes=len(mcp.RECORDS),actual_elf_responses=mcp.COUNTS['actual_elf_responses'],
  selected_case_ids=selected_ids,protocols=totals,source_binding=initial,private_test_sources=private_sources,
  manifest=str(manifest),manifest_identity=identity(manifest),processes=mcp.RECORDS,
  execution=dict(runtime_root=str(HERE.parents[1]),capture_root=str(output),fixture_root=str(fixture_root),manifest_path=str(manifest)),
  independent_input=dict(bytes=input_bytes,sha256=input_hash.hexdigest()),original_mcp_router_executed=False,
  designated_original_body_cases=sum(row['original_body_designated'] for row in rows),
  original_body_comparisons_executed=0,original_reference_status='NOT_RUN',
  public_resolved_path_controls=sum(not row['original_body_designated'] for row in rows),
  all_public_bodies_same_original_resolution_context=False,new_rust_processes=0,fixture_hooks_used=False,
  whole_view_replaced=False,whole_runtime_replaced=False,complete_sdk_frontend=False,
  response_storage_globally_unbounded=False)
 (output/'result.json').write_bytes(mcp.compact(result)+b'\n')
 (output/'failures.json').write_bytes(mcp.compact(failures)+b'\n')
 print(json.dumps({k:v for k,v in result.items() if k not in ['processes','source_binding']},sort_keys=True),flush=True)
 return bool(failures)
if __name__=='__main__':raise SystemExit(main())
