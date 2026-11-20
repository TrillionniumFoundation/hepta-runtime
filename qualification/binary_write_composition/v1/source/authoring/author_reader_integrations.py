#!/usr/bin/env python3
"""Exact retained-reader extension; every original check remains recoverable."""
import argparse,hashlib,json
from pathlib import Path
SHA=lambda b:hashlib.sha256(b).hexdigest()

def author(root):
 outputs={};records={};current=text='';original=b'';edits=[]
 def begin(name):
  nonlocal current,text,original,edits
  current=name;original=(root/'parent/scripts'/name).read_bytes();text=original.decode();edits=[]
 def edit(before,after,count=1):
  nonlocal text
  assert text.count(before)==count,(current,before,text.count(before),count)
  row=dict(before=before,after=after,count=count,before_sha256=SHA(text.encode()));text=text.replace(before,after);row['after_sha256']=SHA(text.encode());edits.append(row)
 def finish():
  value=text
  for row in reversed(edits):
   assert SHA(value.encode())==row['after_sha256'];assert value.count(row['after'])==row['count'];value=value.replace(row['after'],row['before']);assert SHA(value.encode())==row['before_sha256']
  assert value.encode()==original
  outputs[current]=text.encode();records[current]=dict(original=SHA(original),source=SHA(text.encode()),complete_inverse=True,edits=edits)
 begin('read_parent_capture.py')
 edit('from read_parent_build import read_build','from read_composition_build import read_build\nfrom read_composition import Prepared,check_flow\nfrom composition_domain import query_from_case')
 edit('errors=[];last_error=None;last_body=None;parent_calls=0;body_calls=0;growth=None',
      'errors=[];last_error=None;last_body=None;parent_calls=0;body_calls=0;growth=None\n    pure=[];first_parent_input=None;first_parent_frame=None;last_parent_frame=None')
 edit('            if tag in JOURNALS:',
      '            if tag==b"HBCWJR01":\n'
      '                head=tag+read(stream,120);payload=read(stream,U(head,32));all_count+=1\n'
      '                pure.append(dict(head=head,payload=payload,index=all_count));continue\n'
      '            if tag in JOURNALS:')
 edit('                if tag!=b"HBPWJR01":continue\n                if event==1:',
      '                if tag!=b"HBPWJR01":continue\n'
      '                last_parent_frame=all_count\n'
      '                if first_parent_frame is None:\n'
      '                    require(event==1,"first actual parent frame must be its immutable request")\n'
      '                    first_parent_input=payload;first_parent_frame=all_count\n'
      '                if event==1:')
 edit('body_calls=body_calls,all_frames=all_count,final_workspace=last_workspace)',
      'body_calls=body_calls,all_frames=all_count,final_workspace=last_workspace,composition_rows=pure,\n'
      '                first_parent_input=first_parent_input,first_parent_frame=first_parent_frame,last_parent_frame=last_parent_frame)')
 edit('def read_case(folder,binding,case,lane,store,executable):','def read_case(folder,binding,case,lane,store,executable,preparer,fixture):')
 edit('    query=row["query"]\n    if native:',
      '    query=row["query"]\n'
      '    same(query,query_from_case(case,fixture,lane!="native-unobserved"),"complete frozen query independently reconstructed")\n'
      '    prepared=preparer.request(row["preparation"],query,case["id"],lane,packet)if native else None\n'
      '    if not native:require(row["preparation"]is None,"original did not invoke typed/planner preparation")\n'
      '    if native:')
 edit('require(packet==expected,"independent full HIA request encoding")',
      'require(prepared["parent"]==expected,"independent full HIA parent request encoding")')
 edit('        native_journal=journal(folder,process["journal"],store)',
      '        native_journal=journal(folder,process["journal"],store)\n'
      '        original_input=store.get(row["snapshots"]["input"]["bytes"])\n'
      '        require(U(context,80)==len(expected) and original_input[:len(expected)]==expected,"actual entire parent-owned initial request")')
 edit('            require(native_journal["final_workspace"]==store.get(row["snapshots"]["workspace"]["bytes"]),"actual complete final parent workspace")',
      '            require(native_journal["final_workspace"]==store.get(row["snapshots"]["workspace"]["bytes"]),"actual complete final parent workspace")\n'
      '            row["composition_proof"]=check_flow(native_journal["composition_rows"],prepared,store,row,\n'
      '                native_journal["first_parent_input"],native_journal["first_parent_frame"],native_journal["last_parent_frame"])')
 edit('            require(native_journal["all_frames"]==0 and native_journal["parent_calls"]==0,"unobserved lane emitted hidden application journals")',
      '            require(native_journal["all_frames"]==0 and native_journal["parent_calls"]==0,"unobserved lane emitted hidden application journals")\n'
      '            require(native_journal["composition_rows"]==[],"unobserved pure owners emitted hidden journals")\n'
      '            from read_composition import check_unobserved\n'
      '            row["composition_proof"]=check_unobserved(prepared,store,row)')
 edit('report["planned"]==report["completed"]==992','report["planned"]==report["completed"]==985')
 edit('SOURCE/"DOMAIN.json"','SOURCE/"parent/DOMAIN.json"',2)
 edit('    planned=[(case,lane)for case in domain["cases"]for lane in LANES',
      '    admitted=[case for case in domain["cases"]if type(case["expected_version"])is str]\n'
      '    rejected=[case for case in domain["cases"]if case["expected_version"]is None]\n'
      '    require(len(admitted)==254 and len(rejected)==2 and len(admitted)+len(rejected)==256,"complete ordered original typed-domain partition")\n'
      '    require(report["original_parent_inputs"]==256 and report["composed_parent_inputs"]==254,"explicit composition intersection scope")\n'
      '    preparer=Prepared(capture/"preparation",args.images/"adapter")\n'
      '    planned=[(case,lane)for case in admitted for lane in LANES')
 edit('len(planned)==len(report["cases"])==992','len(planned)==len(report["cases"])==985')
 edit('    require(len(planned)==len(report["cases"])==985,"complete frozen original/current lane set")',
      '    entire_original=[(case,lane)for case in domain["cases"]for lane in LANES\n'
      '        if lane!="native-unobserved"or not(case["fault_plans"]or case["descriptor_actor"]or case["nofile"])]\n'
      '    omitted=[(case,lane)for case,lane in entire_original if case["expected_version"]is None]\n'
      '    require(len(entire_original)==992 and len(omitted)==7,"whole original natural domain retained as 985 plus seven typed-refused lanes")\n'
      '    same([(case["id"],lane)for case,lane in omitted],[(217,lane)for lane in LANES]+[(244,lane)for lane in LANES[:3]],"exact original four-plus-three None lanes")\n'
      '    same([(case["id"],lane)for case,lane in entire_original if type(case["expected_version"])is str],\n'
      '         [(case["id"],lane)for case,lane in planned],"independent complete ordered original-to-composed lane projection")\n'
      '    require(len(planned)==len(report["cases"])==985,"complete frozen original/current lane set")')
 edit('row=read_case(folder,binding,case,lane,store,build["executable"])',
      'row=read_case(folder,binding,case,lane,store,build["executable"],preparer,capture/"fixture")')
 edit('row=read_retry(capture/("retry-%02d-"%case["id"]+lane),binding,case,lane,store,build["executable"])',
      'row=read_retry(capture/("retry-%02d-"%case["id"]+lane),binding,case,lane,store,build["executable"],preparer,capture/"fixture")')
 edit('    buffers=store.finish()',
      '    require(len(report["typed_rejections"])==2,"both original None inputs retained")\n'
      '    for case,row in zip(rejected,report["typed_rejections"]):\n'
      '        same(row["input"],case,"complete ordered original None input")\n'
      '        same(row["query"],query_from_case(case,capture/"fixture",True),"exact None input projection")\n'
      '        preparer.request(row["preparation"],row["query"],case["id"],"typed-rejected",None)\n'
      '        require(row["parent_processes_created"]==row["parent_invocations"]==row["parent_effects"]==0,"typed rejection cannot claim a parent invocation")\n'
      '        same(filesystem(row["setup"]),filesystem(row["before_refusal"]),"whole fixture preparation preserves all contents and structural metadata")\n'
      '        same(row["before_refusal"],row["after"],"all None refusal filesystem bytes and metadata remain unchanged")\n'
      '    same(preparer.finish(),report["preparation"],"entire exact actual preparation calls")\n'
      '    buffers=store.finish()')
 edit('schema="hepta.runtime.binary-parent-readback.v1",status="PASS_COMPLETE_FROZEN_PARENT_DOMAIN"',
      'schema="hepta.runtime.binary-write-composition-readback.v1",status="PASS_COMPLETE_FROZEN_COMPOSITION_DOMAIN"')
 edit('cases=256,complete_lane_runs=992,\n                original_runs=512,native_observed_runs=256,native_unobserved_runs=224',
      'cases=254,original_parent_inputs=256,typed_null_refusals=2,complete_lane_runs=985,original_complete_lane_runs=992,\n'
      '                typed_rejected_original_lanes=[dict(id=case["id"],lane=lane)for case,lane in omitted],\n'
      '                original_runs=508,native_observed_runs=254,native_unobserved_runs=223')
 edit('def main():\n    parser=argparse.ArgumentParser(description=__doc__)\n    for name in("capture","images","build","output"):parser.add_argument("--"+name,type=Path,required=True)\n    parser.add_argument("--capture-sha256",required=True)\n    args=parser.parse_args()\n    identity=source_evidence(SOURCE)\n    capture=args.capture.resolve(strict=True)',
      'def read_all(capture,images,build_root,capture_sha256):\n    identity=source_evidence(SOURCE)\n    capture=Path(capture).resolve(strict=True)\n    images=Path(images).resolve(strict=True)\n    build_root=Path(build_root).resolve(strict=True)')
 edit('hashlib.sha256(raw).hexdigest()==args.capture_sha256','hashlib.sha256(raw).hexdigest()==capture_sha256')
 edit('read_build(SOURCE,args.images,args.build)','read_build(SOURCE,images,build_root)')
 edit('Prepared(capture/"preparation",args.images/"adapter")','Prepared(capture/"preparation",images/"adapter")')
 edit('    require(not args.output.exists(),"fresh DATA readback receipt")\n    args.output.write_bytes(encoded(result))',
      '    return result\n\n\ndef main():\n    parser=argparse.ArgumentParser(description=__doc__)\n    for name in("capture","images","build","output"):parser.add_argument("--"+name,type=Path,required=True)\n    parser.add_argument("--capture-sha256",required=True)\n    args=parser.parse_args()\n    require(not args.output.exists(),"fresh DATA readback receipt")\n    result=read_all(args.capture,args.images,args.build,args.capture_sha256)\n    args.output.write_bytes(encoded(result))')
 finish()
 begin('read_retry_capture.py')
 edit('def read_retry(folder,binding,case,lane,store,executable):','def read_retry(folder,binding,case,lane,store,executable,preparer,fixture):')
 edit('    packet=store.get(row["application_input"])',
      '    packet=store.get(row["application_input"])\n'
      '    from composition_domain import query_from_case\n'
      '    same(row["query"],query_from_case(case,fixture,True),"entire original retry query")\n'
      '    if lane=="native-observed":\n'
      '        from read_parent_capture import journal\n'
      '        from read_composition import check_flow\n'
      '        prepared=preparer.request(row["preparation"],row["query"],10000+case["id"],"retry-"+lane,packet)\n'
      '        actual=journal(folder,process["journal"],store)\n'
      '        row["composition_proof"]=check_flow(actual["composition_rows"],prepared,store,row,actual["first_parent_input"],\n'
      '            actual["first_parent_frame"],actual["last_parent_frame"],finished=False)\n'
      '    else:require(row["preparation"]is None and decode(packet)==row["query"],"unchanged full original retry arguments")')
 finish()
 return outputs,records

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();values,records=author(a.source);a.output.mkdir(parents=True,exist_ok=False)
 for name,raw in values.items():(a.output/name).write_bytes(raw)
 (a.output/'reader_integration_edits.json').write_text(json.dumps(records,indent=2,sort_keys=True)+'\n')
 print(json.dumps({n:{k:v for k,v in r.items()if k!='edits'}for n,r in records.items()},sort_keys=True))
if __name__=='__main__':main()
