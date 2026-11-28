#!/usr/bin/env python3
"""Keep every inherited parent effect/observer check, with exact inverse edits."""
import argparse,hashlib,json
from pathlib import Path
SHA=lambda b:hashlib.sha256(b).hexdigest()

def author(root):
 outputs={};records={}
 def begin(name):
  nonlocal current,text,original,edits
  current=name;original=(root/'parent/scripts'/name).read_bytes();text=original.decode();edits=[]
 def edit(before,after,count=1):
  nonlocal text
  assert text.count(before)==count,(current,before,text.count(before),count)
  row=dict(before=before,after=after,count=count,before_sha256=SHA(text.encode()))
  text=text.replace(before,after);row['after_sha256']=SHA(text.encode());edits.append(row)
 def finish():
  value=text
  for row in reversed(edits):
   assert SHA(value.encode())==row['after_sha256'];assert value.count(row['after'])==row['count']
   value=value.replace(row['after'],row['before']);assert SHA(value.encode())==row['before_sha256']
  assert value.encode()==original
  outputs[current]=text.encode();records[current]=dict(original=SHA(original),source=SHA(text.encode()),complete_inverse=True,edits=edits)
 current=text='';original=b'';edits=[]
 begin('carrier.py')
 edit('command in range(1,29)','command in range(1,35)')
 edit('expected[:8]==b"HBPWCI01"','expected[:8]in(b"HBPWCI01",b"HBCWCI01")')
 finish()
 begin('parent_capture.py')
 edit('from protocol import U,stat_value,proc_fds','from protocol import U,stat_value,proc_fds\nfrom composition_prepare import Preparer\nPREPARER=None')
 edit('SOURCE/"scripts/reference_worker.py",SOURCE','SOURCE/"parent/scripts/reference_worker.py",SOURCE/"parent"')
 edit('if command==4:result["actual_process_bytes"]','if command in(4,29):result["actual_process_bytes"]')
 edit('packet=wire(query)if native else encoded(query)',
      'packet,preparation=PREPARER.request(query,case["id"],lane)if native else(encoded(query),None)\n'
      '        require(packet is not None,"the complete typed String intersection must reach the fixed planner")\n'
      '        row["preparation"]=preparation')
 edit('((4,"context"),(5,"workspace"),(6,"output"),(7,"input"),(11,"pool"),(21,"entropy"),(22,"entropy_workspace"))',
      '((4,"context"),(5,"workspace"),(6,"output"),(7,"input"),(11,"pool"),(21,"entropy"),(22,"entropy_workspace"),\n'
      '                                 (29,"composition"),(30,"adapter_workspace"),(31,"planner_workspace"),(32,"adapter_output"),(33,"planner_output"),(34,"composition_input"))')
 edit('            snapshot(11,"pool_after_release")','            snapshot(11,"pool_after_release")\n            snapshot(4,"parent_after_release")\n            snapshot(29,"composition_after_release")\n            snapshot(30,"adapter_after_release")\n            snapshot(32,"adapter_output_after_release")')
 edit('def main():\n    parser','def main():\n    global PREPARER\n    parser')
 edit('SOURCE/"DOMAIN.json"','SOURCE/"parent/DOMAIN.json"',2)
 edit('binary=build/"binary-parent-owner-callable.elf"','binary=build/"binary-write-composition.elf"')
 edit('    rows=[];retry_rows=[]\n    planned=[(case,lane)for case in domain["cases"]for lane in LANES if eligible(case,lane)]',
      '    rows=[];retry_rows=[];typed_rejections=[]\n'
      '    admitted=[case for case in domain["cases"]if type(case["expected_version"])is str]\n'
      '    rejected=[case for case in domain["cases"]if case["expected_version"]is None]\n'
      '    require(len(admitted)==254 and len(rejected)==2 and len(admitted)+len(rejected)==len(domain["cases"]),"complete original typed-domain partition")\n'
      '    PREPARER=Preparer(Path(build_record["images_directory"])/"adapter",output/"preparation")\n'
      '    planned=[(case,lane)for case in admitted for lane in LANES if eligible(case,lane)]\n'
      '    require(len(planned)==985,"complete 254-input original/native lane intersection")')
 edit('        require(source_evidence(SOURCE)==identity,"whole frozen source changed during capture")',
      '        for case in rejected:\n'
      '            fixture=output/"fixture";initial=setup(fixture);query=concrete(case,fixture,True)\n'
      '            before_refusal=projection(fixture)\n'
      '            packet,ordinal=PREPARER.request(query,case["id"],"typed-rejected")\n'
      '            require(packet is None,"original None unexpectedly admitted by typed String owner")\n'
      '            after=projection(fixture);require(encoded(before_refusal)==encoded(after),"typed refusal changed target filesystem")\n'
      '            typed_rejections.append(dict(input=case,query=query,preparation=ordinal,setup=initial,before_refusal=before_refusal,after=after,\n'
      '                parent_processes_created=0,parent_invocations=0,parent_effects=0))\n'
      '            discard(fixture)\n'
      '        preparation=PREPARER.close();PREPARER=None\n'
      '        require(source_evidence(SOURCE)==identity,"whole frozen source changed during capture")')
 edit('                    source=identity,domain=pin(SOURCE/"parent/DOMAIN.json"),build=pin(build/"BUILD.json"),',
      '                    source=identity,domain=pin(SOURCE/"parent/DOMAIN.json"),build=pin(build/"BUILD.json"),\n'
      '                    typed_rejections=typed_rejections,preparation=preparation,original_parent_inputs=256,composed_parent_inputs=254,')
 edit('    except BaseException as error:\n        (output/"FAILURE.json")',
      '    except BaseException as error:\n        if PREPARER is not None:\n            PREPARER.close();PREPARER=None\n        (output/"FAILURE.json")')
 edit('hepta.runtime.binary-parent-capture.v1','hepta.runtime.binary-write-composition-capture.v1')
 edit('run_retry(case,lane,output/"fixture",folder,binary,store,SOURCE)',
      'run_retry(case,lane,output/"fixture",folder,binary,store,SOURCE,PREPARER)')
 finish()
 begin('retry_capture.py')
 edit('def run_retry(case,lane,root,folder,binary,store,source):',
      'def run_retry(case,lane,root,folder,binary,store,source,preparer):')
 edit('source/"scripts/reference_worker.py",source','source/"parent/scripts/reference_worker.py",source/"parent"')
 edit('packet=wire(query)if native else encoded(query)',
      'packet,preparation=preparer.request(query,10000+case["id"],"retry-"+lane)if native else(encoded(query),None)\n'
      '        require(packet is not None,"fixed EINTR input belongs to the original typed String domain")')
 edit('process=process,hooks=dict(events=hooks.events,eof=hooks.eof),','process=process,preparation=preparation,hooks=dict(events=hooks.events,eof=hooks.eof),')
 finish()
 begin('run_capture.py')
 edit('hepta.runtime.binary-parent-owned-capture.v1','hepta.runtime.binary-write-composition-owned-capture.v1')
 finish()
 return outputs,records

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 values,records=author(a.source);a.output.mkdir(parents=True,exist_ok=False)
 for name,raw in values.items():(a.output/name).write_bytes(raw)
 (a.output/'integration_edits.json').write_text(json.dumps(records,indent=2,sort_keys=True)+'\n')
 print(json.dumps({name:{k:v for k,v in row.items()if k!='edits'}for name,row in records.items()},sort_keys=True))
if __name__=='__main__':main()
