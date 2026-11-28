#!/usr/bin/env python3
"""Fresh exact original parent12 and adapter4 builds, with full original receipts."""
import argparse,json,os,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from evidence_common import encoded,pin,require,source_evidence

def command(output,label,argv,limit=120):
 start=time.monotonic_ns()
 with(output/(label+'.stdout')).open('xb')as out,(output/(label+'.stderr')).open('xb')as err:
  child=subprocess.run([str(x)for x in argv],stdout=out,stderr=err,timeout=limit,check=False)
 record=dict(argv=[str(x)for x in argv],returncode=child.returncode,elapsed_ns=time.monotonic_ns()-start,limit_seconds=limit,stdout=pin(output/(label+'.stdout')),stderr=pin(output/(label+'.stderr')))
 (output/(label+'.json')).write_bytes(encoded(record))
 require(child.returncode==0 and record['stderr']['bytes']==0,'complete actual build subprocess '+label)
 return record

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('hepta','retained-bootstrap','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();output=a.output.absolute();require(not output.exists(),'fresh full build');output.mkdir(parents=True)
 identity=source_evidence(ROOT);began=time.monotonic_ns();processes=[];members={};children={}
 for kind in ('parent','adapter'):
  argv=[sys.executable,'-I','-S','-B',ROOT/kind/'scripts/build_images.py','--hepta',a.hepta.resolve(strict=True),'--retained-bootstrap',a.retained_bootstrap.resolve(strict=True),'--output',output/kind]
  processes.append(command(output,kind,argv))
  child=json.loads((output/kind/'IMAGES.json').read_bytes());children[kind]=pin(output/kind/'IMAGES.json')
  names=list(child['members'])if kind=='parent'else['adapter','planner']
  for name in names:
   row=dict(child['members'][name]);row['manifest']=kind+'/'+row['manifest'];row['source_path']=kind+'/'+row['source_path'];members[name]=row
 processes.append(command(output,'original-parent-link',[sys.executable,'-I','-S','-B',ROOT/'parent/scripts/link_callable.py','--images',output/'parent','--output',output/'original-parent-linked'],30))
 original=json.loads((output/'original-parent-linked/BUILD.json').read_bytes())
 require(original['executable']==dict(bytes=1794048,sha256='6e5fefef8a116d25c07e476b92b96f5b5e39a87f74d1dc10bf1f7ba8dbf7d076'),'actual fresh original parent ELF changed')
 processes.append(command(output,'composition-fixture-author',[sys.executable,'-I','-S','-B',ROOT/'authoring/author_composition_fixture.py','--source',ROOT,'--output',output/'authored'],30))
 for name,destination in (('binary_write_composition_fixture.S','asm'),('binary_write_composition_fixture_edits.json','authoring')):
  require((output/'authored'/name).read_bytes()==(ROOT/destination/name).read_bytes(),'full mechanically authored source')
 require(source_evidence(ROOT)==identity,'whole source unchanged while building')
 result=dict(schema='hepta.runtime.binary-write-composition-images.v1',status='FRESH_ACTUAL_B3_COMPILE_PASS',source=identity,children=children,members=members,processes=processes,elapsed_ns=time.monotonic_ns()-began,actual_hia_compilations=16,new_seed_executions=0,new_bootstrap_generations=0,application_executions=0,original_parent_executable=original['executable'],public_binary_write_registered=False,whole_runtime_replaced=False)
 (output/'IMAGES.json').write_bytes(encoded(result));print(json.dumps(dict(status=result['status'],actual_hia_compilations=16,source=identity),sort_keys=True))
if __name__=='__main__':main()
