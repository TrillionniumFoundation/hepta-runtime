#!/usr/bin/env python3
"""Fresh exact builds, original pure domains and actual full private composition."""
import argparse,json,os,signal,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from evidence_common import encoded,decode,pin,require,source_evidence

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in('hepta','retained-bootstrap','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();out=a.output.absolute();require(not out.exists(),'fresh exclusive qualification root');out.mkdir(parents=True)
 source=source_evidence(ROOT);rows=[];began=time.monotonic_ns();python=[sys.executable,'-I','-S','-B']
 def stage(name,arguments,limit):
  started=time.monotonic_ns();command=python+[str(x)for x in arguments]
  record=dict(name=name,argv=command,limit_seconds=limit,cleanup_seconds=5,timed_out=False)
  with(out/(name+'.stdout')).open('xb')as stdout,(out/(name+'.stderr')).open('xb')as stderr:
   child=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=True)
   record.update(pid=child.pid,pgid=os.getpgid(child.pid),parent_pgid=os.getpgrp())
   require(record['pid']==record['pgid']!=record['parent_pgid'],'independent actual qualification stage group')
   (out/(name+'.start.json')).write_bytes(encoded(record))
   try:child.wait(timeout=limit)
   except subprocess.TimeoutExpired:
    record['timed_out']=True;os.killpg(child.pid,signal.SIGTERM)
    try:child.wait(timeout=5)
    except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait()
   record.update(returncode=child.returncode,elapsed_ns=time.monotonic_ns()-started)
  try:os.killpg(child.pid,0)
  except ProcessLookupError:record['whole_group_gone']=True
  else:
   record['whole_group_gone']=False;os.killpg(child.pid,signal.SIGKILL)
  record['streams']={stream:pin(out/(name+'.'+stream))for stream in('stdout','stderr')}
  record['source_after']=source_evidence(ROOT);rows.append(record)
  (out/(name+'.process.json')).write_bytes(encoded(record))
  passed=record['returncode']==0 and not record['timed_out'] and record['whole_group_gone'] and record['source_after']==source
  state=dict(schema='hepta.runtime.binary-write-composition-qualification.v1',source=source,stages=rows,
             elapsed_ns=time.monotonic_ns()-began,status='RUNNING'if passed else'HOLD',public_binary_write_registered=False,whole_runtime_replaced=False)
  (out/'QUALIFICATION.json').write_bytes(encoded(state));print(json.dumps(dict(stage=name,returncode=record['returncode'],elapsed_ns=record['elapsed_ns'],timed_out=record['timed_out']),sort_keys=True),flush=True)
  require(passed,'actual complete qualification stage failed: '+name)
  return state
 stage('source',[ROOT/'scripts/read_composition_source.py'],60)
 stage('reader-controls',[ROOT/'tests/test_composition_data.py'],60)
 stage('parent-reader-controls',[ROOT/'parent/tests/test_parent_data.py'],60)
 stage('adapter-reader-controls',[ROOT/'adapter/tests/test_reader.py'],60)
 stage('build',[ROOT/'scripts/build_images.py','--hepta',a.hepta.resolve(strict=True),'--retained-bootstrap',a.retained_bootstrap.resolve(strict=True),'--output',out/'images'],180)
 stage('link',[ROOT/'scripts/link_callable.py','--images',out/'images','--output',out/'linked'],30)
 stage('build-data',[ROOT/'scripts/read_composition_build.py','--images',out/'images','--build',out/'linked'],60)
 stage('boundary',[ROOT/'scripts/capture_boundary.py','--images',out/'images','--build',out/'linked','--output',out/'boundary'],180)
 stage('boundary-data',[ROOT/'scripts/guarded_read.py','--mode','boundary','--capture',out/'boundary','--images',out/'images','--build',out/'linked',
       '--capture-sha256',pin(out/'boundary/BOUNDARY.json')['sha256'],'--output',out/'BOUNDARY_READBACK.json'],600)
 stage('original-pure-capture',[ROOT/'adapter/scripts/run_capture.py','--images',out/'images/adapter','--output',out/'pure'],1805)
 stage('original-pure-data',[ROOT/'adapter/scripts/guarded_read.py','--capture',out/'pure','--images',out/'images/adapter',
       '--source-sha256',pin(ROOT/'adapter/SOURCE_MANIFEST.json')['sha256'],'--capture-sha256',pin(out/'pure/RUN.json')['sha256'],'--output',out/'PURE_READBACK.json'],180)
 # The unchanged complete-capture supervisor below owns the actual 1800+5
 # product group. This coordinator waits for its receipt; it grants no second
 # product timeout and cannot convert an inner HOLD into qualification.
 stage('full-capture',[ROOT/'scripts/run_capture.py','--build',out/'linked','--output',out/'full'],None)
 state=stage('full-data',[ROOT/'scripts/guarded_read.py','--mode','composition','--capture',out/'full/capture','--images',out/'images','--build',out/'linked',
       '--capture-sha256',pin(out/'full/capture/CAPTURE.json')['sha256'],'--output',out/'READBACK.json'],600)
 state['status']='PASS_COMPLETE_PRIVATE_COMPOSITION';state['source_after']=source_evidence(ROOT)
 state['receipts']={name:pin(out/name)for name in('BOUNDARY_READBACK.json','PURE_READBACK.json','READBACK.json')}
 (out/'QUALIFICATION.json').write_bytes(encoded(state));print(json.dumps(dict(status=state['status'],stages=len(rows),elapsed_ns=state['elapsed_ns']),sort_keys=True),flush=True)

if __name__=='__main__':main()
