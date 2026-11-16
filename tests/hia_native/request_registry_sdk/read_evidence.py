"""One pure, source-bound retained evidence read; no HIA or original execution."""
from pathlib import Path
import argparse,json,sys
parser=argparse.ArgumentParser();parser.add_argument('--source',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
parser.add_argument('--kind',choices=('native','original'),required=True);parser.add_argument('--result',type=Path,required=True)
parser.add_argument('--native-baseline',type=Path);args=parser.parse_args()
sys.dont_write_bytecode=True;sys.path.insert(0,str(args.source/'scripts'))
def audit(event,arguments):
 if event.startswith(('subprocess.','os.exec','os.spawn'))or event in ('os.system','os.posix_spawn','ctypes.dlopen','ctypes.dlsym','mmap.__new__'):
  raise RuntimeError('pure registry reader attempted execution: '+event)
sys.addaudithook(audit)
import hia_native_request_registry_pipeline as p
report=p.read(args.output/'result.json')
if args.kind=='native':value=p.native_evidence(args.source,args.output,report,with_controls=False)
else:
 import hia_native_request_registry_reference as reference
 native=p.read(args.native_baseline)
 value=reference.read_original(args.source,args.output,report,native)
p.write_new(args.result,value)
print(json.dumps({'status':'PASS','artifacts':len(value['artifact_sha256']),'new_native_calls':0,'new_original_processes':0},sort_keys=True))
