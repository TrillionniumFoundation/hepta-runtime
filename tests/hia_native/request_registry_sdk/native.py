"""Execute source-owned private and SDK-schedule captures against the HIA owner."""
from pathlib import Path
import argparse,gzip,hashlib,json,os,struct,sys,time,traceback
ROOT=Path(__file__).resolve().parents[3]
sys.dont_write_bytecode=True
sys.path[:0]=[str(ROOT/'scripts'),str(Path(__file__).resolve().parent)]
from hia_native_loader import NativeModule
import hia_native_request_registry_pipeline as pipeline
from private_cases import Session,Capture,semantic,private
from cases import schedules
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encode(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()
def typed(ident):
    if type(ident)is int:return 1,struct.pack('<q',ident)
    assert type(ident)is str
    return 2,ident.encode()
def actual_records(session):
    output,state=session.buffers()
    used=struct.unpack_from('<Q',state,16)[0];at=64;records=[];ids={}
    while at<used:
        extent,generation,kind,n,flags,reserved=struct.unpack_from('<6Q',state,at)
        assert reserved==0
        key=state[at+48:at+48+n]
        ident=struct.unpack('<q',key)[0]if kind==1 else key.decode('utf-8')
        records.append({'generation':generation,'cancelled':bool(flags&1),'completed':bool(flags&2)})
        ids[generation]=ident;at+=extent
    assert at==used
    return records,ids,output,state

def sdk_execute(module,capture,output):
 plans=schedules();step_count=0
 cases_path=output/'sdk-cases.jsonl'
 with cases_path.open('xb')as destination:
  for case in plans:destination.write(encode(case))
 with gzip.open(output/'native-observations.jsonl.gz','xb',compresslevel=1)as observations:
    for case in plans:
        session=Session(module,capture,'sdk-schedule/'+case['name']);entered=[];emissions=[];notifications=[];reason=None
        for ordinal,step in enumerate(case['steps']):
            op=step['op']
            if op=='init':assert ordinal==0
            elif op=='register':
                kind,key=typed(step['id']);generation=session.call(1,kind=kind,key=key)
                assert generation==step['generation']
                records,ids,_,_=actual_records(session)
                entered.append({'generation':generation,'id':ids[generation]})
            elif op=='cancel':
                if step['id']is not None:
                    kind,key=typed(step['id']);session.call(2,kind=kind,key=key)
                notification={'reason':'notification-'+str(ordinal)}
                if step['id']is not None:notification['requestId']=step['id']
                notifications.append(notification)
            elif op=='complete':
                _,ids,_,_=actual_records(session);generation=step['generation'];session.call(3,generation)
                _,_,actual,_=actual_records(session)
                response=struct.unpack('<8s7Q',actual[:64])
                if response[5]&1:emissions.append({'generation':generation,'id':ids[generation],'error':generation%3==0})
            elif op=='retire':session.call(4,step['generation'])
            elif op=='inspect':session.call(5,step['generation'])
            elif op=='parent':session.call(6)
            elif op=='drain':
                session.call(7,reason=step['reason']);assert reason is None;reason=step['reason']
            else:raise AssertionError(op)
            records,ids,_,_=actual_records(session)
            observations.write(encode({'event':'step','case':case['case'],'ordinal':ordinal,'op':op,'records':records}));step_count+=1
        assert not actual_records(session)[0]
        observations.write(encode({'event':'end','case':case['case'],'started':entered,'notifications':notifications,'emissions':emissions,'terminal':'Cancelled'if reason==2 else'Closed'}))
        session.native.close()
 return {'sessions':len(plans),'steps':step_count,'cases':pipeline.pin(cases_path),'blob_count':len(capture.seen)}

def main():
 parser=argparse.ArgumentParser()
 parser.add_argument('--domain',choices=('private','sdk'),required=True)
 parser.add_argument('--manifest',type=Path,required=True)
 parser.add_argument('--output',type=Path,required=True)
 parser.add_argument('--execution',type=Path,required=True)
 args=parser.parse_args();output=args.output.absolute();started=time.monotonic_ns();error=None
 binding=pipeline.read(args.execution);pins=pipeline.source_table(ROOT)
 assert binding['source_files']==pins and binding['source_root']==str(ROOT)
 assert binding['manifest']==str(args.manifest.absolute())
 manifest=pipeline.pin(args.manifest);assert manifest['sha256']==pipeline.MANIFEST_SHA256
 if args.domain=='sdk':output.mkdir();capture=Capture(output/'native')
 else:capture=Capture(output)
 extra={}
 try:
  with NativeModule(args.manifest,manifest_sha256=manifest['sha256'])as module:
   if args.domain=='private':semantic(module,capture);private(module,capture)
   else:extra=sdk_execute(module,capture,output)
 except BaseException:error=traceback.format_exc();raise
 finally:
  capture.close();assert pipeline.source_table(ROOT)==pins
  result={'status':'PASS'if error is None else'FAIL','error':error,'domain':args.domain,
   'pid':os.getpid(),'started_monotonic_ns':started,'finished_monotonic_ns':time.monotonic_ns(),
   'native_calls':capture.count,'sessions':capture.sessions,'growth':capture.growth,
   'domains':dict(capture.domains),'refusals':dict(capture.errors),'retained_blob_count':len(capture.seen),
   'source_files':pins,'manifest':manifest,'execution':pipeline.pin(args.execution),
   'original_sdk_executed':False,'whole_runtime_replaced':False,**extra}
  pipeline.write_new(output/'RESULT.json',result)
  print(json.dumps({k:v for k,v in result.items()if k!='source_files'},sort_keys=True),flush=True)
if __name__=='__main__':main()
