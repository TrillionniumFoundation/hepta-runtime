"""Capture actual public HIA/SDK sessions and their complete owned state, in CI."""
from pathlib import Path
import argparse,json,os,sys,time
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'capture'))
import capture_common as common
import capture_fixture as fixture_io
import public_cases as cases
import public_observations as observations
import body_fixture
DOMAINS=cases.DOMAINS
DRIVER_FILES=('qualify_public.py','public_cases.py','body_cases.py','body_fixture.py','peer/extract_public_inputs.py','public_observations.py','capture/capture_common.py','capture/capture_fixture.py','corpus/state_reference/native_observations.py','corpus/state_reference/observations.py')
def pins(raw):return {'bytes':len(raw),'sha256':common.sha(raw)}
def whole_snapshot(owned):
    owned.owned(os.fsencode(owned.root),allow_root=True)
    return common.OwnedFixture(owned.root.parent).snapshot([os.fsencode(owned.root).hex()])
def cache_set(path,content):return cases.cache_frame(path,content)
class Native:
    def __init__(self,output,binary,cwd,config=None):
        self.io=fixture_io.RecordedFixtureProcess(output,binary,cwd,strace='/usr/bin/strace',trace=False,extra_argv=() if config is None else ('--runtime-config',str(config)))
    def observe(self):
        refs=[];bodies=[]
        for session in (0,1):
            row,body=self.io.call(session,33,b'');common.need(row['header']['native_return']==0,'native observer return');refs.append(row['index']);bodies.append(body)
        row,shared=self.io.call(0,41,b'');common.need(row['header']['native_return']==0,'shared observer return');refs.append(row['index'])
        return {'exchanges':refs,'state':observations.native_state(bodies,shared)}
    def wire(self,session,raw,response):
        row,body=self.io.public(session,raw);common.need(bool(body)==response,'native declared request framing')
        return {'exchange':row['index'],'wire':body}
    def seed(self,session,raw,owner='cache'):
        slot=32 if owner=='cache' else 64;row,body=self.io.call(session,slot,raw)
        if owner=='cache':common.need(body==b'HVCAR001'+bytes(24) and row['header']['native_return']==32,'native cache seed')
        else:common.need(body[:8]==b'HHISTR01' and len(body)==64 and row['header']['native_return']==64,'native actual shared history seed')
        return {'exchange':row['index'],'wire':body}
    def close(self,failed):return self.io.close(failed=failed)
class Original:
    def __init__(self,output,binary,cwd,config=None):
        common.need(os.environ.get('GITHUB_ACTIONS')=='true','original reference CI-only')
        self.io=common.RecordedPublicProcess(output,binary,cwd,strace='/usr/bin/strace',trace=False,extra_argv=() if config is None else (str(config),));self.sequence=0
    def command(self,kind,session,raw=b'',response=False):
        command={'id':self.sequence,'session':session,'kind':kind}
        if kind!='observe':command.update(wire_hex=raw.hex(),response=response)
        self.sequence+=1;receipt,lines=self.io.exchange(cases.encode(command)+b'\n')
        common.need(receipt['transport']=='response' and len(lines)==1,'complete original fixture response')
        parsed=json.loads(lines[0]);state=observations.original_state(parsed,command);body=bytes.fromhex(parsed['output_hex'])
        return {'exchange':receipt['index'],'wire':body,'state':state}
    def observe(self):
        row=self.command('observe',0);common.need(not row['wire'],'original observation emitted a result');return {'exchanges':[row['exchange']],'state':row['state']}
    def wire(self,session,raw,response):
        row=self.command('wire',session,raw,response);common.need(bool(row['wire'])==response,'original declared request framing');return {k:row[k] for k in ('exchange','wire')}
    def seed(self,session,raw,owner='cache'):
        row=self.command(owner,session,raw)
        if owner=='cache':common.need(row['wire']==b'HVCAR001'+bytes(24),'original cache seed')
        else:common.need(row['wire'][:8]==b'HHISTR01' and len(row['wire'])==64,'original shared history seed')
        return {k:row[k] for k in ('exchange','wire')}
    def close(self,failed):return self.io.close(failed=failed)
def execute(role,binary,fixture,output,domain,case_index=None,shared_tool=None):
    common.need(os.environ.get('GITHUB_ACTIONS')=='true','public semantic execution is CI-only')
    binary=Path(binary).resolve(strict=True);fixture=Path(fixture).absolute();output=Path(output).absolute()
    common.need(role in ('native','original') and domain in DOMAINS,'public role/domain');common.need(not output.is_relative_to(fixture) and not fixture.is_relative_to(output),'separate owned fixture/evidence')
    output.mkdir(parents=True,exist_ok=False);plan=cases.plan(domain,fixture,case_index);rows=plan['rows']
    if plan['body_spec'] is not None:body_fixture.setup(plan['body_spec'],fixture)
    else:fixture.mkdir(parents=True,mode=0o700,exist_ok=False)
    owned=common.OwnedFixture(fixture);initial_actions=owned.actions(plan['actions']);vault=output/'blobs';vault.mkdir()
    tool=common.capture_tool(binary,output,role) if shared_tool is None else shared_tool
    config=None
    if 'runtime_config' in plan:
        config=output/'runtime-config.json';config.write_bytes(common.canonical(plan['runtime_config']))
    report={'schema':'hepta.runtime.extract-public-complete-capture.v1','status':'RUNNING','role':role,'domain':domain,
        'case_index':case_index,'case_name':plan['case_name'],'case_count':len(rows),'fixture':str(fixture),'effective_uid':os.geteuid(),
        'binary':tool,'shared_binary_relative':None if shared_tool is None else '../../tool-'+role+'.bin',
        'runtime_config':None if config is None else {'path':str(config),**pins(config.read_bytes())},
        'input_plan':cases.serial(plan),'initial_actions':initial_actions,'initial_filesystem':whole_snapshot(owned),
        'per_exchange_deadline_seconds':60,'outer_lane_deadline_seconds':180,'public_extract_qualified':False,
        'full_async_cancellation_qualified':False,'remote_sftp_qualified':False,'whole_runtime_replaced':False,
        'driver_sources':{n:common.file_pin(ROOT/n) for n in DRIVER_FILES}}
    (output/'result.json').write_bytes(common.canonical(report));provider=None;failed=True;started=time.monotonic();stream=common.Stream(output/'events.jsonl.gz');completed=0;initial=[];initial_seeds=[]
    def full_body():return body_fixture.tree_snapshot(fixture,vault) if plan['body_spec'] is not None else None
    try:
        provider=(Native if role=='native' else Original)(output/'process',binary,fixture,config)
        for item in plan['initial']:
            result=provider.wire(item['session'],item['wire'],item['response']);initial.append({'session':item['session'],'input':pins(item['wire']),'exchange':result['exchange'],'response':pins(result['wire'])})
        for seed in plan['seeds']:
            result=provider.seed(seed['session'],seed['wire'],seed['owner']);initial_seeds.append({'owner':seed['owner'],'session':seed['session'],'input':pins(seed['wire']),'exchange':result['exchange'],'response':pins(result['wire'])})
        for index,row in enumerate(rows):
            common.need(time.monotonic()-started<180,'complete public lane exceeded 180 seconds')
            actions=owned.actions(row['actions']);seeds=[]
            for seed in row.get('seed') or []:
                raw=cache_set(seed['path'],seed['content']);result=provider.seed(seed['session'],raw);seeds.append({'input':pins(raw),'exchange':result['exchange'],'response':pins(result['wire'])})
            before_tree=whole_snapshot(owned);before_full=full_body();before=provider.observe();wire=cases.row_wire(row,index,plan['modern']);result=provider.wire(row.get('session',0),wire,row['response']);recovery=None
            if not row['response']:
                ping=cases.encode({'jsonrpc':'2.0','id':100000+index,'method':'ping'})+b'\n';reply=provider.wire(row.get('session',0),ping,True);common.need(json.loads(reply['wire'])['id']==100000+index,'discard recovery response identity');recovery={'input':pins(ping),'exchange':reply['exchange'],'response':pins(reply['wire'])}
            after=provider.observe();after_tree=whole_snapshot(owned);after_full=full_body();cleanup=owned.actions(row['after_actions']);cleanup_tree=whole_snapshot(owned)
            event={'index':index,'name':row['name'],'domain':row['domain'],'original_case_id':row.get('original_case_id'),'session':row.get('session',0),
                'input':pins(wire),'exchange':result['exchange'],'response':pins(result['wire']),'actions':actions,'seeds':seeds,'before':before,'after':after,
                'before_filesystem':before_tree,'after_filesystem':after_tree,'after_actions':cleanup,'after_cleanup_filesystem':cleanup_tree,'recovery':recovery,
                'body_full_filesystem':[before_full,after_full] if plan['body_spec'] is not None else None}
            stream.write(common.canonical(event));completed+=1
        report['final_filesystem']=whole_snapshot(owned);report['final_full_body_filesystem']=full_body();report['final_observation']=provider.observe();failed=False
    except BaseException as error:report['failure']=repr(error);raise
    finally:
        close_error=None
        if provider is not None:
            try:report['process']=provider.close(failed)
            except BaseException as error:failed=True;close_error=error;report['close_failure']=repr(error)
        report.update(status='FAIL' if failed else 'PASS',completed_cases=completed,initial=initial,initial_seeds=initial_seeds,events=stream.close(),elapsed_seconds=time.monotonic()-started)
        common.check_tool(tool);(output/'result.json').write_bytes(common.canonical(report))
        if close_error is not None:raise close_error
    return report
def run_lane(role,binary,fixture,output,domain):
    output=Path(output);fixture=Path(fixture)
    if not domain.startswith('body-'):return execute(role,binary,fixture,output,domain)
    output.mkdir(parents=True,exist_ok=False);tool=common.capture_tool(Path(binary).resolve(strict=True),output,role);started=time.monotonic();done=[];report={'status':'RUNNING','domain':domain,'role':role,'binary':tool,'cases':done,'case_count':153,'operation_count':175,'outer_lane_deadline_seconds':180};(output/'lane.json').write_bytes(common.canonical(report))
    try:
        for index,spec in enumerate(cases.body_specs()):
            common.need(time.monotonic()-started<180,'complete 153-case public lane exceeded 180 seconds')
            result=execute(role,binary,fixture,output/'cases'/f'{index:03d}',domain,index,tool);done.append({'index':index,'name':spec['name'],'operations':len(spec['operations']),'result':common.file_pin(output/'cases'/f'{index:03d}'/'result.json')})
            parent=common.OwnedFixture(fixture.parent);cleanup=parent.remove_tree(os.fsencode(fixture));(output/'cases'/f'{index:03d}'/'fixture-retirement.json').write_bytes(common.canonical({'after_full_capture':True,'removed':cleanup}))
        report['status']='PASS'
    except BaseException as error:report['status']='FAIL';report['failure']=repr(error);raise
    finally:report['elapsed_seconds']=time.monotonic()-started;common.check_tool(tool);(output/'lane.json').write_bytes(common.canonical(report))
    return report
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--role',choices=('native','original'),required=True);p.add_argument('--binary',type=Path,required=True);p.add_argument('--fixture',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--domain',choices=DOMAINS,required=True);a=p.parse_args();result=run_lane(a.role,a.binary,a.fixture,a.output,a.domain);print(json.dumps({k:result[k] for k in ('status','domain','role')},sort_keys=True))
