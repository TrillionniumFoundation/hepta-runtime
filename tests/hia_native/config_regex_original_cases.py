"""Additional real installed-config comparisons, using the original four-bin build.

All state directories belong to these fixtures. The internal owner diagnostic
word is recorded but excluded, just as in the baseline owner reference; public
status, result/error bytes, filesystem effects and the complete MCP wire agree.
"""
from pathlib import Path
import gzip,hashlib,json,shutil,struct,subprocess,tempfile,time
import config_owner_cases as owner
import config_mcp_sessions as mcp
from config_mcp_cases import compact,fixture,wire

sha=lambda raw:hashlib.sha256(raw).hexdigest()
OWNER_PATTERNS=[['x'],[r'\p{Greek}+',r')|foo(?:'],['a{327674}']]
MCP_PATTERNS=[['a'],[r'\p{Greek}+',r'(?i:[a-z]+)'],[r')|foo(?:'],['a{327674}']]
REFUSALS=['(',r'\w{500}','a{327675}',r'(?-u:\xFF)']


def compare_regex_owners(native,reference,output):
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    rows=[];streams=[]
    with tempfile.TemporaryDirectory(prefix='same-regex-owner-',dir=output)as temp:
        root=Path(temp)
        for index,patterns in enumerate(OWNER_PATTERNS):
            sides=[]
            for side,binary in [('native',native),('original',reference)]:
                folder=root/'fixture';folder.mkdir();path=folder/'config';state=folder/'state'
                value=owner.config(state)
                value['hosts']['h']['privileged_actions']={'act':{'executable':'/bin/x','allow_extra_args':True,'extra_arg_patterns':patterns}}
                owner.write_config(path,value);responses=[];events=[]
                with owner.Session(binary,path)as session:
                    def call(request):
                        status,code,payload=session.call(request)
                        response=b'HRCFGM01'+struct.pack('<3Q',status,code,len(payload))+payload
                        streams.append({'profile':index,'side':side,'request_hex':request.hex(),'response_hex':response.hex()})
                        responses.append({'status':status,'payload_hex':payload.hex()})
                    for operation in [1,2,3,6]:call(owner.query(operation))
                    events.append(all(not owner.unlocked(state/name)for name in ['controller.owner.lock','controller.lock']))
                    value['state_dir']=str(folder/'second');value['hosts']['h']['privileged_actions']['act']['extra_arg_patterns']=['('];owner.write_config(path,value)
                    call(owner.startup(path));events.append(not(folder/'second').exists())
                    for operation in [1,2,3,6]:call(owner.query(operation))
                    value['hosts']['h']['privileged_actions']['act']['extra_arg_patterns']=['x'];owner.write_config(path,value);call(owner.startup(path))
                    events.append(all(owner.unlocked(folder/'second'/name)for name in ['controller.owner.lock','controller.lock']))
                    for operation in [1,2,3,6]:call(owner.query(operation))
                    events.append(all(not owner.unlocked(state/name)for name in ['controller.owner.lock','controller.lock']))
                events.append(all(owner.unlocked(state/name)for name in ['controller.owner.lock','controller.lock']))
                sides.append({'responses':responses,'events':events,'snapshot':owner.snapshot(folder)});shutil.rmtree(folder)
            assert sides[0]==sides[1],index
            rows.append({'profile':index,'patterns':patterns,'native':sides[0],'original':sides[1]})
    assert len(streams)==84 and all(len(row['native']['responses'])==14 for row in rows)
    raw=(json.dumps(streams,sort_keys=True,separators=(',',':'))+'\n').encode()
    (output/'streams.json.gz').write_bytes(gzip.compress(raw,mtime=0))
    report={'schema':'hepta.runtime.regex-installed-extra.v1','status':'PASS','profiles':rows,'profile_count':3,'response_pairs':42,
            'stream_records':len(streams),'stream_bytes':len(raw),'stream_sha256':sha(raw),'native_internal_diagnostic_word_excluded':True,
            'same_exact_fixture_paths':True,'complete_result_payloads_compared':True}
    (output/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    return {'profile_count':3,'response_pairs':42,'report_sha256':sha((output/'report.json').read_bytes()),'stream_sha256':sha(raw)}


def compare_regex_mcp(native,reference,output):
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    streams=[];profiles=[];refusals=[]
    for index,patterns in enumerate(MCP_PATTERNS):
        with tempfile.TemporaryDirectory(prefix='same-regex-mcp-',dir=output)as temp:
            root=Path(temp);config=root/'config';state=root/'state'
            value={'state_dir':str(state),'hosts':{'h':{'ssh_target':'private-target','remote_state_dir':'/private-state',
                'privileged_actions':{'inspect':{'executable':'/echo','fixed_args':['private-fixed'],'allow_extra_args':True,'extra_arg_patterns':patterns}}}}}
            requests=[wire('host_list',b'{}',1),wire('effective_config',b'null',2),wire('execution_shadow_admit',compact(fixture()),3),
                      wire('execution_shadow_admit',compact(fixture('missing')),4),wire('host_list',b'{"z":0,"a":false}',5),wire('effective_config',b'{}',6)]
            sides=[]
            for side,binary in [('native',native),('original',reference)]:
                config.write_bytes(compact(value));session=mcp.Session(binary,config);start=time.monotonic()
                try:
                    initial=session.start();responses=[]
                    for j,request in enumerate(requests):
                        if j==3:config.write_bytes(b'{"hosts":{}}')
                        response=session.call(request);responses.append(response)
                        streams.append({'profile':index,'side':side,'request_hex':request.hex(),'response_hex':response.hex()})
                    session.close();sides.append(responses)
                finally:session.abort()
                shutil.rmtree(state)
            assert sides[0]==sides[1],index
            profiles.append({'profile':index,'patterns':patterns,'responses':6,'wire_sha256':sha(b'\n'.join(sides[0])),
                             'source_change_did_not_reload':True})
    for index,pattern in enumerate(REFUSALS):
        with tempfile.TemporaryDirectory(prefix='same-regex-error-',dir=output)as temp:
            root=Path(temp);config=root/'config';state=root/'state'
            value={'state_dir':str(state),'hosts':{'h':{'ssh_target':'private-target','remote_state_dir':'/private-state',
                   'privileged_actions':{'inspect':{'executable':'/echo','allow_extra_args':True,'extra_arg_patterns':[pattern]}}}}}
            config.write_bytes(compact(value));sides=[];processes=[]
            for side,binary in [('native',native),('original',reference)]:
                command=[str(binary),'--runtime-config',str(config)];start=time.monotonic()
                done=subprocess.run(command,input=b'',capture_output=True,timeout=30,env={'PATH':'','LC_ALL':'C'})
                sides.append((done.returncode,done.stdout,done.stderr));assert not state.exists()
                processes.append({'side':side,'command':command,'cwd':str(Path.cwd()),'exit_code':done.returncode,
                    'elapsed_seconds':time.monotonic()-start,'stdout_hex':done.stdout.hex(),'stderr_hex':done.stderr.hex(),
                    'timeout_seconds':30,'state_directory_created':False})
            assert sides[0]==sides[1] and sides[0][0]==78
            refusals.append({'profile':index,'pattern':pattern,'processes':processes})
    raw=(json.dumps(streams,sort_keys=True,separators=(',',':'))+'\n').encode()
    (output/'streams.json.gz').write_bytes(gzip.compress(raw,mtime=0))
    report={'schema':'hepta.runtime.regex-mcp-extra.v1','status':'PASS','profiles':profiles,'refusals':refusals,
            'profile_count':4,'response_pairs':24,'refusal_pairs':4,'stream_records':len(streams),
            'stream_bytes':len(raw),'stream_sha256':sha(raw),'same_exact_fixture_paths':True,'complete_mcp_wire_compared':True}
    (output/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    return {'profile_count':4,'response_pairs':24,'refusal_pairs':4,'report_sha256':sha((output/'report.json').read_bytes()),'stream_sha256':sha(raw)}
