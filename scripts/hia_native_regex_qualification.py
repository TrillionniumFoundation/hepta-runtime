"""Admit completed native regex suites and complete original replay artifacts.

Evidence admission performs no regex operation, native call or Rust execution.
Only exact checked corpus joins and their receipts may be created.
"""
from pathlib import Path
import gzip,hashlib,json,math,re,struct,sys,tarfile,tomllib
TESTS=('test_regex_unicode.py','test_regex_syntax.py','test_regex_hir.py','test_regex_nfa_0.py','test_regex_nfa_1.py','test_regex_match.py','test_regex_pipeline.py','test_regex_controls.py','test_config_regex.py')
FOLDERS=('unicode','syntax','hir','nfa-0','nfa-1','match-corpus','pipeline','controls','config-corpus')
GROUPS=(7,6,5,None,None,None,4,4,None)
DOMAIN_CASES={'unicode':6560,'syntax':18976,'hir':34130,'nfa':3584,'match':65440}
CONTROL_COUNTS={'config_corrupt_envelopes':4,'config_corrupt_receipts':15,'config_domain_statuses':3,'config_failed_request_recoveries':3,
 'controller_capacity_refusals':2,'controller_corrupt_receipts':15,'controller_domain_statuses':3,'matcher_capacity_refusals':2,
 'matcher_data_calls':1,'matcher_entries':88,'matcher_invalid_refusals':86,'native_entries':146,'nfa_capacity_refusals':7,
 'nfa_invalid_refusals':21,'setup_hir_entries':6,'setup_nfa_entries':1,'setup_parser_entries':6}
COUNTS={
 'unicode':{'abi_refusals':23,'actual_processes':5,'capacity_refusals':5,'capture_predicate_cases':9002,'direct_calls':9068,'elf_queries':6560,'receipt_refusals':14},
 'syntax':{'capacity_refusals':5,'child_calls':23,'elf_requests':18977,'framing_refusals':16,'native_calls':69,'processes':6,'receipt_refusals':14},
 'hir':{'capacity_refusals':5,'data_calls':23,'elf_requests':25328,'framing_refusals':28,'native_calls':75,'parser_calls':34143,'processes':5,'receipt_refusals':14,'resource_refusals':1},
 'match-corpus':{'cases':65440,'data_calls':3,'haystacks':80,'hir_calls':811,'match_calls':61281,'nfa_calls':1532,'parser_calls':819,'patterns':409,'positive':21506,'size_errors':0,'successes':61280,'syntax_errors':4160},
 'pipeline':{'abi_refusals':14,'elf_requests':32764,'observed_original_budget_boundaries':3,'original_comparisons':32720,'processes':4}}
OWN=['native/regex_abi.md',
 'native/regex_controller.hepta','native/regex_controller_composition.json',
 'native/regex_syntax.hepta','native/regex_syntax_composition.json','native/regex_syntax_packer.hepta',
 'native/regex_hir.hepta','native/regex_hir_composition.json','native/regex_hir_packer.hepta',
 'native/regex_nfa.hepta','native/regex_nfa_composition.json','native/regex_match.hepta','native/regex_match_composition.json',
 'native/regex_unicode.hepta','native/regex_unicode_composition.json','native/regex_unicode_data.hepta','native/regex_unicode_data_composition.json',
 'native/regex_unicode_packer.hepta','native/regex_pipeline_packer.hepta','native/config_regex_packer.hepta',
 'scripts/build_regex_probe.py','scripts/regex_unicode_adapter.S','scripts/regex_syntax_adapter.S','scripts/regex_hir_adapter.S',
 'scripts/regex_pipeline_adapter.S','scripts/config_regex_adapter.S','scripts/hia_native_regex_qualification.py','scripts/hia_native_regex_reference.py',
 'tests/hia_native/regex_test_context.py','tests/hia_native/regex_unicode_fixture.py','tests/hia_native/regex_parser_fixture.py',
 'tests/hia_native/regex_hir_fixture.py','tests/hia_native/regex_nfa_fixture.py','tests/hia_native/regex_match_fixture.py',
 'tests/hia_native/regex_unicode_projection.py','tests/hia_native/regex_nfa_cases.py','tests/hia_native/regex_match_cases.py',
 'tests/hia_native/regex_reference_cases.tar.xz','tests/hia_native/regex_reference_cases.json','tests/hia_native/compare_regex_original.py',
 *('tests/hia_native/'+name for name in TESTS),
 *('tests/hia_native/regex_reference/'+name for name in ['Cargo.toml','Cargo.lock','oracle.rs','ast_projection.rs','hir_projection.rs','original-runtime.lock','source-identity.json'])]
sha=lambda raw:hashlib.sha256(raw).hexdigest()
encoded=lambda value:(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()


def need(ok,message):
    if not ok:raise ValueError('regex evidence: '+message)


def read(path):
    path=Path(path);need(path.is_file()and not path.is_symlink(),'missing regular artifact: '+str(path));return path.read_bytes()


def obj(path):
    def unique(rows):
        values={}
        for key,value in rows:need(key not in values,'duplicate JSON key');values[key]=value
        return values
    value=json.loads(read(path),object_pairs_hook=unique);need(type(value)is dict,'expected object');return value


def finite(value,limit=180):need(type(value)in(int,float)and math.isfinite(value)and 0<=value<limit,'invalid execution duration')


def artifact(output,records,path):
    path=Path(path);need(path.is_relative_to(output)and'..'not in path.parts,'artifact escaped output')
    raw=read(path);records[path.relative_to(output).as_posix()]=sha(raw);return raw


def _prepare_sources(root,output,artifacts):
    index=obj(root/'tests/hia_native/regex_reference_cases.json');archive=root/'tests/hia_native/regex_reference_cases.tar.xz'
    raw=read(archive);need((len(raw),sha(raw))==(index['archive_bytes'],index['archive_sha256']),'retained original archive changed')
    data=output/'regex-native/reference-data';actual={p.relative_to(data).as_posix()for p in data.rglob('*')if p.is_file()}
    need(actual==set(index['files']),'reference fixture inventory changed')
    for name,want in index['files'].items():
        raw=artifact(output,artifacts,data/name);need((len(raw),sha(raw))==(want['bytes'],want['sha256']),'reference fixture bytes changed')
    need(index['domain_cases']==DOMAIN_CASES,'original domain sizes changed');return data,index


def _suite(root,output,aggregate,completed,name,folder,groups,command,bundle,artifacts):
    check,summary=completed(output,aggregate,name)
    need(check['command']==command and check['exit_code']==0 and check['timed_out']is False and not check.get('start_error'),'actual native process incomplete')
    need(check['timeout_seconds']==180,'native suite budget changed');finite(check['elapsed_seconds'])
    stdout=artifact(output,artifacts,output/(name+'.stdout'));stderr=artifact(output,artifacts,output/(name+'.stderr'))
    need((sha(stdout),sha(stderr))==(check['stdout_sha256'],check['stderr_sha256']),'completed process streams changed')
    need(json.loads(stdout)==summary and summary['status']=='PASS','actual native stdout differs')
    path=output/'regex-native'/folder/('native-corpus.json'if groups is None else'result.json')
    stored=json.loads(artifact(output,artifacts,path));need(stored==summary,'retained native result differs from completed stdout');finite(summary['elapsed'])
    if folder in COUNTS:need({k:summary.get(k)for k in COUNTS[folder]}==COUNTS[folder],'native case/control count changed')
    if folder=='controls':need(summary['counts']==CONTROL_COUNTS and summary['source_unchanged']is True and summary['synthetic_acknowledgements_explicit']is True,'internal controls missing or misclassified')
    if groups is not None:
        need(summary.get('tests_run',summary.get('groups'))==groups,'native test group missing')
        text=stderr.decode();need(len(re.findall(r'\.\.\. ok\n',text))==groups and re.search(r'\nRan '+str(groups)+r' tests in [0-9.]+s\n\nOK\n\Z',text)is not None,'native unittest did not finish')
    else:need(stderr==b'','corpus native suite emitted an error')
    for path,digest in summary.get('sources',summary.get('source_sha256',{})).items():need(sha(read(root/path))==digest,'native tested source changed')
    if 'native_source_sha256'in summary:
        need(summary['native_source_sha256']=={p.name:sha(read(p))for p in (root/'native').glob('*.hepta')},'Unicode native source set changed')
        need(summary['test_source_sha256']==sha(read(root/'tests/hia_native'/name)),'Unicode test source changed')
    profile={'unicode':'unicode','syntax':'syntax','hir':'hir','pipeline':'regex','config-corpus':'validation'}.get(folder)
    if profile:need(summary['composition_manifest_sha256']==bundle['executables']['regex_'+profile]['sha256'],'tested native ELF manifest differs')
    for claim in ['regex_compiler_closed','configuration_owner_wired','unconstrained_regex_resources_closed']:
        if claim in summary:need(summary[claim]is False,'scope overclaimed')
    return summary


def _frames(raw):
    at=0;rows=[]
    while at<len(raw):
        need(len(raw)-at>=16,'truncated actual ELF response');code,n=struct.unpack_from('<QQ',raw,at);at+=16
        need(code<=0xffffffff and n<=len(raw)-at,'invalid actual ELF result span');body=raw[at:at+n];at+=n
        if code==0xfffffffd:code=1
        rows.append(f'{code:08x}:'.encode()+body.hex().encode()+b'\n')
    return rows


def _unicode_projection(cases,raw):
    rows=_frames(raw);need(len(rows)==len(cases),'Unicode native query count changed');result=[]
    for case,row in zip(cases,rows,strict=True):
        code,body=row.rstrip(b'\n').split(b':',1)
        if case['kind']=='fold':
            need(code==b'00000000','native fold failed');wire=bytes.fromhex(body.decode());need(len(wire)>=8,'truncated fold result')
            count=struct.unpack_from('<Q',wire)[0];need(len(wire)==8+count*8,'fold span changed')
            points=sorted(set([case['point'],*struct.unpack_from('<'+'Q'*count,wire,8)]));ranges=[]
            for point in points:
                if ranges and point==ranges[-1][1]+1:ranges[-1][1]=point
                else:ranges.append([point,point])
            body=(struct.pack('<Q',len(ranges))+b''.join(struct.pack('<QQ',a,b)for a,b in ranges)).hex().encode()
        result.append(code+b':'+body+b'\n')
    return b''.join(result)


def _store_corpus(output,artifacts,name,request,response,expected_count,create):
    need(request.count(b'\n')==response.count(b'\n')==expected_count,'complete native corpus count differs')
    folder=output/'regex-native/corpora'/name
    if create:folder.mkdir(parents=True,exist_ok=False)
    for filename,raw in [('requests.hex',request),('native-output.txt',response)]:
        path=folder/filename
        if create:
            with path.open('xb')as stream:stream.write(raw)
        need(artifact(output,artifacts,path)==raw,'retained corpus differs from actual native projection')
    return {'directory':str(folder),'cases':expected_count,'requests_bytes':len(request),'requests_sha256':sha(request),'native_output_bytes':len(response),'native_output_sha256':sha(response)}


def native_evidence(root,output,aggregate,completed,bundle,built,commands,source_pins,create=False):
    root=Path(root).resolve(strict=True);output=Path(output).resolve(strict=True);artifacts={};data,index=_prepare_sources(root,output,artifacts)
    summaries={name:_suite(root,output,aggregate,completed,name,folder,groups,commands[name],bundle,artifacts)
               for name,folder,groups in zip(TESTS,FOLDERS,GROUPS,strict=True)}
    corpora={}
    for name in ['unicode','syntax','hir']:
        folder=output/'regex-native'/name;request=artifact(output,artifacts,folder/'requests.hex');response=artifact(output,artifacts,folder/'native-output.txt')
        need(request==read(data/name/'requests.hex')and response==read(data/name/'native-output.txt'),'native complete corpus differs from observed original')
        corpora[name]=_store_corpus(output,artifacts,name,request,response,DOMAIN_CASES[name],create)
    actual=artifact(output,artifacts,output/'regex-native/syntax/elf.stdout')
    need(b''.join(_frames(actual))==read(data/'syntax/native-output.txt'),'actual AST ELF output differs')
    cases=json.loads(read(data/'unicode/cases.json'));wire=b''.join(struct.pack('<Q',len(bytes.fromhex(row['native'])))+bytes.fromhex(row['native'])for row in cases)
    need(artifact(output,artifacts,output/'regex-native/unicode/elf.stdin.bin')==wire,'actual Unicode requests differ')
    need(_unicode_projection(cases,artifact(output,artifacts,output/'regex-native/unicode/elf.stdout.bin'))==read(data/'unicode/native-output.txt'),'actual Unicode response projection differs')
    hir_indices=json.loads(artifact(output,artifacts,output/'regex-native/hir/elf-case-indices.json'))
    need(type(hir_indices)is list and len(hir_indices)==25328 and hir_indices==sorted(set(hir_indices))and all(type(i)is int and 0<=i<34130 for i in hir_indices),'HIR actual input/output map changed')
    hir_rows=read(data/'hir/native-output.txt').splitlines(keepends=True)
    need(_frames(artifact(output,artifacts,output/'regex-native/hir/elf.stdout'))==[hir_rows[i]for i in hir_indices],'actual HIR ELF outputs differ')
    active=set(hir_indices);need(all(row==b'00000001:\n'for i,row in enumerate(hir_rows)if i not in active),'HIR skipped a successful parser case')
    for name in ['unicode','syntax','hir']:
        summary=summaries['test_regex_'+name+'.py'];folder=output/'regex-native'/name
        for key in ['elf.stdin.bin','elf.stdout.bin','elf.stdin','elf.stdout','elf.stderr']:
            if key in summary and (folder/key).exists():
                raw=artifact(output,artifacts,folder/key);need((len(raw),sha(raw))==(summary[key]['bytes'],summary[key]['sha256']),'actual ELF stream changed')
    need(summaries['test_regex_unicode.py']['elf_queries']==6560 and summaries['test_regex_unicode.py']['capture_predicate_cases']==9002,'Unicode domain incomplete')
    need(summaries['test_regex_syntax.py']['elf_requests']==18977 and summaries['test_regex_syntax.py']['full_pattern']['pattern_bytes']==64<<20,'AST full pattern/corpus omitted')
    need(summaries['test_regex_hir.py']['elf_requests']==25328 and summaries['test_regex_hir.py']['parser_calls']==34143,'HIR pipeline domain incomplete')
    indices=[];joined={};boundaries=calls=parser_calls=hir_calls=0
    for shard in [0,1]:
        folder=output/'regex-native'/('nfa-'+str(shard));summary=summaries['test_regex_nfa_'+str(shard)+'.py']
        raw_indices=artifact(output,artifacts,folder/'case-indices.json');current=json.loads(raw_indices)
        need(sha(raw_indices)==summary['case_indices_sha256']and summary['shard']==shard and summary['shards']==2,'NFA shard identity changed')
        expected=[i for i in range(3584)if(i//2)%2==shard];need(current==expected,'NFA partition omitted, repeated or moved a case')
        req=artifact(output,artifacts,folder/'requests.hex');out=artifact(output,artifacts,folder/'native-output.txt')
        need((len(req),sha(req),len(out),sha(out))==(summary['requests_bytes'],summary['requests_sha256'],summary['native_output_bytes'],summary['native_output_sha256']),'NFA native corpus changed')
        need(summary['cases']==len(current)==1792 and summary['complete_domain_cases']==3584,'NFA domain count changed')
        for i,r,s in zip(current,req.splitlines(keepends=True),out.splitlines(keepends=True),strict=True):need(i not in joined,'duplicate NFA case');joined[i]=(r,s)
        indices+=current;boundaries+=summary['boundary_native_calls'];calls+=summary['native_calls'];parser_calls+=summary['parser_calls'];hir_calls+=summary['hir_calls']
    need(sorted(indices)==list(range(3584))and(boundaries,calls,parser_calls,hir_calls)==(576,3016,680,184),'NFA execution/budget controls changed')
    request=b''.join(joined[i][0]for i in range(3584));response=b''.join(joined[i][1]for i in range(3584))
    need(request==read(data/'nfa/requests.hex')and response==read(data/'nfa/native-output.txt'),'joined native NFA bytes differ')
    corpora['nfa']=_store_corpus(output,artifacts,'nfa',request,response,3584,create)
    folder=output/'regex-native/match-corpus';summary=summaries['test_regex_match.py']
    request=artifact(output,artifacts,folder/'requests.hex');response=artifact(output,artifacts,folder/'native-output.txt')
    need(request==read(data/'match/requests.hex')and response==read(data/'match/native-output.txt'),'native Boolean match bytes differ')
    need(summary['cases']==65440 and summary['successes']==61280 and summary['positive']==21506 and summary['syntax_errors']==4160,'matcher domain changed')
    corpora['match']=_store_corpus(output,artifacts,'match',request,response,65440,create)
    pipeline=summaries['test_regex_pipeline.py'];need(pipeline['elf_requests']==32764 and pipeline['original_comparisons']==32720,'complete wrapped service corpus missing')
    config=summaries['test_config_regex.py'];folder=output/'regex-native/config-corpus'
    need(config['cases']==3694 and config['actual_elf_requests']==3472 and config['counts']=={'identity_native_calls':21,'retained_original_comparisons':2063,'typed_native_calls':3694,'typed_refusals':201},'complete configuration-regex execution domain differs')
    need(sum(config['categories'].values())==3694 and config['typed_manifests']=={n:bundle['modules'][n]['sha256']for n in ['json','identity']},'configuration-regex typed dependency changed')
    for name,size,digest in [('requests.hex',14683110,'6ed09450d8ba8959f6a3e7eb4047ca04792b55552232ba37e9a8d3e8fb3f6abb'),
                             ('native-output.txt',5009290,'c309492113e9bfe9106c59b24f720e4621f6ecc3b9e4c8ff0e7c6e5d84318c63'),
                             ('elf.stdin',28059688,'745abb9f607faab674e5c24b1340e869b1b85483c0d643ba2089be807a9d4555'),
                             ('elf.stdout',2652159,'2306afe23144a01c7922383e0b4832dfeb5e037c4da661e62c546e90f38c427e')]:
        raw=artifact(output,artifacts,folder/name);need((len(raw),sha(raw))==(size,digest),'actual configuration-regex corpus/ELF stream changed')
    for folder in ['pipeline','controls']:
        for path in (output/'regex-native'/folder).iterdir():
            if path.is_file():artifact(output,artifacts,path)
    predicate=data/'capture-predicates.txt';predicate_raw=artifact(output,artifacts,predicate)
    result={'schema':'hepta.runtime.regex-native-tests.v1','status':'PASS','source_unchanged':True,'source_pins':source_pins,
            'build_sha256':built['bundle_sha256'],'actual_completed_suites':9,'corpora':corpora,'configuration_corpus':str(output/'regex-native/config-corpus'),
            'capture_predicates':{'path':str(predicate),'bytes':len(predicate_raw),'sha256':sha(predicate_raw)},
            'cases':128690,'native_calls_added_by_evidence_admission':0,'unconstrained_regex_resources_closed':False}
    path=output/'regex-native/result.json';raw=encoded(result)
    if create:
        with path.open('xb')as stream:stream.write(raw)
    need(artifact(output,artifacts,path)==raw,'regex compatibility result was not derived from completed suites')
    return {'status':'PASS','tests':summaries,'corpora':corpora,'configuration_corpus':config,'compatibility_result_sha256':sha(raw),'artifact_sha256':artifacts,
            'corpus_sha256':{name:digest for name,digest in artifacts.items()if '/corpora/'in name},
            'unconstrained_regex_resources_closed':False,'native_calls_added_by_evidence_admission':0}


def original_evidence(root,output,aggregate,completed,native,source_pins):
    from hia_native_regex_reference import REFERENCE_FILES,REMOVED_ENV,check_reference
    root=Path(root).resolve(strict=True);output=Path(output).resolve(strict=True);artifacts={}
    check,summary=completed(output,aggregate,'regex-rust-compare')
    need(check['exit_code']==0 and check['timed_out']is False and not check.get('start_error')and check['timeout_seconds']==180,'original regex process incomplete');finite(check['elapsed_seconds'])
    command=check['command'];prefix=[sys.executable,'-I','-B',str(root/'tests/hia_native/compare_regex_original.py'),'--repo',str(root),'--native-results',str(output/'regex-native/result.json'),'--output',str(output/'regex-original'),'--cargo']
    need(len(command)==14 and command[:11]==prefix and command[12]=='--rustc','original regex invocation changed')
    stdout=artifact(output,artifacts,output/'regex-rust-compare.stdout');stderr=artifact(output,artifacts,output/'regex-rust-compare.stderr')
    need(json.loads(stdout)==summary and(sha(stdout),sha(stderr))==(check['stdout_sha256'],check['stderr_sha256']),'original completed streams differ')
    folder=output/'regex-original';project=folder/'project';report=obj(folder/'report.json');artifact(output,artifacts,folder/'report.json')
    need({k:v for k,v in report.items()if k not in ['records','domains','inputs']}==summary,'original report differs from actual stdout')
    expected={'schema':'hepta.runtime.regex-original-comparison.v1','status':'PASS','source_unchanged':True,'native_result_sha256':native['compatibility_result_sha256'],
              'registry_packages':5,'one_shared_cargo_build':True,'cases':128690,'capture_predicate_cases':1,
              'removed_environment_keys':list(REMOVED_ENV),'runtime_rust_fallback':False,'unconstrained_regex_resources_closed':False}
    need({k:report.get(k)for k in expected}==expected,'original regex completion/domain differs')
    prepared=obj(project/'reference-inputs.json');artifact(output,artifacts,project/'reference-inputs.json')
    files={name:sha(read(root/'tests/hia_native/regex_reference'/name))for name in REFERENCE_FILES}
    need(prepared['files']==report['original_source_sha256']==files and prepared['single_shared_build']is True,'original source custody differs')
    check_reference(project,prepared)
    for name in REFERENCE_FILES:need(artifact(output,artifacts,project/name)==read(root/'tests/hia_native/regex_reference'/name),'compiled original source bytes changed')
    need(sha(read(project/'reference-inputs.json'))==report['reference_inputs_sha256'],'reference preparation receipt differs')
    original={(p['name'],p['version']):p for p in tomllib.loads(read(root/'Cargo.lock').decode())['package']if'checksum'in p};packages=[]
    for row in tomllib.loads(read(project/'Cargo.lock').decode())['package']:
        if'checksum'in row:
            old=original[(row['name'],row['version'])];need((row['source'],row['checksum'])==(old['source'],old['checksum']),'original regex dependency changed');packages.append({k:row[k]for k in ['name','version','source','checksum']})
    need(len(packages)==5 and packages==prepared['packages']==report['locked_packages'],'original registry closure differs')
    binary=project/'target/release/hia-runtime-regex-reference';binary_raw=artifact(output,artifacts,binary)
    need(binary_raw.startswith(b'\x7fELF')and sha(binary_raw)==report['original_binary_sha256'],'actual original binary changed')
    records=report['records'];need([r['name']for r in records]==['rust-version','cargo-build',*DOMAIN_CASES,'capture-predicates'],'original build/replay domain incomplete')
    complete=obj(output/'regex-native/result.json');inputs={str(output/'regex-native/result.json'):native['compatibility_result_sha256'],str(root/'tests/hia_native/compare_regex_original.py'):sha(read(root/'tests/hia_native/compare_regex_original.py')),str(root/'scripts/hia_native_regex_reference.py'):sha(read(root/'scripts/hia_native_regex_reference.py'))}
    inputs.update({str(root/name):digest for name,digest in source_pins.items()})
    for name,row in native['corpora'].items():
        for filename in ['requests.hex','native-output.txt']:
            path=Path(row['directory'])/filename;inputs[str(path)]=sha(artifact(output,artifacts,path))
    predicate=Path(complete['capture_predicates']['path']);inputs[str(predicate)]=sha(artifact(output,artifacts,predicate))
    need(report['inputs']==inputs,'original complete input/source map differs')
    for r in records:
        name=r['name'];need(r['exit_code']==0 and r['timed_out']is False and r['start_error']is None and r['timeout_seconds']==120,'original child did not finish');finite(r['elapsed_seconds'],120)
        compressed=name not in ['rust-version','cargo-build'];out=artifact(output,artifacts,folder/(name+'.stdout'+('.gz'if compressed else'')));out=gzip.decompress(out)if compressed else out
        err=artifact(output,artifacts,folder/(name+'.stderr'))
        need((len(out),sha(out),len(err),sha(err))==(r['stdout_bytes'],r['stdout_sha256'],r['stderr_bytes'],r['stderr_sha256']),'actual original stream changed')
        need(r['cwd']==str(project),'original cwd differs')
        if name=='rust-version':need(r['command']==[command[13],'--version']and out.startswith(b'rustc 1.95.0 '),'original compiler version differs')
        elif name=='cargo-build':need(r['command']==[command[11],'build','--release','--locked','--manifest-path',str(project/'Cargo.toml')],'original Cargo command differs')
        else:
            need(r['command']==[str(binary)],'original executable invocation changed')
            if name=='capture-predicates':request=(b'HREGX001'+struct.pack('<3Q',4,0,0)).hex().encode()+b'\n';need(out==read(predicate),'full original capture predicates differ')
            else:
                row=native['corpora'][name];request=read(Path(row['directory'])/'requests.hex');expected_output=read(Path(row['directory'])/'native-output.txt')
                projected=[]
                for line in out.splitlines():
                    code,body=line.split(b':',1)
                    if code==b'00000001':body=b''
                    elif code==b'00000000'and name in ['nfa','match']:body=body[:16 if name=='nfa'else 32]
                    projected.append(code+b':'+body+b'\n')
                projected=b''.join(projected);stored=gzip.decompress(artifact(output,artifacts,folder/(name+'.projected.txt.gz')))
                need(out.count(b'\n')==DOMAIN_CASES[name]and projected==stored==expected_output,'complete actual original bytes differ')
                expected_domain={'cases':DOMAIN_CASES[name],'request_bytes':len(request),'request_sha256':sha(request),'native_output_bytes':len(expected_output),'native_output_sha256':sha(expected_output),'original_output_bytes':len(out),'original_output_sha256':sha(out),'projected_bytes':len(projected),'projected_sha256':sha(projected),'complete_stream_compared':True}
                need(report['domains'][name]==expected_domain,'original domain receipt differs')
            need((r['request_bytes'],r['request_sha256'])==(len(request),sha(request)),'original complete request differs')
    need(set(report['domains'])==set(DOMAIN_CASES),'original domain set changed')
    progress=obj(folder/'execution-progress.json');artifact(output,artifacts,folder/'execution-progress.json');need(progress=={'status':'PASS','records':records},'original execution never completed')
    return {'schema':'hepta.runtime.regex-original-evidence.v1','status':'PASS','artifact_sha256':artifacts,'domains':report['domains'],
            'corpus_sha256':{name:digest for name,digest in artifacts.items()if name.endswith('.gz')},'original_binary_sha256':report['original_binary_sha256'],
            'native_calls_added_by_evidence_admission':0,'unconstrained_regex_resources_closed':False,'whole_runtime_replaced':False}


def configuration_original_evidence(root,output,original,native,artifacts):
    root=Path(root);output=Path(output);folder=output/'config-original';domains=original['regex_domains']
    need(set(domains)=={'semantics','installed','mcp'},'configuration regex original domain missing')
    row=domains['semantics'];need(row==next(r for r in original['records']if r['name']=='regex'),'configuration regex replay receipt differs')
    expected=native['regex_dependency']['configuration_corpus'];need(row['native_corpus']==expected and row['cases']==3694,'configuration regex replay used another corpus')
    request=artifact(output,artifacts,output/'regex-native/config-corpus/requests.hex');wanted=artifact(output,artifacts,output/'regex-native/config-corpus/native-output.txt')
    need((row['command'],row['cwd'],row['request_bytes'],row['request_sha256'])==([str(folder/'project/target/release/hia-runtime-config-semantics')],str(root),len(request),sha(request)),'configuration regex original invocation changed')
    raw=gzip.decompress(artifact(output,artifacts,folder/'regex.stdout.gz'));stderr=artifact(output,artifacts,folder/'regex.stderr')
    need((len(raw),sha(raw),sha(stderr))==(row['stdout_bytes'],row['stdout_sha256'],row['stderr_sha256']),'configuration original streams changed')
    projected=[]
    for line in raw.splitlines():
        code,body=line.split(b':',1);projected.append(code+b':'+(b''if code==b'ffffffff'else body)+b'\n')
    need(len(projected)==3694 and b''.join(projected)==wanted,'complete configuration regex original output differs')
    need(row['comparison']=={'exact_results':3493,'typed_refusals':201,'explicit_regex_dependency':0},'configuration regex comparison domain changed')
    owner_patterns=[['x'],[r'\p{Greek}+',r')|foo(?:'],['a{327674}']]
    mcp_patterns=[['a'],[r'\p{Greek}+',r'(?i:[a-z]+)'],[r')|foo(?:'],['a{327674}']]
    for name,patterns,count in [('owner',owner_patterns,14),('mcp',mcp_patterns,6)]:
        report_path=folder/('regex-'+name)/'report.json';report=json.loads(artifact(output,artifacts,report_path));stream=gzip.decompress(artifact(output,artifacts,report_path.parent/'streams.json.gz'));records=json.loads(stream)
        need(report['status']=='PASS'and report['profile_count']==len(patterns)and report['response_pairs']==len(patterns)*count,'extra original cases incomplete')
        need((len(records),len(stream),sha(stream))==(report['stream_records'],report['stream_bytes'],report['stream_sha256']),'extra original complete stream changed')
        need(len(records)==2*len(patterns)*count and len(report['profiles'])==len(patterns),'extra original response count differs')
        for index,pattern in enumerate(patterns):
            profile=report['profiles'][index];need(profile['profile']==index and profile['patterns']==pattern,'extra original pattern domain changed')
            n=[r for r in records if r['profile']==index and r['side']=='native'];r=[r for r in records if r['profile']==index and r['side']=='original']
            need(len(n)==len(r)==count,'extra original side omitted')
            for at,(left,right)in enumerate(zip(n,r,strict=True)):
                need(set(left)==set(right)=={'profile','side','request_hex','response_hex'}and left['request_hex']==right['request_hex'],'extra original request differs')
                a=bytes.fromhex(left['response_hex']);b=bytes.fromhex(right['response_hex']);bytes.fromhex(left['request_hex'])
                if name=='owner':
                    need(len(a)>=32 and len(b)>=32 and a[:8]==b[:8]==b'HRCFGM01','typed owner response malformed')
                    sa,da,na=struct.unpack_from('<3Q',a,8);sb,db,nb=struct.unpack_from('<3Q',b,8)
                    need(sa==sb and na==nb==len(a)-32==len(b)-32 and a[32:]==b[32:],'full owner status/result bytes differ')
                    need((da,db)==((6,0)if at==4 else(8,0)if at==9 else(0,0)),'owner diagnostic exclusion widened')
                    need(profile['native']['responses'][at]==profile['original']['responses'][at]=={'status':sa,'payload_hex':a[32:].hex()},'owner projection differs from complete response')
                else:need(a==b,'full MCP response differs')
            if name=='owner':
                need(profile['native']==profile['original']and profile['native']['events']==[True]*5,'owner immutable state/FD events differ')
            else:need(profile['source_change_did_not_reload']is True and profile['responses']==6 and profile['wire_sha256']==sha(b'\n'.join(bytes.fromhex(x['response_hex'])for x in n)),'MCP immutable installation evidence differs')
        if name=='owner':
            need(report['native_internal_diagnostic_word_excluded']is True and report['same_exact_fixture_paths']is True and report['complete_result_payloads_compared']is True,'owner comparison scope changed')
            expected_domain={'profile_count':3,'response_pairs':42,'report_sha256':sha(read(report_path)),'stream_sha256':sha(stream)}
        else:
            need(report['refusal_pairs']==4 and report['same_exact_fixture_paths']is True and report['complete_mcp_wire_compared']is True,'MCP comparison scope changed')
            for index,(entry,pattern)in enumerate(zip(report['refusals'],['(',r'\w{500}','a{327675}',r'(?-u:\xFF)'],strict=True)):
                need(entry['profile']==index and entry['pattern']==pattern and len(entry['processes'])==2,'startup failure domain changed')
                a,b=entry['processes'];need([a['side'],b['side']]==['native','original'],'startup side missing')
                for process in [a,b]:
                    need(process['exit_code']==78 and process['stdout_hex']==''and process['state_directory_created']is False and process['cwd']==str(root)and process['timeout_seconds']==30,'actual startup failure differs');finite(process['elapsed_seconds'],30)
                    need(len(process['command'])==3 and process['command'][1]=='--runtime-config','startup command changed')
                need(a['command'][1:]==b['command'][1:]and a['stderr_hex']==b['stderr_hex'],'startup error/order differs')
            expected_domain={'profile_count':4,'response_pairs':24,'refusal_pairs':4,'report_sha256':sha(read(report_path)),'stream_sha256':sha(stream)}
        need(domains['installed'if name=='owner'else'mcp']==expected_domain,'extra original report binding changed')
    return domains
