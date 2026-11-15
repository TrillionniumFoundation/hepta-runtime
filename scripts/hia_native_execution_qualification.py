"""Admit complete shadow-owner source, native builds, corpora and real receipts."""
from pathlib import Path
import copy,gzip,hashlib,importlib.util,json,struct,sys
from hia_native_build import HEPTA_COMMIT,check_dependency,json_bytes
from hia_native_entropy_qualification import read,native_receipt,inspect_elf
from hia_native_view_cache_qualification import _compiled
ROOT=Path(__file__).resolve().parents[1]
FOLDER='execution-shadow'
SOURCES={'execution_shadow':'65aa4097e00ed497ab38efe4ddf515de99eaf45abeb7ad2829af4381e7704713',
 'execution_json':'d1e1610120fcadd72960f04b742ad6bfcfc3bc430a2b828463f3ab2af1268f14',
 'execution_controller':'5ab993340f2f9bf8b1f6f295098570291307d5bd564332174c2d136454167a10'}
IMAGES={'execution_shadow':'3bbc3adac5227351c0baedbf64eeadbf8c64671341bb36f12674ef90ccaf2f08',
 'execution_json':'d6fd8b1bd60eec2951bd9825edb22b0a5832da2cd99da5117c3169c3c60c0e9a',
 'execution_controller':'1713343da50f0651d05fa561fd958d3ac14a5cecaa5f97bec13a7f517707419a'}
MEMBERS={'core':('execution_shadow','standard','filter'),
 'json':('execution_json','standard','filter'),'controller':('execution_controller','history.v1',None),
 'json_composed':('execution_json','history.v1',None),'core_composed':('execution_shadow','history.v1',None)}
TESTS=('test_execution_shadow.py','test_execution_json.py','test_execution_json_errors.py','test_execution_controller.py')
OWN=tuple('native/'+name+'.hepta' for name in SOURCES)+tuple('native/'+name+'_composition.json' for name in SOURCES)+(
 'native/execution_shadow_abi.md','native/execution_shadow_observations.json',
 'scripts/hia_native_execution_build.py','scripts/hia_native_execution_qualification.py',
 'tests/hia_native/execution_shadow_cases.py','tests/hia_native/execution_json_cases.py',
 'tests/hia_native/execution_original_source.py','tests/hia_native/execution_core_adapter.rs.txt',
 'tests/hia_native/execution_json_adapter.rs.txt','tests/hia_native/execution_original/Cargo.lock',
 'tests/hia_native/execution_json_original_rows.jsonl.gz','tests/hia_native/compare_execution_original.py',
 'tests/hia_native/test_execution_evidence.py',*('tests/hia_native/'+name for name in TESTS))
REFERENCES=('Cargo.lock','src/mcp/runtime/execution.rs','src/mcp/runtime/execution_tests.rs',
 'native/text_budget.hepta','native/binary_codec.hepta','native/serde_json.hepta','native/filter_packer.hepta',
 'tests/hia_native/rust_debug_properties.json','scripts/hia_native_build.py','scripts/hia_native_loader.py',
 'scripts/hia_native_entropy_qualification.py','scripts/hia_native_view_cache_qualification.py')
STREAMS={
 'core/requests.hex.gz':(100138283,'c96bf3654cc4dbf8e7f566bb908b2235149e79834887f81326f1f55cbef59053',73349),
 'core/native-output.hex.gz':(39009956,'361e01960d6ab6b331a6aa9d3bc8c8270a4857a9448187e0825bd20af7e423f6',73349),
 'core/cases.jsonl.gz':(71583395,'c6305d9bec82ef1c919d1ef6019078cd61221d7e6da93417a5c50cb8955b5f26',73349),
 'json/requests.hex.gz':(46711964,'29d49c12d75e1eb61a03ee32f1d6aadee96bbd6252d4fa8eee783b9e3d5d23ad',14960),
 'json/native-output.hex.gz':(41226842,'54ff08730bdb5b472c9d527e0e83b5d560f326ae033af7528dd173b4282f3bdd',14960),
 'json/row-identities.jsonl.gz':(3500897,'41b62d6e840036d00871dd271b86ac8ef840895db4359dd02f874c393b60a947',14960),
 'errors/observations.jsonl.gz':(1512655,'e181c5361a36ac33890e95b9d069f481e56588b27280799abe3555ad27691957',7480),
 'controller/canonical-parameters.jsonl.gz':(43004127,'14402c15e9b01a7679ee700ff9b2f5cde0faca688b82c45225ecd36a0e3719d4',417),
 'controller/observations.jsonl.gz':(263688,'97ea47541624890a5bd5f9551be3a8642acf344cf34bfe3ab4dae37a746f9824',963),
 'controller/outputs.hex.gz':(311866,'e673b93095c11085502d4c6b452df4e4183b5c718d1cc14f604b879b4d32a260',963),
 'controller/requests.hex.gz':(51699818,'d6c65747ea6dd32940a6ea53d94d40c559bbd28b6e77ff1e4a378e9ffc89c738',963)}
sha=lambda raw:hashlib.sha256(raw).hexdigest()

def require(ok,message):
    if not ok:raise ValueError('execution evidence: '+message)
def exact(actual,wanted,message):require(json_bytes(actual)==json_bytes(wanted),message)
def object_at(path):
    def unique(rows):
        out={}
        for key,value in rows:
            require(key not in out,'duplicate JSON key');out[key]=value
        return out
    value=json.loads(read(path),object_pairs_hook=unique);require(type(value) is dict,'expected JSON object');return value
def relative(root,name):
    p=Path(name);require(not p.is_absolute() and p.parts and '..' not in p.parts,'artifact path escaped output')
    return root/p
def source_pins(root):
    result={name:sha(read(root/name)) for name in sorted(set(OWN+REFERENCES))}
    for name,value in SOURCES.items():require(result['native/'+name+'.hepta']==value,'native source changed: '+name)
    require(result['tests/hia_native/execution_json_original_rows.jsonl.gz']=='fffd8475c0ed9857ed02bbea11407ee6a1cfb7fd0521e7123af5bb12e1e9c2aa','original JSON expectation changed')
    return result
def stream_identity(path):
    read(path);size=lines=0;value=hashlib.sha256()
    with gzip.open(path,'rb') as stream:
        while raw:=stream.read(1<<20):size+=len(raw);lines+=raw.count(b'\n');value.update(raw)
    return size,value.hexdigest(),lines
def import_driver(root):
    path=root/'tests/hia_native/execution_original_source.py';read(path)
    spec=importlib.util.spec_from_file_location('execution_original_source',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def source_composition(root,hepta):
    dependency=check_dependency(hepta);sys.path.insert(0,str(hepta))
    from hepta.hia_agent_assembly import assemble_program
    for name in ('execution_shadow','execution_controller'):
        proof=object_at(root/'native'/(name+'_composition.json'))
        require(proof['source_sha256']==SOURCES[name],'composition source identity changed')
        actual={f['name']:f for f in assemble_program(read(root/'native'/(name+'.hepta'))).as_dict()['functions']}
        for row in proof['imports']:
            raw=read(root/row['path']);require(sha(raw)==row['sha256'],'import source changed')
            original={f['name']:f for f in assemble_program(raw).as_dict()['functions']}
            mapping=row['function_relocation'];reverse={new:old for old,new in mapping.items()}
            for old,new in mapping.items():
                require(sha(json.dumps(original[old],sort_keys=True,separators=(',',':')).encode())==row['functions'][old],'imported body hash changed')
                f=copy.deepcopy(actual[new]);f['name']=old
                for block in f['blocks']:
                    for op in block['ops']:
                        if op['op']=='call':op['attrs']['function']=reverse[op['attrs']['function']]
                exact(f,original[old],'imported body differs')
    require(object_at(root/'native/execution_json_composition.json')['source_sha256']==SOURCES['execution_json'],'typed JSON source changed')
    original=import_driver(root).original_files(root)
    return {'compiler_commit':dependency['commit'],'original_source_recipe':json.loads(original['source-recipe.json']),
            'whole_runtime_replaced':False,'production_activated':False}

def build_evidence(bundle_path,*,source_root=ROOT,hepta):
    root=source_root.resolve(strict=True);bundle_path=bundle_path.resolve(strict=True)
    build=bundle_path.parents[2];output=build.parent;bundle=object_at(bundle_path);artifacts={}
    def artifact(path):
        raw=read(path);artifacts[path.relative_to(output).as_posix()]=sha(raw);return raw
    raw=artifact(bundle_path);require(raw==json_bytes(bundle),'bundle encoding changed')
    pins=source_pins(root);exact(bundle['source_pins'],pins,'build source closure changed')
    require(bundle['schema']=='hepta.runtime.execution-shadow-bundle.v1','bundle schema changed')
    for key in ('production_activated','whole_runtime_replaced','old_stack_removal_qualified'):require(bundle.get(key) is False,'bundle overstates completion')
    compiler=artifact(build/'bootstrap/B3.image.bin');bootstrap=object_at(build/'bootstrap/bootstrap.json')
    artifact(build/'bootstrap/bootstrap.json');require(bundle['compiler_commit']==HEPTA_COMMIT and bundle['compiler_sha256']==sha(compiler),'compiler identity differs')
    composition=source_composition(root,hepta);exact(bootstrap['dependency'],check_dependency(hepta),'compiler closure differs')
    require(set(bundle['members'])==set(MEMBERS),'member inventory changed');members={}
    for key,(name,profile,transport) in MEMBERS.items():
        row=bundle['members'][key];path=relative(build,row['manifest']);meta=object_at(path);artifact(path)
        source=artifact(path.parent/meta['source']);image=artifact(path.parent/meta['image'])
        require(source==read(root/'native'/(name+'.hepta')),'compiled source differs')
        exact(row,{'manifest':path.relative_to(build).as_posix(),'manifest_sha256':sha(read(path)),
                   'source':'native/'+name+'.hepta','source_sha256':SOURCES[name],'image_sha256':IMAGES[name],'buffer_profile':profile},'member identity changed')
        caps=[8<<20,8<<20,32<<20] if profile=='standard' else [128<<20,128<<20,256<<20]
        expected={'schema':'hepta.runtime.native-module.v1','abi':'hepta.runtime.borrowed-bytes.linux-x86_64.v1',
          'target':'linux-x86_64','compiler_commit':HEPTA_COMMIT,'compiler_sha256':sha(compiler),
          'source_sha256':SOURCES[name],'image_sha256':IMAGES[name],
          'input_capacity':caps[0],'output_capacity':caps[1],'workspace_capacity':caps[2]}
        exact({k:meta.get(k) for k in expected},expected,'native manifest profile changed')
        require(meta.get('buffer_profile','standard')==profile and sha(image)==IMAGES[name],'native profile/image differs')
        _compiled(output,path.parent,source,image,compiler,artifacts)
        for extra in ('module.request.json','module.stdout.log','module.stderr.log'):artifact(path.parent/extra)
        if transport is None:require(meta['standalone'] is None,'unexpected composed executable')
        else:
            standalone=meta['standalone'];elf=artifact(path.parent/standalone['path'])
            require(standalone['transport']=='filter' and standalone['runtime_python_required'] is False and standalone['runtime_libc_required'] is False,'standalone dependencies changed')
            exact(standalone['inspection'],inspect_elf(elf),'ELF inspection differs')
            require(sha(elf)==standalone['sha256'] and elf[-len(image):]==image,'embedded native image changed')
            packer_source=read(root/'native/filter_packer.hepta');cache=build/'packers'/sha(packer_source)
            packer=artifact(cache/'packer.image.bin');packer_meta=object_at(cache/'manifest.json');artifact(cache/'manifest.json')
            require(artifact(cache/'source.hepta')==packer_source and packer_meta['source_sha256']==sha(packer_source),'packer source changed')
            native_receipt(packer_meta['compile_receipt'],image=compiler,source=packer_source,output=artifact(cache/'packer.output.bin'),produced=packer)
            frame=artifact(path.parent/'pack.input.bin');require(frame==b'HIAFLT01'+struct.pack('<Q',len(image))+image,'packer frame differs')
            pack_result=artifact(path.parent/'pack.output.bin');receipt=object_at(path.parent/'pack.receipt.json')
            exact(standalone['pack_receipt'],receipt,'packer receipt differs')
            native_receipt(receipt,image=packer,source=frame,output=pack_result,produced=elf)
            for extra in ('pack.receipt.json','pack.request.json','pack.stdout.log','pack.stderr.log'):artifact(path.parent/extra)
            for extra in ('packer.receipt.json','packer.request.json','packer.stdout.log','packer.stderr.log','packer.input.bin'):artifact(cache/extra)
            require(standalone['packer_source_sha256']==sha(packer_source),'transport source changed')
        members[key]={'manifest':path.relative_to(output).as_posix(),'source_sha256':sha(source),'image_sha256':sha(image),'manifest_sha256':sha(read(path))}
    return {'schema':'hepta.runtime.execution-build-evidence.v1','bundle_sha256':sha(raw),'source_pins':pins,
            'members':members,'composition':composition,'artifact_sha256':artifacts,'production_activated':False}

def checked_native(bundle_path,folder,*,source_root=ROOT,hepta,stdout):
    root=source_root.resolve(strict=True);folder=folder.resolve(strict=True)
    require(type(stdout) is dict and set(stdout)==set(TESTS),'actual suite stdout set is incomplete')
    build=build_evidence(bundle_path,source_root=root,hepta=hepta);artifacts=dict(build['artifact_sha256'])
    output=Path(bundle_path).resolve().parents[3]
    def artifact(path):
        raw=read(path);artifacts[path.relative_to(output).as_posix()]=sha(raw);return raw
    reports={}
    for name,sub,report_name in zip(TESTS,('core','json','errors','controller'),('native-corpus.json','native-corpus.json','result.json','result.json')):
        report=object_at(folder/sub/report_name);artifact(folder/sub/report_name)
        lines=read(Path(stdout[name])).decode().splitlines();require(len(lines)==1,'unexpected actual stdout shape')
        exact(json.loads(lines[0]),report,'actual suite stdout differs from corpus')
        artifact(Path(stdout[name]));reports[sub]=report
        require(type(report['elapsed_seconds']) in (int,float) and 0<=report['elapsed_seconds']<180,'suite deadline exceeded')
        require(report['production_activated'] is False,'native suite overstates activation')
    core=reports['core'];js=reports['json'];errors=reports['errors'];controller=reports['controller']
    expected_core={'status':'PASS','cases':73349,'successful_records':9323,'maximum_canonical_bytes':4791,
                   'framing_refusals':35,'capacity_refusals':9,'exact_capacity_success':1,'actual_elf_requests':8,
                   'complete_output_sha256':STREAMS['core/native-output.hex.gz'][1]}
    exact({k:core.get(k) for k in expected_core},expected_core,'core coverage changed')
    expected_json={'status':'NATIVE_COMPLETE_RUST_REPLAY_REQUIRED','cases':14960,'accepted':7234,
      'actual_typed_native_calls':12851,'actual_value_native_calls':7480,'actual_core_joins':1950,
      'framing_refusals':40,'capacity_refusals':6,'actual_elf_requests':6,
      'input_raw_sha256':STREAMS['json/requests.hex.gz'][1],'input_raw_bytes':46711964,
      'output_raw_sha256':STREAMS['json/native-output.hex.gz'][1],'output_raw_bytes':41226842}
    exact({k:js.get(k) for k in expected_json},expected_json,'JSON coverage changed')
    expected_errors={'status':'PASS','cases':7480,'counts':{'typed_error':1707,'typed_success':3664,'value_invalid':2109},
      'mismatches':0,'unique_original_errors':299,'original_output_gzip_sha256':source_pins(root)['tests/hia_native/execution_json_original_rows.jsonl.gz']}
    exact({k:errors.get(k) for k in expected_errors},expected_errors,'typed errors are incomplete')
    expected_controller={'status':'PASS','controller_calls':963,'raw_syntax_refusals':738,'mismatches':0,
      'receipt_refusals':28,'payload_refusals':15,'framing_refusals':27,'capacity_refusals':4,'exact_capacity':1,
      'persistent_sequences':[3,6,9],'host_owner':'explicit dependency fixture only','actual_installed_host_comparison':False}
    exact({k:controller.get(k) for k in expected_controller},expected_controller,'controller coverage changed')
    for report,key in [(core,'core'),(js,'json'),(errors,'json')]:
        require(report['source_sha256']==build['members'][key]['source_sha256'] and report['image_sha256']==build['members'][key]['image_sha256'],'test source/image differs')
    require(core['manifest_sha256']==build['members']['core']['manifest_sha256'],'tested core manifest differs')
    require(core['executable_sha256']==object_at(output/build['members']['core']['manifest'])['standalone']['sha256'],'tested core ELF differs')
    exact(controller['sources'],{'controller':SOURCES['execution_controller'],'typed':SOURCES['execution_json'],'core':SOURCES['execution_shadow'],'value':source_pins(root)['native/serde_json.hepta']},'controller child sources changed')
    exact({k:controller['images'][k] for k in ('controller','typed','core')},
          {'controller':IMAGES['execution_controller'],'typed':IMAGES['execution_json'],'core':IMAGES['execution_shadow']},'controller child images changed')
    require(controller['images']['value']=='ab5681bf8b5e8f06ee789e9b21f25871585cd1fb183a768f300d6f5400106fc1','Value child image changed')
    for name,wanted in STREAMS.items():
        path=folder/name;actual=stream_identity(path);require(actual==wanted,'complete corpus differs: '+name);artifact(path)
    for sub,report in [('core',core),('json',js)]:
        require(set(report['files'])=={Path(name).name for name in STREAMS if name.startswith(sub+'/')},'corpus file inventory differs')
        for name,identity in report['files'].items():
            raw=read(folder/sub/name);exact(identity,{'bytes':len(raw),'sha256':sha(raw)},'retained compressed bytes differ')
    for sub in ('errors','controller'):require(artifact(folder/sub/'mismatches.json')==b'[]\n','mismatch inventory is not empty')
    trace_raw=artifact(folder/'controller/call-trace.json');trace=json.loads(trace_raw)
    require(type(trace) is list and len(trace)==2340 and sha(trace_raw)=='4a07f97fc4dc5e125767f9c8c33ef3749801ce5e46367e4b55d9304a07cb4f21','controller trace differs')
    require(len(controller['receipt_controls'])==28 and len(controller['payload_controls'])==15,'refusal details incomplete')
    return {'schema':'hepta.runtime.execution-native-evidence.v1','status':'PASS','build':build,
      'coverage':{'core':expected_core,'json':expected_json,'errors':expected_errors,'controller':expected_controller},
      'reports':reports,'source_pins':source_pins(root),'artifact_sha256':artifacts,
      'production_activated':False,'whole_runtime_replaced':False,'old_stack_removal_qualified':False}

def controls_evidence(folder,native,*,source_root=ROOT,stdout):
    report=object_at(folder/'result.json');raw=read(Path(stdout))
    require(len(raw.decode().splitlines())==1,'evidence-control stdout is incomplete')
    exact(json.loads(raw),report,'evidence-control stdout differs')
    expected={'schema':'hepta.runtime.execution-evidence-controls.v1','status':'PASS','accepted':1,'refusals':20,
              'source_pins':source_pins(source_root),'native_calls_added':0,'rust_calls_added':0,
              'baseline_sha256':sha(json_bytes(native)),'production_activated':False,'whole_runtime_replaced':False}
    exact({key:report.get(key) for key in expected},expected,'evidence controls did not complete')
    require(type(report.get('controls')) is list and len(report['controls'])==20 and all(row.get('refused') is True for row in report['controls']),'missing physical refusal controls')
    require(0<=report['elapsed_seconds']<180,'evidence controls exceeded deadline')
    return {'report':report,'report_sha256':sha(read(folder/'result.json')),'stdout_sha256':sha(raw)}

def original_evidence(root,corpus,folder,*,stdout):
    report=object_at(folder/'comparison.json');raw=read(Path(stdout))
    require(len(raw.decode().splitlines())==1,'original stdout is incomplete');exact(json.loads(raw),report,'original stdout differs')
    expected={'schema':'hepta.runtime.execution-original-comparison.v1','status':'PASS','core_cases':73349,
      'json_cases':14960,'json_accepted':7234,'original_test_cases':5,'source_pins':source_pins(root),
      'production_activated':False,'whole_runtime_replaced':False,'old_stack_removal_qualified':False}
    exact({key:report.get(key) for key in expected},expected,'original replay coverage changed')
    generated=import_driver(root).original_files(root)
    exact(report['source_recipe'],json.loads(generated['source-recipe.json']),'original source recipe changed')
    for name,value in generated.items():require(read(folder/'project'/name)==value,'fresh original project differs')
    for label,key in [('core','original_core_output'),('json','normalized_json_output')]:
        wanted=STREAMS[label+'/native-output.hex.gz'];exact(report[key],{'bytes':wanted[0],'sha256':wanted[1]},'original complete output differs')
    exact(report['original_json_output'],{'bytes':58230252,'sha256':'534afa03ae3a6232a19e8f66f1cbd70d372ac421d79430421b1485e64e897321'},'original complete typed error stream differs')
    required=['rust-version','locked-build','original-tests','core-replay','json-replay']
    checks=report['checks'];require(type(checks) is list and [row['name'] for row in checks]==required,'actual original subprocess inventory differs')
    require(0<=report['elapsed_seconds']<180,'original deadline exceeded')
    for check in checks:
        require(type(check['exit_code']) is int and check['exit_code']==0 and 0<=check['elapsed_seconds']<180,'actual original subprocess failed')
        for stream in ('stdout','stderr'):
            data=read(folder/(check['name']+'.'+stream));exact(check[stream],{'bytes':len(data),'sha256':sha(data)},'original subprocess log changed')
    require(read(folder/'rust-version.stdout').startswith(b'rustc 1.95.0 '),'original compiler version changed')
    require(b'test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out' in read(folder/'original-tests.stdout'),'original tests were incomplete')
    core_output=read(folder/'core-replay.stdout');json_output=read(folder/'json-replay.stdout');normalized=read(folder/'json-normalized.hex')
    exact({'bytes':len(core_output),'sha256':sha(core_output)},report['original_core_output'],'actual original core bytes differ')
    exact({'bytes':len(json_output),'sha256':sha(json_output)},report['original_json_output'],'actual original JSON bytes differ')
    exact({'bytes':len(normalized),'sha256':sha(normalized)},report['normalized_json_output'],'actual normalized JSON bytes differ')
    require(set(report['binaries'])=={'core','json'},'compiled original binary inventory differs')
    for kind,name in [('core','execution-core-original'),('json','execution-json-original')]:
        binary=read(folder/'target/release'/name);exact(report['binaries'][kind],{'bytes':len(binary),'sha256':sha(binary)},'actual compiled original binary changed')
    require(set(report['native_inputs'])=={'core/requests.hex.gz','core/native-output.hex.gz','json/requests.hex.gz','json/native-output.hex.gz'},'original native input inventory differs')
    for name,identity in report['native_inputs'].items():
        data=read(corpus/name);exact(identity,{'bytes':len(data),'sha256':sha(data)},'original consumed a different native corpus')
    wanted_artifacts={'project/'+name for name in generated}|{name+'.'+stream for name in required for stream in ('stdout','stderr')}|{'core.input.hex','json.input.hex','json-normalized.hex','core-original.stdout.gz','json-original.stdout.gz'}
    require(set(report['artifacts'])==wanted_artifacts,'original retained artifact inventory differs')
    for name,identity in report['artifacts'].items():
        data=read(relative(folder,name));exact(identity,{'bytes':len(data),'sha256':sha(data)},'retained original artifact changed')
    return {'report_sha256':sha(read(folder/'comparison.json')),'stdout_sha256':sha(raw),'report':report}
