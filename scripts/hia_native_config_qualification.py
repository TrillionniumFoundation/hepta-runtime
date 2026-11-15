"""Bind actual configuration builds, six native suites and four original domains.

No service policy is executed here. Only create=True may publish the compatibility
result, and only after all six real aggregate process records have been verified.
"""
from pathlib import Path
import ast,gzip,hashlib,importlib.util,json,math,os,re,signal,struct,subprocess,sys,time,tomllib
from hia_native_build import HEPTA_COMMIT,check_dependency,json_bytes
from hia_native_entropy_qualification import read,native_receipt,inspect_elf
from hia_native_view_cache_qualification import _compiled

OWN = ['native/config_execution_schema.json',
 'native/config_fs.hepta',
 'native/config_fs_packer.hepta',
 'native/config_identity.hepta',
 'native/config_identity_composition.json',
 'native/config_json.hepta',
 'native/config_mcp.hepta',
 'native/config_mcp_composition.json',
 'native/config_mcp_packer.hepta',
 'native/config_publication_adapter.json',
 'native/config_owner.hepta',
 'native/config_owner_abi.md',
 'native/config_owner_composition.json',
 'native/config_owner_fixture_packer.hepta',
 'native/config_owner_packer.hepta',
 'native/config_scope.md',
 'native/config_validation.hepta',
 'native/config_validation_composition.json',
 'scripts/build_config_fs_probe.py',
 'scripts/build_config_mcp_service.py',
 'scripts/build_config_owner_probe.py',
 'scripts/build_hia_config_service.py',
 'scripts/config_fs_adapter.S',
 'scripts/config_mcp_adapter.S',
 'scripts/config_owner_adapter.S',
 'scripts/config_schema.py',
 'scripts/hia_native_config_reference.py',
 'tests/hia_native/compare_config_original.py',
 'tests/hia_native/config_fs_cases.py',
 'tests/hia_native/config_mcp_cases.py',
 'tests/hia_native/config_mcp_sessions.py',
 'tests/hia_native/config_owner_cases.py',
 'tests/hia_native/config_reference.tar.gz',
 'tests/hia_native/config_reference_sources.json',
 'tests/hia_native/config_runtime_original_output.txt.gz',
 'tests/hia_native/config_semantics_cases.py',
 'tests/hia_native/config_typed_cases.py',
 'tests/hia_native/run_config_native.py',
 'tests/hia_native/test_config_fs.py',
 'tests/hia_native/test_config_json.py',
 'tests/hia_native/test_config_mcp.py',
 'tests/hia_native/test_config_mcp_receipts.py',
 'tests/hia_native/test_config_owner.py',
 'tests/hia_native/test_config_semantics.py',
 'scripts/hia_native_config_qualification.py']

DEPENDENCIES = ['Cargo.lock',
 'Cargo.toml',
 'native/execution_controller.hepta',
 'native/execution_json.hepta',
 'native/execution_shadow.hepta',
 'native/filter_packer.hepta',
 'native/serde_filter_packer.hepta',
 'native/serde_json.hepta',
 'native/result_publication.hepta',
 'native/result_publication_abi.md',
 'native/result_publication_composition.json',
 'scripts/generate_hia_transport.py',
 'scripts/hia_native_build.py',
 'scripts/hia_native_loader.py',
 'src/main.rs',
 'src/mcp/hia_contract.rs',
 'src/mcp/hia_provider.rs',
 'src/mcp/hia_tool_catalog.json',
 'src/mcp/rea_engine_profile.rs',
 'src/mcp/rea_provider.rs',
 'src/mcp/runtime/config.rs',
 'src/mcp/runtime/config_tests.rs',
 'src/mcp/runtime/effective_config.rs',
 'src/mcp/runtime/effective_config_tests.rs',
 'src/mcp/runtime/execution.rs',
 'src/mcp/runtime/execution_tests.rs',
 'src/mcp/runtime/inspect.rs',
 'src/mcp/runtime/inspect_tests.rs',
 'src/mcp/server.rs',
 'src/mcp/weight_config.rs',
 'src/utils/json_size.rs']

MODULES = {'execution': {'buffer_profile': 'history.v1',
               'image_sha256': '1713343da50f0651d05fa561fd958d3ac14a5cecaa5f97bec13a7f517707419a',
               'input_capacity': 134217728,
               'output_capacity': 134217728,
               'source': 'native/execution_controller.hepta',
               'source_sha256': '5ab993340f2f9bf8b1f6f295098570291307d5bd564332174c2d136454167a10',
               'workspace_capacity': 268435456},
 'execution_core': {'buffer_profile': 'history.v1',
                    'image_sha256': '3bbc3adac5227351c0baedbf64eeadbf8c64671341bb36f12674ef90ccaf2f08',
                    'input_capacity': 134217728,
                    'output_capacity': 134217728,
                    'source': 'native/execution_shadow.hepta',
                    'source_sha256': '65aa4097e00ed497ab38efe4ddf515de99eaf45abeb7ad2829af4381e7704713',
                    'workspace_capacity': 268435456},
 'execution_json': {'buffer_profile': 'history.v1',
                    'image_sha256': 'd6fd8b1bd60eec2951bd9825edb22b0a5832da2cd99da5117c3169c3c60c0e9a',
                    'input_capacity': 134217728,
                    'output_capacity': 134217728,
                    'source': 'native/execution_json.hepta',
                    'source_sha256': 'd1e1610120fcadd72960f04b742ad6bfcfc3bc430a2b828463f3ab2af1268f14',
                    'workspace_capacity': 268435456},
 'fs': {'buffer_profile': 'standard',
        'image_sha256': '8cebd33c8e6d3f88de31424cb82ddf1e36ccd00d0e38a8d7318590997c1c915e',
        'input_capacity': 8388608,
        'output_capacity': 8388608,
        'source': 'native/config_fs.hepta',
        'source_sha256': 'dd55aa68e4479514e052f1ed8c8ec65f024a9f2fef3c5aa86d4cfeb28992ff9d',
        'workspace_capacity': 33554432},
 'identity': {'buffer_profile': 'serde-json.v1',
              'image_sha256': '4d07bbc0b299237b9c935d3a16aa21d641b75d881a2b7de3adfd443cce30db8d',
              'input_capacity': 16777216,
              'output_capacity': 67108864,
              'source': 'native/config_identity.hepta',
              'source_sha256': '59c849f25aa88c5dc9a86b8dc1990889a17abfbedc5d58557e193689894710ad',
              'workspace_capacity': 268435456},
 'identity_composed': {'buffer_profile': 'history.v1',
                       'image_sha256': '4d07bbc0b299237b9c935d3a16aa21d641b75d881a2b7de3adfd443cce30db8d',
                       'input_capacity': 134217728,
                       'output_capacity': 134217728,
                       'source': 'native/config_identity.hepta',
                       'source_sha256': '59c849f25aa88c5dc9a86b8dc1990889a17abfbedc5d58557e193689894710ad',
                       'workspace_capacity': 268435456},
 'json': {'buffer_profile': 'serde-json.v1',
          'image_sha256': 'f241ddb43f90c2677dd018dfaba0ab68dc760951174b8722dda6dced69b526f9',
          'input_capacity': 16777216,
          'output_capacity': 67108864,
          'source': 'native/config_json.hepta',
          'source_sha256': '7cb065173fdb3bf266e1f234a18f8f309865d57db4c07d26e750047e4ec10ccb',
          'workspace_capacity': 268435456},
 'mcp': {'buffer_profile': 'history.v1',
         'image_sha256': 'c7d025f49fb5b5d82e09d8ef11a71126f3f96cb65113e848b83180e495b00d02',
         'input_capacity': 134217728,
         'output_capacity': 134217728,
         'source': 'native/config_mcp.hepta',
         'source_sha256': 'e57a4496fe9bf24372b4ebf8ed0deaeb62d5a3cc1de7e3750df40957b7d4796f',
         'workspace_capacity': 268435456},
 'owner': {'buffer_profile': 'history.v1',
           'image_sha256': '933715c9f0f4c03b70b7379c738a435115d1974eb29a3434e6f25c1c45667502',
           'input_capacity': 134217728,
           'output_capacity': 134217728,
           'source': 'native/config_owner.hepta',
           'source_sha256': '5f9e4cbaf8b8652a3a9eb05bdeccb90149258c9851a5fd8095465ea6cd12e5eb',
           'workspace_capacity': 268435456},
 'publication': {'buffer_profile': 'standard',
                 'image_sha256': 'ec0f5e9586d8668817d13ba4f9385e1f8d04cc7dc14f6cb1ead4e023b8b20af9',
                 'input_capacity': 8388608,
                 'output_capacity': 8388608,
                 'source': 'native/result_publication.hepta',
                 'source_sha256': '279d3c385ea3b7a67d5de14d24ee1a16154a64f87a23cee467c30576f7c69842',
                 'workspace_capacity': 33554432},
 'validation': {'buffer_profile': 'serde-json.v1',
                'image_sha256': 'bb4a71d5a4fed80b99db5c7a0a3004ae21c979ca154089946d9d3373b56178c3',
                'input_capacity': 16777216,
                'output_capacity': 67108864,
                'source': 'native/config_validation.hepta',
                'source_sha256': 'd742645d8a112fe890c5f9f95aaa019bf685b8000e7e21d31a3289bf794e0f11',
                'workspace_capacity': 268435456},
 'validation_composed': {'buffer_profile': 'history.v1',
                         'image_sha256': 'bb4a71d5a4fed80b99db5c7a0a3004ae21c979ca154089946d9d3373b56178c3',
                         'input_capacity': 134217728,
                         'output_capacity': 134217728,
                         'source': 'native/config_validation.hepta',
                         'source_sha256': 'd742645d8a112fe890c5f9f95aaa019bf685b8000e7e21d31a3289bf794e0f11',
                         'workspace_capacity': 268435456},
 'value': {'buffer_profile': 'serde-json.v1',
           'image_sha256': '1a189af4822ae3f167138f3d90277ca028f891c3b34ff2e7ce0ac50ecc2ee7f2',
           'input_capacity': 16777216,
           'output_capacity': 67108864,
           'source': 'native/serde_json.hepta',
           'source_sha256': '6c3afb7d322b3c42d89727651aaae7cc1907a7766773e0bff4fdac9b11567a96',
           'workspace_capacity': 268435456}}

EXECUTABLES = {'fixture': {'adapter_source': 'scripts/config_owner_adapter.S',
             'adapter_source_sha256': 'df7aaff783afc9474dc054025f1747bce8a9c050a495dfbbe92a5c210d360969',
             'elf_bytes': 1382823,
             'elf_sha256': '0a7c171f6add30df84ca9932a29596256a34daee742bb542396b9ce21d4cf7bc',
             'holes': [800, 844, 881, 955, 918],
             'member_names': ['owner', 'fs', 'json', 'validation', 'identity'],
             'packer_source': 'native/config_owner_fixture_packer.hepta',
             'packer_source_sha256': '5a9ddd8cc21e2b9e7b3358ba7f17d80d3750d35776f1858a6a9f5898e6d81659',
             'prefix_bytes': 3239,
             'prefix_sha256': '9f19136b717f3380e94ed0687f8a87ee3e2a7264b5e7b23ee04b131a5df6d98f',
             'schema': 'hepta.runtime.config-owner-native.v1'},
 'fs': {'adapter_source': 'scripts/config_fs_adapter.S',
        'adapter_source_sha256': 'fabd07fd4c9000daa9b98a653490bba40f18371e5bc6e11068a7f316b505b54c',
        'elf_bytes': 111103,
        'elf_sha256': '53477ced0bd5211a4e5af10df08178ef5498604e1760cba0c9fa7d59f6de3ad4',
        'holes': [347],
        'member_names': ['fs'],
        'packer_source': 'native/config_fs_packer.hepta',
        'packer_source_sha256': 'e70df3d2482c0a8ff7a6fd7bd394ea8c424bef7ee0e69d06b51c02ec18dddfb3',
        'prefix_bytes': 1761,
        'prefix_sha256': '2e6f0d53a58189f5f84fa595b1caacd680fe8fe6fe904df8025abda00ee90e88',
        'schema': 'hepta.runtime.config-fs-probe.v1'},
 'mcp': {'adapter_source': 'scripts/config_mcp_adapter.S',
         'adapter_source_sha256': 'f2d0920ca3468f8c38bdc52b0a6d1f34e59560d278fc31cfc65c7a0c4e24db2f',
         'elf_bytes': 3073850,
         'elf_sha256': 'd1859e6b9daf64853414a66739b107fb5d8802b390a146f49bcb45e4e7e62168',
         'holes': [1008, 1115, 1152, 1226, 1189, 1071, 2449, 2921, 3007, 2253, 6296],
         'member_names': ['owner',
                          'fs',
                          'json',
                          'validation',
                          'identity',
                          'mcp',
                          'execution',
                          'execution_json',
                          'execution_core',
                          'value',
                          'publication'],
         'packer_source': 'native/config_mcp_packer.hepta',
         'packer_source_sha256': '6ef606c8776f007945cf86a554449c76a1fcf9fb7ec54087e9af09a690a23809',
         'prefix_bytes': 6591,
         'prefix_sha256': '65eb7b0062d1db99d504224524929129fd1e91cc11d20e42b4602f214c115fce',
         'schema': 'hepta.runtime.config-mcp-native.v1'},
 'owner': {'adapter_source': 'scripts/config_owner_adapter.S',
           'adapter_source_sha256': '129d046c76bc8b0c07b5250860a1a21bb1a040965be35b1266a6a03167a8f038',
           'elf_bytes': 1382786,
           'elf_sha256': 'f143000b8d43856d9327ed0c86ccf013dc3377b51843f7b4f2103b1aaa7ca215',
           'holes': [763, 807, 844, 918, 881],
           'member_names': ['owner', 'fs', 'json', 'validation', 'identity'],
           'packer_source': 'native/config_owner_packer.hepta',
           'packer_source_sha256': '9933db64317c014781cab45b9f893f62b4f877745c86f967ace5c67f2d0a3c49',
           'prefix_bytes': 3202,
           'prefix_sha256': '1e070733cf57d6743f4c5d8a9cffbf78ee5de37613ed4d0b0e20b0c6ac24f956',
           'schema': 'hepta.runtime.config-owner-native.v1'}}

# Two immutable-authority requests contain the actual random fixture pathname.
# Their observed hashes remain retained; only those request fields vary across
# runs. Every response and all other request bytes have a fixed fingerprint.
MCP_TRANSCRIPT_SHA = 'd5ba383f8ff5517d6a4ed3ec4377c46b5b4ffe2ebd982130c6889cc0fc11ffb0'
COMPILER_SHA='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
TESTS=('test_config_json.py','test_config_semantics.py','test_config_fs.py','test_config_owner.py','test_config_mcp.py','test_config_mcp_receipts.py')
GROUPS=(5,6,8,7,5,4)
STREAMS={'typed-corpus':(6491,15953009,'87a619c1f79f22d4e8f5074856d0e49ed4fd475bf2809deb91e79d492f65b7c1',2946846,'7d72f4df20f45a0b2317782dec628048360a79b724d008231d5f6a46439fb9f7'),
 'semantics-corpus':(2063,12206335,'b817774c48233e843a9b7b5f3f1577a0306846946694ca9f6be1c4e0517ddee2',3801646,'7c0348f29ade8b26c1e86ec642146e3b3ab4271474f2fa0954ed7e67eaebdf86')}
COUNTS=(
 {'native_calls':6580,'original_domain_cases':6491,'real_elf_runs':6},
 {'explicit_regex_dependency_cases':4,'native_calls':4049,'original_digest_cases':21,'original_semantic_cases':1837,'original_typed_refusals':201,'real_static_elf_runs':5},
 {'actual_elf_requests':61,'configuration_read_byte_comparisons':5,'eof_retirement_controls':1,'lock_admission_refusals':6,'retained_pair_and_release_controls':16},
 {'actual_elf_requests':73,'actual_lock_custody_controls':4,'actual_startup_refusals':7,'environment_default_controls':7,'exact_name_alias_order_controls':9,'failed_reinstallation_controls':3,'immutable_source_and_path_controls':8,'persistent_query_cache_controls':9,'production_install_authority_refusals':1},
 {'above_old_protocol_node_limit':1,'actual_elf_responses':60,'actual_execution_chain_controls':4,'actual_value_controls':6,'embedded_images_verified':11,'exact_installed_host_controls':3,'final_eof_frame_controls':1,'immutable_authority_controls':4,'lock_custody_controls':4,'missing_null_empty_default_controls':8,'native_number_controls':4,'protocol_profile_refusals':4})
sha=lambda raw:hashlib.sha256(raw).hexdigest()

def require(ok,message):
    if not ok:raise ValueError('configuration evidence: '+message)
def exact(actual,expected,message):require(json_bytes(actual)==json_bytes(expected),message)
def object_at(path):
    def unique(rows):
        result={}
        for key,value in rows:
            require(key not in result,'duplicate JSON key');result[key]=value
        return result
    value=json.loads(read(path),object_pairs_hook=unique)
    require(type(value) is dict,'expected JSON object');return value
def finite(value,limit=180):require(type(value) in (int,float) and math.isfinite(value) and 0<=value<limit,'elapsed limit changed')
def confined(output,value):
    path=Path(value);path=path if path.is_absolute() else output/path
    require(path.is_relative_to(output) and '..' not in path.parts,'artifact escaped output')
    read(path);return path
def artifact(output,values,path):
    raw=read(path);require(path.is_relative_to(output),'artifact escaped output');values[path.relative_to(output).as_posix()]=sha(raw);return raw
def source_pins(root):
    paths=set(OWN+DEPENDENCIES)
    paths.update(['scripts/hia_native_entropy_qualification.py','scripts/hia_native_view_cache_qualification.py'])
    values={name:sha(read(root/name)) for name in sorted(paths)}
    for row in MODULES.values():require(values[row['source']]==row['source_sha256'],'HIA source changed: '+row['source'])
    for row in EXECUTABLES.values():require(values[row['packer_source']]==row['packer_source_sha256'],'HIA packer changed')
    require(values['scripts/config_mcp_adapter.S']==EXECUTABLES['mcp']['adapter_source_sha256'],'fixed publication adapter changed')
    publication=object_at(root/'native/config_publication_adapter.json')
    expected={'schema':'hepta.runtime.config-publication-adapter.v1','adapter_sha256':values['scripts/config_mcp_adapter.S'],'owner_source':MODULES['publication']['source'],'owner_source_sha256':MODULES['publication']['source_sha256'],'owner_image_sha256':MODULES['publication']['image_sha256'],'handoff_module':5,'new_image':10,'same_owner_as_fixture':True,'production_stderr_unchanged':True,'fixture_write_ack_trace':True,'production_write_ack_trace':False,'external_ofd_flags_changed':False,'filesystem_callers_replaced':False,'whole_runtime_replaced':False,'no_application_cumulative_quota_from_windows_or_chunks':True,'bounded_by_lp64_and_real_resources':True}
    exact({k:publication.get(k) for k in expected},expected,'result publication adapter binding or scope changed')
    return values
def launch(root,script,args):
    code='import runpy,sys; root=sys.argv[1]; script=sys.argv[2]; sys.path[:0]=[root+"/scripts",root+"/tests/hia_native"]; sys.argv=sys.argv[2:]; runpy.run_path(script,run_name="__main__")'
    return [sys.executable,'-I','-B','-c',code,str(root),str(root/script),*map(str,args)]

def build_config(hepta,build_root,source_root):
    root=Path(source_root).resolve(strict=True);build=Path(build_root).resolve();output=build.parent
    build.mkdir(exist_ok=True,parents=True);destination=build/'config-build.json';pins=source_pins(root)
    if destination.exists():
        _build_at(root,output,destination,hepta=hepta);return destination
    for suffix in ['stdout','stderr','receipt.json']:
        require(not (build/('config-build.'+suffix)).exists(),'refusing reuse of a previous incomplete build')
    command=launch(root,'scripts/build_hia_config_service.py',['--hepta',Path(hepta).resolve(strict=True),'--build-root',build,'--output',destination])
    env={k:v for k,v in os.environ.items() if not k.startswith(('HIA_','PYTHON'))};env['PYTHONDONTWRITEBYTECODE']='1'
    start=time.monotonic();stdout=stderr=b'';code=None;timed_out=False;cleanup_timeout=False;error=None
    try:
        process=subprocess.Popen(command,cwd=root,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        try:stdout,stderr=process.communicate(timeout=180)
        except subprocess.TimeoutExpired as exc:
            timed_out=True
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            try:stdout,stderr=process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                cleanup_timeout=True;stdout,stderr=exc.stdout or b'',exc.stderr or b''
        code=process.poll()
    except OSError as exc:error={'type':type(exc).__name__,'message':str(exc)}
    elapsed=time.monotonic()-start
    (build/'config-build.stdout').write_bytes(stdout);(build/'config-build.stderr').write_bytes(stderr)
    receipt={'schema':'hepta.runtime.config-build-process.v1','command':command,'cwd':str(root),'exit_code':code,'timed_out':timed_out,'cleanup_timed_out':cleanup_timeout,'start_error':error,'timeout_seconds':180,'cleanup_seconds':3,'elapsed_seconds':elapsed,'stdout_sha256':sha(stdout),'stderr_sha256':sha(stderr),'source_pins':pins,'source_pins_after':source_pins(root)}
    (build/'config-build.receipt.json').write_bytes(json_bytes(receipt))
    require(code==0 and not timed_out and not cleanup_timeout and error is None,'actual build failed; original receipt retained')
    _build_at(root,output,destination,hepta=hepta);return destination

def _compiled_module(root,output,path,expected,compiler,artifacts):
    meta=object_at(path);artifact(output,artifacts,path)
    common={'schema':'hepta.runtime.native-module.v1','abi':'hepta.runtime.borrowed-bytes.linux-x86_64.v1','target':'linux-x86_64','compiler_commit':HEPTA_COMMIT,'compiler_sha256':COMPILER_SHA}
    exact({k:meta.get(k) for k in common},common,'native manifest/compiler differs')
    for k in ['source_sha256','image_sha256','input_capacity','output_capacity','workspace_capacity']:
        if k in expected:exact(meta.get(k),expected[k],'module profile differs: '+k)
    exact(meta.get('buffer_profile','standard'),expected.get('buffer_profile','standard'),'module buffer profile differs')
    source=artifact(output,artifacts,confined(path.parent,meta['source']));image=artifact(output,artifacts,confined(path.parent,meta['image']))
    require(source==read(root/expected['source']) and sha(source)==meta['source_sha256'] and sha(image)==meta['image_sha256'],'compiled source/image differs')
    _compiled(output,path.parent,source,image,compiler,artifacts)
    for name in ['module.request.json','module.stdout.log','module.stderr.log']:artifact(output,artifacts,path.parent/name)
    return meta,image

def _standalone(root,output,path,meta,image,compiler,artifacts):
    standalone=meta['standalone'];require(type(standalone) is dict,'missing actual filter')
    elf=artifact(output,artifacts,confined(path.parent,standalone['path']))
    require(standalone['transport']=='filter' and standalone['runtime_python_required'] is False and standalone['runtime_libc_required'] is False,'filter runtime changed')
    require(sha(elf)==standalone['sha256'] and elf[-len(image):]==image,'filter image changed')
    exact(standalone['inspection'],inspect_elf(elf),'filter ELF inspection changed')
    packer_source=read(root/'native/serde_filter_packer.hepta');cache=output/'build/packers'/sha(packer_source)
    packer=artifact(output,artifacts,cache/'packer.image.bin');pm=object_at(cache/'manifest.json');artifact(output,artifacts,cache/'manifest.json')
    require(artifact(output,artifacts,cache/'source.hepta')==packer_source and pm['source_sha256']==sha(packer_source),'filter packer source changed')
    native_receipt(pm['compile_receipt'],image=compiler,source=packer_source,output=artifact(output,artifacts,cache/'packer.output.bin'),produced=packer)
    frame=artifact(output,artifacts,path.parent/'pack.input.bin');require(frame==b'HIAFLT01'+struct.pack('<Q',len(image))+image,'filter frame changed')
    receipt=object_at(path.parent/'pack.receipt.json');exact(receipt,standalone['pack_receipt'],'filter receipt differs')
    native_receipt(receipt,image=packer,source=frame,output=artifact(output,artifacts,path.parent/'pack.output.bin'),produced=elf)
    for name in ['pack.receipt.json','pack.request.json','pack.stdout.log','pack.stderr.log']:artifact(output,artifacts,path.parent/name)
    for name in ['packer.receipt.json','packer.request.json','packer.stdout.log','packer.stderr.log','packer.input.bin']:artifact(output,artifacts,cache/name)

def _build_at(root,output,path,*,hepta=None):
    root=root.resolve(strict=True);output=output.resolve(strict=True);path=confined(output,path);build=output/'build';artifacts={}
    bundle=object_at(path);raw=artifact(output,artifacts,path);pins=source_pins(root)
    require(path==build/'config-build.json' and bundle['schema']=='hepta.runtime.config-native-build.v1','wrong bundle path/schema')
    require(bundle['compiler_commit']==HEPTA_COMMIT and bundle['compiler_sha256']==COMPILER_SHA and bundle['fresh_cold_qualified'] is False,'compiler or closure claim differs')
    compiler=artifact(output,artifacts,build/'bootstrap/B3.image.bin');bootstrap=object_at(build/'bootstrap/bootstrap.json');artifact(output,artifacts,build/'bootstrap/bootstrap.json')
    require(sha(compiler)==COMPILER_SHA and bootstrap['dependency']['commit']==HEPTA_COMMIT,'pinned compiler changed')
    if hepta is not None:exact(bootstrap['dependency'],check_dependency(Path(hepta).resolve(strict=True)),'compiler source closure differs')
    receipt=object_at(build/'config-build.receipt.json');artifact(output,artifacts,build/'config-build.receipt.json')
    stdout=artifact(output,artifacts,build/'config-build.stdout');stderr=artifact(output,artifacts,build/'config-build.stderr')
    expected={'schema':'hepta.runtime.config-build-process.v1','exit_code':0,'timed_out':False,'cleanup_timed_out':False,'start_error':None,'timeout_seconds':180,'cleanup_seconds':3,'source_pins':pins,'source_pins_after':pins,'stdout_sha256':sha(stdout),'stderr_sha256':sha(stderr),'cwd':str(root)}
    exact({k:receipt.get(k) for k in expected},expected,'actual build process receipt differs');finite(receipt['elapsed_seconds'],183)
    command=receipt['command'];require(len(command)==13 and command[:7]==launch(root,'scripts/build_hia_config_service.py',[]) and command[7]=='--hepta' and command[9:] == ['--build-root',str(build),'--output',str(path)],'fixed build command differs')
    exact(json.loads(stdout),{'output':str(path),'modules':13,'executables':['fs','owner','fixture','mcp']},'actual build stdout is incomplete')
    require(stderr==b'' and set(bundle['modules'])==set(MODULES) and set(bundle['executables'])==set(EXECUTABLES),'build inventory changed')
    modules={}
    for name,want in MODULES.items():
        ref=bundle['modules'][name];mp=confined(output,ref['path']);require(sha(read(mp))==ref['sha256'],'module reference changed')
        meta,image=_compiled_module(root,output,mp,want,compiler,artifacts)
        if name in ['json','validation','identity']:_standalone(root,output,mp,meta,image,compiler,artifacts)
        else:require(meta['standalone'] is None,'unexpected standalone module')
        modules[name]={'path':mp,'meta':meta,'image':image}
    executables={}
    for name,want in EXECUTABLES.items():
        ref=bundle['executables'][name];ep=confined(output,ref['path']);m=object_at(ep);artifact(output,artifacts,ep)
        require(sha(read(ep))==ref['sha256'],'executable manifest changed')
        exact({k:m.get(k) for k in ['schema','elf_sha256','elf_bytes','prefix_bytes','prefix_sha256','packer_source_sha256','adapter_source_sha256']},{k:want[k] for k in ['schema','elf_sha256','elf_bytes','prefix_bytes','prefix_sha256','packer_source_sha256','adapter_source_sha256']},'fixed executable identity differs')
        require(m['compiler_commit']==HEPTA_COMMIT and m['compiler_sha256']==COMPILER_SHA and m['complete_config_owner'] is False and m['fresh_cold_qualified'] is False,'executable authority claim changed')
        elf=artifact(output,artifacts,confined(ep.parent,m['executable']));inspect_elf(elf);require((len(elf),sha(elf))==(want['elf_bytes'],want['elf_sha256']),'fixed ELF bytes differ')
        packpath=confined(output,m['packer_manifest']);require(sha(read(packpath))==m['packer_manifest_sha256'],'packer manifest changed')
        _compiled_module(root,output,packpath,{'source':want['packer_source'],'buffer_profile':'standard','source_sha256':want['packer_source_sha256'],'input_capacity':8<<20,'output_capacity':8<<20,'workspace_capacity':32<<20},compiler,artifacts)
        prefix=bytearray(elf[:want['prefix_bytes']]);struct.pack_into('<QQ',prefix,96,0,0);at=want['prefix_bytes'];images=[]
        member_rows=m.get('members')
        if name=='fs':require(m['module_manifest']==str(modules['fs']['path']) and m['module_manifest_sha256']==bundle['modules']['fs']['sha256'],'filesystem child differs')
        else:require(type(member_rows) is list and len(member_rows)==len(want['member_names']),'image table incomplete')
        for i,(key,hole) in enumerate(zip(want['member_names'],want['holes'],strict=True)):
            actualkey=key+'_composed' if key in ['validation','identity'] else key;child=modules[actualkey];image=child['image'];images.append(image)
            require(elf[hole-1]==0xe8 and hole+4+struct.unpack_from('<i',elf,hole)[0]==at and elf[at:at+len(image)]==image,'native image/call target differs');struct.pack_into('<I',prefix,hole,0)
            if member_rows is not None:
                row=member_rows[i];expected={'id':i,'name':key,'manifest':str(child['path']),'manifest_sha256':sha(read(child['path'])),'source_sha256':sha(read(root/MODULES[actualkey]['source'])),'image_sha256':sha(image),'image_bytes':len(image),'offset':at,'call_displacement_offset':hole}
                expected.update({k:MODULES[actualkey][k] for k in ['buffer_profile','input_capacity','output_capacity','workspace_capacity']})
                if name=='mcp':expected['source']=MODULES[actualkey]['source']
                exact({k:row.get(k) for k in expected},expected,'fixed image table changed')
            at+=len(image)
        require(at==len(elf) and sha(prefix)==want['prefix_sha256'],'fixed prefix/layout differs')
        if name=='fs':frame=b'HIAFLT01'+struct.pack('<Q',len(images[0]))+images[0]
        else:frame=(b'HCFGMCP3' if name=='mcp' else b'HCFGPCK1')+b''.join(struct.pack('<Q',len(i)) for i in images)+bytes(8)+b''.join(images)
        require(m['pack_input_sha256']==sha(frame),'actual pack frame identity changed')
        if name!='fs':require(artifact(output,artifacts,ep.parent/'pack.input.bin')==frame,'retained pack frame changed')
        if name in ['owner','fixture']:require(m['fixture_admin_reinstallation']==(name=='fixture') and m['caller_configuration_installation'] is False,'fixture authority differs')
        if name=='mcp':
            exact(m['call_edges'],{'0':[1,2,3,4],'5':[0,6,9,10],'6':[0,7,8]},'call authority differs')
            require(m['only_effect_owner']==1 and m['protocol_version']=='2025-06-18' and m['caller_configuration_installation'] is False,'MCP startup/effect authority differs')
            exact(m['tool_names'],['host_list','effective_config','execution_shadow_admit'],'advertised tools changed')
            expected_publication={'result_publication_image_id':10,'result_publication_source':MODULES['publication']['source'],'result_publication_source_sha256':MODULES['publication']['source_sha256'],'result_publication_image_sha256':MODULES['publication']['image_sha256'],'result_publication_handoff':'config_mcp.tool_result fixed envelope prefix and original text span','filesystem_hint_callers_replaced':False,'publication_fixture_is_production':False,'regex_compilation_closed':False}
            exact({k:m.get(k) for k in expected_publication},expected_publication,'typed text publication owner or scope differs')
            exact({k:m.get(k) for k in ['builder_source_sha256','generic_build_sha256','generic_loader_sha256']},{'builder_source_sha256':pins['scripts/build_config_mcp_service.py'],'generic_build_sha256':pins['scripts/hia_native_build.py'],'generic_loader_sha256':pins['scripts/hia_native_loader.py']},'actual MCP build source closure differs')
        executables[name]={'manifest':ep.relative_to(output).as_posix(),'sha256':sha(read(ep)),'elf_sha256':sha(elf)}
    require([x['name'] for x in bundle['records']]==['filesystem','owner','fixture','mcp'],'sub-build records incomplete')
    for row in bundle['records']:
        require(row['exit']==0,'sub-build did not complete')
        for stream in ['stdout','stderr']:require(sha(artifact(output,artifacts,build/(row['name']+'.'+stream)))==row[stream+'_sha256'],'sub-build actual output changed')
    return {'schema':'hepta.runtime.config-build-evidence.v1','source_pins':pins,'bundle_sha256':sha(raw),'modules':bundle['modules'],'executables':executables,'artifact_sha256':artifacts}

def build_evidence(root,output,report):
    owner=report['modules']['runtime_config'];require(owner.get('builder')=='runtime_config','builder changed')
    path=confined(output,owner['manifest']);require(sha(read(path))==owner['sha256'],'aggregate bundle differs')
    require(report['compiler_commit']==HEPTA_COMMIT and report['compiler_image_sha256']==COMPILER_SHA,'aggregate compiler differs')
    return _build_at(root,output,path)

def test_commands(root,output,report):
    path=confined(output,report['modules']['runtime_config']['manifest']);bundle=object_at(path)
    modules={k:confined(output,v['path']) for k,v in bundle['modules'].items()};exes={k:confined(output,v['path']) for k,v in bundle['executables'].items()}
    args=[['--manifest',modules['json']],sum((['--'+n+'-manifest',modules[n]] for n in ['json','validation','identity']),[]),['--manifest',exes['fs']],['--manifest',exes['owner'],'--fixture-manifest',exes['fixture']],['--manifest',exes['mcp'],'--output',output/'config-native/mcp'],['--manifest',modules['mcp'],'--output',output/'config-native/receipts']]
    return {name:launch(root,'tests/hia_native/'+name,argv) for name,argv in zip(TESTS,args,strict=True)}

def _suite(output,report,completed,name,groups,command):
    check,summary=completed(output,report,name)
    exact(check.get('command'),command,'actual test command differs: '+name)
    require(check.get('exit_code')==0 and check.get('timed_out') is False and not check.get('start_error'),'test process did not complete')
    require(check.get('timeout_seconds')==180,'test timeout changed');finite(check['elapsed_seconds'])
    require(summary.get('status')=='PASS' and type(summary.get('test_groups',summary.get('groups'))) is int and summary.get('test_groups',summary.get('groups'))==groups,'test groups incomplete')
    stdout=read(output/(name+'.stdout'));stderr=read(output/(name+'.stderr'))
    exact(json.loads(stdout),summary,'complete test stdout differs')
    if name!='test_config_mcp_receipts.py':
        text=stderr.decode();require(len(re.findall(r'\.\.\. ok\n',text))==groups and re.search(r'\nRan '+str(groups)+r' tests in [0-9.]+s\n\nOK\n\Z',text) is not None,'native unittest did not finish every group')
    else:require(stderr==b'','receipt controls emitted unexpected stderr')
    return check,summary

def _corpus(output,folder,build,artifacts):
    path=output/'config-native'/folder;meta=object_at(path/'native-corpus.json');artifact(output,artifacts,path/'native-corpus.json')
    cases,request_size,request_hash,response_size,response_hash=STREAMS[folder]
    require(meta.get('cases')==cases,'corpus case count changed')
    for key,name,size,digest in [('requests','requests.hex',request_size,request_hash),('native_output','native-output.txt',response_size,response_hash)]:
        raw=artifact(output,artifacts,path/name)
        exact((meta.get(key+'_file'),meta.get(key+'_bytes'),meta.get(key+'_sha256')),(name,size,digest),'corpus metadata differs')
        require((len(raw),sha(raw),raw.count(b'\n'))==(size,digest,cases),'complete native corpus bytes differ')
    if folder=='typed-corpus':
        exact({k:meta.get(k) for k in ['source_sha256','image_sha256','manifest_sha256']},{'source_sha256':MODULES['json']['source_sha256'],'image_sha256':MODULES['json']['image_sha256'],'manifest_sha256':build['modules']['json']['sha256']},'typed corpus owner differs')
        require(sum(meta['categories'].values())==6491,'typed category count differs')
    else:
        exact(meta.get('explicit_incomplete_regex_indices'),[450,451,452,454],'regex incompleteness changed')
        exact(meta['manifests'],{n:build['modules'][n]['sha256'] for n in ['json','validation','identity']},'semantic corpus manifests differ')
        exact(meta['sources'],{n:MODULES[n]['source_sha256'] for n in ['json','validation','identity']},'semantic corpus sources differ')
        require(meta['original_output_sha256']=='f749e18917afe6cc798749dd09418bd0682bec2dde92863c4548b26a4f583cbc','original semantic baseline changed')
    return meta

def native_evidence(root,output,report,completed_test_summary,create=False):
    root=Path(root).resolve(strict=True);output=Path(output).resolve(strict=True)
    built=build_evidence(root,output,report);bundle=object_at(output/'build/config-build.json');artifacts=dict(built['artifact_sha256']);commands=test_commands(root,output,report);records=[]
    summaries={}
    for i,(name,groups) in enumerate(zip(TESTS,GROUPS,strict=True)):
        check,summary=_suite(output,report,completed_test_summary,name,groups,commands[name]);summaries[name]=summary
        for suffix in ['stdout','stderr']:artifact(output,artifacts,output/(name+'.'+suffix))
        finite(summary.get('elapsed_seconds',summary.get('elapsed')))
        if i<5:exact(summary.get('counts'),COUNTS[i],'native coverage changed: '+name)
        if i==0:
            require(summary.get('source_sha256')==MODULES['json']['source_sha256'] and summary.get('manifest_sha256')==bundle['modules']['json']['sha256'],'tested typed owner differs')
        elif i==1:exact(summary.get('manifests'),{n:bundle['modules'][n]['sha256'] for n in ['json','validation','identity']},'tested semantic owners differ')
        elif i==2:
            require(summary.get('source_sha256')==MODULES['fs']['source_sha256'] and summary.get('manifest_sha256')==bundle['executables']['fs']['sha256'] and summary.get('adapter_sha256')==source_pins(root)['scripts/config_fs_adapter.S'],'tested filesystem differs')
        elif i==3:
            require(summary.get('source_sha256')==MODULES['owner']['source_sha256'] and summary.get('manifest_sha256')==bundle['executables']['owner']['sha256'] and summary.get('fixture_manifest_sha256')==bundle['executables']['fixture']['sha256'],'tested installed owner differs')
        elif i==4:
            raw=artifact(output,artifacts,output/'config-native/mcp/report.json');stored=json.loads(raw)
            exact({k:v for k,v in stored.items() if k!='transcript'},summary,'MCP actual stdout differs from retained report')
            require(summary.get('source_unchanged') is True and summary.get('manifest_sha256')==bundle['executables']['mcp']['sha256'],'tested MCP executable differs')
            transcript=[]
            require(type(stored['transcript']) is list and len(stored['transcript'])==59,'actual MCP transcript incomplete')
            for index,row in enumerate(stored['transcript']):
                require(set(row)=={'request_bytes','request_sha256','response_bytes','response_sha256'} and all(type(row[k]) is int and 0<=row[k]<=8<<20 for k in ['request_bytes','response_bytes']) and all(type(row[k]) is str and re.fullmatch('[0-9a-f]{64}',row[k]) for k in ['request_sha256','response_sha256']),'actual MCP transcript record malformed')
                transcript.append({k:v for k,v in row.items() if index not in [39,41] or k not in ['request_bytes','request_sha256']})
            require(sha(json.dumps(transcript,sort_keys=True,separators=(',',':')).encode())==MCP_TRANSCRIPT_SHA,'actual MCP response/stable-request transcript changed')
        else:
            stored=json.loads(artifact(output,artifacts,output/'config-native/receipts/report.json'));exact(stored,summary,'receipt-control stdout differs')
            exact({k:summary.get(k) for k in ['native_calls','corrupt_receipt_offsets','capacity_initialization_committed','synthetic_child_receipts','actual_child_semantics_in_separate_static_elf_suite']},{'native_calls':38,'corrupt_receipt_offsets':list(range(0,112,8)),'capacity_initialization_committed':False,'synthetic_child_receipts':True,'actual_child_semantics_in_separate_static_elf_suite':True},'receipt controls incomplete')
            require(summary['manifest_sha256']==bundle['modules']['mcp']['sha256'] and summary['source_sha256']==MODULES['mcp']['source_sha256'],'receipt owner differs')
            require(summary.get('typed_text_publication_handoff_checked') is True,'typed text publication receipt was not checked')
        for claim in ['complete_runtime','complete_config_owner','production_activated','regex_compilation_closed']:
            if claim in summary:require(summary[claim] is False,'native report overstates scope')
        records.append({'name':name,'command':check['command'],'exit':0,'elapsed':check['elapsed_seconds'],'stdout_sha256':check['stdout_sha256'],'stderr_sha256':check['stderr_sha256'],'completed_test_summary':summary})
    corpora={n:_corpus(output,n,built,artifacts) for n in STREAMS}
    compatible={'schema':'hepta.runtime.config-native-tests.v1','status':'PASS','source_unchanged':True,'inputs':source_pins(root),'build_sha256':built['bundle_sha256'],'records':records,
                'modules':bundle['modules'],'executables':bundle['executables'],'corpora':{'typed':str(output/'config-native/typed-corpus'),'semantics':str(output/'config-native/semantics-corpus')},
                'actual_completed_suites':6,'actual_test_groups':35,'complete_config_owner':False,'regex_compilation_closed':False,'fresh_cold_qualified':False}
    path=output/'config-native/result.json';encoded=json_bytes(compatible)
    if create:
        require(not path.exists(),'compatibility result already exists; refusing replacement')
        with path.open('xb') as stream:stream.write(encoded)
    require(artifact(output,artifacts,path)==encoded,'compatibility result was not derived from all six actual records')
    return {'schema':'hepta.runtime.config-native-evidence.v1','status':'PASS','source_pins':source_pins(root),'build':built,'tests':summaries,'corpora':corpora,
            'compatibility_result_sha256':sha(encoded),'artifact_sha256':artifacts,
            'corpus_sha256':{str((Path('config-native')/n/f)):artifacts[str(Path('config-native')/n/f)] for n in STREAMS for f in ['native-corpus.json','requests.hex','native-output.txt']},
            'native_calls_added_by_evidence_admission':0,'complete_config_owner':False,'regex_compilation_closed':False,'whole_runtime_replaced':False,'old_stack_removal_qualified':False}

def _reference_inputs(root,project,artifacts,output):
    spec=object_at(root/'tests/hia_native/config_reference_sources.json');prepared=object_at(project/'reference-inputs.json');artifact(output,artifacts,project/'reference-inputs.json')
    require(prepared['archive_sha256']==sha(read(root/'tests/hia_native/config_reference.tar.gz'))==spec['archive_sha256'] and prepared['metadata_sha256']==sha(read(root/'tests/hia_native/config_reference_sources.json')),'reference preparation source changed')
    exact(prepared['files'],spec['files'],'reference file inventory changed');exact(prepared['original_sources'],spec['original_sources'],'original source inventory differs')
    require(prepared['source_block_count']==54 and prepared['shared_build'] is True,'original extraction domain changed')
    for name,want in spec['original_sources'].items():
        raw=read(root/name);require((len(raw),sha(raw))==(want['bytes'],want['sha256']),'original source changed')
    for name,want in spec['files'].items():
        raw=artifact(output,artifacts,confined(project,name));require((len(raw),sha(raw))==(want['bytes'],want['sha256']),'compiled reference source changed')
    for block in spec['source_blocks']:
        raw=read(root/block['source'])[block['offset']:block['offset']+block['bytes']];require(sha(raw)==block['sha256'],'original block changed')
        for target in block['targets']:require(read(project/target['path'])[target['offset']:target['offset']+len(raw)]==raw,'compiled original function differs')
    original={(p['name'],p['version']):p for p in tomllib.loads(read(root/'Cargo.lock').decode())['package'] if 'checksum' in p};actual=[]
    for row in tomllib.loads(read(project/'Cargo.lock').decode())['package']:
        if 'checksum' in row:
            old=original[(row['name'],row['version'])];require((row['source'],row['checksum'])==(old['source'],old['checksum']),'original registry dependency differs');actual.append({k:row[k] for k in ['name','version','source','checksum']})
    exact(prepared['packages'],actual,'compiled dependency inventory differs');require(len(actual)==100,'original dependency count changed')
    return prepared

def _gzip(path,expected_size=None,expected_sha=None,expected_lines=None):
    data=gzip.decompress(read(path))
    if expected_size is not None:require(len(data)==expected_size,'complete original output length changed')
    if expected_sha is not None:require(sha(data)==expected_sha,'complete original output changed')
    if expected_lines is not None:require(data.count(b'\n')==expected_lines,'original case count changed')
    return data

def original_evidence(root,output,report,completed_test_summary):
    root=Path(root).resolve(strict=True);output=Path(output).resolve(strict=True);native=native_evidence(root,output,report,completed_test_summary)
    check,summary=completed_test_summary(output,report,'config-rust-compare');require(check['exit_code']==0 and check['timed_out'] is False and not check.get('start_error') and check['timeout_seconds']==180,'original process did not complete');finite(check['elapsed_seconds'])
    command=check['command'];expected_prefix=[sys.executable,'-I','-B',str(root/'tests/hia_native/compare_config_original.py'),'--repo',str(root),'--native-results',str(output/'config-native/result.json'),'--output',str(output/'config-original'),'--cargo']
    require(len(command)==14 and command[:11]==expected_prefix and command[12]=='--rustc','original comparison command differs')
    folder=output/'config-original';project=folder/'project';artifacts={}
    for name in ['config-rust-compare.stdout','config-rust-compare.stderr']:artifact(output,artifacts,output/name)
    original=object_at(folder/'report.json');artifact(output,artifacts,folder/'report.json')
    exact({k:v for k,v in original.items() if k not in ['records','domains','inputs']},summary,'actual original stdout differs from retained report')
    expected={'schema':'hepta.runtime.config-original-comparison.v1','status':'PASS','source_unchanged':True,'native_result_sha256':native['compatibility_result_sha256'],'registry_packages':100,'one_shared_cargo_build':True,'total_reference_input_cases':9735,'complete_config_owner':False,'regex_compilation_closed':False,'original_rust_runtime_fallback':False}
    exact({k:original.get(k) for k in expected},expected,'original completion/coverage differs')
    prepared=_reference_inputs(root,project,artifacts,output)
    require(sha(read(project/'reference-inputs.json'))==original['reference_input_sha256'],'reference source receipt changed')
    require(set(original['reference_executables'])=={'typed','semantics','owner','mcp'},'reference executable inventory incomplete')
    for name,digest in original['reference_executables'].items():
        raw=artifact(output,artifacts,project/'target/release'/('hia-runtime-config-'+name));require(sha(raw)==digest and raw.startswith(b'\x7fELF'),'actual original executable changed')
    expected_inputs=[root/'tests/hia_native'/n for n in ['compare_config_original.py','config_mcp_cases.py','config_mcp_sessions.py','config_fs_cases.py','config_owner_cases.py','config_semantics_cases.py','test_config_fs.py','test_config_owner.py','config_reference_sources.json','config_reference.tar.gz']]+[root/'scripts/hia_native_config_reference.py']
    bundle=object_at(output/'build/config-build.json')
    for name in ['owner','fixture','mcp']:
        ep=confined(output,bundle['executables'][name]['path']);expected_inputs.extend([ep,ep.parent/object_at(ep)['executable']])
    exact(original['inputs'],{str(p):sha(read(p)) for p in expected_inputs},'original runner/native/source custody changed')
    records=original['records'];require([r['name'] for r in records]==['rust-version','build','typed','semantics'],'original shared build/replays incomplete')
    for record in records:
        require(record['exit']==0,'original child failed');finite(record['elapsed'])
        name=record['name'];out=read(folder/(name+'.stdout')) if name in ['rust-version','build'] else _gzip(folder/(name+'.stdout.gz'))
        err=artifact(output,artifacts,folder/(name+'.stderr'));artifact(output,artifacts,folder/(name+('.stdout' if name in ['rust-version','build'] else '.stdout.gz')))
        require(sha(out)==record['stdout_sha256'] and sha(err)==record['stderr_sha256'],'actual original build/replay output differs')
        if name=='rust-version':require(record['command']==[command[13],'--version'] and out.startswith(b'rustc '),'compiler version process differs')
        if name=='build':require(record['command']==[command[11],'build','--release','--locked','--bins','--manifest-path',str(project/'Cargo.toml')],'actual Cargo command differs')
        if name in ['typed','semantics']:
            corpus=STREAMS[name+'-corpus']
            exact({k:record.get(k) for k in ['command','cwd','request_bytes','request_sha256']},{'command':[str(project/'target/release'/('hia-runtime-config-'+name))],'cwd':str(root),'request_bytes':corpus[1],'request_sha256':corpus[2]},'original executable invocation/input differs')
    require(set(original['domains'])=={'typed','semantics','installed','mcp'},'original domain missing or added')
    expected_comparisons={'typed':{'exact_results':1879,'typed_refusals':4612,'explicit_regex_dependency':0},'semantics':{'exact_results':1858,'typed_refusals':201,'explicit_regex_dependency':4}}
    for name,stream_name in [('typed','typed-corpus'),('semantics','semantics-corpus')]:
        row=original['domains'][name];exact(row,next(v for v in records if v['name']==name),'original replay record differs');exact(row['native_corpus'],native['corpora'][stream_name],'original replay used a different native corpus');exact(row['comparison'],expected_comparisons[name],'original coverage classifications differ')
        raw=_gzip(folder/(name+'.stdout.gz'),row['stdout_bytes'],row['stdout_sha256'],STREAMS[stream_name][0]);expected_native=read(output/'config-native'/stream_name/'native-output.txt')
        for i,(n,r) in enumerate(zip(expected_native.splitlines(),raw.splitlines(),strict=True)):
            nc,np=n.split(b':',1);rc,rp=r.split(b':',1)
            if name=='semantics' and i in [450,451,452,454]:require(nc==b'fffffffc' and rc in [b'00000000',b'00000001'],'regex boundary was misclassified')
            elif nc in ([b'ffffffff',b'fffffffd'] if name=='typed' else [b'ffffffff']):require(nc==rc and not np,'typed refusal differs')
            else:require(n==r,'full original value bytes differ')
    installed=object_at(folder/'owner-comparison.json');artifact(output,artifacts,folder/'owner-comparison.json');rows=installed['observations']
    source=ast.parse(read(root/'tests/hia_native/config_owner_cases.py'));names={}
    for node in source.body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id in ['FS_CASES','OTHER_CASES']:names[node.targets[0].id]=ast.literal_eval(node.value)
    exact([r['case'] for r in rows],names['FS_CASES']+names['OTHER_CASES'],'original installed scenario domain differs')
    require(installed['cases']==62 and installed['actual_binary_requests']==490 and installed['same_exact_fixture_paths'] is True and installed['native_diagnostic_and_opaque_node_identity_excluded'] is True,'installed comparison scope differs')
    requests=0
    for row in rows:
        require(row['equal'] is True,'installed comparison mismatch');exact(row['native'],row['original'],'original installed result bytes differ')
        for side in ['native','original']:
            value=row[side];require(value['exit'] in [0,78] and type(value['stdout_rows']) is list and type(value['snapshot']) is dict and type(value['stderr_hex']) is str,'installed observations incomplete');requests+=len(value['stdout_rows'])
    require(requests==490,'installed binary response count differs')
    exact(original['domains']['installed'],{'cases':62,'actual_binary_requests':490,'report_sha256':sha(read(folder/'owner-comparison.json'))},'installed report binding differs')
    mr=object_at(folder/'mcp/report.json');artifact(output,artifacts,folder/'mcp/report.json');require(mr['cases']==1119 and mr['actual_sdk_and_installed_owners'] is True and mr['same_exact_fixture_paths'] is True and mr['actual_protocol_version']=='2025-06-18','actual SDK comparison incomplete')
    for side in ['native','original']:
        value=mr[side];require(value['exit']==0 and len(value['rows'])==1119,'MCP process did not complete');finite(value['elapsed'])
        for kind,byteskey in [('requests','request_bytes'),('responses','response_bytes')]:
            path=folder/'mcp'/(side+'-'+kind+'.hex.gz');raw=_gzip(path,value[byteskey],value[kind+'_sha256'],1119);artifact(output,artifacts,path)
            rows=raw.splitlines()
            for line,observed in zip(rows,value['rows'],strict=True):
                decoded=bytes.fromhex(line.decode());prefix='request' if kind=='requests' else 'response';require(len(decoded)==observed[prefix+'_bytes'] and sha(decoded)==observed[prefix+'_sha256'],'actual MCP row/output binding differs')
        initial=artifact(output,artifacts,folder/'mcp'/(side+'-initialize.json'));require(initial.endswith(b'\n') and sha(initial[:-1])==value['initialize_sha256'] and json.loads(initial)['result']['protocolVersion']=='2025-06-18','MCP initialization identity differs')
    exact(mr['native']['rows'],mr['original']['rows'],'full original SDK rows differ')
    for key in ['requests_sha256','responses_sha256','request_bytes','response_bytes']:exact(mr['native'][key],mr['original'][key],'full original MCP stream differs')
    require(mr['native']['requests_sha256']=='0bf7b1898182fe413546664cebc7c9c459bb68039579c9dcc5a16b9bd3a2b4a7' and mr['native']['responses_sha256']=='c8e56dd033e4f06b4028226a5a739e160fbfa0e5961c7ac25038d419649358c5','fixed MCP reference domain changed')
    exact(original['domains']['mcp'],{'cases':1119,'report_sha256':sha(read(folder/'mcp/report.json')),'requests_sha256':mr['native']['requests_sha256'],'responses_sha256':mr['native']['responses_sha256']},'MCP report binding differs')
    require(native_evidence(root,output,report,completed_test_summary)==native,'native evidence changed during reference admission')
    return {'schema':'hepta.runtime.config-original-evidence.v1','status':'PASS','source_pins':source_pins(root),'domains':original['domains'],'original_executables':original['reference_executables'],'registry_packages':100,'artifact_sha256':artifacts,'corpus_sha256':{k:v for k,v in artifacts.items() if k.endswith('.gz')},'native_calls_added_by_evidence_admission':0,'native_binary_requests_in_original_recipe':1364,'whole_runtime_replaced':False,'old_stack_removal_qualified':False}
