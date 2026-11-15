"""Strict read-only admission of configuration span owners and their real captures.

No HIA or Rust is executed here. Recorded commands retain their original absolute
paths; explicit roots relocate only files read by this verifier. Private state
controls and retained original semantics remain separate domains.
"""
from pathlib import Path
from collections import Counter
import argparse, gzip, hashlib, importlib.util, io, json, math, re, stat, struct, sys
sys.dont_write_bytecode = True
U64=(1<<64)-1
GROW=0xffffffd0; CHILD=0xffffffe0; EFFECT=0xfffffff0
INVALID=0xffffffff; CAPACITY=0xfffffffe
COMPILER='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
COMMIT='d3e2c90173cf733e42b299d0c4274df4b593a12f'
SOURCE_PINS=json.loads(r'''{
  "native/canonical_path.hepta": {
    "bytes": 377552,
    "sha256": "5be55498ecc1a2c47d0512d06887eb99007ddb610f30868eccdfd4805162554a"
  },
  "native/config_directory_owner_span.hepta": {
    "bytes": 288259,
    "sha256": "6a0e7817013c32bd7189864c91dc768764ae44988cabe4391446ceafea9b5d81"
  },
  "native/config_fs_span.hepta": {
    "bytes": 78118,
    "sha256": "48d95ca6b5b1289a5641c6a5f538149723f1849b66ff9025b1e7d3bec3844048"
  },
  "native/config_identity.hepta": {
    "bytes": 173403,
    "sha256": "59c849f25aa88c5dc9a86b8dc1990889a17abfbedc5d58557e193689894710ad"
  },
  "native/config_json_span.hepta": {
    "bytes": 236250,
    "sha256": "2a2758e62ba30773c91a9709bba5d1a2efb133b9c4edc4f49b330630af1aa0fd"
  },
  "native/config_mcp.hepta": {
    "bytes": 363953,
    "sha256": "e57a4496fe9bf24372b4ebf8ed0deaeb62d5a3cc1de7e3750df40957b7d4796f"
  },
  "native/config_validation_span.hepta": {
    "bytes": 409025,
    "sha256": "9d29989299491571b6cd6ffc33c8f42ad9556c92812a2654ad0f980bd659bfa9"
  },
  "native/directory_move_guard.hepta": {
    "bytes": 123623,
    "sha256": "7d001c2f38f55092acab17e087a766d6722e08ff3a0cfa93c88924945afb462c"
  },
  "native/execution_controller.hepta": {
    "bytes": 42250,
    "sha256": "5ab993340f2f9bf8b1f6f295098570291307d5bd564332174c2d136454167a10"
  },
  "native/execution_json.hepta": {
    "bytes": 427563,
    "sha256": "d1e1610120fcadd72960f04b742ad6bfcfc3bc430a2b828463f3ab2af1268f14"
  },
  "native/execution_shadow.hepta": {
    "bytes": 137747,
    "sha256": "65aa4097e00ed497ab38efe4ddf515de99eaf45abeb7ad2829af4381e7704713"
  },
  "native/regex_controller.hepta": {
    "bytes": 44605,
    "sha256": "325fb6c201fb854dc5427d4e66ac305eb9bf9d675b873b1927254ee33b569aa5"
  },
  "native/regex_hir.hepta": {
    "bytes": 266390,
    "sha256": "ade22d0698cfa2925d241cc5311ac8b379c9662ff49b5630dbbd48d621cdf162"
  },
  "native/regex_match.hepta": {
    "bytes": 84986,
    "sha256": "1aa3d9fe9ee69d0e5c26f50638329bc9d2d4a00b30711b3fc0b02bbe0fc266fb"
  },
  "native/regex_nfa.hepta": {
    "bytes": 160037,
    "sha256": "bc4b03aedb7a4571fa0a4d87104339848ba5d60831c69aa3e222e18b1f15cf78"
  },
  "native/regex_syntax.hepta": {
    "bytes": 284772,
    "sha256": "038ad6915671a4e6c335ddc757a0a753e7b35c6e903ba01e567d3ecf2d5e2d30"
  },
  "native/regex_unicode_data.hepta": {
    "bytes": 455579,
    "sha256": "53a5ec4d585f0828cb4734071972bc695dcd06ef5291b1060c0bcda4390555e9"
  },
  "native/result_publication.hepta": {
    "bytes": 83668,
    "sha256": "18953ed21ea1ff65266d562a552958f3d0c08857801bf95ca1779743fad0f0fd"
  },
  "native/serde_json.hepta": {
    "bytes": 342221,
    "sha256": "ef9dd3a567acf523257c4245c022b8cefa9b3ddb83075e826f129b1a1f341d18"
  },
  "scripts/config_mcp_grow_adapter.S": {
    "bytes": 45268,
    "sha256": "c4b99fafb1ff25f5b88093a07a29e0a601043db02d947b1e8aebfd4c5493b06f"
  },
  "scripts/hia_native_config_span_build.py": {
    "bytes": 10919,
    "sha256": "95ce28672acb629e8d02cc5d21ae8380b7d1fc3c95abe03ca567b33fed1f5276"
  },
  "scripts/runtime_mcp_workdir_io_bridge.S": {
    "bytes": 20616,
    "sha256": "7a777b14d775e779674fadd9d9b864432c7fda11f855b3b858c1f8177242895f"
  },
  "scripts/view_call_engine.S": {
    "bytes": 24723,
    "sha256": "b138920b829acb0ad2bd6b116735ea86cc87f0bc7dea4e6bd4c86f006c70bde5"
  },
  "tests/hia_native/config_span/canonical_bridge.S": {
    "bytes": 5675,
    "sha256": "c5c4922f099778b5c793360811f56c20124d12676b8a9bfac514863545168d09"
  },
  "tests/hia_native/config_span/config_fixture.py": {
    "bytes": 2585,
    "sha256": "1bad68a614d80888f5d7be044afa1b1c272c89934f817881ebd6843b20bc88c1"
  },
  "tests/hia_native/config_span/graph_sources.json": {
    "bytes": 2749,
    "sha256": "63a621254c469ccd1915c59ebf3724fbd597225e2381b3e14b5d80f9411fcee2"
  },
  "tests/hia_native/config_span/grow_bridge.S": {
    "bytes": 24444,
    "sha256": "85aae00bedd0521ca4d3c4c91de7822aa0a700031d860a2e661b13d1a52a0f04"
  },
  "tests/hia_native/config_span/grow_fixture.S": {
    "bytes": 3979,
    "sha256": "eac97286cad0d53b46b007d98aeee80d94f9863cba91f16d782ea32f9de7ebdc"
  },
  "tests/hia_native/config_span/op8_composition.json": {
    "bytes": 5356,
    "sha256": "a59607d91a95cfe199afbf0f30c8a844742a914f42745d0cf24b3b0fe7b3b495"
  }
}''')
PROFILE_PIN=json.loads(r'''{
  "bytes": 4804,
  "sha256": "c62ce3106ab8b3a0013e0567d4aa9adb1e282080d7ff5f9eb1a6330b190e864b"
}''')
PRODUCER_PINS=json.loads(r'''{
  "guard.py": {
    "bytes": 24290,
    "sha256": "3cef20ea940e3f006a8211724041ac87825cb911a5fa97e511e1de3e69a2c51c"
  },
  "lease.py": {
    "bytes": 11594,
    "sha256": "e33fb01ba9267bab01335871b231d5dfe2b820dfb1fb0da87c5d478cb4e0f25d"
  },
  "run.py": {
    "bytes": 5738,
    "sha256": "c9d7b769963140855e73c0b7d78970d5ea755762e79ceef2b67e2e64a0ad78f2"
  },
  "semantic.py": {
    "bytes": 12912,
    "sha256": "e077d026580442aecb5e8f88815270585aced58b31bdaddc0f43e5da2f6bdb6a"
  },
  "state.py": {
    "bytes": 13763,
    "sha256": "533aa52d4c18bbb2bbe527309f2990dcda25fdb42347f06ff7bedcc74a5d03ca"
  }
}''')
GUARD_SOURCE_PINS=json.loads(r'''{
  "Cargo.lock": {
    "bytes": 396,
    "sha256": "a5e5523362d03e40e8b2dd1bd54d74d56a2bf3018baa33d9a13fa0853a68b34c"
  },
  "Cargo.toml": {
    "bytes": 168,
    "sha256": "1c634e0188096b1b4d87b8cd51691b61a42761444c3986f479b7af40410d6a42"
  },
  "cases.py": {
    "bytes": 7972,
    "sha256": "fc80b0d0f09dafd00ecb51307761b4064acea4fa4f21ad23974479049e22811a"
  },
  "golden/input.bin.gz": {
    "bytes": 58653,
    "sha256": "9af7cd23d7faa162b0c213c750868db6bff0344527bc6db9814ae3bb3f6d4589"
  },
  "golden/manifest.json": {
    "bytes": 176663,
    "sha256": "3f1b77b7fe052709d927c764f423ffa5b57234b2c331e81f4278087af989650b"
  },
  "golden/responses.bin.gz": {
    "bytes": 793,
    "sha256": "9579e641771710dbcc6aca0130540cfbd972080903bc1457a8aba5819f220559"
  },
  "original/config.rs": {
    "bytes": 25272,
    "sha256": "228f83aa263920ef16e6fca93ce52292cae3cecae5be4b47788a7070fee97f35"
  },
  "original/runtime.Cargo.lock": {
    "bytes": 90148,
    "sha256": "7f39704b92d5fc762a98a5313949034db464ca9485827b19b5dde7aa69902d43"
  },
  "qualify.py": {
    "bytes": 3752,
    "sha256": "001fc5872ea974cb477f2a1a3152450aca9dc4090e1833791a8e0cde86b9f3ed"
  },
  "run.py": {
    "bytes": 12370,
    "sha256": "a3e770da5475243b2a25e6636b36036f14ad00d75c4dce3c1dd0ed601a88b235"
  },
  "src/driver.rs": {
    "bytes": 3147,
    "sha256": "33993782b2904cf6632e5c9b6f347f7f64d54b80dd9ab6a530bb524dd377614e"
  },
  "strict_reference.py": {
    "bytes": 33119,
    "sha256": "dd7c9ea00a57bd82fb6295894341818caf875da6f4a3085ac422c097608e9363"
  },
  "test_reference_evidence.py": {
    "bytes": 11808,
    "sha256": "031da5cdcfee16b7fcdb362216edd7ccd58d7e1a9d26cecaacd09c5fb86d0c24"
  },
  "verify_sources.py": {
    "bytes": 3206,
    "sha256": "7ab6b9af116b65597563bea4be4d9856f3a668d3807e5fbecdc305bc9e706b0b"
  }
}''')
def need(value,message):
    if not value:raise ValueError('config span evidence: '+str(message))
def canonical(value):return json.dumps(value,sort_keys=True,ensure_ascii=True,allow_nan=False,separators=(',',':')).encode()+b'\n'
def same(a,b,message):need(canonical(a)==canonical(b),message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def bytes_pin(raw):return {'bytes':len(raw),'sha256':sha(raw)}
def uint(value,message):
    need(type(value)is int and 0<=value<=U64,message);return value
def elapsed(value,limit,message):
    need(type(value)in(int,float)and math.isfinite(value)and 0<value<=limit,message)
def qword(raw,at):
    need(type(at)is int and 0<=at<=len(raw)-8,'u64 outside complete bytes')
    return struct.unpack_from('<Q',raw,at)[0]
def pack(*values):return struct.pack('<'+'Q'*len(values),*values)
def strict_json(raw):
    def pairs(items):
        result={}
        for key,value in items:need(key not in result,'duplicate JSON key');result[key]=value
        return result
    def number(value):
        result=float(value);need(math.isfinite(result),'nonfinite JSON number');return result
    def bad(value):raise ValueError('config span evidence: nonfinite JSON')
    try:return json.loads(raw,object_pairs_hook=pairs,parse_float=number,parse_constant=bad)
    except (UnicodeError,json.JSONDecodeError)as error:raise ValueError('config span evidence: invalid JSON')from error
def inside(root,name):
    root=Path(root).absolute();name=Path(name)
    need(not name.is_absolute()and name.parts and '..'not in name.parts,'artifact path escape')
    for parent in [*reversed(root.parents),root]:
        need(parent.is_dir()and not parent.is_symlink(),'artifact root symlink')
    path=root
    for part in name.parts:
        path/=part;info=path.lstat();need(not stat.S_ISLNK(info.st_mode),'artifact symlink')
    need(stat.S_ISREG(info.st_mode)and info.st_uid==root.stat().st_uid,'artifact file type/owner')
    return path
def file_pin(path):
    with path.open('rb')as stream:return {'bytes':path.stat().st_size,'sha256':hashlib.file_digest(stream,'sha256').hexdigest()}
def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def exact(stream,n):
    need(type(n)is int and 0<=n<1<<34,'record extent')
    raw=stream.read(n);need(len(raw)==n,'truncated complete record');return raw
class Binder:
    def __init__(self,root,label):self.root=Path(root).absolute();self.label=label;self.artifacts={}
    def file(self,name,expected=None):
        name=Path(name).as_posix();path=inside(self.root,name);value=file_pin(path)
        if expected is not None:same(value,expected,'complete artifact '+self.label+'/'+name)
        same(value,self.artifacts.setdefault(name,value),'artifact changed during admission')
        return path
    def data(self,name,expected=None):return self.file(name,expected).read_bytes()
    def json(self,name,expected=None):return strict_json(self.data(name,expected))
class Evidence:
    def __init__(self,roots):
        same(sorted(roots),['build','capture','source'],'explicit admission roots')
        self.b={name:Binder(path,name)for name,path in roots.items()}
        self.b['producers']=Binder(self.b['source'].root/'tests/hia_native/config_span','producers')
        self.b['semantic_source']=self.b['source']
        self.b['guard_source']=Binder(self.b['producers'].root/'guard_original','guard_source')
        self.source=self.b['capture'].json('SOURCE.json')
        same(self.source.get('schema'),'hepta.runtime.config-span-native-source.v1','native source identity')
        for key in ('source_root','build_root','reference_source_root','home','oracle_root','python'):
            value=self.source.get(key);need(type(value)is str and Path(value).is_absolute()and '..'not in Path(value).parts,'recorded absolute root')
        self.old={'source':Path(self.source['source_root']),'build':Path(self.source['build_root']),
                  'semantic_source':Path(self.source['reference_source_root']),'producers':Path(self.source['home']),
                  'guard_source':Path(self.source['oracle_root'])}
        same(str(self.old['semantic_source']),str(self.old['source']),'same complete semantic source')
        same(str(self.old['producers']),str(self.old['source']/'tests/hia_native/config_span'),'formal producer source')
        same(str(self.old['guard_source']),str(self.old['producers']/'guard_original'),'formal original source')
        checks=self.b['capture'].json('checks.json');need(type(checks)is list and len(checks)==4,'all four actual gates')
        target=checks[0].get('command',[])
        need(type(target)is list and len(target)>2 and target[-2]=='--output','actual capture target')
        self.old['capture']=Path(target[-1]).parent
        need(self.old['capture'].is_absolute()and '..'not in self.old['capture'].parts,'actual owned capture root')
        self.checks=checks
    def mapped(self,recorded,expected=None):
        path=Path(recorded);need(path.is_absolute()and '..'not in path.parts,'recorded artifact absolute path')
        for key,prefix in sorted(self.old.items(),key=lambda x:len(x[1].parts),reverse=True):
            if path.is_relative_to(prefix):return self.b[key].file(path.relative_to(prefix),expected)
        raise ValueError('config span evidence: unmapped recorded artifact '+str(path))
    def data(self,recorded,expected=None):return self.mapped(recorded,expected).read_bytes()
    def object(self,recorded,expected=None):return strict_json(self.data(recorded,expected))
    def artifacts(self):
        result={}
        for key,binder in self.b.items():
            for name,value in binder.artifacts.items():
                target='source'if key in ('producers','semantic_source','guard_source')else key
                relative=(binder.root/name).relative_to(self.b[target].root).as_posix()
                same(result.setdefault(target+'/'+relative,value),value,'shared source artifact')
        return dict(sorted(result.items()))
def process(row,command,cwd,timeout,exit_code=0):
    need(type(row)is dict and row.get('timed_out')is False and 'start_error'not in row,'actual process start/timeout')
    same(row.get('command'),command,'actual process command')
    same(row.get('cwd'),str(cwd),'actual process cwd')
    same(row.get('timeout_seconds'),timeout,'actual process deadline')
    same(row.get('exit_code'),exit_code,'actual process exit')
    elapsed(row.get('elapsed_seconds'),timeout,'actual process elapsed')
    if 'pid'in row:need(uint(row['pid'],'actual process PID')>0,'actual positive process PID')
def common_growth(raw,kind=None,required=None):
    need(len(raw)>=32 and raw[:8]==b'HGRWS002'and qword(raw,24)==0,'complete HIA growth record')
    k,n=qword(raw,8),qword(raw,16);need(k in(1,2,3),'HIA growth kind')
    if kind is not None:same(k,kind,'HIA growth kind')
    if required is not None:same(n,required,'HIA required extent')
    return k,n
def compile_receipt(receipt,source,image,output):
    wanted={'status':'returned','abi_status':0,'core_u32':len(image),'result_u64':len(image),'source_unchanged':True,
        'input_bytes':len(source),'input_sha256':sha(source),'source_sha256':sha(source),'artifact_sha256':COMPILER,
        'image_sha256':COMPILER,'output_sha256':sha(output),'forbidden_compiler_modules_loaded':[],
        'produced_bytes':len(image),'produced_sha256':sha(image)}
    same({k:receipt.get(k)for k in wanted},wanted,'full native compiler receipt')
    need(0<len(image)<=1<<20 and len(output)==1<<20 and output[:len(image)]==image,'actual compiler full output/image')
    need(type(receipt.get('native_elapsed_ns'))is int and receipt['native_elapsed_ns']>0,'actual compiler execution time')
def module_evidence(e,path,expected_source=None,history=True):
    meta=e.object(path);folder=Path(path).parent
    wanted={'schema':'hepta.runtime.native-module.v1','abi':'hepta.runtime.borrowed-bytes.linux-x86_64.v1',
            'compiler_commit':COMMIT,'compiler_sha256':COMPILER,'target':'linux-x86_64','standalone':None,
            'qualification':'development_fixed_point'}
    same({k:meta.get(k)for k in wanted},wanted,'native child identity')
    for key in('source','image'):
        need(type(meta.get(key))is str and len(Path(meta[key]).parts)==1 and not Path(meta[key]).is_absolute(),'child artifact component')
    source=e.data(folder/meta['source']);image=e.data(folder/meta['image'])
    same([sha(source),sha(image)],[meta.get('source_sha256'),meta.get('image_sha256')],'complete native source/image')
    if expected_source is not None:need(source==expected_source,'compiled source closure')
    if history:same([meta.get('buffer_profile'),meta.get('input_capacity'),meta.get('output_capacity'),meta.get('workspace_capacity')],
                     ['history.v1',128<<20,128<<20,256<<20],'test carrier profile')
    receipt=e.object(folder/'module.receipt.json');compile_receipt(receipt,source,image,e.data(folder/'module.output.bin'))
    need(e.data(folder/'module.input.bin')==source,'actual compilation input bytes')
    built=e.object(folder/'build.json')
    same(built.get('compile_receipt'),receipt,'persisted actual compilation receipt')
    same(built.get('compiler_dependency'),e.bootstrap['dependency'],'actual compiler source dependency')
    need(built.get('whole_runtime_replaced')is False,'compiler scope')
    need(e.data(folder/'module.stderr.log')==b'','compiler stderr')
    raw_receipt=strict_json(e.data(folder/'module.stdout.log'))
    same(raw_receipt,{k:receipt[k]for k in raw_receipt},'actual compiler stdout receipt')
    req=e.object(folder/'module.request.json')
    same(req,{'capacity':1<<20,'format':'flat-x86-64','image':str(e.old['build']/'build/bootstrap/B3.image.bin'),
              'image_sha256':COMPILER,'output':str(folder/'module.output.bin'),'source':str(folder/'module.input.bin'),
              'source_sha256':sha(source),'workspace_fill':0,'workspace_size':1<<20},'actual compiler borrowed input request')
    need(receipt.get('produced_image')==str(folder/'module.image.bin'),'actual produced image path')
    return meta,image
def build_evidence(e):
    s,b=e.b['source'],e.b['build'];source_rows={}
    for name,value in SOURCE_PINS.items():s.file(name,value);source_rows[str(e.old['source']/name)]=value
    for name,value in PRODUCER_PINS.items():e.b['producers'].file(name,value);source_rows[str(e.old['producers']/name)]=value
    s.file('native/config_span_sources.json',PROFILE_PIN)
    source_rows[str(e.old['source']/'native/config_span_sources.json')]=PROFILE_PIN
    same(e.source.get('files'),source_rows,'complete fixed source/producer closure')
    built=b.json('result.json',e.source.get('build'));e.built=built
    wanted={'schema':'hepta.runtime.config-span-build.v1','status':'PASS','cold_qualification':False,'semantic_qualification':'NOT_RUN','selected_private_slots':[7,8,11],
        'guard_action_magic':'HFDMGA02','public_handler_complete':False,'public_mcp_complete':False,
        'installed_config_startup':True,'shared_installed_config_owner_slot':11}
    same({k:built.get(k)for k in wanted},wanted,'actual static build scope')
    same([built.get('source_root'),built.get('build_root')],[str(e.old['source']),str(e.old['build'])],'actual build roots')
    binding=s.json('native/config_span_sources.json')
    same(binding.get('sources'),SOURCE_PINS,'complete build input profile')
    same(built.get('source_binding'),binding,'actual build checked source profile')
    elapsed(built.get('elapsed_seconds'),180,'actual build duration')
    e.bootstrap=b.json('build/bootstrap/bootstrap.json')
    same([e.bootstrap.get('schema'),e.bootstrap.get('generation_sha256'),e.bootstrap.get('dependency',{}).get('commit'),
        e.bootstrap.get('qualification'),e.bootstrap.get('matching_source_cold_qualified')],
        ['hepta.runtime.native-bootstrap.v1',COMPILER,COMMIT,'development_fixed_point',False],'reused bootstrap identity')
    need(sha(b.data('build/bootstrap/B3.image.bin'))==COMPILER,'actual bootstrap complete image')
    declaration=s.json('tests/hia_native/config_span/graph_sources.json')
    need(type(declaration)is list and len(declaration)==17,'fixed installed configuration source graph')
    members=built.get('members');need(type(members)is list and len(members)==19,'all actual HIA members')
    images={}
    for index,row in enumerate(members):
        need(row.get('fresh_compile')is True,'actual fresh HIA compilation')
        elapsed(row.get('elapsed_seconds'),180,'native child compile elapsed')
        if index<17:
            expected=declaration[index]
            same([row.get('config_slot'),row.get('name'),row.get('source'),row.get('source_sha256')],
                [index,'config-'+expected['name'],str(e.old['source']/expected['source']),expected['sha256']],'fixed configuration slot/order')
        else:
            slot,name,source=(7,'directory-move-guard','native/directory_move_guard.hepta')if index==17 else(8,'canonical','native/canonical_path.hepta')
            same([row.get('slot'),row.get('name'),row.get('source')],[slot,name,str(e.old['source']/source)],'fixed actual extra slot/order')
        src=e.data(row['source']);need(sha(src)==row['source_sha256'],'actual member source pin')
        e.mapped(row['manifest'],{'bytes':e.mapped(row['manifest']).stat().st_size,'sha256':row['manifest_sha256']})
        meta,image=module_evidence(e,row['manifest'],src)
        need(sha(image)==row['image_sha256'],'actual member image pin');images[row['name']]=image
    expected_boundary={str(e.old['source']/name):value for name,value in SOURCE_PINS.items()if not name.startswith('native/')}
    same(built.get('sources'),expected_boundary,'complete static boundary sources')
    need(built.get('binary')==str(e.old['build']/'bridge.elf'),'actual executable provenance')
    elf=b.data('bridge.elf');need(sha(elf)==built.get('binary_sha256'),'actual static ELF complete bytes')
    need(len(elf)>=232 and elf[:16]==b'\x7fELF\x02\x01\x01'+bytes(9),'actual ELF header')
    same(list(struct.unpack_from('<HHIQQQIHHHHHH',elf,16)),[2,62,1,0x4000e8,64,0,0,64,56,3,0,0,0],'static linker ELF structure')
    text_extent=qword(elf,96)
    need(232<=text_extent<=len(elf) and (text_extent+4095)&~4095==len(elf) and elf[text_extent:]==bytes(len(elf)-text_extent),'static linker padding extent')
    same(list(struct.unpack_from('<IIQQQQQQ',elf,64)),[1,5,0,0x400000,0x400000,text_extent,text_extent,4096],'static RX extent')
    same(list(struct.unpack_from('<IIQQQQQQ',elf,120)),[1,6,len(elf),0x400000+len(elf),0x400000+len(elf),0,0,4096],'empty static RW extent')
    same(list(struct.unpack_from('<IIQQQQQQ',elf,176)),[0x6474e551,6,0,0,0,0,0,16],'static nonexecuting stack')
    for name,image in images.items():need(elf.count(image)==1,'exact embedded image '+name)
    link=b.json('link.receipt.json');same(built.get('link'),link,'actual linker receipt')
    obj=b.data('bridge.o');frame=b'HIALNK01'+pack(1,6,0)+b'_start'+pack(len(obj))+obj
    need(b.data('link.input.bin')==frame,'complete actual link input/object')
    same([link.get('input_bytes'),link.get('input_sha256'),link.get('output_bytes'),link.get('output_sha256')],
        [len(frame),sha(frame),len(elf),sha(elf)],'actual full link input/output receipt')
    need(sha(e.data(link['manifest']))==link['manifest_sha256'],'actual linker identity')
    module_evidence(e,link['manifest'],history=False)
    processes=built.get('processes');need(type(processes)is list and len(processes)==2,'actual assembly/inspection processes')
    for name,row,argv,limit in zip(('assemble','readelf'),processes,(
        ['as','--64','-o',str(e.old['build']/'bridge.o'),str(e.old['build']/'combined.S')],
        ['readelf','-lW',str(e.old['build']/'bridge.elf')]),(60,30),strict=True):
        same(b.json(name+'.process.json'),row,'actual complete process receipt')
        process(row,argv,e.old['source'],limit)
        for stream in('stdout','stderr'):b.file(name+'.'+stream,row[stream])
        need(b.data(name+'.stderr')==b'','successful mechanical process stderr')
    need(b'INTERP'not in b.data('readelf.stdout')and b'RWE'not in b.data('readelf.stdout'),'no interpreter or writable executable segment')
    b.file('combined.S')
    return {'fresh_hia_images':19,'actual_static_linker_image':1,'fresh_cold':False,'executable':bytes_pin(elf)}

def combined_evidence(e):
    source=e.b['source']
    engine=source.data('scripts/view_call_engine.S').decode()
    allocator=engine[engine.index('view_allocate:\n'):engine.index('/* Actual partial writes.')]
    need(sha(allocator.encode())==e.built.get('allocator_closure_sha256'),'exact allocator source closure')
    helper=load(source.file('tests/hia_native/config_span/config_fixture.py'),'_config_span_composer')
    fixture=helper.combine(source.data('scripts/config_mcp_grow_adapter.S').decode(),
                           source.data('tests/hia_native/config_span/grow_fixture.S').decode())
    declaration=source.json('tests/hia_native/config_span/graph_sources.json')
    for row in declaration:
        name=row['name'];before='\n'+name+'_call_displacement:\n    .long 0'
        need(fixture.count(before)==1,'actual child call-displacement anchor')
        fixture=fixture.replace(before,'\n'+name+'_call_displacement:\n    .long grow_config_'+name+' - (. + 4)')
    text=source.data('tests/hia_native/config_span/grow_bridge.S').decode()+'\n'+source.data('scripts/runtime_mcp_workdir_io_bridge.S').decode()+'\n'+source.data('tests/hia_native/config_span/canonical_bridge.S').decode()+'\n'+fixture+'\n'+allocator
    marker='grow_fixture_images:\n    .zero 144';need(text.count(marker)==1,'fixed private image table')
    text=text.replace(marker,'grow_fixture_images:\n'+''.join('    .quad '+('grow_image_'+str(i)if i in(7,8,11)else'0')+'\n'for i in range(18)))
    for name in re.findall(r'^\.global ([A-Za-z_][A-Za-z_0-9]*)$',text,re.M):
        if name=='_start':continue
        alias=name+'_flat';text=text.replace('\n'+name+':','\n'+name+':\n'+alias+':')
        text=re.sub(r'\b(call|jmp) '+re.escape(name)+r'\b',lambda m:m[1]+' '+alias,text)
    for row in e.built['members'][17:]:
        path=Path(row['manifest']).parent/e.object(row['manifest'])['image']
        text+='\n.balign 16\ngrow_image_'+str(row['slot'])+':\n    .incbin '+json.dumps(str(path))+'\n'
    for row,decl in zip(e.built['members'][:17],declaration,strict=True):
        name=decl['name'];path=Path(row['manifest']).parent/e.object(row['manifest'])['image']
        text+='\n.balign 16\n'+('grow_image_11:\n'if name=='owner'else'')+'grow_config_'+name+':\n    .incbin '+json.dumps(str(path))+'\n'
    need(e.b['build'].data('combined.S')==text.encode(),'complete mechanical source/image composition')
    linker=e.object(e.built['link']['manifest'])
    need(linker['source_sha256']=='66063b0e8d9b244a8ccec27a31554fe8e77f309ac1fc981286e63befa7559cef','unchanged HIA static linker source')

def focused_processes(e):
    capture=e.b['capture'];old=e.old
    common=['--build',str(old['build']),'--build-sha256',e.source['build']['sha256']]
    declarations=[('guard','guard.py',['--oracle',str(old['guard_source'])]),('semantic','semantic.py',
        ['--reference-source',str(old['semantic_source']),'--loader-source',str(old['source'])]),
        ('state','state.py',['--support',str(old['producers']/'semantic.py'),'--loader-source',str(old['source'])]),
        ('lease','lease.py',[])]
    parent=capture.json('RESULT.json');same(parent.get('checks'),e.checks,'complete actual outer check list')
    wanted={'schema':'hepta.runtime.config-span-native-capture.v1','status':'PASS','actual_test_processes':4,
            'same_source_before_after':True,'build':e.source['build'],'fresh_cold':False,'new_rust_processes':0,
            'public_mcp_complete':False,'fresh_original_comparison_complete':False}
    same({k:parent.get(k)for k in wanted},wanted,'focused scope/result')
    elapsed(parent.get('elapsed_seconds'),180,'focused deadline')
    self_record=capture.json('remote-process.json')
    need(uint(self_record.get('pid'),'actual producer PID')>0,'actual producer identity')
    need(uint(self_record.get('parent_pid'),'actual parent PID')>0,'actual process parent')
    need(type(self_record.get('cgroup'))is str and self_record['cgroup'].endswith('\n'),'actual producer cgroup bytes')
    need(type(self_record.get('cwd'))is str and Path(self_record['cwd']).is_absolute(),'actual producer working directory')
    total=0;pids=[]
    for row,(name,script,extra)in zip(e.checks,declarations,strict=True):
        argv=[e.source['python'],'-I','-B',str(old['producers']/script),*common,*extra,'--output',str(old['capture']/name)]
        same(sorted(row),sorted(['name','command','cwd','environment','pid','timeout_seconds','timed_out','exit_code','elapsed_seconds','stdout','stderr']),'complete actual child receipt')
        process(row,argv,old['producers'],180);same(row['name'],name,'actual gate order')
        same(row['environment'],{'PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1'},'actual gate controlled environment')
        pids.append(row['pid']);total+=row['elapsed_seconds']
        out=capture.data(name+'.stdout',row['stdout']);need(capture.data(name+'.stderr',row['stderr'])==b'','actual gate stderr')
        result=capture.json(name+'/RESULT.json');summary=strict_json(out)
        expected={k:v for k,v in result.items()if k!=('groups'if name=='guard'else'artifacts')}
        same(summary,expected,'complete gate stdout/result')
        producer=capture.json(name+'/remote-process.json')
        same(producer.get('pid'),row['pid'],'actual executed child PID')
        same(producer.get('cgroup'),self_record['cgroup'],'same actual producer child cgroup')
    need(len(set(pids))==4 and self_record['pid']not in pids and total<=parent['elapsed_seconds'],'all actual child durations/PIDs')
    return {'actual_gate_processes':4,'actual_deadline_seconds':180,'actual_elapsed_seconds':parent['elapsed_seconds'],
            'actual_parent_pid':self_record['pid'],'actual_child_pids':pids}

def manifest_artifacts(binder,report,expected_names=None):
    rows=report.get('artifacts');need(type(rows)is dict,'complete artifact table')
    if expected_names is not None:same(sorted(rows),sorted(expected_names),'complete artifact set')
    for name,expected in rows.items():binder.file(name,expected)
def bound_source_table(e,rows,expected_names=None):
    need(type(rows)is dict,'complete producer source table')
    if expected_names is not None:same(sorted(rows),sorted(map(str,expected_names)),'complete producer input set')
    for path,expected in rows.items():e.mapped(path,expected)
def guard_reference(e):
    source=e.b['guard_source'];capture=e.b['capture'];prefix='guard/'
    for name,value in GUARD_SOURCE_PINS.items():source.file(name,value)
    factory=load(source.file('cases.py'),'_config_span_original_cases')
    reader=load(source.file('run.py'),'_config_span_original_output')
    provenance=capture.json(prefix+'original-provenance.json')
    fixture=e.old['capture']/'guard/fixtures'
    wanted={'schema':'hepta.runtime.config-span-guard-golden.v1','original_source':str(e.old['guard_source']),
            'fixture_root':str(fixture),'new_rust_processes':0,'fresh_original_comparison_complete':False,
            'retained_original_bytes_compared':True,'paths_replaced':False,'complete_cases':92}
    same({k:provenance.get(k)for k in wanted},wanted,'complete retained original scope')
    same(provenance.get('bound_files'),{str(e.old['guard_source']/n):v for n,v in GUARD_SOURCE_PINS.items()},'all original source inputs')
    cases=factory.iter_cases(fixture);need(len(cases)==92,'all retained original domains')
    stream=io.BytesIO();factory.encode(stream,cases);wire=stream.getvalue()
    need(capture.data(prefix+'complete-original-domain-input.bin')==wire,'complete current-path original domain input')
    raw=gzip.decompress(source.data('golden/responses.bin.gz'))
    need(len(raw)==15700 and sha(raw)=='2dd340cc7ad260df8f813456ee9f956e606615b989bec53e298d666ccf44ae49','complete frozen original output')
    need(capture.data(prefix+'complete-original-golden-output.bin')==raw,'complete retained original response bytes')
    same([provenance.get('input_bytes'),provenance.get('input_sha256'),provenance.get('response_bytes'),provenance.get('response_sha256')],
         [len(wire),sha(wire),len(raw),sha(raw)],'complete original byte identities')
    observations=reader.parse_output(raw,cases)
    return {'schema':'hepta.runtime.config-span-retained-original.v1','cases':92,'observations':observations,
            'complete_input_bytes':len(wire),'complete_input_sha256':sha(wire),
            'complete_output_bytes':len(raw),'complete_output_sha256':sha(raw),
            'source_files':GUARD_SOURCE_PINS,'new_rust_processes':0,'fresh_original_comparison_complete':False,
            'retained_original_bytes_compared':True,'paths_replaced':False}

def guard_evidence(e,original):
    c=e.b['capture'];prefix='guard/';r=c.json(prefix+'RESULT.json')
    helper=load(e.b['producers'].file('guard.py'),'_config_span_graph_trace')
    factory=load(e.b['guard_source'].file('cases.py'),'_config_span_guard_cases')
    fixture=e.old['capture']/'guard/fixtures'
    cases=factory.iter_cases(fixture);observed=original['observations'];buckets={};excluded=[]
    for case,observation in zip(cases,observed,strict=True):
        reason=None
        if not case['source'].startswith(b'/'):reason='source is outside the resolved absolute guard ABI'
        elif case['operation']==1:
            for root in case['roots']:
                if not root.startswith(b'/'):reason='root is outside installed absolute configuration ABI';break
                try:root.decode('utf-8')
                except UnicodeDecodeError:reason='private raw PathBuf root cannot be supplied by UTF-8 JSON configuration';break
        if reason:excluded.append({'case_id':case['case_id'],'name':case['name'],'reason':reason,'original':observation});continue
        key=None if case['operation']==2 else tuple(case['roots'])
        buckets.setdefault(key,[]).append((case,observation))
    need(len(buckets)==34 and sum(map(len,buckets.values()))==81 and len(excluded)==11,'all selected/excluded original domains')
    provenance=c.json(prefix+'original-provenance.json')
    same(provenance.get('excluded'),excluded,'complete preserved private ABI observations')
    bound_source_table(e,provenance['bound_files'])
    same([provenance['original_source'],provenance['fixture_root'],provenance['new_rust_processes'],provenance['selected_cases']],
         [str(e.old['guard_source']),str(fixture),0,81],'original provenance/scope')
    excluded_ids={60028,60029,60030,60044,60045,60046,60080,60081,60082,60089,60090}
    same(sorted(row['case_id']for row in excluded),sorted(excluded_ids),'all private excluded case identities')
    same(sorted(case['case_id']for pairs in buckets.values()for case,_ in pairs),sorted(set(range(60000,60092))-excluded_ids),'all selected case identities')
    before=c.json(prefix+'filesystem-before.json');after=c.json(prefix+'filesystem-after.json')
    fixture_reader=load(e.b['guard_source'].file('strict_reference.py'),'_config_span_owned_fixture')
    host=c.json(prefix+'remote-process.json')
    for key in ('uid','euid','gid','egid'):need(uint(host.get(key),'fixture '+key)>0,'unprivileged actual fixture process')
    same(host.get('cwd'),str(e.old['producers']),'actual fixture producer working directory')
    fixture_reader.fixture_evidence(before,after,factory,host)
    same(after,before,'actual complete before/after state')
    source=c.json(prefix+'SOURCE.json')
    same([source.get('producer'),source.get('build'),source.get('binary')],
        [PRODUCER_PINS['guard.py'],e.source['build'],e.b['build'].artifacts['bridge.elf']],'actual guard producer/build identity')
    expected_inputs={**e.built['sources']}
    for row in e.built['members']:
        for path in(row['source'],row['manifest'],str(Path(row['manifest']).parent/e.object(row['manifest'])['image'])):
            expected_inputs[path]=file_pin(e.mapped(path))
    same(source.get('inputs'),expected_inputs,'guard complete native source/build binding')
    processes=c.json(prefix+'processes.json');need(type(processes)is list and len(processes)==34,'all actual guard processes')
    groups=[];totalcalls=totalchildren=0;groupids={};pids=[];allgrowth=[]
    for i,((roots,pairs),process_row)in enumerate(zip(buckets.items(),processes,strict=True)):
        name='group-%03d'%i;folder=e.old['capture']/prefix/name;relative=prefix+name+'/'
        argv=[str(e.old['build']/'bridge.elf')]
        if roots is not None:
            conf=json.dumps({'state_dir':str(folder/'state'),'controller_workspace_roots':[x.decode()for x in roots],
                'hosts':{'h':{'ssh_target':'target','remote_state_dir':'/remote'}}},ensure_ascii=False,separators=(',',':')).encode()
            need(c.data(relative+'config.json')==conf,'complete actual configuration bytes')
            argv+=['--runtime-config',str(folder/'config.json')]
        command=['/usr/bin/strace','-qq','-f','-s','0','-xx','-o',str(folder/'kernel.trace'),'-e',
            'trace=readlink,readlinkat,newfstatat,statx,openat,close,write,getcwd,fcntl,mmap,mremap,munmap',*argv]
        process(process_row,command,fixture,60);pids.append(process_row['pid'])
        same([process_row.get('name'),process_row.get('executable_command'),process_row.get('env')],[name,argv,{'PATH':''}],'actual guard process domain')
        for kind,file in(('stdin','input.bin'),('stdout','stdout'),('stderr','stderr'),('kernel_trace','kernel.trace')):
            c.file(relative+file,process_row[kind])
        frames=[b'HFDMGQ02'+pack(1,len(case['source']))+case['source']for case,_ in pairs]
        wire=b''.join(pack(7,len(f))+f for f in frames);need(c.data(relative+'input.bin')==wire,'complete actual native input')
        raw=c.data(relative+'stdout');at=0;rows=[];totals=[0]*6
        for (case,observation),frame in zip(pairs,frames,strict=True):
            need(len(raw)-at>=96 and raw[at:at+8]==b'HRGFR002','complete actual reply header')
            header=raw[at:at+96];at+=96;size=qword(header,24)
            need(48<=size<=len(raw)-at and(qword(header,8),qword(header,16))==(7,48),'actual reply domain/extent')
            body=raw[at:at+size];at+=size;need(body[:8]==b'HFDMGR02'and qword(body,40)==0,'actual guard response ABI')
            status,errno,shortlen,chainlen=struct.unpack_from('<4Q',body,8)
            need(size==48+shortlen+chainlen,'complete short/chain extent')
            short=observation['short']['text'].encode();chain=observation['chain']['text'].encode();want_errno=observation['errno']
            if not observation['errno_present']and chain==short+b': file name contained an unexpected NUL byte':want_errno=65536
            same([status,errno],[observation['status'],want_errno],'full original guard status/errno')
            need(body[48:48+shortlen]==short and body[48+shortlen:]==chain,'complete original short/chain bytes')
            counters=list(struct.unpack_from('<6Q',header,32));totals=[x+y for x,y in zip(totals,counters)]
            rows.append({'case_id':case['case_id'],'input_bytes':len(frame),'input_sha256':sha(frame),'full_body_bytes':len(body),'full_body_sha256':sha(body),
                'status':status,'errno':errno,'short_bytes':shortlen,'chain_bytes':chainlen,'counters':counters})
        need(at==len(raw),'no extra native output')
        same(c.json(relative+'cases.json'),rows,'full native case index')
        trace=helper.trace_summary(c.file(relative+'stderr'),rows)
        trace['configuration_growth_kernel']=helper.growth_kernel(c.file(relative+'kernel.trace'),trace['configuration_growth'])
        groups.append({'name':name,'cases':len(rows),'counters':totals,'trace':trace})
        groupids[name]=[case['case_id']for case,_ in pairs];totalcalls+=totals[0];totalchildren+=totals[3];allgrowth.extend(trace['configuration_growth'])
    same(provenance.get('groups'),groupids,'all original groups and input order');need(len(set(pids))==34,'all actual guard PIDs')
    same(r.get('groups'),groups,'recomputed actual native/ACK/effect sequence')
    expected={'status':'PASS','original_cases_compared':81,'selected_cases':81,'excluded_private_abi_observations':11,
        'public_handler_complete':False,'whole_runtime_replaced':False,'fresh_original_comparison_complete':False,
        'retained_original_bytes_compared':True,'failed_groups':[],'cases':81,'actual_elf_processes':34,
        'actual_native_calls':totalcalls,'actual_child_executions':totalchildren,'fixture_before_after_equal':True,'binary_unchanged':True}
    same({k:r.get(k)for k in expected},expected,'recomputed complete guard counts')
    elapsed(r.get('elapsed_seconds'),180,'actual guard gate duration')
    need({60084,60085}.issubset({case['case_id']for group in buckets.values()for case,_ in group}),'both former config capacity failures retained')
    return {**expected,'configuration_growth_records':len(allgrowth),'kernel_trace_string_limit':0,
            'kernel_write_payloads_complete':False,'complete_stdio_retained':True,'new_rust_processes':0,'live_fixture_required':False}

SEMANTIC_INPUTS={
'scripts/config_schema.py':{'bytes':5675,'sha256':'08d824139f405928b7f30f264158d4756d67daf7d8997aa97bff6e5b0601a6dc'},
'tests/hia_native/config_runtime_original_output.txt.gz':{'bytes':44442,'sha256':'f5877a95b5b85496f94769dcbb1f53ff28acc08dcb70dab0239fade81df7fe0d'},
'tests/hia_native/config_semantics_cases.py':{'bytes':12309,'sha256':'f5115730d8c6f05611371dab40ad3c23c589ac081e45b0571ee4db086a58fe01'},
'tests/hia_native/config_typed_cases.py':{'bytes':6036,'sha256':'0446d2d61b67c92ff2206a32035d6d9e019a55c9752d488c78a486ef59a3581e'}}
SEMANTIC_COUNTS={'actual_child_executions':50,'actual_native_calls':14656,'output_growth':4134,'workspace_growth':6,
    'slot_10':5,'slot_11':2,'slot_12':4,'slot_13':6,'slot_15':48,'slot_2':11334,'slot_3':3236,'slot_4':21}
class SemanticCalls:
    def __init__(self,raw,index):
        self.raw=gzip.open(raw,'rb');self.index=index.open('rb');self.offset=0;self.sequence=0
        self.caps={2:0,3:0,4:32<<20,10:256<<20,11:65536,12:256<<20,13:256<<20,14:32<<20,15:256<<20}
        self.sequences=Counter();self.counts=Counter();self.events=[]
    def record(self):
        header=exact(self.raw,88);need(header[:8]==b'HRCALL02','complete native semantic record magic')
        seq,case,slot,depth,code,wcap,ocap,n,o,f=struct.unpack_from('<10Q',header,8)
        self.sequence+=1;need(seq==self.sequence,'native semantic sequence')
        need(slot in self.caps and depth<=3 and code<=0xffffffff,'native semantic domain')
        wire,output,footer=exact(self.raw,n),exact(self.raw,o),exact(self.raw,f)
        record=header+wire+output+footer
        row={'sequence':seq,'case_id':case,'slot':slot,'depth':depth,'code':code,'workspace_capacity':wcap,'output_capacity':ocap,
             'offset':self.offset,'bytes':len(record),'sha256':sha(record),'input_bytes':n,'input_sha256':sha(wire),
             'output_bytes':o,'output_sha256':sha(output),'footer_bytes':f,'footer_sha256':sha(footer)}
        line=self.index.readline();need(line.endswith(b'\n'),'complete semantic index line');same(strict_json(line),row,'full semantic call/index bytes')
        self.offset+=len(record);self.counts['actual_native_calls']+=1;self.counts['slot_'+str(slot)]+=1
        need(wcap==self.caps[slot],'persistent actual workspace capacity')
        need(o==(code if code<0xffff0000 else 32 if code==GROW else 0)and f==(120 if code==CHILD else 0),'complete native returned extent/footer')
        need(code>=0xffff0000 or code<=ocap,'native result outside output borrow')
        return row,wire,output,footer
    def call(self,case,slot,wire,ocap,depth=0,expected_input_length=None):
        while True:
            row,actual,output,footer=self.record()
            same([row['case_id'],row['slot'],row['depth'],row['output_capacity']],[case,slot,depth,ocap],'actual recursive native call domain')
            if wire is None:
                need(expected_input_length==len(actual),'child full input span size');wire=actual
            need(actual==wire,'same complete continuation input')
            code=row['code']
            if code==GROW:
                kind,needed=common_growth(output);need(slot in(2,3)and kind in(1,2),'semantic growth domain')
                if kind==2:return code,output
                old=self.caps[slot];new=max(4096,old)
                while new<needed:new*=2
                need(old<needed<=new<1<<63,'strict work growth')
                self.caps[slot]=new;self.counts['workspace_growth']+=1
                self.events.append({'kind':'grow','slot':slot,'old':old,'required':needed,'new':new,'sequence':self.sequence});continue
            if code!=CHILD:return code,output
            action=struct.unpack('<15Q',footer);edges={3:{15},15:{10,12,13,14},10:{11},12:{11},14:{11}}
            need(footer[:8]==b'HIACAL01'and action[2]in edges.get(slot,set()),'actual source-owned edge')
            need(action[1]==self.sequences[slot]+1 and action[3]==action[6]==2 and not any(action[9:]),'fresh child exactly once')
            self.sequences[slot]=action[1];limit=self.caps[slot]-256
            ia,ilen,oa,olen=action[4],action[5],action[7],action[8]
            need(ia<=limit and ilen<=limit-ia and oa<=limit and olen<=limit-oa,'complete private child spans')
            need(not ilen or not olen or ia+ilen<=oa or oa+olen<=ia,'disjoint actual child spans')
            child_code,child_output=self.call(case,action[2],None,olen,depth+1,ilen)
            need(child_code!=GROW,'unchanged regex private carrier')
            self.counts['actual_child_executions']+=1
            self.events.append({'kind':'completion','parent':slot,'child':action[2],'sequence':action[1],
                'code':child_code,'child_output_sha256':sha(child_output),'after_call':self.sequence})
    def invoke(self,case,slot,wire):
        outcap=32
        while True:
            code,body=self.call(case,slot,wire,outcap)
            if code!=GROW:return code,body
            _,needed=common_growth(body,2);new=max(4096,outcap)
            while new<needed:new*=2
            need(outcap<needed<=new<1<<63,'strict output growth')
            self.counts['output_growth']+=1;self.events.append({'kind':'output-grow','slot':slot,'old':outcap,'required':needed,'new':new,'sequence':self.sequence})
            outcap=new
    def close(self):
        need(self.raw.read(1)==b''and self.index.read(1)==b'','complete semantic raw/index EOF')
        self.raw.close();self.index.close()
def semantic_evidence(e):
    c=e.b['capture'];b=Binder(c.root/'semantic','semantic');r=b.json('RESULT.json')
    names=['SOURCE.json','calls.bin.gz','calls.jsonl','events.json','remote-process.json','semantic-output.txt',
           'semantic-requests.hex','typed-output.txt','typed-refusal-original-observations.json','typed-requests.hex']
    manifest_artifacts(b,r,names)
    rows=b.json('SOURCE.json');bound_source_table(e,rows)
    need(len(rows)==7,'all semantic producer inputs')
    e.b['source'].file('scripts/hia_native_loader.py',{'bytes':12787,'sha256':'58e2fe0492379340d7471a7857e1aa5de1a9a5d1e37a118852278b131bb1fe06'})
    reference=e.b['semantic_source']
    for name,pin in SEMANTIC_INPUTS.items():reference.file(name,pin)
    before=list(sys.path);sys.path[:0]=[str(reference.root/'scripts'),str(reference.root/'tests/hia_native')]
    try:
        typed=load(reference.file('tests/hia_native/config_typed_cases.py'),'_config_span_typed_cases').cases()
        semantics=load(reference.file('tests/hia_native/config_semantics_cases.py'),'_config_span_semantic_cases').cases()
    finally:sys.path[:]=before
    need(len(typed)==6491 and len(semantics)==2063,'all retained original cases')
    for name,cases in(('typed',typed),('semantic',semantics)):
        need(b.data(name+'-requests.hex')==b''.join(wire.hex().encode()+b'\n'for _,wire in cases),'regenerated complete original '+name+' input')
    original=gzip.decompress(reference.data('tests/hia_native/config_runtime_original_output.txt.gz'))
    need(sha(original)=='f749e18917afe6cc798749dd09418bd0682bec2dde92863c4548b26a4f583cbc','complete retained original semantic output')
    calls=SemanticCalls(b.file('calls.bin.gz'),b.file('calls.jsonl'));results=[]
    for index,(_,wire)in enumerate(typed):
        code,body=calls.invoke(index,2,wire);results.append(f'{code:08x}:'.encode()+body.hex().encode()+b'\n')
    output=b''.join(results);need(b.data('typed-output.txt')==output and sha(output)=='7d72f4df20f45a0b2317782dec628048360a79b724d008231d5f6a46439fb9f7','complete actual typed native output')
    results=[];refusals=[]
    for index,((category,wire),expected)in enumerate(zip(semantics,original.split(b'\n')[:-1],strict=True)):
        cid=10000+index;op=qword(wire,8);parse=wire[:8]+pack(2)+wire[16:];code,arena=calls.invoke(cid,2,parse)
        if code==INVALID:
            need(expected.startswith(b'ffffffff:'),'original typed refusal status')
            refusals.append({'case_id':cid,'category':category,'full_original':expected.decode('ascii'),'native_diagnostic_text_owned':False})
            actual=b'ffffffff:';expected=b'ffffffff:'
        else:
            need(code<0xffff0000,'successful actual JSON arena')
            request=(b'HRCFGI01'if op==4 else b'HRCFGV01')+pack(1 if op==4 else op,len(arena))+arena
            code,body=calls.invoke(cid,4 if op==4 else 3,request);need(code<0xffff0000,'complete actual semantic result')
            if op==4:actual=b'00000000:'+body.hex().encode()
            else:
                need(body[:8]==b'HRCFGR01'and qword(body,24)==len(body)-32,'complete validation body')
                actual=f'{qword(body,8):08x}:'.encode()+body[32:].hex().encode()
        need(actual==expected,'complete original semantic bytes at '+str(cid));results.append(actual+b'\n')
    calls.close();output=b''.join(results)
    need(b.data('semantic-output.txt')==output and sha(output)=='2432dc5bd65694895ddb055a72d59126bd031087a88fb7ba8d838107b4be8748','complete semantic native output')
    same(b.json('typed-refusal-original-observations.json'),refusals,'retained original diagnostic excluded domain')
    same(b.json('events.json'),calls.events,'all actual growth and child completion events')
    same(dict(calls.counts),SEMANTIC_COUNTS,'derived native call domain counts')
    expected={'status':'PASS','typed_cases':6491,'semantic_cases':2063,'actual_hia_counts':dict(calls.counts),
              'new_rust_processes':0,'retained_original_bytes_compared':True,'actual_filesystem_effects':0,
              'test_only_native_bridge':True,'public_mcp_complete':False}
    same({k:r.get(k)for k in expected},expected,'complete semantic scope/result');elapsed(r.get('elapsed_seconds'),180,'actual semantic duration')
    for name,value in b.artifacts.items():c.artifacts['semantic/'+name]=value
    return {**expected,'typed_refusal_diagnostic_text_owned':False,'complete_original_diagnostic_observations':len(refusals)}

STATE_GROUPS=[
('framing-and-complete-refusal-buffers',16),('completed-json-output-growth',4),
('validation-completion-and-corrupt-ack',19),('owner-completed-reply-growth',5),
('owner-retained-child-delivery-and-region-relocation',4),('fs-completion-growth-close-lifetime',11),
('fs-sequence-resource-preflight',1)]
STATE_TAIL=[
('json','json-first-output-growth',GROW),('json','json-cached-operation-mismatch',INVALID),
('json','json-repeat-short-output',GROW),('json','json-complete-cached-arena',2368),
('validation','validation-actual-child-request',CHILD),
*[('validation','validation-corrupt-ack-'+str(i),INVALID)for i in range(15)],
('validation','validation-error-output-growth',GROW),('validation','validation-repeat-output-growth',GROW),
('validation','validation-cached-error-complete',89),
('owner','owner-real-absent-init',0),('owner','owner-absent-output-growth',GROW),
('owner','owner-repeat-short-cached-output',GROW),('owner','owner-cached-reply-complete',94),('owner','owner-repeat-installed-read',94),
('owner','owner-real-configure-first-child',CHILD),('owner','owner-completed-read-needs-growth',GROW),
('owner','owner-repeat-unmapped-growth',GROW),('owner','owner-resume-completed-read-once',CHILD),
('fs','fs-actual-open-request',EFFECT),('fs','fs-completed-open-work-growth',GROW),
('fs','fs-repeat-unmapped-open-growth',GROW),('fs','fs-resume-open-once',EFFECT),
('fs','fs-completed-read-next-window-growth',GROW),('fs','fs-repeat-unmapped-read-growth',GROW),
('fs','fs-resume-read-once',EFFECT),('fs','fs-eof-close-request',EFFECT),
('fs','fs-closed-read-output-growth',GROW),('fs','fs-repeat-closed-output-growth',GROW),
('fs','fs-complete-read-after-growth',65600),('fs','fs-next-effect-sequence-overflow',GROW)]
def state_declarations():
    out=[]
    for owner in('json','validation','fs','owner'):
        out.extend((owner,'malformed-'+owner+'-'+str(n),INVALID)for n in(0,1,152))
        out.append((owner,'short-output-'+owner,CAPACITY))
    return out+STATE_TAIL
JSON_DATA=b'{"state_dir":"/s","hosts":{"h":{"ssh_target":"h","remote_state_dir":"/r","privileged_actions":{"a":{"executable":"/x","allow_extra_args":true,"extra_arg_patterns":["a"]}}}}}'
JSON_WIRE=b'HRCFGJ01'+pack(2,100,2,len(JSON_DATA))+b'/s'+JSON_DATA
def state_before(name,owner,ob,wb,context):
    fresh={'json-first-output-growth','validation-actual-child-request','owner-real-absent-init',
           'owner-real-configure-first-child','fs-actual-open-request'}
    if name.startswith(('malformed-','short-output-')):return
    if name in fresh:
        expected=bytearray(len(wb))
        if name=='owner-real-absent-init':expected[len(wb)-136:len(wb)-128]=pack(4)
        need(wb==expected and ob==bytes(len(ob)),'fresh complete actual private buffers');return
    last_owner,last_name,last_wire,last_out,last_work=context['last']
    need(last_owner==owner,'actual private owner continuity')
    need(len(wb)>=len(last_work)and len(ob)>=len(last_out),'private borrow never shrinks')
    need(ob==last_out+bytes(len(ob)-len(last_out)),'complete output continuation/relocation')
    if name.startswith('validation-corrupt-ack-')or name=='validation-error-output-growth':return
    expected=bytearray(last_work+bytes(len(wb)-len(last_work)))
    footer=len(wb)-256
    if name=='owner-absent-output-growth':expected[footer+120:footer+128]=pack(1)
    if name=='owner-completed-read-needs-growth':
        expected[footer+80:footer+136]=pack((2<<20)+67,context['owner_sequence'],1,0,1,0,(2<<20)+67)
    if name=='fs-completed-open-work-growth':expected[576:608]=pack(context['fs_sequence'],0,17,0)
    if name=='fs-completed-read-next-window-growth':
        at=qword(expected,552);expected[at:at+65536]=b'Z'*65536
        expected[576:608]=pack(context['fs_sequence'],0,65536,0)
    if name in('fs-eof-close-request','fs-closed-read-output-growth'):
        expected[576:608]=pack(context['fs_sequence'],0,0,0)
    if name=='fs-next-effect-sequence-overflow':
        expected[8:24]=pack(60,U64)
        expected[512:608]=pack(3544404732657488456,U64,12,0,0,8454144,2,0,U64,0,17,0)
        expected[152:160]=pack(0)
    need(wb==expected,'complete retained workspace/explicit synthetic ACK')
def state_record(row,parts,expected,context):
    label,wire,ob,wb,oa,wa=parts;owner,name,code=expected
    need(label==name.encode()and row['owner']==owner,'fixed private control name/owner')
    same(row['code'],code,'actual private control return')
    need(len(ob)==len(oa)and len(wb)==len(wa),'unchanged actual mutable borrow sizes')
    refusal=code in(INVALID,CAPACITY)
    same(row.get('expected_code'),code,'fixed expected private result')
    same(row.get('both_buffers_unchanged_required'),refusal,'mandatory complete refusal buffers')
    if refusal:need(ob==oa and wb==wa,'complete refusal output/workspace unchanged')
    state_before(name,owner,ob,wb,context)
    if code==GROW:
        kind,needed=common_growth(oa)
        need(oa[32:]==ob[32:],'growth writes only fixed record')
        if kind==1:need(needed>len(wb),'workspace growth required extent')
        elif kind==2:need(needed>len(ob),'output growth required extent')
        else:need(needed==0 and wb==wa,'resource refusal preserves pending workspace')
        context['required']=needed
    if name.startswith('malformed-'):
        n=int(name.rsplit('-',1)[1]);need(wire==({0:b'',1:b'x',152:b'WRONG000'+bytes(144)}[n]),'exact malformed wire')
        need(wb==b'\x5a'*len(wb)and ob==b'\xa5'*len(ob),'full refusal sentinels')
    elif name.startswith('short-output-'):
        want=b'HRCFGV01'+pack(1,128)+bytes(128)if owner=='validation'else b''
        need(wire==want and len(ob)==(31 if owner in('json','owner')else 0),'exact short-borrow control')
    elif owner=='json':
        want=JSON_WIRE[:8]+pack(1)+JSON_WIRE[16:]if name=='json-cached-operation-mismatch'else JSON_WIRE
        need(wire==want,'complete JSON cached request')
        if name=='json-first-output-growth':need(qword(wa,192)==1,'completed parse cache')
        if name=='json-repeat-short-output':need(wb==wa,'repeated short output did not reparse')
        if name=='json-complete-cached-arena':
            need(oa[:8]==b'HRCFGA01'and qword(wa,192)==0 and code==len(oa),'complete cached arena');context['arena']=oa
    elif owner=='validation':
        need(wire==b'HRCFGV01'+pack(1,len(context['arena']))+context['arena'],'complete validation input')
        footer=len(wb)-256
        if name=='validation-actual-child-request':
            need(wa[footer:footer+8]==b'HIACAL01'and qword(wa,footer+16)==15,'actual regex child selected')
            context['regex_sequence']=qword(wa,footer+8);template=bytearray(wa)
            template[122880:122912]=b'HRGREX01'+pack(0,1,0);template[footer+80:footer+112]=pack(32,context['regex_sequence'],1,0)
            context['completed_regex']=bytes(template)
        elif name.startswith('validation-corrupt-ack-'):
            index=int(name.rsplit('-',1)[1]);template=bytearray(context['completed_regex'])
            struct.pack_into('<Q',template,footer+8*index,qword(template,footer+8*index)^1)
            need(wb==template,'exact one-field corrupt completion')
        elif name=='validation-error-output-growth':
            template=bytearray(context['completed_regex']);template[122880:122912]=b'HRGREX01'+pack(1,0,0)
            need(wb==template and qword(wa,81928)==2,'actual completed regex preserved before parent output growth')
        elif name=='validation-repeat-output-growth':need(wb==wa,'completed regex not executed again')
        else:
            message=b'host `h` privileged action `a` has invalid argument regex'
            need(oa[:8]==b'HRCFGR01'and qword(oa,24)==len(message)and oa[32:]==message and qword(wa,81936)==context['regex_sequence']and qword(wa,81928)==0,'complete cached regex error and sequence')
    elif owner=='owner':
        footer=len(wb)-256
        if name=='owner-real-absent-init':
            need(wire==b''and qword(wb,footer+120)==4,'real native absent initialization')
        elif name in('owner-absent-output-growth','owner-repeat-short-cached-output','owner-cached-reply-complete','owner-repeat-installed-read'):
            need(wire==b'HRCFGQ01'+pack(7,0),'actual same installed owner query')
            if name=='owner-repeat-short-cached-output':need(wb==wa,'cached owner reply retry')
            if code<0xffff0000:need(oa==b'HRCFGM01'+pack(1,9,62)+b'runtime tools are disabled; start with --runtime-config <file>','full absent-config original error')
        elif name=='owner-real-configure-first-child':
            need(wire==b'HRCFGC01'+pack(0,17,0,0,0,0,0)+b'/synthetic-config','real startup input')
            need(wa[footer:footer+8]==b'HIACAL01'and qword(wa,footer+16)==1 and qword(wa,8)==10,'first actual native child is config filesystem')
            context['owner_sequence']=qword(wa,footer+8)
        else:
            payload=b' '*((2<<20)+3);want=b'HRCFSR01'+pack(0,0,0,0,len(payload),0,0)+payload
            need(wire==want,'complete retained child output including wide bytes')
            if name=='owner-repeat-unmapped-growth':need(wb==wa,'completed child retained at repeated growth')
            if name=='owner-resume-completed-read-once':
                footer=len(wa)-256
                need(qword(wa,footer+16)==2 and qword(wa,footer+8)==context['owner_sequence']+1 and qword(wa,footer+112)==0,'completed read delivered once')
                at,n=qword(wa,footer+32),qword(wa,footer+40);need(at<=len(wa)-256 and n<=len(wa)-256-at,'actual relocated child span')
                child=wa[at:at+n];need(child[:8]==b'HRCFGJ01'and child[40+qword(child,24):]==payload,'complete growth relocation preserves delivered bytes')
    elif owner=='fs':
        need(wire==b'HRCFSQ01'+pack(3,2)+b'/x','fixed actual filesystem owner input')
        if name=='fs-actual-open-request':
            need(qword(wa,528)==12,'source-owned open request');context['fs_sequence']=qword(wa,16)
        elif name=='fs-completed-open-work-growth':
            need(qword(wb,576)==context['fs_sequence']and qword(wb,592)==17,'complete synthetic open ACK')
            need(qword(wa,152)==0 and qword(wa,16)==context['fs_sequence'],'open ACK custody before growth')
        elif name in('fs-repeat-unmapped-open-growth','fs-repeat-unmapped-read-growth','fs-repeat-closed-output-growth'):
            need(wb==wa,'completed effect is not consumed twice')
        elif name=='fs-resume-open-once':
            need(qword(wa,16)==context['fs_sequence']+1 and qword(wa,152)==17 and qword(wa,528)==13,'one next read after completed open')
            context['fs_sequence']=qword(wa,16)
        elif name=='fs-completed-read-next-window-growth':
            need(qword(wb,576)==context['fs_sequence']and qword(wb,592)==65536,'complete synthetic read ACK')
            need(qword(wa,160)==0 and qword(wa,16)==context['fs_sequence'],'read ACK unchanged before next window allocation')
        elif name=='fs-resume-read-once':
            need(qword(wa,160)==65536 and qword(wa,16)==context['fs_sequence']+1,'one completed read counted')
            context['fs_sequence']=qword(wa,16)
        elif name=='fs-eof-close-request':
            need(qword(wb,576)==context['fs_sequence']and qword(wb,592)==0,'actual EOF completion')
            need(qword(wa,528)==11 and qword(wa,536)==17 and qword(wa,16)==context['fs_sequence']+1,'one owned close after EOF')
            context['fs_sequence']=qword(wa,16)
        elif name=='fs-closed-read-output-growth':
            need(qword(wb,576)==context['fs_sequence']and qword(wa,152)==0,'completed close releases fd before output growth')
        elif name=='fs-complete-read-after-growth':
            need(oa[:8]==b'HRCFSR01'and qword(oa,40)==65536 and oa[64:]==b'Z'*65536 and qword(wa,16)==context['fs_sequence']and qword(wa,8)==0,'full completed read/cleanup')
        elif name=='fs-next-effect-sequence-overflow':
            common_growth(oa,3,0);need(qword(wb,16)==U64 and qword(wb,152)==0 and wb==wa,'whole pending sequence-overflow workspace')
    context['last']=(owner,name,wire,oa,wa)
def state_evidence(e):
    c=e.b['capture'];b=Binder(c.root/'state','state');r=b.json('RESULT.json')
    manifest_artifacts(b,r,['SOURCE.json','buffers.bin.gz','calls.jsonl','groups.json','remote-process.json'])
    bound_source_table(e,b.json('SOURCE.json'))
    same(b.json('groups.json'),[{'name':name,'native_calls':n}for name,n in STATE_GROUPS],'all private control groups')
    rows=[strict_json(line)for line in b.data('calls.jsonl').split(b'\n')if line]
    declarations=state_declarations();need(len(rows)==len(declarations)==60,'all actual state calls')
    offset=0;context={};counts=Counter()
    with gzip.open(b.file('buffers.bin.gz'),'rb')as stream:
        for index,(row,expected)in enumerate(zip(rows,declarations,strict=True),1):
            header=exact(stream,72);need(header[:8]==b'HRCST002','full state record magic')
            seq,code,*sizes=struct.unpack_from('<8Q',header,8);need(seq==index,'state actual sequence')
            parts=[exact(stream,n)for n in sizes];raw=header+b''.join(parts)
            actual={'sequence':index,'owner':expected[0],'label':expected[1],'offset':offset,'bytes':len(raw),'sha256':sha(raw),'code':code,
                'expected_code':expected[2],'both_buffers_unchanged_required':code in(INVALID,CAPACITY),'parts':[bytes_pin(part)for part in parts]}
            same(row,actual,'complete state call/index and both full buffers')
            state_record(row,parts,expected,context);offset+=len(raw);counts[str(code)]+=1
        need(stream.read(1)==b'','complete state raw EOF')
    expected={'status':'PASS','groups':7,'actual_native_calls':60,'complete_mutable_buffers':True,'synthetic_private_completions':True,
              'actual_filesystem_effects':0,'original_semantic_cases_added':0}
    same({k:r.get(k)for k in expected},expected,'actual state scope/result');elapsed(r.get('elapsed_seconds'),180,'actual state duration')
    for name,value in b.artifacts.items():c.artifacts['state/'+name]=value
    return {**expected,'return_counts':dict(counts)}

def parse_receipts(raw):
    at=0;rows=[]
    sizes={b'HRCGRO02':80,b'HRGTR002':224,b'HRCNAK02':128,b'HWDIOAK2':160}
    while at<len(raw)and raw[at:at+8]in sizes:
        size=sizes[raw[at:at+8]];need(size<=len(raw)-at,'complete actual stderr receipt')
        rows.append((at,raw[at:at+size]));at+=size
    return rows,raw[at:]
def growth_receipts(rows,kernel,allow_enomem=False):
    capacities=[16<<20,32<<20,65536,65536,65536,262144];pointers={};derived=[];expected_calls=[];failed=0
    for offset,raw in rows:
        if raw[:8]!=b'HRCGRO02':continue
        seq,descriptor,selector,old,needed,new,result,oldptr,newptr=struct.unpack_from('<9Q',raw,8)
        need(seq==len(derived)+1 and descriptor<6 and selector<5,'actual configuration growth order/descriptor')
        need(old==capacities[descriptor]and old<needed and oldptr>0 and oldptr%4096==0,'actual owned growth capacity/pointer')
        if descriptor in pointers:need(oldptr==pointers[descriptor],'same owned mapping across growth')
        attempted=old
        while attempted<needed:attempted*=2
        need(attempted<1<<63,'representable actual mechanical growth')
        if result>>63:
            need(allow_enomem and result==U64-11 and new==old and newptr==oldptr,'actual failed resize preserves custody')
            failed+=1;expected_calls.append((oldptr,old,attempted,-12))
        else:
            need(result==newptr and newptr>0 and newptr%4096==0 and new==attempted,'exact actual mremap success')
            expected_calls.append((oldptr,old,attempted,newptr));capacities[descriptor]=new;pointers[descriptor]=newptr
        derived.append({'offset':offset,'record':[seq,descriptor,selector,old,needed,new,result,oldptr,newptr]})
    actual=[]
    pattern=re.compile(r'mremap\((0x[0-9a-f]+), ([0-9]+), ([0-9]+), MREMAP_MAYMOVE\)\s+= (0x[0-9a-f]+|-1 ENOMEM[^\n]*)')
    for m in pattern.finditer(kernel):
        a,b,c,d=m.groups();actual.append((int(a,16),int(b),int(c),-12 if d.startswith('-1')else int(d,16)))
    at=0
    for expected in expected_calls:
        while at<len(actual)and actual[at]!=expected:at+=1
        need(at<len(actual),'actual kernel growth receipt tuple');at+=1
    same(failed,1 if allow_enomem else 0,'all actual ENOMEM outcomes')
    return derived,capacities,{'recorded_growth':len(derived),'actual_mremap_calls':len(actual),'actual_enomem':failed,'ordered_all_bound':True}
def complete_stderr_writes(kernel,stderr):
    parts=[]
    for line in kernel.splitlines():
        if 'write(2,'not in line:continue
        m=re.fullmatch(r'\d+\s+write\(2, "((?:\\x[0-9a-f]{2})*)", (\d+)\)\s+= (\d+)',line)
        need(m is not None,'complete bounded kernel stderr write')
        raw=bytes.fromhex(m[1].replace('\\x',''));asked,got=int(m[2]),int(m[3])
        need(asked==len(raw)and 0<=got<=asked,'actual kernel stderr write extent');parts.append(raw[:got])
    need(b''.join(parts)==stderr,'complete actual kernel write bytes bind stderr')
def lease_trace(rows,replies,owner_capacity):
    graph=[raw for _,raw in rows if raw[:8]==b'HRGTR002'];need(all(raw[:8]in(b'HRCGRO02',b'HRGTR002')for _,raw in rows),'lease receipt domain')
    case=0;counts=[0]*6;sequence=0;pending=None;lastoutput=None;outcap=4096;owner_sequence=None
    for raw in graph:
        seq,slot,event,code,work,out,phase,continuation,extent=struct.unpack_from('<9Q',raw,8)
        sequence+=1;need(seq==sequence and slot==11 and event in(1,2),'actual installed read receipt sequence/domain')
        need(work==owner_capacity and phase==0 and extent==0 and raw[80:192]==bytes(112),'same installed owner read borrow')
        if owner_sequence is None:owner_sequence=continuation
        need(continuation==owner_sequence,'installed read preserves completed startup sequence')
        output=raw[192:224]
        if event==1:
            need(pending is None and out==outcap,'actual read retry after growth')
            counts[0]+=1
            if code==CAPACITY:
                if lastoutput is not None:need(output==lastoutput,'short read preserves previous complete output header')
                pending=(work,out,phase,continuation,output)
            else:
                need(code<0xffff0000 and case<len(replies),'actual installed read completion')
                header,body=replies[case]
                need(code==len(body)and output==body[:32]and qword(header,80)==work and qword(header,88)==out,'actual returned body/header capacity binding')
                same(list(struct.unpack_from('<6Q',header,32)),counts,'actual query native/growth counters')
                counts=[0]*6;case+=1
            lastoutput=output
        else:
            need(code==0 and pending is not None,'actual read growth follows capacity')
            oldwork,oldout,oldphase,oldseq,oldoutput=pending
            need(work==oldwork and out==2*oldout and phase==oldphase and continuation==oldseq and output==oldoutput,'exact mechanical read-output resize without reexecution')
            counts[2]+=1;outcap=out;pending=None
    need(case==len(replies)and pending is None and not any(counts),'all installed read continuations complete')
    return len(graph)
def lease_observations(rows,old_capture,native_pids):
    need(type(rows)is list and len(rows)==6,'all actual lease observation phases')
    for index,name in enumerate(('ordinary','wide')):
        installed,renamed,released=rows[index*3:index*3+3]
        same([(r.get('name'),r.get('phase'))for r in(installed,renamed,released)],
             [(name,'installed'),(name,'renamed-live'),(name,'released')],'real lease phase order')
        for record in(installed,renamed,released):
            same(sorted(record.get('locks',{})),['controller.lock','controller.owner.lock'],'two real installed locks')
            for key,value in record['locks'].items():
                same(sorted(value),['device','inode','links','locked_by_other','mode','size','uid'],'complete lock inode observation')
                for field in('device','inode','uid'):need(uint(value[field],'lock '+field)>0,'actual lock identity')
                same([value['mode'],value['links'],value['size']],[384,1,0],'actual created lock mode/links/size')
                need(value['locked_by_other']is(record is not released),'actual lock acquisition/release outcome')
        same(installed['locks'],renamed['locks'],'same exact inode leases after path replacement')
        same({k:{a:b for a,b in v.items()if a!='locked_by_other'}for k,v in installed['locks'].items()},
             {k:{a:b for a,b in v.items()if a!='locked_by_other'}for k,v in released['locks'].items()},'same released inode identities')
        first,second=installed.get('fd'),renamed.get('fd')
        same(sorted(first),['0','1','2','3','4'],'actual installed descriptor set');same(sorted(second),sorted(first),'retained descriptor set')
        for fd in first:
            a,z=first[fd],second[fd];same(sorted(a),['fdinfo','target'],'complete descriptor observer')
            same(sorted(z),['fdinfo','target'],'complete continued descriptor observer')
            clean=lambda text:'\n'.join(line for line in text.split('\n')if not line.startswith('pos:'))
            need(clean(a['fdinfo'])==clean(z['fdinfo']),'descriptor flags/mount/inode/lock unchanged')
            if fd in('3','4'):
                key='controller.owner.lock'if fd=='3'else'controller.lock'
                need(a['target']==str(old_capture/'lease'/name/'state'/key)and z['target']==str(old_capture/'lease'/name/'renamed-state'/key),'actual locked pathname rename')
                need('\nino:\t'+str(installed['locks'][key]['inode'])+'\n'in a['fdinfo'],'observed fd same lock inode')
                need('FLOCK  ADVISORY  WRITE '+str(native_pids[name])+' 'in a['fdinfo'],'same native process owns lease')
            else:need(a['target']==z['target'],'actual transport descriptor identity unchanged')
    return {'retained_locks':4,'released_locks':4,'path_replacement_preserves_inode_custody':True}
def lease_evidence(e):
    c=e.b['capture'];b=Binder(c.root/'lease','lease');r=b.json('RESULT.json');manifest_artifacts(b,r)
    same(b.json('SOURCE.json'),{'producer':PRODUCER_PINS['lease.py'],'build':e.source['build'],'binary':e.b['build'].artifacts['bridge.elf']},'actual lease producer/build identity')
    process_names=[name+'/'+part for name in('ordinary','wide')for part in('primary','contender','reopened')]+['resource/limited']
    expected_files=['SOURCE.json','observations.json','remote-process.json','ordinary/config.json','ordinary/initial-config.json',
        'ordinary/contender-config.json','wide/config.json','wide/initial-config.json','wide/contender-config.json','resource/config.json']
    expected_files.extend(name+'/'+part for name in process_names for part in('stdin','stdout','stderr','kernel.trace','process.json','queries.json','trace.json'))
    same(sorted(r['artifacts']),sorted(expected_files),'complete seven process lease artifact set')
    query_count=0;allgrowth=[];proofs=[];pids=[];native_pids={}
    for name in('ordinary','wide','resource'):
        root=str(e.old['capture']/'lease'/'ordinary-root')if name=='ordinary'else'/'+('x'if name=='wide'else'r')*((33<<20)+17)
        state=e.old['capture']/'lease'/name/'state'
        def conf(target):return json.dumps({'state_dir':str(target),'controller_workspace_roots':[root],
            'hosts':{'h':{'ssh_target':'private-target','remote_state_dir':'/remote'}}},ensure_ascii=False,separators=(',',':')).encode()
        if name=='resource':need(b.data(name+'/config.json')==conf(state),'complete actual resource config input')
        else:
            need(b.data(name+'/initial-config.json')==conf(state)and b.data(name+'/contender-config.json')==conf(state.parent/'renamed-state'),'complete actual initial/reopen config')
            need(b.data(name+'/config.json')==b'not json and not reloaded','actual live config mutation retained')
        for part in(('limited',)if name=='resource'else('primary','contender','reopened')):
            rel=name+'/'+part+'/';folder=e.old['capture']/'lease'/name/part
            config=folder.parent/('config.json'if part in('primary','limited')else'contender-config.json')
            executable=[str(e.old['build']/'bridge.elf'),'--runtime-config',str(config)]
            argv=['/usr/bin/strace','-qq','-f','-s','256','-xx','-o',str(folder/'kernel.trace'),'-e',
                'trace=mmap,mremap,munmap,openat,close,flock,read,write,mkdirat,newfstatat',*executable]
            record=b.json(rel+'process.json');expected_exit=78 if part=='contender'else 75 if part=='limited'else 0
            process(record,argv,folder,60,expected_exit)
            same([record.get('executable_command'),record.get('env'),record.get('rlimit_as')],
                 [executable,{'PATH':''},4<<30 if part=='limited'else None],'actual installed process environment/resource bound')
            pids.append(record['pid'])
            for stream in('stdin','stdout','stderr','kernel.trace'):b.file(rel+stream,record['streams'][stream])
            indices=([None,0,0,0]if part=='primary'else[0]if part=='reopened'else[])
            frames=[pack(11,24 if index is None else 32)+b'HRCFGQ01'+pack(7,0 if index is None else 8)+(b''if index is None else pack(index))for index in indices]
            need(b.data(rel+'stdin')==b''.join(frames),'all actual installed read request bytes')
            raw=b.data(rel+'stdout');at=0;replies=[];query_rows=[]
            for ordinal,(index,frame)in enumerate(zip(indices,frames,strict=True)):
                need(len(raw)-at>=96,'complete actual installed read reply')
                header=raw[at:at+96];at+=96;n=qword(header,24)
                need(header[:8]==b'HRGFR002'and qword(header,8)==11 and qword(header,16)==n and 32<=n<=len(raw)-at,'actual installed read header/extent')
                body=raw[at:at+n];at+=n;root_bytes=root.encode()
                expected=b'HRCFGM01'+pack(0,0,8,1)if index is None else b'HRCFGM01'+pack(0,0,24+len(root_bytes),1,0,len(root_bytes))+root_bytes
                need(body==expected,'complete exact installed root bytes across mutations')
                need(uint(record.get('native_pid'),'native process PID')>0,'actual kernel child PID')
                query_rows.append({'ordinal':ordinal,'input_bytes':len(frame),'input_sha256':sha(frame),'header_hex':header.hex(),'body_bytes':len(body),'body_sha256':sha(body),'native_pid':record['native_pid']})
                replies.append((header,body))
            need(at==len(raw),'complete installed output EOF');same(b.json(rel+'queries.json'),query_rows,'full actual installed query index')
            if part=='primary':native_pids[name]=record['native_pid']
            if not indices:need(record.get('native_pid')is None,'no completed-query PID observation claimed')
            query_count+=len(indices)
            stderr=b.data(rel+'stderr');kernel=b.data(rel+'kernel.trace').decode('ascii');complete_stderr_writes(kernel,stderr)
            rows,tail=parse_receipts(stderr)
            growth,caps,proof=growth_receipts(rows,kernel,part=='limited')
            graph_count=lease_trace(rows,replies,caps[0])
            same(b.json(rel+'trace.json'),{'configuration_growth':growth,'graph_records':graph_count,'tail_hex':tail.hex(),'tail_bytes':len(tail)},'all actual stderr records/production diagnostics')
            if part=='contender':
                expected=('controller state directory '+str(state.parent/'renamed-state')+' is already owned or cannot be locked: lock acquisition failed because the operation would block\n').encode()
                need(tail==expected and re.search(r'flock\([^\n]*LOCK_EX\|LOCK_NB\)\s+= -1 (EAGAIN|EWOULDBLOCK)\b',kernel),'complete actual competing process lock refusal')
            else:need(tail==b'','no unaccounted actual stderr')
            if part=='limited':
                need(graph_count==0 and proof['actual_enomem']==1,'actual allocation rejection before graph query')
                state_hex=''.join('\\x%02x'%byte for byte in str(state).encode())
                filesystem_lines='\n'.join(line for line in kernel.splitlines()if re.search(r'\b(?:openat|mkdirat|newfstatat)\(',line))
                need(state_hex not in filesystem_lines,'allocation failure precedes installation state I/O')
            allgrowth.extend(growth);proofs.append({'name':name+'/'+part,**proof,'kernel_stderr_bytes_bound':len(stderr)})
    need(len(set(pids))==7,'all actual lease process identities')
    observations=lease_observations(b.json('observations.json'),e.old['capture'],native_pids)
    expected={'status':'PASS','actual_elf_processes':7,'actual_queries':query_count,'same_installed_owner':True,
        'actual_retained_locks':4,'actual_competing_lock_refusals':2,'actual_enomem_processes':1,'new_rust_processes':0,'public_mcp_complete':False}
    same({k:r.get(k)for k in expected},expected,'complete actual lease result');need(query_count==10,'all repeated reads')
    elapsed(r.get('elapsed_seconds'),180,'actual lease duration')
    for name,value in b.artifacts.items():c.artifacts['lease/'+name]=value
    return {**expected,'configuration_growth_records':len(allgrowth),'kernel_proofs':proofs,'lock_observations':observations,
            'trace_string_limit':256,'live_fixture_required':False}

def native_evidence(roots):
    e=Evidence(roots);build=build_evidence(e);combined_evidence(e);processes=focused_processes(e)
    original=guard_reference(e);guard=guard_evidence(e,original)
    semantic=semantic_evidence(e);state=state_evidence(e);lease=lease_evidence(e)
    artifacts=e.artifacts()
    for key,b in e.b.items():
        for name,want in list(b.artifacts.items()):same(file_pin(inside(b.root,name)),want,'artifact changed during final admission')
    return {'schema':'hepta.runtime.config-span-native-evidence.v1','status':'PASS','build':build,'actual_gate_processes':processes,
        'guard':guard,'semantic':semantic,'private_state':state,'installed_lease':lease,
        'retained_original':{k:v for k,v in original.items()if k!='observations'},
        'live_fixture_required':False,'fresh_cold':False,'new_native_calls':0,'new_rust_processes':0,'public_mcp_complete':False,
        'legacy_abi_replaced':False,'fresh_original_comparison_complete':False,'artifacts':len(artifacts),'artifact_bytes':{k:v['bytes']for k,v in artifacts.items()},
        'artifact_sha256':{k:v['sha256']for k,v in artifacts.items()}}
def main():
    p=argparse.ArgumentParser();p.add_argument('--roots',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    result=native_evidence(strict_json(a.roots.read_bytes()))
    with a.output.open('x')as stream:json.dump(result,stream,sort_keys=True,indent=2,allow_nan=False);stream.write('\n')
    print(json.dumps({'status':'PASS','artifacts':result['artifacts'],'guard_cases':result['guard']['cases'],'private_state_calls':result['private_state']['actual_native_calls'],
        'semantic_cases':8554,'actual_elf_processes':41,'new_native_calls':0,'new_rust_processes':0,'evidence':file_pin(a.output)},sort_keys=True))
if __name__=='__main__':main()





