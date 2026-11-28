"""Actual typed HIA -> seven-image validator -> retained RuntimeConfig corpus.

Only the existing observed baseline is compared locally. Every extended input
is exported for a new execution of the unchanged original Rust validator.
"""
from pathlib import Path
import collections,copy,gzip,hashlib,json,os,random,select,struct,subprocess,sys,time

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'tests/hia_native')]
from regex_test_context import data,artifact,module_manifest,executable_manifest
from hia_native_loader import NativeModule,NativeRejected
from config_semantics_cases import cases as baseline_cases,base,variants
sha=lambda raw:hashlib.sha256(raw).hexdigest()


def row(value,operation=1):
    raw=json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()
    default=b'/default-state'
    return b'HRCFGJ01'+struct.pack('<4Q',operation,100,len(default),len(raw))+default+raw


def cases():
    result=list(baseline_cases())
    patterns=[];seen=set()
    for line in data('match/requests.hex').read_bytes().splitlines():
        wire=bytes.fromhex(line.decode());op,n,h=struct.unpack_from('<3Q',wire,8)
        if op!=1:continue
        pattern=wire[32:32+n].decode()
        if pattern not in seen:seen.add(pattern);patterns.append(pattern)
    for pattern in patterns:
        value=base()
        value['hosts']['h']['privileged_actions']={'act':{'executable':'/echo','allow_extra_args':True,'extra_arg_patterns':[pattern]}}
        for op in [1,2,3]:result.append(('locked_regex_pattern',row(value,op)))
    rng=random.Random(1397217)
    extra=[]
    for line in data('hir/requests.hex').read_bytes().splitlines():
        wire=bytes.fromhex(line.decode());op,n,h=struct.unpack_from('<3Q',wire,8)
        if op==8:extra.append(wire[32:32+n].decode())
    for pattern in rng.sample(extra,min(240,len(extra))):
        value=base()
        value['hosts']['h']['privileged_actions']={'act':{'executable':'/echo','allow_extra_args':True,'extra_arg_patterns':['a',pattern,'b']}}
        result.append(('hir_pattern_after_valid',row(value)))
    for pattern in ['(',r'\w{500}','a{327675}','a{327674}',r'(?-u:\xFF)',r'\p{NoSuchProperty}',r')|foo(?:',r'(?x)# trailing comment']:
        for issue in range(9):
            value=variants()['all'];host=value['hosts']['h']
            action={'executable':'/echo','allow_extra_args':True,'extra_arg_patterns':[pattern]}
            host['privileged_actions']={'m':copy.deepcopy(action),'z':{'executable':'relative'}}
            if issue==0:value['state_dir']='relative'
            if issue==1:value['controller_workspace_roots']=['relative']
            if issue==2:host['ssh_target']='-bad'
            if issue==3:host['privileged_actions']['m']['timeout_seconds']=0
            if issue==4:host['privileged_actions']['m']['allow_extra_args']=False
            if issue==5:host['privileged_actions']['m']['extra_arg_patterns']=[pattern]*33
            if issue==6:host['privileged_actions']['a']={'executable':'relative'}
            if issue==7:value['hosts']['z']={'ssh_target':'-bad','remote_state_dir':'/r'}
            if issue==8:value['weight_workers']['w']['host']='missing'
            for op in [1,3]:result.append(('first_error_order',row(value,op)))
    for n in [1,2,31,32,33]:
        for where in [0,n-1]:
            for pattern in ['a','(']:
                value=base();patterns=['b']*n;patterns[where]=pattern
                value['hosts']['h']['privileged_actions']={'act':{'executable':'/echo','allow_extra_args':True,'extra_arg_patterns':patterns}}
                result.append(('ordered_pattern_count',row(value)))
    return result


class NativeValidator:
    def __init__(self,manifest):
        self.manifest=manifest;self.meta=json.loads(manifest.read_bytes())
        executable=manifest.parent/self.meta['executable']
        assert sha(executable.read_bytes())==self.meta['executable_sha256']
        self.process=subprocess.Popen([str(executable)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'','LC_ALL':'C'})
        self.input=bytearray();self.output=bytearray();self.calls=0
    def read(self,n):
        out=bytearray();end=time.monotonic()+30
        while len(out)<n:
            remain=end-time.monotonic()
            assert remain>0 and select.select([self.process.stdout],[],[],remain)[0],'native configuration regex request timed out'
            raw=os.read(self.process.stdout.fileno(),n-len(out));assert raw,('native configuration validator exited',self.process.poll(),self.process.stderr.read())
            out.extend(raw)
        self.output.extend(out);return bytes(out)
    def call(self,wire):
        request=struct.pack('<Q',len(wire))+wire;self.input.extend(request)
        self.process.stdin.write(request);self.process.stdin.flush()
        code,n=struct.unpack('<2Q',self.read(16));assert n<=128<<20
        out=self.read(n);self.calls+=1
        assert code==0,(code,wire[:32].hex())
        magic,status,diagnostic,size=struct.unpack_from('<8s3Q',out)
        assert magic==b'HRCFGR01' and size==len(out)-32 and status in (0,1)
        return status,out[32:]
    def close(self):
        self.process.stdin.close();self.process.wait(timeout=15)
        assert(self.process.returncode,self.process.stderr.read())==(0,b'')


def main():
    output=artifact('config-corpus')
    output.mkdir(mode=0o700)
    rows=cases();requests=b''.join(w.hex().encode()+b'\n' for _,w in rows)
    (output/'requests.hex').write_bytes(requests)
    original=gzip.decompress((ROOT/'tests/hia_native/config_runtime_original_output.txt.gz').read_bytes()).splitlines()
    assert len(original)==2063
    paths={name:module_manifest(name)for name in ['json','identity']}
    modules={name:NativeModule(path,manifest_sha256=sha(path.read_bytes()))for name,path in paths.items()}
    parser=modules['json'].session(output_capacity=16<<20,workspace_capacity=32<<20)
    identity=modules['identity'].session(output_capacity=16<<20,workspace_capacity=32<<20)
    manifest=executable_manifest('validation');validator=NativeValidator(manifest)
    counts=collections.Counter();outputs=[];start=time.monotonic()
    try:
        for index,(category,wire) in enumerate(rows):
            operation=struct.unpack_from('<Q',wire,8)[0];parse=bytearray(wire);struct.pack_into('<Q',parse,8,2)
            counts['typed_native_calls']+=1
            try:arena=parser.invoke(bytes(parse))
            except NativeRejected as error:
                assert error.code==0xffffffff
                code=error.code;payload=b'';counts['typed_refusals']+=1
            else:
                if operation==4:
                    payload=identity.invoke(b'HRCFGI01'+struct.pack('<2Q',1,len(arena))+arena);code=0;counts['identity_native_calls']+=1
                else:
                    code,payload=validator.call(b'HRCFGV01'+struct.pack('<2Q',operation,len(arena))+arena)
            line=f'{code:08x}:'.encode()+payload.hex().encode()+b'\n';outputs.append(line)
            if index<len(original):
                a,b=original[index].split(b':',1)
                assert a==f'{code:08x}'.encode(),(index,category,a,line)
                if code!=0xffffffff:assert b==payload.hex().encode(),(index,category,original[index],line)
                counts['retained_original_comparisons']+=1
        validator.close()
    finally:
        if validator.process.poll() is None:validator.process.kill();validator.process.wait(timeout=15)
        parser.close();identity.close()
        for m in modules.values():m.close()
    result_bytes=b''.join(outputs);(output/'native-output.txt').write_bytes(result_bytes)
    assert len(rows)==3694 and sha(requests)=='6ed09450d8ba8959f6a3e7eb4047ca04792b55552232ba37e9a8d3e8fb3f6abb'
    assert sha(result_bytes)=='c309492113e9bfe9106c59b24f720e4621f6ecc3b9e4c8ff0e7c6e5d84318c63'
    (output/'elf.stdin').write_bytes(validator.input);(output/'elf.stdout').write_bytes(validator.output)
    source_paths=['native/config_validation.hepta','native/config_regex_packer.hepta','scripts/config_regex_adapter.S','scripts/build_regex_probe.py','tests/hia_native/test_config_regex.py']
    source_paths += [x['source'] for x in validator.meta['members']]
    report={'schema':'hepta.runtime.config-regex-corpus.v1','status':'PASS','cases':len(rows),'elapsed':time.monotonic()-start,
        'categories':dict(collections.Counter(k for k,_ in rows)),'counts':dict(counts),'actual_elf_requests':validator.calls,
        'requests_file':'requests.hex','requests_bytes':len(requests),'requests_sha256':sha(requests),
        'native_output_file':'native-output.txt','native_output_bytes':len(result_bytes),'native_output_sha256':sha(result_bytes),
        'elf_input_bytes':len(validator.input),'elf_input_sha256':sha(validator.input),'elf_output_bytes':len(validator.output),'elf_output_sha256':sha(validator.output),
        'composition_manifest_sha256':sha(manifest.read_bytes()),'typed_manifests':{n:sha(p.read_bytes())for n,p in paths.items()},
        'sources':{n:sha((ROOT/n).read_bytes())for n in sorted(set(source_paths))},
        'new_original_extended_replay_completed':False,'installed_configuration_wired':False,'unconstrained_regex_resources_closed':False}
    (output/'native-corpus.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps(report,sort_keys=True))


if __name__=='__main__':main()
