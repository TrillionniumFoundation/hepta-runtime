"""Real static-ELF administrator configuration installation and custody tests."""
from pathlib import Path
import argparse,collections,fcntl,hashlib,json,os,select,stat,struct,subprocess,tempfile,time,unittest

ROOT=Path(__file__).resolve().parents[2]
COUNTS=collections.Counter();MANIFEST=None;FIXTURE=None
sha=lambda b:hashlib.sha256(b).hexdigest()

def config(state,hosts=None):
    result={'hosts':hosts or {'h':{'ssh_target':'target','remote_state_dir':'/remote'}}}
    if state is not None:result['state_dir']=os.fsdecode(state)
    return result

def query(op,key=b''):
    key=key.encode() if isinstance(key,str) else key
    return b'HRCFGQ01'+struct.pack('<2Q',op,len(key))+key

def startup(path,env=None):
    env=env or {};pieces=[os.fsencode(path)];flags=0
    for i,name in enumerate(['HEPTA_RUNTIME_STATE_DIR','XDG_STATE_HOME','HOME','TMPDIR']):
        if name in env:flags|=1<<i;pieces.append(os.fsencode(env[name]))
        else:pieces.append(b'')
    return b'HRCFGC01'+struct.pack('<7Q',flags,*map(len,pieces),0)+b''.join(pieces)

def unlocked(path):
    fd=os.open(path,os.O_RDWR)
    try:
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);return True
        except BlockingIOError:return False
    finally:os.close(fd)

class Session:
    def __init__(self,binary,path,*,env=None,closed_stderr=False):
        environment={'PATH':'','LC_ALL':'C'};environment.update(env or {})
        def setup():
            os.umask(0o22)
            if closed_stderr:os.close(2)
        self.process=subprocess.Popen([str(binary),'--runtime-config',os.fsdecode(path)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=environment,preexec_fn=setup)
    def read(self,n):
        out=bytearray();end=time.monotonic()+15
        while len(out)<n:
            remain=end-time.monotonic()
            if remain<=0 or not select.select([self.process.stdout],[],[],remain)[0]:raise AssertionError('actual native owner timed out')
            data=os.read(self.process.stdout.fileno(),n-len(out))
            if not data:raise AssertionError(('native owner exited',self.process.poll(),self.process.stderr.read()))
            out.extend(data)
        return bytes(out)
    def call(self,wire):
        self.process.stdin.write(struct.pack('<Q',len(wire))+wire);self.process.stdin.flush()
        n=struct.unpack('<Q',self.read(8))[0];assert 32<=n<=128<<20
        out=self.read(n);magic,status,code,size=struct.unpack_from('<8s3Q',out)
        assert magic==b'HRCFGM01' and size==len(out)-32
        COUNTS['actual_elf_requests']+=1
        return status,code,out[32:]
    def fd_count(self):return len(list(Path(f'/proc/{self.process.pid}/fd').iterdir()))
    def close(self):
        self.process.stdin.close();self.process.wait(timeout=15)
        assert (self.process.returncode,self.process.stderr.read())==(0,b'')
    def __enter__(self):return self
    def __exit__(self,*args):
        if args[0]:self.process.kill();self.process.wait(timeout=15)
        else:self.close()

class ConfigurationOwner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifests=[]
        for path,fixture in [(MANIFEST,False),(FIXTURE,True)]:
            m=json.loads(path.read_bytes());b=path.parent/m['executable']
            assert sha(b.read_bytes())==m['elf_sha256'] and m['fixture_admin_reinstallation']==fixture
            assert sha((ROOT/'scripts/config_owner_adapter.S').read_bytes())==m['adapter_base_sha256']
            assert [item['id'] for item in m['members']]==[0,1,2,3,4,10,11,12,13,14,15]
            for item in m['members']:
                p=Path(item['manifest']);data=json.loads(p.read_bytes())
                assert sha(p.read_bytes())==item['manifest_sha256']
                assert sha((ROOT/item['source']).read_bytes())==item['source_sha256']
                image=(p.parent/data['image']).read_bytes();assert sha(image)==item['image_sha256']
                assert b.read_bytes()[item['offset']:item['offset']+len(image)]==image
            cls.manifests.append(m)
        cls.binary=MANIFEST.parent/cls.manifests[0]['executable'];cls.fixture=FIXTURE.parent/cls.manifests[1]['executable']
    def write(self,path,value):
        path.write_text(json.dumps(value,ensure_ascii=False,separators=(',',':')))
    def ok(self,session,op,key=b''):
        status,code,data=session.call(query(op,key));self.assertEqual((status,code),(0,0));return data
    def failed_start(self,path,expected,env=None):
        environment={'PATH':'','LC_ALL':'C'};environment.update(env or {})
        p=subprocess.run([str(self.binary),'--runtime-config',os.fsdecode(path)],input=b'',capture_output=True,env=environment,timeout=15)
        self.assertEqual((p.returncode,p.stdout,p.stderr),(78,b'',expected+b'\n'))
        COUNTS['actual_startup_refusals']+=1
    def test_01_installed_queries_and_retained_locks(self):
        with tempfile.TemporaryDirectory(prefix='hia-config-owner-') as td:
            root=Path(td);path=root/'config';state=root/'one/../state';self.write(path,config(state))
            with Session(self.binary,path) as s:
                a=self.ok(s,1);b=self.ok(s,2);digest=self.ok(s,3);canonical=self.ok(s,6)
                self.assertEqual(canonical,os.fsencode(root/'state'));self.assertEqual(len(digest),32)
                self.assertEqual(json.loads(a)['hosts'][0]['name'],'h');self.assertEqual(json.loads(b)['hosts'][0]['alias'],'h')
                self.assertFalse(unlocked(root/'state/controller.owner.lock'));self.assertFalse(unlocked(root/'state/controller.lock'))
                count=s.fd_count()
                for _ in range(3):
                    self.assertEqual([self.ok(s,op) for op in [1,2,3]],[a,b,digest]);self.assertEqual(s.fd_count(),count)
                COUNTS['persistent_query_cache_controls']+=9
            self.assertTrue(unlocked(root/'state/controller.owner.lock'));self.assertTrue(unlocked(root/'state/controller.lock'))
            COUNTS['actual_lock_custody_controls']+=4
    def test_02_host_name_and_alias_first_order(self):
        with tempfile.TemporaryDirectory(prefix='hia-config-host-') as td:
            root=Path(td);path=root/'config';hosts={'a':{'ssh_target':'z','remote_state_dir':'/r'},'z':{'ssh_target':'other','remote_state_dir':'/r'}};self.write(path,config(root/'state',hosts))
            with Session(self.binary,path) as s:
                for op,key,want in [(4,'a',b'a'),(4,'z',b'z'),(5,'z',b'a'),(5,'other',b'z'),(5,'missing',b'')]:
                    out=self.ok(s,op,key)
                    if not want:self.assertEqual(out,b'');continue
                    magic,generation,token,n=struct.unpack_from('<8s3Q',out);self.assertEqual((magic,generation,n,out[32:]),(b'HRCFHOST',1,len(want),want));self.assertGreater(token,0)
                for key in ['', 'not-configured','中😀','raw\0key']:
                    status,code,out=s.call(query(4,key));self.assertEqual((status,out),(1,f'unknown host `{key}`; call host_list for configured names'.encode()))
                COUNTS['exact_name_alias_order_controls']+=9
    def test_03_original_environment_precedence_and_non_utf8(self):
        with tempfile.TemporaryDirectory(prefix='hia-config-env-') as td:
            root=Path(td);path=root/'config';self.write(path,config(None))
            examples=[({'HEPTA_RUNTIME_STATE_DIR':str(root/'explicit'),'XDG_STATE_HOME':str(root/'ignored')},root/'explicit'),
                      ({'XDG_STATE_HOME':str(root/'xdg')},root/'xdg/hepta-runtime'),
                      ({'HOME':str(root/'home')},root/'home/.local/state/hepta-runtime'),
                      ({'TMPDIR':str(root/'temp')},root/'temp/.local/state/hepta-runtime'),
                      ({'HEPTA_RUNTIME_STATE_DIR':os.fsencode(root)+b'/raw-\xff-state'},os.fsencode(root)+b'/raw-\xff-state')]
            for env,state in examples:
                with Session(self.binary,path,env=env) as s:
                    self.assertEqual(self.ok(s,6),os.fsencode(state));self.ok(s,1);self.ok(s,2)
                    if isinstance(state,bytes):
                        for _ in range(2):self.assertEqual(s.call(query(3))[::2],(1,b'path contains invalid UTF-8 characters'))
                    else:self.assertEqual(len(self.ok(s,3)),32)
            self.failed_start(path,b'controller state directory must be absolute',{'HEPTA_RUNTIME_STATE_DIR':''})
            self.failed_start(path,b'controller state directory must be absolute',{'XDG_STATE_HOME':''})
            COUNTS['environment_default_controls']+=7
    def test_04_original_file_and_path_changes_do_not_reload(self):
        with tempfile.TemporaryDirectory(prefix='hia-config-immutable-') as td:
            root=Path(td);path=root/'config';state=root/'state';self.write(path,config(state))
            with Session(self.binary,path) as s:
                before=[self.ok(s,op) for op in [1,2,3,6]]
                path.write_bytes(b'not JSON');state.rename(root/'renamed');state.mkdir(mode=0o700)
                for _ in range(2):self.assertEqual([self.ok(s,op) for op in [1,2,3,6]],before)
                self.assertFalse(unlocked(root/'renamed/controller.owner.lock'));self.assertFalse(unlocked(root/'renamed/controller.lock'));self.assertEqual(list(state.iterdir()),[])
                COUNTS['immutable_source_and_path_controls']+=8
    def test_05_second_install_keeps_old_value_and_exact_effect_order(self):
        with tempfile.TemporaryDirectory(prefix='hia-config-second-') as td:
            root=Path(td);path=root/'config';first=root/'first';self.write(path,config(first))
            with Session(self.fixture,path) as s:
                before=[self.ok(s,op) for op in [1,2,3,6]];fds=s.fd_count()
                second=root/'second';self.write(path,config(second,{'new':{'ssh_target':'new-target','remote_state_dir':'/new'}}))
                self.assertEqual(s.call(startup(path))[::2],(1,b'runtime config was already initialized'))
                for name in ['jobs','audit']:self.assertTrue((second/name).is_dir())
                for name in ['controller.owner.lock','controller.lock']:self.assertTrue(unlocked(second/name));self.assertFalse(unlocked(first/name))
                self.assertEqual(s.fd_count(),fds);self.assertEqual([self.ok(s,op) for op in [1,2,3,6]],before)
                invalid=root/'not-created';self.write(path,{'state_dir':str(invalid),'hosts':{}})
                status,code,error=s.call(startup(path));self.assertEqual(status,1);self.assertIn(b'at least one host',error);self.assertFalse(invalid.exists())
                self.write(path,config(first));status,code,error=s.call(startup(path));self.assertEqual(status,1);self.assertIn(b'lock acquisition failed because the operation would block',error)
                self.assertEqual([self.ok(s,op) for op in [1,2,3,6]],before);self.assertEqual(s.fd_count(),fds)
                COUNTS['failed_reinstallation_controls']+=3
    def test_06_failure_contexts_and_regex_failure_precedes_installation(self):
        with tempfile.TemporaryDirectory(prefix='hia-config-reject-') as td:
            root=Path(td);path=root/'config';state=root/'state'
            self.failed_start(path,b'failed to read runtime config '+os.fsencode(path))
            path.write_bytes(b'{"hosts":');self.failed_start(path,b'invalid runtime config JSON '+os.fsencode(path))
            bad=config(state);bad['hosts']['h']['privileged_actions']={'act':{'executable':'/bin/x','allow_extra_args':True,'extra_arg_patterns':['(']}}
            self.write(path,bad);self.failed_start(path,b'host `h` privileged action `act` has invalid argument regex');self.assertFalse(state.exists())
            self.write(path,config(state));state.mkdir(mode=0o755);os.chmod(state,0o755)
            self.failed_start(path,b'controller state directory must be owned by the current user with mode 0700');self.assertEqual(list(state.iterdir()),[])
            os.chmod(state,0o700);target=root/'target';target.mkdir(mode=0o755);os.chmod(target,0o755);os.symlink(target,state/'jobs')
            self.failed_start(path,b'controller state subdirectory jobs must not be a symlink');self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o755)
            self.assertTrue(unlocked(state/'controller.owner.lock'));self.assertTrue(unlocked(state/'controller.lock'))
    def test_07_closed_stderr_and_production_cannot_reinstall(self):
        with tempfile.TemporaryDirectory(prefix='hia-config-authority-') as td:
            root=Path(td);path=root/'config';state=root/'state';self.write(path,config(state))
            with Session(self.binary,path,closed_stderr=True) as s:
                self.ok(s,1);self.ok(s,3);self.assertFalse(unlocked(state/'controller.owner.lock'))
            s=Session(self.binary,path);self.ok(s,1)
            wire=startup(path);s.process.stdin.write(struct.pack('<Q',len(wire))+wire);s.process.stdin.flush();s.process.stdin.close()
            s.process.wait(timeout=15);self.assertEqual((s.process.returncode,s.process.stdout.read(),s.process.stderr.read()),(111,b'',b''))
            self.assertTrue(unlocked(state/'controller.owner.lock'));self.assertTrue(unlocked(state/'controller.lock'))
            COUNTS['production_install_authority_refusals']+=1
    def test_08_regex_installation_and_failed_reinstallation_keep_authority(self):
        with tempfile.TemporaryDirectory(prefix='hia-config-regex-owner-') as td:
            root=Path(td);path=root/'config';state=root/'state'
            value=config(state);value['hosts']['h']['privileged_actions']={'act':{'executable':'/bin/x','allow_extra_args':True,'extra_arg_patterns':['x',r'\p{Greek}+',r')|foo(?:']}}
            self.write(path,value)
            with Session(self.fixture,path) as s:
                before=[self.ok(s,op) for op in [1,2,3,6]];fds=s.fd_count()
                self.assertFalse(unlocked(state/'controller.owner.lock'));self.assertFalse(unlocked(state/'controller.lock'))
                newstate=root/'not-created';value['state_dir']=str(newstate)
                for pattern in ['(',r'\w{500}','a{327675}',r'(?-u:\xFF)']:
                    value['hosts']['h']['privileged_actions']['act']['extra_arg_patterns']=[pattern];self.write(path,value)
                    status,code,error=s.call(startup(path))
                    self.assertEqual((status,error),(1,b'host `h` privileged action `act` has invalid argument regex'))
                    self.assertFalse(newstate.exists());self.assertEqual(s.fd_count(),fds)
                    self.assertEqual([self.ok(s,op) for op in [1,2,3,6]],before)
                    COUNTS['regex_failed_reinstallation_controls']+=1
                value['hosts']['h']['privileged_actions']['act']['extra_arg_patterns']=['x'];self.write(path,value)
                self.assertEqual(s.call(startup(path))[::2],(1,b'runtime config was already initialized'))
                self.assertEqual(s.fd_count(),fds);self.assertEqual([self.ok(s,op) for op in [1,2,3,6]],before)
                self.assertTrue((newstate/'jobs').is_dir());self.assertTrue((newstate/'audit').is_dir())
                self.assertTrue(unlocked(newstate/'controller.owner.lock'));self.assertTrue(unlocked(newstate/'controller.lock'))
                COUNTS['regex_valid_reinstallation_effect_controls']+=1
            self.assertTrue(unlocked(state/'controller.owner.lock'));self.assertTrue(unlocked(state/'controller.lock'))

def main():
    global MANIFEST,FIXTURE
    p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--fixture-manifest',type=Path,required=True);a=p.parse_args()
    MANIFEST=a.manifest.resolve(strict=True);FIXTURE=a.fixture_manifest.resolve(strict=True)
    t=time.monotonic();result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ConfigurationOwner))
    report=dict(schema='hepta.runtime.config-owner-native-tests.v1',status='PASS' if result.wasSuccessful() else 'FAIL',test_groups=result.testsRun,counts=dict(COUNTS),elapsed_seconds=time.monotonic()-t,
                manifest_sha256=sha(MANIFEST.read_bytes()),fixture_manifest_sha256=sha(FIXTURE.read_bytes()),source_sha256=sha((ROOT/'native/config_owner.hepta').read_bytes()),
                actual_original_owner_comparison_completed=False,complete_config_owner=False,regex_compilation_closed=False)
    print(json.dumps(report,sort_keys=True));raise SystemExit(0 if result.wasSuccessful() else 1)

if __name__=='__main__':main()
