"""Actual kernel tests for the HIA configuration filesystem owner.

The internal binary interface is a fixture transport, never a caller-facing
configuration installation API. No reference Rust executes on this machine.
"""
from pathlib import Path
import argparse,collections,fcntl,hashlib,json,os,select,stat,struct,subprocess,tempfile,time,unittest

ROOT=Path(__file__).resolve().parents[2]
COUNTS=collections.Counter()
MANIFEST=None
sha=lambda b:hashlib.sha256(b).hexdigest()

class Session:
    def __init__(self,binary,*,umask=0o22,closed_stderr=False):
        def setup():
            os.umask(umask)
            if closed_stderr:os.close(2)
        self.process=subprocess.Popen([str(binary)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,env={'PATH':'','LC_ALL':'C'},preexec_fn=setup)
    def read(self,n):
        out=bytearray();deadline=time.monotonic()+10
        while len(out)<n:
            remaining=deadline-time.monotonic()
            if remaining<=0 or not select.select([self.process.stdout],[],[],remaining)[0]:raise AssertionError('native fixture response timeout')
            chunk=os.read(self.process.stdout.fileno(),n-len(out))
            if not chunk:raise AssertionError(('native fixture exited',self.process.poll(),bytes(out)))
            out.extend(chunk)
        return bytes(out)
    def call(self,path=None,handles=None,operation=1):
        if handles is None:
            raw=os.fsencode(path);wire=b'HRCFSQ01'+struct.pack('<2Q',operation,len(raw))+raw
        else:wire=b'HRCFSQ01'+struct.pack('<4Q',2,16,*handles)
        self.process.stdin.write(struct.pack('<Q',len(wire))+wire);self.process.stdin.flush()
        n=struct.unpack('<Q',self.read(8))[0];assert 64<=n<=(8388608 if operation==3 else 8256)
        out=self.read(n);magic,status,error,owner,legacy,size,detail,reserved=struct.unpack_from('<8s7Q',out)
        assert magic==b'HRCFSR01' and size==len(out)-64 and reserved==0
        COUNTS['actual_elf_requests']+=1
        return dict(status=status,errno=error,handles=(owner,legacy),path=out[64:],detail=detail)
    def fd_count(self):return len(list(Path(f'/proc/{self.process.pid}/fd').iterdir()))
    def close(self):
        if self.process.stdin and not self.process.stdin.closed:self.process.stdin.close()
        code=self.process.wait(timeout=10);stderr=self.process.stderr.read()
        assert (code,stderr)==(0,b''),(code,stderr)
    def __enter__(self):return self
    def __exit__(self,*args):
        if args[0]:
            self.process.kill();self.process.wait(timeout=10)
        else:self.close()

def can_lock(path):
    fd=os.open(path,os.O_RDWR)
    try:
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return False
        return True
    finally:os.close(fd)

class ConfigurationFilesystem(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.meta=json.loads(MANIFEST.read_bytes());cls.binary=MANIFEST.parent/cls.meta['executable']
        assert sha(cls.binary.read_bytes())==cls.meta['elf_sha256']
        assert sha((ROOT/'native/config_fs.hepta').read_bytes())==cls.meta['source_sha256']
        assert sha((ROOT/'scripts/config_fs_adapter.S').read_bytes())==cls.meta['adapter_source_sha256']
    def success(self,session,path):
        before=session.fd_count();result=session.call(path)
        self.assertEqual((result['status'],result['errno']),(0,0),result)
        self.assertEqual(result['path'],os.path.realpath(os.fsencode(path)))
        self.assertGreater(result['handles'][0],0);self.assertGreater(result['handles'][1],result['handles'][0])
        canonical=Path(os.fsdecode(result['path']))
        self.assertEqual(session.fd_count(),before+2)
        for name in ['controller.owner.lock','controller.lock']:
            f=canonical/name;self.assertTrue(f.is_file());self.assertEqual(stat.S_IMODE(f.stat().st_mode),0o600);self.assertFalse(can_lock(f))
        for name in ['jobs','audit']:
            f=canonical/name;self.assertTrue(f.is_dir());self.assertEqual(stat.S_IMODE(f.stat().st_mode),0o700)
        release=session.call(handles=result['handles']);self.assertEqual((release['status'],release['handles'],release['path']),(0,(0,0),b''))
        self.assertEqual(session.fd_count(),before)
        for name in ['controller.owner.lock','controller.lock']:self.assertTrue(can_lock(canonical/name))
        COUNTS['retained_pair_and_release_controls']+=1
        return result
    def test_08_configuration_read_bytes_bounds_and_cleanup(self):
        with tempfile.TemporaryDirectory(prefix='hia-config-read-') as raw,Session(self.binary) as session:
            root=Path(raw);path=root/'config.json';link=root/'alias';os.symlink(path,link)
            before=session.fd_count()
            for data in [b'',b'{}',b'{"raw":"\xff"}',bytes(range(256))*257,b'x'*8388544]:
                path.write_bytes(data);out=session.call(link,operation=3)
                self.assertEqual((out['status'],out['errno'],out['handles'],out['path']),(0,0,(0,0),data))
                self.assertEqual(session.fd_count(),before)
                COUNTS['configuration_read_byte_comparisons']+=1
            path.write_bytes(b'x'*8388545);out=session.call(path,operation=3)
            self.assertEqual((out['status'],out['errno'],out['handles'],out['path']),(14,0,(0,0),b''))
            for name,error in [(root/'missing',2),(root,21),(os.fsencode(root)+b'/bad\0path',22)]:
                out=session.call(name,operation=3)
                self.assertEqual((out['status'],out['errno'],out['handles'],out['path']),(13,error,(0,0),b''))
                self.assertEqual(session.fd_count(),before)
            path.write_bytes(b'{"recovery":true}');out=session.call(path,operation=3)
            self.assertEqual((out['status'],out['path']),(0,path.read_bytes()));self.assertEqual(session.fd_count(),before)
            self.success(session,root/'state-after-read')
    def test_01_create_private_state_and_canonical_paths(self):
        with tempfile.TemporaryDirectory(prefix='hia-config-fs-') as raw,Session(self.binary) as session:
            root=Path(raw)
            for path in [root/'a'/'..'/'state',root/'nested'/'one'/'two',root/'unicode-中😀']:
                self.success(session,path)
            os.symlink('.',root/'short')
            self.success(session,root/'short'/'extra'/'middle'/'..'/'state')
            (root/'long-target'/'child').mkdir(parents=True,mode=0o700)
            os.symlink('long-target/child',root/'long')
            self.success(session,root/'long'/'state')
            os.symlink(root/'long-target',root/'absolute')
            self.success(session,root/'absolute'/'another')
            self.success(session,os.fsencode(root)+b'/raw-\xff-state')
            self.success(session,'//'+str(root).lstrip('/')+'///existing/./state')
    def test_02_existing_permissions_and_subdirectory_repair_order(self):
        with tempfile.TemporaryDirectory(prefix='hia-config-fs-') as raw,Session(self.binary) as session:
            root=Path(raw);state=root/'state';state.mkdir(mode=0o755);os.chmod(state,0o755)
            before=session.fd_count();out=session.call(state)
            self.assertEqual((out['status'],out['errno'],out['handles']),(4,0,(0,0)))
            self.assertEqual(list(state.iterdir()),[]);self.assertEqual(stat.S_IMODE(state.stat().st_mode),0o755);self.assertEqual(session.fd_count(),before)
            os.chmod(state,0o700);(state/'jobs').mkdir(mode=0o777);os.chmod(state/'jobs',0o777)
            (state/'audit').mkdir(mode=0o755);self.success(session,state)
    def test_03_owner_and_legacy_file_admission(self):
        with tempfile.TemporaryDirectory(prefix='hia-config-fs-') as raw,Session(self.binary) as session:
            root=Path(raw)
            for name in ['owner-permissive','owner-hardlink','owner-fifo','owner-symlink','legacy-permissive','legacy-hardlink','legacy-symlink']:
                state=root/name;state.mkdir(mode=0o700)
                lock=state/('controller.lock' if name.startswith('legacy') else 'controller.owner.lock')
                target=root/(name+'-target')
                if name.endswith('permissive'):
                    lock.write_bytes(b'keep');os.chmod(lock,0o644)
                elif name.endswith('hardlink'):
                    target.write_bytes(b'private');os.chmod(target,0o600);os.link(target,lock)
                elif name.endswith('fifo'):os.mkfifo(lock,0o600)
                else:
                    target.write_bytes(b'private');os.chmod(target,0o600);os.symlink(target,lock)
                before=session.fd_count()
                if name=='legacy-permissive':
                    self.success(session,state);self.assertEqual(lock.read_bytes(),b'keep');continue
                out=session.call(state)
                expected=9 if name=='owner-permissive' else 8 if name.endswith('hardlink') else 7 if name.endswith('fifo') else 5
                self.assertEqual(out['status'],expected,(name,out));self.assertEqual(out['handles'],(0,0));self.assertEqual(session.fd_count(),before)
                if name.endswith('symlink'):self.assertEqual(out['errno'],40);self.assertEqual(target.read_bytes(),b'private')
                self.assertFalse((state/'jobs').exists());COUNTS['lock_admission_refusals']+=1
    def test_04_two_nonblocking_locks_and_failure_cleanup(self):
        with tempfile.TemporaryDirectory(prefix='hia-config-fs-') as raw,Session(self.binary) as session:
            root=Path(raw)
            for blocked in ['controller.owner.lock','controller.lock']:
                state=root/blocked;state.mkdir(mode=0o700);fd=os.open(state/blocked,os.O_RDWR|os.O_CREAT,0o600)
                try:
                    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);before=session.fd_count();start=time.monotonic();out=session.call(state)
                    self.assertLess(time.monotonic()-start,2);self.assertEqual((out['status'],out['errno'],out['handles']),(11,11,(0,0)));self.assertEqual(session.fd_count(),before)
                    if blocked=='controller.owner.lock':self.assertFalse((state/'controller.lock').exists())
                    else:self.assertTrue(can_lock(state/'controller.owner.lock'))
                finally:os.close(fd)
                self.success(session,state)
    def test_05_symlinked_subdirectory_rejected_without_chmod_target(self):
        with tempfile.TemporaryDirectory(prefix='hia-config-fs-') as raw,Session(self.binary) as session:
            root=Path(raw)
            for name in ['jobs','audit']:
                state=root/name;state.mkdir(mode=0o700);target=root/(name+'-target');target.mkdir(mode=0o755);os.chmod(target,0o755);os.symlink(target,state/name)
                before=session.fd_count();out=session.call(state)
                self.assertEqual((out['status'],out['errno'],out['handles']),(12,0,(0,0)));self.assertEqual(out['detail'],1 if name=='jobs' else 2)
                self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o755);self.assertEqual(session.fd_count(),before)
                self.assertTrue(can_lock(state/'controller.owner.lock'));self.assertTrue(can_lock(state/'controller.lock'))
                (state/name).unlink();self.success(session,state)
    def test_06_kernel_path_errors_and_recovery(self):
        with tempfile.TemporaryDirectory(prefix='hia-config-fs-') as raw,Session(self.binary) as session:
            root=Path(raw);(root/'file').write_bytes(b'preserve');os.symlink('cycle',root/'cycle')
            for path,error in [(os.fsencode(root)+b'/\0bad',22),(root/('x'*256),36),(root/'file',17),(root/'file'/'child',20),(root/'cycle',17)]:
                before=session.fd_count();out=session.call(path);self.assertEqual((out['status'],out['errno']),(1,error),(path,out));self.assertEqual(out['handles'],(0,0));self.assertEqual(session.fd_count(),before)
            self.assertEqual((root/'file').read_bytes(),b'preserve');self.success(session,root/'later')
    def test_07_multiple_retained_roots_and_eof_release(self):
        with tempfile.TemporaryDirectory(prefix='hia-config-fs-') as raw:
            root=Path(raw)
            with Session(self.binary,umask=0,closed_stderr=True) as session:
                count=session.fd_count();a=session.call(root/'a');b=session.call(root/'b')
                self.assertEqual((a['status'],b['status']),(0,0));self.assertEqual(session.fd_count(),count+4)
                session.call(handles=a['handles']);self.assertTrue(can_lock(root/'a/controller.owner.lock'));self.assertFalse(can_lock(root/'b/controller.owner.lock'))
            self.assertTrue(can_lock(root/'b/controller.owner.lock'));self.assertTrue(can_lock(root/'b/controller.lock'))
            COUNTS['eof_retirement_controls']+=1

def main():
    global MANIFEST
    p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,default=os.environ.get('HIA_CONFIG_FS_MANIFEST'));args=p.parse_args();assert args.manifest
    MANIFEST=args.manifest.resolve();start=time.monotonic();result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ConfigurationFilesystem))
    summary={'schema':'hepta.runtime.config-fs-native-tests.v1','status':'PASS' if result.wasSuccessful() else 'FAIL','test_groups':result.testsRun,'counts':dict(COUNTS),'elapsed_seconds':time.monotonic()-start,'manifest_sha256':sha(MANIFEST.read_bytes()),'source_sha256':sha((ROOT/'native/config_fs.hepta').read_bytes()),'adapter_sha256':sha((ROOT/'scripts/config_fs_adapter.S').read_bytes()),'actual_original_comparison_completed':False,'complete_config_owner':False}
    print(json.dumps(summary,sort_keys=True),flush=True);raise SystemExit(0 if result.wasSuccessful() else 1)

if __name__=='__main__':main()
