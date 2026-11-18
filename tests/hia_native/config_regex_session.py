"""Test-only framing for the complete native validation/regex child chain."""
from pathlib import Path
import hashlib,json,os,select,struct,subprocess,time
from hia_native_loader import NativeRejected,NativeCapacityError


class NativeValidator:
    def __init__(self,manifest,source_root):
        self.manifest=manifest;self.meta=json.loads(manifest.read_bytes());self.closed=False
        executable=manifest.parent/self.meta['executable'];elf=executable.read_bytes()
        sha=lambda raw:hashlib.sha256(raw).hexdigest()
        assert sha(elf)==self.meta['executable_sha256']
        assert [row['id']for row in self.meta['members']]==[3,15,10,12,13,14,11]
        for row in self.meta['members']:
            source='native/config_validation.hepta'if row['id']==3 else row['source']
            assert sha((source_root/source).read_bytes())==row['source_sha256']
            assert sha(elf[row['offset']:row['offset']+row['image_bytes']])==row['image_sha256']
        self.process=subprocess.Popen([str(executable)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'','LC_ALL':'C'})
        self.calls=0
    def read(self,n):
        result=bytearray();deadline=time.monotonic()+30
        while len(result)<n:
            remaining=deadline-time.monotonic()
            assert remaining>0 and select.select([self.process.stdout],[],[],remaining)[0],'native validation timeout'
            chunk=os.read(self.process.stdout.fileno(),n-len(result))
            assert chunk,('native validation EOF',self.process.poll(),self.process.stderr.read())
            result.extend(chunk)
        return bytes(result)
    def invoke(self,wire):
        self.process.stdin.write(struct.pack('<Q',len(wire))+wire);self.process.stdin.flush();self.calls+=1
        code,n=struct.unpack('<2Q',self.read(16));assert n<=128<<20
        result=self.read(n)
        if code==0:return result
        assert n==0
        if code==0xfffffffe:raise NativeCapacityError('native validation capacity')
        raise NativeRejected('native validation domain refusal',code)
    def close(self):
        if self.closed:return
        self.closed=True;self.process.stdin.close();self.process.wait(timeout=15)
        assert(self.process.returncode,self.process.stderr.read())==(0,b'')
    def __enter__(self):return self
    def __exit__(self,*args):
        if args[0] and self.process.poll() is None:self.closed=True;self.process.kill();self.process.wait(timeout=15)
        else:self.close()
