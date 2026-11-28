"""Run the static HIA MCP and the unchanged original owners through rmcp.

This is a test runner. The Rust reference is permitted only in CI or the owned
remote reference environment. Both complete tool-response wire byte streams
are retained; neither Python JSON formatting nor core-only results are an oracle.
"""
from pathlib import Path
import argparse,collections,gzip,hashlib,json,os,select,shutil,subprocess,tempfile,time,tomllib
from config_mcp_cases import cases,compact
sha=lambda b:hashlib.sha256(b).hexdigest()

class Session:
    def __init__(self,binary,path):
        self.p=subprocess.Popen([str(binary),'--runtime-config',str(path)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'','LC_ALL':'C'})
        self.pending=bytearray();self.count=0
    def line(self):
        end=time.monotonic()+60
        while b'\n' not in self.pending:
            left=end-time.monotonic()
            if left<=0 or not select.select([self.p.stdout],[],[],left)[0]:raise AssertionError(('actual MCP timeout',self.count,self.p.poll()))
            b=os.read(self.p.stdout.fileno(),65536)
            if not b:raise AssertionError(('actual MCP EOF',self.count,self.p.poll(),self.p.stderr.read()))
            self.pending.extend(b)
        line,_,rest=self.pending.partition(b'\n');self.pending=bytearray(rest);return bytes(line)
    def call(self,raw):self.p.stdin.write(raw+b'\n');self.p.stdin.flush();self.count+=1;return self.line()
    def start(self):
        raw=compact({'jsonrpc':'2.0','id':0,'method':'initialize','params':{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'original-comparison','version':'1'}}})
        line=self.call(raw);parsed=json.loads(line);assert parsed['result']['protocolVersion']=='2025-06-18'
        self.p.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n');self.p.stdin.flush();return line
    def close(self):
        self.p.stdin.close();self.p.wait(timeout=30);stderr=self.p.stderr.read()
        assert (self.p.returncode,stderr,bytes(self.pending))==(0,b'',b'')
    def abort(self):
        if self.p.poll() is None:self.p.kill();self.p.wait(timeout=15)

def run(binary,config,out,label):
    result=[];session=Session(binary,config);start=time.monotonic()
    try:
        initial=session.start();(out/(label+'-initialize.json')).write_bytes(initial+b'\n')
        inputs=hashlib.sha256();outputs=hashlib.sha256();inbytes=outbytes=0
        with gzip.open(out/(label+'-requests.hex.gz'),'wb') as req,gzip.open(out/(label+'-responses.hex.gz'),'wb') as resp:
            for name,raw in cases():
                line=session.call(raw);got=json.loads(line)
                assert got.get('jsonrpc')=='2.0' and isinstance(got.get('result'),dict),(name,line[:2048])
                assert set(got['result'])=={'content','isError'} and len(got['result']['content'])==1
                a=raw.hex().encode()+b'\n';b=line.hex().encode()+b'\n';req.write(a);resp.write(b);inputs.update(a);outputs.update(b);inbytes+=len(a);outbytes+=len(b)
                result.append({'label':name,'request_sha256':sha(raw),'response_sha256':sha(line),'is_error':got['result']['isError'],'request_bytes':len(raw),'response_bytes':len(line)})
        session.close()
        return {'rows':result,'requests_sha256':inputs.hexdigest(),'responses_sha256':outputs.hexdigest(),'request_bytes':inbytes,'response_bytes':outbytes,'elapsed':time.monotonic()-start,'exit':session.p.returncode,'initialize_sha256':sha(initial)}
    finally:session.abort()
