#!/usr/bin/env python3
import http.server,json,os,pathlib,subprocess,sys,tempfile,threading,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
BRIDGE=ROOT/'deploy/chatgpt_mcp_bridge.py'

class Fake(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'; seen=[]
    def log_message(self,*a): pass
    def do_POST(self):
        n=int(self.headers.get('Content-Length','0')); raw=self.rfile.read(n); req=json.loads(raw)
        Fake.seen.append((req.get('method'),self.headers.get('Mcp-Session-Id'),self.headers.get('MCP-Protocol-Version'),self.headers.get('X-Hepta-Runtime-Token')))
        method=req.get('method'); ident=req.get('id')
        if method=='notifications/initialized':
            self.send_response(202);self.send_header('Content-Length','0');self.end_headers();return
        if method=='initialize':
            value={'jsonrpc':'2.0','id':ident,'result':{'protocolVersion':'2025-06-18','capabilities':{'tools':{}},'serverInfo':{'name':'private','version':'1'}}}
            self._sse(value,session='session-fixture');return
        if method=='tools/list':
            value={'jsonrpc':'2.0','id':ident,'result':{'tools':[{'name':'host_list','inputSchema':{'type':'object'}},{'name':'shell_start','inputSchema':{'type':'object'}}]}}
            self._json(value);return
        if method=='tools/call' and req.get('params',{}).get('name')=='host_list':
            content=json.dumps({'hosts':[{'name':'main'}]})
            self._json({'jsonrpc':'2.0','id':ident,'result':{'content':[{'type':'text','text':content}]}});return
        self._json({'jsonrpc':'2.0','id':ident,'error':{'code':-32601,'message':'unknown'}})
    def _json(self,v):
        b=json.dumps(v,separators=(',',':')).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
    def _sse(self,v,session=None):
        b=('data: '+json.dumps(v,separators=(',',':'))+'\n\n').encode();self.send_response(200);self.send_header('Content-Type','text/event-stream');self.send_header('Content-Length',str(len(b))); 
        if session:self.send_header('Mcp-Session-Id',session)
        self.end_headers();self.wfile.write(b)

class Stdio(unittest.TestCase):
    def test_stdio_bridge_retains_session_and_filters_tools(self):
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Fake);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        with tempfile.TemporaryDirectory() as d:
            token=pathlib.Path(d)/'token';token.write_text('fixture-secret');os.chmod(token,0o600)
            proc=subprocess.Popen([sys.executable,str(BRIDGE),'--stdio','--upstream',f'http://127.0.0.1:{server.server_port}/mcp','--token-file',str(token)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
            def send(v,expect=True):
                proc.stdin.write(json.dumps(v,separators=(',',':'))+'\n');proc.stdin.flush()
                if not expect:return None
                line=proc.stdout.readline()
                if not line:
                    self.fail(proc.stderr.read())
                return json.loads(line)
            try:
                init=send({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'fixture','version':'1'}}})
                self.assertEqual(init['result']['serverInfo']['name'],'hepta-chatgpt-readonly')
                tools=send({'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}})['result']['tools']
                self.assertEqual([x['name'] for x in tools],['host_list'])
                self.assertTrue(tools[0]['annotations']['readOnlyHint']);self.assertFalse(tools[0]['annotations']['destructiveHint'])
                denied=send({'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'shell_start','arguments':{}}})
                self.assertEqual(denied['error']['code'],-32601)
                host=send({'jsonrpc':'2.0','id':4,'method':'tools/call','params':{'name':'host_list','arguments':{}}})
                self.assertIn('hosts',host['result']['content'][0]['text'])
                upstream=[x for x in Fake.seen if x[0] in ('tools/list','tools/call')]
                self.assertTrue(all(x[1]=='session-fixture' for x in upstream))
                self.assertTrue(all(x[2]=='2025-06-18' for x in upstream))
                self.assertTrue(all(x[3]=='fixture-secret' for x in upstream))
            finally:
                proc.terminate();proc.wait(timeout=5)
                for stream in (proc.stdin,proc.stdout,proc.stderr):
                    if stream is not None: stream.close()
                server.shutdown();server.server_close();thread.join(timeout=2)

if __name__=='__main__':unittest.main(verbosity=2)
