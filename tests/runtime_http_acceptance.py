#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real MCP acceptance. Creates only isolated runtime jobs, not production jobs.
Run locally on the controller with permission to read its token, never print it.
"""
import argparse, json, pathlib, subprocess, time, urllib.request, urllib.error, uuid
class Client:
    def __init__(self,url,token):
        self.url=url;self.token=token;self.session=None;self.i=0
        self.rpc('initialize',{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'hepta-acceptance','version':'1'}})
        self.rpc('notifications/initialized',{},notify=True)
    def rpc(self,method,params,notify=False):
        self.i+=1;data={'jsonrpc':'2.0','method':method,'params':params}
        if not notify:data['id']=self.i
        h={'Content-Type':'application/json','Accept':'application/json, text/event-stream','X-Hepta-Runtime-Token':self.token,'MCP-Protocol-Version':'2025-06-18'}
        if self.session:h['Mcp-Session-Id']=self.session
        with urllib.request.urlopen(urllib.request.Request(self.url,data=json.dumps(data).encode(),headers=h),timeout=50) as response:
            self.session=response.headers.get('Mcp-Session-Id',self.session);raw=response.read().decode()
        if notify:return None
        objects=[json.loads(line[5:].strip()) for line in raw.splitlines() if line.startswith('data:') and line[5:].strip()]
        obj=objects[-1] if objects else json.loads(raw)
        if 'error' in obj:raise RuntimeError(obj['error'])
        return obj['result']
    def call(self,name,args,denied=False):
        r=self.rpc('tools/call',{'name':name,'arguments':args})
        txt='\n'.join(x.get('text','') for x in r.get('content',[]) if x.get('type')=='text')
        if denied:
            assert r.get('isError'),(name,txt)
            return txt
        assert not r.get('isError'),(name,txt)
        try:return json.loads(txt)
        except json.JSONDecodeError:return txt

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--url',default='http://127.0.0.1:8789/mcp');ap.add_argument('--token-file',default='/etc/hepta-runtime/mcp-token');ap.add_argument('--restart-unit',default='hepta-runtime-canary.service');ap.add_argument('--out',required=True);args=ap.parse_args()
    token=pathlib.Path(args.token_file).read_text().strip();c=Client(args.url,token);checks=[];prefix=uuid.uuid4().hex[:12]
    def passed(name,detail=None):
        checks.append({'check':name,'result':'passed','detail':detail});print('PASS',name,flush=True)
        pathlib.Path(args.out).write_text(json.dumps({'checks':checks,'partial':True},indent=2))
    names={x['name'] for x in c.rpc('tools/list',{}).get('tools',[])}
    assert {'process_start','process_read','process_wait','process_cancel','pty_start','hardware_snapshot','network_inspect','service_status'}<=names
    assert 'shell' not in names;passed('MCP discovery / unrestricted shell absent',len(names))
    for header,expected in [({},401),({'X-Hepta-Runtime-Token':token,'Origin':'https://example.invalid'},403)]:
        try:urllib.request.urlopen(urllib.request.Request(args.url,data=b'{}',headers={'Content-Type':'application/json',**header}),timeout=5);raise AssertionError('unauthorized request accepted')
        except urllib.error.HTTPError as e:assert e.code==expected,e.code
    passed('HTTP unauthorized and browser-origin rejection')
    hosts=c.call('host_list',{})['hosts'];snapshots={}
    for h in hosts:
        name=h['name'];s=c.call('hardware_snapshot',{'host':name});assert s.get('hostname');snapshots[name]={'hostname':s['hostname'],'schema':s.get('schema')}
    passed('four-host hardware snapshots',snapshots)
    for host in ['rog','pocket4','x230','mac']:
        cwd='/Users/hepta-runtime/workspaces' if host=='mac' else '/var/lib/hepta-runtime/workspaces'
        p={'host':host,'executable':'/usr/bin/python3','args':['-c',"import os,sys;print('HOST_OK',os.getuid());print(sys.argv[1]);print(sys.stdin.read())","quote '\" ; $() 中文"],'cwd':cwd,'stdin':'INPUT_OK','timeout_seconds':20,'idempotency_key':prefix+'-'+host}
        j=c.call('process_start',p)['job']['id'];wait=c.call('process_wait',{'host':host,'job_id':j,'timeout_seconds':20});assert wait['state']=='succeeded',wait
        read=c.call('process_read',{'host':host,'job_id':j});assert 'INPUT_OK' in read['stdout']['text'];assert p['args'][2] in read['stdout']['text']
        again=c.call('process_start',p);assert again['reused'] and again['job']['id']==j
        c.call('process_start',{**p,'stdin':'CHANGED'},denied=True)
        c.call('process_read',{'host':host,'job_id':j,'stdout_offset':read['stdout']['size']+1},denied=True)
        passed(host+' argv/stdin/exit/idempotency/cursor')
    p={'host':'rog','executable':'/usr/bin/python3','args':['-c',"import os,socket,json;print(json.dumps({'uid':os.getuid(),'interfaces':socket.if_nameindex(),'state_visible':os.path.exists('/var/lib/hepta-runtime/.ssh'),'control_visible':os.path.exists('/etc/hepta-runtime/job-policy.json')}))"],'cwd':'/var/lib/hepta-runtime/workspaces','timeout_seconds':20}
    j=c.call('process_start',p)['job']['id'];assert c.call('process_wait',{'host':'rog','job_id':j,'timeout_seconds':20})['state']=='succeeded'
    d=json.loads(c.call('process_read',{'host':'rog','job_id':j})['stdout']['text']);assert d['uid']>=61184 and d['interfaces']==[[1,'lo']] and not d['state_visible'] and not d['control_visible'],d
    passed('actual namespace, separate UID and credential isolation',d)
    c.call('process_status',{'host':'pocket4','job_id':j},denied=True)
    c.call('process_cancel',{'host':'rog','job_id':'not-a-real-job'},denied=True)
    c.call('process_start',{'host':'pocket4','executable':'/usr/bin/sudo','args':['id']},denied=True)
    c.call('view',{'path':'/var/lib/hepta-runtime/.ssh/id_ed25519'},denied=True)
    c.call('view',{'path':'ssh://hepta-pocket4/home/alex/Jts/jts.ini'},denied=True)
    passed('wrong-host, unknown-job, sudo and protected paths denied')
    link='link-'+prefix;p['args']=['-c',f"import os;os.symlink('/var/lib/hepta-runtime/.ssh/id_ed25519','/workspace/{link}')"]
    j=c.call('process_start',p)['job']['id'];assert c.call('process_wait',{'host':'rog','job_id':j,'timeout_seconds':20})['state']=='succeeded'
    c.call('view',{'path':'ssh://hepta-rog/var/lib/hepta-runtime/workspaces/'+link},denied=True)
    passed('remote symlink cannot expose controller SSH key')
    p['args']=['-c',"import time;print('BEGIN',flush=True);time.sleep(120)"];p['timeout_seconds']=60
    j=c.call('process_start',p)['job']['id'];cancel=c.call('process_cancel',{'host':'rog','job_id':j});assert cancel['result'] in ('stop_requested','already_exited')
    assert c.call('process_wait',{'host':'rog','job_id':j,'timeout_seconds':10})['state']=='cancelled'
    passed('owned-unit cancellation')
    p['timeout_seconds']=1;j=c.call('process_start',p)['job']['id'];w=c.call('process_wait',{'host':'rog','job_id':j,'timeout_seconds':10});assert w['state']=='timed_out' and w['exit_code']==124,w
    passed('timeout terminates owned cgroup and preserves exit status')
    p['args']=['-c',"import sys;sys.stdout.buffer.write('中文α'.encode());sys.stderr.write('ERR')"];p['timeout_seconds']=20
    j=c.call('process_start',p)['job']['id'];c.call('process_wait',{'host':'rog','job_id':j,'timeout_seconds':10});cursor=0;data=b''
    while True:
        r=c.call('process_read',{'host':'rog','job_id':j,'stdout_offset':cursor,'limit':1});part=r['stdout'];data+=bytes.fromhex(part['bytes_hex']);assert part['next_offset']>=cursor;cursor=part['next_offset']
        if part['eof']:break
    assert data.decode()=='中文α';passed('one-byte lossless Unicode log pagination')
    session=c.call('pty_start',{'host':'rog','executable':'/usr/bin/python3','args':['-q'],'cwd':'/var/lib/hepta-runtime/workspaces'})['session_id']
    ready=''
    for _ in range(40):
        ready=c.call('pty_read',{'host':'rog','session_id':session})['text']
        if '>>>' in ready:break
        time.sleep(.2)
    assert '>>>' in ready,ready
    c.call('pty_write',{'host':'rog','session_id':session,'data':"print('PTY_OK')\n"})
    for _ in range(30):
        text=c.call('pty_read',{'host':'rog','session_id':session})['text']
        if '\nPTY_OK\r\n' in text:break
        time.sleep(.2)
    assert '\nPTY_OK\r\n' in text,text
    c.call('pty_close',{'host':'rog','session_id':session});passed('real PTY interactive input/read/close')
    p['args']=['-c',f"import time;open('once-{prefix}','a').write('1');print('RESTART_BEGIN',flush=True);time.sleep(10);print('RESTART_END',flush=True);print('ONCE_CONTENT='+open('once-{prefix}').read(),flush=True)"];p['timeout_seconds']=30;p['idempotency_key']=prefix+'-restart'
    j=c.call('process_start',p)['job']['id'];time.sleep(.5)
    subprocess.run(['systemctl','restart',args.restart_unit],check=True,timeout=40)
    for _ in range(50):
        try:c=Client(args.url,token);break
        except (OSError,urllib.error.URLError):time.sleep(.2)
    again=c.call('process_start',p);assert again['reused'] and again['job']['id']==j
    w=c.call('process_wait',{'host':'rog','job_id':j,'timeout_seconds':25});assert w['state']=='succeeded',w
    output=c.call('process_read',{'host':'rog','job_id':j})['stdout']['text'];assert 'RESTART_BEGIN' in output and 'RESTART_END' in output
    assert output.splitlines().count('ONCE_CONTENT=1')==1,output
    passed('actual controller systemd restart: same job ID, logs and completion')
    c.call('network_inspect',{'host':'pocket4'});c.call('service_status',{'host':'pocket4','services':['actions.runner.TrillionniumFoundation.pocket4.service']});passed('read-only network and protected service inspection')
    pathlib.Path(args.out).write_text(json.dumps({'checks':checks,'partial':False,'passed':len(checks),'at_unix':time.time()},indent=2));print('ALL_PASS',len(checks),flush=True)
if __name__=='__main__':main()
