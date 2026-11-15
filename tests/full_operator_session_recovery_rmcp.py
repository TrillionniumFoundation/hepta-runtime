#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real rmcp short-idle-expiry acceptance with a disposable authenticated server.

Builds a tiny, separate fixture using the repository's locked rmcp version.
No production runtime binary, configuration, token or service is modified.
"""
import argparse
import json
import os
import pathlib
import secrets
import select
import subprocess
import sys
import tempfile
import time
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'deploy'))
import chatgpt_full_operator as F
from mcp_tool_contract import ToolContract,make_contract
from runtime_http_acceptance import Client

RUST=r'''// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
//! Isolated short-timeout rmcp protocol acceptance server.
use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}};
use std::time::Duration;
use rmcp::{tool, tool_handler, tool_router, ServerHandler};
use rmcp::model::{ServerCapabilities, ServerConfig};
use rmcp::transport::streamable_http_server::{StreamableHttpService,
    StreamableHttpServerConfig, session::local::LocalSessionManager};

#[derive(Clone)]
struct Fixture { changed: Arc<AtomicBool>, effects: Arc<AtomicUsize> }
#[tool_router]
impl Fixture {
    #[tool(description="Inspect disposable fixture metadata", annotations(
        read_only_hint=true, destructive_hint=false, idempotent_hint=true, open_world_hint=false))]
    fn host_list(&self) -> String {
        serde_json::json!({"effects":self.effects.load(Ordering::SeqCst)}).to_string()
    }
    #[tool(description="Set disposable session workdir marker", annotations(
        read_only_hint=false, destructive_hint=false, idempotent_hint=true, open_world_hint=false))]
    fn workdir(&self) -> String { self.changed.store(true,Ordering::SeqCst); "set".into() }
    #[tool(description="Read disposable session workdir marker", annotations(
        read_only_hint=true, destructive_hint=false, idempotent_hint=true, open_world_hint=false))]
    fn view(&self) -> String { self.changed.load(Ordering::SeqCst).to_string() }
    #[tool(description="Record a synthetic effect without executing commands", annotations(
        read_only_hint=false, destructive_hint=true, idempotent_hint=false, open_world_hint=false))]
    fn shell_start(&self) -> String { self.effects.fetch_add(1,Ordering::SeqCst); "recorded".into() }
}
#[tool_handler(router=Self::tool_router())]
impl ServerHandler for Fixture {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }
}
async fn auth(request: axum::extract::Request, next: axum::middleware::Next)
    -> axum::response::Response {
    use axum::response::IntoResponse;
    let expected=std::env::var("HEPTA_FIXTURE_TOKEN").unwrap_or_default();
    if expected.is_empty() || request.headers().get("X-Hepta-Runtime-Token")
        .and_then(|v|v.to_str().ok()) != Some(expected.as_str()) {
        return axum::http::StatusCode::UNAUTHORIZED.into_response();
    }
    next.run(request).await
}
#[tokio::main]
async fn main() -> Result<(),Box<dyn std::error::Error>> {
    let effects=Arc::new(AtomicUsize::new(0));
    let mut manager=LocalSessionManager::default();
    manager.session_config.keep_alive=Some(Duration::from_millis(600));
    let service=StreamableHttpService::new(move || Ok(Fixture {
        changed:Arc::new(AtomicBool::new(false)), effects:effects.clone()
    }),Arc::new(manager),StreamableHttpServerConfig::default());
    let app=axum::Router::new().nest_service("/mcp",service)
        .layer(axum::middleware::from_fn(auth));
    let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    println!("http://{}/mcp",listener.local_addr()?);
    axum::serve(listener,app).await?;
    Ok(())
}
'''


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--work-root',type=pathlib.Path,default=ROOT.parent/'session-recovery-fixture')
    parser.add_argument('--out',type=pathlib.Path)
    args=parser.parse_args();args.work_root.mkdir(mode=0o700,parents=True,exist_ok=True)
    lock=(ROOT/'Cargo.lock').read_text()
    import re
    version=re.search(r'\[\[package\]\]\nname = "rmcp"\nversion = "([^"]+)"',lock).group(1)
    checks=[];proxies=[];process=None
    def passed(name):checks.append(name);print('PASS',name,flush=True)
    with tempfile.TemporaryDirectory(prefix='case-',dir=args.work_root) as folder:
        work=pathlib.Path(folder);(work/'src').mkdir()
        (work/'src/main.rs').write_text(RUST)
        (work/'Cargo.toml').write_text('[package]\nname="hepta-session-recovery-fixture"\nversion="0.0.0"\nedition="2021"\n'
            '[dependencies]\nrmcp={version="='+version+'",features=["server","macros","transport-streamable-http-server"]}\n'
            'tokio={version="1.53.1",features=["rt-multi-thread","macros","net"]}\n'
            'axum={version="0.8",default-features=false,features=["http1","tokio"]}\n'
            'serde_json="1.0.151"\n[profile.dev]\ndebug=0\n')
        target=args.work_root/'target'
        build=subprocess.run(['cargo','build','--offline','--manifest-path',str(work/'Cargo.toml'),
            '--target-dir',str(target)],capture_output=True,text=True,timeout=240)
        if build.returncode:raise RuntimeError(build.stderr[-6000:])
        token=secrets.token_hex(32)
        process=subprocess.Popen([str(target/'debug/hepta-session-recovery-fixture')],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
            env={**os.environ,'HEPTA_FIXTURE_TOKEN':token})
        try:
            if not select.select([process.stdout],[],[],10)[0]:raise AssertionError('fixture startup deadline')
            url=process.stdout.readline().strip();assert url.startswith('http://127.0.0.1:')
            client=Client(url,token);contract=ToolContract(make_contract(client.rpc('tools/list',{})['tools']))
            init={'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'real-rmcp-expiry','version':'1'}}
            counter=0
            def dispatch(proxy,method,params):
                nonlocal counter
                counter+=1;return proxy.dispatch({'jsonrpc':'2.0','id':counter,'method':method,'params':params})
            def call(proxy,name):return dispatch(proxy,'tools/call',{'name':name,'arguments':{}})
            def proxy():
                value=F.NativeProxy(url,token,contract,timeout=3);proxies.append(value)
                assert 'result' in dispatch(value,'initialize',init);return value
            with mock.patch.object(F,'KEEPALIVE_INTERVAL',.1):
                live=proxy();assert 'result' in call(live,'workdir');sid=live.session
                time.sleep(1.4)
                viewed=call(live,'view');assert viewed['result']['content'][0]['text']=='true',viewed
                assert live.session==sid
                passed('real rmcp heartbeat preserves native session and workdir past two idle timeouts')
                cold=proxy();cold._keepalive_stop.set();cold._keepalive_thread.join(1)
                sid=cold.session;time.sleep(.9)
                assert 'result' in call(cold,'host_list');assert cold.session!=sid
                refused=call(cold,'view');assert refused['error']['data']['reinitialize_required'] is True
                assert refused['error']['data']['outcome']=='not_submitted'
                refused=call(cold,'shell_start');assert refused['error']['data']['outcome']=='not_submitted'
                effects=json.loads(call(cold,'host_list')['result']['content'][0]['text'])['effects']
                assert effects==0
                passed('real rmcp exact stale-session 404 recovers host reads while refusing lost state and writes')
                assert 'result' in dispatch(cold,'initialize',init)
                assert 'result' in call(cold,'shell_start')
                assert json.loads(call(cold,'host_list')['result']['content'][0]['text'])['effects']==1
                passed('explicit initialize restores operations with exactly one synthetic effect')
            receipt={'schema':'hepta-rmcp-session-recovery-acceptance-v1','complete':True,
                'rmcp_version':version,'native_idle_timeout_ms':600,'checks':checks,
                'installed_service_changed':False,'real_host_actions_executed':False}
            if args.out:
                args.out.parent.mkdir(parents=True,exist_ok=True)
                args.out.write_text(json.dumps(receipt,indent=2)+'\n')
            print('ALL_PASS',len(checks),flush=True)
        finally:
            for item in proxies:item.close()
            if process is not None:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
                process.stdout.close();process.stderr.close()


if __name__=='__main__':main()
