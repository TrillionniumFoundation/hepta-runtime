#!/usr/bin/env python3
import argparse, http.client, json, os, pathlib, socket, subprocess, sys, tempfile, time

ROOT = pathlib.Path(__file__).resolve().parents[1]
BRIDGE = ROOT / "deploy/chatgpt_mcp_bridge.py"
ALLOWED = {
    "host_list","process_status","file_info",
    "stream_handoff_list","stream_handoff_status","stream_handoff_read","document_read",
}

def unix_http(path, method, payload=None, headers=None):
    body = b"" if payload is None else json.dumps(payload,separators=(",",":")).encode()
    hdr = {
        "Host":"hepta-chatgpt.local",
        "Connection":"close",
        "Content-Length":str(len(body)),
        "Accept":"application/json, text/event-stream",
    }
    if payload is not None: hdr["Content-Type"]="application/json"
    if headers: hdr.update(headers)
    request = (method+" /mcp HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k,v in hdr.items()) + "\r\n").encode()+body
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(20); s.connect(path); s.sendall(request)
    chunks=[]
    while True:
        b=s.recv(65536)
        if not b: break
        chunks.append(b)
    s.close(); raw=b"".join(chunks)
    head,_,body=raw.partition(b"\r\n\r\n")
    lines=head.decode(errors="replace").split("\r\n")
    status=int(lines[0].split()[1]); response_headers={}
    for line in lines[1:]:
        if ":" in line:
            k,v=line.split(":",1); response_headers[k.lower()]=v.strip()
    value=None
    content_type=response_headers.get("content-type","").lower()
    if body and "text/event-stream" in content_type:
        events=[json.loads(line[5:].strip()) for line in body.decode().splitlines()
                if line.startswith("data:") and line[5:].strip()]
        value=events[-1] if events else None
    elif body:
        value=json.loads(body)
    return status,response_headers,value

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--token-file",required=True); ap.add_argument("--out",required=True)
    a=ap.parse_args()
    report={"complete":False,"checks":[],"allowed_tools":sorted(ALLOWED)}
    def passed(label,detail=None):
        report["checks"].append({"check":label,"detail":detail})
        pathlib.Path(a.out).write_text(json.dumps(report,indent=2)+"\n")
        print("PASS",label,flush=True)

    # Backend must not be anonymously callable.
    conn=http.client.HTTPConnection("127.0.0.1",8790,timeout=5)
    init={"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"bridge-acceptance-direct","version":"1"}}}
    conn.request("POST","/mcp",json.dumps(init),{"Content-Type":"application/json","Accept":"application/json"})
    resp=conn.getresponse(); direct_status=resp.status; resp.read(); conn.close()
    if direct_status not in (401,403): raise AssertionError(f"backend unexpectedly anonymous: {direct_status}")
    passed("private runtime rejects anonymous direct MCP",direct_status)

    with tempfile.TemporaryDirectory(prefix="hepta-chatgpt-bridge-") as td:
        root=pathlib.Path(td); os.chmod(root,0o700); sock=str(root/"bridge.sock")
        log=(root/"bridge.log").open("wb")
        proc=subprocess.Popen([sys.executable,str(BRIDGE),"--socket",sock,"--token-file",a.token_file],
                              stdin=subprocess.DEVNULL,stdout=log,stderr=log)
        try:
            for _ in range(100):
                if pathlib.Path(sock).exists(): break
                if proc.poll() is not None: raise RuntimeError((root/"bridge.log").read_text(errors="replace"))
                time.sleep(.05)
            else: raise RuntimeError("bridge socket did not appear")
            if pathlib.Path(sock).stat().st_mode & 0o077: raise AssertionError("bridge socket is not private")

            # A caller-supplied Authorization header is deliberately ignored.
            status,h,initial=unix_http(sock,"POST",init,{"Authorization":"Bearer definitely-not-the-runtime-token"})
            assert status==200 and initial["result"]["serverInfo"]["name"]=="hepta-chatgpt-readonly", initial
            session=h.get("mcp-session-id")
            passed("bridge injects private local backend credential and ignores caller Authorization",
                   {"session":bool(session),"server":initial["result"]["serverInfo"]["name"]})

            n={"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
            nh={"MCP-Protocol-Version":"2025-06-18"}
            if session: nh["Mcp-Session-Id"]=session
            status,_,_=unix_http(sock,"POST",n,nh)
            assert status in (200,202)
            passed("MCP initialized notification accepted",status)

            req={"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
            status,_,listing=unix_http(sock,"POST",req,nh)
            assert status==200 and "result" in listing, listing
            tools=listing["result"]["tools"]; names={t["name"] for t in tools}
            assert names==ALLOWED,(names,ALLOWED)
            for tool in tools:
                ann=tool.get("annotations") or {}
                assert ann.get("readOnlyHint") is True
                assert ann.get("destructiveHint") is False
                assert ann.get("idempotentHint") is True
                assert ann.get("openWorldHint") is False
            passed("tool discovery exposes exactly seven read-only allowlisted tools",sorted(names))

            call={"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"host_list","arguments":{}}}
            status,_,value=unix_http(sock,"POST",call,nh)
            assert status==200 and "result" in value,value
            content=value["result"].get("content") or []
            text=next(x["text"] for x in content if x.get("type")=="text")
            hosts=json.loads(text)["hosts"]
            assert len(hosts)==6,hosts
            passed("read-only host_list traverses facade into authenticated six-host runtime",len(hosts))

            denied={"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"shell_start","arguments":{"host":"main","executable":"/bin/true"}}}
            status,_,value=unix_http(sock,"POST",denied,nh)
            assert status==200 and value["error"]["code"]==-32601,value
            passed("write/execute tool is rejected before backend forwarding","shell_start")

            status,_,health=unix_http(sock,"GET",None)
            # GET /mcp is intentionally not a health surface; only POST is accepted.
            assert status==405
            passed("facade has no accidental MCP GET surface",status)

            report.update(complete=True,passed=len(report["checks"]),backend_direct_status=direct_status,
                          socket_mode=oct(pathlib.Path(sock).stat().st_mode & 0o777),
                          inbound_authorization_forwarded=False,backend_token_in_report=False)
            pathlib.Path(a.out).write_text(json.dumps(report,indent=2)+"\n")
            print("CHATGPT_BRIDGE_ACCEPTANCE_PASS",report["passed"])
        finally:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)
            log.close()

if __name__=="__main__": main()
