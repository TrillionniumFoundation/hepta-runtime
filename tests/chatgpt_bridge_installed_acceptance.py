#!/usr/bin/env python3
import argparse,http.client,json,pathlib,socket

ALLOWED={"host_list","process_status","file_info","stream_handoff_list","stream_handoff_status","stream_handoff_read","document_read"}

def call(sock,payload,headers=None):
    body=json.dumps(payload,separators=(",",":")).encode()
    hdr={"Host":"hepta-chatgpt.local","Connection":"close","Content-Type":"application/json","Content-Length":str(len(body))}
    if headers:hdr.update(headers)
    req=("POST /mcp HTTP/1.1\r\n"+"".join(f"{k}: {v}\r\n" for k,v in hdr.items())+"\r\n").encode()+body
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(20);s.connect(sock);s.sendall(req);chunks=[]
    while True:
        b=s.recv(65536)
        if not b:break
        chunks.append(b)
    s.close();raw=b"".join(chunks);head,_,body=raw.partition(b"\r\n\r\n");lines=head.decode(errors="replace").split("\r\n")
    status=int(lines[0].split()[1]);out={}
    for line in lines[1:]:
        if ":" in line:
            k,v=line.split(":",1);out[k.lower()]=v.strip()
    value=None
    ctype=out.get("content-type","")
    if body and "text/event-stream" in ctype:
        objects=[json.loads(line[5:].strip()) for line in body.decode().splitlines() if line.startswith("data:") and line[5:].strip()]
        value=objects[-1] if objects else None
    elif body:
        value=json.loads(body)
    return status,out,value

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--socket",required=True);ap.add_argument("--out",required=True);a=ap.parse_args()
    report={"complete":False,"checks":[]}
    def ok(label,detail=None):
        report["checks"].append({"check":label,"detail":detail});pathlib.Path(a.out).write_text(json.dumps(report,indent=2)+"\n");print("PASS",label,flush=True)

    init={"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"installed-bridge-acceptance","version":"1"}}}
    status,h,value=call(a.socket,init,{"Authorization":"Bearer caller-value-must-be-ignored"})
    assert status==200 and value["result"]["serverInfo"]["name"]=="hepta-chatgpt-readonly",value
    session=h.get("mcp-session-id");ok("installed facade authenticates locally while ignoring caller Authorization",{"session":bool(session)})

    common={"MCP-Protocol-Version":"2025-06-18"}
    if session:common["Mcp-Session-Id"]=session
    notify={"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
    status,_,_=call(a.socket,notify,common);assert status in (200,202);ok("initialized notification accepted",status)

    status,_,listing=call(a.socket,{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}},common)
    tools=listing["result"]["tools"];names={t["name"] for t in tools};assert names==ALLOWED,(names,ALLOWED)
    for t in tools:
        ann=t.get("annotations") or {}
        assert ann.get("readOnlyHint") is True and ann.get("destructiveHint") is False and ann.get("idempotentHint") is True and ann.get("openWorldHint") is False
    ok("exact seven-tool read-only discovery",sorted(names))

    status,_,value=call(a.socket,{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"host_list","arguments":{}}},common)
    content=value["result"]["content"];text=next(x["text"] for x in content if x.get("type")=="text");hosts=json.loads(text)["hosts"];assert len(hosts)==6
    ok("golden host_list returns all six configured hosts",len(hosts))

    status,_,value=call(a.socket,{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"shell_start","arguments":{"host":"main","executable":"/bin/true"}}},common)
    assert value["error"]["code"]==-32601
    ok("shell_start rejected by facade before private runtime","-32601")

    status,_,value=call(a.socket,{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"stream_handoff_list","arguments":{"limit":1}}},common)
    assert "result" in value and not value["result"].get("isError",False)
    ok("read-only stream_handoff_list traverses installed broker")

    report.update(complete=True,passed=len(report["checks"]),allowed_tools=sorted(ALLOWED),caller_authorization_forwarded=False)
    pathlib.Path(a.out).write_text(json.dumps(report,indent=2)+"\n");print("CHATGPT_INSTALLED_BRIDGE_PASS",report["passed"])

if __name__=="__main__":main()
