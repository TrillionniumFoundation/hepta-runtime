#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Inspect fully retained trace bytes without executing a captured program."""
from pathlib import Path
import argparse,hashlib,io,json,os,struct,urllib.error,urllib.parse,urllib.request,zipfile
def require(v,m):
    if not v:raise ValueError(m)
class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    require(not a.output.exists(),"fresh proof output");a.output.mkdir(parents=True)
    req=urllib.request.Request("https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/14307025682/zip",
        headers={"Authorization":"Bearer "+os.environ["GH_TOKEN"],"Accept":"application/vnd.github+json"})
    try:r=urllib.request.build_opener(Redirect()).open(req,timeout=60)
    except urllib.error.HTTPError as e:
        require(e.code in (301,302,303,307,308),"redirect");url=e.headers["Location"]
        require(urllib.parse.urlparse(url).scheme=="https","HTTPS");r=urllib.request.urlopen(url,timeout=60)
    with r:raw=r.read()
    require(len(raw)==768722 and hashlib.sha256(raw).hexdigest()=="183618b8b56e58adb2844e0316074c6f982d70508cda2af2dda664c091ffb376","full independent proof ZIP")
    (a.output/"PROOF.zip").write_bytes(raw)
    out=[]
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        require(len(z.namelist())==len(set(z.namelist())) and z.testzip() is None,"complete ZIP members")
        index=json.loads(z.read("FILES.json"));rows={r["path"]:r for r in index["files"]}
        report=json.loads(z.read("REVIEW.json"));require(report["artifact"]==14306501241 and report["files"]==11243,"full-read proof identity")
        for n in z.namelist():
            if not n.endswith("/stderr"):continue
            value=z.read(n);key=n.removeprefix("selected/")
            expected=rows[key]
            require(len(value)==expected["bytes"] and hashlib.sha256(value).hexdigest()==expected["sha256"],"retained complete stderr")
            records=[];gaps=[];at=0
            while at<len(value):
                if value[at:at+8]==b"HRGTR002" and at+224<=len(value):
                    w=struct.unpack_from("<28Q",value,at)
                    records.append(dict(offset=at,seq=w[1],slot=w[2],event=w[3],rc=w[4],phase=w[7],length=w[9],
                        action=value[at+80:at+192].hex(),header=value[at+192:at+224].hex()))
                    at+=224
                else:
                    end=value.find(b"HRGTR002",at+1)
                    if end<0:end=len(value)
                    gaps.append(dict(offset=at,bytes=end-at,head=value[at:min(end,at+256)].hex(),tail=value[max(at,end-128):end].hex()))
                    at=end
            errors=[r for r in records if r["event"]==1 and r["rc"]>=4294901760 and r["rc"] not in (4294967280,4294967248,4294967245)]
            out.append(dict(path=n,bytes=len(value),records=len(records),gaps=gaps,
                first_errors=errors[:20],last_errors=errors[-10:],tail=records[-20:]))
    (a.output/"DIAGNOSTIC.json").write_text(json.dumps(out,sort_keys=True,indent=2)+"\n")
    print("SELECTED_DIAGNOSTIC="+json.dumps(out,sort_keys=True))
if __name__=="__main__":main()
