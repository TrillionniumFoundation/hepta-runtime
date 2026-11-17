#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Byte-only diagnostic of both retained actual failed lifecycle producers."""
from pathlib import Path
import argparse,collections,gzip,hashlib,json,struct,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
U=lambda b,n:struct.unpack_from("<Q",b,n)[0]
IDENTITIES={
"legacy":dict(artifact=14342040058,zip=dict(bytes=10239830,sha256="a9fec68e2011839804b0dca6be25f74a30d7612d6b524b6ed088be19e312c6b9"),
archive=dict(bytes=9362475,sha256="6e00800e9998367da74f73f32ef8a214443f28f13a5179a66d2a5caf96f2f95b")),
"modern":dict(artifact=14341831077,zip=dict(bytes=7685896,sha256="47204d0931939b0846ac4c805b878604993ecf7dc834681fcd4abf3c340db79d"),
archive=dict(bytes=7150653,sha256="16a00cf0259ae1496754b3559273f5596a99b171b339e3978f030386add58303"))}
def main():
    p=argparse.ArgumentParser();p.add_argument("--retained",type=Path,required=True)
    p.add_argument("--build-recipe",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    sys.path.insert(0,str(a.retained));from common import canonical,decode,pin,require,sha,source_evidence
    from buffer_store import Reader
    import readonly
    source=source_evidence(a.retained)
    for r in decode((HERE/"SOURCE_MANIFEST.json").read_bytes())["files"]:
        require(pin(HERE/r["path"])=={k:r[k] for k in ("bytes","sha256")},"inspector source")
    sys.path.insert(0,str(a.build_recipe/"current"));from restore_full import restore
    restored={label:restore(a.output/label,identity) for label,identity in IDENTITIES.items()}
    def operation():
        result={}
        for label,(root,archive) in restored.items():
            domain=root/"capture/native";cases=[];plan=decode((domain/"PLAN.json").read_bytes())
            for case in sorted((domain/"cases").iterdir()):
                sr=Reader(case/"buffers")
                commands=decode((case/"COMMANDS.json").read_bytes())
                controls=decode((case/"process/CONTROLS.json").read_bytes())
                process=decode((case/"process/PROCESS.json").read_bytes())
                kept={r["case"]:r for r in plan["cases"]}[int(case.name)]
                row=dict(case=int(case.name),name=kept["name"],era=kept["era"],commands=len(commands),
                    controls=len(controls),process={k:process[k] for k in ("pid","exit_code","elapsed_seconds","timed_out","completion_error","cleanup_errors")},
                    complete=(case/"RESULT.json").exists())
                if not row["complete"]:
                    row["failure"]=decode((case/"FAILURE.json").read_bytes())
                    row["last_commands"]=[dict(number=r["number"],request=decode(sr.get(r["request"])),result=r["result"],
                        state_control=r["state_control"]) for r in commands[-5:]]
                    tail=[]
                    for r in controls[-5:]:
                        co=sr.get(r["coordinator"]);pms=[sr.get(x) for x in r["pms"]]
                        tail.append(dict(number=r["number"],request_hex=sr.get(r["request"]).hex(),
                            header_hex=sr.get(r["header"]).hex(),events=[list(struct.unpack_from("<8Q",co,512+i*64)) for i in range(U(co,448))],
                            pms=[{str(n):U(b,n) for n in (216,224,232,240,272,296,304,312,320,328,816,832,1232,1256,1264)} for b in pms]))
                    row["last_controls"]=tail
                    path=case/"process/host-trace.gz";raw=gzip.decompress(path.read_bytes())
                    require(dict(bytes=len(raw),sha256=sha(raw))==process["files"]["host-trace"]["raw"],"whole actual trace")
                    at=0;count=0;grow=collections.deque(maxlen=40);events=collections.deque(maxlen=16)
                    while at<len(raw):
                        magic=raw[at:at+8]
                        if magic==b"HRGTR002":
                            require(len(raw)-at>=224,"whole native trace frame");b=raw[at:at+224]
                            grow.append(dict(offset=at,header=list(struct.unpack_from("<10Q",b)),workspace_256_hex=b[80:192].hex(),output_prefix_hex=b[192:224].hex()))
                            length=224
                        elif magic==b"HRCNAK02":
                            length=128;require(len(raw)-at>=length,"whole actual canonical ACK trace")
                        elif magic==b"HPTREV01":
                            require(len(raw)-at>=128,"whole host trace header");b=raw[at:at+128];length=U(b,8)
                            require(length==128+U(b,72)+U(b,80)+U(b,88) and length<=len(raw)-at,"whole host trace spans")
                            base=at+128;parts=[]
                            for extent in (U(b,72),U(b,80),U(b,88)):
                                value=raw[base:base+extent];base+=extent
                                parts.append(dict(bytes=extent,sha256=sha(value),prefix_hex=value[:256].hex()))
                            events.append(dict(offset=at,header=list(struct.unpack_from("<16Q",b)),parts=parts))
                        else:
                            row["unparsed_trace_tail"]=dict(offset=at,bytes=len(raw)-at,prefix_hex=raw[at:at+256].hex());break
                        at+=length;count+=1
                    row["trace"]=dict(bytes=len(raw),sha256=sha(raw),parsed_bytes=at,frames=count,last_grow=list(grow),last_events=list(events))
                cases.append(row)
            result[label]=dict(archive=archive,cases=cases)
        return dict(status="COMPLETE_ARCHIVE_RETAINED_FAILURE_DIAGNOSTIC",sources=source,roles=result,
            hia_executed=False,rust_executed=False,semantic_replay=False,qualification=False)
    proof=readonly.guarded(operation,roots=[HERE,a.retained,*[x[0] for x in restored.values()]])
    (a.output/"READONLY.json").write_bytes(canonical(proof));(a.output/"DIAGNOSTIC.json").write_bytes(canonical(proof["evidence"]))
    print("RETAINED_FAILURE_DIAGNOSTIC "+json.dumps(proof["evidence"],sort_keys=True),flush=True)
if __name__=="__main__":main()
