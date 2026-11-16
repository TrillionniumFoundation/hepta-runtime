"""Ordinary framing corpus for owned serial stdio and the exact SDK transport."""
from pathlib import Path
from dataclasses import dataclass
import argparse, hashlib, json
CAP=16*1024*1024
def sha(raw):return hashlib.sha256(raw).hexdigest()
def wire(value):return json.dumps(value,ensure_ascii=False,separators=(",",":")).encode()
def ping(identifier=1):return wire({"jsonrpc":"2.0","id":identifier,"method":"ping"})
def padded(total,ending=b"\n",identifier=1):
    body=ping(identifier)
    assert total>=len(body)+len(ending)
    return body+b" "*(total-len(body)-len(ending))+ending
def inputs():
    a,b,c=ping(1),ping(2),ping(3)
    return [
        ("empty",b"",8192),
        ("ping-lf",a+b"\n",8192),
        ("ping-crlf",a+b"\r\n",8192),
        ("json-whitespace",b" \t"+a+b" \t\n",8192),
        ("three-complete",a+b"\n"+b+b"\n"+c+b"\n",8192),
        ("empty-lines",b"\n\r\n"+a+b"\n\n",8192),
        ("bom-line",b"\xef\xbb\xbf"+a+b"\n",8192),
        ("bom-each-line",b"\xef\xbb\xbf"+a+b"\n\xef\xbb\xbf"+b+b"\n",8192),
        ("unicode-id",ping("ordinary-文-🟢")+b"\n",8192),
        ("eof-tail",a,8192),
        ("eof-cr-tail",a+b"\r",8192),
        ("complete-then-tail",a+b"\n"+b,8192),
        ("crlf-then-tail",a+b"\r\n"+b,8192),
        ("small-byte-chunks",a+b"\n"+b+b"\n",1),
        ("cap-minus-one",padded(CAP-1),65536),
        ("cap-equal",padded(CAP),65536),
        ("cap-plus-one",padded(CAP+1),65536),
        ("over-cap-then-complete",padded(CAP+1)+b+b"\n",65536),
        ("over-cap-eof-tail",padded(CAP+1,ending=b""),65536),
        ("cap-crlf",padded(CAP,ending=b"\r\n"),65536),
        ("cap-plus-one-crlf",padded(CAP+1,ending=b"\r\n"),65536),
        ("cap-then-complete",padded(CAP)+b+b"\n",65536),
        ("two-complete-then-tail",a+b"\n"+b+b"\n"+c,8192),
        ("cap-unicode-id",padded(CAP,identifier="ordinary-文"),65536),
    ]
def records():
    result=[]
    for label,payload,chunk in inputs():
        result.append(dict(label=label,mode="async",input_file="cases/inputs/"+label+".bin",chunk_size=chunk,
                           input_bytes=len(payload),input_sha256=sha(payload)))
    for label,target in [("codec-eof-tail","eof-tail"),("codec-eof-cr-tail","eof-cr-tail"),
                         ("codec-complete-then-tail","complete-then-tail"),("codec-over-cap-eof","over-cap-eof-tail")]:
        parent=next(r for r in result if r["label"]==target)
        result.append(dict(label=label,mode="codec-eof",input_file=parent["input_file"],
                           input_bytes=parent["input_bytes"],input_sha256=parent["input_sha256"]))
    return result
def build(output):
    output=Path(output).resolve();folder=output/"cases";folder.mkdir(parents=True,exist_ok=False)
    (folder/"inputs").mkdir()
    for label,payload,_ in inputs():(folder/"inputs"/(label+".bin")).write_bytes(payload)
    rows=records()
    raw=b"".join(wire({k:v for k,v in row.items() if k not in ("input_bytes","input_sha256")})+b"\n" for row in rows)
    (folder/"reference-input.jsonl").write_bytes(raw)
    manifest=dict(schema="hepta.public-serial-transport.corpus.v1",
        current_line_limit_bytes_including_lf=CAP,async_cases=24,codec_eof_reference_only_cases=4,
        exact_sdk_default_limit=True,codec_is_not_public_transport=True,
        ordinary_ping_data_only=True,special_risk_inputs=False,tool_bodies_invoked=False,
        selected_modes=["async","codec-eof"],shutdown_service_mode_selected=False,
        partial_receive_cancellation_mode_selected=False,writer_callback_timing_qualified=False,
        author_sha256=sha(Path(__file__).read_bytes()),reference_input=dict(bytes=len(raw),sha256=sha(raw)),cases=rows)
    (folder/"manifest.json").write_text(json.dumps(manifest,sort_keys=True,indent=2)+"\n")
    return manifest
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--output",required=True,type=Path);a=p.parse_args()
    result=build(a.output);print(json.dumps({k:v for k,v in result.items() if k!="cases"},sort_keys=True))
