#!/usr/bin/env python3
"""Complete original-only profile gate and saved guard custody, without target calls."""
from pathlib import Path
import argparse,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from legacy_common import canonical,decode,owned,pin,require,source_evidence
from guard_refs import tree,saved_guard
import legacy_read_profile as read_profile
import legacy_cases as cases
from readonly import guarded
def verify(source,work,group):
    identity=source_evidence(source);gate=decode(owned(work,"GATE.json").read_bytes())
    origin=decode(owned(work,"ORIGIN.json").read_bytes());old=Path(origin["work"]);oldsource=Path(origin["source"])
    require(owned(work,"ORIGIN.json").read_bytes()==owned(work/"admission","ORIGIN.json").read_bytes(),
        "immutable original profile origin copy")
    rows=decode(owned(work,"processes/processes.json").read_bytes())
    require(rows==gate["processes"]and [(p["name"],p["timeout_seconds"])for p in rows]==
        [("source-check",60),("runtime-source",60),("original-profile",60),("full-read",180)],
        "complete original profile producer process table")
    values={p["name"]:read_profile.process(work/"processes",p,p["name"],p["timeout_seconds"])for p in rows}
    pre=decode(owned(work/"admission","processes/processes.json").read_bytes());require(pre==rows[:3],"immutable pre-read process records")
    for row in pre:
        for key in("stdout","stderr"):
            name=row[key]["file"];require(owned(work/"processes",name).read_bytes()==owned(work/"admission/processes",name).read_bytes(),
                "entire immutable pre-read process stream")
    expected=[
        [origin["python"],"-I","-S","-B",str(oldsource/"scripts/driver.py"),"check","--work",str(old),"--group",str(group),
            "--source-manifest-sha256",identity["manifest"]["sha256"]],
        [origin["python"],"-I","-S","-B",str(oldsource/"scripts/runtime.py"),"--output",str(old/"runtime")],
        [origin["python"],"-I","-S","-B",str(oldsource/"scripts/original_capture.py"),"--group",str(group),"--runtime",str(old/"runtime"),
            "--output",str(old/"capture")],
        [origin["python"],"-I","-S","-B",str(oldsource/"scripts/read_profile.py"),"--source",str(oldsource),"--work",str(old),"--group",str(group)]]
    require(all(row["argv"]==command and row["cwd"]==str(oldsource)for row,command in zip(rows,expected)),
        "every exact bounded original profile producer command")
    require(gate["schema"]=="hepta.runtime.python-json-value.original-profile-gate.v1"and gate["status"]=="PASS"
        and gate["source"]==identity and gate["group"]==str(group)and gate["source_check"]==values["source-check"]
        ==decode(owned(work,"SOURCE_CHECK.json").read_bytes())and gate["runtime"]==values["runtime-source"]
        and gate["actual"]==values["original-profile"]==decode(owned(work/"capture","CAPTURE.json").read_bytes())
        and gate["original_calls"]==gate["actual"]["cases"]and gate["native_applications"]==gate["application_replays"]==0,
        "complete actual original-only producer gate")
    actual=read_profile.verify(source,work,group);primary=decode(owned(work,"READONLY.json").read_bytes())
    require(primary==values["full-read"]and primary["evidence"]==gate["read"]==actual,"full actual depth result")
    refs=saved_guard(primary,{str(oldsource):tree(source),str(old/"capture"):tree(work/"capture"),
        str(old/"runtime"):tree(work/"runtime"),str(old/"admission"):tree(work/"admission")})
    return dict(status="COMPLETE_RETAINED_ORIGINAL_JSON_PROFILE_GATE_PASS",profile=actual,
        saved_guard_full_file_references=refs,new_original_calls=0,new_native_calls=0,application_replays=0)
def main():
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--work",type=Path,required=True)
    p.add_argument("--group",required=True);a=p.parse_args();source,work=a.source.resolve(strict=True),a.work.resolve(strict=True)
    cases.set_source(source)
    "".encode("utf-32-le","surrogatepass")
    value=guarded(lambda:verify(source,work,a.group),roots=[source,work])
    print(canonical(value).decode(),end="")
if __name__=="__main__":main()
