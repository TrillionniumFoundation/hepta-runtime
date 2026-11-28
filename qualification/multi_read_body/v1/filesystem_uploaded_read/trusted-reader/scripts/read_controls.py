"""Independent complete producer/guard/physical-copy admission; no semantic replay."""
from pathlib import Path
import copy,gzip,hashlib
from evidence_common import decode,encoded,pin,require,source_evidence
from read_build_evidence import tree,saved_guard
import read_build_evidence,read_capture
def identities(root):
    files,dirs=tree(root)
    return {p:dict(**pin(v[0]),mode=v[1])for p,v in files.items()},dirs
def controls(source,data,frozen,actual,returned,controls_origin,original_source):
    source,data,capture=map(Path,(source,data,frozen))
    guarded_files=0
    controls=decode((capture/"controls/RESULT.json").read_bytes())
    require(controls==returned
        and controls["status"]=="EIGHT_PHYSICAL_REFUSALS_TWO_FULL_RELOCATIONS_PASS"
        and controls["guard_probes"]==110 and controls["application_executions"]==0,"whole ten guarded controls")
    names=["native-buffer","original-stdout","native-journal","original-case","native-image","source-manifest","honest-native-result","honest-original-result"]
    require([c["name"]for c in controls["physical"]]==names and len(controls["relocations"])==2,"physical domain fixed")
    base_files,base_dirs=identities(data);source_files,source_dirs=identities(source)
    for c in controls["physical"]:
        root=capture/"controls"/c["name"];copied=root/"data";selected_source=root/"source"if c["name"]=="source-manifest"else source
        mutation=decode((root/"MUTATION.json").read_bytes());require(mutation==c["mutation"],"full mutation record")
        prefix=controls_origin+"/"+c["name"]+("/source"if c["name"]=="source-manifest"else"/data")
        relative=Path(mutation["file"]).relative_to(prefix).as_posix()
        changed=(selected_source if c["name"]=="source-manifest"else copied)/relative
        original=(source if c["name"]=="source-manifest"else data)/relative
        before=(root/"changed-before.bin").read_bytes();after=(root/"changed-after.bin").read_bytes()
        require(before==original.read_bytes()and after==changed.read_bytes()and before!=after
            and mutation["before"]==dict(**pin(original),mode=original.stat().st_mode&0o777)
            and mutation["after"]==dict(**pin(changed),mode=changed.stat().st_mode&0o777)
            and mutation["before_bytes"]==pin(root/"changed-before.bin")and mutation["after_bytes"]==pin(root/"changed-after.bin"),
            "real physical full before/after bytes")
        copied_files,copied_dirs=identities(copied);require(copied_dirs==base_dirs and set(copied_files)==set(base_files),"complete physical copy set")
        changes={p for p in base_files if base_files[p]!=copied_files[p]}
        if c["name"]=="source-manifest":
            require(not changes and after==before+b"\nACTUAL_BAD_SOURCE\n","source-only physical change")
            sf,sd=identities(selected_source);require(sd==source_dirs and set(sf)==set(source_files)
                and {p for p in sf if sf[p]!=source_files[p]}=={"SOURCE_MANIFEST.json"},"only one physical source mutation")
        elif c["name"].startswith("honest-"):
            require(changes=={relative,str(Path(relative).with_name("CAPTURE.json"))}and mutation["honestly_resealed"],"honest control changed only full case and own seal")
            left=[decode(x)for x in gzip.decompress(before).splitlines()]
            right=[decode(x)for x in gzip.decompress(after).splitlines()]
            altered=copy.deepcopy(right);a=left[0]["actual"]["chain"]["invocations"][0]["result"]
            b=altered[0]["actual"]["chain"]["invocations"][0]["result"]
            require("__physically_resealed_bad_field__"not in a and b.pop("__physically_resealed_bad_field__")is True,
                "one honestly resealed whole-result alteration")
            require(altered==left,"no additional honest control mutation")
            folder=changed.parent;report=decode((folder/"CAPTURE.json").read_bytes())
            raw=gzip.decompress(after);rows=raw.splitlines(keepends=True)
            require(report["cases_file"]==pin(changed)and report["cases_raw"]==dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
                and report["case_rows"]==[dict(id=v["input"]["id"],bytes=len(r),sha256=hashlib.sha256(r).hexdigest())for v,r in zip(right,rows)],"honest complete reseal")
            base_report=decode((original.parent/"CAPTURE.json").read_bytes())
            require({k:v for k,v in report.items()if k not in("cases_file","cases_raw","case_rows")}
                =={k:v for k,v in base_report.items()if k not in("cases_file","cases_raw","case_rows")},"honest seal changed no other producer record")
        else:
            require(changes=={relative}and not mutation["honestly_resealed"],"one physical byte-bearing file change")
            if c["name"]=="native-buffer":
                a,b=gzip.decompress(before),gzip.decompress(after);require(b==bytes([a[0]^1])+a[1:],"real complete buffer alteration")
            else:require(after==bytes([before[0]^1])+before[1:],"real byte alteration")
        guard=decode((root/"READONLY.json").read_bytes())
        selected_origin=controls_origin+"/"+c["name"]+"/source"if c["name"]=="source-manifest"else original_source
        data_origin=controls_origin+"/"+c["name"]+"/data"
        guarded_files+=saved_guard(guard,{selected_origin:tree(selected_source),data_origin:tree(copied)})
        require(guard["evidence"]==c["evidence"]and guard["evidence"]["status"]=="REJECTED"and c["guard_probes"]==11,
            "physical original guarded rejection")
    for index,c in enumerate(controls["relocations"],1):
        require(c["name"]=="relocated-"+str(index),"fixed complete relocation")
        root=capture/"controls"/c["name"];sf,sd=identities(root/"source");df,dd=identities(root/"data")
        require((sf,sd)==(source_files,source_dirs)and(df,dd)==(base_files,base_dirs),"all complete relocated source/data bytes and modes")
        guard=decode((root/"READONLY.json").read_bytes())
        base=controls_origin+"/"+c["name"]
        guarded_files+=saved_guard(guard,{base+"/source":tree(root/"source"),base+"/data":tree(root/"data")})
        require(guard["evidence"]==actual==c["evidence"]and c["guard_probes"]==11 and c["entries"]==guard["entries"],"complete retained relocation result")
    require({p.name for p in (capture/"controls").iterdir()}==set(names)|{"relocated-1","relocated-2","RESULT.json"},
        "complete physical control root inventory")
    return controls,guarded_files
