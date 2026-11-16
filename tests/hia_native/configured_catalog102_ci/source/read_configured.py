"""Read complete catalog buffers without executing HIA, Rust, or a process."""
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import configured_common as c


def verify(source, build, output):
    sources,proof,frontend=c.source_check(source);builds,modules=c.build_check(build,source)
    r=c.BASE.Reader(output);report=r.document("result.json");cases=c.cases(source)
    assert report["schema"]=="hepta.runtime.catalog-configured-native.v1"
    assert report["status"]=="ACTUAL_NATIVE_CAPTURE_READER_REQUIRED"
    assert report["source_profile"]==c.pin((source/"source-profile.json").read_bytes())
    assert report["public_all_configuration_qualified"] is False and report["whole_runtime_replaced"] is False
    for field in ("pid","parent_pid","pgid"):assert type(report[field]) is int and report[field]>0
    assert type(report["elapsed_ns"]) is int and 0<report["elapsed_ns"]<=180_000_000_000
    assert type(report["native_deadline_seconds"]) is int and report["native_deadline_seconds"]==180
    assert len(report["records"])==len(cases)
    assert type(report["actual_native_calls"]) is int
    assert report["actual_native_calls"]==sum(len(row["owners"]) for row in cases)
    packed=(source/"retained/native/catalog-common.lzss").read_bytes()
    packed+=bytes((-len(packed))%8)
    asset=(source/"retained/native/catalog-mode-0.bin").read_bytes()
    common=asset[asset.index(b'"tools":['):]
    assert len(packed)==proof["decompressed_destination_base"]==6960
    assert len(packed)+len(common)==22151
    previous={};rows=[];matrix=[]
    for ordinal,(case,row) in enumerate(zip(cases,report["records"],strict=True)):
        assert row["case"]==case["name"]
        assert [call["owner"] for call in row["calls"]]==case["owners"]
        complete=[]
        for call in row["calls"]:
            for field in ("output_capacity","workspace_capacity","code"):
                assert type(call[field]) is int and call[field]>=0
            assert call["output_capacity"]==case["output_capacity"] and call["workspace_capacity"]==case["workspace_capacity"]
            out,work=c.BASE.read_call(r,call,case["wire"],f"case-{ordinal:04d}-{call['owner']}")
            complete.append((call["code"],out,work))
        if case["kind"]=="retained":
            assert complete[0]==complete[1],("retained complete buffers changed",case["name"])
        else:
            code,out,work=complete[0]
            before_out,before_work=previous.get(case["group"],(b"\xa7"*len(out),b"\x59"*len(work)))
            if case["kind"]=="invalid":
                assert code==0xffffffff and out==before_out and work==before_work,case["name"]
            else:
                mode,flags,installed=struct.unpack_from("<3Q",case["wire"],16)
                wanted=c.projected_asset(source,mode,flags,installed)
                if len(out)<32:
                    assert code==0xfffffffe and out==before_out and work==before_work
                elif len(work)<c.WORKSPACE:
                    assert code==0xffffffd0 and out[:32]==b"HGRWS002"+struct.pack("<3Q",1,c.WORKSPACE,0)
                    assert out[32:]==before_out[32:] and work==before_work
                elif len(out)<32+len(wanted):
                    assert code==0xffffffd0 and out[:32]==b"HGRWS002"+struct.pack("<3Q",2,32+len(wanted),0)
                    assert out[32:]==before_out[32:] and work==before_work
                else:
                    assert code==32 and out[:32]==b"HRCATR02"+struct.pack("<3Q",0,len(wanted),0)
                    assert out[32:32+len(wanted)]==wanted
                    assert out[32+len(wanted):]==before_out[32+len(wanted):]
                    assert work==packed+common+before_work[len(packed)+len(common):]
                    if case["name"].startswith("matrix-"):
                        matrix.append({"mode":mode,"flags":flags,"installed":installed,"fragment":c.pin(wanted)})
            if case["group"]:previous[case["group"]]=(out,work)
        rows.append({"case":case["name"],"calls":len(complete)})
    assert [(row["installed"],row["flags"],row["mode"]) for row in matrix]==[(i,f,m) for i in range(4) for f in c.FLAGS for m in (0,1)]
    return {"status":"COMPLETE_CONFIGURED_CATALOG_NATIVE_READONLY_PASS", "cases":len(cases),
        "actual_native_calls":report["actual_native_calls"],"retained_cases":87,"retained_non_list_operations":18,
        "matrix":matrix,"source_files":sources.files,"build_files":builds.files,"native_files":r.files,
        "modules":modules,"case_rows":rows,"process_launches":0,"native_execution":False,"rust_execution":False,
        "public_all_configuration_qualified":False,"public_handler_admission_qualified":False,"whole_runtime_replaced":False}
