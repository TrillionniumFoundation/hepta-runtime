"""Pure admission of frozen engine storage evidence. No native execution."""
from pathlib import Path
import argparse,json,struct,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from common import source,read,pin,SHA
from layout import layout,rebind,upgrade,undo
from memory import maps,cover,absent,stack_pointer,u64,qput,MASK
INVALID=0xffffffff
RESOURCE=0xfffffffc
BOUNDARY=0xfffffff9
class Objects:
    def __init__(self,root):
        self.root=root;self.cache={};self.seen=set();self.physical_bytes=0;self.snapshots=0
    def get(self,value):
        assert set(value)=={"bytes","sha256"} and type(value["bytes"]) is int and value["bytes"]>=0
        key=value["sha256"];assert len(key)==64 and all(c in "0123456789abcdef" for c in key)
        if key not in self.cache:
            raw=read(self.root/key);assert pin(raw)==value;self.cache[key]=raw
        raw=self.cache[key];assert len(raw)==value["bytes"]
        self.seen.add(key);self.physical_bytes+=len(raw);return raw
class Model:
    def __init__(self,case,leaf,objects,frame):
        self.case=case;self.count=case["slots"];self.layout=layout(self.count);self.leaf=leaf
        self.objects=objects;self.frame=frame;self.regions={};self.engine=None;self.native_calls=0
        self.output_frames=set();self.canonical=[];self.stack={};self.data={};self.mapped={}
    def adopt(self,snapshot,label,capacity,guard,kind,slot=None,borrowed=False):
        actual=snapshot["regions"][label]
        assert actual["capacity"]==capacity and actual["guard"] is guard and actual["kind"]==kind
        assert actual["slot"]==slot and actual["borrowed"] is borrowed and actual["mapped"] is True
        address=actual["address"];assert type(address) is int and 0<address<(1<<63)
        if guard:assert address%4096==0
        descriptor={k:actual[k] for k in ("address","capacity","guard","kind","slot","borrowed")}
        assert label not in self.regions;self.regions[label]=descriptor
        self.data[label]=bytearray(capacity);self.mapped[label]=True
        return address
    def address(self,label):return self.regions[label]["address"]
    def word(self,slot,offset):return self.layout["descriptor_base"]+64*slot+offset
    def get_word(self,slot,offset):return u64(self.data["engine"],self.word(slot,offset))
    def set_word(self,slot,offset,value):qput(self.data["engine"],self.word(slot,offset),value)
    def bit(self,slot,kind,value):
        if slot<64:offset=64 if kind=="work" else 72;bit=slot
        else:offset=self.layout["work_high" if kind=="work" else "output_high"]+8*((slot-64)//64);bit=slot%64
        raw=self.data["engine"];word=u64(raw,offset)
        qput(raw,offset,word|(1<<bit) if value else word&~(1<<bit))
    def bit_value(self,slot,kind):
        if slot<64:offset=64 if kind=="work" else 72;bit=slot
        else:offset=self.layout["work_high" if kind=="work" else "output_high"]+8*((slot-64)//64);bit=slot%64
        return (u64(self.data["engine"],offset)>>bit)&1
    def validate(self,snapshot):
        assert set(snapshot)=={"maps","regions"} and set(snapshot["regions"])==set(self.regions)
        rows=maps(self.objects.get(snapshot["maps"]))
        intervals=[]
        for label,expected in self.regions.items():
            value=snapshot["regions"][label]
            assert {k:value[k] for k in expected}==expected,(self.case["name"],label,"physical descriptor")
            assert set(value)==set(expected)|{"mapped","physical"}
            assert value["mapped"] is self.mapped[label],(self.case["name"],label,"mapping lifetime")
            address=expected["address"];capacity=expected["capacity"]
            if self.mapped[label]:
                assert cover(rows,address,capacity,"rw-p"),(label,"writable extent")
                if expected["guard"]:assert cover(rows,address+capacity,4096,"---p"),(label,"guard page")
                raw=self.objects.get(value["physical"])
                assert raw==self.data[label],(self.case["name"],label,"complete physical bytes")
                intervals.append((address,address+capacity+(4096 if expected["guard"] else 0),label))
            else:
                assert value["physical"] is None and expected["guard"]
                assert absent(rows,address,capacity+4096),(label,"retirement")
        intervals.sort()
        assert all(a[1]<=b[0] for a,b in zip(intervals,intervals[1:])),intervals
        self.objects.snapshots+=1
    def initial(self,row):
        assert row["kind"]=="create" and row["case"]==self.case["name"] and row["slots"]==self.count
        assert row["role"]==self.case["role"]
        for label,size in (("frame",80),("table",8*self.count+16),("node",528)):
            self.adopt(row["before"],label,size,False,label)
        self.data["frame"][:]=self.frame+b"\xc3"*16
        for slot in range(self.count):qput(self.data["table"],8*slot,self.leaf)
        self.data["table"][8*self.count:]=b"\xef"*16
        self.data["node"][512:]=b"\xd7"*16
        self.validate(row["before"])
        self.engine=self.adopt(row["after"],"engine",self.layout["engine_bytes"],True,"engine")
        assert row["return_u64"]==self.engine
        assert row["fixture_node_engine_write"]==dict(offset=392,value=self.engine)
        qput(self.data["node"],392,self.engine)
        qput(self.data["engine"],0,self.address("table"))
        qput(self.data["engine"],8,self.engine+self.layout["descriptor_base"])
        self.data["engine"][40:48]=b"HRGENG02"
        for slot in range(self.count):self.set_word(slot,0,self.leaf)
        self.native_calls=1;self.validate(row["after"]);self.canonical.append(self.normalized())
    def new_buffer(self,after,slot,kind,capacity,borrowed=False):
        label=kind+":"+str(slot)
        address=self.adopt(after,label,capacity,True,kind,slot,borrowed)
        if borrowed:self.data[label][:]=bytes([0x5a if kind=="work" else 0xa5])*capacity
        self.set_word(slot,8 if kind=="work" else 32,address)
        self.set_word(slot,16 if kind=="work" else 40,capacity)
        if not borrowed:self.bit(slot,kind,1)
    def control(self,after,slot):
        kind="workdir-control" if slot==15 else "filesystem-control"
        address=self.adopt(after,kind,4096,True,kind)
        qput(self.data["engine"],192 if slot==15 else 200,address)
        value=self.data[kind];qput(value,0,self.address("frame"))
        for off,n in ((8,64),(16,self.address("work:"+str(slot))),(24,1056768 if slot==15 else 8192),
                      (32,self.address("output:"+str(slot))),(40,4096),(48,64),(72,MASK),(80,MASK)):
            qput(value,off,n)
        actual=self.objects.get(after["regions"][kind]["physical"])
        rows=maps(self.objects.get(after["maps"]));offset=152 if slot==15 else 184
        stack=u64(actual,offset);assert stack_pointer(rows,stack),(kind,"inactive stack pointer")
        self.stack[kind]=stack;qput(value,offset,stack)
        if slot==15:
            for off,n in ((120,self.engine),(128,self.leaf),(136,BOUNDARY)):qput(value,off,n)
        else:
            for off,n in ((88,MASK),(112,1),(120,64),(128,BOUNDARY),(168,self.engine),(176,self.leaf),
                          (200,1),(264,1),(272,64),(304,64),(312,4096),(320,8192)):
                qput(value,off,n)
            value[256:264]=b"HFSPCL02"
    def action(self,row,index,action):
        assert row["kind"]=="action" and row["case"]==self.case["name"] and row["index"]==index
        assert row["action"]==action
        self.validate(row["before"])
        op=action["op"];slot=action.get("slot");details={};expected=None;calls=0
        if op=="invoke":
            calls=1
            if slot>=self.count:expected=INVALID
            elif self.get_word(slot,0)==0:expected=RESOURCE
            else:
                for kind in ("work","output"):
                    if self.get_word(slot,8 if kind=="work" else 32)==0:
                        capacity=1056768 if slot==15 and kind=="work" else 8192 if slot==24 and kind=="work" else 4096
                        self.new_buffer(row["after"],slot,kind,capacity)
                self.data["output:"+str(slot)][:64]=self.frame;self.output_frames.add(slot)
                qput(self.data["engine"],128,u64(self.data["engine"],128)+1)
                expected=BOUNDARY if slot in (15,24) else 64
                self.set_word(slot,48,expected);self.set_word(slot,56,0 if slot in (15,24) else 64)
                if slot in (15,24):self.control(row["after"],slot)
        elif op in ("detach","restore"):
            calls=1;expected=0;desc=self.word(18,0);continuation=512+64*18;node=self.data["node"];engine=self.data["engine"]
            if op=="detach":
                assert self.bit_value(18,"work")==self.bit_value(18,"output")==1
                assert self.get_word(18,48)==self.get_word(18,56)==64
                node[88:152]=engine[desc:desc+64];node[152:216]=engine[continuation:continuation+64]
                qput(node,216,3);engine[desc+8:desc+64]=bytes(56);engine[continuation:continuation+64]=bytes(64)
                self.bit(18,"work",0);self.bit(18,"output",0)
            else:
                assert u64(node,216)==3 and engine[desc+8:desc+64]==bytes(56)
                engine[desc:desc+64]=node[88:152];engine[continuation:continuation+64]=node[152:216]
                self.bit(18,"work",1);self.bit(18,"output",1);qput(node,216,0)
        elif op=="borrow":
            calls=2;assert self.get_word(slot,8)==self.get_word(slot,32)==0
            for kind in ("work","output"):self.new_buffer(row["after"],slot,kind,4096,True)
            details["allocations"]={kind:self.address(kind+":"+str(slot)) for kind in ("work","output")}
        elif op=="zero_entry":
            details["previous"]=self.get_word(slot,0);self.set_word(slot,0,0)
        elif op=="busy":
            off=512+64*slot;details["previous"]=u64(self.data["engine"],off);qput(self.data["engine"],off,action["value"])
        elif op in ("unalign","repair"):
            kind=action["kind"];off=8 if kind=="work" else 32
            details["previous"]=self.get_word(slot,off)
            value=self.address(kind+":"+str(slot))+(1 if op=="unalign" else 0)
            self.set_word(slot,off,value);details["written"]=value
        elif op=="destroy":
            calls=1;engine=self.data["engine"]
            busy=any(u64(engine,512+64*i) or u64(engine,520+64*i) for i in range(self.count))
            if busy:expected=MASK-21
            else:
                failed=False
                for i in range(self.count):
                    for kind,po,co in (("work",8,16),("output",32,40)):
                        if not self.bit_value(i,kind):continue
                        label=kind+":"+str(i);address=self.get_word(i,po)
                        if address%4096:
                            assert address==self.address(label)+1
                            failed=True
                        else:
                            assert address==self.address(label) and self.mapped[label]
                            self.mapped[label]=False;self.set_word(i,po,0);self.set_word(i,co,0);self.bit(i,kind,0)
                expected=MASK-21 if failed else 0
                if not failed:
                    for kind in ("workdir-control","filesystem-control","engine"):
                        if kind in self.mapped:self.mapped[kind]=False
        elif op=="release_borrows":
            assert self.mapped["engine"] is False;releases=[]
            for label,region in sorted(self.regions.items()):
                if region["borrowed"]:
                    assert self.mapped[label];self.mapped[label]=False
                    releases.append(dict(label=label,result=0,errno=0))
            details["releases"]=releases
        else:raise AssertionError(op)
        assert row["return_u64"]==expected,(self.case["name"],index,op,"return",row["return_u64"],expected)
        assert row["details"]==details and row["actual_native_calls"]==calls
        self.native_calls+=calls;self.validate(row["after"]);self.canonical.append(self.normalized())
    def normalized(self):
        """Exact physical buffers, with only validated native addresses normalized."""
        labels=["engine","table","frame","node"]+sorted(k for k in self.regions if k not in {"engine","table","frame","node"})
        ids={label:(index+2)<<32 for index,label in enumerate(labels)}
        def pointer(value):
            if value==0:return 0
            if value==self.leaf:return 1<<32
            for label,region in self.regions.items():
                if region["address"]<=value<region["address"]+region["capacity"]:
                    return ids[label]+value-region["address"]
            raise AssertionError(("unexpected pointer",value))
        result={}
        for label,region in sorted(self.regions.items()):
            raw=bytearray(self.data[label]);kind=region["kind"]
            offsets=[]
            if kind=="engine":
                offsets=[0,8,192,200]
                offsets += [self.word(i,j) for i in range(self.count) for j in (0,8,32)]
            elif kind=="table":offsets=list(range(0,8*self.count,8))
            elif kind=="node":offsets=[392,88,96,120]
            elif kind=="workdir-control":offsets=[0,16,32,120,128];qput(raw,152,0)
            elif kind=="filesystem-control":offsets=[0,16,32,168,176];qput(raw,184,0)
            for off in offsets:qput(raw,off,pointer(u64(raw,off)))
            result[label]=dict(capacity=region["capacity"],guard=region["guard"],kind=kind,slot=region["slot"],
                borrowed=region["borrowed"],mapped=self.mapped[label],
                full_normalized_physical_sha256=SHA(raw) if self.mapped[label] else None)
        return result
def admit(build,output,expected_source):
    identity=source(expected_source);build=Path(build).resolve(strict=True);output=Path(output).resolve(strict=True)
    buildraw=read(build/"BUILD.json");compiled=json.loads(buildraw);capture=json.loads(read(output/"NATIVE.json"))
    assert compiled["status"]=="PASS" and capture["status"]=="CAPTURED"
    assert capture["source_manifest_sha256"]==compiled["source_manifest_sha256"]==identity
    assert capture["build"]==pin(buildraw)
    assert capture["host_semantic_fallback"] is False and capture["old_graph_above_59_executed"] is False
    domain=json.loads(read(ROOT/"DOMAIN.json"));cases=json.loads(read(ROOT/"CASES.json"))
    old=read(ROOT/"reference/runtime_mcp_extra_engine.S").decode();base=read(ROOT/"engines/new_59.S").decode()
    assert upgrade(old)==base and undo(base)==old
    assert compiled["engine_variants"]==len(domain["new_slot_counts"])+1==19
    assert set(compiled["images"])=={"old59"}|{"new"+str(n) for n in domain["new_slot_counts"]}
    for role,info in compiled["images"].items():
        count=59 if role=="old59" else int(role[3:])
        assert info["slots"]==count and info["layout"]==layout(count)
        sourcebytes=old.encode() if role=="old59" else read(ROOT/"engines"/("new_"+str(count)+".S"))
        if role!="old59":assert sourcebytes.decode()==rebind(base,count)
        assert pin(sourcebytes)==info["source"]
        assert pin(read(build/role/"combined.S"))==info["combined"]
        assert pin(read(build/role/"module.bin"))==info["image"],(role,"compiled engine image bytes")
        assert info["old_low_words_only"] is (role=="old59")
    for name,tool in compiled["assembler_toolchain"].items():
        assert pin(read(build/"toolchain"/name))=={k:tool[k] for k in ("bytes","sha256")}
    compiler=json.loads(read(ROOT/"COMPILER_IDENTITY.json"));assert compiled["compiler"]==compiler
    retained={p.relative_to(build/"compiler-source").as_posix() for p in (build/"compiler-source").rglob("*") if p.is_file()}
    assert retained==set(compiler["files"]) and len(retained)==1080
    for path,expected in compiler["files"].items():assert SHA(read(build/"compiler-source"/path))==expected
    bootstrap=json.loads(read(build/"hia/bootstrap/bootstrap.json"))
    assert bootstrap["dependency"]==compiler and bootstrap["qualification"]=="development_fixed_point"
    compiler_pin=dict(bytes=673413,sha256="bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0")
    assert compiled["compiler_image"]==compiler_pin and bootstrap["generation_sha256"]==compiler_pin["sha256"]
    assert bootstrap["compiler_source_sha256"]==compiler["files"]["examples/hia_bootstrap/selfhost.hepta"]
    for label in ("B1","B2","B3"):assert pin(read(build/"hia/bootstrap"/(label+".image.bin")))==compiler_pin
    manifest=read(build/compiled["hia_leaf"]["manifest"]);assert pin(manifest)==compiled["hia_leaf"]["manifest_pin"]
    leafmeta=json.loads(manifest);assert leafmeta["source_sha256"]==SHA(read(ROOT/"native/fixture_leaf.hepta"))
    leafbase=(build/compiled["hia_leaf"]["manifest"]).parent
    assert pin(read(leafbase/leafmeta["image"]))==compiled["hia_leaf"]["image"]
    assert read(leafbase/leafmeta["source"])==read(ROOT/"native/fixture_leaf.hepta")
    processes=json.loads(read(build/"processes/processes.json"));assert len(processes)==4+6*19
    for process in processes:
        assert process["completed"] is True and process["timed_out"] is False and process["exit_code"]==0
        assert process["timeout_seconds"]==60 and process["elapsed_seconds"]<60 and process["pid"]==process["pgid"]
        for key in ("stdout","stderr"):
            info=process[key];assert pin(read(build/"processes"/info["file"]))=={k:info[k] for k in ("bytes","sha256")}
    journal=read(output/"journal.ndjson");assert pin(journal)==capture["journal"]
    rows=[json.loads(line) for line in journal.splitlines()];assert rows and rows[0]["kind"]=="session" and rows[-1]["kind"]=="session_end"
    objects=Objects(output/"objects");start=rows[0];assert start["source_manifest_sha256"]==identity and start["build"]==pin(buildraw)
    leaf=start["leaf_address"];assert type(leaf) is int and 0<leaf<(1<<63)
    assert pin(objects.get(start["leaf"]))==compiled["hia_leaf"]["image"]
    cursor=1;models={};calls=0;canonical={}
    for case in cases["cases"]:
        row=rows[cursor];cursor+=1
        info=compiled["images"][case["role"]]
        assert pin(objects.get(row["engine_image"]))==info["image"]
        maprows=maps(objects.get(row["before"]["maps"]))
        assert cover(maprows,row["engine_image_address"],info["image"]["bytes"],"r-xp")
        assert cover(maprows,leaf,compiled["hia_leaf"]["image"]["bytes"],"r-xp")
        model=Model(case,leaf,objects,bytes.fromhex(cases["frame_hex"]));model.initial(row)
        for index,action in enumerate(case["actions"]):
            model.action(rows[cursor],index,action);cursor+=1
        end=rows[cursor];cursor+=1
        assert end["kind"]=="case_end" and end["case"]==case["name"] and end["actions"]==len(case["actions"])
        assert end["all_case_native_mappings_retired"] is True
        assert not any(model.mapped[label] for label,region in model.regions.items() if region["guard"])
        assert pin(objects.get(end["engine_image_after"]))==info["image"]
        calls+=model.native_calls;models[case["name"]]=model
        if case["role"] in {"old59","new59"}:canonical[(case["role"],case["scenario"])]=model.canonical
    assert cursor==len(rows)-1
    ending=rows[-1];assert ending["completed_cases"]==[case["name"] for case in cases["cases"]]
    assert ending["actual_native_calls"]==calls==capture["actual_native_calls"]
    assert objects.get(ending["leaf_after"])==objects.get(start["leaf"])
    for scenario in ("main","output-failure","empty"):
        assert canonical[("old59",scenario)]==canonical[("new59",scenario)],("old/new59 full bytes",scenario)
    actual_objects={p.name for p in (output/"objects").iterdir()}
    assert actual_objects==objects.seen
    assert len(actual_objects)==capture["objects"]
    assert sum(len(v) for v in objects.cache.values())==capture["unique_bytes"]
    # The reader intentionally revisits immutable objects while proving independent conditions.
    assert objects.snapshots==capture["snapshots"]==2*domain["cases"]+2*domain["planned_actions"]
    physical_total=start["leaf"]["bytes"]+ending["leaf_after"]["bytes"]
    for row in rows[1:-1]:
        if row["kind"] in ("create","action"):
            for key in ("before","after"):
                snap=row[key];physical_total+=snap["maps"]["bytes"]
                physical_total+=sum(value["physical"]["bytes"] for value in snap["regions"].values() if value["mapped"])
        if row["kind"]=="create":physical_total+=row["engine_image"]["bytes"]
        if row["kind"]=="case_end":physical_total+=row["engine_image_after"]["bytes"]
    assert physical_total==capture["physical_bytes"]
    assert capture["cases"]==domain["cases"]==57
    assert capture["actions"]==domain["planned_actions"]==sum(len(c["actions"]) for c in cases["cases"])
    assert capture["elapsed_seconds"]<domain["native_seconds"]
    assert source()==identity
    return dict(schema="hepta.runtime.engine-layout.admission.v1",status="PASS",source_manifest_sha256=identity,
        roles=19,cases=57,actions=capture["actions"],actual_native_calls=calls,
        complete_physical_bytes=capture["physical_bytes"],unique_physical_bytes=capture["unique_bytes"],
        snapshots=capture["snapshots"],objects=capture["objects"],old_new_59_complete_normalized_equal=True,
        fixed_low_word_consumers_preserved=True,extended_slot_counts=domain["new_slot_counts"],
        native_calls_performed_by_reader=0,private_storage_only=True,public_tools=False,whole_runtime_replaced=False)
def main():
    p=argparse.ArgumentParser();p.add_argument("--build",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True);p.add_argument("--source-manifest-sha256",required=True)
    a=p.parse_args();print(json.dumps(admit(a.build,a.output,a.source_manifest_sha256),sort_keys=True))
if __name__=="__main__":main()
