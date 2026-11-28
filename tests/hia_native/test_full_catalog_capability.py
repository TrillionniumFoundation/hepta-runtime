"""Actual complete catalog comparisons and composite boundary controls."""
from pathlib import Path
import concurrent.futures,ctypes,gzip,hashlib,json,os,struct,sys,time,unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"scripts"));sys.path.insert(0,str(Path(__file__).resolve().parent))
from hia_native_loader import NativeModule
from full_catalog_loader import CatalogCapability
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
ENCODE=lambda value:(json.dumps(value,sort_keys=True,indent=2)+"\n").encode()
TOTAL=4096+(100<<20);REQUEST=4096;REPLY=4096+(2<<20);WORK=4096+(4<<20)
FRAME_CAP=2<<20;FILL=0xa7;WORK_FILL=0x59
def query(flags,modern,profile=136):
    return b"HRMCD002"+struct.pack("<4Q",7,modern,flags,profile)
def private(wire,stage=0,code=0):
    return b"HFCAPQ01"+struct.pack("<3Q",stage,len(wire),code)+wire
def pin(path):
    raw=Path(path).read_bytes()
    return {"bytes":len(raw),"sha256":SHA(raw)}
class FullCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build=Path(os.environ["HIA_FULL_CATALOG_BUILD"]).resolve(strict=True)
        cls.output=Path(os.environ["HIA_FULL_CATALOG_EVIDENCE"]).absolute()
        cls.output.mkdir(parents=True,exist_ok=False)
        cls.build_pin=pin(cls.build/"BUILD.json")
        cls.report=json.loads((cls.build/"BUILD.json").read_bytes())
        cls.cap=CatalogCapability(cls.build,build_sha256=cls.build_pin["sha256"])
        cls.addClassCleanup(cls.cap.close)
        cls.modules={}
        for name in ("owner","policy","value","sdk","retained"):
            row=cls.report["members"][name]
            cls.modules[name]=NativeModule(cls.build/row["manifest"],manifest_sha256=row["manifest_pin"]["sha256"])
            cls.addClassCleanup(cls.modules[name].close)
        cls.policy=ROOT/"tests/hia_native/catalog_policy_ci/source"
        cls.raw_input=(cls.policy/"catalog-input.json").read_bytes()
        cls.assertions={"raw_declarations":len(json.loads(cls.raw_input)),"rows":[],"calls":[],
            "old_comparisons":0,"malformed_queries":0,"capacity_controls":0,"owner_controls":0}
        cls.count=0
        names=set(cls.report["source_files"])|{str(Path(__file__).resolve().relative_to(ROOT)),
            "tests/hia_native/full_catalog_loader.py"}
        names.update("tests/hia_native/catalog_policy_ci/source/"+name for name in cls.report["policy_source_closure"])
        cls.source_before={name:pin(ROOT/name) for name in sorted(names)}
        cls.artifact_before={row["image"]:pin(cls.build/row["image"]) for row in cls.report["members"].values()}
        cls.artifact_before[cls.report["flat_image"]["path"]]=pin(cls.build/cls.report["flat_image"]["path"])
        cls.expected={}
        assert cls.assertions["raw_declarations"]==136
    @classmethod
    def record(cls,label,wire,code,out,workspace):
        number=cls.count;cls.count+=1
        row={"number":number,"label":label,"code":code,"buffers":{}}
        for kind,raw in (("input",wire),("output",out),("workspace",workspace)):
            path=cls.output/(f"{number:03d}-{label}.{kind}.gz")
            path.write_bytes(gzip.compress(raw,compresslevel=1,mtime=0))
            row["buffers"][kind]={"path":path.name,"bytes":len(raw),"sha256":SHA(raw),"compressed":pin(path)}
        cls.assertions["calls"].append(row)
        return row
    def call(self,module,label,wire,oc,wc):
        code,out,w=module.invoke_raw(wire,output_capacity=oc,workspace_capacity=wc,output_fill=FILL,workspace_fill=WORK_FILL)
        self.record(label,wire,code,out,w)
        return code,out,w
    def suffix(self,wire,label,oc=FRAME_CAP,wc=TOTAL+32):
        code,out,w=self.call(self.cap,label,wire,oc,wc)
        self.assertEqual(code,32)
        self.assertEqual(out[:8],b"HRCATR02")
        status,size,zero=struct.unpack_from("<3Q",out,8)
        self.assertEqual((status,zero),(0,0));self.assertLessEqual(32+size,oc)
        self.assertEqual(out[32+size:],bytes([FILL])*(oc-32-size))
        if wc>TOTAL:self.assertEqual(w[TOTAL:],bytes([WORK_FILL])*(wc-TOTAL))
        return out[32:32+size]
    def original_pipeline(self,flags,modern):
        label=f"original-{flags:02d}-{modern}"
        wire=b"HCATCQ01"+struct.pack("<7Q",1,flags,modern,len(self.raw_input),0,0,0)+self.raw_input
        code,out,w=self.call(self.modules["policy"],label+"-policy",wire,FRAME_CAP,32<<20)
        self.assertEqual(out[:8],b"HCATCR01")
        status,offset,size,count,rf,rm,zero=struct.unpack_from("<7Q",out,8)
        self.assertEqual((status,offset,rf,rm,zero),(0,64,flags,modern,0))
        self.assertEqual(code,64+size);self.assertEqual(out[code:],bytes([FILL])*(len(out)-code))
        body=out[64:code];del out,w
        wire=b"HSJVAL01"+struct.pack("<2Q",1,len(body))+body
        code,out,w=self.call(self.modules["value"],label+"-value",wire,FRAME_CAP,32<<20)
        self.assertTrue(0<code<=len(out));self.assertEqual(out[code:],bytes([FILL])*(len(out)-code))
        body=out[:code];del out,w
        wire=b"HRRSP001"+struct.pack("<2Q",4,len(body))+body
        code,out,w=self.call(self.modules["sdk"],label+"-sdk",wire,FRAME_CAP,96<<20)
        self.assertEqual(out[:8],b"HRRPO001")
        kind,rflags,offset,size,policy,z1,z2=struct.unpack_from("<7Q",out,8)
        self.assertEqual((kind,rflags,offset,policy,z1,z2),(4,0,64,0,0,0))
        self.assertEqual(code,64+size);self.assertEqual(out[code:],bytes([FILL])*(len(out)-code))
        typed=out[64:code]
        self.assertEqual(len(json.loads(typed)["tools"]),count)
        return typed,count
    def test_01_complete_136_input_all_18_policy_shapes_and_actual_flags1_wires(self):
        for flags in (0,*range(1,16,2)):
            for modern in (0,1):
                with self.subTest(flags=flags,modern=modern):
                    typed,count=self.original_pipeline(flags,modern)
                    expected=b',"result":'+typed+b"}"
                    actual=self.suffix(query(flags,modern),f"composite-{flags:02d}-{modern}")
                    self.assertEqual(actual,expected)
                    self.expected[(flags,modern)]=expected
                    self.assertions["rows"].append({"flags":flags,"modern":modern,"input_tools":136,
                        "visible_tools":count,"wire_bytes":len(actual),"wire_sha256":SHA(actual)})
                    if flags==1:
                        label="modern" if modern else "ordinary"
                        self.assertEqual(typed,(ROOT/f"authoring/public_extract/catalog_assets/actual/{label}.typed.json").read_bytes())
                print(json.dumps({"shape_complete":len(self.assertions["rows"]),"flags":flags,"modern":modern,"visible_tools":count}),flush=True)
        self.assertEqual(len(self.assertions["rows"]),18)
    def test_02_retained_operations_preserve_entire_return_output_workspace(self):
        wires=[b"",b"\0",b"x"*7,b"x"*8,b"x"*15,b"x"*16,b"x"*40]
        for magic in (b"HRMCD001",b"HRMCD002",b"INVALID!"):
            for operation in (0,1,2,3,4,5,6,8,9,0xffffffffffffffff):
                for argument in (0,1,8):
                    wires.append(magic+struct.pack("<2Q",operation,argument))
                    wires.append(magic+struct.pack("<4Q",operation,argument,0,11))
        for index,wire in enumerate(wires):
            with self.subTest(index=index):
                reference=self.call(self.modules["retained"],f"old-{index:03d}",wire,16384,32768)
                actual=self.call(self.cap,f"passthrough-{index:03d}",wire,16384,32768)
                self.assertEqual(actual,reference)
                self.assertions["old_comparisons"]+=1
        self.assertEqual(self.assertions["old_comparisons"],len(wires))
    def test_03_invalid_queries_short_outputs_and_workspace_growth_do_not_publish(self):
        good=query(1,0,11)
        wires=[good[:n] for n in (16,17,23,24,31,32,39)]
        wires += [good+b"\0",good+b"\0"*8]
        wires += [query(f,m,p) for f,m,p in ((0,2,11),(1,2,11),(2,0,11),(16,0,136),
            (2,0,136),(4,1,136),(14,0,136),(0,0,12),(0,0,0),(1,0,0xffffffffffffffff))]
        for index,wire in enumerate(wires):
            code,out,w=self.call(self.cap,f"invalid-{index:02d}",wire,64,128)
            self.assertEqual(code,0xffffffff)
            self.assertEqual(out,bytes([FILL])*64);self.assertEqual(w,bytes([WORK_FILL])*128)
            self.assertions["malformed_queries"]+=1
        for capacity in (0,1,8,16,31):
            code,out,w=self.call(self.cap,f"short-output-{capacity}",good,capacity,128)
            self.assertEqual(code,0xfffffffe)
            self.assertEqual(out,bytes([FILL])*capacity);self.assertEqual(w,bytes([WORK_FILL])*128)
            self.assertions["capacity_controls"]+=1
        for capacity in (0,1,127,TOTAL-1):
            code,out,w=self.call(self.cap,f"short-work-{capacity}",good,64,capacity)
            self.assertEqual(code,0xffffffd0)
            self.assertEqual(out,b"HGRWS002"+struct.pack("<3Q",1,TOTAL,0)+bytes([FILL])*32)
            self.assertEqual(w,bytes([WORK_FILL])*capacity)
            self.assertions["capacity_controls"]+=1
    def test_04_exact_final_output_capacity_and_legacy_present_flags(self):
        expected=self.expected[(1,0)];needed=32+len(expected);wire=query(1,0,11)
        code,out,w=self.call(self.cap,"final-capacity-minus-one",wire,needed-1,TOTAL)
        self.assertEqual(code,0xffffffd0)
        self.assertEqual(out[:32],b"HGRWS002"+struct.pack("<3Q",2,needed,0))
        self.assertEqual(out[32:],bytes([FILL])*(needed-1-32))
        self.assertions["capacity_controls"]+=1
        for delta in (0,1):
            self.assertEqual(self.suffix(wire,"final-capacity-"+str(delta),needed+delta),expected)
            self.assertions["capacity_controls"]+=1
        self.assertEqual(self.suffix(query(0,1,11),"legacy-no-config-modern"),self.expected[(0,1)])
    def test_05_native_owner_emits_complete_declaration_frame_and_refuses_bad_child_headers(self):
        module=self.modules["owner"];wire=query(1,0,11)
        with module.session(output_capacity=64,workspace_capacity=TOTAL) as session:
            ctypes.memset(session._output,FILL,64);ctypes.memset(session._workspace,WORK_FILL,TOTAL)
            code,out,w=session.invoke_raw(private(wire))
            self.record("owner-initialize",private(wire),code,out,w)
            self.assertEqual(code,0xffffffb1);self.assertEqual(out,bytes([FILL])*64)
            ctypes.memmove(ctypes.addressof(session._workspace)+REQUEST+64,self.raw_input,len(self.raw_input))
            code,out,w=session.invoke_raw(private(wire,1,0))
            self.record("owner-policy-input",private(wire,1,0),code,out,w)
            self.assertEqual(code,0xffffffb1)
            size=64+len(self.raw_input)
            self.assertEqual(w[REQUEST:REQUEST+size],b"HCATCQ01"+struct.pack("<7Q",1,1,0,len(self.raw_input),0,0,0)+self.raw_input)
            self.assertEqual(struct.unpack_from("<9Q",w,0),(2,2,0,REQUEST,size,REPLY,FRAME_CAP,WORK,32<<20))
            self.assertions["owner_controls"]+=2
            cases=[
                (2,0,64,b"BADMAGIC"+struct.pack("<7Q",0,64,0,1,1,0,0)),
                (2,0,64,b"HCATCR01"+struct.pack("<7Q",1,64,0,1,1,0,0)),
                (2,0,64,b"HCATCR01"+struct.pack("<7Q",0,64,1,1,1,0,0)),
                (2,0,64,b"HCATCR01"+struct.pack("<7Q",0,64,0,137,1,0,0)),
                (2,0,64,b"HCATCR01"+struct.pack("<7Q",0,64,0,1,3,0,0)),
                (3,1,0,b"\0"*64),
                (4,2,64,b"BADMAGIC"+struct.pack("<7Q",4,0,64,0,0,0,0)),
                (4,2,64,b"HRRPO001"+struct.pack("<7Q",3,0,64,0,0,0,0)),
                (4,2,64,b"HRRPO001"+struct.pack("<7Q",4,0,64,1,0,0,0)),
                (4,2,64,b"HRRPO001"+struct.pack("<7Q",4,0,64,0,1,0,0))]
            for index,(phase,child,returned,reply) in enumerate(cases):
                ctypes.memset(session._output,FILL,64)
                ctypes.memset(session._workspace,WORK_FILL,TOTAL)
                state=struct.pack("<12Q",phase,2,child,REQUEST,0,REPLY,FRAME_CAP,WORK,96<<20,1,0,0)
                ctypes.memmove(session._workspace,state,len(state))
                ctypes.memmove(ctypes.addressof(session._workspace)+REPLY,reply,len(reply))
                before=ctypes.string_at(session._workspace,TOTAL)
                code,out,w=session.invoke_raw(private(wire,1,returned))
                self.record(f"owner-refusal-{index:02d}",private(wire,1,returned),code,out,w)
                self.assertEqual(code,0xffffffff);self.assertEqual(out,bytes([FILL])*64);self.assertEqual(w,before)
                self.assertions["owner_controls"]+=1
    def test_06_independent_simultaneous_calls_share_only_sealed_code(self):
        def worker(shape):
            with CatalogCapability(self.build,build_sha256=self.build_pin["sha256"]) as module:
                flags,modern=shape;wire=query(flags,modern)
                code,out,w=module.invoke_raw(wire,output_capacity=FRAME_CAP,workspace_capacity=TOTAL+32,
                    output_fill=FILL,workspace_fill=WORK_FILL)
                return shape,wire,code,out,w
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            rows=list(pool.map(worker,((0,0),(15,1))))
        for shape,wire,code,out,w in rows:
            self.record("concurrent-"+str(shape[0]),wire,code,out,w)
            self.assertEqual(code,32)
            n=struct.unpack_from("<Q",out,16)[0]
            self.assertEqual(out[32:32+n],self.expected[shape])
            self.assertEqual(out[32+n:],bytes([FILL])*(len(out)-32-n))
            self.assertEqual(w[TOTAL:],bytes([WORK_FILL])*32)
    @classmethod
    def tearDownClass(cls):
        cls.source_after={name:pin(ROOT/name) for name in cls.source_before}
        cls.artifact_after={name:pin(cls.build/name) for name in cls.artifact_before}
        assert cls.source_before==cls.source_after
        assert cls.artifact_before==cls.artifact_after
        assert pin(cls.build/"BUILD.json")==cls.build_pin

if __name__=="__main__":
    started=time.monotonic()
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(FullCatalogTests))
    if hasattr(FullCatalogTests,"output"):
        record={"schema":"hepta.runtime.full-catalog-composite-controls.v1","status":"PASS" if result.wasSuccessful() else "FAIL",
            "tests_run":result.testsRun,"failures":len(result.failures),"errors":len(result.errors),"skipped":len(result.skipped),
            "seconds":time.monotonic()-started,"build":FullCatalogTests.build_pin,
            "details":getattr(FullCatalogTests,"assertions",{}),"source_before":getattr(FullCatalogTests,"source_before",{}),
            "source_after":getattr(FullCatalogTests,"source_after",{}),"artifact_before":getattr(FullCatalogTests,"artifact_before",{}),
            "artifact_after":getattr(FullCatalogTests,"artifact_after",{}),"original_rust_processes_started":0,
            "original_216_rust_handler_cases_rerun":False,"retained_actual_flags1_wires_compared":2,
            "public_runtime_dispatch_qualified":False,"whole_runtime_replaced":False}
        (FullCatalogTests.output/"result.json").write_bytes(ENCODE(record))
        print(json.dumps({k:record[k] for k in ("status","tests_run","failures","errors","skipped","seconds")}),flush=True)
    raise SystemExit(0 if result.wasSuccessful() else 1)
