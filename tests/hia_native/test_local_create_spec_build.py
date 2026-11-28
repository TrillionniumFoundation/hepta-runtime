"""Execute the fixed full-Local prefix/packer and strict source refusals."""
from pathlib import Path
import collections,ctypes,gzip,json,os,struct,subprocess,sys,tempfile,time,unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
sys.path.insert(0,str(ROOT/'tests/hia_native/local_create/spec'))
from hia_native_loader import NativeModule
import hia_native_local_create_spec_build as build
import hia_native_local_create_spec_state_qualification as evidence
import build_cases
OUTPUT=Path(os.environ['HIA_LOCAL_CREATE_SPEC_OUTPUT']).resolve()/'build-controls'
MANIFEST=Path(os.environ['HIA_LOCAL_CREATE_SPEC_MANIFEST']).resolve()
COUNTS=collections.Counter()
Q=lambda n:struct.pack('<Q',n)
pin=evidence.pin
write=lambda path,value:path.write_bytes(evidence.compact(value)+b'\n')

class BuildControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OUTPUT.mkdir(parents=True,exist_ok=False)
        cls.sources=evidence.source_evidence(ROOT)
        cls.component=build.source_evidence(ROOT)
        cls.metadata=build.verify_build(MANIFEST,source_root=ROOT)

    def test_01_exact_native_prefix(self):
        commands=[['as','--64','-o',str(OUTPUT/'adapter.o'),str(ROOT/'scripts/local_create_spec_adapter.S')],
                  ['ld','-nostdlib','-Ttext=0','-e','_start','-o',str(OUTPUT/'adapter.elf'),str(OUTPUT/'adapter.o')],
                  ['objcopy','-O','binary','--only-section=.text',str(OUTPUT/'adapter.elf'),str(OUTPUT/'adapter.bin')],
                  ['readelf','-r',str(OUTPUT/'adapter.elf')]]
        records=[]
        for index,command in enumerate(commands):
            began=time.monotonic();run=subprocess.run(command,capture_output=True,timeout=30,env={**os.environ,'LC_ALL':'C'})
            COUNTS['actual_assembler_processes']+=1
            for label,raw in(('stdout',run.stdout),('stderr',run.stderr)):(OUTPUT/(str(index)+'.'+label)).write_bytes(raw)
            records.append(dict(command=command,timeout_seconds=30,exit_code=run.returncode,
                elapsed_seconds=time.monotonic()-began,stdout=pin(run.stdout),stderr=pin(run.stderr)))
            write(OUTPUT/'assembler-processes.json',records)
            self.assertEqual(run.returncode,0,run.stderr)
        self.assertIn(b'There are no relocations',run.stdout)
        self.assertEqual((OUTPUT/'adapter.bin').read_bytes(),bytes.fromhex(self.component['prefix_hex'])[176:])
        COUNTS['complete_adapter_comparisons']+=1

    def test_02_complete_actual_packer_arrays(self):
        wire=(MANIFEST.parent/'pack.input.bin').read_bytes()
        extent=self.component['executable_bytes'];records=[]
        with gzip.open(OUTPUT/'packer-arrays.bin.gz','wb')as archive,NativeModule(
                MANIFEST.parent/'packer.json',manifest_sha256=build.digest((MANIFEST.parent/'packer.json').read_bytes()))as module:
            for label,request,capacity,want in build_cases.packer_cases(wire,extent):
                initial=[request,b'\xa7'*capacity,b'\x5a'*64]
                before=[b'G'*16+value+b'g'*16 for value in initial]
                buffers=[ctypes.create_string_buffer(raw,len(raw))for raw in before];args=[]
                for raw,buf in zip(before,buffers):args.extend((ctypes.addressof(buf)+16,len(raw)-32))
                with module._lock:code=module._entry(*args)
                after=[buf.raw for buf in buffers]
                for raw in before+after:archive.write(Q(len(raw))+raw)
                records.append(dict(name=label,code=code,capacities=list(map(len,initial))))
                write(OUTPUT/'packer-calls.json',records);COUNTS['actual_packer_calls']+=1
                self.assertEqual(code,want);self.assertEqual(after[0],before[0]);self.assertEqual(after[2],before[2])
                for raw in after:self.assertEqual((raw[:16],raw[-16:]),(b'G'*16,b'g'*16))
                if code<0xffff0000:
                    self.assertEqual(after[1][16:16+code],build_cases.packed(self.component,request))
                    self.assertEqual(after[1][16+code:],before[1][16+code:])
                else:self.assertEqual(after[1],before[1])

    def test_03_actual_source_and_artifact_refusals(self):
        records=[]
        with gzip.open(OUTPUT/'mutation-bytes.bin.gz','wb')as archive:
            for category,edits in(('artifact',build_cases.artifact_mutations(build.MEMBERS)),
                                   ('source',build_cases.source_mutations(build.SOURCE_FILES))):
                for label,relative,operation,field,value in edits:
                    with tempfile.TemporaryDirectory(prefix=category+'-',dir=OUTPUT)as temporary:
                        target=Path(temporary)
                        names=evidence.BUILD_ARTIFACTS if category=='artifact'else build.SOURCE_FILES
                        origin=MANIFEST.parent if category=='artifact'else ROOT
                        for name in names:
                            path=target/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(build.read(origin/name))
                        path=target/relative;before=path.read_bytes();after=build_cases.mutated(before,operation,field,value)
                        self.assertNotEqual(before,after);path.write_bytes(after)
                        with self.assertRaises((ValueError,KeyError,TypeError,json.JSONDecodeError))as caught:
                            if category=='artifact':build.verify_build(target/'manifest.json',source_root=ROOT)
                            else:build.source_evidence(target)
                        for raw in(before,after):archive.write(Q(len(raw))+raw)
                        records.append(dict(category=category,name=label,relative=relative,operation=operation,
                            field=field,value=value,before=pin(before),after=pin(after),
                            exception=type(caught.exception).__name__,message=str(caught.exception)))
                        COUNTS[category+'_refusals']+=1
                        write(OUTPUT/'refusals.json',records)
        self.assertEqual(build.verify_build(MANIFEST,source_root=ROOT),self.metadata)
        self.assertEqual(evidence.source_evidence(ROOT),self.sources)
        COUNTS['valid_artifact_admissions']+=1

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(BuildControls))
    passed=result.wasSuccessful()and result.testsRun==3 and not(result.skipped or result.expectedFailures or result.unexpectedSuccesses)
    passed=passed and dict(COUNTS)==evidence.BUILD_COUNTS
    summary=dict(schema='hepta.runtime.local-create-spec-build-suite.v1',status='PASS'if passed else'FAIL',
        tests_run=result.testsRun,expected_tests=3,failures=len(result.failures),errors=len(result.errors),
        skipped=len(result.skipped),expected_failures=len(result.expectedFailures),unexpected_successes=len(result.unexpectedSuccesses),
        counts=dict(COUNTS),source_inputs=getattr(BuildControls,'sources',None),
        execution=dict(source_root=str(ROOT),manifest=str(MANIFEST),output=str(OUTPUT.parent.parent)),
        manifest_sha256=build.digest(MANIFEST.read_bytes()),**build.SCOPE)
    if OUTPUT.is_dir():write(OUTPUT/'summary.json',summary)
    print(evidence.compact(summary).decode(),flush=True)
    raise SystemExit(0 if passed else 1)
