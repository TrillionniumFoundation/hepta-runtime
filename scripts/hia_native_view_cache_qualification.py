"""Bind actual cache test execution, complete corpus and native build artifacts.

This verifier never reconstructs test invocation receipts. The aggregate must
run test_view_cache.py through its real record_check and pass completed_test_summary.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys

from hia_native_build import HEPTA_COMMIT, json_bytes
from hia_native_entropy_qualification import digest, inspect_elf, native_receipt, object_at, read
from hia_native_scope_qualification import embedded_images

FOLDER = 'view-cache-rust-oracle'
CORPUS_FILES = ('native-corpus.json','requests.bin.gz','native-output.bin.gz','domains.jsonl.gz')
COUNTS = {'native_image_calls':13873,'native_elf_requests':66,'original_operations':13875,
          'lifecycle_operations':22,'poison_injections':2,'view_plan_adapters':8,
          'frame_refusals':17,'capacity_refusals':6,'state_refusals':9,
          'view_image_calls':13,'reference_rows':13907}
CASES = 13907
WIRE_BYTES, WIRE_SHA256 = 13663258, '4dc50bb111351d4c7bd5ae2e53d3fae6cc1506aefd5df91f11984465bb3c3dec'
OUTPUT_BYTES, OUTPUT_SHA256 = 12790132, '78ee60da25ae71ce9982e812b51168ac93fb8b68b97c9a5efe4d110ced423fbc'
DOMAINS_BYTES, DOMAINS_SHA256 = 1643782, 'b430e34b0cde8ffebe31efceafba7dbe7f173a394d6179987951fe7bfbc3e802'


def _relative(output, value):
    relative=Path(value)
    if relative.is_absolute() or not relative.parts or '..' in relative.parts:
        raise ValueError('cache artifact escaped qualification output')
    return output/relative


def _driver(root):
    path=root/'tests/hia_native/compare_view_cache_original.py'
    read(path)
    spec=importlib.util.spec_from_file_location('cache_original_replay',path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _compiled(output, folder, source, image, compiler, artifacts):
    receipt=object_at(folder/'module.receipt.json')
    native_receipt(receipt,image=compiler,source=source,output=read(folder/'module.output.bin'),produced=image)
    built=object_at(folder/'build.json')
    if (read(folder/'module.input.bin')!=source or read(folder/'module.image.bin')!=image
            or receipt.get('produced_sha256')!=digest(image) or receipt.get('produced_bytes')!=len(image)
            or built.get('compile_receipt')!=receipt
            or built.get('compiler_dependency')!=object_at(output/'build/bootstrap/bootstrap.json').get('dependency')):
        raise ValueError('cache native compilation receipt differs')
    for name in ('module.receipt.json','module.input.bin','module.output.bin','module.image.bin','build.json'):
        path=folder/name;artifacts[path.relative_to(output).as_posix()]=digest(read(path))


def _module(root,output,report,key,source,artifacts):
    owner=report['modules'][key]
    if owner.get('builder')!='borrowed_bytes' or owner.get('source')!='native/'+key+'.hepta':
        raise ValueError('cache tested module builder differs')
    path=_relative(output,owner['manifest']);raw=read(path);module=json.loads(raw)
    if (digest(raw)!=owner['sha256'] or module.get('schema')!='hepta.runtime.native-module.v1'
            or module.get('abi')!='hepta.runtime.borrowed-bytes.linux-x86_64.v1'
            or module.get('target')!='linux-x86_64' or module.get('compiler_commit')!=HEPTA_COMMIT
            or module.get('compiler_sha256')!=report['compiler_image_sha256']
            or module.get('source_sha256')!=digest(source)):
        raise ValueError('cache tested module identity differs')
    for name in ('source','image'):
        part=Path(module[name])
        if part.is_absolute() or len(part.parts)!=1:
            raise ValueError('cache native module artifact path differs')
        artifact=path.parent/part;data=read(artifact)
        if digest(data)!=module[name+'_sha256'] or (name=='source' and data!=source):
            raise ValueError('cache native module artifact changed')
        artifacts[artifact.relative_to(output).as_posix()]=digest(data)
    artifacts[path.relative_to(output).as_posix()]=digest(raw)
    return path,module,read(path.parent/module['image'])


def native_evidence(root: Path,output: Path,report: dict,completed,*,reference_root: Path|None=None):
    reference_root=root if reference_root is None else reference_root
    check,summary=completed(output,report,'test_view_cache.py')
    command=check.get('command',[])
    stderr=read(output/'test_view_cache.py.stderr').decode()
    if (len(command)!=4 or command[1:]!=['-I','-B',str(root/'tests/hia_native/test_view_cache.py')]
            or summary.get('status')!='PASS' or summary.get('test_groups')!=8
            or type(summary.get('counts')) is not dict or set(summary['counts'])!=set(COUNTS)
            or any(type(summary['counts'][k]) is not int or summary['counts'][k]!=v for k,v in COUNTS.items())
            or len(re.findall(r'\.\.\. ok\n',stderr))!=8
            or not re.search(r'\nRan 8 tests in [0-9.]+s\n\nOK\n\Z',stderr)):
        raise ValueError('cache actual native suite did not finish all declared groups')
    folder=output/FOLDER
    for name in CORPUS_FILES:read(folder/name)
    metadata,wire,expected,domains=_driver(root).checked_corpus(folder,root,reference_root)
    if metadata!=summary:
        raise ValueError('cache corpus does not match its actual test stdout')
    if ((len(wire),digest(wire),len(expected),digest(expected))!=(WIRE_BYTES,WIRE_SHA256,OUTPUT_BYTES,OUTPUT_SHA256)
            or metadata['files']['domains.jsonl.gz']['raw_bytes']!=DOMAINS_BYTES
            or metadata['files']['domains.jsonl.gz']['raw_sha256']!=DOMAINS_SHA256):
        raise ValueError('cache complete retained sequence bytes differ')
    proof=object_at(root/'native/view_cache_composition.json')
    compiler=read(output/'build/bootstrap/B3.image.bin')
    if digest(compiler)!=report['compiler_image_sha256'] or report['compiler_commit']!=HEPTA_COMMIT:
        raise ValueError('cache compiler image changed')
    artifacts={'build/bootstrap/B3.image.bin':digest(compiler),
               'build/bootstrap/bootstrap.json':digest(read(output/'build/bootstrap/bootstrap.json'))}
    source=read(root/'native/view_cache.hepta')
    direct_path,direct,image=_module(root,output,report,'view_cache',source,artifacts)
    if (direct.get('input_capacity')!=8<<20 or direct.get('output_capacity')!=8<<20
            or direct.get('workspace_capacity')!=32<<20
            or summary.get('native_module')!={k:direct[k] for k in
                   ['compiler_commit','compiler_sha256','source_sha256','image_sha256']}):
        raise ValueError('cache actual image execution profile differs')
    _compiled(output,direct_path.parent,source,image,compiler,artifacts)
    view_source=read(reference_root/'native/view_render.hepta')
    view_path,view,view_image=_module(reference_root,output,report,'view_render',view_source,artifacts)
    if (view.get('buffer_profile')!='view-render.v1' or view.get('input_capacity')!=16<<20
            or view.get('output_capacity')!=16<<20 or view.get('workspace_capacity')!=256<<20
            or summary.get('view_module')!={**{k:view[k] for k in
            ['compiler_commit','compiler_sha256','source_sha256','image_sha256']},'manifest_sha256':digest(read(view_path))}):
        raise ValueError('cache plan used a different actual view image')
    _compiled(output,view_path.parent,view_source,view_image,compiler,artifacts)
    owner=report['cache_composition']
    if owner.get('builder')!='composition_fixture':
        raise ValueError('cache test transport builder differs')
    path=_relative(output,owner['manifest']);raw=read(path);composition=json.loads(raw)
    if (digest(raw)!=owner['sha256'] or composition.get('schema')!='hepta.runtime.native-composition.v1'
            or composition.get('compiler_commit')!=HEPTA_COMMIT
            or composition.get('compiler_sha256')!=digest(compiler)
            or len(composition.get('members',[]))!=2):
        raise ValueError('cache composition identity differs')
    profile=[{'id':0,'name':'view-cache-hex-fixture','flags':1,'call_mask':2,
              'input_capacity':8<<20,'output_capacity':8<<20,'workspace_capacity':16<<20,
              'source_sha256':proof['transport_source_sha256']},
             {'id':1,'name':'view-cache','flags':0,'call_mask':0,
              'input_capacity':8<<20,'output_capacity':1048608,'workspace_capacity':8<<20,
              'source_sha256':proof['source_sha256']}]
    if composition.get('profile')!=profile:
        raise ValueError('cache table privilege or capacity profile differs')
    rows=[('packer',reference_root/'native/composition_packer.hepta',composition['packer']),
          ('module_00',root/'tests/hia_native/view_cache_hex_transport.hepta',composition['members'][0]),
          ('module_01',root/'native/view_cache.hepta',composition['members'][1])]
    images=[];frame=bytearray(b'HIABND01'+struct.pack('<3Q',2,0,0))
    for index,(stem,original,row) in enumerate(rows):
        if row.get('manifest')!=stem+'.json':
            raise ValueError('cache child manifest path differs')
        child_path=path.parent/(stem+'.json');child_raw=read(child_path);child=json.loads(child_raw)
        child_source=read(path.parent/(stem+'.hepta'));child_image=read(path.parent/(stem+'.image.bin'))
        contract={'schema':'hepta.runtime.native-module.v1','abi':'hepta.runtime.borrowed-bytes.linux-x86_64.v1',
                  'target':'linux-x86_64','compiler_commit':HEPTA_COMMIT,'compiler_sha256':digest(compiler),
                  'source':stem+'.hepta','image':stem+'.image.bin','input_capacity':8<<20,
                  'output_capacity':8<<20,'workspace_capacity':32<<20,'standalone':None}
        if (digest(child_raw)!=row['manifest_sha256'] or child_source!=read(original)
                or digest(child_source)!=row['source_sha256'] or digest(child_image)!=row['image_sha256']
                or child.get('source_sha256')!=digest(child_source) or child.get('image_sha256')!=digest(child_image)
                or any(type(child.get(k)) is not type(v) or child[k]!=v for k,v in contract.items())):
            raise ValueError('cache packed child source/image identity differs')
        compiled=output/'build/modules'/('composition-'+digest(child_source)[:24])
        _compiled(output,compiled,child_source,child_image,compiler,artifacts)
        for name in (stem+'.json',stem+'.hepta',stem+'.image.bin'):
            artifact=path.parent/name;artifacts[artifact.relative_to(output).as_posix()]=digest(read(artifact))
        if index:
            images.append(child_image);p=profile[index-1]
            frame.extend(struct.pack('<8Q',len(child_image),p['input_capacity'],p['output_capacity'],p['workspace_capacity'],p['flags'],p['call_mask'],0,0))
            frame.extend(bytes.fromhex(digest(child_source))+bytes.fromhex(digest(child_image))+child_image)
    if images[1]!=image or proof['packer_source_sha256']!=digest(read(reference_root/'native/composition_packer.hepta')):
        raise ValueError('cache packed state owner or frozen packer differs')
    executable=read(path.parent/'native-local-read.elf')
    layout=embedded_images(executable,profile,images)
    key=digest(json_bytes({'compiler':digest(compiler),'members':profile,'packer':proof['packer_source_sha256']}))
    binding={'manifest_sha256':digest(raw),'executable_sha256':digest(executable),'images':list(map(digest,images)),
             'source_profile':profile,'embedded_table':layout}
    if (composition.get('key')!=key or composition.get('frame_sha256')!=digest(frame)
            or composition.get('frame_bytes')!=len(frame) or composition.get('executable')!='native-local-read.elf'
            or composition.get('executable_sha256')!=digest(executable) or composition.get('inspection')!=inspect_elf(executable)
            or composition.get('packing')!={'owner':'HIA','input_unchanged':True,'buffer_canaries_unchanged':True,
                                           'packer_image_sha256':composition['packer']['image_sha256']}
            or summary.get('composition')!=binding):
        raise ValueError('cache packed artifact differs from actual tested ELF')
    for name in ('manifest.json','native-local-read.elf'):
        artifact=path.parent/name;artifacts[artifact.relative_to(output).as_posix()]=digest(read(artifact))
    return {'status':'PASS','counts':COUNTS,'captured_native_cases':CASES,
            'original_operations':COUNTS['original_operations'],'reference_domains':domains,
            'native_cases_added_by_replay':0,'source_sha256':digest(source),'image_sha256':digest(image),
            'composition_sha256':digest(read(root/'native/view_cache_composition.json')),
            'executable_sha256':digest(executable),'source_profile':profile,'elf_embedding':layout,
            'compiler_sha256':digest(compiler),'original_sources':proof['original_sources'],
            'wire_bytes':WIRE_BYTES,'wire_sha256':WIRE_SHA256,'native_output_bytes':OUTPUT_BYTES,
            'native_output_sha256':OUTPUT_SHA256,'corpus_metadata_sha256':digest(read(folder/'native-corpus.json')),
            'corpus_sha256':{(folder/name).relative_to(output).as_posix():digest(read(folder/name)) for name in CORPUS_FILES},
            'artifact_sha256':artifacts,'test_stdout_sha256':check['stdout_sha256'],'test_stderr_sha256':check['stderr_sha256'],
            'oracle_sources_sha256':{name:digest(read(root/name)) for name in
                ['tests/hia_native/oracle_view_cache.rs','tests/hia_native/view_cache_oracle_source.py','tests/hia_native/compare_view_cache_original.py']},
            'production_activated':False,'complete_original_tool_parity':False,
            'unbounded_storage_qualified':False,'shared_concurrency_qualified':False}


def qualification_evidence(root,output,report,completed,*,reference_root=None):
    """Aggregate entry: require the actual owner suite and verifier controls."""
    native=native_evidence(root,output,report,completed,reference_root=reference_root)
    check,summary=completed(output,report,'test_view_cache_evidence.py')
    stderr=read(output/'test_view_cache_evidence.py.stderr').decode()
    expected={'schema':'hepta.runtime.view-cache-evidence-tests.v1','status':'PASS',
              'test_groups':4,'refusal_controls':10,'native_calls_added':0,
              'test_sha256':digest(read(root/'tests/hia_native/test_view_cache_evidence.py'))}
    if (summary!=expected or check.get('command',[None])[1:]!=['-I','-B',str(root/'tests/hia_native/test_view_cache_evidence.py')]
            or len(re.findall(r'\.\.\. ok\n',stderr))!=4
            or not re.search(r'\nRan 4 tests in [0-9.]+s\n\nOK\n\Z',stderr)):
        raise ValueError('cache evidence-control executable suite differs')
    return {**native,'evidence_controls':{**summary,'stdout_sha256':check['stdout_sha256'],
                                        'stderr_sha256':check['stderr_sha256']}}


def compare_original(root,output,report,rustc,completed,record_check,env):
    """Actual required Rust compile/replay entry; returns no extra native calls."""
    evidence=qualification_evidence(root,output,report,completed)
    if evidence!=report.get('view_cache_evidence'):
        raise ValueError('cache native evidence changed before actual Rust replay')
    folder=output/FOLDER;binary=folder/'original-cache.elf';result_path=folder/'rust-driver-result.json'
    if binary.exists() or result_path.exists() or (folder/'rust-comparison.json').exists():
        raise ValueError('cache Rust invocation output already exists')
    source=root/'tests/hia_native/oracle_view_cache.rs'
    record_check(output,report,name='view-cache-rust-compile',
        command=[str(rustc),'-O','--edition=2024',str(source),'-o',str(binary)],env=env,timeout=60)
    binary_hash=digest(read(binary))
    row=record_check(output,report,name='view-cache-rust-compare',
        command=[sys.executable,'-I','-B',str(root/'tests/hia_native/compare_view_cache_original.py'),
                 '--corpus',str(folder),'--binary',str(binary),'--result',str(result_path)],env=env,timeout=60)
    observed=json.loads(row.stdout)
    if (row.stderr or observed!=object_at(result_path) or observed.get('status')!='PASS'
            or type(observed.get('rust_oracle_cases')) is not int or observed['rust_oracle_cases']!=CASES
            or observed.get('binary_sha256')!=binary_hash or digest(read(binary))!=binary_hash
            or observed.get('requests_sha256')!=WIRE_SHA256 or observed.get('rust_output_sha256')!=OUTPUT_SHA256
            or observed.get('native_output_sha256')!=OUTPUT_SHA256 or observed.get('output_bytes')!=OUTPUT_BYTES
            or observed.get('native_corpus_sha256')!=evidence['corpus_metadata_sha256']
            or observed.get('comparison_driver_sha256')!=digest(read(root/'tests/hia_native/compare_view_cache_original.py'))
            or qualification_evidence(root,output,report,completed)!=evidence):
        raise ValueError('cache actual original Rust replay differs')
    result={**observed,'compiled_by_qualification_recipe':True,'native_cases_added_by_replay':0,
            'original_operations':COUNTS['original_operations'],'production_activated':False,
            'complete_original_tool_parity':False,'whole_runtime_replaced':False}
    with (folder/'rust-comparison.json').open('x') as stream:
        stream.write(json.dumps(result,indent=2,sort_keys=True)+'\n')
    return result
