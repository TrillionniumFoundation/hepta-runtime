"""Relocatable, inert full-byte admission of both actual compiler graphs."""
from pathlib import Path
import io
import struct
import tarfile
import tomllib
from common import ROOT, COMPILER, HEPTA_COMMIT, HEPTA_TREE, encoded, files, loads, pin, read, require, sha, source
from verify_reference import verify as verify_original_source


def processes(folder,expected):
    rows=loads(read(folder/'processes.json'))
    require([r['name'] for r in rows]==[r[0] for r in expected],'complete expected process set')
    identities=set()
    for row,(name,budget) in zip(rows,expected,strict=True):
        require(row['timeout_seconds']==budget,'actual process command and original budget')
        require(row['exit_code']==0 and row['timed_out'] is False and row['completed'] is True
                and 0<row['elapsed_seconds']<=budget,'successful bounded process completion')
        require(type(row['pid']) is int and row['pid']>1 and row['pgid']==row['pid']
                and row['pid']!=row['parent_pid'] and row['pid'] not in identities,'actual process custody')
        identities.add(row['pid'])
        require(row['stdin'] is None,'no hidden process input')
        for stream in ('stdout','stderr'):
            item=row[stream];require(item['file']==name+'.'+stream,'complete stream path')
            require(pin(read(folder/item['file']))=={k:item[k] for k in ('bytes','sha256')},'complete process stream')
    return rows


def compiler(root):
    dependency=loads(read(ROOT/'COMPILER_FILES.json'))
    require(dependency['commit']==HEPTA_COMMIT and dependency['tree']==HEPTA_TREE
            and len(dependency['files'])==1080,'complete pinned compiler source closure')
    retained=files(root/'compiler-source')
    require(set(retained)==set(dependency['files']),'complete retained compiler source set')
    for name,row in retained.items():
        require(row['sha256']==dependency['files'][name],'retained compiler source: '+name)
    folder=root/'bootstrap';bootstrap=loads(read(folder/'bootstrap.json'))
    require(bootstrap['dependency']==dependency and bootstrap['generation_sha256']==COMPILER,'bootstrap compiler identity')
    source_raw=read(root/'compiler-source/examples/hia_bootstrap/selfhost.hepta')
    require(bootstrap['compiler_source_sha256']==sha(source_raw),'bootstrap source bytes')
    for label in ('B1','B2','B3'):
        image=read(folder/(label+'.image.bin'));out=read(folder/(label+'.output.bin'))
        receipt=loads(read(folder/(label+'.receipt.json')))
        require(pin(image)==dict(bytes=673413,sha256=COMPILER),'exact fixed-point generation')
        require(read(folder/(label+'.input.bin'))==source_raw,'full compiler input')
        require(len(out)==1048576 and out[:len(image)]==image and out[len(image):]==b'\xa5'*(len(out)-len(image)),
                'complete compiler output and tail')
        require(receipt['status']=='returned' and receipt['source_unchanged'] is True
                and receipt['produced_sha256']==COMPILER and receipt['output_sha256']==sha(out)
                and receipt['result_u64']==receipt['core_u32']==len(image)
                and receipt['forbidden_compiler_modules_loaded']==[],'actual bootstrap receipt')
    return dependency


def module(root,name,source_name,expected=None):
    folder=root/'modules'/name;raw=read(folder/'manifest.json');manifest=loads(raw)
    code=read(folder/'module.image.bin');source_raw=read(ROOT/source_name)
    out=read(folder/'module.output.bin');receipt=loads(read(folder/'module.receipt.json'))
    require(manifest['schema']=='hepta.runtime.native-module.v1' and manifest['name']==name
            and manifest['abi']=='hepta.runtime.borrowed-bytes.linux-x86_64.v1' and manifest['target']=='linux-x86_64'
            and manifest['compiler_commit']==HEPTA_COMMIT and manifest['compiler_sha256']==COMPILER
            and manifest['source']==name+'.hepta' and manifest['source_sha256']==sha(source_raw)
            and manifest['image']=='module.image.bin' and manifest['image_sha256']==sha(code)
            and manifest['standalone'] is None and manifest['buffer_profile']=='history.v1','native module identity')
    if expected is not None: require(pin(code)==expected,'native module identity')
    require(read(folder/(name+'.hepta'))==read(folder/'module.input.bin')==source_raw,'exact module compiler source')
    require(0<len(code)<1048576 and len(out)==1048576 and out[:len(code)]==code
            and out[len(code):]==b'\xa5'*(len(out)-len(code)),'full module compiler output and tail')
    require(receipt['status']=='returned' and receipt['source_unchanged'] is True
            and receipt['artifact_sha256']==receipt['image_sha256']==COMPILER
            and receipt['input_sha256']==receipt['source_sha256']==sha(source_raw)
            and receipt['produced_sha256']==sha(code) and receipt['output_sha256']==sha(out)
            and receipt['result_u64']==receipt['core_u32']==receipt['produced_bytes']==len(code)
            and receipt['forbidden_compiler_modules_loaded']==[],'actual exact B3 module compilation')
    built=loads(read(folder/'build.json'))
    require(built['compile_receipt']==receipt and built['compiler_dependency']==loads(read(ROOT/'COMPILER_FILES.json')),
            'complete actual module compilation receipt')
    return raw,code


def native(root):
    root=Path(root);built=loads(read(root/'BUILD.json'));members=loads(read(ROOT/'MEMBERS.json'))
    require(built['schema']=='hepta.extract-lines.native-build.v1' and built['status']=='PASS'
            and built['source_manifest_sha256']==source() and built['compiler_sha256']==COMPILER
            and built['copied_bootstrap'] is False and built['fresh_module_compiles']==15
            and built['actual_packer_calls']==1 and built['public_handler_qualified'] is False,'fresh native graph binding')
    compiler(root);images=[]
    require(len(built['members'])==len(members['members'])==14,'complete fourteen-owner graph')
    for row,expected in zip(built['members'],members['members'],strict=True):
        require(row['manifest']=='modules/'+expected['name']+'/manifest.json'
                and {k:row[k] for k in expected}==expected,'fixed ordered member graph')
        raw,code=module(root,expected['name'],expected['source'],
                        dict(bytes=expected['image_bytes'],sha256=expected['image_sha256']))
        require(row['manifest_pin']==pin(raw),'bound actual member manifest');images.append(code)
    raw,_=module(root,'extract-fixture-packer','native/extract_fixture_packer.hepta')
    require(built['packer_manifest']=='modules/extract-fixture-packer/manifest.json'
            and built['packer_manifest_pin']==pin(raw),'actual HIA packer manifest')
    prefix=bytearray(read(ROOT/'native/fixture-prefix.bin'));size=len(prefix)+sum(map(len,images))
    struct.pack_into('<2Q',prefix,96,size,size)
    struct.pack_into('<14Q',prefix,members['table_offset'],*(len(x) for x in images))
    actual=read(root/'extract-lines.elf');expected=bytes(prefix)+b''.join(images)
    require(actual==expected and pin(actual)==members['expected_executable'],'exact fourteen-owner native executable')
    require(built['executable']==dict(path='extract-lines.elf',**pin(actual)),'retained native executable binding')
    require(read(root/'pack.input.bin')==b'HEXTPX01'+struct.pack('<14Q',*(len(x) for x in images))+b''.join(images)
            and read(root/'pack.output.bin')==actual+b'\xb3'*4096
            and read(root/'pack.workspace.bin')==b'\xc7'*4096,'complete physical HIA packer buffers')
    rows=processes(root/'assembly-processes',[(x,60) for x in ('assemble','link','binary','relocations','symbols')])
    require(b'There are no relocations' in read(root/'assembly-processes/relocations.stdout'),'no adapter relocations')
    symbols={line.split()[-1]:int(line.split()[0],16) for line in read(root/'assembly-processes/symbols.stdout').decode().splitlines() if len(line.split())==3}
    require(built['exports']==members['exports']=={name:symbols['local_extract_lines_'+name] for name in members['exports']}
            and built['export_code']==members['export_code']==pin(read(root/'export.bin')),'exact exported mechanical adapter')
    return dict(status='PASS',compiler_files=1080,compiled_modules=15,actual_packer_calls=1,
                executable=pin(actual),export_code=built['export_code'])


def original(root):
    root=Path(root);built=loads(read(root/'BUILD.json'))
    require(built['schema']=='hepta.extract-lines.original-build.v1' and built['status']=='PASS'
            and built['source_manifest_sha256']==source() and built['original_source']==verify_original_source()
            and built['fresh_locked_builds']==1 and built['fresh_target_directory'] is True
            and built['exact_target_registry_packages']==15 and built['public_handler_qualified'] is False,
            'exact fresh original build binding')
    require(files(root/'project')==files(ROOT/'reference'),'all actual original source bytes and modes')
    expected_profile={'opt-level':1,'debug':2,'debug-assertions':True,'overflow-checks':True,'codegen-units':256,'lto':False,'incremental':False}
    require(built['profile']==expected_profile,'unchanged original development profile')
    rows=processes(root/'processes',[('format',60),('rust-version',60),('cargo-version',60),('metadata',180),('rust-build',900)])
    version=read(root/'processes/rust-version.stdout').decode()
    require('\nrelease: 1.95.0\n' in version and '\nhost: x86_64-unknown-linux-gnu\n' in version,'actual original Rust version')
    producer=Path(built['producer_root']);rust=Path(built['rust_bin'])
    config=['--config','build.rustc='+__import__('json').dumps(str(rust/'rustc'))]
    for key,value in expected_profile.items():config+=['--config','profile.dev.'+key+'='+__import__('json').dumps(value)]
    require(rows[-1]['argv']==[str(rust/'cargo'),*config,'build','--locked','--offline','--target','x86_64-unknown-linux-gnu',
                '--manifest-path',str(producer/'project/Cargo.toml'),'--target-dir',str(producer/'target')],
            'exact original locked offline build command')
    metadata=loads(read(root/'processes/metadata.stdout'));require(len(metadata['packages'])==16,'original package metadata closure')
    require(len(built['registry'])==15,'fifteen actual original registry packages')
    target={(p['name'],p['version'],p.get('source')):p.get('checksum') for p in tomllib.loads(read(ROOT/'reference/target/Cargo.lock').decode())['package']}
    retained=set()
    for row in built['registry']:
        key=(row['name'],row['version'],row['source']);require(key not in retained,'unique retained package');retained.add(key)
        require(target[key]==row['checksum'],'exact target package checksum')
        path='registry/'+row['name']+'-'+row['version']+'/source.crate'
        require(row['archive']==path,'fixed crate archive path')
        raw=read(root/path);require(sha(raw)==row['checksum'],'entire actual registry archive')
        expected={}
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
            for entry in archive.getmembers():
                parts=Path(entry.name).parts
                require(parts and parts[0]==row['name']+'-'+row['version'] and '..' not in parts,'safe crate member')
                if entry.isdir():continue
                require(entry.isfile() and len(parts)>1,'regular exact crate source')
                name=Path(*parts[1:]).as_posix();data=archive.extractfile(entry).read()
                expected[name]=dict(**pin(data),mode=entry.mode&0o777)
                require(read(root/Path(path).parent/'source'/name)==data,'full retained registry source')
        require(row['files']==expected==files(root/Path(path).parent/'source'),'complete compiled package source set')
    require(retained=={(p['name'],p['version'],p['source']) for p in metadata['packages'] if p.get('source')},'metadata and actual registry closure')
    code=read(root/'original-extract-lines')
    require(code.startswith(b'\x7fELF') and built['executable']==dict(path='original-extract-lines',**pin(code))
            and read(root/'target/x86_64-unknown-linux-gnu/debug/hepta-extract-lines-original-oracle')==code,'actual original executable custody')
    return dict(status='PASS',exact_original_items=88,registry_packages=15,executable=pin(code))
