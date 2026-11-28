"""Complete compiler, dependency and process readback; no loader or subprocess import."""
from pathlib import Path
import io
import json
import tarfile
import tomllib
from common import ROOT,COMPILER,encoded,loads,pin,read,require,sha,files,source
from commands import commands

CHILD_FIELDS={'status','result_u64','abi_status','return_encoding','core_u32','source_sha256',
    'image_sha256','output_sha256','source_unchanged','output_unchanged','workspace_header',
    'native_elapsed_ns','forbidden_compiler_modules_loaded','loader_operations','limits'}

def invocation(folder,label,input_raw,image_raw,expected_image,fmt):
    receipt=loads(read(folder/(label+'.receipt.json')))
    stdout=loads(read(folder/(label+'.stdout.log')))
    require(set(stdout)==CHILD_FIELDS and read(folder/(label+'.stderr.log'))==b'',
            'complete actual compiler child stdout/stderr')
    for key,value in stdout.items():
        require(encoded(receipt.get(key))==encoded(value),'actual compiler stdout equals retained receipt: '+key)
    full=read(folder/(label+'.output.bin'))
    request=loads(read(folder/(label+'.request.json')))
    require(read(folder/(label+'.input.bin'))==input_raw and sha(image_raw)==request['image_sha256']
            and request['source_sha256']==sha(input_raw) and request['format']==fmt
            and request['capacity']==request['workspace_size']==1<<20 and request['workspace_fill']==0,
            'actual complete compiler request')
    require(receipt['status']=='returned' and type(receipt['abi_status']) is int and receipt['abi_status']==0
        and type(receipt['core_u32']) is int and receipt['core_u32']==len(expected_image)
        and receipt['result_u64']==len(expected_image) and receipt['source_unchanged'] is True
        and receipt['input_bytes']==len(input_raw) and receipt['input_sha256']==sha(input_raw)
        and receipt['artifact_sha256']==sha(image_raw) and receipt['format']==fmt
        and receipt['source_sha256']==sha(input_raw) and receipt['image_sha256']==sha(image_raw)
        and receipt['output_sha256']==sha(full) and len(full)==1<<20
        and full[:len(expected_image)]==expected_image
        and full[len(expected_image):]==b'\xa5'*((1<<20)-len(expected_image))
        and receipt['forbidden_compiler_modules_loaded']==[]
        and receipt['produced_bytes']==len(expected_image) and receipt['produced_sha256']==sha(expected_image)
        and type(receipt['wall_elapsed_ns']) is int and 0<=receipt['wall_elapsed_ns']<=20_000_000_000,
        'actual HIA compiler complete output including unused tail')
    return receipt

def compilation(root):
    fixed=loads(read(ROOT/'COMPILER_IDENTITY.json'))
    build=loads(read(root/'build/BUILD.json'))
    folder=root/'build/bootstrap';bootstrap=loads(read(folder/'bootstrap.json'))
    require(build['compiler']==fixed==bootstrap['dependency'] and build['source_manifest_sha256']==source(),
            'complete fixed compiler and current owner source identity')
    retained=files(root/'build/compiler-source')
    require(set(retained)==set(fixed['files']) and len(retained)==1080,'complete compiler file set')
    for name,row in retained.items():require(row['sha256']==fixed['files'][name],'every compiler source byte')
    require(bootstrap['schema']=='hepta.runtime.native-bootstrap.v1'
        and bootstrap['qualification']=='development_fixed_point'
        and bootstrap['matching_source_cold_qualified'] is False
        and bootstrap['generation_sha256']==COMPILER,'fixed-point scope without a new cold-gate claim')
    compiler_source=read(root/'build/compiler-source/examples/hia_bootstrap/selfhost.hepta')
    require(bootstrap['compiler_source_sha256']==sha(compiler_source),'complete compiler source input')
    images=[read(folder/(label+'.image.bin')) for label in ('B1','B2','B3')]
    require(all(pin(image)==dict(bytes=673413,sha256=COMPILER) for image in images),'all three fresh compiler generations')
    seed_path=Path(loads(read(folder/'B1.request.json'))['image']).name
    previous=read(folder/seed_path)
    for index,label in enumerate(('B1','B2','B3')):
        receipt=invocation(folder,label,compiler_source,previous,images[index],
                           'seed-shared' if index==0 else 'flat-x86-64')
        require(receipt==bootstrap['generation_receipts'][index],'full generation receipt equality')
        previous=images[index]
    wanted={'audit-record-io':'native/audit_record_io.hepta','audit-json':'imports/audit_json.hepta'}
    require(set(build['modules'])==set(wanted),'both actual semantic HIA owners')
    modules={}
    for name,path in wanted.items():
        module=root/'build/modules'/name
        raw=read(ROOT/path);image=read(module/'module.image.bin')
        manifest=loads(read(module/'manifest.json'))
        identity=build['modules'][name]
        require(read(module/(name+'.hepta'))==raw and manifest['source']==name+'.hepta'
            and manifest['source_sha256']==sha(raw) and manifest['image']=='module.image.bin'
            and manifest['image_sha256']==sha(image) and manifest['compiler_sha256']==COMPILER
            and manifest['compiler_commit']==fixed['commit'] and manifest['standalone'] is None
            and manifest['schema']=='hepta.runtime.native-module.v1'
            and manifest['abi']=='hepta.runtime.borrowed-bytes.linux-x86_64.v1'
            and manifest['target']=='linux-x86_64' and manifest['qualification']=='development_fixed_point'
            and manifest.get('buffer_profile','standard')=='standard'
            and [manifest[k] for k in ('input_capacity','output_capacity','workspace_capacity')]==[8<<20,8<<20,32<<20],
            'exact compiled borrowed-buffer native manifest')
        receipt=invocation(module,'module',raw,images[-1],image,'flat-x86-64')
        record=loads(read(module/'build.json'))
        require(record['compiler_dependency']==fixed and record['compile_receipt']==receipt
            and record['whole_runtime_replaced'] is False,'actual full native build receipt')
        require(identity==dict(source_path=path,source=pin(raw),image=pin(image),
            manifest=dict(path='modules/'+name+'/manifest.json',**pin(read(module/'manifest.json')))),
            'complete source image and module-manifest binding')
        modules[name]=dict(source=pin(raw),image=pin(image),manifest=pin(read(module/'manifest.json')))
    return dict(compiler_files=1080,compiler_image=pin(images[-1]),modules=modules)

def dependencies(root):
    packages=[p for p in tomllib.loads(read(ROOT/'reference/Cargo.lock').decode())['package'] if 'source' in p]
    target=tomllib.loads(read(ROOT/'reference/target-Cargo.lock').decode())['package']
    expected={(p['name'],p['version']):p for p in target if 'source' in p}
    require(all(expected[(p['name'],p['version'])]==p for p in packages),'unchanged target locked package records')
    require(len(packages)==19,'complete original dependency package set')
    names={p['name']+'-'+p['version'] for p in packages}
    require({p.name for p in (root/'vendor').iterdir()}==names
            and {p.name for p in (root/'crates').iterdir()}=={n+'.crate' for n in names},
            'exact original registry archive and source domains')
    count=0;total=0
    for p in packages:
        name=p['name']+'-'+p['version'];archive=read(root/'crates'/(name+'.crate'))
        require(sha(archive)==p['checksum'],'locked complete original crate archive')
        checksum=loads(read(root/'vendor'/name/'.cargo-checksum.json'))
        require(checksum['package']==p['checksum'],'original vendored package checksum')
        observed={}
        with tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz') as tar:
            for member in tar:
                if member.isdir():continue
                require(member.isfile() and member.name.startswith(name+'/'),'original crate ordinary member')
                relative=member.name[len(name)+1:]
                require(relative and '..' not in Path(relative).parts and relative not in observed,
                        'exact unique original crate source path')
                with tar.extractfile(member) as stream:raw=stream.read()
                require(len(raw)==member.size and read(root/'vendor'/name/relative)==raw,
                        'every original implementation byte equals its locked archive')
                observed[relative]=dict(**pin(raw),mode=member.mode&0o777);count+=1;total+=len(raw)
        actual=files(root/'vendor'/name,('.cargo-checksum.json',))
        require(actual==observed and checksum['files']=={n:r['sha256'] for n,r in observed.items()},
                'no missing or extra original registry implementation files')
    return dict(packages=19,source_files=count,source_bytes=total)

def custody(root,metadata):
    rows=loads(read(root/'processes/processes.json'));wanted=commands(metadata)
    require(metadata['commands']==wanted and len(rows)==len(wanted),'complete fixed process sequence')
    for row,command in zip(rows,wanted,strict=True):
        require(row['name']==command['name'] and row['argv']==command['argv']
            and row['cwd']==command['cwd'] and row['timeout_seconds']==command['timeout']
            and type(row['pid']) is int and row['pid']>1 and type(row['parent_pid']) is int
            and row['parent_pid']>1 and row['parent_pid']!=row['pid'] and row['pgid']==row['pid']
            and row['exit_code']==0 and row['timed_out'] is False and row['completed'] is True
            and type(row['elapsed_seconds']) in (int,float) and 0<=row['elapsed_seconds']<=command['timeout'],
            'actual bounded owned process with successful wait')
        require(row['stdin'] is None,'all child inputs use the frozen explicit paths')
        for kind in ('stdout','stderr'):
            identity=row[kind]
            require(identity['file']==row['name']+'.'+kind
                and pin(read(root/'processes'/identity['file']))=={k:identity[k] for k in ('bytes','sha256')},
                'complete process stdout/stderr')
        if row['name'] in ('format','native','original'):
            require(read(root/'processes'/(row['name']+'.stderr'))==b'','complete outer driver stderr empty')
    require(b'\nrelease: 1.95.0\n' in read(root/'processes/toolchain.stdout')
        and b'\nhost: x86_64-unknown-linux-gnu\n' in read(root/'processes/toolchain.stdout')
        and read(root/'processes/cargo-version.stdout').startswith(b'cargo 1.95.0 '),'fixed actual original toolchain')
    require(pin(read(root/'original.elf'))==metadata['original_binary'] and read(root/'original.elf')[:4]==b'\x7fELF',
            'complete actual original binary')
    env=metadata['environment']['explicit_reference_environment']
    rust=Path(metadata['rust_bin'])
    require(env['RUSTC']==str(rust/'rustc') and env['RUSTDOC']==str(rust/'rustdoc')
        and env['CARGO_TARGET_DIR']==str(Path(metadata['build_temporary'])/'target')
        and env['CARGO_BUILD_TARGET']=='x86_64-unknown-linux-gnu'
        and all(env[n]=='' for n in ('RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','CARGO_BUILD_RUSTC_WRAPPER',
            'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER','CARGO_ENCODED_RUSTFLAGS','CARGO_ENCODED_RUSTDOCFLAGS','CARGO_BUILD_RUSTFLAGS'))
        and metadata['audit_trace_environment_absent'] is True,'nonambient original build and trace environment')
    return rows
