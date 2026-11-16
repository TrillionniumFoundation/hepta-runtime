"""Pure admission of the source-bound 71-image public/private pair.

The shared 71 actual members must be freshly compiled once by the public
build and reused identically by the private fixture. No cold-bootstrap claim
is granted. Recorded absolute artifact names stay unchanged. An optional strict read_bytes(Path)->bytes maps
those names to a byte-identical artifact relocation without rewriting receipts.
"""
from pathlib import Path
import hashlib, importlib.util, json, math, stat, struct, sys

sha=lambda b:hashlib.sha256(b).hexdigest()

def dual_build_evidence(root,public_manifest,private_manifest,*,read_bytes=None,reader_path=None):
    root=Path(root);reader_path=root/'scripts/hia_native_runtime_mcp_evidence.py' if reader_path is None else Path(reader_path);artifacts={};cache={}
    def require(ok,message):
        if not ok:raise ValueError('filesystem public build evidence: '+message)
    def read(path):
        path=Path(path);require(path.is_absolute() and '..' not in path.parts,'artifact is not an absolute owned name')
        name=str(path)
        if name not in cache:
            if read_bytes is None:
                require(path.resolve()==path.absolute() and stat.S_ISREG(path.lstat().st_mode),'artifact is not a regular file')
                raw=path.read_bytes()
            else:raw=read_bytes(path)
            require(type(raw) is bytes,'artifact mapper did not return full bytes')
            cache[name]=raw;artifacts[name]={'bytes':len(raw),'sha256':sha(raw)}
        return cache[name]
    def decode(raw):
        def pairs(items):
            value={}
            for key,item in items:
                require(key not in value,'duplicate JSON key');value[key]=item
            return value
        def bad(_):raise ValueError('filesystem public build evidence: nonfinite JSON')
        return json.loads(raw,object_pairs_hook=pairs,parse_constant=bad)
    read(Path(__file__).resolve())
    source_raw=read(root/'native/runtime_mcp_sources.json')
    source=decode(source_raw);require(source['schema']=='hepta.runtime.public-source-closure.v2','source schema differs')
    for name,pin in source['sources'].items():
        relative=Path(name);require(not relative.is_absolute() and '..' not in relative.parts and relative.as_posix()==name,'source escaped checkout')
        raw=read(root/name);require(pin=={'bytes':len(raw),'sha256':sha(raw)},'source changed: '+name)
    reader=read(reader_path)
    sys.path.insert(0,str(root/'scripts'))
    spec=importlib.util.spec_from_file_location('_frozen_fs_public_build_primitives',reader_path)
    q=importlib.util.module_from_spec(spec);exec(compile(reader,str(reader_path),'exec'),q.__dict__)
    class Streams:
        output=Path('/')
        def read(self,name):return read(Path('/')/name)
        def object(self,name):return decode(self.read(name))
    require(sha(source_raw)==q.SOURCE_MANIFEST_SHA256,'source manifest differs from the trusted current reader')
    evidence=Streams();binding={'manifest_sha256':sha(source_raw),'files':source['sources']};rows=[];all_images=None;public_rows={}
    from hia_native_runtime_mcp_build import FIXTURE_BOUNDARIES
    def module(path,expected_source,expected_profile):
        raw=read(path);meta=decode(raw);folder=path.parent
        require(meta.get('name')==folder.name,'actual compiler module name differs')
        q.exact([meta.get(k) for k in ('schema','abi','target','standalone')],
                ['hepta.runtime.native-module.v1','hepta.runtime.borrowed-bytes.linux-x86_64.v1','linux-x86_64',None],
                'compiled module interface differs')
        q.exact(meta.get('buffer_profile','standard'),expected_profile,'compiled buffer profile differs')
        q.exact([meta.get(k) for k in ('compiler_commit','compiler_sha256')],[q.HEPTA_COMMIT,q.COMPILER_SHA256],'compiler identity differs')
        for key in ('source','image'):require(type(meta.get(key)) is str and Path(meta[key]).name==meta[key],'module artifact escaped folder')
        compiled_source=read(folder/meta['source']);image=read(folder/meta['image'])
        q.exact(compiled_source,expected_source,'complete compiled HIA input differs')
        require(meta['source_sha256']==sha(compiled_source) and meta['image_sha256']==sha(image),'source/image digest differs')
        q.exact([meta.get(k) for k in ('input_capacity','output_capacity','workspace_capacity')],list(q.BUFFER_PROFILES[expected_profile]),'declared buffer capacities differ')
        require(meta.get('qualification')=='development_fixed_point','reused module overclaims qualification')
        request=decode(read(folder/'module.request.json'));compiler_path=Path(request['image']);compiler=read(compiler_path)
        require(sha(compiler)==q.COMPILER_SHA256,'actual compiler image bytes differ')
        build=decode(read(folder/'build.json'));dependency=build['compiler_dependency']
        require(dependency.get('commit')==q.HEPTA_COMMIT and dependency.get('tree')==q.HEPTA_TREE
                and dependency.get('files',{}).get('examples/hia_bootstrap/elf_static_linker.hepta')==q.LINKER_SOURCE_SHA256,
                'actual compiler dependency differs')
        q.compilation(evidence,folder,compiled_source,image,compiler,dependency,folder,compiler_path)
        return meta,image
    for private,manifest_path in [(False,Path(public_manifest)),(True,Path(private_manifest))]:
        raw=read(manifest_path)
        bundle=decode(raw);folder=manifest_path.parent
        q.exact(bundle['source_binding'],binding,'built/current source closure differs')
        q.exact(bundle['manifest_path'],str(manifest_path),'recorded manifest origin differs')
        require(bundle.get('schema')=='hepta.runtime.mcp-view-build.v2' and bundle.get('status')=='PASS','actual bundle failed')
        require(type(bundle['elapsed_seconds']) in (float,int) and math.isfinite(bundle['elapsed_seconds']) and 0<bundle['elapsed_seconds']<180,'actual bundle time differs')
        q.exact(bundle['private_instance_fixture'],private,'public/private entry differs')
        q.exact(bundle['fixture_sessions'],2 if private else None,'fixture session count differs')
        q.exact(bundle['fixture_pseudo_selectors'],[33,34,35,36] if private else [],'fixture selector scope differs')
        q.exact(bundle['actual_fixture_private_selectors'],private,'private selector claim differs')
        q.exact([bundle.get(k) for k in ('compiler_commit','compiler_image_sha256')],
                [q.HEPTA_COMMIT,q.COMPILER_SHA256],'bundle compiler identity differs')
        q.exact(bundle.get('config_table'),q.CONFIG,'installed config table differs')
        q.exact(bundle.get('extra_table'),q.EXTRA,'public-engine table differs')
        q.exact(bundle.get('view_table'),q.VIEW,'View-engine table differs')
        q.exact(bundle.get('batch_table'),q.BATCH,'Batch-engine table differs')
        q.exact(bundle.get('physical_images'),71,'physical member count differs')
        q.exact({k:bundle.get(k) for k in ('shared_session_slot','shared_installed_config_owner_slot',
            'filesystem_gateway_slot','filesystem_caller_slot','filesystem_io_slot','filesystem_fence_slot',
            'native_fence_slot','view_scope_cache_alias_slots','config_span_owner_control_offsets',
            'config_span_footer_from_capacity','public_configuration_from_stdin','public_private_instance_selectors')},
            dict(shared_session_slot=6,shared_installed_config_owner_slot=11,filesystem_gateway_slot=21,
                 filesystem_caller_slot=23,filesystem_io_slot=24,filesystem_fence_slot=27,native_fence_slot=28,
                 view_scope_cache_alias_slots={'29':6,'30':5,'31':7,'32':8},
                 config_span_owner_control_offsets=[1024,1032],config_span_footer_from_capacity=256,
                 public_configuration_from_stdin=False,public_private_instance_selectors=False),
            'private ownership or shared-instance layout differs')
        q.exact({k:bundle.get(k) for k in ('batch_gateway_slot','batch_params_slot','batch_engine_slot','batch_catalog_slot',
            'batch_shared_view_cache','batch_public_async_cancellation_qualified')},
            dict(batch_gateway_slot=33,batch_params_slot=34,batch_engine_slot=35,batch_catalog_slot=36,
                 batch_shared_view_cache=True,batch_public_async_cancellation_qualified=False),'Batch instance ownership differs')
        for flag in q.FALSE_FLAGS:q.exact(bundle.get(flag),False,'unqualified build claim: '+flag)
        boundaries=[q.BASE,*(FIXTURE_BOUNDARIES if private else [q.TRANSPORT]),*q.BOUNDARIES]
        q.exact(bundle.get('boundary_sources'),{name:sha(read(root/name)) for name in boundaries},
                'source-bound mechanical input inventory differs')
        q.exact([r['name'] for r in bundle['members']],[m[0] for m in q.MEMBERS],'fixed HIA member set differs')
        images={};image_paths={}
        for row,(name,source_name,profile) in zip(bundle['members'],q.MEMBERS):
            path=Path(row['manifest']);q.exact(sha(read(path)),row['manifest_sha256'],'member manifest identity differs')
            q.exact(row['source'],'native/'+source_name+'.hepta','member source name differs')
            q.exact(row.get('fresh_compile'),not private,'shared members must be freshly compiled exactly once')
            if private:
                q.exact({key:value for key,value in row.items() if key!='fresh_compile'},
                        {key:value for key,value in public_rows[name].items() if key!='fresh_compile'},
                        'private fixture did not reuse the public compiled member')
            else:
                q.exact(path.name,'manifest.json','member manifest filename differs')
                q.exact(path.parent.name,'runtime-mcp-'+name.replace('_','-'),'fresh member module name differs')
                public_rows[name]=row
            meta,image=module(path,read(root/row['source']),profile)
            q.exact((row['image_bytes'],row['image_sha256'],row['source_sha256']),
                    (len(image),sha(image),meta['source_sha256']),'member declaration differs')
            images[name]=image;image_paths[name]=str(path.parent/meta['image'])
        if all_images is None:all_images=images
        else:
            q.exact(sorted(images),sorted(all_images),'two executables have different image inventories')
            for name in images:q.exact(images[name],all_images[name],'two executables differ in complete HIA image: '+name)
        q.exact(read(folder/'combined.S'),q.adapter_source(root,private_fixture=private).encode(),'actual assembly does not match frozen boundary')
        obj=read(folder/'bridge.o');plan=q.link_plan(obj,images);elf=read(folder/bundle['elf'])
        q.exact(read(folder/'link.input.bin'),b'HIALNK01'+struct.pack('<3Q',1,6,0)+b'_start'+struct.pack('<Q',len(obj))+obj,'actual linker input differs')
        q.exact(read(folder/'linked-prefix.elf'),plan['prefix'],'actual HIA-linked prefix differs')
        q.exact(read(folder/'pack.input.bin'),plan['input'],'complete HIA image appends and patches differ')
        q.exact(elf,plan['elf'],'complete actual ELF differs')
        structure=q.elf_structure(elf,obj,images)
        q.exact((bundle.get('assembled_source_sha256'),bundle.get('object_sha256'),bundle.get('elf_sha256'),bundle.get('elf_bytes')),
                (sha(read(folder/'combined.S')),sha(obj),sha(elf),len(elf)),'bundle binary declarations differ')
        q.exact(bundle.get('elf'),'filesystem-fixture.elf' if private else 'runtime-mcp.elf','entry executable name differs')
        q.exact(read(folder/'pack.output.bin'),b'HIAIMR02'+struct.pack('<3Q',0,len(elf),0)+elf,'complete actual packer output differs')
        q.exact(bundle['physical_image_members'],plan['order'],'fixed image order differs')
        q.exact(bundle['fence_table'],q.FENCE,'native fence range differs')
        workcap=(64+71*8+4095)&~4095;workspace=bytearray(workcap)
        struct.pack_into('<QQ',workspace,8,plan['text_end'],len(elf))
        for i,offset in enumerate(plan['positions']):struct.pack_into('<Q',workspace,64+i*8,offset)
        q.exact(read(folder/'pack.workspace.bin'),bytes(workspace),'complete HIA packer workspace differs')
        for label in ('link','pack'):
            receipt=decode(read(folder/(label+'.receipt.json')));q.exact(receipt,bundle[label],'actual HIA build receipt differs')
            require(receipt.get('fresh_compile') is True,'actual HIA link/pack image was not freshly compiled')
            require(type(receipt.get('elapsed_seconds')) in (float,int) and math.isfinite(receipt['elapsed_seconds']) and 0<receipt['elapsed_seconds']<180,'actual HIA link/pack time differs')
            path=Path(receipt['manifest']);q.exact(sha(read(path)),receipt['manifest_sha256'],'actual HIA build image manifest differs')
            source_module=decode(read(path));hia_source=read(path.parent/source_module['source'])
            if label=='link':q.exact(sha(hia_source),q.LINKER_SOURCE_SHA256,'upstream linker source differs')
            else:q.exact(hia_source,read(root/'native/runtime_mcp_image_packer.hepta'),'packer source differs')
            module(path,hia_source,'standard' if label=='link' else 'history.v1')
        pack=bundle['pack'];q.exact(pack['fixed_patches'],[list(p) for p in plan['patches']],'actual fixed patch list differs')
        q.exact(pack['image_sources'],[image_paths[n] for n in plan['order']],'actual image append source differs')
        q.exact(pack['image_offsets'],plan['positions'],'actual image offsets differ')
        for process in bundle['boundary_processes']:
            name=process['name'];timeout=60 if name=='assemble' else 30
            commands={'assemble':['as','--64','-o',str(folder/'bridge.o'),str(folder/'combined.S')],
                      'relocations':['readelf','-r',str(folder/'bridge.o')],
                      'readelf':['readelf','-lW',str(folder/bundle['elf'])]}
            require(name in commands,'unexpected native boundary process')
            q.exact(process['command'],commands[name],'actual boundary command differs')
            q.exact(process['cwd'],bundle['source_root'],'actual boundary cwd differs')
            require(type(process['exit_code']) is int and process['exit_code']==0 and process['timed_out'] is False
                    and type(process['timeout_seconds']) is int and process['timeout_seconds']==timeout
                    and type(process['elapsed_seconds']) in (float,int) and math.isfinite(process['elapsed_seconds'])
                    and 0<process['elapsed_seconds']<timeout,'actual boundary process failed/timed out')
            q.exact(decode(read(folder/(name+'.process.json'))),process,'actual boundary receipt copy differs')
            for key in ('stdout','stderr'):
                data=read(folder/(name+'.'+key));q.exact(process[key],{'bytes':len(data),'sha256':sha(data)},'boundary full raw stream differs')
                if key=='stderr' or name=='assemble':q.exact(data,b'','boundary emitted diagnostics')
        q.exact([p['name'] for p in bundle['boundary_processes']],['assemble','relocations','readelf'],'boundary process inventory differs')
        rows.append({'private_fixture':private,'manifest':str(manifest_path),'manifest_sha256':sha(raw),
                     'elf_bytes':len(elf),'elf_sha256':sha(elf),'members':71,'patches':93,
                     'fresh_member_compiles':sum(r['fresh_compile'] for r in bundle['members']),
                     'actual_fresh_link_pack_compiles':2,'elf_structure':structure})
    return {'status':'PASS','shared_fresh_member_qualification':True,'fresh_cold_qualified':False,'new_native_processes':0,'new_rust_processes':0,
            'current_original_sdk_comparison':False,'frozen_source_binding':binding,'bundles':rows,
            'artifacts':dict(sorted(artifacts.items())),'artifact_sha256':{k:v['sha256'] for k,v in sorted(artifacts.items())}}
