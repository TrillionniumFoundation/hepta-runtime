"""Two actual HIA stages: pinned ELF prefix link, then full image packing."""
from pathlib import Path
import hashlib,json,struct,time
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def write(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')

def pack(out,native,physical,configuration,images,view_images,view_slots,execute,source_root,*,create_images,body_images,authority_images,batch_images,extract_images,ssh_images=None):
    from hia_native_loader import NativeModule
    processes=[execute(out,'relocations',['readelf','-r',str(out/'bridge.o')],30)]
    if b'There are no relocations' not in (out/'relocations.stdout').read_bytes():
        raise ValueError('mechanical prefix requires an unexpected relocation')
    obj=(out/'bridge.o').read_bytes();entry=b'_start'
    frame=b'HIALNK01'+struct.pack('<3Q',1,len(entry),0)+entry+struct.pack('<Q',len(obj))+obj
    (out/'link.input.bin').write_bytes(frame)
    linker=native.compile('wide-elf-linker',native.hepta/'examples/hia_bootstrap/elf_static_linker.hepta',standalone=None)
    before=time.monotonic()
    with NativeModule(linker,manifest_sha256=SHA(linker.read_bytes())) as module:
        prefix=module.invoke(frame,output_capacity=8<<20,workspace_capacity=32<<20)
    (out/'linked-prefix.elf').write_bytes(prefix)
    link={'actual_return':len(prefix),'fresh_compile':True,'elapsed_seconds':time.monotonic()-before,'manifest':str(linker),'manifest_sha256':SHA(linker.read_bytes()),
        'input_bytes':len(frame),'input_sha256':SHA(frame),'output_bytes':len(prefix),'output_sha256':SHA(prefix),
        'output_capacity':8<<20,'workspace_capacity':32<<20,'pinned_linker_source_unchanged':True}
    write(out/'link.receipt.json',link)
    shoff=struct.unpack_from('<Q',obj,40)[0];shnum=struct.unpack_from('<H',obj,60)[0]
    sections=[struct.unpack_from('<IIQQQQIIQQ',obj,shoff+i*64) for i in range(shnum)]
    names=sections[struct.unpack_from('<H',obj,62)[0]];strings=obj[names[4]:names[4]+names[5]]
    section_names=[strings[h[0]:strings.index(0,h[0])].decode() for h in sections]
    text_index=section_names.index('.text');text=sections[text_index]
    if prefix[256:256+text[5]]!=obj[text[4]:text[4]+text[5]] or struct.unpack_from('<Q',prefix,96)[0]!=256+text[5]:
        raise ValueError('actual HIA linked text extent or bytes differ')
    symbols={}
    for h in sections:
        if h[1]!=2:continue
        st=sections[h[6]];names=obj[st[4]:st[4]+st[5]]
        for at in range(h[4],h[4]+h[5],24):
            name,info,other,section,value,size=struct.unpack_from('<IBBHQQ',obj,at)
            if section==text_index:
                key=names[name:names.index(0,name)].decode();symbols[key]=value
    ordered=list(physical);indices={image:i for i,image in enumerate(ordered)};patches=[]
    for name,image in configuration.items():patches.append((2,256+symbols[name+'_call_displacement'],indices[image]))
    for slot,image in images.items():patches.append((1,256+symbols['grow_fixture_images']+slot*8,indices[image]))
    for slot,key in enumerate(view_slots):patches.append((1,256+symbols['runtime_grow_view_images']+slot*8,indices[view_images[key]]))
    if len(create_images)!=7:raise ValueError('private Create table differs')
    for slot,image in enumerate(create_images):patches.append((1,256+symbols['runtime_text_create_images']+slot*8,indices[image]))
    if len(body_images)!=12:raise ValueError('private body table differs')
    for slot,image in enumerate(body_images):patches.append((1,256+symbols['runtime_text_body_images']+slot*8,indices[image]))
    if len(authority_images)!=9:raise ValueError('private authority table differs')
    for slot,image in enumerate(authority_images):patches.append((1,256+symbols['runtime_authority_images']+slot*8,indices[image]))
    if len(batch_images)!=14:raise ValueError('private Batch table differs')
    for slot,image in enumerate(batch_images):patches.append((1,256+symbols['runtime_batch_body_images']+slot*8,indices[image]))
    if len(extract_images)!=14:raise ValueError('private Extract table differs')
    for slot,image in enumerate(extract_images):patches.append((1,256+symbols['runtime_extract_body_images']+slot*8,indices[image]))
    if ssh_images is not None:
        if len(ssh_images)!=5:raise ValueError('private SSH table differs')
        for slot,image in enumerate(ssh_images):patches.append((1,256+symbols['runtime_ssh_images']+slot*8,indices[image]))
    raw_images=[image.read_bytes() for image in ordered]
    packed_input=(b'HIAIMG02'+struct.pack('<4Q',len(prefix),len(ordered),len(patches),0)+prefix
        +b''.join(struct.pack('<Q',len(image)) for image in raw_images)
        +b''.join(struct.pack('<3Q',*row) for row in patches)+b''.join(raw_images))
    (out/'pack.input.bin').write_bytes(packed_input)
    expected=bytearray(prefix);positions=[]
    for image in raw_images:
        expected+=bytes((-len(expected))%16);positions.append(len(expected));expected+=image
    text_end=len(expected);expected+=bytes((-len(expected))%4096)
    for kind,at,index in patches:
        if kind==1:struct.pack_into('<Q',expected,at,4194304+positions[index])
        else:struct.pack_into('<I',expected,at,positions[index]-at-4)
    struct.pack_into('<QQ',expected,96,text_end,text_end)
    struct.pack_into('<QQQ',expected,128,len(expected),4194304+len(expected),4194304+len(expected))
    source=source_root/'native/runtime_mcp_image_packer.hepta'
    packer=native.compile('wide-image-pack',source,standalone=None,buffer_profile='history.v1')
    before=time.monotonic();capacity=32+len(expected);workcap=(64+len(ordered)*8+4095)&~4095
    with NativeModule(packer,manifest_sha256=SHA(packer.read_bytes())) as module:
        code,raw_output,work=module.invoke_raw(packed_input,output_capacity=capacity,workspace_capacity=workcap)
    (out/'pack.output.bin').write_bytes(raw_output);(out/'pack.workspace.bin').write_bytes(work)
    if code!=32 or raw_output[:32]!=b'HIAIMR02'+struct.pack('<3Q',0,len(expected),0) or raw_output[32:]!=expected:
        raise ValueError('actual HIA image pack differs from fixed source-linked layout: '+str(code))
    elf=raw_output[32:]
    pack_receipt={'fresh_compile':True,'elapsed_seconds':time.monotonic()-before,'manifest':str(packer),'manifest_sha256':SHA(packer.read_bytes()),
        'input_bytes':len(packed_input),'input_sha256':SHA(packed_input),'output_bytes':len(raw_output),'output_sha256':SHA(raw_output),
        'actual_return':code,'output_capacity':capacity,'workspace_capacity':workcap,'prefix_text_offset':256,
        'fixed_patches':patches,'image_offsets':positions,'image_sources':[str(image) for image in ordered]}
    write(out/'pack.receipt.json',pack_receipt)
    return elf,link,pack_receipt,processes
