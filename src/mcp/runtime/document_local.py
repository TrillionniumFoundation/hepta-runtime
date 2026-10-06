# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Fixed local document parser/author. No command strings, remote fetches or sudo.
Requests receive controller-policy roots from Rust, not from tool arguments.
Document writes require a source fingerprint and preserve the input on failure.
"""
import base64
import fcntl
import hashlib
import io
import json
import os
import pathlib
import re
import resource
import stat
import subprocess
import sys
import tempfile
import warnings
import zipfile
from xml.sax.saxutils import escape

FILE_LIMIT = 32 * 1024 * 1024
TEXT_LIMIT = 240 * 1024
IMAGE_LIMIT = 512 * 1024


def checked(q, path):
    p = pathlib.Path(path)
    if not p.is_absolute() or '..' in p.parts: raise ValueError('absolute document path required')
    resolved = p.resolve()
    if not any(resolved == pathlib.Path(root).resolve() or pathlib.Path(root).resolve() in resolved.parents for root in q['roots']):
        raise PermissionError('document path is outside controller roots')
    return resolved


def parent_fd(path):
    path=pathlib.Path(path)
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
    fd=os.open('/',flags)
    try:
        for part in path.parts[1:-1]:
            nxt=os.open(part,flags,dir_fd=fd);os.close(fd);fd=nxt
        return fd,path.name
    except BaseException:
        os.close(fd);raise


def read_at(fd,name):
    f=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
    with os.fdopen(f,'rb') as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size>FILE_LIMIT:raise ValueError('document must be a regular file at most 32 MiB')
        data=stream.read(FILE_LIMIT+1);after=os.fstat(stream.fileno())
        if len(data)>FILE_LIMIT or (before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise ValueError('document changed during read')
    return data,hashlib.sha256(data).hexdigest(),stat.S_IMODE(before.st_mode)&0o777


def read_bytes(path):
    fd,name=parent_fd(path)
    try:
        data,digest,_=read_at(fd,name);return data,digest
    finally:os.close(fd)


def publish(q,path,data,expected):
    path=checked(q,path)
    if expected is None:raise ValueError('expected_sha256 is required; use absent for create-only')
    if len(data)>FILE_LIMIT:raise ValueError('generated document exceeds 32 MiB')
    fd,name=parent_fd(path)
    tmp='.hepta-document-'+__import__('secrets').token_hex(12)
    try:
        lock='.hepta-document-'+hashlib.sha256(name.encode()).hexdigest()[:24]+'.lock'
        f=os.open(lock,os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,0o600,dir_fd=fd)
        with os.fdopen(f,'w') as guard:
            if not stat.S_ISREG(os.fstat(guard.fileno()).st_mode):raise ValueError('invalid document lock')
            fcntl.flock(guard.fileno(),fcntl.LOCK_EX)
            try:_,existing,mode=read_at(fd,name)
            except FileNotFoundError:existing,mode='absent',0o600
            if expected!=existing:raise ValueError('stale document fingerprint; no write applied')
            f=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
            with os.fdopen(f,'wb') as stream:
                stream.write(data);stream.flush();os.fchmod(stream.fileno(),mode);os.fsync(stream.fileno())
            if existing=='absent':
                os.link(tmp,name,src_dir_fd=fd,dst_dir_fd=fd,follow_symlinks=False);os.unlink(tmp,dir_fd=fd)
            else:
                if read_at(fd,name)[1]!=expected:raise ValueError('document changed before commit')
                os.replace(tmp,name,src_dir_fd=fd,dst_dir_fd=fd)
            os.fsync(fd)
    finally:
        try:os.unlink(tmp,dir_fd=fd)
        except FileNotFoundError:pass
        os.close(fd)
    return {'path':str(path),'sha256':hashlib.sha256(data).hexdigest(),'size':len(data),'atomic_replace':True}


def safe_zip(data):
    z = zipfile.ZipFile(io.BytesIO(data))
    infos = z.infolist()
    if len(infos) > 10000 or sum(x.file_size for x in infos) > 128 * 1024 * 1024: raise ValueError('OOXML expansion exceeds budget')
    if len({x.filename for x in infos}) != len(infos): raise ValueError('duplicate OOXML members')
    for info in infos:
        if info.flag_bits & 1 or '..' in pathlib.PurePosixPath(info.filename).parts or info.filename.startswith('/'): raise ValueError('invalid OOXML package')
        if info.filename.endswith('.xml'):
            content = z.read(info)
            if b'<!DOCTYPE' in content or b'<!ENTITY' in content: raise ValueError('XML declarations are not accepted')
    return z


def image_preview(data):
    from PIL import Image, ImageOps
    Image.MAX_IMAGE_PIXELS = 20_000_000
    with warnings.catch_warnings():
        warnings.simplefilter('error', Image.DecompressionBombWarning)
        with Image.open(io.BytesIO(data), formats=['PNG','JPEG','WEBP','GIF','BMP','TIFF']) as img:
            img.load(); info={'width':img.width,'height':img.height,'format':img.format,'frames':getattr(img,'n_frames',1)}
            preview=ImageOps.exif_transpose(img).convert('RGB');preview.thumbnail((1200,1200))
            out=io.BytesIO();preview.save(out,'JPEG',quality=80)
            if len(out.getvalue())>IMAGE_LIMIT: raise ValueError('preview exceeds response limit')
    return info, {'type':'image','mimeType':'image/jpeg','data':base64.b64encode(out.getvalue()).decode()}


def read_document(q):
    path=checked(q,q['path']);data,digest=read_bytes(path)
    if q.get('expected_sha256') not in (None,digest): raise ValueError('document fingerprint changed')
    offset=max(0,int(q.get('offset') or 0));length=max(1,min(100,int(q.get('length') or 20)))
    kind=path.suffix.lower();result={'path':str(path),'sha256':digest,'size':len(data)};images=[]
    if q['op']=='image_read' or kind in ('.png','.jpg','.jpeg','.webp','.gif','.bmp','.tif','.tiff'):
        meta,image=image_preview(data);result.update(meta);images.append(image)
    elif kind=='.docx':
        from docx import Document
        from docx.text.paragraph import Paragraph
        from docx.table import Table
        with safe_zip(data) as package:
            doc=Document(io.BytesIO(data));nodes=list(doc.element.body)
            if q.get('xml_part'):
                name=q['xml_part']
                if not re.fullmatch(r'word/(document|header\d+|footer\d+)\.xml',name):raise ValueError('unsupported DOCX part')
                from lxml import etree
                xml=etree.tostring(etree.fromstring(package.read(name),parser=etree.XMLParser(resolve_entities=False,no_network=True)),pretty_print=True,encoding='unicode')
                lines=xml.splitlines();result.update({'xml_part':name,'lines':lines[offset:offset+length],'total_lines':len(lines),'next_offset':min(len(lines),offset+length)})
            else:
                blocks=[]
                for i,node in enumerate(nodes[offset:offset+length],offset):
                    tag=node.tag.rsplit('}',1)[-1]
                    if tag=='p':
                        p=Paragraph(node,doc);blocks.append({'index':i,'type':'paragraph','text':p.text,'style':p.style.name})
                    elif tag=='tbl':blocks.append({'index':i,'type':'table','rows':[[c.text for c in r.cells] for r in Table(node,doc).rows]})
                result.update({'elements':blocks,'next_offset':min(len(nodes),offset+length),'total_elements':len(nodes),'image_refs':[n for n in package.namelist() if n.startswith('word/media/')][:128]})
    elif kind in ('.xlsx','.xlsm'):
        with safe_zip(data): pass
        from openpyxl import load_workbook
        from openpyxl.utils.cell import range_boundaries
        book=load_workbook(io.BytesIO(data),read_only=True,data_only=bool(q.get('cached_values',False)),keep_links=False)
        try:
            name=q.get('sheet') or book.sheetnames[0]
            if name not in book.sheetnames and name.isdigit() and int(name)<len(book.sheetnames):name=book.sheetnames[int(name)]
            if name not in book.sheetnames:raise ValueError('unknown worksheet')
            region=q.get('range') or f'A{offset+1}:T{offset+length}'
            if ':' not in region:raise ValueError('use FROM:TO worksheet ranges')
            c1,r1,c2,r2=range_boundaries(region)
            if not all(isinstance(x,int) and x>0 for x in (c1,r1,c2,r2)) or r2<r1 or c2<c1 or (c2-c1+1)*(r2-r1+1)>5000:raise ValueError('invalid worksheet range')
            rows=[[v.isoformat() if hasattr(v,'isoformat') else v for v in row] for row in book[name].iter_rows(min_col=c1,max_col=c2,min_row=r1,max_row=r2,values_only=True)]
            result.update({'sheets':book.sheetnames,'sheet':name,'range':region,'rows':rows,'formulas_recalculated':False})
        finally:book.close()
    elif kind=='.pdf':
        from pypdf import PdfReader
        pdf=PdfReader(io.BytesIO(data))
        if pdf.is_encrypted:raise ValueError('encrypted PDF is not unlocked by this tool')
        length=min(length,2 if q.get('render') else 10)
        if offset>=len(pdf.pages):raise ValueError('page index outside PDF')
        result.update({'page_count':len(pdf.pages),'next_offset':min(len(pdf.pages),offset+length),'pages':[{'index':i,'text':pdf.pages[i].extract_text() or ''} for i in range(offset,min(len(pdf.pages),offset+length))],'ocr_performed':False})
        if q.get('render'):
            with tempfile.TemporaryDirectory(prefix='hepta-pdf-preview-') as folder:
                source=pathlib.Path(folder)/'source.pdf';source.write_bytes(data)
                for page in result['pages']:
                    out=pathlib.Path(folder)/('page-'+str(page['index']))
                    subprocess.run(['/usr/bin/pdftoppm','-f',str(page['index']+1),'-l',str(page['index']+1),'-singlefile','-scale-to','1200','-png',str(source),str(out)],check=True,capture_output=True,timeout=20)
                    _,image=image_preview(pathlib.Path(str(out)+'.png').read_bytes());images.append(image)
    else:raise ValueError('supported documents: DOCX, XLSX/XLSM, PDF and raster images; use view for text')
    encoded=json.dumps(result,ensure_ascii=False)
    if len(encoded.encode())>TEXT_LIMIT:raise ValueError('result too large; narrow document range')
    return [{'type':'text','text':encoded},*images]


def create_bytes(kind,content):
    out=io.BytesIO()
    if kind=='docx':
        from docx import Document
        doc=Document()
        if not isinstance(content,str):raise ValueError('DOCX creation requires markdown text')
        for line in content.splitlines():
            level=len(line)-len(line.lstrip('#'))
            if 1<=level<=3:doc.add_heading(line[level:].lstrip(),level)
            else:doc.add_paragraph(line)
        doc.save(out)
    elif kind=='xlsx':
        from openpyxl import Workbook
        if not isinstance(content,dict) or not 1<=len(content)<=20:raise ValueError('XLSX content maps sheet names to row arrays')
        book=Workbook();book.remove(book.active)
        count=0
        for name,rows in content.items():
            sheet=book.create_sheet(name)
            for row in rows:
                count+=len(row)
                if count>10000:raise ValueError('too many cells')
                sheet.append(row)
        book.save(out)
    elif kind=='pdf':
        if not isinstance(content,str):raise ValueError('PDF creation requires markdown text')
        from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,PageBreak
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.cidfonts import UnicodeCIDFont
        pdfmetrics.registerFont(UnicodeCIDFont('STSong-Light'));styles=getSampleStyleSheet()
        for style in styles.byName.values():style.fontName='STSong-Light'
        items=[]
        for line in content.splitlines():
            if line.strip()=='<!-- pagebreak -->':items.append(PageBreak());continue
            level=len(line)-len(line.lstrip('#'));style=styles['Heading'+str(level)] if 1<=level<=3 else styles['BodyText']
            text=line[level:].lstrip() if 1<=level<=3 else line
            items.extend([Paragraph(escape(text) or '&#160;',style),Spacer(1,4)])
        SimpleDocTemplate(out).build(items)
    else:raise ValueError('unsupported authored format')
    return out.getvalue()


def edit_docx(q):
    path=checked(q,q['path']);data,sha=read_bytes(path)
    if q.get('expected_sha256')!=sha:raise ValueError('edit requires current source SHA256')
    if path.suffix.lower()!='.docx':raise ValueError('this exact-XML edit supports DOCX only')
    part=q.get('part') or 'word/document.xml'
    if not re.fullmatch(r'word/(document|header\d+|footer\d+)\.xml',part):raise ValueError('unsupported DOCX part')
    old,new=q['old_xml'],q['new_xml'];count=int(q.get('expected_replacements') or 1)
    if not old or not 1<=count<=1000:raise ValueError('invalid expected replacement count')
    with safe_zip(data) as package:
        text=package.read(part).decode()
        if text.count(old)!=count:raise ValueError('DOCX match count differs; no edit applied')
        text=text.replace(old,new)
        if '<!DOCTYPE' in text or '<!ENTITY' in text:raise ValueError('XML declarations rejected')
        from lxml import etree
        etree.fromstring(text.encode(),parser=etree.XMLParser(resolve_entities=False,no_network=True))
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w') as writer:
            for info in package.infolist():writer.writestr(info,text.encode() if info.filename==part else package.read(info))
    result=publish(q,str(path),out.getvalue(),sha);result['changed_parts']=[part];result['unselected_zip_payloads_preserved']=True
    return [{'type':'text','text':json.dumps(result)}]



def remote_call(q, op, path, **fields):
    import shlex
    config=q['remote']
    roots=config['read_roots'] if op in ('read','info') else config['write_roots']
    candidates=[root for root in roots if path==root or path.startswith(root.rstrip('/')+'/')]
    if not candidates:raise PermissionError('remote document outside configured roots')
    payload={'op':op,'path':path,'root':max(candidates,key=len),**fields}
    args=['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ForwardAgent=no',
          '-o','ConnectTimeout=8',config['ssh_target'],'/usr/bin/python3 -I -c '+shlex.quote(q['file_helper'])]
    result=subprocess.run(args,input=json.dumps(payload),text=True,capture_output=True,timeout=25)
    if result.returncode:raise RuntimeError('remote document file operation: '+result.stderr[-2000:])
    return json.loads(result.stdout)


def remote_fetch(q,path,expected_sha):
    offset=0;version=None;data=bytearray()
    while True:
        part=remote_call(q,'read',path,offset=offset,limit=1024*1024,expected_version=version)
        if part['size']>FILE_LIMIT:raise ValueError('remote document exceeds 32 MiB')
        version=part['version'];block=base64.b64decode(part['data_base64'],validate=True)
        if hashlib.sha256(block).hexdigest()!=part['chunk_sha256']:raise ValueError('remote chunk integrity failed')
        data.extend(block);offset=part['next_offset']
        if part['eof']:break
        if not block:raise ValueError('remote read made no progress')
    sha=hashlib.sha256(data).hexdigest()
    if expected_sha not in (None,sha):raise ValueError('remote source SHA256 changed')
    return bytes(data),version,sha


def remote_publish(q,path,data,prior):
    encoded=base64.b64encode(data).decode()
    if len(data)<=1024*1024:return remote_call(q,'write',path,data_base64=encoded,expected_version=prior)
    import secrets
    upload='document-'+secrets.token_hex(16)
    for offset in range(0,len(data),1024*1024):
        remote_call(q,'upload_chunk',path,upload_id=upload,offset=offset,
                    data_base64=base64.b64encode(data[offset:offset+1024*1024]).decode(),expected_version=prior)
    return remote_call(q,'upload_commit',path,upload_id=upload,size=len(data),sha256=hashlib.sha256(data).hexdigest())


def remote_document(q):
    op=q['op'];path=q['path']
    with tempfile.TemporaryDirectory(prefix='hepta-remote-document-') as folder:
        local=pathlib.Path(folder)/('source'+pathlib.PurePosixPath(path).suffix)
        request={k:v for k,v in q.items() if k not in ('remote','file_helper','host')}
        request['path']=str(local);request['roots']=[folder]
        prior='absent'
        if op!='write' or q.get('expected_sha256')!='absent':
            data,prior,sha=remote_fetch(q,path,q.get('expected_sha256'))
            local.write_bytes(data)
        mapped={str(local):path}
        if op=='pdf_edit':
            output=pathlib.Path(folder)/'output.pdf';request['output_path']=str(output)
            mapped[str(output)]=q['output_path']
            output_prior='absent'
            if q['output_expected_sha256']!='absent':
                original,output_prior,_=remote_fetch(q,q['output_path'],q['output_expected_sha256'])
                output.write_bytes(original)
            request['operations']=[dict(o) for o in q['operations']]
            for i,item in enumerate(request['operations']):
                if item.get('source_path'):
                    data,_,_=remote_fetch(q,item['source_path'],item['source_sha256'])
                    source=pathlib.Path(folder)/f'insert-{i}.pdf';source.write_bytes(data)
                    mapped[str(source)]=item['source_path'];item['source_path']=str(source)
        result=main(request)
        if op in ('write','edit_docx','pdf_edit','worksheet_edit'):
            output=pathlib.Path(request['output_path']) if op=='pdf_edit' else local
            destination=q['output_path'] if op=='pdf_edit' else path
            publish_result=remote_publish(q,destination,output.read_bytes(),output_prior if op=='pdf_edit' else prior)
            meta=json.loads(result[0]['text']);meta['publication_version']=publish_result['version'];result[0]['text']=json.dumps(meta)
        for content in result:
            if content['type']=='text':
                meta=json.loads(content['text'])
                for field in ('path','source_path','output_path'):
                    if meta.get(field) in mapped:meta[field]=mapped[meta[field]]
                meta['host']=q['host'];meta['transport']='native_remote_file_transfer'
                content['text']=json.dumps(meta,ensure_ascii=False)
        return result


def edit_pdf(q):
    from pypdf import PdfReader,PdfWriter
    source=checked(q,q['path']);target=checked(q,q['output_path'])
    if source==target or target.suffix.lower()!='.pdf':raise ValueError('PDF edit requires a distinct PDF output path')
    data,sha=read_bytes(source)
    if q.get('expected_sha256')!=sha:raise ValueError('PDF source fingerprint changed')
    reader=PdfReader(io.BytesIO(data))
    if reader.is_encrypted:raise ValueError('encrypted PDFs are not unlocked by edit')
    # Editing invalidates cryptographic signatures; reject rather than claim preservation.
    for field in (reader.get_fields() or {}).values():
        if field.get('/FT')=='/Sig':raise ValueError('signed PDF editing is not qualified')
    operations=q['operations']
    if not 1<=len(operations)<=100:raise ValueError('PDF edit requires 1..100 operations')
    writer=PdfWriter(clone_from=reader)
    for item in operations:
        if item['type']=='delete':
            indexes=item['page_indexes']
            if not indexes or len(set(indexes))!=len(indexes) or any(not isinstance(i,int) or isinstance(i,bool) or i<0 or i>=len(writer.pages) for i in indexes):raise ValueError('invalid deletion page index')
            for i in sorted(indexes,reverse=True):writer.remove_page(i,clean=True)
        elif item['type']=='insert':
            at=item['page_index']
            if not isinstance(at,int) or isinstance(at,bool) or not 0<=at<=len(writer.pages):raise ValueError('invalid insertion page index')
            if bool(item.get('source_path'))==bool(item.get('markdown')):raise ValueError('insert requires exactly one source PDF or markdown text')
            if item.get('source_path'):
                content,part_sha=read_bytes(checked(q,item['source_path']))
                if part_sha!=item.get('source_sha256'):raise ValueError('inserted source PDF fingerprint changed')
            else:content=create_bytes('pdf',item['markdown'])
            part=PdfReader(io.BytesIO(content))
            if part.is_encrypted:raise ValueError('encrypted insert source')
            writer.merge(at,part)
        else:raise ValueError('unsupported PDF operation')
    if not len(writer.pages):raise ValueError('refusing empty PDF result')
    out=io.BytesIO();writer.write(out)
    result=publish(q,str(target),out.getvalue(),q['output_expected_sha256'])
    result.update({'source_path':str(source),'source_sha256':sha,'page_count':len(writer.pages),
                   'source_unchanged':read_bytes(source)[1]==sha,'page_deletion_is_secure_redaction':False})
    return [{'type':'text','text':json.dumps(result)}]


def edit_worksheet(q):
    import math
    import posixpath
    from lxml import etree
    from openpyxl.utils.cell import range_boundaries,get_column_letter
    path=checked(q,q['path']);data,sha=read_bytes(path)
    if path.suffix.lower() not in ('.xlsx','.xlsm') or sha!=q['expected_sha256']:
        raise ValueError('worksheet edit requires current XLSX/XLSM fingerprint')
    ns={'s':'http://schemas.openxmlformats.org/spreadsheetml/2006/main',
        'r':'http://schemas.openxmlformats.org/officeDocument/2006/relationships'}
    tag='{'+ns['s']+'}';parser=etree.XMLParser(resolve_entities=False,no_network=True)
    def parse(payload):
        if b'<!DOCTYPE' in payload or b'<!ENTITY' in payload:raise ValueError('XML declarations rejected')
        return etree.fromstring(payload,parser=parser)
    with safe_zip(data) as package:
        if any(n.startswith('_xmlsignatures/') for n in package.namelist()):raise ValueError('signed workbook edit not qualified')
        workbook=parse(package.read('xl/workbook.xml'));rels=parse(package.read('xl/_rels/workbook.xml.rels'))
        targets={n.get('Id'):n.get('Target') for n in rels if n.get('TargetMode')!='External'}
        sheets={n.get('name'):n.get('{'+ns['r']+'}id') for n in workbook.find('s:sheets',ns)}
        sheet=q.get('sheet') or next(iter(sheets))
        if sheet not in sheets and sheet.isdigit() and int(sheet)<len(sheets):sheet=list(sheets)[int(sheet)]
        if sheet not in sheets:raise ValueError('unknown worksheet')
        source=targets[sheets[sheet]];source=source.lstrip('/') if source.startswith('/') else posixpath.normpath('xl/'+source)
        if not source.startswith('xl/worksheets/') or '..' in source.split('/'):raise ValueError('unsupported worksheet relationship')
        tree=parse(package.read(source));body=tree.find('s:sheetData',ns)
        c1,r1,c2,r2=range_boundaries(q['range'])
        if not all(isinstance(v,int) and v>0 for v in (c1,r1,c2,r2)) or r1>r2 or c1>c2 or r2>1048576 or c2>16384 or (r2-r1+1)*(c2-c1+1)>5000:
            raise ValueError('invalid bounded worksheet range')
        values=q['values']
        if len(values)!=r2-r1+1 or any(not isinstance(row,list) or len(row)!=c2-c1+1 for row in values):raise ValueError('worksheet range and value dimensions differ')
        if tree.find('s:mergeCells',ns) is not None:raise ValueError('merged worksheet edits require separate merge-aware implementation')
        for f in tree.findall('.//s:f',ns):
            if f.get('t') not in (None,'normal'):raise ValueError('shared/array/data-table formula edit not qualified')
        for rr,row in enumerate(values,r1):
            node=body.find(f"s:row[@r='{rr}']",ns)
            if node is None:node=etree.SubElement(body,tag+'row',r=str(rr))
            for cc,value in enumerate(row,c1):
                coord=get_column_letter(cc)+str(rr);cell=node.find(f"s:c[@r='{coord}']",ns)
                if cell is None:cell=etree.SubElement(node,tag+'c',r=coord)
                for child in list(cell):
                    if child.tag in (tag+'f',tag+'v',tag+'is'):cell.remove(child)
                cell.attrib.pop('t',None)
                if isinstance(value,str):
                    if len(value)>32767:raise ValueError('Excel text cell too long')
                    if value.startswith('='):
                        if not value[1:]:raise ValueError('empty formula')
                        etree.SubElement(cell,tag+'f').text=value[1:]
                    else:
                        cell.set('t','inlineStr');text=etree.SubElement(etree.SubElement(cell,tag+'is'),tag+'t');text.text=value
                        text.set('{http://www.w3.org/XML/1998/namespace}space','preserve')
                elif isinstance(value,bool):cell.set('t','b');etree.SubElement(cell,tag+'v').text='1' if value else '0'
                elif isinstance(value,(int,float)):
                    if not math.isfinite(value):raise ValueError('nonfinite worksheet number')
                    etree.SubElement(cell,tag+'v').text=str(value)
                elif value is not None:raise ValueError('worksheet cells must be scalar values')
            cells=[x for x in node if x.tag==tag+'c'];others=[x for x in node if x.tag!=tag+'c']
            node[:]=sorted(cells,key=lambda x:range_boundaries(x.get('r')+':'+x.get('r'))[0])+others
        body[:]=sorted(body,key=lambda x:int(x.get('r')))
        dimension=tree.find('s:dimension',ns)
        if dimension is not None:tree.remove(dimension)
        replacements={source:etree.tostring(tree,encoding='UTF-8',xml_declaration=True)}
        # Any edit may invalidate dependent formula caches, even on another sheet.
        for name in package.namelist():
            if name.startswith('xl/worksheets/') and name.endswith('.xml'):
                candidate=parse(replacements.get(name,package.read(name)));changed=False
                for cell in candidate.findall('.//s:c',ns):
                    if cell.find('s:f',ns) is not None:
                        for cached in list(cell.findall('s:v',ns)):cell.remove(cached);changed=True
                if changed:replacements[name]=etree.tostring(candidate,encoding='UTF-8',xml_declaration=True)
        calc=workbook.find('s:calcPr',ns)
        if calc is None:calc=etree.SubElement(workbook,tag+'calcPr')
        calc.set('fullCalcOnLoad','1');calc.set('forceFullCalc','1');calc.set('calcMode','auto')
        replacements['xl/workbook.xml']=etree.tostring(workbook,encoding='UTF-8',xml_declaration=True)
        removed=set()
        for rel in list(rels):
            if rel.get('Type','').endswith('/calcChain'):
                target=rel.get('Target');removed.add(target.lstrip('/') if target.startswith('/') else posixpath.normpath('xl/'+target));rels.remove(rel)
        if removed:
            replacements['xl/_rels/workbook.xml.rels']=etree.tostring(rels,encoding='UTF-8',xml_declaration=True)
            types=parse(package.read('[Content_Types].xml'))
            for entry in list(types):
                if entry.get('PartName','').lstrip('/') in removed:types.remove(entry)
            replacements['[Content_Types].xml']=etree.tostring(types,encoding='UTF-8',xml_declaration=True)
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w') as writer:
            writer.comment=package.comment
            for info in package.infolist():
                if info.filename not in removed:writer.writestr(info,replacements.get(info.filename,package.read(info)))
    result=publish(q,str(path),out.getvalue(),sha)
    result.update({'sheet':sheet,'range':q['range'],'changed_parts':list(replacements),'removed_parts':sorted(removed),
                   'unselected_zip_payloads_preserved':True,'formulas_recalculated':False,'formula_caches_invalidated':True,
                   'recalculation_required':True})
    return [{'type':'text','text':json.dumps(result)}]

def main(q):
    if q.get('remote'):return remote_document(q)
    if q['op']=='pdf_edit':return edit_pdf(q)
    if q['op']=='worksheet_edit':return edit_worksheet(q)
    if q['op'] in ('read','image_read'):return read_document(q)
    if q['op']=='write':
        path=checked(q,q['path']);kind=q['format']
        if path.suffix.lower()!='.'+kind:raise ValueError('format must match extension')
        result=publish(q,str(path),create_bytes(kind,q['content']),q.get('expected_sha256'));result['formulas_recalculated']=False
        return [{'type':'text','text':json.dumps(result)}]
    if q['op']=='edit_docx':return edit_docx(q)
    raise ValueError('unsupported document operation')


if __name__=='__main__':
    try:
        resource.setrlimit(resource.RLIMIT_AS,(1024*1024*1024,1024*1024*1024))
        resource.setrlimit(resource.RLIMIT_CPU,(30,30))
        resource.setrlimit(resource.RLIMIT_FSIZE,(64*1024*1024,64*1024*1024))
        q=json.load(sys.stdin);result=main(q)
        payload=json.dumps(result,ensure_ascii=True)
        if len(payload.encode())>2*1024*1024:raise ValueError('document response exceeds budget')
        print(payload)
    except Exception as error:
        print(type(error).__name__+': '+str(error),file=sys.stderr);raise SystemExit(1)
