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
        book=load_workbook(io.BytesIO(data),read_only=True,data_only=False,keep_links=False)
        try:
            name=q.get('sheet') or book.sheetnames[0]
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


def main(q):
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
