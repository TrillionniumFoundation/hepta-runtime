# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Password-file PDF access and byte-preserving signed-revision operations.
Passwords are private files, never command arguments, audit values or results.
CMS verification checks cryptographic integrity, not certificate trust or DocMDP.
"""
import hashlib
import io
import json
import os
import pathlib
import stat
import subprocess
import tempfile


def pdf_password(q, key):
    path=q.get(key)
    if not path:return None
    source=checked(q,path);fd,name=parent_fd(source)
    try:
        f=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
        with os.fdopen(f,'rb') as stream:
            st=os.fstat(stream.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077 or st.st_nlink!=1:
                raise PermissionError('PDF password file must be private, singly linked and owned by the parser account')
            data=stream.read(4097)
            if len(data)>4096:raise ValueError('PDF password file too large')
            try:return data.decode('utf-8').removesuffix('\n').removesuffix('\r')
            except UnicodeError:raise ValueError('PDF password file must be UTF-8') from None
    finally:os.close(fd)


def pdf_open(q,data,owner_required=False):
    from pypdf import PdfReader
    from pypdf._encryption import PasswordType
    reader=PdfReader(io.BytesIO(data));method=0
    if reader.is_encrypted:
        password=pdf_password(q,'password_file')
        if password is None:raise ValueError('encrypted PDF requires a private password_file')
        try:method=reader.decrypt(password)
        except Exception:raise ValueError('PDF password authentication failed') from None
        if not method:raise ValueError('PDF password authentication failed')
        if owner_required and method!=PasswordType.OWNER_PASSWORD:
            raise PermissionError('PDF owner password required for protection changes')
    return reader


def pdf_signature_info(data,reader):
    from pypdf.generic import IndirectObject
    found=[];seen=set()
    fields=(reader.get_fields() or {}).values()
    for field in fields:
        if field.get('/FT')!='/Sig' or not field.get('/V'):continue
        value=field['/V'].get_object()
        ident=getattr(value,'indirect_reference',None)
        ident=(ident.idnum,ident.generation) if isinstance(ident,IndirectObject) else id(value)
        if ident in seen:continue
        seen.add(ident)
        if len(found)>=20:raise ValueError('PDF signature budget exceeded')
        ranges=value.get('/ByteRange');contents=value.get('/Contents')
        info={'subfilter':str(value.get('/SubFilter','')),'certificate_trust_evaluated':False,'certification_policy_evaluated':False}
        if not ranges or len(ranges)!=4 or any(not isinstance(n,int) or isinstance(n,bool) for n in ranges):
            info['integrity']='invalid_byte_range';found.append(info);continue
        start,length,tail,count=map(int,ranges)
        if start!=0 or length<=0 or tail<=length or count<=0 or tail+count>len(data):
            info['integrity']='invalid_byte_range';found.append(info);continue
        try:signature=contents.original_bytes if hasattr(contents,'original_bytes') else bytes(contents)
        except (TypeError,ValueError):info['integrity']='invalid_contents';found.append(info);continue
        gap=data[length:tail]
        try:
            if not gap.startswith(b'<') or not gap.endswith(b'>'):raise ValueError()
            decoded=bytes.fromhex(gap[1:-1].decode('ascii'))
            if decoded!=signature:raise ValueError()
        except (ValueError,UnicodeError):
            info['integrity']='unsupported_or_mismatched_signature_gap';found.append(info);continue
        info.update(byte_range=list(ranges),signed_revision_size=tail+count,covers_current_file=tail+count==len(data),signed_bytes_sha256=hashlib.sha256(data[:length]+data[tail:tail+count]).hexdigest())
        if info['subfilter'] not in ('/adbe.pkcs7.detached','/ETSI.CAdES.detached'):
            info['integrity']='unsupported_subfilter';found.append(info);continue
        try:
            if len(signature)<2 or signature[0]!=0x30:raise ValueError()
            n=signature[1]
            if n&0x80:
                octets=n&0x7f
                if not 1<=octets<=4 or len(signature)<2+octets:raise ValueError()
                size=2+octets+int.from_bytes(signature[2:2+octets],'big')
            else:size=2+n
            if size>len(signature):raise ValueError()
            with tempfile.TemporaryDirectory(prefix='hepta-pdf-cms-') as directory:
                root=pathlib.Path(directory);cms=root/'signature.der';signed=root/'signed.bin'
                cms.write_bytes(signature[:size]);signed.write_bytes(data[:length]+data[tail:tail+count]);cms.chmod(0o600);signed.chmod(0o600)
                result=subprocess.run(['/usr/bin/openssl','cms','-verify','-binary','-inform','DER','-in',str(cms),'-content',str(signed),'-noverify','-out',os.devnull],capture_output=True,timeout=10)
            info['integrity']='valid' if result.returncode==0 else 'invalid'
        except (OSError,ValueError,subprocess.TimeoutExpired):info['integrity']='verification_unavailable'
        found.append(info)
    return {'signature_count':len(found),'signatures':found,'certificate_trust_evaluated':False,'current_revision_fully_signed':bool(found) and any(v.get('integrity')=='valid' and v.get('covers_current_file') for v in found)}


def pdf_secure(q):
    from pypdf import PdfReader,PdfWriter
    source=checked(q,q['path']);data,sha=read_bytes(source)
    if sha!=q['expected_sha256']:raise ValueError('PDF source fingerprint changed')
    action=q['action'];reader=pdf_open(q,data,owner_required=action in ('encrypt_copy','decrypt_copy'))
    signatures=pdf_signature_info(data,reader)
    metadata={'path':str(source),'sha256':sha,'size':len(data),'encrypted':reader.is_encrypted,'page_count':len(reader.pages),**signatures}
    if action=='inspect':return [{'type':'text','text':json.dumps(metadata)}]
    target=checked(q,q['output_path'])
    if target==source or target.suffix.lower()!='.pdf':raise ValueError('PDF security operation requires a distinct PDF output')
    if action=='append_metadata':
        if not q.get('allow_unsigned_revision'):raise ValueError('explicit allow_unsigned_revision required; changed content is not signed by the old signature')
        if reader.is_encrypted:raise ValueError('incremental metadata on encrypted PDFs is not yet supported')
        if reader.trailer['/Root'].get('/Perms'):
            raise ValueError('certified PDF modification requires explicit certification-policy validation')
        writer=PdfWriter(reader,incremental=True)
        title=q.get('title')
        if not isinstance(title,str) or not title or len(title)>2048:raise ValueError('bounded title is required')
        writer.add_metadata({'/Title':title})
    elif action in ('encrypt_copy','decrypt_copy'):
        if signatures['signature_count']:raise ValueError('encryption rewrite of a signed PDF would invalidate signatures; use inspect or an explicit incremental revision')
        if action=='decrypt_copy' and not reader.is_encrypted:raise ValueError('source is not encrypted')
        writer=PdfWriter(clone_from=reader)
        if action=='encrypt_copy':
            user=pdf_password(q,'output_user_password_file');owner=pdf_password(q,'output_owner_password_file')
            if user is None or owner is None or not owner:raise ValueError('explicit output user and nonempty owner password files required')
            writer.encrypt(user,owner,algorithm='AES-256')
    else:raise ValueError('unknown PDF security operation')
    buffer=io.BytesIO();writer.write(buffer);output=buffer.getvalue()
    if action=='append_metadata':
        if not output.startswith(data):raise ValueError('incremental write changed original signed bytes')
        after=pdf_signature_info(output,PdfReader(io.BytesIO(output)))
        if len(after['signatures'])!=len(signatures['signatures']):raise ValueError('signature fields changed')
        for before,now in zip(signatures['signatures'],after['signatures']):
            if before.get('signed_bytes_sha256')!=now.get('signed_bytes_sha256') or before['integrity']!=now['integrity']:
                raise ValueError('original signature integrity changed')
    else:after={'signature_count':0,'current_revision_fully_signed':False}
    if read_bytes(source)[1]!=sha:raise ValueError('source changed before derived PDF publication')
    result=publish(q,str(target),output,q['output_expected_sha256'])
    result.update({'action':action,'source_path':str(source),'source_sha256':sha,'source_unchanged':read_bytes(source)[1]==sha,'output_encrypted':action=='encrypt_copy','original_bytes_are_prefix':action=='append_metadata','new_revision_is_signed':False,'certificate_trust_evaluated':False,'certification_policy_evaluated':False,'source_signatures':signatures,'output_signatures':after})
    return [{'type':'text','text':json.dumps(result)}]


def remote_pdf_secure(q):
    import base64
    with tempfile.TemporaryDirectory(prefix='hepta-remote-pdf-secure-') as directory:
        root=pathlib.Path(directory);source=root/'source.pdf'
        data,_,_=remote_fetch(q,q['path'],q['expected_sha256']);source.write_bytes(data);source.chmod(0o600)
        request={k:v for k,v in q.items() if k not in ('host','remote','file_helper')}
        request.update(path=str(source),roots=[str(root)])
        for key in ('password_file','output_user_password_file','output_owner_password_file'):
            if q.get(key):
                result=remote_call(q,'private_read',q[key])
                if result.get('private_file_verified') is not True:raise ValueError('remote private file not verified')
                secret=root/key;secret.write_bytes(base64.b64decode(result['data_base64'],validate=True));secret.chmod(0o600)
                request[key]=str(secret)
        write=q['action']!='inspect';prior='absent';output=root/'output.pdf'
        if write:
            request['output_path']=str(output)
            if q['output_expected_sha256']!='absent':
                previous,prior,_=remote_fetch(q,q['output_path'],q['output_expected_sha256']);output.write_bytes(previous);output.chmod(0o600)
        blocks=pdf_secure(request);info=json.loads(blocks[0]['text'])
        if write:
            publication=remote_publish(q,q['output_path'],output.read_bytes(),prior)
            info.update(path=q['output_path'],source_path=q['path'],publication_version=publication['version'])
        else:info['path']=q['path']
        info.update(host=q['host'],transport='native_remote_file_transfer')
        blocks[0]['text']=json.dumps(info)
        return blocks
