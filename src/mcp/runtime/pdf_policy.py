# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Offline DocMDP/FieldMDP revision analysis and verified form-only derived copies.
Cryptographic byte/anchor checks remain independent of the difference-analysis
engine. Never imports a signing key, fetches a certificate, or signs new content.
"""
import hashlib
import io
import json
import logging


def pdf_modification_policy(data,q,signature_info):
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.diff_analysis import DEFAULT_DIFF_POLICY, StandardDiffPolicy, FormUpdatingRule, SigFieldCreationRule, SigFieldModificationRule, GenericFieldModificationRule
    import importlib.metadata
    engine_version=importlib.metadata.version('pyhanko')
    # Tighten the upstream contract: existing appearance streams may not be
    # overwritten. New appearances must be new references. This also avoids an
    # upstream 0.37.0 false positive on appearances last changed before signing.
    strict_policy=StandardDiffPolicy(global_rules=list(DEFAULT_DIFF_POLICY.global_rules),
        form_rule=FormUpdatingRule(field_rules=[SigFieldCreationRule(),
            SigFieldModificationRule(allow_in_place_appearance_stream_changes=False),
            GenericFieldModificationRule(allow_in_place_appearance_stream_changes=False)]))
    result={'policy_engine':'pyhanko','policy_engine_version':engine_version,'network_validation_performed':False,'in_place_appearance_rewrites_allowed':False,
            'certification_policy_evaluated':False,'field_lock_policy_evaluated':False,
            'revocation_evaluated':False,'trusted_signing_time_evaluated':False,'signature_policies':[]}
    # Diagnostic exception text can contain document content. Results expose only
    # bounded status/type data; the original worker keeps its existing CPU limits.
    logger=logging.getLogger('pyhanko');old_level=logger.level;logger.setLevel(logging.CRITICAL)
    try:
        reader=PdfFileReader(io.BytesIO(data),strict=True)
        if reader.encrypted:
            secret=pdf_password(q,'password_file')
            if secret is None:raise ValueError('private password file required')
            authentication=reader.decrypt(secret)
            if not authentication.status:raise ValueError('PDF password authentication failed')
        signatures=reader.embedded_regular_signatures
        if len(signatures)>20:raise ValueError('policy signature budget exceeded')
        baseline={tuple(v.get('byte_range',())):v for v in signature_info['signatures']}
        for embedded in signatures:
            entry={'field_name':embedded.field_name,'policy_evaluated':False,'modifications_permitted':None}
            try:
                ranges=list(embedded.sig_object['/ByteRange']);old=baseline.get(tuple(ranges))
                if old is None:raise ValueError('signature parser byte-range disagreement')
                permission=embedded.docmdp_level
                entry['docmdp_permission']=permission.value if permission is not None else None
                entry['field_lock_present']=embedded.fieldmdp is not None
                embedded.compute_integrity_info(diff_policy=strict_policy)
                summary=embedded.summarise_integrity_info()
                diff=summary.get('diff_result');coverage=summary.get('coverage')
                entry.update(byte_range=ranges,coverage=coverage.name if coverage is not None else 'UNKNOWN',
                             policy_evaluated=True,modifications_permitted=summary.get('docmdp_ok'),
                             byte_integrity_valid=old.get('integrity')=='valid',
                             changed_form_fields=sorted(getattr(diff,'changed_form_fields',set()))[:100],
                             modification_level=getattr(getattr(diff,'modification_level',None),'name','UNKNOWN'),
                             certificate_trust_evaluated=old.get('certificate_trust_evaluated',False),
                             certificate_chain_valid=old.get('certificate_chain_valid'))
            except Exception as error:
                entry.update(policy_evaluated=False,modifications_permitted=None,analysis_error_type=type(error).__name__)
            result['signature_policies'].append(entry)
        entries=result['signature_policies']
        result['signature_parser_counts_match']=len(entries)==signature_info['signature_count']
        result['certification_policy_evaluated']=any(e.get('docmdp_permission') is not None and e['policy_evaluated'] for e in entries)
        result['field_lock_policy_evaluated']=any(e.get('field_lock_present') and e['policy_evaluated'] for e in entries)
        result['all_present_signature_policies_pass']=bool(entries) and result['signature_parser_counts_match'] and all(e['policy_evaluated'] and e.get('byte_integrity_valid') and e['modifications_permitted'] is True for e in entries)
    except Exception as error:
        result.update(analysis_error_type=type(error).__name__,all_present_signature_policies_pass=False,signature_parser_counts_match=False)
    finally:logger.setLevel(old_level)
    return result


def pdf_policy_operation(q,data,reader,source,source_sha,signatures,trust):
    from pypdf import PdfReader,PdfWriter
    policy=pdf_modification_policy(data,q,signatures)
    if q['action']=='validate_policy':
        return [{'type':'text','text':json.dumps({'path':str(source),'sha256':source_sha,'encrypted':reader.is_encrypted,
                    'signature_integrity':signatures,**policy})}]
    if q['action']!='fill_form_copy':raise ValueError('unknown policy action')
    if reader.is_encrypted:raise ValueError('certified encrypted-form editing is not qualified; inspect or owner-authorized derived decryption first')
    if not q.get('allow_unsigned_revision'):raise ValueError('explicit allow_unsigned_revision is required for filled revision')
    if trust is None:raise ValueError('form filling requires explicit SHA256-pinned certificate anchors')
    if not policy['all_present_signature_policies_pass']:raise ValueError('source signature or modification policy did not validate')
    entries=policy['signature_policies']
    if not any(e.get('docmdp_permission') in (2,3) for e in entries) or any(e.get('docmdp_permission')==1 for e in entries):
        raise ValueError('certification permission does not admit form filling')
    if not all(e.get('certificate_chain_valid') is True for e in entries):raise ValueError('source signer is not trusted by the supplied anchors')
    fields=q.get('form_values') or {}
    if not 1<=len(fields)<=32 or any(not isinstance(k,str) or not isinstance(v,str) or len(k)>256 or len(v)>2048 for k,v in fields.items()):
        raise ValueError('bounded text-field values required')
    if any(any(not 32<=ord(char)<=126 for char in value) for value in fields.values()):
        raise ValueError('this appearance-writing contract requires printable ASCII; additional font glyph coverage is not yet qualified')
    acro=reader.trailer['/Root'].get('/AcroForm')
    if not acro or '/XFA' in acro.get_object():raise ValueError('ordinary AcroForm required; XFA is not supported')
    available=reader.get_fields() or {}
    for key,value in fields.items():
        field=available.get(key)
        if field is None or field.get('/FT')!='/Tx':raise ValueError('requested field is missing or not a text field')
        flags=int(field.get('/Ff',0))
        if flags & (1|4096|8192|1048576|33554432):raise ValueError('read-only/multiline/password/file-select/rich-text field requires separate support')
        if len(value)>int(field.get('/MaxLen',2048)):raise ValueError('text exceeds the field MaxLen')
        if '/AA' in field or '/A' in field:raise ValueError('active form actions are not executed')
    target=checked(q,q['output_path'])
    if target==source or target.suffix.lower()!='.pdf':raise ValueError('distinct PDF output required')
    # Use pypdf only to build appearance content privately. Publish with the
    # explicit incremental writer so unrelated streams/dictionaries stay untouched.
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.pdf_utils import generic
    selected=[]
    for page in reader.pages:
        for reference in page.get('/Annots',[]):
            widget=reference.get_object();name=widget.get('/T')
            if name not in fields:continue
            if '/Parent' in widget or widget.get('/Subtype')!='/Widget' or widget.get('/FT')!='/Tx' or not hasattr(reference,'idnum'):
                raise ValueError('only direct single-widget text fields are admitted')
            selected.append((str(name),reference.idnum,reference.generation))
    if len(selected)!=len(fields) or {name for name,_,_ in selected}!=set(fields):
        raise ValueError('missing, duplicate or hierarchical field widget requires separate support')
    writer=PdfWriter(reader,incremental=True)
    writer.update_page_form_field_values(list(writer.pages),fields,auto_regenerate=None)
    draft=io.BytesIO();writer.write(draft);draft_reader=PdfFileReader(io.BytesIO(draft.getvalue()))
    publication_writer=IncrementalPdfFileWriter(io.BytesIO(data))
    for name,number,generation in selected:
        ref=generic.Reference(number,generation,publication_writer)
        original_widget=publication_writer.get_object(ref)
        generated_widget=draft_reader.get_object(generic.Reference(number,generation,draft_reader))
        appearance=publication_writer.import_object(generated_widget['/AP']['/N'])
        old_ap=original_widget.get('/AP')
        new_ap=generic.DictionaryObject(dict(old_ap.get_object()) if old_ap else {})
        new_ap[generic.pdf_name('/N')]=publication_writer.add_object(appearance)
        original_widget[generic.pdf_name('/V')]=generic.TextStringObject(fields[name])
        original_widget[generic.pdf_name('/AP')]=new_ap
        publication_writer.mark_update(ref)
    buffer=io.BytesIO();publication_writer.write(buffer);output=buffer.getvalue()
    if not output.startswith(data):raise ValueError('form fill did not retain the exact original signed prefix')
    after_reader=PdfReader(io.BytesIO(output));after=pdf_signature_info(output,after_reader,trust)
    after_policy=pdf_modification_policy(output,q,after)
    if not after_policy['all_present_signature_policies_pass']:raise ValueError('derived form revision failed DocMDP/FieldMDP analysis; no output published')
    if len(after['signatures'])!=len(signatures['signatures']):raise ValueError('signature count changed')
    for prior,current in zip(signatures['signatures'],after['signatures']):
        if prior.get('signed_bytes_sha256')!=current.get('signed_bytes_sha256') or current.get('integrity')!='valid' or current.get('certificate_chain_valid') is not True:
            raise ValueError('original signature integrity/trust changed')
    changed=set().union(*(set(e.get('changed_form_fields',[])) for e in after_policy['signature_policies']))
    if not changed<=set(fields):raise ValueError('unrequested form field changed')
    actual=after_reader.get_form_text_fields()
    if any(actual.get(k)!=v for k,v in fields.items()):raise ValueError('form value roundtrip differs')
    if read_bytes(source)[1]!=source_sha:raise ValueError('source changed before form publication')
    publication=publish(q,str(target),output,q['output_expected_sha256'])
    publication.update(action='fill_form_copy',source_path=str(source),source_sha256=source_sha,
                       source_unchanged=read_bytes(source)[1]==source_sha,original_bytes_are_prefix=True,
                       changed_form_field_names=sorted(fields),new_revision_is_signed=False,
                       source_policy=policy,output_policy=after_policy,output_signatures=after)
    return [{'type':'text','text':json.dumps(publication)}]
