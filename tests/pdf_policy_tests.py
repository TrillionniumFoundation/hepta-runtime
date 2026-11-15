#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Synthetic real certification signatures and allowed/forbidden incremental edits.
No real signing identity, key, or user document is opened by these tests.
"""
import datetime
import hashlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('policy_documents',ROOT/'src/mcp/runtime/document_local.py');D=importlib.util.module_from_spec(spec);spec.loader.exec_module(D)
exec(compile((ROOT/'src/mcp/runtime/pdf_security.py').read_text(),'pdf_security.py','exec'),D.__dict__)


def certified_fixture(permission=2,locked=False):
    from reportlab.pdfgen import canvas
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from asn1crypto import x509 as ax509, keys
    from pyhanko_certvalidator.registry import SimpleCertificateStore
    from pyhanko.sign import signers,fields
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    page=io.BytesIO();c=canvas.Canvas(page,pagesize=(420,300));c.drawString(36,255,'Hepta certified form fixture')
    c.drawString(36,216,'Editable');c.acroForm.textfield(name='Editable',value='Before',x=130,y=200,width=220,height=25,fontName='Helvetica',fontSize=12)
    c.drawString(36,156,'Locked');c.acroForm.textfield(name='Locked',value='Keep',x=130,y=140,width=220,height=25,fontName='Helvetica',fontSize=12)
    c.showPage();c.save()
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048);name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Hepta disposable policy signer')]);now=datetime.datetime.now(datetime.timezone.utc)
    cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=5)).not_valid_after(now+datetime.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True).sign(key,hashes.SHA256())
    signer=signers.SimpleSigner(signing_cert=ax509.Certificate.load(cert.public_bytes(serialization.Encoding.DER)),signing_key=keys.PrivateKeyInfo.load(key.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())),cert_registry=SimpleCertificateStore())
    field_lock=fields.FieldMDPSpec(action=fields.FieldMDPAction.INCLUDE,fields=['Locked']) if locked else None
    signature=signers.PdfSigner(signers.PdfSignatureMetadata(field_name='Certifier',certify=True,docmdp_permissions=fields.MDPPerm(permission)),signer=signer,new_field_spec=fields.SigFieldSpec(sig_field_name='Certifier',field_mdp_spec=field_lock))
    output=io.BytesIO();signature.sign_pdf(IncrementalPdfFileWriter(io.BytesIO(page.getvalue())),output=output)
    return output.getvalue(),cert.public_bytes(serialization.Encoding.PEM)


class PdfPolicy(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='hepta-policy-test-');self.root=pathlib.Path(self.temp.name).resolve()
        self.source=self.root/'certified.pdf';self.trust=self.root/'trust.pem';self.output=self.root/'filled.pdf'
        data,cert=certified_fixture();self.source.write_bytes(data);self.trust.write_bytes(cert)
    def tearDown(self):self.temp.cleanup()
    def call(self,action='validate_policy',**extra):
        q={'action':action,'path':str(self.source),'expected_sha256':hashlib.sha256(self.source.read_bytes()).hexdigest(),
           'roots':[str(self.root)],'trust_store_file':str(self.trust),'trust_store_sha256':hashlib.sha256(self.trust.read_bytes()).hexdigest(),
           'output_path':str(self.output),'output_expected_sha256':'absent','form_values':{'Editable':'After'},'allow_unsigned_revision':True,**extra}
        return json.loads(D.pdf_secure(q)[0]['text'])
    def test_intact_certified_policy_is_independent_of_signature_integrity(self):
        info=self.call();self.assertTrue(info['all_present_signature_policies_pass'],info);self.assertTrue(info['certification_policy_evaluated'])
        policy=info['signature_policies'][0];self.assertEqual(policy['docmdp_permission'],2);self.assertTrue(policy['certificate_chain_valid'])
        self.assertFalse(info['revocation_evaluated']);self.assertFalse(info['trusted_signing_time_evaluated'])
    def test_form_fill_preserves_signed_prefix_and_validates_allowed_revision(self):
        from pypdf import PdfReader
        original=self.source.read_bytes();result=self.call('fill_form_copy')
        self.assertTrue(result['original_bytes_are_prefix']);self.assertFalse(result['new_revision_is_signed'])
        self.assertEqual(original,self.source.read_bytes());self.assertTrue(self.output.read_bytes().startswith(original))
        self.assertEqual(PdfReader(self.output).get_form_text_fields(),{'Editable':'After','Locked':'Keep'})
        policy=result['output_policy'];self.assertTrue(policy['all_present_signature_policies_pass'],policy)
        self.assertEqual(policy['signature_policies'][0]['modification_level'],'FORM_FILLING')
        self.assertFalse(result['output_signatures']['current_revision_fully_signed'])
    def test_no_changes_certification_refuses_form_fill(self):
        data,cert=certified_fixture(permission=1);self.source.write_bytes(data);self.trust.write_bytes(cert)
        with self.assertRaisesRegex(ValueError,'permission'):self.call('fill_form_copy')
        self.assertFalse(self.output.exists());self.assertEqual(self.source.read_bytes(),data)
    def test_field_lock_refuses_locked_value_but_allows_unlocked_value(self):
        data,cert=certified_fixture(locked=True);self.source.write_bytes(data);self.trust.write_bytes(cert)
        with self.assertRaisesRegex(ValueError,'FieldMDP'):self.call('fill_form_copy',form_values={'Locked':'Tampered'})
        self.assertFalse(self.output.exists());self.assertEqual(self.source.read_bytes(),data)
        result=self.call('fill_form_copy');self.assertTrue(result['output_policy']['field_lock_policy_evaluated'])
    def test_forbidden_page_change_leaves_old_cms_intact_but_policy_fails(self):
        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
        from pyhanko.pdf_utils import generic
        writer=IncrementalPdfFileWriter(io.BytesIO(self.source.read_bytes()));page_ref,_=writer.find_page_for_modification(0);page=page_ref.get_object()
        page[generic.pdf_name('/MediaBox')]=generic.ArrayObject([generic.NumberObject(v) for v in [0,0,600,900]]);writer.mark_update(page_ref)
        output=io.BytesIO();writer.write(output);self.source.write_bytes(output.getvalue())
        result=self.call();self.assertEqual(result['signature_integrity']['signatures'][0]['integrity'],'valid')
        self.assertFalse(result['all_present_signature_policies_pass']);self.assertFalse(result['signature_policies'][0]['modifications_permitted'])
    def test_wrong_anchor_refuses_publication(self):
        _,cert=certified_fixture();self.trust.write_bytes(cert)
        with self.assertRaisesRegex(ValueError,'trusted'):self.call('fill_form_copy')
        self.assertFalse(self.output.exists())
    def test_unsigned_source_never_reported_certified(self):
        self.source.write_bytes(D.create_bytes('pdf','# Unsigned'))
        info=self.call();self.assertFalse(info['certification_policy_evaluated']);self.assertFalse(info['all_present_signature_policies_pass'])
    def test_bad_requests_leave_original_and_destination_unchanged(self):
        before=self.source.read_bytes()
        for extra in ({'expected_sha256':'0'*64},{'form_values':{'Missing':'No'}},{'form_values':{'Editable':'line\nbreak'}},{'allow_unsigned_revision':False}):
            with self.assertRaises(ValueError):self.call('fill_form_copy',**extra)
            self.assertFalse(self.output.exists());self.assertEqual(self.source.read_bytes(),before)
        self.output.write_bytes(b'KEEP')
        with self.assertRaises(ValueError):self.call('fill_form_copy')
        self.assertEqual(self.output.read_bytes(),b'KEEP')

    def test_in_place_appearance_stream_updates_are_rejected(self):
        from pypdf import PdfReader,PdfWriter
        original=self.source.read_bytes();writer=PdfWriter(PdfReader(io.BytesIO(original)),incremental=True)
        writer.update_page_form_field_values(list(writer.pages),{'Editable':'No in-place stream'},auto_regenerate=None)
        out=io.BytesIO();writer.write(out);self.source.write_bytes(out.getvalue())
        result=self.call()
        self.assertFalse(result['in_place_appearance_rewrites_allowed'])
        self.assertFalse(result['all_present_signature_policies_pass'])
        self.assertEqual(result['signature_integrity']['signatures'][0]['integrity'],'valid')

    def test_unqualified_glyphs_are_not_silently_published_as_blank_appearances(self):
        original=self.source.read_bytes()
        with self.assertRaisesRegex(ValueError,'glyph coverage'):self.call('fill_form_copy',form_values={'Editable':'中文'})
        self.assertEqual(self.source.read_bytes(),original);self.assertFalse(self.output.exists())



if __name__=='__main__':unittest.main(verbosity=2)
