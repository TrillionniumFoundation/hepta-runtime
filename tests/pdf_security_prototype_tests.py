#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Isolated fixtures for the native PDF protection and signature-integrity worker.
Synthetic self-signed certificates test integrity only, never public trust.
"""
import datetime
import hashlib
import importlib.util
import io
import json
import pathlib
import re
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('security_document',ROOT/'src/mcp/runtime/document_local.py');D=importlib.util.module_from_spec(s);s.loader.exec_module(D)
exec(compile((ROOT/'src/mcp/runtime/pdf_security.py').read_text(),'pdf_security.py','exec'),D.__dict__)


def signed_fixture(data,certificate_output=None):
    from pypdf import PdfReader,PdfWriter
    from pypdf.generic import DictionaryObject,NameObject,ArrayObject,NumberObject,ByteStringObject,TextStringObject
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs7
    writer=PdfWriter(clone_from=PdfReader(io.BytesIO(data)));writer.add_metadata({'/Title':'FixtureOriginal'})
    signature=DictionaryObject({NameObject('/Type'):NameObject('/Sig'),NameObject('/Filter'):NameObject('/Adobe.PPKLite'),NameObject('/SubFilter'):NameObject('/adbe.pkcs7.detached'),NameObject('/ByteRange'):ArrayObject([NumberObject(0),NumberObject(1111111111),NumberObject(2222222222),NumberObject(3333333333)]),NameObject('/Contents'):ByteStringObject(b'\0'*8192)})
    field=DictionaryObject({NameObject('/FT'):NameObject('/Sig'),NameObject('/T'):TextStringObject('SyntheticFixture'),NameObject('/V'):writer._add_object(signature)})
    writer._root_object[NameObject('/AcroForm')]=writer._add_object(DictionaryObject({NameObject('/Fields'):ArrayObject([writer._add_object(field)])}))
    out=io.BytesIO();writer.write(out);raw=out.getvalue();match=re.search(rb'/Contents\s*(<0{16384}>)',raw);assert match
    start,end=match.span(1);ranges=[0,start,end,len(raw)-end]
    raw=raw.replace(b'1111111111',f'{start:010d}'.encode()).replace(b'2222222222',f'{end:010d}'.encode()).replace(b'3333333333',f'{len(raw)-end:010d}'.encode())
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048);name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Hepta disposable test signer')]);now=datetime.datetime.now(datetime.timezone.utc)
    cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(days=1)).sign(key,hashes.SHA256())
    if certificate_output is not None:certificate_output.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    cms=pkcs7.PKCS7SignatureBuilder().set_data(raw[:start]+raw[end:]).add_signer(cert,key,hashes.SHA256()).sign(serialization.Encoding.DER,[pkcs7.PKCS7Options.DetachedSignature,pkcs7.PKCS7Options.Binary])
    encoded=cms.hex().encode();assert len(encoded)<=16384
    return raw[:start+1]+encoded.ljust(16384,b'0')+raw[end-1:]


class PdfSecurityPrototype(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='hepta-pdf-security-');self.root=pathlib.Path(self.temp.name).resolve();self.source=self.root/'source.pdf';self.source.write_bytes(D.create_bytes('pdf','# Original\nHello 中文'))
    def tearDown(self):self.temp.cleanup()
    def secret(self,name,value):
        p=self.root/name;p.write_text(value);p.chmod(0o600);return str(p)
    def call(self,action,source=None,**params):
        path=source or self.source
        q={'action':action,'path':str(path),'expected_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'roots':[str(self.root)],'output_path':str(self.root/'output.pdf'),'output_expected_sha256':'absent',**params}
        return json.loads(D.pdf_secure(q)[0]['text'])
    def test_real_cms_signature_integrity_and_unsigned_append_are_distinct(self):
        self.source.write_bytes(signed_fixture(self.source.read_bytes()));original=self.source.read_bytes()
        info=self.call('inspect');self.assertEqual(info['signature_count'],1);self.assertEqual(info['signatures'][0]['integrity'],'valid');self.assertTrue(info['current_revision_fully_signed']);self.assertFalse(info['certificate_trust_evaluated'])
        changed=self.call('append_metadata',allow_unsigned_revision=True,title='New revision')
        self.assertTrue(changed['original_bytes_are_prefix']);self.assertFalse(changed['new_revision_is_signed']);self.assertEqual(changed['output_signatures']['signatures'][0]['integrity'],'valid');self.assertFalse(changed['output_signatures']['current_revision_fully_signed'])
        self.assertEqual(self.source.read_bytes(),original);self.assertTrue((self.root/'output.pdf').read_bytes().startswith(original))
    def test_signature_tampering_is_not_reported_valid(self):
        raw=signed_fixture(self.source.read_bytes());self.assertIn(b'FixtureOriginal',raw)
        self.source.write_bytes(raw.replace(b'FixtureOriginal',b'FixtureTampered'))
        result=self.call('inspect');self.assertEqual(result['signatures'][0]['integrity'],'invalid')
    def test_explicit_revision_acknowledgement_required(self):
        with self.assertRaisesRegex(ValueError,'allow_unsigned_revision'):self.call('append_metadata',title='No')
        self.assertFalse((self.root/'output.pdf').exists())
    def test_aes256_owner_authenticated_decryption_preserves_source(self):
        from pypdf import PdfReader
        user=self.secret('user.txt','fixture-user-password');owner=self.secret('owner.txt','fixture-owner-password')
        result=self.call('encrypt_copy',output_user_password_file=user,output_owner_password_file=owner);encrypted=self.root/'output.pdf';raw=encrypted.read_bytes();self.assertTrue(result['output_encrypted'])
        pdf=PdfReader(io.BytesIO(raw));self.assertTrue(pdf.is_encrypted);self.assertEqual(pdf.decrypt('fixture-user-password'),1)
        info=self.call('inspect',source=encrypted,password_file=user);self.assertTrue(info['encrypted'])
        with self.assertRaises(PermissionError):self.call('decrypt_copy',source=encrypted,password_file=user,output_path=str(self.root/'denied.pdf'))
        result=self.call('decrypt_copy',source=encrypted,password_file=owner,output_path=str(self.root/'clear.pdf'))
        self.assertTrue(result['source_unchanged']);self.assertEqual(raw,encrypted.read_bytes());self.assertFalse(PdfReader(str(self.root/'clear.pdf')).is_encrypted)
        self.assertIn('Original',PdfReader(str(self.root/'clear.pdf')).pages[0].extract_text())
        self.assertNotIn('fixture-owner-password',json.dumps(result));self.assertNotIn('fixture-user-password',json.dumps(result))
    def test_private_password_file_and_wrong_password_errors_do_not_expose_secret(self):
        p=self.secret('secret.txt','fixture-private-secret');path=pathlib.Path(p);path.chmod(0o644)
        with self.assertRaises(PermissionError):self.call('encrypt_copy',output_user_password_file=p,output_owner_password_file=p)
        self.assertFalse((self.root/'output.pdf').exists());path.chmod(0o600)
        self.call('encrypt_copy',output_user_password_file=p,output_owner_password_file=p)
        wrong=self.secret('wrong.txt','must-not-appear-in-error')
        with self.assertRaises(ValueError) as err:self.call('inspect',source=self.root/'output.pdf',password_file=wrong)
        self.assertNotIn('must-not-appear-in-error',str(err.exception))
    def test_create_only_output_and_source_fingerprint_fail_closed(self):
        target=self.root/'output.pdf';target.write_bytes(b'keep')
        with self.assertRaises(ValueError):self.call('append_metadata',allow_unsigned_revision=True,title='No')
        self.assertEqual(target.read_bytes(),b'keep')
        with self.assertRaises(ValueError):self.call('inspect',expected_sha256='0'*64)
    def test_signed_rewrite_is_refused_without_corrupting_the_signature(self):
        self.source.write_bytes(signed_fixture(self.source.read_bytes()));before=self.source.read_bytes();secret=self.secret('key.txt','fixture-only')
        with self.assertRaisesRegex(ValueError,'invalidate'):self.call('encrypt_copy',output_user_password_file=secret,output_owner_password_file=secret)
        self.assertEqual(before,self.source.read_bytes());self.assertFalse((self.root/'output.pdf').exists())

    def test_certified_modification_is_refused_without_claiming_docmdp_validity(self):
        from pypdf import PdfReader,PdfWriter
        from pypdf.generic import DictionaryObject,NameObject
        writer=PdfWriter(clone_from=PdfReader(io.BytesIO(self.source.read_bytes())))
        writer._root_object[NameObject('/Perms')]=DictionaryObject({NameObject('/DocMDP'):DictionaryObject()})
        out=io.BytesIO();writer.write(out);self.source.write_bytes(out.getvalue());before=self.source.read_bytes()
        with self.assertRaisesRegex(ValueError,'certified'):self.call('append_metadata',allow_unsigned_revision=True,title='Not certified')
        self.assertEqual(before,self.source.read_bytes());self.assertFalse((self.root/'output.pdf').exists())



    def test_explicit_trust_root_accepts_signer_but_does_not_claim_revocation(self):
        trust=self.root/'trust.pem';self.source.write_bytes(signed_fixture(self.source.read_bytes(),trust))
        result=self.call('inspect',trust_store_file=str(trust),trust_store_sha256=hashlib.sha256(trust.read_bytes()).hexdigest())
        sig=result['signatures'][0]
        self.assertEqual(sig['integrity'],'valid');self.assertTrue(sig['certificate_chain_valid']);self.assertTrue(sig['certificate_trust_evaluated'])
        self.assertFalse(sig['revocation_evaluated']);self.assertFalse(sig['certification_policy_evaluated']);self.assertFalse(sig['trusted_signing_time_evaluated'])

    def test_wrong_explicit_root_does_not_accept_intact_untrusted_signature(self):
        self.source.write_bytes(signed_fixture(self.source.read_bytes()))
        wrong=self.root/'other.pem';signed_fixture(D.create_bytes('pdf','# Other'),wrong)
        result=self.call('inspect',trust_store_file=str(wrong),trust_store_sha256=hashlib.sha256(wrong.read_bytes()).hexdigest())
        sig=result['signatures'][0]
        self.assertEqual(sig['integrity'],'valid');self.assertTrue(sig['certificate_trust_evaluated']);self.assertFalse(sig['certificate_chain_valid'])

    def test_stale_or_unpaired_trust_bundle_is_rejected(self):
        trust=self.root/'trust.pem';self.source.write_bytes(signed_fixture(self.source.read_bytes(),trust))
        before=self.source.read_bytes()
        with self.assertRaisesRegex(ValueError,'together'):self.call('inspect',trust_store_file=str(trust))
        with self.assertRaisesRegex(ValueError,'changed'):self.call('inspect',trust_store_file=str(trust),trust_store_sha256='0'*64)
        self.assertEqual(before,self.source.read_bytes())

    def test_trusted_signature_does_not_sign_unsigned_incremental_revision(self):
        trust=self.root/'trust.pem';self.source.write_bytes(signed_fixture(self.source.read_bytes(),trust))
        result=self.call('append_metadata',allow_unsigned_revision=True,title='Explicit new revision',trust_store_file=str(trust),trust_store_sha256=hashlib.sha256(trust.read_bytes()).hexdigest())
        sig=result['output_signatures']['signatures'][0]
        self.assertTrue(sig['certificate_chain_valid']);self.assertEqual(sig['integrity'],'valid')
        self.assertFalse(result['new_revision_is_signed']);self.assertFalse(result['output_signatures']['current_revision_fully_signed'])


if __name__=='__main__':unittest.main(verbosity=2)
