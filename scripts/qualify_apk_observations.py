#!/usr/bin/env python3
"""Finite, complete-report differential for the frozen REA 6.8.0 APK contract.

The original npm provider runs only as an oracle. Generated declarations carry
no claim of valid signatures; the seed corpus contains real Android-produced
positive packages and the earlier forged-signature counterexample. No package
is installed or executed. The minimal-crate mode is explicitly not a runtime
qualification; the runtime mode exercises the actual isolated worker.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import tarfile
import time
import zipfile
import zlib


FROZEN_PACKAGE = '8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb'
V2, V3, V31 = 0x7109871a, 0xf05368c0, 0x1b93ad61
ROTATION, STAMP_V1, STAMP_V2 = 0x3ba06f8c, 0x2b09189e, 0x6dff800d


def sha(data):
    return hashlib.sha256(data).hexdigest()


def lp(data):
    return struct.pack('<I', len(data)) + data


def take(data, at=0):
    length = struct.unpack_from('<I', data, at)[0]
    end = at + 4 + length
    assert end <= len(data)
    return data[at + 4:end], end


def elements(data):
    result, at = [], 0
    while at < len(data):
        item, at = take(data, at)
        result.append(item)
    return result


def signing_layout(data):
    end = data.rindex(b'PK\x05\x06')
    central = struct.unpack_from('<I', data, end + 16)[0]
    start = central
    if data[central - 16:central] == b'APK Sig Block 42':
        start = central - struct.unpack_from('<Q', data, central - 24)[0] - 8
    return start, central, end


def block_pairs(data):
    start, central, _ = signing_layout(data)
    assert start < central
    result, at = [], start + 8
    while at < central - 24:
        length, ident = struct.unpack_from('<QI', data, at)
        result.append((ident, data[at + 12:at + 8 + length]))
        at += length + 8
    return result


def rebuild(data, pairs, directory_gap=b''):
    start, central, end = signing_layout(data)
    values = b''.join(struct.pack('<QI', len(value) + 4, ident) + value for ident, value in pairs)
    size = struct.pack('<Q', len(values) + 24)
    block = size + values + size + b'APK Sig Block 42'
    ending = bytearray(data[end:])
    struct.pack_into('<I', ending, 16, start + len(block))
    return data[:start] + block + data[central:end] + directory_gap + ending


def raw_signer(data, v3):
    signed, at = take(data)
    outer_sdk = data[at:at + 8] if v3 else b''
    at += len(outer_sdk)
    signatures, at = take(data, at)
    key, at = take(data, at)
    digests, p = take(signed)
    certificates, p = take(signed, p)
    sdk = signed[p:p + 8] if v3 else b''
    p += len(sdk)
    attrs, p = take(signed, p)
    return dict(digests=elements(digests), certificates=elements(certificates),
                attributes=elements(attrs), sdk=sdk, outer_sdk=outer_sdk,
                signed_tail=signed[p:], signatures=elements(signatures),
                key=key, tail=data[at:])


def encode_signer(signer):
    signed = (lp(b''.join(map(lp, signer['digests']))) +
              lp(b''.join(map(lp, signer['certificates']))) + signer['sdk'] +
              lp(b''.join(map(lp, signer['attributes']))) + signer['signed_tail'])
    return (lp(signed) + signer['outer_sdk'] + lp(b''.join(map(lp, signer['signatures']))) +
            lp(signer['key']) + signer['tail'])


def change_signers(data, ident, change, outer_tail=None):
    pairs = block_pairs(data)
    index = next(i for i, pair in enumerate(pairs) if pair[0] == ident)
    value = pairs[index][1]
    encoded, at = take(value)
    signers = [raw_signer(s, ident != V2) for s in elements(encoded)]
    change(signers)
    pairs[index] = (ident, lp(b''.join(lp(encode_signer(s)) for s in signers)) +
                    (value[at:] if outer_tail is None else outer_tail))
    return rebuild(data, pairs)


def first_certificate(data, ident=V2):
    value = next(v for k, v in block_pairs(data) if k == ident)
    signers, _ = take(value)
    return raw_signer(elements(signers)[0], ident != V2)['certificates'][0]


def der(tag, value):
    length = len(value)
    if length < 128:
        encoded = bytes([length])
    else:
        width = (length.bit_length() + 7) // 8
        encoded = bytes([0x80 + width]) + length.to_bytes(width, 'big')
    return bytes([tag]) + encoded + value


def der_read(data):
    tag, length, at = data[0], data[1], 2
    if length & 128:
        width = length & 127
        assert width
        length = int.from_bytes(data[at:at + width], 'big')
        at += width
    return tag, data[at:at + length], data[at + length:]


def der_elements(data):
    result = []
    while data:
        tag, content, data = der_read(data)
        result.append((tag, content))
    return result


def der_sequence(items):
    return b''.join(der(tag, content) for tag, content in items)


def encoded_oid(text):
    values = list(map(int, text.split('.')))
    out = bytearray()
    for value in [40 * values[0] + values[1], *values[2:]]:
        encoded = [value & 127]
        value >>= 7
        while value:
            encoded.append(128 | (value & 127))
            value >>= 7
        out.extend(reversed(encoded))
    return der(6, out)


def compressed_generator(parameters, generator):
    fields = der_elements(der_read(parameters)[1])
    field = der_elements(fields[1][1])
    width = (len(generator) - 1) // 2
    x, y = int.from_bytes(generator[1:1 + width], 'big'), int.from_bytes(generator[1 + width:], 'big')
    if field[0][1] == bytes.fromhex('2a8648ce3d0102'):
        items = der_elements(field[1][1])
        bits = int.from_bytes(items[0][1], 'big')
        powers = ([int.from_bytes(items[2][1], 'big')] if items[2][0] == 2 else
                  [int.from_bytes(content, 'big') for _, content in der_elements(items[2][1])])
        modulus = (1 << bits) | 1
        for power in powers:
            modulus |= 1 << power
        def multiply(a, b):
            out = 0
            while b:
                if b & 1:
                    out ^= a
                b >>= 1
                a <<= 1
                if a >> bits:
                    a ^= modulus
            return out
        def inverse(a):
            out = 1
            for bit in bin((1 << bits) - 2)[2:]:
                out = multiply(out, out)
                if bit == '1':
                    out = multiply(out, a)
            return out
        bit = (multiply(y, inverse(x)) & 1) if x else 0
    else:
        bit = y & 1
    return bytes([2 | bit]) + generator[1:1 + width]


def cert_parts(cert):
    outer = der_elements(der_read(cert)[1])
    tbs = der_elements(outer[0][1])
    offset = int(tbs[0][0] == 0xa0)
    return outer, tbs, offset


def cert_field(cert, index, tag, content):
    outer, tbs, offset = cert_parts(cert)
    tbs[offset + index] = (tag, content)
    outer[0] = (0x30, der_sequence(tbs))
    return der(0x30, der_sequence(outer))


def key_identifier(cert):
    _, tbs, _ = cert_parts(cert)
    extension = next(c for t, c in tbs if t == 0xa3)
    sequence = der_elements(der_read(extension)[1])
    for _, content in sequence:
        fields = der_elements(content)
        if fields[0] == (6, bytes.fromhex('551d0e')):
            return der_read(fields[-1][1])[1]
    raise AssertionError('owned certificate has no SKI')


def cms(cert, *, certificates=None, infos=1, ski=False, issuer=None, indefinite=False,
        signature=None, oid_bytes=None, encap=None):
    _, tbs, offset = cert_parts(cert)
    sid = (der(0x80, key_identifier(cert)) if ski else
           der(0x30, (der(*tbs[offset + 2]) if issuer is None else issuer) + der(*tbs[offset])))
    digest = der(0x30, der(6, bytes.fromhex('608648016503040201')))
    algorithm = der(0x30, der(6, oid_bytes or bytes.fromhex('2a864886f70d010101')))
    signature = der(4, b'owned declaration, deliberately not an authentic signature') if signature is None else signature
    info = der(0x30, der(2, b'\x01') + sid + digest + algorithm + signature)
    certs = der(0xa0, b''.join([cert] if certificates is None else certificates))
    encap = der(0x30, der(6, bytes.fromhex('2a864886f70d010701'))) if encap is None else encap
    content = der(2, b'\x01') + der(0x31, digest) + encap + certs + der(0x31, info * infos)
    wrap = lambda tag, data: bytes([tag, 0x80]) + data + b'\0\0' if indefinite else der(tag, data)
    return wrap(0x30, der(6, bytes.fromhex('2a864886f70d010702')) + wrap(0xa0, wrap(0x30, content)))


def make_zip(entries):
    """Stored/deflated records with explicit test-only central/local overrides."""
    data, directory = bytearray(), bytearray()
    for spec in entries:
        name, body = spec['name'], spec.get('data', b'')
        method = spec.get('method', 0)
        flags = spec.get('flags', 0)
        if method == 8:
            compressor = zlib.compressobj(wbits=-15)
            stored = compressor.compress(body) + compressor.flush()
        else:
            stored = body
        stored = spec.get('stored', stored)
        local_name = spec.get('local_name', name)
        size = spec.get('size', len(body))
        crc = zlib.crc32(body)
        local = len(data)
        header = bytearray(30)
        header[:4] = b'PK\x03\x04'
        struct.pack_into('<HH', header, 6, spec.get('local_flags', flags), method)
        struct.pack_into('<IIIHH', header, 14, spec.get('local_crc', crc), len(stored), size, len(local_name), 0)
        data += header + local_name + stored
        record = bytearray(46)
        record[:4] = b'PK\x01\x02'
        struct.pack_into('<HH', record, 8, flags, method)
        struct.pack_into('<IIIHHH', record, 16, crc, len(stored), size, len(name), 0, 0)
        struct.pack_into('<I', record, 42, local)
        directory += record + name
    end = bytearray(22)
    end[:4] = b'PK\x05\x06'
    struct.pack_into('<HHII', end, 8, len(entries), len(entries), len(directory), len(data))
    return bytes(data + directory + end)


def v1_zip(block, **options):
    return make_zip([{'name': b'META-INF/MANIFEST.MF'}, {'name': b'META-INF/OWNED.SF'},
                     {'name': b'META-INF/OWNED.RSA', 'data': block, **options}])


def corpus(fixtures, profile='legacy'):
    cases = {p.stem: p.read_bytes() for p in sorted(fixtures.glob('*.apk'))}
    assert len(cases) == 20
    base = cases['custom-0103-rsa']
    rotated = cases['rotation-v31']
    cert = first_certificate(base)
    other = first_certificate(cases['ecdsa-v2-v3'])
    add = lambda name, value: cases.__setitem__('declared-' + name, value)
    for name, options in [
        ('pkcs7-stored', {}), ('pkcs7-ber', {'indefinite': True}),
        ('pkcs7-second-cert', {'certificates': [other, cert]}),
        ('pkcs7-no-cert', {'certificates': []}), ('pkcs7-two-infos', {'infos': 2}),
        ('pkcs7-32-infos', {'infos': 32}), ('pkcs7-33-infos', {'infos': 33}),
        ('pkcs7-32-certs', {'certificates': [cert] * 32}),
        ('pkcs7-33-certs', {'certificates': [cert] * 33}),
        ('pkcs7-ski', {'ski': True}),
        ('pkcs7-constructed-signature', {'signature': der(0x24, der(4, b'one') + der(0x24, der(4, b'two')))}),
        ('pkcs7-bad-signature-fragment', {'signature': der(0x24, der(2, b'\x01'))}),
        ('pkcs7-big-oid', {'oid_bytes': b'\x2a' + b'\x81' * 62 + b'\x01'}),
        ('pkcs7-overlong-oid', {'oid_bytes': b'\x2a' + b'\x81' * 63 + b'\x01'}),
    ]:
        add(name, v1_zip(cms(cert, **options)))
    block = cms(cert)
    add('pkcs7-deflated', v1_zip(block, method=8))
    add('pkcs7-trailing', v1_zip(block + b'ignored-after-ContentInfo'))
    add('pkcs7-encryption-marker', v1_zip(block, flags=1))
    add('pkcs7-local-encryption-marker', v1_zip(block, local_flags=1))
    add('pkcs7-descriptor-marker', v1_zip(block, flags=8))
    add('pkcs7-descriptor-mismatch', v1_zip(block, local_flags=8))
    add('pkcs7-local-crc-mismatch', v1_zip(block, local_crc=123))
    add('pkcs7-unsupported-method', v1_zip(block, method=99))
    add('pkcs7-bad-deflate', v1_zip(block, method=8, stored=b'\xff\xff\xff'))
    add('pkcs7-inflate-cap', v1_zip(b'A' * (1048576 + 1), method=8, size=1))
    add('pkcs7-declared-cap', v1_zip(b'A' * (1048576 + 1), method=8))
    add('pkcs7-truncated-ber', v1_zip(b'\x30\x80'))
    nested = der(4, b'')
    for _ in range(34):
        nested = der(0xa0, nested)
    add('pkcs7-depth-cap', v1_zip(cms(cert, encap=der(0x30, nested))))
    add('pkcs7-node-cap', v1_zip(cms(cert, encap=der(0x30, b'\x05\0' * 65536))))
    normalized = der(0x30, der(0x31, der(0x30, der(6, bytes.fromhex('550403')) + der(0x13, b'  HEPTA   APK TEST RSA  '))))
    add('pkcs7-normalized-issuer', v1_zip(cms(cert, issuer=normalized)))
    add('pkcs7-unknown-issuer', v1_zip(cms(cert, issuer=der(0x30, b''))))
    add('pkcs7-one-damaged-one-readable', make_zip([
        {'name': b'META-INF/A.SF'}, {'name': b'META-INF/A.RSA', 'data': b'\x30\x80'},
        {'name': b'META-INF/B.SF'}, {'name': b'META-INF/B.RSA', 'data': block}]))
    for duplicate in (b'META-INF/MANIFEST.MF', b'META-INF/OWNED.SF', b'META-INF/OWNED.RSA', b'assets/duplicate'):
        entries = [{'name': b'META-INF/MANIFEST.MF'}, {'name': b'META-INF/OWNED.SF'}, {'name': b'META-INF/OWNED.RSA', 'data': block}]
        if duplicate == b'assets/duplicate':
            entries.append({'name': duplicate})
        entries.append({'name': duplicate, 'data': block if duplicate.endswith(b'.RSA') else b''})
        add('duplicate-' + duplicate.decode().replace('/', '-'), make_zip(entries))
    add('case-sensitive-v1', make_zip([{'name': b'META-INF/OWNED.sf'}, {'name': b'META-INF/OWNED.RSA', 'data': block}]))
    add('java-local-name', make_zip([{'name': b'META-INF/\xed\xa0\x80.SF'}, {'name': b'META-INF/\xed\xa0\x80.RSA', 'local_name': b'META-INF/\xef\xbf\xbd.RSA', 'data': block}]))
    add('java-duplicate-names', make_zip([{'name': b'META-INF/\xed\xa0\x80.SF'}, {'name': b'META-INF/\xef\xbf\xbd.SF'}, {'name': b'META-INF/\xed\xa0\x80.RSA', 'data': block}]))

    for name, fn in [
        ('empty-certificates', lambda s: s[0].update(certificates=[])),
        ('empty-certificate-der', lambda s: s[0].update(certificates=[b''])),
        ('unreadable-certificate-der', lambda s: s[0].update(certificates=[b'\x30\x80\0\0'])),
        ('empty-signatures', lambda s: s[0].update(signatures=[])),
        ('duplicate-digest', lambda s: s[0]['digests'].append(s[0]['digests'][0])),
        ('different-algorithm-lists', lambda s: s[0]['signatures'].__setitem__(0, struct.pack('<I', 0x0104) + s[0]['signatures'][0][4:])),
        ('record-suffix', lambda s: s[0]['digests'].__setitem__(0, s[0]['digests'][0] + b'unknown-tail')),
        ('signature-suffix', lambda s: s[0]['signatures'].__setitem__(0, s[0]['signatures'][0] + b'unknown-tail')),
        ('signer-suffix', lambda s: s[0].update(tail=b'unknown-tail')),
        ('signed-data-suffix', lambda s: s[0].update(signed_tail=b'unknown-tail')),
        ('empty-signers', lambda s: s.clear()),
        ('33-signers', lambda s: s.extend([s[0]] * 32)),
    ]:
        add(name, change_signers(base, V2, fn))
    add('scheme-suffix', change_signers(base, V2, lambda s: None, outer_tail=b'unknown-tail'))
    pairs = block_pairs(base)
    add('duplicate-scheme-id', rebuild(base, [pairs[0], pairs[0]]))
    add('content-layout-gap', rebuild(base, pairs, b'gap-after-directory'))
    add('stamp-v1', rebuild(base, pairs + [(STAMP_V1, lp(lp(cert)))]))
    add('stamp-v2', rebuild(base, pairs + [(STAMP_V2, lp(lp(other)))]))
    add('stamp-prefer-v2', rebuild(base, pairs + [(STAMP_V1, lp(lp(cert))), (STAMP_V2, lp(lp(other)))]))
    add('stamp-damaged-v2-no-fallback', rebuild(base, pairs + [(STAMP_V1, lp(lp(cert))), (STAMP_V2, b'\xff')]))
    add('stamp-empty-certificate', rebuild(base, pairs + [(STAMP_V2, lp(lp(b'')))]))

    def mutate_rotation(signers, mode):
        attrs = signers[0]['attributes']
        index = next(i for i, attr in enumerate(attrs) if struct.unpack_from('<I', attr)[0] == ROTATION)
        ident, value = attrs[index][:4], attrs[index][4:]
        if mode == 'version':
            value = struct.pack('<I', 2) + value[4:]
        elif mode == 'truncated':
            value = value[:9]
        elif mode == 'empty':
            value = struct.pack('<I', 1)
        elif mode == '33-nodes':
            nodes = elements(value[4:])
            value = struct.pack('<I', 1) + b''.join(lp(nodes[0]) for _ in range(33))
        elif mode == 'unknown-flags':
            nodes = elements(value[4:])
            signed, at = take(nodes[0])
            nodes[0] = lp(signed) + struct.pack('<I', 0xffffffff) + nodes[0][at + 4:]
            value = value[:4] + b''.join(map(lp, nodes))
        attrs[index] = ident + value
    for mode in ('version', 'truncated', 'empty', '33-nodes', 'unknown-flags'):
        add('rotation-' + mode, change_signers(rotated, V31, lambda s, mode=mode: mutate_rotation(s, mode)))
    add('v31-sdk-copy-mismatch', change_signers(rotated, V31, lambda s: s[0].update(outer_sdk=b'\xff' * 8)))

    for label, tag, value in [
        ('utf8', 12, '中文 é'.encode()), ('punctuation', 12, b' #test,+"\\<>;= '),
        ('controls', 12, b'line\n\t\0\x01end'), ('teletex', 20, b'\xe9\xff'),
        ('bmp', 30, '中é'.encode('utf-16be')), ('universal', 28, '中é'.encode('utf-32be')),
        ('invalid-utf8', 12, b'\xff'), ('invalid-octets', 4, b'abc')]:
        name = der(0x31, der(0x30, der(6, bytes.fromhex('550403')) + der(tag, value)))
        modified = cert_field(cert, 4, 0x30, name)
        add('certificate-' + label, change_signers(base, V2, lambda s, modified=modified: s[0].update(certificates=[modified])))
    for label, value in [('negative', b'\xff'), ('zero', b'\0'), ('positive', b'\0\x80'), ('nonminimal', b'\0\x01')]:
        modified = cert_field(cert, 0, 2, value)
        add('serial-' + label, change_signers(base, V2, lambda s, modified=modified: s[0].update(certificates=[modified])))
    _, tbs, offset = cert_parts(cert)
    validity = der_elements(tbs[offset + 3][1])
    for label, tag, value in [('invalid', 23, b'bad'), ('offset', 23, b'261104010203+0100'),
                              ('offset-day', 23, b'261104000203+0100'),
                              ('offset-year', 23, b'000101000000+0200'),
                              ('offset-leap', 23, b'000301000000+0200'),
                              ('offset-negative', 23, b'991231230000-0200'),
                              ('generalized-offset', 24, b'20500101000000-0100'),
                              ('fraction', 24, b'20501104010203.123Z')]:
        modified = cert_field(cert, 3, 0x30, der(tag, value) + der(*validity[1]))
        add('date-' + label, change_signers(base, V2, lambda s, modified=modified: s[0].update(certificates=[modified])))

    # Each public-key fact is independently nullable. These are declarations,
    # including deliberately damaged SPKIs, never trusted certificate chains.
    _, ec_tbs, ec_offset = cert_parts(other)
    ec_spki = der_elements(ec_tbs[ec_offset + 5][1])
    ec_algorithm = der_elements(ec_spki[0][1])
    rsa_key = der_elements(tbs[offset + 5][1])[1][1]
    for label, algorithm, key in [
        ('ec-valid', ec_spki[0][1], ec_spki[1][1]),
        ('ec-off-curve', ec_spki[0][1], b'\0\x04' + b'\0' * (len(ec_spki[1][1]) - 2)),
        ('ec-short', ec_spki[0][1], b'\0\x04\x01'),
        ('ec-unknown-curve', der_sequence([ec_algorithm[0], (6, bytes.fromhex('2a0304'))]), ec_spki[1][1]),
        ('rsa-empty', der(6, bytes.fromhex('2a864886f70d010101')) + der(5, b''), b'\0'),
        ('rsa-one-integer', der(6, bytes.fromhex('2a864886f70d010101')), b'\0' + der(0x30, der(2, b'\x01'))),
        ('rsa-trailing-integer', der(6, bytes.fromhex('2a864886f70d010101')), b'\0' + der(0x30, der(2, b'\x01') * 3)),
        ('rsa-negative', der(6, bytes.fromhex('2a864886f70d010101')), b'\0' + der(0x30, der(2, b'\xff') + der(2, b'\x03'))),
        ('rsa-zero', der(6, bytes.fromhex('2a864886f70d010101')), b'\0' + der(0x30, der(2, b'\0') * 2)),
        ('rsa-pss', der(6, bytes.fromhex('2a864886f70d01010a')), rsa_key),
        ('rsa-pss-bad-params', der(6, bytes.fromhex('2a864886f70d01010a')) + der(2, b'\x01'), rsa_key),
        ('rsa-non-null-params', der(6, bytes.fromhex('2a864886f70d010101')) + der(2, b'\x01'), rsa_key),
        ('rsa-inner-trailing', der(6, bytes.fromhex('2a864886f70d010101')), rsa_key + b'trailing'),
        ('ed25519', der(6, bytes.fromhex('2b6570')), b'\0' + bytes(range(32))),
        ('ed25519-null-params', der(6, bytes.fromhex('2b6570')) + der(5, b''), b'\0' + bytes(range(32))),
        ('ed448', der(6, bytes.fromhex('2b6571')), b'\0' + bytes(range(57))),
        ('x25519', der(6, bytes.fromhex('2b656e')), b'\0' + bytes(range(32))),
        ('x448', der(6, bytes.fromhex('2b656f')), b'\0' + bytes(range(56))),
        ('unknown', der(6, bytes.fromhex('2a0304')), rsa_key),
    ]:
        modified = cert_field(cert, 5, 0x30, der(0x30, algorithm) + der(3, key))
        add('public-key-' + label, change_signers(base, V2, lambda s, modified=modified: s[0].update(certificates=[modified])))

    public_curves = json.loads((fixtures.parent / 'rea_apk_signature_observation_curves.json').read_text())
    for row in public_curves['rows']:
        parameters = bytes.fromhex(row['parameters_der'])
        generator = der_elements(der_read(parameters)[1])[3][1]
        encodings = [('explicit', parameters, generator)]
        if row['oid'] is not None:
            named = encoded_oid(row['oid'])
            compressed = compressed_generator(parameters, generator)
            encodings += [('named', named, generator), ('compressed', named, compressed),
                          ('off-curve', named, b'\x04' + b'\0' * (len(generator) - 1))]
            if row['name'] in ('prime256v1', 'sect163k1'):
                encodings += [('hybrid', named, bytes([compressed[0] + 4]) + generator[1:]),
                              ('infinity', named, b'\0')]
        for label, params, point in encodings:
            spki = der(0x30, encoded_oid('1.2.840.10045.2.1') + params) + der(3, b'\0' + point)
            modified = cert_field(cert, 5, 0x30, spki)
            add('curve-' + row['name'] + '-' + label, change_signers(base, V2, lambda s, modified=modified: s[0].update(certificates=[modified])))

    _, central, end = signing_layout(base)
    count = struct.unpack_from('<H', base, end + 10)[0]
    size = struct.unpack_from('<I', base, end + 12)[0]
    zip64 = struct.pack('<IQHHIIQQQQ', 0x06064b50, 44, 45, 45, 0, 0, count, count, size, central)
    locator = struct.pack('<IIQI', 0x07064b50, 0, end, 1)
    ending = bytearray(base[end:])
    struct.pack_into('<HHII', ending, 8, 65535, 65535, 0xffffffff, 0xffffffff)
    add('zip64-directory', base[:end] + zip64 + locator + ending)
    add('empty-zip', make_zip([]))
    add('not-a-zip', b'plain selected bytes')
    add('truncated-zip', b'PK\x03\x04' + b'\0' * 30)
    forged_end = bytearray(base)
    struct.pack_into('<H', forged_end, len(forged_end) - 2, 22)
    add('ambiguous-eocd', bytes(forged_end) + b'PK\x05\x06' + b'\0' * 18)
    if profile == 'frozen':
        for count in (4096, 4097):
            add('frozen-pairs-' + str(count), rebuild(base, [(i, b'') for i in range(count)]))
            for field, record in [('certificates', b''), ('attributes', struct.pack('<I', 0)),
                                  ('digests', struct.pack('<I', 0xffffffff) + lp(b'')),
                                  ('signatures', struct.pack('<I', 0x0103) + lp(b''))]:
                add('frozen-' + field + '-' + str(count), change_signers(base, V2, lambda s, field=field, record=record, count=count: s[0].update({field:[record] * count})))
        for field, value in [('certificates', [b'\0' * 65537]), ('key', b'\0' * 65537),
                             ('signatures', [struct.pack('<I', 0x0103) + lp(b'\0' * 16385)]),
                             ('digests', [struct.pack('<I', 0xffffffff) + lp(b'\0' * 129)])]:
            add('frozen-large-' + field, change_signers(base, V2, lambda s, field=field, value=value: s[0].update({field:value})))
        add('frozen-large-block', rebuild(base, pairs + [(0x11223344, b'\0' * (17 * 1024 * 1024))]))
        add('frozen-directory-50001', make_zip([{'name':b'assets/repeated'}] * 50001))
        add('frozen-v1-entry-cap', make_zip([{'name':b'META-INF/OWNED.SF'}] * 4097))
        original = raw_signer(elements(take(next(v for k,v in pairs if k == V2))[0])[0], False)
        fixed = 4096 + 256 + 512 + 256 + 4 * len(cert) + 160 + 160 * len(original['signatures'])
        digest_length = (8 * 1024 * 1024 - fixed) // 2
        for extra in (0, 1):
            digest = struct.pack('<I', 0xffffffff) + lp(b'\0' * (digest_length + extra))
            add('frozen-output-digest-' + str(extra), change_signers(base, V2, lambda s, digest=digest: s[0].update(digests=[digest])))
        fixed += 2 * len(take(original['digests'][0], 4)[0])
        stamp_length = (8 * 1024 * 1024 - fixed) // 4
        for extra in (0, 1):
            stamp = lp(lp(cert))
            stamp += b'\0' * (stamp_length + extra - len(stamp))
            add('frozen-output-stamp-' + str(extra), rebuild(base, pairs + [(STAMP_V2, stamp)]))
        entries = [{'name': b'META-INF/MANIFEST.MF'}, {'name': b'META-INF/OWNED.SF'},
                   {'name': b'META-INF/OWNED.RSA', 'data': block}, {'name': b'META-INF/OWNED.SF'}]
        plain = make_zip(entries)
        _, cd, end = signing_layout(plain)
        cd_size = struct.unpack_from('<I', plain, end + 12)[0]
        extra = struct.pack('<IQHHIIQQQQ', 0x06064b50, 44, 45, 45, 0, 0, 4, 4, cd_size, cd)
        extra += struct.pack('<IIQI', 0x07064b50, 0, end, 1)
        for count in (3, 4):
            ending = bytearray(plain[end:])
            struct.pack_into('<HHI', ending, 8, count, count, 0xffffffff)
            add('frozen-classic-count-' + str(count), plain[:end] + extra + ending)
        # This remains below the frozen 512 MiB input allowance and above the
        # separately retained legacy 128 MiB boundary. No package is executed.
        add('frozen-input-over-legacy', b'\0' * (129 * 1024 * 1024) + make_zip([]))
    return cases


NODE = r'''
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
const request=JSON.parse(readFileSync(0,'utf8'));
const {ApkSignatureProvider}=await import(pathToFileURL(request.provider).href);
const provider=new ApkSignatureProvider();const reports=[];
try { for(const entry of request.files) {
 const result=await provider.inspect({path:entry.path});
 reports.push(result.ok ? {name:entry.name,ok:true,value:{result:result.value.result,limitations:result.value.limitations}}
  : {name:entry.name,ok:false,error:{_tag:result.error._tag,resource:result.error.resource??null,reason:result.error.reason??null,issues:result.error.issues??null,reportedLimits:result.error.reportedLimits??null}});
} } finally {await provider.close();}
process.stdout.write(JSON.stringify(reports));
'''


def differences(left, right, path='$'):
    if type(left) is not type(right):
        return [dict(path=path, native=left, reference=right)]
    if isinstance(left, dict):
        result = []
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                result.append(dict(path=path + '.' + key, native=left.get(key), reference=right.get(key), missing=True))
            else:
                result.extend(differences(left[key], right[key], path + '.' + key))
        return result
    if isinstance(left, list):
        if len(left) != len(right):
            return [dict(path=path + '.length', native=len(left), reference=len(right))]
        return [change for index, (a, b) in enumerate(zip(left, right)) for change in differences(a, b, path + f'[{index}]')]
    return [] if left == right else [dict(path=path, native=left, reference=right)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--mode', choices=['minimal-crate', 'runtime'], required=True)
    parser.add_argument('--profile', choices=['legacy', 'frozen'], default='legacy')
    parser.add_argument('--worker-command')
    parser.add_argument('--worker-report', choices=['legacy-envelope', 'static-inspection'], default='legacy-envelope')
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--rea-install', type=Path, required=True)
    parser.add_argument('--rea-tarball', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    fixtures = args.out / 'cases'
    fixtures.mkdir()
    package_bytes = args.rea_tarball.read_bytes()
    assert sha(package_bytes) == FROZEN_PACKAGE
    checked = 0
    with tarfile.open(fileobj=io.BytesIO(package_bytes), mode='r:gz') as archive:
        for member in archive:
            if member.isfile():
                assert member.name.startswith('package/') and '..' not in Path(member.name).parts
                assert (args.rea_install / member.name.removeprefix('package/')).read_bytes() == archive.extractfile(member).read()
                checked += 1
    cases = corpus(args.repo / 'tests/fixtures/rea_apk_signature', args.profile)
    manifest = []
    for name, data in cases.items():
        path = fixtures / (name + '.apk')
        path.write_bytes(data)
        manifest.append(dict(name=name, path=str(path.resolve()), sha256=sha(data), bytes=len(data)))
    (args.out / 'cases.json').write_text(json.dumps(manifest, indent=2) + '\n')
    request = dict(provider=str(args.rea_install / 'dist/apkSignature/ApkSignatureProvider.js'), files=manifest)
    oracle = subprocess.run(['node', '--input-type=module', '-e', NODE], input=json.dumps(request).encode(), capture_output=True, timeout=90)
    (args.out / 'rea.stdout.json').write_bytes(oracle.stdout)
    (args.out / 'rea.stderr.log').write_bytes(oracle.stderr)
    assert oracle.returncode == 0, oracle.stderr.decode(errors='replace')
    reference = {row['name']: row for row in json.loads(oracle.stdout)}
    results, failures = [], []
    for case in manifest:
        name = case['name']
        command = [str(args.binary)]
        if args.mode == 'runtime':
            command += [args.worker_command or 'rea-apk-signature-worker']
        elif args.profile == 'frozen':
            command += ['--frozen-static']
        started = time.monotonic()
        native = subprocess.run(command, input=cases[name], capture_output=True, timeout=90, env={}, cwd='/')
        (args.out / (name + '.native.stdout.json')).write_bytes(native.stdout)
        (args.out / (name + '.native.stderr.log')).write_bytes(native.stderr)
        if args.mode == 'minimal-crate':
            assert native.returncode == 0, native.stderr.decode(errors='replace')
            actual = json.loads(native.stdout)
        elif native.returncode == 0:
            report = json.loads(native.stdout)
            if args.worker_report == 'legacy-envelope':
                assert report['verification']['complete_android_verification'] is False
                actual = dict(ok=True, value=report['static_inspection'])
            else:
                actual = dict(ok=True, value=report)
        else:
            line = native.stderr.decode().splitlines()[0]
            assert line.startswith('HEPTA_APK_TYPED_ERROR '), line
            actual = dict(ok=False, error=json.loads(line.removeprefix('HEPTA_APK_TYPED_ERROR ')))
        assert len(native.stdout) <= (8 * 1048576 if args.profile == 'frozen' else 1048576) + 64
        expected = reference[name]
        if actual['ok'] and expected['ok']:
            expected['value']['result']['artifact']['path'] = None
            change = differences(actual['value'], expected['value'])
        elif not actual['ok'] and not expected['ok']:
            change = differences({key:actual['error'][key] for key in ('_tag', 'resource')},
                                 {key:expected['error'][key] for key in ('_tag', 'resource')})
        else:
            change = [dict(path='$.ok', native=actual, reference=expected)]
        row = dict(name=name, sha256=case['sha256'], bytes=case['bytes'], native_exit=native.returncode,
                   seconds=time.monotonic()-started, differences=change, passed=not change,
                   native_outcome=actual['ok'], reference_outcome=expected['ok'])
        results.append(row)
        if change:
            failures.append(name)
            print('DIFFERENCE', name, json.dumps(change[:3], ensure_ascii=False), flush=True)
        else:
            print('MATCH', name, flush=True)
    source_names = ['rea_apk_signature.rs', 'rea_apk_signature_parser.rs', 'rea_apk_signature_observation.rs',
                    'rea_apk_signature_archive.rs', 'rea_apk_signature_certificate.rs', 'rea_apk_signature_v1.rs',
                    'rea_apk_signature_public_key.rs', 'rea_apk_signature_curves.rs', 'rea_apk_signature_observation_tests.rs']
    summary = dict(format='hepta.apk-static-contract-qualification.v1', mode=args.mode, profile=args.profile,
                   runtime_release_qualified=args.mode == 'runtime' and not failures,
                   binary_sha256=sha(args.binary.read_bytes()),
                   frozen_npm_tarball_sha256=FROZEN_PACKAGE, frozen_install_files_checked=checked,
                   public_curve_fixture_sha256=sha((args.repo/'tests/fixtures/rea_apk_signature_observation_curves.json').read_bytes()),
                   source_sha256={name:sha((args.repo/'src/mcp'/name).read_bytes()) for name in source_names},
                   corpus_cases=len(cases), matched=len(results)-len(failures), failures=failures, results=results,
                   comparison='Full declared report and limitation arrays, or producing-boundary error tag/resource. Path is bound separately by controller.',
                   scope='Finite original-producer differential within existing native bounds; not Android trust/installability or retained Evidence qualification.')
    (args.out / 'qualification.json').write_text(json.dumps(summary, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps({key:summary[key] for key in ('mode','corpus_cases','matched','failures','binary_sha256')}), flush=True)
    raise SystemExit(bool(failures))


if __name__ == '__main__':
    main()
