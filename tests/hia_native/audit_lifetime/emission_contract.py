"""Inert exact byte contracts for the two lifetime HIA emitters."""
import struct

INVALID = 0xffffffff
CAPACITY = 0xfffffffe


def replace(wire, offset, value):
    return wire[:offset] + struct.pack('<Q', value) + wire[offset + 8:]


def refs_contract(composition):
    wire = b'HAREMP01' + struct.pack('<Q', 1)
    image = bytes.fromhex(composition['reference_hex'])
    return wire, image, [
        ('valid', wire, len(image) + 17, len(image)),
        ('short', wire[:-1], len(image), INVALID),
        ('long', wire + b'\0', len(image), INVALID),
        ('magic', b'X' + wire[1:], len(image), INVALID),
        ('version', replace(wire, 8, 2), len(image), INVALID),
        ('capacity', wire, len(image) - 1, CAPACITY),
    ]


def callable_contract(controller, refs, sync, composition):
    wire = b'HARPMP01' + struct.pack('<4Q', 1, len(controller), len(refs), len(sync))
    wire += controller + refs + sync
    image = bytearray.fromhex(composition['template_hex'])
    offsets = composition['offsets']
    image[offsets['refs']:offsets['refs'] + len(refs)] = refs
    image[offsets['sync']:offsets['sync'] + len(sync)] = sync
    image.extend(controller)
    image = bytes(image)
    size = len(image)
    return wire, image, [
        ('valid', wire, size + 17, size),
        ('short', wire[:-1], size, INVALID),
        ('long', wire + b'\0', size, INVALID),
        ('magic', b'X' + wire[1:], size, INVALID),
        ('version', replace(wire, 8, 2), size, INVALID),
        ('controller-empty', replace(wire, 16, 0), size, INVALID),
        ('controller-limit', replace(wire, 16, 0xffffffffffffffff), size, INVALID),
        ('refs-size', replace(wire, 24, len(refs) - 1), size, INVALID),
        ('sync-size', replace(wire, 32, len(sync) - 1), size, INVALID),
        ('capacity', wire, size - 1, CAPACITY),
    ]
