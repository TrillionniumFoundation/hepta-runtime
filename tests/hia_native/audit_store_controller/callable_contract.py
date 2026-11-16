"""Pure exact callable packing contract shared by producer and inert reader."""
import struct
from common import pin, require


def inputs(controller, synchronization, composition):
    require(pin(controller) == composition['controller'], 'exact qualified controller input')
    require(pin(synchronization) == composition['synchronization'], 'exact native synchronization input')
    stub = bytes.fromhex(composition['adapter_hex'])
    require(pin(stub) == composition['adapter'], 'complete mechanical adapter')
    require(composition['offsets'] == dict(entry=0, controller=len(stub),
                                         sync=len(stub) + len(controller),
                                         end=len(stub) + len(controller) + len(synchronization)),
            'exact embedded module offsets')
    wire = b'HAPMPK01' + struct.pack('<3Q', 1, len(controller), len(synchronization)) + controller + synchronization
    return wire, stub + controller + synchronization


def cases(wire, size):
    return [
        ('valid', wire, size + 64, size),
        ('empty', b'', size + 64, 0xffffffff),
        ('short', wire[:-1], size + 64, 0xffffffff),
        ('long', wire + b'\0', size + 64, 0xffffffff),
        ('magic', b'X' + wire[1:], size + 64, 0xffffffff),
        ('version', wire[:8] + struct.pack('<Q', 2) + wire[16:], size + 64, 0xffffffff),
        ('controller-length', wire[:16] + struct.pack('<Q', 160543) + wire[24:], size + 64, 0xffffffff),
        ('sync-length', wire[:24] + struct.pack('<Q', 1634) + wire[32:], size + 64, 0xffffffff),
        ('capacity', wire, size - 1, 0xfffffffe),
    ]

