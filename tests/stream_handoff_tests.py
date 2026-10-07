#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Protocol/authority tests for opt-in, same-UID, already-owned pipe transfer."""
import array
import hashlib
import importlib.util
import json
import os
import pathlib
import socket
import tempfile
import threading
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('streamhandoff',ROOT/'deploy/stream_handoff.py');H=importlib.util.module_from_spec(spec);spec.loader.exec_module(H)


class StreamHandoff(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='hepta-handoff-unit-');self.root=pathlib.Path(self.temp.name)
        self.r,self.w=os.pipe();self.ident=H.identity(os.getpid());self.key='unit-handoff-identity-1'
    def tearDown(self):os.close(self.r);os.close(self.w);self.temp.cleanup()
    def message(self):
        return {'handoff_id':self.key,'sender_io_quiesced':True,'sender_identity':self.ident,'application_identities':[self.ident],
                'descriptors':[{'role':'stdin_writer','identity':H.pipe_description(self.w)}]}
    def send(self,message,fd=None,expect_failure=False):
        left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        try:
            left.sendmsg([json.dumps(message).encode()],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[self.w if fd is None else fd]))])
            with mock.patch.object(H,'validate_stdio'):
                if expect_failure:
                    with self.assertRaises((ValueError,PermissionError)):H.receive(right,self.root/'receipt.json',self.key)
                    return None
                result,fds=H.receive(right,self.root/'receipt.json',self.key)
            ack=json.loads(left.recv(4096))
            return result,fds,ack
        finally:left.close();right.close()
    def test_pipe_object_and_cloexec_are_preserved(self):
        result,fds,ack=self.send(self.message())
        try:
            self.assertEqual(H.pipe_description(fds['stdin_writer']),H.pipe_description(self.w))
            self.assertFalse(os.get_inheritable(fds['stdin_writer']))
            self.assertEqual(ack['receipt_sha256'],hashlib.sha256((self.root/'receipt.json').read_bytes()).hexdigest())
            self.assertFalse(result['memory_copied']);self.assertFalse(result['application_stopped'])
        finally:
            for fd in fds.values():os.close(fd)
    def test_missing_quiescence_ack_is_rejected(self):
        request=self.message();request['sender_io_quiesced']=False;self.send(request,expect_failure=True)
        self.assertFalse((self.root/'receipt.json').exists())
        with self.assertRaisesRegex(ValueError,'acknowledgement'):H.transfer('/not-opened',self.key,{},[])
    def test_stale_sender_and_resource_are_rejected(self):
        request=self.message();request['sender_identity']={**self.ident,'start_ticks':self.ident['start_ticks']+1};self.send(request,expect_failure=True)
        request=self.message();request['descriptors'][0]['identity']['inode']+=1;self.send(request,expect_failure=True)
    def test_role_must_match_read_or_write_mode(self):
        request=self.message();request['descriptors'][0]['role']='stdout_reader';self.send(request,expect_failure=True)
    def test_non_pipe_cannot_be_transferred(self):
        path=self.root/'not-pipe';path.write_bytes(b'fixture')
        with path.open('rb') as f:
            with self.assertRaisesRegex(ValueError,'pipe'):H.pipe_description(f.fileno())
    def test_mismatched_app_stdio_refused(self):
        with self.assertRaises((ValueError,FileNotFoundError,PermissionError)):
            H.validate_stdio(self.ident,[{'role':'stdin_writer','identity':{'device':0,'inode':0,'access':os.O_WRONLY}}])
    def test_socket_directory_is_private_and_not_overwritten(self):
        path=self.root/'handoff.sock';listener=H.listener(path)
        try:
            self.assertEqual(path.stat().st_mode&0o777,0o600)
            with self.assertRaises(ValueError):H.listener(path)
        finally:listener.close();path.unlink()
        self.root.chmod(0o755)
        with self.assertRaises(PermissionError):H.listener(path)
        self.root.chmod(0o700)
    def test_different_uid_rejected_before_data_read(self):
        import struct
        fake=mock.Mock();fake.getsockopt.return_value=struct.pack('3i',1,os.getuid()+1,os.getgid())
        with self.assertRaises(PermissionError):H.peer(fake,os.getuid())
    def test_receipt_cannot_be_overwritten_by_retry(self):
        (self.root/'receipt.json').write_text('KEEP')
        left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        try:
            left.sendmsg([json.dumps(self.message()).encode()],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[self.w]))])
            with mock.patch.object(H,'validate_stdio'),self.assertRaises(FileExistsError):H.receive(right,self.root/'receipt.json',self.key)
            self.assertEqual((self.root/'receipt.json').read_text(),'KEEP')
        finally:left.close();right.close()


if __name__=='__main__':unittest.main(verbosity=2)
