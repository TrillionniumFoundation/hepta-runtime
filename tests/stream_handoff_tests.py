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
ownspec=importlib.util.spec_from_file_location('dchandoffowner',ROOT/'deploy/dc_handoff_owner.py');O=importlib.util.module_from_spec(ownspec);ownspec.loader.exec_module(O)


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


    def test_descriptor_delivery_without_ack_is_ambiguous_not_retryable(self):
        path=self.root/'ambiguous.sock';listener=H.listener(path);accepted=[]
        def server():
            conn,_=listener.accept()
            with conn:
                _,control,_,_=conn.recvmsg(H.MAX_MESSAGE,socket.CMSG_SPACE(H.MAX_FDS*array.array('i').itemsize),socket.MSG_CMSG_CLOEXEC)
                received=[]
                for level,kind,raw in control:
                    if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                        values=array.array('i');values.frombytes(raw[:len(raw)-(len(raw)%values.itemsize)]);received.extend(values)
                accepted.extend(received)
                for fd in received:os.close(fd)
                # Close without ACK: the sender can no longer prove whether ownership was accepted.
        worker=threading.Thread(target=server);worker.start()
        try:
            with self.assertRaises(H.AmbiguousTransferError) as caught:
                H.transfer(path,self.key,{'stdin_writer':self.w},[os.getpid()],acknowledge_quiesced_io=True)
            manifest=caught.exception.manifest
            self.assertEqual(manifest['handoff_id'],self.key)
            self.assertEqual(manifest['application_identities'],[self.ident])
            self.assertEqual(manifest['descriptors'][0]['identity'],H.pipe_description(self.w))
            self.assertTrue(manifest['sender_io_quiesced'])
        finally:
            worker.join(timeout=3);listener.close();path.unlink(missing_ok=True)
        self.assertEqual(len(accepted),1)

    def test_lost_ack_reconcile_requires_exact_receipt_and_live_broker_identity(self):
        manifest={**self.message(),'history_finalized':True}
        receipt={'session_id':self.key,'sender_identity':self.ident,'application_identities':[self.ident],
                 'descriptors':manifest['descriptors'],'history_finalized':True}
        path=self.root/'native-receipt.json';path.write_text(json.dumps(receipt));path.chmod(0o600)
        status={'owner_accepted':True,'session_id':self.key,'owner_identity':self.ident,'application_identities':[self.ident]}
        with mock.patch.object(O,'control_request',return_value=status):
            accepted=O.reconciled_acceptance(path,manifest,self.root/'handoff.sock')
        self.assertTrue(accepted['accepted']);self.assertTrue(accepted['reconciled_lost_ack'])
        self.assertEqual(accepted['receipt_sha256'],hashlib.sha256(path.read_bytes()).hexdigest())
        with mock.patch.object(O,'control_request',return_value={**status,'owner_accepted':False}),self.assertRaisesRegex(ValueError,'live native broker'):
            O.reconciled_acceptance(path,manifest,self.root/'handoff.sock')
        wrong={**receipt,'application_identities':[{**self.ident,'start_ticks':self.ident['start_ticks']+1}]};path.write_text(json.dumps(wrong))
        with mock.patch.object(O,'control_request',return_value=status),self.assertRaisesRegex(ValueError,'receipt does not match'):
            O.reconciled_acceptance(path,manifest,self.root/'handoff.sock')


if __name__=='__main__':unittest.main(verbosity=2)
