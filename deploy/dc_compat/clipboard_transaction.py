# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Worker-thread portal clipboard transactions; original data stays private.

The portal has no compare-and-set operation and cannot restore another process'
ownership. We restore an offer serving every snapshotted original MIME byte,
unless a foreign owner change was observed. Keep this object and pump its signal
callbacks while idle: a restored offer is lazy and must outlive run(). No action
is replayed, including after a failed paste or uncertain restoration.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import fcntl
import hashlib
import math
import os
import pathlib
import select
import stat
import threading
import time
import uuid

from .processes import _private_root, _publish, _read_file
from .registry import ToolError

CLIPBOARD = 'org.freedesktop.portal.Clipboard'
TEXT_MIMES = ('text/plain;charset=utf-8', 'text/plain')


class ClipboardTransactionError(ToolError):
    """Only receipt metadata is safe for a public tool response."""
    def __init__(self, reason, receipt):
        self.receipt = dict(receipt, failure_reason=reason, automatic_retry=False)
        super().__init__('Clipboard transaction ' + reason + '; no automatic retry; original data remains private')


@dataclass
class _Offer:
    kind: str
    session: str
    mimes: tuple
    data: dict | None = None
    backup_id: str | None = None
    entries: dict = field(default_factory=dict)
    published_epoch: int = -1


class ClipboardTransaction:
    """Call exclusively on the portal worker, including both signal methods.

    call has _Portal._call's signature. pump(seconds) dispatches the same worker
    context. paste(keys) validates then submits one physical combo and releases
    it even on error. make_options(mimes) creates {'mime_types': Variant('as',...)}.
    max_snapshot_bytes is an explicit administrator budget, never a truncation.
    MIME count/name budgets default to 256/1024 UTF-8 bytes and are configurable;
    an offer exceeding either is refused whole before any clipboard write.
    The caller must feed complete SelectionOwnerChanged signals from the initial
    RequestClipboard/Start, not construct an offer from a UTF-8-only read.
    """
    def __init__(self, call, pump, paste, session_getter, state_dir, *,
                 max_snapshot_bytes, make_options, timeout_seconds=5.0,
                 max_mime_types=256, max_mime_name_bytes=1024):
        if type(max_snapshot_bytes) is not int or max_snapshot_bytes < 0:
            raise ValueError('An explicit nonnegative clipboard snapshot byte budget is required')
        if not isinstance(timeout_seconds, (int, float)) or not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError('A positive finite transfer timeout is required')
        if not all(callable(x) for x in (call, pump, paste, session_getter, make_options)):
            raise ValueError('Clipboard worker callbacks are required')
        if (type(max_mime_types) is not int or max_mime_types <= 0
                or type(max_mime_name_bytes) is not int or max_mime_name_bytes <= 0):
            raise ValueError('Positive administrator MIME metadata budgets are required')
        self.call, self.pump, self.paste = call, pump, paste
        self.session_getter, self.make_options = session_getter, make_options
        self.max_snapshot_bytes, self.timeout = max_snapshot_bytes, float(timeout_seconds)
        self.max_mime_types, self.max_mime_name_bytes = max_mime_types, max_mime_name_bytes
        self.state_dir = pathlib.Path(state_dir)
        self.directory = _private_root(self.state_dir)
        self.root_identity = (os.fstat(self.directory).st_dev, os.fstat(self.directory).st_ino)
        self.owner_fd = None
        try:
            self.owner_fd = os.open('owner.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                                    0o600, dir_fd=self.directory)
            info = os.fstat(self.owner_fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                raise ToolError('Unsafe clipboard transaction owner lock')
            fcntl.flock(self.owner_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            if self.owner_fd is not None:
                os.close(self.owner_fd)
            os.close(self.directory)
            raise
        self.thread = None
        self.epoch = self.external_epoch = 0
        self.observed = None
        self.serving = None
        self.active = None
        self.pending = deque()
        self.transferring = False
        self.seen_serials = set()
        self.closed = False

    def _worker(self):
        if self.closed:
            raise ToolError('Clipboard transaction owner is closed')
        current = threading.get_ident()
        if self.thread is None:
            self.thread = current
        elif current != self.thread:
            raise ToolError('Clipboard transactions must stay on one portal worker')

    def _guard(self):
        self._worker()
        fd = os.open('/', os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for part in self.state_dir.parts[1:]:
                following = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd)
                fd = following
            info = os.fstat(fd)
            if ((info.st_dev, info.st_ino) != self.root_identity or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise ToolError('Clipboard backup root changed')
            current = os.stat('owner.lock', dir_fd=self.directory, follow_symlinks=False)
            owner = os.fstat(self.owner_fd)
            if ((current.st_dev, current.st_ino) != (owner.st_dev, owner.st_ino) or current.st_nlink != 1
                    or not stat.S_ISREG(current.st_mode) or current.st_uid != os.getuid()
                    or stat.S_IMODE(current.st_mode) != 0o600):
                raise ToolError('Clipboard backup owner changed')
        finally:
            os.close(fd)

    def _mimes(self, value):
        # GNOME 46 emits a tuple-wrapped (as), despite the portal docs saying
        # as: Mutter g_variant_new("(^as)") and the GNOME backend's explicit
        # G_VARIANT_TYPE("(as)") forwarding. Accept precisely that known form.
        if isinstance(value, tuple) and len(value) == 1 and isinstance(value[0], (list, tuple)):
            value = value[0]
        if (not isinstance(value, (list, tuple)) or not 1 <= len(value) <= self.max_mime_types
                or any(not isinstance(x, str) or not x or '\x00' in x for x in value)
                or len(value) != len(set(value))):
            return None
        try:
            if any(len(x.encode('utf-8')) > self.max_mime_name_bytes for x in value):
                return None
        except UnicodeError:
            return None
        return tuple(value)

    def selection_changed(self, session, options):
        self._worker()
        if session != self.session_getter():
            return False
        self.epoch += 1
        options = options if isinstance(options, dict) else {}
        owned = options.get('session_is_owner')
        owned = owned if type(owned) is bool else None
        mimes = self._mimes(options.get('mime_types'))
        # Own announcements can omit mime_types. Only our explicit outstanding
        # publication provides the complete offer in that case.
        if mimes is None and 'mime_types' not in options and owned is True and self.serving is not None:
            mimes = self.serving.mimes
        self.observed = {'session': session, 'epoch': self.epoch, 'owned': owned, 'mimes': mimes}
        if owned is not True:
            self.external_epoch += 1
            self.serving = None
        return True

    def _owned(self, offer):
        value = self.observed
        return bool(value and self.session_getter() == offer.session == value['session']
                    and value['owned'] is True and value['epoch'] > offer.published_epoch
                    and value['mimes'] is not None and set(value['mimes']) == set(offer.mimes))

    def _same_snapshot_owner(self, epoch, session):
        self.pump(0)
        if self.epoch != epoch or self.session_getter() != session:
            raise ToolError('Clipboard owner changed during snapshot')

    def _read_fd(self, fd, target, digest, remaining, epoch, session):
        os.set_blocking(fd, False)
        total = 0
        deadline = time.monotonic() + self.timeout
        while True:
            self._same_snapshot_owner(epoch, session)
            if time.monotonic() >= deadline:
                raise TimeoutError('Clipboard source did not finish')
            if not select.select([fd], [], [], min(.01, max(0, deadline - time.monotonic())))[0]:
                self.pump(.001)
                continue
            try:
                block = os.read(fd, min(65536, remaining - total + 1))
            except BlockingIOError:
                continue
            if not block:
                return total
            if total + len(block) > remaining:
                raise OverflowError('Clipboard snapshot budget exceeded')
            target.write(block)
            digest.update(block)
            total += len(block)

    def _original_data(self, offer, mime):
        self._guard()
        if offer.data is not None:
            return offer.data[mime]
        folder = os.open(offer.backup_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=self.directory)
        try:
            info = os.fstat(folder)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ToolError('Unsafe private clipboard snapshot')
            item = offer.entries[mime]
            raw = _read_file(folder, item['file'], self.max_snapshot_bytes)
            if len(raw) != item['bytes'] or hashlib.sha256(raw).hexdigest() != item['sha256']:
                raise ToolError('Private original clipboard bytes changed')
            return raw
        finally:
            os.close(folder)

    def _snapshot(self, session, epoch, mimes):
        if self.observed['owned'] is True:
            old = self.serving
            if old is None or old.kind not in ('restored_original', 'explicit_text') or not self._owned(old):
                raise ToolError('Current session offer has no complete original snapshot')
            if old.kind == 'restored_original':
                if sum(row['bytes'] for row in old.entries.values()) > self.max_snapshot_bytes:
                    raise OverflowError('Clipboard snapshot budget exceeded')
                for mime in mimes:
                    self._original_data(old, mime)
                    self._same_snapshot_owner(epoch, session)
                return old
        else:
            old = None
        identity = 'clipboard-' + uuid.uuid4().hex
        self.active['backup_id'] = identity
        os.mkdir(identity, 0o700, dir_fd=self.directory)
        folder = os.open(identity, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.directory)
        entries, total = {}, 0
        try:
            _publish(folder, 'snapshot.json', {'version': 1, 'complete': False})
            for index, mime in enumerate(mimes):
                self._same_snapshot_owner(epoch, session)
                source = None
                target = None
                try:
                    name = f'format-{index:06d}.bin'
                    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                         0o600, dir_fd=folder)
                    digest = hashlib.sha256()
                    target = os.fdopen(descriptor, 'wb')
                    if old is not None:
                        raw = self._original_data(old, mime)
                        if total + len(raw) > self.max_snapshot_bytes:
                            raise OverflowError('Clipboard snapshot budget exceeded')
                        target.write(raw)
                        digest.update(raw)
                        count = len(raw)
                    else:
                        source = self.call(CLIPBOARD, 'SelectionRead', '(os)', (session, mime), fd=True)
                        count = self._read_fd(source, target, digest, self.max_snapshot_bytes - total, epoch, session)
                    target.flush()
                    os.fsync(target.fileno())
                    entries[mime] = {'file': name, 'bytes': count, 'sha256': digest.hexdigest()}
                    total += count
                finally:
                    if source is not None:
                        os.close(source)
                    if target is not None:
                        target.close()
            self._same_snapshot_owner(epoch, session)
            _publish(folder, 'snapshot.json', {'version': 1, 'complete': True, 'entries': entries})
            os.fsync(self.directory)
        finally:
            os.close(folder)
        return _Offer('restored_original', session, mimes, backup_id=identity, entries=entries)

    def _publish_offer(self, offer, *, expected_epoch=None, expected_foreign=None):
        self._guard()
        self.pump(0)
        if ((expected_epoch is not None and self.epoch != expected_epoch)
                or (expected_foreign is not None and self.external_epoch != expected_foreign)
                or self.session_getter() != offer.session):
            raise ToolError('Clipboard changed before publication')
        offer.published_epoch = self.epoch
        self.serving = offer
        self.call(CLIPBOARD, 'SetSelection', '(oa{sv})', (offer.session, self.make_options(offer.mimes)))

    def _wait_owned(self, offer, foreign_epoch):
        deadline = time.monotonic() + self.timeout
        while True:
            if self.external_epoch != foreign_epoch or self.session_getter() != offer.session:
                raise ToolError('Clipboard ownership changed')
            if self._owned(offer):
                return
            if time.monotonic() >= deadline:
                raise TimeoutError('Clipboard ownership was not confirmed')
            self.pump(.01)

    def selection_transfer(self, session, mime, serial):
        self._worker()
        if session != self.session_getter() or self.serving is None:
            return False
        key = (session, serial)
        if key in self.seen_serials:
            return True
        self.seen_serials.add(key)
        self.pending.append((self.serving, mime, serial))
        if self.transferring:
            return True
        self.transferring = True
        try:
            while self.pending:
                self._transfer(*self.pending.popleft())
        finally:
            self.transferring = False
        return True

    def _transfer(self, offer, mime, serial):
        fd, success, count, done = None, False, 0, False
        try:
            if type(serial) is not int or not 0 <= serial <= 0xffffffff or not self._owned(offer):
                raise ToolError('Unowned clipboard transfer')
            # Verify all original bytes before writing any part to a consumer.
            data = self._original_data(offer, mime)
            fd = self.call(CLIPBOARD, 'SelectionWrite', '(ou)', (offer.session, serial), fd=True)
            os.set_blocking(fd, False)
            deadline = time.monotonic() + self.timeout
            while count < len(data):
                self.pump(0)
                if self.serving is not offer or not self._owned(offer):
                    raise ToolError('Clipboard ownership changed during transfer')
                if time.monotonic() >= deadline:
                    raise TimeoutError('Clipboard consumer did not finish')
                if select.select([], [fd], [], .01)[1]:
                    try:
                        count += os.write(fd, memoryview(data)[count:count + 65536])
                    except BlockingIOError:
                        continue
            os.close(fd)
            fd = None
            success = True
        except Exception:
            success = False
        finally:
            if fd is not None:
                os.close(fd)
            try:
                self.call(CLIPBOARD, 'SelectionWriteDone', '(oub)', (offer.session, serial, success))
                done = True
            except Exception:
                success = False
            if self.active is not None and offer.kind == 'temporary_text':
                self.active['transfers'].append({'serial': serial, 'bytes_written': count,
                    'complete': success, 'selection_write_done': done})

    def _restore(self, original, temporary, foreign_epoch):
        self.pump(0)
        if self.external_epoch != foreign_epoch:
            return 'external_owner_changed_not_overwritten'
        if not self._owned(temporary) or self.serving is not temporary:
            return 'ownership_unconfirmed_not_overwritten'
        for mime in original.mimes:
            self._original_data(original, mime)
        self.pump(0)
        if self.external_epoch != foreign_epoch or not self._owned(temporary):
            return 'external_owner_changed_not_overwritten'
        self._publish_offer(original, expected_epoch=self.epoch, expected_foreign=foreign_epoch)
        self._wait_owned(original, foreign_epoch)
        if self.external_epoch != foreign_epoch:
            return 'external_change_observed_during_restore'
        return 'complete_original_mime_offer_serving'

    def run(self, text, paste_keys=('CTRL', 'V')):
        self._worker()
        receipt = {'transaction_id': uuid.uuid4().hex, 'paste_attempted': False,
            'clipboard_publication_attempted': False, 'original_bytes_snapshot_complete': False,
            'original_bytes_offer_restored': False, 'original_owner_restored': False,
            'atomic_compare_and_set_available': False, 'backup_retained': False,
            'automatic_retry': False, 'target_input_verified': False,
            'transfer_consumer_identity_known': False, 'transfers': []}
        if self.active is not None:
            raise ClipboardTransactionError('already_active', receipt)
        if (not isinstance(text, str) or '\x00' in text or not isinstance(paste_keys, (list, tuple))
                or not paste_keys or any(not isinstance(x, str) or not x or '\x00' in x for x in paste_keys)):
            raise ClipboardTransactionError('invalid_input', receipt)
        self.active = {'transfers': [], 'backup_id': None}
        original = temporary = None
        failure = None
        foreign_epoch = self.external_epoch
        try:
            self._guard()
            self.pump(0)
            value, session = self.observed, self.session_getter()
            if (not session or not value or value['session'] != session or value['mimes'] is None
                    or value['owned'] is None):
                raise ToolError('Complete initial clipboard offer is unavailable')
            epoch, foreign_epoch = self.epoch, self.external_epoch
            original = self._snapshot(session, epoch, value['mimes'])
            receipt['original_bytes_snapshot_complete'] = True
            self.active['backup_id'] = original.backup_id
            self._same_snapshot_owner(epoch, session)
            temporary = _Offer('temporary_text', session, TEXT_MIMES, data={mime: text.encode('utf-8') for mime in TEXT_MIMES})
            receipt['clipboard_publication_attempted'] = True
            self._publish_offer(temporary, expected_epoch=epoch, expected_foreign=foreign_epoch)
            self._wait_owned(temporary, foreign_epoch)
            # The protocol does not identify readers. Only a transfer observed
            # after the single paste attempt is useful evidence; it still is
            # not proof that the intended application accepted the text.
            self.active['transfers'].clear()
            receipt['paste_attempted'] = True
            self.paste(tuple(paste_keys))
            deadline = time.monotonic() + self.timeout
            while not self.active['transfers']:
                if self.external_epoch != foreign_epoch or not self._owned(temporary):
                    raise ToolError('Clipboard changed while pasting')
                if time.monotonic() >= deadline:
                    raise TimeoutError('No target clipboard transfer completed')
                self.pump(.01)
            if not any(item['complete'] and item['selection_write_done'] for item in self.active['transfers']):
                raise ToolError('Target clipboard transfer was not complete')
        except Exception as error:
            failure = 'snapshot_budget_exceeded' if isinstance(error, OverflowError) else (
                'transfer_or_owner_timeout' if isinstance(error, TimeoutError) else 'snapshot_or_transaction_refused')
        finally:
            if temporary is not None and receipt['clipboard_publication_attempted']:
                try:
                    restoration = self._restore(original, temporary, foreign_epoch)
                except Exception:
                    restoration = 'restore_failed_private_backup_retained'
                receipt['restoration'] = restoration
                receipt['original_bytes_offer_restored'] = restoration == 'complete_original_mime_offer_serving'
                if not receipt['original_bytes_offer_restored']:
                    failure = failure or 'original_offer_not_restored'
            else:
                receipt['restoration'] = 'not_needed_no_clipboard_publication'
            receipt['transfers'] = list(self.active['transfers'])
            receipt['backup_retained'] = self.active['backup_id'] is not None
            self.active = None
        if failure is not None:
            raise ClipboardTransactionError(failure, receipt)
        return receipt

    def offer_text(self, text):
        """An explicit clipboard-set action, without pretending to restore it."""
        self._worker()
        if self.active is not None or not isinstance(text, str) or '\x00' in text:
            raise ToolError('Invalid or overlapping explicit clipboard set')
        session = self.session_getter()
        if not session:
            raise ToolError('No clipboard session')
        offer = _Offer('explicit_text', session, TEXT_MIMES, data={m: text.encode('utf-8') for m in TEXT_MIMES})
        foreign = self.external_epoch
        self._publish_offer(offer)
        self._wait_owned(offer, foreign)
        return {'characters': len(text)}

    def reset(self):
        """Call only after portal session close/revocation; backups are retained."""
        self._worker()
        if self.active is not None or self.serving is not None and self.session_getter():
            raise ToolError('Cannot reset an active transaction or a live lazy clipboard offer')
        self.observed = self.serving = None
        self.pending.clear()
        self.seen_serials.clear()
        self.epoch += 1
        self.external_epoch += 1

    def close(self):
        if self.closed:
            return
        self._worker()
        if self.active is not None or self.serving is not None and self.session_getter():
            raise ToolError('Close the portal session before releasing its lazy clipboard offer')
        self.reset()
        os.close(self.owner_fd)
        os.close(self.directory)
        self.closed = True
