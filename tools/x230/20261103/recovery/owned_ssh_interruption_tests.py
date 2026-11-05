#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Safety guards for the optional canary; every signal and pidfd is mocked."""
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import owned_ssh_interruption as subject


class MasterArguments(unittest.TestCase):
    def setUp(self):
        self.profile = {"ssh_config": "/private/run/profile/ssh_config",
                        "agent_socket": "/private/held-agent", "known_hosts": "/private/run/known_hosts",
                        "socket_parent": "/private/sockets"}
        self.path = "/private/sockets/hp-o-123-" + "a" * 32 + "/m-7"
        options = {"ControlMaster": "yes", "ControlPersist": "no", "ForkAfterAuthentication": "no",
                   "ProxyCommand": "none", "ProxyJump": "none", "ForwardAgent": "no",
                   "IdentityAgent": self.profile["agent_socket"],
                   "UserKnownHostsFile": self.profile["known_hosts"], "ControlPath": self.path}
        self.argv = ["/usr/bin/ssh", "-F", self.profile["ssh_config"], "-T"]
        for key, value in options.items():
            self.argv += ["-o", key + "=" + value]
        self.argv += ["-N", "-n", "--", "fixed-host"]

    def check(self, argv=None, controller=123, target="fixed-host"):
        return subject.master_control_path(argv or self.argv, controller, target, self.profile)

    def test_exact_private_master_is_recognized(self):
        self.assertEqual(self.check(), Path(self.path))

    def test_other_host_or_controller_is_refused(self):
        for kwargs in ({"controller": 124}, {"target": "another-host"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(RuntimeError):
                self.check(**kwargs)

    def test_slave_and_duplicate_options_are_refused(self):
        slave = ["ControlMaster=no" if x == "ControlMaster=yes" else x for x in self.argv]
        duplicate = self.argv[:-2] + ["-o", "ControlMaster=yes"] + self.argv[-2:]
        for argv in (slave, duplicate):
            with self.subTest(argv=argv), self.assertRaises(RuntimeError):
                self.check(argv)

    def test_unexpected_flags_or_socket_escape_are_refused(self):
        extra_flag = self.argv[:-2] + ["-f"] + self.argv[-2:]
        escaped = ["ControlPath=/private/sockets/../elsewhere/m-7"
                   if x.startswith("ControlPath=") else x for x in self.argv]
        wrong_profile = list(self.argv)
        wrong_profile[2] = "/other/ssh_config"
        for argv in (extra_flag, escaped, wrong_profile):
            with self.subTest(argv=argv), self.assertRaises(RuntimeError):
                self.check(argv)


class PinnedSignal(unittest.TestCase):
    def setUp(self):
        self.controller = SimpleNamespace(child=SimpleNamespace(pid=123))
        self.original = {"pid": 456, "birth_ticks": 1000}

    def test_identity_change_before_pinning_never_signals(self):
        with patch.object(subject, "verify_master", return_value={}), \
                patch.object(subject.os, "pidfd_open") as pin, \
                patch.object(subject.signal, "pidfd_send_signal") as send:
            with self.assertRaises(RuntimeError):
                subject.interrupt_master(self.controller, "fixed-host", {}, self.original)
            pin.assert_not_called()
            send.assert_not_called()

    def test_identity_change_after_pinning_closes_without_signalling(self):
        with patch.object(subject, "verify_master", side_effect=[self.original, {}]), \
                patch.object(subject.os, "pidfd_open", return_value=77), \
                patch.object(subject.os, "close") as close, \
                patch.object(subject.signal, "pidfd_send_signal") as send:
            with self.assertRaises(RuntimeError):
                subject.interrupt_master(self.controller, "fixed-host", {}, self.original)
            send.assert_not_called()
            close.assert_called_once_with(77)

    def test_original_pidfd_is_signalled_once_and_retained_to_terminal_observation(self):
        poller = MagicMock()
        poller.poll.return_value = [(77, subject.select.POLLIN)]
        with patch.object(subject, "verify_master", return_value=self.original), \
                patch.object(subject.os, "pidfd_open", return_value=77), \
                patch.object(subject.os, "close") as close, \
                patch.object(subject.select, "poll", return_value=poller), \
                patch.object(subject.signal, "pidfd_send_signal") as send:
            result = subject.interrupt_master(self.controller, "fixed-host", {}, self.original)
            send.assert_called_once_with(77, subject.signal.SIGKILL)
            close.assert_called_once_with(77)
            self.assertTrue(result["pidfd_terminal_observed"])
            self.assertFalse(result["socket_removed_by_harness"])


if __name__ == "__main__":
    unittest.main()
