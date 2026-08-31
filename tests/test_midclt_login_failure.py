# SPDX-License-Identifier: LGPL-3.0-or-later
"""Regression test: `midclt call` must report a login failure as a failure.

A rejected login previously printed to stdout and exited 0, so shell callers reading the exit
code or capturing stdout saw a successful, JSON-producing run. It must now write to stderr and
exit non-zero.
"""
import contextlib
import io
import sys
import unittest
from unittest import mock

import truenas_api_client


class TestMidcltLoginFailureExit(unittest.TestCase):
    def _run_main(self, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, 'argv', argv), \
                mock.patch.object(truenas_api_client, 'Client') as mock_client, \
                contextlib.redirect_stdout(stdout), \
                contextlib.redirect_stderr(stderr):
            # `with Client(...) as c:` -> c is the entered context manager. Make login fail.
            mock_client.return_value.__exit__.return_value = False  # do not swallow SystemExit
            c = mock_client.return_value.__enter__.return_value
            c.login_with_password.side_effect = ValueError('Invalid username or password')
            c.login_with_api_key.side_effect = ValueError('Invalid API key')
            with self.assertRaises(SystemExit) as ctx:
                truenas_api_client.main()
        return ctx.exception.code, stdout.getvalue(), stderr.getvalue()

    def test_password_login_failure_exits_nonzero_on_stderr(self):
        code, out, err = self._run_main(
            ['midclt', '-u', 'ws://h/api/current', '-U', 'admin', '-P', 'wrong', 'call', 'system.info']
        )
        self.assertEqual(code, 1)
        self.assertIn('Failed to login', err)
        self.assertNotIn('Failed to login', out)

    def test_api_key_login_failure_exits_nonzero_on_stderr(self):
        code, out, err = self._run_main(
            ['midclt', '-u', 'ws://h/api/current', '-K', '1-badkey', 'call', 'system.info']
        )
        self.assertEqual(code, 1)
        self.assertIn('Failed to login', err)
        self.assertNotIn('Failed to login', out)


if __name__ == '__main__':
    unittest.main()
