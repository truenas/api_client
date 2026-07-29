# SPDX-License-Identifier: LGPL-3.0-or-later
"""Job.result() and the connection-close error broadcast, for jobs that don't finish normally.

Both the current JSON-RPC client and the legacy client share this path, so both are covered.
"""
import errno
import unittest
from collections import defaultdict
from threading import Event, Lock

from truenas_api_client import JSONRPCClient, Job
from truenas_api_client.legacy import LegacyClient, Job as LegacyJob
from truenas_api_client.exc import ClientException, ValidationErrors


def _bare(cls, **attrs):
    """Build an instance without running __init__ (which would open a connection)."""
    obj = object.__new__(cls)
    for name, value in attrs.items():
        setattr(obj, name, value)
    return obj


def _current():
    return _bare(JSONRPCClient, _calls={}, _jobs=defaultdict(dict), _jobs_lock=Lock())


def _legacy():
    return _bare(LegacyClient, _calls={}, _jobs=defaultdict(dict), _jobs_lock=Lock(),
                 _connected=Event(), _closed=Event(), _connection_error=None)


class _MutatingEvent(Event):
    """Event whose set() inserts into `jobs`, simulating a job arriving during iteration."""

    def __init__(self, jobs):
        super().__init__()
        self._jobs = jobs

    def set(self):
        self._jobs['inserted-during-iteration'] = {}
        super().set()


class TestAbortedJobResult(unittest.TestCase):
    """An aborted job (no exc_info) reports failure via ClientException."""

    def _check(self, client, job_cls):
        job = job_cls(client, 'j1')
        client._jobs['j1'].update(state='ABORTED', exc_info=None, exception=None, error=None)
        client._jobs['j1']['__ready'].set()
        with self.assertRaises(ClientException):
            job.result()

    def test_current(self):
        self._check(_current(), Job)

    def test_legacy(self):
        self._check(_legacy(), LegacyJob)


class TestValidationJobResult(unittest.TestCase):
    """A validation-failed job surfaces as ValidationErrors, not a generic ClientException."""

    def _check(self, client, job_cls):
        job = job_cls(client, 'j1')
        client._jobs['j1'].update(
            state='FAILED',
            exc_info={'type': 'VALIDATION', 'repr': 'ValidationErrors',
                      'extra': [('field', 'is required', errno.EINVAL)]},
            exception='validation failed', error='validation failed')
        client._jobs['j1']['__ready'].set()
        with self.assertRaises(ValidationErrors):
            job.result()

    def test_current(self):
        self._check(_current(), Job)

    def test_legacy(self):
        self._check(_legacy(), LegacyJob)


class TestJobResultAfterDisconnect(unittest.TestCase):
    """A job left unfinished by a dropped connection reports failure via ClientException."""

    def test_current(self):
        c = _current()
        job = Job(c, 'j1')
        c._broadcast_error(ClientException('closed', errno.ECONNABORTED))
        with self.assertRaises(ClientException):
            job.result()

    def test_legacy(self):
        c = _legacy()
        job = LegacyJob(c, 'j1')
        c.on_close(1006)
        with self.assertRaises(ClientException):
            job.result()


class TestBroadcastConcurrentModification(unittest.TestCase):
    """The close-time broadcast tolerates the jobs dict being resized during iteration."""

    def test_current(self):
        c = _current()
        c._jobs['j1'] = {'__ready': _MutatingEvent(c._jobs)}
        c._broadcast_error(ClientException('closed', errno.ECONNABORTED))
        self.assertIn('inserted-during-iteration', c._jobs)

    def test_legacy(self):
        c = _legacy()
        c._jobs['j1'] = {'__ready': _MutatingEvent(c._jobs)}
        c.on_close(1006)
        self.assertIn('inserted-during-iteration', c._jobs)


if __name__ == '__main__':
    unittest.main()
