# SPDX-License-Identifier: LGPL-3.0-or-later
"""The client must not accumulate state for jobs it will never be asked about.

The server sends `core.get_jobs` events for every job the credentials can read, so a
long-lived client sees jobs started by every other client on the system.
"""
import unittest
from collections import defaultdict
from threading import Event, Lock

from truenas_api_client import Call, JSONRPCClient, Job
from truenas_api_client.config import UNCLAIMED_JOBS_MAX
from truenas_api_client.legacy import LegacyClient, Job as LegacyJob


def _bare(cls, **attrs):
    obj = object.__new__(cls)
    for name, value in attrs.items():
        setattr(obj, name, value)
    return obj


def _current(new_style=True):
    client = _bare(JSONRPCClient, _calls={}, _jobs=defaultdict(dict), _jobs_lock=Lock(),
                   _unclaimed_jobs={}, _new_style_jobs=new_style,
                   _event_callbacks=defaultdict(list))
    client._event_callbacks['core.get_jobs'].append(
        {'callback': client._jobs_callback, 'sync': True, 'event': Event()}
    )
    return client


def _legacy():
    return _bare(LegacyClient, _calls={}, _jobs=defaultdict(dict), _jobs_lock=Lock(),
                 _unclaimed_jobs={})


def _fields(job_id, state, message_ids, result=None):
    return {'id': job_id, 'message_ids': message_ids, 'method': 'pool.dataset.query',
            'arguments': [], 'state': state, 'result': result, 'error': None, 'exception': None,
            'exc_info': None, 'logs_excerpt': None,
            'progress': {'percent': 100, 'description': '', 'extra': None}}


def _run(client, job_id, message_ids, result=None):
    for state in ('RUNNING', 'SUCCESS'):
        fields = _fields(job_id, state, message_ids, result)
        client._recv({'method': 'collection_update', 'params': {
            'collection': 'core.get_jobs', 'msg': 'changed', 'id': job_id, 'fields': fields,
        }})


class TestForeignJobsDropped(unittest.TestCase):
    """Jobs belonging to other clients leave nothing behind."""

    def test_current(self):
        client = _current()
        for job_id in range(500):
            _run(client, job_id, ['another-clients-message-id'], result='x' * 512)

        self.assertEqual(len(client._jobs), 0)

    def test_legacy_keeps_bounded_window(self):
        client = _legacy()
        for job_id in range(500):
            client._jobs_callback('CHANGED', fields=_fields(job_id, 'SUCCESS', [], 'x' * 512))

        self.assertLessEqual(len(client._jobs), UNCLAIMED_JOBS_MAX)


class TestOurJobsKept(unittest.TestCase):
    """A job this client started is still delivered, even if it finishes first."""

    def test_result_arrives_before_job_object_exists(self):
        client = _current()
        call = Call('pool.scrub.run', (), wants_job=True)
        client._calls[call.id] = call

        _run(client, 42, [call.id], result='done')

        self.assertEqual(call.job_id, 42)
        self.assertEqual(Job(client, call.result).result(), 'done')
        self.assertEqual(len(client._jobs), 0)

    def test_legacy_result_arrives_before_job_object_exists(self):
        client = _legacy()
        client._jobs_callback('CHANGED', fields=_fields(7, 'SUCCESS', [], 'done'))

        self.assertEqual(LegacyJob(client, 7).result(), 'done')
        self.assertEqual(len(client._jobs), 0)


class TestFireAndForgetJob(unittest.TestCase):
    """Calling a job method without `job=` returns the job id and keeps no state."""

    def test_current(self):
        client = _current()
        for job_id in range(500):
            call = Call('pool.scrub.run', (), wants_job=False)
            client._calls[call.id] = call
            _run(client, job_id, [call.id], result='x' * 512)
            self.assertEqual(call.result, job_id)

        self.assertEqual(len(client._jobs), 0)
        self.assertEqual(len(client._calls), 0)


if __name__ == '__main__':
    unittest.main()
