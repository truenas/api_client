# SPDX-License-Identifier: LGPL-3.0-or-later
"""JSONRPCClient.wait() with `job` set, for calls that never became a trackable job.

With new-style jobs the server does not answer a job method with its id: the id arrives in a
`core.get_jobs` event, which `_process_message` uses to set `Call.job_id`. A method that is not a
job, and a job declared `transient=True`, produce no such event, so the call returns the method's
own result and there is no job to wait on.
"""
import unittest
from collections import defaultdict
from threading import Event, Lock

from truenas_api_client import Call, JSONRPCClient, Job
from truenas_api_client.exc import ClientException


def _client(new_style=True):
    """Build a client without running __init__, which would open a connection."""
    obj = object.__new__(JSONRPCClient)
    obj._calls = {}
    obj._jobs = defaultdict(dict)
    obj._jobs_lock = Lock()
    obj._call_timeout = 10
    obj._new_style_jobs = new_style
    return obj


def _returned(method='some.method', result=None, job_id=None):
    call = Call(method, ())
    call.result = result
    call.job_id = job_id
    call.returned.set()
    return call


class TestWaitWithoutTrackableJob(unittest.TestCase):
    """No `core.get_jobs` event named the call, so its own result is the answer."""

    def test_non_job_method_returns_its_result(self):
        client = _client()
        call = _returned('vm.start', result=True)

        self.assertIs(client.wait(call, job=True), True)

    def test_transient_job_returns_its_result(self):
        client = _client()
        call = _returned('pool.scrub', result=None)

        self.assertIsNone(client.wait(call, job=True))

    def test_int_result_is_not_mistaken_for_a_job_id(self):
        """The result of a non-job method can be an integer without being a job id."""
        client = _client()
        call = _returned('some.count', result=7)

        self.assertEqual(client.wait(call, job=True), 7)

    def test_job_return_raises_rather_than_waiting_forever(self):
        client = _client()
        call = _returned('vm.start', result=True)

        with self.assertRaises(ClientException):
            client.wait(call, job='RETURN')

    def test_call_is_unregistered(self):
        client = _client()
        call = _returned('vm.start', result=True)
        client._calls[call.id] = call

        client.wait(call, job=True)

        self.assertNotIn(call.id, client._calls)


class TestWaitWithTrackableJob(unittest.TestCase):
    """A `core.get_jobs` event set `job_id`, so the job is waited on as before."""

    def test_uses_job_id_not_result(self):
        client = _client()
        call = _returned('pool.import_pool', result=42, job_id=42)
        client._jobs[42].update(state='SUCCESS', result='done', __ready=Event())
        client._jobs[42]['__ready'].set()

        self.assertEqual(client.wait(call, job=True), 'done')

    def test_job_return_gives_the_job(self):
        client = _client()
        call = _returned('pool.import_pool', result=42, job_id=42)

        jobobj = client.wait(call, job='RETURN')

        self.assertIsInstance(jobobj, Job)
        self.assertEqual(jobobj.job_id, 42)


class TestLegacyJobs(unittest.TestCase):
    """Against a server without new-style jobs the id is the call's plain result."""

    def test_result_is_used_as_the_job_id(self):
        client = _client(new_style=False)
        call = _returned('pool.import_pool', result=42)

        jobobj = client.wait(call, job='RETURN')

        self.assertIsInstance(jobobj, Job)
        self.assertEqual(jobobj.job_id, 42)


if __name__ == '__main__':
    unittest.main()
