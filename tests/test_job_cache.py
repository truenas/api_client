# SPDX-License-Identifier: LGPL-3.0-or-later
"""The client must not keep a record of every job it ever hears about.

A connection is subscribed to `core.get_jobs` the first time it makes a call. The job update
handler saves the last update of each job so that a `Job` built for it can hand back the
result. Jobs started by other clients, and the periodic jobs middleware runs on its own, arrive
on that same subscription. Nobody on this side waits for those, so once they finish their
records have to go. A connection that stays open on a busy system otherwise keeps every job it
ever saw. A console left open for 77 days reached 56 GB this way.
"""

import unittest
from collections import defaultdict
from threading import Lock

from truenas_api_client import JSONRPCClient, Job
from truenas_api_client.legacy import LegacyClient, Job as LegacyJob


def _bare(cls, **attrs):
    """Build an instance without running __init__ (which would open a connection)."""
    obj = object.__new__(cls)
    for name, value in attrs.items():
        setattr(obj, name, value)
    return obj


def _current():
    """JSONRPCClient with no socket. Server messages are pushed in with `_recv`."""
    return _bare(
        JSONRPCClient,
        _calls={},
        _jobs=defaultdict(dict),
        _jobs_lock=Lock(),
        _jobs_watching=False,
        _new_style_jobs=True,
        _event_callbacks=defaultdict(list),
        _set_options_call=None,
        _call_timeout=5,
        _log_py_exceptions=False,
        _py_exceptions=False,
    )


def _job_update(msg, job_id, state, message_ids=(), result=None):
    """A `core.get_jobs` notification shaped like middleware sends it."""
    return {
        "jsonrpc": "2.0",
        "method": "collection_update",
        "params": {
            "collection": "core.get_jobs",
            "msg": msg,
            "id": job_id,
            "fields": {
                "id": job_id,
                "message_ids": list(message_ids),
                "method": "ipmi.sel.elist",
                "state": state,
                "progress": {
                    "percent": 100 if state == "SUCCESS" else 0,
                    "description": "",
                    "extra": None,
                },
                "result": result,
                "error": None,
                "exception": None,
                "exc_info": None,
            },
        },
    }


def _response(call_id, result):
    return {"jsonrpc": "2.0", "id": call_id, "result": result}


class _FakeServer:
    """Answers whatever the client sends, synchronously, by pushing replies into `client._recv`.

    Job methods are answered the way middleware does with new style jobs. The job is announced
    with the request id in `message_ids` and then finishes right away. All of that lands before
    `call()` gets a chance to build a `Job`, which is the race the client has to survive.
    """

    def __init__(self, client, jobs):
        self.client = client
        self.jobs = jobs
        self.next_job_id = 1
        client._send = self.send

    def send(self, data):
        method = data["method"]
        if method == "core.subscribe":
            self.client._recv(_response(data["id"], "subscription id"))
        elif method in self.jobs:
            job_id = self.next_job_id
            self.next_job_id += 1
            self.client._recv(
                _job_update("added", job_id, "WAITING", message_ids=[data["id"]])
            )
            self.client._recv(
                _job_update("changed", job_id, "RUNNING", message_ids=[data["id"]])
            )
            self.client._recv(
                _job_update(
                    "changed",
                    job_id,
                    "SUCCESS",
                    message_ids=[data["id"]],
                    result=self.jobs[method],
                )
            )
        else:
            self.client._recv(_response(data["id"], f"{method} result"))


def _subscribed_client():
    """A client that has made one plain call, which is all it takes to be subscribed to jobs."""
    client = _current()
    _FakeServer(client, jobs={"pool.scrub.scrub": "scrub done"})
    client.call("system.info")
    return client


class TestForeignJobsAreForgotten(unittest.TestCase):
    """Jobs nobody on this side is waiting for must not pile up."""

    def test_finished_jobs_are_dropped(self):
        client = _subscribed_client()

        # Middleware runs ipmi.sel.elist every five minutes by itself. Each run carries the whole
        # system event log as its result. Over months this is what filled the console CLI.
        for job_id in range(1, 1001):
            client._recv(_job_update("added", job_id, "WAITING"))
            client._recv(_job_update("changed", job_id, "RUNNING"))
            client._recv(
                _job_update("changed", job_id, "SUCCESS", result=["sel entry"] * 100)
            )

        self.assertEqual(
            len(client._jobs), 0, f"{len(client._jobs)} finished jobs are still held"
        )

    def test_failed_and_aborted_jobs_are_dropped(self):
        client = _subscribed_client()

        client._recv(_job_update("added", 1, "WAITING"))
        client._recv(_job_update("changed", 1, "FAILED"))
        client._recv(_job_update("added", 2, "WAITING"))
        client._recv(_job_update("changed", 2, "ABORTED"))

        self.assertEqual(len(client._jobs), 0)

    def test_running_jobs_are_kept_until_they_finish(self):
        client = _subscribed_client()

        client._recv(_job_update("added", 1, "WAITING"))
        client._recv(_job_update("changed", 1, "RUNNING"))
        self.assertIn(1, client._jobs)

        client._recv(_job_update("changed", 1, "SUCCESS"))
        self.assertNotIn(1, client._jobs)

    def test_job_started_without_the_job_flag_is_not_kept(self):
        client = _subscribed_client()

        job_id = client.call("pool.scrub.scrub", 1, "START")

        self.assertEqual(job_id, 1)
        self.assertEqual(len(client._jobs), 0)


class TestOwnJobsStillWork(unittest.TestCase):
    """Dropping finished jobs must not lose the ones this client asked for and is waiting on."""

    def test_job_that_finishes_before_wait_returns_its_result(self):
        client = _current()
        _FakeServer(client, jobs={"pool.scrub.scrub": "scrub done"})

        self.assertEqual(
            client.call("pool.scrub.scrub", 1, "START", job=True), "scrub done"
        )
        self.assertEqual(len(client._jobs), 0)

    def test_returned_job_object_hands_back_the_result(self):
        client = _current()
        _FakeServer(client, jobs={"pool.scrub.scrub": "scrub done"})

        job = client.call("pool.scrub.scrub", 1, "START", job="RETURN")

        self.assertIsInstance(job, Job)
        self.assertEqual(job.result(), "scrub done")
        self.assertEqual(len(client._jobs), 0)

    def test_job_built_before_it_finishes_still_returns_its_result(self):
        client = _subscribed_client()
        client._recv(_job_update("added", 7, "WAITING"))
        job = Job(client, 7)

        client._recv(_job_update("changed", 7, "SUCCESS", result="late result"))

        self.assertEqual(job.result(), "late result")
        self.assertEqual(len(client._jobs), 0)


def _legacy():
    """LegacyClient with no socket that is already subscribed to job updates."""
    return _bare(
        LegacyClient,
        _calls={},
        _jobs=defaultdict(dict),
        _jobs_lock=Lock(),
        _jobs_watching=True,
        _event_callbacks=defaultdict(list),
        _pings={},
        _call_timeout=5,
        _log_py_exceptions=False,
        _py_exceptions=False,
    )


def _legacy_fields(job_id, state, result=None):
    return {
        "id": job_id,
        "method": "ipmi.sel.elist",
        "state": state,
        "result": result,
        "progress": {
            "percent": 100 if state == "SUCCESS" else 0,
            "description": "",
            "extra": None,
        },
        "error": None,
        "exception": None,
        "exc_info": None,
    }


class _FakeLegacyServer:
    """Answers a legacy job call with the job id and then finishes the job before `wait()` runs."""

    def __init__(self, client, jobs):
        self.client = client
        self.jobs = jobs
        self.next_job_id = 1
        client._send = self.send

    def send(self, data):
        method = data["method"]
        if method in self.jobs:
            job_id = self.next_job_id
            self.next_job_id += 1
            self.client._recv({"id": data["id"], "msg": "result", "result": job_id})
            self.client._jobs_callback(
                "ADDED", fields=_legacy_fields(job_id, "WAITING")
            )
            self.client._jobs_callback(
                "CHANGED", fields=_legacy_fields(job_id, "SUCCESS", self.jobs[method])
            )
        else:
            self.client._recv(
                {"id": data["id"], "msg": "result", "result": f"{method} result"}
            )


class TestLegacyForeignJobsAreForgotten(unittest.TestCase):
    """The legacy client shares the same job handling and the same problem."""

    def test_finished_jobs_are_dropped(self):
        client = _legacy()

        for job_id in range(1, 1001):
            client._jobs_callback("ADDED", fields=_legacy_fields(job_id, "WAITING"))
            client._jobs_callback("CHANGED", fields=_legacy_fields(job_id, "RUNNING"))
            client._jobs_callback(
                "CHANGED", fields=_legacy_fields(job_id, "SUCCESS", ["sel entry"] * 100)
            )

        self.assertEqual(
            len(client._jobs), 0, f"{len(client._jobs)} finished jobs are still held"
        )

    def test_running_jobs_are_kept_until_they_finish(self):
        client = _legacy()

        client._jobs_callback("ADDED", fields=_legacy_fields(1, "WAITING"))
        client._jobs_callback("CHANGED", fields=_legacy_fields(1, "RUNNING"))
        self.assertIn(1, client._jobs)

        client._jobs_callback("CHANGED", fields=_legacy_fields(1, "ABORTED"))
        self.assertNotIn(1, client._jobs)


class TestLegacyOwnJobsStillWork(unittest.TestCase):
    def test_job_that_finishes_before_wait_returns_its_result(self):
        client = _legacy()
        _FakeLegacyServer(client, jobs={"pool.scrub.scrub": "scrub done"})

        self.assertEqual(
            client.call("pool.scrub.scrub", 1, "START", job=True), "scrub done"
        )
        self.assertEqual(len(client._jobs), 0)

    def test_returned_job_object_hands_back_the_result(self):
        client = _legacy()
        _FakeLegacyServer(client, jobs={"pool.scrub.scrub": "scrub done"})

        job = client.call("pool.scrub.scrub", 1, "START", job="RETURN")

        self.assertIsInstance(job, LegacyJob)
        self.assertEqual(job.result(), "scrub done")
        self.assertEqual(len(client._jobs), 0)

    def test_job_started_without_the_job_flag_is_not_kept(self):
        client = _legacy()
        _FakeLegacyServer(client, jobs={"pool.scrub.scrub": "scrub done"})

        self.assertEqual(client.call("pool.scrub.scrub", 1, "START"), 1)
        self.assertEqual(len(client._jobs), 0)


if __name__ == "__main__":
    unittest.main()
