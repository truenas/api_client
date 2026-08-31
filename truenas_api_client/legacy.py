"""The websocket client prior to implementing JSONRPC-2.0 protocol. Used for backwards compatibility."""

from base64 import b64decode
from collections import defaultdict
import errno
import logging
import pickle
from threading import Event, Lock, Thread
import uuid

from websockets.exceptions import ConnectionClosed

from . import ejson as json
from .auth_api_key import APIKeyAuthMech, api_key_authenticate
from .config import CALL_TIMEOUT
from .exc import ClientException, ValidationErrors, CallTimeout
from .transport import WSClient
from .utils import MIDDLEWARE_RUN_DIR, undefined, UndefinedType

logger = logging.getLogger(__name__)


class Call:
    def __init__(self, method, params):
        self.id = str(uuid.uuid4())
        self.method = method
        self.params = params
        self.returned = Event()
        self.result = None
        self.errno = None
        self.error = None
        self.trace = None
        self.type = None
        self.extra = None
        self.py_exception = None


class Job:
    def __init__(self, client, job_id, callback=None):
        self.client = client
        self.job_id = job_id
        # If a job event has been received already then we must set an Event
        # to wait for this job to finish.
        # Otherwise we create a new stub for the job with the Event for when
        # the job event arrives to use existing event.
        with client._jobs_lock:
            job = client._jobs[job_id]
            self.event = job.get('__ready')
            if self.event is None:
                self.event = job['__ready'] = Event()
            job['__callback'] = callback

    def __repr__(self):
        return f'<Job[{self.job_id}]>'

    def result(self):
        # Wait indefinitely for the job event with state SUCCESS/FAILED/ABORTED
        self.event.wait()
        job = self.client._jobs.pop(self.job_id, None)
        if job is None:
            raise ClientException('No job event was received.')
        state = job.get('state')
        if state == 'SUCCESS':
            return job['result']

        exc_info = job.get('exc_info')
        if exc_info:
            if exc_info['type'] == 'VALIDATION':
                raise ValidationErrors(exc_info['extra'] or [])
            raise ClientException(
                job['error'],
                trace={
                    'class': exc_info['type'],
                    'frames': [],
                    'formatted': job['exception'],
                    'repr': exc_info.get('repr') or job['exception'].splitlines()[-1],
                },
                extra=exc_info['extra'],
            )
        # Aborted or interrupted jobs have no exc_info to build a trace from.
        raise ClientException(job.get('error') or f'Job {self.job_id} did not succeed (state={state!r})')


class LegacyClient:
    def __init__(self, uri=None, reserved_ports=False, private_methods=False, py_exceptions=False,
                 log_py_exceptions=False, call_timeout: float | UndefinedType = undefined, verify_ssl=True):
        """
        Arguments:
           :reserved_ports(bool): should the local socket used a reserved port
        """
        if uri is None:
            uri = f'ws+unix://{MIDDLEWARE_RUN_DIR}/middlewared.sock'

        if call_timeout is undefined:
            call_timeout = CALL_TIMEOUT

        self._calls = {}
        self._jobs = defaultdict(dict)
        self._jobs_lock = Lock()
        self._jobs_watching = False
        self._pings = {}
        self._py_exceptions = py_exceptions
        self._log_py_exceptions = log_py_exceptions
        self._call_timeout = call_timeout
        self._event_callbacks = defaultdict(list)
        self._closed = Event()
        self._connected = Event()
        self._connection_error = None
        self._ws = WSClient(
            uri,
            client=self,
            reserved_ports=reserved_ports,
            verify_ssl=verify_ssl,
            unix_ws_path='/websocket',
        )
        self._ws.connect()
        self._connected.wait(10)
        if not self._connected.is_set():
            raise ClientException('Failed connection handshake')
        if self._connection_error is not None:
            raise ClientException(self._connection_error)

    def __enter__(self):
        return self

    def __exit__(self, typ, value, traceback):
        self.close()
        if typ is not None:
            raise

    def _send(self, data):
        try:
            self._ws.send(json.dumps(data))
        except (AttributeError, ConnectionClosed):
            # happens when other node on HA is rebooted, for example, and there are
            # running tasks in the event loop (i.e. failover.call_remote failover.get_disks_local)
            raise ClientException('Unexpected closure of remote connection', errno.ECONNABORTED)

    def _recv(self, message):
        _id = message.get('id')
        msg = message.get('msg')
        if msg == 'connected':
            self._connected.set()
        elif msg == 'failed':
            self._connection_error = 'Unsupported protocol version'
            self._connected.set()
        elif msg == 'pong' and _id is not None:
            ping_event = self._pings.get(_id)
            if ping_event:
                ping_event.set()
        elif _id is not None and msg == 'result':
            if call := self._calls.get(_id):
                call.result = message.get('result')
                if 'error' in message:
                    call.errno = message['error'].get('error')
                    call.error = message['error'].get('reason')
                    call.trace = message['error'].get('trace')
                    call.type = message['error'].get('type')
                    call.extra = message['error'].get('extra')
                    if self._py_exceptions and (py_exception := message['error'].get('py_exception')):
                        try:
                            call.py_exception = pickle.loads(b64decode(py_exception))
                        except Exception as e:
                            logger.warning("Error unpickling call exception: %r", e)
                call.returned.set()
                self._unregister_call(call)
            else:
                if 'error' in message:
                    for events in self._event_callbacks.values():
                        for event in events:
                            if event['id'] == _id:
                                event['error'] = message['error']
                                event['ready'].set()
                                break
        elif msg in ('added', 'changed', 'removed'):
            if self._event_callbacks:
                if '*' in self._event_callbacks:
                    for event in self._event_callbacks['*']:
                        self._run_callback(event, [msg.upper()], message)
                if message['collection'] in self._event_callbacks:
                    for event in self._event_callbacks[message['collection']]:
                        self._run_callback(event, [msg.upper()], message)
        elif msg == 'ready':
            for subid in message['subs']:
                # FIXME: We may need to keep a different index for id
                # so we don't hve to iterate through all.
                # This is fine for just a dozen subscriptions
                for events in self._event_callbacks.values():
                    for event in events:
                        if subid == event['id']:
                            event['ready'].set()
                            break
        elif msg == 'nosub':
            if message['collection'] in self._event_callbacks:
                for event in self._event_callbacks[message['collection']]:
                    if 'error' in message:
                        event['error'] = message['error']['reason'] or message['error']['error']
                    event['ready'].set()
                    event['event'].set()

    def _run_callback(self, event, args, kwargs):
        if event['sync']:
            event['callback'](*args, **kwargs)
        else:
            Thread(
                target=event['callback'], args=args, kwargs=kwargs, daemon=True,
            ).start()

    def on_open(self):
        features = []
        if self._py_exceptions:
            features.append('PY_EXCEPTIONS')
        self._send({
            'msg': 'connect',
            'version': '1',
            'support': ['1'],
            'features': features,
        })

    def on_close(self, code, reason=None):
        error = f'WebSocket connection closed with code={code!r}, reason={reason!r}'

        self._connection_error = error
        self._connected.set()

        # Snapshot: _calls/_jobs can be resized concurrently (a woken waiter pops, the reader inserts).
        for call in list(self._calls.values()):
            if not call.returned.is_set():
                call.errno = errno.ECONNABORTED
                call.error = error
                call.returned.set()

        for job in list(self._jobs.values()):
            event = job.get('__ready')
            if event is None:
                event = job['__ready'] = Event()

            if not event.is_set():
                # The connection dropped, so the real outcome is unknown (the job may still be
                # running server-side); just mark it non-SUCCESS for Job.result().
                job['state'] = 'UNKNOWN'
                job['error'] = error
                job['exception'] = error
                job['exc_info'] = {
                    'type': 'Exception',
                    'repr': error,
                    'extra': None,
                }
                event.set()

        self._closed.set()

    def _register_call(self, call):
        self._calls[call.id] = call

    def _unregister_call(self, call):
        self._calls.pop(call.id, None)

    def _jobs_callback(self, mtype, **message):
        """
        Method to process the received job events.
        """
        fields = message.get('fields')
        job_id = fields['id']
        with self._jobs_lock:
            if fields:
                job = self._jobs[job_id]
                job.update(fields)
                if callable(job.get('__callback')):
                    Thread(
                        target=job['__callback'], args=(job,), daemon=True,
                    ).start()
                if mtype == 'CHANGED' and job['state'] in ('SUCCESS', 'FAILED', 'ABORTED'):
                    # If an Event already exist we just set it to mark it finished.
                    # Otherwise, we create a new Event.
                    # This is to prevent a race-condition of job finishing before
                    # the client can create the Event.
                    event = job.get('__ready')
                    if event is None:
                        event = job['__ready'] = Event()
                    event.set()

    def _jobs_subscribe(self):
        """
        Subscribe to job updates, calling `_jobs_callback` on every new event.
        """
        self._jobs_watching = True
        self.subscribe('core.get_jobs', self._jobs_callback, sync=True)

    def call(self, method, *params, background=False, callback=None, job=False, timeout=undefined):
        if timeout is undefined:
            timeout = self._call_timeout

        # We need to make sure we are subscribed to receive job updates
        if job and not self._jobs_watching:
            self._jobs_subscribe()

        c = Call(method, params)
        self._register_call(c)
        try:
            self._send({
                'msg': 'method',
                'method': c.method,
                'id': c.id,
                'params': c.params,
            })

            if background:
                return c

            return self.wait(c, callback=callback, job=job, timeout=timeout)
        finally:
            if not background:
                self._unregister_call(c)

    def wait(self, c, *, callback=None, job=False, timeout=undefined):
        if timeout is undefined:
            timeout = self._call_timeout

        try:
            if not c.returned.wait(timeout):
                raise CallTimeout()

            if c.errno:
                if c.py_exception:
                    if self._log_py_exceptions:
                        logger.error(c.trace["formatted"])
                    raise c.py_exception
                if c.trace and c.type == 'VALIDATION':
                    raise ValidationErrors(c.extra)
                raise ClientException(c.error, c.errno, c.trace, c.extra)

            if job:
                jobobj = Job(self, c.result, callback=callback)
                if job == 'RETURN':
                    return jobobj
                return jobobj.result()

            return c.result
        finally:
            self._unregister_call(c)

    @staticmethod
    def event_payload():
        return {
            'id': str(uuid.uuid4()),
            'callback': None,
            'sync': False,
            'ready': Event(),
            'error': None,
            'event': Event(),
        }

    def subscribe(self, name, callback, payload=None, sync=False):
        payload = payload or self.event_payload()
        payload.update({
            'callback': callback,
            'sync': sync,
        })
        self._event_callbacks[name].append(payload)
        self._send({
            'msg': 'sub',
            'id': payload['id'],
            'name': name,
        })
        if not payload['ready'].wait(10):
            raise ValueError('Did not receive a response to the subscription request')
        if payload['error']:
            raise ValueError(payload['error'])
        return payload['id']

    def unsubscribe(self, id_):
        self._send({
            'msg': 'unsub',
            'id': id_,
        })
        for k, events in list(self._event_callbacks.items()):
            events = [v for v in events if v['id'] != id_]
            if events:
                self._event_callbacks[k] = events
            else:
                self._event_callbacks.pop(k)

    def ping(self, timeout=10):
        _id = str(uuid.uuid4())
        event = self._pings[_id] = Event()
        self._send({
            'msg': 'ping',
            'id': _id,
        })

        if not event.wait(timeout):
            return False
        return True

    def login_with_api_key(
        self,
        username: str,
        api_key: str,
        auth_mechanism: APIKeyAuthMech = APIKeyAuthMech.PLAIN,
        *,
        channel_binding: bool = True,
    ) -> None:
        """
        Helper function to authenticate via API key to the truenas server. Legacy TrueNAS servers
        had a significantly different API key implementation. They were de-facto linked to the root
        account with a per-key server-side allowlist defined that declared what middleware methods
        were authorized for the key.

        Args:
            username: this parameter is ignored for legacy clients. It exists to ensure consistent
               function signatures for API consumers.
            api_key: either the key material or an absolute path to the file where it is stored
            auth_mechanism: "PLAIN" is the only supported value -- legacy servers cannot do SCRAM,
               so a ValueError is raised if SCRAM is specified. Kept for signature parity with the
               non-legacy client.
            channel_binding: ignored for legacy clients. Legacy TrueNAS servers do not implement
               SCRAM, so there is no channel binding to negotiate. It exists to ensure consistent
               function signatures for API consumers.

        Returns:
            None

        Raises:
            ValueError: an error occurred during authentication.
        """
        if auth_mechanism == APIKeyAuthMech.SCRAM:
            raise ValueError('Legacy TrueNAS servers do not implement SCRAM authentication')

        api_key_authenticate(self, auth_mechanism, username, api_key, use_legacy_endpoint=True)

    def login_with_password(self, username: str, password: str, *, otp_token: str | None = None) -> None:
        """
        Authenticate via username and password.

        Uses auth.login which accepts an optional otp_token for
        two-factor authentication.

        Args:
            username: account username
            password: account password
            otp_token: one-time password token for two-factor authentication

        Raises:
            ValueError: authentication failed
        """
        if not self.call('auth.login', username, password, otp_token):
            raise ValueError('Invalid username or password')

    def close(self):
        self._ws.close()
        # Wait for websocketclient thread to close
        self._closed.wait(1)
        self._ws = None
