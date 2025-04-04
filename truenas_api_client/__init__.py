"""Provides a simple way to call middleware API endpoints using a websocket connection.

The full websocket API documentation can be found at https://www.truenas.com/docs/api/core_websocket_api.html.

Example::

    $ midclt ping && echo 'Connected' || echo 'Unable to ping'
    Connected
    $ midclt call user.create '{"full_name": "John Doe", "username": "user", "password": "pass", "group_create": true}'
    70
    $ midclt call user.get_instance 70
    {"id": 70, "uid": 3000, "username": "user", "unixhash": ... }
    $ midclt call user.query '[["full_name", "=", "John Doe"]]'
    {"id": 70, "uid": 3000, "username": "user", "unixhash": ... }

Example::

    with Client() as c:  # Local IPC
        print(c.ping())  # pong
        user = {"full_name": "John Doe", "username": "user", "password": "pass", "group_create": True}
        id = c.call("user.create", user)
        user = c.call("user.get_instance", id)
        print(user["full_name"])  # John Doe

Example::

    c = Client("ws://example.com/api/current")  # Remote websocket connection
    c.close()

"""
import argparse
from base64 import b64decode
from collections import defaultdict
from collections.abc import Callable, Iterable
from getpass import getpass
import errno
import logging
import pickle
import pprint
import random
import socket
import sys
from threading import Event, Lock, Thread
import time
from typing import Any, Literal, Protocol, TypeAlias, TypedDict
import urllib.parse
import uuid

import ssl
from websocket import WebSocketApp
from websocket._abnf import STATUS_NORMAL
from websocket._exceptions import WebSocketException, WebSocketConnectionClosedException
from websocket._http import connect, proxy_info
from websocket._socket import sock_opt

from . import ejson as json
from .config import CALL_TIMEOUT
from .exc import ReserveFDException, ClientException, ErrnoMixin, ValidationErrors, CallTimeout  # noqa
from .legacy import LegacyClient
from .jsonrpc import CollectionUpdateParams, ErrorObj, JobFields, JSONRPCError, JSONRPCMessage, TruenasError
from .utils import MIDDLEWARE_RUN_DIR, ProgressBar, undefined, UndefinedType, set_socket_options

logger = logging.getLogger(__name__)


UNIX_SOCKET_PREFIX = "ws+unix://"
DUMMY_HOSTNAME = "ws://localhost/api/current"  # Advised by official docs to use dummy hostname


class Client:
    """Implicit wrapper of either a `JSONRPCClient` or a `LegacyClient`."""

    def uri_check(self, uri: str | None, py_exceptions: bool):
        # We pickle_load when handling py_exceptions, reduce risk of MITM on client causing a pickle.load
        # of malicious information by only allowing this over unix domain socket.
        if uri and py_exceptions and not uri.startswith(UNIX_SOCKET_PREFIX):
            raise ClientException('py_exceptions are only allowed for connections to unix domain socket')

    def __init__(self, uri: str | None = None, reserved_ports=False, private_methods=False, py_exceptions=False,
                 log_py_exceptions=False, call_timeout: float | UndefinedType = undefined, verify_ssl=True):
        """Initialize either a `JSONRPCClient` or a `LegacyClient`.

        Use `JSONRPCClient` unless `uri` ends with '/websocket'.

        Args:
            uri: The address to connect to. Defaults to the local middlewared socket.
            reserved_ports: `True` if the local socket should use a reserved port.
            private_methods: `True` if calling private methods should be allowed
            py_exceptions: `True` if the server should include exception objects in
                `message['error']['data']['py_exception']`.
            log_py_exceptions: `True` if exception tracebacks from API calls should be logged.
            call_timeout: Number of seconds to allow an API call before timing out. Can be overridden on a per-call
                basis. Defaults to `CALL_TIMEOUT`.
            verify_ssl: `True` if SSL certificate should be verified before connecting.

        Raises:
            ClientException: `WSClient` timed out or some other connection error occurred.

        """
        if uri is not None and uri.endswith('/websocket'):
            client_class = LegacyClient
        else:
            client_class = JSONRPCClient

        self.uri_check(uri, py_exceptions)

        self.__client = client_class(uri, reserved_ports, private_methods, py_exceptions, log_py_exceptions,
                                     call_timeout, verify_ssl)

    def __getattr__(self, item):
        return getattr(self.__client, item)

    def __enter__(self):
        return self.__client.__enter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self.__client.__exit__(exc_type, exc_val, exc_tb)


class WSClient:
    """A supporter class for `JSONRPCClient` that manages the `WebSocket` connection to the server.

    The object used by `JSONRPCClient` to send and receive data.

    """
    def __init__(self, url: str, *, client: 'JSONRPCClient', reserved_ports: bool = False, verify_ssl: bool = True):
        """Initialize a `WSClient`.

        Args:
            url: The websocket to connect to. `ws://` or `wss://` for secure connection.
            client: Reference to the `JSONRPCClient` instance that uses this object.
            reserved_ports: `True` if the `socket` should bind to a reserved port, i.e. 600-1024.
            verify_ssl: `True` if SSL certificate should be verified before connecting.

        """
        self.url = url
        self.client = client
        self.reserved_ports = reserved_ports
        self.verify_ssl = verify_ssl

        self.socket: socket.socket
        self.app: WebSocketApp

    def connect(self):
        """Connect a `socket` and start a `WebSocketApp` in a daemon `Thread`.

        Raises:
            Exception: The `socket` failed to connect.

        """
        if self.url.startswith(UNIX_SOCKET_PREFIX):
            self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.socket.connect(self.url.removeprefix(UNIX_SOCKET_PREFIX))
            app_url = DUMMY_HOSTNAME
        elif self.reserved_ports:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            self._bind_to_reserved_port()
            try:
                self.socket.connect((urllib.parse.urlparse(self.url).hostname,
                                     urllib.parse.urlparse(self.url).port or 80))
            except Exception:
                self.socket.close()
                raise
            app_url = DUMMY_HOSTNAME
        else:
            sockopt = sock_opt(None, None if self.verify_ssl else {"cert_reqs": ssl.CERT_NONE})
            sockopt.timeout = 10
            self.socket = connect(self.url, sockopt, proxy_info(), None)[0]
            app_url = self.url

        self.app = WebSocketApp(
            app_url,
            socket=self.socket,
            on_open=self._on_open,
            on_message=self._on_message,
            on_error=self._on_error,
            on_close=self._on_close,
        )
        Thread(daemon=True, target=self.app.run_forever).start()

    def send(self, data: bytes | str):
        """Send data to the server by calling `WebSocketApp.send()`.

        Args:
            data: The serialized JSON-RPC v2.0-formatted request to send.

        """
        return self.app.send(data)

    def close(self):
        """Cleanly close the `WebSocket` connection to the server."""
        self.app.close()
        self.client.on_close(STATUS_NORMAL)

    def _bind_to_reserved_port(self):
        """Bind to a random port in the 600-1024 range.

        Raises:
            ReserveFDException: Five failed attempts with different ports.

        """
        # linux doesn't have a mechanism to allow the kernel to dynamically
        # assign ports in the "privileged" range (i.e. 600 - 1024) so we
        # loop through and call bind() on a privileged port explicitly since
        # middlewared runs as root.

        # generate 5 random numbers in the `port_low`, `port_high` range
        # so that we guarantee we use a different port from the last
        # iteration in the for loop
        port_low = 600
        port_high = 1024

        ports_to_try = random.sample(range(port_low, port_high), 5)

        for port in ports_to_try:
            try:
                self.socket.bind(('', port))
                return
            except OSError:
                time.sleep(0.1)
                continue

        raise ReserveFDException()

    def _on_open(self, app):
        """Callback passed to the `WebSocketApp` to execute when `run_forever` is called.

        Configure the `socket` and call `client.on_open()`.

        """
        # TCP keepalive settings don't apply to local unix sockets
        if UNIX_SOCKET_PREFIX not in self.url:
            set_socket_options(self.socket)

        # if we're able to connect put socket in blocking mode
        # until all operations complete or error is raised
        self.socket.settimeout(None)

        self.client.on_open()

    def _on_message(self, app, data):
        """Callback passed to the `WebSocketApp` to execute when data is received.

        Pass the received data to the `JSONRPCClient`.

        """
        self.client._recv(json.loads(data))

    def _on_error(self, app, e):
        """Callback passed to the `WebSocketApp` to execute when an error occurs.

        Log the error.

        """
        logger.warning("Websocket client error: %r", e)
        self.client._ws_connection_error = e

    def _on_close(self, app, code, reason):
        """Callback passed to the `WebSocketApp` to execute when it closes.

        Close the `JSONRPCClient`.

        """
        self.client.on_close(code, reason)


class Call:
    """An encapsulation of the data from a single request-response pair."""

    def __init__(self, method: str, params: tuple):
        """Initialize a `Call` object with an automatically-assigned id.

        Args:
            method: The API method being called.
            params: Arguments passed to the method.

        """
        self.id = str(uuid.uuid4())
        self.method = method
        self.params = params
        self.returned = Event()
        self.result: Any = None
        self.error: ClientException | None = None
        self.py_exception: BaseException | None = None


class _JobDict(JobFields):
    """Contains data received from the server for a particular running job."""
    __ready: Event
    """Is set when the job returns or ends in error."""
    __callback: '_JobCallback | None'
    """Procedure to execute each time a job update is received."""


_JobCallback: TypeAlias = Callable[[_JobDict], None]


class Job:
    """A long-running background process on the server initiated by an API call.

    Every `Job` is responsible for a corresponding `_JobDict` in the client's list of jobs.

    """
    def __init__(self, client: 'JSONRPCClient', job_id: str, callback: _JobCallback | None = None):
        """Initialize `Job`.

        Args:
            client: Reference to the client that created this `Job` and receives updates on its progress.
            job_id: The job id returned by the server. Index of this `Job` in the `client._jobs` dictionary.
            callback: A procedure to be called every time a job event is received.

        """
        self.client = client
        self.job_id = job_id
        # If a job event has been received already then we must set an Event
        # to wait for this job to finish.
        # Otherwise, we create a new stub for the job with the Event for when
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
        """Wait for the job to finish and return its result.

        Returns:
            Any: The job's result.

        Raises:
            ValidationErrors: The job failed due to one or more validation errors.
            ClientException: No job event was received or it did not succeed.

        """
        # Wait indefinitely for the job event with state SUCCESS/FAILED/ABORTED
        self.event.wait()
        job = self.client._jobs.pop(self.job_id, None)
        if job is None:
            raise ClientException('No job event was received.')
        if job['state'] != 'SUCCESS':
            if job['exc_info'] and job['exc_info']['type'] == 'VALIDATION':
                raise ValidationErrors(job['exc_info']['extra'] or [])
            raise ClientException(
                job['error'],
                trace={
                    'class': job['exc_info']['type'],
                    'frames': [],
                    'formatted': job['exception'],
                    'repr': job['exc_info'].get('repr', job['exception'].splitlines()[-1]),
                },
                extra=job['exc_info']['extra']
            )
        return job['result']


class _EventCallbackProtocol(Protocol):
    """Specifies how event callbacks should be defined."""
    def __call__(self, mtype: str, **message: Any) -> None:
        pass


class _PartialPayload(TypedDict):
    """Type returned by `JSONRPCClient.event_payload`.

    Contains the required fields of `_Payload`.

    """
    callback: _EventCallbackProtocol | None
    sync: bool
    event: Event


class _Payload(_PartialPayload, total=False):
    """Contains data for managing a subscription.

    Attributes:
        callback: Procedure to call when the event is triggered.
        sync: If `True`, main client thread blocks until `callback` finishes each time it is invoked. Otherwise, run
            `callback` in the background as a daemon `Thread`.
        event: `Event` that is set when the subscription should end.
        error: Information included in the Notification if the subscription ended in error.
        id: Random UUID assigned by `core.subscribe`.

    """
    error: str | TruenasError | None
    id: str


class JSONRPCClient:
    """The object used to interface with the TrueNAS API.

    Keeps track of the calls made, jobs submitted, and callbacks. Maintains a websocket connection using a `WSClient`.

    """
    def __init__(self, uri: str | None = None, reserved_ports=False, private_methods=False, py_exceptions=False,
                 log_py_exceptions=False, call_timeout: float | UndefinedType = undefined, verify_ssl=True):
        """Initialize a `JSONRPCClient`.

        Args:
            uri: The address to connect to. Defaults to the local middlewared socket.
            reserved_ports: `True` if the local socket should use a reserved port.
            private_methods: `True` if calling private methods should be allowed
            py_exceptions: `True` if the server should include exception objects in
                `message['error']['data']['py_exception']`.
            log_py_exceptions: `True` if exception tracebacks from API calls should be logged.
            call_timeout: Number of seconds to allow an API call before timing out. Can be overridden on a per-call
                basis. Defaults to `CALL_TIMEOUT`.
            verify_ssl: `True` if SSL certificate should be verified before connecting.

        Raises:
            ClientException: `WSClient` timed out or some other connection error occurred.

        """
        if uri is None:
            uri = f'{UNIX_SOCKET_PREFIX}{MIDDLEWARE_RUN_DIR}/middlewared.sock'

        if call_timeout is undefined:
            call_timeout = CALL_TIMEOUT

        self._calls: dict[str, Call] = {}
        self._jobs: defaultdict[str, _JobDict] = defaultdict(dict)  # type: ignore
        self._jobs_lock = Lock()
        self._jobs_watching = False
        self._private_methods = private_methods
        self._py_exceptions = py_exceptions
        self._log_py_exceptions = log_py_exceptions
        self._call_timeout = call_timeout
        self._event_callbacks: defaultdict[str, list[_Payload]] = defaultdict(list)
        self._set_options_call: Call | None = None
        self._closed = Event()
        self._connected = Event()
        self._connection_error: str | None = None
        self._ws_connection_error: WebSocketException
        self._ws = WSClient(
            uri,
            client=self,
            reserved_ports=reserved_ports,
            verify_ssl=verify_ssl,
        )
        self._ws.connect()
        self._connected.wait(10)
        if not self._connected.is_set():
            raise ClientException('Failed connection handshake')
        if hasattr(self, '_ws_connection_error'):
            if isinstance(self._ws_connection_error, WebSocketException):
                raise self._ws_connection_error
        if self._connection_error is not None:
            raise ClientException(self._connection_error)

    def __enter__(self):
        return self

    def __exit__(self, typ, value, traceback):
        self.close()

    def _send(self, data):
        """Send data to the server using `WSClient`.

        Args:
            data: Object serializable with `ejson`.

        Raises:
            ClientException: Connection to the server closed prematurely.

        """
        try:
            self._ws.send(json.dumps(data))
        except (AttributeError, WebSocketConnectionClosedException):
            # happens when other node on HA is rebooted, for example, and there are
            # running tasks in the event loop (i.e. failover.call_remote failover.get_disks_local)
            raise ClientException('Unexpected closure of remote connection', errno.ECONNABORTED)

    def _recv(self, message: JSONRPCMessage):
        """Process a deserialized JSON-RPC v2.0 message from the server.

        The TrueNAS websocket `JSONRPCClient` receives data from the server in two standard forms: Notifications and
        Responses. These are defined in the JSON-RPC v2.0 protocol at https://www.jsonrpc.org/specification.

        In the TrueNAS websocket client, Notifications are used to communicate subscription updates including when a
        subscription is terminated. These subscription updates also include updates about jobs submitted by the client
        via `core.get_jobs`.

        A Response is the server's answer to a Request sent by the client which may or may not come back immediately
        depending on the Request sent.

        Args:
            message: Deserialized JSON-RPC v2.0 data from the server.

        """
        try:
            if 'method' in message:
                match message['method']:
                    case 'collection_update':
                        if self._event_callbacks:
                            params = message['params']
                            if '*' in self._event_callbacks:
                                for event in self._event_callbacks['*']:
                                    self._run_callback(event, [params['msg'].upper()], params)
                            if params['collection'] in self._event_callbacks:
                                for event in self._event_callbacks[params['collection']]:
                                    self._run_callback(event, [params['msg'].upper()], params)
                    case 'notify_unsubscribed':
                        params = message['params']
                        if params['collection'] in self._event_callbacks:
                            for event in self._event_callbacks[params['collection']]:
                                if 'error' in params:
                                    event['error'] = params['error']['reason'] or params['error']
                                event['event'].set()
                    case _:
                        logger.error('Received unknown notification %r', message['method'])
            elif 'id' in message:
                if self._set_options_call and message['id'] == self._set_options_call.id:
                    if 'error' in message:
                        try:
                            self._parse_error(message['error'], self._set_options_call)
                        except Exception:
                            logger.error('Unhandled exception in JSONRPCClient._parse_error', exc_info=True)
                        else:
                            logger.error('Error setting client options: %r', self._set_options_call.error)
                    self._connected.set()
                elif call := self._calls.get(message['id']):
                    if 'result' in message:
                        call.result = message['result']
                    if 'error' in message:
                        try:
                            self._parse_error(message['error'], call)
                        except Exception:
                            logger.error('Unhandled exception in JSONRPCClient._parse_error', exc_info=True)
                    call.returned.set()
                    self._unregister_call(call)
                else:
                    if 'result' in message:
                        logger.error('Received a success response for non-registered method call %r', message['id'])
                    elif 'error' in message:
                        try:
                            error = self._parse_error_and_unpickle_exception(message['error'])[0]
                        except Exception:
                            logger.error('Unhandled exception in JSONRPCClient._parse_error', exc_info=True)
                            error = None

                        if message['id'] is None:
                            logger.error('Received a global connection error: %r', error)
                        else:
                            logger.error('Received an error response for non-registered method call %r: %r',
                                         message['id'], error)

                        if error:
                            self._broadcast_error(error)
                    else:
                        logger.error('Received a response for non-registered method call %r', message['id'])
            else:
                logger.error('Received unknown message %r', message)
        except Exception:
            logger.error('Unhandled exception in JSONRPCClient._recv', exc_info=True)

    def _parse_error(self, error: ErrorObj, call: Call):
        """Convert an error received from the server into a `ClientException` and store it.

        Args:
            error: The JSON object received in an error Response.
            call: The associated `Call` object with which to store the `ClientException`.
        """
        call.error, call.py_exception = self._parse_error_and_unpickle_exception(error)

    def _parse_error_and_unpickle_exception(self, error: ErrorObj) -> tuple[ClientException, Exception | None]:
        """Convert an error received from the server into a `ClientException` and, possibly, unpickle original
        exception.

        Args:
            error: The JSON object received in an error Response.
        """
        code = JSONRPCError(error['code'])
        py_exception = None
        if self._py_exceptions and code in [JSONRPCError.INVALID_PARAMS, JSONRPCError.TRUENAS_CALL_ERROR]:
            data = error['data']
            error = ClientException(data['reason'], data['error'], data['trace'], data['extra'])
            if 'py_exception' in data:
                try:
                    py_exception = pickle.loads(b64decode(data['py_exception']))
                except Exception as e:
                    logger.warning("Error unpickling call exception: %r", e)
        elif code == JSONRPCError.INVALID_PARAMS:
            error = ValidationErrors(error['data']['extra'])
        elif code == JSONRPCError.TRUENAS_CALL_ERROR:
            data = error['data']
            error = ClientException(data['reason'], data['error'], data['trace'], data['extra'])
        else:
            error = ClientException(error.get('message') or code.name)

        return error, py_exception

    def _run_callback(self, event: _Payload, args: Iterable[str], kwargs: CollectionUpdateParams):
        """Call the passed `_Payload`'s callback function.

        Block until the callback returns if `event['sync']` is set. Otherwise, run in a separate daemon `Thread`.

        Args:
            event: The `_Payload` whose callback to run.
            args: Positional arguments to the callback.
            kwargs: Keyword arguments to the callback.

        """
        if event['callback'] is None:
            return
        if event['sync']:
            event['callback'](*args, **kwargs)
        else:
            Thread(target=event['callback'], args=args, kwargs=kwargs, daemon=True).start()

    def on_open(self):
        """Make an API call to `core.set_options` to configure how middlewared sends its responses."""
        self._set_options_call = self.call("core.set_options", {
            "private_methods": self._private_methods,
            "py_exceptions": self._py_exceptions,
        }, background=True)

    def on_close(self, code: int, reason: str | None = None):
        """Close this `JSONRPCClient` in response to the `WebSocketApp` closing.

        End all unanswered calls and unreturned jobs with an error.

        Args:
            code: One of several closing frame status codes defined in `websocket._abnf`.
            reason: A message to accompany the closing code and provide more information.

        """
        error = f'WebSocket connection closed with code={code!r}, reason={reason!r}'

        self._connection_error = error
        self._connected.set()

        self._broadcast_error(ClientException(error, errno.ECONNABORTED))

        self._closed.set()

    def _broadcast_error(self, error: ClientException):
        for call in self._calls.values():
            if not call.returned.is_set():
                call.error = error
                call.returned.set()

        for job in self._jobs.values():
            event = job.get('__ready')
            if event is None:
                event = job['__ready'] = Event()

            if not event.is_set():
                error_repr = repr(error)
                job['error'] = error_repr
                job['exception'] = error_repr
                job['exc_info'] = {
                    'type': 'Exception',
                    'repr': error_repr,
                    'extra': None,
                }
                event.set()

    def _register_call(self, call: Call):
        """Save a `Call` and index it by its id."""
        self._calls[call.id] = call

    def _unregister_call(self, call: Call):
        """Remove a `Call` after it has returned."""
        self._calls.pop(call.id, None)

    def _jobs_callback(self, mtype: str, *, fields: JobFields, **message):
        """Process a received job event.

        Update the saved job info, execute its saved callback in the background, and set its "__ready" flag if its
        "state" is received.

        Args:
            mtype: Indicates if the job state has changed.
            **message: The members contained in `CollectionUpdateParams`.

        Keyword Args:
            fields (JobFields): Contains job id and other information about the job from the server.

        """
        job_id = fields['id']
        with self._jobs_lock:
            if fields:
                job = self._jobs[job_id]
                job.update(**fields)
                if callable(job.get('__callback')):
                    Thread(target=job['__callback'], args=(job,), daemon=True).start()
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
        """Subscribe to job updates, calling `_jobs_callback` on every new event."""
        self._jobs_watching = True
        self.subscribe('core.get_jobs', self._jobs_callback, sync=True)

    def call(self, method: str, *params, background=False, callback: _JobCallback | None = None,
             job: Literal['RETURN'] | bool = False, register_call: bool | None = None,
             timeout: float | UndefinedType = undefined) -> Any:
        """The primary way to send call requests to the API.

        Send a JSON-RPC v2.0 Request to the server.

        Args:
            method: An API endpoint to call.
            *params: Arguments to pass to the endpoint.
            background: If `background=True`, send the request and return a `Call` object before receiving a response.
                By default, wait for the call to return instead.
            callback: The callback to pass to the job if `job` is set.
            job: If set, subscribe to job updates and if `background=False`, create a `Job`. If `job='RETURN'`, return
                the `Job` object rather than just its result.
            timeout: Number of seconds to allow the call before timing out if `background=False`.

        Returns:
            Call: If `background` is set, return an object representing the request-response pair.
            Job: If `job='RETURN'`, return the `Job` object.
            Any: Otherwise, return the result of the call.

        Raises:
            ClientException: Connection to the server closed prematurely or the call ended in error.
            CallTimeout: The call took longer than `timeout` seconds to return.

        """
        if register_call is None:
            register_call = not background

        if timeout is undefined:
            timeout = self._call_timeout

        # We need to make sure we are subscribed to receive job updates
        if job and not self._jobs_watching:
            self._jobs_subscribe()

        c = Call(method, params)
        if register_call:
            self._register_call(c)
        try:
            self._send({
                'jsonrpc': '2.0',
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

    def wait(self, c: Call, *, callback: _JobCallback | None = None, job: Literal['RETURN'] | bool = False,
             timeout: float | UndefinedType = undefined) -> Any:
        """Wait for an API call to return and return its result.

        Args:
            c: The `Call` object containing the data that was sent.
            callback: The callback to pass to the job if `job` is set.
            job: If set, create a `Job`. If `job='RETURN'`, return the `Job` object rather than just its result.
            timeout: Override the default number of seconds until a timeout exception occurs.

        Returns:
            Job: If `job='RETURN'`, return the `Job` object.
            Any: If `job=True`, return the job's result. Otherwise, return the call's result.

        Raises:
            CallTimeout: The call took longer than `timeout` seconds to return.
            ClientException: The call ended in error and `py_exception` was not enabled for `c`.
            BaseException: The call ended in error and `py_exception` was enabled for `c`.

        """
        if timeout is undefined:
            timeout = self._call_timeout

        try:
            if not c.returned.wait(timeout):  # type: ignore
                raise CallTimeout()

            if c.error:
                if c.py_exception:
                    if self._log_py_exceptions and c.error.trace:
                        logger.error(c.error.trace["formatted"])
                    raise c.py_exception
                else:
                    raise c.error

            if job:
                jobobj = Job(self, c.result, callback=callback)
                if job == 'RETURN':
                    return jobobj
                return jobobj.result()

            return c.result
        finally:
            self._unregister_call(c)

    @staticmethod
    def event_payload() -> _Payload:
        """Create an empty payload.

        Returns:
            _Payload: Empty `_Payload`.

        """
        return {
            'callback': None,
            'sync': False,
            'event': Event(),
        }

    def subscribe(self, name: str, callback: _EventCallbackProtocol, payload: _Payload | None = None,
                  sync: bool = False) -> str:
        """Subscribe to an event by calling `core.subscribe`.

        Args:
            name: The name of the event to subscribe to.
            callback: A procedure to call when an event is triggered.
            payload: Dictionary containing subscription information.
            sync: If `True`, main client thread blocks until `callback` finishes each time it is invoked. Otherwise,
                run `callback` in the background as a daemon `Thread`.

        Returns:
            str: The `_Payload` id assigned by `core.subscribe`.

        """
        payload = payload or self.event_payload()
        payload.update({
            'callback': callback,
            'sync': sync,
        })
        self._event_callbacks[name].append(payload)
        payload['id'] = self.call('core.subscribe', name, timeout=10)
        return payload['id']

    def unsubscribe(self, id_: str):
        """Call `core.unsubscribe` and remove all associated `_Payload`s

        Args:
            id_: `id` of the `_Payload` to remove.

        """
        self.call('core.unsubscribe', id_)
        for k, events in list(self._event_callbacks.items()):
            events = [v for v in events if v.get('id') != id_]
            if events:
                self._event_callbacks[k] = events
            else:
                self._event_callbacks.pop(k)

    def ping(self, timeout: float = 10) -> Literal['pong']:
        """Call `core.ping` to verify connection to the server.

        Args:
            timeout: Number of seconds to allow before raising `CallTimeout`.

        Raises:
            ClientException: Connection to the server closed prematurely or the call ended in error.
            CallTimeout: The call took longer than `timeout` seconds to return.

        """
        c = self.call('core.ping', background=True, register_call=True)
        return self.wait(c, timeout=timeout)

    def close(self):
        """Allow one second for the `WSClient` to close."""
        self._ws.close()
        # Wait for websocketclient thread to close
        self._closed.wait(1)
        del self._ws


def get_parser():
    """Construct the argument parser for `midclt`."""
    parser = argparse.ArgumentParser()

    # midclt options
    parser.add_argument('-u', '--uri')
    parser.add_argument('-U', '--username')
    parser.add_argument('-P', '--password')
    parser.add_argument('-K', '--api-key')
    parser.add_argument('-t', '--timeout', type=int)

    subparsers = parser.add_subparsers(help='sub-command help', dest='name')

    # call options
    iparser = subparsers.add_parser('call', help='Call a TrueNAS API method')
    iparser.add_argument('-q', '--quiet', help='Don\'t print error info', action='store_true')
    iparser.add_argument('-j', '--job', help='Call a long-running job', action='store_true')
    iparser.add_argument(
        '-jp',
        '--job-print',
        help='Method to print job progress',
        type=str,
        choices=('progressbar', 'description'),
        default='progressbar',
    )
    iparser.add_argument('method', nargs='+')

    # ping
    subparsers.add_parser('ping', help='Test connection to the server')

    # subscribe options
    iparser = subparsers.add_parser('subscribe', help='Receive event messages in a continuous stream')
    iparser.add_argument('event')
    iparser.add_argument('-n', '--number', type=int, help='Number of events to wait before exit')
    iparser.add_argument('-t', '--timeout', type=int)

    return parser


def main():
    """The entry point for midclt. Run `midclt -h` to see usage.

    Sub-commands:
        call, ping, subscribe

    Options:
        -h, -u URI, -U USERNAME, -P PASSWORD, -K API_KEY, -t TIMEOUT

    Raises:
        ValueError: Login failed (`midclt call`) or a subscription terminated with an error (`midclt subscribe`).

    """
    parser = get_parser()
    args = parser.parse_args()

    if args.username and not args.password:
        args.password = getpass()

    def from_json(args):
        for i in args:
            try:
                yield json.loads(i)
            except Exception:
                yield i

    if args.name == 'call':
        try:
            with Client(uri=args.uri) as c:
                try:
                    if args.username and args.password:
                        if not c.call('auth.login', args.username, args.password):
                            raise ValueError('Invalid username or password')
                    elif args.api_key:
                        if not c.call('auth.login_with_api_key', args.api_key):
                            raise ValueError('Invalid API key')
                except Exception as e:
                    print("Failed to login: ", e)
                    sys.exit(0)
                try:
                    kwargs = {}
                    if args.timeout:
                        kwargs['timeout'] = args.timeout
                    if args.job:
                        if args.job_print == 'progressbar':
                            # display the job progress and status message while we wait

                            def pb_callback(progress_bar: ProgressBar, job: _JobDict):
                                """Update `progress_bar` with information in `job['progress']`."""
                                try:
                                    progress_bar.update(
                                        job['progress']['percent'], job['progress']['description']
                                    )
                                except Exception as e:
                                    print(f'Failed to update progress bar: {e!s}', file=sys.stderr)

                            with ProgressBar() as progress_bar:
                                kwargs.update(
                                    job=True,
                                    callback=lambda job: pb_callback(progress_bar, job)
                                )
                                rv = c.call(args.method[0], *list(from_json(args.method[1:])), **kwargs)
                                progress_bar.finish()
                        else:
                            lastdesc = ''

                            def callback(job: _JobDict):
                                """Print `job`'s description to `stderr` if it has changed."""
                                nonlocal lastdesc
                                desc = job['progress']['description']
                                if desc is not None and desc != lastdesc:
                                    print(desc, file=sys.stderr)
                                lastdesc = desc

                            kwargs.update({
                                'job': True,
                                'callback': callback,
                            })
                            rv = c.call(args.method[0], *list(from_json(args.method[1:])), **kwargs)
                    else:
                        rv = c.call(args.method[0], *list(from_json(args.method[1:])), **kwargs)
                    if isinstance(rv, (int, str)):
                        print(rv)
                    else:
                        print(json.dumps(rv))
                except ClientException as e:
                    if not args.quiet:
                        if e.error:
                            print(e.error, file=sys.stderr)
                        if e.trace:
                            print(e.trace['formatted'], file=sys.stderr)
                        if e.extra:
                            pprint.pprint(e.extra, stream=sys.stderr)
                    sys.exit(1)
        except (FileNotFoundError, ConnectionRefusedError):
            print('Failed to run middleware call. Daemon not running?', file=sys.stderr)
            sys.exit(1)
    elif args.name == 'ping':
        with Client(uri=args.uri) as c:
            if not (result := c.ping()):
                sys.exit(1)
            print(result)
    elif args.name == 'subscribe':
        with Client(uri=args.uri) as c:

            subscribe_payload = c.event_payload()
            event = subscribe_payload['event']
            number = 0

            def cb(mtype: str, **message):
                """Print the event message and unsubscribe if the maximum number of events is reached."""
                nonlocal number
                print(json.dumps(message))
                number += 1
                if args.number and number >= args.number:
                    event.set()

            c.subscribe(args.event, cb, subscribe_payload)  # type: ignore (`LegacyClient` does not return `_Payload`)

            if not event.wait(timeout=args.timeout):
                sys.exit(1)

            if 'error' in subscribe_payload and subscribe_payload['error']:
                raise ValueError(subscribe_payload['error'])
            sys.exit(0)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
