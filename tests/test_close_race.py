# SPDX-License-Identifier: LGPL-3.0-or-later
"""WSClient.close() must survive the websocket-client 1.9.1 close race.

WebSocketApp.close() in websocket-client 1.9.1 reads self.sock after the close
handshake, but the run_forever thread's teardown() clears self.sock concurrently,
raising AttributeError (github.com/websocket-client/websocket-client/issues/1056).
"""
import unittest

from websocket import WebSocketApp

from truenas_api_client import WSClient
from websocket._abnf import STATUS_NORMAL


def _bare(cls, **attrs):
    """Build an instance without running __init__ (which would open a connection)."""
    obj = object.__new__(cls)
    for name, value in attrs.items():
        setattr(obj, name, value)
    return obj


class _ClientStub:
    """Records on_close() calls made by WSClient."""

    def __init__(self):
        self.close_codes = []

    def on_close(self, code):
        self.close_codes.append(code)


class _RacingSock:
    """Socket whose close() clears app.sock, simulating teardown() winning the race."""

    close_frame = None

    def __init__(self, app):
        self._app = app

    def close(self, **kwargs):
        self._app.sock = None


class _BrokenApp:
    """App whose close() raises like WebSocketApp.close() does when the race is lost."""

    def close(self, **kwargs):
        raise AttributeError("'NoneType' object has no attribute 'close_frame'")


class TestCloseRace(unittest.TestCase):
    def test_close_survives_teardown_race(self):
        """Replays the race against the installed websocket-client version."""
        app = WebSocketApp('ws://127.0.0.1/api/current')
        app.sock = _RacingSock(app)
        client = _ClientStub()
        ws = _bare(WSClient, app=app, client=client)

        ws.close()

        self.assertIsNone(app.sock)
        self.assertEqual(client.close_codes, [STATUS_NORMAL])

    def test_close_swallows_attribute_error(self):
        """The workaround path itself, independent of the websocket-client version."""
        client = _ClientStub()
        ws = _bare(WSClient, app=_BrokenApp(), client=client)

        ws.close()

        self.assertEqual(client.close_codes, [STATUS_NORMAL])


if __name__ == '__main__':
    unittest.main()
