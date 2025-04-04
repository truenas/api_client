"""Utility classes for use in the TrueNAS API client.

Includes `Struct` for creating regular objects out of `Mapping`s with string
keys and `ProgressBar` for displaying the progress of a task in the CLI.

Attributes:
    MIDDLEWARE_RUN_DIR: Directory containing the middlewared Unix domain socket.
    undefined: A dummy object similar in purpose to `None` that indicates an unset variable.

"""
import socket
import sys

from typing import Any, final, Mapping


MIDDLEWARE_RUN_DIR = '/var/run/middleware'


@final
class UndefinedType:
    def __new__(cls):
        if not hasattr(cls, '_instance'):
            cls._instance = super().__new__(cls)
        return cls._instance


undefined = UndefinedType()


class Struct:
    """Simpler wrapper to access using object attributes instead of keys.

    This is meant for compatibility when switch scripts to use middleware
    client instead of django directly.

    Example::

        >>> d = {'a':1, 'b':'2', 'c': [3, '4', {'d':5}], 'e':{'f':{'g':6}}}
        >>> s = Struct(d)
        >>> s.c
        [3, '4', {'d':5}]
        >>> s.e.f.g
        6

    """
    def __init__(self, mapping: Mapping[str, Any]):
        """Initialize a `Struct` with a `Mapping`.

        Args:
            mapping: Contains string keys that will become the `Struct`'s attribute names.

        """
        for k, v in mapping.items():
            if isinstance(v, dict):
                setattr(self, k, Struct(v))
            else:
                setattr(self, k, v)


class ProgressBar(object):
    """A simple text-based progress bar that writes to `sys.stderr`.

    Status: (message)
    Total Progress: [#####################___________________] 53.00%

    Example:
        ```
        with ProgressBar() as pb:
            for step in range(1, 101):
                pb.update(step)
        ```

    Attributes:
        message: String to display next to "Status".
        percentage: A float from `0.0` to `100.0` representing the total progress.
        write_stream: This is `sys.stderr` by default but can be any `TextIO`.
        used_flag: Indicates whether `update()` has been called.
        extra: A string or printable object to display after the status message.

    """
    def __init__(self):
        self.message = None
        self.percentage = 0
        self.write_stream = sys.stderr
        self.used_flag = False
        self.extra = None

    def __enter__(self):
        return self

    def draw(self):
        """Erase the previous progress bar and draw an updated one.

        If `self.extra` is set, will display "Status: (message) Extra: (extra)".

        """
        progress_width = 40
        filled_width = int(self.percentage * progress_width)
        self.write_stream.write('\033[2K\033[A\033[2K\r')
        self.write_stream.write(
            f'Status: {(self.message or "(none)").strip()}' + (
                f' Extra: {self.extra}' if self.extra else ''
            ) + '\n'
        )
        self.write_stream.write(
            'Total Progress: [{}{}] {:.2%}'.format(
                '#' * filled_width, '_' * (progress_width - filled_width), self.percentage
            )
        )
        self.write_stream.flush()

    def update(self, percentage: float | None = None, message: str | None = None):
        """Update the progress bar with a new percentage and/or message, redrawing it.

        Args:
            percentage: The new percentage to display. A value of `100.0` represents full.
            message: The "Status" message to display above the progress bar.

        """
        if not self.used_flag:
            self.write_stream.write('\n')
            self.used_flag = True
        if percentage:
            self.percentage = float(percentage / 100.0)
        if message:
            self.message = message
        self.draw()

    def finish(self):
        """Fill the progress bar to 100%."""
        self.percentage = 1

    def __exit__(self, typ, value, traceback):
        if self.used_flag:
            self.draw()
            self.write_stream.write('\n')


def set_socket_options(socobj):
    plat = sys.platform
    if plat not in ('win32', 'linux', 'freebsd', 'darwin'):
        raise RuntimeError('Unsupported platform')

    # enable keepalives on the socket
    socobj.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    # If the other node panics then the socket will
    # remain open and we'll have to wait until the
    # TCP timeout value expires (60 seconds default).
    # To account for this:
    #   1. if the socket is idle for 1 seconds
    #   2. send a keepalive packet every 1 second
    #   3. for a maximum up to 5 times
    #
    # after 5 times (5 seconds of no response), the socket will be closed
    if plat in ('linux', 'freebsd', 'win32'):
        socobj.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 1)  # pytype: disable=module-attr

    else:
        socobj.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPALIVE, 1)  # pytype: disable=module-attr

    socobj.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 1)
    socobj.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
