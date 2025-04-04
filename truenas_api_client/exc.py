"""Defines general classes for handling exceptions which may be raised through the client."""

from collections.abc import Iterable
import errno

from .jsonrpc import ErrorExtra, TruenasTraceback

try:
    from libzfs import Error as ZFSError  # pytype: disable=import-error
except ImportError:
    # this happens on our CI/CD runners as they do not install the py-libzfs module to run our api integration tests
    LIBZFS = False
else:
    LIBZFS = True


class ReserveFDException(Exception):
    """A `WSClient` instance failed to bind to a reserved port."""
    pass


class ErrnoMixin:
    """Provides custom error codes and a function to get the name of an error code."""

    ENOMETHOD = 201
    """Service not found or method not found in service."""
    ESERVICESTARTFAILURE = 202
    """Service failed to start."""
    EALERTCHECKERUNAVAILABLE = 203
    """Alert checker unavailable."""
    EREMOTENODEERROR = 204
    """Remote node responded with an error."""
    EDATASETISLOCKED = 205
    """Locked datasets."""
    EINVALIDRRDTIMESTAMP = 206
    """Invalid RRD timestamp."""
    ENOTAUTHENTICATED = 207
    """Client not authenticated."""
    ESSLCERTVERIFICATIONERROR = 208
    """SSL certificate/host key could not be verified."""

    @classmethod
    def _get_errname(cls, code: int) -> str | None:
        """Get the name of an error given its error code.

        Args:
            code: An error code for either a ZFSError or a custom error defined in this class.

        Returns:
            str: The name of the associated error.
            None: `code` does not match any known errors.

        """
        if LIBZFS and 2000 <= code <= 2100:
            return 'EZFS_' + ZFSError(code).name
        for k, v in cls.__dict__.items():
            if k.startswith("E") and v == code:
                return k


class ClientException(ErrnoMixin, Exception):
    """Represents any exception that might arise from a `Client`."""

    def __init__(self, error: str, errno: int | None = None, trace: TruenasTraceback | None = None,
                 extra: list[ErrorExtra] | None = None):
        """Initialize `ClientException`.

        Args:
            error: An error message offering a reason for the exception.
            errno: An error code to classify the error.
            trace: Traceback information from the server.
            extra: Any other errors pertaining to the exception.

        """
        self.errno = errno
        self.error = error
        self.trace = trace
        self.extra = extra

    def __str__(self):
        return self.error


class ValidationErrors(ClientException):
    """A raisable collection of `ErrorExtra`s that indicates a validation error occurred on the server."""

    def __init__(self, errors: Iterable[ErrorExtra]):
        """Initialize `ValidationErrors`.

        Args:
            errors: List of error codes and messages from the server.

        """
        self.errors = []
        for e in errors:
            self.errors.append(ErrorExtra(e[0], e[1], e[2]))

        super().__init__(str(self))

    def __str__(self):
        msgs = []
        for e in self.errors:
            errcode = errno.errorcode.get(e.errcode, 'EUNKNOWN')
            msgs.append(f'[{errcode}] {e.attribute or "ALL"}: {e.errmsg}')
        return '\n'.join(msgs)


class CallTimeout(ClientException):
    """A special `ClientException` raised when a `Call` times out before it can return a result."""
    def __init__(self):
        """Initiate a `ClientException` with message `"Call timeout"`."""
        super().__init__("Call timeout", errno.ETIMEDOUT)
