from collections import namedtuple
import errno

try:
    from libzfs import Error as ZFSError
except ImportError:
    # this happens on our CI/CD runners as they do not install the py-libzfs module to run our api integration tests
    LIBZFS = False
else:
    LIBZFS = True


class ReserveFDException(Exception):
    pass


class ErrnoMixin:
    ENOMETHOD = 201
    ESERVICESTARTFAILURE = 202
    EALERTCHECKERUNAVAILABLE = 203
    EREMOTENODEERROR = 204
    EDATASETISLOCKED = 205
    EINVALIDRRDTIMESTAMP = 206
    ENOTAUTHENTICATED = 207
    ESSLCERTVERIFICATIONERROR = 208

    @classmethod
    def _get_errname(cls, code):
        if LIBZFS and 2000 <= code <= 2100:
            return 'EZFS_' + ZFSError(code).name
        for k, v in cls.__dict__.items():
            if k.startswith("E") and v == code:
                return k


class ClientException(ErrnoMixin, Exception):
    def __init__(self, error, errno=None, trace=None, extra=None):
        self.errno = errno
        self.error = error
        self.trace = trace
        self.extra = extra

    def __str__(self):
        return self.error


Error = namedtuple('Error', ['attribute', 'errmsg', 'errcode'])


class ValidationErrors(ClientException):
    def __init__(self, errors):
        self.errors = []
        for e in errors:
            self.errors.append(Error(e[0], e[1], e[2]))

        super().__init__(str(self))

    def __str__(self):
        msgs = []
        for e in self.errors:
            errcode = errno.errorcode.get(e.errcode, 'EUNKNOWN')
            msgs.append(f'[{errcode}] {e.attribute or "ALL"}: {e.errmsg}')
        return '\n'.join(msgs)


class CallTimeout(ClientException):
    def __init__(self):
        super().__init__("Call timeout", errno.ETIMEDOUT)
