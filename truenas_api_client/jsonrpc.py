"""Collection of types used to reference the structure of JSONRPC-2.0 messages received from the server.

https://www.jsonrpc.org/specification

"""
import enum
from typing import Any, Literal, NamedTuple, TypeAlias, TypedDict


class JSONRPCError(enum.Enum):
    # https://www.jsonrpc.org/specification
    INVALID_JSON = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603
    # Custom error codes from -32000 to -32099 as allowed by the specification above
    TRUENAS_TOO_MANY_CONCURRENT_CALLS = -32000
    TRUENAS_CALL_ERROR = -32001


class JobProgress(TypedDict):
    percent: float
    description: str


class ErrorExtra(NamedTuple):
    attribute: str
    errmsg: str
    errcode: int


class ExcInfo(TypedDict):
    type: str
    extra: list[ErrorExtra] | None
    repr: str


class JobFields(TypedDict):
    id: str
    state: str
    progress: JobProgress
    result: Any
    exc_info: ExcInfo
    error: str
    exception: str


class CollectionUpdateParams(TypedDict):
    msg: str
    collection: str
    id: Any
    fields: JobFields
    extra: dict


class CollectionUpdate(TypedDict):
    jsonrpc: Literal['2.0']
    method: Literal['collection_update']
    params: CollectionUpdateParams


TruenasTraceback = TypedDict('TruenasTraceback', {
    'class': str,
    'frames': list[dict[str, Any]],
    'formatted': str,
    'repr': str,
})
# Has to be defined this way because `class` is a keyword.


class TruenasError(TypedDict):
    error: int
    errname: str
    reason: str
    trace: TruenasTraceback | None
    extra: list[ErrorExtra]
    py_exception: str


class NotifyUnsubscribedParams(TypedDict):
    collection: str
    error: TruenasError


class NotifyUnsubscribed(TypedDict):
    jsonrpc: Literal['2.0']
    method: Literal['notify_unsubscribed']
    params: NotifyUnsubscribedParams


class SuccessResponse(TypedDict):
    jsonrpc: Literal['2.0']
    result: Any
    id: str


class ErrorObj(TypedDict):
    code: int
    message: str | None
    data: TruenasError


class ErrorResponse(TypedDict):
    jsonrpc: Literal['2.0']
    error: ErrorObj
    id: str


Notification: TypeAlias = CollectionUpdate | NotifyUnsubscribed
Response: TypeAlias = SuccessResponse | ErrorResponse
JSONRPCMessage: TypeAlias = Notification | Response
