import enum


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
