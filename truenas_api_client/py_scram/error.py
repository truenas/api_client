# SPDX-License-Identifier: LGPL-3.0-or-later
# SCRAM exception classes

# Error codes from truenas_scram C library
SCRAM_E_SUCCESS = 0
SCRAM_E_INVALID_REQUEST = 1
SCRAM_E_MEMORY_ERROR = 2
SCRAM_E_CRYPTO_ERROR = 3
SCRAM_E_BASE64_ERROR = 4
SCRAM_E_PARSE_ERROR = 5
SCRAM_E_FORMAT_ERROR = 6
SCRAM_E_AUTH_FAILED = 7
SCRAM_E_FAULT = 8

# Error code to string mapping
ERROR_CODE_NAMES = {
    SCRAM_E_SUCCESS: "SCRAM_E_SUCCESS",
    SCRAM_E_INVALID_REQUEST: "SCRAM_E_INVALID_REQUEST",
    SCRAM_E_MEMORY_ERROR: "SCRAM_E_MEMORY_ERROR",
    SCRAM_E_CRYPTO_ERROR: "SCRAM_E_CRYPTO_ERROR",
    SCRAM_E_BASE64_ERROR: "SCRAM_E_BASE64_ERROR",
    SCRAM_E_PARSE_ERROR: "SCRAM_E_PARSE_ERROR",
    SCRAM_E_FORMAT_ERROR: "SCRAM_E_FORMAT_ERROR",
    SCRAM_E_AUTH_FAILED: "SCRAM_E_AUTH_FAILED",
    SCRAM_E_FAULT: "SCRAM_E_FAULT",
}


class ScramError(RuntimeError):
    """
    SCRAM-specific exception.

    Compatible with truenas_pyscram.ScramError from the C extension.

    Attributes:
        code: Integer error code (one of SCRAM_E_* constants)
        message: Error message string
    """

    def __init__(self, message: str, code: int = SCRAM_E_FAULT):
        """
        Initialize ScramError.

        Args:
            message: Error message
            code: Error code (defaults to SCRAM_E_FAULT)
        """
        super().__init__(message)
        self.code = code

    def __repr__(self):
        """Return repr of the error."""
        code_name = ERROR_CODE_NAMES.get(self.code, "UNKNOWN_ERROR")
        return f"ScramError({code_name}: {super().__str__()})"


__all__ = [
    'ScramError',
    'SCRAM_E_SUCCESS',
    'SCRAM_E_INVALID_REQUEST',
    'SCRAM_E_MEMORY_ERROR',
    'SCRAM_E_CRYPTO_ERROR',
    'SCRAM_E_BASE64_ERROR',
    'SCRAM_E_PARSE_ERROR',
    'SCRAM_E_FORMAT_ERROR',
    'SCRAM_E_AUTH_FAILED',
    'SCRAM_E_FAULT',
]
