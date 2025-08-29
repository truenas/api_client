# SPDX-License-Identifier: LGPL-3.0-or-later
# Pure Python SCRAM-SHA-512 implementation
# Compatible API with truenas_pyscram C extension

from .error import (
    ScramError,
    SCRAM_E_SUCCESS,
    SCRAM_E_INVALID_REQUEST,
    SCRAM_E_MEMORY_ERROR,
    SCRAM_E_CRYPTO_ERROR,
    SCRAM_E_BASE64_ERROR,
    SCRAM_E_PARSE_ERROR,
    SCRAM_E_FORMAT_ERROR,
    SCRAM_E_AUTH_FAILED,
    SCRAM_E_FAULT,
)

from .scram_crypto import (
    CryptoDatum,
    generate_nonce,
    scram_hi,
    scram_h,
    scram_hmac_sha512,
    scram_create_client_key,
    scram_create_server_key,
    scram_create_stored_key,
    scram_xor_bytes,
    scram_constant_time_compare,
    scram_create_auth_message,
    generate_scram_auth_data,
    SCRAM_MAX_ITERS,
    SCRAM_MIN_ITERS,
    SCRAM_DEFAULT_ITERS,
    SCRAM_NONCE_SIZE,
)

from .common import (
    GS2_SEPARATOR,
    GS2_NO_CHANNEL_BINDING,
    ScramAuthData,
)

from .client_first import ClientFirstMessage
from .server_first import ServerFirstMessage
from .client_final import ClientFinalMessage
from .server_final import ServerFinalMessage

from .verify import (
    verify_server_signature,
    verify_client_final_message,
)


__all__ = [
    # Core types
    'CryptoDatum',
    'ScramAuthData',

    # Exceptions
    'ScramError',

    # Message classes
    'ClientFirstMessage',
    'ServerFirstMessage',
    'ClientFinalMessage',
    'ServerFinalMessage',

    # Verification functions
    'verify_server_signature',
    'verify_client_final_message',

    # Auth data generation
    'generate_scram_auth_data',

    # Cryptographic functions
    'generate_nonce',
    'scram_hi',
    'scram_h',
    'scram_hmac_sha512',
    'scram_create_client_key',
    'scram_create_server_key',
    'scram_create_stored_key',
    'scram_xor_bytes',
    'scram_constant_time_compare',
    'scram_create_auth_message',

    # Error codes
    'SCRAM_E_SUCCESS',
    'SCRAM_E_INVALID_REQUEST',
    'SCRAM_E_MEMORY_ERROR',
    'SCRAM_E_CRYPTO_ERROR',
    'SCRAM_E_BASE64_ERROR',
    'SCRAM_E_PARSE_ERROR',
    'SCRAM_E_FORMAT_ERROR',
    'SCRAM_E_AUTH_FAILED',
    'SCRAM_E_FAULT',

    # Constants
    'GS2_SEPARATOR',
    'GS2_NO_CHANNEL_BINDING',
    'SCRAM_MAX_ITERS',
    'SCRAM_MIN_ITERS',
    'SCRAM_DEFAULT_ITERS',
    'SCRAM_NONCE_SIZE',
]
