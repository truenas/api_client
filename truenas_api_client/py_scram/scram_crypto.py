# SPDX-License-Identifier: LGPL-3.0-or-later
# Pure python implementation of SCRAM cryptographic operations
# Based on truenas_scram C library functions in src/scram/scram_utils.c

import hmac
import hashlib

from ssl import RAND_bytes


__all__ = [
    'CryptoDatum',
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
    'generate_scram_auth_data',
    'SCRAM_MAX_ITERS',
    'SCRAM_MIN_ITERS',
    'SCRAM_DEFAULT_ITERS',
    'SCRAM_NONCE_SIZE',
]


# Constants from truenas_scram.h
SCRAM_MAX_ITERS = 5000000
SCRAM_MIN_ITERS = 50000
SCRAM_DEFAULT_ITERS = 500000
SCRAM_NONCE_SIZE = 32


class CryptoDatum(bytes):
    """Wrapper around bytes object to provide consistency with CryptoDatum type
    in the cpython extension."""
    def __new__(cls, value):
        return super().__new__(cls, value)

    def __repr__(self):
        return f'CryptoDatum({hex(id(self))})'


def generate_nonce() -> CryptoDatum:
    """Generate a random 32 byte nonce for ClientFirstMessage.

    Uses RAND_bytes from OpenSSL for cryptographically secure random data.
    This is equivalent to scram_generate_nonce() from the C library.

    Returns:
        CryptoDatum containing 32 bytes of random data
    """
    nonce_data = RAND_bytes(SCRAM_NONCE_SIZE)
    return CryptoDatum(nonce_data)


def scram_hi(key: CryptoDatum, salt: CryptoDatum, iterations: int) -> CryptoDatum:
    """
    Perform PBKDF2-HMAC-SHA512 key derivation as specified in RFC 5802.

    This implements the Hi(str, salt, i) function from RFC 5802 Section 2.2.
    Uses PBKDF2 with HMAC-SHA-512 to derive a salted password from the input key.

    Args:
        key: Input key material (typically the password or API key)
        salt: Cryptographic salt for key derivation
        iterations: Number of PBKDF2 iterations (must be >= SCRAM_MIN_ITERS)

    Returns:
        CryptoDatum containing the derived key (64 bytes for SHA-512)

    Raises:
        ValueError: If parameters are invalid or iterations out of range
    """
    if not isinstance(key, (CryptoDatum, bytes)) or len(key) == 0:
        raise ValueError('Invalid key parameter')

    if not isinstance(salt, (CryptoDatum, bytes)) or len(salt) == 0:
        raise ValueError('Invalid salt parameter')

    if not isinstance(iterations, int):
        raise TypeError('Iterations must be an integer')

    if iterations < SCRAM_MIN_ITERS or iterations > SCRAM_MAX_ITERS:
        raise ValueError(f'Iterations must be between {SCRAM_MIN_ITERS} and {SCRAM_MAX_ITERS}')

    # PBKDF2-HMAC-SHA512
    derived_key = hashlib.pbkdf2_hmac('sha512', bytes(key), bytes(salt), iterations)
    return CryptoDatum(derived_key)


def scram_h(data: CryptoDatum) -> CryptoDatum:
    """
    Perform SHA-512 hash function as specified in RFC 5802.

    This implements the H(str) function from RFC 5802 Section 2.2.
    Computes the SHA-512 hash of the input data. Used primarily for
    generating the stored key from the client key.

    Args:
        data: Input data to hash

    Returns:
        CryptoDatum containing the SHA-512 hash (64 bytes)

    Raises:
        ValueError: If data is invalid
    """
    if not isinstance(data, (CryptoDatum, bytes)) or len(data) == 0:
        raise ValueError('Invalid data parameter')

    digest = hashlib.sha512(bytes(data)).digest()
    return CryptoDatum(digest)


def scram_hmac_sha512(key: CryptoDatum, data: CryptoDatum) -> CryptoDatum:
    """
    Perform HMAC-SHA-512 operation as specified in RFC 5802.

    This implements HMAC-SHA-512 as referenced in RFC 5802 Section 2.2.
    Computes the HMAC using SHA-512 hash function. Used for generating
    client keys, server keys, and authentication signatures in SCRAM.

    Args:
        key: HMAC key material
        data: Data to authenticate

    Returns:
        CryptoDatum containing the HMAC-SHA-512 result (64 bytes)

    Raises:
        ValueError: If parameters are invalid
    """
    if not isinstance(key, (CryptoDatum, bytes)) or len(key) == 0:
        raise ValueError('Invalid key parameter')

    if not isinstance(data, (CryptoDatum, bytes)) or len(data) == 0:
        raise ValueError('Invalid data parameter')

    result = hmac.digest(bytes(key), bytes(data), hashlib.sha512)
    return CryptoDatum(result)


def scram_create_client_key(salted_password: CryptoDatum) -> CryptoDatum:
    """
    Generate the client key as specified in RFC 5802.

    This implements ClientKey generation from RFC 5802 Section 3.
    ClientKey := HMAC(SaltedPassword, "Client Key").
    The client key is used to generate the client proof during authentication.

    Args:
        salted_password: The salted password derived from scram_hi()

    Returns:
        CryptoDatum containing the client key (64 bytes)

    Raises:
        ValueError: If salted_password is invalid
    """
    client_key_string = CryptoDatum(b'Client Key')
    return scram_hmac_sha512(salted_password, client_key_string)


def scram_create_server_key(salted_password: CryptoDatum) -> CryptoDatum:
    """
    Generate the server key as specified in RFC 5802.

    This implements ServerKey generation from RFC 5802 Section 3.
    ServerKey := HMAC(SaltedPassword, "Server Key").
    The server key is used by the server to generate authentication signatures.

    Args:
        salted_password: The salted password derived from scram_hi()

    Returns:
        CryptoDatum containing the server key (64 bytes)

    Raises:
        ValueError: If salted_password is invalid
    """
    server_key_string = CryptoDatum(b'Server Key')
    return scram_hmac_sha512(salted_password, server_key_string)


def scram_create_stored_key(client_key: CryptoDatum) -> CryptoDatum:
    """
    Generate the stored key as specified in RFC 5802.

    This implements StoredKey generation from RFC 5802 Section 3.
    StoredKey := H(ClientKey).
    The stored key is what the server stores instead of the plaintext
    password for authentication verification.

    Args:
        client_key: The client key generated from salted password

    Returns:
        CryptoDatum containing the stored key (64 bytes)

    Raises:
        ValueError: If client_key is invalid
    """
    return scram_h(client_key)


def scram_xor_bytes(a: CryptoDatum, b: CryptoDatum) -> CryptoDatum:
    """
    Perform XOR operation on two byte arrays.

    This is used to compute the client proof in SCRAM authentication:
    ClientProof := ClientKey XOR ClientSignature

    Args:
        a: First byte array
        b: Second byte array

    Returns:
        CryptoDatum containing the XOR result

    Raises:
        ValueError: If parameters are invalid or sizes don't match
    """
    if not isinstance(a, (CryptoDatum, bytes)) or len(a) == 0:
        raise ValueError('Invalid first parameter')

    if not isinstance(b, (CryptoDatum, bytes)) or len(b) == 0:
        raise ValueError('Invalid second parameter')

    if len(a) != len(b):
        raise ValueError('Byte array sizes do not match')

    result = bytes(x ^ y for x, y in zip(bytes(a), bytes(b)))
    return CryptoDatum(result)


def scram_constant_time_compare(a: CryptoDatum, b: CryptoDatum) -> bool:
    """
    Perform constant-time comparison of two byte arrays.

    This is critical for security to prevent timing attacks during
    authentication verification. Uses hmac.compare_digest which is
    designed for constant-time comparisons.

    Args:
        a: First byte array
        b: Second byte array

    Returns:
        True if the arrays are equal, False otherwise

    Raises:
        ValueError: If parameters are invalid
    """
    if not isinstance(a, (CryptoDatum, bytes)) or len(a) == 0:
        raise ValueError('Invalid first parameter')

    if not isinstance(b, (CryptoDatum, bytes)) or len(b) == 0:
        raise ValueError('Invalid second parameter')

    # hmac.compare_digest handles size mismatches gracefully and securely
    return hmac.compare_digest(bytes(a), bytes(b))


def scram_create_auth_message(
    client_first_bare: str,
    server_first_msg: str,
    client_final_without_proof: str
) -> str:
    """
    Create SCRAM authentication message as specified in RFC 5802.

    This creates the AuthMessage used in SCRAM authentication as defined
    in RFC 5802 Section 3:
    AuthMessage := client-first-message-bare + "," +
                   server-first-message + "," +
                   client-final-without-proof

    Args:
        client_first_bare: Client first message without GS2 header
        server_first_msg: Complete server first message
        client_final_without_proof: Client final message without proof

    Returns:
        String containing the auth message

    Raises:
        ValueError: If any parameter is invalid
    """
    if not isinstance(client_first_bare, str) or not client_first_bare:
        raise ValueError('Invalid client_first_bare parameter')

    if not isinstance(server_first_msg, str) or not server_first_msg:
        raise ValueError('Invalid server_first_msg parameter')

    if not isinstance(client_final_without_proof, str) or not client_final_without_proof:
        raise ValueError('Invalid client_final_without_proof parameter')

    return f'{client_first_bare},{server_first_msg},{client_final_without_proof}'


def generate_scram_auth_data(
    *,
    salted_password: CryptoDatum,
    salt: CryptoDatum,
    iterations: int,
):
    """
    Generate SCRAM authentication data from a salted password.

    This is compatible with the truenas_pyscram C extension API.
    The salted_password should be the output of scram_hi (PBKDF2).

    Args:
        salted_password: Salted password from scram_hi/PBKDF2 (required)
        salt: Salt that was used for PBKDF2 (required)
        iterations: PBKDF2 iterations that were used (required)

    Returns:
        ScramAuthData with all computed keys

    Raises:
        TypeError: If any parameter is missing or of wrong type
        ValueError: If iterations is out of valid range
    """
    # Import here to avoid circular dependency
    from .common import ScramAuthData

    if not isinstance(salted_password, CryptoDatum):
        raise TypeError('salted_password must be a CryptoDatum instance')

    if not isinstance(salt, CryptoDatum):
        raise TypeError('salt must be a CryptoDatum instance')

    if not isinstance(iterations, int):
        raise TypeError('iterations must be an integer')

    if iterations < SCRAM_MIN_ITERS or iterations > SCRAM_MAX_ITERS:
        raise ValueError(f'iterations must be between {SCRAM_MIN_ITERS} and {SCRAM_MAX_ITERS}')

    # Generate client key and stored key
    client_key = scram_create_client_key(salted_password)
    stored_key = scram_create_stored_key(client_key)

    # Generate server key
    server_key = scram_create_server_key(salted_password)

    return ScramAuthData(
        salt=salt,
        iterations=iterations,
        salted_password=salted_password,
        client_key=client_key,
        stored_key=stored_key,
        server_key=server_key,
    )
