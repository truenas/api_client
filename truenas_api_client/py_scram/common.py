# SPDX-License-Identifier: LGPL-3.0-or-later
# Pure python implementation of truenas_pyscram for platforms that do not
# have cpython extension available

import stringprep
import unicodedata
from dataclasses import dataclass

from .scram_crypto import CryptoDatum


__all__ = ['GS2_SEPARATOR', 'GS2_NO_CHANNEL_BINDING', 'ScramAuthData', 'CryptoDatum', 'saslprep']


# Constants
GS2_SEPARATOR = ',,'
GS2_NO_CHANNEL_BINDING = 'biws'  # base64 of "n,,"


def saslprep(input_str: str) -> str:
    """
    Implements the SASLprep profile of stringprep (RFC 4013).

    This profile is intended to prepare Unicode strings representing simple
    user names and passwords for comparison or use in cryptographic functions
    (e.g., message digests).

    Per RFC 5802, Section 5.1, this treats the string as a query string,
    meaning unassigned Unicode code points are allowed.

    Args:
        input_str: The string to prepare

    Returns:
        The prepared string

    Raises:
        TypeError: If input_str is not a string
        ValueError: If the string contains prohibited characters or violates bidi rules

    References:
        RFC 5802, Section 5.1 - SCRAM username preparation
        RFC 4013 - SASLprep: Stringprep Profile for User Names and Passwords
        RFC 3454 - Preparation of Internationalized Strings ("stringprep")
    """
    if not isinstance(input_str, str):
        raise TypeError('input_str must be a string')

    if not input_str:
        return input_str

    # RFC 4013, Section 2.1: Mapping
    # Map using RFC 3454, Table B.1 (commonly mapped to nothing)
    # Non-ASCII space characters are removed
    mapped = ''.join(c for c in input_str if not stringprep.in_table_b1(c))

    # RFC 4013, Section 2.2: Normalization
    # Normalize using Unicode normalization form KC (RFC 3454, Section 4)
    normalized = unicodedata.normalize('NFKC', mapped)

    # RFC 4013, Section 2.3: Prohibited Output
    # Check for prohibited characters as defined in RFC 3454
    for i, c in enumerate(normalized):
        # RFC 3454, Table C.1.2: Non-ASCII space characters
        if stringprep.in_table_c12(c):
            raise ValueError(
                f'Character at position {i} is prohibited (RFC 3454, C.1.2: Non-ASCII space)'
            )

        # RFC 3454, Table C.2.1: ASCII control characters
        if stringprep.in_table_c21(c):
            raise ValueError(
                f'Character at position {i} is prohibited (RFC 3454, C.2.1: ASCII control)'
            )

        # RFC 3454, Table C.2.2: Non-ASCII control characters
        if stringprep.in_table_c22(c):
            raise ValueError(
                f'Character at position {i} is prohibited (RFC 3454, C.2.2: Non-ASCII control)'
            )

        # RFC 3454, Table C.3: Private use characters
        if stringprep.in_table_c3(c):
            raise ValueError(
                f'Character at position {i} is prohibited (RFC 3454, C.3: Private use)'
            )

        # RFC 3454, Table C.4: Non-character code points
        if stringprep.in_table_c4(c):
            raise ValueError(
                f'Character at position {i} is prohibited (RFC 3454, C.4: Non-character)'
            )

        # RFC 3454, Table C.5: Surrogate codes
        if stringprep.in_table_c5(c):
            raise ValueError(
                f'Character at position {i} is prohibited (RFC 3454, C.5: Surrogate)'
            )

        # RFC 3454, Table C.6: Inappropriate for plain text
        if stringprep.in_table_c6(c):
            raise ValueError(
                f'Character at position {i} is prohibited '
                f'(RFC 3454, C.6: Inappropriate for plain text)'
            )

        # RFC 3454, Table C.7: Inappropriate for canonical representation
        if stringprep.in_table_c7(c):
            raise ValueError(
                f'Character at position {i} is prohibited '
                f'(RFC 3454, C.7: Inappropriate for canonical representation)'
            )

        # RFC 3454, Table C.8: Change display properties or deprecated
        if stringprep.in_table_c8(c):
            raise ValueError(
                f'Character at position {i} is prohibited '
                f'(RFC 3454, C.8: Change display properties)'
            )

        # RFC 3454, Table C.9: Tagging characters
        if stringprep.in_table_c9(c):
            raise ValueError(
                f'Character at position {i} is prohibited (RFC 3454, C.9: Tagging character)'
            )

        # RFC 3454, Table A.1: Unassigned code points are allowed per RFC 5802, Section 5.1
        # (treating username as a query string)

    # RFC 4013, Section 2.4: Bidirectional Characters
    # Check bidirectional characters per RFC 3454, Section 6
    # RFC 3454, Table D.1: Characters with bidirectional property "R" or "AL"
    has_RandALCat = any(stringprep.in_table_d1(c) for c in normalized)
    # RFC 3454, Table D.2: Characters with bidirectional property "L"
    has_LCat = any(stringprep.in_table_d2(c) for c in normalized)

    if has_RandALCat:
        # RFC 3454, Section 6, Rule 2: If a string contains any RandALCat character,
        # the string MUST NOT contain any LCat character
        if has_LCat:
            raise ValueError(
                'String contains both RandALCat and LCat characters (RFC 3454, Section 6)'
            )

        # RFC 3454, Section 6, Rule 3: If a string contains any RandALCat character,
        # a RandALCat character MUST be the first character of the string, and
        # a RandALCat character MUST be the last character of the string
        if not stringprep.in_table_d1(normalized[0]):
            raise ValueError(
                'First character must be RandALCat when string contains RandALCat '
                '(RFC 3454, Section 6)'
            )
        if not stringprep.in_table_d1(normalized[-1]):
            raise ValueError(
                'Last character must be RandALCat when string contains RandALCat '
                '(RFC 3454, Section 6)'
            )

    return normalized


@dataclass
class ScramAuthData:
    """Client-side authentication information dataclass that is used for generating
    client requests and to validate server responses"""
    salt: CryptoDatum
    iterations: int
    salted_password: CryptoDatum | None  # technically only ClientKey is required for client protocol
    client_key: CryptoDatum
    stored_key: CryptoDatum | None
    server_key: CryptoDatum | None
