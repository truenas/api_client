# SPDX-License-Identifier: LGPL-3.0-or-later
# ServerFirstMessage implementation

from base64 import b64encode, b64decode

from .scram_crypto import CryptoDatum, generate_nonce, SCRAM_MAX_ITERS
from .client_first import ClientFirstMessage
from .error import ScramError, SCRAM_E_INVALID_REQUEST


__all__ = ['ServerFirstMessage']


class ServerFirstMessage:
    __rfc_str = '<UNINITIALIZED>'

    def __generate_rfc_string(self):
        nonce_b64 = b64encode(self.nonce).decode()
        salt_b64 = b64encode(self.salt).decode()
        return f'r={nonce_b64},s={salt_b64},i={self.iterations}'

    def __init__(
        self,
        *,
        client_first: ClientFirstMessage | None = None,
        salt: CryptoDatum | None = None,
        iterations: int | None = None,
        rfc_string: str | None = None,
    ):
        # Check for mutually exclusive parameters
        if rfc_string and client_first:
            raise ValueError('Cannot specify both rfc_string and client_first parameters')

        if not rfc_string and not client_first:
            raise ValueError('Must specify either rfc_string or client_first parameter')

        if rfc_string:
            # Parse from RFC string
            self.__parse_rfc_string(rfc_string)
        else:
            # Create new message from parameters
            if not isinstance(client_first, ClientFirstMessage):
                raise TypeError('client_first must be a ClientFirstMessage instance')

            if not isinstance(salt, CryptoDatum):
                raise TypeError('salt must be a CryptoDatum instance')

            if not isinstance(iterations, int):
                raise TypeError('iterations must be an integer')

            # Generate server nonce and combine with client nonce
            server_nonce = generate_nonce()
            combined_nonce = CryptoDatum(client_first.nonce + server_nonce)

            self.__nonce = combined_nonce
            self.__salt = salt
            self.__iterations = iterations
            self.__rfc_str = self.__generate_rfc_string()

    def __parse_rfc_string(self, rfc_string: str):
        """Parse ServerFirstMessage from RFC 5802 formatted string.
        Format: r=<nonce>,s=<salt>,i=<iterations>
        """
        parts = rfc_string.split(',')
        if len(parts) != 3:
            raise ValueError('Invalid server first message format')

        nonce_b64 = None
        salt_b64 = None
        iterations = None

        for part in parts:
            if not part:
                raise ValueError('Invalid server first message format')

            key, _, value = part.partition('=')
            if not value:
                raise ValueError('Invalid server first message format')

            if key == 'r':
                nonce_b64 = value
            elif key == 's':
                salt_b64 = value
            elif key == 'i':
                try:
                    iterations = int(value)
                except ValueError:
                    raise ValueError('Invalid iteration count in server first message')
            else:
                raise ValueError(f'Unknown key in server first message: {key}')

        if nonce_b64 is None or salt_b64 is None or iterations is None:
            raise ValueError('Missing required fields in server first message')

        # Validate iterations (like C extension does)
        if iterations > SCRAM_MAX_ITERS:
            raise ScramError(
                f'{iterations}: exceeds maximum of {SCRAM_MAX_ITERS}',
                SCRAM_E_INVALID_REQUEST
            )

        try:
            nonce_bytes = b64decode(nonce_b64)
            salt_bytes = b64decode(salt_b64)
        except Exception as e:
            raise ValueError(f'Invalid base64 encoding in server first message: {e}')

        self.__nonce = CryptoDatum(nonce_bytes)
        self.__salt = CryptoDatum(salt_bytes)
        self.__iterations = iterations
        self.__rfc_str = rfc_string

    @property
    def nonce(self):
        return self.__nonce

    @property
    def salt(self):
        return self.__salt

    @property
    def iterations(self):
        return self.__iterations

    def __str__(self):
        return self.__rfc_str
