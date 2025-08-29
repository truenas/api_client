# SPDX-License-Identifier: LGPL-3.0-or-later
# ClientFinalMessage implementation

from base64 import b64encode, b64decode

from .scram_crypto import CryptoDatum, scram_hmac_sha512, scram_xor_bytes
from .common import GS2_SEPARATOR, GS2_NO_CHANNEL_BINDING
from .client_first import ClientFirstMessage
from .server_first import ServerFirstMessage


__all__ = ['ClientFinalMessage']


class ClientFinalMessage:
    __rfc_str = '<UNITIALIZED>'

    def __compute_auth_message(
        self,
        client_first: ClientFirstMessage,
        server_first: ServerFirstMessage,
        channel_binding_b64: str
    ) -> str:
        """Compute the auth message as per RFC 5802.

        AuthMessage = client-first-message-bare + "," +
                      server-first-message + "," +
                      client-final-message-without-proof
        """
        # Get client-first-message-bare (without GS2 header and separator)
        client_first_str = str(client_first)
        if GS2_SEPARATOR in client_first_str:
            client_first_bare = client_first_str.split(GS2_SEPARATOR, 1)[1]
        else:
            # If no separator, assume the whole thing is bare
            client_first_bare = client_first_str

        # Get server-first-message
        server_first_str = str(server_first)

        # Create client-final-message-without-proof
        nonce_b64 = b64encode(self.__nonce).decode()
        client_final_no_proof = f'c={channel_binding_b64},r={nonce_b64}'

        return f'{client_first_bare},{server_first_str},{client_final_no_proof}'

    def __compute_client_proof(
        self,
        client_key: CryptoDatum,
        stored_key: CryptoDatum,
        auth_message: str
    ) -> CryptoDatum:
        """Compute the client proof as per RFC 5802.

        ClientSignature = HMAC(StoredKey, AuthMessage)
        ClientProof = ClientKey XOR ClientSignature
        """
        auth_message_bytes = CryptoDatum(auth_message.encode())
        client_signature = scram_hmac_sha512(stored_key, auth_message_bytes)
        client_proof = scram_xor_bytes(client_key, client_signature)
        return client_proof

    def __generate_rfc_string(self, channel_binding_b64: str) -> str:
        """Generate RFC 5802 formatted client final message."""
        nonce_b64 = b64encode(self.__nonce).decode()
        client_proof_b64 = b64encode(self.__client_proof).decode()
        return f'c={channel_binding_b64},r={nonce_b64},p={client_proof_b64}'

    def __init__(
        self,
        *,
        client_first: ClientFirstMessage | None = None,
        server_first: ServerFirstMessage | None = None,
        client_key: CryptoDatum | None = None,
        stored_key: CryptoDatum | None = None,
        channel_binding: CryptoDatum | None = None,
        rfc_string: str | None = None,
    ):
        # Check for mutually exclusive parameters
        if rfc_string and client_first:
            raise ValueError('Cannot specify both rfc_string and other parameters')

        if not rfc_string and not client_first:
            raise ValueError('Must specify either rfc_string or message parameters')

        if rfc_string:
            # Parse from RFC string
            self.__parse_rfc_string(rfc_string)
        else:
            # Create new message from parameters
            if not isinstance(client_first, ClientFirstMessage):
                raise TypeError('client_first must be a ClientFirstMessage instance')

            if not isinstance(server_first, ServerFirstMessage):
                raise TypeError('server_first must be a ServerFirstMessage instance')

            if not isinstance(client_key, CryptoDatum):
                raise TypeError('client_key must be a CryptoDatum instance')

            if not isinstance(stored_key, CryptoDatum):
                raise TypeError('stored_key must be a CryptoDatum instance')

            if channel_binding is not None and not isinstance(channel_binding, CryptoDatum):
                raise TypeError('channel_binding must be a CryptoDatum instance or None')

            # Use the nonce from server_first (combined client+server nonce)
            self.__nonce = server_first.nonce
            self.__channel_binding = channel_binding
            self.__gs2_header = client_first.gs2_header

            # Prepare channel binding for message
            if channel_binding:
                # Encode GS2 header + channel binding data
                gs2_header_str = client_first.gs2_header or 'n,,'
                cb_data = gs2_header_str.encode() + bytes(channel_binding)
                channel_binding_b64 = b64encode(cb_data).decode()
            else:
                # No channel binding - use standard GS2_NO_CHANNEL_BINDING
                channel_binding_b64 = GS2_NO_CHANNEL_BINDING

            # Compute auth message
            auth_message = self.__compute_auth_message(client_first, server_first, channel_binding_b64)

            # Compute client proof
            self.__client_proof = self.__compute_client_proof(client_key, stored_key, auth_message)

            # Generate RFC string
            self.__rfc_str = self.__generate_rfc_string(channel_binding_b64)

    def __parse_rfc_string(self, rfc_string: str):
        """Parse ClientFinalMessage from RFC 5802 formatted string.

        Format: c=<channel-binding>,r=<nonce>,p=<client-proof>
        """
        parts = rfc_string.split(',')
        if len(parts) < 2:
            raise ValueError('Invalid client final message format')

        channel_binding_b64 = None
        nonce_b64 = None
        client_proof_b64 = None

        for part in parts:
            if not part:
                raise ValueError('Invalid client final message format')

            key, _, value = part.partition('=')
            if not value:
                raise ValueError('Invalid client final message format')

            if key == 'c':
                channel_binding_b64 = value
            elif key == 'r':
                nonce_b64 = value
            elif key == 'p':
                client_proof_b64 = value
            else:
                raise ValueError(f'Unknown key in client final message: {key}')

        if channel_binding_b64 is None or nonce_b64 is None:
            raise ValueError('Missing required fields in client final message')

        try:
            nonce_bytes = b64decode(nonce_b64)
            channel_binding_bytes = b64decode(channel_binding_b64)

            # Check if channel binding is GS2_NO_CHANNEL_BINDING ("biws" = base64("n,,"))
            if channel_binding_bytes == b'n,,':
                channel_binding_bytes = None

            # Client proof is optional when parsing (might be parsing without-proof variant)
            if client_proof_b64:
                client_proof_bytes = b64decode(client_proof_b64)
            else:
                client_proof_bytes = None
        except Exception as e:
            raise ValueError(f'Invalid base64 encoding in client final message: {e}')

        self.__nonce = CryptoDatum(nonce_bytes)
        self.__channel_binding = CryptoDatum(channel_binding_bytes) if channel_binding_bytes else None
        self.__client_proof = CryptoDatum(client_proof_bytes) if client_proof_bytes else None
        self.__gs2_header = None
        self.__rfc_str = rfc_string

    @property
    def nonce(self):
        return self.__nonce

    @property
    def client_proof(self):
        return self.__client_proof

    @property
    def channel_binding(self):
        return self.__channel_binding

    @property
    def gs2_header(self):
        return self.__gs2_header

    def __str__(self):
        return self.__rfc_str
