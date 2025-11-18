# SPDX-License-Identifier: LGPL-3.0-or-later
# ServerFinalMessage implementation

from base64 import b64encode, b64decode

from .scram_crypto import CryptoDatum, scram_hmac_sha512, scram_xor_bytes, scram_h, scram_constant_time_compare
from .common import GS2_SEPARATOR, GS2_NO_CHANNEL_BINDING
from .client_first import ClientFirstMessage
from .server_first import ServerFirstMessage
from .client_final import ClientFinalMessage


__all__ = ['ServerFinalMessage']


class ServerFinalMessage:
    __rfc_str = '<UNITIALIZED>'

    def __compute_auth_message(
        self,
        client_first: ClientFirstMessage,
        server_first: ServerFirstMessage,
        client_final: ClientFinalMessage
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
            client_first_bare = client_first_str

        # Get server-first-message
        server_first_str = str(server_first)

        # Get client-final-message-without-proof
        # Reconstruct the channel binding part
        if client_final.channel_binding:
            gs2_header_str = client_first.gs2_header or 'n,,'
            cb_data = gs2_header_str.encode() + bytes(client_final.channel_binding)
            channel_binding_b64 = b64encode(cb_data).decode()
        else:
            channel_binding_b64 = GS2_NO_CHANNEL_BINDING

        nonce_b64 = b64encode(client_final.nonce).decode()
        client_final_no_proof = f'c={channel_binding_b64},r={nonce_b64}'

        return f'{client_first_bare},{server_first_str},{client_final_no_proof}'

    def __verify_client_proof(
        self,
        client_final: ClientFinalMessage,
        stored_key: CryptoDatum,
        auth_message: str
    ) -> bool:
        """Verify the client proof as per RFC 5802.

        Server verifies by:
        1. Computing ClientSignature = HMAC(StoredKey, AuthMessage)
        2. Recovering ClientKey = ClientProof XOR ClientSignature
        3. Computing H(ClientKey) and comparing with StoredKey
        """
        if not client_final.client_proof:
            raise ValueError('Client final message has no proof')

        auth_message_bytes = CryptoDatum(auth_message.encode())
        client_signature = scram_hmac_sha512(stored_key, auth_message_bytes)

        # Recover ClientKey from ClientProof XOR ClientSignature
        recovered_client_key = scram_xor_bytes(client_final.client_proof, client_signature)

        # Verify that H(ClientKey) == StoredKey
        recovered_stored_key = scram_h(recovered_client_key)
        return scram_constant_time_compare(recovered_stored_key, stored_key)

    def __compute_server_signature(
        self,
        server_key: CryptoDatum,
        auth_message: str
    ) -> CryptoDatum:
        """Compute the server signature as per RFC 5802.

        ServerSignature = HMAC(ServerKey, AuthMessage)
        """
        auth_message_bytes = CryptoDatum(auth_message.encode())
        return scram_hmac_sha512(server_key, auth_message_bytes)

    def __generate_rfc_string(self) -> str:
        """Generate RFC 5802 formatted server final message."""
        signature_b64 = b64encode(self.__signature).decode()
        return f'v={signature_b64}'

    def __init__(
        self,
        *,
        client_first: ClientFirstMessage | None = None,
        server_first: ServerFirstMessage | None = None,
        client_final: ClientFinalMessage | None = None,
        stored_key: CryptoDatum | None = None,
        server_key: CryptoDatum | None = None,
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

            if not isinstance(client_final, ClientFinalMessage):
                raise TypeError('client_final must be a ClientFinalMessage instance')

            if not isinstance(stored_key, CryptoDatum):
                raise TypeError('stored_key must be a CryptoDatum instance')

            if not isinstance(server_key, CryptoDatum):
                raise TypeError('server_key must be a CryptoDatum instance')

            # Compute auth message
            auth_message = self.__compute_auth_message(client_first, server_first, client_final)

            # Verify client proof first (server should do this before sending final message)
            if not self.__verify_client_proof(client_final, stored_key, auth_message):
                raise ValueError('Client proof verification failed')

            # Compute server signature
            self.__signature = self.__compute_server_signature(server_key, auth_message)

            # Generate RFC string
            self.__rfc_str = self.__generate_rfc_string()

    def __parse_rfc_string(self, rfc_string: str):
        """Parse ServerFinalMessage from RFC 5802 formatted string.

        Format: v=<signature>
        """
        if not rfc_string.startswith('v='):
            raise ValueError('Invalid server final message format: must start with "v="')

        signature_b64 = rfc_string[2:]  # Skip "v="

        # Check for unexpected additional attributes
        if ',' in signature_b64:
            raise ValueError('Invalid server final message format: unexpected additional attributes')

        try:
            signature_bytes = b64decode(signature_b64)
        except Exception as e:
            raise ValueError(f'Invalid base64 encoding in server final message: {e}')

        self.__signature = CryptoDatum(signature_bytes)
        self.__rfc_str = rfc_string

    @property
    def signature(self):
        return self.__signature

    def __str__(self):
        return self.__rfc_str
