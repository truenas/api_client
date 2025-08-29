# SPDX-License-Identifier: LGPL-3.0-or-later
"""
SCRAM-SHA-512 Authentication Implementation

This module implements the SCRAM-SHA-512 (Salted Challenge Response Authentication Mechanism)
protocol as defined in RFC 5802 for authentication with TrueNAS servers over JSON-RPC.

## Overview

SCRAM is a challenge-response mechanism that provides mutual authentication between client
and server without transmitting passwords over the network. It protects against:
- Eavesdropping (passwords never sent in clear text)
- Replay attacks (uses nonces)
- Server impersonation (mutual authentication via server signature verification)
- Dictionary attacks (uses salted password hashing with high iteration counts)

## Authentication Flow (JSON-RPC Messages)

    CLIENT                                                                                  SERVER

    1. JSON-RPC Request:
       {
         "method": "auth.login_ex",
         "params": [{
           "mechanism": "SCRAM",
           "scram_type": "CLIENT_FIRST_MESSAGE",
           "rfc_str": "n,,n=<username>,r=<nonce>"
         }]
       }
    ----------------------------------------------------------------------------------------------->

                                                       2. Server:
                                                          - Lookup user's salt, iterations, StoredKey
                                                          - Generate server nonce

                                                       3. JSON-RPC Response:
                                                          {
                                                            "result": {
                                                              "response_type": "SCRAM_RESPONSE",
                                                              "scram_type": "SERVER_FIRST_MESSAGE",
                                                              "rfc_str": "r=<combined-nonce>,
                                                                          s=<salt-base64>,
                                                                          i=<iterations>"
                                                            }
                                                          }
    <-----------------------------------------------------------------------------------------------

    4. Client computes:
       - SaltedPassword = Hi(password, salt, iterations)
       - ClientKey = HMAC(SaltedPassword, "Client Key")
       - StoredKey = H(ClientKey)
       - AuthMessage = client-first + "," + server-first + "," + client-final-without-proof
       - ClientSignature = HMAC(StoredKey, AuthMessage)
       - ClientProof = ClientKey XOR ClientSignature

    5. JSON-RPC Request:
       {
         "method": "auth.login_ex",
         "params": [{
           "mechanism": "SCRAM",
           "scram_type": "CLIENT_FINAL_MESSAGE",
           "rfc_str": "c=<channel-binding>,r=<nonce>,p=<client-proof>"
         }]
       }
    ----------------------------------------------------------------------------------------------->

                                                       6. Server verifies:
                                                          - Recover ClientKey from proof
                                                          - Compute H(ClientKey)
                                                          - Compare with StoredKey

                                                       7. If valid, compute:
                                                          - ServerSignature using ServerKey

                                                       8. JSON-RPC Response:
                                                          {
                                                            "result": {
                                                              "response_type": "SCRAM_RESPONSE",
                                                              "scram_type": "SERVER_FINAL_MESSAGE",
                                                              "rfc_str": "v=<server-signature>"
                                                            }
                                                          }
    <-----------------------------------------------------------------------------------------------

    9. Client verifies:
       - Compute expected ServerSignature using ServerKey
       - Compare with received signature

    [Authentication Complete - Both parties verified]

## RFC References

- RFC 5802: Salted Challenge Response Authentication Mechanism (SCRAM)
- RFC 4013: SASLprep - String preparation for usernames and passwords
- RFC 3454: Preparation of Internationalized Strings ("stringprep")
- RFC 2104: HMAC: Keyed-Hashing for Message Authentication
"""

import hashlib
from enum import StrEnum
from typing import TypedDict

try:
    import truenas_pyscram  # type: ignore
except ImportError:
    # On some platforms the truenas_pyscram cpython extension is not available
    # in this case we fall back to using the pure python implementation in this
    # library
    from . import py_scram as truenas_pyscram


# Import constants
SCRAM_MAX_ITERS = getattr(truenas_pyscram, 'SCRAM_MAX_ITERS', 5000000)

# Export message classes, exception, and error codes for compatibility
ClientFirstMessage = truenas_pyscram.ClientFirstMessage
ServerFirstMessage = truenas_pyscram.ServerFirstMessage
ClientFinalMessage = truenas_pyscram.ClientFinalMessage
ServerFinalMessage = truenas_pyscram.ServerFinalMessage
CryptoDatum = truenas_pyscram.CryptoDatum
ScramError = truenas_pyscram.ScramError

# Export error codes
SCRAM_E_AUTH_FAILED = getattr(truenas_pyscram, 'SCRAM_E_AUTH_FAILED', 7)


class ScramMessageType(StrEnum):
    CLIENT_FIRST_MESSAGE = 'CLIENT_FIRST_MESSAGE'
    SERVER_FIRST_MESSAGE = 'SERVER_FIRST_MESSAGE'
    CLIENT_FINAL_MESSAGE = 'CLIENT_FINAL_MESSAGE'
    SERVER_FINAL_MESSAGE = 'SERVER_FINAL_MESSAGE'


class ScramMessage(TypedDict):
    scram_type: ScramMessageType
    """ The type of SCRAM message. This will be one of: "CLIENT_FIRST_MESSAGE",
    "SERVER_FIRST_MESSAGE", "CLIENT_FINAL_MESSAGE", "SERVER_FINAL_MESSAGE" """
    rfc_str: str
    """ The RFC5802 string associated with the scram_type. These messages are generated
    by the scram library based on the client and/or server response and stored secrets. """


class TNScramClient:
    """
    Implementation of SCRAM-SHA512 client for authentication with TrueNAS servers over JSON-RPC.
    The TrueNAS API client will convert client / server JSON-RPC communication to the dataclasses
    defined above.
    """
    def __init__(
        self,
        *,
        raw_key_material: str | None = None,
        client_key: truenas_pyscram.CryptoDatum | None = None,
        stored_key: truenas_pyscram.CryptoDatum | None = None,
        server_key: truenas_pyscram.CryptoDatum | None = None,
        api_key_id: int = 0,
    ):
        """
        Initialize SCRAM client with either raw key material (password/API key) or pre-computed keys.

        Args:
            raw_key_material: Raw password or API key string
            client_key: Pre-computed client key (mandatory if raw_key_material not provided)
            stored_key: Pre-computed stored key (mandatory if raw_key_material not provided)
            server_key: Pre-computed server key (optional, needed for server verification)
            api_key_id: API key ID (0 for password authentication, non-zero for API key auth)

        Raises:
            ValueError: If neither raw_key_material nor (client_key and stored_key) are provided
        """
        if raw_key_material is None:
            if client_key is None or stored_key is None:
                raise ValueError('Must provide either raw_key_material or both client_key and stored_key')

        self.raw_key_material = raw_key_material
        self.client_key = client_key
        self.stored_key = stored_key
        self.server_key = server_key
        self.api_key_id = api_key_id

        # These will be populated during the authentication flow
        self.client_first_message = None
        self.server_first_message = None
        self.client_final_message = None
        self.server_final_message = None

    def get_client_first_message(
        self,
        username: str,
        gs2_header: str | None = None
    ) -> ScramMessage:
        """
        Generate the first message of the client-server exchange. We slightly depart
        from RFC here in that we're passing the api_key_id to the server as well as the username.
        This allows the server to select the correct key material for the authentication attempt
        since users may have more than one API key associated with their account.

        Args:
            username: Username for authentication
            gs2_header: GS2 header for channel binding (optional)

        Returns:
            ClientFirstMessage object
        """
        # Build kwargs, only include gs2_header if it's not None
        kwargs = {
            'username': username,
            'api_key_id': self.api_key_id,
        }
        if gs2_header is not None:
            kwargs['gs2_header'] = gs2_header

        self.client_first_message = truenas_pyscram.ClientFirstMessage(**kwargs)
        return ScramMessage(
            scram_type=ScramMessageType.CLIENT_FIRST_MESSAGE,
            rfc_str=str(self.client_first_message)
        )

    def get_client_final_message(
        self,
        server_resp_dict: ScramMessage,
        channel_binding: truenas_pyscram.CryptoDatum | None = None,
    ) -> ScramMessage:
        """
        RFC5802 section 3 (SCRAM Algorithm Overview) has the following description:

        SaltedPassword  := Hi(Normalize(password), salt, i)
        ClientKey       := HMAC(SaltedPassword, "Client Key")
        StoredKey       := H(ClientKey)
        AuthMessage     := client-first-message-bare + "," +
                           server-first-message + "," +
                           client-final-message-without-proof
        ClientSignature := HMAC(StoredKey, AuthMessage)
        ClientProof     := ClientKey XOR ClientSignature

        Args:
            server_resp_dict: Server response dictionary with 'scram_type' and 'rfc_str'
            channel_binding: Optional channel binding data

        Returns:
            ClientFinalMessage object
        """
        if server_resp_dict['scram_type'] != ScramMessageType.SERVER_FIRST_MESSAGE:
            raise TypeError(f'{server_resp_dict["scram_type"]}: unexpected response type')

        server_resp = truenas_pyscram.ServerFirstMessage(rfc_string=server_resp_dict['rfc_str'])
        if server_resp.iterations > SCRAM_MAX_ITERS:
            raise ValueError(f'{server_resp.iterations}: received unexpectedly high iteration count from server')

        self.server_first_message = server_resp

        # Generate keys if we have raw_key_material
        if self.raw_key_material is not None:
            # Convert raw password/key to bytes and compute salted password
            password_bytes = self.raw_key_material.encode('utf-8')

            # Compute salted password using PBKDF2-HMAC-SHA512 (scram_hi)
            salted_password_bytes = hashlib.pbkdf2_hmac(
                'sha512',
                password_bytes,
                bytes(server_resp.salt),
                server_resp.iterations
            )
            salted_password = truenas_pyscram.CryptoDatum(salted_password_bytes)

            # Generate auth data from salted password
            auth_data = truenas_pyscram.generate_scram_auth_data(
                salted_password=salted_password,
                salt=server_resp.salt,
                iterations=server_resp.iterations
            )
            self.client_key = auth_data.client_key
            self.stored_key = auth_data.stored_key
            if self.server_key is None:
                self.server_key = auth_data.server_key

        # Create client final message
        self.client_final_message = truenas_pyscram.ClientFinalMessage(
            client_first=self.client_first_message,
            server_first=self.server_first_message,
            client_key=self.client_key,
            stored_key=self.stored_key,
            channel_binding=channel_binding
        )
        return ScramMessage(
            scram_type=ScramMessageType.CLIENT_FINAL_MESSAGE,
            rfc_str=str(self.client_final_message)
        )

    def verify_server_final_message(self, server_resp_dict: ScramMessage) -> bool:
        """
        This is the final stage where we verify that the server has access to the
        the ServerKey. See RFC5802 section 3.

        The server signature is computed as:
        ServerSignature := HMAC(ServerKey, AuthMessage)

        Args:
            server_resp_dict: Server response dictionary with 'scram_type' and 'rfc_str'

        Returns:
            True if verification succeeds

        Raises:
            TypeError: If response type is not SERVER_FINAL_MESSAGE
            ValueError: If server response lacks signature or verification fails
        """
        if server_resp_dict['scram_type'] != ScramMessageType.SERVER_FINAL_MESSAGE:
            raise TypeError(f'{server_resp_dict["scram_type"]}: unexpected response type')

        server_resp = truenas_pyscram.ServerFinalMessage(rfc_string=server_resp_dict['rfc_str'])
        if not server_resp.signature:
            raise ValueError('Server response lacks signature')

        self.server_final_message = server_resp

        # Verify the server signature
        if self.server_key is None:
            raise ValueError('Cannot verify server signature without server_key')

        # Both C extension and pure Python raise ScramError on failure
        # Returns None on success
        truenas_pyscram.verify_server_signature(
            client_first=self.client_first_message,
            server_first=self.server_first_message,
            client_final=self.client_final_message,
            server_final=self.server_final_message,
            server_key=self.server_key
        )

        return True
