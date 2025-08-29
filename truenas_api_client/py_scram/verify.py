# SPDX-License-Identifier: LGPL-3.0-or-later
# SCRAM verification functions

from base64 import b64encode

from .scram_crypto import CryptoDatum, scram_hmac_sha512, scram_xor_bytes, scram_h, scram_constant_time_compare
from .common import GS2_SEPARATOR, GS2_NO_CHANNEL_BINDING
from .client_first import ClientFirstMessage
from .server_first import ServerFirstMessage
from .client_final import ClientFinalMessage
from .server_final import ServerFinalMessage
from .error import ScramError, SCRAM_E_AUTH_FAILED


__all__ = ['verify_server_signature', 'verify_client_final_message']


def verify_server_signature(
    client_first: ClientFirstMessage,
    server_first: ServerFirstMessage,
    client_final: ClientFinalMessage,
    server_final: ServerFinalMessage,
    server_key: CryptoDatum
):
    """Verify the server signature in the ServerFinalMessage.

    This function is used by the client to verify that the server has access
    to the correct authentication credentials. It computes the expected
    ServerSignature and compares it with the signature in the ServerFinalMessage.

    Per RFC 5802 Section 3:
    ServerSignature := HMAC(ServerKey, AuthMessage)

    Args:
        client_first: The ClientFirstMessage that was sent
        server_first: The ServerFirstMessage that was received
        client_final: The ClientFinalMessage that was sent
        server_final: The ServerFinalMessage to verify
        server_key: The server key derived from the user's credentials

    Returns:
        None on success

    Raises:
        TypeError: If any parameter is not of the correct type
        ValueError: If any message object is not properly initialized
        ScramError: If signature verification fails
    """
    # Validate parameters
    if not isinstance(client_first, ClientFirstMessage):
        raise TypeError('client_first must be a ClientFirstMessage instance')

    if not isinstance(server_first, ServerFirstMessage):
        raise TypeError('server_first must be a ServerFirstMessage instance')

    if not isinstance(client_final, ClientFinalMessage):
        raise TypeError('client_final must be a ClientFinalMessage instance')

    if not isinstance(server_final, ServerFinalMessage):
        raise TypeError('server_final must be a ServerFinalMessage instance')

    if not isinstance(server_key, CryptoDatum):
        raise TypeError('server_key must be a CryptoDatum instance')

    # Compute the auth message
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

    auth_message = f'{client_first_bare},{server_first_str},{client_final_no_proof}'

    # Calculate expected ServerSignature = HMAC(ServerKey, AuthMessage)
    auth_message_bytes = CryptoDatum(auth_message.encode())
    expected_signature = scram_hmac_sha512(server_key, auth_message_bytes)

    # Compare the expected signature with the received signature
    if not scram_constant_time_compare(expected_signature, server_final.signature):
        raise ScramError('server signature verification failed', SCRAM_E_AUTH_FAILED)

    # Return None on success (like C extension)
    return None


def verify_client_final_message(
    client_first: ClientFirstMessage,
    server_first: ServerFirstMessage,
    client_final: ClientFinalMessage,
    stored_key: CryptoDatum
):
    """Verify the client proof in the ClientFinalMessage.

    This function is used by the server to verify that the client has access
    to the correct authentication credentials. It recovers the ClientKey from
    the ClientProof and verifies it against the StoredKey.

    Per RFC 5802 Section 3:
    ClientSignature := HMAC(StoredKey, AuthMessage)
    ClientKey := ClientProof XOR ClientSignature
    Verify: H(ClientKey) == StoredKey

    Args:
        client_first: The ClientFirstMessage that was received
        server_first: The ServerFirstMessage that was sent
        client_final: The ClientFinalMessage to verify
        stored_key: The stored key from the user's credentials

    Returns:
        None on success

    Raises:
        TypeError: If any parameter is not of the correct type
        ValueError: If any message object is not properly initialized
        ScramError: If client proof verification fails
    """
    # Validate parameters
    if not isinstance(client_first, ClientFirstMessage):
        raise TypeError('client_first must be a ClientFirstMessage instance')

    if not isinstance(server_first, ServerFirstMessage):
        raise TypeError('server_first must be a ServerFirstMessage instance')

    if not isinstance(client_final, ClientFinalMessage):
        raise TypeError('client_final must be a ClientFinalMessage instance')

    if not isinstance(stored_key, CryptoDatum):
        raise TypeError('stored_key must be a CryptoDatum instance')

    if not client_final.client_proof:
        raise ValueError('Client final message has no proof')

    # Compute the auth message
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

    auth_message = f'{client_first_bare},{server_first_str},{client_final_no_proof}'

    # Calculate ClientSignature = HMAC(StoredKey, AuthMessage)
    auth_message_bytes = CryptoDatum(auth_message.encode())
    client_signature = scram_hmac_sha512(stored_key, auth_message_bytes)

    # Recover ClientKey from ClientProof XOR ClientSignature
    recovered_client_key = scram_xor_bytes(client_final.client_proof, client_signature)

    # Verify that H(ClientKey) == StoredKey
    recovered_stored_key = scram_h(recovered_client_key)
    if not scram_constant_time_compare(recovered_stored_key, stored_key):
        raise ScramError('client proof verification failed', SCRAM_E_AUTH_FAILED)

    # Return None on success (like C extension)
    return None
