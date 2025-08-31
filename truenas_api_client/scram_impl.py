# Data classes and implementation of SCRAM-SHA-512 authentication
# This is based on RFC5802 and later RFCs and a 2025 draft for
# SCRAM-SHA-512.
#
# Details of authentication exchange between client and server
# are in RFC5802 Section 5.

import hmac
import hashlib
import secrets

from base64 import b64encode, b64decode
from dataclasses import dataclass
from enum import StrEnum


class TNScramAuthMessage(StrEnum):
    API_KEY_SCRAM = 'API_KEY_SCRAM'
    API_KEY_SCRAM_FINAL = 'API_KEY_SCRAM_FINAL'


class TNScramAuthResponse(StrEnum):
    SCRAM_RESP_INIT = 'SCRAM_RESP_INIT'
    SCRAM_RESP_FINAL = 'SCRAM_RESP_FINAL'


SCRAM_MAX_ITERS = 5000000  # We set maximum iterations to in theory prevent DOS from malicious server


@dataclass
class ClientFirstMessage:
    """
    The first authentication message from the client. This initiates the conversation with the server. At this point
    the SCRAM client is in posession of a username and password (or a ClientKey/ServerKey).

    For this implementation we require 32 bytes that are base64-encoded. This value MUST be different for each
    authentication attempt.

    API keys returned from the truenas server contain its datastore primary key `api_key_id` and actual key material
    separated by a dash (-) character. For example: "7-VqZfWCloeIoYsJbquX7BGaD45JBtOUx0NFHxg5ll7e4QLH1cG5XTtdGU0KbBxxRL"
    has an api_key_id of `7`.
    """
    api_key_id: int
    username: str
    nonce: str

    def to_rfc_string(self) -> str:
        """ Convert our data class into the strings specified in RFC5802. Used for some computations """
        return f'n={self.username},r={self.nonce}'


@dataclass
class ServerFirstMessage:
    """
    The server response to the first authentication message from the client.

    This response includes the salt and iteration count that the client should use for creating the ClientProof. The
    nonce returned by the server is the client nonce string with the server nonce string appended to it.
    """
    salt: str  # base64 encoded
    iteration_count: int
    nonce: str  # client nonce + nonce generated server-side (will be 64 base64 characters)

    def to_rfc_string(self) -> str:
        """ Convert our data class into the strings specified in RFC5802. Used for some computations """
        return f'r={self.nonce},s={self.salt},i={self.iteration_count}'


@dataclass
class ClientFinalMessage:
    """
    After receiving the ServerFirstMessage, the client sends the nonce from the ServerFirstMessage and a client_proof
    computed using pbkdf_sha512 and then base64 encoded.

    Currently we don't support channel bindings.
    """
    channel_binding: str | None  # base64 encoded GS2 Header for SCRAM-SHA512-PLUS.
    nonce: str  # Copy of nonce from ServerFirstMessage
    client_proof: str | None  # base64 encoded

    def to_rfc_string(self) -> str:
        gs2_header = self.channel_binding or 'biws'  # biws == base64("")
        if not self.client_proof:
            return f'c={gs2_header},r={self.nonce}'

        return f'c={gs2_header},r={self.nonce},p={self.client_proof}'


@dataclass
class ServerFinalMessage:
    """
    This is the final message from the server after successful authentication. It contains a single key "signature"
    that the client uses to verify that the server has access to the user's authentication information.
    """
    signature: str  # base64 encoded


# The following functions are defined and named in a way to make them easier to understand in
# the context of the authentication RFC

def generate_scram_nonce() -> str:
    """ Create a base64 string containing random 32 bytes """
    return b64encode(secrets.token_bytes(32)).decode()


def hi(password: bytes, salt: bytes, iterations: int) -> bytes:
    """ pbkdf2_hmac. Function named to line up directly with RFC5802 pseudo-code for Hi() """
    return hashlib.pbkdf2_hmac('sha512', password, salt, iterations)


def h(data: bytes) -> bytes:
    """SHA-512 hash function. Function named to line up directly wiht RFC5802 pseudo-code for H()"""
    return hashlib.sha512(data).digest()


def hmac_sha512(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA-512"""
    return hmac.new(key, data, hashlib.sha512).digest()


def create_scram_client_key(salted_api_key: bytes) -> bytes:
    """ Create the "ClientKey" specified in RFC """
    return hmac_sha512(salted_api_key, b'Client Key')


def create_scram_server_key(salted_api_key: bytes) -> bytes:
    """ Create the "ServerKey" specified in RFC """
    return hmac_sha512(salted_api_key, b'Server Key')


def create_scram_auth_message(
    client_first: ClientFirstMessage,
    server_first: ServerFirstMessage,
    client_final_no_proof: ClientFinalMessage,
):
    """ Create the "AuthMessage" as specified in RFC. """
    c1_rfc = client_first.to_rfc_string()
    s1_rfc = server_first.to_rfc_string()
    c2_rfc = client_final_no_proof.to_rfc_string()
    return f'{c1_rfc},{s1_rfc},{c2_rfc}'


class TNScramClient:
    """
    Implmentation of SCRAM-SHA512 client for authentication with TrueNAS servers over JSON-RPC.
    The TrueNAS API client will convert client / server JSON-RPC communication to the dataclasses
    defined above.
    """
    def __init__(self, api_key_data: str):
        key_id, key_data = api_key_data.split('-', 1)
        self.api_key_id = int(key_id)
        self.api_key_data = key_data
        self.auth_message = None

        # We need to keep a copy of the first message we send to the server since it's
        # used to generate the AuthMessage that's part of the ClientSignature / ClientProof
        # in the final client message
        self.client_first_message = None

    def get_client_first_message(self, username: str) -> ClientFirstMessage:
        """
        Generate the first message of the client-server exchange. We slightly depart
        from RFC here in that we're passing the api_key_id to the server as well as the username.
        This allows the server to select the correct key material for the authentication attempt
        since users may have more than one API key associated with their account.
        """
        self.client_first_message = ClientFirstMessage(
            username=username,
            api_key_id=self.api_key_id,
            nonce=generate_scram_nonce()
        )
        return self.client_first_message

    def get_client_final_message(
        self,
        server_resp: ServerFirstMessage,
        channel_binding: str | None
    ) -> ClientFinalMessage:
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
        """
        if channel_binding is not None:
            raise NotImplementedError('Channel binding support has not been addded yet')

        if server_resp.iteration_count > SCRAM_MAX_ITERS:
            raise ValueError(f'{server_resp.iteration_count}: recieved unexpectedly high iteration count from server')

        message = ClientFinalMessage(channel_binding=channel_binding, nonce=server_resp.nonce, client_proof=None)

        # Compute the SaltedPassword. We store a copy because it will be reused for validating
        # the server response.
        self.salted_api_key = hi(self.api_key_data.encode(), b64decode(server_resp.salt), server_resp.iteration_count)

        # Now create the ClientKey
        client_key = create_scram_client_key(self.salted_api_key)

        # Now create the StoredKey that is used to generate the ClientSignature
        stored_key = h(client_key)

        # Now get the components we use to create the AuthMessage
        self.auth_message = create_scram_auth_message(self.client_first_message, server_resp, message)

        # Now get the ClientSignature
        client_signature = hmac_sha512(stored_key, self.auth_message.encode())

        # Now create the ClientProof for the message
        client_proof = bytes(a ^ b for a, b in zip(client_key, client_signature))
        message.client_proof = b64encode(client_proof).decode()

        return message

    def verify_server_final_message(self, server_resp: ServerFinalMessage) -> bool:
        """
        This is the final stage where we verify that the server has access to the
        the ServerKey. See RFC5802 section 3.
        """

        if not server_resp.signature:
            raise ValueError('Server response lacks signature')

        server_key = create_scram_server_key(self.salted_api_key)
        expected_signature = hmac_sha512(server_key, self.auth_message.encode())
        received_signature = b64decode(server_resp.signature)
        return hmac.compare_digest(expected_signature, received_signature)


@dataclass
class TNScramServerData:
    """
    Dataclass containing required information for SCRAM server to authenticate a credential.

    algorithm - cryptographic algorithm used by server. This is currently hard-coded to SHA512
    salt - random octet string that is combined with key before applying one-way encryption function.
    iteration_count - number of iterations of the hash function
    server_key - output of HMAC(SaltedPassword, "Server Key")
    stored_key - output of H(HMAC(SaltedPassword, "Client Key"))
    """
    algorithm: str
    salt: bytes
    iteration_count: int
    stored_key: bytes
    server_key: bytes


class TNScramServer:
    """
    Reference implementation of the server portion of the authentication protocol. This can
    be used for development and testing purposes
    """

    def __init__(self, data: TNScramServerData):
        """
        This assumes that the server has already used the `username` and `api_key_id` to
        retrieve the stored_key, server_key, salt, and iters for checking the auth attempt.
        These all can be parsed out of existing "PLAIN" API key on server backend. Example:

        ' (a)            (b)      (c)                    (d)
        '$pbkdf2-sha512$500000$OU9jM3RlbjBjZUNFUk1QLw==$rAIjTGgc0oae/nfNKoFonWQmBSEjrofpIF6cRbXvUhFhrRZQ9OBFum7BarO5XJSgA6yR5WPcvmBcCtmkG3qCkg=='  # noqa

        contains the following elements per RFC5802:

        a. algorithm
        b. iterations
        c. salt (base64-encoded)
        d. hash "SaltedPassword" (base64-encoded)

        So what someone wishing to use above for plain API auth server-side should do is (referencing functions defined above):
        1. convert the above hash (d) into a StoredKey by the following operation:
        1a. b64decode the hash
        1b. client_key = create_scram_client_key(the_hash)
        1c. StoredKey = h(client_key)

        2. convert the above hash (d) into a ServerKey by the following operation
        2a. b64decode the hash
        2b. ServerKey = create_scram_server_key(the_hash)

        Server-side authentication only requires the server to keep the iterations, salt, StoredKey, and ServerKey.
        Although the latter two items can be calculated at runtime is the above SaltedPassword is stored on-disk, this
        may pose a security issue because someone with the above SaltedPassword (d) may be able to trivially construct
        a ClientKey without knowing the password.
        """
        self.data = data
        self.client_first_message = None
        self.server_first_message = None

    def get_server_first_message(self, client_resp: ClientFirstMessage) -> ServerFirstMessage:
        """
        We've received message from client including username and nonce. We respond
        with the iterations and salt needed to proceed with authentication (as well as our server
        nonce, which MUST be unique to this conversation).
        """

        # keep copy of first message since it will be used to validate the ClientProof
        # in its final message
        self.client_first_message = client_resp
        server_nonce = generate_scram_nonce()

        # keep copy of our response because we need the nonce to validate the ClientProof
        self.server_first_message = ServerFirstMessage(
            salt=b64encode(self.data.salt).decode(),
            iteration_count=self.data.iteration_count,
            nonce=client_resp.nonce + server_nonce
        )
        return self.server_first_message

    def get_server_final_message(self, client_resp: ClientFinalMessage) -> ServerFinalMessage | None:
        """
        Validate the ClientProof that the client generated to show it has access to either
        the original password or the ClientKey + StoredKey or the SaltedPassword. Returns
        ServerFinalMessage on success or None on failure.

        Server authenticates the client computing the ClientSignature and XORing that with the
        ClientProof (provided by the client in this message) to recover the ClientKey and then
        comparing digest with the StoredKey (self.stored_key). See RFC5802.
        """
        client_resp_no_proof = ClientFinalMessage(client_resp.channel_binding, client_resp.nonce, None)

        auth_message = create_scram_auth_message(
            self.client_first_message,
            self.server_first_message,
            client_resp_no_proof
        )

        client_proof = b64decode(client_resp.client_proof)
        client_signature = hmac_sha512(self.data.stored_key, auth_message.encode())
        assert len(client_proof) == len(client_signature)

        client_key = bytes(a ^ b for a, b in zip(client_proof, client_signature))

        if not hmac.compare_digest(h(client_key), self.data.stored_key):
            return None

        server_signature = hmac_sha512(self.data.server_key, auth_message.encode())

        return ServerFinalMessage(signature=b64encode(server_signature).decode())
