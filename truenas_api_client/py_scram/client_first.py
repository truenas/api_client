# SPDX-License-Identifier: LGPL-3.0-or-later
# ClientFirstMessage implementation

from base64 import b64encode

from .scram_crypto import generate_nonce
from .common import GS2_SEPARATOR, saslprep


__all__ = ['ClientFirstMessage']


class ClientFirstMessage:
    __rfc_str = '<UNITIALIZED>'

    def __generate_rfc_string(self):
        nonce_b64 = b64encode(self.nonce).decode()
        name = self.username
        hdr = self.gs2_header or 'n'

        # an API key id of zero means that we're doing scram auth with actual user credential
        if self.api_key_id != 0:
            # API key auth
            name += f':{self.api_key_id}'

        return f'{hdr}{GS2_SEPARATOR}n={name},r={nonce_b64}'

    def __init__(
        self,
        *,
        username: str,
        api_key_id: int = 0,
        gs2_header: str | None = None,
    ):
        if not username:
            raise ValueError('Must specify username')

        if not isinstance(username, str):
            raise TypeError('Username must be string')

        if not isinstance(api_key_id, int):
            raise TypeError('API key ID must be an integer')

        if gs2_header and not isinstance(gs2_header, str):
            raise TypeError('GS2 header must be string if provided')

        self.__nonce = generate_nonce()
        # RFC 5802, Section 5.1: "Before sending the username to the server, the client SHOULD
        # prepare the username using the 'SASLprep' profile [RFC4013] of the 'stringprep'
        # algorithm [RFC3454] treating it as a query string (i.e., unassigned Unicode code
        # points are allowed)."
        self.__username = saslprep(username)
        self.__api_key_id = api_key_id
        self.__gs2_header = gs2_header
        self.__rfc_str = self.__generate_rfc_string()

    @property
    def nonce(self):
        return self.__nonce

    @property
    def username(self):
        return self.__username

    @property
    def api_key_id(self):
        return self.__api_key_id

    @property
    def gs2_header(self):
        return self.__gs2_header

    def __str__(self):
        return self.__rfc_str
