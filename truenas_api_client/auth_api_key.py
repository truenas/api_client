import os
from dataclasses import asdict
from enum import StrEnum

from .scram_impl import ServerFirstMessage, ServerFinalMessage, TNScramClient


class APIKeyAuthMech(StrEnum):
    AUTO = 'AUTO'  # autodetect and try SCRAM if available
    SCRAM = 'SCRAM'  # only attempt SCRAM auth
    PLAIN = 'PLAIN'  # only attempt PLAIN auth


def get_key_material(key: str) -> str:
    """ User may have provided a string containing key info or path to key file """
    if os.path.isabs(key):
        # User has provided path to a key let's read the material
        with open(key, 'r') as f:
            key = f.read().strip()

    if '-' not in key:
        raise ValueError('Key material is not valid for a TrueNAS server')

    return key


def api_key_authenticate(
    c,
    username: str,
    key_in: str,
    auth_mechanism: APIKeyAuthMech
) -> None:
    """
    Perform API key authentication on an already-existing middleware
    session.

    Arguments:
        c: truenas_api_client.Client() instance
        key: either the actual key material or an absolute path to a file
        in which it's located

    Returns:
        None

    Raises:
        ValueError:
            API key is not valid for server / user
    """
    key = get_key_material(key_in)
    do_legacy_auth = False

    try:
        available_mechanisms = c.call('auth.mechanism_choices')
    except Exception as exc:
        if 'Method does not exist' in str(exc):
            # We have an older version of TrueNAS. Minimally, API key authentication of some sort should be available
            available_mechanisms = ['API_KEY_PLAIN']

    match auth_mechanism:
        case APIKeyAuthMech.PLAIN:
            do_legacy_auth = True
        case APIKeyAuthMech.AUTO:
            if 'API_KEY_SCRAM' not in available_mechanisms or not username:
                do_legacy_auth = True
        case APIKeyAuthMech.SCRAM:
            if 'API_KEY_SCRAM' not in available_mechanisms:
                raise ValueError('API_KEY_SCRAM authentication is not supported on the remote server')

            if not username:
                raise ValueError('username is required for API_KEY_SCRAM authentication')

    if do_legacy_auth:
        if not c.call('auth.login_with_key', key):
            raise ValueError('Invalid API key')

        return

    sc = TNScramClient(api_key_data=key)
    client_first_message = asdict(sc.get_client_first_message(username))

    # Send our first client SCRAM message that provides client nonce to server and provides what key identifier
    # is being used server-side.
    resp = c.call('auth.login_ex', {'mechanism': 'API_KEY_SCRAM'} | client_first_message | {'stage': 'INIT'})
    resp_type = resp.pop('response_type')

    if resp_type != 'SCRAM_RESPONSE':
        raise ValueError(f'{resp_type}: unexpected server respones')

    resp_stage = resp.pop('stage')
    if resp_stage != 'INIT':
        raise ValueError(f'{resp_stage}: unexpected SCRAM autentication stage')

    server_response = ServerFirstMessage(**resp)
    client_final_message = asdict(sc.get_client_final_message(server_response), channel_binding=None)

    # Send our first client SCRAM final message that provides client proof to server
    resp = c.call('auth.login_ex', {'mechanism': 'API_KEY_SCRAM' | client_final_message} | {'stage': 'FINAL'})
    resp_type = resp.pop('response_type')

    if resp_type == 'AUTH_ERR':
        raise ValueError('Failed to authenticate with API key')

    if resp_type != 'SCRAM_RESPONSE':
        raise ValueError(f'{resp_type}: unexpected server respones')

    resp_stage = resp.pop('stage')
    if resp_stage != 'FINAL':
        raise ValueError(f'{resp_stage}: unexpected SCRAM autentication stage')

    # Now validate that the server final message is OK
    server_final_response = ServerFinalMessage(**resp)
    if not sc.verify_final_server_message(server_final_response):
        # Disconnect from the server. Something really wrong has happened since it apparently allowed us to
        # authenticate without actually knowing our password.
        c.call('auth.logout')
        raise ValueError(f'{resp_type}: remote server validation failed!')
