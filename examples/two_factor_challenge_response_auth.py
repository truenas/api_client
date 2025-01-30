import pyotp
import truenas_api_client

from getpass import getpass


TOTP_INTERVAL = 30
TOTP_DIGITS = 6
TOTP_FILE = "doesnotexist"
USERNAME = "myusername"
PASSWORD = "mypassword"


def get_totp_secret() -> str:
    """ This assumes the TOTP secret is written somewhere on client """
    try:
        with open(TOTP_FILE, 'r') as f:
            return f.read()
    except Exception:
        return None


def get_2fa_token(secret: str) -> str:
    return pyotp.TOTP(secret, interval=TOTP_INTERVAL, digits=TOTP_DIGITS).now()


def authenticate_client(c: truenas_api_client.Client) -> bool:
    resp = c.call("auth.login_ex", {
        "mechanism": "PASSWORD_PLAIN",
        "username": USERNAME,
        "password": PASSWORD
    })

    match resp["response_type"]:
        case "SUCCESS":
            # two-factor auth not configured for account
            return True
        case "AUTH_ERR":
            # Bad username or password
            return False
        case "OTP_REQUIRED":
            # two-factor is configured for account
            # getpass is here as example of how to prompt for password in script
            # This of course shouldn't be done if script isn't interactive.
            otp_token = get_2fa_token(secret) or getpass()
            resp = c.call("auth.login_ex_continue", {
                "mechanism": "OTP_TOKEN",
                "otp_token": otp_token
            })

            # For interactive session the `auth.login_ex_continue` may
            # reply with OTP_REQUIRED again if the user fat-fingered input
            # since this is machine input no amount of attempts will succeed
            return resp["response_type"] == "SUCCESS"
        case _:
            raise ValueError(f'{resp["response_type"]}: Unexpected response type')


secret = get_totp_secret()

with truenas_api_client.Client("wss://example.internal/api/current") as c:
    # Authenticate using some pre-existing API key
    assert authenticate_client(c)
