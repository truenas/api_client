# Pure Python SCRAM-SHA-512 Implementation

This directory contains a pure Python implementation of the SCRAM-SHA-512 authentication mechanism as defined in [RFC 5802](https://tools.ietf.org/html/rfc5802).

## Purpose

This implementation serves as a **fallback** for platforms where the `truenas_pyscram` C extension is not available. The TrueNAS API client will automatically use this pure Python implementation when the C extension cannot be loaded.

The C extension ([truenas_scram](https://github.com/truenas/truenas_scram)) is the preferred implementation for performance reasons, but this fallback ensures compatibility across all platforms, including:
- Architectures where the C extension hasn't been compiled
- Development environments where building C extensions is inconvenient
- Non-Linux platforms or embedded systems

## SCRAM Protocol Overview

SCRAM (Salted Challenge Response Authentication Mechanism) is a secure authentication protocol that provides:

- **Mutual authentication**: Both client and server prove their identity
- **Password protection**: Passwords are never transmitted over the network
- **Salt and iteration count**: Protection against rainbow table attacks
- **Channel binding support**: Will be added in a future version

### Authentication Flow

The SCRAM authentication process involves four messages:

1. **Client First Message**: Client sends username and a randomly generated nonce
2. **Server First Message**: Server responds with salt, iteration count, and combined nonce
3. **Client Final Message**: Client sends proof of password knowledge (ClientProof)
4. **Server Final Message**: Server sends proof of server key knowledge (ServerSignature)

### Key Derivation

SCRAM uses PBKDF2 for key derivation:

```
SaltedPassword  := PBKDF2(Normalize(password), salt, iterations)
ClientKey       := HMAC(SaltedPassword, "Client Key")
StoredKey       := H(ClientKey)
ServerKey       := HMAC(SaltedPassword, "Server Key")
```

The client computes a proof without revealing the password:

```
ClientSignature := HMAC(StoredKey, AuthMessage)
ClientProof     := ClientKey XOR ClientSignature
```

The server verifies the client and computes its own signature:

```
ServerSignature := HMAC(ServerKey, AuthMessage)
```

## Implementation Structure

- **`scram_crypto.py`**: Cryptographic primitives (HMAC, SHA-512, XOR, constant-time comparison)
- **`client_first.py`**: ClientFirstMessage implementation
- **`server_first.py`**: ServerFirstMessage implementation
- **`client_final.py`**: ClientFinalMessage implementation
- **`server_final.py`**: ServerFinalMessage implementation
- **`verify.py`**: Server signature verification
- **`common.py`**: Shared constants and utilities
- **`error.py`**: Exception classes

## Usage

This implementation is used automatically by the `TNScramClient` class in `scram_impl.py`. You typically don't need to interact with these modules directly:

```python
from truenas_api_client.scram_impl import TNScramClient

# Create client with password
client = TNScramClient(raw_key_material="password123")

# Or with pre-computed keys
client = TNScramClient(
    client_key=client_key,
    stored_key=stored_key,
    server_key=server_key
)

# Follow SCRAM authentication flow
msg1 = client.get_client_first_message(username="user")
# ... exchange messages with server ...
msg2 = client.get_client_final_message(server_response)
# ... exchange messages with server ...
verified = client.verify_server_final_message(server_response)
```

## API Compatibility

This pure Python implementation maintains API compatibility with the `truenas_pyscram` C extension, ensuring seamless fallback behavior. All message classes, functions, and error codes are identical between the two implementations.

## Security Considerations

- Uses constant-time comparison for signature verification to prevent timing attacks
- Enforces maximum iteration count limit (`SCRAM_MAX_ITERS = 5,000,000`) to prevent DoS
- All cryptographic operations use Python's standard `hashlib` and `hmac` libraries

## Performance

While this pure Python implementation is fully functional and secure, it may be significantly slower than the C extension, particularly for high iteration counts. For production use on supported platforms, the C extension is strongly recommended.

## References

- [truenas_scram C Extension](https://github.com/truenas/truenas_scram) - High-performance C implementation
- [RFC 5802 - Salted Challenge Response Authentication Mechanism (SCRAM)](https://tools.ietf.org/html/rfc5802)
- [RFC 4013 - SASLprep: Stringprep Profile for User Names and Passwords](https://tools.ietf.org/html/rfc4013)
- [RFC 2104 - HMAC: Keyed-Hashing for Message Authentication](https://tools.ietf.org/html/rfc2104)
