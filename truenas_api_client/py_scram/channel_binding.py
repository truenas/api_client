# SPDX-License-Identifier: LGPL-3.0-or-later
# Pure python RFC 5929 tls-server-end-point channel binding.
#
# Mirrors scram_compute_tls_server_end_point() in the truenas_scram C library so
# that py_scram and the truenas_pyscram cpython extension produce identical
# bindings for the same certificate. The C library selects the digest with
# OpenSSL's X509_get_signature_info(); the maps and RSASSA-PSS handling below
# reproduce that selection without an OpenSSL/cryptography dependency.
#
# IMPORTANT: this pure-python implementation is a FALLBACK -- it runs only when the
# truenas_pyscram C extension is not installed (see scram_impl.py, which prefers
# truenas_pyscram.compute_tls_server_end_point() and drops to py_scram only on
# ImportError). In a normal install the C extension is present, so the parser below
# is rarely exercised; that is exactly why it is conformance-tested against both
# truenas_pyscram (tests/scram/test_compatibility.py) and python-cryptography
# (tests/scram/test_py_scram.py) across every supported signature algorithm.

import hashlib

from .scram_crypto import CryptoDatum


__all__ = ['CB_TLS_SERVER_END_POINT', 'compute_tls_server_end_point']


# RFC 5929 channel-binding type name (the "cb-name" in a "p=" gs2 flag).
CB_TLS_SERVER_END_POINT = 'tls-server-end-point'


# Map a certificate signatureAlgorithm OID to its *raw* signature digest -- before
# the RFC 5929 4.1 MD5/SHA-1 -> SHA-256 promotion, which compute_tls_server_end_point
# applies uniformly below. This mirrors OpenSSL's OBJ_find_sigid_algs() (used by
# X509_get_signature_info()), which the C library relies on. RSASSA-PSS is handled
# separately because its digest lives in the signature parameters, not the OID;
# EdDSA is intentionally absent (no single well-defined hash -> undefined, rejected).
_SIG_OID_TO_HASH = {
    # RSASSA-PKCS1-v1_5
    '1.2.840.113549.1.1.4': 'md5',      # md5WithRSAEncryption  -> promoted to sha256
    '1.2.840.113549.1.1.5': 'sha1',     # sha1WithRSAEncryption -> promoted to sha256
    '1.2.840.113549.1.1.14': 'sha224',  # sha224WithRSAEncryption
    '1.2.840.113549.1.1.11': 'sha256',  # sha256WithRSAEncryption
    '1.2.840.113549.1.1.12': 'sha384',  # sha384WithRSAEncryption
    '1.2.840.113549.1.1.13': 'sha512',  # sha512WithRSAEncryption
    # ECDSA
    '1.2.840.10045.4.1': 'sha1',        # ecdsa-with-SHA1 -> promoted to sha256
    '1.2.840.10045.4.3.1': 'sha224',    # ecdsa-with-SHA224
    '1.2.840.10045.4.3.2': 'sha256',    # ecdsa-with-SHA256
    '1.2.840.10045.4.3.3': 'sha384',    # ecdsa-with-SHA384
    '1.2.840.10045.4.3.4': 'sha512',    # ecdsa-with-SHA512
    # DSA (OpenSSL resolves these via OBJ_find_sigid_algs; SHA-384/512 DSA have no
    # OpenSSL sigid and are therefore omitted so we reject them exactly as C does).
    '1.2.840.10040.4.3': 'sha1',        # id-dsa-with-sha1 -> promoted to sha256
    '2.16.840.1.101.3.4.3.1': 'sha224',  # id-dsa-with-sha224
    '2.16.840.1.101.3.4.3.2': 'sha256',  # id-dsa-with-sha256
}

# RSASSA-PSS encodes its message digest in the signatureAlgorithm parameters
# (RSASSA-PSS-params), not in the OID, so it is resolved separately.
_RSASSA_PSS_OID = '1.2.840.113549.1.1.10'

# Digest OIDs that can appear in an RSASSA-PSS hashAlgorithm field.
_HASH_OID_TO_NAME = {
    '1.2.840.113549.2.5': 'md5',
    '1.3.14.3.2.26': 'sha1',
    '2.16.840.1.101.3.4.2.4': 'sha224',
    '2.16.840.1.101.3.4.2.1': 'sha256',
    '2.16.840.1.101.3.4.2.2': 'sha384',
    '2.16.840.1.101.3.4.2.3': 'sha512',
}


def _read_tlv(buf: bytes, offset: int) -> tuple[int, int, int]:
    """Read a DER TLV header. Returns (tag, value_start, value_end).

    Only the low-tag-number form is handled, which is all that is needed to reach
    a certificate's signatureAlgorithm (SEQUENCE/OBJECT IDENTIFIER tags) and the
    RSASSA-PSS parameters. Raises ValueError (rather than IndexError) on truncated
    input, since the certificate comes off the wire.
    """
    if offset + 2 > len(buf):
        raise ValueError('truncated DER (TLV header)')
    tag = buf[offset]
    ptr = offset + 1
    length_byte = buf[ptr]
    ptr += 1
    if length_byte < 0x80:
        length = length_byte
    else:
        num = length_byte & 0x7f
        if ptr + num > len(buf):
            raise ValueError('truncated DER (length)')
        length = int.from_bytes(buf[ptr:ptr + num], 'big')
        ptr += num
    if ptr + length > len(buf):
        raise ValueError('truncated DER (value)')
    return tag, ptr, ptr + length


def _decode_oid(data: bytes) -> str:
    first = data[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in data[1:]:
        value = (value << 7) | (byte & 0x7f)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return '.'.join(parts)


def _signature_algorithm(cert_der: bytes) -> tuple[str, bytes]:
    """Return (oid, parameters) of the certificate's signatureAlgorithm.

    ``parameters`` is the raw DER of the AlgorithmIdentifier parameters field (the
    bytes following the algorithm OID), or ``b''`` when absent. Needed for
    RSASSA-PSS, whose digest is carried there rather than in the OID.
    """
    # Certificate ::= SEQUENCE { tbsCertificate SEQUENCE, signatureAlgorithm SEQUENCE, ... }
    tag, cert_start, _ = _read_tlv(cert_der, 0)
    if tag != 0x30:
        raise ValueError('not a DER certificate')

    # Skip tbsCertificate.
    tag, _, after_tbs = _read_tlv(cert_der, cert_start)
    if tag != 0x30:
        raise ValueError('malformed certificate (tbsCertificate)')

    # signatureAlgorithm ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY }
    tag, sig_alg_start, sig_alg_end = _read_tlv(cert_der, after_tbs)
    if tag != 0x30:
        raise ValueError('malformed certificate (signatureAlgorithm)')

    tag, oid_start, oid_end = _read_tlv(cert_der, sig_alg_start)
    if tag != 0x06:
        raise ValueError('malformed certificate (algorithm OID)')

    oid = _decode_oid(cert_der[oid_start:oid_end])
    parameters = cert_der[oid_end:sig_alg_end]
    return oid, parameters


def _rsassa_pss_hash(parameters: bytes) -> str:
    """Extract the message digest from RSASSA-PSS-params.

        RSASSA-PSS-params ::= SEQUENCE {
            hashAlgorithm [0] AlgorithmIdentifier DEFAULT sha1, ... }

    An absent hashAlgorithm defaults to SHA-1 (RFC 4055), matching what OpenSSL
    reports for such a certificate (which the RFC 5929 4.1 promotion then maps to
    SHA-256). Raises ValueError for an unrecognized digest, as the C library does.
    """
    if not parameters:
        return 'sha1'  # all params defaulted

    tag, seq_start, seq_end = _read_tlv(parameters, 0)
    if tag != 0x30:
        raise ValueError('malformed RSASSA-PSS parameters')
    if seq_start >= seq_end:
        return 'sha1'  # empty SEQUENCE -> all defaults

    # First element, if present, is the [0] EXPLICIT hashAlgorithm.
    tag, h_start, h_end = _read_tlv(parameters, seq_start)
    if tag != 0xA0:
        return 'sha1'  # hashAlgorithm omitted -> default SHA-1

    tag, alg_start, _ = _read_tlv(parameters, h_start)
    if tag != 0x30:
        raise ValueError('malformed RSASSA-PSS hashAlgorithm')

    tag, oid_start, oid_end = _read_tlv(parameters, alg_start)
    if tag != 0x06:
        raise ValueError('malformed RSASSA-PSS hashAlgorithm OID')

    oid = _decode_oid(parameters[oid_start:oid_end])
    name = _HASH_OID_TO_NAME.get(oid)
    if name is None:
        raise ValueError(f'tls-server-end-point: unsupported RSASSA-PSS hash {oid}')
    return name


def compute_tls_server_end_point(cert_der: bytes) -> CryptoDatum:
    """Compute the RFC 5929 tls-server-end-point channel binding for a DER cert.

    The binding is the certificate hashed with the digest from its own signature
    algorithm, with MD5 and SHA-1 promoted to SHA-256 (RFC 5929 4.1). RSASSA-PSS is
    supported by reading the digest from its signature parameters, and DSA/ECDSA/
    RSA-PKCS1 from the algorithm OID. Signature algorithms with no single
    well-defined hash (e.g. EdDSA) are rejected. This mirrors OpenSSL's
    X509_get_signature_info(), which the C library uses.
    """
    cert_der = bytes(cert_der)
    oid, parameters = _signature_algorithm(cert_der)

    if oid == _RSASSA_PSS_OID:
        hash_name = _rsassa_pss_hash(parameters)
    else:
        hash_name = _SIG_OID_TO_HASH.get(oid)
    if hash_name is None:
        raise ValueError(f'tls-server-end-point is undefined for signature algorithm {oid}')

    # RFC 5929 4.1: MD5 and SHA-1 signature hashes are promoted to SHA-256.
    if hash_name in ('md5', 'sha1'):
        hash_name = 'sha256'

    digest = hashlib.new(hash_name, cert_der).digest()
    return CryptoDatum(digest)
