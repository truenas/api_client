# SPDX-License-Identifier: LGPL-3.0-or-later
# Pure python RFC 5929 tls-server-end-point channel binding.
#
# Mirrors scram_compute_tls_server_end_point() in the truenas_scram C library so
# that py_scram and the truenas_pyscram cpython extension produce identical
# bindings for the same certificate.

import hashlib

from .scram_crypto import CryptoDatum


__all__ = ['CB_TLS_SERVER_END_POINT', 'compute_tls_server_end_point']


# RFC 5929 channel-binding type name (the "cb-name" in a "p=" gs2 flag).
CB_TLS_SERVER_END_POINT = 'tls-server-end-point'


# Map a certificate signatureAlgorithm OID to the digest used for
# tls-server-end-point. Per RFC 5929 4.1 the certificate's own signature hash is
# used, except MD5 and SHA-1 are promoted to SHA-256. Values below are the
# already-promoted (effective) digest names.
_SIG_OID_TO_HASH = {
    # RSASSA-PKCS1-v1_5
    '1.2.840.113549.1.1.4': 'sha256',   # md5WithRSAEncryption  -> promoted
    '1.2.840.113549.1.1.5': 'sha256',   # sha1WithRSAEncryption -> promoted
    '1.2.840.113549.1.1.14': 'sha224',  # sha224WithRSAEncryption
    '1.2.840.113549.1.1.11': 'sha256',  # sha256WithRSAEncryption
    '1.2.840.113549.1.1.12': 'sha384',  # sha384WithRSAEncryption
    '1.2.840.113549.1.1.13': 'sha512',  # sha512WithRSAEncryption
    # ECDSA
    '1.2.840.10045.4.1': 'sha256',      # ecdsa-with-SHA1 -> promoted
    '1.2.840.10045.4.3.1': 'sha224',    # ecdsa-with-SHA224
    '1.2.840.10045.4.3.2': 'sha256',    # ecdsa-with-SHA256
    '1.2.840.10045.4.3.3': 'sha384',    # ecdsa-with-SHA384
    '1.2.840.10045.4.3.4': 'sha512',    # ecdsa-with-SHA512
}


def _read_tlv(buf: bytes, offset: int) -> tuple[int, int, int]:
    """Read a DER TLV header. Returns (tag, value_start, value_end).

    Only the low-tag-number form is handled, which is all that is needed to reach
    a certificate's signatureAlgorithm (SEQUENCE/OBJECT IDENTIFIER tags).
    """
    tag = buf[offset]
    ptr = offset + 1
    length_byte = buf[ptr]
    ptr += 1
    if length_byte < 0x80:
        length = length_byte
    else:
        num = length_byte & 0x7f
        length = int.from_bytes(buf[ptr:ptr + num], 'big')
        ptr += num
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


def _signature_algorithm_oid(cert_der: bytes) -> str:
    # Certificate ::= SEQUENCE { tbsCertificate SEQUENCE, signatureAlgorithm SEQUENCE, ... }
    tag, cert_start, _ = _read_tlv(cert_der, 0)
    if tag != 0x30:
        raise ValueError('not a DER certificate')

    # Skip tbsCertificate.
    tag, _, after_tbs = _read_tlv(cert_der, cert_start)
    if tag != 0x30:
        raise ValueError('malformed certificate (tbsCertificate)')

    # signatureAlgorithm ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY }
    tag, sig_alg_start, _ = _read_tlv(cert_der, after_tbs)
    if tag != 0x30:
        raise ValueError('malformed certificate (signatureAlgorithm)')

    tag, oid_start, oid_end = _read_tlv(cert_der, sig_alg_start)
    if tag != 0x06:
        raise ValueError('malformed certificate (algorithm OID)')

    return _decode_oid(cert_der[oid_start:oid_end])


def compute_tls_server_end_point(cert_der: bytes) -> CryptoDatum:
    """Compute the RFC 5929 tls-server-end-point channel binding for a DER cert.

    The binding is the certificate hashed with the digest from its own signature
    algorithm (MD5/SHA-1 promoted to SHA-256). Signature algorithms with no single
    well-defined hash (e.g. EdDSA, RSASSA-PSS) are rejected, matching the C library.
    """
    oid = _signature_algorithm_oid(bytes(cert_der))
    hash_name = _SIG_OID_TO_HASH.get(oid)
    if hash_name is None:
        raise ValueError(f'tls-server-end-point is undefined for signature algorithm {oid}')

    digest = hashlib.new(hash_name, bytes(cert_der)).digest()
    return CryptoDatum(digest)
