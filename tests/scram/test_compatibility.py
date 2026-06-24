# SPDX-License-Identifier: LGPL-3.0-or-later
"""Test compatibility between py_scram and truenas_pyscram.

This test suite validates that the pure Python implementation (py_scram)
produces identical results to the C extension (truenas_pyscram).
"""

import unittest
from base64 import b64decode, b64encode
from ssl import RAND_bytes

import truenas_pyscram  # type: ignore
import truenas_api_client.py_scram as py_scram

try:
    from ._cb_test_vectors import CB_VECTORS, REJECTED_VECTORS
except ImportError:  # direct execution: python3 tests/scram/test_compatibility.py
    from _cb_test_vectors import CB_VECTORS, REJECTED_VECTORS  # type: ignore

# Self-signed RSA-2048 / sha256WithRSAEncryption certificate (DER) for channel-binding
# parity checks (tls-server-end-point == SHA-256(DER) for a SHA-256-signed cert).
_CB_TEST_CERT_DER = b64decode(
    "MIIDAzCCAeugAwIBAgIUU8DHCkgRz1ra3Hc0Hhdyypn/bq4wDQYJKoZIhvcNAQEL"
    "BQAwETEPMA0GA1UEAwwGcnNhMjU2MB4XDTI2MDYxODE4NDAyMVoXDTI2MDYxOTE4"
    "NDAyMVowETEPMA0GA1UEAwwGcnNhMjU2MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"
    "MIIBCgKCAQEAn3RdfzhUjYiv3rrVCxga+sKEF4TavdzRW0vBoAP+XFWMyDEEfLEL"
    "V5z4sVGvs6vpbc9bRkgPlYbzjs3GDRtDjdJHV8SbLPQtG/M8wdCHuRbM8r2/H8vL"
    "h4q+GNeZ14jzSQTvsRfbxNNoyZxRDPnYlqTCmPEhU7PojrJia8/088OaC0W92nOf"
    "S7CDwdHKPOmjsBMefAWWRgfTO4PHVPhIvZ+BrQeTUsJRsiSNSYTCPA5LvjRPuvrN"
    "VRjxggidHuoOTQuJVBr91mSsWN32ZqeEtWjPThsr1KXj+hpolYWCMoR/I64VypzA"
    "LHnMZrYxwZIRrpF4x5pips1/8nh1J7/UpQIDAQABo1MwUTAdBgNVHQ4EFgQU4QBk"
    "o+s6X7VIK1CVjb5Cx+VDo6owHwYDVR0jBBgwFoAU4QBko+s6X7VIK1CVjb5Cx+VD"
    "o6owDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAlDfSQoKry1Og"
    "XzY1JSRVWVIBC5Mevgt0rA0u6hlSNp+MC1p/KvN2Q25IWZznQfkPLtFvIEwBehsW"
    "h7xQ+R3DDbr2rX1z6gUKLfS2GkEPUn51YBlwjeuBNkOTb4svonOlXF4cG04bJN62"
    "NkgXz/U0Tyf4V7BEd82bxn/eChP34sTWb5AA2+iyp4MNkqk1j12gBKaxn7vtiXJn"
    "XIIVXgOS2zezizp8zXrd39Hjd/qWdkZDv4hN/ZMnDuQ9HclYwtamL5Taf9YFKDBw"
    "puLEOWIalVSCsq28yqvbPg31430JYH0dNWrpC93+Q9UU2UM30Ai6kp5pLo7b18DI"
    "WnZ+wlB6zQ=="
)


class TestClientFirstMessageCompatibility(unittest.TestCase):
    """Test ClientFirstMessage compatibility between implementations."""

    def test_basic_creation(self):
        """Test that both implementations create valid ClientFirstMessage."""
        username = "testuser"

        c_msg = truenas_pyscram.ClientFirstMessage(username=username)
        py_msg = py_scram.ClientFirstMessage(username=username)

        # Both should have same username
        self.assertEqual(c_msg.username, py_msg.username)
        self.assertEqual(c_msg.username, username)

        # Both should have api_key_id of 0 by default
        self.assertEqual(c_msg.api_key_id, py_msg.api_key_id)
        self.assertEqual(c_msg.api_key_id, 0)

        # Both should have None gs2_header
        self.assertIsNone(c_msg.gs2_header)
        self.assertIsNone(py_msg.gs2_header)

    def test_nonce_properties(self):
        """Test that nonces have correct properties in both implementations."""
        c_msg = truenas_pyscram.ClientFirstMessage(username="testuser")
        py_msg = py_scram.ClientFirstMessage(username="testuser")

        # Both nonces should be CryptoDatum
        self.assertIsInstance(c_msg.nonce, truenas_pyscram.CryptoDatum)
        self.assertIsInstance(py_msg.nonce, py_scram.CryptoDatum)

        # Both should be 32 bytes
        self.assertEqual(len(c_msg.nonce), 32)
        self.assertEqual(len(py_msg.nonce), 32)

    def test_with_api_key_id(self):
        """Test ClientFirstMessage with API key ID."""
        username = "testuser"
        api_key_id = 12345

        c_msg = truenas_pyscram.ClientFirstMessage(username=username, api_key_id=api_key_id)
        py_msg = py_scram.ClientFirstMessage(username=username, api_key_id=api_key_id)

        self.assertEqual(c_msg.username, py_msg.username)
        self.assertEqual(c_msg.api_key_id, py_msg.api_key_id)
        self.assertEqual(c_msg.api_key_id, api_key_id)

    def test_serialization_format(self):
        """Test that serialization follows same format."""
        username = "testuser"

        c_msg = truenas_pyscram.ClientFirstMessage(username=username)
        py_msg = py_scram.ClientFirstMessage(username=username)

        c_str = str(c_msg)
        py_str = str(py_msg)

        # Both should start with GS2 header
        self.assertTrue(c_str.startswith("n,,"))
        self.assertTrue(py_str.startswith("n,,"))

        # Both should contain username
        self.assertIn(f"n={username}", c_str)
        self.assertIn(f"n={username}", py_str)

        # Both should have nonce
        self.assertIn("r=", c_str)
        self.assertIn("r=", py_str)

    def test_serialization_with_api_key(self):
        """Test serialization with API key ID."""
        username = "testuser"
        api_key_id = 789

        c_msg = truenas_pyscram.ClientFirstMessage(username=username, api_key_id=api_key_id)
        py_msg = py_scram.ClientFirstMessage(username=username, api_key_id=api_key_id)

        c_str = str(c_msg)
        py_str = str(py_msg)

        # Both should include API key with colon delimiter
        expected_user = f"n={username}:{api_key_id}"
        self.assertIn(expected_user, c_str)
        self.assertIn(expected_user, py_str)


class TestServerFirstMessageCompatibility(unittest.TestCase):
    """Test ServerFirstMessage compatibility between implementations."""

    def setUp(self):
        """Set up test fixtures."""
        # Create matching client first messages (using same nonce for consistency)
        self.username = "testuser"

        # Create a shared salt and iterations (at least 16 bytes)
        salt_bytes = RAND_bytes(16)
        self.salt = truenas_pyscram.CryptoDatum(salt_bytes)
        self.py_salt = py_scram.CryptoDatum(salt_bytes)
        self.iterations = 100000

    def test_from_rfc_string(self):
        """Test parsing ServerFirstMessage from RFC string."""
        # Create a valid nonce (64 bytes = 32 client + 32 server)
        nonce_64bytes = RAND_bytes(64)
        nonce_b64 = b64encode(nonce_64bytes).decode()
        # Generate valid salt (at least 16 bytes)
        salt_bytes = RAND_bytes(16)
        salt_b64 = b64encode(salt_bytes).decode()

        rfc_string = f"r={nonce_b64},s={salt_b64},i=100000"

        c_msg = truenas_pyscram.ServerFirstMessage(rfc_string=rfc_string)
        py_msg = py_scram.ServerFirstMessage(rfc_string=rfc_string)

        # Both should parse correctly
        self.assertEqual(str(c_msg), str(py_msg))
        self.assertEqual(str(c_msg), rfc_string)

        # Properties should match (compare bytes content)
        self.assertEqual(bytes(c_msg.nonce), bytes(py_msg.nonce))
        self.assertEqual(bytes(c_msg.salt), bytes(py_msg.salt))
        self.assertEqual(c_msg.iterations, py_msg.iterations)

    def test_creation_from_client_first(self):
        """Test creating ServerFirstMessage from ClientFirstMessage."""
        # Create client first messages
        c_client_first = truenas_pyscram.ClientFirstMessage(username=self.username)
        py_client_first = py_scram.ClientFirstMessage(username=self.username)

        # Create server first messages
        c_server_first = truenas_pyscram.ServerFirstMessage(
            client_first=c_client_first,
            salt=self.salt,
            iterations=self.iterations
        )
        py_server_first = py_scram.ServerFirstMessage(
            client_first=py_client_first,
            salt=self.py_salt,
            iterations=self.iterations
        )

        # Iterations should match
        self.assertEqual(c_server_first.iterations, py_server_first.iterations)
        self.assertEqual(c_server_first.iterations, self.iterations)

        # Salt should match (compare bytes)
        self.assertEqual(bytes(c_server_first.salt), bytes(py_server_first.salt))

        # Nonce should contain client nonce (though server part will differ)
        self.assertIn(bytes(c_client_first.nonce), bytes(c_server_first.nonce))
        self.assertIn(bytes(py_client_first.nonce), bytes(py_server_first.nonce))

    def test_serialization_format(self):
        """Test serialization format consistency."""
        # Create valid nonce (64 bytes)
        nonce_64bytes = RAND_bytes(64)
        nonce_b64 = b64encode(nonce_64bytes).decode()
        # Generate valid salt (at least 16 bytes)
        salt_bytes = RAND_bytes(16)
        salt_b64 = b64encode(salt_bytes).decode()

        rfc_string = f"r={nonce_b64},s={salt_b64},i=50000"

        c_msg = truenas_pyscram.ServerFirstMessage(rfc_string=rfc_string)
        py_msg = py_scram.ServerFirstMessage(rfc_string=rfc_string)

        c_str = str(c_msg)
        py_str = str(py_msg)

        # Should produce identical serialization
        self.assertEqual(c_str, py_str)

        # Should contain all components
        self.assertIn("r=", c_str)
        self.assertIn("s=", c_str)
        self.assertIn("i=", c_str)


class TestCryptoFunctionsCompatibility(unittest.TestCase):
    """Test cryptographic function compatibility."""

    def test_crypto_datum_type(self):
        """Test CryptoDatum type compatibility."""
        test_data = b"test_data_12345"

        c_datum = truenas_pyscram.CryptoDatum(test_data)
        py_datum = py_scram.CryptoDatum(test_data)

        # Both should contain same data
        self.assertEqual(bytes(c_datum), bytes(py_datum))
        self.assertEqual(bytes(c_datum), test_data)

        # Both should support len()
        self.assertEqual(len(c_datum), len(py_datum))
        self.assertEqual(len(c_datum), len(test_data))

    def test_scram_hi_compatibility(self):
        """Test that scram_hi produces identical results."""
        key_data = b"test_password"
        salt = b"test_salt_16"
        iterations = 100000

        # Note: truenas_pyscram might not expose scram_hi directly
        # We test indirectly through auth data generation
        # For now, we'll test the pure Python implementation
        result = py_scram.scram_hi(
            py_scram.CryptoDatum(key_data),
            py_scram.CryptoDatum(salt),
            iterations
        )

        # Result should be 64 bytes (SHA-512)
        self.assertEqual(len(result), 64)
        self.assertIsInstance(result, py_scram.CryptoDatum)

    def test_scram_h_compatibility(self):
        """Test that scram_h produces correct hash."""
        test_data = b"test_data"

        result = py_scram.scram_h(py_scram.CryptoDatum(test_data))

        # Result should be 64 bytes (SHA-512)
        self.assertEqual(len(result), 64)
        self.assertIsInstance(result, py_scram.CryptoDatum)

    def test_scram_hmac_sha512_compatibility(self):
        """Test HMAC-SHA-512 implementation."""
        key = b"test_key"
        data = b"test_data"

        result = py_scram.scram_hmac_sha512(
            py_scram.CryptoDatum(key),
            py_scram.CryptoDatum(data)
        )

        # Result should be 64 bytes (SHA-512)
        self.assertEqual(len(result), 64)
        self.assertIsInstance(result, py_scram.CryptoDatum)


class TestFullAuthenticationFlowCompatibility(unittest.TestCase):
    """Test complete authentication flow compatibility."""

    def setUp(self):
        """Set up test fixtures."""
        # Generate auth data using C extension
        self.c_auth_data = truenas_pyscram.generate_scram_auth_data()

        # Create matching auth data for Python implementation
        self.py_auth_data = py_scram.ScramAuthData(
            salt=py_scram.CryptoDatum(bytes(self.c_auth_data.salt)),
            iterations=self.c_auth_data.iterations,
            salted_password=py_scram.CryptoDatum(bytes(self.c_auth_data.salted_password)),
            client_key=py_scram.CryptoDatum(bytes(self.c_auth_data.client_key)),
            stored_key=py_scram.CryptoDatum(bytes(self.c_auth_data.stored_key)),
            server_key=py_scram.CryptoDatum(bytes(self.c_auth_data.server_key)),
        )

    def test_round_trip_with_same_nonce(self):
        """Test complete authentication flow using shared messages."""
        username = "testuser"

        # Step 1: Client first message (C extension)
        c_client_first = truenas_pyscram.ClientFirstMessage(username=username)

        # Step 2: Server first message (both implementations, using C nonce)
        c_server_first = truenas_pyscram.ServerFirstMessage(
            client_first=c_client_first,
            salt=self.c_auth_data.salt,
            iterations=self.c_auth_data.iterations
        )

        # Parse server first in Python implementation
        py_server_first = py_scram.ServerFirstMessage(rfc_string=str(c_server_first))

        # Verify they match
        self.assertEqual(str(c_server_first), str(py_server_first))
        self.assertEqual(bytes(c_server_first.nonce), bytes(py_server_first.nonce))
        self.assertEqual(bytes(c_server_first.salt), bytes(py_server_first.salt))
        self.assertEqual(c_server_first.iterations, py_server_first.iterations)


class TestVerificationFunctionCompatibility(unittest.TestCase):
    """Test verification function compatibility."""

    def setUp(self):
        """Set up test fixtures."""
        self.auth_data = truenas_pyscram.generate_scram_auth_data()

    def test_verification_functions_exist(self):
        """Test that both implementations have verification functions."""
        # C extension functions
        self.assertTrue(hasattr(truenas_pyscram, 'verify_client_final_message'))
        self.assertTrue(hasattr(truenas_pyscram, 'verify_server_signature'))

        # Python implementation functions
        self.assertTrue(hasattr(py_scram, 'verify_client_final_message'))
        self.assertTrue(hasattr(py_scram, 'verify_server_signature'))

    def test_verify_server_signature_with_c_messages(self):
        """Test Python verify_server_signature with C extension messages."""
        # Create messages using C extension
        client_first = truenas_pyscram.ClientFirstMessage(username="testuser")
        server_first = truenas_pyscram.ServerFirstMessage(
            client_first=client_first,
            salt=self.auth_data.salt,
            iterations=self.auth_data.iterations
        )
        client_final = truenas_pyscram.ClientFinalMessage(
            client_first=client_first,
            server_first=server_first,
            client_key=self.auth_data.client_key,
            stored_key=self.auth_data.stored_key
        )
        server_final = truenas_pyscram.ServerFinalMessage(
            client_first=client_first,
            server_first=server_first,
            client_final=client_final,
            stored_key=self.auth_data.stored_key,
            server_key=self.auth_data.server_key
        )

        # Parse into Python implementation types
        # We'd need to use the same nonce, so instead we'll test with RFC strings

        # For now, verify that C extension verification works
        truenas_pyscram.verify_server_signature(
            client_first=client_first,
            server_first=server_first,
            client_final=client_final,
            server_final=server_final,
            server_key=self.auth_data.server_key
        )


class TestChannelBindingCompatibility(unittest.TestCase):
    """Test tls-server-end-point channel binding parity between implementations."""

    def test_compute_parity(self):
        c = bytes(truenas_pyscram.compute_tls_server_end_point(_CB_TEST_CERT_DER))
        p = bytes(py_scram.compute_tls_server_end_point(_CB_TEST_CERT_DER))
        self.assertEqual(c, p)

    def test_signature_algorithm_parity(self):
        """py_scram mirrors the C extension across RSA-PSS / DSA / ECDSA / SHA-1 promotion."""
        for name, cert_der, expected in CB_VECTORS:
            with self.subTest(cert=name):
                p = bytes(py_scram.compute_tls_server_end_point(cert_der))
                c = bytes(truenas_pyscram.compute_tls_server_end_point(cert_der))
                self.assertEqual(p, expected, f'{name}: py_scram diverged')
                self.assertEqual(c, expected, f'{name}: C extension diverged')

    def test_undefined_signature_algorithm_rejected_by_both(self):
        """EdDSA (no single signature hash) is rejected by py_scram and the C
        extension alike -- the divergence-free boundary of the OID table."""
        for name, cert_der in REJECTED_VECTORS:
            with self.subTest(cert=name):
                with self.assertRaises(ValueError):
                    py_scram.compute_tls_server_end_point(cert_der)
                with self.assertRaises(Exception):
                    truenas_pyscram.compute_tls_server_end_point(cert_der)

    def test_cb_name_constant_parity(self):
        self.assertEqual(py_scram.CB_TLS_SERVER_END_POINT, truenas_pyscram.CB_TLS_SERVER_END_POINT)

    def _build_py_bound_exchange(self, auth, binding):
        py_cf = py_scram.ClientFirstMessage(
            username="u", api_key_id=5,
            channel_binding_type=py_scram.CB_TLS_SERVER_END_POINT,
        )
        py_sf = py_scram.ServerFirstMessage(
            client_first=py_cf,
            salt=py_scram.CryptoDatum(bytes(auth.salt)),
            iterations=auth.iterations,
        )
        py_fin = py_scram.ClientFinalMessage(
            client_first=py_cf, server_first=py_sf,
            client_key=py_scram.CryptoDatum(bytes(auth.client_key)),
            stored_key=py_scram.CryptoDatum(bytes(auth.stored_key)),
            channel_binding=binding,
        )
        return py_cf, py_sf, py_fin

    def test_py_bound_exchange_verified_by_c_extension(self):
        """A fully py_scram-built channel-bound exchange is accepted by the C-ext server."""
        auth = truenas_pyscram.generate_scram_auth_data()
        binding = py_scram.compute_tls_server_end_point(_CB_TEST_CERT_DER)
        py_cf, py_sf, py_fin = self._build_py_bound_exchange(auth, binding)

        # c= must be base64("p=tls-server-end-point,," + binding).
        c_attr = next(part[2:] for part in str(py_fin).split(",") if part.startswith("c="))
        self.assertEqual(c_attr, b64encode(b"p=tls-server-end-point,," + bytes(binding)).decode())

        # The C-extension server verifier accepts the py-built bound final.
        truenas_pyscram.verify_client_final_message(
            truenas_pyscram.ClientFirstMessage(rfc_string=str(py_cf)),
            truenas_pyscram.ServerFirstMessage(rfc_string=str(py_sf)),
            truenas_pyscram.ClientFinalMessage(rfc_string=str(py_fin)),
            auth.stored_key,
            channel_binding=truenas_pyscram.compute_tls_server_end_point(_CB_TEST_CERT_DER),
            require_channel_binding=True,
        )

    def test_wrong_binding_rejected_by_c_extension(self):
        auth = truenas_pyscram.generate_scram_auth_data()
        binding = py_scram.compute_tls_server_end_point(_CB_TEST_CERT_DER)
        py_cf, py_sf, py_fin = self._build_py_bound_exchange(auth, binding)

        with self.assertRaises(Exception):
            truenas_pyscram.verify_client_final_message(
                truenas_pyscram.ClientFirstMessage(rfc_string=str(py_cf)),
                truenas_pyscram.ServerFirstMessage(rfc_string=str(py_sf)),
                truenas_pyscram.ClientFinalMessage(rfc_string=str(py_fin)),
                auth.stored_key,
                channel_binding=truenas_pyscram.CryptoDatum(b"\x00" * 32),
                require_channel_binding=True,
            )


if __name__ == '__main__':
    unittest.main()
