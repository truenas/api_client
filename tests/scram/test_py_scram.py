# SPDX-License-Identifier: LGPL-3.0-or-later
"""Test pure Python SCRAM implementation (py_scram).

This test suite validates the pure Python implementation works correctly
independent of the C extension.
"""

import unittest

import truenas_api_client.py_scram as py_scram


class TestCryptoDatum(unittest.TestCase):
    """Test CryptoDatum class."""

    def test_creation(self):
        """Test creating CryptoDatum."""
        data = b"test_data"
        datum = py_scram.CryptoDatum(data)

        self.assertEqual(bytes(datum), data)
        self.assertEqual(len(datum), len(data))

    def test_repr(self):
        """Test CryptoDatum repr."""
        data = b"test"
        datum = py_scram.CryptoDatum(data)

        repr_str = repr(datum)
        self.assertIn("CryptoDatum", repr_str)


class TestClientFirstMessage(unittest.TestCase):
    """Test ClientFirstMessage class."""

    def test_basic_creation(self):
        """Test creating ClientFirstMessage."""
        msg = py_scram.ClientFirstMessage(username="testuser")

        self.assertEqual(msg.username, "testuser")
        self.assertEqual(msg.api_key_id, 0)
        self.assertIsNone(msg.gs2_header)
        self.assertIsInstance(msg.nonce, py_scram.CryptoDatum)
        self.assertEqual(len(msg.nonce), 32)

    def test_with_api_key(self):
        """Test ClientFirstMessage with API key ID."""
        msg = py_scram.ClientFirstMessage(username="testuser", api_key_id=123)

        self.assertEqual(msg.username, "testuser")
        self.assertEqual(msg.api_key_id, 123)

    def test_with_gs2_header(self):
        """Test ClientFirstMessage with GS2 header."""
        msg = py_scram.ClientFirstMessage(username="testuser", gs2_header="n")

        self.assertEqual(msg.gs2_header, "n")

    def test_serialization(self):
        """Test ClientFirstMessage serialization."""
        msg = py_scram.ClientFirstMessage(username="testuser")
        serialized = str(msg)

        self.assertIn("n=testuser", serialized)
        self.assertIn("r=", serialized)
        self.assertTrue(serialized.startswith("n,,"))

    def test_serialization_with_api_key(self):
        """Test serialization with API key."""
        msg = py_scram.ClientFirstMessage(username="testuser", api_key_id=456)
        serialized = str(msg)

        self.assertIn("n=testuser:456", serialized)

    def test_nonce_randomness(self):
        """Test that nonces are random."""
        msg1 = py_scram.ClientFirstMessage(username="testuser")
        msg2 = py_scram.ClientFirstMessage(username="testuser")

        self.assertNotEqual(msg1.nonce, msg2.nonce)

    def test_invalid_username(self):
        """Test error handling for invalid username."""
        with self.assertRaises(TypeError):
            py_scram.ClientFirstMessage(username=123)  # type: ignore

        with self.assertRaises(ValueError):
            py_scram.ClientFirstMessage(username="")

    def test_invalid_api_key_id(self):
        """Test error handling for invalid API key ID."""
        with self.assertRaises(TypeError):
            py_scram.ClientFirstMessage(username="testuser", api_key_id="not_int")  # type: ignore

    def test_saslprep_normalization(self):
        """Test that username is normalized using SASLprep (RFC 5802, Section 5.1)."""
        # U+200B (zero-width space) should be mapped to nothing per RFC 3454, Table B.1
        username_with_zwsp = "test\u200Buser"
        msg = py_scram.ClientFirstMessage(username=username_with_zwsp)
        # Zero-width space should be removed
        self.assertEqual(msg.username, "testuser")

    def test_saslprep_nfkc_normalization(self):
        """Test that username undergoes NFKC normalization."""
        # U+2168 (Roman numeral IX) should normalize to "IX"
        username_with_roman = "user\u2168"
        msg = py_scram.ClientFirstMessage(username=username_with_roman)
        # Should be normalized to regular ASCII
        self.assertEqual(msg.username, "userIX")

    def test_saslprep_nbsp_to_space(self):
        """Test that non-breaking space is normalized to regular space via NFKC."""
        # U+00A0 (non-breaking space) is normalized to U+0020 (regular space) by NFKC
        username_with_nbsp = "test\u00A0user"
        msg = py_scram.ClientFirstMessage(username=username_with_nbsp)
        # Non-breaking space should be normalized to regular space
        self.assertEqual(msg.username, "test user")

    def test_saslprep_prohibited_characters(self):
        """Test that prohibited characters raise ValueError."""
        # Test with ASCII control character (C.2.1)
        with self.assertRaises(ValueError) as ctx:
            py_scram.ClientFirstMessage(username="test\x00user")
        self.assertIn("prohibited", str(ctx.exception).lower())

        # Test with non-ASCII control character (C.2.2)
        with self.assertRaises(ValueError) as ctx:
            py_scram.ClientFirstMessage(username="test\u0080user")
        self.assertIn("prohibited", str(ctx.exception).lower())


class TestServerFirstMessage(unittest.TestCase):
    """Test ServerFirstMessage class."""

    def test_from_rfc_string(self):
        """Test parsing ServerFirstMessage from RFC string."""
        rfc_string = "r=Y2xpZW50bm9uY2U=,s=c2FsdA==,i=50000"
        msg = py_scram.ServerFirstMessage(rfc_string=rfc_string)

        self.assertEqual(str(msg), rfc_string)
        self.assertEqual(msg.iterations, 50000)
        self.assertIsInstance(msg.nonce, py_scram.CryptoDatum)
        self.assertIsInstance(msg.salt, py_scram.CryptoDatum)

    def test_from_client_first(self):
        """Test creating ServerFirstMessage from ClientFirstMessage."""
        client_first = py_scram.ClientFirstMessage(username="testuser")
        salt = py_scram.CryptoDatum(b"test_salt")
        iterations = 100000

        server_first = py_scram.ServerFirstMessage(
            client_first=client_first,
            salt=salt,
            iterations=iterations
        )

        self.assertEqual(server_first.iterations, iterations)
        self.assertEqual(server_first.salt, salt)
        # Nonce should contain client nonce
        self.assertIn(client_first.nonce, server_first.nonce)
        # Nonce should be longer (client + server)
        self.assertGreater(len(server_first.nonce), len(client_first.nonce))

    def test_serialization(self):
        """Test ServerFirstMessage serialization."""
        client_first = py_scram.ClientFirstMessage(username="testuser")
        salt = py_scram.CryptoDatum(b"test_salt")

        server_first = py_scram.ServerFirstMessage(
            client_first=client_first,
            salt=salt,
            iterations=100000
        )

        serialized = str(server_first)
        self.assertIn("r=", serialized)
        self.assertIn("s=", serialized)
        self.assertIn("i=100000", serialized)

    def test_invalid_rfc_string(self):
        """Test error handling for invalid RFC string."""
        with self.assertRaises(ValueError):
            py_scram.ServerFirstMessage(rfc_string="invalid")

        with self.assertRaises(ValueError):
            py_scram.ServerFirstMessage(rfc_string="r=test")  # Missing fields

    def test_mutually_exclusive_parameters(self):
        """Test that rfc_string and client_first are mutually exclusive."""
        client_first = py_scram.ClientFirstMessage(username="testuser")
        salt = py_scram.CryptoDatum(b"salt")

        with self.assertRaises(ValueError):
            py_scram.ServerFirstMessage(
                client_first=client_first,
                salt=salt,
                iterations=100000,
                rfc_string="r=test,s=test,i=100000"
            )

    def test_missing_parameters(self):
        """Test error when neither parameter set is provided."""
        with self.assertRaises(ValueError):
            py_scram.ServerFirstMessage()


class TestClientFinalMessage(unittest.TestCase):
    """Test ClientFinalMessage class."""

    def setUp(self):
        """Set up test fixtures."""
        self.client_first = py_scram.ClientFirstMessage(username="testuser")
        self.salt = py_scram.CryptoDatum(b"test_salt_16bytes")
        self.server_first = py_scram.ServerFirstMessage(
            client_first=self.client_first,
            salt=self.salt,
            iterations=100000
        )

        # Generate keys using crypto functions
        key_data = b"test_password"
        salted_password = py_scram.scram_hi(
            py_scram.CryptoDatum(key_data),
            self.salt,
            100000
        )
        self.client_key = py_scram.scram_create_client_key(salted_password)
        self.stored_key = py_scram.scram_create_stored_key(self.client_key)

    def test_creation(self):
        """Test creating ClientFinalMessage."""
        client_final = py_scram.ClientFinalMessage(
            client_first=self.client_first,
            server_first=self.server_first,
            client_key=self.client_key,
            stored_key=self.stored_key
        )

        self.assertIsInstance(client_final.nonce, py_scram.CryptoDatum)
        self.assertIsInstance(client_final.client_proof, py_scram.CryptoDatum)
        self.assertEqual(client_final.nonce, self.server_first.nonce)

    def test_serialization(self):
        """Test ClientFinalMessage serialization."""
        client_final = py_scram.ClientFinalMessage(
            client_first=self.client_first,
            server_first=self.server_first,
            client_key=self.client_key,
            stored_key=self.stored_key
        )

        serialized = str(client_final)
        self.assertIn("c=", serialized)
        self.assertIn("r=", serialized)
        self.assertIn("p=", serialized)

    def test_from_rfc_string(self):
        """Test parsing ClientFinalMessage from RFC string."""
        rfc_string = "c=biws,r=Y2xpZW50bm9uY2U=,p=cHJvb2Y="
        client_final = py_scram.ClientFinalMessage(rfc_string=rfc_string)

        self.assertEqual(str(client_final), rfc_string)
        self.assertIsNone(client_final.channel_binding)  # biws = "n,,"


class TestServerFinalMessage(unittest.TestCase):
    """Test ServerFinalMessage class."""

    def setUp(self):
        """Set up test fixtures."""
        self.client_first = py_scram.ClientFirstMessage(username="testuser")
        self.salt = py_scram.CryptoDatum(b"test_salt_16bytes")
        self.server_first = py_scram.ServerFirstMessage(
            client_first=self.client_first,
            salt=self.salt,
            iterations=100000
        )

        # Generate keys
        key_data = b"test_password"
        salted_password = py_scram.scram_hi(
            py_scram.CryptoDatum(key_data),
            self.salt,
            100000
        )
        self.client_key = py_scram.scram_create_client_key(salted_password)
        self.stored_key = py_scram.scram_create_stored_key(self.client_key)
        self.server_key = py_scram.scram_create_server_key(salted_password)

        self.client_final = py_scram.ClientFinalMessage(
            client_first=self.client_first,
            server_first=self.server_first,
            client_key=self.client_key,
            stored_key=self.stored_key
        )

    def test_creation(self):
        """Test creating ServerFinalMessage."""
        server_final = py_scram.ServerFinalMessage(
            client_first=self.client_first,
            server_first=self.server_first,
            client_final=self.client_final,
            stored_key=self.stored_key,
            server_key=self.server_key
        )

        self.assertIsInstance(server_final.signature, py_scram.CryptoDatum)
        self.assertEqual(len(server_final.signature), 64)  # SHA-512

    def test_serialization(self):
        """Test ServerFinalMessage serialization."""
        server_final = py_scram.ServerFinalMessage(
            client_first=self.client_first,
            server_first=self.server_first,
            client_final=self.client_final,
            stored_key=self.stored_key,
            server_key=self.server_key
        )

        serialized = str(server_final)
        self.assertTrue(serialized.startswith("v="))

    def test_from_rfc_string(self):
        """Test parsing ServerFinalMessage from RFC string."""
        rfc_string = "v=c2lnbmF0dXJl"
        server_final = py_scram.ServerFinalMessage(rfc_string=rfc_string)

        self.assertEqual(str(server_final), rfc_string)

    def test_invalid_client_proof(self):
        """Test that invalid client proof is detected."""
        # Create a client final with wrong stored key
        wrong_stored_key = py_scram.CryptoDatum(b"x" * 64)
        wrong_client_final = py_scram.ClientFinalMessage(
            client_first=self.client_first,
            server_first=self.server_first,
            client_key=self.client_key,
            stored_key=wrong_stored_key
        )

        # Server final should fail to create with mismatched keys
        with self.assertRaises(ValueError):
            py_scram.ServerFinalMessage(
                client_first=self.client_first,
                server_first=self.server_first,
                client_final=wrong_client_final,
                stored_key=self.stored_key,
                server_key=self.server_key
            )


class TestVerificationFunctions(unittest.TestCase):
    """Test verification functions."""

    def setUp(self):
        """Set up test fixtures."""
        self.client_first = py_scram.ClientFirstMessage(username="testuser")
        self.salt = py_scram.CryptoDatum(b"test_salt_16bytes")
        self.server_first = py_scram.ServerFirstMessage(
            client_first=self.client_first,
            salt=self.salt,
            iterations=100000
        )

        # Generate keys
        key_data = b"test_password"
        salted_password = py_scram.scram_hi(
            py_scram.CryptoDatum(key_data),
            self.salt,
            100000
        )
        self.client_key = py_scram.scram_create_client_key(salted_password)
        self.stored_key = py_scram.scram_create_stored_key(self.client_key)
        self.server_key = py_scram.scram_create_server_key(salted_password)

        self.client_final = py_scram.ClientFinalMessage(
            client_first=self.client_first,
            server_first=self.server_first,
            client_key=self.client_key,
            stored_key=self.stored_key
        )

        self.server_final = py_scram.ServerFinalMessage(
            client_first=self.client_first,
            server_first=self.server_first,
            client_final=self.client_final,
            stored_key=self.stored_key,
            server_key=self.server_key
        )

    def test_verify_server_signature_success(self):
        """Test successful server signature verification."""
        # Should not raise an exception
        py_scram.verify_server_signature(
            client_first=self.client_first,
            server_first=self.server_first,
            client_final=self.client_final,
            server_final=self.server_final,
            server_key=self.server_key
        )

    def test_verify_server_signature_failure(self):
        """Test server signature verification with wrong key."""
        wrong_server_key = py_scram.CryptoDatum(b"x" * 64)

        with self.assertRaises(py_scram.ScramError) as ctx:
            py_scram.verify_server_signature(
                client_first=self.client_first,
                server_first=self.server_first,
                client_final=self.client_final,
                server_final=self.server_final,
                server_key=wrong_server_key
            )

        self.assertEqual(ctx.exception.code, py_scram.SCRAM_E_AUTH_FAILED)

    def test_verify_client_final_message_success(self):
        """Test successful client final message verification."""
        # Should not raise an exception
        py_scram.verify_client_final_message(
            client_first=self.client_first,
            server_first=self.server_first,
            client_final=self.client_final,
            stored_key=self.stored_key
        )

    def test_verify_client_final_message_failure(self):
        """Test client final message verification with wrong key."""
        wrong_stored_key = py_scram.CryptoDatum(b"x" * 64)

        with self.assertRaises(py_scram.ScramError) as ctx:
            py_scram.verify_client_final_message(
                client_first=self.client_first,
                server_first=self.server_first,
                client_final=self.client_final,
                stored_key=wrong_stored_key
            )

        self.assertEqual(ctx.exception.code, py_scram.SCRAM_E_AUTH_FAILED)


class TestCryptoFunctions(unittest.TestCase):
    """Test cryptographic functions."""

    def test_scram_hi(self):
        """Test PBKDF2 key derivation."""
        key = py_scram.CryptoDatum(b"password")
        salt = py_scram.CryptoDatum(b"salt1234")
        iterations = 100000

        result = py_scram.scram_hi(key, salt, iterations)

        self.assertIsInstance(result, py_scram.CryptoDatum)
        self.assertEqual(len(result), 64)  # SHA-512

    def test_scram_h(self):
        """Test SHA-512 hash."""
        data = py_scram.CryptoDatum(b"test_data")

        result = py_scram.scram_h(data)

        self.assertIsInstance(result, py_scram.CryptoDatum)
        self.assertEqual(len(result), 64)  # SHA-512

    def test_scram_hmac_sha512(self):
        """Test HMAC-SHA-512."""
        key = py_scram.CryptoDatum(b"key")
        data = py_scram.CryptoDatum(b"data")

        result = py_scram.scram_hmac_sha512(key, data)

        self.assertIsInstance(result, py_scram.CryptoDatum)
        self.assertEqual(len(result), 64)  # SHA-512

    def test_scram_xor_bytes(self):
        """Test XOR operation."""
        a = py_scram.CryptoDatum(b"\x01\x02\x03")
        b = py_scram.CryptoDatum(b"\x04\x05\x06")

        result = py_scram.scram_xor_bytes(a, b)

        expected = bytes([0x01 ^ 0x04, 0x02 ^ 0x05, 0x03 ^ 0x06])
        self.assertEqual(bytes(result), expected)

    def test_scram_constant_time_compare(self):
        """Test constant-time comparison."""
        a = py_scram.CryptoDatum(b"test")
        b = py_scram.CryptoDatum(b"test")
        c = py_scram.CryptoDatum(b"diff")

        self.assertTrue(py_scram.scram_constant_time_compare(a, b))
        self.assertFalse(py_scram.scram_constant_time_compare(a, c))


if __name__ == '__main__':
    unittest.main()
