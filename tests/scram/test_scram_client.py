# SPDX-License-Identifier: LGPL-3.0-or-later
"""Test TNScramClient high-level interface.

This test suite validates the TNScramClient class that provides a
high-level interface for SCRAM authentication.
"""

import unittest

import truenas_pyscram  # type: ignore
from truenas_api_client.scram_impl import TNScramClient, ScramMessageType


class TestTNScramClientInit(unittest.TestCase):
    """Test TNScramClient initialization."""

    def test_init_with_raw_key_material(self):
        """Test initialization with raw key material."""
        client = TNScramClient(raw_key_material="test_password")

        self.assertEqual(client.raw_key_material, "test_password")
        self.assertIsNone(client.client_key)
        self.assertIsNone(client.stored_key)
        self.assertIsNone(client.server_key)
        self.assertEqual(client.api_key_id, 0)

    def test_init_with_api_key_id(self):
        """Test initialization with API key ID."""
        client = TNScramClient(raw_key_material="test_key", api_key_id=123)

        self.assertEqual(client.api_key_id, 123)

    def test_init_with_precomputed_keys(self):
        """Test initialization with pre-computed keys."""
        client_key = truenas_pyscram.CryptoDatum(b"x" * 64)
        stored_key = truenas_pyscram.CryptoDatum(b"y" * 64)
        server_key = truenas_pyscram.CryptoDatum(b"z" * 64)

        client = TNScramClient(
            client_key=client_key,
            stored_key=stored_key,
            server_key=server_key
        )

        self.assertIsNone(client.raw_key_material)
        self.assertEqual(client.client_key, client_key)
        self.assertEqual(client.stored_key, stored_key)
        self.assertEqual(client.server_key, server_key)

    def test_init_without_required_params(self):
        """Test that initialization fails without required parameters."""
        with self.assertRaises(ValueError) as ctx:
            TNScramClient()

        self.assertIn("raw_key_material", str(ctx.exception))

    def test_init_with_only_client_key(self):
        """Test that initialization fails with only client_key."""
        client_key = truenas_pyscram.CryptoDatum(b"x" * 64)

        with self.assertRaises(ValueError):
            TNScramClient(client_key=client_key)

    def test_init_with_only_stored_key(self):
        """Test that initialization fails with only stored_key."""
        stored_key = truenas_pyscram.CryptoDatum(b"x" * 64)

        with self.assertRaises(ValueError):
            TNScramClient(stored_key=stored_key)


class TestTNScramClientFirstMessage(unittest.TestCase):
    """Test ClientFirstMessage generation."""

    def test_get_client_first_message_basic(self):
        """Test basic client first message generation."""
        client = TNScramClient(raw_key_material="test_password")

        client.get_client_first_message(username="testuser")

        self.assertIsInstance(client.client_first_message, truenas_pyscram.ClientFirstMessage)
        self.assertEqual(client.client_first_message.username, "testuser")
        self.assertEqual(client.client_first_message.api_key_id, 0)
        self.assertIsNone(client.client_first_message.gs2_header)

    def test_get_client_first_message_with_api_key(self):
        """Test client first message with API key ID."""
        client = TNScramClient(raw_key_material="test_key", api_key_id=456)

        client.get_client_first_message(username="apiuser")

        self.assertEqual(client.client_first_message.username, "apiuser")
        self.assertEqual(client.client_first_message.api_key_id, 456)

    def test_get_client_first_message_with_gs2_header(self):
        """Test client first message with GS2 header."""
        client = TNScramClient(raw_key_material="test_password")

        client.get_client_first_message(
            username="testuser",
            gs2_header="p=tls-unique"
        )

        self.assertEqual(client.client_first_message.gs2_header, "p=tls-unique")

    def test_client_first_message_stored(self):
        """Test that client first message is stored in client."""
        client = TNScramClient(raw_key_material="test_password")

        client.get_client_first_message(username="testuser")

        self.assertIsNotNone(client.client_first_message)
        self.assertIsInstance(client.client_first_message, truenas_pyscram.ClientFirstMessage)


class TestTNScramClientFinalMessage(unittest.TestCase):
    """Test ClientFinalMessage generation."""

    def setUp(self):
        """Set up test fixtures."""
        self.password = "test_password"
        self.username = "testuser"

        # Create auth data for testing
        self.auth_data = truenas_pyscram.generate_scram_auth_data()

    def test_get_client_final_message_with_raw_key(self):
        """Test client final message generation with raw key material."""
        client = TNScramClient(raw_key_material=self.password)
        client.get_client_first_message(username=self.username)

        # Create a server first message
        server_first_msg = truenas_pyscram.ServerFirstMessage(
            client_first=client.client_first_message,
            salt=self.auth_data.salt,
            iterations=self.auth_data.iterations
        )

        server_resp = {
            'scram_type': ScramMessageType.SERVER_FIRST_RESPONSE,
            'rfc_str': str(server_first_msg)
        }

        client.get_client_final_message(server_resp)

        self.assertIsInstance(client.client_final_message, truenas_pyscram.ClientFinalMessage)
        self.assertIsNotNone(client.client_key)
        self.assertIsNotNone(client.stored_key)
        self.assertIsNotNone(client.server_key)

    def test_get_client_final_message_with_precomputed_keys(self):
        """Test client final message with pre-computed keys."""
        client = TNScramClient(
            client_key=self.auth_data.client_key,
            stored_key=self.auth_data.stored_key,
            server_key=self.auth_data.server_key
        )
        client.get_client_first_message(username=self.username)

        server_first_msg = truenas_pyscram.ServerFirstMessage(
            client_first=client.client_first_message,
            salt=self.auth_data.salt,
            iterations=self.auth_data.iterations
        )

        server_resp = {
            'scram_type': ScramMessageType.SERVER_FIRST_RESPONSE,
            'rfc_str': str(server_first_msg)
        }

        client.get_client_final_message(server_resp)

        self.assertIsInstance(client.client_final_message, truenas_pyscram.ClientFinalMessage)

    def test_get_client_final_message_wrong_type(self):
        """Test error handling for wrong message type."""
        client = TNScramClient(raw_key_material=self.password)
        client.get_client_first_message(username=self.username)

        server_resp = {
            'scram_type': ScramMessageType.SERVER_FINAL_RESPONSE,
            'rfc_str': 'v=test'
        }

        with self.assertRaises(TypeError) as ctx:
            client.get_client_final_message(server_resp)

        self.assertIn("SERVER_FINAL_RESPONSE", str(ctx.exception))

    def test_get_client_final_message_high_iterations(self):
        """Test error handling for too high iteration count."""
        client = TNScramClient(raw_key_material=self.password)
        client.get_client_first_message(username=self.username)

        # Create a server first message with very high iterations
        from ssl import RAND_bytes
        from base64 import b64encode
        from truenas_api_client.scram_impl import ScramError, SCRAM_MAX_ITERS

        nonce_b64 = b64encode(RAND_bytes(64)).decode()
        salt_b64 = b64encode(RAND_bytes(16)).decode()
        high_iters = 10000000  # Above SCRAM_MAX_ITERS

        rfc_string = f"r={nonce_b64},s={salt_b64},i={high_iters}"

        server_resp = {
            'scram_type': ScramMessageType.SERVER_FIRST_RESPONSE,
            'rfc_str': rfc_string
        }

        # Both C extension and pure Python raise ScramError
        with self.assertRaises(ScramError) as ctx:
            client.get_client_final_message(server_resp)

        self.assertIn(str(SCRAM_MAX_ITERS), str(ctx.exception))


class TestTNScramClientVerification(unittest.TestCase):
    """Test server final message verification."""

    def setUp(self):
        """Set up test fixtures."""
        self.password = "test_password"
        self.username = "testuser"
        self.auth_data = truenas_pyscram.generate_scram_auth_data()

    def test_verify_server_final_message_success(self):
        """Test successful server final message verification."""
        client = TNScramClient(raw_key_material=self.password)
        client.get_client_first_message(username=self.username)

        # Server first
        server_first_msg = truenas_pyscram.ServerFirstMessage(
            client_first=client.client_first_message,
            salt=self.auth_data.salt,
            iterations=self.auth_data.iterations
        )
        server_resp_first = {
            'scram_type': ScramMessageType.SERVER_FIRST_RESPONSE,
            'rfc_str': str(server_first_msg)
        }
        client.get_client_final_message(server_resp_first)

        # Server final
        server_final_msg = truenas_pyscram.ServerFinalMessage(
            client_first=client.client_first_message,
            server_first=client.server_first_message,
            client_final=client.client_final_message,
            stored_key=client.stored_key,
            server_key=client.server_key
        )
        server_resp_final = {
            'scram_type': ScramMessageType.SERVER_FINAL_RESPONSE,
            'rfc_str': str(server_final_msg)
        }

        result = client.verify_server_final_message(server_resp_final)

        self.assertTrue(result)
        self.assertEqual(str(client.server_final_message), str(server_final_msg))

    def test_verify_server_final_message_wrong_type(self):
        """Test error handling for wrong message type."""
        client = TNScramClient(raw_key_material=self.password)

        server_resp = {
            'scram_type': ScramMessageType.SERVER_FIRST_RESPONSE,
            'rfc_str': 'r=test,s=test,i=100000'
        }

        with self.assertRaises(TypeError) as ctx:
            client.verify_server_final_message(server_resp)

        self.assertIn("SERVER_FIRST_RESPONSE", str(ctx.exception))

    def test_verify_server_final_message_no_server_key(self):
        """Test error when server_key is not available."""
        # Create client with only client_key and stored_key (no server_key)
        client = TNScramClient(
            client_key=self.auth_data.client_key,
            stored_key=self.auth_data.stored_key
        )
        client.get_client_first_message(username=self.username)

        server_first_msg = truenas_pyscram.ServerFirstMessage(
            client_first=client.client_first_message,
            salt=self.auth_data.salt,
            iterations=self.auth_data.iterations
        )
        server_resp_first = {
            'scram_type': ScramMessageType.SERVER_FIRST_RESPONSE,
            'rfc_str': str(server_first_msg)
        }
        client.get_client_final_message(server_resp_first)

        # Try to verify without server_key
        server_resp_final = {
            'scram_type': ScramMessageType.SERVER_FINAL_RESPONSE,
            'rfc_str': 'v=dGVzdA=='
        }

        with self.assertRaises(ValueError) as ctx:
            client.verify_server_final_message(server_resp_final)

        self.assertIn("server_key", str(ctx.exception))


class TestTNScramClientFullFlow(unittest.TestCase):
    """Test complete SCRAM authentication flow."""

    def test_full_auth_flow_with_raw_key(self):
        """Test complete authentication flow with raw key material."""
        password = "test_password"
        username = "testuser"

        # Generate auth data that would be stored on server
        auth_data = truenas_pyscram.generate_scram_auth_data()

        # Client side
        client = TNScramClient(raw_key_material=password)

        # Step 1: Client first message
        client.get_client_first_message(username=username)
        self.assertIsNotNone(client.client_first_message)

        # Step 2: Server first message (simulated server response)
        server_first = truenas_pyscram.ServerFirstMessage(
            client_first=client.client_first_message,
            salt=auth_data.salt,
            iterations=auth_data.iterations
        )
        server_resp_first = {
            'scram_type': ScramMessageType.SERVER_FIRST_RESPONSE,
            'rfc_str': str(server_first)
        }

        # Step 3: Client final message
        client.get_client_final_message(server_resp_first)
        self.assertIsNotNone(client.client_final_message)

        # Verify keys were generated
        self.assertIsNotNone(client.client_key)
        self.assertIsNotNone(client.stored_key)
        self.assertIsNotNone(client.server_key)

        # Step 4: Server final message (simulated server response)
        server_final = truenas_pyscram.ServerFinalMessage(
            client_first=client.client_first_message,
            server_first=server_first,
            client_final=client.client_final_message,
            stored_key=client.stored_key,
            server_key=client.server_key
        )
        server_resp_final = {
            'scram_type': ScramMessageType.SERVER_FINAL_RESPONSE,
            'rfc_str': str(server_final)
        }

        # Step 5: Verify server signature
        result = client.verify_server_final_message(server_resp_final)
        self.assertTrue(result)

    def test_full_auth_flow_with_precomputed_keys(self):
        """Test complete authentication flow with pre-computed keys."""
        username = "testuser"

        # Pre-computed auth data
        auth_data = truenas_pyscram.generate_scram_auth_data()

        # Client side with pre-computed keys
        client = TNScramClient(
            client_key=auth_data.client_key,
            stored_key=auth_data.stored_key,
            server_key=auth_data.server_key
        )

        # Complete flow
        client.get_client_first_message(username=username)

        server_first = truenas_pyscram.ServerFirstMessage(
            client_first=client.client_first_message,
            salt=auth_data.salt,
            iterations=auth_data.iterations
        )
        server_resp_first = {
            'scram_type': ScramMessageType.SERVER_FIRST_RESPONSE,
            'rfc_str': str(server_first)
        }

        client.get_client_final_message(server_resp_first)

        server_final = truenas_pyscram.ServerFinalMessage(
            client_first=client.client_first_message,
            server_first=server_first,
            client_final=client.client_final_message,
            stored_key=auth_data.stored_key,
            server_key=auth_data.server_key
        )
        server_resp_final = {
            'scram_type': ScramMessageType.SERVER_FINAL_RESPONSE,
            'rfc_str': str(server_final)
        }

        result = client.verify_server_final_message(server_resp_final)
        self.assertTrue(result)

    def test_full_auth_flow_with_api_key(self):
        """Test complete authentication flow with API key."""
        api_key = "api_key_secret"
        username = "apiuser"
        api_key_id = 789

        auth_data = truenas_pyscram.generate_scram_auth_data()

        client = TNScramClient(
            raw_key_material=api_key,
            api_key_id=api_key_id
        )

        client.get_client_first_message(username=username)
        self.assertEqual(client.client_first_message.api_key_id, api_key_id)

        server_first = truenas_pyscram.ServerFirstMessage(
            client_first=client.client_first_message,
            salt=auth_data.salt,
            iterations=auth_data.iterations
        )
        server_resp_first = {
            'scram_type': ScramMessageType.SERVER_FIRST_RESPONSE,
            'rfc_str': str(server_first)
        }

        client.get_client_final_message(server_resp_first)

        server_final = truenas_pyscram.ServerFinalMessage(
            client_first=client.client_first_message,
            server_first=server_first,
            client_final=client.client_final_message,
            stored_key=client.stored_key,
            server_key=client.server_key
        )
        server_resp_final = {
            'scram_type': ScramMessageType.SERVER_FINAL_RESPONSE,
            'rfc_str': str(server_final)
        }

        result = client.verify_server_final_message(server_resp_final)
        self.assertTrue(result)


if __name__ == '__main__':
    unittest.main()
