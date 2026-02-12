# SPDX-License-Identifier: LGPL-3.0-or-later
"""Unit tests for auth_api_key module.

Tests the parsing logic, key material handling, and data transformations
without requiring a live TrueNAS server connection.
"""

import json
import tempfile
import unittest
from pathlib import Path

from truenas_api_client.auth_api_key import (
    KeyData,
    KeyDataType,
    RAW_KEY_SEPARATOR,
    _parse_ini_config,
    get_key_material,
)


class TestRawKeySeparator(unittest.TestCase):
    """Test the RAW_KEY_SEPARATOR constant."""

    def test_separator_is_dash(self):
        """Verify the separator is a dash as documented."""
        self.assertEqual(RAW_KEY_SEPARATOR, '-')


class TestGetKeyMaterialRawKey(unittest.TestCase):
    """Test get_key_material with raw API key strings."""

    def test_raw_key_simple(self):
        """Test parsing a simple raw API key."""
        key = "123-abc123def456"
        result = get_key_material(key)

        self.assertIsInstance(result, KeyData)
        self.assertEqual(result.key_data_type, KeyDataType.RAW)
        self.assertIsInstance(result.key_data, dict)
        self.assertEqual(result.key_data['raw_key'], key)

    def test_raw_key_realistic_format(self):
        """Test raw key with realistic alphanumeric format (no dashes in key material)."""
        # Based on actual API output - key material is alphanumeric only
        key = "456-uz8DhKHFhRIUQIvjzabPYtpy5wf1DJ3ZBLlDgNVhRAFT7Y6pJGUlm0n3apwxWEU4"
        result = get_key_material(key)

        self.assertEqual(result.key_data_type, KeyDataType.RAW)
        self.assertEqual(result.key_data['raw_key'], key)

    def test_raw_key_long_id(self):
        """Test raw key with long numeric ID."""
        key = "999999999-verylongkeydata"
        result = get_key_material(key)

        self.assertEqual(result.key_data_type, KeyDataType.RAW)
        self.assertEqual(result.key_data['raw_key'], key)


class TestGetKeyMaterialJSON(unittest.TestCase):
    """Test get_key_material with JSON-formatted strings."""

    def test_json_with_raw_key(self):
        """Test JSON containing raw_key field."""
        data = {"raw_key": "789-jsonkey123"}
        json_str = json.dumps(data)
        result = get_key_material(json_str)

        self.assertEqual(result.key_data_type, KeyDataType.RAW)
        self.assertEqual(result.key_data['raw_key'], "789-jsonkey123")

    def test_json_with_precomputed_keys(self):
        """Test JSON with pre-computed cryptographic keys."""
        data = {
            "client_key": "Y2xpZW50a2V5MTIz",
            "stored_key": "c3RvcmVka2V5NDU2",
            "server_key": "c2VydmVya2V5Nzg5",
            "api_key_id": 42
        }
        json_str = json.dumps(data)
        result = get_key_material(json_str)

        self.assertEqual(result.key_data_type, KeyDataType.PRECOMPUTED)
        precomputed = result.key_data
        self.assertEqual(precomputed['client_key'], "Y2xpZW50a2V5MTIz")
        self.assertEqual(precomputed['stored_key'], "c3RvcmVka2V5NDU2")
        self.assertEqual(precomputed['server_key'], "c2VydmVya2V5Nzg5")
        self.assertEqual(precomputed['api_key_id'], 42)

    def test_json_missing_required_field(self):
        """Test JSON missing a required field raises ValueError."""
        data = {
            "client_key": "Y2xpZW50a2V5MTIz",
            "stored_key": "c3RvcmVka2V5NDU2",
            # Missing server_key
            "api_key_id": 42
        }
        json_str = json.dumps(data)

        with self.assertRaises(ValueError) as ctx:
            get_key_material(json_str)
        self.assertIn("Missing required field", str(ctx.exception))


class TestGetKeyMaterialINI(unittest.TestCase):
    """Test get_key_material with INI/ConfigParser format."""

    def test_ini_with_section_header(self):
        """Test INI format with [TRUENAS_API_KEY] section."""
        ini_str = """[TRUENAS_API_KEY]
client_key = Y2xpZW50a2V5MTIz
stored_key = c3RvcmVka2V5NDU2
server_key = c2VydmVya2V5Nzg5
api_key_id = 100
"""
        result = get_key_material(ini_str)

        self.assertEqual(result.key_data_type, KeyDataType.PRECOMPUTED)
        precomputed = result.key_data
        self.assertEqual(precomputed['api_key_id'], 100)
        self.assertEqual(precomputed['client_key'], "Y2xpZW50a2V5MTIz")

    def test_ini_without_section_header(self):
        """Test INI format without section header uses [DEFAULT] section."""
        # ConfigParser requires section headers, so we use [DEFAULT]
        ini_str = """[DEFAULT]
client_key = Y2xpZW50a2V5MTIz
stored_key = c3RvcmVka2V5NDU2
server_key = c2VydmVya2V5Nzg5
api_key_id = 200
"""
        result = get_key_material(ini_str)

        self.assertEqual(result.key_data_type, KeyDataType.PRECOMPUTED)
        self.assertEqual(result.key_data['api_key_id'], 200)

    def test_ini_single_section_any_name(self):
        """Test INI with single section accepts any name."""
        ini_str = """[credentials]
client_key = base64data1
stored_key = base64data2
server_key = base64data3
api_key_id = 300
"""
        result = get_key_material(ini_str)

        self.assertEqual(result.key_data_type, KeyDataType.PRECOMPUTED)
        self.assertEqual(result.key_data['api_key_id'], 300)

    def test_ini_with_multiple_sections_requires_truenas_api_key(self):
        """Test INI with multiple sections requires [TRUENAS_API_KEY]."""
        ini_str = """[other]
client_key = wrong1
stored_key = wrong2
server_key = wrong3
api_key_id = 999

[TRUENAS_API_KEY]
client_key = correct1
stored_key = correct2
server_key = correct3
api_key_id = 400
"""
        result = get_key_material(ini_str)

        self.assertEqual(result.key_data_type, KeyDataType.PRECOMPUTED)
        self.assertEqual(result.key_data['api_key_id'], 400)
        self.assertEqual(result.key_data['client_key'], "correct1")

    def test_ini_with_multiple_sections_without_truenas_api_key_fails(self):
        """Test INI with multiple sections but no [TRUENAS_API_KEY] raises error."""
        ini_str = """[section1]
client_key = data1

[section2]
client_key = data2
"""
        with self.assertRaises(ValueError) as ctx:
            get_key_material(ini_str)
        self.assertIn("TRUENAS_API_KEY", str(ctx.exception))

    def test_ini_with_raw_key(self):
        """Test INI format with raw_key field."""
        ini_str = """[TRUENAS_API_KEY]
raw_key = 500-rawkeydata
"""
        result = get_key_material(ini_str)

        self.assertEqual(result.key_data_type, KeyDataType.RAW)
        self.assertEqual(result.key_data['raw_key'], "500-rawkeydata")


class TestParseINIConfig(unittest.TestCase):
    """Test the _parse_ini_config helper function."""

    def test_single_section(self):
        """Test parsing INI with single section."""
        ini_str = """[credentials]
client_key = test1
api_key_id = 123
"""
        result = _parse_ini_config(ini_str)

        self.assertEqual(result['client_key'], "test1")
        self.assertEqual(result['api_key_id'], 123)  # Should be converted to int

    def test_default_section_explicit(self):
        """Test parsing INI with explicit [DEFAULT] section."""
        ini_str = """[DEFAULT]
client_key = test2
api_key_id = 456
"""
        result = _parse_ini_config(ini_str)

        self.assertEqual(result['client_key'], "test2")
        self.assertEqual(result['api_key_id'], 456)

    def test_api_key_id_type_conversion(self):
        """Test that api_key_id is converted from string to int."""
        ini_str = """[test]
api_key_id = 789
other_field = stays_string
"""
        result = _parse_ini_config(ini_str)

        self.assertIsInstance(result['api_key_id'], int)
        self.assertEqual(result['api_key_id'], 789)
        self.assertIsInstance(result['other_field'], str)


class TestGetKeyMaterialFromFile(unittest.TestCase):
    """Test get_key_material with file paths."""

    def test_read_json_from_file(self):
        """Test reading JSON key data from a file."""
        data = {
            "client_key": "fromfile1",
            "stored_key": "fromfile2",
            "server_key": "fromfile3",
            "api_key_id": 600
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            f.flush()
            temp_path = f.name

        try:
            result = get_key_material(temp_path)

            self.assertEqual(result.key_data_type, KeyDataType.PRECOMPUTED)
            self.assertEqual(result.key_data['api_key_id'], 600)
        finally:
            Path(temp_path).unlink()

    def test_read_raw_key_from_file(self):
        """Test reading raw API key from a file."""
        raw_key = "700-keyfromfile"

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(raw_key)
            f.flush()
            temp_path = f.name

        try:
            result = get_key_material(temp_path)

            self.assertEqual(result.key_data_type, KeyDataType.RAW)
            self.assertEqual(result.key_data['raw_key'], raw_key)
        finally:
            Path(temp_path).unlink()

    def test_read_ini_from_file(self):
        """Test reading INI key data from a file."""
        ini_content = """[TRUENAS_API_KEY]
client_key = inifile1
stored_key = inifile2
server_key = inifile3
api_key_id = 800
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.ini', delete=False) as f:
            f.write(ini_content)
            f.flush()
            temp_path = f.name

        try:
            result = get_key_material(temp_path)

            self.assertEqual(result.key_data_type, KeyDataType.PRECOMPUTED)
            self.assertEqual(result.key_data['api_key_id'], 800)
        finally:
            Path(temp_path).unlink()


class TestGetKeyMaterialErrors(unittest.TestCase):
    """Test error handling in get_key_material."""

    def test_invalid_json_and_ini(self):
        """Test that invalid JSON and INI raises descriptive error."""
        invalid_data = "this is {not valid json or ini"

        with self.assertRaises(ValueError) as ctx:
            get_key_material(invalid_data)

        error_msg = str(ctx.exception)
        self.assertIn("Key material must be either", error_msg)
        self.assertIn("JSON error:", error_msg)
        self.assertIn("INI error:", error_msg)

    def test_empty_string_with_no_dash(self):
        """Test empty string without dash raises error."""
        with self.assertRaises(ValueError):
            get_key_material("")

    def test_raw_key_wrong_type(self):
        """Test that non-string raw_key raises error."""
        data = {"raw_key": 12345}
        json_str = json.dumps(data)

        with self.assertRaises(ValueError) as ctx:
            get_key_material(json_str)
        self.assertIn("raw_key must be a string", str(ctx.exception))

    def test_precomputed_client_key_wrong_type(self):
        """Test that non-string client_key raises error."""
        data = {
            "client_key": 123,  # Should be string
            "stored_key": "c3RvcmVka2V5NDU2",
            "server_key": "c2VydmVya2V5Nzg5",
            "api_key_id": 42
        }
        json_str = json.dumps(data)

        with self.assertRaises(ValueError) as ctx:
            get_key_material(json_str)
        self.assertIn("client_key must be a string", str(ctx.exception))

    def test_precomputed_api_key_id_wrong_type(self):
        """Test that non-int api_key_id raises error."""
        data = {
            "client_key": "Y2xpZW50a2V5MTIz",
            "stored_key": "c3RvcmVka2V5NDU2",
            "server_key": "c2VydmVya2V5Nzg5",
            "api_key_id": "should_be_int"  # Should be int
        }
        json_str = json.dumps(data)

        with self.assertRaises(ValueError) as ctx:
            get_key_material(json_str)
        self.assertIn("api_key_id must be an int", str(ctx.exception))


class TestKeyDataType(unittest.TestCase):
    """Test the KeyDataType enum."""

    def test_enum_values(self):
        """Test KeyDataType enum has correct values."""
        self.assertEqual(KeyDataType.RAW, 'RAW')
        self.assertEqual(KeyDataType.PRECOMPUTED, 'PRECOMPUTED')

    def test_enum_comparison(self):
        """Test KeyDataType can be compared."""
        self.assertEqual(KeyDataType.RAW, KeyDataType.RAW)
        self.assertNotEqual(KeyDataType.RAW, KeyDataType.PRECOMPUTED)


if __name__ == '__main__':
    unittest.main()
