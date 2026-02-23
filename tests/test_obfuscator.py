"""Unit tests for obfuscator encrypt/decrypt and key file operations."""

import json
import os
import tempfile

import pytest

from pii_pseudonymizer.obfuscator import KEY_FILE_VERSION, OBFUSCATED_PATTERN, Obfuscator


class TestEncryptDecrypt:
    """Test AES-SIV encrypt/decrypt round trips."""

    @pytest.fixture
    def obfuscator(self):
        return Obfuscator("test-passphrase-123")

    def test_basic_round_trip(self, obfuscator):
        original = "Alice"
        encrypted = obfuscator.obfuscate_value(original, "first_name", "name")
        decrypted = obfuscator.deobfuscate_value(encrypted, "first_name", "name")
        assert decrypted == original

    def test_determinism(self, obfuscator):
        """Same input always produces same output."""
        v1 = obfuscator.obfuscate_value("Alice", "first_name", "name")
        v2 = obfuscator.obfuscate_value("Alice", "first_name", "name")
        assert v1 == v2

    def test_different_values_different_output(self, obfuscator):
        v1 = obfuscator.obfuscate_value("Alice", "first_name", "name")
        v2 = obfuscator.obfuscate_value("Bob", "first_name", "name")
        assert v1 != v2

    def test_same_value_different_columns(self, obfuscator):
        """Same value in different columns produces different ciphertext."""
        v1 = obfuscator.obfuscate_value("Alice", "first_name", "name")
        v2 = obfuscator.obfuscate_value("Alice", "last_name", "name")
        assert v1 != v2

    def test_null_passthrough(self, obfuscator):
        assert obfuscator.obfuscate_value(None, "col", "name") is None
        assert obfuscator.deobfuscate_value(None, "col", "name") is None

    def test_empty_passthrough(self, obfuscator):
        assert obfuscator.obfuscate_value("", "col", "name") == ""
        assert obfuscator.obfuscate_value("  ", "col", "name") == "  "

    def test_output_format(self, obfuscator):
        encrypted = obfuscator.obfuscate_value("alice@test.com", "email", "email")
        assert encrypted.startswith("[EMAIL:")
        assert encrypted.endswith("]")
        assert OBFUSCATED_PATTERN.match(encrypted)

    def test_prefix_mapping(self, obfuscator):
        """Different PII types produce different prefixes."""
        name = obfuscator.obfuscate_value("Alice", "col", "name")
        email = obfuscator.obfuscate_value("a@b.com", "col", "email")
        ssn = obfuscator.obfuscate_value("123-45-6789", "col", "ssn")
        assert name.startswith("[NAME:")
        assert email.startswith("[EMAIL:")
        assert ssn.startswith("[SSN:")

    def test_non_obfuscated_passthrough(self, obfuscator):
        """Values that don't match the pattern are returned as-is."""
        assert obfuscator.deobfuscate_value("plain text", "col", "name") == "plain text"
        assert obfuscator.deobfuscate_value("12345", "col", "name") == "12345"

    def test_unicode_round_trip(self, obfuscator):
        original = "Müller-Schmidt"
        encrypted = obfuscator.obfuscate_value(original, "name", "name")
        decrypted = obfuscator.deobfuscate_value(encrypted, "name", "name")
        assert decrypted == original

    def test_long_value_round_trip(self, obfuscator):
        original = "123 Main Street, Apartment 4B, Springfield, IL 62704"
        encrypted = obfuscator.obfuscate_value(original, "address", "address")
        decrypted = obfuscator.deobfuscate_value(encrypted, "address", "address")
        assert decrypted == original


class TestRowOperations:
    """Test batch row obfuscation/deobfuscation."""

    @pytest.fixture
    def obfuscator(self):
        return Obfuscator("test-passphrase-123")

    def test_obfuscate_rows(self, obfuscator):
        headers = ["name", "email", "dept"]
        rows = [
            {"name": "Alice", "email": "alice@test.com", "dept": "Engineering"},
            {"name": "Bob", "email": "bob@test.com", "dept": "Marketing"},
        ]
        cols = [
            {"name": "name", "pii_type": "name"},
            {"name": "email", "pii_type": "email"},
        ]
        result = obfuscator.obfuscate_rows(headers, rows, cols)

        # Sensitive columns obfuscated
        assert result[0]["name"].startswith("[NAME:")
        assert result[0]["email"].startswith("[EMAIL:")
        # Non-sensitive unchanged
        assert result[0]["dept"] == "Engineering"
        # Original unchanged
        assert rows[0]["name"] == "Alice"

    def test_round_trip_rows(self, obfuscator):
        headers = ["name", "ssn"]
        rows = [
            {"name": "Alice", "ssn": "123-45-6789"},
        ]
        cols = [
            {"name": "name", "pii_type": "name"},
            {"name": "ssn", "pii_type": "ssn"},
        ]
        obf_rows = obfuscator.obfuscate_rows(headers, rows, cols)
        dec_rows = obfuscator.deobfuscate_rows(headers, obf_rows, cols)
        assert dec_rows[0]["name"] == "Alice"
        assert dec_rows[0]["ssn"] == "123-45-6789"


class TestKeyFile:
    """Test key file save/load operations."""

    def test_key_file_round_trip(self):
        passphrase = "test-key-file-123"
        obfuscator = Obfuscator(passphrase)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            key_path = f.name

        try:
            sheets_columns = {
                "Sheet1": [
                    {"name": "first_name", "pii_type": "name"},
                    {"name": "email", "pii_type": "email"},
                ],
            }
            obfuscator.save_key_file(key_path, "test.xlsx", sheets_columns)

            # Load and verify
            obfuscator2, key_data = Obfuscator.from_key_file(key_path, passphrase)
            assert key_data["version"] == KEY_FILE_VERSION
            assert "Sheet1" in key_data["sheets"]
            columns = key_data["sheets"]["Sheet1"]["columns"]
            assert "first_name" in columns
            assert columns["first_name"]["pii_type"] == "name"
            assert columns["email"]["pii_type"] == "email"

            # Verify encryption works with loaded obfuscator
            original = "Alice"
            enc1 = obfuscator.obfuscate_value(original, "first_name", "name")
            enc2 = obfuscator2.obfuscate_value(original, "first_name", "name")
            assert enc1 == enc2

        finally:
            os.unlink(key_path)

    def test_key_file_v3_encrypted_metadata(self):
        """Verify that the key file v3 encrypts sheet/column metadata."""
        passphrase = "test-encrypted-metadata"
        obfuscator = Obfuscator(passphrase)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            key_path = f.name

        try:
            sheets_columns = {
                "Employees": [{"name": "ssn", "pii_type": "ssn"}],
            }
            obfuscator.save_key_file(key_path, "test.xlsx", sheets_columns)

            # Read raw file: should NOT contain plaintext column names
            with open(key_path) as f:
                raw = f.read()
                raw_data = json.loads(raw)

            assert "encrypted_metadata" in raw_data
            assert "sheets" not in raw_data  # sheets should NOT be in plaintext
            assert "ssn" not in raw  # column name should not appear in plaintext
            assert "Employees" not in raw  # sheet name should not appear

            # Summary should be present
            assert "summary" in raw_data
            assert raw_data["summary"]["sheet_count"] == 1
            assert raw_data["summary"]["column_count"] == 1

        finally:
            os.unlink(key_path)

    def test_key_file_hmac_integrity(self):
        """Verify HMAC detects tampering."""
        passphrase = "test-hmac-integrity"
        obfuscator = Obfuscator(passphrase)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            key_path = f.name

        try:
            sheets_columns = {
                "Sheet1": [{"name": "name", "pii_type": "name"}],
            }
            obfuscator.save_key_file(key_path, "test.xlsx", sheets_columns)

            # Tamper with the file
            with open(key_path) as f:
                data = json.load(f)
            data["source_file"] = "tampered.xlsx"
            with open(key_path, "w") as f:
                json.dump(data, f, indent=2)

            # Loading should fail HMAC check
            with pytest.raises(ValueError, match="integrity check failed"):
                Obfuscator.from_key_file(key_path, passphrase)

        finally:
            os.unlink(key_path)

    def test_wrong_passphrase_fails(self):
        """Wrong passphrase should fail to decrypt metadata."""
        passphrase = "correct-passphrase"
        obfuscator = Obfuscator(passphrase)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            key_path = f.name

        try:
            sheets_columns = {
                "Sheet1": [{"name": "name", "pii_type": "name"}],
            }
            obfuscator.save_key_file(key_path, "test.xlsx", sheets_columns)

            # Try with wrong passphrase — should fail at HMAC or decryption
            with pytest.raises((ValueError, Exception)):
                Obfuscator.from_key_file(key_path, "wrong-passphrase")

        finally:
            os.unlink(key_path)

    def test_flat_list_backward_compat(self):
        """Flat list input should be treated as Sheet1."""
        passphrase = "test-compat"
        obfuscator = Obfuscator(passphrase)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            key_path = f.name

        try:
            flat_columns = [
                {"name": "email", "pii_type": "email"},
            ]
            obfuscator.save_key_file(key_path, "test.xlsx", flat_columns)

            _obfuscator2, key_data = Obfuscator.from_key_file(key_path, passphrase)
            assert "Sheet1" in key_data["sheets"]

        finally:
            os.unlink(key_path)

    def test_custom_iteration_count_persists_in_keyfile(self):
        """Configured PBKDF2 iterations should be preserved and reused on load."""
        passphrase = "test-custom-iterations"
        obfuscator = Obfuscator(passphrase, iterations=123456)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            key_path = f.name

        try:
            sheets_columns = {"Sheet1": [{"name": "email", "pii_type": "email"}]}
            obfuscator.save_key_file(key_path, "test.xlsx", sheets_columns)

            with open(key_path) as f:
                raw = json.load(f)
            assert raw["iterations"] == 123456

            loaded_obfuscator, _ = Obfuscator.from_key_file(key_path, passphrase)
            assert loaded_obfuscator.iterations == 123456
        finally:
            os.unlink(key_path)
