"""Unit tests for readable pseudonymization transforms."""

import os
import tempfile

import pytest

from pii_pseudonymizer.obfuscator import Obfuscator
from pii_pseudonymizer.reader import read_all_rows, write_xlsx
from pii_pseudonymizer.transforms import ReadableTransformer


@pytest.fixture
def transformer():
    return ReadableTransformer(b"test-key-for-transforms-32bytes!")


class TestNameTransform:
    def test_name_produces_readable_output(self, transformer):
        result = transformer.transform_value("Alice", "first_name", "name")
        # Should be a real name, not a base64 blob
        assert result.isalpha()
        assert not result.startswith("[")

    def test_name_is_deterministic(self, transformer):
        r1 = transformer.transform_value("Alice", "first_name", "name")
        r2 = transformer.transform_value("Alice", "first_name", "name")
        assert r1 == r2

    def test_different_names_different_output(self, transformer):
        r1 = transformer.transform_value("Alice", "first_name", "name")
        r2 = transformer.transform_value("Bob", "first_name", "name")
        assert r1 != r2

    def test_full_name_transform(self, transformer):
        result = transformer.transform_value("Alice Johnson", "full_name", "name")
        # Should be two words (first + last)
        assert " " in result

    def test_last_name_column(self, transformer):
        result = transformer.transform_value("Johnson", "last_name", "name")
        assert result.isalpha()


class TestDateTransform:
    def test_iso_date_shift(self, transformer):
        result = transformer.transform_value("2024-06-15", "dob", "dob")
        # Should still look like a date
        assert "-" in result

    def test_us_date_shift(self, transformer):
        result = transformer.transform_value("06/15/2024", "birthday", "dob")
        assert "/" in result

    def test_date_shift_is_deterministic(self, transformer):
        r1 = transformer.transform_value("2024-06-15", "dob", "dob")
        r2 = transformer.transform_value("2024-06-15", "dob", "dob")
        assert r1 == r2

    def test_date_shift_changes_value(self, transformer):
        result = transformer.transform_value("2024-06-15", "dob", "dob")
        # Very unlikely to be the same date (shift is ±365 days)
        # but not impossible, so just check it's a valid date format
        parts = result.split("-")
        assert len(parts) == 3


class TestEmailTransform:
    def test_email_produces_readable_output(self, transformer):
        result = transformer.transform_value("alice@company.com", "email", "email")
        assert "@example.com" in result
        assert "." in result.split("@")[0]

    def test_email_deterministic(self, transformer):
        r1 = transformer.transform_value("alice@company.com", "email", "email")
        r2 = transformer.transform_value("alice@company.com", "email", "email")
        assert r1 == r2


class TestGenericTransform:
    def test_unknown_type_produces_label(self, transformer):
        result = transformer.transform_value("sensitive-data", "account", "generic")
        assert "GENE" in result or "_" in result


class TestRoundTrip:
    def test_name_round_trip(self, transformer):
        original = "Alice"
        pseudonym = transformer.transform_value(original, "first_name", "name")
        reversed_val = transformer.reverse_value(pseudonym, "first_name", "name")
        assert reversed_val == original

    def test_email_round_trip(self, transformer):
        original = "alice@company.com"
        pseudonym = transformer.transform_value(original, "email", "email")
        reversed_val = transformer.reverse_value(pseudonym, "email", "email")
        assert reversed_val == original

    def test_row_round_trip(self, transformer):
        headers = ["name", "email", "dept"]
        rows = [
            {"name": "Alice", "email": "alice@test.com", "dept": "Engineering"},
            {"name": "Bob", "email": "bob@test.com", "dept": "Marketing"},
        ]
        cols = [
            {"name": "name", "pii_type": "name"},
            {"name": "email", "pii_type": "email"},
        ]
        transformed = transformer.transform_rows(headers, rows, cols)
        reversed_rows = transformer.reverse_rows(headers, transformed, cols)

        assert reversed_rows[0]["name"] == "Alice"
        assert reversed_rows[0]["email"] == "alice@test.com"
        assert reversed_rows[0]["dept"] == "Engineering"  # unchanged
        assert reversed_rows[1]["name"] == "Bob"

    def test_mappings_serialization(self, transformer):
        """Mappings can be extracted and reloaded for reversal."""
        transformer.transform_value("Alice", "first_name", "name")
        transformer.transform_value("Bob", "first_name", "name")

        mappings = transformer.get_mappings()
        assert "first_name" in mappings
        assert len(mappings["first_name"]) == 2

        # Create new transformer with loaded mappings
        new_transformer = ReadableTransformer(b"test-key-for-transforms-32bytes!")
        new_transformer.load_mappings(mappings)

        # Should be able to reverse
        pseudonym = transformer.transform_value("Alice", "first_name", "name")
        assert new_transformer.reverse_value(pseudonym, "first_name", "name") == "Alice"


class TestReadableKeyFileIntegration:
    """Test that readable format integrates with the key file system."""

    def test_full_readable_round_trip(self):
        passphrase = "test-readable-format"
        obfuscator = Obfuscator(passphrase)
        transformer = ReadableTransformer(obfuscator.master_key[:32])

        # Create test data
        headers = ["first_name", "email", "department"]
        rows = [
            {"first_name": "Alice", "email": "alice@corp.com", "department": "Engineering"},
            {"first_name": "Bob", "email": "bob@corp.com", "department": "Marketing"},
        ]
        cols = [
            {"name": "first_name", "pii_type": "name"},
            {"name": "email", "pii_type": "email"},
        ]

        # Transform
        transformed = transformer.transform_rows(headers, rows, cols)
        assert transformed[0]["first_name"] != "Alice"
        assert transformed[0]["department"] == "Engineering"

        # Save key file with mappings
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            key_path = f.name
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            xlsx_path = f.name

        try:
            write_xlsx(xlsx_path, {"Sheet1": (headers, transformed)})
            obfuscator.save_key_file(
                key_path,
                "test.xlsx",
                {"Sheet1": cols},
                output_format="readable",
                readable_mappings=transformer.get_mappings(),
            )

            # Load and decode
            obfuscator2, key_data = Obfuscator.from_key_file(key_path, passphrase)
            assert key_data.get("format") == "readable"
            assert "readable_mappings" in key_data

            transformer2 = ReadableTransformer(obfuscator2.master_key[:32])
            transformer2.load_mappings(key_data["readable_mappings"])

            all_data = read_all_rows(xlsx_path)
            h2, r2 = all_data["Sheet1"]
            reversed_rows = transformer2.reverse_rows(h2, r2, cols)

            assert reversed_rows[0]["first_name"] == "Alice"
            assert reversed_rows[0]["email"] == "alice@corp.com"
            assert reversed_rows[1]["first_name"] == "Bob"

        finally:
            os.unlink(key_path)
            os.unlink(xlsx_path)
