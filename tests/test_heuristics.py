"""Unit tests for heuristics-based PII detection."""

import pytest

from pii_pseudonymizer.heuristics import _match_header, analyze_all_columns, analyze_column


class TestHeaderMatching:
    """Test header pattern matching."""

    @pytest.mark.parametrize(
        "header,expected",
        [
            ("first_name", "name"),
            ("last_name", "name"),
            ("full_name", "name"),
            ("fname", "name"),
            ("lname", "name"),
            ("surname", "name"),
            ("given_name", "name"),
            ("maiden_name", "name"),
            ("employee_name", "name"),
            ("name", "name"),
            ("Name", "name"),
            ("email", "email"),
            ("e-mail", "email"),
            ("email_address", "email"),
            ("contact_email", "email"),
            ("phone", "phone"),
            ("telephone", "phone"),
            ("mobile", "phone"),
            ("cell", "phone"),
            ("fax", "phone"),
            ("home_phone", "phone"),
            ("ssn", "ssn"),
            ("social_security", "ssn"),
            ("national_id", "ssn"),
            ("tax_id", "ssn"),
            ("passport_num", "ssn"),
            ("driver_license", "ssn"),
            ("address", "address"),
            ("street", "address"),
            ("city", "address"),
            ("state", "address"),
            ("zip_code", "address"),
            ("postal_code", "address"),
            ("country", "address"),
            ("dob", "dob"),
            ("date_of_birth", "dob"),
            ("birthday", "dob"),
            ("age", "dob"),
            ("account_num", "financial"),
            ("credit_card", "financial"),
            ("routing_num", "financial"),
            ("iban", "financial"),
            ("salary", "financial"),
        ],
    )
    def test_header_matches(self, header, expected):
        assert _match_header(header) == expected

    @pytest.mark.parametrize(
        "header",
        [
            "employee_id",
            "department",
            "quantity",
            "total_amount",
            "status",
            "created_at",
            "updated_at",
            "description",
            "invoice_number",
            "order_id",
            "product_code",
        ],
    )
    def test_header_no_match(self, header):
        assert _match_header(header) is None


class TestValueMatching:
    """Test value pattern matching."""

    def test_email_values(self):
        result = analyze_column(
            "contact", ["alice@example.com", "bob@test.org", "carol@company.co.uk"]
        )
        assert result["value_match_pii_type"] == "email"
        assert result["value_match_ratio"] > 0.5

    def test_ssn_values(self):
        result = analyze_column("id_field", ["123-45-6789", "234-56-7890", "345-67-8901"])
        assert result["value_match_pii_type"] == "ssn"
        assert result["value_match_ratio"] > 0.5

    def test_phone_values(self):
        result = analyze_column(
            "contact_info", ["+1 (555) 123-4567", "555-987-6543", "(800) 555-0199"]
        )
        assert result["value_match_pii_type"] == "phone"

    def test_credit_card_values(self):
        result = analyze_column("payment", ["4111-1111-1111-1111", "5500 0000 0000 0004"])
        assert result["value_match_pii_type"] == "credit_card"

    def test_ip_address_values(self):
        result = analyze_column("server", ["192.168.1.1", "10.0.0.1", "172.16.0.100"])
        assert result["value_match_pii_type"] == "ip_address"

    def test_non_pii_values(self):
        result = analyze_column("amount", ["100", "200", "350", "42.50"])
        assert result["pii_type"] == "none"
        assert result["heuristic_score"] == "none"


class TestScoring:
    """Test confidence scoring logic."""

    def test_high_score_header_and_values(self):
        """Header match + value match = high confidence."""
        result = analyze_column(
            "email", ["alice@example.com", "bob@test.org", "carol@company.co.uk"]
        )
        assert result["heuristic_score"] == "high"
        assert result["confidence"] >= 0.7

    def test_medium_score_header_only(self):
        """Header match without value matches = medium confidence."""
        result = analyze_column("first_name", ["Alice", "Bob", "Carol"])
        assert result["heuristic_score"] == "medium"
        assert result["confidence"] == 0.7

    def test_medium_score_values_only(self):
        """Value matches without header match = medium confidence."""
        result = analyze_column(
            "field_x", ["alice@example.com", "bob@test.org", "carol@company.co.uk"]
        )
        assert result["heuristic_score"] == "medium"
        assert 0.5 <= result["confidence"] < 0.8

    def test_no_score(self):
        """Neither header nor value match = no confidence."""
        result = analyze_column("quantity", ["10", "20", "30"])
        assert result["heuristic_score"] == "none"
        assert result["confidence"] == 0.0


class TestAnalyzeAllColumns:
    """Test batch column analysis."""

    def test_analyze_multiple_columns(self):
        columns = [
            {"index": 0, "name": "first_name", "samples": ["Alice", "Bob"], "dtype_guess": "text"},
            {"index": 1, "name": "email", "samples": ["a@b.com", "c@d.com"], "dtype_guess": "text"},
            {
                "index": 2,
                "name": "department",
                "samples": ["Engineering", "HR"],
                "dtype_guess": "text",
            },
        ]
        results = analyze_all_columns(columns)
        assert len(results) == 3
        assert results[0]["pii_type"] == "name"
        assert results[1]["pii_type"] == "email"
        assert results[2]["pii_type"] == "none"

    def test_preserves_index_and_dtype(self):
        columns = [
            {"index": 5, "name": "salary", "samples": ["50000"], "dtype_guess": "numeric"},
        ]
        results = analyze_all_columns(columns)
        assert results[0]["index"] == 5
        assert results[0]["dtype_guess"] == "numeric"


class TestPhoneRegexAccuracy:
    """Test that the tightened phone regex avoids false positives."""

    def test_real_phone_numbers(self):
        """Actual phone numbers should still be detected."""
        result = analyze_column(
            "contact",
            [
                "+1 (555) 123-4567",
                "555-987-6543",
                "(800) 555-0199",
            ],
        )
        assert result["value_match_pii_type"] == "phone"

    def test_invoice_numbers_not_phone(self):
        """Invoice numbers like INV-1234-5678 should NOT match as phone."""
        result = analyze_column(
            "invoice",
            [
                "INV-1234-5678",
                "INV-2345-6789",
                "INV-3456-7890",
            ],
        )
        assert result["value_match_pii_type"] != "phone"

    def test_short_digit_strings_not_phone(self):
        """Short digit-only strings should NOT match as phone."""
        result = analyze_column("code", ["12345", "67890", "11111"])
        assert result["value_match_pii_type"] != "phone"

    def test_dates_not_phone(self):
        """Date-like patterns should not match as phone."""
        result = analyze_column("date_field", ["01/15/2024", "12/31/2023", "06/01/2025"])
        # Should match "date", not "phone"
        assert result["value_match_pii_type"] != "phone"

    def test_ip_addresses_not_phone(self):
        """IP addresses should match ip_address, not phone."""
        result = analyze_column("server_ip", ["192.168.1.1", "10.0.0.1", "172.16.0.100"])
        assert result["value_match_pii_type"] == "ip_address"


class TestHeaderValueConflict:
    """Test header-value conflict resolution (Phase 2)."""

    def test_header_match_no_values_downgrades(self):
        """Header matches PII pattern but no sample values match -> downgrade."""
        # "phone" header matches phone PII type (which has value patterns),
        # but none of the sample values look like phone numbers -> downgrade
        result = analyze_column("phone", ["N/A", "pending", "none", "TBD"])
        assert result["heuristic_score"] == "low"
        assert result["confidence"] == 0.4
        assert any("needs review" in e for e in result["evidence"])

    def test_header_match_with_values_stays_high(self):
        """Header + value match should remain high confidence."""
        result = analyze_column("email", ["a@b.com", "c@d.com", "e@f.com"])
        assert result["heuristic_score"] == "high"
        assert result["confidence"] >= 0.7
