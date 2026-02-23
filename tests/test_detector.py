"""Unit tests for PII detector merging logic."""

from pii_pseudonymizer.detector import PIIDetector


class TestDetectorFinancialDeprioritization:
    """Financial columns should default to SKIP."""

    def test_salary_column_defaults_to_skip(self):
        detector = PIIDetector(ollama_client=None)
        metadata = {
            "columns": [
                {
                    "index": 0,
                    "name": "salary",
                    "samples": ["50000", "75000", "90000"],
                    "dtype_guess": "numeric",
                },
            ]
        }
        results = detector.detect(metadata)
        salary_result = results[0]
        assert salary_result["pii_type"] == "financial"
        assert salary_result["action"] == "SKIP"
        assert any("deprioritized" in e.lower() for e in salary_result["evidence"])

    def test_name_column_still_obfuscates(self):
        detector = PIIDetector(ollama_client=None)
        metadata = {
            "columns": [
                {
                    "index": 0,
                    "name": "first_name",
                    "samples": ["Alice", "Bob"],
                    "dtype_guess": "text",
                },
            ]
        }
        results = detector.detect(metadata)
        assert results[0]["action"] == "OBFUSCATE"

    def test_mixed_columns(self):
        detector = PIIDetector(ollama_client=None)
        metadata = {
            "columns": [
                {
                    "index": 0,
                    "name": "first_name",
                    "samples": ["Alice", "Bob"],
                    "dtype_guess": "text",
                },
                {
                    "index": 1,
                    "name": "email",
                    "samples": ["a@b.com", "c@d.com"],
                    "dtype_guess": "text",
                },
                {
                    "index": 2,
                    "name": "salary",
                    "samples": ["50000", "75000"],
                    "dtype_guess": "numeric",
                },
                {
                    "index": 3,
                    "name": "department",
                    "samples": ["Engineering", "Marketing"],
                    "dtype_guess": "text",
                },
            ]
        }
        results = detector.detect(metadata)
        by_name = {r["name"]: r for r in results}
        assert by_name["first_name"]["action"] == "OBFUSCATE"
        assert by_name["email"]["action"] == "OBFUSCATE"
        assert by_name["salary"]["action"] == "SKIP"
        assert by_name["department"]["action"] == "SKIP"
