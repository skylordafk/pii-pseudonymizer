"""Tests for Phase 4: Enhanced LLM pipeline features."""

import os
import tempfile

from pii_pseudonymizer.config import Config
from pii_pseudonymizer.detector import PIIDetector


class TestAllowlistDenylist:
    """Test allowlist/denylist loading and application."""

    def test_load_empty_lists(self):
        lists = Config.load_lists("/nonexistent/path.json")
        assert lists["always_pii"] == []
        assert lists["never_pii"] == []

    def test_save_and_load_lists(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name

        try:
            lists_data = {
                "always_pii": ["secret_notes", "personal_id"],
                "never_pii": ["department", "product_code"],
            }
            Config.save_lists(lists_data, path)

            loaded = Config.load_lists(path)
            assert loaded["always_pii"] == ["secret_notes", "personal_id"]
            assert loaded["never_pii"] == ["department", "product_code"]
        finally:
            os.unlink(path)

    def test_denylist_forces_obfuscate(self):
        """Columns in always_pii should be forced to OBFUSCATE."""
        lists = {"always_pii": ["secret_notes"], "never_pii": []}
        detector = PIIDetector(ollama_client=None, lists=lists)

        metadata = {
            "columns": [
                {
                    "index": 0,
                    "name": "secret_notes",
                    "samples": ["some data"],
                    "null_count": 0,
                    "total_count": 1,
                    "dtype_guess": "text",
                },
                {
                    "index": 1,
                    "name": "department",
                    "samples": ["Engineering"],
                    "null_count": 0,
                    "total_count": 1,
                    "dtype_guess": "text",
                },
            ]
        }

        results = detector.detect(metadata)
        secret_notes = next(r for r in results if r["name"] == "secret_notes")
        assert secret_notes["action"] == "OBFUSCATE"
        assert any("Denylist" in e for e in secret_notes["evidence"])

    def test_allowlist_forces_skip(self):
        """Columns in never_pii should be forced to SKIP."""
        lists = {"always_pii": [], "never_pii": ["first_name"]}
        detector = PIIDetector(ollama_client=None, lists=lists)

        metadata = {
            "columns": [
                {
                    "index": 0,
                    "name": "first_name",
                    "samples": ["Alice", "Bob"],
                    "null_count": 0,
                    "total_count": 2,
                    "dtype_guess": "text",
                },
            ]
        }

        results = detector.detect(metadata)
        first_name = results[0]
        # Even though heuristics would detect this as name PII, allowlist forces SKIP
        assert first_name["action"] == "SKIP"
        assert first_name["pii_type"] == "none"
        assert any("Allowlist" in e for e in first_name["evidence"])

    def test_denylist_case_insensitive(self):
        """Denylist matching should be case-insensitive."""
        lists = {"always_pii": ["Secret_Notes"], "never_pii": []}
        detector = PIIDetector(ollama_client=None, lists=lists)

        metadata = {
            "columns": [
                {
                    "index": 0,
                    "name": "secret_notes",
                    "samples": ["data"],
                    "null_count": 0,
                    "total_count": 1,
                    "dtype_guess": "text",
                },
            ]
        }

        results = detector.detect(metadata)
        assert results[0]["action"] == "OBFUSCATE"


class TestThoroughMode:
    """Test thorough mode initialization and context tracking."""

    def test_detector_thorough_flag(self):
        detector = PIIDetector(ollama_client=None, thorough=True)
        assert detector.thorough is True

    def test_add_approved_context(self):
        detector = PIIDetector(ollama_client=None, thorough=True)
        detector.add_approved_context("email", "email", 0.95)
        detector.add_approved_context("phone", "phone", 0.8)
        assert len(detector._approved_context) == 2
        assert detector._approved_context[0]["name"] == "email"
        assert detector._approved_context[1]["pii_type"] == "phone"

    def test_thorough_without_ollama_uses_heuristics(self):
        """Thorough mode without Ollama still works (heuristics only)."""
        detector = PIIDetector(ollama_client=None, thorough=True)

        metadata = {
            "columns": [
                {
                    "index": 0,
                    "name": "email",
                    "samples": ["alice@test.com", "bob@test.com"],
                    "null_count": 0,
                    "total_count": 2,
                    "dtype_guess": "text",
                },
            ]
        }

        results = detector.detect(metadata)
        assert len(results) == 1
        assert results[0]["action"] == "OBFUSCATE"
        assert results[0]["pii_type"] == "email"


class TestOllamaPerColumnSchema:
    """Test the per-column analysis method exists and has correct interface."""

    def test_analyze_column_individual_exists(self):
        from pii_pseudonymizer.ollama_client import OllamaClient

        client = OllamaClient()
        assert hasattr(client, "analyze_column_individual")

    def test_context_examples_format(self):
        """Verify context examples are properly structured."""
        detector = PIIDetector(ollama_client=None, thorough=True)
        detector.add_approved_context("first_name", "name", 0.9)

        context = detector._approved_context
        assert len(context) == 1
        assert "name" in context[0]
        assert "pii_type" in context[0]
        assert "confidence" in context[0]


class TestOllamaClientConfig:
    """Configurable Ollama options should be applied to API payloads."""

    def test_chat_uses_client_defaults(self, monkeypatch):
        from pii_pseudonymizer.ollama_client import OllamaClient

        captured = {}

        class FakeResp:
            def raise_for_status(self):
                return None

            def json(self):
                return {"message": {"content": "{}"}}

        def fake_post(url, json, timeout):
            captured["url"] = url
            captured["json"] = json
            captured["timeout"] = timeout
            return FakeResp()

        monkeypatch.setattr("pii_pseudonymizer.ollama_client.requests.post", fake_post)

        client = OllamaClient(num_ctx=4096, temperature=0.25)
        client.chat([{"role": "user", "content": "hi"}], timeout=12)

        assert captured["json"]["options"]["num_ctx"] == 4096
        assert captured["json"]["options"]["temperature"] == 0.25
        assert captured["timeout"] == 12

    def test_chat_allows_per_request_overrides(self, monkeypatch):
        from pii_pseudonymizer.ollama_client import OllamaClient

        captured = {}

        class FakeResp:
            def raise_for_status(self):
                return None

            def json(self):
                return {"message": {"content": "{}"}}

        def fake_post(url, json, timeout):
            captured["json"] = json
            return FakeResp()

        monkeypatch.setattr("pii_pseudonymizer.ollama_client.requests.post", fake_post)

        client = OllamaClient(num_ctx=2048, temperature=0)
        client.chat(
            [{"role": "user", "content": "hi"}],
            num_ctx=1024,
            temperature=0.1,
        )

        assert captured["json"]["options"]["num_ctx"] == 1024
        assert captured["json"]["options"]["temperature"] == 0.1
