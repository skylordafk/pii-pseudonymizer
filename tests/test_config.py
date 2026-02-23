"""Unit tests for configuration loading."""

import json
import os
import tempfile

from pii_pseudonymizer.config import Config


class TestConfig:
    def test_defaults(self):
        config = Config()
        assert config.ollama_url == "http://localhost:11434"
        assert config.default_model == "mistral:7b"
        assert config.pbkdf2_iterations == 480000
        assert config.max_sample_values == 10

    def test_load_from_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(
                {
                    "ollama_url": "http://custom:11434",
                    "default_model": "llama2:13b",
                    "timeout_seconds": 300,
                },
                f,
            )
            path = f.name

        try:
            config = Config.load(path)
            assert config.ollama_url == "http://custom:11434"
            assert config.default_model == "llama2:13b"
            assert config.timeout_seconds == 300
            # Defaults for unspecified fields
            assert config.pbkdf2_iterations == 480000
        finally:
            os.unlink(path)

    def test_load_missing_file(self):
        """Missing config file falls back to defaults."""
        config = Config.load("/nonexistent/config.json")
        assert config.ollama_url == "http://localhost:11434"

    def test_load_ignores_unknown_keys(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(
                {
                    "ollama_url": "http://custom:11434",
                    "unknown_key": "ignored",
                },
                f,
            )
            path = f.name

        try:
            config = Config.load(path)
            assert config.ollama_url == "http://custom:11434"
            assert not hasattr(config, "unknown_key")
        finally:
            os.unlink(path)

    def test_load_expands_user_in_keys_directory(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"keys_directory": "~/.config/pii-pseudonymizer/keys"}, f)
            path = f.name

        try:
            config = Config.load(path)
            assert "~" not in config.keys_directory
            assert config.keys_directory.endswith(".config/pii-pseudonymizer/keys")
        finally:
            os.unlink(path)
