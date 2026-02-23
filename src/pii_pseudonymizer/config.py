"""Configuration loading and defaults."""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    """Application configuration with defaults."""

    ollama_url: str = "http://localhost:11434"
    default_model: str = "mistral:7b"
    fallback_model: str = "qwen2.5:3b"
    num_ctx: int = 2048
    temperature: float = 0
    timeout_seconds: int = 120
    pbkdf2_iterations: int = 480000
    max_sample_values: int = 10
    keys_directory: str = field(
        default_factory=lambda: str(Path.home() / ".config" / "pii-pseudonymizer" / "keys")
    )
    output_directory: str = "output"

    @classmethod
    def load(cls, config_path: str | None = None) -> "Config":
        """Load config from JSON file, falling back to defaults.

        Search order:
        1. Explicit path (if given)
        2. ./config.json (working directory)
        3. ~/.config/pii-pseudonymizer/config.json
        4. Defaults
        """
        search_paths = []
        if config_path:
            search_paths.append(config_path)
        search_paths.extend(
            [
                "config.json",
                str(Path.home() / ".config" / "pii-pseudonymizer" / "config.json"),
            ]
        )

        for path in search_paths:
            if os.path.isfile(path):
                try:
                    with open(path) as f:
                        data = json.load(f)
                    return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
                except (json.JSONDecodeError, TypeError):
                    continue

        return cls()

    @staticmethod
    def _lists_path():
        """Path to the allowlist/denylist file."""
        return str(Path.home() / ".config" / "pii-pseudonymizer" / "lists.json")

    @classmethod
    def load_lists(cls, lists_path=None):
        """Load the allowlist (never PII) and denylist (always PII).

        Returns:
            dict with 'always_pii' and 'never_pii' lists of strings.
        """
        path = lists_path or cls._lists_path()
        if os.path.isfile(path):
            try:
                with open(path) as f:
                    data = json.load(f)
                return {
                    "always_pii": data.get("always_pii", []),
                    "never_pii": data.get("never_pii", []),
                }
            except (json.JSONDecodeError, TypeError):
                pass
        return {"always_pii": [], "never_pii": []}

    @classmethod
    def save_lists(cls, lists_data, lists_path=None):
        """Save the allowlist/denylist to disk."""
        path = lists_path or cls._lists_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(lists_data, f, indent=2)
