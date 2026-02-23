# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PII Pseudonymizer is a Python CLI tool that detects and reversibly pseudonymizes personally identifiable information (PII) in Excel (.xlsx) files. It supports two pseudonymization formats: AES-256-SIV deterministic encryption (`--format=encrypted`) and readable fake data with HMAC-based deterministic transforms (`--format=readable`). Multi-sheet workbooks with cross-sheet formula detection are supported.

## Commands

```bash
# Install (editable, with dev dependencies)
pip install -e ".[dev]"

# Run tests
make test          # or: python -m pytest tests/ -v
# Run a single test file
python -m pytest tests/test_transforms.py -v
# Run a single test
python -m pytest tests/test_transforms.py::TestRoundTrip::test_name_round_trip -v

# Lint and format
make lint          # ruff check src/ tests/
make format        # ruff format src/ tests/

# Pseudonymize (heuristics only)
pii-pseudonymizer data.xlsx --no-llm
# Pseudonymize (readable format)
pii-pseudonymizer data.xlsx --no-llm --format=readable
# Pseudonymize (with LLM, thorough mode)
pii-pseudonymizer data.xlsx --model mistral:7b --thorough

# Decode
pii-pseudonymizer --decode output/data_pseudonymized.xlsx --keyfile keys/key_*.json

# Search for a term
pii-pseudonymizer data.xlsx --search "John Smith"
# Ctrl+F pseudonymize matching cells
pii-pseudonymizer data.xlsx --pseudonymize-term "John Smith"

# Decrypt a single value
pii-pseudonymizer decrypt-value "[NAME:base64...]" --keyfile key.json \
    --column first_name --pii-type name

# Launch standalone tkinter decrypt GUI
pii-decrypt-gui
```

## Architecture

### Package Structure

```
src/pii_pseudonymizer/
├── cli.py            # CLI entry point, workflow orchestration
├── config.py         # Config dataclass with JSON loading, allowlist/denylist
├── decoder.py        # Decode workflow with progress callback
├── decrypt_gui.py    # Standalone tkinter GUI for decryption
├── detector.py       # Two-stage detection: heuristics + LLM, thorough mode
├── heuristics.py     # Regex-based PII detection on headers/values
├── obfuscator.py     # AES-256-SIV encryption, key file v3 (encrypted metadata + HMAC)
├── ollama_client.py  # Ollama REST client, batch and per-column analysis
├── reader.py         # XLSX I/O via openpyxl, formula detection
├── transforms.py     # Readable pseudonymization: fake names, date shifting, email
└── tui.py            # Rich-based interactive column selector with cell exclusions
```

### Obfuscation Pipeline

`cli.py:run_obfuscate()` → `reader.read_xlsx()` → `detector.PIIDetector.detect()` → `tui.confirm_columns_tui()` → `obfuscator.Obfuscator` or `transforms.ReadableTransformer` → `reader.write_xlsx()`

### Detection: Two-Stage Design

`detector.py` merges results from two sources with allowlist/denylist overrides:
1. **heuristics.py** — Regex-based pattern matching on column headers and sample values (always runs). Has pattern priority ordering and header-value conflict resolution.
2. **ollama_client.py** — Sends samples to a local Ollama LLM for classification. In `--thorough` mode, analyzes each column individually with context-aware few-shot examples.

### Two Pseudonymization Formats

- `--format=encrypted` (default): `[PREFIX:base64_ciphertext]` using AES-256-SIV. Fully reversible via passphrase.
- `--format=readable`: Deterministic fake names (HMAC-indexed from curated lists), shifted dates (per-column offset), fake emails. Reversible via encrypted mapping in key file.

### Key Design Decisions

- **Deterministic encryption**: AES-SIV mode ensures same plaintext always produces same ciphertext
- **Associated data**: Each encrypted value includes `column_name:pii_type` as authenticated associated data
- **Key file v3**: Metadata (sheets, columns, PII types, readable mappings) is AES-SIV encrypted. HMAC-SHA256 integrity check. Plaintext summary (sheet count, column count) visible without passphrase.
- **Default key location**: `~/.config/pii-pseudonymizer/keys/` (outside project directory, away from AI agents)
- **Cell-level exclusions**: Specific values in an obfuscated column can be excluded (e.g., company names in a "name" column). Stored in key file per-column.
- **Allowlist/denylist**: Persistent `lists.json` at `~/.config/pii-pseudonymizer/lists.json` with `always_pii` and `never_pii` column name lists.
- **Network isolation check**: Warns if network is available during pseudonymization (suppressible with `--allow-online`).
- **Financial deprioritization**: Financial-type columns default to SKIP; user opts in manually.

### Dependencies

Python 3.12+ with: `openpyxl` (XLSX I/O), `cryptography` (AES-SIV, PBKDF2), `requests` (Ollama HTTP API), `rich` (TUI column selector).
