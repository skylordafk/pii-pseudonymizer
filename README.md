# PII Pseudonymizer

A Python CLI tool that detects and reversibly pseudonymizes personally identifiable information (PII) in Excel (.xlsx) files. Designed for working with sensitive spreadsheet data alongside online AI models — pseudonymize locally, work with AI remotely, then reverse the pseudonymization on results.

## Features

- **Two-stage PII detection**: regex-based heuristics + optional local LLM (via Ollama) for ambiguous columns
- **Two pseudonymization formats**:
  - `--format=encrypted` — AES-256-SIV deterministic encryption (`[NAME:base64...]`)
  - `--format=readable` — deterministic fake names, shifted dates, fake emails (AI-friendly)
- **Multi-sheet support** with cross-sheet formula dependency detection
- **Cell-level exclusions** — exclude specific values (e.g., company names) within an obfuscated column
- **Ctrl+F pseudonymization** — find a term across all sheets and pseudonymize matching cells
- **Thorough mode** — per-column LLM analysis with interactive approval and context-aware detection
- **Allowlist/denylist** — persistent lists of column names that are always/never PII
- **Key file security** — encrypted metadata (AES-SIV), HMAC integrity check, default storage outside project directory
- **Network isolation check** — warns if network is available during pseudonymization
- **Standalone decryption GUI** — tkinter app for decrypting values without the CLI
- **Round-trip verification** — automatically verifies pseudonymization is deterministic and reversible

## Installation

```bash
# Clone and install
git clone https://github.com/<your-username>/pii-pseudonymizer.git
cd pii-pseudonymizer
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Requires Python 3.12+.

## Quick Start

```bash
# Pseudonymize with heuristics only (no Ollama needed)
pii-pseudonymizer data.xlsx --no-llm

# Pseudonymize with readable fake names
pii-pseudonymizer data.xlsx --no-llm --format=readable

# Pseudonymize with LLM detection (requires Ollama running locally)
pii-pseudonymizer data.xlsx --model mistral:7b

# Decode
pii-pseudonymizer --decode output/data_pseudonymized.xlsx --keyfile ~/.config/pii-pseudonymizer/keys/key_*.json

# Search for a term
pii-pseudonymizer data.xlsx --search "John Smith"

# Ctrl+F pseudonymize matching cells
pii-pseudonymizer data.xlsx --pseudonymize-term "John Smith"

# Decrypt a single value
pii-pseudonymizer decrypt-value "[NAME:base64...]" --keyfile key.json \
    --column first_name --pii-type name

# Launch decryption GUI
pii-decrypt-gui
```

## How It Works

1. **Read** the Excel file (all sheets, metadata, formula dependencies)
2. **Detect** PII columns via regex heuristics and optional Ollama LLM
3. **Confirm** interactively — toggle columns, set PII types, exclude specific values
4. **Pseudonymize** selected columns (encrypted tokens or readable fakes)
5. **Verify** round-trip correctness on random samples
6. **Save** output file + encrypted key file (stores no key material, only salt + metadata)

The passphrase is never stored. You need both the key file and passphrase to reverse.

## Security Model

- **AES-256-SIV** deterministic encryption with **PBKDF2-SHA256** key derivation (480k iterations)
- **Key file v3**: column metadata encrypted with a separate derived key, HMAC-SHA256 integrity check
- **Default key location**: `~/.config/pii-pseudonymizer/keys/` (outside project, away from AI agents)
- **Passphrase input**: interactive, `PII_PASSPHRASE` env var, or `--passphrase-fd` (GnuPG-style)
- Deterministic encryption means same input always produces same output — this enables verification but reveals repetition patterns. Document this trade-off for your use case.

## Configuration

Optional `config.json` in the working directory or `~/.config/pii-pseudonymizer/config.json`:

```json
{
  "ollama_url": "http://localhost:11434",
  "default_model": "mistral:7b",
  "timeout_seconds": 120,
  "keys_directory": "~/.config/pii-pseudonymizer/keys",
  "output_directory": "output"
}
```

## Development

```bash
make test       # Run tests (pytest)
make lint       # Lint (ruff check)
make format     # Format (ruff format)
```

## License

MIT
