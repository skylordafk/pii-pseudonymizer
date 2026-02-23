# PII Pseudonymizer

A Python CLI tool that detects and reversibly pseudonymizes personally identifiable information (PII) in Excel (.xlsx) files. Pseudonymize sensitive spreadsheets locally before sharing them with online AI models, then reverse the pseudonymization on the results.

## Installation

### Prerequisites

- Python 3.12+
- **For the decryption GUI only:** tkinter (system package, not pip-installable)

Install tkinter if you want the GUI:

```bash
# Ubuntu / Debian
sudo apt install python3-tk

# Fedora / RHEL
sudo dnf install python3-tkinter

# Arch
sudo pacman -S tk

# macOS (Homebrew) — match your Python version:
brew install python-tk@3.13
```

### Setup

```bash
git clone https://github.com/skylordafk/pii-pseudonymizer.git
cd pii-pseudonymizer
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .
```

> **Note:** If you're on an older pip (< 21.3), the `pip install --upgrade pip` step is important — older versions can't do editable installs from `pyproject.toml` alone.

## Quick Start

You have an Excel file with sensitive data (names, emails, SSNs, etc.) and you want to pseudonymize it before uploading it somewhere.

### 1. Pseudonymize

```bash
# Activate the virtual environment (if not already active)
source .venv/bin/activate

# Run on your file — heuristics-only mode, no external services needed
pii-pseudonymizer yourfile.xlsx --no-llm
```

The tool will:
- Scan every column for PII patterns (names, emails, phones, SSNs, etc.)
- Show you what it found and let you toggle columns on/off
- Ask you to set a passphrase
- Write a pseudonymized copy to `output/yourfile_pseudonymized.xlsx`
- Save an encrypted key file to `~/.config/pii-pseudonymizer/keys/`

Use `--format=readable` if you want AI-friendly fake names/dates instead of encrypted tokens:

```bash
pii-pseudonymizer yourfile.xlsx --no-llm --format=readable
```

### 2. Decode

When you're ready to reverse the pseudonymization:

```bash
pii-pseudonymizer --decode output/yourfile_pseudonymized.xlsx \
    --keyfile ~/.config/pii-pseudonymizer/keys/key_*.json
```

You'll be prompted for the same passphrase you set during pseudonymization.

### 3. Decryption GUI

For decrypting individual values or files through a graphical interface:

```bash
pii-decrypt-gui
```

Browse to your key file, enter your passphrase, and decrypt single values or entire files. The GUI auto-loads the key when you click Decrypt, auto-selects the correct PII type for each column, and accepts encrypted values with or without brackets.

> Requires tkinter — see [Prerequisites](#prerequisites) above if you get a "no module named tkinter" error.

## Other Commands

```bash
# Pseudonymize with local LLM detection (requires Ollama running locally)
pii-pseudonymizer yourfile.xlsx --model mistral:7b

# Search for a term across all sheets (no pseudonymization, just search)
pii-pseudonymizer yourfile.xlsx --search "John Smith"

# Find and pseudonymize all cells matching a term
pii-pseudonymizer yourfile.xlsx --pseudonymize-term "John Smith"

# Decrypt a single value from the command line
pii-pseudonymizer decrypt-value "[NAME:base64...]" --keyfile key.json \
    --column first_name --pii-type name
```

## How It Works

1. **Read** the Excel file (all sheets, metadata, formula dependencies)
2. **Detect** PII columns via regex heuristics and optional local LLM (Ollama)
3. **Confirm** interactively — toggle columns, set PII types, exclude specific values
4. **Pseudonymize** selected columns (encrypted tokens or readable fakes)
5. **Verify** round-trip correctness on random samples
6. **Save** output file + encrypted key file

The passphrase is never stored. You need both the key file and the passphrase to reverse.

## Pseudonymization Formats

| Format | Flag | Output looks like | Best for |
|--------|------|-------------------|----------|
| Encrypted | `--format=encrypted` (default) | `[NAME:aGVsbG8...]` | Maximum security, opaque tokens |
| Readable | `--format=readable` | `Patricia Morrison` | AI analysis, preserves data shape |

Both formats are deterministic (same input = same output) and fully reversible.

## Security Model

- **AES-256-SIV** deterministic encryption with **PBKDF2-SHA256** key derivation (480k iterations)
- **Key file**: column metadata encrypted, HMAC-SHA256 integrity check, stores no key material
- **Default key location**: `~/.config/pii-pseudonymizer/keys/` (outside project directory)
- **Network isolation check**: warns if network is active during pseudonymization
- Passphrase input: interactive prompt, `PII_PASSPHRASE` env var, or `--passphrase-fd N` (GnuPG-style)

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
pip install -e ".[dev]"
make test       # Run tests (pytest)
make lint       # Lint (ruff check)
make format     # Format (ruff format)
```

## License

MIT
