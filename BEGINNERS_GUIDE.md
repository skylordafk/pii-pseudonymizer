# Beginner's Guide

This guide walks you through setting up PII Pseudonymizer from scratch on a fresh macOS or Linux machine. If you already have Python 3.12+, git, and pip, skip ahead to [Clone and Install](#2-clone-and-install).

---

## 1. Install Prerequisites

### macOS

Open **Terminal** (search for it in Spotlight, or find it in Applications > Utilities).

**Install Homebrew** (macOS package manager):

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Follow the on-screen instructions. When it finishes, it will tell you to run a command to add Homebrew to your PATH — run that command.

**Install Python and Git:**

```bash
brew install python@3.13 git
```

**Install tkinter** (needed only for the decryption GUI):

```bash
brew install python-tk@3.13
```

Verify it worked:

```bash
python3 --version
# Should print Python 3.13.x
git --version
# Should print git version 2.x.x
```

### Linux (Ubuntu / Debian)

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv git
```

For the GUI:

```bash
sudo apt install python3-tk
```

Verify:

```bash
python3 --version
# Should print Python 3.12+ (Ubuntu 24.04 ships 3.12)
```

### Linux (Fedora)

```bash
sudo dnf install python3 python3-pip git
```

For the GUI:

```bash
sudo dnf install python3-tkinter
```

---

## 2. Clone and Install

**Clone the repository** (downloads the source code to your machine):

```bash
git clone https://github.com/skylordafk/pii-pseudonymizer.git
cd pii-pseudonymizer
```

**Create a virtual environment** (isolates this project's packages from the rest of your system):

```bash
python3 -m venv .venv
```

**Activate the virtual environment** (you'll need to do this each time you open a new terminal):

```bash
source .venv/bin/activate
```

Your prompt should now show `(.venv)` at the beginning.

**Upgrade pip** (ensures the installer is new enough to handle modern Python packages):

```bash
pip install --upgrade pip
```

**Install PII Pseudonymizer:**

```bash
pip install -e .
```

The `-e` flag installs in "editable" mode, meaning you can pull updates with `git pull` without reinstalling.

---

## 3. Verify Installation

```bash
pii-pseudonymizer --help
```

You should see a help screen listing available commands and flags. If you get `command not found`, make sure your virtual environment is activated (you should see `(.venv)` in your prompt).

To verify the GUI:

```bash
pii-decrypt-gui
```

A window should open. Close it for now — we'll use it later.

---

## 4. Your First Pseudonymization

Suppose you have an Excel file called `contacts.xlsx` with columns like Name, Email, Phone, and Company.

**Run the pseudonymizer:**

```bash
pii-pseudonymizer contacts.xlsx --no-llm
```

`--no-llm` means it uses built-in pattern matching only (no AI model needed).

**What happens next:**

1. The tool scans every column for PII patterns
2. An interactive screen appears showing what it found — use arrow keys to toggle columns on/off, then press Enter to confirm
3. You'll be asked to create a passphrase — pick something memorable, you'll need it to reverse the process
4. Two files are created:
   - `output/contacts_pseudonymized.xlsx` — your pseudonymized spreadsheet
   - A key file in `~/.config/pii-pseudonymizer/keys/` — needed for decoding

Open the output file in Excel or any spreadsheet app to see the result. PII columns will contain encrypted tokens like `[NAME:aGVsbG8...]`.

**Want readable fake names instead of encrypted tokens?** Add `--format=readable`:

```bash
pii-pseudonymizer contacts.xlsx --no-llm --format=readable
```

This replaces real names with realistic fake ones (e.g., "John Smith" becomes "Patricia Morrison"), which is useful when sharing data with AI tools that work better with natural-looking data.

---

## 5. Decoding (Reversing the Pseudonymization)

When you're ready to restore the original data:

```bash
pii-pseudonymizer --decode output/contacts_pseudonymized.xlsx \
    --keyfile ~/.config/pii-pseudonymizer/keys/key_*.json
```

Enter the same passphrase you used during pseudonymization. The decoded file is saved alongside the pseudonymized one.

---

## 6. Using the Decryption GUI

The GUI is useful for decrypting individual values or files without the command line.

```bash
pii-decrypt-gui
```

**To decrypt a single value:**

1. Click **Browse** next to Key File and select your `.json` key file
2. Enter your passphrase
3. Paste an encrypted value (e.g., `[NAME:aGVsbG8...]`) into the input field
4. Select the column name and PII type (the GUI auto-selects when possible)
5. Click **Decrypt**

**To decrypt an entire file:**

1. Load your key file and enter your passphrase (same as above)
2. Switch to the **File** tab
3. Browse to the pseudonymized `.xlsx` file
4. Click **Decrypt File**

---

## 7. Troubleshooting

### "command not found: pii-pseudonymizer"

Your virtual environment isn't activated. Run:

```bash
source .venv/bin/activate
```

You need to do this every time you open a new terminal window.

### "No module named tkinter"

tkinter is a system package, not installable via pip. Install it with your system package manager:

- **macOS:** `brew install python-tk@3.13`
- **Ubuntu/Debian:** `sudo apt install python3-tk`
- **Fedora:** `sudo dnf install python3-tkinter`

### "pip install -e ." fails with an error about pyproject.toml

Your pip is too old. Upgrade it first:

```bash
pip install --upgrade pip
```

Then retry `pip install -e .`.

### Python version is too old (3.11 or lower)

PII Pseudonymizer requires Python 3.12+. Check your version:

```bash
python3 --version
```

- **macOS:** `brew install python@3.13` and make sure `/opt/homebrew/bin` is in your PATH
- **Ubuntu:** Consider using Ubuntu 24.04+, or install from the `deadsnakes` PPA
- **Fedora:** `sudo dnf install python3.13`

### "ModuleNotFoundError: No module named 'pii_pseudonymizer'"

You're running Python outside the virtual environment. Make sure you see `(.venv)` in your prompt, or run commands with the venv Python directly:

```bash
.venv/bin/pii-pseudonymizer --help
```
