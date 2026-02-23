"""Tests for encrypt/decrypt GUI functionality (TDD — encrypt support)."""

import json
import os
import tempfile

import openpyxl
import pytest

try:
    import tkinter as tk
    from tkinter import ttk

    _test_root = tk.Tk()
    _test_root.destroy()
    HAS_DISPLAY = True
except (ImportError, tk.TclError):
    HAS_DISPLAY = False

pytestmark = pytest.mark.skipif(not HAS_DISPLAY, reason="No display available")


@pytest.fixture
def tk_root():
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def gui(tk_root):
    from pii_pseudonymizer.decrypt_gui import DecryptGUI

    return DecryptGUI(tk_root)


@pytest.fixture
def sample_xlsx():
    """Create a simple xlsx file for testing."""
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
        filepath = f.name

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Sheet1"
    ws.append(["first_name", "last_name", "email", "department"])
    ws.append(["Alice", "Johnson", "alice@example.com", "Engineering"])
    ws.append(["Bob", "Smith", "bob@example.com", "Marketing"])
    ws.append(["Carol", "Williams", "carol@example.com", "HR"])
    wb.save(filepath)
    wb.close()

    yield filepath

    if os.path.exists(filepath):
        os.unlink(filepath)


@pytest.fixture
def temp_paths():
    """Provide temporary paths for output files."""
    paths = {
        "output": tempfile.mktemp(suffix=".xlsx"),
        "key": tempfile.mktemp(suffix=".json"),
    }
    yield paths
    for p in paths.values():
        if os.path.exists(p):
            os.unlink(p)


class TestGUIStructure:
    """Test that the GUI has the expected encrypt UI elements."""

    def test_gui_title_reflects_both_modes(self, gui):
        """Window title should indicate both encrypt and decrypt capability."""
        title = gui.root.title()
        assert "pseudonymizer" in title.lower() or "pii" in title.lower()

    def test_gui_has_encrypt_value_tab(self, gui):
        """GUI should have an 'Encrypt Value' tab in the notebook."""
        notebook = self._find_notebook(gui)
        assert notebook is not None, "No notebook widget found"
        tab_names = [notebook.tab(i, "text") for i in notebook.tabs()]
        assert "Encrypt Value" in tab_names

    def test_gui_has_encrypt_file_tab(self, gui):
        """GUI should have an 'Encrypt File' tab in the notebook."""
        notebook = self._find_notebook(gui)
        assert notebook is not None, "No notebook widget found"
        tab_names = [notebook.tab(i, "text") for i in notebook.tabs()]
        assert "Encrypt File" in tab_names

    def test_encrypt_value_widgets_exist(self, gui):
        """Encrypt Value tab should have the required input/output widgets."""
        assert hasattr(gui, "enc_column_var")
        assert hasattr(gui, "enc_type_combo")
        assert hasattr(gui, "enc_input_text")
        assert hasattr(gui, "enc_output_text")

    def test_encrypt_file_widgets_exist(self, gui):
        """Encrypt File tab should have file selection and column scanning."""
        assert hasattr(gui, "enc_file_input_var")
        assert hasattr(gui, "enc_file_output_var")
        assert hasattr(gui, "enc_key_output_var")
        assert hasattr(gui, "enc_format_var")

    def _find_notebook(self, gui):
        """Walk widget tree to find the ttk.Notebook."""
        for child in gui.root.winfo_children():
            for subchild in child.winfo_children():
                if isinstance(subchild, ttk.Notebook):
                    return subchild
        return None


class TestEncryptSingleValue:
    """Test single value encryption through the GUI."""

    def test_encrypt_value_with_passphrase_only(self, gui):
        """Encrypt a value using just a passphrase (no key file needed)."""
        gui.passphrase_var.set("test-passphrase-123")
        gui.enc_column_var.set("first_name")
        gui.enc_type_var.set("name")
        gui.enc_input_text.delete("1.0", tk.END)
        gui.enc_input_text.insert("1.0", "Alice")

        gui._encrypt_value()

        result = gui.enc_output_text.get("1.0", tk.END).strip()
        assert result.startswith("[NAME:")
        assert result.endswith("]")

    def test_encrypt_value_deterministic(self, gui):
        """Same input produces same encrypted output."""
        gui.passphrase_var.set("test-passphrase-123")
        gui.enc_column_var.set("first_name")
        gui.enc_type_var.set("name")

        gui.enc_input_text.delete("1.0", tk.END)
        gui.enc_input_text.insert("1.0", "Alice")
        gui._encrypt_value()
        result1 = gui.enc_output_text.get("1.0", tk.END).strip()

        gui.enc_input_text.delete("1.0", tk.END)
        gui.enc_input_text.insert("1.0", "Alice")
        gui._encrypt_value()
        result2 = gui.enc_output_text.get("1.0", tk.END).strip()

        assert result1 == result2

    def test_encrypt_value_different_types(self, gui):
        """Different PII types produce different prefixes."""
        gui.passphrase_var.set("test-passphrase-123")
        gui.enc_column_var.set("col")

        gui.enc_type_var.set("name")
        gui.enc_input_text.delete("1.0", tk.END)
        gui.enc_input_text.insert("1.0", "Alice")
        gui._encrypt_value()
        name_result = gui.enc_output_text.get("1.0", tk.END).strip()

        gui.enc_type_var.set("email")
        gui.enc_input_text.delete("1.0", tk.END)
        gui.enc_input_text.insert("1.0", "alice@test.com")
        gui._encrypt_value()
        email_result = gui.enc_output_text.get("1.0", tk.END).strip()

        assert name_result.startswith("[NAME:")
        assert email_result.startswith("[EMAIL:")

    def test_encrypt_with_loaded_key_uses_same_salt(self, gui, temp_paths):
        """When a key file is loaded, encrypt should use the same salt for consistency."""
        from pii_pseudonymizer.obfuscator import Obfuscator

        passphrase = "test-key-consistency"
        obfuscator = Obfuscator(passphrase)
        sheets_columns = {"Sheet1": [{"name": "first_name", "pii_type": "name"}]}
        obfuscator.save_key_file(temp_paths["key"], "test.xlsx", sheets_columns)

        # Load the key file in the GUI
        gui.key_path_var.set(temp_paths["key"])
        gui.passphrase_var.set(passphrase)
        gui._load_key()

        # Encrypt a value through the GUI
        gui.enc_column_var.set("first_name")
        gui.enc_type_var.set("name")
        gui.enc_input_text.delete("1.0", tk.END)
        gui.enc_input_text.insert("1.0", "Alice")
        gui._encrypt_value()
        gui_result = gui.enc_output_text.get("1.0", tk.END).strip()

        # Encrypt the same value with the original obfuscator
        direct_result = obfuscator.obfuscate_value("Alice", "first_name", "name")

        assert gui_result == direct_result


class TestEncryptDecryptRoundTrip:
    """Test that values encrypted in the GUI can be decrypted."""

    def test_encrypt_then_decrypt_single_value(self, gui, temp_paths):
        """Encrypt a value, then decrypt it — should get back the original."""
        from pii_pseudonymizer.obfuscator import Obfuscator

        passphrase = "test-roundtrip-gui"

        # First, create and load a key file so both encrypt and decrypt use same salt
        obfuscator = Obfuscator(passphrase)
        sheets_columns = {"Sheet1": [{"name": "first_name", "pii_type": "name"}]}
        obfuscator.save_key_file(temp_paths["key"], "test.xlsx", sheets_columns)

        gui.key_path_var.set(temp_paths["key"])
        gui.passphrase_var.set(passphrase)
        gui._load_key()

        # Encrypt
        gui.enc_column_var.set("first_name")
        gui.enc_type_var.set("name")
        gui.enc_input_text.delete("1.0", tk.END)
        gui.enc_input_text.insert("1.0", "Alice")
        gui._encrypt_value()
        encrypted = gui.enc_output_text.get("1.0", tk.END).strip()

        # Decrypt using the existing decrypt tab
        gui.column_var.set("first_name")
        gui.type_var.set("name")
        gui.input_text.delete("1.0", tk.END)
        gui.input_text.insert("1.0", encrypted)
        gui._decrypt_value()
        decrypted = gui.output_text.get("1.0", tk.END).strip()

        assert decrypted == "Alice"


class TestEncryptFile:
    """Test file encryption through the GUI."""

    def test_scan_columns_from_xlsx(self, gui, sample_xlsx):
        """Scanning an xlsx file should populate the column list."""
        gui.enc_file_input_var.set(sample_xlsx)
        gui._scan_columns()

        columns = gui._get_scanned_columns()
        col_names = [c["name"] for c in columns]
        assert "first_name" in col_names
        assert "last_name" in col_names
        assert "email" in col_names
        assert "department" in col_names

    def test_encrypt_file_produces_output(self, gui, sample_xlsx, temp_paths):
        """Encrypting an xlsx file should produce an output file."""
        gui.passphrase_var.set("test-file-encrypt")
        gui.enc_file_input_var.set(sample_xlsx)
        gui.enc_file_output_var.set(temp_paths["output"])
        gui.enc_key_output_var.set(temp_paths["key"])

        # Scan and select columns
        gui._scan_columns()
        gui._select_encrypt_columns(
            [
                {"name": "first_name", "pii_type": "name"},
                {"name": "email", "pii_type": "email"},
            ]
        )

        gui._encrypt_file()

        assert os.path.exists(temp_paths["output"]), "Output xlsx not created"
        assert os.path.exists(temp_paths["key"]), "Key file not created"

    def test_encrypt_file_key_file_is_valid(self, gui, sample_xlsx, temp_paths):
        """The key file produced by file encryption should be loadable."""
        from pii_pseudonymizer.obfuscator import Obfuscator

        passphrase = "test-file-keyfile"
        gui.passphrase_var.set(passphrase)
        gui.enc_file_input_var.set(sample_xlsx)
        gui.enc_file_output_var.set(temp_paths["output"])
        gui.enc_key_output_var.set(temp_paths["key"])

        gui._scan_columns()
        gui._select_encrypt_columns(
            [{"name": "first_name", "pii_type": "name"}]
        )
        gui._encrypt_file()

        # Load the key file — should succeed
        obfuscator, key_data = Obfuscator.from_key_file(temp_paths["key"], passphrase)
        assert "sheets" in key_data
        sheets = key_data["sheets"]
        # Find the sheet with first_name
        found = False
        for sheet_meta in sheets.values():
            if "first_name" in sheet_meta.get("columns", {}):
                found = True
                assert sheet_meta["columns"]["first_name"]["pii_type"] == "name"
        assert found, "first_name column not found in key file"

    def test_encrypt_file_data_is_pseudonymized(self, gui, sample_xlsx, temp_paths):
        """The output file should have pseudonymized values in selected columns."""
        from pii_pseudonymizer.reader import read_all_rows

        passphrase = "test-file-data"
        gui.passphrase_var.set(passphrase)
        gui.enc_file_input_var.set(sample_xlsx)
        gui.enc_file_output_var.set(temp_paths["output"])
        gui.enc_key_output_var.set(temp_paths["key"])

        gui._scan_columns()
        gui._select_encrypt_columns(
            [
                {"name": "first_name", "pii_type": "name"},
                {"name": "email", "pii_type": "email"},
            ]
        )
        gui._encrypt_file()

        # Read output file
        out_sheets = read_all_rows(temp_paths["output"])
        _headers, rows = list(out_sheets.values())[0]

        # Encrypted columns should have [PREFIX:...] format
        assert rows[0]["first_name"].startswith("[NAME:")
        assert rows[0]["email"].startswith("[EMAIL:")
        # Non-encrypted columns should be unchanged
        assert rows[0]["department"] == "Engineering"

    def test_encrypt_file_round_trip(self, gui, sample_xlsx, temp_paths):
        """Encrypt a file, then decrypt it — original data should be recovered."""
        from pii_pseudonymizer.decoder import decode_file
        from pii_pseudonymizer.reader import read_all_rows

        passphrase = "test-file-roundtrip"
        gui.passphrase_var.set(passphrase)
        gui.enc_file_input_var.set(sample_xlsx)
        gui.enc_file_output_var.set(temp_paths["output"])
        gui.enc_key_output_var.set(temp_paths["key"])

        gui._scan_columns()
        gui._select_encrypt_columns(
            [
                {"name": "first_name", "pii_type": "name"},
                {"name": "last_name", "pii_type": "name"},
                {"name": "email", "pii_type": "email"},
            ]
        )
        gui._encrypt_file()

        # Decode the encrypted file
        decoded_path = temp_paths["output"].replace(".xlsx", "_decoded.xlsx")
        try:
            result = decode_file(
                temp_paths["output"],
                temp_paths["key"],
                passphrase,
                decoded_path,
                verify_only=False,
            )
            assert result["status"] == "success"
            assert result["round_trip_ok"]

            # Compare original and decoded data
            orig_sheets = read_all_rows(sample_xlsx)
            decoded_sheets = read_all_rows(decoded_path)

            orig_headers, orig_rows = list(orig_sheets.values())[0]
            dec_headers, dec_rows = list(decoded_sheets.values())[0]

            for i, (orig, dec) in enumerate(zip(orig_rows, dec_rows)):
                for col in ["first_name", "last_name", "email"]:
                    assert str(orig[col]).strip() == str(dec[col]).strip(), (
                        f"Row {i} col '{col}': '{orig[col]}' != '{dec[col]}'"
                    )
        finally:
            if os.path.exists(decoded_path):
                os.unlink(decoded_path)

    def test_encrypt_file_readable_format(self, gui, sample_xlsx, temp_paths):
        """File encryption with readable format should produce human-readable pseudonyms."""
        from pii_pseudonymizer.reader import read_all_rows

        passphrase = "test-readable-format"
        gui.passphrase_var.set(passphrase)
        gui.enc_file_input_var.set(sample_xlsx)
        gui.enc_file_output_var.set(temp_paths["output"])
        gui.enc_key_output_var.set(temp_paths["key"])
        gui.enc_format_var.set("readable")

        gui._scan_columns()
        gui._select_encrypt_columns(
            [{"name": "first_name", "pii_type": "name"}]
        )
        gui._encrypt_file()

        # Read output — should be readable names, not [NAME:...] tokens
        out_sheets = read_all_rows(temp_paths["output"])
        _headers, rows = list(out_sheets.values())[0]
        first_val = rows[0]["first_name"]
        assert not first_val.startswith("[NAME:"), f"Expected readable name, got {first_val}"
        # Should be a real-looking name (string, not empty)
        assert isinstance(first_val, str) and len(first_val) > 0
