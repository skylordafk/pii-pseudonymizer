"""Tests for cell-level exclusions and Ctrl+F pseudonymization."""

import os
import tempfile

from pii_pseudonymizer.obfuscator import Obfuscator
from pii_pseudonymizer.reader import write_xlsx
from pii_pseudonymizer.tui import _handle_exclusion_command


class TestExclusionCommands:
    """Test the TUI exclusion command handler."""

    def _make_flat(self):
        """Create a sample flat list for testing."""
        results = [
            {"name": "first_name", "pii_type": "name", "action": "OBFUSCATE"},
            {"name": "email", "pii_type": "email", "action": "OBFUSCATE"},
            {"name": "department", "pii_type": "none", "action": "SKIP"},
        ]
        return [("Sheet1", r) for r in results]

    def test_add_exclusion(self):
        flat = self._make_flat()
        result = _handle_exclusion_command("1 x Acme Corp", flat)
        assert result is True
        assert "Acme Corp" in flat[0][1]["exclusions"]

    def test_add_multiple_exclusions(self):
        flat = self._make_flat()
        _handle_exclusion_command("1 x Acme Corp", flat)
        _handle_exclusion_command("1 x Big Co", flat)
        assert len(flat[0][1]["exclusions"]) == 2
        assert "Acme Corp" in flat[0][1]["exclusions"]
        assert "Big Co" in flat[0][1]["exclusions"]

    def test_remove_exclusion(self):
        flat = self._make_flat()
        _handle_exclusion_command("1 x Acme Corp", flat)
        _handle_exclusion_command("1 xr Acme Corp", flat)
        assert len(flat[0][1]["exclusions"]) == 0

    def test_show_exclusions(self, capsys):
        flat = self._make_flat()
        _handle_exclusion_command("1 x SomeValue", flat)
        result = _handle_exclusion_command("1 xi", flat)
        assert result is True

    def test_show_empty_exclusions(self, capsys):
        flat = self._make_flat()
        result = _handle_exclusion_command("1 xi", flat)
        assert result is True

    def test_invalid_index_returns_false(self):
        flat = self._make_flat()
        result = _handle_exclusion_command("99 x value", flat)
        assert result is False

    def test_non_exclusion_command_returns_false(self):
        flat = self._make_flat()
        result = _handle_exclusion_command("1 name", flat)
        assert result is False

    def test_single_word_returns_false(self):
        flat = self._make_flat()
        result = _handle_exclusion_command("done", flat)
        assert result is False

    def test_non_numeric_first_part_returns_false(self):
        flat = self._make_flat()
        result = _handle_exclusion_command("abc x value", flat)
        assert result is False


class TestExclusionInObfuscation:
    """Test that excluded values are preserved during obfuscation."""

    def test_excluded_values_not_obfuscated(self):
        """Excluded cell values should remain unchanged in the output."""
        passphrase = "test-exclusion-pass"
        obfuscator = Obfuscator(passphrase)

        headers = ["full_name", "department"]
        rows = [
            {"full_name": "Alice Johnson", "department": "Engineering"},
            {"full_name": "Acme Corp", "department": "N/A"},
            {"full_name": "Bob Smith", "department": "Marketing"},
        ]
        cols = [{"name": "full_name", "pii_type": "name"}]

        # Obfuscate all
        obf_rows = obfuscator.obfuscate_rows(headers, rows, cols)

        # Apply exclusions: restore "Acme Corp"
        exclusions = {"full_name": {"Acme Corp"}}
        for orig, obf in zip(rows, obf_rows, strict=True):
            for col_name, excl_vals in exclusions.items():
                orig_val = orig.get(col_name)
                if orig_val is not None and str(orig_val).strip() in excl_vals:
                    obf[col_name] = orig_val

        # Verify: Acme Corp unchanged, others obfuscated
        assert obf_rows[0]["full_name"] != "Alice Johnson"
        assert obf_rows[0]["full_name"].startswith("[NAME:")
        assert obf_rows[1]["full_name"] == "Acme Corp"  # excluded
        assert obf_rows[2]["full_name"] != "Bob Smith"
        assert obf_rows[2]["full_name"].startswith("[NAME:")


class TestExclusionsInKeyFile:
    """Test that exclusions are stored in the key file."""

    def test_exclusions_stored_and_loaded(self):
        passphrase = "test-exclusion-keyfile"
        obfuscator = Obfuscator(passphrase)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            key_path = f.name

        try:
            sheets_columns = {
                "Sheet1": [{"name": "full_name", "pii_type": "name"}],
            }
            exclusions = {
                "Sheet1": {"full_name": ["Acme Corp", "Big Co"]},
            }
            obfuscator.save_key_file(
                key_path,
                "test.xlsx",
                sheets_columns,
                exclusions=exclusions,
            )

            # Load and verify
            _ob2, key_data = Obfuscator.from_key_file(key_path, passphrase)
            sheet_meta = key_data["sheets"]["Sheet1"]
            col_meta = sheet_meta["columns"]["full_name"]
            assert col_meta["pii_type"] == "name"
            assert col_meta["obfuscated"] is True
            assert sorted(col_meta["exclusions"]) == ["Acme Corp", "Big Co"]
        finally:
            os.unlink(key_path)

    def test_no_exclusions_key_clean(self):
        """Key file without exclusions should not have exclusions field."""
        passphrase = "test-no-exclusions"
        obfuscator = Obfuscator(passphrase)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            key_path = f.name

        try:
            sheets_columns = {
                "Sheet1": [{"name": "email", "pii_type": "email"}],
            }
            obfuscator.save_key_file(key_path, "test.xlsx", sheets_columns)

            _ob2, key_data = Obfuscator.from_key_file(key_path, passphrase)
            col_meta = key_data["sheets"]["Sheet1"]["columns"]["email"]
            assert "exclusions" not in col_meta
        finally:
            os.unlink(key_path)


class TestCtrlFPseudonymization:
    """Test the search-and-pseudonymize cell-targeting logic."""

    def test_find_term_in_multiple_columns(self):
        """Searching should find a term across different columns and sheets."""
        from pii_pseudonymizer.cli import _search_cells

        headers = ["name", "notes", "manager"]
        rows = [
            {"name": "Alice", "notes": "Report to Alice", "manager": "Alice"},
            {"name": "Bob", "notes": "Works with Carol", "manager": "Carol"},
        ]

        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            xlsx_path = f.name

        try:
            write_xlsx(xlsx_path, {"Sheet1": (headers, rows)})
            _all_sheets, found = _search_cells(xlsx_path, "Alice")

            assert len(found) == 3  # name, notes, manager columns
            sheets = {f["column"] for f in found}
            assert "name" in sheets
            assert "notes" in sheets
            assert "manager" in sheets
        finally:
            os.unlink(xlsx_path)

    def test_case_insensitive_search(self):
        """Search should be case-insensitive."""
        from pii_pseudonymizer.cli import _search_cells

        headers = ["name"]
        rows = [{"name": "ALICE"}, {"name": "alice"}, {"name": "Bob"}]

        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            xlsx_path = f.name

        try:
            write_xlsx(xlsx_path, {"Sheet1": (headers, rows)})
            _all_sheets, found = _search_cells(xlsx_path, "alice")
            assert len(found) == 2
        finally:
            os.unlink(xlsx_path)

    def test_no_matches_returns_empty(self):
        """Searching for a non-existent term returns empty."""
        from pii_pseudonymizer.cli import _search_cells

        headers = ["name"]
        rows = [{"name": "Alice"}]

        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            xlsx_path = f.name

        try:
            write_xlsx(xlsx_path, {"Sheet1": (headers, rows)})
            _all_sheets, found = _search_cells(xlsx_path, "nonexistent")
            assert len(found) == 0
        finally:
            os.unlink(xlsx_path)
