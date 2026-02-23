"""Standalone tkinter GUI for encrypting and decrypting pseudonymized values.

Cross-platform (macOS + Linux), uses only stdlib (tkinter). Never sends data anywhere.
Launch with: python -m pii_pseudonymizer.decrypt_gui
"""

import os
import sys

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except ImportError:
    print("Error: tkinter is not installed.")
    print()
    print("tkinter is a system package and cannot be installed with pip.")
    print("Install it for your OS:")
    print()
    print("  Ubuntu/Debian:  sudo apt install python3-tk")
    print("  Fedora/RHEL:    sudo dnf install python3-tkinter")
    print("  Arch:           sudo pacman -S tk")
    print("  macOS (brew):   brew install python-tk")
    print()
    sys.exit(1)

# PII types available for selection
PII_TYPES = ["name", "email", "phone", "ssn", "address", "dob", "financial", "generic", "date"]


class DecryptGUI:
    """Lightweight GUI for encrypting and decrypting pseudonymized values or files."""

    def __init__(self, root):
        self.root = root
        self.root.title("PII Pseudonymizer")
        self.root.geometry("700x550")
        self.root.minsize(500, 400)

        self.obfuscator = None
        self.key_data = None
        self._column_type_map = {}  # (sheet_name, column_name) -> pii_type
        self._columns_by_sheet = {}  # sheet_name -> list[column_name]
        self._scanned_columns = []  # populated by _scan_columns()
        self._selected_encrypt_columns = []  # set by _select_encrypt_columns()
        self._enc_obfuscator = None  # cached obfuscator for encrypt (no key file)
        self._enc_passphrase = None  # passphrase used to create _enc_obfuscator

        self._build_ui()

    def _build_ui(self):
        # Main frame with padding
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        # Key file section
        key_frame = ttk.LabelFrame(main, text="Key File", padding=5)
        key_frame.pack(fill=tk.X, pady=(0, 10))

        self.key_path_var = tk.StringVar()
        ttk.Entry(key_frame, textvariable=self.key_path_var, width=50).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5)
        )
        ttk.Button(key_frame, text="Browse...", command=self._browse_key).pack(side=tk.LEFT)

        # Passphrase section
        pass_frame = ttk.LabelFrame(main, text="Passphrase", padding=5)
        pass_frame.pack(fill=tk.X, pady=(0, 10))

        self.passphrase_var = tk.StringVar()
        ttk.Entry(pass_frame, textvariable=self.passphrase_var, show="*", width=40).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5)
        )
        ttk.Button(pass_frame, text="Load Key", command=self._load_key).pack(side=tk.LEFT)

        self.status_var = tk.StringVar(value="No key loaded")
        ttk.Label(main, textvariable=self.status_var, foreground="gray").pack(anchor=tk.W)

        # Notebook for tabs
        notebook = ttk.Notebook(main)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        # Tab 1: Single value decryption
        self._build_decrypt_value_tab(notebook)

        # Tab 2: Decrypt File
        self._build_decrypt_file_tab(notebook)

        # Tab 3: Encrypt Value
        self._build_encrypt_value_tab(notebook)

        # Tab 4: Encrypt File
        self._build_encrypt_file_tab(notebook)

    # ── Tab builders ──────────────────────────────────────────────

    def _build_decrypt_value_tab(self, notebook):
        single_frame = ttk.Frame(notebook, padding=10)
        notebook.add(single_frame, text="Single Value")

        sel_frame = ttk.Frame(single_frame)
        sel_frame.pack(fill=tk.X, pady=(0, 5))

        ttk.Label(sel_frame, text="Sheet:").pack(side=tk.LEFT)
        self.sheet_var = tk.StringVar()
        self.sheet_combo = ttk.Combobox(
            sel_frame, textvariable=self.sheet_var, width=20, state="readonly"
        )
        self.sheet_combo.pack(side=tk.LEFT, padx=5)

        ttk.Label(sel_frame, text="Column:").pack(side=tk.LEFT)
        self.column_var = tk.StringVar()
        self.column_combo = ttk.Combobox(
            sel_frame, textvariable=self.column_var, width=20, state="readonly"
        )
        self.column_combo.pack(side=tk.LEFT, padx=5)

        ttk.Label(sel_frame, text="Type:").pack(side=tk.LEFT, padx=(10, 0))
        self.type_var = tk.StringVar()
        self.type_combo = ttk.Combobox(
            sel_frame, textvariable=self.type_var, width=12, state="readonly"
        )
        self.type_combo.pack(side=tk.LEFT, padx=5)

        ttk.Label(single_frame, text="Pseudonymized value:").pack(anchor=tk.W)
        self.input_text = tk.Text(single_frame, height=3, wrap=tk.WORD)
        self.input_text.pack(fill=tk.X, pady=(0, 5))

        ttk.Button(single_frame, text="Decrypt", command=self._decrypt_value).pack(pady=5)

        ttk.Label(single_frame, text="Decrypted:").pack(anchor=tk.W)
        self.output_text = tk.Text(single_frame, height=3, wrap=tk.WORD, state=tk.DISABLED)
        self.output_text.pack(fill=tk.X)

    def _build_decrypt_file_tab(self, notebook):
        file_frame = ttk.Frame(notebook, padding=10)
        notebook.add(file_frame, text="Decrypt File")

        input_row = ttk.Frame(file_frame)
        input_row.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(input_row, text="Input file:").pack(side=tk.LEFT)
        self.file_input_var = tk.StringVar()
        ttk.Entry(input_row, textvariable=self.file_input_var, width=40).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=5
        )
        ttk.Button(input_row, text="Browse...", command=self._browse_input).pack(side=tk.LEFT)

        output_row = ttk.Frame(file_frame)
        output_row.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(output_row, text="Output file:").pack(side=tk.LEFT)
        self.file_output_var = tk.StringVar()
        ttk.Entry(output_row, textvariable=self.file_output_var, width=40).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=5
        )
        ttk.Button(output_row, text="Browse...", command=self._browse_output).pack(side=tk.LEFT)

        btn_frame = ttk.Frame(file_frame)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Decrypt File", command=self._decrypt_file).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Verify Only", command=self._verify_file).pack(
            side=tk.LEFT, padx=10
        )

        self.file_status_var = tk.StringVar()
        ttk.Label(file_frame, textvariable=self.file_status_var, wraplength=600).pack(
            anchor=tk.W, pady=5
        )

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(file_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=5)

    def _build_encrypt_value_tab(self, notebook):
        enc_frame = ttk.Frame(notebook, padding=10)
        notebook.add(enc_frame, text="Encrypt Value")

        # Column name and PII type
        sel_frame = ttk.Frame(enc_frame)
        sel_frame.pack(fill=tk.X, pady=(0, 5))

        ttk.Label(sel_frame, text="Column:").pack(side=tk.LEFT)
        self.enc_column_var = tk.StringVar()
        ttk.Entry(sel_frame, textvariable=self.enc_column_var, width=20).pack(
            side=tk.LEFT, padx=5
        )

        ttk.Label(sel_frame, text="Type:").pack(side=tk.LEFT, padx=(10, 0))
        self.enc_type_var = tk.StringVar(value="name")
        self.enc_type_combo = ttk.Combobox(
            sel_frame,
            textvariable=self.enc_type_var,
            width=12,
            values=PII_TYPES,
            state="readonly",
        )
        self.enc_type_combo.pack(side=tk.LEFT, padx=5)

        # Plaintext input
        ttk.Label(enc_frame, text="Plaintext value:").pack(anchor=tk.W)
        self.enc_input_text = tk.Text(enc_frame, height=3, wrap=tk.WORD)
        self.enc_input_text.pack(fill=tk.X, pady=(0, 5))

        ttk.Button(enc_frame, text="Encrypt", command=self._encrypt_value).pack(pady=5)

        # Encrypted output
        ttk.Label(enc_frame, text="Encrypted:").pack(anchor=tk.W)
        self.enc_output_text = tk.Text(enc_frame, height=3, wrap=tk.WORD, state=tk.DISABLED)
        self.enc_output_text.pack(fill=tk.X)

    def _build_encrypt_file_tab(self, notebook):
        enc_file_frame = ttk.Frame(notebook, padding=10)
        notebook.add(enc_file_frame, text="Encrypt File")

        # Input file
        input_row = ttk.Frame(enc_file_frame)
        input_row.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(input_row, text="Input file:").pack(side=tk.LEFT)
        self.enc_file_input_var = tk.StringVar()
        ttk.Entry(input_row, textvariable=self.enc_file_input_var, width=40).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=5
        )
        ttk.Button(input_row, text="Browse...", command=self._browse_enc_input).pack(side=tk.LEFT)

        # Scan columns button
        scan_row = ttk.Frame(enc_file_frame)
        scan_row.pack(fill=tk.X, pady=(0, 5))
        ttk.Button(scan_row, text="Scan Columns", command=self._scan_columns).pack(side=tk.LEFT)
        self.enc_scan_status_var = tk.StringVar()
        ttk.Label(scan_row, textvariable=self.enc_scan_status_var, foreground="gray").pack(
            side=tk.LEFT, padx=10
        )

        # Column list with PII type selection
        col_frame = ttk.LabelFrame(enc_file_frame, text="Columns to encrypt", padding=5)
        col_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        # Scrollable listbox for columns
        list_frame = ttk.Frame(col_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL)
        self.enc_columns_listbox = tk.Listbox(
            list_frame, selectmode=tk.EXTENDED, yscrollcommand=scrollbar.set, height=5
        )
        scrollbar.config(command=self.enc_columns_listbox.yview)
        self.enc_columns_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # PII type for selected columns
        type_row = ttk.Frame(col_frame)
        type_row.pack(fill=tk.X, pady=(5, 0))
        ttk.Label(type_row, text="PII type for selected:").pack(side=tk.LEFT)
        self.enc_col_type_var = tk.StringVar(value="name")
        ttk.Combobox(
            type_row,
            textvariable=self.enc_col_type_var,
            width=12,
            values=PII_TYPES,
            state="readonly",
        ).pack(side=tk.LEFT, padx=5)
        ttk.Button(type_row, text="Set Type", command=self._set_column_types).pack(
            side=tk.LEFT, padx=5
        )

        # Format selection
        fmt_row = ttk.Frame(enc_file_frame)
        fmt_row.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(fmt_row, text="Format:").pack(side=tk.LEFT)
        self.enc_format_var = tk.StringVar(value="encrypted")
        ttk.Radiobutton(
            fmt_row, text="Encrypted", variable=self.enc_format_var, value="encrypted"
        ).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(
            fmt_row, text="Readable", variable=self.enc_format_var, value="readable"
        ).pack(side=tk.LEFT, padx=5)

        # Output file
        output_row = ttk.Frame(enc_file_frame)
        output_row.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(output_row, text="Output file:").pack(side=tk.LEFT)
        self.enc_file_output_var = tk.StringVar()
        ttk.Entry(output_row, textvariable=self.enc_file_output_var, width=40).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=5
        )
        ttk.Button(output_row, text="Browse...", command=self._browse_enc_output).pack(
            side=tk.LEFT
        )

        # Key file output
        key_row = ttk.Frame(enc_file_frame)
        key_row.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(key_row, text="Key file:").pack(side=tk.LEFT)
        self.enc_key_output_var = tk.StringVar()
        ttk.Entry(key_row, textvariable=self.enc_key_output_var, width=40).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=5
        )
        ttk.Button(key_row, text="Browse...", command=self._browse_enc_key_output).pack(
            side=tk.LEFT
        )

        # Encrypt button
        ttk.Button(enc_file_frame, text="Encrypt File", command=self._encrypt_file).pack(pady=5)

        # Status
        self.enc_file_status_var = tk.StringVar()
        ttk.Label(enc_file_frame, textvariable=self.enc_file_status_var, wraplength=600).pack(
            anchor=tk.W, pady=5
        )

    # ── Browse helpers ────────────────────────────────────────────

    def _browse_key(self):
        path = filedialog.askopenfilename(
            title="Select key file",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if path:
            self.key_path_var.set(path)

    def _browse_input(self):
        path = filedialog.askopenfilename(
            title="Select pseudonymized file",
            filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")],
        )
        if path:
            self.file_input_var.set(path)
            if not self.file_output_var.get():
                base, ext = os.path.splitext(path)
                self.file_output_var.set(f"{base}_decoded{ext}")

    def _browse_output(self):
        path = filedialog.asksaveasfilename(
            title="Save decoded file as",
            defaultextension=".xlsx",
            filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")],
        )
        if path:
            self.file_output_var.set(path)

    def _browse_enc_input(self):
        path = filedialog.askopenfilename(
            title="Select file to encrypt",
            filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")],
        )
        if path:
            self.enc_file_input_var.set(path)
            if not self.enc_file_output_var.get():
                base, ext = os.path.splitext(path)
                self.enc_file_output_var.set(f"{base}_pseudonymized{ext}")

    def _browse_enc_output(self):
        path = filedialog.asksaveasfilename(
            title="Save encrypted file as",
            defaultextension=".xlsx",
            filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")],
        )
        if path:
            self.enc_file_output_var.set(path)

    def _browse_enc_key_output(self):
        path = filedialog.asksaveasfilename(
            title="Save key file as",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if path:
            self.enc_key_output_var.set(path)

    # ── Key loading ───────────────────────────────────────────────

    def _load_key(self):
        key_path = self.key_path_var.get().strip()
        passphrase = self.passphrase_var.get()

        if not key_path:
            messagebox.showerror("Error", "Please select a key file.")
            return
        if not passphrase:
            messagebox.showerror("Error", "Please enter a passphrase.")
            return
        if not os.path.isfile(key_path):
            messagebox.showerror("Error", f"Key file not found: {key_path}")
            return

        try:
            from pii_pseudonymizer.obfuscator import Obfuscator

            self.obfuscator, self.key_data = Obfuscator.from_key_file(key_path, passphrase)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load key file:\n{e}")
            self.status_var.set("Key load failed")
            return

        # Populate column/type dropdowns from key data
        sheets = self.key_data.get("sheets", {})
        types = set()
        total_columns = 0
        self._column_type_map = {}
        self._columns_by_sheet = {}
        for sheet_name, sheet_meta in sheets.items():
            for col_name, col_info in sheet_meta.get("columns", {}).items():
                if col_info.get("obfuscated"):
                    pii_type = col_info.get("pii_type", "generic")
                    self._columns_by_sheet.setdefault(sheet_name, []).append(col_name)
                    types.add(pii_type)
                    self._column_type_map[(sheet_name, col_name)] = pii_type
                    total_columns += 1

        sheet_names = sorted(self._columns_by_sheet.keys())
        self.sheet_combo["values"] = sheet_names
        self.type_combo["values"] = sorted(types)
        if sheet_names:
            self.sheet_combo.current(0)
            self._on_sheet_selected()
        elif types:
            self.type_combo.current(0)

        # Bind selection updates
        self.sheet_combo.bind("<<ComboboxSelected>>", lambda _: self._on_sheet_selected())
        # Bind column selection to auto-update type
        self.column_combo.bind("<<ComboboxSelected>>", lambda _: self._on_column_selected())

        file_format = self.key_data.get("format", "encrypted")
        self.status_var.set(
            f"Key loaded: {len(sheets)} sheet(s), {total_columns} column(s), format={file_format}"
        )

    def _on_sheet_selected(self):
        """Update available columns when a sheet is selected."""
        sheet = self.sheet_var.get()
        columns = sorted(set(self._columns_by_sheet.get(sheet, [])))
        self.column_combo["values"] = columns
        if columns:
            self.column_combo.current(0)
            self._on_column_selected()
        else:
            self.column_var.set("")

    def _on_column_selected(self):
        """Auto-select the PII type when a column is chosen."""
        sheet = self.sheet_var.get()
        col = self.column_var.get()
        pii_type = self._column_type_map.get((sheet, col))
        if pii_type:
            self.type_var.set(pii_type)

    # ── Decrypt operations ────────────────────────────────────────

    def _ensure_key_loaded(self):
        """Auto-load the key if path and passphrase are filled but key isn't loaded yet."""
        if self.obfuscator:
            return True
        if self.key_path_var.get().strip() and self.passphrase_var.get():
            self._load_key()
        if not self.obfuscator:
            messagebox.showerror("Error", "Load a key file first.")
            return False
        return True

    def _decrypt_value(self):
        if not self._ensure_key_loaded():
            return

        value = self.input_text.get("1.0", tk.END).strip()
        sheet = self.sheet_var.get().strip()
        column = self.column_var.get()
        pii_type = self.type_var.get()

        if not value:
            return
        if not sheet:
            messagebox.showerror("Error", "Select a sheet.")
            return
        if not column:
            messagebox.showerror("Error", "Select a column.")
            return
        if not pii_type:
            messagebox.showerror("Error", "Select a PII type.")
            return

        try:
            file_format = self.key_data.get("format", "encrypted")
            if file_format == "readable":
                from pii_pseudonymizer.transforms import ReadableTransformer

                transformer = ReadableTransformer(self.obfuscator.master_key[:32])
                mappings = self.key_data.get("readable_mappings", {})
                transformer.load_mappings(mappings)
                result = transformer.reverse_value(
                    value, column, pii_type, sheet_name=sheet
                )
                if str(result) == value:
                    for sname, col_name in self._column_type_map:
                        result = transformer.reverse_value(
                            value,
                            col_name,
                            self._column_type_map[(sname, col_name)],
                            sheet_name=sname,
                        )
                        if str(result) != value:
                            break
            else:
                try:
                    result = self.obfuscator.deobfuscate_value(value, column, pii_type)
                except Exception:
                    # Wrong column/type combo — try all known pairs from key file
                    result = None
                    for (_sname, col), pt in self._column_type_map.items():
                        try:
                            result = self.obfuscator.deobfuscate_value(value, col, pt)
                            break
                        except Exception:
                            continue
                    if result is None:
                        raise

            self.output_text.config(state=tk.NORMAL)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", str(result))
            self.output_text.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

    def _run_decode(self, verify_only=False):
        if not self._ensure_key_loaded():
            return

        input_path = self.file_input_var.get().strip()
        output_path = self.file_output_var.get().strip() if not verify_only else None

        if not input_path:
            messagebox.showerror("Error", "Select an input file.")
            return
        if not os.path.isfile(input_path):
            messagebox.showerror("Error", f"File not found: {input_path}")
            return

        passphrase = self.passphrase_var.get()
        key_path = self.key_path_var.get().strip()

        self.progress_var.set(0)
        self.file_status_var.set("Decoding...")
        self.root.update_idletasks()

        def progress_cb(sheet_name, sheet_idx, total_sheets):
            pct = ((sheet_idx + 1) / total_sheets) * 100
            self.progress_var.set(pct)
            self.file_status_var.set(f"Decoding sheet {sheet_idx + 1}/{total_sheets}: {sheet_name}")
            self.root.update_idletasks()

        from pii_pseudonymizer.decoder import decode_file

        result = decode_file(
            input_path,
            key_path,
            passphrase,
            output_path,
            verify_only,
            progress_cb=progress_cb,
        )

        self.progress_var.set(100)

        if result["status"] == "error":
            self.file_status_var.set(f"Error: {result['message']}")
            messagebox.showerror("Error", result["message"])
            return

        msg = (
            f"Sheets: {', '.join(result['sheets_decoded'])}\n"
            f"Rows: {result['total_rows']:,}\n"
            f"Columns: {', '.join(result['columns_decoded'])}\n"
            f"Round-trip: {'PASS' if result['round_trip_ok'] else 'FAIL'}"
        )

        if result["output_path"]:
            msg += f"\nSaved to: {result['output_path']}"
            self.file_status_var.set(f"Done. Output: {result['output_path']}")
        else:
            self.file_status_var.set("Verification complete.")

        if result["round_trip_ok"]:
            messagebox.showinfo("Success", msg)
        else:
            messagebox.showwarning("Warning", msg + "\n\nRound-trip verification failed.")

    def _decrypt_file(self):
        self._run_decode(verify_only=False)

    def _verify_file(self):
        self._run_decode(verify_only=True)

    # ── Encrypt operations ────────────────────────────────────────

    def _encrypt_value(self):
        """Encrypt a single plaintext value."""
        passphrase = self.passphrase_var.get()
        if not passphrase:
            messagebox.showerror("Error", "Please enter a passphrase.")
            return

        column = self.enc_column_var.get().strip()
        pii_type = self.enc_type_var.get()
        value = self.enc_input_text.get("1.0", tk.END).strip()

        if not value:
            return
        if not column:
            messagebox.showerror("Error", "Enter a column name.")
            return
        if not pii_type:
            messagebox.showerror("Error", "Select a PII type.")
            return

        try:
            # If a key file is loaded, use its obfuscator (same salt) for consistency.
            # Otherwise, reuse a cached obfuscator for the same passphrase so that
            # repeated encrypts are deterministic (same salt).
            if self.obfuscator:
                obf = self.obfuscator
            else:
                from pii_pseudonymizer.obfuscator import Obfuscator

                if self._enc_obfuscator is None or self._enc_passphrase != passphrase:
                    self._enc_obfuscator = Obfuscator(passphrase)
                    self._enc_passphrase = passphrase
                obf = self._enc_obfuscator

            result = obf.obfuscate_value(value, column, pii_type)

            self.enc_output_text.config(state=tk.NORMAL)
            self.enc_output_text.delete("1.0", tk.END)
            self.enc_output_text.insert("1.0", str(result))
            self.enc_output_text.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    def _scan_columns(self):
        """Read column headers from the input xlsx file."""
        input_path = self.enc_file_input_var.get().strip()
        if not input_path:
            messagebox.showerror("Error", "Select an input file first.")
            return
        if not os.path.isfile(input_path):
            messagebox.showerror("Error", f"File not found: {input_path}")
            return

        try:
            from pii_pseudonymizer.reader import read_xlsx

            metadata = read_xlsx(input_path)

            self._scanned_columns = []
            self._selected_encrypt_columns = []
            self.enc_columns_listbox.delete(0, tk.END)

            for sname in metadata["sheet_names"]:
                sheet_meta = metadata["sheets"][sname]
                for col in sheet_meta.get("columns", []):
                    entry = {
                        "name": col["name"],
                        "sheet": sname,
                        "pii_type": "generic",
                    }
                    self._scanned_columns.append(entry)
                    self.enc_columns_listbox.insert(
                        tk.END, f"[{sname}] {col['name']}"
                    )

            self.enc_scan_status_var.set(
                f"Found {len(self._scanned_columns)} column(s) "
                f"in {len(metadata['sheet_names'])} sheet(s)"
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file:\n{e}")

    def _get_scanned_columns(self):
        """Return the list of scanned column dicts."""
        return list(self._scanned_columns)

    def _select_encrypt_columns(self, columns):
        """Programmatically set which columns to encrypt (for testing and API use).

        Args:
            columns: list of dicts with 'name', 'pii_type', and optional 'sheet'
        """
        self._selected_encrypt_columns = list(columns)

        # Update PII types in the scanned columns to match.
        # If sheet is omitted, apply to matching names across all sheets.
        selected_by_sheet = {}
        selected_by_name = {}
        for col in columns:
            if col.get("sheet"):
                selected_by_sheet[(col["sheet"], col["name"])] = col["pii_type"]
            else:
                selected_by_name[col["name"]] = col["pii_type"]

        for col in self._scanned_columns:
            key = (col["sheet"], col["name"])
            if key in selected_by_sheet:
                col["pii_type"] = selected_by_sheet[key]
            elif col["name"] in selected_by_name:
                col["pii_type"] = selected_by_name[col["name"]]

    def _set_column_types(self):
        """Set the PII type for currently selected columns in the listbox."""
        pii_type = self.enc_col_type_var.get()
        selected_indices = self.enc_columns_listbox.curselection()

        if not selected_indices:
            messagebox.showinfo("Info", "Select columns in the list first.")
            return

        for idx in selected_indices:
            if idx < len(self._scanned_columns):
                self._scanned_columns[idx]["pii_type"] = pii_type
                col = self._scanned_columns[idx]
                self.enc_columns_listbox.delete(idx)
                self.enc_columns_listbox.insert(
                    idx, f"[{col['sheet']}] {col['name']} ({pii_type})"
                )

    def _get_columns_to_encrypt(self):
        """Determine which columns to encrypt.

        If _select_encrypt_columns was called (programmatic/test), use that.
        Otherwise, use selected items in the listbox.
        """
        if self._selected_encrypt_columns:
            return self._selected_encrypt_columns

        # Use listbox selection
        selected_indices = self.enc_columns_listbox.curselection()
        if not selected_indices:
            return []

        return [
            {
                "sheet": self._scanned_columns[i]["sheet"],
                "name": self._scanned_columns[i]["name"],
                "pii_type": self._scanned_columns[i]["pii_type"],
            }
            for i in selected_indices
            if i < len(self._scanned_columns)
        ]

    def _encrypt_file(self):
        """Encrypt (pseudonymize) an xlsx file."""
        passphrase = self.passphrase_var.get()
        if not passphrase:
            messagebox.showerror("Error", "Please enter a passphrase.")
            return

        input_path = self.enc_file_input_var.get().strip()
        output_path = self.enc_file_output_var.get().strip()
        key_path = self.enc_key_output_var.get().strip()

        if not input_path:
            messagebox.showerror("Error", "Select an input file.")
            return
        if not os.path.isfile(input_path):
            messagebox.showerror("Error", f"File not found: {input_path}")
            return
        if not output_path:
            messagebox.showerror("Error", "Specify an output file path.")
            return
        if not key_path:
            messagebox.showerror("Error", "Specify a key file path.")
            return

        columns_to_encrypt = self._get_columns_to_encrypt()
        if not columns_to_encrypt:
            messagebox.showerror("Error", "Select at least one column to encrypt.")
            return

        output_format = self.enc_format_var.get()

        try:
            self.enc_file_status_var.set("Encrypting...")
            self.root.update_idletasks()

            from pii_pseudonymizer.obfuscator import Obfuscator
            from pii_pseudonymizer.reader import read_xlsx, transform_workbook

            obfuscator = Obfuscator(passphrase)

            readable_transformer = None
            if output_format == "readable":
                from pii_pseudonymizer.transforms import ReadableTransformer

                readable_transformer = ReadableTransformer(obfuscator.master_key[:32])

            metadata = read_xlsx(input_path)
            # Build per-sheet mapping with sheet-scoped identity.
            selected_by_sheet = {}
            selected_by_name = {}
            for col in columns_to_encrypt:
                if col.get("sheet"):
                    selected_by_sheet[(col["sheet"], col["name"])] = col["pii_type"]
                else:
                    selected_by_name[col["name"]] = col["pii_type"]

            sheets_columns = {}
            for sname in metadata["sheet_names"]:
                headers = metadata["sheets"][sname].get("headers", [])
                sheet_map = {}
                for header in headers:
                    key = (sname, header)
                    if key in selected_by_sheet:
                        sheet_map[header] = selected_by_sheet[key]
                    elif header in selected_by_name:
                        sheet_map[header] = selected_by_name[header]
                if sheet_map:
                    sheets_columns[sname] = [
                        {"name": name, "pii_type": pii_type}
                        for name, pii_type in sheet_map.items()
                    ]

            if not sheets_columns:
                messagebox.showerror(
                    "Error", "None of the selected columns were found in the file."
                )
                return

            def _transform_cell(value, column_name, pii_type, sheet_name):
                if readable_transformer:
                    return readable_transformer.transform_value(
                        value,
                        column_name,
                        pii_type,
                        sheet_name=sheet_name,
                    )
                return obfuscator.obfuscate_value(value, column_name, pii_type)

            stats = transform_workbook(
                input_path,
                output_path,
                sheets_columns,
                _transform_cell,
            )

            readable_mappings = (
                readable_transformer.get_mappings() if readable_transformer else None
            )
            obfuscator.save_key_file(
                key_path,
                os.path.basename(input_path),
                sheets_columns,
                output_format=output_format,
                readable_mappings=readable_mappings,
            )

            total_rows = sum(metadata["sheets"][s]["row_count"] for s in sheets_columns)
            total_cols = sum(len(cols) for cols in sheets_columns.values())
            self.enc_file_status_var.set(
                f"Done. {total_rows} rows, {total_cols} column(s) encrypted, "
                f"{stats['transformed_cells']} cell(s) transformed. "
                f"Output: {output_path}"
            )
            messagebox.showinfo(
                "Success",
                f"File encrypted successfully.\n\n"
                f"Output: {output_path}\n"
                f"Key file: {key_path}\n\n"
                f"Keep your key file and passphrase safe!",
            )
        except Exception as e:
            self.enc_file_status_var.set(f"Error: {e}")
            messagebox.showerror("Encryption Error", str(e))


def main():
    root = tk.Tk()
    DecryptGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
