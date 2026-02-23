"""Standalone tkinter GUI for decrypting pseudonymized values.

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


class DecryptGUI:
    """Lightweight GUI for decrypting single pseudonymized values or entire files."""

    def __init__(self, root):
        self.root = root
        self.root.title("PII Pseudonymizer — Decrypt")
        self.root.geometry("700x500")
        self.root.minsize(500, 400)

        self.obfuscator = None
        self.key_data = None

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
        single_frame = ttk.Frame(notebook, padding=10)
        notebook.add(single_frame, text="Single Value")

        # Column and type selection
        sel_frame = ttk.Frame(single_frame)
        sel_frame.pack(fill=tk.X, pady=(0, 5))

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

        # Input
        ttk.Label(single_frame, text="Pseudonymized value:").pack(anchor=tk.W)
        self.input_text = tk.Text(single_frame, height=3, wrap=tk.WORD)
        self.input_text.pack(fill=tk.X, pady=(0, 5))

        ttk.Button(single_frame, text="Decrypt", command=self._decrypt_value).pack(pady=5)

        # Output
        ttk.Label(single_frame, text="Decrypted:").pack(anchor=tk.W)
        self.output_text = tk.Text(single_frame, height=3, wrap=tk.WORD, state=tk.DISABLED)
        self.output_text.pack(fill=tk.X)

        # Tab 2: File decryption
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
            # Auto-fill output
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
        columns = []
        types = set()
        for sheet_meta in sheets.values():
            for col_name, col_info in sheet_meta.get("columns", {}).items():
                if col_info.get("obfuscated"):
                    columns.append(col_name)
                    types.add(col_info.get("pii_type", "generic"))

        self.column_combo["values"] = sorted(set(columns))
        self.type_combo["values"] = sorted(types)
        if columns:
            self.column_combo.current(0)
        if types:
            self.type_combo.current(0)

        file_format = self.key_data.get("format", "encrypted")
        self.status_var.set(
            f"Key loaded: {len(sheets)} sheet(s), {len(columns)} column(s), format={file_format}"
        )

    def _decrypt_value(self):
        if not self.obfuscator:
            messagebox.showerror("Error", "Load a key file first.")
            return

        value = self.input_text.get("1.0", tk.END).strip()
        column = self.column_var.get()
        pii_type = self.type_var.get()

        if not value:
            return
        if not column:
            messagebox.showerror("Error", "Select a column.")
            return
        if not pii_type:
            messagebox.showerror("Error", "Select a PII type.")
            return

        try:
            # Check if readable format
            file_format = self.key_data.get("format", "encrypted")
            if file_format == "readable":
                from pii_pseudonymizer.transforms import ReadableTransformer

                transformer = ReadableTransformer(self.obfuscator.master_key[:32])
                mappings = self.key_data.get("readable_mappings", {})
                transformer.load_mappings(mappings)
                result = transformer.reverse_value(value, column, pii_type)
            else:
                result = self.obfuscator.deobfuscate_value(value, column, pii_type)

            self.output_text.config(state=tk.NORMAL)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", str(result))
            self.output_text.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

    def _run_decode(self, verify_only=False):
        if not self.obfuscator:
            messagebox.showerror("Error", "Load a key file first.")
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


def main():
    root = tk.Tk()
    DecryptGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
