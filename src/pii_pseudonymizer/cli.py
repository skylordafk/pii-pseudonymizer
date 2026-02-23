"""CLI entry point — detect and pseudonymize sensitive data in Excel files."""

import argparse
import getpass
import os
import random
import socket
import sys
from datetime import datetime

from pii_pseudonymizer.config import Config
from pii_pseudonymizer.decoder import decode_file
from pii_pseudonymizer.detector import PIIDetector
from pii_pseudonymizer.obfuscator import Obfuscator
from pii_pseudonymizer.ollama_client import OllamaClient
from pii_pseudonymizer.reader import read_all_rows, read_xlsx, write_xlsx
from pii_pseudonymizer.tui import confirm_columns_tui


def print_header():
    print()
    print("=" * 60)
    print("  PII Pseudonymizer")
    print("  Detect and reversibly pseudonymize sensitive data in Excel files")
    print("=" * 60)
    print()


def print_step(num, total, message):
    print(f"[{num}/{total}] {message}")


def print_table(results, sheet_name=None):
    """Print detection results as a formatted table."""
    if sheet_name:
        print(f"\n  --- Sheet: {sheet_name} ---")

    if not results:
        print("  (no columns)")
        return

    num_w = 3
    name_w = max(len(r["name"]) for r in results)
    name_w = min(max(name_w, 10), 30)
    type_w = 10
    conf_w = 10
    src_w = 10
    act_w = 10

    header = (
        f"  {'#':<{num_w}}  "
        f"{'Column Name':<{name_w}}  "
        f"{'PII Type':<{type_w}}  "
        f"{'Confidence':<{conf_w}}  "
        f"{'Source':<{src_w}}  "
        f"{'Action':<{act_w}}"
    )
    separator = "  " + "-" * (len(header) - 2)

    print(header)
    print(separator)

    for i, r in enumerate(results, 1):
        conf_str = f"{r['confidence']:.2f}" if r["confidence"] > 0 else "-"
        src_str = r["source"] if r["source"] != "none" else "-"
        name_display = r["name"][:name_w]
        print(
            f"  {i:<{num_w}}  "
            f"{name_display:<{name_w}}  "
            f"{r['pii_type']:<{type_w}}  "
            f"{conf_str:<{conf_w}}  "
            f"{src_str:<{src_w}}  "
            f"{r['action']:<{act_w}}"
        )
    print()


def print_formula_report(formulas):
    """Print cross-sheet formula dependencies."""
    deps = formulas.get("sheet_dependencies", {})
    has_deps = any(refs for refs in deps.values())

    if not has_deps:
        print("  No cross-sheet formula references found.")
        return

    print("  Cross-sheet formula dependencies:")
    for sheet, refs in deps.items():
        if refs:
            print(f"    {sheet} -> {', '.join(refs)}")

    refs = formulas.get("cross_sheet_refs", [])
    if refs:
        shown = refs[:10]
        print(f"\n  Sample cross-sheet formulas ({len(refs)} total):")
        for ref in shown:
            print(f"    {ref['from_sheet']}!{ref['from_cell']}: {ref['formula']}")
        if len(refs) > 10:
            print(f"    ... and {len(refs) - 10} more")

    print()
    print("  NOTE: Cross-sheet formulas link data between sheets. If a column")
    print("  on one sheet pulls values from a sensitive column on another sheet,")
    print("  both should be pseudonymized to avoid leaking data.")
    print()


def confirm_columns(all_results):
    """
    Let user adjust column classifications interactively.

    all_results: dict of sheet_name -> list of result dicts
    """
    # Build a flat numbered list for easy reference
    flat = []
    for sname, results in all_results.items():
        for r in results:
            flat.append((sname, r))

    print("  Enter a number to toggle OBFUSCATE <-> SKIP,")
    print("  '<number> <type>' to set a PII type (e.g. '3 name'),")
    print("  or 'done' to proceed, 'quit' to abort.")
    print()

    while True:
        try:
            choice = input("  > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n  Aborted.")
            sys.exit(1)

        if choice == "done" or choice == "":
            break
        if choice in ("quit", "q", "exit"):
            print("  Aborted.")
            sys.exit(0)

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(flat):
                sname, r = flat[idx]
                if r["action"] == "OBFUSCATE":
                    r["action"] = "SKIP"
                    r["pii_type"] = "none"
                    print(f"  [{sname}] '{r['name']}' -> SKIP")
                else:
                    r["action"] = "OBFUSCATE"
                    if r["pii_type"] == "none":
                        r["pii_type"] = "generic"
                    print(f"  [{sname}] '{r['name']}' -> OBFUSCATE (type: {r['pii_type']})")
            else:
                print(f"  Invalid number. Enter 1-{len(flat)}.")
        except ValueError:
            parts = choice.split(None, 1)
            if len(parts) == 2:
                try:
                    idx = int(parts[0]) - 1
                    pii_type = parts[1].strip()
                    valid_types = [
                        "name",
                        "email",
                        "phone",
                        "ssn",
                        "address",
                        "dob",
                        "financial",
                        "generic",
                        "none",
                    ]
                    if 0 <= idx < len(flat) and pii_type in valid_types:
                        sname, r = flat[idx]
                        r["pii_type"] = pii_type
                        r["action"] = "OBFUSCATE" if pii_type != "none" else "SKIP"
                        print(f"  [{sname}] '{r['name']}' -> {r['action']} (type: {pii_type})")
                    else:
                        print(f"  Usage: <number> <type>  (types: {', '.join(valid_types)})")
                except ValueError:
                    print("  Enter a column number, 'done', or 'quit'.")
            else:
                print("  Enter a column number, 'done', or 'quit'.")

    return all_results


def get_passphrase(passphrase_fd=None):
    """Get passphrase from user with confirmation, or from file descriptor."""
    # Check environment variable first
    env_passphrase = os.environ.get("PII_PASSPHRASE")
    if env_passphrase:
        # Clear from environment immediately
        del os.environ["PII_PASSPHRASE"]
        return env_passphrase

    # Read from file descriptor if specified
    if passphrase_fd is not None:
        try:
            with os.fdopen(passphrase_fd, "r", closefd=False) as f:
                return f.readline().rstrip("\n")
        except OSError as e:
            print(f"  Error reading passphrase from fd {passphrase_fd}: {e}")
            sys.exit(1)

    # Interactive input
    while True:
        try:
            p1 = getpass.getpass("  Enter passphrase: ")
            if len(p1) < 4:
                print("  Passphrase too short (minimum 4 characters). Try again.")
                continue
            p2 = getpass.getpass("  Confirm passphrase: ")
            if p1 != p2:
                print("  Passphrases don't match. Try again.")
                continue
            return p1
        except (EOFError, KeyboardInterrupt):
            print("\n  Aborted.")
            sys.exit(1)


def check_network_connectivity():
    """Check if network is available. Returns True if connected."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect(("1.1.1.1", 443))
        sock.close()
        return True
    except (OSError, TimeoutError):
        return False


def _search_cells(input_path, term):
    """Search all cells in a file for a term. Returns (all_sheets, found_list)."""
    all_sheets = read_all_rows(input_path)
    found = []
    for sname, (_headers, rows) in all_sheets.items():
        for row_idx, row in enumerate(rows, 2):  # row 2 = first data row
            for col_name, value in row.items():
                if value is not None and term.lower() in str(value).lower():
                    found.append(
                        {
                            "sheet": sname,
                            "row": row_idx,
                            "row_index": row_idx - 2,  # 0-based index into data rows
                            "column": col_name,
                            "value": str(value),
                        }
                    )
    return all_sheets, found


def run_interactive_approval(all_results, detector):
    """In thorough mode, show LLM reasoning and let user approve/deny each LLM result.

    Approved classifications are fed back into the detector's context for
    cross-column learning.
    """
    llm_columns = []
    for sname, results in all_results.items():
        for r in results:
            if r["source"] in ("llm", "both") and r["action"] == "OBFUSCATE":
                llm_columns.append((sname, r))

    if not llm_columns:
        return

    print("\n  Interactive approval for LLM-classified columns:")
    print("  For each column, type 'y' to approve, 'n' to deny, or 's' to skip.\n")

    for sname, r in llm_columns:
        # Show reasoning from evidence
        reasoning = ""
        for ev in r.get("evidence", []):
            if ev.startswith("LLM:"):
                reasoning = ev[4:].strip()
                break

        print(f"  [{sname}] {r['name']}")
        print(f"    Type: {r['pii_type']}  Confidence: {r['confidence']:.2f}")
        if reasoning:
            print(f"    Reasoning: {reasoning}")

        try:
            choice = input("    Approve? [Y/n/s] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n  Skipping remaining approvals.")
            break

        if choice == "n":
            r["action"] = "SKIP"
            r["pii_type"] = "none"
            print("    -> Denied (set to SKIP)")
        elif choice == "s":
            print("    -> Skipped")
        else:
            # Approved (default)
            detector.add_approved_context(r["name"], r["pii_type"], r["confidence"])
            print("    -> Approved")

    print()


def run_search(args):
    """Search all cells in a file for a term."""
    input_path = args.input
    term = args.search

    if not os.path.exists(input_path):
        print(f"  Error: File not found: {input_path}")
        sys.exit(1)

    print(f"\n  Searching for '{term}' in {os.path.basename(input_path)}...")
    _all_sheets, found = _search_cells(input_path, term)

    if not found:
        print(f"  No occurrences of '{term}' found.")
    else:
        print(f"\n  Found {len(found)} occurrence(s):\n")
        for f in found[:100]:
            print(f"    {f['sheet']}!{f['column']}:{f['row']}  ->  {f['value']}")
        if len(found) > 100:
            print(f"    ... and {len(found) - 100} more")
    print()


def run_ctrlf_pseudonymize(args, config):
    """Ctrl+F pseudonymization: find a term and pseudonymize matching cells."""
    input_path = args.input
    term = args.pseudonymize_term

    if not os.path.exists(input_path):
        print(f"  Error: File not found: {input_path}")
        sys.exit(1)

    # Network check
    if not args.allow_online and check_network_connectivity():
        print("  WARNING: Network connectivity detected.")
        print("  Use --allow-online to suppress this warning.")
        try:
            response = input("  Continue anyway? [y/N] ").strip().lower()
            if response != "y":
                sys.exit(0)
        except (EOFError, KeyboardInterrupt):
            sys.exit(1)

    print(f"\n  Searching for '{term}' in {os.path.basename(input_path)}...")
    all_sheets, found = _search_cells(input_path, term)

    if not found:
        print(f"  No occurrences of '{term}' found. Nothing to do.")
        return

    # Display matches
    print(f"\n  Found {len(found)} occurrence(s):\n")
    for f in found[:100]:
        print(f"    {f['sheet']}!{f['column']}:{f['row']}  ->  {f['value']}")
    if len(found) > 100:
        print(f"    ... and {len(found) - 100} more")

    # Summarize by column
    col_summary = {}
    for f in found:
        key = (f["sheet"], f["column"])
        col_summary[key] = col_summary.get(key, 0) + 1
    print("\n  Affected columns:")
    for (sname, col_name), count in sorted(col_summary.items()):
        print(f"    {sname}.{col_name}: {count} cell(s)")

    # Confirm
    print()
    try:
        response = input("  Pseudonymize these cells? [y/N] ").strip().lower()
        if response != "y":
            print("  Aborted.")
            return
    except (EOFError, KeyboardInterrupt):
        print("\n  Aborted.")
        return

    # Get PII type
    print(
        "\n  PII type for matched cells "
        "(name, email, phone, ssn, address, dob, generic) [generic]: ",
        end="",
    )
    try:
        pii_type = input().strip().lower() or "generic"
    except (EOFError, KeyboardInterrupt):
        pii_type = "generic"

    # Get passphrase
    print()
    passphrase = get_passphrase(args.passphrase_fd)

    output_format = args.output_format
    obfuscator = Obfuscator(passphrase)

    readable_transformer = None
    if output_format == "readable":
        from pii_pseudonymizer.transforms import ReadableTransformer

        readable_transformer = ReadableTransformer(obfuscator.master_key[:32])

    # Build set of (sheet, row_index, column) to pseudonymize
    cells_to_pseudonymize = set()
    for f in found:
        cells_to_pseudonymize.add((f["sheet"], f["row_index"], f["column"]))

    # Build sheets_columns for key file (unique columns that were affected)
    sheets_columns = {}
    for sname, col_name in sorted(col_summary.keys()):
        if sname not in sheets_columns:
            sheets_columns[sname] = []
        sheets_columns[sname].append({"name": col_name, "pii_type": pii_type})

    # Pseudonymize only matching cells
    print("\n  Pseudonymizing...")
    output_sheets = {}
    total_cells = 0
    for sname, (headers, rows) in all_sheets.items():
        new_rows = []
        for row_idx, row in enumerate(rows):
            new_row = dict(row)
            for col_name in headers:
                if (sname, row_idx, col_name) in cells_to_pseudonymize:
                    val = new_row.get(col_name)
                    if val is not None:
                        if readable_transformer:
                            new_row[col_name] = readable_transformer.transform_value(
                                val, col_name, pii_type
                            )
                        else:
                            new_row[col_name] = obfuscator.obfuscate_value(val, col_name, pii_type)
                        total_cells += 1
            new_rows.append(new_row)
        output_sheets[sname] = (headers, new_rows)

    # Output paths
    if args.output:
        output_path = args.output
    else:
        base = os.path.basename(input_path)
        name, ext = os.path.splitext(base)
        output_path = os.path.join(config.output_directory, f"{name}_pseudonymized{ext}")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    key_path = args.keyfile or os.path.join(config.keys_directory, f"key_{timestamp}.json")

    write_xlsx(output_path, output_sheets)
    readable_mappings = readable_transformer.get_mappings() if readable_transformer else None
    obfuscator.save_key_file(
        key_path,
        os.path.basename(input_path),
        sheets_columns,
        output_format=output_format,
        readable_mappings=readable_mappings,
    )

    print(f"  Pseudonymized {total_cells} cell(s)")
    print(f"  Output: {output_path}")
    print(f"  Key file: {key_path}")
    print()


def run_obfuscate(args, config):
    """Main pseudonymization workflow."""
    input_path = args.input
    total_steps = 6

    if not os.path.exists(input_path):
        print(f"  Error: File not found: {input_path}")
        sys.exit(1)

    # Network isolation check
    if not args.allow_online and check_network_connectivity():
        print("  WARNING: Network connectivity detected.")
        print("  For maximum security, disconnect from the network before pseudonymizing.")
        print("  Use --allow-online to suppress this warning.")
        print()
        try:
            response = input("  Continue anyway? [y/N] ").strip().lower()
            if response != "y":
                print("  Aborted. Disconnect from network and try again.")
                sys.exit(0)
        except (EOFError, KeyboardInterrupt):
            print("\n  Aborted.")
            sys.exit(1)

    # Step 1: Read file (all sheets)
    print_step(1, total_steps, "Reading file...")
    try:
        metadata = read_xlsx(input_path)
    except Exception as e:
        print(f"  Error reading file: {e}")
        sys.exit(1)

    sheet_names = metadata["sheet_names"]
    print(f"  File: {os.path.basename(input_path)}")
    print(f"  Sheets: {len(sheet_names)}")
    total_rows = 0
    total_cols = 0
    for sname in sheet_names:
        s = metadata["sheets"][sname]
        total_rows += s["row_count"]
        total_cols += len(s["columns"])
        print(f"    {sname}: {s['row_count']:,} rows, {len(s['columns'])} columns")
    print(f"  Total: {total_rows:,} rows, {total_cols} columns")
    print()

    # Report formula dependencies
    formulas = metadata.get("formulas", {})
    formula_cols = formulas.get("formula_columns", {})
    has_formulas = any(cols for cols in formula_cols.values())
    has_cross_refs = any(refs for refs in formulas.get("sheet_dependencies", {}).values())

    if has_formulas:
        print("  Formula analysis:")
        for sname in sheet_names:
            fcols = formula_cols.get(sname, {})
            if fcols:
                col_list = ", ".join(f"{c} ({n})" for c, n in fcols.items())
                print(f"    {sname}: formulas in [{col_list}]")
        print()

    if has_cross_refs:
        print_formula_report(formulas)

    # Step 2: Detect PII (all sheets)
    print_step(2, total_steps, "Analyzing columns for sensitive data...")

    # Try to connect to Ollama
    ollama = None
    if not args.no_llm:
        model = args.model or config.default_model
        client = OllamaClient(
            base_url=config.ollama_url,
            model=model,
        )
        healthy, msg = client.health_check()
        if healthy:
            ollama = client
            print(f"  Ollama connected (model: {model})")
            print("  Warming up model (first call may take a moment)...")
            try:
                client.chat(
                    [{"role": "user", "content": "Reply OK"}],
                    temperature=0,
                    timeout=config.timeout_seconds,
                )
                print("  Model ready.")
            except Exception:
                print("  Model warm-up timed out, but will continue.")
        else:
            print(f"  Ollama not available: {msg}")
            print("  Continuing with heuristics only.")
    else:
        print("  Skipping LLM analysis (--no-llm flag)")

    # Load allowlist/denylist
    lists = Config.load_lists(args.lists)
    if lists["always_pii"] or lists["never_pii"]:
        print(
            f"  Loaded lists: {len(lists['always_pii'])} always-PII, "
            f"{len(lists['never_pii'])} never-PII"
        )

    detector = PIIDetector(ollama_client=ollama, thorough=args.thorough, lists=lists)

    # Run detection per sheet
    all_results = {}
    for sname in sheet_names:
        sheet_meta = metadata["sheets"][sname]
        if not sheet_meta["columns"]:
            continue
        # Build a per-sheet metadata dict matching the format detector expects
        per_sheet_meta = {
            "columns": sheet_meta["columns"],
        }
        results = detector.detect(per_sheet_meta)
        all_results[sname] = results

    # Count categories across all sheets
    total_obfuscate = 0
    total_heuristic = 0
    total_llm = 0
    for _sname, results in all_results.items():
        total_obfuscate += sum(1 for r in results if r["action"] == "OBFUSCATE")
        total_heuristic += sum(
            1 for r in results if r["source"] == "heuristic" and r["action"] == "OBFUSCATE"
        )
        total_llm += sum(
            1 for r in results if r["source"] in ("llm", "both") and r["action"] == "OBFUSCATE"
        )

    print()
    print(f"  Detected {total_obfuscate} sensitive column(s) across {len(all_results)} sheet(s)")
    print(f"    Heuristic matches: {total_heuristic}")
    if total_llm:
        print(f"    LLM classifications: {total_llm}")
    print()

    # Step 3: Show results and confirm
    print_step(3, total_steps, "Detection results:")

    # In thorough mode, run interactive approval for LLM results
    if args.thorough and total_llm:
        run_interactive_approval(all_results, detector)

    # Collect sample values for TUI display
    column_samples = {}
    for sname in sheet_names:
        for col in metadata["sheets"][sname].get("columns", []):
            column_samples[col["name"]] = col.get("samples", [])[:3]

    all_results = confirm_columns_tui(all_results, column_samples)

    # Build per-sheet columns to obfuscate (with exclusions)
    sheets_columns = {}
    sheets_exclusions = {}  # sheet_name -> {col_name: set of excluded values}
    any_to_obfuscate = False
    for sname, results in all_results.items():
        cols = []
        col_exclusions = {}
        for r in results:
            if r["action"] == "OBFUSCATE":
                cols.append({"name": r["name"], "pii_type": r["pii_type"]})
                excl = r.get("exclusions", set())
                if excl:
                    col_exclusions[r["name"]] = excl
        if cols:
            sheets_columns[sname] = cols
            if col_exclusions:
                sheets_exclusions[sname] = col_exclusions
            any_to_obfuscate = True

    if not any_to_obfuscate:
        print("\n  No columns selected for pseudonymization. Nothing to do.")
        sys.exit(0)

    total_cols_obf = sum(len(c) for c in sheets_columns.values())
    print(
        f"\n  Will pseudonymize {total_cols_obf} column(s) across {len(sheets_columns)} sheet(s):"
    )
    for sname, cols in sheets_columns.items():
        print(f"    {sname}: {', '.join(c['name'] + ' (' + c['pii_type'] + ')' for c in cols)}")
    print()

    # Step 4: Get passphrase
    print_step(4, total_steps, "Set encryption passphrase:")
    passphrase = get_passphrase(args.passphrase_fd)
    print()

    # Step 5: Obfuscate (all sheets)
    print_step(5, total_steps, "Pseudonymizing...")

    all_sheets_data = read_all_rows(input_path)
    obfuscator = Obfuscator(passphrase)
    output_format = args.output_format

    # Set up transformer based on format
    readable_transformer = None
    if output_format == "readable":
        from pii_pseudonymizer.transforms import ReadableTransformer

        readable_transformer = ReadableTransformer(obfuscator.master_key[:32])

    obfuscated_sheets = {}
    total_processed = 0
    for sname in metadata["sheet_names"]:
        if sname not in all_sheets_data:
            continue
        headers, rows = all_sheets_data[sname]
        if sname in sheets_columns:
            if readable_transformer:
                obf_rows = readable_transformer.transform_rows(headers, rows, sheets_columns[sname])
            else:
                obf_rows = obfuscator.obfuscate_rows(headers, rows, sheets_columns[sname])

            # Apply cell-level exclusions: restore original values for excluded cells
            col_exclusions = sheets_exclusions.get(sname, {})
            if col_exclusions:
                excluded_count = 0
                for orig_row, obf_row in zip(rows, obf_rows, strict=True):
                    for col_name, excl_values in col_exclusions.items():
                        orig_val = orig_row.get(col_name)
                        if orig_val is not None and str(orig_val).strip() in excl_values:
                            obf_row[col_name] = orig_val
                            excluded_count += 1
                if excluded_count:
                    print(f"    {sname}: {excluded_count} cell(s) excluded from obfuscation")

            obfuscated_sheets[sname] = (headers, obf_rows)
            total_processed += len(rows)
            print(f"    {sname}: {len(rows):,} rows, {len(sheets_columns[sname])} column(s)")
        else:
            # Pass through unchanged
            obfuscated_sheets[sname] = (headers, rows)

    # Determine output paths
    if args.output:
        output_path = args.output
    else:
        base = os.path.basename(input_path)
        name, ext = os.path.splitext(base)
        output_dir = config.output_directory
        output_path = os.path.join(output_dir, f"{name}_pseudonymized{ext}")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if args.keyfile:
        key_path = args.keyfile
    else:
        key_path = os.path.join(config.keys_directory, f"key_{timestamp}.json")

    # Warn if key path is inside working directory
    key_abs = os.path.abspath(key_path)
    cwd_abs = os.path.abspath(".")
    if key_abs.startswith(cwd_abs):
        print("  WARNING: Key file is stored inside the working directory.")
        print("  An AI agent with file access could read this. Consider using")
        print(f"  --keyfile with a path outside the project (default: {config.keys_directory})")
        print()

    # Write output (all sheets)
    write_xlsx(output_path, obfuscated_sheets)
    readable_mappings = readable_transformer.get_mappings() if readable_transformer else None
    # Convert exclusion sets to lists for JSON serialization
    serializable_exclusions = {
        sname: {col: sorted(vals) for col, vals in cols.items()}
        for sname, cols in sheets_exclusions.items()
    }
    obfuscator.save_key_file(
        key_path,
        os.path.basename(input_path),
        sheets_columns,
        output_format=output_format,
        readable_mappings=readable_mappings,
        exclusions=serializable_exclusions if serializable_exclusions else None,
    )

    print(f"\n  Processed {total_processed:,} rows across {len(sheets_columns)} sheet(s)")
    print(f"  Output: {output_path}")
    print(f"  Key file: {key_path}")
    print()

    # Step 6: Verify
    print_step(6, total_steps, "Verification...")

    all_ok = True
    for sname in sheets_columns:
        if sname not in all_sheets_data or sname not in obfuscated_sheets:
            continue
        _orig_headers, orig_rows = all_sheets_data[sname]
        _, obf_rows = obfuscated_sheets[sname]
        cols = sheets_columns[sname]
        col_exclusions = sheets_exclusions.get(sname, {})

        sample_size = min(50, len(orig_rows))
        indices = (
            random.sample(range(len(orig_rows)), sample_size)
            if len(orig_rows) > sample_size
            else range(len(orig_rows))
        )

        for idx in indices:
            for col in cols:
                col_name = col["name"]
                pii_type = col["pii_type"]
                original = orig_rows[idx].get(col_name)
                obfuscated = obf_rows[idx].get(col_name)

                if original is None or str(original).strip() == "":
                    continue

                # Skip verification for excluded cells
                excl_values = col_exclusions.get(col_name, set())
                if str(original).strip() in excl_values:
                    continue

                if readable_transformer:
                    # For readable mode, verify the mapping reverses correctly
                    reversed_val = readable_transformer.reverse_value(
                        obfuscated, col_name, pii_type
                    )
                    if str(reversed_val) != str(original).strip():
                        all_ok = False
                        break
                else:
                    re_obfuscated = obfuscator.obfuscate_value(original, col_name, pii_type)
                    if str(re_obfuscated) != str(obfuscated):
                        all_ok = False
                        break

                    decoded = obfuscator.deobfuscate_value(obfuscated, col_name, pii_type)
                    if str(decoded) != str(original).strip():
                        all_ok = False
                        break

    if all_ok:
        print(
            "  Verified random samples from each sheet: "
            "all values are deterministic and reversible."
        )
    else:
        print("  WARNING: Verification found mismatches! Check the output carefully.")

    print()
    print("  Done. Keep your key file and passphrase safe — you need both to decode.")
    print(f"  To decode: pii-pseudonymizer --decode {output_path} --keyfile {key_path}")
    print()


def run_decode(args):
    """Decode workflow."""
    if not args.keyfile:
        print("  Error: --keyfile is required for decode mode.")
        sys.exit(1)

    # Get passphrase
    env_passphrase = os.environ.get("PII_PASSPHRASE")
    if env_passphrase:
        passphrase = env_passphrase
        del os.environ["PII_PASSPHRASE"]
    elif args.passphrase_fd is not None:
        try:
            with os.fdopen(args.passphrase_fd, "r", closefd=False) as f:
                passphrase = f.readline().rstrip("\n")
        except OSError as e:
            print(f"  Error reading passphrase from fd {args.passphrase_fd}: {e}")
            sys.exit(1)
    else:
        passphrase = getpass.getpass("  Enter passphrase: ")

    def _decode_progress(sheet_name, sheet_idx, total_sheets):
        sys.stdout.write(f"\r  Decoding sheet {sheet_idx + 1}/{total_sheets}: {sheet_name}...  ")
        sys.stdout.flush()

    print()
    print("  Decoding...")

    result = decode_file(
        args.input,
        args.keyfile,
        passphrase,
        args.output,
        args.verify_only,
        progress_cb=_decode_progress,
    )
    # Clear progress line
    sys.stdout.write("\r" + " " * 60 + "\r")
    sys.stdout.flush()

    if result["status"] == "error":
        print(f"\n  Error: {result['message']}")
        sys.exit(1)

    print(f"  Sheets decoded: {', '.join(result['sheets_decoded'])}")
    print(f"  Total rows: {result['total_rows']:,}")
    print(f"  Columns decoded: {', '.join(result['columns_decoded'])}")
    print(f"  Round-trip verification: {'PASS' if result['round_trip_ok'] else 'FAIL'}")

    if result["output_path"]:
        print(f"  Output saved to: {result['output_path']}")
    elif args.verify_only:
        print("  Verification-only mode: no output file written.")

    if not result["round_trip_ok"]:
        print("\n  WARNING: Round-trip verification failed on some values.")

    print()


def run_decrypt_value(args):
    """Decrypt a single pseudonymized value."""
    if not args.keyfile:
        print("  Error: --keyfile is required.")
        sys.exit(1)
    if not args.column:
        print("  Error: --column is required for decrypt-value.")
        sys.exit(1)
    if not args.pii_type:
        print("  Error: --pii-type is required for decrypt-value.")
        sys.exit(1)

    # Get passphrase
    env_passphrase = os.environ.get("PII_PASSPHRASE")
    if env_passphrase:
        passphrase = env_passphrase
        del os.environ["PII_PASSPHRASE"]
    elif args.passphrase_fd is not None:
        try:
            with os.fdopen(args.passphrase_fd, "r", closefd=False) as f:
                passphrase = f.readline().rstrip("\n")
        except OSError as e:
            print(f"  Error reading passphrase from fd {args.passphrase_fd}: {e}")
            sys.exit(1)
    else:
        passphrase = getpass.getpass("  Enter passphrase: ")

    try:
        obfuscator, _ = Obfuscator.from_key_file(args.keyfile, passphrase)
    except Exception as e:
        print(f"  Error: {e}")
        sys.exit(1)

    result = obfuscator.deobfuscate_value(args.value, args.column, args.pii_type)
    print(result)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "PII Pseudonymizer — detect and reversibly pseudonymize sensitive data in Excel files"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Pseudonymize:
    pii-pseudonymizer data.xlsx
    pii-pseudonymizer data.xlsx --output output/safe.xlsx --model mistral:7b
    pii-pseudonymizer data.xlsx --no-llm          # heuristics only, no Ollama needed

  Decode:
    pii-pseudonymizer --decode output/data_pseudonymized.xlsx --keyfile keys/key_20260222.json
    pii-pseudonymizer --decode output/data_pseudonymized.xlsx --keyfile key.json --verify-only

  Search for a term:
    pii-pseudonymizer data.xlsx --search "John Smith"

  Ctrl+F pseudonymize (find and pseudonymize matching cells):
    pii-pseudonymizer data.xlsx --pseudonymize-term "John Smith"

  Decrypt a single value:
    pii-pseudonymizer decrypt-value "[NAME:base64...]" --keyfile key.json \\
        --column first_name --pii-type name
""",
    )

    subparsers = parser.add_subparsers(dest="command")

    # decrypt-value subcommand
    dv_parser = subparsers.add_parser(
        "decrypt-value",
        help="Decrypt a single pseudonymized value",
    )
    dv_parser.add_argument("value", help="The pseudonymized value (e.g. [NAME:base64...])")
    dv_parser.add_argument("--keyfile", "-k", required=True, help="Key file path (.json)")
    dv_parser.add_argument("--column", required=True, help="Column name")
    dv_parser.add_argument("--pii-type", required=True, help="PII type (name, email, etc.)")
    dv_parser.add_argument(
        "--passphrase-fd",
        type=int,
        default=None,
        help="Read passphrase from this file descriptor",
    )

    # Main arguments (for non-subcommand usage)
    parser.add_argument("input", nargs="?", help="Path to .xlsx file")
    parser.add_argument("--output", "-o", help="Output file path")
    parser.add_argument("--keyfile", "-k", help="Key file path (.json)")
    parser.add_argument(
        "--model",
        "-m",
        default=None,
        help="Ollama model name (default from config)",
    )
    parser.add_argument(
        "--decode",
        "-d",
        action="store_true",
        help="Decode mode: reverse pseudonymization",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="With --decode: only verify, don't write output",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM analysis, use heuristics only",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Path to config.json",
    )
    parser.add_argument(
        "--passphrase-fd",
        type=int,
        default=None,
        help="Read passphrase from this file descriptor (like GnuPG)",
    )
    parser.add_argument(
        "--allow-online",
        action="store_true",
        help="Suppress network connectivity warning",
    )
    parser.add_argument(
        "--search",
        default=None,
        help="Search all cells for a term (no pseudonymization)",
    )
    parser.add_argument(
        "--format",
        choices=["encrypted", "readable"],
        default="encrypted",
        dest="output_format",
        help="Pseudonymization format (default: encrypted)",
    )
    parser.add_argument(
        "--pseudonymize-term",
        default=None,
        help="Find a term and pseudonymize all matching cells (Ctrl+F mode)",
    )
    parser.add_argument(
        "--thorough",
        action="store_true",
        help="Thorough LLM analysis: analyze each column individually with progress",
    )
    parser.add_argument(
        "--lists",
        default=None,
        help="Path to allowlist/denylist JSON file",
    )

    args = parser.parse_args()

    # Handle decrypt-value subcommand
    if args.command == "decrypt-value":
        run_decrypt_value(args)
        return

    if not args.input:
        parser.print_help()
        sys.exit(1)

    config = Config.load(args.config)

    print_header()

    # Search mode
    if args.search:
        run_search(args)
        return

    # Ctrl+F pseudonymization mode
    if args.pseudonymize_term:
        run_ctrlf_pseudonymize(args, config)
        return

    if args.decode:
        run_decode(args)
    else:
        run_obfuscate(args, config)


if __name__ == "__main__":
    main()
