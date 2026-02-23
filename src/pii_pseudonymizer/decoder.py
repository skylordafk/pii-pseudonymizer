"""Standalone decoder/verification tool for pseudonymized xlsx files."""

import argparse
import getpass
import sys

from pii_pseudonymizer.obfuscator import OBFUSCATED_PATTERN, Obfuscator
from pii_pseudonymizer.reader import read_all_rows, transform_workbook


def decode_file(
    input_path, key_file_path, passphrase, output_path=None, verify_only=False, progress_cb=None
):
    """
    Decode a pseudonymized xlsx file (all sheets).

    Args:
        input_path: path to pseudonymized xlsx
        key_file_path: path to key file
        passphrase: user's passphrase
        output_path: where to write decoded xlsx (None = auto-name)
        verify_only: if True, just check decryption works without writing
        progress_cb: optional callback(sheet_name, sheet_index, total_sheets)

    Returns:
        dict with status, total_rows, sheets_decoded, columns_decoded, output_path
    """
    # Load key file and create obfuscator
    try:
        obfuscator, key_data = Obfuscator.from_key_file(key_file_path, passphrase)
    except Exception as e:
        return {"status": "error", "message": f"Failed to load key file: {e}"}

    sheets_info = key_data.get("sheets", {})
    if not sheets_info:
        return {"status": "error", "message": "No sheet info found in key file"}

    # Check format and set up readable transformer if needed
    file_format = key_data.get("format", "encrypted")
    readable_transformer = None
    if file_format == "readable":
        from pii_pseudonymizer.transforms import ReadableTransformer

        readable_transformer = ReadableTransformer(obfuscator.master_key[:32])
        readable_transformer.load_mappings(key_data.get("readable_mappings", {}))

    # Read all sheets from the pseudonymized file
    all_sheets = read_all_rows(input_path)

    total_rows = 0
    all_columns_decoded = []
    sheets_decoded = []
    sheets_to_decode = {}
    sample_ok = True

    total_sheets = len(sheets_info)
    for sheet_idx, (sheet_name, sheet_meta) in enumerate(sheets_info.items()):
        if progress_cb:
            progress_cb(sheet_name, sheet_idx, total_sheets)

        columns_info = sheet_meta.get("columns", {})
        columns_to_decode = [
            {"name": name, "pii_type": info["pii_type"]}
            for name, info in columns_info.items()
            if info.get("obfuscated", False)
        ]
        if not columns_to_decode:
            continue

        if sheet_name not in all_sheets:
            continue

        sheets_to_decode[sheet_name] = columns_to_decode

        headers, rows = all_sheets[sheet_name]
        if not rows:
            continue

        # Decode
        try:
            if readable_transformer:
                decoded_rows = readable_transformer.reverse_rows(
                    headers, rows, columns_to_decode, sheet_name=sheet_name
                )
            else:
                decoded_rows = obfuscator.deobfuscate_rows(headers, rows, columns_to_decode)
        except Exception as e:
            return {
                "status": "error",
                "message": (
                    f"Decryption failed on sheet '{sheet_name}'. Wrong passphrase? Error: {e}"
                ),
            }

        # Verify a sample from this sheet
        for orig, decoded in zip(rows[:5], decoded_rows[:5], strict=True):
            for col in columns_to_decode:
                col_name = col["name"]
                if col_name not in orig or orig[col_name] is None:
                    continue

                orig_str = str(orig[col_name])
                decoded_str = str(decoded.get(col_name))

                # Plaintext passthrough (e.g. exclusions or non-token data).
                if decoded_str == orig_str:
                    continue

                if readable_transformer:
                    re_obfuscated = readable_transformer.transform_value(
                        decoded[col_name], col_name, col["pii_type"], sheet_name=sheet_name
                    )
                else:
                    if not OBFUSCATED_PATTERN.match(orig_str):
                        sample_ok = False
                        continue
                    re_obfuscated = obfuscator.obfuscate_value(
                        decoded[col_name], col_name, col["pii_type"]
                    )

                if str(re_obfuscated) != orig_str:
                    sample_ok = False

        total_rows += len(rows)
        all_columns_decoded.extend(f"{sheet_name}.{c['name']}" for c in columns_to_decode)
        sheets_decoded.append(sheet_name)

    if verify_only:
        return {
            "status": "success" if sample_ok else "warning",
            "total_rows": total_rows,
            "sheets_decoded": sheets_decoded,
            "columns_decoded": all_columns_decoded,
            "round_trip_ok": sample_ok,
            "output_path": None,
        }

    # Write output
    if not output_path:
        if input_path.endswith(".xlsx"):
            output_path = input_path.replace(".xlsx", "_decoded.xlsx")
        else:
            output_path = input_path + "_decoded.xlsx"

    def _decode_transform(value, column_name, pii_type, sheet_name):
        if readable_transformer:
            return readable_transformer.reverse_value(
                value, column_name, pii_type, sheet_name=sheet_name
            )
        return obfuscator.deobfuscate_value(value, column_name, pii_type)

    try:
        transform_workbook(
            input_path,
            output_path,
            sheets_to_decode,
            _decode_transform,
        )
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to write decoded workbook: {e}",
        }

    return {
        "status": "success",
        "total_rows": total_rows,
        "sheets_decoded": sheets_decoded,
        "columns_decoded": all_columns_decoded,
        "round_trip_ok": sample_ok,
        "output_path": output_path,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Decode a pseudonymized xlsx file using a key file and passphrase"
    )
    parser.add_argument("input", help="Path to pseudonymized .xlsx file")
    parser.add_argument("--keyfile", required=True, help="Path to key file (.json)")
    parser.add_argument("--output", help="Output path (default: input_decoded.xlsx)")
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Only verify decryption works, don't write output",
    )

    args = parser.parse_args()

    passphrase = getpass.getpass("Enter passphrase: ")

    print("\nDecoding...")
    result = decode_file(args.input, args.keyfile, passphrase, args.output, args.verify_only)

    if result["status"] == "error":
        print(f"\nError: {result['message']}")
        sys.exit(1)

    print(f"\n  Sheets decoded: {', '.join(result['sheets_decoded'])}")
    print(f"  Total rows: {result['total_rows']:,}")
    print(f"  Columns decoded: {', '.join(result['columns_decoded'])}")
    print(f"  Round-trip verification: {'PASS' if result['round_trip_ok'] else 'FAIL'}")

    if result["output_path"]:
        print(f"  Output saved to: {result['output_path']}")

    if not result["round_trip_ok"]:
        print("\n  WARNING: Round-trip verification failed on some values.")
        print("  The decoded data may not perfectly match the originals.")


if __name__ == "__main__":
    main()
