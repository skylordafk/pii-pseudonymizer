"""TUI column selector using rich for interactive column confirmation."""

from rich.console import Console
from rich.table import Table
from rich.text import Text

console = Console()


def display_results_table(all_results):
    """Display detection results as a rich table grouped by sheet."""
    global_num = 0
    for sname, results in all_results.items():
        table = Table(title=f"Sheet: {sname}", show_lines=False, pad_edge=False)
        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("Column", min_width=12, max_width=30)
        table.add_column("PII Type", width=10)
        table.add_column("Conf.", width=6, justify="right")
        table.add_column("Source", width=10)
        table.add_column("Action", width=12)
        table.add_column("Samples", max_width=40, no_wrap=True)

        if not results:
            console.print(f"  [dim]Sheet {sname}: no columns[/dim]")
            continue

        for r in results:
            global_num += 1
            conf_str = f"{r['confidence']:.2f}" if r["confidence"] > 0 else "-"
            src_str = r["source"] if r["source"] != "none" else "-"

            if r["action"] == "OBFUSCATE":
                action_text = Text("OBFUSCATE", style="bold green")
            else:
                action_text = Text("SKIP", style="dim")

            # Show a few sample values if available
            samples = r.get("samples", [])
            samples_str = ", ".join(str(s)[:15] for s in samples[:3])
            if len(samples) > 3:
                samples_str += "..."

            table.add_row(
                str(global_num),
                r["name"],
                r["pii_type"],
                conf_str,
                src_str,
                action_text,
                samples_str,
            )

        console.print(table)
        console.print()


def _handle_exclusion_command(choice, flat):
    """Handle cell-level exclusion commands. Returns True if handled."""
    parts = choice.split(None, 2)
    if len(parts) < 2:
        return False

    try:
        idx = int(parts[0]) - 1
    except ValueError:
        return False

    if not (0 <= idx < len(flat)):
        return False

    cmd = parts[1].lower()
    sname, r = flat[idx]

    # Ensure exclusions set exists
    if "exclusions" not in r:
        r["exclusions"] = set()

    if cmd == "xi":
        # Show exclusions
        if r["exclusions"]:
            console.print(f"  [{sname}] '{r['name']}' exclusions:")
            for val in sorted(r["exclusions"]):
                console.print(f"    - {val}")
        else:
            console.print(f"  [{sname}] '{r['name']}' has no exclusions.")
        return True

    if cmd == "x" and len(parts) >= 3:
        # Add exclusion
        value = parts[2]
        r["exclusions"].add(value)
        console.print(
            f"  [{sname}] '{r['name']}': excluded [yellow]'{value}'[/yellow] "
            f"({len(r['exclusions'])} total)"
        )
        return True

    if cmd == "xr" and len(parts) >= 3:
        # Remove exclusion
        value = parts[2]
        r["exclusions"].discard(value)
        console.print(
            f"  [{sname}] '{r['name']}': removed exclusion '{value}' "
            f"({len(r['exclusions'])} remaining)"
        )
        return True

    return False


def confirm_columns_tui(all_results, column_samples=None):
    """
    Interactive column selector using rich formatting.

    Args:
        all_results: dict of sheet_name -> list of result dicts
        column_samples: optional dict of column_name -> list of sample values

    Returns:
        modified all_results dict
    """
    import sys

    # Inject samples into results for display
    if column_samples:
        for _sname, results in all_results.items():
            for r in results:
                if r["name"] in column_samples:
                    r["samples"] = column_samples[r["name"]]

    # Display table
    display_results_table(all_results)

    # Build flat index
    flat = []
    for sname, results in all_results.items():
        for r in results:
            flat.append((sname, r))

    console.print("[bold]Adjust columns:[/bold]")
    console.print("  [dim]<number>[/dim]          Toggle OBFUSCATE/SKIP")
    console.print("  [dim]<number> <type>[/dim]    Set PII type (name, email, phone, ssn, ...)")
    console.print("  [dim]<number> x <value>[/dim] Exclude a specific value from obfuscation")
    console.print("  [dim]<number> xi[/dim]        Show exclusions for a column")
    console.print("  [dim]<number> xr <value>[/dim] Remove an exclusion")
    console.print("  [dim]a[/dim]                 Select all")
    console.print("  [dim]n[/dim]                 Select none")
    console.print("  [dim]/term[/dim]             Filter columns by name")
    console.print("  [dim]done[/dim]              Proceed")
    console.print("  [dim]quit[/dim]              Abort")
    console.print()

    while True:
        try:
            choice = input("  > ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n  Aborted.")
            sys.exit(1)

        lower = choice.lower()

        if lower in ("done", ""):
            break
        if lower in ("quit", "q", "exit"):
            console.print("  Aborted.")
            sys.exit(0)

        # Select all
        if lower == "a":
            for _sname, r in flat:
                if r["pii_type"] != "none":
                    r["action"] = "OBFUSCATE"
                elif r["pii_type"] == "none":
                    r["action"] = "OBFUSCATE"
                    r["pii_type"] = "generic"
            console.print("  [green]All columns set to OBFUSCATE[/green]")
            continue

        # Select none
        if lower == "n":
            for _sname, r in flat:
                r["action"] = "SKIP"
            console.print("  [dim]All columns set to SKIP[/dim]")
            continue

        # Search/filter
        if lower.startswith("/"):
            term = lower[1:].strip()
            if not term:
                continue
            matches = [
                (i + 1, sname, r) for i, (sname, r) in enumerate(flat) if term in r["name"].lower()
            ]
            if not matches:
                console.print(f"  No columns matching '{term}'")
            else:
                for num, sname, r in matches:
                    action_style = "green" if r["action"] == "OBFUSCATE" else "dim"
                    console.print(
                        f"  {num:<4} [{sname}] {r['name']:<20} "
                        f"{r['pii_type']:<10} [{action_style}]{r['action']}[/{action_style}]"
                    )
            continue

        # Check for exclusion commands: "<number> x <value>", "<number> xi", "<number> xr <value>"
        exclusion_handled = _handle_exclusion_command(choice, flat)
        if exclusion_handled:
            continue

        # Toggle or set type
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(flat):
                sname, r = flat[idx]
                if r["action"] == "OBFUSCATE":
                    r["action"] = "SKIP"
                    r["pii_type"] = "none"
                    console.print(f"  [{sname}] '{r['name']}' -> [dim]SKIP[/dim]")
                else:
                    r["action"] = "OBFUSCATE"
                    if r["pii_type"] == "none":
                        r["pii_type"] = "generic"
                    console.print(
                        f"  [{sname}] '{r['name']}' -> [green]OBFUSCATE[/green] "
                        f"(type: {r['pii_type']})"
                    )
            else:
                console.print(f"  Invalid number. Enter 1-{len(flat)}.")
        except ValueError:
            parts = choice.split(None, 1)
            if len(parts) == 2:
                try:
                    idx = int(parts[0]) - 1
                    pii_type = parts[1].strip().lower()
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
                        console.print(
                            f"  [{sname}] '{r['name']}' -> {r['action']} (type: {pii_type})"
                        )
                    else:
                        console.print(
                            f"  Usage: <number> <type>  (types: {', '.join(valid_types)})"
                        )
                except ValueError:
                    console.print("  Enter a column number, 'done', or 'quit'.")
            else:
                console.print("  Enter a column number, 'done', or 'quit'.")

    return all_results
