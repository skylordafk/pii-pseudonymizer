"""Two-stage PII detection: heuristics first, then LLM for ambiguous columns."""

from pii_pseudonymizer.heuristics import DEPRIORITIZED_TYPES, analyze_all_columns
from pii_pseudonymizer.ollama_client import OllamaClient  # noqa: F401


class PIIDetector:
    def __init__(self, ollama_client=None, thorough=False, lists=None):
        """
        Args:
            ollama_client: OllamaClient instance, or None to skip LLM analysis
            thorough: if True, analyze each column individually with larger context
            lists: dict with 'always_pii' and 'never_pii' lists of column names/terms
        """
        self.ollama = ollama_client
        self.thorough = thorough
        self.lists = lists or {"always_pii": [], "never_pii": []}
        # Context for thorough mode: tracks approved classifications
        self._approved_context = []

    def detect(self, file_metadata):
        """
        Full detection pipeline.

        Args:
            file_metadata: dict from reader.read_xlsx()

        Returns:
            list of dicts, one per column:
                {
                    'index': int,
                    'name': str,
                    'pii_type': str,
                    'confidence': float,
                    'source': 'heuristic' | 'llm' | 'both' | 'none',
                    'action': 'OBFUSCATE' | 'SKIP',
                    'evidence': list[str],
                }
        """
        columns = file_metadata["columns"]

        # Stage 1: Heuristics
        heuristic_results = analyze_all_columns(columns)

        # Separate into categories
        high_confidence = []
        needs_llm = []
        no_pii = []

        for h in heuristic_results:
            if h["heuristic_score"] == "high":
                high_confidence.append(h)
            elif h["heuristic_score"] in ("medium", "low"):
                needs_llm.append(h)
            else:
                # Only send text columns with "none" score to LLM if they have
                # data; skip purely numeric/date/empty columns
                if h["dtype_guess"] == "text" and self.ollama:
                    needs_llm.append(h)
                else:
                    no_pii.append(h)

        # Stage 2: LLM analysis for ambiguous columns
        llm_results = {}
        if needs_llm and self.ollama:
            llm_columns = []
            for h in needs_llm:
                # Find matching column data for samples
                col_data = next((c for c in columns if c["index"] == h["index"]), None)
                samples = col_data["samples"] if col_data else []
                llm_columns.append(
                    {
                        "name": h["name"],
                        "samples": samples,
                        "heuristic_guess": h["pii_type"] if h["pii_type"] != "none" else "unknown",
                    }
                )

            if self.thorough:
                # Thorough mode: analyze each column individually with progress
                llm_results = self._analyze_thorough(llm_columns)
            else:
                try:
                    llm_classifications = self.ollama.analyze_columns(llm_columns)
                    for lc in llm_classifications:
                        llm_results[lc["name"]] = lc
                except Exception as e:
                    print(f"  Warning: LLM analysis failed ({e}). Using heuristics only.")

        # Merge results
        final_results = []

        # High-confidence heuristic matches -> OBFUSCATE (financial defaults to SKIP)
        for h in high_confidence:
            action = "SKIP" if h["pii_type"] in DEPRIORITIZED_TYPES else "OBFUSCATE"
            evidence = list(h["evidence"])
            if h["pii_type"] in DEPRIORITIZED_TYPES:
                evidence.append("Financial data deprioritized; opt in manually if needed")
            final_results.append(
                {
                    "index": h["index"],
                    "name": h["name"],
                    "pii_type": h["pii_type"],
                    "confidence": h["confidence"],
                    "source": "heuristic",
                    "action": action,
                    "evidence": evidence,
                }
            )

        # Ambiguous columns -> merge heuristic + LLM
        for h in needs_llm:
            llm = llm_results.get(h["name"])
            if llm and llm.get("is_sensitive"):
                # LLM says sensitive
                pii_type = llm.get("pii_type", h["pii_type"])
                if pii_type == "none":
                    pii_type = h["pii_type"]
                confidence = max(h["confidence"], llm.get("confidence", 0.5))
                source = "both" if h["confidence"] > 0.3 else "llm"
                evidence = h["evidence"] + [f"LLM: {llm.get('reasoning', '')}"]
                final_results.append(
                    {
                        "index": h["index"],
                        "name": h["name"],
                        "pii_type": pii_type if pii_type != "none" else "generic",
                        "confidence": confidence,
                        "source": source,
                        "action": "OBFUSCATE",
                        "evidence": evidence,
                    }
                )
            elif llm and not llm.get("is_sensitive"):
                # LLM says not sensitive
                final_results.append(
                    {
                        "index": h["index"],
                        "name": h["name"],
                        "pii_type": "none",
                        "confidence": llm.get("confidence", 0.5),
                        "source": "llm",
                        "action": "SKIP",
                        "evidence": [f"LLM: {llm.get('reasoning', '')}"],
                    }
                )
            else:
                # No LLM result for this column; use heuristic result
                action = "OBFUSCATE" if h["confidence"] >= 0.5 else "SKIP"
                evidence = list(h["evidence"])
                # Deprioritize financial detections
                if h["pii_type"] in DEPRIORITIZED_TYPES and action == "OBFUSCATE":
                    action = "SKIP"
                    evidence.append("Financial data deprioritized; opt in manually if needed")
                final_results.append(
                    {
                        "index": h["index"],
                        "name": h["name"],
                        "pii_type": h["pii_type"],
                        "confidence": h["confidence"],
                        "source": "heuristic",
                        "action": action,
                        "evidence": evidence,
                    }
                )

        # No-PII columns -> SKIP
        for h in no_pii:
            final_results.append(
                {
                    "index": h["index"],
                    "name": h["name"],
                    "pii_type": "none",
                    "confidence": 0.0,
                    "source": "none",
                    "action": "SKIP",
                    "evidence": [],
                }
            )

        # Apply allowlist/denylist overrides
        always_pii = {t.lower() for t in self.lists.get("always_pii", [])}
        never_pii = {t.lower() for t in self.lists.get("never_pii", [])}

        for r in final_results:
            name_lower = r["name"].lower()
            if name_lower in always_pii:
                r["action"] = "OBFUSCATE"
                if r["pii_type"] == "none":
                    r["pii_type"] = "generic"
                r["evidence"] = [*r.get("evidence", []), "Denylist: always treat as PII"]
                r["source"] = r["source"] if r["source"] != "none" else "denylist"
            elif name_lower in never_pii:
                r["action"] = "SKIP"
                r["pii_type"] = "none"
                r["evidence"] = [*r.get("evidence", []), "Allowlist: never treat as PII"]

        # Sort by column index
        final_results.sort(key=lambda x: x["index"])
        return final_results

    def add_approved_context(self, name, pii_type, confidence):
        """Add an approved classification to the context for future LLM calls."""
        self._approved_context.append(
            {"name": name, "pii_type": pii_type, "confidence": confidence}
        )

    def _analyze_thorough(self, llm_columns):
        """Analyze columns individually in thorough mode with progress."""
        import sys

        llm_results = {}
        total = len(llm_columns)

        for i, col in enumerate(llm_columns, 1):
            sys.stdout.write(f"\r  Analyzing column {i}/{total}: '{col['name']}'...  ")
            sys.stdout.flush()

            result = self.ollama.analyze_column_individual(
                col,
                context_examples=self._approved_context,
                num_ctx=4096,
                timeout=300,
            )
            if result:
                llm_results[result.get("name", col["name"])] = result

        # Clear progress line
        sys.stdout.write("\r" + " " * 60 + "\r")
        sys.stdout.flush()
        print(f"  Thorough analysis complete: {total} column(s) analyzed")

        return llm_results
