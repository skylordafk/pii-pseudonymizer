"""Ollama API client with structured JSON output support."""

import json

import requests

ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "columns": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "is_sensitive": {"type": "boolean"},
                    "pii_type": {
                        "type": "string",
                        "enum": [
                            "name",
                            "email",
                            "phone",
                            "ssn",
                            "address",
                            "dob",
                            "financial",
                            "generic",
                            "none",
                        ],
                    },
                    "confidence": {"type": "number"},
                    "reasoning": {"type": "string"},
                },
                "required": ["name", "is_sensitive", "pii_type", "confidence", "reasoning"],
            },
        }
    },
    "required": ["columns"],
}


class OllamaClient:
    def __init__(
        self,
        base_url="http://localhost:11434",
        model="mistral:7b",
        num_ctx=2048,
        temperature=0,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.num_ctx = num_ctx
        self.temperature = temperature

    def health_check(self):
        """Check if Ollama is running and the model is available."""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if resp.status_code != 200:
                return False, "Ollama is not responding"
            models = [m["name"] for m in resp.json().get("models", [])]
            # Check for exact match or match without tag
            model_base = self.model.split(":")[0]
            found = any(self.model in m or model_base in m for m in models)
            if not found:
                return False, f"Model '{self.model}' not found. Available: {models}"
            return True, "OK"
        except requests.ConnectionError:
            return False, ("Cannot connect to Ollama. Is it running? Try: systemctl start ollama")
        except Exception as e:
            return False, f"Error: {e}"

    def chat(self, messages, schema=None, temperature=None, timeout=300, num_ctx=None):
        """
        Send a chat request to Ollama.

        Args:
            messages: list of {role, content} dicts
            schema: optional JSON schema for structured output
            temperature: optional override (default from client config)
            timeout: seconds
            num_ctx: optional context-window override (default from client config)

        Returns:
            dict with 'content' (str) and 'raw' (full response)
        """
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.temperature if temperature is None else temperature,
                "num_ctx": self.num_ctx if num_ctx is None else num_ctx,
            },
        }

        if schema:
            payload["format"] = schema

        resp = requests.post(
            f"{self.base_url}/api/chat",
            json=payload,
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()

        content = data.get("message", {}).get("content", "")
        return {"content": content, "raw": data}

    def analyze_columns(self, columns_to_analyze):
        """
        Ask the LLM to classify ambiguous columns for PII.

        Args:
            columns_to_analyze: list of dicts with 'name', 'samples', 'heuristic_guess'

        Returns:
            list of classification dicts from the LLM
        """
        if not columns_to_analyze:
            return []

        # Build prompt
        column_blocks = []
        for col in columns_to_analyze:
            samples_str = ", ".join(f'"{s}"' for s in col["samples"][:5])
            block = (
                f'  Column: "{col["name"]}"\n'
                f"  Sample values: [{samples_str}]\n"
                f"  Initial guess: {col.get('heuristic_guess', 'unknown')}"
            )
            column_blocks.append(block)

        columns_text = "\n\n".join(column_blocks)

        prompt = f"""Classify each spreadsheet column as sensitive (containing personally \
identifiable information) or not sensitive.

PII types to detect: name, email, phone, ssn, address, dob, financial, generic (other PII)
If a column is NOT sensitive, use pii_type "none".

Columns to classify:

{columns_text}

For each column provide:
- name: the column name exactly as shown
- is_sensitive: true or false
- pii_type: the type of PII detected, or "none"
- confidence: your confidence from 0.0 to 1.0
- reasoning: one sentence explanation"""

        messages = [
            {
                "role": "system",
                "content": (
                    "You are a data privacy analyst. Your job is to identify columns "
                    "that contain personally identifiable information (PII) in spreadsheet data. "
                    "Respond with the requested JSON structure only."
                ),
            },
            {"role": "user", "content": prompt},
        ]

        result = self.chat(messages, schema=ANALYSIS_SCHEMA, timeout=300)

        try:
            parsed = json.loads(result["content"])
            return parsed.get("columns", [])
        except json.JSONDecodeError as e:
            import sys

            print(
                f"  WARNING: LLM returned invalid JSON (falling back to heuristics): {e}",
                file=sys.stderr,
            )
            print(f"  LLM response preview: {result['content'][:200]!r}", file=sys.stderr)
            return []
        except KeyError as e:
            import sys

            print(
                f"  WARNING: LLM response missing expected field '{e}' "
                f"(falling back to heuristics)",
                file=sys.stderr,
            )
            return []

    def analyze_column_individual(self, column, context_examples=None, num_ctx=4096, timeout=300):
        """
        Analyze a single column in thorough mode with optional context.

        Args:
            column: dict with 'name', 'samples', 'heuristic_guess'
            context_examples: optional list of already-approved column classifications
                              to provide few-shot context
            num_ctx: context window size for thorough mode
            timeout: per-column timeout in seconds

        Returns:
            classification dict or None on failure
        """
        samples_str = ", ".join(f'"{s}"' for s in column["samples"][:10])

        context_section = ""
        if context_examples:
            examples = []
            for ex in context_examples[-5:]:  # Last 5 approved examples
                examples.append(
                    f'  - Column "{ex["name"]}": {ex["pii_type"]} '
                    f"(confidence {ex['confidence']:.1f})"
                )
            context_section = "\n\nAlready classified columns (for reference):\n" + "\n".join(
                examples
            )

        prompt = f"""Analyze this single spreadsheet column and determine if it contains \
personally identifiable information (PII).

Column: "{column["name"]}"
Sample values: [{samples_str}]
Initial heuristic guess: {column.get("heuristic_guess", "unknown")}
{context_section}

PII types: name, email, phone, ssn, address, dob, financial, generic (other PII), none

Provide:
- name: the column name exactly as shown
- is_sensitive: true or false
- pii_type: the type of PII detected, or "none"
- confidence: your confidence from 0.0 to 1.0
- reasoning: detailed explanation of your classification"""

        single_column_schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "is_sensitive": {"type": "boolean"},
                "pii_type": {
                    "type": "string",
                    "enum": [
                        "name",
                        "email",
                        "phone",
                        "ssn",
                        "address",
                        "dob",
                        "financial",
                        "generic",
                        "none",
                    ],
                },
                "confidence": {"type": "number"},
                "reasoning": {"type": "string"},
            },
            "required": ["name", "is_sensitive", "pii_type", "confidence", "reasoning"],
        }

        messages = [
            {
                "role": "system",
                "content": (
                    "You are an expert data privacy analyst. Analyze the column carefully. "
                    "Consider the column name, the sample values, and any patterns. "
                    "Be thorough and precise in your classification."
                ),
            },
            {"role": "user", "content": prompt},
        ]

        try:
            result = self.chat(
                messages,
                schema=single_column_schema,
                timeout=timeout,
                num_ctx=num_ctx,
            )
            parsed = json.loads(result["content"])
            return parsed
        except json.JSONDecodeError as e:
            import sys

            print(
                f"  WARNING: LLM returned invalid JSON for column '{column['name']}': {e}",
                file=sys.stderr,
            )
            return None
        except Exception as e:
            import sys

            print(
                f"  WARNING: LLM analysis failed for column '{column['name']}': {e}",
                file=sys.stderr,
            )
            return None

    def query(self, question):
        """Free-form query for interactive use. Returns response text."""
        messages = [{"role": "user", "content": question}]
        result = self.chat(messages, temperature=0.1, timeout=120)
        return result["content"]
