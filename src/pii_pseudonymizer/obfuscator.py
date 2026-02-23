"""Reversible deterministic pseudonymization using AES-SIV encryption."""

import base64
import hashlib
import hmac
import json
import os
import re
from datetime import UTC, datetime

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 480000
KEY_FILE_VERSION = 3

PII_TYPE_PREFIXES = {
    "name": "NAME",
    "email": "EMAIL",
    "phone": "PHONE",
    "ssn": "SSN",
    "address": "ADDR",
    "dob": "DOB",
    "financial": "FIN",
    "generic": "PII",
    "credit_card": "FIN",
    "ip_address": "PII",
    "zip_code": "ADDR",
    "date": "DATE",
}

# Regex to detect obfuscated values: [PREFIX:base64data]
OBFUSCATED_PATTERN = re.compile(r"^\[([A-Z]+):([A-Za-z0-9_\-+=/.]+)\]$")


class Obfuscator:
    def __init__(self, passphrase, salt=None):
        """
        Initialize with passphrase. If salt is None, generate a new one.
        Provide an existing salt when loading from a key file for decryption.
        """
        self.salt = salt if salt is not None else os.urandom(16)
        self.master_key = self._derive_key(passphrase, self.salt)
        self.cipher = AESSIV(self.master_key)
        # Derive separate keys for key file encryption and HMAC
        self._metadata_key = self._derive_secondary_key(passphrase, self.salt, b"metadata-enc")
        self._hmac_key = self._derive_secondary_key(passphrase, self.salt, b"hmac-integrity")

    def _derive_key(self, passphrase, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,  # 512 bits for AES-256-SIV
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        return kdf.derive(passphrase.encode("utf-8"))

    def _derive_secondary_key(self, passphrase, salt, context):
        """Derive a secondary key using HKDF-like approach (PBKDF2 with context-modified salt)."""
        modified_salt = hashlib.sha256(salt + context).digest()[:16]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=modified_salt,
            iterations=PBKDF2_ITERATIONS,
        )
        return kdf.derive(passphrase.encode("utf-8"))

    def obfuscate_value(self, value, column_name, pii_type):
        """
        Deterministically encrypt a single value.

        Same (value, column_name, pii_type, key) -> same ciphertext.
        Returns a string like [NAME:base64data].
        """
        if value is None:
            return None
        str_val = str(value).strip()
        if not str_val:
            return value

        associated_data = [f"{column_name}:{pii_type}".encode()]
        ciphertext = self.cipher.encrypt(str_val.encode("utf-8"), associated_data)
        encoded = base64.urlsafe_b64encode(ciphertext).decode("ascii")

        prefix = PII_TYPE_PREFIXES.get(pii_type, "PII")
        return f"[{prefix}:{encoded}]"

    def deobfuscate_value(self, obfuscated, column_name, pii_type):
        """
        Reverse pseudonymization for a single value.
        Returns the original plaintext string.
        """
        if obfuscated is None:
            return None
        str_val = str(obfuscated).strip()
        if not str_val:
            return obfuscated

        match = OBFUSCATED_PATTERN.match(str_val)
        if not match:
            return obfuscated  # Not an obfuscated value

        encoded = match.group(2)
        ciphertext = base64.urlsafe_b64decode(encoded)
        associated_data = [f"{column_name}:{pii_type}".encode()]

        plaintext = self.cipher.decrypt(ciphertext, associated_data)
        return plaintext.decode("utf-8")

    def obfuscate_rows(self, headers, rows, columns_to_obfuscate):
        """
        Obfuscate specified columns across all rows.

        Args:
            headers: list of column header strings
            rows: list of row dicts {column_name: value}
            columns_to_obfuscate: list of dicts with 'name' and 'pii_type'

        Returns:
            list of modified row dicts (new list, originals unchanged)
        """
        col_map = {c["name"]: c["pii_type"] for c in columns_to_obfuscate}

        obfuscated_rows = []
        for row in rows:
            new_row = dict(row)
            for col_name, pii_type in col_map.items():
                if col_name in new_row:
                    new_row[col_name] = self.obfuscate_value(new_row[col_name], col_name, pii_type)
            obfuscated_rows.append(new_row)
        return obfuscated_rows

    def deobfuscate_rows(self, headers, rows, columns_to_deobfuscate):
        """
        Reverse pseudonymization for specified columns across all rows.

        Args:
            headers: list of column header strings
            rows: list of row dicts
            columns_to_deobfuscate: list of dicts with 'name' and 'pii_type'

        Returns:
            list of decoded row dicts
        """
        col_map = {c["name"]: c["pii_type"] for c in columns_to_deobfuscate}

        decoded_rows = []
        for row in rows:
            new_row = dict(row)
            for col_name, pii_type in col_map.items():
                if col_name in new_row:
                    new_row[col_name] = self.deobfuscate_value(
                        new_row[col_name], col_name, pii_type
                    )
            decoded_rows.append(new_row)
        return decoded_rows

    def _encrypt_metadata(self, metadata_dict):
        """Encrypt the sheets metadata section using AES-SIV with the metadata key."""
        from cryptography.hazmat.primitives.ciphers.aead import AESSIV as MetaSIV

        plaintext = json.dumps(metadata_dict).encode("utf-8")
        # Use metadata key (32 bytes) — need 64 bytes for AES-256-SIV
        # Expand by doubling (first 32 for auth, second 32 for encryption)
        expanded_key = self._metadata_key + hashlib.sha256(self._metadata_key).digest()
        cipher = MetaSIV(expanded_key)
        ciphertext = cipher.encrypt(plaintext, [b"key-file-metadata"])
        return base64.b64encode(ciphertext).decode("ascii")

    def _decrypt_metadata(self, encrypted_b64):
        """Decrypt the sheets metadata section."""
        from cryptography.hazmat.primitives.ciphers.aead import AESSIV as MetaSIV

        ciphertext = base64.b64decode(encrypted_b64)
        expanded_key = self._metadata_key + hashlib.sha256(self._metadata_key).digest()
        cipher = MetaSIV(expanded_key)
        plaintext = cipher.decrypt(ciphertext, [b"key-file-metadata"])
        return json.loads(plaintext.decode("utf-8"))

    def _compute_hmac(self, data_bytes):
        """Compute HMAC-SHA256 over key file content."""
        return hmac.new(self._hmac_key, data_bytes, hashlib.sha256).hexdigest()

    def save_key_file(
        self,
        filepath,
        source_file,
        sheets_columns,
        output_format="encrypted",
        readable_mappings=None,
        exclusions=None,
    ):
        """
        Save the key file containing salt and per-sheet column metadata.

        The passphrase is NOT stored. The user must remember it.
        Key file v3: metadata (sheets section) is encrypted, HMAC for integrity.

        Args:
            filepath: where to write the key file
            source_file: original filename
            sheets_columns: dict mapping sheet_name -> list of
                            {'name': str, 'pii_type': str} dicts.
                            For backward compat, also accepts a flat list
                            (treated as a single unnamed sheet).
            output_format: "encrypted" or "readable"
            readable_mappings: if format is "readable", dict of column_name -> {pseudonym: original}
            exclusions: optional dict of sheet_name -> {col_name: list of excluded values}
        """
        # Normalize to per-sheet format
        if isinstance(sheets_columns, list):
            sheets_columns = {"Sheet1": sheets_columns}

        sheets_data = {}
        for sheet_name, cols in sheets_columns.items():
            sheet_exclusions = (exclusions or {}).get(sheet_name, {})
            columns_data = {}
            for col in cols:
                col_data = {
                    "pii_type": col["pii_type"],
                    "obfuscated": True,
                }
                col_excl = sheet_exclusions.get(col["name"])
                if col_excl:
                    col_data["exclusions"] = col_excl
                columns_data[col["name"]] = col_data
            sheets_data[sheet_name] = {"columns": columns_data}

        # Include readable mappings if present
        metadata_to_encrypt = {
            "sheets": sheets_data,
            "format": output_format,
        }
        if readable_mappings:
            metadata_to_encrypt["readable_mappings"] = readable_mappings

        # Encrypt the full metadata
        encrypted_metadata = self._encrypt_metadata(metadata_to_encrypt)

        # Plaintext summary (inspectable without passphrase)
        total_columns = sum(len(cols) for cols in sheets_columns.values())
        summary = {
            "sheet_count": len(sheets_columns),
            "column_count": total_columns,
            "sheet_names_hash": hashlib.sha256(
                ",".join(sorted(sheets_columns.keys())).encode()
            ).hexdigest()[:16],
        }

        data = {
            "version": KEY_FILE_VERSION,
            "algorithm": "AES-256-SIV",
            "kdf": "PBKDF2-SHA256",
            "iterations": PBKDF2_ITERATIONS,
            "salt": base64.b64encode(self.salt).decode("ascii"),
            "created_at": datetime.now(UTC).isoformat(),
            "source_file": source_file,
            "summary": summary,
            "encrypted_metadata": encrypted_metadata,
        }

        # Compute HMAC over the serialized data (excluding the hmac field itself)
        data_bytes = json.dumps(data, sort_keys=True).encode("utf-8")
        data["hmac"] = self._compute_hmac(data_bytes)

        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def from_key_file(cls, key_filepath, passphrase):
        """
        Load an Obfuscator from a key file.

        Returns (Obfuscator, key_data_dict).
        Handles v1 (flat 'columns'), v2 (per-sheet 'sheets'), and v3 (encrypted metadata).
        """
        with open(key_filepath) as f:
            key_data = json.load(f)

        salt = base64.b64decode(key_data["salt"])
        obfuscator = cls(passphrase, salt=salt)

        version = key_data.get("version", 1)

        if version >= 3 and "encrypted_metadata" in key_data:
            # v3: verify HMAC, decrypt metadata
            stored_hmac = key_data.pop("hmac", None)
            if stored_hmac:
                data_bytes = json.dumps(key_data, sort_keys=True).encode("utf-8")
                computed_hmac = obfuscator._compute_hmac(data_bytes)
                if not hmac.compare_digest(stored_hmac, computed_hmac):
                    raise ValueError(
                        "Key file integrity check failed (HMAC mismatch). "
                        "File may be tampered with or wrong passphrase."
                    )
                key_data["hmac"] = stored_hmac  # restore for completeness

            decrypted = obfuscator._decrypt_metadata(key_data["encrypted_metadata"])
            # v3 stores metadata in a wrapper with 'sheets', 'format', 'readable_mappings'
            if isinstance(decrypted, dict) and "sheets" in decrypted:
                key_data["sheets"] = decrypted["sheets"]
                key_data["format"] = decrypted.get("format", "encrypted")
                if "readable_mappings" in decrypted:
                    key_data["readable_mappings"] = decrypted["readable_mappings"]
            else:
                # Older v3 without wrapper
                key_data["sheets"] = decrypted

        elif version < 2 and "columns" in key_data:
            # Normalize v1 format to v2
            key_data["sheets"] = {"Sheet1": {"columns": key_data.pop("columns")}}
            key_data["version"] = 2

        return obfuscator, key_data
