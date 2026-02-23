"""Regex-based PII detection for column headers and data values."""

import re

# Header patterns: map PII type -> list of regex patterns (case-insensitive)
HEADER_PATTERNS = {
    "name": [
        r"\b(first[_\s]?name|last[_\s]?name|full[_\s]?name|fname|lname)\b",
        r"\b(sur[_\s]?name|given[_\s]?name|maiden[_\s]?name|middle[_\s]?name)\b",
        r"\b(contact[_\s]?name|employee[_\s]?name|customer[_\s]?name|patient[_\s]?name)\b",
        r"\b(person[_\s]?name|applicant[_\s]?name|user[_\s]?name|username)\b",
        r"\b(name|nombre|nom)\b",
        r"\b(emergency[_\s]?contact|next[_\s]?of[_\s]?kin|beneficiary)\b",
        r"\b(guardian|spouse|partner|parent|mother|father)\b",
    ],
    "email": [
        r"\b(e[_\s\-]?mail|email[_\s]?addr|e[_\s\-]?mail[_\s]?address)\b",
        r"\b(contact[_\s]?email|work[_\s]?email|personal[_\s]?email)\b",
    ],
    "phone": [
        r"\b(phone|tel|telephone|mobile|cell|fax|contact[_\s]?number)\b",
        r"\b(phone[_\s]?num|tel[_\s]?num|mobile[_\s]?num|cell[_\s]?num)\b",
        r"\b(home[_\s]?phone|work[_\s]?phone|office[_\s]?phone)\b",
    ],
    "ssn": [
        r"\b(ssn|social[_\s]?security|social[_\s]?security[_\s]?number)\b",
        r"\b(national[_\s]?id|national[_\s]?insurance|sin|nino|tax[_\s]?id|tin)\b",
        r"\b(id[_\s]?number|identification[_\s]?number|passport[_\s]?num)\b",
        r"\b(driver[_\s]?license|dl[_\s]?number|license[_\s]?number)\b",
    ],
    "address": [
        r"\b(address|addr|street|street[_\s]?address|mailing[_\s]?address)\b",
        r"\b(home[_\s]?address|residence|physical[_\s]?address)\b",
        r"\b(city|state|zip|zip[_\s]?code|postal|postal[_\s]?code)\b",
        r"\b(country|province|region|county)\b",
    ],
    "dob": [
        r"\b(dob|date[_\s]?of[_\s]?birth|birth[_\s]?date|birthday|born)\b",
        r"\b(age|birth[_\s]?year)\b",
    ],
    "financial": [
        r"\b(account[_\s]?num|acct[_\s]?num|credit[_\s]?card|card[_\s]?num)\b",
        r"\b(routing[_\s]?num|iban|swift|bic|bank[_\s]?account)\b",
        r"\b(salary|wage|income|compensation|pay[_\s]?rate)\b",
    ],
}

# PII types where financial detection defaults to SKIP
DEPRIORITIZED_TYPES = {"financial"}

# Value patterns: regex to match against actual cell values
VALUE_PATTERNS = {
    "email": re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"),
    "ssn": re.compile(r"^\d{3}-\d{2}-\d{4}$"),
    # Phone: require >=7 digits total, must have grouping separators (spaces, dashes, dots,
    # parens), reject pure digit strings under 10 digits to avoid matching invoice numbers
    "phone": re.compile(
        r"^[\+]?(?:\(\d{1,4}\)|\d{1,4})[\s\-\.]"  # country/area code + separator
        r"[\d\s\-\.()]{6,14}$"  # remaining digits with separators
    ),
    "credit_card": re.compile(r"^\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}$"),
    "ip_address": re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),
    "zip_code": re.compile(r"^\d{5}-\d{4}$"),
    "date": re.compile(r"^\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}$"),
}


def _count_digits(s):
    """Count the number of digit characters in a string."""
    return sum(1 for c in s if c.isdigit())


def _is_phone_value(value):
    """Enhanced phone validation: require grouping separators and >=7 digits."""
    s = value.strip()
    # Must have at least 7 digits
    if _count_digits(s) < 7:
        return False
    # Reject if it matches credit card pattern (4 groups of 4 digits)
    if VALUE_PATTERNS["credit_card"].match(s):
        return False
    # Reject pure digit strings under 10 digits (likely invoice/ID numbers)
    stripped = s.lstrip("+")
    if stripped.isdigit() and len(stripped) < 10:
        return False
    # Reject if it looks like an IP address
    if VALUE_PATTERNS["ip_address"].match(s):
        return False
    # Reject values starting with non-digit, non-phone chars (e.g. INV-1234-5678)
    if s and not s[0].isdigit() and s[0] not in ("+", "("):
        return False
    # Must have at least one separator (space, dash, dot, or parenthesis)
    if not re.search(r"[\s\-\.\(\)]", s):
        # Allow if it's a long international number (10+ digits)
        return _count_digits(s) >= 10
    # Reject if too many digits (>15 is not a phone number)
    if _count_digits(s) > 15:
        return False
    return VALUE_PATTERNS["phone"].match(s) is not None


def analyze_column(column_name, sample_values):
    """
    Analyze a single column for PII using heuristic patterns.

    Returns:
        {
            'name': str,
            'heuristic_score': 'high' | 'medium' | 'low' | 'none',
            'pii_type': str,
            'confidence': float,
            'header_match': bool,
            'value_match_pii_type': str or None,
            'value_match_ratio': float,
            'evidence': list[str],
        }
    """
    result = {
        "name": column_name,
        "heuristic_score": "none",
        "pii_type": "none",
        "confidence": 0.0,
        "header_match": False,
        "value_match_pii_type": None,
        "value_match_ratio": 0.0,
        "evidence": [],
    }

    # Stage 1: Check column header
    header_pii_type = _match_header(column_name)
    if header_pii_type:
        result["header_match"] = True
        result["pii_type"] = header_pii_type
        result["evidence"].append(f"Header '{column_name}' matches pattern for {header_pii_type}")

    # Stage 2: Check sample values
    if sample_values:
        value_pii_type, match_ratio = _match_values(sample_values)
        if value_pii_type:
            result["value_match_pii_type"] = value_pii_type
            result["value_match_ratio"] = match_ratio
            result["evidence"].append(
                f"{match_ratio:.0%} of sample values match {value_pii_type} pattern"
            )

    # Compute overall score
    # Types that have verifiable value patterns (can confirm via sample data)
    _types_with_value_patterns = {"email", "ssn", "phone", "credit_card", "ip_address", "zip_code"}

    if result["header_match"] and result["value_match_ratio"] > 0.5:
        result["heuristic_score"] = "high"
        result["confidence"] = min(0.95, 0.7 + result["value_match_ratio"] * 0.3)
        # Header match takes priority for PII type (more reliable than value pattern)
    elif (
        result["header_match"]
        and result["value_match_ratio"] == 0.0
        and sample_values
        and result["pii_type"] in _types_with_value_patterns
    ):
        # Header matches PII pattern with verifiable type, but zero sample values match
        # -> downgrade. Catches false positives like "state" header with non-address values.
        result["heuristic_score"] = "low"
        result["confidence"] = 0.4
        result["evidence"].append("Header matches but no sample values confirm; needs review")
    elif result["header_match"]:
        result["heuristic_score"] = "medium"
        result["confidence"] = 0.7
    elif result["value_match_ratio"] > 0.5:
        result["heuristic_score"] = "medium"
        result["confidence"] = 0.5 + result["value_match_ratio"] * 0.2
        result["pii_type"] = result["value_match_pii_type"]
    elif result["value_match_ratio"] > 0.2:
        result["heuristic_score"] = "low"
        result["confidence"] = 0.3
        result["pii_type"] = result["value_match_pii_type"]

    return result


def _match_header(column_name):
    """Check column name against header patterns. Returns PII type or None."""
    name_lower = column_name.lower().strip()
    for pii_type, patterns in HEADER_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, name_lower, re.IGNORECASE):
                return pii_type
    return None


def _match_values(sample_values):
    """
    Check sample values against value patterns.
    Returns (pii_type, match_ratio) or (None, 0.0).
    """
    if not sample_values:
        return None, 0.0

    best_type = None
    best_ratio = 0.0

    str_values = [str(v).strip() for v in sample_values if v is not None and str(v).strip()]
    if not str_values:
        return None, 0.0

    # Check specific patterns first, then general ones (credit_card before phone, etc.)
    pattern_priority = ["email", "ssn", "credit_card", "ip_address", "zip_code", "date", "phone"]
    for pii_type in pattern_priority:
        if pii_type not in VALUE_PATTERNS:
            continue
        if pii_type == "phone":
            # Use enhanced phone validation
            matches = sum(1 for v in str_values if _is_phone_value(v))
        else:
            matches = sum(1 for v in str_values if VALUE_PATTERNS[pii_type].match(v))
        ratio = matches / len(str_values)
        if ratio > best_ratio:
            best_ratio = ratio
            best_type = pii_type

    if best_ratio > 0.2:
        return best_type, best_ratio
    return None, 0.0


def analyze_all_columns(columns):
    """
    Analyze all columns from a read_xlsx result.

    Args:
        columns: list of column dicts from reader.read_xlsx()

    Returns:
        list of analysis result dicts
    """
    results = []
    for col in columns:
        result = analyze_column(col["name"], col["samples"])
        result["index"] = col["index"]
        result["dtype_guess"] = col.get("dtype_guess", "unknown")
        results.append(result)
    return results
