"""Smart pseudonymization transforms: fake names, date shifting, etc.

Used by --format=readable mode. All transforms are deterministic and reversible
via the encrypted mapping stored in the key file.
"""

import hashlib
import hmac
import re
from datetime import datetime, timedelta

# Curated name lists for deterministic fake name generation
FIRST_NAMES = [
    "Aaron",
    "Abigail",
    "Adam",
    "Adrian",
    "Aiden",
    "Alex",
    "Alice",
    "Amanda",
    "Amber",
    "Amy",
    "Andrew",
    "Angela",
    "Anna",
    "Anthony",
    "Arthur",
    "Ashley",
    "Austin",
    "Barbara",
    "Benjamin",
    "Beth",
    "Blake",
    "Brandon",
    "Brian",
    "Brooke",
    "Bruce",
    "Caleb",
    "Cameron",
    "Carl",
    "Carlos",
    "Carol",
    "Caroline",
    "Catherine",
    "Charles",
    "Charlotte",
    "Chase",
    "Chris",
    "Clara",
    "Claudia",
    "Colin",
    "Connor",
    "Craig",
    "Crystal",
    "Curtis",
    "Cynthia",
    "Dale",
    "Dana",
    "Daniel",
    "Daphne",
    "David",
    "Dawn",
    "Dean",
    "Debra",
    "Derek",
    "Diana",
    "Diane",
    "Donald",
    "Donna",
    "Dorothy",
    "Douglas",
    "Dylan",
    "Earl",
    "Edward",
    "Eleanor",
    "Elena",
    "Elijah",
    "Elizabeth",
    "Ellen",
    "Emily",
    "Emma",
    "Eric",
    "Erica",
    "Ethan",
    "Eugene",
    "Eva",
    "Evan",
    "Evelyn",
    "Faith",
    "Felix",
    "Fiona",
    "Florence",
    "Francis",
    "Frank",
    "Gail",
    "Garrett",
    "Gary",
    "George",
    "Gerald",
    "Gloria",
    "Gordon",
    "Grace",
    "Grant",
    "Gregory",
    "Hannah",
    "Harold",
    "Harry",
    "Heather",
    "Helen",
    "Henry",
    "Holly",
    "Howard",
    "Ian",
    "Irene",
    "Isaac",
    "Isabel",
    "Jack",
    "Jacob",
    "James",
    "Jane",
    "Janet",
    "Jason",
    "Jean",
    "Jeffrey",
    "Jennifer",
    "Jeremy",
    "Jessica",
    "Joan",
    "Joel",
    "John",
    "Jonathan",
    "Jordan",
    "Joseph",
    "Joshua",
    "Joyce",
    "Juan",
    "Judith",
    "Julia",
    "Julian",
    "Julie",
    "Justin",
    "Karen",
    "Karl",
    "Kate",
    "Katherine",
    "Keith",
    "Kelly",
    "Kenneth",
    "Kevin",
    "Kim",
    "Kyle",
    "Lance",
    "Larry",
    "Laura",
    "Lauren",
    "Lawrence",
    "Leo",
    "Leon",
    "Leslie",
    "Lillian",
    "Linda",
    "Lisa",
    "Logan",
    "Lois",
    "Louis",
    "Lucas",
    "Lucy",
    "Luke",
    "Lynn",
    "Madison",
    "Malcolm",
    "Marco",
    "Margaret",
    "Maria",
    "Marie",
    "Mark",
    "Martha",
    "Martin",
    "Mary",
    "Mason",
    "Matthew",
    "Megan",
    "Melissa",
    "Michael",
    "Michelle",
    "Miles",
    "Monica",
    "Nancy",
    "Natalie",
    "Nathan",
    "Neil",
    "Nicholas",
    "Nicole",
    "Nina",
    "Noah",
    "Nora",
    "Norman",
    "Oliver",
    "Olivia",
    "Oscar",
    "Owen",
    "Pamela",
    "Patricia",
    "Patrick",
    "Paul",
    "Paula",
    "Peter",
    "Philip",
    "Rachel",
    "Ralph",
    "Randy",
    "Raymond",
    "Rebecca",
    "Regina",
    "Richard",
    "Rita",
    "Robert",
    "Robin",
    "Roger",
    "Ronald",
    "Rose",
    "Roy",
    "Ruby",
    "Russell",
    "Ruth",
    "Ryan",
    "Sabrina",
    "Samuel",
    "Sandra",
    "Sara",
    "Sarah",
    "Scott",
    "Sean",
    "Seth",
    "Sharon",
    "Sheila",
    "Simon",
    "Sophia",
    "Stephanie",
    "Stephen",
    "Steven",
    "Stuart",
    "Susan",
    "Sydney",
    "Sylvia",
    "Tamara",
    "Teresa",
    "Terry",
    "Theodore",
    "Thomas",
    "Timothy",
    "Tina",
    "Todd",
    "Tony",
    "Tracy",
    "Travis",
    "Trevor",
    "Tyler",
    "Valerie",
    "Vanessa",
    "Vernon",
    "Victor",
    "Victoria",
    "Vincent",
    "Virginia",
    "Walter",
    "Wanda",
    "Warren",
    "Wayne",
    "Wendy",
    "Wesley",
    "Whitney",
    "William",
    "Zachary",
    "Zoe",
]

LAST_NAMES = [
    "Adams",
    "Allen",
    "Anderson",
    "Andrews",
    "Armstrong",
    "Bailey",
    "Baker",
    "Banks",
    "Barnes",
    "Barrett",
    "Bell",
    "Bennett",
    "Berry",
    "Bishop",
    "Black",
    "Blair",
    "Blake",
    "Boyd",
    "Bradley",
    "Brooks",
    "Brown",
    "Bryant",
    "Burke",
    "Burns",
    "Butler",
    "Campbell",
    "Carroll",
    "Carter",
    "Chapman",
    "Clark",
    "Cole",
    "Coleman",
    "Collins",
    "Cook",
    "Cooper",
    "Cox",
    "Craig",
    "Crawford",
    "Cross",
    "Cruz",
    "Daniels",
    "Davidson",
    "Davis",
    "Dean",
    "Dixon",
    "Douglas",
    "Duncan",
    "Dunn",
    "Edwards",
    "Elliott",
    "Ellis",
    "Evans",
    "Ferguson",
    "Fields",
    "Fisher",
    "Fleming",
    "Fletcher",
    "Floyd",
    "Ford",
    "Foster",
    "Fox",
    "Francis",
    "Franklin",
    "Freeman",
    "Gardner",
    "Gibson",
    "Gilbert",
    "Gomez",
    "Gordon",
    "Graham",
    "Grant",
    "Gray",
    "Green",
    "Griffin",
    "Hall",
    "Hamilton",
    "Hansen",
    "Harper",
    "Harris",
    "Harrison",
    "Hart",
    "Harvey",
    "Hayes",
    "Henderson",
    "Henry",
    "Hernandez",
    "Hicks",
    "Hill",
    "Hoffman",
    "Holmes",
    "Howard",
    "Hughes",
    "Hunt",
    "Hunter",
    "Jackson",
    "James",
    "Jenkins",
    "Jensen",
    "Johnson",
    "Johnston",
    "Jones",
    "Jordan",
    "Kelly",
    "Kennedy",
    "Kim",
    "King",
    "Knight",
    "Lambert",
    "Lane",
    "Lawrence",
    "Lee",
    "Lewis",
    "Lloyd",
    "Long",
    "Lopez",
    "Lucas",
    "Lynch",
    "Marshall",
    "Martin",
    "Martinez",
    "Mason",
    "Matthews",
    "Maxwell",
    "McDonald",
    "Meyer",
    "Miller",
    "Mills",
    "Mitchell",
    "Moore",
    "Morgan",
    "Morris",
    "Morrison",
    "Murphy",
    "Murray",
    "Myers",
    "Nelson",
    "Newman",
    "Nichols",
    "Olson",
    "Owens",
    "Palmer",
    "Parker",
    "Patterson",
    "Payne",
    "Pearson",
    "Perry",
    "Peters",
    "Peterson",
    "Phillips",
    "Pierce",
    "Porter",
    "Powell",
    "Price",
    "Quinn",
    "Ramirez",
    "Reed",
    "Reid",
    "Reynolds",
    "Rice",
    "Richards",
    "Richardson",
    "Riley",
    "Rivera",
    "Roberts",
    "Robertson",
    "Robinson",
    "Rodriguez",
    "Rogers",
    "Rose",
    "Ross",
    "Russell",
    "Ryan",
    "Sanders",
    "Schmidt",
    "Scott",
    "Shaw",
    "Simmons",
    "Simpson",
    "Smith",
    "Snyder",
    "Spencer",
    "Stanley",
    "Stevens",
    "Stewart",
    "Stone",
    "Sullivan",
    "Taylor",
    "Thomas",
    "Thompson",
    "Torres",
    "Turner",
    "Walker",
    "Wallace",
    "Walsh",
    "Ward",
    "Warren",
    "Washington",
    "Watson",
    "Webb",
    "Wells",
    "West",
    "Wheeler",
    "White",
    "Williams",
    "Willis",
    "Wilson",
    "Wood",
    "Wright",
    "Young",
]

# Date pattern for parsing
_DATE_PATTERNS = [
    (re.compile(r"^(\d{4})-(\d{1,2})-(\d{1,2})$"), "%Y-%m-%d"),  # ISO
    (re.compile(r"^(\d{1,2})/(\d{1,2})/(\d{4})$"), "%m/%d/%Y"),  # US
    (re.compile(r"^(\d{1,2})-(\d{1,2})-(\d{4})$"), "%m-%d-%Y"),
    (re.compile(r"^(\d{1,2})\.(\d{1,2})\.(\d{4})$"), "%m.%d.%Y"),
    (re.compile(r"^(\d{1,2})/(\d{1,2})/(\d{2})$"), "%m/%d/%y"),  # 2-digit year
]


def _hmac_index(key, value, list_size):
    """Deterministically select an index from HMAC-SHA256."""
    h = hmac.new(key, value.encode("utf-8"), hashlib.sha256).digest()
    return int.from_bytes(h[:4], "big") % list_size


def _hmac_offset(key, column_name, max_days=365):
    """Deterministically compute a date offset from HMAC."""
    h = hmac.new(key, column_name.encode("utf-8"), hashlib.sha256).digest()
    # Offset between -max_days and +max_days
    raw = int.from_bytes(h[:4], "big")
    return (raw % (2 * max_days + 1)) - max_days


class ReadableTransformer:
    """Deterministic readable pseudonymization using HMAC-derived mappings.

    Produces fake names, shifted dates, etc. that AI can reason about naturally.
    The reverse mapping is stored encrypted in the key file.
    """

    def __init__(self, hmac_key):
        """
        Args:
            hmac_key: bytes key for HMAC operations (derived from passphrase)
        """
        self.hmac_key = hmac_key
        # Track forward mappings for storage in key file
        self._mappings = {}  # column_name -> {original: pseudonym}

    def transform_value(self, value, column_name, pii_type):
        """Transform a single value based on PII type.

        Returns the pseudonymized value (readable fake).
        """
        if value is None:
            return None
        str_val = str(value).strip()
        if not str_val:
            return value

        # Create column-specific HMAC key
        col_key = hmac.new(self.hmac_key, column_name.encode("utf-8"), hashlib.sha256).digest()

        if pii_type in ("name",):
            result = self._transform_name(str_val, col_key, column_name)
        elif pii_type in ("dob", "date"):
            result = self._transform_date(str_val, col_key, column_name)
        elif pii_type == "email":
            result = self._transform_email(str_val, col_key, column_name)
        else:
            # For types without a readable transform, use a deterministic label
            idx = _hmac_index(col_key, str_val, 10000)
            prefix = pii_type.upper()[:4]
            result = f"{prefix}_{idx:04d}"

        # Store mapping
        if column_name not in self._mappings:
            self._mappings[column_name] = {}
        self._mappings[column_name][result] = str_val

        return result

    def reverse_value(self, pseudonym, column_name, pii_type):
        """Reverse a readable pseudonym using the stored mapping."""
        if pseudonym is None:
            return None
        str_val = str(pseudonym).strip()
        if not str_val:
            return pseudonym

        mapping = self._mappings.get(column_name, {})
        return mapping.get(str_val, pseudonym)

    def get_mappings(self):
        """Return all mappings for key file storage."""
        return dict(self._mappings)

    def load_mappings(self, mappings):
        """Load mappings from key file for reversal."""
        self._mappings = dict(mappings)

    def _transform_name(self, name, col_key, column_name):
        """Generate a deterministic fake name."""
        # Split into parts if it looks like "First Last"
        parts = name.split()
        col_lower = column_name.lower()

        if "first" in col_lower or "fname" in col_lower or "given" in col_lower:
            # First name column
            idx = _hmac_index(col_key, name, len(FIRST_NAMES))
            return FIRST_NAMES[idx]
        elif "last" in col_lower or "lname" in col_lower or "sur" in col_lower:
            # Last name column
            idx = _hmac_index(col_key, name, len(LAST_NAMES))
            return LAST_NAMES[idx]
        elif len(parts) >= 2:
            # Full name: generate first + last
            first_idx = _hmac_index(col_key, parts[0], len(FIRST_NAMES))
            last_idx = _hmac_index(col_key, parts[-1], len(LAST_NAMES))
            return f"{FIRST_NAMES[first_idx]} {LAST_NAMES[last_idx]}"
        else:
            # Single name, use first names
            idx = _hmac_index(col_key, name, len(FIRST_NAMES))
            return FIRST_NAMES[idx]

    def _transform_date(self, date_str, col_key, column_name):
        """Shift a date by a deterministic per-column offset."""
        offset_days = _hmac_offset(col_key, column_name)

        # Try to parse the date
        for pattern, fmt in _DATE_PATTERNS:
            if pattern.match(date_str):
                try:
                    dt = datetime.strptime(date_str, fmt)
                    shifted = dt + timedelta(days=offset_days)
                    return shifted.strftime(fmt)
                except ValueError:
                    continue

        # If it's a datetime object rendered as string, try ISO parse
        try:
            dt = datetime.fromisoformat(date_str)
            shifted = dt + timedelta(days=offset_days)
            return shifted.isoformat()
        except (ValueError, TypeError):
            pass

        # Can't parse: fall back to generic label
        idx = _hmac_index(col_key, date_str, 10000)
        return f"DATE_{idx:04d}"

    def _transform_email(self, email, col_key, column_name):
        """Generate a deterministic fake email."""
        if "@" in email:
            local, _domain = email.rsplit("@", 1)
            # Generate a fake local part from a name
            first_idx = _hmac_index(col_key, local, len(FIRST_NAMES))
            last_idx = _hmac_index(col_key, email, len(LAST_NAMES))
            fake_local = f"{FIRST_NAMES[first_idx].lower()}.{LAST_NAMES[last_idx].lower()}"
            return f"{fake_local}@example.com"
        # Not a valid email format
        idx = _hmac_index(col_key, email, 10000)
        return f"user_{idx:04d}@example.com"

    def transform_rows(self, headers, rows, columns_to_transform):
        """Transform specified columns across all rows.

        Args:
            headers: list of column header strings
            rows: list of row dicts
            columns_to_transform: list of dicts with 'name' and 'pii_type'

        Returns:
            list of transformed row dicts
        """
        col_map = {c["name"]: c["pii_type"] for c in columns_to_transform}

        transformed_rows = []
        for row in rows:
            new_row = dict(row)
            for col_name, pii_type in col_map.items():
                if col_name in new_row:
                    new_row[col_name] = self.transform_value(new_row[col_name], col_name, pii_type)
            transformed_rows.append(new_row)
        return transformed_rows

    def reverse_rows(self, headers, rows, columns_to_reverse):
        """Reverse transformation for specified columns."""
        col_map = {c["name"]: c["pii_type"] for c in columns_to_reverse}

        reversed_rows = []
        for row in rows:
            new_row = dict(row)
            for col_name, pii_type in col_map.items():
                if col_name in new_row:
                    new_row[col_name] = self.reverse_value(new_row[col_name], col_name, pii_type)
            reversed_rows.append(new_row)
        return reversed_rows
