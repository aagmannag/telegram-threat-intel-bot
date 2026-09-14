"""
keyword_prefilter.py — Proper multi-keyword search

4 methods working together:
  1. Exact match        — "data leak" found in text
  2. Proximity match    — "database" and "dump" within N words of each other
  3. OR / Synonym match — "pwned", "breached", "compromised" all mean "hacked"
  4. Fuzzy match        — "d4ta l3ak", "dataleak" still matches "data leak"
"""

import re
from rapidfuzz import fuzz  # pip install rapidfuzz
from app.keywords import KEYWORDS, HIGH_RISK_KEYWORDS


# ══════════════════════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════════════════════

# Method 2 — how many words apart two words can be and still count as a match
PROXIMITY_WINDOW = 6

# Method 4 — how similar a word needs to be to count as fuzzy match (0-100)
FUZZY_THRESHOLD = 82

# ══════════════════════════════════════════════════════════════════════════════
# PROXIMITY PAIRS
# Two words that together mean something dangerous, even if not adjacent
# ══════════════════════════════════════════════════════════════════════════════

PROXIMITY_PAIRS = [
    ("database",  "dump"),
    ("database",  "leak"),
    ("database",  "breach"),
    ("database",  "stolen"),
    ("database",  "exposed"),
    ("source",    "code"),
    ("credit",    "card"),
    ("zero",      "day"),
    ("password",  "dump"),
    ("password",  "stolen"),
    ("password",  "exposed"),
    ("data",      "sold"),
    ("data",      "stolen"),
    ("data",      "exposed"),
    ("user",      "dump"),
    ("account",   "dump"),
    ("account",   "stolen"),
    ("private",   "key"),
    ("ssh",       "key"),
    ("api",       "key"),
    ("admin",     "access"),
    ("root",      "access"),
    ("backdoor",  "found"),
    ("shell",     "upload"),
    ("remote",    "access"),
    ("files",     "encrypted"),
    ("ransom",    "demand"),
    ("backup",    "deleted"),
    ("server",    "hacked"),
    ("site",      "defaced"),
    ("network",   "breached"),
]

# ══════════════════════════════════════════════════════════════════════════════
# SYNONYM GROUPS
# Any word in the group matches — they all mean the same threat
# ══════════════════════════════════════════════════════════════════════════════

SYNONYM_GROUPS = {
    "hacked": [
        "compromised", "pwned", "breached", "owned", "got in",
        "infiltrated", "unauthorized access", "intruded"
    ],
    "data leak": [
        "data exposed", "data spilled", "info leaked", "information leaked",
        "records exposed", "data published", "data released", "data dumped",
        "data stolen", "exfiltrated"
    ],
    "malware": [
        "virus", "worm", "payload", "implant", "trojan",
        "backdoor", "rootkit", "stager", "loader", "dropper"
    ],
    "ransomware": [
        "encrypted files", "ransom demand", "decrypt key", "ransom note",
        "files locked", "pay ransom", "bitcoin ransom", "crypto ransom"
    ],
    "ddos": [
        "flood attack", "traffic attack", "knocked offline", "took down",
        "service down", "overloaded server", "layer 7 attack", "amplification attack"
    ],
    "vulnerability": [
        "security flaw", "security hole", "security bug", "cve-",
        "patch bypass", "unpatched", "security weakness", "attack surface"
    ],
    "credential leak": [
        "login dump", "combo list", "username password", "user pass",
        "credentials leaked", "accounts leaked", "logins leaked"
    ],
    "database dump": [
        "db dump", "sql dump", "mysql dump", "full database",
        "table dump", "records dump", "rows leaked"
    ],
    "defacement": [
        "website defaced", "page defaced", "mirror added", "zone-h",
        "index replaced", "homepage hacked"
    ],
    "exploit": [
        "poc released", "proof of concept", "exploit code", "exploit kit",
        "weaponized", "exploit public", "0day released"
    ],
}

# ══════════════════════════════════════════════════════════════════════════════
# REGEX PATTERNS
# Catch things no keyword list would ever cover
# ══════════════════════════════════════════════════════════════════════════════

REGEX_PATTERNS = [
    # Record counts — "50,000 users", "1.2M records", "500k accounts"
    (re.compile(r"\b\d[\d,]*\s*[kKmMbB]?\s*(?:users?|records?|accounts?|emails?|rows?|entries)\b", re.I),
     "record_count"),

    # CVE identifiers
    (re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
     "cve_id"),

    # IP addresses
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
     "ip_address"),

    # Onion / dark web links
    (re.compile(r"\b\w+\.onion\b", re.I),
     "onion_link"),

    # Suspicious TLDs used by hackers
    (re.compile(r"\b\w+\.(?:to|cc|su|pw|xyz|ru)\b", re.I),
     "suspicious_domain"),

    # "sold for" / "price" / "buy" near data context
    (re.compile(r"\b(?:sold?|selling|buy|purchase|price)\b.{0,40}\b(?:data|database|accounts?|creds?)\b", re.I),
     "data_for_sale"),

    # Paste sites
    (re.compile(r"\b(?:pastebin|ghostbin|rentry|hastebin|paste\.ee)\b", re.I),
     "paste_site"),

    # "X GB of data" / "X TB dump"
    (re.compile(r"\b\d+\s*(?:gb|tb|mb)\s*(?:of\s*)?(?:data|dump|database|files?)\b", re.I),
     "data_size"),

    # Telegram dump channels pattern
    (re.compile(r"@\w+(?:leak|dump|hack|crack|breach|data)\w*", re.I),
     "leak_channel"),
]


# ══════════════════════════════════════════════════════════════════════════════
# METHOD 1 — Exact match
# text    = "major data leak from Indian bank"
# keyword = "data leak"
# result  = FOUND 
# ══════════════════════════════════════════════════════════════════════════════

def _exact_match(text_lower: str) -> list[str]:
    return [kw for kw in KEYWORDS if kw.lower() in text_lower]


# ══════════════════════════════════════════════════════════════════════════════
# METHOD 2 — Proximity match
# text   = "a large database of indian users was dumped yesterday"
# checks = is "database" within 6 words of "dump"?
#          database(pos 3) ... dumped(pos 8) = distance 5 FOUND
# ══════════════════════════════════════════════════════════════════════════════

def _proximity_match(words: list[str]) -> list[str]:
    """
    For each PROXIMITY_PAIR (word_a, word_b), find all positions of both words
    in the token list. If any pair of positions is within PROXIMITY_WINDOW words,
    record it as a match.

    Example:
      text  = "a large database of indian users was dumped yesterday"
      words = ["a","large","database","of","indian","users","was","dumped","yesterday"]
      pair  = ("database", "dump")
      pos_a = [2]  (database at index 2)
      pos_b = [7]  (dumped at index 7)
      distance = 5 → within window of 6 → MATCH 
    """
    found = []
    for word_a, word_b in PROXIMITY_PAIRS:
        positions_a = [i for i, w in enumerate(words) if word_a in w]
        positions_b = [i for i, w in enumerate(words) if word_b in w]

        for pa in positions_a:
            for pb in positions_b:
                if abs(pa - pb) <= PROXIMITY_WINDOW:
                    match_str = f"{word_a} ↔ {word_b}"
                    if match_str not in found:
                        found.append(match_str)
                    break

    return found


# ══════════════════════════════════════════════════════════════════════════════
# METHOD 3 — Synonym / OR match
# text    = "the server was compromised by threat actors"
# keyword = "hacked" → not found
# synonym = "compromised" → FOUND reported as "compromised (=hacked)"
# ══════════════════════════════════════════════════════════════════════════════

def _synonym_match(text_lower: str, already_found: list[str]) -> list[str]:
    """
    Check if any synonym of a keyword is in the text.
    Only triggers if the base keyword wasn't already found by exact match.

    Example:
      text = "the server was compromised by threat actors"
      "hacked" not in text → check synonyms → "compromised" IS in text → match 
      reports as: "compromised (= hacked)"
    """
    found = []
    already_lower = {k.lower() for k in already_found}

    for base_keyword, synonyms in SYNONYM_GROUPS.items():
        if base_keyword.lower() in already_lower:
            continue  # already caught by exact match, skip

        for syn in synonyms:
            if syn.lower() in text_lower:
                found.append(f"{syn} (={base_keyword})")
                break  # one synonym per group is enough

    return found


# ══════════════════════════════════════════════════════════════════════════════
# METHOD 4 — Fuzzy match
# text    = "d4ta l3ak from hdfc bank"
# keyword = "data leak"
# similarity score = 83%  → above threshold of 82% reported as "~data leak"
# ══════════════════════════════════════════════════════════════════════════════

def _fuzzy_match(text_lower: str, already_found: list[str]) -> list[str]:
    """
    Slide a window across the text and check similarity to each keyword.
    Catches typos, leet speak, deliberate obfuscation.

    Example:
      keyword = "data leak"  (9 chars)
      window  = "d4ta l3ak"  (9 chars)
      score   = fuzz.ratio("data leak", "d4ta l3ak") = 83 → above threshold 
      reports as: "~data leak"

    Only runs on keywords NOT already found by exact match (saves time).
    """
    already_lower = {k.lower() for k in already_found}
    found = []

    for kw in KEYWORDS:
        kw_lower = kw.lower()
        if kw_lower in already_lower:
            continue  # skip already found

        kw_len = len(kw_lower)
        if kw_len < 4:
            continue  # too short to fuzzy match reliably

        # Slide window of keyword length (+2 tolerance) across text
        step = max(1, kw_len // 3)
        for i in range(0, max(1, len(text_lower) - kw_len + 3), step):
            chunk = text_lower[i: i + kw_len + 2]
            if not chunk:
                continue
            score = fuzz.ratio(kw_lower, chunk)
            if score >= FUZZY_THRESHOLD:
                fuzzy_str = f"~{kw}"
                if fuzzy_str not in found:
                    found.append(fuzzy_str)
                break  # one match per keyword is enough

    return found


# ══════════════════════════════════════════════════════════════════════════════
# METHOD 5 — Regex pattern match
# finds IP addresses, CVEs, record counts, onion links, prices for data, paste sites
# text = "selling 50,000 user records, CVE-2024-1234, contact @leakchannel"
# → catches "50,000 user records"  (record_count)
# → catches "CVE-2024-1234"        (cve_id)
# → catches "@leakchannel"         (leak_channel)
# ══════════════════════════════════════════════════════════════════════════════

def _regex_match(text: str) -> list[dict]:
    """
    Run all regex patterns against the original text.
    Returns list of {type, value} dicts.

    Example:
      text = "leaked 50,000 user records from CVE-2024-1234"
      → [{"type": "record_count", "value": "50,000 user records"},
         {"type": "cve_id",       "value": "CVE-2024-1234"}]
    """
    found = []
    for pattern, label in REGEX_PATTERNS:
        matches = pattern.findall(text)
        for m in matches[:3]:  # cap at 3 per pattern
            found.append({"type": label, "value": m.strip()})
    return found


# ══════════════════════════════════════════════════════════════════════════════
# MAIN FILTER FUNCTION — replaces the old keyword_prefilter()
# ══════════════════════════════════════════════════════════════════════════════

def keyword_prefilter(message_data: dict) -> dict | None:
    """
    Runs all 5 keyword search methods on the message.
    Returns enriched dict if any method fires, or None to drop the message.
    """
    text       = message_data["text"]
    text_lower = text.lower()
    words      = text_lower.split()

    # ── Run all 5 methods ─────────────────────────────────────────────────────
    exact     = _exact_match(text_lower)
    proximity = _proximity_match(words) # is "database" within 6 words
    synonyms  = _synonym_match(text_lower, exact) # "compromised" → FOUND   reported as "compromised (=hacked)"
    fuzzy     = _fuzzy_match(text_lower, exact) # d4ta l3ak from hdfc bank
    regex     = _regex_match(text)

    # ── Drop if NOTHING matched ───────────────────────────────────────────────
    all_text_matches = exact + proximity + synonyms + fuzzy
    if not all_text_matches and not regex:
        return None  # not worth a Gemini API call

    # ── High-risk subset ──────────────────────────────────────────────────────
    high_risk = [kw for kw in exact if kw.lower() in {h.lower() for h in HIGH_RISK_KEYWORDS}]

    # ── Debug print (remove in production) ───────────────────────────────────
    if all_text_matches or regex:
        print(f"\n  🔍 Keyword matches for msg {message_data.get('message_id')}:")
        if exact:     print(f"     Exact    : {exact}")
        if proximity: print(f"     Proximity: {proximity}")
        if synonyms:  print(f"     Synonyms : {synonyms}")
        if fuzzy:     print(f"     Fuzzy    : {fuzzy}")
        if regex:     print(f"     Regex    : {[r['type']+':'+r['value'][:30] for r in regex]}")

    return {
        **message_data,
        "exact_keywords":     exact,
        "proximity_matches":  proximity,
        "synonym_matches":    synonyms,
        "fuzzy_matches":      fuzzy,
        "regex_matches":      regex,
        "high_risk_keywords": high_risk,
        # Combined list for easy display
        "all_matches":        all_text_matches,
    }