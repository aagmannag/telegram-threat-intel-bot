# ── Tier 1: Exact / substring keywords ────────────────────────────────────────
KEYWORDS = [
    # Data breaches
    "data leak", "leak data", "database dump", "db dump", "db leak",
    "data breach", "breach", "leaked database", "dump", "combo list",
    "credential dump", "password leak", "password dump",
    "credit card leak", "card dump", "cvv dump", "fullz",
    # Attacks
    "hacked", "hacked sites", "got hacked", "we hacked",
    "cyber attack", "cyberattack", "ddos", "deface", "defacement",
    "ransomware", "malware", "trojan", "rat ", "botnet",
    "zero day", "0day", "0-day", "exploit", "vulnerability",
    "rce", "sqli", "xss", "lfi", "rfi",
    # Dark web / underground
    "dark web", "darkweb", "deep web", "telegram leak",
    "source code leak", "source code dump",
    # Threat actors
    "opindia", 
]

# ── Tier 2: HIGH risk — auto-elevates risk score ──────────────────────────────
HIGH_RISK_KEYWORDS = [
    "ransomware", "zero day", "0day", "credit card leak", "card dump",
    "cvv dump", "fullz", "database dump", "db dump", "source code leak",
    "password leak", "password dump", "credential dump", "rce",
]

# ── Tier 3: Fuzzy patterns (regex) ────────────────────────────────────────────
# These catch variations the exact list would miss
import re

FUZZY_PATTERNS = [
    re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),          # IP address
    re.compile(r"https?://\S+"),                                        # URLs
    re.compile(r"\b\w+\.(?:onion|to|cc|su|pw)\b", re.I),              # suspicious TLDs
    re.compile(r"\bbypass\b", re.I),
    re.compile(r"\bshell\b", re.I),
    re.compile(r"\bstealer\b", re.I),
    re.compile(r"\binfostealer\b", re.I),
    re.compile(r"\bphishing\b", re.I),
    re.compile(r"\bspyware\b", re.I),
    re.compile(r"\bkeylogger\b", re.I),
    re.compile(r"\bdata of\s+\d+", re.I),                             # "data of 50000 users"
    re.compile(r"\b\d+[kKmM]?\s+(?:users?|records?|accounts?)\b"),    # "50k users"
    re.compile(r"\bsold\b.{0,30}\b(?:data|creds|accounts)\b", re.I), # "sold ... data"
]