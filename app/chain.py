"""
chain.py — Fixed LangChain + Gemini pipeline with proper multi-keyword search

Changes:
  - Removed old keyword_prefilter() — now imported from keyword_prefilter.py
  - Removed FUZZY_PATTERNS import — handled inside keyword_prefilter.py
  - build_output() updated to include proximity_matches and synonym_matches
  - final_risk_score() updated to score proximity + synonym matches
"""

import json
import re
from datetime import datetime

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate

# ── NEW: import multi-keyword search from its own file ─────────────────────────
from app.keyword_prefilter import keyword_prefilter
from app.config import GEMINI_API_KEY

# ── LLM setup ──────────────────────────────────────────────────────────────────
llm = ChatGoogleGenerativeAI(
    model="gemini-2.5-flash",
    google_api_key=GEMINI_API_KEY,
    temperature=0.1,
)

_GEMINI_UNAVAILABLE = False


def _is_quota_error(exc: Exception) -> bool:
    message = str(exc).lower()
    return (
        "resource_exhausted" in message
        or "quota" in message
        or "429" in message
        or "retry in" in message
    )


def _disable_gemini(exc: Exception) -> None:
    global _GEMINI_UNAVAILABLE
    if not _GEMINI_UNAVAILABLE:
        print(f"    ⚠️  Gemini unavailable; using keyword fallback: {exc}")
    _GEMINI_UNAVAILABLE = True


def _heuristic_threat_type(data: dict) -> str:
    signal_text = " ".join(
        [
            " ".join(data.get("exact_keywords", [])),
            " ".join(data.get("high_risk_keywords", [])),
            " ".join(data.get("proximity_matches", [])),
            " ".join(data.get("synonym_matches", [])),
            " ".join(data.get("fuzzy_matches", [])),
            " ".join(match.get("type", "") for match in data.get("regex_matches", []) if isinstance(match, dict)),
        ]
    ).lower()

    if any(token in signal_text for token in ("ransomware", "ransom", "encrypted files")):
        return "Ransomware"
    if any(token in signal_text for token in ("credential", "password", "combo list", "fullz", "login dump", "accounts leaked")):
        return "CredentialLeak"
    if any(token in signal_text for token in ("database", "data leak", "data breach", "dump", "records", "exfiltrated")):
        return "DataBreach"
    if any(token in signal_text for token in ("exploit", "cve", "0day", "zero day", "rce")):
        return "Exploit"
    if any(token in signal_text for token in ("ddos", "traffic attack", "amplification")):
        return "DDoS"
    if any(token in signal_text for token in ("defacement", "defaced", "homepage hacked", "site defaced")):
        return "Defacement"
    if any(token in signal_text for token in ("malware", "trojan", "rootkit", "backdoor", "payload", "dropper")):
        return "Malware"
    if any(token in signal_text for token in ("phishing", "stealer", "keylogger")):
        return "PhishingKit"
    if any(token in signal_text for token in ("hacked", "breached", "pwned", "compromised", "opindia")):
        return "Hacktivism"
    return "Other"


def _heuristic_classification(data: dict) -> dict:
    has_high_risk = bool(data.get("high_risk_keywords"))
    has_exact = len(data.get("exact_keywords", [])) >= 2
    has_proximity = len(data.get("proximity_matches", [])) >= 1
    has_synonym = len(data.get("synonym_matches", [])) >= 1
    has_fuzzy = len(data.get("fuzzy_matches", [])) >= 2
    has_regex = len(data.get("regex_matches", [])) >= 1

    is_threat = has_high_risk or has_exact or has_proximity or has_synonym or (has_fuzzy and has_regex)
    confidence = 0.0
    if has_high_risk:
        confidence = 0.92
    elif has_proximity or has_synonym:
        confidence = 0.83
    elif has_exact:
        confidence = 0.75
    elif has_fuzzy and has_regex:
        confidence = 0.68
    elif has_regex:
        confidence = 0.55

    return {
        **data,
        "is_threat": is_threat,
        "threat_type": _heuristic_threat_type(data) if is_threat else "Noise",
        "classification_confidence": confidence,
        "classification_reasoning": "Gemini quota exhausted — keyword fallback used",
    }


# ══════════════════════════════════════════════════════════════════════════════
# HELPER — strip markdown fences from Gemini JSON responses
# ══════════════════════════════════════════════════════════════════════════════

def _parse_gemini_json(raw: str) -> dict:
    text = raw.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return json.loads(text.strip())


# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 — Language detection + translation
# ══════════════════════════════════════════════════════════════════════════════

_lang_prompt = ChatPromptTemplate.from_messages([
    ("system",
     """You are a language detection and translation assistant.
You MUST respond with ONLY a raw JSON object. No markdown. No code fences. No explanation.

Respond exactly like this:
{{"language": "Russian", "language_code": "ru", "english_text": "translated text here"}}

Rules:
- Detect the language of the input text
- If the text is NOT English, translate it to English
- If the text IS English, return it unchanged in english_text
- Never include markdown formatting in your response"""),
    ("human", "{text}"),
])


async def detect_and_translate(data: dict) -> dict:
    text = data["text"]

    # Heuristic: if >85% ASCII, it's likely English — skip API call
    ascii_ratio = sum(1 for c in text if ord(c) < 128) / max(len(text), 1)
    if ascii_ratio > 0.85:
        return {
            **data,
            "language":        "English",
            "language_code":   "en",
            "translated_text": text,
        }

    if _GEMINI_UNAVAILABLE:
        return {
            **data,
            "language":        "Unknown",
            "language_code":   "??",
            "translated_text": text,
        }

    try:
        response = await llm.ainvoke(
            _lang_prompt.format_messages(text=text[:1500])
        )
        raw = response.content
        print(f"    🌐 Lang raw response: {raw[:100]}")

        result = _parse_gemini_json(raw)
        return {
            **data,
            "language":        result.get("language", "Unknown"),
            "language_code":   result.get("language_code", "??"),
            "translated_text": result.get("english_text", text),
        }

    except Exception as e:
        print(f"    ⚠️  Translation error: {e}")
        if _is_quota_error(e):
            _disable_gemini(e)
            return {
                **data,
                "language":        "Unknown",
                "language_code":   "??",
                "translated_text": text,
            }
        try:
            simple = await llm.ainvoke(
                f"Translate this text to English. Reply with ONLY the translation:\n\n{text[:1000]}"
            )
            return {
                **data,
                "language":        "Unknown",
                "language_code":   "??",
                "translated_text": simple.content.strip(),
            }
        except Exception as e2:
            print(f"    ⚠️  Fallback translation failed: {e2}")
            return {**data, "language": "Unknown", "language_code": "??", "translated_text": text}


# ══════════════════════════════════════════════════════════════════════════════
# STEP 3 — Threat classification
# ══════════════════════════════════════════════════════════════════════════════

_classify_prompt = ChatPromptTemplate.from_messages([
    ("system",
     """You are a cyber threat intelligence analyst.
Analyze the message and classify it. You MUST respond with ONLY a raw JSON object. No markdown. No code fences.

Respond exactly like this:
{{"is_threat": true, "threat_type": "DataBreach", "confidence": 0.95, "reasoning": "one sentence"}}

threat_type must be one of: DataBreach, Ransomware, DDoS, Defacement, Malware, Exploit, PhishingKit, CredentialLeak, Hacktivism, ThreatActor, Noise, Other

A message IS a threat if it: claims credit for an attack, shares stolen data, sells exploits, announces active campaigns, shares hacking tools.
A message is NOT a threat (Noise) if it is: language lessons, news discussion, memes, ads, general tech talk, education content."""),
    ("human", "{text}"),
])


async def classify_threat(data: dict) -> dict:
    text_to_analyze = data.get("translated_text", data["text"])

    if _GEMINI_UNAVAILABLE:
        return _heuristic_classification(data)

    try:
        response = await llm.ainvoke(
            _classify_prompt.format_messages(text=text_to_analyze[:2000])
        )
        raw = response.content
        print(f"    🔍 Classify raw response: {raw[:100]}")

        result = _parse_gemini_json(raw)
        return {
            **data,
            "is_threat":                 result.get("is_threat", False),
            "threat_type":               result.get("threat_type", "Unknown"),
            "classification_confidence": float(result.get("confidence", 0.0)),
            "classification_reasoning":  result.get("reasoning", ""),
        }

    except Exception as e:
        print(f"    ⚠️  Classification error: {e}")
        if _is_quota_error(e):
            _disable_gemini(e)
        has_high_risk = bool(data.get("high_risk_keywords"))
        has_exact     = len(data.get("exact_keywords", [])) >= 2
        has_proximity = len(data.get("proximity_matches", [])) >= 1
        return _heuristic_classification({
            **data,
            "is_threat": has_high_risk or has_exact or has_proximity,
        })


# ══════════════════════════════════════════════════════════════════════════════
# STEP 4 — Entity extraction
# ══════════════════════════════════════════════════════════════════════════════

_entity_prompt = ChatPromptTemplate.from_messages([
    ("system",
     """You are a cyber threat intelligence entity extractor.
You MUST respond with ONLY a raw JSON object. No markdown. No code fences.

Respond exactly like this:
{{"ips": [], "urls": [], "organizations": [], "countries": [], "attack_tools": [], "data_types": [], "record_count": null, "threat_actor": null}}

Extract from the message:
- ips: IP addresses
- urls: URLs or suspicious domains
- organizations: targeted companies/orgs
- countries: affected countries
- attack_tools: malware names, exploit names, tools
- data_types: types of stolen data (passwords, credit cards, etc.)
- record_count: number of records if mentioned
- threat_actor: hacker name or group name if mentioned

Return empty lists [] if nothing found."""),
    ("human", "{text}"),
])


async def extract_entities(data: dict) -> dict:
    if not data.get("is_threat") and data.get("classification_confidence", 0) > 0.85:
        return {**data, "entities": {}}

    text_to_analyze = data.get("translated_text", data["text"])

    if _GEMINI_UNAVAILABLE:
        entities = {"ips": [], "urls": [], "organizations": [], "countries": [], "attack_tools": [], "data_types": [], "record_count": None, "threat_actor": None}
        for match in data.get("regex_matches", []):
            if not isinstance(match, dict):
                continue
            match_type = match.get("type", "")
            value = match.get("value", "")
            if match_type == "ip_address" and value not in entities["ips"]:
                entities["ips"].append(value)
            elif match_type in {"suspicious_domain", "onion_link", "paste_site"} and value not in entities["urls"]:
                entities["urls"].append(value)
            elif match_type == "record_count":
                entities["record_count"] = value
        return {**data, "entities": entities}

    try:
        response = await llm.ainvoke(
            _entity_prompt.format_messages(text=text_to_analyze[:2000])
        )
        entities = _parse_gemini_json(response.content)

        # Merge regex-found IPs/URLs from keyword_prefilter
        for match in data.get("regex_matches", []):
            val = match.get("value", "") if isinstance(match, dict) else str(match)
            if re.match(r"\d+\.\d+\.\d+\.\d+", val):
                if val not in entities.get("ips", []):
                    entities.setdefault("ips", []).append(val)
            elif re.match(r"https?://", val):
                if val not in entities.get("urls", []):
                    entities.setdefault("urls", []).append(val)

        return {**data, "entities": entities}

    except Exception as e:
        print(f"    ⚠️  Entity extraction error: {e}")
        if _is_quota_error(e):
            _disable_gemini(e)
        return {**data, "entities": {}}


# ══════════════════════════════════════════════════════════════════════════════
# STEP 5 — Summarization
# ══════════════════════════════════════════════════════════════════════════════

_summarize_prompt = ChatPromptTemplate.from_messages([
    ("system",
     """You are a cyber threat intelligence summarizer.
Write exactly 2 sentences summarizing this message for a security analyst.
Be specific: include WHO was attacked, WHAT data was leaked, and HOW MANY records if mentioned.
Respond with ONLY the 2-sentence summary. No JSON. No bullet points. No markdown."""),
    ("human", "{text}"),
])


async def summarize_message(data: dict) -> dict:
    if not data.get("is_threat") and data.get("classification_confidence", 0) > 0.85:
        return {**data, "summary": "Not a cyber threat — classified as noise."}

    text_to_analyze = data.get("translated_text", data["text"])

    if _GEMINI_UNAVAILABLE:
        return {**data, "summary": text_to_analyze[:200]}

    try:
        response = await llm.ainvoke(
            _summarize_prompt.format_messages(text=text_to_analyze[:2000])
        )
        summary = response.content.strip()
        if summary.startswith("{") or summary.startswith("```"):
            summary = re.sub(r"[{}\"`]", "", summary)[:300]
        print(f"    📝 Summary: {summary[:80]}")
        return {**data, "summary": summary}

    except Exception as e:
        print(f"    ⚠️  Summarization error: {e}")
        if _is_quota_error(e):
            _disable_gemini(e)
        return {**data, "summary": text_to_analyze[:200]}


# ══════════════════════════════════════════════════════════════════════════════
# STEP 6 — Final risk scoring (updated for new match types)
# ══════════════════════════════════════════════════════════════════════════════

def final_risk_score(data: dict) -> dict:
    score = 0

    # Exact keyword signals
    score += len(data.get("exact_keywords", [])) * 2
    score += len(data.get("high_risk_keywords", [])) * 5

    # NEW — proximity matches are strong signal (two dangerous words near each other)
    score += len(data.get("proximity_matches", [])) * 4

    # NEW — synonym matches
    score += len(data.get("synonym_matches", [])) * 2

    # NEW — fuzzy matches (weaker signal — might be noise)
    score += len(data.get("fuzzy_matches", [])) * 1

    # NEW — regex matches scored by type
    for match in data.get("regex_matches", []):
        match_type = match.get("type", "") if isinstance(match, dict) else ""
        if match_type in ("record_count", "cve_id", "data_for_sale"):
            score += 4  # high signal
        elif match_type in ("onion_link", "paste_site", "data_size"):
            score += 3
        else:
            score += 1  # ip, url, suspicious domain

    # LLM classification
    if data.get("is_threat"):
        score += 10
    score += int(data.get("classification_confidence", 0) * 10)

    # Entity richness
    entities = data.get("entities", {})
    score += len(entities.get("ips", [])) * 2
    score += len(entities.get("organizations", [])) * 2
    score += 3 if entities.get("record_count") else 0
    score += 3 if entities.get("threat_actor") else 0
    score += len(entities.get("data_types", [])) * 2

    # Threat type bonus
    critical_types = {"Ransomware", "CredentialLeak", "Exploit", "DataBreach"}
    if data.get("threat_type") in critical_types:
        score += 8

    if score >= 35:
        risk_level = "CRITICAL"
    elif score >= 22:
        risk_level = "HIGH"
    elif score >= 12:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {**data, "risk_level": risk_level, "risk_score": score}


# ══════════════════════════════════════════════════════════════════════════════
# STEP 7 — Clean output (updated to include all new match fields)
# ══════════════════════════════════════════════════════════════════════════════

def build_output(data: dict) -> dict:
    return {
        "channel_name":              data["channel_name"],
        "channel_id":                data["channel_id"],
        "message_id":                data["message_id"],
        "timestamp":                 data["timestamp"],
        "collected_at":              str(datetime.utcnow()),
        "original_language":         data.get("language", "English"),
        "language_code":             data.get("language_code", "en"),
        "message_text":              data["text"],
        "translated_text":           data.get("translated_text", data["text"]),
        "summary":                   data.get("summary", ""),

        # All keyword match types
        "exact_keywords":            data.get("exact_keywords", []),
        "high_risk_keywords":        data.get("high_risk_keywords", []),
        "proximity_matches":         data.get("proximity_matches", []),   # NEW
        "synonym_matches":           data.get("synonym_matches", []),     # NEW
        "fuzzy_matches":             data.get("fuzzy_matches", []),       # NEW
        "regex_matches":             data.get("regex_matches", []),
        "all_matches":               data.get("all_matches", []),         # NEW

        # LLM classification
        "is_threat":                 data.get("is_threat", False),
        "threat_type":               data.get("threat_type", "Unknown"),
        "classification_confidence": data.get("classification_confidence", 0.0),
        "classification_reasoning":  data.get("classification_reasoning", ""),

        # Entities
        "entities":                  data.get("entities", {}),

        # Risk
        "risk_level":                data.get("risk_level", "LOW"),
        "risk_score":                data.get("risk_score", 0),
    }


# ══════════════════════════════════════════════════════════════════════════════
# FULL ASYNC PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

async def run_pipeline(message_data: dict) -> dict | None:

    # Step 1 — multi-keyword pre-filter (free, no API call)
    data = keyword_prefilter(message_data)
    if data is None:
        return None

    # Step 2 — detect language + translate
    data = await detect_and_translate(data)

    # Step 3 — classify: real threat or noise?
    data = await classify_threat(data)

    # Drop confirmed noise with no high-risk / proximity keywords
    if (not data.get("is_threat")
            and data.get("classification_confidence", 0) > 0.80
            and not data.get("high_risk_keywords")
            and not data.get("proximity_matches")):
        print(f"    🗑️  Dropped as noise: {data['channel_name']} — "
              f"{data.get('classification_reasoning', '')}")
        return None

    # Step 4 — extract entities
    data = await extract_entities(data)

    # Step 5 — summarize
    data = await summarize_message(data)

    # Step 6 — risk score
    data = final_risk_score(data)

    # Step 7 — build clean output
    return build_output(data)