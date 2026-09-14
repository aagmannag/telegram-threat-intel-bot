import json
import os

DATA_FOLDER = "data"
OUTPUT_FILE = os.path.join(DATA_FOLDER, "output.json")

_seen_ids: set = set()
_initialized: bool = False


def _ensure_initialized():
    global _initialized
    if _initialized:
        return
    _initialized = True
    if not os.path.exists(OUTPUT_FILE):
        return
    try:
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            records = json.load(f)
        for r in records:
            _seen_ids.add((r.get("channel_id"), r.get("message_id")))
    except Exception as e:
        print(f"⚠️  Could not load existing output.json: {e}")


def init_seen_ids():
    _ensure_initialized()
    print(f"📂 Loaded {len(_seen_ids)} existing records for deduplication.")


def is_duplicate(channel_id, message_id) -> bool:
    _ensure_initialized()
    return (channel_id, message_id) in _seen_ids


def save_to_json(data: dict) -> bool:
    _ensure_initialized()
    key = (data.get("channel_id"), data.get("message_id"))
    if key in _seen_ids:
        return False

    os.makedirs(DATA_FOLDER, exist_ok=True)
    existing = []
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except Exception:
            existing = []

    existing.append(data)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=4, ensure_ascii=False)

    _seen_ids.add(key)
    return True