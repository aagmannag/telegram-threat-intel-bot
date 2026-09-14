import asyncio
from telethon import events

from app.telegram_client import client, start_client
from app.chain import run_pipeline
from app.storage import save_to_json, init_seen_ids
from app.scraper import scrape_history


# ── Live listener ──────────────────────────────────────────────────────────────

@client.on(events.NewMessage(incoming=True))
async def handler(event):
    message = event.message
    if not message.text:
        return

    chat = await event.get_chat()
    channel_name = getattr(chat, "title", "Private/Saved")

    print(f"\n📩 New message | {channel_name} | {message.text[:80]}")

    message_data = {
        "channel_name": channel_name,
        "channel_id": event.chat_id,
        "message_id": message.id,
        "text": message.text,
        "timestamp": str(message.date),
    }

    result = await run_pipeline(message_data)

    if result:
        saved = save_to_json(result)
        if saved:
            level = result["risk_level"]
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(level, "⚪")
            print(f"\n{icon} {level} THREAT DETECTED")
            print(f"   Channel   : {result['channel_name']}")
            print(f"   Type      : {result['threat_type']}")
            print(f"   Keywords  : {result['exact_keywords']}")
            print(f"   Language  : {result['original_language']}")
            print(f"   Summary   : {result['summary']}")
            print(f"   Entities  : {result['entities']}")
            print(f"   Score     : {result['risk_score']}")
            print("=" * 60)


# ── Boot ───────────────────────────────────────────────────────────────────────

async def main():
    await start_client()
    init_seen_ids()

    print("🔄 Syncing dialogs …")
    await client.get_dialogs()

    await scrape_history()

    print("📡 Gemini-powered Bot Listening for new messages …\n")
    await client.run_until_disconnected()


if __name__ == "__main__":
    asyncio.run(main())