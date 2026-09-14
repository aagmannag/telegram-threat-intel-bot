from telethon import TelegramClient
from app.config import API_ID, API_HASH

client = TelegramClient("session", API_ID, API_HASH)

async def start_client():
    await client.start()
    print("✅ Telegram client started")