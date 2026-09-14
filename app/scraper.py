"""
scraper.py — Historical scraper using the full async Gemini pipeline.

Uses a bounded queue + worker pattern:
  - 1 producer: iterates messages from Telegram
  - N workers: process messages through the LLM pipeline concurrently
This keeps Telegram streaming fast while LLM calls run in parallel.
"""

import asyncio
from telethon.tl.types import Channel, Chat

from app.telegram_client import client
from app.chain import run_pipeline
from app.storage import save_to_json, is_duplicate
from app.config import HISTORY_LIMIT, SCRAPE_DELAY, CHANNELS

# Number of parallel LLM workers per channel
_LLM_WORKERS = 5

# Max messages queued waiting for LLM (backpressure)
_QUEUE_SIZE = 50


async def _process_worker(queue: asyncio.Queue, results: list, worker_id: int):
    """Pulls message_data off the queue and runs the full pipeline."""
    while True:
        item = await queue.get()
        if item is None:  # poison pill
            queue.task_done()
            break
        try:
            result = await run_pipeline(item)
            if result:
                saved = save_to_json(result)
                if saved:
                    results.append(result)
                    print(f"    💾 [{worker_id}] Saved: [{result['risk_level']}] "
                          f"{result['threat_type']} — {result['summary'][:80]}…")
        except Exception as e:
            print(f"    ⚠️  Worker {worker_id} error: {e}")
        finally:
            queue.task_done()


async def _scrape_channel(entity, semaphore: asyncio.Semaphore) -> int:
    """Scrape one channel: stream messages → queue → parallel LLM workers."""
    async with semaphore:
        name = getattr(entity, "title", str(entity.id))
        channel_id = entity.id
        print(f"\n  ⏳ Scraping '{name}' …")

        queue = asyncio.Queue(maxsize=_QUEUE_SIZE)
        results = []

        # Start LLM workers
        workers = [
            asyncio.create_task(_process_worker(queue, results, i))
            for i in range(_LLM_WORKERS)
        ]

        # Stream messages from Telegram into the queue
        scanned = 0
        skipped = 0
        async for message in client.iter_messages(entity, limit=HISTORY_LIMIT):
            if not message.text:
                continue
            if is_duplicate(channel_id, message.id):
                skipped += 1
                continue

            await queue.put({
                "channel_name": name,
                "channel_id": channel_id,
                "message_id": message.id,
                "text": message.text,
                "timestamp": str(message.date),
            })
            scanned += 1

        # Send poison pills to stop workers
        for _ in range(_LLM_WORKERS):
            await queue.put(None)

        # Wait for all workers to finish
        await asyncio.gather(*workers)

        saved = len(results)
        print(f"  ✅ '{name}': scanned {scanned}, saved {saved} threats, skipped {skipped} duplicates.")
        await asyncio.sleep(SCRAPE_DELAY)
        return saved


async def scrape_history():
    if HISTORY_LIMIT == 0:
        print("⏭️  HISTORY_LIMIT=0, skipping historical scrape.")
        return

    print("\n🔍 Starting historical scrape with Gemini pipeline …")

    if CHANNELS:
        entities = []
        for ch in CHANNELS:
            try:
                entities.append(await client.get_entity(ch))
            except Exception as e:
                print(f"  ⚠️  Could not resolve '{ch}': {e}")
    else:
        dialogs = await client.get_dialogs()
        entities = [d.entity for d in dialogs if isinstance(d.entity, (Channel, Chat))]

    print(f"📡 Found {len(entities)} channel(s)/group(s) to scrape.\n")

    # Max 2 channels scraped simultaneously (LLM rate limit awareness)
    semaphore = asyncio.Semaphore(2)
    tasks = [_scrape_channel(entity, semaphore) for entity in entities]
    await asyncio.gather(*tasks)

    print("\n✅ Historical scrape complete.\n")