import os
from dotenv import load_dotenv

load_dotenv()

API_ID = int(os.getenv("API_ID"))
API_HASH = os.getenv("API_HASH")
PHONE_NUMBER = os.getenv("PHONE_NUMBER")

# Gemini
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# Scraping settings
HISTORY_LIMIT = int(os.getenv("HISTORY_LIMIT", 500))
SCRAPE_DELAY = float(os.getenv("SCRAPE_DELAY", 1.5))

# Pin specific channels (leave empty = auto-discover all)
CHANNELS = [
            "WhiteRoseIntel",
            "LunarisSec",
            "The BlackH4t MD-Ghost",
            "RuskiNet Group",
            "SILENT PUNISHER PK"
            ]