# 🛡️ Telegram Threat Intelligence Bot

A real-time **Cyber Threat Intelligence (CTI)** tool that monitors Telegram channels, filters messages using multi-layer keyword matching, classifies threats using **Google Gemini AI**, and visualizes results on an interactive **Streamlit dashboard**.

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Running the Project](#-running-the-project)
- [Project Structure](#-project-structure)
- [How It Works](#-how-it-works)

---

## ✨ Features

- 📡 **Live Telegram monitoring** — listens to all joined channels in real-time
- 🔍 **Multi-layer keyword filtering** — exact match, proximity, synonym, fuzzy, and regex
- 🌐 **Auto language detection & translation** via Gemini AI
- 🤖 **AI-powered threat classification** — identifies threat type, confidence, and reasoning
- 🧩 **Entity extraction** — IPs, URLs, orgs, countries, tools, threat actors
- 📊 **Risk scoring** — CRITICAL / HIGH / MEDIUM / LOW
- 💾 **History scraping** — scrapes last N messages from all channels on startup
- 📈 **Interactive dashboard** — visualize threats with charts and filters

---

## 🏗️ Architecture

```
python -m app.main
        │
        ├─ 1. telegram_client.py  → connects to Telegram using API credentials
        ├─ 2. storage.py          → loads existing seen message IDs from disk
        ├─ 3. scraper.py          → scrapes history (last 500 msgs per channel)
        │       └─ chain.py → run_pipeline()
        │               ├─ Step 1: keyword_prefilter()   [FREE — no API cost]
        │               ├─ Step 2: detect_and_translate() [Gemini API #1]
        │               ├─ Step 3: classify_threat()      [Gemini API #2]
        │               ├─ Step 4: extract_entities()     [Gemini API #3]
        │               ├─ Step 5: summarize_message()    [Gemini API #4]
        │               ├─ Step 6: final_risk_score()     [pure logic]
        │               └─ Step 7: build_output()         → saved to output.json
        └─ 4. live listener → same pipeline for every new incoming message
```

---

## ✅ Prerequisites

- Python **3.10+**
- A **Telegram account** (not a bot token — a real user account)
- A **Google Gemini API key**

---

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

### 3. Activate the virtual environment

**Windows:**
```bash
venv\Scripts\activate
```

**macOS / Linux:**
```bash
source venv/bin/activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

---

## ⚙️ Configuration

### 1. Copy the example environment file

```bash
cp .env.example .env
```

### 2. Fill in your credentials in `.env`

```env
API_ID=your_telegram_api_id
API_HASH=your_telegram_api_hash
PHONE_NUMBER=+1234567890
GEMINI_API_KEY=your_gemini_api_key_here
HISTORY_LIMIT=500
SCRAPE_DELAY=1.5
```

**Where to get credentials:**
| Variable | Where to get it |
|---|---|
| `API_ID` & `API_HASH` | [my.telegram.org](https://my.telegram.org) → "API development tools" |
| `PHONE_NUMBER` | Your Telegram account phone number (with country code) |
| `GEMINI_API_KEY` | [aistudio.google.com](https://aistudio.google.com/app/apikey) |

> ⚠️ **Never commit your `.env` file to GitHub.** It is already listed in `.gitignore`.

---

## ▶️ Running the Project

The project has **two components** that run separately (open two terminals).

### Terminal 1 — Start the Bot (scraper + live listener)

```bash
# Make sure your venv is activated first
python -m app.main
```

On first run, Telegram will ask for your **phone number** and a **verification code** sent to your Telegram app. After that, a `session.session` file is saved locally so you won't need to log in again.

**Expected output:**
```
✅ Telegram client started
📂 Loaded 0 existing records
🔄 Syncing dialogs …
🔍 Scraping history from X channels …
📡 Gemini-powered Bot Listening for new messages …
```

### Terminal 2 — Start the Dashboard

```bash
# Make sure your venv is activated first
streamlit run dashboard.py
```

Then open your browser at **http://localhost:8501**

---

## 📁 Project Structure

```
├── app/
│   ├── main.py               # Entry point — boots bot and live listener
│   ├── config.py             # Loads environment variables from .env
│   ├── telegram_client.py    # Telegram connection (Telethon)
│   ├── scraper.py            # Scrapes message history from channels
│   ├── chain.py              # Full AI pipeline (7 steps)
│   ├── keyword_prefilter.py  # Multi-layer keyword matching (no API cost)
│   ├── keywords.py           # Keyword and pattern definitions
│   └── storage.py            # Reads/writes data/output.json
├── data/
│   └── output.json           # Saved threat records (auto-created, git-ignored)
├── dashboard.py              # Streamlit dashboard UI
├── requirements.txt          # Python dependencies
├── .env.example              # Template for environment variables
└── .gitignore
```

---

## 🔄 How It Works

Each message goes through a **7-step pipeline** in `chain.py`:

| Step | Function | Description | API Cost |
|------|----------|-------------|----------|
| 1 | `keyword_prefilter()` | Multi-layer keyword filter — drops irrelevant messages | Free |
| 2 | `detect_and_translate()` | Detects language; translates to English if needed | Gemini #1 |
| 3 | `classify_threat()` | Classifies threat type and confidence; drops noise | Gemini #2 |
| 4 | `extract_entities()` | Extracts IPs, URLs, orgs, countries, tools, actors | Gemini #3 |
| 5 | `summarize_message()` | Generates a 2-sentence analyst summary | Gemini #4 |
| 6 | `final_risk_score()` | Combines all signals → CRITICAL/HIGH/MEDIUM/LOW | Free |
| 7 | `build_output()` | Assembles the final structured record | Free |

Messages that don't pass the keyword filter or are classified as noise are **dropped early** to minimize API calls.

---

## 📄 License

This project is for educational and research purposes.