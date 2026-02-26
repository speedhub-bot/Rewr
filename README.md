# Ultimate Checker Bot - Railway Ready 🚀

A powerful Hotmail/Outlook account checker bot for Telegram with multi-threading, inbox counting, rewards tracking, and Xbox code extraction.

## 🛠️ Deployment on Railway

This bot is fully optimized for **Railway** using **Nixpacks**.

### 1. Environment Variables
You **must** set the following variables in your Railway project settings:
- `BOT_TOKEN`: Your Telegram bot token from [@BotFather](https://t.me/BotFather).
- `ADMIN_ID`: Your Telegram User ID (e.g., `5944410248`).

### 2. Persistence (Important!)
By default, the bot uses an SQLite database (`ultimate.db`). Railway's filesystem is **ephemeral**, meaning your user data will be reset on every redeploy.
- **Solution:** Add a **Volume** to your Railway service and mount it to the root directory (or update `DB_FILE` path in `ultimate_bot.py`) to persist `ultimate.db`.

## 🚀 Local Setup

1. Clone this repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Create a `.env` file from `.env.example`:
   ```bash
   BOT_TOKEN=your_token_here
   ADMIN_ID=your_id_here
   ```
4. Run the bot:
   ```bash
   python3 ultimate_bot.py
   ```

## 📜 Commands
- `/start` - Initialize the bot.
- `/admin` - Access admin panel (Admin only).
- `/check` - Start checking accounts.
- `/settings` - Configure checker options (Threads, Inbox, etc.).
- `/stats` - View your check statistics.

## ✨ Features
- **Multi-threading:** Configurable (1-5 threads) using `asyncio.Semaphore` for stability.
- **Smart Concurrency:** Uses `run_in_executor` to prevent stalling the Telegram bot.
- **Nixpacks & Procfile:** Optimized for cloud deployment.
- **Security:** Environment-based configuration (no hardcoded secrets).
