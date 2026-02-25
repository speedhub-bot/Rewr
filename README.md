# Ultimate Checker Bot

This bot is optimized for deployment on [Railway](https://railway.app/).

## Setup Instructions

### 1. Environment Variables
Set the following environment variables in your Railway project:
- `BOT_TOKEN`: Your Telegram Bot Token from @BotFather.
- `ADMIN_ID`: Your Telegram User ID (e.g., `5944410248`).

### 2. Deployment
- The bot uses a `Procfile` to define the worker process.
- Railway will automatically detect the `Procfile` and start the bot as a worker.
- Make sure to use the `python-3.11` runtime (as specified in `runtime.txt`).

### 3. Persistence
- The bot uses SQLite for storage (`ultimate.db`).
- By default, Railway's filesystem is ephemeral. To persist user data and credits across restarts, you should mount a **Railway Volume** at `/app` (or change the `DB_FILE` path in `ultimate_bot.py` to point to a mounted volume).

## Commands
- `/start` - Start the bot
- `/check` - Check accounts (email:password)
- `/settings` - Configure checker threads and features
- `/admin` - Admin panel (Admin only)
- `/stats` - View your statistics
