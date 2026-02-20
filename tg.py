"""
Norman-Earn Telegram Admin Bot
================================
Setup:
1. Message @BotFather on Telegram → /newbot → copy the token
2. Get your Telegram chat ID: message @userinfobot → copy your id
3. Fill in BOT_TOKEN and ADMIN_CHAT_ID below
4. pip install python-telegram-bot sqlalchemy
5. Run: python telegram_bot.py  (keep running alongside app.py)

Commands:
  /start        - Welcome message
  /stats        - Platform overview
  /pending      - List all pending withdrawals
  /user <name>  - Look up a user by username
  /ban <name>   - Ban a user (clears session, locks account)
  /unban <name> - Unban a user
  /setadmin <name> - Give admin flag to a user
  /miners       - Top 10 miners by balance
  /recent       - Last 10 signups
"""

import logging
import sys
import os
import pathlib
from dotenv import load_dotenv
load_dotenv(dotenv_path=pathlib.Path(r'C:/Users/awesome/Desktop/python/website/backend/.env'))
from datetime import datetime
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler,
    ContextTypes, MessageHandler, filters,
)

# ── SQLAlchemy direct DB access (same db as Flask) ──
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# ══════════════════════════════════════════
#  CONFIG — fill these in
# ══════════════════════════════════════════
BOT_TOKEN     = "YOUR_BOT_TOKEN_HERE"       # from @BotFather
ADMIN_CHAT_ID =  123456789                  # your Telegram user ID (integer)
DB_PATH = "sqlite:///C:/Users/awesome/Desktop/python/website/backend/users.db"

# ══════════════════════════════════════════
#  DB SETUP
# ══════════════════════════════════════════
engine = create_engine(
    DB_PATH,
    connect_args={"check_same_thread": False},
)
Session = sessionmaker(bind=engine)

# Silence all logs — only show our own print() messages
logging.basicConfig(level=logging.CRITICAL)
logging.getLogger("httpx").setLevel(logging.CRITICAL)
logging.getLogger("telegram").setLevel(logging.CRITICAL)
logging.getLogger("apscheduler").setLevel(logging.CRITICAL)
log = logging.getLogger(__name__)


# ── Guard: only ADMIN_CHAT_ID can use this bot ──
def admin_only(func):
    async def wrapper(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
        if update.effective_chat.id != ADMIN_CHAT_ID:
            await update.message.reply_text("⛔ Unauthorized.")
            return
        try:
            await func(update, ctx)
        except Exception as e:
            print(f"[BOT ERROR] {func.__name__}: {e}")
            await update.message.reply_text(f"❌ Error: {str(e)}")
    wrapper.__name__ = func.__name__
    return wrapper


def admin_only_callback(func):
    async def wrapper(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
        if update.effective_chat.id != ADMIN_CHAT_ID:
            await update.callback_query.answer("⛔ Unauthorized.")
            return
        try:
            await func(update, ctx)
        except Exception as e:
            print(f"[BOT ERROR] {func.__name__}: {e}")
            await update.callback_query.answer(f"❌ Error: {str(e)}")
    wrapper.__name__ = func.__name__
    return wrapper


def db_query(sql, params=None):
    """Run a SELECT and return all rows as dicts."""
    with engine.connect() as conn:
        result = conn.execute(text(sql), params or {})
        keys = result.keys()
        return [dict(zip(keys, row)) for row in result.fetchall()]


def db_exec(sql, params=None):
    """Run INSERT/UPDATE/DELETE."""
    with engine.begin() as conn:
        conn.execute(text(sql), params or {})


def safe_count(sql, params=None):
    """Run a COUNT query safely, return 0 on any error."""
    try:
        return db_query(sql, params)[0]["c"]
    except Exception:
        return 0

def safe_sum(sql, params=None):
    """Run a SUM query safely, return 0.0 on any error."""
    try:
        return db_query(sql, params)[0]["s"]
    except Exception:
        return 0.0


def fmt_dt(iso):
    if not iso:
        return "—"
    try:
        return datetime.fromisoformat(str(iso)).strftime("%d %b %Y %H:%M")
    except:
        return str(iso)


def network_label(n):
    labels = {
        "usdt_bep20": "USDT BEP-20",
        "usdt_trc20": "USDT TRC-20",
        "usdt_erc20": "USDT ERC-20",
        "btc":        "Bitcoin",
        "bnb":        "BNB",
        "eth":        "Ethereum",
    }
    return labels.get(n, n.upper())


# ══════════════════════════════════════════
#  /start
# ══════════════════════════════════════════
@admin_only
async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "⬡ *Norman-Earn Admin Bot*\n\n"
        "Available commands:\n"
        "📊 /stats — Platform overview\n"
        "💰 /pending — Pending withdrawals\n"
        "👤 /user `<username>` — User lookup\n"
        "🚫 /ban `<username>` — Ban user\n"
        "✅ /unban `<username>` — Unban user\n"
        "⭐ /setadmin `<username>` — Make admin\n"
        "🏆 /miners — Top 10 by balance\n"
        "🆕 /recent — Last 10 signups\n"
        "✏️ /edit `<user>` `<amount>` — Set balance\n",
        parse_mode="Markdown"
    )


# ══════════════════════════════════════════
#  /stats
# ══════════════════════════════════════════
@admin_only
async def cmd_stats(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    users      = safe_count("SELECT COUNT(*) as c FROM user")
    verified   = safe_count("SELECT COUNT(*) as c FROM user WHERE is_verified=1")
    banned     = safe_count("SELECT COUNT(*) as c FROM user WHERE is_banned=1") if _col_exists("is_banned") else 0
    total_gems = safe_sum("SELECT COALESCE(SUM(total_earned),0) as s FROM user")
    total_bal  = safe_sum("SELECT COALESCE(SUM(balance),0) as s FROM user")
    pending_w  = safe_count("SELECT COUNT(*) as c FROM withdrawal_request WHERE status='pending'")
    approved_w = safe_count("SELECT COUNT(*) as c FROM withdrawal_request WHERE status='approved'")
    total_usd  = safe_sum("SELECT COALESCE(SUM(usd_value),0) as s FROM withdrawal_request WHERE status='approved'")
    referrals  = safe_count("SELECT COUNT(*) as c FROM user WHERE referred_by IS NOT NULL AND is_verified=1")

    lines = [
        "📊 *Platform Stats*",
        "",
        f"👥 Total accounts:      `{users}`",
        f"✅ Verified:            `{verified}`",
        f"🚫 Banned:              `{banned}`",
        f"👥 Valid referrals:     `{referrals}`",
        "",
        f"💎 Total gems mined:    `{float(total_gems):.2f}`",
        f"💰 Total balance held:  `{float(total_bal):.2f}`",
        f"💵 Held USD value:      `${float(total_bal)/10:.2f}`",
        "",
        f"🏦 Pending withdrawals: `{pending_w}`",
        f"✅ Approved payouts:    `{approved_w}`",
        f"💵 Total paid out:      `${float(total_usd):.2f}`",
    ]
    await update.message.reply_text("\n".join(lines), parse_mode="Markdown")


def _col_exists(col):
    try:
        db_query(f"SELECT {col} FROM user LIMIT 1")
        return True
    except Exception:
        return False


# ══════════════════════════════════════════
#  /pending — list pending withdrawals
# ══════════════════════════════════════════
@admin_only
async def cmd_pending(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    try:
        rows = db_query(
            "SELECT * FROM withdrawal_request WHERE status='pending' ORDER BY created_at ASC LIMIT 10"
        )
    except Exception:
        await update.message.reply_text("✅ No withdrawals submitted yet.")
        return
    if not rows:
        await update.message.reply_text("✅ No pending withdrawals right now!")
        return

    await update.message.reply_text(
        f"💰 *{len(rows)} Pending Withdrawal(s)*\n_(showing up to 10)_",
        parse_mode="Markdown"
    )

    for r in rows:
        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("✅ Approve", callback_data=f"approve_{r['id']}"),
                InlineKeyboardButton("❌ Reject",  callback_data=f"reject_{r['id']}"),
            ]
        ])
        await update.message.reply_text(
            f"🔔 *Withdrawal #{r['id']}*\n"
            f"{'─'*28}\n"
            f"👤 User:      `{r['username']}`\n"
            f"📧 Email:     `{r['email']}`\n"
            f"🌐 Network:   `{network_label(r['network'])}`\n"
            f"💳 Wallet:    `{r['wallet']}`\n"
            f"💎 Gems:      `{r['gems']:.4f}`\n"
            f"💵 USD Value: `${r['usd_value']:.2f}`\n"
            f"🕐 Requested: `{fmt_dt(r['created_at'])}`\n",
            parse_mode="Markdown",
            reply_markup=keyboard,
        )


# ══════════════════════════════════════════
#  Approve / Reject callback buttons
# ══════════════════════════════════════════
@admin_only_callback
async def handle_callback(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query  = update.callback_query
    await query.answer()
    data   = query.data  # e.g. "approve_7" or "reject_7"
    action, wid = data.split("_", 1)
    wid = int(wid)

    rows = db_query("SELECT * FROM withdrawal_request WHERE id=:id", {"id": wid})
    if not rows:
        await query.edit_message_text("❌ Withdrawal not found.")
        return

    r = rows[0]
    if r["status"] != "pending":
        await query.edit_message_text(
            f"ℹ️ Already processed as *{r['status']}*.",
            parse_mode="Markdown"
        )
        return

    now = datetime.utcnow().isoformat()

    if action == "approve":
        db_exec(
            "UPDATE withdrawal_request SET status='approved', processed_at=:t WHERE id=:id",
            {"t": now, "id": wid}
        )
        await query.edit_message_text(
            f"✅ *Approved* Withdrawal #{wid}\n"
            f"👤 `{r['username']}` · 💵 `${r['usd_value']:.2f}`\n"
            f"🌐 {network_label(r['network'])} → `{r['wallet']}`\n\n"
            f"⚠️ Remember to send the crypto manually!",
            parse_mode="Markdown"
        )

    elif action == "reject":
        # Refund gems back to user balance
        db_exec(
            "UPDATE user SET balance = balance + :gems WHERE username=:u",
            {"gems": r["gems"], "u": r["username"]}
        )
        db_exec(
            "UPDATE withdrawal_request SET status='rejected', processed_at=:t, admin_note='Rejected by admin' WHERE id=:id",
            {"t": now, "id": wid}
        )
        await query.edit_message_text(
            f"❌ *Rejected* Withdrawal #{wid}\n"
            f"👤 `{r['username']}` · 💎 `{r['gems']:.4f}` gems refunded.",
            parse_mode="Markdown"
        )


# ══════════════════════════════════════════
#  /user <username>
# ══════════════════════════════════════════
@admin_only
async def cmd_user(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("Usage: /user `<username>`", parse_mode="Markdown")
        return

    uname = ctx.args[0].strip()
    rows  = db_query("SELECT * FROM user WHERE username=:u", {"u": uname})
    if not rows:
        await update.message.reply_text(f"❌ User `{uname}` not found.", parse_mode="Markdown")
        return

    u = rows[0]

    # Count referrals
    ref_count = db_query(
        "SELECT COUNT(*) as c FROM user WHERE referred_by=:code AND is_verified=1 AND has_iron_pickaxe=1",
        {"code": u["referral_code"]}
    )[0]["c"]

    # Withdrawal history
    try:
        withdrawals = db_query(
            "SELECT COUNT(*) as c, COALESCE(SUM(usd_value),0) as total FROM withdrawal_request WHERE username=:u",
            {"u": uname}
        )[0]
    except Exception:
        withdrawals = {"c": 0, "total": 0.0}

    status_line = []
    if u.get("is_verified"):    status_line.append("✅ Verified")
    else:                        status_line.append("❌ Unverified")
    if u.get("is_admin"):        status_line.append("⭐ Admin")
    if u.get("is_banned"):       status_line.append("🚫 BANNED")
    if u.get("has_iron_pickaxe"):status_line.append("⛏ Has Iron Pickaxe")

    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🚫 Ban",    callback_data=f"ban_{uname}"),
            InlineKeyboardButton("✅ Unban",  callback_data=f"unban_{uname}"),
            InlineKeyboardButton("⭐ Admin",  callback_data=f"admin_{uname}"),
        ]
    ])

    await update.message.reply_text(
        f"👤 *User: {u['username']}*\n"
        f"{'─'*28}\n"
        f"📧 Email:         `{u['email']}`\n"
        f"📱 Phone:         `{u['phone'] or '—'}`\n"
        f"🔑 Ref Code:      `{u['referral_code'] or '—'}`\n"
        f"👥 Referred by:   `{u['referred_by'] or '—'}`\n"
        f"👥 Valid referrals: `{ref_count}`\n"
        f"\n"
        f"💎 Balance:       `{u['balance']:.4f}`\n"
        f"📈 Total Mined:   `{u['total_earned']:.4f}`\n"
        f"⛏ Mining Start:  `{fmt_dt(u['mining_start'])}`\n"
        f"\n"
        f"🏦 Withdrawals:   `{withdrawals['c']}` (${withdrawals['total']:.2f} total)\n"
        f"📅 Joined:        `{fmt_dt(u['created_at'])}`\n"
        f"\n"
        f"Status: {' · '.join(status_line)}\n",
        parse_mode="Markdown",
        reply_markup=keyboard,
    )


# ══════════════════════════════════════════
#  /ban <username>  &  /unban <username>
# ══════════════════════════════════════════
@admin_only
async def cmd_ban(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("Usage: /ban `<username>`", parse_mode="Markdown")
        return
    uname = ctx.args[0].strip()
    _ensure_ban_col()
    rows = db_query("SELECT id FROM user WHERE username=:u", {"u": uname})
    if not rows:
        await update.message.reply_text(f"❌ User `{uname}` not found.", parse_mode="Markdown")
        return
    db_exec("UPDATE user SET is_banned=1, session_token=NULL WHERE username=:u", {"u": uname})
    await update.message.reply_text(f"🚫 `{uname}` has been *banned* and logged out.", parse_mode="Markdown")


@admin_only
async def cmd_unban(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("Usage: /unban `<username>`", parse_mode="Markdown")
        return
    uname = ctx.args[0].strip()
    _ensure_ban_col()
    rows = db_query("SELECT id FROM user WHERE username=:u", {"u": uname})
    if not rows:
        await update.message.reply_text(f"❌ User `{uname}` not found.", parse_mode="Markdown")
        return
    db_exec("UPDATE user SET is_banned=0 WHERE username=:u", {"u": uname})
    await update.message.reply_text(f"✅ `{uname}` has been *unbanned*.", parse_mode="Markdown")


def _ensure_ban_col():
    """Add is_banned column if it doesn't exist yet."""
    try:
        db_query("SELECT is_banned FROM user LIMIT 1")
    except:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE user ADD COLUMN is_banned INTEGER DEFAULT 0"))


# ══════════════════════════════════════════
#  /setadmin <username>
# ══════════════════════════════════════════
@admin_only
async def cmd_setadmin(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("Usage: /setadmin `<username>`", parse_mode="Markdown")
        return
    uname = ctx.args[0].strip()
    rows = db_query("SELECT id FROM user WHERE username=:u", {"u": uname})
    if not rows:
        await update.message.reply_text(f"❌ User `{uname}` not found.", parse_mode="Markdown")
        return
    db_exec("UPDATE user SET is_admin=1 WHERE username=:u", {"u": uname})
    await update.message.reply_text(f"⭐ `{uname}` is now an *admin*.", parse_mode="Markdown")


# ══════════════════════════════════════════
#  /miners — top 10 by balance
# ══════════════════════════════════════════
@admin_only
async def cmd_miners(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    try:
        rows = db_query(
            "SELECT username, balance, total_earned FROM user WHERE is_verified=1 ORDER BY balance DESC LIMIT 10"
        )
    except Exception as e:
        await update.message.reply_text(f"❌ DB error: {e}")
        return
    if not rows:
        await update.message.reply_text("No verified miners yet.")
        return

    lines = ["🏆 *Top 10 Miners by Balance*\n"]
    medals = ["🥇","🥈","🥉"] + ["🔹"]*7
    for i, r in enumerate(rows):
        lines.append(
            f"{medals[i]} `{r['username']}` — 💎`{r['balance']:.4f}` (total: `{r['total_earned']:.2f}`)"
        )
    await update.message.reply_text("\n".join(lines), parse_mode="Markdown")


# ══════════════════════════════════════════
#  /recent — last 10 signups
# ══════════════════════════════════════════
@admin_only
async def cmd_recent(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    try:
        rows = db_query(
            "SELECT username, email, is_verified, created_at FROM user ORDER BY created_at DESC LIMIT 10"
        )
    except Exception as e:
        await update.message.reply_text(f"❌ DB error: {e}")
        return
    if not rows:
        await update.message.reply_text("No users yet.")
        return

    lines = ["🆕 *Last 10 Signups*\n"]
    for r in rows:
        v = "✅" if r["is_verified"] else "⏳"
        lines.append(f"{v} `{r['username']}` · {fmt_dt(r['created_at'])}")
    await update.message.reply_text("\n".join(lines), parse_mode="Markdown")


# ══════════════════════════════════════════
#  Inline button callbacks (/user card buttons)
# ══════════════════════════════════════════
@admin_only_callback
async def handle_user_callback(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query  = update.callback_query
    await query.answer()
    data   = query.data

    if data.startswith("ban_"):
        uname = data[4:]
        _ensure_ban_col()
        db_exec("UPDATE user SET is_banned=1, session_token=NULL WHERE username=:u", {"u": uname})
        await query.edit_message_text(f"🚫 `{uname}` has been *banned* and logged out.", parse_mode="Markdown")

    elif data.startswith("unban_"):
        uname = data[6:]
        _ensure_ban_col()
        db_exec("UPDATE user SET is_banned=0 WHERE username=:u", {"u": uname})
        await query.edit_message_text(f"✅ `{uname}` has been *unbanned*.", parse_mode="Markdown")

    elif data.startswith("admin_"):
        uname = data[6:]
        db_exec("UPDATE user SET is_admin=1 WHERE username=:u", {"u": uname})
        await query.edit_message_text(f"⭐ `{uname}` is now an *admin*.", parse_mode="Markdown")

    elif data.startswith("approve_") or data.startswith("reject_"):
        await handle_callback(update, ctx)


# ══════════════════════════════════════════
#  PROACTIVE ALERTS — call this from Flask
#  when a withdrawal is submitted
# ══════════════════════════════════════════
async def send_withdrawal_alert(app, withdrawal: dict):
    """
    Call this from Flask routes when a new withdrawal is created.
    Pass the WithdrawalRequest.to_dict() result.
    """
    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("✅ Approve", callback_data=f"approve_{withdrawal['id']}"),
            InlineKeyboardButton("❌ Reject",  callback_data=f"reject_{withdrawal['id']}"),
        ]
    ])
    text_msg = (
        f"🔔 *New Withdrawal Request!*\n"
        f"{'─'*28}\n"
        f"👤 User:      `{withdrawal['username']}`\n"
        f"📧 Email:     `{withdrawal['email']}`\n"
        f"🌐 Network:   `{network_label(withdrawal['network'])}`\n"
        f"💳 Wallet:    `{withdrawal['wallet']}`\n"
        f"💎 Gems:      `{withdrawal['gems']:.4f}`\n"
        f"💵 USD Value: `${withdrawal['usd_value']:.2f}`\n"
        f"🕐 Time:      `{fmt_dt(withdrawal['created_at'])}`\n"
    )
    await app.bot.send_message(
        chat_id=ADMIN_CHAT_ID,
        text=text_msg,
        parse_mode="Markdown",
        reply_markup=keyboard,
    )


# ══════════════════════════════════════════
#  /edit <username> <amount> — set balance
# ══════════════════════════════════════════
@admin_only
async def cmd_edit(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if len(ctx.args) < 2:
        await update.message.reply_text( "Usage: /edit `<username>` `<amount>`", parse_mode="Markdown")
        return

    uname = ctx.args[0].strip()
    try:
        amount = float(ctx.args[1])
    except ValueError:
        await update.message.reply_text("❌ Amount must be a number. Example: /edit john 20000")
        return

    rows = db_query("SELECT id, balance FROM user WHERE username=:u", {"u": uname})
    if not rows:
        await update.message.reply_text(f"❌ User `{uname}` not found.", parse_mode="Markdown")
        return

    old_balance = rows[0]["balance"]
    db_exec(
        "UPDATE user SET balance=:b, total_earned=CASE WHEN total_earned < :b THEN :b ELSE total_earned END WHERE username=:u",
        {"b": amount, "u": uname}
    )

    await update.message.reply_text(
        f"✅ *Balance Updated*\n"
        f"👤 User:        `{uname}`\n"
        f"💎 Old balance: `{float(old_balance):.4f}`\n"
        f"💎 New balance: `{amount:.4f}`",
        parse_mode="Markdown"
    )


# ══════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════
def main():
    if BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
        print("❌ Please set BOT_TOKEN and ADMIN_CHAT_ID in telegram_bot.py before running!")
        sys.exit(1)

    app = Application.builder().token(BOT_TOKEN).build()

    # Commands
    app.add_handler(CommandHandler("start",    cmd_start))
    app.add_handler(CommandHandler("stats",    cmd_stats))
    app.add_handler(CommandHandler("pending",  cmd_pending))
    app.add_handler(CommandHandler("user",     cmd_user))
    app.add_handler(CommandHandler("ban",      cmd_ban))
    app.add_handler(CommandHandler("unban",    cmd_unban))
    app.add_handler(CommandHandler("setadmin", cmd_setadmin))
    app.add_handler(CommandHandler("miners",   cmd_miners))
    app.add_handler(CommandHandler("recent",   cmd_recent))
    app.add_handler(CommandHandler("edit",     cmd_edit))

    # Inline button callbacks
    app.add_handler(CallbackQueryHandler(handle_callback,      pattern=r"^(approve|reject)_"))
    app.add_handler(CallbackQueryHandler(handle_user_callback, pattern=r"^(ban|unban|admin)_"))

    print("✅ Norman-Earn Admin Bot is running...")
    print(f"   Only chat ID {ADMIN_CHAT_ID} can use this bot.")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()