from flask import Blueprint, request, jsonify, current_app
from dotenv import load_dotenv
import os
load_dotenv()
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, WithdrawalRequest, DailyQuest
from datetime import datetime, timedelta
from functools import wraps
import secrets
import random
import json
import re
import requests  # for Telegram alert

main_routes = Blueprint('main', __name__)

# ── Per-route rate limits (IP-based) ──
# Stored in memory — resets on server restart but good enough for most attacks
# Format: { ip: { 'count': N, 'window_start': datetime } }
_rate_store = {}

def rate_limit(key, max_calls, window_seconds):
    """Returns (allowed, retry_after_seconds). Call at start of a route."""
    now = datetime.utcnow()
    entry = _rate_store.get(key)
    if entry is None or (now - entry['start']).total_seconds() >= window_seconds:
        _rate_store[key] = {'count': 1, 'start': now}
        return True, 0
    if entry['count'] >= max_calls:
        retry = window_seconds - int((now - entry['start']).total_seconds())
        return False, max(1, retry)
    entry['count'] += 1
    return True, 0

# Strike counter — persists across rate limit windows (DB-backed via User table)
_strike_store = {}

def increment_strike(key):
    _strike_store[key] = _strike_store.get(key, 0) + 1
    return _strike_store[key]

def get_strikes(key):
    return _strike_store.get(key, 0)

# ── Bot / abuse detection helpers ──
BOT_SIGNALS = [
    'python-requests', 'curl', 'wget', 'httpx', 'aiohttp',
    'axios', 'node-fetch', 'go-http', 'java/', 'libwww',
]

def is_bot_request():
    """Detect requests that look automated."""
    ua = request.headers.get('User-Agent', '').lower()
    # Missing or suspicious user agent
    if not ua or any(sig in ua for sig in BOT_SIGNALS):
        return True, "Automated client detected"
    # Missing Origin header on a POST (browsers always send it)
    origin = request.headers.get('Origin', '')
    if not origin:
        return True, "Missing Origin header"
    # Origin must be our frontend
    allowed_origins = ['https://norman-earn.vercel.app', 'http://localhost:3000']
    if origin not in allowed_origins:
        return True, f"Invalid origin: {origin}"
    return False, None


# ── Rate limiter (initialized in app.py, accessed here) ──
def get_limiter():
    return current_app.extensions.get('limiter')

# ── Auth decorator — validates session token ──
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '').strip()
        if not token:
            return jsonify({"success": False, "message": "Unauthorized — no token."}), 401
        user = User.query.filter_by(session_token=token).first()
        if not user:
            return jsonify({"success": False, "message": "Invalid or expired session."}), 401
        if user.token_created and (datetime.utcnow() - user.token_created).days >= 7:
            user.session_token = None
            user.token_created = None
            db.session.commit()
            return jsonify({"success": False, "message": "Session expired. Please log in again."}), 401
        # Check if banned
        if user.is_banned:
            return jsonify({"success": False, "message": "Account suspended. Contact support."}), 403
        request.current_user = user
        return f(*args, **kwargs)
    return decorated

# ── Admin auth decorator ──
def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '').strip()
        if not token:
            return jsonify({"success": False, "message": "Unauthorized."}), 401
        user = User.query.filter_by(session_token=token).first()
        if not user or not user.is_admin:
            return jsonify({"success": False, "message": "Admin access required."}), 403
        if user.token_created and (datetime.utcnow() - user.token_created).days >= 7:
            user.session_token = None
            db.session.commit()
            return jsonify({"success": False, "message": "Session expired."}), 401
        request.current_user = user
        return f(*args, **kwargs)
    return decorated

# ── Auto-migrate missing columns on startup ──
def run_migrations(app):
    """Add any missing columns to existing DB without dropping data."""
    with app.app_context():
        from sqlalchemy import text as _text
        migrations = [
            'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS signup_ip VARCHAR(45)',
            'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS is_banned BOOLEAN DEFAULT false',
            'ALTER TABLE daily_quest ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true',
        ]
        with db.engine.begin() as conn:
            for stmt in migrations:
                try:
                    conn.execute(_text(stmt))
                except Exception as e:
                    print(f"[MIGRATION] {stmt[:50]}... -> {e}")
        print("[MIGRATION] Done.")

# ── Helpers ──
def gen_referral_code(username):
    suffix = secrets.token_hex(3).upper()
    return f"NE-{username[:4].upper()}-{suffix}"

def gen_otp():
    return str(random.randint(100000, 999999))

def gen_session_token():
    return secrets.token_hex(32)

# Telegram config — set these to match your telegram_bot.py
TELEGRAM_BOT_TOKEN    = os.getenv('BOT_TOKEN', '')
TELEGRAM_ADMIN_CHATID = int(os.getenv('ADMIN_CHAT_ID', '0'))


def send_security_alert(alert_type, details: dict):
    """Send a security/fraud alert to admin Telegram immediately."""
    import threading
    def _send():
        try:
            if not TELEGRAM_BOT_TOKEN or TELEGRAM_ADMIN_CHATID == 0:
                return
            icons = {
                "referral_farm":   "🚨",
                "same_ip_ref":     "⚠️",
                "suspicious_bal":  "💰",
                "rate_limit":      "🛑",
                "banned_ip":       "🔒",
                "fake_withdraw":   "💸",
            }
            icon = icons.get(alert_type, "🚨")
            lines = [
                f"{icon} *SECURITY ALERT — {alert_type.replace('_',' ').upper()}*",
                "",
            ]
            # Offending user
            if details.get("username"):
                lines.append(f"👤 Username: `{details['username']}`")
            if details.get("email"):
                lines.append(f"📧 Email: `{details['email']}`")
            if details.get("ip"):
                lines.append(f"🌐 IP: `{details['ip']}`")
            if details.get("ref_code") and details["ref_code"] != "none":
                lines.append(f"🔗 Ref Code Used: `{details['ref_code']}`")

            # Referrer (real account being farmed)
            if details.get("referrer") or details.get("referrer_email"):
                lines.append("")
                lines.append("*— Referrer Account —*")
                if details.get("referrer"):
                    lines.append(f"👑 Real Username: `{details['referrer']}`")
                if details.get("referrer_email"):
                    lines.append(f"📬 Real Email: `{details['referrer_email']}`")

            if details.get("balance"):
                lines.append(f"💎 Balance: `{details['balance']}`")
            if details.get("reason"):
                lines.append(f"")
                lines.append(f"📝 Reason: {details['reason']}")

            # Strike counter
            if details.get("strikes"):
                strike_num = details["strikes"]
                bar = "🔴" * min(strike_num, 10)
                lines.append(f"⚡ Strike Count: {bar} #{strike_num}")

            lines.append("")
            lines.append("_Use /ban <username> to ban this user._")

            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json={
                    "chat_id":    TELEGRAM_ADMIN_CHATID,
                    "text":       "\n".join(lines),
                    "parse_mode": "Markdown",
                },
                timeout=5,
            )
        except Exception as e:
            print(f"[SECURITY ALERT ERROR] {e}")
    threading.Thread(target=_send, daemon=True).start()


def send_telegram_alert(w):
    """Fire-and-forget — spawns daemon thread, NEVER blocks the HTTP response."""
    import threading
    def _send():
        try:
            if (not TELEGRAM_BOT_TOKEN
                    or TELEGRAM_BOT_TOKEN == "YOUR_BOT_TOKEN_HERE"
                    or TELEGRAM_ADMIN_CHATID == 0):
                return  # not configured yet, skip silently
            network_labels = {
                "usdt_bep20":"USDT BEP-20","usdt_trc20":"USDT TRC-20",
                "usdt_erc20":"USDT ERC-20","btc":"Bitcoin","bnb":"BNB","eth":"Ethereum",
            }
            lines = [
                "🔔 *New Withdrawal Request!*",
                "",
                f"👤 User: `{w['username']}`",
                f"🌐 Network: `{network_labels.get(w['network'], w['network'])}`",
                f"💳 Wallet: `{w['wallet']}`",
                f"💎 Gems: `{w['gems']:.4f}`",
                f"💵 USD: `${w['usd_value']:.2f}`",
                "",
                "Use /pending to approve or reject.",
            ]
            keyboard = {"inline_keyboard":[[
                {"text":"✅ Approve","callback_data":f"approve_{w['id']}"},
                {"text":"❌ Reject", "callback_data":f"reject_{w['id']}"},
            ]]}
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json={
                    "chat_id":    TELEGRAM_ADMIN_CHATID,
                    "text":       "\n".join(lines),
                    "parse_mode": "Markdown",
                    "reply_markup": keyboard,
                },
                timeout=3,
            )
        except Exception as e:
            print(f"[TELEGRAM ALERT ERROR]: {e}")
    threading.Thread(target=_send, daemon=True).start()


def send_otp_email(user, otp, subject="🔑 Your Norman-Earn Verification Code", heading="Verify Your Email", body_text="Use the code below to verify your email address."):
    from threading import Thread
    from flask import current_app
    from flask_mail import Message
    app  = current_app._get_current_object()
    mail = app.config['MAIL_INSTANCE']

    html_body = f"""
        <div style="font-family:Arial,sans-serif;max-width:500px;margin:auto;background:#04040d;color:#fff;border-radius:16px;overflow:hidden;">
          <div style="background:linear-gradient(135deg,#00ffcc,#00b894);padding:24px;text-align:center;">
            <h1 style="margin:0;color:#04040d;font-size:22px;">NORMAN-EARN</h1>
            <p style="margin:4px 0 0;color:#04040d99;font-size:12px;letter-spacing:3px;">GEM MINING PLATFORM</p>
          </div>
          <div style="padding:32px;text-align:center;">
            <h2 style="color:#00ffcc;margin-bottom:8px;">{heading}</h2>
            <p style="color:#ffffff88;margin-bottom:28px;">{body_text}</p>
            <div style="background:#0d0d1c;border:2px solid #00ffcc33;border-radius:16px;padding:24px;margin-bottom:24px;">
              <p style="color:#ffffff55;font-size:11px;letter-spacing:3px;margin-bottom:12px;">YOUR CODE</p>
              <div style="font-size:42px;font-weight:bold;letter-spacing:12px;color:#00ffcc;font-family:monospace;">{otp}</div>
            </div>
            <p style="color:#ffffff44;font-size:12px;line-height:1.7;">
              Expires in <strong style="color:#ffd700;">15 minutes</strong>.<br>
              If you didn't request this, ignore the email.
            </p>
          </div>
          <div style="background:#0a0a12;padding:16px;text-align:center;border-top:1px solid #ffffff0a;">
            <p style="color:#ffffff22;font-size:11px;margin:0;">Norman-Earn - Gem Mining Platform</p>
          </div>
        </div>
    """

    msg = Message(subject=subject, recipients=[user.email], html=html_body)

    def send_async(app, msg):
        with app.app_context():
            try:
                mail.send(msg)
                print(f"[EMAIL] Sent to {user.email}")
            except Exception as e:
                print(f"[EMAIL ERROR] {e}")

    Thread(target=send_async, args=(app, msg), daemon=True).start()

# ── Compute current gems/hr from upgrades ──
UPGRADE_BOOSTS = {
    "t1":0.05,"t2":0.12,"t3":0.28,"t4":0.55,"t5":2.0,"t6":4.5,
    "w1":0.06,"w2":0.14,"w3":0.32,"w4":0.65,"w5":2.8,"w6":5.5,
    "m1":0.08,"m2":0.16,"m3":0.42,"m4":0.80,"m5":3.2,"m6":6.5,
}
BASE_GEMS_PER_HR = 10 / 24

def calc_gems_per_hr(upgrades_json):
    try:
        owned = json.loads(upgrades_json or "{}")
    except Exception:
        owned = {}
    boost = sum(UPGRADE_BOOSTS.get(uid, 0) * lvl for uid, lvl in owned.items())
    return BASE_GEMS_PER_HR + boost


# ══════════════════════════════════════════
#  SIGNUP  (rate limited: 5/day per IP)
# ══════════════════════════════════════════
@main_routes.route('/api/users', methods=['POST'])
def create_user():
    # Get real IP — Railway/Render proxy sets X-Forwarded-For
    ip = (request.headers.get('X-Forwarded-For') or request.remote_addr or '').split(',')[0].strip()

    # ── Bot detection — check BEFORE parsing body ──
    bot, bot_reason = is_bot_request()
    if bot:
        send_security_alert("rate_limit", {
            "username": "BOT",
            "email":    "N/A",
            "ip":       ip,
            "ref_code": request.get_json(silent=True, force=True) and (request.get_json(silent=True, force=True).get('referral_code') or 'none') or 'none',
            "strikes":  increment_strike(f'strike_signup_{ip}'),
            "reason":   f"Bot/script detected: {bot_reason}"
        })
        # Return fake success to confuse scripts
        return jsonify({"success": True, "message": "Account created!", "token": "invalid"}), 200

    # Parse body
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "No data received."}), 400

    username = (data.get('username') or '').strip()
    email    = (data.get('email')    or '').strip().lower()
    phone    = (data.get('phone')    or '').strip()
    password = (data.get('password') or '')
    ref_code = (data.get('referral_code') or '').strip().upper()

    # Max 2 signups per IP per day
    allowed, retry = rate_limit(f'signup_{ip}', 2, 86400)
    if not allowed:
        strikes = increment_strike(f'strike_signup_{ip}')

        # Get referrer real info
        referrer_info = None
        if ref_code:
            ref_user = User.query.filter_by(referral_code=ref_code).first()
            if ref_user:
                referrer_info = {"username": ref_user.username, "email": ref_user.email}

        send_security_alert("rate_limit", {
            "username":         username  or "unknown",
            "email":            email     or "unknown",
            "ip":               ip,
            "ref_code":         ref_code  or "none",
            "referrer":         referrer_info["username"] if referrer_info else None,
            "referrer_email":   referrer_info["email"]    if referrer_info else None,
            "strikes":          strikes,
            "reason":           "Hit signup rate limit (2/day) — possible bot/spam"
        })
        # Real users get a helpful message, bots already got fake success above
        return jsonify({"success": False,
            "message": "Too many signups from your network today. Try again tomorrow."}), 429

    if not all([username, email, phone, password]):
        return jsonify({"success": False, "message": "All fields are required."}), 400
    if len(password) < 7:
        return jsonify({"success": False, "message": "Password must be at least 7 characters."}), 400
    if not re.search(r'\d', password):
        return jsonify({"success": False, "message": "Password must contain at least one number."}), 400
    if not re.match(r'^[a-zA-Z0-9_]+$', data.get('username','').strip()):
        return jsonify({"success": False, "message": "Username can only contain letters, numbers, and underscores."}), 400
    # Accept international format e.g. +2348012345678 or any dial code + number
    if not re.match(r'^\+\d{6,15}$', phone):
        return jsonify({"success": False, "message": "Invalid phone number format."}), 400
    # Gmail only, max 2 dots before @
    if not re.match(r'^[a-zA-Z0-9]+(\.[a-zA-Z0-9]+){0,2}@gmail\.com$', email):
        return jsonify({"success": False, "message": "Only @gmail.com addresses allowed (max 2 dots before @)."}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"success": False, "message": "Username already taken."}), 409
    if User.query.filter_by(email=email).first():
        return jsonify({"success": False, "message": "Email already registered."}), 409
    if User.query.filter_by(phone=phone).first():
        return jsonify({"success": False, "message": "Phone number already registered."}), 409

    referrer = None
    if ref_code:
        referrer = User.query.filter_by(referral_code=ref_code).first()
        if not referrer:
            return jsonify({"success": False, "message": "Invalid referral code."}), 400
        # Prevent self-referral by email or phone
        if referrer.email == email or referrer.phone == phone:
            return jsonify({"success": False, "message": "You cannot refer yourself."}), 400
        # Prevent same IP being referred more than once by the same referrer
        existing_ip_ref = User.query.filter_by(
            referred_by=ref_code, signup_ip=ip
        ).first()
        if existing_ip_ref:
            send_security_alert("referral_farm", {
                "username": username, "email": email, "ip": ip,
                "ref_code": ref_code, "referrer": referrer.username,
                "reason": f"IP {ip} already has a referred account under this code"
            })
            return jsonify({"success": False,
                "message": "A referral from your network already exists."}), 400
        # Referrer cannot refer from their own IP (prevent self-farming with VPN)
        if referrer.signup_ip and referrer.signup_ip == ip:
            send_security_alert("same_ip_ref", {
                "username": username, "email": email, "ip": ip,
                "ref_code": ref_code, "referrer": referrer.username,
                "reason": "Signup IP matches referrer's IP — possible self-farm"
            })
            return jsonify({"success": False,
                "message": "You cannot refer someone from the same network."}), 400
        # Cap: max 50 referrals per user
        existing_refs = User.query.filter_by(referred_by=ref_code).count()
        if existing_refs >= 50:
            return jsonify({"success": False,
                "message": "This referral code is no longer accepting new referrals."}), 400

    new_user = User(
        username=username,
        email=email,
        phone=phone,
        password=generate_password_hash(password),
        is_verified=True,
        referral_code=gen_referral_code(username),
        referred_by=ref_code if referrer else None,
        balance=2.0,
        total_earned=2.0,
        upgrades_owned="{}",
        signup_ip=ip,
    )
    db.session.add(new_user)
    db.session.commit()

    # Referral bonus is credited in /api/buy-upgrade when iron pickaxe is bought
    # This prevents fake account farming — they must actually spend gems

    # Generate token and log user in immediately
    import secrets
    token = secrets.token_hex(32)
    new_user.session_token = token
    new_user.token_created = datetime.utcnow()
    db.session.commit()

    print(f"[SIGNUP] {username} registered and auto-logged in")
    return jsonify({
        "success": True,
        "message": "Account created! Welcome to Norman-Earn.",
        "token": token,
        "user": new_user.to_dict()
    }), 201


# ══════════════════════════════════════════
#  VERIFY SIGNUP OTP
# ══════════════════════════════════════════
@main_routes.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    data  = request.get_json()
    email = (data.get('email') or '').strip().lower()
    otp   = (data.get('otp')   or '').strip()

    if not email or not otp:
        return jsonify({"success": False, "message": "Email and code are required."}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"success": False, "message": "Account not found."}), 404
    if user.is_verified:
        return jsonify({"success": False, "message": "Account already verified."}), 400

    stored  = (user.otp_code or '').strip()
    entered = otp.strip()

    if not stored:
        return jsonify({"success": False, "message": "No code found. Request a new one."}), 400
    if user.otp_expires < datetime.utcnow():
        return jsonify({"success": False, "message": "Code expired. Request a new one."}), 400
    if stored != entered:
        user.otp_attempts = (user.otp_attempts or 0) + 1
        if user.otp_attempts >= 5:
            user.otp_code = None; user.otp_expires = None; user.otp_attempts = 0
            db.session.commit()
            return jsonify({"success": False, "message": "Too many wrong attempts. Request a new code."}), 429
        db.session.commit()
        remaining = 5 - user.otp_attempts
        return jsonify({"success": False, "message": f"Incorrect code. {remaining} attempt(s) remaining."}), 400

    user.is_verified  = True
    user.otp_code     = None
    user.otp_expires  = None
    user.otp_attempts = 0

    # ── Referral signup bonus: give referrer +10 gems when referred user verifies ──
    if user.referred_by:
        referrer = User.query.filter_by(referral_code=user.referred_by).first()
        if referrer:
            referrer.balance      += 10.0
            referrer.total_earned += 10.0
            print(f'[REFERRAL] {referrer.username} earned +10 gems (referral signup bonus from {user.username})')

    db.session.commit()

    return jsonify({"success": True, "message": "Email verified! You can now log in.", "user": user.to_dict()})


# ══════════════════════════════════════════
#  RESEND SIGNUP OTP
# ══════════════════════════════════════════
@main_routes.route('/api/resend-otp', methods=['POST'])
def resend_otp():
    data  = request.get_json()
    email = (data.get('email') or '').strip().lower()

    # Rate limit: max 3 OTP requests per email per hour
    allowed, retry = rate_limit(f'otp_{email}', 3, 3600)
    if not allowed:
        return jsonify({"success": False,
            "message": f"Too many code requests. Wait {retry//60+1} minute(s)."}), 429

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"success": False, "message": "No account found."}), 404
    if user.is_verified:
        return jsonify({"success": False, "message": "Account already verified."}), 400

    otp = gen_otp()
    user.otp_code    = otp
    user.otp_expires = datetime.utcnow() + timedelta(minutes=15)
    db.session.commit()

    try:
        send_otp_email(user, otp, heading=f"Hey {user.username}! 👋", body_text="Here is your new verification code.")
        return jsonify({"success": True, "message": "New code sent!"})
    except Exception as e:
        print(f"[EMAIL ERROR]: {e}")
        return jsonify({"success": False, "message": "Failed to send email."}), 500


# ══════════════════════════════════════════
#  LOGIN — returns session token
# ══════════════════════════════════════════
@main_routes.route('/api/login', methods=['POST'])
def login():
    data       = request.get_json()
    method     = (data.get('method')     or '')
    identifier = (data.get('identifier') or '').strip()
    password   = (data.get('password')   or '')

    if not all([method, identifier, password]):
        return jsonify({"success": False, "message": "All fields are required."}), 400

    user = None
    if method == 'username':
        user = User.query.filter_by(username=identifier).first()
    elif method == 'email':
        user = User.query.filter_by(email=identifier.lower()).first()
    elif method == 'phone':
        user = User.query.filter_by(phone=identifier).first()
    else:
        return jsonify({"success": False, "message": "Invalid login method."}), 400

    # ── IP rate limit: max 20 login attempts per IP per hour ──
    ip = request.remote_addr
    allowed, retry = rate_limit(f'login_ip_{ip}', 20, 3600)
    if not allowed:
        return jsonify({"success": False,
            "message": f"Too many attempts from your network. Try again in {retry//60+1} minutes."}), 429

    if not user or not check_password_hash(user.password, password):
        # Track failed attempts on the account
        if user:
            user.failed_logins = (user.failed_logins or 0) + 1
            if user.failed_logins >= 5:
                user.locked_until  = datetime.utcnow() + timedelta(minutes=15)
                user.failed_logins = 0
                db.session.commit()
                return jsonify({"success": False,
                    "message": "Too many failed attempts. Account locked for 15 minutes."}), 429
            db.session.commit()
        return jsonify({"success": False, "message": "Invalid credentials."}), 401

    # Check ban BEFORE anything else
    if user.is_banned:
        return jsonify({"success": False, "message": "Your account has been suspended. Contact support."}), 403

    # ── Check lockout ──
    if user.locked_until and datetime.utcnow() < user.locked_until:
        secs = int((user.locked_until - datetime.utcnow()).total_seconds())
        mins = secs // 60 + 1
        return jsonify({"success": False,
            "message": f"Account locked due to failed attempts. Try again in {mins} minute(s)."}), 429

    if not user.is_verified:
        return jsonify({
            "success": False,
            "message": "Please verify your email before logging in.",
            "needs_verification": True,
            "email": user.email
        }), 403

    # Successful login — reset failure counters
    user.failed_logins = 0
    user.locked_until  = None

    # Generate fresh session token
    token = gen_session_token()
    user.session_token  = token
    user.token_created  = datetime.utcnow()
    db.session.commit()

    return jsonify({
        "success": True,
        "token":   token,
        "user":    user.to_dict(),
    })


# ══════════════════════════════════════════
#  LOGOUT — invalidate token
# ══════════════════════════════════════════
@main_routes.route('/api/logout', methods=['POST'])
@require_auth
def logout():
    user = request.current_user
    user.session_token = None
    user.token_created = None
    db.session.commit()
    return jsonify({"success": True, "message": "Logged out."})


# ══════════════════════════════════════════
#  GET PROFILE — validate token + return state
# ══════════════════════════════════════════
@main_routes.route('/api/profile', methods=['GET'])
@require_auth
def get_profile():
    user = request.current_user
    return jsonify({"success": True, "user": user.to_dict()})


# ══════════════════════════════════════════
#  SYNC MINING STATE — save balance/upgrades/mining_start to DB
# ══════════════════════════════════════════
# ══════════════════════════════════════════
#  START MINING
# ══════════════════════════════════════════
@main_routes.route('/api/start-mining', methods=['POST'])
@require_auth
def start_mining():
    user = request.current_user
    now  = datetime.utcnow()

    if user.mining_start:
        # Already mining — return current state
        elapsed = (now - user.mining_start).total_seconds()
        return jsonify({
            "success":      True,
            "mining_start": user.mining_start.isoformat(),
            "elapsed":      elapsed,
            "already_mining": True,
        })

    user.mining_start = now
    db.session.commit()
    return jsonify({
        "success":      True,
        "mining_start": user.mining_start.isoformat(),
        "already_mining": False,
    })


# ══════════════════════════════════════════
#  CLAIM MINING
# ══════════════════════════════════════════
@main_routes.route('/api/claim-mining', methods=['POST'])
@require_auth
def claim_mining():
    user = request.current_user
    now  = datetime.utcnow()

    if not user.mining_start:
        return jsonify({"success": False, "message": "Not currently mining."}), 400

    elapsed = (now - user.mining_start).total_seconds()
    elapsed = min(elapsed, 86400)  # cap at 24h

    # Calculate gems earned server-side
    owned = json.loads(user.upgrades_owned or '{}')
    BOOSTS = {
        't1':0.05,'t2':0.12,'t3':0.28,'t4':0.55,'t5':2.0,'t6':4.5,
        'w1':0.06,'w2':0.14,'w3':0.32,'w4':0.65,'w5':2.8,'w6':5.5,
        'm1':0.08,'m2':0.16,'m3':0.42,'m4':0.80,'m5':3.2,'m6':6.5,
    }
    boost       = sum(BOOSTS.get(k, 0) * v for k, v in owned.items())
    rate        = BASE_GEMS_PER_SECOND * (1 + boost)
    gems_earned = round(rate * elapsed, 6)

    user.balance      += gems_earned
    user.total_earned += gems_earned
    user.mining_start  = None

    # 10% referral cut
    if user.referred_by and gems_earned > 0:
        referrer = User.query.filter_by(referral_code=user.referred_by).first()
        same_ip  = (user.signup_ip and referrer and referrer.signup_ip == user.signup_ip)
        if referrer and not same_ip:
            cut = round(gems_earned * 0.10, 6)
            referrer.balance      += cut
            referrer.total_earned += cut

    db.session.commit()
    return jsonify({
        "success":      True,
        "gems_earned":  gems_earned,
        "balance":      user.balance,
        "total_earned": user.total_earned,
    })


# ── Mining constants (must match frontend) ──
BASE_GEMS_PER_SECOND = (10 / 24) / 3600   # 10 gems/day → per second
MAX_SINGLE_CYCLE     = 10.5                # max gems one 24hr cycle can earn

@main_routes.route('/api/sync', methods=['POST'])
@require_auth
def sync_state():
    user = request.current_user
    data = request.get_json()
    now  = datetime.utcnow()

    # ── ONLY accept upgrades_owned and mining_start from frontend ──
    # NEVER trust balance or total_earned from client
    # upgrades_owned is now managed by /api/buy-upgrade — ignore from sync
    # Only accept mining_start from frontend

    if 'mining_start' in data:
        ms = data['mining_start']
        if ms:
            try:
                start = datetime.fromisoformat(ms)
                # Reject if mining_start is in the future or more than 25hrs ago
                diff_hours = (now - start).total_seconds() / 3600
                if -0.1 <= diff_hours <= 25:
                    user.mining_start = start
                else:
                    print(f'[SECURITY] {user.username} sent suspicious mining_start: {diff_hours:.1f}h ago')
            except Exception:
                pass
        else:
            # mining stopped — calculate gems earned server-side
            if user.mining_start:
                elapsed = (now - user.mining_start).total_seconds()
                # Cap at 24hr cycle
                elapsed = min(elapsed, 86400)

                # Calculate boost from upgrades
                owned = json.loads(user.upgrades_owned or '{}')
                BOOSTS = {
                    't1':0.05,'t2':0.12,'t3':0.28,'t4':0.55,'t5':2.0,'t6':4.5,
                    'w1':0.06,'w2':0.14,'w3':0.32,'w4':0.65,'w5':2.8,'w6':5.5,
                    'm1':0.08,'m2':0.16,'m3':0.42,'m4':0.80,'m5':3.2,'m6':6.5,
                }
                boost = sum(BOOSTS.get(k, 0) * v for k, v in owned.items())
                rate = BASE_GEMS_PER_SECOND * (1 + boost)
                gems_earned = round(rate * elapsed, 6)

                # Cap earned gems to prevent abuse
                MAX_RATE_BOOST = sum(BOOSTS.values()) * 10000  # absolute max
                max_possible = BASE_GEMS_PER_SECOND * (1 + MAX_RATE_BOOST) * 86400
                gems_earned = min(gems_earned, max_possible)

                old_total = user.total_earned
                user.balance      += gems_earned
                user.total_earned += gems_earned
                user.mining_start  = None

                # ── 10% referral cut — only if not same IP ──
                if user.referred_by and gems_earned > 0:
                    cut = round(gems_earned * 0.10, 6)
                    referrer = User.query.filter_by(referral_code=user.referred_by).first()
                    same_ip = (user.signup_ip and referrer and
                               referrer.signup_ip == user.signup_ip)
                    if referrer and cut > 0 and not same_ip:
                        referrer.balance      += cut
                        referrer.total_earned += cut
                        print(f'[REFERRAL CUT] {referrer.username} +{cut:.4f} gems')

                print(f'[MINING] {user.username} earned {gems_earned:.4f} gems in {elapsed:.0f}s')

    db.session.commit()
    return jsonify({
        "success":      True,
        "message":      "State synced.",
        "balance":      user.balance,
        "total_earned": user.total_earned,
    })


# ══════════════════════════════════════════
#  BUY IRON PICKAXE — mark on backend
# ══════════════════════════════════════════
# ══════════════════════════════════════════
#  BUY UPGRADE — server validates cost & deducts balance
# ══════════════════════════════════════════
UPGRADE_COSTS = {
    't1':1,   't2':3,   't3':8,   't4':18,  't5':20,  't6':35,
    'w1':1.5, 'w2':4,   'w3':10,  'w4':20,  'w5':22,  'w6':38,
    'm1':2,   'm2':4,   'm3':12,  'm4':22,  'm5':24,  'm6':40,
}
MAX_UPGRADE_QTY = 10000  # max quantity per upgrade type

@main_routes.route('/api/buy-upgrade', methods=['POST'])
@require_auth
def buy_upgrade():
    user = request.current_user
    data = request.get_json()
    upg_id = (data.get('upgrade_id') or '').strip()

    if upg_id not in UPGRADE_COSTS:
        return jsonify({"success": False, "message": "Invalid upgrade."}), 400

    cost = UPGRADE_COSTS[upg_id]

    if user.balance < cost:
        return jsonify({"success": False, "message": f"Insufficient balance. Need {cost} gems."}), 400

    owned = json.loads(user.upgrades_owned or '{}')
    current_qty = owned.get(upg_id, 0)

    if current_qty >= MAX_UPGRADE_QTY:
        return jsonify({"success": False, "message": "Maximum quantity reached for this upgrade."}), 400

    # Deduct cost and add upgrade server-side
    user.balance -= cost
    owned[upg_id] = current_qty + 1
    user.upgrades_owned = json.dumps(owned)

    # Iron pickaxe special flag + referral bonus
    if upg_id == 't2' and not user.has_iron_pickaxe:
        user.has_iron_pickaxe = True
        # Credit referrer only after strict anti-abuse checks
        if user.referred_by:
            referrer = User.query.filter_by(referral_code=user.referred_by).first()
            if referrer and referrer.username != user.username:
                now = datetime.utcnow()
                account_age_hours = (now - user.created_at).total_seconds() / 3600

                # Check 1: account must be at least 24 hours old
                if account_age_hours < 24:
                    send_security_alert("referral_farm", {
                        "username": user.username, "email": user.email,
                        "ip": user.signup_ip, "ref_code": user.referred_by,
                        "referrer": referrer.username,
                        "reason": f"Bonus blocked — suspicious activity (account age {account_age_hours:.1f}h, minimum 24h required)"
                    })
                # Check 2: referred user and referrer must not share IP
                elif user.signup_ip and referrer.signup_ip and user.signup_ip == referrer.signup_ip:
                    send_security_alert("same_ip_ref", {
                        "username": user.username, "email": user.email,
                        "ip": user.signup_ip, "ref_code": user.referred_by,
                        "referrer": referrer.username,
                        "reason": "Bonus blocked — suspicious activity (referred user IP matches referrer IP)"
                    })
                # Check 3: referrer must have been active (has mined something)
                elif referrer.total_earned < 2.0:
                    print(f'[REFERRAL BLOCKED] referrer {referrer.username} has not mined yet')
                else:
                    referrer.balance      += 10.0
                    referrer.total_earned += 10.0
                    print(f'[REFERRAL] {referrer.username} earned +10 gems (from {user.username})')

    db.session.commit()

    return jsonify({
        "success":        True,
        "message":        "Upgrade purchased!",
        "balance":        user.balance,
        "upgrades_owned": owned,
    })


@main_routes.route('/api/buy-iron-pickaxe', methods=['POST'])
@require_auth
def buy_iron_pickaxe():
    user = request.current_user
    # Iron pickaxe costs 3 gems (t2) — check balance before granting
    IRON_PICKAXE_COST = 3.0
    if user.has_iron_pickaxe:
        return jsonify({"success": True, "message": "Already owned.", "now_valid_referral": bool(user.referred_by)})
    if user.balance < IRON_PICKAXE_COST:
        return jsonify({"success": False, "message": "Insufficient balance to buy Iron Pickaxe."}), 400
    user.balance -= IRON_PICKAXE_COST
    user.has_iron_pickaxe = True
    db.session.commit()
    return jsonify({
        "success": True,
        "message": "Iron Pickaxe purchased!",
        "balance": user.balance,
        "now_valid_referral": bool(user.referred_by),
    })


# ══════════════════════════════════════════
#  FORGOT PASSWORD — send OTP
# ══════════════════════════════════════════
@main_routes.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data  = request.get_json()
    email = (data.get('email') or '').strip().lower()

    if not email:
        return jsonify({"success": False, "message": "Email is required."}), 400

    # Rate limit: max 3 password reset requests per email per hour
    allowed, retry = rate_limit(f'forgot_{email}', 3, 3600)
    if not allowed:
        return jsonify({"success": False,
            "message": f"Too many reset requests. Wait {retry//60+1} minute(s)."}), 429

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"success": False, "message": "No account found with that email address."}), 404

    otp = gen_otp()
    user.otp_code    = otp
    user.otp_expires = datetime.utcnow() + timedelta(minutes=15)
    db.session.commit()

    try:
        send_otp_email(user, otp,
            subject="🔐 Norman-Earn Password Reset Code",
            heading="Password Reset Request",
            body_text="Use the code below to reset your password."
        )
    except Exception as e:
        print(f"[EMAIL ERROR]: {e}")
        return jsonify({"success": False, "message": "Failed to send email. Try again."}), 500

    return jsonify({"success": True, "message": f"Reset code sent to {email}."})


# ══════════════════════════════════════════
#  VERIFY RESET OTP
# ══════════════════════════════════════════
@main_routes.route('/api/verify-reset-otp', methods=['POST'])
def verify_reset_otp():
    data  = request.get_json()
    email = (data.get('email') or '').strip().lower()
    otp   = (data.get('otp')   or '').strip()

    if not email or not otp:
        return jsonify({"success": False, "message": "Email and code are required."}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"success": False, "message": "Account not found."}), 404

    stored  = (user.otp_code or '').strip()
    entered = otp.strip()

    if not stored:
        return jsonify({"success": False, "message": "No code found. Request a new one."}), 400
    if user.otp_expires < datetime.utcnow():
        return jsonify({"success": False, "message": "Code expired. Request a new one."}), 400
    if stored != entered:
        user.otp_attempts = (user.otp_attempts or 0) + 1
        if user.otp_attempts >= 5:
            user.otp_code = None; user.otp_expires = None; user.otp_attempts = 0
            db.session.commit()
            return jsonify({"success": False, "message": "Too many wrong attempts. Request a new reset code."}), 429
        db.session.commit()
        remaining = 5 - user.otp_attempts
        return jsonify({"success": False, "message": f"Incorrect code. {remaining} attempt(s) remaining."}), 400

    return jsonify({"success": True, "message": "Code verified."})


# ══════════════════════════════════════════
#  RESET PASSWORD
# ══════════════════════════════════════════
@main_routes.route('/api/reset-password', methods=['POST'])
def reset_password():
    data         = request.get_json()
    email        = (data.get('email')        or '').strip().lower()
    new_password = (data.get('new_password') or '')

    if not email or not new_password:
        return jsonify({"success": False, "message": "Email and new password are required."}), 400
    if len(new_password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters."}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"success": False, "message": "Account not found."}), 404
    if not user.otp_code or user.otp_expires < datetime.utcnow():
        return jsonify({"success": False, "message": "Session expired. Please start over."}), 400

    user.password    = generate_password_hash(new_password)
    user.otp_code    = None
    user.otp_expires = None
    user.is_verified = True
    user.session_token = None  # force re-login after reset
    db.session.commit()

    return jsonify({"success": True, "message": "Password reset successfully!"})


# ══════════════════════════════════════════
#  WITHDRAWAL REQUEST — saved to DB
# ══════════════════════════════════════════
@main_routes.route('/api/withdraw', methods=['POST'])
@require_auth
def withdraw():
    user = request.current_user
    data = request.get_json()
    now  = datetime.utcnow()

    network = (data.get('network') or '').strip()
    wallet  = (data.get('wallet')  or '').strip()
    gems    = float(data.get('gems', 0))

    if not network or not wallet:
        return jsonify({"success": False, "message": "Network and wallet address are required."}), 400

    # ── Fraud checks ──
    # 1. Account must be at least 7 days old
    account_age_days = (now - user.created_at).days
    if account_age_days < 7:
        return jsonify({"success": False, "message": f"Account must be at least 7 days old to withdraw. ({7 - account_age_days} days remaining)"}), 403

    # 2. Must have iron pickaxe (paid upgrade)
    if not user.has_iron_pickaxe:
        return jsonify({"success": False, "message": "You must own the Iron Pickaxe upgrade to withdraw."}), 403

    # 3. Rate limit — max 1 withdrawal per 24 hours per user
    allowed, retry = rate_limit(f'withdraw_{user.username}', 1, 86400)
    if not allowed:
        return jsonify({"success": False, "message": f"You can only withdraw once per 24 hours. Try again in {retry//3600+1}h."}), 429

    # 4. Minimum withdrawal
    if gems < 50:
        return jsonify({"success": False, "message": "Minimum withdrawal is 50 gems."}), 400

    # 5. Can't withdraw more than actual balance
    if gems > user.balance:
        return jsonify({"success": False, "message": "Insufficient balance."}), 400

    # 6. Balance sanity check — flag suspiciously high balances
    MAX_LEGIT_BALANCE = 100000  # adjust as needed
    if user.balance > MAX_LEGIT_BALANCE:
        send_security_alert("suspicious_bal", {
            "username": user.username, "email": user.email,
            "ip": request.remote_addr, "balance": f"{user.balance:.2f} gems",
            "reason": f"Attempted withdrawal with balance {user.balance:.2f} gems (max legit: {MAX_LEGIT_BALANCE})"
        })
        return jsonify({"success": False, "message": "Your account has been flagged for review. Contact support."}), 403

    # 5% transaction fee — deduct full amount, user receives 95%
    fee_gems  = round(gems * 0.05, 4)
    net_gems  = round(gems - fee_gems, 4)
    usd_value = round(net_gems / 10, 2)

    user.balance -= gems
    db.session.commit()

    wr = WithdrawalRequest(
        username  = user.username,
        email     = user.email,
        network   = network,
        wallet    = wallet,
        gems      = net_gems,
        usd_value = usd_value,
        status    = "pending",
    )
    db.session.add(wr)
    db.session.commit()

    # Notify admin on Telegram immediately
    send_telegram_alert(wr.to_dict())

    return jsonify({
        "success":   True,
        "message":   f"Submitted! You receive ${wr.usd_value:.2f} after 5% fee.",
        "request_id": wr.id,
    })


# ══════════════════════════════════════════
#  GET REFERRALS
# ══════════════════════════════════════════
@main_routes.route('/api/referrals/<username>', methods=['GET'])
def get_referrals(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"success": False, "message": "User not found."}), 404

    referred_by_username = None
    if user.referred_by:
        referrer = User.query.filter_by(referral_code=user.referred_by).first()
        if referrer:
            referred_by_username = referrer.username

    referred_users = User.query.filter_by(referred_by=user.referral_code).all()

    verified = []
    pending  = []
    now = datetime.utcnow()
    for r in referred_users:
        # Check if bonus was blocked for this referral
        age_hours   = (now - r.created_at).total_seconds() / 3600
        same_ip     = (r.signup_ip and user.signup_ip and r.signup_ip == user.signup_ip)
        bonus_blocked = same_ip or age_hours < 24

        entry = {
            "username":        r.username,
            "joined":          r.created_at.strftime("%Y-%m-%d"),
            "is_verified":     r.is_verified,
            "has_iron_pickaxe":r.has_iron_pickaxe,
            "earned":          r.total_earned,
            "bonus_blocked":   bonus_blocked,
            "block_reason":    ("Same network" if same_ip else "Account too new") if bonus_blocked else None,
        }
        if r.is_verified and r.has_iron_pickaxe:
            verified.append(entry)
        else:
            pending.append(entry)

    # Calculate actual referral gems credited (signup bonuses + 10% cut)
    # Count only referrals where iron pickaxe was bought (bonus was actually paid)
    actual_signup_bonuses = User.query.filter_by(
        referred_by=user.referral_code,
        has_iron_pickaxe=True
    ).count() * 10.0

    # 10% cut estimate from verified referrals' total_earned
    actual_cut = sum(r.total_earned * 0.10 for r in
        User.query.filter_by(referred_by=user.referral_code, is_verified=True).all()
    )

    return jsonify({
        "success":              True,
        "verified":             verified,
        "pending":              pending,
        "count":                len(verified),
        "referral_code":        user.referral_code,
        "referred_by":          referred_by_username,
        "referral_gems_earned": round(actual_signup_bonuses + actual_cut, 4),
        "signup_bonuses":       round(actual_signup_bonuses, 4),
        "mining_cut":           round(actual_cut, 4),
    })


# ══════════════════════════════════════════
#  DELETE ACCOUNT
# ══════════════════════════════════════════
@main_routes.route('/api/delete-account', methods=['POST'])
@require_auth
def delete_account():
    user = request.current_user
    data = request.get_json()
    password = data.get('password','').strip()

    if not password:
        return jsonify({"success": False, "message": "Password required to delete account."}), 400
    if not check_password_hash(user.password, password):
        return jsonify({"success": False, "message": "Incorrect password."}), 401

    try:
        # Delete all related records first
        WithdrawalRequest.query.filter_by(username=user.username).delete()

        # Remove username from any daily quest winner lists
        quests = DailyQuest.query.all()
        for q in quests:
            import json as _json
            winners = _json.loads(q.winners or "[]")
            if user.username in winners:
                winners.remove(user.username)
                q.winners = _json.dumps(winners)

        # Nullify referred_by for users they referred (keep their accounts)
        User.query.filter_by(referred_by=user.referral_code).update({"referred_by": None})

        db.session.delete(user)
        db.session.commit()
        return jsonify({"success": True, "message": "Account deleted."})
    except Exception as e:
        db.session.rollback()
        print(f"[DELETE ERROR] {e}")
        return jsonify({"success": False, "message": "Failed to delete account. Please try again."}), 500


# ══════════════════════════════════════════
#  GET MY WITHDRAWALS
# ══════════════════════════════════════════
@main_routes.route('/api/my-withdrawals', methods=['GET'])
@require_auth
def my_withdrawals():
    user = request.current_user
    records = WithdrawalRequest.query.filter_by(username=user.username)        .order_by(WithdrawalRequest.created_at.desc()).limit(20).all()
    return jsonify({
        "success": True,
        "withdrawals": [r.to_dict() for r in records],
    })


# ══════════════════════════════════════════
#  ACHIEVEMENTS
# ══════════════════════════════════════════
ACHIEVEMENTS = [
    {"id":"inv1",  "title":"First Recruit",  "desc":"Invite 1 verified friend",         "icon":"👥","reward":5,  "type":"referrals",    "target":1  },
    {"id":"inv5",  "title":"Squad Builder",  "desc":"Invite 5 verified friends",         "icon":"🫂","reward":15, "type":"referrals",    "target":5  },
    {"id":"inv10", "title":"Referral King",  "desc":"Invite 10 verified friends",        "icon":"👑","reward":30, "type":"referrals",    "target":10 },
    {"id":"inv25", "title":"Mining Empire",  "desc":"Invite 25 verified friends",        "icon":"🏰","reward":75, "type":"referrals",    "target":25 },
    {"id":"upg3",  "title":"Gear Up",        "desc":"Buy 3 upgrades",                   "icon":"⚙️","reward":10, "type":"upgrades",     "target":3  },
    {"id":"upg5",  "title":"Tool Master",    "desc":"Buy 5 tool upgrades",              "icon":"🔧","reward":20, "type":"tool_upgrades","target":5  },
    {"id":"upg10", "title":"Full Arsenal",   "desc":"Own 10 total upgrades",            "icon":"💥","reward":35, "type":"upgrades",     "target":10 },
    {"id":"mine1", "title":"First Strike",   "desc":"Complete your first mine cycle",   "icon":"⛏️","reward":5,  "type":"cycles",       "target":1  },
    {"id":"mine10","title":"Veteran Miner",  "desc":"Complete 10 mine cycles",          "icon":"🪨","reward":20, "type":"cycles",       "target":10 },
    {"id":"gems50","title":"Gem Collector",  "desc":"Mine 50 gems total",               "icon":"💎","reward":10, "type":"total_mined",  "target":50 },
    {"id":"gems200","title":"Diamond Hands", "desc":"Mine 200 gems total",              "icon":"💠","reward":25, "type":"total_mined",  "target":200},
    {"id":"gems500","title":"Gem Tycoon",    "desc":"Mine 500 gems total",              "icon":"🏆","reward":60, "type":"total_mined",  "target":500},
    {"id":"str3",  "title":"Hat Trick",      "desc":"Claim daily bonus 3 days in a row","icon":"🔥","reward":10, "type":"streak",       "target":3  },
    {"id":"str7",  "title":"Weekly Warrior", "desc":"Claim daily bonus 7 days in a row","icon":"⚡","reward":25, "type":"streak",       "target":7  },
]

def check_achievement_progress(user):
    owned      = json.loads(user.upgrades_owned or "{}")
    claimed    = json.loads(user.achievements_claimed or "[]")
    tool_upgs  = sum(v for k, v in owned.items() if k.startswith("t"))
    total_upgs = sum(owned.values())
    ref_count  = User.query.filter_by(referred_by=user.referral_code)        .filter_by(is_verified=True).filter_by(has_iron_pickaxe=True).count()

    result = []
    for a in ACHIEVEMENTS:
        t = a["type"]
        if   t == "referrals":      current = ref_count
        elif t == "upgrades":       current = total_upgs
        elif t == "tool_upgrades":  current = tool_upgs
        elif t == "total_mined":    current = user.total_earned
        elif t == "cycles":         current = int(user.total_earned / 10)
        else:                       current = 0
        result.append({
            **a,
            "current": min(current, a["target"]),
            "claimed": a["id"] in claimed,
            "complete": current >= a["target"],
        })
    return result


@main_routes.route("/api/achievements", methods=["GET"])
@require_auth
def get_achievements():
    user = request.current_user
    return jsonify({"success": True, "achievements": check_achievement_progress(user)})


@main_routes.route("/api/achievements/claim", methods=["POST"])
@require_auth
def claim_achievement():
    user   = request.current_user
    data   = request.get_json()
    ach_id = (data.get("id") or "").strip()

    ach = next((a for a in ACHIEVEMENTS if a["id"] == ach_id), None)
    if not ach:
        return jsonify({"success": False, "message": "Achievement not found."}), 404

    claimed = json.loads(user.achievements_claimed or "[]")
    if ach_id in claimed:
        return jsonify({"success": False, "message": "Already claimed."}), 400

    progress = check_achievement_progress(user)
    item     = next((p for p in progress if p["id"] == ach_id), None)
    if not item or not item["complete"]:
        return jsonify({"success": False, "message": "Not completed yet."}), 400

    user.balance              += ach["reward"]
    user.total_earned         += ach["reward"]
    claimed.append(ach_id)
    user.achievements_claimed  = json.dumps(claimed)
    db.session.commit()

    return jsonify({
        "success": True,
        "message": f"+{ach['reward']} gems claimed!",
        "reward":  ach["reward"],
        "balance": user.balance,
    })


# ══════════════════════════════════════════
#  DAILY LOGIN BONUS
# ══════════════════════════════════════════
@main_routes.route('/api/daily-bonus', methods=['POST'])
@require_auth
def claim_daily_bonus():
    user = request.current_user
    now  = datetime.utcnow()
    BONUS_GEMS = 5.0

    # Must wait 24 hours from account creation before first claim
    hours_since_signup = (now - user.created_at).total_seconds() / 3600
    if hours_since_signup < 24:
        secs_left = int((24 * 3600) - (now - user.created_at).total_seconds())
        return jsonify({
            "success":    False,
            "message":    "You must wait 24 hours after signup to claim your first bonus.",
            "next_claim": secs_left,
        }), 400

    # Check if already claimed in last 24 hours
    if user.last_bonus_claim:
        secs_since = (now - user.last_bonus_claim).total_seconds()
        if secs_since < 86400:
            secs_left = int(86400 - secs_since)
            return jsonify({
                "success":    False,
                "message":    "Already claimed. Come back in 24 hours.",
                "next_claim": secs_left,
            }), 400

    # Credit bonus
    user.balance          += BONUS_GEMS
    user.total_earned     += BONUS_GEMS
    user.last_bonus_claim  = now
    db.session.commit()

    return jsonify({
        "success":  True,
        "message":  f"+{BONUS_GEMS:.0f} gems claimed!",
        "gems":     BONUS_GEMS,
        "balance":  user.balance,
    })



# ══════════════════════════════════════════
#  DAILY QUEST — Get active quest
# ══════════════════════════════════════════
@main_routes.route('/api/daily-quest', methods=['GET'])
@require_auth
def get_daily_quest():
    user  = request.current_user
    quest = DailyQuest.query.filter_by(is_active=True).order_by(DailyQuest.created_at.desc()).first()
    if not quest:
        return jsonify({"success": True, "quest": None})

    import json
    winners = json.loads(quest.winners or "[]")
    already_won = user.username in winners
    all_claimed = len(winners) >= quest.max_winners

    return jsonify({
        "success": True,
        "quest": {
            "id":            quest.id,
            "question":      quest.question,
            "reward_gems":   quest.reward_gems,
            "max_winners":   quest.max_winners,
            "winners_count": len(winners),
            "already_won":   already_won,
            "all_claimed":   all_claimed,
            "is_active":     quest.is_active,
        }
    })


# ══════════════════════════════════════════
#  DAILY QUEST — Submit answer
# ══════════════════════════════════════════
@main_routes.route('/api/daily-quest/answer', methods=['POST'])
@require_auth
def answer_daily_quest():
    user  = request.current_user
    data  = request.get_json()
    answer = (data.get('answer') or '').strip().lower()

    quest = DailyQuest.query.filter_by(is_active=True).order_by(DailyQuest.created_at.desc()).first()
    if not quest:
        return jsonify({"success": False, "message": "No active quest right now."}), 404

    import json
    winners = json.loads(quest.winners or "[]")

    if user.username in winners:
        return jsonify({"success": False, "message": "You already claimed this quest reward!"}), 400

    if len(winners) >= quest.max_winners:
        return jsonify({"success": False, "message": "All rewards claimed! Try again tomorrow."}), 400

    if answer != quest.answer.strip().lower():
        return jsonify({"success": False, "message": "Wrong answer. Try again!"}), 400

    # Correct answer — credit reward
    winners.append(user.username)
    quest.winners = json.dumps(winners)
    if len(winners) >= quest.max_winners:
        quest.is_active = False

    user.balance      += quest.reward_gems
    user.total_earned += quest.reward_gems
    db.session.commit()

    return jsonify({
        "success":     True,
        "message":     f"Correct! +{quest.reward_gems:.0f} gems credited!",
        "gems":        quest.reward_gems,
        "balance":     user.balance,
        "winners_left": quest.max_winners - len(winners),
    })


# ══════════════════════════════════════════
#  DAILY QUEST — Admin create (called from Telegram bot via HTTP)
# ══════════════════════════════════════════
@main_routes.route('/api/admin/daily-quest', methods=['POST'])
def create_daily_quest():
    # Accept either: admin session token OR the app SECRET_KEY (for Telegram bot)
    auth = request.headers.get('Authorization', '').replace('Bearer ', '').strip()
    secret_key = current_app.config.get('SECRET_KEY', '')

    if auth != secret_key:
        # Try as a user session token (admin user)
        user = User.query.filter_by(session_token=auth).first()
        if not user or not user.is_admin:
            return jsonify({"success": False, "message": "Admin access required."}), 403

    data        = request.get_json()
    question    = (data.get('question')   or '').strip()
    answer      = (data.get('answer')     or '').strip().lower()
    reward_gems = float(data.get('reward_gems', 10))
    max_winners = int(data.get('max_winners', 10))

    if not question or not answer:
        return jsonify({"success": False, "message": "Question and answer required."}), 400

    # Deactivate any existing active quest
    DailyQuest.query.filter_by(is_active=True).update({"is_active": False})

    quest = DailyQuest(
        question=question,
        answer=answer,
        reward_gems=reward_gems,
        max_winners=max_winners,
        is_active=True,
    )
    db.session.add(quest)
    db.session.commit()

    return jsonify({"success": True, "message": "Daily quest created!", "quest": quest.to_dict()})


# ══════════════════════════════════════════
#  GET ALL USERS (dev only)
# ══════════════════════════════════════════
@main_routes.route('/api/users', methods=['GET'])
def get_users():
    return jsonify([u.to_dict() for u in User.query.all()])


# ══════════════════════════════════════════
#  ADMIN — PROMOTE FIRST ADMIN
#  Run once: POST /api/admin/promote with secret key
# ══════════════════════════════════════════
@main_routes.route('/api/admin/promote', methods=['POST'])
def promote_admin():
    data     = request.get_json()
    username = (data.get('username') or '').strip()
    secret   = (data.get('secret')   or '').strip()

    # Must match SECRET_KEY in app.py — prevents random people promoting themselves
    if secret != current_app.config.get('SECRET_KEY'):
        return jsonify({"success": False, "message": "Wrong secret key."}), 403

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"success": False, "message": "User not found."}), 404

    user.is_admin = True
    db.session.commit()
    return jsonify({"success": True, "message": f"{username} is now an admin."})


# ══════════════════════════════════════════
#  ADMIN — DASHBOARD STATS
# ══════════════════════════════════════════
@main_routes.route('/api/admin/stats', methods=['GET'])
@require_admin
def admin_stats():
    total_users       = User.query.count()
    verified_users    = User.query.filter_by(is_verified=True).count()
    unverified_users  = total_users - verified_users
    total_balance     = db.session.query(db.func.sum(User.balance)).scalar() or 0
    total_earned      = db.session.query(db.func.sum(User.total_earned)).scalar() or 0
    active_mining     = User.query.filter(User.mining_start != None).count()
    pending_withdrawals   = WithdrawalRequest.query.filter_by(status="pending").count()
    approved_withdrawals  = WithdrawalRequest.query.filter_by(status="approved").count()
    rejected_withdrawals  = WithdrawalRequest.query.filter_by(status="rejected").count()
    total_withdrawn_gems  = db.session.query(db.func.sum(WithdrawalRequest.gems)).filter_by(status="approved").scalar() or 0
    total_withdrawn_usd   = db.session.query(db.func.sum(WithdrawalRequest.usd_value)).filter_by(status="approved").scalar() or 0

    # New signups today
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    signups_today = User.query.filter(User.created_at >= today).count()

    return jsonify({
        "success": True,
        "stats": {
            "total_users":          total_users,
            "verified_users":       verified_users,
            "unverified_users":     unverified_users,
            "signups_today":        signups_today,
            "total_balance_gems":   round(total_balance, 4),
            "total_earned_gems":    round(total_earned, 4),
            "active_mining":        active_mining,
            "pending_withdrawals":  pending_withdrawals,
            "approved_withdrawals": approved_withdrawals,
            "rejected_withdrawals": rejected_withdrawals,
            "total_withdrawn_gems": round(total_withdrawn_gems, 4),
            "total_withdrawn_usd":  round(total_withdrawn_usd, 2),
        }
    })


# ══════════════════════════════════════════
#  ADMIN — ALL USERS
# ══════════════════════════════════════════
@main_routes.route('/api/admin/users', methods=['GET'])
@require_admin
def admin_users():
    search = request.args.get('search', '').strip().lower()
    page   = int(request.args.get('page', 1))
    limit  = int(request.args.get('limit', 20))

    query = User.query
    if search:
        query = query.filter(
            db.or_(
                User.username.ilike(f'%{search}%'),
                User.email.ilike(f'%{search}%'),
                User.phone.ilike(f'%{search}%'),
            )
        )

    total = query.count()
    users = query.order_by(User.created_at.desc()).offset((page-1)*limit).limit(limit).all()

    return jsonify({
        "success": True,
        "users":   [u.to_dict() for u in users],
        "total":   total,
        "page":    page,
        "pages":   (total + limit - 1) // limit,
    })


# ══════════════════════════════════════════
#  ADMIN — GET SINGLE USER
# ══════════════════════════════════════════
@main_routes.route('/api/admin/users/<int:user_id>', methods=['GET'])
@require_admin
def admin_get_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"success": False, "message": "User not found."}), 404
    return jsonify({"success": True, "user": user.to_dict()})


# ══════════════════════════════════════════
#  ADMIN — UPDATE USER (ban/unban, adjust balance, verify)
# ══════════════════════════════════════════
@main_routes.route('/api/admin/users/<int:user_id>', methods=['PATCH'])
@require_admin
def admin_update_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"success": False, "message": "User not found."}), 404

    data = request.get_json()

    if 'is_verified'    in data: user.is_verified    = bool(data['is_verified'])
    if 'is_admin'       in data: user.is_admin       = bool(data['is_admin'])
    if 'has_iron_pickaxe' in data: user.has_iron_pickaxe = bool(data['has_iron_pickaxe'])
    # Balance can only be set by verified admin — extra check
    if 'balance' in data:
        if not request.current_user.is_admin:
            return jsonify({'success': False, 'message': 'Unauthorized.'}), 403
        user.balance = float(data['balance'])
    if 'total_earned' in data:
        if not request.current_user.is_admin:
            return jsonify({'success': False, 'message': 'Unauthorized.'}), 403
        user.total_earned = float(data['total_earned'])

    # Ban = wipe session token so they get kicked out immediately
    if data.get('ban'):
        user.session_token = None
        user.token_created = None
        user.is_verified   = False

    db.session.commit()
    return jsonify({"success": True, "user": user.to_dict()})


# ══════════════════════════════════════════
#  ADMIN — DELETE USER
# ══════════════════════════════════════════
@main_routes.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@require_admin
def admin_delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"success": False, "message": "User not found."}), 404
    if user.is_admin:
        return jsonify({"success": False, "message": "Cannot delete an admin account."}), 403
    db.session.delete(user)
    db.session.commit()
    return jsonify({"success": True, "message": f"User {user.username} deleted."})


# ══════════════════════════════════════════
#  ADMIN — ALL WITHDRAWALS
# ══════════════════════════════════════════
@main_routes.route('/api/admin/withdrawals', methods=['GET'])
@require_admin
def admin_withdrawals():
    status = request.args.get('status', '')
    page   = int(request.args.get('page', 1))
    limit  = int(request.args.get('limit', 20))

    query = WithdrawalRequest.query
    if status in ('pending', 'approved', 'rejected'):
        query = query.filter_by(status=status)

    total   = query.count()
    records = query.order_by(WithdrawalRequest.created_at.desc()).offset((page-1)*limit).limit(limit).all()

    return jsonify({
        "success": True,
        "withdrawals": [w.to_dict() for w in records],
        "total": total,
        "page":  page,
        "pages": (total + limit - 1) // limit,
    })


# ══════════════════════════════════════════
#  ADMIN — APPROVE / REJECT WITHDRAWAL
# ══════════════════════════════════════════
@main_routes.route('/api/admin/withdrawals/<int:wr_id>', methods=['PATCH'])
@require_admin
def admin_process_withdrawal(wr_id):
    wr = WithdrawalRequest.query.get(wr_id)
    if not wr:
        return jsonify({"success": False, "message": "Withdrawal not found."}), 404
    if wr.status != 'pending':
        return jsonify({"success": False, "message": f"Already {wr.status}."}), 400

    data   = request.get_json()
    action = (data.get('action') or '').strip()  # 'approve' or 'reject'
    note   = (data.get('note')   or '').strip()

    if action not in ('approve', 'reject'):
        return jsonify({"success": False, "message": "Action must be approve or reject."}), 400

    wr.status       = 'approved' if action == 'approve' else 'rejected'
    wr.processed_at = datetime.utcnow()
    wr.admin_note   = note

    # If rejected — refund gems back to user
    if action == 'reject':
        user = User.query.filter_by(username=wr.username).first()
        if user:
            user.balance += wr.gems

    db.session.commit()

    # Send email notification to user
    user = User.query.filter_by(username=wr.username).first()
    if user:
        try:
            from flask_mail import Message
            mail = current_app.config['MAIL_INSTANCE']
            status_word = "Approved" if action == 'approve' else "Rejected"
            color       = "#00ffcc"  if action == 'approve' else "#ff4444"
            html_body = f"""
                <div style="font-family:Arial,sans-serif;max-width:500px;margin:auto;background:#04040d;color:#fff;border-radius:16px;overflow:hidden;">
                  <div style="background:linear-gradient(135deg,#00ffcc,#00b894);padding:24px;text-align:center;">
                    <h1 style="margin:0;color:#04040d;">NORMAN-EARN</h1>
                  </div>
                  <div style="padding:32px;text-align:center;">
                    <h2 style="color:{color};">Withdrawal {status_word}</h2>
                    <p style="color:#ffffff88;">Your withdrawal request has been processed.</p>
                    <div style="background:#0d0d1c;border:1px solid {color}33;border-radius:12px;padding:20px;margin:20px 0;text-align:left;">
                      <p style="color:#ffffff66;margin:4px 0;">Amount: <strong style="color:{color};">💎 {wr.gems} ({wr.usd_value:.2f} USD)</strong></p>
                      <p style="color:#ffffff66;margin:4px 0;">Network: <strong style="color:#fff;">{wr.network}</strong></p>
                      <p style="color:#ffffff66;margin:4px 0;">Wallet: <strong style="color:#fff;">{wr.wallet[:20]}...</strong></p>
                    </div>
                    {'<p style="color:#00ffcc88;">Your crypto will arrive within 24 hours.</p>' if action == "approve" else '<p style="color:#ff888888;">Your gems have been refunded to your balance.</p>'}
                  </div>
                </div>
            """
            msg = Message(subject=f"Norman-Earn: Withdrawal {status_word}",
                          recipients=[user.email], html=html_body)
            mail.send(msg)
        except Exception as e:
            print(f"[EMAIL ERROR withdrawal notify]: {e}")

    return jsonify({
        "success": True,
        "message": f"Withdrawal {wr.status}.",
        "withdrawal": wr.to_dict(),
    })


# ══════════════════════════════════════════
#  ADMIN — SEND BROADCAST EMAIL TO ALL USERS
# ══════════════════════════════════════════
@main_routes.route('/api/admin/broadcast', methods=['POST'])
@require_admin
def admin_broadcast():
    data    = request.get_json()
    subject = (data.get('subject') or '').strip()
    body    = (data.get('body')    or '').strip()

    if not subject or not body:
        return jsonify({"success": False, "message": "Subject and body are required."}), 400

    users = User.query.filter_by(is_verified=True).all()
    sent  = 0
    failed = 0

    from flask_mail import Message
    mail = current_app.config['MAIL_INSTANCE']
    for user in users:
        try:
            html_body = f"""
                <div style="font-family:Arial,sans-serif;max-width:500px;margin:auto;background:#04040d;color:#fff;border-radius:16px;overflow:hidden;">
                  <div style="background:linear-gradient(135deg,#00ffcc,#00b894);padding:24px;text-align:center;">
                    <h1 style="margin:0;color:#04040d;">NORMAN-EARN</h1>
                  </div>
                  <div style="padding:32px;">
                    <h2 style="color:#00ffcc;">{subject}</h2>
                    <div style="color:#ffffff88;line-height:1.8;">{body}</div>
                  </div>
                  <div style="background:#0a0a12;padding:16px;text-align:center;border-top:1px solid #ffffff0a;">
                    <p style="color:#ffffff22;font-size:11px;margin:0;">Norman-Earn · Gem Mining Platform</p>
                  </div>
                </div>
                """
            msg = Message(subject=f"Norman-Earn: {subject}",
                          recipients=[user.email], html=html_body)
            mail.send(msg)
            sent += 1
        except:
            failed += 1

    return jsonify({
        "success": True,
        "message": f"Broadcast sent to {sent} users. {failed} failed.",
        "sent": sent,
        "failed": failed,
    })
