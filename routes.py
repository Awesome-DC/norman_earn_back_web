from flask import Blueprint, request, jsonify, current_app
from dotenv import load_dotenv
import os
load_dotenv()
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, WithdrawalRequest
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
    import requests as req
    app = current_app._get_current_object()
    resend_key = app.config.get('RESEND_API_KEY', '')
    mail_from  = app.config.get('MAIL_FROM', 'onboarding@resend.dev')

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

    def send_async(app, to_email, subject, html_body, resend_key, mail_from):
        with app.app_context():
            try:
                response = req.post(
                    "https://api.resend.com/emails",
                    headers={
                        "Authorization": f"Bearer {resend_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "from": f"Norman-Earn <{mail_from}>",
                        "to": [to_email],
                        "subject": subject,
                        "html": html_body
                    }
                )
                if response.status_code == 200 or response.status_code == 201:
                    print(f"[EMAIL] Sent successfully to {to_email}")
                else:
                    print(f"[EMAIL ERROR] Resend returned {response.status_code}: {response.text}")
            except Exception as e:
                print(f"[EMAIL ERROR] {e}")

    Thread(target=send_async, args=(app, user.email, subject, html_body, resend_key, mail_from), daemon=True).start()

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
    # IP rate limit: 5 signups per IP per day
    ip = request.remote_addr
    allowed, retry = rate_limit(f'signup_{ip}', 5, 86400)
    if not allowed:
        return jsonify({"success": False,
            "message": "Too many signups from your network today. Try again tomorrow."}), 429

    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "No data received."}), 400

    username = (data.get('username') or '').strip()
    email    = (data.get('email')    or '').strip().lower()
    phone    = (data.get('phone')    or '').strip()
    password = (data.get('password') or '')
    ref_code = (data.get('referral_code') or '').strip().upper()

    if not all([username, email, phone, password]):
        return jsonify({"success": False, "message": "All fields are required."}), 400
    if len(password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters."}), 400
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
        if not referrer.is_verified:
            return jsonify({"success": False, "message": "Referral code belongs to an unverified account."}), 400

    otp         = gen_otp()
    otp_expires = datetime.utcnow() + timedelta(minutes=15)

    new_user = User(
        username=username,
        email=email,
        phone=phone,
        password=generate_password_hash(password),
        otp_code=otp,
        otp_expires=otp_expires,
        referral_code=gen_referral_code(username),
        referred_by=ref_code if referrer else None,
        balance=2.0,
        total_earned=2.0,
        upgrades_owned="{}",
    )
    db.session.add(new_user)
    db.session.commit()

    try:
        send_otp_email(new_user, otp,
            subject="🔑 Your Norman-Earn Verification Code",
            heading=f"Hey {new_user.username}! 👋",
            body_text="Use the code below to verify your email and start mining gems."
        )
    except Exception as e:
        print(f"[EMAIL ERROR]: {e}")
        return jsonify({"success": True, "message": "Account created but email failed.", "email": email, "email_error": True}), 201

    return jsonify({"success": True, "message": f"Code sent to {email}.", "email": email}), 201


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
@main_routes.route('/api/sync', methods=['POST'])
@require_auth
def sync_state():
    user = request.current_user
    data = request.get_json()

    old_total = user.total_earned

    if 'balance' in data:
        user.balance = float(data['balance'])
    if 'total_earned' in data:
        user.total_earned = float(data['total_earned'])
    if 'upgrades_owned' in data:
        user.upgrades_owned = json.dumps(data['upgrades_owned'])
    if 'mining_start' in data:
        ms = data['mining_start']
        user.mining_start = datetime.fromisoformat(ms) if ms else None

    # ── 10% referral cut: when total_earned increases, give 10% to referrer ──
    new_total = user.total_earned
    if user.referred_by and new_total > old_total:
        gems_earned = new_total - old_total
        cut = round(gems_earned * 0.10, 6)
        referrer = User.query.filter_by(referral_code=user.referred_by).first()
        if referrer and cut > 0:
            referrer.balance      += cut
            referrer.total_earned += cut
            print(f'[REFERRAL CUT] {referrer.username} earned +{cut:.4f} gems (10% of {user.username} mined {gems_earned:.4f})')

    db.session.commit()
    return jsonify({"success": True, "message": "State synced."})


# ══════════════════════════════════════════
#  BUY IRON PICKAXE — mark on backend
# ══════════════════════════════════════════
@main_routes.route('/api/buy-iron-pickaxe', methods=['POST'])
@require_auth
def buy_iron_pickaxe():
    user = request.current_user
    user.has_iron_pickaxe = True
    db.session.commit()
    return jsonify({
        "success": True,
        "message": "Iron Pickaxe recorded.",
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

    network = (data.get('network') or '').strip()
    wallet  = (data.get('wallet')  or '').strip()
    gems    = float(data.get('gems', 0))

    if not network or not wallet:
        return jsonify({"success": False, "message": "Network and wallet address are required."}), 400
    if gems < 50:
        return jsonify({"success": False, "message": "Minimum withdrawal is 50 gems."}), 400
    if gems > user.balance:
        return jsonify({"success": False, "message": "Insufficient balance."}), 400

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
    for r in referred_users:
        entry = {
            "username":        r.username,
            "joined":          r.created_at.strftime("%Y-%m-%d"),
            "is_verified":     r.is_verified,
            "has_iron_pickaxe":r.has_iron_pickaxe,
            "earned":          r.total_earned,
        }
        if r.is_verified and r.has_iron_pickaxe:
            verified.append(entry)
        else:
            pending.append(entry)

    return jsonify({
        "success":      True,
        "verified":     verified,
        "pending":      pending,
        "count":        len(verified),
        "referral_code":user.referral_code,
        "referred_by":  referred_by_username,
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

    # Delete withdrawal records too
    WithdrawalRequest.query.filter_by(username=user.username).delete()
    db.session.delete(user)
    db.session.commit()
    return jsonify({"success": True, "message": "Account deleted."})


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

    # Check if already claimed today (compare date only, not time)
    if user.last_bonus_claim:
        last = user.last_bonus_claim
        # Same calendar day in UTC = already claimed
        if last.date() >= now.date():
            # Calculate seconds until midnight UTC
            from datetime import timezone
            midnight = datetime(now.year, now.month, now.day, 23, 59, 59)
            secs_left = int((midnight - now).total_seconds()) + 1
            return jsonify({
                "success":    False,
                "message":    "Already claimed today.",
                "next_claim": secs_left,  # seconds until they can claim again
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
    if 'balance'        in data: user.balance        = float(data['balance'])
    if 'total_earned'   in data: user.total_earned   = float(data['total_earned'])

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
            import requests as req
            resend_key = current_app.config.get('RESEND_API_KEY', '')
            mail_from  = current_app.config.get('MAIL_FROM', 'onboarding@resend.dev')
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
            req.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {resend_key}", "Content-Type": "application/json"},
                json={"from": f"Norman-Earn <{mail_from}>", "to": [user.email],
                      "subject": f"Norman-Earn: Withdrawal {status_word}", "html": html_body}
            )
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

    import requests as req
    resend_key = current_app.config.get('RESEND_API_KEY', '')
    mail_from  = current_app.config.get('MAIL_FROM', 'onboarding@resend.dev')
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
            req.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {resend_key}", "Content-Type": "application/json"},
                json={"from": f"Norman-Earn <{mail_from}>", "to": [user.email],
                      "subject": f"Norman-Earn: {subject}", "html": html_body}
            )
            sent += 1
        except:
            failed += 1

    return jsonify({
        "success": True,
        "message": f"Broadcast sent to {sent} users. {failed} failed.",
        "sent": sent,
        "failed": failed,
    })
