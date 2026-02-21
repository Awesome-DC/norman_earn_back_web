from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    phone         = db.Column(db.String(20), unique=True, nullable=True)
    password      = db.Column(db.String(255), nullable=False)

    # Email OTP verification
    is_verified       = db.Column(db.Boolean, default=False)
    otp_code          = db.Column(db.String(6), nullable=True)
    otp_expires       = db.Column(db.DateTime, nullable=True)

    # Referral
    referral_code     = db.Column(db.String(30), unique=True, nullable=True)
    referred_by       = db.Column(db.String(30), nullable=True)

    # Anti-cracker
    has_iron_pickaxe  = db.Column(db.Boolean, default=False)

    # Ban
    is_banned         = db.Column(db.Boolean, default=False)

    # Daily bonus
    last_bonus_claim  = db.Column(db.DateTime, nullable=True)

    # Achievements — JSON string of claimed achievement IDs e.g. '["first_mine","inv5"]'
    achievements_claimed = db.Column(db.Text, default="[]")

    # Admin
    is_admin          = db.Column(db.Boolean, default=False)

    # ── NEW: JWT session token ──
    session_token     = db.Column(db.String(64), nullable=True)
    token_created     = db.Column(db.DateTime, nullable=True)

    # ── NEW: Backend mining state ──
    balance           = db.Column(db.Float, default=2.0)
    total_earned      = db.Column(db.Float, default=2.0)
    mining_start      = db.Column(db.DateTime, nullable=True)  # None = idle
    upgrades_owned    = db.Column(db.Text, default="{}")       # JSON string

    # Brute force protection
    failed_logins     = db.Column(db.Integer, default=0)   # consecutive failed login attempts
    locked_until      = db.Column(db.DateTime, nullable=True) # account locked until this time
    otp_attempts      = db.Column(db.Integer, default=0)   # wrong OTP attempts

    created_at        = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id":              self.id,
            "username":        self.username,
            "email":           self.email,
            "phone":           self.phone,
            "is_verified":     self.is_verified,
            "referral_code":   self.referral_code,
            "referred_by":     self.referred_by,
            "has_iron_pickaxe":self.has_iron_pickaxe,
            "is_banned":       self.is_banned,
            "last_bonus_claim": self.last_bonus_claim.isoformat() if self.last_bonus_claim else None,
            "achievements_claimed": self.achievements_claimed or "[]",
            "is_admin":        self.is_admin,
            "balance":         self.balance,
            "total_earned":    self.total_earned,
            "mining_start":    self.mining_start.isoformat() if self.mining_start else None,
            "upgrades_owned":  self.upgrades_owned,
        }


class WithdrawalRequest(db.Model):
    """── NEW: Track every withdrawal request ──"""
    id          = db.Column(db.Integer, primary_key=True)
    username    = db.Column(db.String(80), nullable=False)
    email       = db.Column(db.String(120), nullable=False)
    network     = db.Column(db.String(30), nullable=False)   # e.g. usdt_bep20
    wallet      = db.Column(db.String(200), nullable=False)
    gems        = db.Column(db.Float, nullable=False)
    usd_value   = db.Column(db.Float, nullable=False)
    status      = db.Column(db.String(20), default="pending") # pending|approved|rejected
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    processed_at= db.Column(db.DateTime, nullable=True)
    admin_note  = db.Column(db.String(300), nullable=True)

    def to_dict(self):
        return {
            "id":           self.id,
            "username":     self.username,
            "email":        self.email,
            "network":      self.network,
            "wallet":       self.wallet,
            "gems":         self.gems,
            "usd_value":    self.usd_value,
            "status":       self.status,
            "created_at":   self.created_at.isoformat(),
            "processed_at": self.processed_at.isoformat() if self.processed_at else None,
            "admin_note":   self.admin_note,
        }
