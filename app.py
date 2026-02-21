from flask import Flask
from flask_cors import CORS
from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from models import db
from routes import main_routes
from dotenv import load_dotenv
import os

load_dotenv()  # reads .env file from same directory

app = Flask(__name__)
# Only allow requests from your frontend — change this to your real domain in production
CORS(app, origins=[
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'https://norman-earn.onrender.com',
    'https://norman-earn.vercel.app',
])

# ── Security headers — added to every response ──
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options']  = 'nosniff'
    response.headers['X-Frame-Options']          = 'DENY'
    response.headers['X-XSS-Protection']         = '1; mode=block'
    response.headers['Referrer-Policy']          = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy']       = 'geolocation=(), microphone=(), camera=()'
    return response

# ── Database ──
# PostgreSQL in production, SQLite for local dev
_db_url = os.getenv('DATABASE_URL', 'sqlite:///users.db')
# Render gives 'postgres://' but SQLAlchemy needs 'postgresql://'
if _db_url.startswith('postgres://'):
    _db_url = _db_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = _db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY']                     = os.getenv('SECRET_KEY', 'fallback-dev-secret-change-me')

# ── Gmail SMTP ──
app.config['MAIL_SERVER']         = 'smtp.gmail.com'
app.config['MAIL_PORT']           = 587
app.config['MAIL_USE_TLS']        = True
app.config['MAIL_USERNAME']       = os.getenv('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD']       = os.getenv('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = ('Norman-Earn', os.getenv('MAIL_USERNAME', ''))

# ── Telegram Bot config (also used by routes.py for alerts) ──
BOT_TOKEN     = os.getenv('BOT_TOKEN', '')
ADMIN_CHAT_ID = int(os.getenv('ADMIN_CHAT_ID', '0'))

# ── Rate limiter — protects against brute force and spam ──
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
    headers_enabled=True,  # sends X-RateLimit headers so client knows limits
)
app.config['LIMITER'] = limiter

db.init_app(app)
mail = Mail(app)
app.config['MAIL_INSTANCE'] = mail

app.register_blueprint(main_routes)

with app.app_context():
    db.create_all()  # Creates all tables fresh on PostgreSQL
    print('[DB] Tables ready.')

if __name__ == '__main__':
    app.run(debug=True)
