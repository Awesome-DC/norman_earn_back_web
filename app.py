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
    'https://norman-earn-git-main-awesome-dcs-projects.vercel.app',
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
app.config['MAIL_PORT']           = 465
app.config['MAIL_USE_TLS']        = False
app.config['MAIL_USE_SSL']        = True
app.config['MAIL_USERNAME']       = 'normansearn@gmail.com'
app.config['MAIL_PASSWORD']       = 'kqimrnokgvpjyuny'
app.config['MAIL_DEFAULT_SENDER'] = ('Norman-Earn', 'normansearn@gmail.com')

# ── Telegram Bot config (also used by routes.py for alerts) ──
BOT_TOKEN     = "8360348188:AAFE5QV4t6qsSjYQg6hw_6jxvDpPyiPa5Os"
ADMIN_CHAT_ID = 8038576832

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
    db.create_all()
    # Fix phone column size for international numbers
    try:
        from sqlalchemy import text
        with db.engine.begin() as conn:
            conn.execute(text('ALTER TABLE "user" ALTER COLUMN phone TYPE VARCHAR(20)'))
            print('[DB] Phone column updated to VARCHAR(20)')
    except Exception as e:
        print(f'[DB] Phone column already correct or error: {e}')
    print('[DB] Tables ready.')

if __name__ == '__main__':
    app.run(debug=True)
