import os
import uuid
import base64
import datetime
import threading
import time
from math import ceil

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, desc
from sqlalchemy.orm import DeclarativeBase, Session

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

from backup import backup_database

# ---------------- App setup ----------------
app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET", "change-this-to-a-very-secret-value")

# In-memory map to keep derived encryption keys for active sessions:
# TOKEN (str) -> key_bytes (32 urlsafe base64 bytes)
ENC_KEYS = {}

# ---------------- Database ----------------
engine = create_engine("sqlite:///diary.db", connect_args={"check_same_thread": False})

class Base(DeclarativeBase): pass

class User(Base, UserMixin):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False)
    password = Column(String(255), nullable=False)   # hashed password
    salt = Column(String(100), nullable=False)       # base64 salt for KDF

class Entry(Base):
    __tablename__ = "entries"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    title = Column(Text, nullable=False)       # encrypted (fernet token string)
    description = Column(Text, nullable=False) # encrypted
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow)

Base.metadata.create_all(engine)

# ---------------- Login manager ----------------
login_manager = LoginManager(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(uid):
    with Session(engine) as s:
        return s.get(User, int(uid))

# ---------------- Helper: derive key from password + salt ----------------
def derive_fernet_key(password: str, salt_b64: str) -> bytes:
    """
    Derive a 32-byte key and return urlsafe_b64encoded bytes suitable for Fernet.
    """
    password_bytes = password.encode()
    salt = base64.b64decode(salt_b64)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=250_000,
    )
    key = kdf.derive(password_bytes)
    return base64.urlsafe_b64encode(key)  # Fernet key

# ---------------- Auto backup thread ----------------
def auto_backup_loop():
    while True:
        try:
            backup_database()
        except Exception as ex:
            print("Backup error:", ex)
        time.sleep(86400)  # 24 hours

threading.Thread(target=auto_backup_loop, daemon=True).start()

# ---------------- Routes ----------------
@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("entries"))
    return render_template("index.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Please fill username and password.")
            return redirect(url_for("register"))

        # create per-user salt
        salt = os.urandom(16)
        salt_b64 = base64.b64encode(salt).decode()

        with Session(engine) as s:
            if s.query(User).filter_by(username=username).first():
                flash("Username already exists.")
                return redirect(url_for("register"))
            user = User(
                username=username,
                password=generate_password_hash(password),
                salt=salt_b64
            )
            s.add(user)
            s.commit()
        flash("Registered. Now login.")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        with Session(engine) as s:
            user = s.query(User).filter_by(username=username).first()
            if not user or not check_password_hash(user.password, password):
                flash("Invalid username or password.")
                return redirect(url_for("login"))

            # Derive encryption key now (from password + user's salt)
            try:
                fernet_key = derive_fernet_key(password, user.salt)  # bytes
            except Exception as ex:
                flash("Encryption key derivation failed.")
                return redirect(url_for("login"))

            # Generate a random token and keep key server-side in ENC_KEYS
            token = uuid.uuid4().hex
            ENC_KEYS[token] = fernet_key  # store key bytes (urlsafe_b64)
            session['enc_token'] = token  # store token in client session (signed cookie)
            login_user(user)
            return redirect(url_for("entries"))
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    # remove stored key
    token = session.pop('enc_token', None)
    if token and token in ENC_KEYS:
        ENC_KEYS.pop(token, None)
    logout_user()
    return redirect(url_for("index"))


def get_fernet_for_current_session():
    token = session.get('enc_token')
    if not token:
        return None
    key = ENC_KEYS.get(token)
    if not key:
        return None
    return Fernet(key)


# ---------------- Entry routes ----------------
@app.route("/entries")
@login_required
def entries():
    page = int(request.args.get("page", 1) or 1)
    per = 15
    f = get_fernet_for_current_session()
    if f is None:
        flash("Encryption key not available. Please log in again.")
        return redirect(url_for("logout"))

    with Session(engine) as s:
        total = s.query(Entry).filter_by(user_id=current_user.id).count()
        pages = max(1, ceil(total / per))
        rows = (s.query(Entry)
                .filter_by(user_id=current_user.id)
                .order_by(desc(Entry.created_at))
                .offset((page - 1) * per)
                .limit(per)
                .all())

        entries = []
        for r in rows:
            try:
                title = f.decrypt(r.title.encode()).decode()
            except Exception:
                title = "[Decrypt error]"
            try:
                desc = f.decrypt(r.description.encode()).decode()
            except Exception:
                desc = "[Decrypt error]"
            entries.append({
                "id": r.id,
                "title": title,
                "description": desc,
                "created_at": r.created_at,
                "updated_at": r.updated_at
            })
    return render_template("entries.html", entries=entries, page=page, pages=pages)


@app.route("/add", methods=["GET","POST"])
@login_required
def add_entry():
    f = get_fernet_for_current_session()
    if f is None:
        flash("Encryption key not available.")
        return redirect(url_for("logout"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        if not title or not description:
            flash("Both title and description are required.")
            return redirect(url_for("add_entry"))

        enc_title = f.encrypt(title.encode()).decode()
        enc_desc = f.encrypt(description.encode()).decode()
        with Session(engine) as s:
            e = Entry(
                user_id=current_user.id,
                title=enc_title,
                description=enc_desc,
                created_at=datetime.datetime.utcnow(),
                updated_at=datetime.datetime.utcnow()
            )
            s.add(e)
            s.commit()
        flash("Entry saved.")
        return redirect(url_for("entries"))
    return render_template("diary.html")


@app.route("/edit/<int:id>", methods=["GET","POST"])
@login_required
def edit_entry(id):
    f = get_fernet_for_current_session()
    if f is None:
        flash("Encryption key not available.")
        return redirect(url_for("logout"))

    with Session(engine) as s:
        e = s.get(Entry, id)
        if not e or e.user_id != current_user.id:
            flash("Not found.")
            return redirect(url_for("entries"))

        if request.method == "POST":
            title = request.form.get("title", "").strip()
            description = request.form.get("description", "").strip()
            if not title or not description:
                flash("Both fields required.")
                return redirect(url_for("edit_entry", id=id))
            e.title = f.encrypt(title.encode()).decode()
            e.description = f.encrypt(description.encode()).decode()
            e.updated_at = datetime.datetime.utcnow()
            s.commit()
            flash("Updated.")
            return redirect(url_for("entries"))

        # GET -> decrypt for form
        try:
            dec_title = f.decrypt(e.title.encode()).decode()
        except Exception:
            dec_title = ""
        try:
            dec_description = f.decrypt(e.description.encode()).decode()
        except Exception:
            dec_description = ""
        return render_template("edit.html", entry=e, title=dec_title, description=dec_description)


@app.route("/delete/<int:id>", methods=["POST"])
@login_required
def delete_entry(id):
    with Session(engine) as s:
        e = s.get(Entry, id)
        if e and e.user_id == current_user.id:
            s.delete(e)
            s.commit()
            flash("Deleted.")
    return redirect(url_for("entries"))

# ---------------- Utility: change password (re-encryption NOT handled) ----------------
@app.route("/change_password", methods=["GET","POST"])
@login_required
def change_password():
    """
    NOTE: This implementation changes the stored hashed password and salt.
    It DOES NOT re-encrypt existing entries with the new password-derived key.
    To fully support password change, you'd need to decrypt all entries with old key
    and re-encrypt with new key. That requires the old password (available now)
    and should be implemented carefully. For now we show a simple route that enforces
    the warning.
    """
    if request.method == "POST":
        old = request.form.get("old_password", "")
        new = request.form.get("new_password", "")
        if not old or not new:
            flash("Fill both fields."); return redirect(url_for("change_password"))
        with Session(engine) as s:
            user = s.get(User, current_user.id)
            if not user or not check_password_hash(user.password, old):
                flash("Old password incorrect."); return redirect(url_for("change_password"))

            # WARNING to user
            flash("Warning: existing entries will NOT be re-encrypted automatically. This demo does not rotate keys.")
            # update password and salt
            new_salt = base64.b64encode(os.urandom(16)).decode()
            user.password = generate_password_hash(new)
            user.salt = new_salt
            s.commit()
            # clear existing enc key
            token = session.pop('enc_token', None)
            if token:
                ENC_KEYS.pop(token, None)
            logout_user()
            flash("Password changed. Please login again (and note: older entries cannot be decrypted).")
            return redirect(url_for("login"))
    return render_template("change_password.html")


# ---------------- Run ----------------
if __name__ == "__main__":
    os.makedirs("backups", exist_ok=True)
    app.run(debug=True)
