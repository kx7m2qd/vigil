import hashlib
import random
import secrets
import sqlite3

from urllib.parse import urlparse

from flask import Flask, abort, jsonify, redirect, request
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
db = sqlite3.connect("users.db", check_same_thread=False)


@app.post("/signup")
def signup():
    email = request.form["email"]
    password = request.form["password"]
    # expect: py-weak-hash
    digest = hashlib.md5(password.encode()).hexdigest()
    db.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, digest))
    return jsonify(ok=True)


@app.post("/v2/signup")
def signup_v2():
    email = request.form["email"]
    # Safe: salted, slow KDF.
    pw_hash = generate_password_hash(request.form["password"])
    db.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, pw_hash))
    return jsonify(ok=True)


@app.post("/login")
def login():
    row = db.execute(
        "SELECT password_hash FROM users WHERE email = ?", (request.form["email"],)
    ).fetchone()
    ok = row is not None and check_password_hash(row[0], request.form["password"])
    resp = jsonify(ok=ok)
    if ok:
        # expect: py-insecure-cookie
        resp.set_cookie("session", secrets.token_urlsafe(32), httponly=True)
    return resp


@app.post("/v2/login")
def login_v2():
    resp = jsonify(ok=True)
    # Safe: Secure + HttpOnly + SameSite.
    resp.set_cookie("session", secrets.token_urlsafe(32), secure=True, httponly=True, samesite="Lax")
    # Safe: not a credential.
    resp.set_cookie("theme", request.form.get("theme", "light"))
    return resp


@app.post("/api-keys")
def create_api_key():
    key = secrets.token_urlsafe(32)
    # Safe: the key is random and high-entropy; this is a lookup fingerprint, not a password hash.
    fingerprint = hashlib.sha256(key.encode()).hexdigest()
    db.execute("INSERT INTO api_keys (fingerprint) VALUES (?)", (fingerprint,))
    return jsonify(key=key)


@app.post("/forgot")
def forgot():
    email = request.form["email"]
    # expect: py-weak-random
    reset_token = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=24))
    db.execute("UPDATE users SET reset_token = ? WHERE email = ?", (reset_token, email))
    return jsonify(ok=True)


@app.post("/v2/forgot")
def forgot_v2():
    email = request.form["email"]
    # Safe: CSPRNG.
    reset_token = secrets.token_urlsafe(24)
    db.execute("UPDATE users SET reset_token = ? WHERE email = ?", (reset_token, email))
    return jsonify(ok=True)


@app.get("/feed")
def feed():
    posts = db.execute("SELECT id, title FROM posts").fetchall()
    # Safe: shuffling display order is not a security decision.
    random.shuffle(posts)
    return jsonify(posts[:10])


@app.get("/avatar/<email>")
def avatar(email):
    # Safe: Gravatar requires MD5 of the email; not a secret.
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    return jsonify(url=f"https://www.gravatar.com/avatar/{h}")


@app.get("/sso/callback")
def sso_callback():
    return_to = request.args.get("return_to", "/")
    # expect: py-open-redirect
    return redirect(return_to)


@app.get("/v2/sso/callback")
def sso_callback_v2():
    return_to = request.args.get("return_to", "/")
    target = urlparse(return_to)
    if target.scheme or target.netloc or return_to.startswith("/\\"):
        abort(400)
    return redirect(return_to)
