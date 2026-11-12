from fastapi import Response
from flask import Flask, make_response

app = Flask(__name__)


def login(sid):
    resp = make_response("ok")
    # ruleid: py-insecure-cookie
    resp.set_cookie("prefs", "dark", secure=False, httponly=True)
    # ruleid: py-insecure-cookie
    resp.set_cookie("session_id", sid, httponly=True)
    # ruleid: py-insecure-cookie
    resp.set_cookie("auth_token", sid)
    return resp


def api_login(response: Response, token: str):
    # ruleid: py-insecure-cookie
    response.set_cookie(key="access_token", value=token, httponly=True)


def login_fixed(sid):
    resp = make_response("ok")
    # ok: py-insecure-cookie
    resp.set_cookie("session_id", sid, secure=True, httponly=True, samesite="Lax")
    # ok: py-insecure-cookie
    resp.set_cookie("theme", "dark")
    # ok: py-insecure-cookie
    resp.set_cookie("sid", sid, secure=app.config["COOKIE_SECURE"])
    return resp


def api_login_fixed(response: Response, token: str):
    # ok: py-insecure-cookie
    response.set_cookie(key="access_token", value=token, httponly=True, secure=True)


# ruleid: py-insecure-cookie
SESSION_COOKIE_SECURE = False
# ruleid: py-insecure-cookie
app.config["SESSION_COOKIE_SECURE"] = False
# ruleid: py-insecure-cookie
app.config.update(SESSION_COOKIE_SECURE=False, SESSION_COOKIE_HTTPONLY=True)
# ok: py-insecure-cookie
CSRF_COOKIE_SECURE = True
# ok: py-insecure-cookie
DEBUG = False
