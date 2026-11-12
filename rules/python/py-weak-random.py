import random
import secrets
import string
from random import randint

from flask import make_response, session


def remember_me(mysession, cookie):
    value = str(random.normalvariate(0, 1))[2:]
    # ruleid: py-weak-random
    mysession[cookie] = value


def start_reset(user):
    # ruleid: py-weak-random
    user.reset_token = "".join(random.choice(string.ascii_letters) for _ in range(32))


def send_otp():
    # ruleid: py-weak-random
    otp_code = randint(100000, 999999)
    return otp_code


def login_response():
    sid = "%x" % random.getrandbits(128)
    resp = make_response("ok")
    # ruleid: py-weak-random
    resp.set_cookie("sid", sid)
    return resp


def csrf():
    # ruleid: py-weak-random
    session["csrf"] = random.random()


def new_key(db, owner):
    # ruleid: py-weak-random
    db.insert(owner=owner, api_key=random.randbytes(16).hex())


def make_reset():
    # ruleid: py-weak-random
    reset_token = "%032x" % random.getrandbits(128)
    return reset_token


def backoff(delay):
    # ok: py-weak-random
    return delay * (1 + random.random())


def pick(items):
    # ok: py-weak-random
    picked = random.sample(items, 3)
    return picked


def mime_boundary():
    # ok: py-weak-random
    token = random.randrange(10**9)
    return "===%d==" % token


def start_reset_fixed(user):
    # ok: py-weak-random
    user.reset_token = secrets.token_urlsafe(32)


def login_response_fixed():
    rng = random.SystemRandom()
    resp = make_response("ok")
    # ok: py-weak-random
    resp.set_cookie("sid", str(rng.getrandbits(128)))
    return resp


def remember_me_fixed(mysession, cookie):
    # ok: py-weak-random
    mysession[cookie] = str(random.SystemRandom().random())
