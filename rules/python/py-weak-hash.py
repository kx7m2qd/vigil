import hashlib

from flask import request
from werkzeug.security import generate_password_hash


def set_password(user, password):
    # ruleid: py-weak-hash
    user.pw_hash = hashlib.md5(password.encode()).hexdigest()


def apop(self, user, secret):
    digest = self.timestamp + secret
    # ruleid: py-weak-hash
    digest = hashlib.md5(digest).hexdigest()
    return digest


def login():
    h = hashlib.sha1()
    # ruleid: py-weak-hash
    h.update(request.form["password"].encode())
    return h.hexdigest()


def register(db, name, pw):
    # ruleid: py-weak-hash
    db.insert(name=name, password_hash=hashlib.md5(pw.encode()).hexdigest())


def save_hash(directory, bar):
    h = hashlib.new("md5")
    h.update(bar)
    result = h.digest()
    f = open(f"{directory}/passwordFile.txt", "a")
    # ruleid: py-weak-hash
    f.write(f"hash_value={result}\n")


def store_reset(row, data):
    # ruleid: py-weak-hash
    row["password"] = hashlib.sha1(data).hexdigest()


def change_password(user, new_password):
    # ruleid: py-weak-hash
    user.hashed_password = hashlib.sha1(new_password.encode()).hexdigest()


def etag(body):
    # ok: py-weak-hash
    return hashlib.md5(body).hexdigest()


def upload(filename, sign_password=None):
    """Upload a file, signing it with the given passphrase."""
    sign(filename, sign_password)
    with open(filename, "rb") as f:
        file_data = f.read()
    # ok: py-weak-hash
    return hashlib.md5(file_data).hexdigest()


def set_password_fixed(user, password):
    # ok: py-weak-hash
    user.pw_hash = generate_password_hash(password)


def fingerprint(password):
    # ok: py-weak-hash
    return hashlib.sha256(password.encode()).hexdigest()


def legacy_lookup(password):
    # ok: py-weak-hash
    return hashlib.md5(password.encode(), usedforsecurity=False).hexdigest()


def copy_form(user):
    # ok: py-weak-hash
    user.password = request.form["password"]


def sign(filename, passphrase):
    pass
