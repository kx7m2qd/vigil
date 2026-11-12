import urllib.parse

import markupsafe

from flask import Flask, request, session

app = Flask(__name__)


@app.route("/impersonate", methods=["POST"])
def impersonate():
    # ruleid: py-trust-boundary
    session["user_id"] = request.form["uid"]
    return "ok"


@app.route("/remember")
def remember():
    who = urllib.parse.unquote_plus(request.cookies.get("who", ""))
    # ruleid: py-trust-boundary
    session["username"] = who.strip()
    return "ok"


@app.route("/role", methods=["POST"])
def set_role():
    # ruleid: py-trust-boundary
    session["is_admin"] = request.args.get("admin") == "1" or request.form["role"]
    return "ok"


@app.route("/pref", methods=["POST"])
def save_pref():
    name = request.form["name"]
    # ruleid: py-trust-boundary
    session[name] = request.form["value"]
    return "ok"


@app.route("/restore", methods=["POST"])
def restore():
    # ruleid: py-trust-boundary
    session.update(request.get_json())
    return "ok"


def django_login(request):
    # ruleid: py-trust-boundary
    request.session["account_id"] = int(request.POST["account"])
    return None


@app.route("/login", methods=["POST"])
def login():
    user = User.query.filter_by(name=request.form["name"]).first()
    if user is None or not user.check_password(request.form["password"]):
        return "no", 401
    # ok: py-trust-boundary
    session["user_id"] = user.id
    return "ok"


@app.route("/theme", methods=["POST"])
def theme():
    # ok: py-trust-boundary
    session["theme"] = request.form.get("theme", "light")
    return "ok"


@app.route("/cart", methods=["POST"])
def cart():
    # ok: py-trust-boundary
    session["cart"] = request.get_json()["items"]
    return "ok"


@app.route("/next")
def remember_next():
    # ok: py-trust-boundary
    session["next"] = request.args.get("next", "/")
    return "ok"


class User:
    query = None


@app.route("/wrapped")
def wrapped_param():
    wrapped = RequestWrapper(request)
    uid = wrapped.get_form_parameter("uid")
    # ruleid: py-trust-boundary
    session["userid"] = markupsafe.escape(uid)
    return "ok"


class RequestWrapper:
    def __init__(self, req):
        self.req = req
