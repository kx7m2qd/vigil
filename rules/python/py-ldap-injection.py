import re

import ldap
import ldap.filter
import ldap3
from flask import Flask, request
from ldap3.utils.conv import escape_filter_chars

app = Flask(__name__)
SERVER = ldap3.Server("ldap://directory.internal")
BASE = "ou=users,dc=example,dc=com"


def get_connection():
    return ldap3.Connection(SERVER, auto_bind=True)


@app.route("/user")
def find_user():
    uid = request.args.get("uid")
    conn = get_connection()
    # ruleid: py-ldap-injection
    conn.search(BASE, f"(&(objectClass=person)(uid={uid}))", attributes=["cn"])
    return str(conn.entries)


@app.route("/login", methods=["POST"])
def login():
    user = request.form["user"]
    with ldap3.Connection(SERVER, auto_bind=True) as c:
        # ruleid: py-ldap-injection
        c.search(search_base=BASE, search_filter="(uid=" + user + ")")
        return "ok" if c.entries else "no"


@app.route("/group")
def group():
    cn = request.args["cn"]
    l = ldap.initialize("ldap://directory.internal")
    # ruleid: py-ldap-injection
    return str(l.search_s(BASE, ldap.SCOPE_SUBTREE, "(cn=%s)" % cn))


def django_view(request):
    mail = request.GET["mail"]
    ldap_conn = get_connection()
    # ruleid: py-ldap-injection
    ldap_conn.search(BASE, "(mail={})".format(mail))
    return str(ldap_conn.entries)


@app.route("/user-safe")
def find_user_safe():
    uid = escape_filter_chars(request.args.get("uid", ""))
    conn = get_connection()
    # ok: py-ldap-injection
    conn.search(BASE, f"(&(objectClass=person)(uid={uid}))", attributes=["cn"])
    return str(conn.entries)


@app.route("/group-safe")
def group_safe():
    l = ldap.initialize("ldap://directory.internal")
    # ok: py-ldap-injection
    return str(l.search_s(BASE, ldap.SCOPE_SUBTREE, ldap.filter.filter_format("(cn=%s)", [request.args["cn"]])))


@app.route("/static")
def static():
    conn = get_connection()
    # ok: py-ldap-injection
    conn.search(BASE, "(objectClass=person)")
    return str(conn.entries)


@app.route("/grep")
def grep():
    # ok: py-ldap-injection
    return str(re.search(r"\d+", request.args["text"]))


@app.route("/items")
def items():
    index = SearchIndex()
    # ok: py-ldap-injection
    return str(index.search("products", request.args["q"]))


class SearchIndex:
    def search(self, name, query):
        return []
