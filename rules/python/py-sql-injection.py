import sqlite3

from flask import Flask, request
from sqlalchemy import text

app = Flask(__name__)
db = sqlite3.connect("app.db")


@app.route("/user")
def user():
    name = request.args.get("name")
    cur = db.cursor()
    # ruleid: py-sql-injection
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return str(cur.fetchall())


@app.route("/order")
def order():
    cur = db.cursor()
    # ruleid: py-sql-injection
    cur.execute("SELECT * FROM orders WHERE id = %s" % request.args["id"])
    return str(cur.fetchall())


@app.route("/report")
def report(session=None):
    col = request.args.get("sort")
    # ruleid: py-sql-injection
    return str(session.execute(text("SELECT * FROM sales ORDER BY " + col)).all())


@app.route("/safe")
def safe():
    cur = db.cursor()
    # ok: py-sql-injection
    cur.execute("SELECT * FROM users WHERE name = ?", (request.args.get("name"),))
    return str(cur.fetchall())


@app.route("/safe-int")
def safe_int():
    oid = int(request.args["id"])
    cur = db.cursor()
    # ok: py-sql-injection
    cur.execute(f"SELECT * FROM orders WHERE id = {oid}")
    return str(cur.fetchall())
