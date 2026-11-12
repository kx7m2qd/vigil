import os
import pickle
import shlex
import sqlite3
import subprocess

import yaml
from flask import Flask, jsonify, render_template, request
from markupsafe import escape

app = Flask(__name__)
db = sqlite3.connect("app.db", check_same_thread=False)


@app.get("/search")
def search():
    term = request.args.get("q", "")
    cur = db.cursor()
    # expect: py-sql-injection
    cur.execute(f"SELECT id, title FROM posts WHERE title LIKE '%{term}%'")
    return jsonify(cur.fetchall())


@app.get("/post/<pid>")
def post(pid):
    cur = db.cursor()
    # Safe: parameterized.
    cur.execute("SELECT id, title FROM posts WHERE id = ?", (pid,))
    return jsonify(cur.fetchone())


@app.get("/tag")
def tag():
    name = request.args["name"]
    cur = db.cursor()
    # expect: py-sql-injection
    cur.execute("SELECT * FROM tags WHERE name = '%s'" % name)
    return jsonify(cur.fetchall())


@app.post("/ping")
def ping():
    host = request.form["host"]
    # expect: py-command-injection
    out = subprocess.check_output("ping -c 1 " + host, shell=True)
    return out


@app.post("/ping-safe")
def ping_safe():
    host = request.form["host"]
    # Safe: argv list, no shell.
    return subprocess.check_output(["ping", "-c", "1", host])


@app.post("/lookup")
def lookup():
    domain = request.json["domain"]
    # expect: py-command-injection
    os.system("nslookup " + domain)
    return "", 204


@app.post("/lookup-safe")
def lookup_safe():
    domain = request.json["domain"]
    os.system("nslookup " + shlex.quote(domain))
    return "", 204


@app.post("/import")
def import_session():
    # expect: py-unsafe-deserialization
    data = pickle.loads(request.get_data())
    return jsonify(data)


@app.post("/config")
def config():
    # expect: py-unsafe-deserialization
    cfg = yaml.load(request.get_data(), Loader=yaml.Loader)
    return jsonify(cfg)


@app.post("/config-safe")
def config_safe():
    return jsonify(yaml.safe_load(request.get_data()))


@app.get("/welcome")
def welcome():
    user = request.args.get("user", "guest")
    # expect: py-xss
    return f"<h2>Welcome back, {user}</h2>"


@app.get("/welcome-safe")
def welcome_safe():
    user = request.args.get("user", "guest")
    return f"<h2>Welcome back, {escape(user)}</h2>"


@app.get("/profile")
def profile():
    return render_template("profile.html", user=request.args.get("user"))
