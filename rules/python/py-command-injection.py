import os
import shlex
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    # ruleid: py-command-injection
    os.system("ping -c 1 " + host)
    return "ok"


@app.route("/archive", methods=["POST"])
def archive():
    name = request.form["name"]
    # ruleid: py-command-injection
    out = subprocess.check_output(f"tar czf /tmp/{name}.tgz /srv/data", shell=True)
    return out


def django_view(request):
    path = request.GET.get("path")
    # ruleid: py-command-injection
    return os.popen("ls -la " + path).read()


@app.route("/safe-list")
def safe_list():
    host = request.args.get("host")
    # ok: py-command-injection
    subprocess.run(["ping", "-c", "1", host], check=True)
    return "ok"


@app.route("/safe-quote")
def safe_quote():
    host = shlex.quote(request.args.get("host"))
    # ok: py-command-injection
    os.system("ping -c 1 " + host)
    return "ok"


@app.route("/constant")
def constant():
    # ok: py-command-injection
    subprocess.run("uptime", shell=True)
    return "ok"
