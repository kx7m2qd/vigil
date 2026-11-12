import os
import pathlib
import shutil

import flask
from flask import request, send_file, send_from_directory
from werkzeug.utils import secure_filename

app = flask.Flask(__name__)
UPLOADS = "/srv/uploads"


@app.route("/download")
def download():
    name = request.args.get("name")
    # ruleid: py-path-traversal
    return send_file(os.path.join(UPLOADS, name))


@app.route("/read", methods=["POST"])
def read():
    path = f"{UPLOADS}/{request.form['file']}"
    # ruleid: py-path-traversal
    with open(path) as fh:
        return fh.read()


@app.route("/delete", methods=["POST"])
def delete():
    target = pathlib.Path(UPLOADS) / request.json["name"]
    # ruleid: py-path-traversal
    target.unlink()
    return "", 204


@app.route("/report")
def report():
    name = request.cookies.get("report", "default.txt")
    # ruleid: py-path-traversal
    return pathlib.Path(UPLOADS, name).read_text()


@app.route("/archive", methods=["POST"])
def archive():
    # ruleid: py-path-traversal
    shutil.copy(request.form["src"], "/srv/archive/")
    return "ok"


def django_view(req):
    # ruleid: py-path-traversal
    return open(os.path.join(UPLOADS, req.GET["f"])).read()


@app.route("/download-safe")
def download_safe():
    # ok: py-path-traversal
    return send_from_directory(UPLOADS, request.args.get("name"))


@app.route("/read-safe", methods=["POST"])
def read_safe():
    # ok: py-path-traversal
    with open(os.path.join(UPLOADS, secure_filename(request.form["file"]))) as fh:
        return fh.read()


@app.route("/basename-safe")
def basename_safe():
    # ok: py-path-traversal
    return open(os.path.join(UPLOADS, os.path.basename(request.args["f"]))).read()


@app.route("/resolve-safe")
def resolve_safe():
    base = pathlib.Path(UPLOADS)
    p = (base / request.args["f"]).resolve()
    if not str(p).startswith(str(base)):
        return "invalid path", 400
    # ok: py-path-traversal
    return p.read_text()


@app.route("/relative-safe")
def relative_safe():
    base = pathlib.Path(UPLOADS).resolve()
    p = (base / request.args["f"]).resolve()
    if not p.is_relative_to(base):
        flask.abort(400)
        return
    # ok: py-path-traversal
    return p.read_bytes()


@app.route("/dotdot-safe", methods=["POST"])
def dotdot_safe():
    name = request.form["f"]
    if "../" in name:
        return "File name must not include '../'"
    # ok: py-path-traversal
    return open(f"{UPLOADS}/{name}").read()


@app.route("/fixed")
def fixed():
    # ok: py-path-traversal
    return open(os.path.join(UPLOADS, "index.html")).read()
