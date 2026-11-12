import ast
import os
from pathlib import Path

from flask import Blueprint, abort, request, send_file, send_from_directory
from werkzeug.utils import secure_filename

files = Blueprint("files", __name__)
EXPORTS = Path("/var/app/exports")


@files.get("/exports/<path:name>")
def export(name):
    # Route params are clean: Werkzeug's `path` converter rejects `..` segments.
    return send_from_directory(EXPORTS, name)


@files.get("/export")
def export_by_query():
    name = request.args.get("file", "latest.csv")
    # expect: py-path-traversal
    return send_file(os.path.join(EXPORTS, name), as_attachment=True)


@files.post("/avatar")
def avatar():
    upload = request.files["avatar"]
    upload.save(EXPORTS / secure_filename(upload.filename))
    return "", 204


@files.delete("/export")
def delete_export():
    target = EXPORTS / request.json["name"]
    # expect: py-path-traversal
    target.unlink(missing_ok=True)
    return "", 204


@files.delete("/export-safe")
def delete_export_safe():
    target = (EXPORTS / request.json["name"]).resolve()
    if not target.is_relative_to(EXPORTS):
        abort(400)
        return
    target.unlink(missing_ok=True)
    return "", 204


@files.post("/formula")
def formula():
    expr = request.form["expr"]
    # expect: py-code-injection
    return {"value": eval(expr, {"__builtins__": {}})}


@files.post("/formula-safe")
def formula_safe():
    return {"value": ast.literal_eval(request.form["expr"])}
