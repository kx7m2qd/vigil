import ast
import json

import flask
from flask import request

app = flask.Flask(__name__)


@app.route("/calc", methods=["POST"])
def calc():
    expr = request.form["expression"]
    # ruleid: py-code-injection
    return str(eval(expr))


@app.route("/hook", methods=["POST"])
def hook():
    body = request.get_json()
    code = f"result = {body['formula']}"
    scope = {}
    # ruleid: py-code-injection
    exec(code, {}, scope)
    return str(scope["result"])


@app.route("/filter")
def filter_rows():
    cond = request.args.get("where", "True")
    # ruleid: py-code-injection
    fn = compile(f"lambda row: {cond}", "<filter>", "eval")
    return str(fn)


def django_view(req):
    # ruleid: py-code-injection
    return eval(req.GET["q"])


@app.route("/calc-safe", methods=["POST"])
def calc_safe():
    # ok: py-code-injection
    return str(ast.literal_eval(request.form["expression"]))


@app.route("/settings", methods=["POST"])
def settings():
    # ok: py-code-injection
    return json.loads(request.form["settings"])


@app.route("/literal-only", methods=["POST"])
def literal_only():
    value = request.form["v"]
    if not value.startswith("'") or not value.endswith("'") or "'" in value[1:-1]:
        return "Eval argument must be a plain string literal."
    # ok: py-code-injection
    return eval(value)


@app.route("/version")
def version():
    # ok: py-code-injection
    return str(eval("1 + 1"))


@app.route("/page")
def page():
    # ok: py-code-injection
    return str(eval(str(int(request.args["n"])) + " * 10"))
