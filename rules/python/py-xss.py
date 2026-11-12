import html
import os
import subprocess

from django.http import HttpResponse
from django.shortcuts import render
from django.utils.safestring import mark_safe
from flask import Flask, Markup, jsonify, make_response, render_template, render_template_string, request, send_file
from markupsafe import escape

app = Flask(__name__)


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    # ruleid: py-xss
    return f"<h1>Hello {name}</h1>"


@app.route("/search", methods=["POST"])
def search():
    q = request.form.get("q")
    body = "<p>Results for " + q + "</p>"
    # ruleid: py-xss
    return body, 200


@app.route("/greet")
def greet():
    name = request.args["name"]
    # ruleid: py-xss
    return render_template_string("<p>Hi " + name + "</p>")


@app.route("/bio")
def bio():
    bio = request.form["bio"]
    # ruleid: py-xss
    return render_template("profile.html", bio=Markup(bio))


@app.route("/resp")
def resp():
    msg = request.args.get("msg")
    # ruleid: py-xss
    return make_response(f"<div>{msg}</div>")


def django_view(request):
    name = request.GET.get("name")
    # ruleid: py-xss
    return HttpResponse("<b>" + name + "</b>")


def django_safe(request):
    comment = request.POST["comment"]
    # ruleid: py-xss
    return render(request, "c.html", {"c": mark_safe(comment)})


@app.route("/hello-safe")
def hello_safe():
    name = request.args.get("name", "")
    # ok: py-xss
    return f"<h1>Hello {escape(name)}</h1>"


@app.route("/search-safe")
def search_safe():
    q = html.escape(request.args.get("q", ""))
    # ok: py-xss
    return "<p>Results for " + q + "</p>"


@app.route("/tpl")
def tpl():
    name = request.args.get("name")
    # ok: py-xss
    return render_template("hello.html", name=name)


@app.route("/api")
def api():
    name = request.args.get("name")
    # ok: py-xss
    return jsonify(name=name)


@app.route("/api-dict")
def api_dict():
    name = request.args.get("name")
    # ok: py-xss
    return {"name": name}


@app.route("/header")
def header():
    ref = request.headers.get("Referer")
    resp = make_response(("Saved.", {"X-From": ref}))
    # ok: py-xss
    return resp


@app.route("/where")
def where():
    # ok: py-xss
    return f"You are at {request.path}"


@app.route("/page/<int:n>")
def page(n):
    count = int(request.args.get("count", "10"))
    # ok: py-xss
    return f"<p>{count} items</p>"


def django_escaped(request):
    name = request.GET.get("name")
    # ok: py-xss
    return HttpResponse("<b>" + html.escape(name) + "</b>")


@app.route("/ping")
def ping():
    host = request.args.get("host")
    # ok: py-xss
    return subprocess.check_output(["ping", "-c", "1", host])


@app.route("/download")
def download():
    name = request.args.get("file")
    # ok: py-xss
    return send_file(os.path.join("/srv/exports", name))
