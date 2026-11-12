import urllib.parse
from urllib.parse import urlparse

from django.http import HttpResponseRedirect
from django.shortcuts import redirect as dj_redirect
from django.utils.http import url_has_allowed_host_and_scheme
from flask import Flask, abort, redirect, request, url_for

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():
    next_url = request.args.get("next", "/")
    # ruleid: py-open-redirect
    return redirect(next_url)


@app.route("/out")
def out():
    # ruleid: py-open-redirect
    return redirect(request.form["url"])


@app.route("/root")
def root():
    page = request.args.get("page")
    # ruleid: py-open-redirect
    return redirect("/" + page)


@app.route("/go")
def go():
    resp = app.make_response("")
    # ruleid: py-open-redirect
    resp.headers["Location"] = request.cookies.get("return_to")
    return resp


def django_login(request):
    target = request.GET.get("next")
    # ruleid: py-open-redirect
    return HttpResponseRedirect(target)


def django_logout(request):
    # ruleid: py-open-redirect
    return dj_redirect(request.POST["next"])


@app.route("/login-safe", methods=["POST"])
def login_safe():
    next_url = request.args.get("next", "/")
    if urlparse(next_url).netloc not in ("", "example.com"):
        abort(400)
    # ok: py-open-redirect
    return redirect(next_url)


@app.route("/login-safe2", methods=["POST"])
def login_safe2():
    next_url = request.args.get("next", "/")
    url = urllib.parse.urlparse(next_url)
    if url.netloc not in ["example.com"] or url.scheme != "https":
        return "Invalid URL."
    # ok: py-open-redirect
    return redirect(next_url)


@app.route("/docs")
def docs():
    page = request.args.get("page")
    # ok: py-open-redirect
    return redirect("/docs/" + page)


@app.route("/user")
def user():
    name = request.args.get("name")
    # ok: py-open-redirect
    return redirect(url_for("profile", name=name))


@app.route("/home")
def home():
    # ok: py-open-redirect
    return redirect(request.path + "/")


@app.route("/login-safe3", methods=["POST"])
def login_safe3():
    next_url = request.form.get("next", "/")
    try:
        url = urlparse(next_url)
        if url.netloc not in ("", "example.com"):
            return "Invalid URL.", 400
    except ValueError:
        return "Bad URL.", 400
    # ok: py-open-redirect
    return redirect(next_url)


def django_safe(request):
    target = request.GET.get("next")
    if not url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()}):
        target = "/"
    # ok: py-open-redirect
    return HttpResponseRedirect(target)
