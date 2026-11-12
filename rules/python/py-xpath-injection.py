import io

import elementpath
import lxml.etree
from flask import Flask, request
from lxml import etree

app = Flask(__name__)
TREE = etree.parse("users.xml")


@app.route("/user")
def find_user():
    uid = request.args.get("id")
    # ruleid: py-xpath-injection
    nodes = TREE.xpath(f"//user[@id='{uid}']")
    return str(len(nodes))


@app.route("/login", methods=["POST"])
def login():
    name = request.form["name"]
    query = "//user[name='" + name + "' and password='" + request.form["password"] + "']"
    # ruleid: py-xpath-injection
    find = lxml.etree.XPath(query)
    return "ok" if find(TREE) else "no"


@app.route("/search")
def search():
    term = request.cookies.get("term")
    # ruleid: py-xpath-injection
    return str(elementpath.select(TREE, "//item[title='%s']" % term))


@app.route("/buffer")
def buffer():
    buf = io.StringIO()
    buf.write("//user[@id='")
    buf.write(request.args["id"])
    buf.write("']")
    # ruleid: py-xpath-injection
    return str(TREE.xpath(buf.getvalue()))


def django_view(request):
    dept = request.GET["dept"]
    # ruleid: py-xpath-injection
    return str(TREE.xpath("//employee[dept='{}']".format(dept)))


@app.route("/user-safe")
def find_user_safe():
    uid = request.args.get("id")
    # ok: py-xpath-injection
    nodes = TREE.xpath("//user[@id=$uid]", uid=uid)
    return str(len(nodes))


@app.route("/search-safe")
def search_safe():
    term = request.args.get("term")
    # ok: py-xpath-injection
    return str(elementpath.select(TREE, "//item[title=$t]", variables={"t": term}))


@app.route("/escaped")
def escaped():
    uid = request.args.get("id")
    # ok: py-xpath-injection
    return str(TREE.xpath(f"//user[@id='{uid.replace("'", "&apos;")}']"))


@app.route("/numeric")
def numeric():
    # ok: py-xpath-injection
    return str(TREE.xpath(f"//user[@id={int(request.args['id'])}]"))


@app.route("/static")
def static():
    # ok: py-xpath-injection
    return str(TREE.xpath("//user[@active='true']"))


@app.route("/guarded")
def guarded():
    uid = request.args.get("id", "")
    if "'" in uid:
        return "Employee ID must not contain apostrophes", 400
    # ok: py-xpath-injection
    return str(TREE.xpath(f"//user[@id='{uid}']"))
