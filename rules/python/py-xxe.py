import xml.dom.minidom
import xml.sax
import xml.sax.handler

import defusedxml.minidom
from flask import Flask, request
from lxml import etree

app = Flask(__name__)


@app.route("/sax", methods=["POST"])
def sax_enabled():
    body = request.form["xml"]
    parser = xml.sax.make_parser()
    parser.setFeature(xml.sax.handler.feature_external_ges, True)
    # ruleid: py-xxe
    doc = xml.dom.minidom.parseString(body, parser)
    return doc.documentElement.tagName


@app.route("/sax-pes", methods=["POST"])
def sax_pes():
    body = request.get_data()
    parser = xml.sax.make_parser()
    parser.setFeature(xml.sax.handler.feature_external_pes, 1)
    # ruleid: py-xxe
    parser.feed(body)
    return "ok"


@app.route("/lxml", methods=["POST"])
def lxml_resolve():
    parser = etree.XMLParser(resolve_entities=True)
    # ruleid: py-xxe
    root = etree.fromstring(request.data, parser)
    return root.tag


@app.route("/lxml-net", methods=["POST"])
def lxml_network():
    parser = etree.XMLParser(no_network=False)
    # ruleid: py-xxe
    tree = etree.parse(request.files["doc"], parser=parser)
    return tree.getroot().tag


def django_view(request):
    parser = etree.XMLParser(resolve_entities=True)
    # ruleid: py-xxe
    return etree.fromstring(request.body, parser).tag


@app.route("/default", methods=["POST"])
def sax_default():
    body = request.form["xml"]
    parser = xml.sax.make_parser()
    # ok: py-xxe
    doc = xml.dom.minidom.parseString(body, parser)
    return doc.documentElement.tagName


@app.route("/disabled", methods=["POST"])
def sax_disabled():
    body = request.form["xml"]
    parser = xml.sax.make_parser()
    parser.setFeature(xml.sax.handler.feature_external_ges, False)
    # ok: py-xxe
    doc = xml.dom.minidom.parseString(body, parser)
    return doc.documentElement.tagName


@app.route("/constant", methods=["POST"])
def sax_constant():
    parser = xml.sax.make_parser()
    parser.setFeature(xml.sax.handler.feature_external_ges, True)
    # ok: py-xxe
    doc = xml.dom.minidom.parseString("<a>static</a>", parser)
    return doc.documentElement.tagName


@app.route("/lxml-safe", methods=["POST"])
def lxml_safe():
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    # ok: py-xxe
    return etree.fromstring(request.data, parser).tag


@app.route("/defused", methods=["POST"])
def defused():
    # ok: py-xxe
    return defusedxml.minidom.parseString(request.data).documentElement.tagName
