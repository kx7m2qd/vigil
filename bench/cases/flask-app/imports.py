from flask import Blueprint, request
from lxml import etree

imports = Blueprint("imports", __name__)


@imports.post("/import/catalog")
def import_catalog():
    # Copied from a Stack Overflow answer so `&nbsp;` and friends in supplier feeds resolve.
    parser = etree.XMLParser(resolve_entities=True, remove_blank_text=True)
    # expect: py-xxe
    root = etree.fromstring(request.get_data(), parser)
    return {"items": len(root.findall("item"))}


@imports.post("/import/catalog-v2")
def import_catalog_v2():
    parser = etree.XMLParser(resolve_entities=False, no_network=True, remove_blank_text=True)
    root = etree.fromstring(request.get_data(), parser)
    return {"items": len(root.findall("item"))}
