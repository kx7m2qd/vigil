from flask import Blueprint, abort, request
from lxml import etree

directory = Blueprint("directory", __name__)
STAFF = etree.parse("/var/app/data/staff.xml")


@directory.get("/staff")
def staff_by_team():
    team = request.args.get("team", "")
    # expect: py-xpath-injection
    people = STAFF.xpath(f"/staff/person[team='{team}']/name/text()")
    return {"people": [str(p) for p in people]}


@directory.get("/staff/<int:staff_id>")
def staff_by_id(staff_id):
    # Route converter guarantees an int.
    person = STAFF.xpath(f"/staff/person[@id={staff_id}]")
    if not person:
        abort(404)
    return {"name": person[0].findtext("name")}


@directory.get("/staff/search")
def staff_search():
    name = request.args.get("name", "")
    people = STAFF.xpath("/staff/person[contains(name, $q)]/name/text()", q=name)
    return {"people": [str(p) for p in people]}
