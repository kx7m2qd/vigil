import ldap3
from flask import Blueprint, current_app, request
from ldap3.utils.conv import escape_filter_chars

people = Blueprint("people", __name__)


def directory():
    server = ldap3.Server(current_app.config["LDAP_URL"])
    return ldap3.Connection(server, current_app.config["LDAP_BIND_DN"], current_app.config["LDAP_BIND_PW"], auto_bind=True)


@people.get("/people/lookup")
def lookup():
    name = request.args.get("name", "")
    conn = directory()
    # expect: py-ldap-injection
    conn.search("ou=people,dc=corp,dc=example", f"(&(objectClass=person)(cn=*{name}*))", attributes=["cn", "mail"])
    return {"people": [e.entry_attributes_as_dict for e in conn.entries]}


@people.get("/people/by-mail")
def by_mail():
    mail = escape_filter_chars(request.args.get("mail", ""))
    conn = directory()
    conn.search("ou=people,dc=corp,dc=example", f"(&(objectClass=person)(mail={mail}))", attributes=["cn"])
    return {"people": [e.entry_attributes_as_dict for e in conn.entries]}
