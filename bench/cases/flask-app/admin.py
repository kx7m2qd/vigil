from flask import Blueprint, abort, request, session

admin = Blueprint("admin", __name__)


@admin.post("/admin/switch-user")
def switch_user():
    # Support tool: "view the app as this customer". Nothing checks the caller is staff.
    # expect: py-trust-boundary
    session["user_id"] = request.form["customer_id"]
    return "", 204


@admin.post("/admin/switch-user-v2")
def switch_user_v2():
    if not session.get("is_staff"):
        abort(403)
    customer = Customer.query.get_or_404(request.form["customer_id"])
    session["impersonating"] = True
    session["user_id"] = customer.id
    return "", 204


@admin.post("/prefs")
def prefs():
    session["theme"] = request.form.get("theme", "light")
    return "", 204


class Customer:
    query = None
