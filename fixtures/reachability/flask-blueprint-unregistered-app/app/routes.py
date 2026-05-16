from flask import Blueprint, redirect, request

bp = Blueprint("auth", __name__)


# Keep line numbers aligned with fixtures/semgrep/taint-result-with-blueprint-trace.json.
@bp.get("/login")
def login():
    _ = request.args.get("audit")
    next_url = request.args["next"]
    if next_url:
        return redirect(next_url)
    return redirect("/")
