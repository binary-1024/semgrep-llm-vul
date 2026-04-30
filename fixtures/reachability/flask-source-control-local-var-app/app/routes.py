from flask import Flask, redirect, request

app = Flask(__name__)


def index():
    return "ok"


# Keep lines aligned with the local-var Semgrep trace fixture.
@app.route("/login")
def login():
    audit_flag = request.args.get("audit")
    next_url = request.values.get("next") or "/"
    if audit_flag and next_url:
        return redirect(next_url)
    return redirect("/")
