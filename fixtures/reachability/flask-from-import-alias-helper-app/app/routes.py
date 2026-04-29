from app import helpers as h
from flask import Flask, request

app = Flask(__name__)


def index():
    return "ok"


# Keep line numbers aligned with
# fixtures/semgrep/taint-result-with-from-import-alias-helper-trace.json.
@app.route("/login")
def login():
    _ = request.args.get("audit")
    next_url = request.args["next"]
    return h.issue_redirect(next_url)
