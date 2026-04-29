from app.helpers import issue_redirect
from flask import Flask, request

app = Flask(__name__)


def index():
    return "ok"


# Keep line numbers aligned with fixtures/semgrep/taint-result-with-cross-file-helper-trace.json.
@app.route("/login")
def login():
    _ = request.args.get("audit")
    next_url = request.args["next"]
    return issue_redirect(next_url)
