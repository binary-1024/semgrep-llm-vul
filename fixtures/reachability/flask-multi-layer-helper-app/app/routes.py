from flask import Flask, redirect, request

app = Flask(__name__)


def index():
    return "ok"


# Keep line numbers aligned with fixtures/semgrep/taint-result-with-multi-layer-helper-trace.json.
@app.route("/login")
def login():
    _ = request.args.get("audit")
    next_url = request.args["next"]
    return prepare_redirect(next_url)


def prepare_redirect(next_url):
    audited_next = next_url
    return issue_redirect(audited_next)


def issue_redirect(next_url):
    if next_url:
        return redirect(next_url)
    return redirect("/")
