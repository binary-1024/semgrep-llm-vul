from flask import Flask, redirect, request

app = Flask(__name__)


def index():
    return "ok"


# Keep line numbers aligned with fixtures/semgrep/taint-result-with-helper-trace.json.
@app.route("/login")
def login():
    _ = request.args.get("audit")
    next_url = request.args["next"]
    return issue_redirect(next_url)


def issue_redirect(next_url):
    if next_url:
        return redirect(next_url)
    return redirect("/")
