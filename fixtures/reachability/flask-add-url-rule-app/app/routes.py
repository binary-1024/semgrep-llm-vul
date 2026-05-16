from flask import Flask, redirect, request

app = Flask(__name__)


def index():
    return "ok"


def login():
    _ = request.args.get("audit")
    next_url = request.args["next"]
    if next_url:
        return redirect(next_url)
    return redirect("/")


# Keep line numbers aligned with fixtures/semgrep/taint-result-with-add-url-rule-trace.json.
app.add_url_rule("/login", view_func=login, methods=["GET"])
