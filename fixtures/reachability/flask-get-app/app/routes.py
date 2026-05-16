from flask import Flask, redirect, request

app = Flask(__name__)


def index():
    return "ok"


# Keep line numbers aligned with fixtures/semgrep/taint-result-with-app-get-trace.json.
@app.get("/login")
def login():
    _ = request.args.get("audit")
    next_url = request.args["next"]
    if next_url:
        return redirect(next_url)
    return redirect("/")
