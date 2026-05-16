from flask import Flask, redirect, request

app = Flask(__name__)


# Keep line numbers aligned with fixtures/semgrep/taint-result-with-relative-path-guard-trace.json.
@app.route("/login")
def login():
    next_url = request.args["next"]
    if not next_url.startswith("/"):
        return redirect("/")
    return redirect(next_url)
