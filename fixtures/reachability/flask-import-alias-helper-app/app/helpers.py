from flask import redirect


# Keep line numbers aligned with fixtures/semgrep/taint-result-with-import-alias-helper-trace.json.
def issue_redirect(next_url):
    if next_url:
        return redirect(next_url)
    return redirect("/")
