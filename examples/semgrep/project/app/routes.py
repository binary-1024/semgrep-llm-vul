from flask import redirect, request


def jump():
    next_url = request.args["next"]
    return redirect(next_url)
