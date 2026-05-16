from app.routes import bp
from flask import Flask

app = Flask(__name__)
app.register_blueprint(bp, url_prefix="/auth")
