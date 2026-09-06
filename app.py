from flask import Flask

from config import (
    UPLOAD_FOLDER,
    REPORT_FOLDER,
    SQLALCHEMY_DATABASE_URI,
    SQLALCHEMY_TRACK_MODIFICATIONS,
)

from database.database import db
from models.case import Case
from models.evidence import Evidence
from models.event import Event
from models.alert import Alert


app = Flask(__name__)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["REPORT_FOLDER"] = REPORT_FOLDER
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = SQLALCHEMY_TRACK_MODIFICATIONS

db.init_app(app)
with app.app_context():
    db.create_all()


@app.route("/")
def home():
    return "CyberTrace is running!"


if __name__ == "__main__":
    app.run(debug=True)