import json
from pathlib import Path

from flask import (
    Flask,
    render_template
)

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent

JSON_REPORT = (
    BASE_DIR /
    "reports" /
    "json" /
    "security_report.json"
)


def load_report():

    if not JSON_REPORT.exists():

        return {}

    with open(
        JSON_REPORT,
        "r",
        encoding="utf-8"
    ) as f:

        return json.load(f)


@app.route("/")
def dashboard():
    return render_template(
        "dashboard.html",
        data=load_report()
    )


@app.route("/threats")
def threats():

    return render_template(
        "threats.html",
        data=load_report()
    )


@app.route("/attackers")
def attackers():

    return render_template(
        "attackers.html",
        data=load_report()
    )


@app.route("/analytics")
def analytics():

    return render_template(
        "analytics.html",
        data=load_report()
    )


@app.route("/report")
def reports():

    return render_template(
        "report.html",
        data=load_report()
    )


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )