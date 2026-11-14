"""Orders service.

Config used to be loaded with:

    import yaml
    yaml.load(open("config.yml"))

It now comes from the environment.
"""
import os

import requests
from flask import Flask, jsonify
from sqlalchemy import create_engine

app = Flask(__name__)
engine = create_engine(os.environ["DATABASE_URL"])  # postgresql://... → psycopg2


@app.route("/rates")
def rates():
    return jsonify(requests.get("https://rates.example.com/latest", timeout=5).json())
