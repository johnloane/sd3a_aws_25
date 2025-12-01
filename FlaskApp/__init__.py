from flask import Flask, render_template, request, session, abort, redirect, flash
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
import json
import time
import pathlib
from dotenv import load_dotenv
import os
from flask_sqlalchemy import SQLAlchemy
import requests
from functools import wraps
import sys

from . import my_db


#codespecialist.com https://www.youtube.com/watch?v=FKgJEfrhU1E

load_dotenv("/var/www/FlaskApp/FlaskApp/.env")
db = my_db.db
app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI")
print(os.getenv("SQLALCHEMY_DATABASE_URI"))
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)


GOOGLE_CLIENT_ID = os.getenv("client_id")
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, ".client_secrets.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file = client_secrets_file,
    scopes=[
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid"
    ],
    redirect_uri = "https://sd3a25.online/callback"
)

alive = 0
data = {}

def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)
        else:
            return function()
    return wrapper


@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response = request.url)
    
    if not session["state"] == request.args["state"]:
        abort(500)
    
    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)
    
    id_info = id_token.verify_oauth2_token(id_token = credentials._id_token, request=token_request, audience=GOOGLE_CLIENT_ID)
    
    session["google_id"] = id_info.get("sub")
    print("GOOGLE_ID: " + session["google_id"])
    session["name"] = id_info.get("name")
    print(session["name"])
    return redirect("/protected_area")
    
@app.route("/logout")
def logout():
    my_db.user_logout(session['google_id'])
    session.clear()
    return redirect("/")


@app.route("/protected_area")
@login_is_required
def protected_area():
    my_db.add_user_and_login(session['name'], session['google_id'])
    is_admin = my_db.is_admin(session['google_id'])
    return render_template("protected_area.html", is_admin=is_admin, online_users = my_db.get_all_logged_in_users())
    
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/keep_alive")
def keep_alive():
    global alive, data
    alive += 1
    keep_alive_count = str(alive)
    data["keep_alive"] = keep_alive_count
    parsed_json = json.dumps(data)
    return str(parsed_json)


if __name__ == "__main__":
    app.run()
