from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect
import os
import pandas as pd
from shlex import quote
from sqlite3 import connect
from sqlalchemy import create_engine


app = Flask(__name__, template_folder="templates", static_folder="static")
engine = create_engine("sqlite:///web_server/users.db")
anti_bot = {}

@app.route("/")
def hello_world():
    return """<a href='/login'>Login</a><br/> 
    <a href='/signup'>Signup</a>"""

@app.route("/login")
def login():
    return render_template("login.html")

@app.route("/login/<error>")
def login_err(error):
    return render_template("login.html", error=error)

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")
    elif request.method == "POST":
        user = pd.DataFrame.from_dict([{
            "firstname": request.form.get("first_name"),
            "lastname": request.form.get("last_name"),
            "username": request.form.get("username"),
            "password": request.form.get("password")
        }])
        user.to_sql(name="users", con=engine, if_exists="append", index=False)
        return redirect("/login")
    else:
        return "<p>Something went wrong</p>"


@app.route("/welcome", methods=["POST"])
def welcome():
    username = request.form.get("username")
    password = request.form.get("password")
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    with connect("web_server/users.db") as connection:
        cursor = connection.cursor()
        rs = cursor.executescript(query).execute(query)
        for row in rs:
            return render_template("welcome.html", first_name=row[0], last_name=row[1])
    
    return redirect("/login/User not found or password is incorrect")
    
@app.route("/safe_welcome", methods=["POST"])
def safe_welcome():
    # if user is not a bot he will not be able to login on the 10's attemt
    # unless the server restarts/crashed
    if request.remote_addr in anti_bot:
        anti_bot_info = anti_bot[request.remote_addr]
        if datetime.now() > anti_bot_info["ttl"]:
            anti_bot[request.remote_addr] = {
                "attempts": 1,
                "ttl": datetime.now() + timedelta(minutes=1)
            }
        else:
            anti_bot[request.remote_addr]["attempts"] += 1
            if anti_bot[request.remote_addr]["attempts"] > 1000:
                return "You are a bot"
    else:
        anti_bot[request.remote_addr] = {
            "attempts": 1,
            "ttl": datetime.now() + timedelta(minutes=1)
        }
    username = request.form.get("username")
    password = request.form.get("password")
    # safe from sql injection because we use ? instead of the actual value
    query = f"SELECT * FROM users WHERE username=? AND password=?"
    with connect("web_server/users.db") as connection:
        cursor = connection.cursor()
        rs = cursor.execute(query, (username, password))
        for row in rs:
            first_name = row[0]
            last_name = row[1]
            image_path = f"{first_name}-{last_name}.jpg"
            # check if exists
            cmd = f'ls web_server/static/{quote(image_path)}'
            res = os.popen(cmd)
            # res = os.popen(f'ls web_server/static/a; echo balagan > balagan.txt ;')
            res_text = res.read()
            if not res_text:
                image_path = "default.png"
            return render_template("welcome.html", 
                                   first_name=first_name, 
                                   last_name=last_name,
                                   image_path=image_path)
    
    return redirect("/login/User not found or password is incorrect")



if __name__ == "__main__":
    app.run()#(debug=True) 