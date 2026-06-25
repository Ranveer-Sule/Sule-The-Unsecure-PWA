from datetime import timedelta
from datetime import date
import logging
import re
import secrets
from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask import session
from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS
import user_management as dbHandler

# Code snippet for logging a message
# app.logger.critical("message")


app = Flask(__name__)
logging.basicConfig(
    filename="app_errors.log",
    level=logging.ERROR,
    format="%(asctime)s %(levelname)s: %(message)s",
)
logging.getLogger("werkzeug").setLevel(logging.ERROR)
csrf = CSRFProtect(app)
app.secret_key = secrets.token_hex(32)  # Generate a random secret key
app.config["SESSION_COOKIE_HTTPONLY"] = True  # Mitigate XSS attacks by preventing JavaScript access to cookies
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=10)  
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # Mitigate CSRF attacks by restricting cross-site cookie sending
# Enable CORS to allow cross-origin requests (needed for CSRF demo in Codespaces)
CORS(app, origins=[
    "http://localhost:5500",
    "http://127.0.0.1:5500",
])
ALLOWED_REDIRECTS = ["/", "/index.html", "/signup.html", "/success.html"] # Define allowed redirect URLs

def safe_redirect(url):
    if url in ALLOWED_REDIRECTS:
        return redirect(url, code=302)
    else:
        return redirect("/", code=302)  # Redirect to home if URL is not allowed

def valid_username(username):
    # 3-20 characters, letters/numbers/underscore only
    return re.fullmatch(r"[A-Za-z0-9_]{3,20}", username) is not None

def valid_password(password):
    return 8<= len(password) <= 64

def valid_feedback(feedback):
    return 1 <= len(feedback) <= 500

@app.route("/success.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def addFeedback():
    if 'username' not in session:
        return safe_redirect("/")
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return safe_redirect(url)
    if request.method == "POST":
        feedback = request.form["feedback"]
        if not valid_feedback(feedback):
            return render_template("/success.html", state=False, value="Back", feedback_items=dbHandler.listFeedback())
        dbHandler.insertFeedback(feedback)
        feedback_items = dbHandler.listFeedback()
        return render_template("/success.html", state=True, value="Back", feedback_items=feedback_items)
    else:
        feedback_items = dbHandler.listFeedback()
        return render_template("/success.html", state=True, value="Back", feedback_items=feedback_items)


@app.route("/signup.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def signup():
    today = date.today()
    max_dob = today.replace(year=today.year - 13)  # Users must be at least 13 years old
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return safe_redirect(url)
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        DoB = request.form["dob"]
        if not valid_username(username) or not valid_password(password):
            return render_template("/signup.html", max_dob=max_dob, msg="Invalid username or password format.")
        dbHandler.insertUser(username, password, DoB)
        return render_template("/index.html")
    else:
        return render_template("/signup.html", max_dob=max_dob)


@app.route("/index.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
@app.route("/", methods=["POST", "GET"])
def home():
    # Simple Dynamic menu
    if 'username' in session:
        feedback_items = dbHandler.listFeedback()
        return render_template("/success.html", state=True, value=session['username'], feedback_items=feedback_items)
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return safe_redirect(url)
    # Pass message to front end
    elif request.method == "GET":
        msg = request.args.get("msg", "")
        return render_template("/index.html", msg=msg)
    elif request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if not valid_username(username) or not valid_password(password):
            return render_template("/index.html", msg="Invalid username or password.")
        try:
            isLoggedIn = dbHandler.retrieveUsers(username, password)
        except Exception as e:
            app.logger.error("Login Check failed: %s", e, exc_info=True)
            isLoggedIn = False
        if isLoggedIn:
            session.clear()  # Clear any existing session data to prevent session fixation
            session.permanent = True 
            session["username"] = username
            feedback_items = dbHandler.listFeedback()
            return render_template("/success.html", value=username, state=isLoggedIn, feedback_items=feedback_items)
        else:
            return render_template("/index.html", msg="Invalid username or password.")
    else:
        return render_template("/index.html")

@app.route("/logout")
def logout():
    session.pop("username", None)  # Remove the username from the session
    return safe_redirect("/")  # Redirect to the home page after logout

@app.errorhandler(500)
def server_error(e):
    app.logger.error("Server Error: %s", e, exc_info=True)
    return render_template("/index.html", msg="An internal server error occurred. Please try again later."), 500

@app.errorhandler(404)
def not_found_error(e):
    return render_template("/index.html", msg="Page not found."), 404

if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=False, host="0.0.0.0", port=5500)
