from datetime import timedelta
from datetime import date
import time
import logging
import re
import secrets
from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask import session
from flask_wtf.csrf import CSRFProtect
from flask_csp.csp import create_csp_header, csp_header
from flask_cors import CORS
import user_management as dbHandler
import pyotp
import qrcode
import base64
from io import BytesIO


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
app.config["SESSION_COOKIE_SECURE"] = True  # Ensure cookies are only sent over HTTPS
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=10)  
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # Mitigate CSRF attacks by restricting cross-site cookie sending
# Enable CORS to allow cross-origin requests (needed for CSRF demo in Codespaces)
CORS(app, origins=[
    "http://localhost:5500",
    "http://127.0.0.1:5500",
])
ALLOWED_REDIRECTS = ["/", "/index.html", "/signup.html", "/success.html", "/verify_2fa"] # Define allowed redirect URLs
login_attempts = {}  # Dictionary to track login attempts
MAX_ATTEMPTS = 5  # Maximum allowed login attempts
LOCKOUT_TIME = timedelta(minutes=5)  # Lockout duration after exceeding max attempts
CSP_POLICY = {
    "default-src": "'self'",
    "img-src": "'self' data:",
    "frame-ancestors": "'none'",
    "report-uri" : "",
}

def make_qr_b64(uri):
    img = qrcode.make(uri)
    stream = BytesIO()
    img.save(stream, format="PNG")
    return base64.b64encode(stream.getvalue()).decode("utf-8")


# Function to check if a username is currently locked out due to too many failed login attempts
def is_locked_out(username):
    if username in login_attempts:
        locked_until = login_attempts[username][1]
        if time.time() < locked_until:
            return True
    return False

# Function to record a failed login attempt for a given username
def record_failed_attempt(username):
    if username not in login_attempts:
        login_attempts[username] = [0, 0]
    login_attempts[username][0] += 1 # Add 1 to the count of failed attempts
    if login_attempts[username][0] >= MAX_ATTEMPTS:
        login_attempts[username][1] = time.time() + LOCKOUT_TIME.total_seconds()

# Function to redirect users safely to allowed URLs, preventing open redirect vulnerabilities
def safe_redirect(url):
    if url in ALLOWED_REDIRECTS:
        return redirect(url, code=302)
    else:
        return redirect("/", code=302)  # Redirect to home if URL is not allowed

# Validation functions for user input
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
        secret = dbHandler.insertUser(username, password, DoB)
        recovery_codes = dbHandler.generateRecoveryCodes(username)
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="Unsecure PWA")
        qr_code = make_qr_b64(uri)
        return render_template("show_qr.html", secret=secret, qr_code=qr_code, recovery_codes=recovery_codes)
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
        if is_locked_out(username):
            return render_template("/index.html", msg="Too many failed login attempts. Please try again later.")
        try:
            isLoggedIn = dbHandler.retrieveUsers(username, password)
        except Exception as e:
            app.logger.error("Login Check failed: %s", e, exc_info=True)
            isLoggedIn = False
        if isLoggedIn:
            login_attempts.pop(username, None)  # Reset failed attempts on successful login
            session.clear()  # Clear any existing session data to prevent session fixation
            session["pending_2fa"] = username
            return safe_redirect("/verify_2fa")
        else:
            record_failed_attempt(username)
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

@app.after_request
def set_security_headers(response):
    response.headers["Content-Security-Policy"] = create_csp_header(CSP_POLICY)  # Apply the Content Security Policy
    response.headers["X-Content-Type-Options"] = "nosniff"  # Prevent MIME type sniffing
    response.headers["X-XSS-Protection"] = "1; mode=block"  # Enable XSS protection in browsers
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Frame-Options"] = "DENY"  # Prevent clickjacking
    return response

@app.route("/verify_2fa", methods=["GET", "POST"])
def verify_2fa():
    username = session.get("pending_2fa")
    if not username:
        return safe_redirect("/")  # Redirect to home if no pending 2FA session
    if request.method == "POST":
        otp = request.form['otp']
        secret = dbHandler.getUserSecret(username)
        if secret and pyotp.TOTP(secret).verify(otp) or dbHandler.useRecoveryCode(username, otp):
            session.clear()
            session.permanent = True
            session["username"] = username
            return safe_redirect("/success.html")
        else:
            return render_template("/verify_2fa.html", msg="Invalid Code. Please try again.")
    return render_template("/verify_2fa.html")

if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=False, host="0.0.0.0", port=5500, ssl_context="adhoc", threaded=True)  # Use adhoc SSL context for HTTPS
