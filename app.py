import os
from flask import Flask, render_template, request, redirect, url_for
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user
)

from models import db, User
from hash import generate_sha256
from phishing import analyze_url
from file_analyzer import analyze_file

# -------------------------------------------------
# App Configuration
# -------------------------------------------------

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "blackice-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///blackice.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Cookie/session fixes for Render
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["REMEMBER_COOKIE_DURATION"] = 86400  # 1 day

# -------------------------------------------------
# Initialize Database
# -------------------------------------------------

db.init_app(app)

# -------------------------------------------------
# Login Manager
# -------------------------------------------------

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------------------------------------
# Routes
# -------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")
    @app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


# ---------------- PASSWORD -----------------------

@app.route("/password")
def password():
    return render_template("password.html")

# ---------------- HASHING ------------------------

@app.route("/hash", methods=["GET", "POST"])
def hash_tool():
    hashed_value = None

    if request.method == "POST":
        text = request.form.get("text")
        if text:
            hashed_value = generate_sha256(text)

    return render_template("hash.html", hashed_value=hashed_value)

# ---------------- PHISHING -----------------------

@app.route("/phishing", methods=["GET", "POST"])
def phishing():
    data = None

    if request.method == "POST":
        url = request.form.get("url")
        if url:
            data = analyze_url(url)

    return render_template("phishing.html", data=data)

# ---------------- FILE ANALYZER ------------------

@app.route("/file", methods=["GET", "POST"])
@login_required
def file_analyzer():
    data = None

    if request.method == "POST":
        uploaded_file = request.files.get("file")

        if uploaded_file and uploaded_file.filename:
            temp_path = "temp_" + uploaded_file.filename
            uploaded_file.save(temp_path)

            data = analyze_file(temp_path, uploaded_file.filename)

            os.remove(temp_path)

    return render_template("fileanalyzer.html", data=data)

# ---------------- REGISTER -----------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        try:
            username = request.form.get("username")
            email = request.form.get("email")
            password = request.form.get("password")

            if not username or not email or not password:
                return "All fields are required"

            if User.query.filter_by(email=email).first():
                return "Email already exists"

            user = User(username=username, email=email)
            user.set_password(password)

            db.session.add(user)
            db.session.commit()

            login_user(user)
            return redirect(url_for("home"))

        except Exception as e:
            return f"Registration error: {e}"

    return render_template("register.html")

# ---------------- LOGIN --------------------------

from sqlalchemy import or_

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        identity = request.form.get("identity")
        password = request.form.get("password")

        if not identity or not password:
            error = "All fields are required."
        else:
            user = User.query.filter(
                or_(User.email == identity, User.username == identity)
            ).first()

            if not user:
                error = "You are not registered. Please register first."
            elif not user.check_password(password):
                error = "Incorrect password."
            else:
                login_user(user, remember=True)
                return redirect(url_for("home"))

    return render_template("login.html", error=error)


# ---------------- LOGOUT -------------------------

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

# -------------------------------------------------
# Create Database Tables (Render needs this)
# -------------------------------------------------

with app.app_context():
    db.create_all()

# -------------------------------------------------
# Run Server
# -------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
