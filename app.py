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

app.config["SECRET_KEY"] = "blackice-secret-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///blackice.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

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

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        try:
            email = request.form.get("email")
            password = request.form.get("password")

            user = User.query.filter_by(email=email).first()

            if user and user.check_password(password):
                login_user(user)
                return redirect(url_for("home"))

            return "Invalid email or password"

        except Exception as e:
            return f"Login error: {e}"

    return render_template("login.html")

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
