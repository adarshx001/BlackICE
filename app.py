import os
from flask import Flask, render_template, request

from hash import generate_sha256
from phishing import analyze_url
from file_analyzer import analyze_file

# -------------------------------------------------
# App Configuration
# -------------------------------------------------

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "blackice-secret-key")

# -------------------------------------------------
# Routes
# -------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/dashboard")
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


# -------------------------------------------------
# Run Server
# -------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
