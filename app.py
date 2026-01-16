from flask import Flask, render_template, request, redirect, url_for, session, abort, send_file
from pymongo import MongoClient
import bcrypt, gridfs, re
from bson import ObjectId
from io import BytesIO
from datetime import datetime

app = Flask(__name__)
app.secret_key = "super_secret_key"

# database connection
client = MongoClient("mongodb://localhost:27017/")
db = client["user_db"]
users_collection = db["users"]
users_collection.create_index('email', unique=True)

fs = gridfs.GridFS(db)

# routes
@app.route("/")
def index():
    if session.get("email"):
        if session.get("is_admin"):
            return redirect(url_for("admin_dashboard"))
        else:
            return redirect(url_for("upload_file"))
    return render_template("login.html")


# login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password").encode('utf-8')

        user = users_collection.find_one({"email": email.lower()})
        if user and bcrypt.checkpw(password, user["password"]):
            session["email"] = email.lower()
            session["is_admin"] = True if email == "admin@gmail.com" else False
            return redirect(url_for("index"))

        return render_template("login.html", error="Invalid email or password")

    return render_template("login.html")


# signup
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        re_password = request.form.get("re_password")

        def isStrong(password: str) -> str:
            if len(password) < 8:
                return "Password must be at least 8 characters long"
            if not re.search(r"[A-Z]", password):
                return "Password must contain an uppercase letter"
            if not re.search(r"[a-z]", password):
                return "Password must contain a lowercase letter"
            if not re.search(r"\d", password):
                return "Password must contain a number"
            if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password):
                return "Password must contain a special character"
            return True
    
        if isStrong(password):
            if password != re_password:
                return render_template("signup.html", error="Passwords do not match")

            if users_collection.find_one({"email": email.lower()}):
                return render_template("signup.html", error="User already exists")

            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            users_collection.insert_one({
                "email": email.lower(), 
                "password": hashed_password
            })
            return "Password Stored Successfully"

        return redirect(url_for("login"))

    return render_template("signup.html")


# logout
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# upload file
@app.route("/upload", methods=["GET", "POST"])
def upload_file():
    if not session.get("email"):
        return redirect(url_for("login"))

    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            return render_template("upload.html", error="No file selected")
        fs.put(
            file,
            filename=file.filename,
            content_type=file.content_type,
            uploaded_by=session["email"],
            upload_date=datetime.now()
        )
        return render_template("upload.html", success="File uploaded successfully")

    return render_template("upload.html")


# SHOW FILES (All users can view/download)
@app.route("/show_files")
def show_files():
    if not session.get("email"):
        return redirect(url_for("login"))

    files = list(fs.find())
    return render_template("files.html", files=files)


# download file
@app.route("/file/<file_id>")
def get_file(file_id):
    file = fs.get(ObjectId(file_id))
    return send_file(
        BytesIO(file.read()),
        download_name=file.filename,
        mimetype=file.content_type,
        as_attachment=False
    )


# admin delete file
@app.route("/delete_file/<file_id>", methods=["POST"])
def delete_file(file_id):
    if not session.get("is_admin"):
        abort(403)
    try:
        fs.delete(ObjectId(file_id))
    except Exception as e:
        return f"Error deleting file: {str(e)}"
    return redirect(url_for("admin_dashboard"))


# ADMIN DASHBOARD
@app.route("/admin", methods=["GET"])
def admin_dashboard():
    if not session.get("is_admin"):
        abort(403)

    users = list(users_collection.find())
    files = list(fs.find())
    return render_template("admin_dashboard.html", users=users, files=files)


if __name__ == "__main__":
    app.run(debug=True)
