from flask import Flask, render_template, request, flash, redirect, url_for, session, abort, send_file
from pymongo import MongoClient
import bcrypt, re
from bson import ObjectId
from io import BytesIO
from datetime import datetime
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from bson.binary import Binary
from agent import summarize_text_agent

app = Flask(__name__)
app.secret_key = "super_secret_key"

# email configration
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB
MAX_FILE_SIZE = 16 * 1024 * 1024
app.config["MAIL_USERNAME"] = "esalpha337@gmail.com"
app.config["MAIL_PASSWORD"] = "App_Password"  # 16 digit
app.config["MAIL_DEFAULT_SENDER"] = "esalpha337@gmail.com"
app.config["MAIL_DEBUG"] = True


mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

# database connection
client = MongoClient("mongodb://localhost:27017/")
db = client["FileManager"]
users_collection = db["users"]
files_collection = db["files"]
users_collection.create_index("email", unique=True)


# Email verification link
def send_verification_email(email):
    token = serializer.dumps(email, salt="email-verify")

    verify_link = url_for("verify_email", token=token, _external=True)

    msg = Message(
        subject="Verify Your Email",
        recipients=[email],
        body=f"""
            Welcome!

            Please verify your email by clicking the link below:

            {verify_link}

            This link will expire in 1 hour.
            """
            )
    mail.send(msg)

# Password reset link
def send_password_reset_email(email):
    token = serializer.dumps(email, salt="password-reset")

    reset_link = url_for("reset_password", token=token, _external=True)

    msg = Message(
        subject="Reset Your Password",
        recipients=[email],
        body=f"""
            You requested a password reset.

            Click the link below to reset your password:
            {reset_link}

            This link will expire in 30 minutes.

            If you did not request this, please ignore this email.
            """
            )

    mail.send(msg)


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
        email = request.form.get("email").lower()
        password = request.form.get("password").encode("utf-8")

        user = users_collection.find_one({"email": email})

        if not user or not bcrypt.checkpw(password, user["password"]):
            flash("Invalid email or password", "danger")
            return redirect(url_for("login"))

        if not user.get("is_verified"):
            flash("Please verify your email first", "info")
            return redirect(url_for("login"))

        session["email"] = email
        session["is_admin"] = email == "esalpha337@gmail.com"

        flash("Logged in successfully", "success")
        return redirect(url_for("index"))

    return render_template("login.html")


# signup 
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        re_password = request.form.get("re_password")

        def isStrong(password):
            if len(password) < 8:
                return False, "Password must be at least 8 characters long"
            if not re.search(r"[A-Z]", password):
                return False, "Password must contain an uppercase letter"
            if not re.search(r"[a-z]", password):
                return False, "Password must contain a lowercase letter"
            if not re.search(r"\d", password):
                return False, "Password must contain a number"
            if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password):
                return False, "Password must contain a special character"
            return True, None

        strong, error_msg = isStrong(password)
        if not strong:
            flash(error_msg, "danger")
            return redirect(url_for("signup"))

        if password != re_password:
            flash("Passwords do not match", "danger")
            return redirect(url_for("signup"))

        if users_collection.find_one({"email": email.lower()}):
            flash("User already exists", "danger")
            return redirect(url_for("signup"))

        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        )

        users_collection.insert_one({
            "email": email.lower(),
            "password": hashed_password,
            "is_verified": False,
            "created_at": datetime.now()
        })

        send_verification_email(email.lower())

        flash(
            "Verification email sent. Please check your inbox.",
            "success"
        )
        return redirect(url_for("login"))

    return render_template("signup.html")


# forget password via link
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email").lower()

        if users_collection.find_one({"email": email}):
            send_password_reset_email(email)

        flash(
            "If this email exists, a reset link has been sent.",
            "info"
        )
        return redirect(url_for("login"))

    return render_template("forget.html")


# reset password
@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = serializer.loads(
            token,
            salt="password-reset",
            max_age=1800
        )
    except SignatureExpired:
        return "Reset link expired", 400
    except BadSignature:
        return "Invalid reset link", 400

    if request.method == "POST":
        password = request.form.get("password")
        re_password = request.form.get("re_password")

        def isStrong(password):
            if len(password) < 8:
                return False, "Password must be at least 8 characters long"
            if not re.search(r"[A-Z]", password):
                return False, "Password must contain an uppercase letter"
            if not re.search(r"[a-z]", password):
                return False, "Password must contain a lowercase letter"
            if not re.search(r"\d", password):
                return False, "Password must contain a number"
            if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password):
                return False, "Password must contain a special character"
            return True, None

        strong, error_msg = isStrong(password)
        if not strong:
            return render_template("reset.html", error=error_msg)

        if password != re_password:
            flash("Password does not match", "danger")
            return render_template("reset_password.html")

        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        )

        users_collection.update_one(
            {"email": email},
            {"$set": {"password": hashed_password}}
        )

        flash("Password reset successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html")


# logout
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# Verification
@app.route("/verify/<token>")
def verify_email(token):
    try:
        email = serializer.loads(
            token,
            salt="email-verify",
            max_age=3600
        )
    except SignatureExpired:
        flash("Verification link expired", "danger")
        return redirect(url_for("login"))
    except BadSignature:
        flash("Invalid verification link", "danger")
        return redirect(url_for("login"))

    users_collection.update_one(
        {"email": email},
        {"$set": {"is_verified": True, "verified_at": datetime.now()}}
    )

    session['email'] = email

    flash("Email verified successfully. You can now log in.", "success")
    return redirect(url_for("login"))


# upload files
@app.route("/upload", methods=["GET", "POST"])
def upload_file():
    if not session.get("email"):
        return redirect(url_for("login"))

    if request.method == "POST":
        file = request.files.get("file")

        if not file or file.filename == "":
            return render_template("upload.html", error="No file selected")

        file.seek(0, 2)
        file_size = file.tell()
        file.seek(0)

        if file_size > MAX_FILE_SIZE:
            return render_template(
                "upload.html",
                error="File exceeds 16 MB size limit"
            )

        files_collection.insert_one({
            "filename": file.filename,
            "content_type": file.content_type,
            "data": Binary(file.read()),
            "uploaded_by": session["email"],
            "upload_date": datetime.now()
        })
        flash("File Upload Successfully", 'success')
        return render_template("upload.html")

    return render_template("upload.html")


# show files (All users can view/download)
@app.route("/show_files")
def show_files():
    if not session.get("email"):
        return redirect(url_for("login"))

    files = list(files_collection.find())
    return render_template("files.html", files=files)


# download file
@app.route("/get_file/<file_id>")
def get_file(file_id):
    file = files_collection.find_one({"_id": ObjectId(file_id)})
    if not file:
        abort(404)

    return send_file(
        BytesIO(file["data"]),
        download_name=file["filename"],
        mimetype=file["content_type"],
        as_attachment=False
    )


# summarize uploaded file content
@app.route('/summarize/<file_id>')
def summarize(file_id):
    if not session.get("email"):
        return redirect(url_for("login"))

    file = files_collection.find_one({"_id": ObjectId(file_id)})
    if not file:
        abort(404)

    try:
        text = file["data"].decode("utf-8")
    except Exception:
        abort(400, "Unsupported file type")

    summary = summarize_text_agent(text)

    output = BytesIO()
    output.write(summary.encode("utf-8"))
    output.seek(0)

    summary_filename = f"summary_{file['filename']}.txt"

    return send_file(
        output,
        download_name=summary_filename,
        mimetype="text/plain",
        as_attachment=True
    )


# admin delete file
@app.route("/delete_file/<file_id>", methods=["POST"])
def delete_file(file_id):
    if not session.get("is_admin"):
        abort(403)

    files_collection.delete_one({"_id": ObjectId(file_id)})
    flash('file deleted successfully', 'success')
    return redirect(url_for("admin_dashboard"))


# admin dashboard
@app.route("/admin", methods=["GET"])
def admin_dashboard():
    if not session.get("is_admin"):
        abort(403)

    users = list(users_collection.find())
    files = list(files_collection.find())
    return render_template("admin_dashboard.html", users=users, files=files)


@app.errorhandler(413)
def file_too_large(error):
    flash("File too large. Maximum allowed size is 16 MB.",'danger')
    return render_template(
        "upload.html",
    ), 413


if __name__ == "__main__":
    app.run(debug=True)

