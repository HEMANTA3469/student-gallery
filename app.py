import os, sqlite3
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
DB_PATH = os.path.join(BASE_DIR, "gallery.db")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key-before-deployment")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS photos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'General',
            filename TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        if not conn.execute("SELECT id FROM admins WHERE username = ?", ("admin",)).fetchone():
            conn.execute("INSERT INTO admins (username, password_hash) VALUES (?, ?)",
                         ("admin", generate_password_hash("admin123")))

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_id"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

@app.route("/")
def index():
    category = request.args.get("category", "").strip()
    with db() as conn:
        categories = [r["category"] for r in conn.execute(
            "SELECT DISTINCT category FROM photos ORDER BY category COLLATE NOCASE").fetchall()]
        if category:
            photos = conn.execute("SELECT * FROM photos WHERE category = ? ORDER BY id DESC", (category,)).fetchall()
        else:
            photos = conn.execute("SELECT * FROM photos ORDER BY id DESC").fetchall()
    return render_template("index.html", photos=photos, categories=categories, selected=category)

@app.route("/admin/login", methods=["GET", "POST"])
def login():
    if session.get("admin_id"):
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with db() as conn:
            admin = conn.execute("SELECT * FROM admins WHERE username = ?", (username,)).fetchone()
        if admin and check_password_hash(admin["password_hash"], password):
            session["admin_id"] = admin["id"]
            session["admin_username"] = admin["username"]
            return redirect(url_for("dashboard"))
        flash("Incorrect username or password.", "error")
    return render_template("login.html")

@app.route("/admin")
@admin_required
def dashboard():
    with db() as conn:
        photos = conn.execute("SELECT * FROM photos ORDER BY id DESC").fetchall()
    return render_template("admin.html", photos=photos)

@app.route("/admin/upload", methods=["POST"])
@admin_required
def upload():
    title = request.form.get("title", "").strip()
    category = request.form.get("category", "General").strip() or "General"
    file = request.files.get("photo")
    if not title or not file or not file.filename:
        flash("Please enter a title and choose a photo.", "error")
        return redirect(url_for("dashboard"))
    if not allowed_file(file.filename):
        flash("Use JPG, JPEG, PNG, GIF or WEBP images only.", "error")
        return redirect(url_for("dashboard"))
    filename = secure_filename(file.filename)
    stem, ext = os.path.splitext(filename)
    filename = f"{stem[:60]}_{os.urandom(4).hex()}{ext.lower()}"
    file.save(os.path.join(UPLOAD_FOLDER, filename))
    with db() as conn:
        conn.execute("INSERT INTO photos (title, category, filename) VALUES (?, ?, ?)",
                     (title[:120], category[:60], filename))
    flash("Photo uploaded successfully.", "success")
    return redirect(url_for("dashboard"))

@app.route("/admin/delete/<int:photo_id>", methods=["POST"])
@admin_required
def delete_photo(photo_id):
    with db() as conn:
        photo = conn.execute("SELECT * FROM photos WHERE id = ?", (photo_id,)).fetchone()
        if photo:
            path = os.path.join(UPLOAD_FOLDER, photo["filename"])
            if os.path.isfile(path):
                os.remove(path)
            conn.execute("DELETE FROM photos WHERE id = ?", (photo_id,))
            flash("Photo deleted.", "success")
    return redirect(url_for("dashboard"))

@app.route("/admin/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.errorhandler(413)
def too_large(_error):
    flash("Image is too large. Maximum upload size is 8 MB.", "error")
    return redirect(url_for("dashboard"))

init_db()
if __name__ == "__main__":
    app.run(debug=True)
