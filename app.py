from flask import Flask, render_template, request, redirect, url_for, abort, session, send_from_directory
from functools import wraps
import sqlite3
import os
import hmac
import re
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-this-flask-secret")

DATABASE = "library.db"
UPLOAD_FOLDER = "static/uploads"
COVER_FOLDER = "static/covers"
ICON_FOLDER = "icons"
ADMIN_ACCESS_KEY = os.environ.get("WREAD_ADMIN_KEY", "change-this-admin-key")
ALLOWED_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".avif"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(COVER_FOLDER, exist_ok=True)

# ---------------- DATABASE ----------------
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def _natural_sort_key(value):
    normalized = value.replace("\\", "/").lower()
    return [
        int(part) if part.isdigit() else part
        for part in re.split(r"(\d+)", normalized)
    ]

def _is_allowed_image_filename(filename):
    _, ext = os.path.splitext(filename)
    return ext.lower() in ALLOWED_IMAGE_EXTENSIONS

def ensure_series_cover_column():
    db = get_db()
    try:
        columns = {row["name"] for row in db.execute("PRAGMA table_info(series)").fetchall()}
        if columns and "cover_path" not in columns:
            db.execute("ALTER TABLE series ADD COLUMN cover_path TEXT")
            db.commit()
    finally:
        db.close()

def ensure_bookmarks_table():
    db = get_db()
    try:
        db.execute("""
            CREATE TABLE IF NOT EXISTS bookmarks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                series_id INTEGER NOT NULL,
                last_chapter INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (series_id) REFERENCES series(id)
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_bookmarks_user_id ON bookmarks(user_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_bookmarks_user_series ON bookmarks(user_id, series_id)")
        db.commit()
    finally:
        db.close()

def _is_safe_next_path(path):
    return bool(path) and path.startswith("/") and not path.startswith("//")

def require_admin_key(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if session.get("is_admin"):
            return view_func(*args, **kwargs)
        return redirect(url_for("admin_access", next=request.path))
    return wrapped

def require_user_login(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if session.get("user_id"):
            return view_func(*args, **kwargs)
        return redirect(url_for("user_login", next=request.path))
    return wrapped

@app.context_processor
def inject_admin_state():
    return {
        "is_admin": bool(session.get("is_admin")),
        "is_user_logged_in": bool(session.get("user_id")),
        "current_username": session.get("user_username")
    }

ensure_series_cover_column()
ensure_bookmarks_table()

# ---------------- HOME ----------------
@app.route("/")
def index():
    db = get_db()
    series = db.execute("SELECT * FROM series").fetchall()
    bookmarked_series_ids = set()
    user_id = session.get("user_id")
    if user_id:
        bookmark_rows = db.execute(
            "SELECT series_id FROM bookmarks WHERE user_id = ?",
            (user_id,)
        ).fetchall()
        bookmarked_series_ids = {row["series_id"] for row in bookmark_rows}
    db.close()
    return render_template("index.html", series=series, bookmarked_series_ids=bookmarked_series_ids)

@app.route("/series/<slug>")
def series_detail(slug):
    db = get_db()
    series = db.execute(
        "SELECT id, title, slug, genre, description, cover_path FROM series WHERE slug = ?",
        (slug,)
    ).fetchone()
    if not series:
        db.close()
        abort(404)

    chapter_rows = db.execute("""
        SELECT DISTINCT chapter_number
        FROM chapters
        WHERE series_id = ?
        ORDER BY chapter_number
    """, (series["id"],)).fetchall()
    available_chapters = [row["chapter_number"] for row in chapter_rows]
    first_chapter = available_chapters[0] if available_chapters else None

    is_saved = False
    user_id = session.get("user_id")
    if user_id:
        is_saved = bool(db.execute(
            "SELECT 1 FROM bookmarks WHERE user_id = ? AND series_id = ? LIMIT 1",
            (user_id, series["id"])
        ).fetchone())

    db.close()
    return render_template(
        "series_detail.html",
        series=series,
        first_chapter=first_chapter,
        chapter_count=len(available_chapters),
        available_chapters=available_chapters,
        is_saved=is_saved
    )

@app.route("/user/login", methods=["GET", "POST"])
def user_login():
    error = None
    next_path = request.args.get("next") or request.form.get("next") or url_for("index")
    if not _is_safe_next_path(next_path):
        next_path = url_for("index")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute(
            "SELECT id, username, password, role FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        db.close()

        if user and hmac.compare_digest(user["password"], password):
            session["user_id"] = user["id"]
            session["user_username"] = user["username"]
            session["user_role"] = user["role"]
            return redirect(next_path)
        error = "Invalid username or password."

    return render_template("user_login.html", error=error, next_path=next_path)

@app.route("/user/register", methods=["GET", "POST"])
def user_register():
    error = None
    next_path = request.args.get("next") or request.form.get("next") or url_for("index")
    if not _is_safe_next_path(next_path):
        next_path = url_for("index")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not password:
            error = "Username and password are required."
        elif len(username) < 3:
            error = "Username must be at least 3 characters."
        elif len(password) < 4:
            error = "Password must be at least 4 characters."
        elif password != confirm_password:
            error = "Passwords do not match."
        else:
            db = get_db()
            user = None
            try:
                db.execute(
                    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                    (username, password, "user")
                )
                db.commit()
                user = db.execute(
                    "SELECT id, username, role FROM users WHERE username = ?",
                    (username,)
                ).fetchone()
            except sqlite3.IntegrityError:
                error = "Username already exists."
            finally:
                db.close()

            if user:
                session["user_id"] = user["id"]
                session["user_username"] = user["username"]
                session["user_role"] = user["role"]
                return redirect(next_path)

    return render_template("user_register.html", error=error, next_path=next_path)

@app.route("/user/logout")
def user_logout():
    session.pop("user_id", None)
    session.pop("user_username", None)
    session.pop("user_role", None)
    return redirect(url_for("index"))

@app.route("/user/profile")
@require_user_login
def user_profile():
    user_id = session.get("user_id")
    db = get_db()
    user = db.execute(
        "SELECT id, username, role FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()
    if not user:
        db.close()
        session.pop("user_id", None)
        session.pop("user_username", None)
        session.pop("user_role", None)
        return redirect(url_for("user_login"))

    bookmark_count = db.execute(
        "SELECT COUNT(*) AS total FROM bookmarks WHERE user_id = ?",
        (user_id,)
    ).fetchone()["total"]
    db.close()

    return render_template("user_profile.html", user=user, bookmark_count=bookmark_count)

@app.route("/user/bookmarks")
@require_user_login
def user_bookmarks():
    user_id = session.get("user_id")
    db = get_db()
    series = db.execute("""
        SELECT DISTINCT s.id, s.title, s.slug, s.genre, s.description, s.cover_path
        FROM bookmarks AS b
        INNER JOIN series AS s ON s.id = b.series_id
        WHERE b.user_id = ?
        ORDER BY s.title
    """, (user_id,)).fetchall()
    db.close()
    return render_template("user_bookmarks.html", series=series)

@app.route("/bookmark/<slug>", methods=["POST"])
@require_user_login
def toggle_bookmark(slug):
    next_path = request.form.get("next") or request.args.get("next") or url_for("index")
    if not _is_safe_next_path(next_path):
        next_path = url_for("index")

    user_id = session.get("user_id")
    db = get_db()
    series = db.execute(
        "SELECT id FROM series WHERE slug = ?",
        (slug,)
    ).fetchone()
    if not series:
        db.close()
        abort(404)

    existing = db.execute(
        "SELECT 1 FROM bookmarks WHERE user_id = ? AND series_id = ? LIMIT 1",
        (user_id, series["id"])
    ).fetchone()

    if existing:
        db.execute(
            "DELETE FROM bookmarks WHERE user_id = ? AND series_id = ?",
            (user_id, series["id"])
        )
    else:
        db.execute(
            "INSERT INTO bookmarks (user_id, series_id, last_chapter) VALUES (?, ?, ?)",
            (user_id, series["id"], None)
        )
    db.commit()
    db.close()
    return redirect(next_path)

@app.route("/admin/access", methods=["GET", "POST"])
def admin_access():
    error = None
    next_path = request.args.get("next") or request.form.get("next") or url_for("admin_panel")
    if not _is_safe_next_path(next_path):
        next_path = url_for("admin_panel")

    if request.method == "POST":
        submitted_key = request.form.get("access_key", "")
        if hmac.compare_digest(submitted_key, ADMIN_ACCESS_KEY):
            session["is_admin"] = True
            return redirect(next_path)
        error = "Invalid access key."

    return render_template("admin_access.html", error=error, next_path=next_path)

@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("index"))

@app.route("/icons/<path:filename>")
def icon_asset(filename):
    _, ext = os.path.splitext(filename)
    if ext.lower() != ".svg":
        abort(404)
    return send_from_directory(ICON_FOLDER, filename)

@app.route("/admin")
@require_admin_key
def admin_panel():
    db = get_db()
    series = db.execute("SELECT id, title, slug, cover_path FROM series ORDER BY title").fetchall()
    chapter_map = {}
    for s in series:
        chapter_rows = db.execute("""
            SELECT DISTINCT chapter_number
            FROM chapters
            WHERE series_id = ?
            ORDER BY chapter_number
        """, (s["id"],)).fetchall()
        chapter_map[s["slug"]] = [row["chapter_number"] for row in chapter_rows]
    db.close()
    return render_template(
        "admin_panel.html",
        series=series,
        chapter_map=chapter_map,
        notice=request.args.get("notice"),
        error=request.args.get("error")
    )

@app.route("/admin/delete-chapter/<slug>/<int:chapter_number>", methods=["POST"])
@require_admin_key
def delete_chapter(slug, chapter_number):
    db = get_db()
    series = db.execute(
        "SELECT id, title FROM series WHERE slug=?",
        (slug,)
    ).fetchone()

    if not series:
        db.close()
        return redirect(url_for("admin_panel", error="Series not found."))

    pages = db.execute("""
        SELECT image_path
        FROM chapters
        WHERE series_id = ? AND chapter_number = ?
    """, (series["id"], chapter_number)).fetchall()

    if not pages:
        db.close()
        return redirect(url_for("admin_panel", error=f"Chapter {chapter_number} not found."))

    db.execute("""
        DELETE FROM chapters
        WHERE series_id = ? AND chapter_number = ?
    """, (series["id"], chapter_number))
    db.commit()
    db.close()

    static_root = os.path.normcase(os.path.abspath("static"))
    for page in pages:
        relative_path = page["image_path"].lstrip("/\\")
        absolute_path = os.path.normcase(os.path.abspath(relative_path))
        if not absolute_path.startswith(static_root + os.sep):
            continue
        try:
            if os.path.isfile(absolute_path):
                os.remove(absolute_path)
        except OSError:
            pass

    return redirect(
        url_for(
            "admin_panel",
            notice=f"Deleted chapter {chapter_number} from {series['title']}."
        )
    )

@app.route("/admin/set-cover/<slug>", methods=["POST"])
@require_admin_key
def set_cover(slug):
    cover_image = request.files.get("cover_image")
    if not cover_image or not cover_image.filename:
        return redirect(url_for("admin_panel", error="Please select a cover image file."))
    if not _is_allowed_image_filename(cover_image.filename):
        return redirect(url_for("admin_panel", error="Invalid cover image format."))

    db = get_db()
    series = db.execute(
        "SELECT title, cover_path FROM series WHERE slug = ?",
        (slug,)
    ).fetchone()
    if not series:
        db.close()
        return redirect(url_for("admin_panel", error="Series not found."))

    cover_base_name = secure_filename(os.path.basename(cover_image.filename))
    _, cover_ext = os.path.splitext(cover_base_name)
    cover_ext = cover_ext.lower()
    new_cover_filename = f"{slug}_cover{cover_ext}"
    new_cover_save_path = os.path.join(COVER_FOLDER, new_cover_filename)
    new_cover_db_path = f"covers/{new_cover_filename}"
    old_cover_db_path = series["cover_path"] or ""

    cover_image.save(new_cover_save_path)
    db.execute(
        "UPDATE series SET cover_path = ? WHERE slug = ?",
        (new_cover_db_path, slug)
    )
    db.commit()
    db.close()

    if old_cover_db_path and old_cover_db_path != new_cover_db_path:
        static_root = os.path.normcase(os.path.abspath("static"))
        old_cover_absolute_path = os.path.normcase(os.path.abspath(os.path.join("static", old_cover_db_path)))
        if old_cover_absolute_path.startswith(static_root + os.sep):
            try:
                if os.path.isfile(old_cover_absolute_path):
                    os.remove(old_cover_absolute_path)
            except OSError:
                pass

    return redirect(url_for("admin_panel", notice=f"Updated cover for {series['title']}."))

# ---------------- ADD SERIES ----------------
@app.route("/admin/add-series", methods=["GET", "POST"])
@require_admin_key
def add_series():
    if request.method == "POST":
        title = request.form["title"]
        slug = request.form["slug"]
        genre = request.form.get("genre")
        description = request.form.get("description")
        cover_image = request.files.get("cover_image")

        if not cover_image or not cover_image.filename:
            return "Cover image is required.", 400
        if not _is_allowed_image_filename(cover_image.filename):
            return "Invalid cover image format.", 400

        cover_base_name = secure_filename(os.path.basename(cover_image.filename))
        _, cover_ext = os.path.splitext(cover_base_name)
        cover_ext = cover_ext.lower()
        cover_filename = f"{slug}_cover{cover_ext}"
        cover_save_path = os.path.join(COVER_FOLDER, cover_filename)
        cover_db_path = f"covers/{cover_filename}"

        db = get_db()
        try:
            existing = db.execute("SELECT 1 FROM series WHERE slug = ?", (slug,)).fetchone()
            if existing:
                return "Slug already exists. Use a unique slug.", 400

            cover_image.save(cover_save_path)
            db.execute("""
                INSERT INTO series (title, slug, genre, description, cover_path)
                VALUES (?, ?, ?, ?, ?)
            """, (title, slug, genre, description, cover_db_path))
            db.commit()
        except sqlite3.IntegrityError:
            if os.path.exists(cover_save_path):
                os.remove(cover_save_path)
            return "Slug already exists. Use a unique slug.", 400
        finally:
            db.close()

        return redirect(url_for("admin_panel"))

    return render_template("add_series.html")

# ---------------- UPLOAD CHAPTER (MULTIPLE IMAGES) ----------------
@app.route("/admin/upload/<slug>", methods=["GET", "POST"])
@require_admin_key
def upload_chapter(slug):
    db = get_db()
    series = db.execute(
        "SELECT id, title FROM series WHERE slug=?",
        (slug,)
    ).fetchone()

    if not series:
        return "Series not found", 404

    series_id = series["id"]

    if request.method == "POST":
        chapter_number = int(request.form["chapter_number"])
        images = [
            img for img in request.files.getlist("images[]")
            if img and img.filename
        ]
        images.sort(key=lambda img: _natural_sort_key(os.path.basename(img.filename)))

        if not images:
            db.close()
            return "No files were selected.", 400

        page_number = 1
        saved_any = False
        for img in images:
            original_name = secure_filename(os.path.basename(img.filename))
            _, ext = os.path.splitext(original_name)
            ext = ext.lower()
            if ext not in ALLOWED_IMAGE_EXTENSIONS:
                continue

            filename = f"{slug}_ch{chapter_number}_{page_number}{ext or '.jpg'}"
            save_path = os.path.join(UPLOAD_FOLDER, filename)
            img.save(save_path)

            db.execute("""
                INSERT INTO chapters (series_id, chapter_number, page_number, image_path)
                VALUES (?, ?, ?, ?)
            """, (
                series_id,
                chapter_number,
                page_number,
                "/" + save_path.replace("\\", "/")
            ))

            saved_any = True
            page_number += 1

        if not saved_any:
            db.close()
            return "No valid image files found in the selected folder.", 400

        db.commit()
        db.close()
        return redirect(url_for("read_chapter", slug=slug, chapter_number=chapter_number))

    return render_template("upload_chapter.html", series=series)

# ---------------- READER (DB BASED – FINAL) ----------------
@app.route('/read/<slug>/chapter/<int:chapter_number>')
def read_chapter(slug, chapter_number):
    db = get_db()

    series = db.execute(
        "SELECT id, title FROM series WHERE slug = ?",
        (slug,)
    ).fetchone()

    if not series:
        db.close()
        abort(404)

    pages = db.execute("""
        SELECT image_path
        FROM chapters
        WHERE series_id = ? AND chapter_number = ?
        ORDER BY page_number
    """, (series['id'], chapter_number)).fetchall()

    chapter_rows = db.execute("""
        SELECT DISTINCT chapter_number
        FROM chapters
        WHERE series_id = ?
        ORDER BY chapter_number
    """, (series['id'],)).fetchall()

    available_chapters = [row["chapter_number"] for row in chapter_rows]

    if not pages:
        db.close()
        abort(404)

    images = [
        url_for('static', filename=page['image_path'].replace('static/', ''))
        for page in pages
    ]

    db.close()

    return render_template(
        'reader.html',
        images=images,
        chapter_number=chapter_number,
        series=series,
        slug=slug,
        available_chapters=available_chapters
    )

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)
