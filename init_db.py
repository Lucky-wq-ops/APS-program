import sqlite3

# IMPORTANT: must match app.py
DB_NAME = "library.db"

conn = sqlite3.connect(DB_NAME)
cursor = conn.cursor()

# ---------- USERS ----------
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL
)
""")

# ---------- SERIES ----------
cursor.execute("""
CREATE TABLE IF NOT EXISTS series (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    genre TEXT,
    description TEXT,
    cover_path TEXT
)
""")

# ---------- CHAPTERS ----------
cursor.execute("""
CREATE TABLE IF NOT EXISTS chapters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    series_id INTEGER NOT NULL,
    chapter_number INTEGER NOT NULL,
    page_number INTEGER NOT NULL,
    image_path TEXT NOT NULL,
    FOREIGN KEY (series_id) REFERENCES series(id)
)
""")

# ---------- BOOKMARKS ----------
cursor.execute("""
CREATE TABLE IF NOT EXISTS bookmarks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    series_id INTEGER NOT NULL,
    last_chapter INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (series_id) REFERENCES series(id)
)
""")

conn.commit()
conn.close()

print("✅ All tables created successfully in library.db")
