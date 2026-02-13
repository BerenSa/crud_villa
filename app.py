from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
from markupsafe import escape
import os

app = Flask(__name__)
CORS(app)


# =========================
# DB
# =========================
def get_db():
    return sqlite3.connect("db.sqlite")


# Crear tabla automática
con = get_db()
con.execute("""
CREATE TABLE IF NOT EXISTS items(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT
)
""")
con.close()


# =========================
# Headers de seguridad
# =========================
@app.after_request
def secure_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    return resp


# =========================
# VALIDACIÓN SIMPLE
# =========================
def clean_input(text):
    text = escape(text.strip())

    # bloqueo básico XSS (suficiente para tarea)
    if "<" in text or ">" in text:
        return None
    return text


# =========================
# CRUD
# =========================

# READ
@app.route("/items", methods=["GET"])
def get_items():
    con = get_db()
    rows = con.execute("SELECT * FROM items").fetchall()
    con.close()

    data = [{"id": r[0], "name": r[1]} for r in rows]
    return jsonify(data)


# CREATE
@app.route("/items", methods=["POST"])
def add_item():
    raw = request.json.get("name", "")
    name = clean_input(raw)

    if not name:
        return {"e
