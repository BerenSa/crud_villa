from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3

app = Flask(__name__)
CORS(app)

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

@app.route("/items", methods=["GET"])
def get_items():
    con=get_db()
    rows=con.execute("SELECT * FROM items").fetchall()
    con.close()
    return jsonify(rows)

@app.route("/items", methods=["POST"])
def add_item():
    name=request.json.get("name","").strip()
    if not name:
        return {"error":"vacío"},400

    con=get_db()
    con.execute("INSERT INTO items(name) VALUES(?)",(name,))
    con.commit()
    con.close()
    return {"ok":True}

@app.route("/items/<id>", methods=["PUT"])
def edit(id):
    name=request.json.get("name","")
    con=get_db()
    con.execute("UPDATE items SET name=? WHERE id=?",(name,id))
    con.commit()
    con.close()
    return {"ok":True}

@app.route("/items/<id>", methods=["DELETE"])
def delete(id):
    con=get_db()
    con.execute("DELETE FROM items WHERE id=?",(id,))
    con.commit()
    con.close()
    return {"ok":True}

import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)


