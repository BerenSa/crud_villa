from flask import Flask, request, jsonify, abort
from flask_cors import CORS
import sqlite3
from markupsafe import escape
import os
from flask import render_template
import re
from datetime import datetime, timedelta
from collections import defaultdict
from urllib.parse import urlparse


app = Flask(__name__)
CORS(app, supports_credentials=True, origins=['http://localhost:*', 'http://127.0.0.1:*', 'https://*.onrender.com'])

# Rate limiting simple
request_history = defaultdict(list)
MAX_REQUESTS_PER_MINUTE = 30

# Control de intentos fallidos
failed_attempts = defaultdict(list)
MAX_FAILED_ATTEMPTS = 10
BLOCK_DURATION_MINUTES = 15

# Límites de seguridad para requests
MAX_CONTENT_LENGTH = 10240  # 10KB máximo (más flexible)
MAX_JSON_PAYLOAD = 10240  # 10KB para JSON

# Lista blanca de métodos HTTP permitidos
ALLOWED_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']

# Configurar límite de contenido en la app
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

@app.route("/")
def home():
    return render_template("index.html")

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
# Validación de Seguridad de URLs
# =========================
def validate_origin():
    """Validar que la solicitud provenga de un origen seguro"""
    # Permitir solicitudes GET sin validación de origen
    if request.method == 'GET':
        return True
    
    referer = request.headers.get('Referer', '')
    origin = request.headers.get('Origin', '')
    host = request.headers.get('Host', '')
    
    # Si es desarrollo local, permitir
    if any(h in host for h in ['localhost', '127.0.0.1']):
        return True
    
    # Si es producción, validar referer
    if referer:
        parsed = urlparse(referer)
        # El referer debe venir del mismo host
        if parsed.netloc and parsed.netloc != host:
            return False
    
    return True


@app.before_request
def security_checks():
    """Verificaciones de seguridad antes de cada request"""
    # Verificar intentos fallidos bloqueados (solo para rutas de API)
    if request.path.startswith('/items'):
        if not check_failed_attempts():
            abort(429, description=f"Demasiados intentos fallidos. Bloqueado por {BLOCK_DURATION_MINUTES} minutos.")
    
    # Validar método HTTP
    if request.method not in ALLOWED_METHODS:
        abort(405)
    
    # Validar longitud de URL (prevenir ataques de URL excesivamente largas)
    if len(request.url) > 2048:
        abort(414)  # URI Too Long
    
    # Validar path traversal en la URL
    if '..' in request.path or '//' in request.path.replace('http://', '').replace('https://', ''):
        abort(400)
    
    # Validar Content-Length para requests con body
    if request.method in ['POST', 'PUT']:
        content_length = request.content_length
        if content_length and content_length > MAX_CONTENT_LENGTH:
            abort(413, description="Request demasiado grande")
    
    # Validar Content-Type solo para POST y PUT (no para DELETE)
    if request.method in ['POST', 'PUT'] and request.path.startswith('/items'):
        content_type = request.headers.get('Content-Type', '')
        # Si hay contenido, debe ser JSON
        if content_type and 'application/json' not in content_type.lower():
            abort(415, description="Content-Type debe ser application/json")
    
    # Validar origen para rutas de API (más permisivo para desarrollo)
    if request.path.startswith('/items') and request.method != 'GET':
        if not validate_origin():
            # En desarrollo, solo advertir pero permitir
            pass


# =========================
# Headers de seguridad
# =========================
@app.after_request
def secure_headers(resp):
    # Headers básicos de seguridad
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-XSS-Protection"] = "1; mode=block"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    # Política de permisos
    resp.headers["Permissions-Policy"] = (
        "geolocation=(), "
        "microphone=(), "
        "camera=(), "
        "payment=(), "
        "usb=(), "
        "magnetometer=(), "
        "gyroscope=(), "
        "accelerometer=()"
    )
    
    # Content Security Policy robusta
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "upgrade-insecure-requests"
    )
    
    # Limitar información del servidor
    resp.headers["Server"] = "SecureServer"
    
    # Cache control para contenido sensible
    if request.path.startswith('/items'):
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
    
    return resp


# Manejo de errores personalizados para no revelar información
@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Solicitud inválida"}), 400

@app.errorhandler(403)
def forbidden(e):
    return jsonify({"error": "Acceso denegado"}), 403

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Recurso no encontrado"}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Método no permitido"}), 405

@app.errorhandler(413)
def request_too_large(e):
    return jsonify({"error": "Request demasiado grande"}), 413

@app.errorhandler(414)
def uri_too_long(e):
    return jsonify({"error": "URL demasiado larga"}), 414

@app.errorhandler(415)
def unsupported_media_type(e):
    return jsonify({"error": "Tipo de contenido no soportado"}), 415

@app.errorhandler(429)
def too_many_requests(e):
    return jsonify({"error": "Demasiadas solicitudes. Intenta más tarde."}), 429

@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Error interno del servidor"}), 500



# =========================
# RATE LIMITING Y CONTROL DE INTENTOS
# =========================
def check_rate_limit():
    ip = request.remote_addr
    now = datetime.now()
    
    # Limpiar requests antiguos
    request_history[ip] = [t for t in request_history[ip] 
                           if now - t < timedelta(minutes=1)]
    
    if len(request_history[ip]) >= MAX_REQUESTS_PER_MINUTE:
        return False
    
    request_history[ip].append(now)
    return True


def check_failed_attempts():
    """Verificar si la IP ha sido bloqueada por intentos fallidos"""
    ip = request.remote_addr
    now = datetime.now()
    
    # Limpiar intentos antiguos
    failed_attempts[ip] = [t for t in failed_attempts[ip] 
                          if now - t < timedelta(minutes=BLOCK_DURATION_MINUTES)]
    
    if len(failed_attempts[ip]) >= MAX_FAILED_ATTEMPTS:
        return False
    
    return True


def register_failed_attempt():
    """Registrar un intento fallido"""
    ip = request.remote_addr
    failed_attempts[ip].append(datetime.now())


# =========================
# VALIDACIÓN ROBUSTA
# =========================

# Límites de seguridad
MAX_NAME_LENGTH = 50
MIN_NAME_LENGTH = 1
MAX_ITEMS_IN_DB = 1000

# Caracteres peligrosos a bloquear
DANGEROUS_CHARS = ['<', '>', '{', '}', '[', ']', '|', '\\', '^', '`', 
                   ';', '&', '$', '(', ')', '"', "'", '=', '%']

def clean_input(text):
    """Validación y sanitización estricta de inputs"""
    if not text or not isinstance(text, str):
        return None
    
    # Eliminar espacios extras
    text = text.strip()
    
    # Validar longitud
    if len(text) < MIN_NAME_LENGTH or len(text) > MAX_NAME_LENGTH:
        return None
    
    # Bloquear caracteres peligrosos
    for char in DANGEROUS_CHARS:
        if char in text:
            return None
    
    # Solo permitir letras, números, espacios y algunos caracteres básicos
    if not re.match(r'^[a-zA-Z0-9áéíóúÁÉÍÓÚñÑüÜ\s._-]+$', text):
        return None
    
    # Escape adicional por seguridad
    text = escape(text)
    
    return text


def check_db_limit():
    """Verificar que no se exceda el límite de registros"""
    con = get_db()
    count = con.execute("SELECT COUNT(*) FROM items").fetchone()[0]
    con.close()
    return count < MAX_ITEMS_IN_DB


# =========================
# CRUD
# =========================

# READ
@app.route("/items", methods=["GET"])
def get_items():
    # Validar parámetros de query string si existen
    for key in request.args.keys():
        if key not in ['page', 'limit', 'sort']:  # parámetros permitidos
            return {"error": "Parámetro no permitido"}, 400
    
    con = get_db()
    rows = con.execute("SELECT * FROM items ORDER BY id DESC LIMIT 1000").fetchall()
    con.close()

    data = [{"id": r[0], "name": r[1]} for r in rows]
    return jsonify(data)


# CREATE
@app.route("/items", methods=["POST"])
def add_item():
    # Rate limiting
    if not check_rate_limit():
        return {"error": "Demasiadas solicitudes. Intenta más tarde."}, 429
    
    # Verificar límite de registros
    if not check_db_limit():
        return {"error": "Límite de registros alcanzado"}, 400
    
    # Validación de tipo de datos
    try:
        data = request.get_json()
        if not data or not isinstance(data, dict):
            register_failed_attempt()
            return {"error": "Debe enviar un objeto JSON válido"}, 400
        
        raw = data.get("name", "")
        
        # Validar que sea string
        if not isinstance(raw, str):
            register_failed_attempt()
            return {"error": "El campo 'name' debe ser texto"}, 400
        
    except Exception as e:
        register_failed_attempt()
        return {"error": "Error al procesar la solicitud"}, 400
    
    name = clean_input(raw)

    if not name:
        register_failed_attempt()
        return {"error": "Input inválido. Solo se permiten letras, números y caracteres básicos (._-). Máximo 50 caracteres."}, 400

    con = get_db()
    con.execute("INSERT INTO items(name) VALUES(?)", (name,))
    con.commit()
    con.close()

    return {"ok": True}


# UPDATE
@app.route("/items/<int:item_id>", methods=["PUT"])
def edit(item_id):
    # Rate limiting
    if not check_rate_limit():
        return {"error": "Demasiadas solicitudes. Intenta más tarde."}, 429
    
    # Validar que el ID sea razonable
    if item_id < 1 or item_id > 999999:
        register_failed_attempt()
        return {"error": "ID inválido"}, 400
    
    # Verificar que el item existe antes de actualizar
    con = get_db()
    exists = con.execute("SELECT id FROM items WHERE id=?", (item_id,)).fetchone()
    if not exists:
        con.close()
        register_failed_attempt()
        return {"error": "Recurso no encontrado"}, 404
    
    # Validación de tipo de datos
    try:
        data = request.get_json()
        if not data or not isinstance(data, dict):
            con.close()
            register_failed_attempt()
            return {"error": "Debe enviar un objeto JSON válido"}, 400
        
        raw = data.get("name", "")
        
        # Validar que sea string
        if not isinstance(raw, str):
            con.close()
            register_failed_attempt()
            return {"error": "El campo 'name' debe ser texto"}, 400
        
    except Exception as e:
        con.close()
        register_failed_attempt()
        return {"error": "Error al procesar la solicitud"}, 400
    
    name = clean_input(raw)

    if not name:
        con.close()
        register_failed_attempt()
        return {"error": "Input inválido. Solo se permiten letras, números y caracteres básicos (._-). Máximo 50 caracteres."}, 400

    con.execute(
        "UPDATE items SET name=? WHERE id=?",
        (name, item_id)
    )
    con.commit()
    con.close()

    return {"ok": True}


# DELETE
@app.route("/items/<int:item_id>", methods=["DELETE"])
def delete(item_id):
    # Rate limiting
    if not check_rate_limit():
        return {"error": "Demasiadas solicitudes. Intenta más tarde."}, 429
    
    # Validar que el ID sea razonable
    if item_id < 1 or item_id > 999999:
        register_failed_attempt()
        return {"error": "ID inválido"}, 400
    
    con = get_db()
    
    # Verificar que el item existe antes de eliminar
    exists = con.execute("SELECT id FROM items WHERE id=?", (item_id,)).fetchone()
    if not exists:
        con.close()
        register_failed_attempt()
        return {"error": "Recurso no encontrado"}, 404
    
    con.execute("DELETE FROM items WHERE id=?", (item_id,))
    con.commit()
    con.close()

    return {"ok": True}


# =========================
# RUN
# =========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
