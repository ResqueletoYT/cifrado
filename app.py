from flask import Flask, request, render_template_string, redirect
from datetime import datetime
import pytz
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import os

app = Flask(__name__)

# =================== CONFIGURACIÓN ===================

SECRET_HISTORIAL_PASSWORD = "dastanxainhoa2025"
SAVE_HISTORIAL = True  # Activado por defecto
HISTORIAL_FILE = "historial.txt"
ZONA_MADRID = pytz.timezone("Europe/Madrid")
THEMES = {
    "claro": {"bg": "#ffffff", "fg": "#000000"},
    "oscuro": {"bg": "#121212", "fg": "#f1f1f1"},
    "ciberpunk": {"bg": "#0f0f23", "fg": "#39ff14"},
}

# =================== FUNCIONES ===================

def pad(s):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

def unpad(s):
    return s[:-ord(s[len(s) - 1:])]

def cifrar(texto, clave):
    key = hashlib.sha256(clave.encode()).digest()
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(texto).encode())
    return base64.b64encode(iv + ct_bytes).decode()

def descifrar(texto, clave):
    try:
        raw = base64.b64decode(texto)
        key = hashlib.sha256(clave.encode()).digest()
        iv = raw[:16]
        ct = raw[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct).decode())
    except:
        return "[ERROR DESCIFRANDO]"

def guardar_historial(accion, mensaje, clave):
    if SAVE_HISTORIAL:
        hora = datetime.now(ZONA_MADRID).strftime("%Y-%m-%d %H:%M:%S")
        with open(HISTORIAL_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{hora}] Acción: {accion} | Clave: {clave} | Mensaje: {mensaje}\n")

def leer_historial():
    if os.path.exists(HISTORIAL_FILE):
        with open(HISTORIAL_FILE, "r", encoding="utf-8") as f:
            return f.read()
    return "No hay historial aún."

def buscar_en_historial(palabra):
    if os.path.exists(HISTORIAL_FILE):
        with open(HISTORIAL_FILE, "r", encoding="utf-8") as f:
            return "\n".join([line for line in f if palabra.lower() in line.lower()])
    return "No se encontró nada."

# =================== CABECERAS DE SEGURIDAD ===================

@app.after_request
def aplicar_cabeceras(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
    return response

# =================== HTML DINÁMICO ===================

TEMPLATE = """
<!DOCTYPE html>
<html lang="auto">
<head>
    <meta charset="UTF-8">
    <title>🔐 Encriptados 🔓</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            background-color: {{ theme.bg }};
            color: {{ theme.fg }};
            font-family: Arial, sans-serif;
            padding: 20px;
        }
        textarea, input[type="text"], input[type="password"] {
            width: 100%%; padding: 10px; margin-bottom: 10px; border-radius: 5px;
        }
        button {
            padding: 10px; margin: 5px; border: none; border-radius: 5px;
            cursor: pointer; background-color: {{ theme.fg }}; color: {{ theme.bg }};
        }
        .row { display: flex; flex-wrap: wrap; gap: 10px; }
        .row > * { flex: 1; min-width: 120px; }
        .historial { white-space: pre-wrap; max-height: 300px; overflow-y: scroll; background: #eee; color: #111; padding: 10px; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>🔐 Encriptados 🔓</h1>

    <form method="POST" action="/">
        <label>Texto:</label>
        <textarea name="texto" required>{{ texto or "" }}</textarea>

        <label>Clave:</label>
        <input type="text" name="clave" minlength="1" maxlength="100" required>

        <div class="row">
            <button name="accion" value="cifrar">Cifrar</button>
            <button name="accion" value="descifrar">Descifrar</button>
            <button type="button" onclick="copiarResultado()">📋 Copiar Resultado</button>
        </div>

        <label>Resultado:</label>
        <textarea readonly id="resultado">{{ resultado or "" }}</textarea>

        <div class="row">
            <label>Tema:</label>
            <select name="tema" onchange="this.form.submit()">
                {% for key in temas %}
                    <option value="{{ key }}" {% if key == tema_actual %}selected{% endif %}>{{ key.title() }}</option>
                {% endfor %}
            </select>
        </div>

        <div class="row">
            <label><input type="checkbox" name="guardar" value="1" {% if guardar %}checked{% endif %}> Guardar historial</label>
        </div>
    </form>

    <hr>
    <form method="POST" action="/historial">
        <label>Ver historial (contraseña):</label>
        <input type="password" name="pass" required>
        <button type="submit">Ver</button>
    </form>

    <form method="POST" action="/buscar">
        <label>Buscar en historial:</label>
        <input type="text" name="buscar" required>
        <button type="submit">Buscar</button>
    </form>

    {% if historial %}
        <h3>Historial:</h3>
        <div class="historial">{{ historial }}</div>
    {% endif %}

    <script>
        function copiarResultado() {
            let copyText = document.getElementById("resultado");
            copyText.select();
            document.execCommand("copy");
            alert("Texto copiado");
        }
    </script>
</body>
</html>
"""

# =================== RUTAS ===================

@app.route("/", methods=["GET", "POST"])
def index():
    global SAVE_HISTORIAL
    resultado, texto = "", ""
    tema_actual = request.form.get("tema") or "claro"
    guardar = request.form.get("guardar") == "1"

    if request.method == "POST":
        texto = request.form.get("texto", "")
        clave = request.form.get("clave", "")
        accion = request.form.get("accion")

        if accion and clave:
            if accion == "cifrar":
                resultado = cifrar(texto, clave)
                guardar_historial("Cifrar", resultado, clave)
            elif accion == "descifrar":
                resultado = descifrar(texto, clave)
                guardar_historial("Descifrar", texto, clave)

        SAVE_HISTORIAL = guardar

    return render_template_string(TEMPLATE, resultado=resultado, texto=texto,
                                  tema_actual=tema_actual, temas=THEMES,
                                  theme=THEMES.get(tema_actual, THEMES["claro"]),
                                  guardar=SAVE_HISTORIAL, historial=None)

@app.route("/historial", methods=["POST"])
def ver_historial():
    if request.form.get("pass") == SECRET_HISTORIAL_PASSWORD:
        data = leer_historial()
    else:
        data = "Contraseña incorrecta."

    return render_template_string(TEMPLATE, resultado="", texto="", historial=data,
                                  tema_actual="claro", temas=THEMES,
                                  theme=THEMES["claro"], guardar=SAVE_HISTORIAL)

@app.route("/buscar", methods=["POST"])
def buscar_historial():
    palabra = request.form.get("buscar", "")
    resultado = buscar_en_historial(palabra)
    return render_template_string(TEMPLATE, resultado="", texto="", historial=resultado,
                                  tema_actual="claro", temas=THEMES,
                                  theme=THEMES["claro"], guardar=SAVE_HISTORIAL)

# =================== EJECUCIÓN ===================

if __name__ == "__main__":
    app.run(debug=True)
