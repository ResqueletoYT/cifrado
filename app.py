from flask import Flask, request, render_template_string, send_file
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import datetime
import json
import os
import io

app = Flask(__name__)
HISTORIAL_KEY = "dastanxainhoa2025"
HISTORIAL_FILE = "historial.enc"
MAX_DIAS_HISTORIAL = 30

# ==== CIFRADO Y DESCIFRADO ====

def rellenar(texto):
    padding_len = 16 - len(texto.encode('utf-8')) % 16
    return texto + chr(padding_len) * padding_len

def quitar_relleno(texto):
    padding_len = ord(texto[-1])
    return texto[:-padding_len]

def generar_clave(clave):
    return clave.encode("utf-8").ljust(32, b"0")[:32]

def encriptar(mensaje, clave):
    clave_bytes = generar_clave(clave)
    iv = get_random_bytes(16)
    cipher = AES.new(clave_bytes, AES.MODE_CBC, iv)
    mensaje_bytes = rellenar(mensaje).encode("utf-8")
    mensaje_cifrado = cipher.encrypt(mensaje_bytes)
    return base64.urlsafe_b64encode(iv + mensaje_cifrado).decode("utf-8")

def desencriptar(mensaje_cifrado, clave):
    clave_bytes = generar_clave(clave)
    mensaje_cifrado = base64.urlsafe_b64decode(mensaje_cifrado)
    iv = mensaje_cifrado[:16]
    mensaje_bytes = mensaje_cifrado[16:]
    cipher = AES.new(clave_bytes, AES.MODE_CBC, iv)
    mensaje = cipher.decrypt(mensaje_bytes).decode("utf-8")
    return quitar_relleno(mensaje)

# ==== HISTORIAL CIFRADO ====

def limpiar_historial_viejo(historial):
    ahora = datetime.datetime.now()
    return [e for e in historial if (ahora - datetime.datetime.strptime(e["fecha_hora"], "%Y-%m-%d %H:%M:%S")).days <= MAX_DIAS_HISTORIAL]

def guardar_historial(entrada):
    historial = []
    if os.path.exists(HISTORIAL_FILE):
        try:
            with open(HISTORIAL_FILE, "r") as f:
                contenido = f.read()
                if contenido:
                    historial_json = desencriptar(contenido, HISTORIAL_KEY)
                    historial = json.loads(historial_json)
        except Exception:
            historial = []

    historial.append(entrada)
    historial = limpiar_historial_viejo(historial)
    nuevo_historial_json = json.dumps(historial, ensure_ascii=False)
    contenido_cifrado = encriptar(nuevo_historial_json, HISTORIAL_KEY)
    with open(HISTORIAL_FILE, "w") as f:
        f.write(contenido_cifrado)

def obtener_ip():
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        return request.remote_addr
    else:
        return request.environ['HTTP_X_FORWARDED_FOR']

# ==== HTML + JS ====

HTML_TEMPLATE = """
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Sistema de Mensajes Cifrados con Historial Seguro</title>
  <style>
    body { font-family: Arial; margin: 40px; background: #f0f0f0; }
    .container { max-width: 700px; background: white; padding: 20px; border-radius: 8px; margin: auto; }
    textarea, input, button { width: 100%; font-size: 1em; padding: 10px; margin: 8px 0; box-sizing: border-box; }
    button { background: #007BFF; color: white; border: none; border-radius: 5px; cursor: pointer; }
    button:hover { background: #0056b3; }
    label { font-weight: bold; }
    pre { background: #eee; padding: 10px; white-space: pre-wrap; word-wrap: break-word; }
    details { margin-top: 20px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>📜 Sistema de Mensajes Cifrados con Historial Seguro</h1>
    <form method="POST">
      <label>🔐 Clave para cifrar/descifrar:</label>
      <input type="password" name="clave" required maxlength="32" placeholder="Tu clave secreta">
      <label>✉️ Mensaje:</label>
      <textarea name="mensaje" required placeholder="Escribe aquí el mensaje..."></textarea>
      <label>⚙️ ¿Qué quieres hacer?</label>
      <input type="radio" id="encriptar" name="accion" value="encriptar" checked><label for="encriptar"> Cifrar</label>
      <input type="radio" id="desencriptar" name="accion" value="desencriptar"><label for="desencriptar"> Descifrar</label>
      <button type="submit">Procesar</button>
    </form>

    {% if resultado %}
      <h2>✅ Resultado:</h2>
      <pre id="resultado">{{ resultado }}</pre>
      <button onclick="copiarResultado()">📋 Copiar</button>
    {% endif %}

    {% if error %}
      <p style="color:red;"><strong>⚠️ Error:</strong> {{ error }}</p>
    {% endif %}

    <details>
      <summary><strong>📂 Ver historial (requiere clave maestra)</strong></summary>
      <form method="POST" action="/historial">
        <label>Clave maestra:</label>
        <input type="password" name="clave_maestra" required placeholder="Clave maestra">
        <button type="submit">Mostrar historial</button>
      </form>
      {% if historial %}
        <pre>{{ historial }}</pre>
        <form method="POST" action="/descargar">
          <input type="hidden" name="clave_maestra" value="{{ clave_maestra }}">
          <button type="submit">⬇️ Descargar historial</button>
        </form>
      {% endif %}
      {% if error_historial %}
        <p style="color:red;">⚠️ {{ error_historial }}</p>
      {% endif %}
    </details>
  </div>

  <script>
    function copiarResultado() {
      const texto = document.getElementById("resultado").innerText;
      navigator.clipboard.writeText(texto).then(() => {
        alert("¡Resultado copiado!");
      });
    }
  </script>
</body>
</html>
"""

# ==== RUTAS PRINCIPALES ====

@app.route("/", methods=["GET", "POST"])
def index():
    resultado = None
    error = None
    if request.method == "POST":
        clave = request.form.get("clave")
        mensaje = request.form.get("mensaje")
        accion = request.form.get("accion")

        if not clave or not mensaje or not accion:
            error = "⚠️ Faltan datos."
        else:
            try:
                if accion == "encriptar":
                    resultado = encriptar(mensaje, clave)
                    mensaje_procesado = resultado
                elif accion == "desencriptar":
                    resultado = desencriptar(mensaje, clave)
                    mensaje_procesado = resultado
                else:
                    error = "⚠️ Acción no válida."
                    return render_template_string(HTML_TEMPLATE, error=error)
                
                entrada = {
                    "fecha_hora": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "ip": obtener_ip(),
                    "accion": accion,
                    "mensaje_original": mensaje,
                    "mensaje_procesado": mensaje_procesado
                }
                guardar_historial(entrada)

            except Exception:
                error = "⚠️ Clave incorrecta o mensaje mal copiado."
    return render_template_string(HTML_TEMPLATE, resultado=resultado, error=error)

@app.route("/historial", methods=["POST"])
def mostrar_historial():
    clave_maestra = request.form.get("clave_maestra")
    historial = None
    error_historial = None
    if not clave_maestra:
        error_historial = "Debes introducir la clave maestra."
    elif clave_maestra != HISTORIAL_KEY:
        error_historial = "Clave maestra incorrecta."
    else:
        try:
            if os.path.exists(HISTORIAL_FILE):
                with open(HISTORIAL_FILE, "r") as f:
                    contenido_cifrado = f.read()
                historial_json = desencriptar(contenido_cifrado, HISTORIAL_KEY)
                historial_data = json.loads(historial_json)
                texto = ""
                for i, e in enumerate(historial_data, 1):
                    texto += f"{i}. [{e['fecha_hora']}] IP: {e['ip']}\n"
                    texto += f"   Acción: {e['accion']}\n"
                    texto += f"   Mensaje original: {e['mensaje_original']}\n"
                    texto += f"   Mensaje procesado: {e['mensaje_procesado']}\n\n"
                historial = texto
        except Exception:
            error_historial = "No se pudo cargar el historial correctamente."
    return render_template_string(HTML_TEMPLATE, historial=historial, error_historial=error_historial, clave_maestra=clave_maestra)

@app.route("/descargar", methods=["POST"])
def descargar_historial():
    clave_maestra = request.form.get("clave_maestra")
    if clave_maestra != HISTORIAL_KEY:
        return "❌ Clave maestra incorrecta", 403
    if not os.path.exists(HISTORIAL_FILE):
        return "No hay historial."
    with open(HISTORIAL_FILE, "r") as f:
        contenido_cifrado = f.read()
    historial_json = desencriptar(contenido_cifrado, HISTORIAL_KEY)
    historial_data = json.loads(historial_json)

    buffer = io.StringIO()
    for i, e in enumerate(historial_data, 1):
        buffer.write(f"{i}. [{e['fecha_hora']}] IP: {e['ip']}\n")
        buffer.write(f"   Acción: {e['accion']}\n")
        buffer.write(f"   Mensaje original: {e['mensaje_original']}\n")
        buffer.write(f"   Mensaje procesado: {e['mensaje_procesado']}\n\n")
    buffer.seek(0)
    return send_file(io.BytesIO(buffer.getvalue().encode()), mimetype="text/plain", as_attachment=True, download_name="historial.txt")

# ==== ARRANQUE APP ====

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
# EXPANSIÓN MODULAR PARA SISTEMA DE AMIGOS Y CHAT PRIVADO
# Este bloque debe integrarse en el archivo principal "app.py" justo después de los modelos y antes de las rutas

from sqlalchemy import or_
from flask import jsonify

# ------------------------ MODELO PARA MENSAJES DE CHAT ------------------------
class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# ------------------------ FUNCIÓN PARA COMPROBAR AMISTAD ------------------------
def son_amigos(user1_id, user2_id):
    return Amistad.query.filter(
        or_(
            (Amistad.usuario_id == user1_id) & (Amistad.amigo_id == user2_id),
            (Amistad.usuario_id == user2_id) & (Amistad.amigo_id == user1_id)
        )
    ).first() is not None

# ------------------------ RUTA PARA AGREGAR AMIGOS ------------------------
@app.route("/agregar_amigo", methods=["POST"])
@login_required
def agregar_amigo():
    amigo_email = request.form.get("email")
    amigo = User.query.filter_by(email=amigo_email).first()

    if not amigo or amigo.id == current_user.id:
        return jsonify({"error": "Usuario no válido."}), 400

    if son_amigos(current_user.id, amigo.id):
        return jsonify({"error": "Ya son amigos."}), 400

    amistad = Amistad(usuario_id=current_user.id, amigo_id=amigo.id)
    db.session.add(amistad)
    db.session.commit()
    return redirect(url_for('ver_amigos'))

# ------------------------ RUTA PARA VER AMIGOS ------------------------
@app.route("/amigos")
@login_required
def ver_amigos():
    amistades = Amistad.query.filter_by(usuario_id=current_user.id).all()
    amigos = [User.query.get(a.amigo_id) for a in amistades]
    return render_template("amigos.html", amigos=amigos)

# ------------------------ RUTA PARA VER CHAT PRIVADO ------------------------
@app.route("/chat/<int:amigo_id>", methods=["GET", "POST"])
@login_required
def chat_privado(amigo_id):
    if not son_amigos(current_user.id, amigo_id):
        return "No son amigos", 403

    amigo = User.query.get_or_404(amigo_id)

    if request.method == "POST":
        mensaje = request.form.get("mensaje")
        if mensaje:
            nuevo = ChatMessage(sender_id=current_user.id, receiver_id=amigo_id, message=mensaje)
            db.session.add(nuevo)
            db.session.commit()
            return redirect(url_for('chat_privado', amigo_id=amigo_id))

    mensajes = ChatMessage.query.filter(
        or_(
            (ChatMessage.sender_id == current_user.id) & (ChatMessage.receiver_id == amigo_id),
            (ChatMessage.sender_id == amigo_id) & (ChatMessage.receiver_id == current_user.id)
        )
    ).order_by(ChatMessage.timestamp.asc()).all()

    return render_template("chat.html", amigo=amigo, mensajes=mensajes)

# ------------------------ PLANTILLAS BÁSICAS JINJA (PUEDES MEJORAR VISUAL) ------------------------
# templates/amigos.html
"""
{% extends "base.html" %}
{% block content %}
<h2>👥 Lista de Amigos</h2>
<ul>
{% for amigo in amigos %}
    <li>
        {{ amigo.nombre }} - <a href="{{ url_for('chat_privado', amigo_id=amigo.id) }}">Chatear</a>
    </li>
{% endfor %}
</ul>
<form method="POST" action="/agregar_amigo">
    <input type="text" name="email" placeholder="Email del amigo" required>
    <button type="submit">Agregar amigo</button>
</form>
{% endblock %}
"""

# templates/chat.html
"""
{% extends "base.html" %}
{% block content %}
<h2>💬 Chat con {{ amigo.nombre }}</h2>
<div style="background: #f9f9f9; padding: 10px; border-radius: 5px;">
{% for msg in mensajes %}
    <p><strong>{{ 'Tú' if msg.sender_id == current_user.id else amigo.nombre }}:</strong> {{ msg.message }}</p>
{% endfor %}
</div>
<form method="POST">
    <input type="text" name="mensaje" placeholder="Escribe tu mensaje..." required>
    <button type="submit">Enviar</button>
</form>
{% endblock %}
"""
