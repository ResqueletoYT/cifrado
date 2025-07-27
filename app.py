from flask import Flask, request, render_template_string
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import datetime
import json
import os

app = Flask(__name__)

# Cambia esta clave maestra para proteger el historial (solo tú la debes saber)
HISTORIAL_KEY = "dastanxainhoa2025"

HISTORIAL_FILE = "historial.enc"

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
    nuevo_historial_json = json.dumps(historial, ensure_ascii=False)
    contenido_cifrado = encriptar(nuevo_historial_json, HISTORIAL_KEY)
    with open(HISTORIAL_FILE, "w") as f:
        f.write(contenido_cifrado)

def obtener_ip():
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        return request.remote_addr
    else:
        return request.environ['HTTP_X_FORWARDED_FOR']

HTML_TEMPLATE = """
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Sistema de Mensajes Cifrados con Historial Seguro</title>
  <style>
  body {
  font-family: Arial, sans-serif;
  margin: 10px;
  background: #f0f0f0;
}

.container {
  max-width: 700px;
  margin: auto;
  background: white;
  padding: 15px;
  border-radius: 8px;
  box-sizing: border-box;
}

textarea, input[type=text], input[type=password], button {
  width: 100%;
  padding: 12px;
  margin: 8px 0;
  box-sizing: border-box;
  font-size: 1.1em;
}

button {
  background-color: #007BFF;
  color: white;
  border: none;
  cursor: pointer;
  border-radius: 5px;
}

button:hover {
  background-color: #0056b3;
}

label {
  font-weight: bold;
}

details summary {
  cursor: pointer;
  font-weight: bold;
  margin-top: 20px;
}
    body { font-family: Arial, sans-serif; margin: 40px; background: #f0f0f0; }
    .container { max-width: 700px; background: white; padding: 20px; border-radius: 8px; }
    textarea { width: 100%; height: 100px; }
    input[type=text], input[type=password] { width: 100%; padding: 8px; margin: 6px 0; }
    button { padding: 10px 20px; margin-top: 10px; }
    pre { background: #eee; padding: 10px; white-space: pre-wrap; word-wrap: break-word; }
    details { margin-top: 20px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>📜 Sistema de Mensajes Cifrados con Historial Seguro</h1>
    <form method="POST">
      <label>Clave secreta para cifrar/descifrar:</label>
      <input type="password" name="clave" required maxlength="32" placeholder="Tu clave secreta">
      
      <label>Mensaje:</label>
      <textarea name="mensaje" required placeholder="Escribe aquí el mensaje..."></textarea>
      
      <label>¿Cifrar o descifrar?</label><br>
      <input type="radio" id="encriptar" name="accion" value="encriptar" checked>
      <label for="encriptar">Cifrar</label>
      <input type="radio" id="desencriptar" name="accion" value="desencriptar">
      <label for="desencriptar">Descifrar</label><br><br>
      
      <button type="submit">Procesar</button>
    </form>

    {% if resultado %}
      <h2>Resultado:</h2>
      <pre>{{ resultado }}</pre>
    {% endif %}

    {% if error %}
      <p style="color:red;"><strong>Error:</strong> {{ error }}</p>
    {% endif %}

    <details>
      <summary><strong>Ver historial (requiere clave maestra)</strong></summary>
      <form method="POST" action="/historial">
        <label>Introduce clave maestra:</label>
        <input type="password" name="clave_maestra" required placeholder="Clave maestra">
        <button type="submit">Mostrar historial</button>
      </form>
      {% if historial %}
        <pre>{{ historial }}</pre>
      {% endif %}
      {% if error_historial %}
        <p style="color:red;">{{ error_historial }}</p>
      {% endif %}
    </details>
  </div>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    resultado = None
    error = None
    if request.method == "POST":
        clave = request.form.get("clave")
        mensaje = request.form.get("mensaje")
        accion = request.form.get("accion")

        if not clave or not mensaje or not accion:
            error = "Faltan datos."
        else:
            try:
                if accion == "encriptar":
                    resultado = encriptar(mensaje, clave)
                    mensaje_original = mensaje
                    mensaje_procesado = resultado
                elif accion == "desencriptar":
                    resultado = desencriptar(mensaje, clave)
                    mensaje_original = mensaje
                    mensaje_procesado = resultado
                else:
                    error = "Acción no válida."
                    mensaje_original = None
                    mensaje_procesado = None

                if not error:
                    # Guardar en historial la info completa
                    entrada = {
                        "fecha_hora": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "ip": obtener_ip(),
                        "accion": accion,
                        "mensaje_original": mensaje_original,
                        "mensaje_procesado": mensaje_procesado
                    }
                    guardar_historial(entrada)

            except Exception:
                error = "Clave incorrecta o texto mal copiado."

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
            else:
                historial = "No hay historial aún."
        except Exception:
            error_historial = "No se pudo cargar el historial o la clave maestra es incorrecta."

    return render_template_string(HTML_TEMPLATE, historial=historial, error_historial=error_historial)

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

# =======================
# Módulo: Extensiones Avanzadas
# =======================

from flask_socketio import SocketIO, emit, join_room, leave_room
from datetime import datetime, timedelta
import pytz
import os
import json
import requests

# Inicializar WebSocket (agrega esto en la app Flask principal)
socketio = SocketIO(app)

# ============================
# 1. Configuración y Constantes
# ============================

ZONA_HORARIA = pytz.timezone('Europe/Madrid')
CLAVE_MAESTRA = "tu_clave_maestra_secreta"
ARCHIVO_HISTORIAL = "historial.json"
ARCHIVO_USUARIOS = "usuarios.json"
TIEMPO_LIMPIEZA = 30  # en días

# ============================
# 2. Funciones Auxiliares
# ============================

def obtener_hora_local():
    return datetime.now(ZONA_HORARIA).strftime('%Y-%m-%d %H:%M:%S')

def limpiar_historial():
    if not os.path.exists(ARCHIVO_HISTORIAL):
        return
    with open(ARCHIVO_HISTORIAL, 'r', encoding='utf-8') as f:
        historial = json.load(f)
    ahora = datetime.now(ZONA_HORARIA)
    historial = [e for e in historial if (ahora - datetime.strptime(e['fecha_hora'], '%Y-%m-%d %H:%M:%S')).days <= TIEMPO_LIMPIEZA]
    with open(ARCHIVO_HISTORIAL, 'w', encoding='utf-8') as f:
        json.dump(historial, f, ensure_ascii=False, indent=2)

def obtener_ubicacion():
    try:
        ip_info = requests.get("https://ipinfo.io").json()
        return ip_info.get("city", "¿?") + ", " + ip_info.get("country", "¿?")
    except:
        return "Desconocida"

def guardar_en_historial(modo, original, procesado):
    limpiar_historial()
    entrada = {
        "fecha_hora": obtener_hora_local(),
        "modo": modo,
        "mensaje_original": original,
        "mensaje_procesado": procesado,
        "ubicacion": obtener_ubicacion()
    }
    if os.path.exists(ARCHIVO_HISTORIAL):
        with open(ARCHIVO_HISTORIAL, 'r', encoding='utf-8') as f:
            historial = json.load(f)
    else:
        historial = []
    historial.append(entrada)
    with open(ARCHIVO_HISTORIAL, 'w', encoding='utf-8') as f:
        json.dump(historial, f, ensure_ascii=False, indent=2)

# ============================
# 3. Mensajes de visualización única
# ============================

mensajes_temporales = {}  # clave: id, valor: mensaje

def guardar_mensaje_temporal(id_msg, contenido):
    mensajes_temporales[id_msg] = contenido

def obtener_y_borrar_mensaje_temporal(id_msg):
    return mensajes_temporales.pop(id_msg, None)

# ============================
# 4. Búsqueda en historial
# ============================

def buscar_historial(filtro: str):
    if not os.path.exists(ARCHIVO_HISTORIAL):
        return []
    with open(ARCHIVO_HISTORIAL, 'r', encoding='utf-8') as f:
        historial = json.load(f)
    return [e for e in historial if filtro.lower() in json.dumps(e, ensure_ascii=False).lower()]

# ============================
# 5. WebSockets para chat en vivo
# ============================

usuarios_conectados = {}

@socketio.on('join')
def handle_join(data):
    usuario = data['usuario']
    room = data['sala']
    join_room(room)
    usuarios_conectados[usuario] = room
    emit('estado', {'msg': f'{usuario} se ha unido a la sala.'}, room=room)

@socketio.on('mensaje')
def handle_mensaje(data):
    usuario = data['usuario']
    sala = usuarios_conectados.get(usuario)
    msg = data['msg']
    if sala:
        emit('nuevo_mensaje', {'usuario': usuario, 'msg': msg, 'hora': obtener_hora_local()}, room=sala)

@socketio.on('salir')
def handle_salir(data):
    usuario = data['usuario']
    room = usuarios_conectados.pop(usuario, None)
    if room:
        leave_room(room)
        emit('estado', {'msg': f'{usuario} ha salido de la sala.'}, room=room)

# ============================
# 6. Clave maestra para acceder historial
# ============================

def verificar_clave_maestra(clave):
    return clave == CLAVE_MAESTRA

# ============================
# 7. Guardado cifrado remoto (estructura básica)
# ============================

def guardar_remoto_cifrado(data, clave):
    # Simulación: guardar local, pero se puede extender a Firebase, etc.
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from base64 import b64encode

    key = clave[:32].ljust(32).encode()
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(json.dumps(data).encode())

    paquete = {
        "nonce": b64encode(nonce).decode(),
        "ciphertext": b64encode(ciphertext).decode(),
        "tag": b64encode(tag).decode()
    }
    with open("copia_remota_simulada.json", 'w', encoding='utf-8') as f:
        json.dump(paquete, f, indent=2)

# ============================
# FIN DEL MÓDULO
# ============================
# ¡Puedes importar o copiar estas funciones al final de tu app!
