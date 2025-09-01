# ===============================
# 1. IMPORTS Y CONFIGURACIÓN
# ===============================
from flask import Flask, request, render_template_string, redirect, url_for, send_file
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64, os, json
from datetime import datetime
import pytz

app = Flask(__name__)

# Archivos auxiliares
HISTORIAL_FILE = "historial.txt"
STATS_FILE = "stats.json"
CONFIG_FILE = "config.json"

# Contraseña secreta para acceder a historial y modificar su ON/OFF
HISTORIAL_PASSWORD = "dastanxainhoa2025"

# ===============================
# 2. FUNCIONES AUXILIARES
# ===============================

def cargar_stats():
    """Carga estadísticas desde stats.json o crea si no existe"""
    if not os.path.exists(STATS_FILE):
        return {"cifrados": 0, "descifrados": 0}
    with open(STATS_FILE, "r") as f:
        return json.load(f)

def guardar_stats(stats):
    """Guarda estadísticas"""
    with open(STATS_FILE, "w") as f:
        json.dump(stats, f)

def cargar_config():
    """Configura si historial está activo o no"""
    if not os.path.exists(CONFIG_FILE):
        return {"guardar_historial": True}
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

def guardar_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f)

def guardar_historial(accion, mensaje, clave, ip):
    """Guarda entrada en historial.txt con fecha/hora en Madrid"""
    config = cargar_config()
    if not config["guardar_historial"]:
        return
    madrid = pytz.timezone("Europe/Madrid")
    fecha = datetime.now(madrid).strftime("%Y-%m-%d %H:%M:%S")
    with open(HISTORIAL_FILE, "a") as f:
        f.write(f"[{fecha}] {ip} | {accion.upper()} | Clave: {clave[:3]}*** | Mensaje: {mensaje[:30]}...\n")

# ===============================
# 3. CIFRADO / DESCIFRADO
# ===============================

def cifrar(mensaje, clave):
    key = clave.encode("utf-8")
    key = key[:32].ljust(32, b"0")  # Ajusta longitud AES
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(mensaje.encode("utf-8"), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode("utf-8")
    ct = base64.b64encode(ct_bytes).decode("utf-8")
    return iv + ":" + ct

def descifrar(texto, clave):
    try:
        iv, ct = texto.split(":")
        iv = base64.b64decode(iv)
        ct = base64.b64decode(ct)
        key = clave.encode("utf-8")
        key = key[:32].ljust(32, b"0")
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size).decode("utf-8")
    except:
        return "❌ Error al descifrar (clave incorrecta o mensaje corrupto)"

# ===============================
# 4. INTERFAZ HTML + THEMES
# ===============================

BASE_HTML = """
<!DOCTYPE html>
<html lang="{{ lang }}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🔒 Encriptados 🔓</title>
<style>
/* ----------- ESTILOS BASE ----------- */
body {
  font-family: Arial, sans-serif;
  text-align: center;
  margin: 0; padding: 0;
  background: var(--bg);
  color: var(--text);
}
.container { padding: 20px; max-width: 600px; margin: auto; }
textarea { width: 100%; height: 120px; margin: 10px 0; }
button { margin: 5px; padding: 10px; border: none; cursor: pointer; }
.result { margin-top: 10px; padding: 10px; border: 1px solid #ccc; word-wrap: break-word; }

/* ----------- THEMES ----------- */
:root {
  --bg: #111; --text: #eee; --btn: #444; --btn-text: #fff;
}
body.claro { --bg: #fff; --text: #000; --btn: #ddd; --btn-text: #000; }
body.oscuro { --bg: #000; --text: #0f0; --btn: #111; --btn-text: #0f0; }
body.cielo { --bg: #87ceeb; --text: #003366; --btn: #4682b4; --btn-text: #fff; }
body.neon { --bg: #0f0f0f; --text: #ff00ff; --btn: #222; --btn-text: #ff0; }
body.matrix { --bg: #000; --text: #0f0; --btn: #050; --btn-text: #0f0; }
body.retro { --bg: #f4ecd8; --text: #5a3e2b; --btn: #c9a66b; --btn-text: #000; }

</style>
<script>
function cambiarTema() {
  const temas = ["claro","oscuro","cielo","neon","matrix","retro"];
  let actual = document.body.className;
  let idx = temas.indexOf(actual);
  let siguiente = temas[(idx+1)%temas.length];
  document.body.className = siguiente;
  localStorage.setItem("tema", siguiente);
}
function copiar(id) {
  let texto = document.getElementById(id).innerText;
  navigator.clipboard.writeText(texto);
  alert("📋 Copiado al portapapeles!");
}
window.onload = () => {
  let tema = localStorage.getItem("tema") || "claro";
  document.body.className = tema;
}
</script>
</head>
<body>
<div class="container">
<h2>🔒 Encriptados 🔓</h2>
<form method="POST" action="/cifrar">
  <textarea name="mensaje" placeholder="Escribe tu mensaje aquí..."></textarea><br>
  <input type="password" name="clave" placeholder="Clave (1-100 caracteres)" required><br>
  <button type="submit">Cifrar</button>
</form>
<form method="POST" action="/descifrar">
  <textarea name="mensaje" placeholder="Pega aquí el mensaje cifrado..."></textarea><br>
  <input type="password" name="clave" placeholder="Clave usada para cifrar" required><br>
  <button type="submit">Descifrar</button>
</form>
<div class="result" id="resultado">{{ resultado }}</div>
<button onclick="copiar('resultado')">📋 Copiar Resultado</button>
<br><br>
<a href="/historial">📜 Historial</a> | <a href="/estadisticas">📊 Estadísticas</a>
<br><br>
<button onclick="cambiarTema()">🎨 Cambiar Tema</button>
</div>
</body>
</html>
"""

# ===============================
# 5. RUTAS PRINCIPALES
# ===============================

@app.route("/", methods=["GET"])
def index():
    return render_template_string(BASE_HTML, resultado="", lang="es")

@app.route("/cifrar", methods=["POST"])
def ruta_cifrar():
    mensaje = request.form["mensaje"]
    clave = request.form["clave"]
    ip = request.remote_addr
    res = cifrar(mensaje, clave)
    guardar_historial("cifrar", mensaje, clave, ip)
    stats = cargar_stats(); stats["cifrados"] += 1; guardar_stats(stats)
    return render_template_string(BASE_HTML, resultado=res, lang="es")

@app.route("/descifrar", methods=["POST"])
def ruta_descifrar():
    mensaje = request.form["mensaje"]
    clave = request.form["clave"]
    ip = request.remote_addr
    res = descifrar(mensaje, clave)
    guardar_historial("descifrar", mensaje, clave, ip)
    stats = cargar_stats(); stats["descifrados"] += 1; guardar_stats(stats)
    return render_template_string(BASE_HTML, resultado=res, lang="es")

# ===============================
# 6. HISTORIAL CON PROTECCIÓN
# ===============================

@app.route("/historial", methods=["GET", "POST"])
def ver_historial():
    if request.method == "POST":
        password = request.form.get("password")
        if password != HISTORIAL_PASSWORD:
            return "<h3>❌ Contraseña incorrecta</h3>"
        config = cargar_config()
        with open(HISTORIAL_FILE, "r") as f:
            datos = f.read()
        return f"""
        <h2>📜 Historial</h2>
        <pre>{datos}</pre>
        <form method="POST" action="/toggle_historial">
            <input type="hidden" name="password" value="{password}">
            <button type="submit">
                Guardar historial: {"ON" if config["guardar_historial"] else "OFF"}
            </button>
        </form>
        <a href='/'>⬅️ Volver</a>
        """
    return """
    <form method="POST">
      <input type="password" name="password" placeholder="Contraseña">
      <button type="submit">Acceder</button>
    </form>
    """

@app.route("/toggle_historial", methods=["POST"])
def toggle_historial():
    password = request.form.get("password")
    if password != HISTORIAL_PASSWORD:
        return "<h3>❌ Contraseña incorrecta</h3>"
    config = cargar_config()
    config["guardar_historial"] = not config["guardar_historial"]
    guardar_config(config)
    return redirect(url_for("ver_historial"))

# ===============================
# 7. ESTADÍSTICAS
# ===============================

@app.route("/estadisticas")
def estadisticas():
    stats = cargar_stats()
    return f"""
    <h2>📊 Estadísticas</h2>
    <p>Mensajes cifrados: {stats['cifrados']}</p>
    <p>Mensajes descifrados: {stats['descifrados']}</p>
    <a href='/'>⬅️ Volver</a>
    """

# ===============================
# 8. EJECUCIÓN
# ===============================

if __name__ == "__main__":
    app.run(debug=True)
