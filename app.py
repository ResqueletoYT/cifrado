# 🔐 ENCRIPTADOS - WEB DE CIFRADO AVANZADO 🔐
# 💡 FUNCIONALIDADES: Cifrado con clave, historial seguro con contraseña, selector de temas, soporte multilenguaje, interfaz móvil + PC, estadísticas, y más.
# 📦 Requiere: Flask, pycryptodome, pytz, flask_socketio, eventlet

from flask import Flask, request, redirect, make_response
from flask_socketio import SocketIO
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from datetime import datetime
import pytz, os, json

app = Flask(__name__)
socketio = SocketIO(app)
SECRET_HISTORIAL_PASSWORD = "dastanxainhoa2025"
HISTORIAL_FILE = "historial.txt"
STATS_FILE = "stats.json"
IDIOMAS = {"es": "Español", "en": "English"}
TEMAS = {
    "claro": {"bg": "#ffffff", "fg": "#000000"},
    "oscuro": {"bg": "#121212", "fg": "#ffffff"},
    "cielo": {"bg": "#e0f7fa", "fg": "#00796b"},
    "neon": {"bg": "#000000", "fg": "#39ff14"},
    "pastel": {"bg": "#ffe0f0", "fg": "#5c4d7d"}
}
if not os.path.exists(STATS_FILE):
    with open(STATS_FILE, "w") as f:
        json.dump({"cifrados": 0, "descifrados": 0}, f)

def idioma_usuario():
    lang = request.headers.get("Accept-Language", "es").split(",")[0][:2]
    return lang if lang in IDIOMAS else "es"

def cifrar(texto, clave):
    clave = clave.encode().ljust(32, b"\0")[:32]
    iv = os.urandom(16)
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(texto.encode(), AES.block_size))
    return b64encode(iv + ct_bytes).decode()

def descifrar(texto, clave):
    clave = clave.encode().ljust(32, b"\0")[:32]
    raw = b64decode(texto)
    iv = raw[:16]
    ct = raw[16:]
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

def registrar_historial(accion, mensaje, clave):
    madrid = pytz.timezone("Europe/Madrid")
    hora = datetime.now(madrid).strftime("%Y-%m-%d %H:%M:%S")
    linea = f"{hora} | {accion} | Mensaje: {mensaje[:100]} | Clave usada: {clave[:20]}\n"
    with open(HISTORIAL_FILE, "a", encoding="utf-8") as f:
        f.write(linea)

def actualizar_estadisticas(accion):
    with open(STATS_FILE, "r+") as f:
        datos = json.load(f)
        datos[accion] += 1
        f.seek(0)
        json.dump(datos, f)
        f.truncate()

@app.route("/", methods=["GET", "POST"])
def index():
    idioma = idioma_usuario()
    tema = request.cookies.get("tema", "oscuro")
    bg = TEMAS[tema]["bg"]
    fg = TEMAS[tema]["fg"]
    mensaje = resultado = ""
    if request.method == "POST":
        texto = request.form.get("mensaje", "")
        clave = request.form.get("clave", "")
        accion = request.form.get("accion", "")
        if not clave or not texto:
            resultado = "❌ Introduce mensaje y clave."
        else:
            try:
                if accion == "cifrar":
                    resultado = cifrar(texto, clave)
                    registrar_historial("Cifrado", texto, clave)
                    actualizar_estadisticas("cifrados")
                elif accion == "descifrar":
                    resultado = descifrar(texto, clave)
                    registrar_historial("Descifrado", texto, clave)
                    actualizar_estadisticas("descifrados")
                mensaje = texto
            except:
                resultado = "❌ Error al procesar el mensaje."
    temas_options = "".join(f'<option value="{k}">{k.title()}</option>' for k in TEMAS)
    html = f"""
    <html><head><title>🔐 Encriptados 🔓</title>
    <style>
    body {{ background:{bg}; color:{fg}; font-family:sans-serif; text-align:center; }}
    textarea {{ width:90%; height:120px; margin:10px; font-size:16px; }}
    input[type=text] {{ width:60%; padding:10px; font-size:16px; }}
    button {{ padding:10px 20px; font-size:16px; margin:5px; }}
    select {{ padding:5px; font-size:14px; }}
    </style></head><body>
    <h1>🔐 Encriptados 🔓</h1>
    <form method="post">
        <textarea name="mensaje" placeholder="Escribe aquí...">{mensaje}</textarea><br>
        <input type="text" name="clave" placeholder="Clave (hasta 100 caracteres)"><br>
        <button type="submit" name="accion" value="cifrar">Cifrar</button>
        <button type="submit" name="accion" value="descifrar">Descifrar</button>
    </form>
    <textarea readonly onclick="navigator.clipboard.writeText(this.value);">{resultado}</textarea><br>
    <form method="get" action="/historial"><button>Ver Historial 🔒</button></form>
    <form method="get" action="/estadisticas"><button>Ver Estadísticas 📊</button></form>
    <form method="post" action="/tema">
        <label>Tema:</label>
        <select name="tema">{temas_options}</select>
        <button type="submit">Cambiar</button>
    </form></body></html>
    """
    return html

@app.route("/tema", methods=["POST"])
def cambiar_tema():
    tema = request.form.get("tema", "oscuro")
    if tema not in TEMAS:
        tema = "oscuro"
    res = make_response(redirect("/"))
    res.set_cookie("tema", tema)
    return res

@app.route("/historial", methods=["GET", "POST"])
def historial():
    if request.method == "POST":
        passw = request.form.get("pass", "")
        if passw == SECRET_HISTORIAL_PASSWORD:
            try:
                with open(HISTORIAL_FILE, "r", encoding="utf-8") as f:
                    contenido = f.read()
            except:
                contenido = "No hay historial aún."
            return f"""
            <html><body><h2>Historial de Actividad</h2>
            <textarea style='width:90%;height:400px;' readonly>{contenido}</textarea><br>
            <form method='get' action='/'><button>Volver</button></form></body></html>
            """
        else:
            return redirect("/historial")
    return """
    <html><body><h2>Introduce la contraseña del historial</h2>
    <form method='post'><input type='password' name='pass'><button type='submit'>Ver</button></form>
    <form method='get' action='/'><button>Volver</button></form></body></html>
    """

@app.route("/estadisticas", methods=["GET"])
def estadisticas():
    with open(STATS_FILE, "r") as f:
        stats = json.load(f)
    return f"""
    <html><body><h2>📊 Estadísticas Personales</h2>
    <p>Mensajes cifrados: {stats["cifrados"]}</p>
    <p>Mensajes descifrados: {stats["descifrados"]}</p>
    <form method='get' action='/'><button>Volver</button></form></body></html>
    """

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=10000)

