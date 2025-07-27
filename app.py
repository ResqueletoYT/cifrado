# Generador del archivo base "app.py" completo con todo el sistema desde cero:
# - Cifrado y descifrado con clave personalizada (de 1 a 100 caracteres)
# - Interfaz bonita, moderna y adaptativa
# - Historial oculto hasta ingresar contraseña
# - Selector de múltiples temas
# - Estadísticas personales
# - Todo embebido en un solo archivo Python
# - Seguro y sin dependencias externas (sin archivos .html/.css/.js)

from flask import Flask, request, render_template_string, redirect, url_for
from datetime import datetime
from base64 import b64encode, b64decode
import pytz
import os

app = Flask(__name__)
app.secret_key = "clave_secreta_segura"

HISTORIAL_FILE = "historial.txt"
CONTRASENA_HISTORIAL = "dastanxainhoa2025"
ESTADISTICAS = {"cifrados": 0, "descifrados": 0}
HISTORIAL_ACTIVO = True

# Temas visuales
temas = {
    "Claro": "body{background:#fff;color:#000;}",
    "Oscuro": "body{background:#121212;color:#fff;}",
    "Matrix": "body{background:#000;color:#0f0;font-family:monospace;}",
    "Cyberpunk": "body{background:#0f0f2f;color:#ff00cc;font-family:'Courier New';}",
    "Azul Neón": "body{background:#001F3F;color:#7FDBFF;}",
    "Retro 90s": "body{background:#f0e68c;color:#000080;font-family:'Comic Sans MS';}",
    "Solarizado": "body{background:#fdf6e3;color:#657b83;}",
    "Aesthetic": "body{background:#ffe4e1;color:#8b008b;font-family:'Georgia';}",
    "Rosa Futurista": "body{background:#ff69b4;color:#222;}",
    "Dracula": "body{background:#282a36;color:#f8f8f2;}",
}

# Utilidades
def cifrar(texto, clave):
    texto_bytes = texto.encode("utf-8")
    clave_bytes = clave.encode("utf-8")
    resultado = bytes([b ^ clave_bytes[i % len(clave_bytes)] for i, b in enumerate(texto_bytes)])
    return b64encode(resultado).decode("utf-8")

def descifrar(texto_cifrado, clave):
    texto_bytes = b64decode(texto_cifrado)
    clave_bytes = clave.encode("utf-8")
    resultado = bytes([b ^ clave_bytes[i % len(clave_bytes)] for i, b in enumerate(texto_bytes)])
    return resultado.decode("utf-8")

def registrar_historial(texto, resultado, clave, accion):
    if not HISTORIAL_ACTIVO: return
    zona_madrid = pytz.timezone("Europe/Madrid")
    hora = datetime.now(zona_madrid).strftime("%Y-%m-%d %H:%M:%S")
    with open(HISTORIAL_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{hora}] Acción: {accion}\nMensaje: {texto}\nResultado: {resultado}\nClave usada: {clave}\n---\n")

# HTML Embebido con selector de tema y visualización del historial protegida
HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>🔒 Encriptados 🔓</title>
    <style>
        body {{ font-family: Arial; padding:20px; }}
        .caja {{ margin: 10px 0; }}
        {estilo}
    </style>
    <script>
        function copiar(id){{
            const texto = document.getElementById(id);
            navigator.clipboard.writeText(texto.innerText);
            alert("Texto copiado al portapapeles");
        }}
    </script>
</head>
<body>
    <h1>🔒 Encriptados 🔓</h1>
    <form method="post">
        <div class="caja">
            <textarea name="mensaje" rows="4" cols="50" placeholder="Escribe el mensaje...">{mensaje}</textarea>
        </div>
        <div class="caja">
            <input type="text" name="clave" placeholder="Clave para (des)cifrar (1-100 caracteres)" value="{clave}">
        </div>
        <div class="caja">
            <select name="tema">
                {temas_opciones}
            </select>
            <button name="cifrar" type="submit">Cifrar</button>
            <button name="descifrar" type="submit">Descifrar</button>
        </div>
        <div class="caja">
            <b>Resultado:</b>
            <div id="resultado">{resultado}</div>
            <button onclick="copiar('resultado')" type="button">📋 Copiar</button>
        </div>
        <hr>
        <div class="caja">
            <input type="password" name="clave_historial" placeholder="Clave para ver historial o estadísticas">
            <button name="ver_historial" type="submit">📜 Ver Historial</button>
            <button name="ver_estadisticas" type="submit">📊 Ver Estadísticas</button>
        </div>
        {bloque_extra}
    </form>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    mensaje = ""
    clave = ""
    resultado = ""
    bloque_extra = ""
    estilo = temas.get("Claro")
    tema_actual = "Claro"

    if request.method == "POST":
        mensaje = request.form.get("mensaje", "")
        clave = request.form.get("clave", "")
        tema_actual = request.form.get("tema", "Claro")
        estilo = temas.get(tema_actual, estilo)

        if "cifrar" in request.form and mensaje and clave:
            resultado = cifrar(mensaje, clave)
            registrar_historial(mensaje, resultado, clave, "Cifrado")
            ESTADISTICAS["cifrados"] += 1

        elif "descifrar" in request.form and mensaje and clave:
            try:
                resultado = descifrar(mensaje, clave)
                registrar_historial(mensaje, resultado, clave, "Descifrado")
                ESTADISTICAS["descifrados"] += 1
            except:
                resultado = "[ERROR al descifrar: clave incorrecta o mensaje malformado]"

        elif "ver_historial" in request.form:
            clave_h = request.form.get("clave_historial", "")
            if clave_h == CONTRASENA_HISTORIAL:
                if os.path.exists(HISTORIAL_FILE):
                    with open(HISTORIAL_FILE, "r", encoding="utf-8") as f:
                        contenido = f"<pre>{f.read()}</pre>"
                else:
                    contenido = "No hay historial guardado aún."
                bloque_extra = contenido
            else:
                bloque_extra = "<b style='color:red'>❌ Contraseña incorrecta</b>"

        elif "ver_estadisticas" in request.form:
            clave_h = request.form.get("clave_historial", "")
            if clave_h == CONTRASENA_HISTORIAL:
                bloque_extra = f"""
                <ul>
                    <li>🔐 Mensajes cifrados: {ESTADISTICAS['cifrados']}</li>
                    <li>🔓 Mensajes descifrados: {ESTADISTICAS['descifrados']}</li>
                </ul>"""
            else:
                bloque_extra = "<b style='color:red'>❌ Contraseña incorrecta</b>"

    temas_opciones = "".join([f"<option value='{t}' {'selected' if t==tema_actual else ''}>{t}</option>" for t in temas])

    return render_template_string(HTML.format(
        mensaje=mensaje,
        clave=clave,
        resultado=resultado,
        estilo=estilo,
        temas_opciones=temas_opciones,
        bloque_extra=bloque_extra
    ))

if __name__ == "__main__":
    app.run(debug=True)

