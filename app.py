from flask import Flask, render_template_string, request, redirect
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import pytz
from datetime import datetime

app = Flask(__name__)
HISTORIAL_FILE = 'historial.txt'
CLAVE_HISTORIAL = 'dastanxainhoa2025'

html_template = '''
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>🔒 Encriptados 🔓</title>
    <style>
        body {
            font-family: 'Segoe UI', sans-serif;
            background: var(--bg-color);
            color: var(--text-color);
            text-align: center;
            padding: 30px;
            transition: all 0.4s ease-in-out;
        }
        :root {
            --bg-color: #f1f1f1;
            --text-color: #222;
            --card-bg: #ffffff;
        }
        .dark {
            --bg-color: #1e1e1e;
            --text-color: #fff;
            --card-bg: #2c2c2c;
        }
        h1 {
            font-size: 2.5em;
        }
        form {
            background: var(--card-bg);
            padding: 20px;
            border-radius: 15px;
            margin: 20px auto;
            max-width: 600px;
            box-shadow: 0 0 15px rgba(0,0,0,0.1);
        }
        textarea, input[type=text] {
            width: 90%;
            padding: 10px;
            margin: 10px 0;
            border-radius: 10px;
            border: 1px solid #ccc;
            font-size: 16px;
        }
        button {
            padding: 10px 20px;
            margin: 10px;
            border: none;
            border-radius: 10px;
            cursor: pointer;
            font-size: 16px;
            background-color: #0099ff;
            color: white;
            transition: 0.3s;
        }
        button:hover {
            background-color: #00cc88;
        }
        .result, .historial {
            background: var(--card-bg);
            margin: 20px auto;
            padding: 15px;
            border-radius: 10px;
            max-width: 600px;
            box-shadow: 0 0 15px rgba(0,0,0,0.1);
            text-align: left;
            white-space: pre-wrap;
        }
        .toggle {
            background: #888;
            position: fixed;
            top: 20px;
            right: 20px;
        }
    </style>
</head>
<body>
    <button class="toggle" onclick="toggleMode()">🌗 Tema</button>
    <h1>🔒 Encriptados 🔓</h1>

    <form method="post" autocomplete="off">
        <textarea name="mensaje" placeholder="Escribe tu mensaje..." required></textarea><br>
        <input type="text" name="clave" maxlength="100" placeholder="Clave (1-100 caracteres)" required><br>
        <button name="accion" value="cifrar">Cifrar</button>
        <button name="accion" value="descifrar">Descifrar</button>
    </form>

    <form method="post" autocomplete="off">
        <input type="text" name="clave_historial" placeholder="Contraseña para ver historial">
        <button name="accion" value="ver_historial">Ver historial</button>
    </form>

    {% if resultado %}
    <div class="result">
        <strong>Resultado:</strong><br>{{ resultado }}
    </div>
    {% endif %}

    {% if historial %}
    <div class="historial">
        <strong>Historial:</strong><br>{{ historial }}
    </div>
    {% elif error %}
    <div class="historial" style="color: red;">
        {{ error }}
    </div>
    {% endif %}

<script>
    function toggleMode() {
        document.body.classList.toggle("dark");
        localStorage.setItem("modo", document.body.classList.contains("dark") ? "oscuro" : "claro");
    }

    window.onload = () => {
        if (localStorage.getItem("modo") === "oscuro") {
            document.body.classList.add("dark");
        }
    }
</script>
</body>
</html>
'''

def hora_madrid():
    return datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S")

def guardar_historial(accion, clave, mensaje):
    with open(HISTORIAL_FILE, 'a', encoding='utf-8') as f:
        f.write(f"[{hora_madrid()}] Acción: {accion.upper()}\n")
        f.write(f"  Clave usada: {clave}\n")
        f.write(f"  Mensaje: {mensaje}\n")
        f.write("-" * 40 + "\n")

def cifrar(mensaje, clave):
    key = pad(clave.encode(), 16)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(mensaje.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode()
    ct = base64.b64encode(ct_bytes).decode()
    return iv + ct

def descifrar(texto, clave):
    key = pad(clave.encode(), 16)
    iv = base64.b64decode(texto[:24])
    ct = base64.b64decode(texto[24:])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    mensaje = unpad(cipher.decrypt(ct), AES.block_size)
    return mensaje.decode()

@app.route('/', methods=['GET', 'POST'])
def home():
    resultado = historial = error = ''
    if request.method == 'POST':
        accion = request.form.get('accion')
        clave = request.form.get('clave', '')
        mensaje = request.form.get('mensaje', '')

        if accion in ['cifrar', 'descifrar'] and mensaje and clave:
            try:
                if accion == 'cifrar':
                    resultado = cifrar(mensaje, clave)
                    guardar_historial("cifrado", clave, mensaje)
                elif accion == 'descifrar':
                    resultado = descifrar(mensaje, clave)
                    guardar_historial("descifrado", clave, resultado)
            except Exception as e:
                error = f"❌ Error: {str(e)}"
        
        elif accion == 'ver_historial':
            clave_h = request.form.get('clave_historial', '')
            if clave_h == CLAVE_HISTORIAL:
                try:
                    with open(HISTORIAL_FILE, 'r', encoding='utf-8') as f:
                        historial = f.read()
                except FileNotFoundError:
                    historial = "Historial vacío."
            else:
                error = "❌ Contraseña incorrecta para acceder al historial."

    return render_template_string(html_template, resultado=resultado, historial=historial, error=error)

if __name__ == '__main__':
    app.run(debug=True)
