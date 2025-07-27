from flask import Flask, request, redirect, render_template_string
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

app = Flask(__name__)
app.secret_key = 'clave-super-secreta'

historial = []

html_template = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>App de Cifrado</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #121212;
            color: #f0f0f0;
            padding: 2rem;
        }
        h1 {
            color: #00bcd4;
        }
        form {
            background: #1e1e1e;
            padding: 2rem;
            border-radius: 12px;
            max-width: 600px;
            margin: auto;
        }
        input[type="text"], textarea {
            width: 100%;
            padding: 10px;
            margin-top: 8px;
            margin-bottom: 16px;
            border-radius: 8px;
            border: none;
        }
        button {
            background-color: #00bcd4;
            color: white;
            padding: 12px 20px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
        }
        .resultado, .historial {
            background: #2e2e2e;
            padding: 1rem;
            margin-top: 2rem;
            border-radius: 8px;
        }
    </style>
</head>
<body>
    <h1>🔐 App de Cifrado</h1>
    <form method="POST" action="/">
        <label>Mensaje:</label>
        <textarea name="mensaje" rows="4" required>{{ mensaje or "" }}</textarea>

        <label>Clave (16 caracteres):</label>
        <input type="text" name="clave" maxlength="16" required value="{{ clave or "" }}">

        <button name="accion" value="cifrar">Cifrar</button>
        <button name="accion" value="descifrar">Descifrar</button>
    </form>

    {% if resultado %}
    <div class="resultado">
        <strong>Resultado:</strong>
        <p>{{ resultado }}</p>
    </div>
    {% endif %}

    {% if historial %}
    <div class="historial">
        <strong>Historial:</strong>
        <ul>
            {% for item in historial %}
            <li>{{ item }}</li>
            {% endfor %}
        </ul>
    </div>
    {% endif %}
</body>
</html>
"""

def pad(text):
    while len(text) % 16 != 0:
        text += ' '
    return text

def cifrar(texto, clave):
    clave = pad(clave)[:16].encode()
    texto = pad(texto)
    cipher = AES.new(clave, AES.MODE_ECB)
    cifrado = cipher.encrypt(texto.encode())
    return base64.b64encode(cifrado).decode()

def descifrar(texto_cifrado, clave):
    clave = pad(clave)[:16].encode()
    texto_cifrado = base64.b64decode(texto_cifrado)
    cipher = AES.new(clave, AES.MODE_ECB)
    descifrado = cipher.decrypt(texto_cifrado).decode().rstrip()
    return descifrado

@app.route("/", methods=["GET", "POST"])
def index():
    mensaje, clave, resultado = "", "", ""
    if request.method == "POST":
        mensaje = request.form["mensaje"]
        clave = request.form["clave"]
        accion = request.form["accion"]

        try:
            if accion == "cifrar":
                resultado = cifrar(mensaje, clave)
                historial.insert(0, f"Cifrado: {resultado}")
            elif accion == "descifrar":
                resultado = descifrar(mensaje, clave)
                historial.insert(0, f"Descifrado: {resultado}")
        except Exception as e:
            resultado = f"❌ Error: {str(e)}"

    return render_template_string(html_template, mensaje=mensaje, clave=clave, resultado=resultado, historial=historial[:10])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
