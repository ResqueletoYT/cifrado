from flask import Flask, request, render_template_string
from Crypto.Cipher import AES
import base64

app = Flask(__name__)
app.secret_key = 'clave-super-secreta'
historial = []

html_template = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>App de Cifrado</title>
    <style>
        body { font-family: sans-serif; background: #121212; color: #eee; padding: 2rem; }
        form { background: #1e1e1e; padding: 1.5rem; border-radius: 12px; max-width: 600px; margin: auto; }
        input, textarea, button { width: 100%; padding: 10px; margin-top: 1rem; border-radius: 8px; border: none; }
        button { background: #00bcd4; color: white; cursor: pointer; }
        .resultado, .historial { background: #2e2e2e; padding: 1rem; margin-top: 2rem; border-radius: 8px; }
    </style>
</head>
<body>
    <h1>🔐 Cifrador Seguro</h1>
    <form method="post">
        <label>Mensaje:</label>
        <textarea name="mensaje" required>{{ mensaje or "" }}</textarea>
        <label>Clave (16, 24 o 32 caracteres):</label>
        <input type="text" name="clave" required maxlength="32" value="{{ clave or "" }}">
        <button name="accion" value="cifrar">Cifrar</button>
        <button name="accion" value="descifrar">Descifrar</button>
    </form>

    {% if resultado %}
    <div class="resultado">
        <strong>Resultado:</strong><br>
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
    pad_len = AES.block_size - (len(text) % AES.block_size)
    return text + chr(pad_len) * pad_len

def unpad(text):
    pad_len = ord(text[-1])
    return text[:-pad_len]

def cifrar(texto, clave):
    if len(clave) not in [16, 24, 32]:
        raise ValueError("La clave debe tener 16, 24 o 32 caracteres.")
    cipher = AES.new(clave.encode(), AES.MODE_ECB)
    texto_padded = pad(texto)
    cifrado = cipher.encrypt(texto_padded.encode())
    return base64.b64encode(cifrado).decode()

def descifrar(cifrado_b64, clave):
    if len(clave) not in [16, 24, 32]:
        raise ValueError("La clave debe tener 16, 24 o 32 caracteres.")
    cipher = AES.new(clave.encode(), AES.MODE_ECB)
    cifrado = base64.b64decode(cifrado_b64)
    texto_padded = cipher.decrypt(cifrado).decode()
    return unpad(texto_padded)

@app.route("/", methods=["GET", "POST"])
def index():
    mensaje = clave = resultado = ""
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
