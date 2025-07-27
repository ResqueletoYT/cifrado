from flask import Flask, render_template_string, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os
from datetime import datetime
import pytz

app = Flask(__name__)
HISTORIAL_FILE = 'historial.txt'
CLAVE_HISTORIAL = 'dastanxainhoa2025'

# HTML + estilo moderno
template = '''
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>🔒 Encriptados 🔓</title>
  <style>
    body {
      font-family: 'Segoe UI', sans-serif;
      background: #0f2027;
      background: linear-gradient(to right, #2c5364, #203a43, #0f2027);
      color: #fff;
      text-align: center;
      padding: 30px;
    }
    h1 {
      font-size: 2.5em;
      margin-bottom: 20px;
    }
    form {
      margin: 20px auto;
      background: #ffffff11;
      padding: 20px;
      border-radius: 15px;
      width: 90%;
      max-width: 600px;
    }
    input[type=text], textarea {
      width: 90%;
      padding: 10px;
      margin: 10px 0;
      border-radius: 10px;
      border: none;
      resize: vertical;
      font-size: 16px;
    }
    button {
      padding: 10px 20px;
      margin: 10px;
      font-size: 16px;
      background-color: #00c9ff;
      border: none;
      border-radius: 10px;
      cursor: pointer;
      transition: 0.3s;
    }
    button:hover {
      background-color: #92fe9d;
    }
    .result {
      background: #ffffff22;
      margin: 20px auto;
      padding: 15px;
      border-radius: 10px;
      width: 90%;
      max-width: 600px;
    }
    pre {
      white-space: pre-wrap;
      text-align: left;
    }
  </style>
</head>
<body>
  <h1>🔒 Encriptados 🔓</h1>
  <form method="post">
    <textarea name="mensaje" placeholder="Escribe tu mensaje aquí..." required></textarea><br>
    <input type="text" name="clave" placeholder="Clave personalizada (1-100 caracteres)" required><br>
    <button type="submit" name="accion" value="cifrar">Cifrar</button>
    <button type="submit" name="accion" value="descifrar">Descifrar</button>
  </form>

  <form method="post">
    <input type="text" name="clave_historial" placeholder="Contraseña para ver historial">
    <button type="submit" name="accion" value="ver_historial">Ver historial</button>
  </form>

  {% if resultado %}
    <div class="result">
      <h3>Resultado:</h3>
      <p>{{ resultado }}</p>
    </div>
  {% endif %}

  {% if historial %}
    <div class="result">
      <h3>Historial:</h3>
      <pre>{{ historial }}</pre>
    </div>
  {% elif error %}
    <div class="result" style="color: red;">
      <p>{{ error }}</p>
    </div>
  {% endif %}
</body>
</html>
'''

def hora_madrid():
    return datetime.now(pytz.timezone('Europe/Madrid')).strftime('%Y-%m-%d %H:%M:%S')

def guardar_en_historial(accion, clave, mensaje):
    with open(HISTORIAL_FILE, 'a', encoding='utf-8') as f:
        f.write(f"[{hora_madrid()}] Acción: {accion.upper()}\n")
        f.write(f"  Clave usada: {clave}\n")
        f.write(f"  Mensaje: {mensaje}\n")
        f.write("—" * 40 + "\n")

def cifrar_aes(mensaje, clave):
    key = pad(clave.encode(), 16)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(mensaje.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode()
    ct = base64.b64encode(ct_bytes).decode()
    return iv + ct

def descifrar_aes(cifrado, clave):
    key = pad(clave.encode(), 16)
    iv = base64.b64decode(cifrado[:24])
    ct = base64.b64decode(cifrado[24:])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

@app.route('/', methods=['GET', 'POST'])
def index():
    resultado = historial = error = ''
    if request.method == 'POST':
        accion = request.form.get('accion')
        mensaje = request.form.get('mensaje', '')
        clave = request.form.get('clave', '')

        if accion == 'cifrar' and mensaje and clave:
            try:
                resultado = cifrar_aes(mensaje, clave)
                guardar_en_historial("cifrado", clave, mensaje)
            except Exception as e:
                error = f"Error al cifrar: {str(e)}"

        elif accion == 'descifrar' and mensaje and clave:
            try:
                resultado = descifrar_aes(mensaje, clave)
                guardar_en_historial("descifrado", clave, resultado)
            except Exception as e:
                error = f"Error al descifrar: {str(e)}"

        elif accion == 'ver_historial':
            if request.form.get('clave_historial') == CLAVE_HISTORIAL:
                try:
                    with open(HISTORIAL_FILE, 'r', encoding='utf-8') as f:
                        historial = f.read()
                except FileNotFoundError:
                    historial = "No hay historial todavía."
            else:
                error = "❌ Contraseña incorrecta para ver el historial."

    return render_template_string(template, resultado=resultado, historial=historial, error=error)

if __name__ == '__main__':
    app.run(debug=True)
