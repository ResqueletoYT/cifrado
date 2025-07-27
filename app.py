from flask import Flask, render_template_string, request, redirect
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os
from datetime import datetime
import pytz

app = Flask(__name__)
HISTORIAL_FILE = 'historial.txt'
CLAVE_HISTORIAL = 'dastanxainhoa2025'

# HTML embebido con estilo
template = '''
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Encriptador</title>
  <style>
    body {
      font-family: 'Segoe UI', sans-serif;
      background: linear-gradient(to right, #141e30, #243b55);
      color: white;
      text-align: center;
      padding: 40px;
    }
    input, textarea, button {
      padding: 10px;
      margin: 10px;
      border-radius: 10px;
      border: none;
      font-size: 16px;
    }
    input[type=text], textarea {
      width: 80%;
    }
    button {
      background: #00c6ff;
      color: black;
      cursor: pointer;
    }
    .result {
      margin-top: 20px;
      background-color: #ffffff22;
      padding: 15px;
      border-radius: 10px;
    }
  </style>
</head>
<body>
  <h1>🔐 Cifrado / Descifrado AES</h1>
  <form method="post">
    <textarea name="mensaje" placeholder="Escribe tu mensaje..." required>{{ mensaje or '' }}</textarea><br>
    <input type="text" name="clave" placeholder="Clave personalizada (1-100 caracteres)" required value="{{ clave or '' }}"><br>
    <button type="submit" name="accion" value="cifrar">Cifrar</button>
    <button type="submit" name="accion" value="descifrar">Descifrar</button>
  </form>
  {% if resultado %}
    <div class="result">
      <h3>Resultado:</h3>
      <p>{{ resultado }}</p>
    </div>
  {% endif %}
  <hr>
  <h2>📜 Ver historial</h2>
  <form method="post">
    <input type="text" name="clave_historial" placeholder="Contraseña para ver historial">
    <button type="submit" name="accion" value="ver_historial">Ver historial</button>
  </form>
  {% if historial %}
    <div class="result">
      <pre>{{ historial }}</pre>
    </div>
  {% elif error %}
    <div class="result">
      <p style="color: red;">{{ error }}</p>
    </div>
  {% endif %}
</body>
</html>
'''

def hora_madrid():
    zona_madrid = pytz.timezone('Europe/Madrid')
    return datetime.now(zona_madrid).strftime('%Y-%m-%d %H:%M:%S')

def guardar_en_historial(accion, clave, mensaje):
    with open(HISTORIAL_FILE, 'a', encoding='utf-8') as f:
        f.write(f"[{hora_madrid()}] Acción: {accion.upper()}\n")
        f.write(f"  Clave: {clave}\n")
        f.write(f"  Mensaje: {mensaje}\n")
        f.write("—" * 40 + "\n")

def cifrar_aes(mensaje, clave):
    key = clave.encode('utf-8')
    key = pad(key, 16)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(mensaje.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct

def descifrar_aes(cifrado, clave):
    key = clave.encode('utf-8')
    key = pad(key, 16)
    iv = base64.b64decode(cifrado[:24])
    ct = base64.b64decode(cifrado[24:])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

@app.route('/', methods=['GET', 'POST'])
def index():
    resultado = historial = error = mensaje = clave = ''
    if request.method == 'POST':
        accion = request.form['accion']
        mensaje = request.form.get('mensaje', '')
        clave = request.form.get('clave', '')

        if accion == 'cifrar' and mensaje and clave:
            try:
                resultado = cifrar_aes(mensaje, clave)
                guardar_en_historial("cifrado", clave, mensaje)
            except Exception as e:
                error = f"Error al cifrar: {e}"

        elif accion == 'descifrar' and mensaje and clave:
            try:
                resultado = descifrar_aes(mensaje, clave)
                guardar_en_historial("descifrado", clave, resultado)
            except Exception as e:
                error = f"Error al descifrar: {e}"

        elif accion == 'ver_historial':
            if request.form.get('clave_historial') == CLAVE_HISTORIAL:
                try:
                    with open(HISTORIAL_FILE, 'r', encoding='utf-8') as f:
                        historial = f.read()
                except FileNotFoundError:
                    historial = "No hay historial aún."
            else:
                error = "Contraseña incorrecta para ver el historial."

    return render_template_string(template, resultado=resultado, historial=historial, error=error, mensaje=mensaje, clave=clave)

if __name__ == '__main__':
    app.run(debug=True)
