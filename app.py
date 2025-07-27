from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import os
import json
import time
from datetime import datetime, timedelta
import pytz
import requests

app = Flask(__name__)
app.secret_key = 'clave_secreta_para_sesiones'

# Variables globales y datos simulados
USUARIOS = {}
AMIGOS = {}
HISTORIAL = []
MENSAJES_TEMPORALES = {}
CLAVE_MAESTRA = 'clavehistorial'
HISTORIAL_LIMPIEZA_DIAS = 30

KEY = b'claveaesclaveaes'  # 16 bytes (AES-128)

# --- FUNCIONES DE CIFRADO/ DESCIFRADO ---
def cifrar(texto):
    cipher = AES.new(KEY, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(texto.encode('utf-8'))
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def descifrar(texto_cifrado):
    datos = base64.b64decode(texto_cifrado)
    nonce = datos[:16]
    ciphertext = datos[16:]
    cipher = AES.new(KEY, AES.MODE_EAX, nonce=nonce)
    texto = cipher.decrypt(ciphertext).decode('utf-8')
    return texto

# --- FUNCIONES AUXILIARES ---
def obtener_hora():
    zona_horaria = pytz.timezone('Europe/Madrid')
    return datetime.now(zona_horaria).strftime('%Y-%m-%d %H:%M:%S')

def obtener_ubicacion():
    try:
        res = requests.get("http://ip-api.com/json/").json()
        return f"{res.get('city', '')}, {res.get('country', '')}"
    except:
        return "Ubicación desconocida"

def limpiar_historial():
    limite = datetime.now() - timedelta(days=HISTORIAL_LIMPIEZA_DIAS)
    global HISTORIAL
    HISTORIAL = [x for x in HISTORIAL if datetime.strptime(x['fecha_hora'], '%Y-%m-%d %H:%M:%S') > limite]

# --- RUTAS PRINCIPALES ---
@app.route('/')
def inicio():
    if 'usuario' in session:
        return redirect(url_for('panel'))
    return render_template_string(TEMPLATE_LOGIN)

@app.route('/registro', methods=['POST'])
def registro():
    usuario = request.form['usuario']
    password = request.form['password']
    if usuario in USUARIOS:
        return "Usuario ya registrado"
    USUARIOS[usuario] = password
    AMIGOS[usuario] = []
    return redirect(url_for('inicio'))

@app.route('/login', methods=['POST'])
def login():
    usuario = request.form['usuario']
    password = request.form['password']
    if USUARIOS.get(usuario) == password:
        session['usuario'] = usuario
        return redirect(url_for('panel'))
    return "Login incorrecto"

@app.route('/panel')
def panel():
    if 'usuario' not in session:
        return redirect(url_for('inicio'))
    return render_template_string(TEMPLATE_PANEL, usuario=session['usuario'])

@app.route('/cifrar', methods=['POST'])
def cifrar_texto():
    if 'usuario' not in session:
        return redirect(url_for('inicio'))
    texto = request.form['mensaje']
    cifrado = cifrar(texto)
    entrada = {
        'usuario': session['usuario'],
        'mensaje_original': texto,
        'mensaje_cifrado': cifrado,
        'fecha_hora': obtener_hora(),
        'ubicacion': obtener_ubicacion(),
        'accion': 'Cifrado'
    }
    HISTORIAL.append(entrada)
    return jsonify(entrada)

@app.route('/descifrar', methods=['POST'])
def descifrar_texto():
    if 'usuario' not in session:
        return redirect(url_for('inicio'))
    texto_cifrado = request.form['mensaje']
    try:
        texto = descifrar(texto_cifrado)
    except:
        return jsonify({'error': 'Mensaje inválido'})
    entrada = {
        'usuario': session['usuario'],
        'mensaje_original': texto,
        'mensaje_cifrado': texto_cifrado,
        'fecha_hora': obtener_hora(),
        'ubicacion': obtener_ubicacion(),
        'accion': 'Descifrado'
    }
    HISTORIAL.append(entrada)
    return jsonify(entrada)

@app.route('/historial', methods=['POST'])
def ver_historial():
    clave = request.form['clave']
    if clave != CLAVE_MAESTRA:
        return jsonify({'error': 'Clave maestra incorrecta'})
    limpiar_historial()
    filtro = request.form.get('filtro', '').lower()
    resultados = [x for x in HISTORIAL if filtro in x['mensaje_original'].lower() or filtro in x['mensaje_cifrado'].lower() or filtro in x['fecha_hora'].lower() or filtro in x['ubicacion'].lower() or filtro in x['usuario'].lower()]
    return jsonify(resultados[::-1])

# --- HTML DE LOGIN Y PANEL RESPONSIVO ---
TEMPLATE_LOGIN = '''
<!doctype html><html><head><title>Login</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{font-family:sans-serif;text-align:center;padding:20px;}input,button{margin:5px;width:90%;max-width:300px;font-size:16px;padding:10px;}</style></head><body>
<h2>Registro</h2><form action="/registro" method="post"><input name="usuario" placeholder="Usuario"><input name="password" type="password" placeholder="Contraseña"><button>Registrar</button></form>
<h2>Login</h2><form action="/login" method="post"><input name="usuario" placeholder="Usuario"><input name="password" type="password" placeholder="Contraseña"><button>Entrar</button></form>
</body></html>
'''

TEMPLATE_PANEL = '''
<!doctype html><html><head><title>Panel</title><meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font-family:sans-serif;padding:20px;max-width:600px;margin:auto;}
input,textarea,button{width:100%;margin:5px 0;padding:10px;font-size:16px;}
#resultado{white-space:pre-wrap;}
</style>
</head><body>
<h2>Bienvenido, {{usuario}}</h2>
<textarea id="mensaje" placeholder="Escribe aquí..."></textarea>
<button onclick="cifrar()">Cifrar</button>
<button onclick="descifrar()">Descifrar</button>
<div id="resultado"></div><hr>
<input id="clave" placeholder="Clave maestra">
<input id="filtro" placeholder="Buscar en historial por palabra, fecha, usuario, ubicación">
<button onclick="verHistorial()">Ver historial</button>
<ul id="historial"></ul><hr>
<script>
function cifrar(){
  fetch('/cifrar', {method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:`mensaje=${encodeURIComponent(document.getElementById('mensaje').value)}`})
  .then(r=>r.json()).then(d=>{
    document.getElementById('resultado').innerText = `Cifrado: ${d.mensaje_cifrado}`;
  });
}
function descifrar(){
  fetch('/descifrar', {method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:`mensaje=${encodeURIComponent(document.getElementById('mensaje').value)}`})
  .then(r=>r.json()).then(d=>{
    if(d.error){ alert(d.error); return; }
    document.getElementById('resultado').innerText = `Original: ${d.mensaje_original}\nCifrado: ${d.mensaje_cifrado}`;
  });
}
function verHistorial(){
  fetch('/historial', {method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:`clave=${document.getElementById('clave').value}&filtro=${document.getElementById('filtro').value}`})
  .then(r=>r.json()).then(d=>{
    if(d.error){alert(d.error);return;}
    document.getElementById('historial').innerHTML = d.map(x=>`<li>[${x.fecha_hora}] (${x.ubicacion}) ${x.accion} → Original: ${x.mensaje_original}, Cifrado: ${x.mensaje_cifrado}</li>`).join('');
  });
}
</script></body></html>
'''

if __name__ == '__main__':
    try:
        port = int(os.environ.get('PORT', '5000'))
    except (ValueError, TypeError):
        port = 5000
    app.run(host='0.0.0.0', port=port)
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64

# Constantes
SALT_SIZE = 16
IV_SIZE = 16
KEY_SIZE = 32  # AES-256
PBKDF2_ITERATIONS = 100_000

def derive_key(password: str, salt: bytes) -> bytes:
    """Deriva una clave AES a partir de la contraseña y la sal usando PBKDF2."""
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)

def encrypt(plaintext: str, password: str) -> str:
    """Cifra el texto usando AES-CBC con clave derivada del password.
    Devuelve el resultado codificado en base64 con formato: salt + iv + ciphertext."""
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password.encode(), salt)
    iv = get_random_bytes(IV_SIZE)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Padding PKCS7
    pad_len = AES.block_size - len(plaintext.encode()) % AES.block_size
    padding = chr(pad_len) * pad_len
    padded_text = plaintext + padding

    ciphertext = cipher.encrypt(padded_text.encode())
    encrypted_data = salt + iv + ciphertext
    return base64.b64encode(encrypted_data).decode()

def decrypt(enc_b64: str, password: str) -> str:
    """Descifra el texto cifrado en base64 con la clave derivada de password.
    Devuelve el texto original o lanza excepción si la clave es incorrecta."""
    encrypted_data = base64.b64decode(enc_b64)
    salt = encrypted_data[:SALT_SIZE]
    iv = encrypted_data[SALT_SIZE:SALT_SIZE+IV_SIZE]
    ciphertext = encrypted_data[SALT_SIZE+IV_SIZE:]

    key = derive_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_text = cipher.decrypt(ciphertext)

    # Quitar padding PKCS7
    pad_len = padded_text[-1]
    if isinstance(pad_len, str):  # En python3 es int, en python2 str
        pad_len = ord(pad_len)
    if pad_len < 1 or pad_len > AES.block_size:
        raise ValueError("Clave incorrecta o datos corruptos")
    return padded_text[:-pad_len].decode()

# Ejemplo de uso
if __name__ == "__main__":
    texto = input("Texto a cifrar: ")
    clave = input("Clave para cifrar: ")

    cifrado = encrypt(texto, clave)
    print(f"Texto cifrado:\n{cifrado}\n")

    clave_descifrado = input("Clave para descifrar: ")
    try:
        descifrado = decrypt(cifrado, clave_descifrado)
        print(f"Texto descifrado:\n{descifrado}")
    except Exception as e:
        print(f"Error al descifrar: {str(e)}")
