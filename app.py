# app.py (TODO EN UN SOLO BLOQUE)
from flask import Flask, request, redirect, render_template_string, session, url_for
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_sqlalchemy import SQLAlchemy
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import os
import hashlib

app = Flask(__name__)
app.secret_key = 'clave_secreta_super_segura'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///usuarios.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# MODELOS
class Usuario(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(80), unique=True, nullable=False)
    contraseña = db.Column(db.String(200), nullable=False)

class Mensaje(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    contenido = db.Column(db.Text, nullable=False)
    clave_hash = db.Column(db.String(64), nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'))

# ENCRIPTACIÓN
BLOCK_SIZE = 16

def pad(s):
    return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

def unpad(s):
    return s[:-ord(s[len(s) - 1:])]

def encrypt(raw, password):
    raw = pad(raw)
    key = hashlib.sha256(password.encode()).digest()
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = base64.b64encode(iv + cipher.encrypt(raw.encode()))
    return encrypted.decode('utf-8')

def decrypt(enc, password):
    enc = base64.b64decode(enc)
    key = hashlib.sha256(password.encode()).digest()
    iv = enc[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(enc[16:])
    return unpad(decrypted.decode('utf-8'))

# LOGIN MANAGER
@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

# RUTAS
@app.route('/')
@login_required
def index():
    mensajes = Mensaje.query.filter_by(usuario_id=current_user.id).all()
    return render_template_string(TEMPLATE_INDEX, usuario=current_user.nombre, mensajes=mensajes)

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        nombre = request.form['usuario']
        contraseña = request.form['contraseña']
        if Usuario.query.filter_by(nombre=nombre).first():
            return 'Usuario ya registrado.'
        nuevo = Usuario(nombre=nombre, contraseña=contraseña)
        db.session.add(nuevo)
        db.session.commit()
        return redirect('/login')
    return render_template_string(TEMPLATE_REGISTER)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = Usuario.query.filter_by(nombre=request.form['usuario']).first()
        if usuario and usuario.contraseña == request.form['contraseña']:
            login_user(usuario)
            return redirect('/')
        return 'Credenciales incorrectas.'
    return render_template_string(TEMPLATE_LOGIN)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')

@app.route('/cifrar', methods=['POST'])
@login_required
def cifrar():
    texto = request.form['mensaje']
    clave = request.form['clave']
    cifrado = encrypt(texto, clave)
    hash_clave = hashlib.sha256(clave.encode()).hexdigest()
    nuevo = Mensaje(contenido=cifrado, clave_hash=hash_clave, usuario_id=current_user.id)
    db.session.add(nuevo)
    db.session.commit()
    return redirect('/')

@app.route('/descifrar/<int:id>', methods=['POST'])
@login_required
def descifrar(id):
    clave = request.form['clave']
    mensaje = Mensaje.query.get(id)
    if not mensaje:
        return 'Mensaje no encontrado.'
    hash_clave = hashlib.sha256(clave.encode()).hexdigest()
    if mensaje.clave_hash != hash_clave:
        return 'Clave incorrecta.'
    try:
        texto = decrypt(mensaje.contenido, clave)
        return f"Mensaje descifrado: {texto}"
    except:
        return 'Error al descifrar.'

# HTML EMBEBIDO (INTERFAZ BONITA)
TEMPLATE_LOGIN = '''
<!DOCTYPE html><html><head><title>Login</title></head><body>
<h2>Iniciar Sesión</h2>
<form method="post">
  <input name="usuario" placeholder="Usuario" required><br>
  <input name="contraseña" type="password" placeholder="Contraseña" required><br>
  <button type="submit">Entrar</button>
</form>
<a href="/registro">Registrarse</a>
</body></html>
'''

TEMPLATE_REGISTER = '''
<!DOCTYPE html><html><head><title>Registro</title></head><body>
<h2>Registrarse</h2>
<form method="post">
  <input name="usuario" placeholder="Usuario" required><br>
  <input name="contraseña" type="password" placeholder="Contraseña" required><br>
  <button type="submit">Crear cuenta</button>
</form>
<a href="/login">Ya tengo cuenta</a>
</body></html>
'''

TEMPLATE_INDEX = '''
<!DOCTYPE html><html><head><title>Inicio</title></head><body>
<h2>Bienvenido, {{ usuario }}</h2>
<a href="/logout">Cerrar sesión</a>
<h3>Enviar mensaje cifrado</h3>
<form action="/cifrar" method="post">
  <input name="mensaje" placeholder="Mensaje a cifrar" required><br>
  <input name="clave" placeholder="Clave para cifrar" required><br>
  <button type="submit">Cifrar y guardar</button>
</form>
<h3>Mensajes guardados</h3>
<ul>
{% for m in mensajes %}
  <li>
    {{ m.contenido }}
    <form action="/descifrar/{{ m.id }}" method="post" style="display:inline">
      <input name="clave" placeholder="Clave para descifrar" required>
      <button type="submit">Descifrar</button>
    </form>
  </li>
{% endfor %}
</ul>
</body></html>
'''

# INICIALIZACIÓN BASE DE DATOS
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
