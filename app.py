# -----------------------------
# IMPORTACIONES Y CONFIGURACIÓN BÁSICA
# -----------------------------
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64, hashlib, os, datetime

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite3"
app.config["SECRET_KEY"] = "clave-ultrasecreta"
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# -----------------------------
# MODELOS DE BASE DE DATOS
# -----------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))

class Amistad(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    amigo_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    emisor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receptor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    mensaje_cifrado = db.Column(db.Text)
    clave = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# -----------------------------
# FLASK-LOGIN: CARGA DE USUARIO
# -----------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -----------------------------
# FUNCIONES DE CIFRADO
# -----------------------------
def generar_clave(clave):
    return hashlib.sha256(clave.encode()).digest()

def rellenar(texto):
    padding_len = 16 - len(texto.encode('utf-8')) % 16
    return texto + chr(padding_len) * padding_len

def quitar_relleno(texto):
    padding_len = ord(texto[-1])
    return texto[:-padding_len]

def encriptar(mensaje, clave):
    clave_bytes = generar_clave(clave)
    iv = get_random_bytes(16)
    cipher = AES.new(clave_bytes, AES.MODE_CBC, iv)
    mensaje_bytes = rellenar(mensaje).encode("utf-8")
    mensaje_cifrado = cipher.encrypt(mensaje_bytes)
    return base64.urlsafe_b64encode(iv + mensaje_cifrado).decode("utf-8")

def desencriptar(mensaje_cifrado, clave):
    clave_bytes = generar_clave(clave)
    datos = base64.urlsafe_b64decode(mensaje_cifrado.encode("utf-8"))
    iv = datos[:16]
    mensaje_bytes = datos[16:]
    cipher = AES.new(clave_bytes, AES.MODE_CBC, iv)
    mensaje_descifrado = cipher.decrypt(mensaje_bytes).decode("utf-8")
    return quitar_relleno(mensaje_descifrado)

# -----------------------------
# RUTAS PARA REGISTRO E INICIO DE SESIÓN
# -----------------------------
@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        nombre = request.form["nombre"]
        email = request.form["email"]
        password = request.form["password"]
        if User.query.filter_by(email=email).first():
            flash("Email ya registrado")
            return redirect("/registro")
        nuevo = User(nombre=nombre, email=email, password=password)
        db.session.add(nuevo)
        db.session.commit()
        flash("Usuario creado")
        return redirect("/login")
    return render_template("registro.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = User.query.filter_by(email=email, password=password).first()
        if user:
            login_user(user)
            return redirect("/")
        else:
            flash("Credenciales incorrectas")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")

# -----------------------------
# RUTA PRINCIPAL: CIFRADO / DESCIFRADO
# -----------------------------
@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    resultado = ""
    if request.method == "POST":
        mensaje = request.form["mensaje"]
        clave = request.form["clave"]
        accion = request.form["accion"]
        if accion == "encriptar":
            resultado = encriptar(mensaje, clave)
        elif accion == "desencriptar":
            try:
                resultado = desencriptar(mensaje, clave)
            except:
                resultado = "Error al descifrar"
    return render_template("index.html", resultado=resultado)

# -----------------------------
# RUTAS DE AMISTADES Y CHAT PRIVADO
# -----------------------------
@app.route("/amigos")
@login_required
def ver_amigos():
    amistades = Amistad.query.filter_by(usuario_id=current_user.id).all()
    amigos = [User.query.get(a.amigo_id) for a in amistades]
    return render_template("amigos.html", amigos=amigos)

@app.route("/agregar_amigo", methods=["POST"])
@login_required
def agregar_amigo():
    email = request.form["email"]
    amigo = User.query.filter_by(email=email).first()
    if amigo and amigo.id != current_user.id:
        ya_son = Amistad.query.filter_by(usuario_id=current_user.id, amigo_id=amigo.id).first()
        if not ya_son:
            db.session.add(Amistad(usuario_id=current_user.id, amigo_id=amigo.id))
            db.session.commit()
            flash("Amigo añadido")
    return redirect("/amigos")

@app.route("/chat_privado/<int:amigo_id>", methods=["GET", "POST"])
@login_required
def chat_privado(amigo_id):
    if request.method == "POST":
        texto = request.form["mensaje"]
        clave = request.form["clave"]
        cifrado = encriptar(texto, clave)
        msg = ChatMessage(emisor_id=current_user.id, receptor_id=amigo_id, mensaje_cifrado=cifrado, clave=clave)
        db.session.add(msg)
        db.session.commit()
    mensajes = ChatMessage.query.filter(
        ((ChatMessage.emisor_id==current_user.id) & (ChatMessage.receptor_id==amigo_id)) |
        ((ChatMessage.emisor_id==amigo_id) & (ChatMessage.receptor_id==current_user.id))
    ).order_by(ChatMessage.timestamp).all()
    return render_template("chat.html", mensajes=mensajes, amigo=User.query.get(amigo_id))

# -----------------------------
# EJECUCIÓN
# -----------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
