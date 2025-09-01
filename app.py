# app.py
# ============================================
#  ENCRIPTADOS 🔒🔓 - Web de Cifrado en 1 archivo
# ============================================

from flask import Flask, request, redirect, make_response, render_template_string, send_file, jsonify
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime, timedelta
import pytz, os, json, io, re, secrets

app = Flask(__name__)

# ------------------ Config -------------------
HISTORIAL_FILE = "historial.txt"        # Se genera en el mismo directorio de app.py
STATS_FILE     = "stats.json"
HIST_PASS      = "dastanxainhoa2025"    # Contraseña para ver/usar historial
AUTOLIMPIEZA_DIAS = 30                  # Auto limpieza del .txt (y vista) cada 30 días
MAX_KEY_LEN    = 100                    # Longitud máxima de clave de cifrado
SAVE_HISTORY_DEFAULT = True             # Por defecto se guarda historial
BLOCK_AFTER_FAILED = 3                  # Bloqueo tras N intentos fallidos en historial
APP_TITLE = "🔒 Encriptados 🔓"

# Temas (bg= fondo, fg= texto). Añadimos varios "molones"
THEMES = {
    "claro":     {"bg": "#ffffff", "fg": "#000000"},
    "oscuro":    {"bg": "#0f1115", "fg": "#e6edf3"},
    "retro":     {"bg": "#1a1a1a", "fg": "#00ffcc"},
    "matrix":    {"bg": "#000000", "fg": "#00ff00"},
    "neon":      {"bg": "#0b0b0b", "fg": "#ff00ff"},
    "pastel":    {"bg": "#fff0f6", "fg": "#413a4f"},
    "cielo":     {"bg": "#e6f7ff", "fg": "#004d66"},
    "bosque":    {"bg": "#0f2d1c", "fg": "#b9f6ca"},
    "hielo":     {"bg": "#eaf6ff", "fg": "#1f3b4d"},
    "fuego":     {"bg": "#2b0b0e", "fg": "#ffb3a7"},
    "profundo":  {"bg": "#0d1117", "fg": "#c9d1d9"},
    "escalera":  {"bg": "linear-gradient(135deg, #222 0%, #2d2d2d 25%, #383838 50%, #434343 75%, #4e4e4e 100%)", "fg": "#ffffff"},
    "galaxia":   {"bg": "linear-gradient(120deg,#1d2b64,#f8cdda)", "fg": "#ffffff"},
    "auto":      None  # Se decide por hora
}

# ------------------ Estado -------------------
if not os.path.exists(STATS_FILE):
    with open(STATS_FILE, "w") as f:
        json.dump({"cifrados": 0, "descifrados": 0, "puntos": 0}, f)

FAILED_ATTEMPTS = {}      # ip -> conteo fallido (sólo para historial)
AUTO_MESSAGES = {}        # id -> {"cipher":..., "key_hint":..., "created_at":...}

# ------------------ Utilidades ---------------
def tz_madrid_now():
    return datetime.now(pytz.timezone("Europe/Madrid"))

def format_madrid(dt=None):
    if dt is None:
        dt = tz_madrid_now()
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def escape_html(text):
    # Escapado simple para evitar inyecciones en HTML renderizado
    return (text.replace("&","&amp;")
                .replace("<","&lt;")
                .replace(">","&gt;"))

def autolimpiar_historial():
    if not os.path.exists(HISTORIAL_FILE):
        return
    limite = tz_madrid_now() - timedelta(days=AUTOLIMPIEZA_DIAS)
    out = []
    with open(HISTORIAL_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                fecha_str = line.split(" | ")[0]
                fecha = datetime.strptime(fecha_str, "%Y-%m-%d %H:%M:%S")
                if fecha >= limite:
                    out.append(line)
            except Exception:
                # Si no parsea, conservamos por seguridad
                out.append(line)
    with open(HISTORIAL_FILE, "w", encoding="utf-8") as f:
        f.writelines(out)

def theme_now():
    h = tz_madrid_now().hour
    if 6 <= h < 12:
        return "cielo"
    elif 12 <= h < 20:
        return "claro"
    else:
        return "oscuro"

def get_theme_values(theme_name):
    if theme_name == "auto" or theme_name not in THEMES:
        theme_name = theme_now()
    t = THEMES.get(theme_name, THEMES["oscuro"])
    return t["bg"], t["fg"], theme_name

def aes_encrypt(plaintext, key):
    if not (1 <= len(key) <= MAX_KEY_LEN):
        raise ValueError("Clave inválida.")
    k = key.encode("utf-8").ljust(32, b"\0")[:32]
    iv = os.urandom(16)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
    # Hacemos más largo el resultado añadiendo un tag aleatorio (no criptográfico) al final
    tag = os.urandom(8)
    return b64encode(iv + ct + tag).decode("utf-8")

def aes_decrypt(ciphertext_b64, key):
    if not (1 <= len(key) <= MAX_KEY_LEN):
        raise ValueError("Clave inválida.")
    raw = b64decode(ciphertext_b64)
    iv, payload = raw[:16], raw[16:]
    # quitar tag extra
    ct = payload[:-8] if len(payload) > 8 else payload
    k = key.encode("utf-8").ljust(32, b"\0")[:32]
    cipher = AES.new(k, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size).decode("utf-8")
    return pt

def add_stats(kind):
    with open(STATS_FILE, "r+", encoding="utf-8") as f:
        data = json.load(f)
        if kind in ("cifrados","descifrados"):
            data[kind] += 1
            data["puntos"] += 5 if kind == "cifrados" else 3
        f.seek(0); json.dump(data, f); f.truncate()

def append_history(ip, action, in_text, out_text):
    # No guardar claves de cifrado/descifrado. Sólo acción, hora, IP y tamaños/muestras.
    if not SAVE_HISTORY_DEFAULT:
        return
    line = (f"{format_madrid()} | IP:{ip} | {action} | "
            f"len_in:{len(in_text)} | len_out:{len(out_text)} | "
            f"sample_in:{escape_html(in_text[:60])} | sample_out:{escape_html(out_text[:60])}\n")
    with open(HISTORIAL_FILE, "a", encoding="utf-8") as f:
        f.write(line)

def is_blocked(ip):
    return FAILED_ATTEMPTS.get(ip, 0) >= BLOCK_AFTER_FAILED

# --------------- Seguridad (cabeceras) ---------------
@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return resp

# ---------------- Templates (inline) -----------------
BASE_PAGE = """
<!doctype html>
<html lang="es"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{title}}</title>
<style>
:root{
  --bg: {{bg}};
  --fg: {{fg}};
  --card: rgba(255,255,255,0.06);
  --muted: rgba(255,255,255,0.6);
  --accent: #6ee7ff;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,"Helvetica Neue",Arial}
.wrapper{max-width:900px;margin:0 auto;padding:20px}
.header{display:flex;flex-wrap:wrap;gap:8px;align-items:center;justify-content:space-between;margin-bottom:16px}
.title{font-size:clamp(1.2rem,3vw,1.6rem);font-weight:700}
.card{background:var(--card);backdrop-filter:blur(6px);border:1px solid rgba(255,255,255,0.08);border-radius:14px;padding:16px;margin-bottom:16px}
.row{display:flex;gap:10px;flex-wrap:wrap}
.row > *{flex:1 1 260px}
textarea,input,select,button{width:100%;padding:12px;border-radius:10px;border:1px solid rgba(255,255,255,0.14);background:rgba(0,0,0,0.08);color:var(--fg);font-size:16px}
textarea{min-height:130px;resize:vertical}
button{cursor:pointer}
.badge{display:inline-block;padding:6px 10px;border-radius:999px;border:1px solid rgba(255,255,255,0.15);font-size:13px}
.kbd{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;border:1px solid rgba(255,255,255,0.2);padding:2px 6px;border-radius:6px}
.muted{color:var(--muted);font-size:14px}
.footer{opacity:.8;font-size:13px;text-align:center;margin-top:14px}
.copy-btn{white-space:nowrap}
@media (max-width:640px){
  .row{flex-direction:column}
}
</style>
</head>
<body>
<div class="wrapper">
  <div class="header">
    <div class="title">{{app_title}}</div>
    <form method="post" action="/tema" class="row" style="gap:8px;align-items:center;max-width:460px">
      <select name="tema">
        {{theme_options}}
      </select>
      <button type="submit">Tema</button>
      <button type="button" onclick="toggleSave()">{{save_label}}</button>
    </form>
  </div>

  <div class="card">
    <form method="post" action="/" id="form-main">
      <div class="row">
        <textarea name="mensaje" placeholder="Escribe tu mensaje...">{{mensaje}}</textarea>
        <div>
          <input type="password" name="clave" placeholder="Clave (1-{{maxk}} caracteres)">
          <div class="row">
            <button name="accion" value="cifrar">Cifrar</button>
            <button name="accion" value="descifrar">Descifrar</button>
          </div>
          <label style="display:flex;gap:8px;align-items:center;margin-top:8px">
            <input type="checkbox" name="autodestruir" {{autodestruir_checked}} style="width:auto">
            Mensaje de un solo uso (link privado)
          </label>
        </div>
      </div>
    </form>
  </div>

  <div class="card">
    <label>Resultado</label>
    <div class="row">
      <textarea id="resultado" readonly>{{resultado}}</textarea>
      <button class="copy-btn" onclick="copyRes()">Copiar</button>
    </div>
    <div class="muted">Consejo: pulsa <span class="kbd">Click</span> para copiar 👆</div>
  </div>

  <div class="row">
    <form action="/historial" method="get" class="card"><button>Historial 🔐</button></form>
    <form action="/estadisticas" method="get" class="card"><button>Estadísticas 📊</button></form>
    <form action="/ayuda" method="get" class="card"><button>Ayuda 💡</button></form>
  </div>

  <div class="footer">Hecho con ❤️ — Zona horaria: Madrid ({{now}})</div>
</div>

<script>
function copyRes(){
  const t = document.getElementById('resultado');
  t.select(); t.setSelectionRange(0, 99999);
  navigator.clipboard.writeText(t.value);
  alert('Copiado al portapapeles ✅');
}
function toggleSave(){
  fetch('/toggle_save', {method:'POST'}).then(()=>location.reload());
}
</script>
</body></html>
"""

HIST_PAGE_LOCKED = """
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Historial</title>
<style>
body{margin:0;background:#0f1115;color:#e6edf3;font-family:system-ui;display:flex;min-height:100vh;align-items:center;justify-content:center}
.card{width:min(720px,92vw);background:#151a22;border:1px solid #223; border-radius:14px;padding:18px}
input,button{width:100%;padding:12px;border-radius:10px;border:1px solid #334;background:#0b0f14;color:#e6edf3}
.muted{opacity:.8;font-size:13px;margin-top:10px}
</style></head><body>
<div class="card">
  <h2>🔐 Historial (protegido)</h2>
  <form method="post" action="/historial">
    <input type="password" name="pass" placeholder="Contraseña">
    <button type="submit">Entrar</button>
  </form>
  <div class="muted">Bloqueo tras varios intentos fallidos.</div>
  <form method="get" action="/"><button type="submit" style="margin-top:10px">Volver</button></form>
</div></body></html>
"""

HIST_PAGE = """
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Historial</title>
<style>
body{margin:0;background:#0f1115;color:#e6edf3;font-family:system-ui}
.wrapper{max-width:1000px;margin:0 auto;padding:16px}
.card{background:#151a22;border:1px solid #223;border-radius:14px;padding:14px;margin-bottom:12px}
textarea,input,select,button{width:100%;padding:10px;border-radius:10px;border:1px solid #334;background:#0b0f14;color:#e6edf3}
textarea{min-height:300px}
.row{display:flex;gap:10px;flex-wrap:wrap}
.row>*{flex:1 1 240px}
.muted{opacity:.8;font-size:13px}
</style></head><body>
<div class="wrapper">
  <div class="card">
    <h2>Historial</h2>
    <div class="row">
      <input type="date" id="f_fecha">
      <input type="text" id="f_accion" placeholder="Acción (Cifrado/Descifrado)">
      <input type="text" id="f_ip" placeholder="Filtrar por IP">
      <input type="text" id="f_palabra" placeholder="Palabra clave (muestra)">
      <button onclick="buscar()">Buscar</button>
      <form method="get" action="/descargar_historial"><button type="submit">Descargar .txt</button></form>
    </div>
  </div>
  <div class="card">
    <textarea id="out" readonly>{{contenido}}</textarea>
  </div>
  <form method="get" action="/"><button>Volver</button></form>
</div>
<script>
function buscar(){
  const q = new URLSearchParams({
    fecha: document.getElementById('f_fecha').value || '',
    accion: document.getElementById('f_accion').value || '',
    ip: document.getElementById('f_ip').value || '',
    palabra: document.getElementById('f_palabra').value || '',
  });
  fetch('/buscar?'+q.toString()).then(r=>r.json()).then(data=>{
    document.getElementById('out').value = data.join('\\n');
  });
}
</script>
</body></html>
"""

STATS_PAGE = """
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Estadísticas</title>
<style>
body{margin:0;background:#0f1115;color:#e6edf3;font-family:system-ui}
.wrapper{max-width:800px;margin:0 auto;padding:16px}
.card{background:#151a22;border:1px solid #223;border-radius:14px;padding:14px;margin-bottom:12px}
.metric{display:flex;justify-content:space-between;margin:8px 0;padding:10px;border:1px solid #233;border-radius:10px}
</style></head><body>
<div class="wrapper">
  <div class="card"><h2>📊 Estadísticas</h2>
    <div class="metric"><strong>Cifrados</strong><span>{{c}}</span></div>
    <div class="metric"><strong>Descifrados</strong><span>{{d}}</span></div>
    <div class="metric"><strong>Puntos</strong><span>{{p}}</span></div>
  </div>
  <form method="get" action="/"><button>Volver</button></form>
</div></body></html>
"""

HELP_PAGE = """
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ayuda</title>
<style>
body{margin:0;background:#0f1115;color:#e6edf3;font-family:system-ui}
.wrapper{max-width:800px;margin:0 auto;padding:16px}
.card{background:#151a22;border:1px solid #223;border-radius:14px;padding:14px;margin-bottom:12px}
</style></head><body>
<div class="wrapper">
  <div class="card"><h2>Ayuda 💡</h2>
  <p>• Cifra y descifra con AES-CBC. La clave no se guarda en ningún sitio (solo se registran muestras del texto y longitudes si el historial está activo).</p>
  <p>• El historial está protegido por contraseña: <code>{{hist_pass}}</code>. Tras 3 intentos fallidos, se bloquea por IP hasta reiniciar.</p>
  <p>• Auto-tema por hora si eliges el tema <b>auto</b>.</p>
  <p>• Los mensajes de un solo uso generan un enlace único; al abrirlo se destruyen.</p>
  <p>• Autolimpieza del historial: {{days}} días.</p>
  </div>
  <form method="get" action="/"><button>Volver</button></form>
</div></body></html>
"""

# ------------------- Rutas --------------------
@app.route("/", methods=["GET","POST"])
def index():
    autolimpiar_historial()

    tema_cookie = request.cookies.get("tema","auto")
    bg, fg, tema_name = get_theme_values(tema_cookie)
    mensaje = ""
    resultado = ""
    ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
    save_label = "Guardar historial: ON" if SAVE_HISTORY_DEFAULT else "Guardar historial: OFF"

    if request.method == "POST":
        texto = request.form.get("mensaje","")
        clave = request.form.get("clave","")
        accion = request.form.get("accion","")
        autodestruir = request.form.get("autodestruir") == "on"
        mensaje = texto

        try:
            if not texto or not clave:
                resultado = "⚠️ Introduce mensaje y clave."
            elif accion == "cifrar":
                resultado = aes_encrypt(texto, clave)
                add_stats("cifrados")
                append_history(ip, "Cifrado", texto, resultado)
                if autodestruir:
                    # Genera enlace de un solo uso
                    uid = secrets.token_urlsafe(8)
                    AUTO_MESSAGES[uid] = {
                        "cipher": resultado,
                        "created_at": format_madrid()
                    }
                    resultado += f"\n\n🔗 Enlace de un solo uso: {request.host_url.rstrip('/')}/uno/{uid}"
            elif accion == "descifrar":
                resultado = aes_decrypt(texto, clave)
                add_stats("descifrados")
                append_history(ip, "Descifrado", texto, resultado)
            else:
                resultado = "Acción no válida."
        except Exception as e:
            resultado = f"❌ Error al procesar: {escape_html(str(e))}"

    theme_options = "\n".join(
        [f"<option value='{k}' {'selected' if k==tema_name or (tema_cookie=='auto' and k==tema_name) else ''}>{k.title()}</option>" 
         for k in THEMES.keys()]
    )

    html = render_template_string(
        BASE_PAGE,
        title=APP_TITLE,
        app_title=APP_TITLE,
        bg=bg, fg=fg,
        mensaje=escape_html(mensaje),
        resultado=escape_html(resultado),
        theme_options=theme_options,
        save_label=save_label,
        maxk=MAX_KEY_LEN,
        autodestruir_checked="checked" if False else "",
        now=format_madrid()
    )
    resp = make_response(html)
    return resp

@app.route("/tema", methods=["POST"])
def set_tema():
    tema = request.form.get("tema","auto")
    resp = make_response(redirect("/"))
    resp.set_cookie("tema", tema, httponly=True, samesite="Lax")
    return resp

@app.route("/toggle_save", methods=["POST"])
def toggle_save():
    global SAVE_HISTORY_DEFAULT
    SAVE_HISTORY_DEFAULT = not SAVE_HISTORY_DEFAULT
    return ("",204)

# ----- Mensajes de un solo uso -----
@app.route("/uno/<uid>", methods=["GET"])
def one_time(uid):
    data = AUTO_MESSAGES.pop(uid, None)
    if not data:
        return "<pre>❌ Mensaje no existe o ya fue leído.</pre><a href='/'>Volver</a>"
    ct = data["cipher"]
    return f"""<html><body style="font-family:system-ui;padding:14px">
    <h3>Mensaje autodestructivo (solo lectura)</h3>
    <textarea style="width:100%;min-height:200px">{escape_html(ct)}</textarea>
    <p>⚠️ Al recargar, este enlace dejará de funcionar.</p>
    <a href="/">Volver</a></body></html>"""

# ----- Historial protegido -----
@app.route("/historial", methods=["GET","POST"])
def historial():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
    if request.method == "GET":
        if is_blocked(ip):
            return render_template_string(HIST_PAGE_LOCKED)
        return render_template_string(HIST_PAGE_LOCKED)

    # POST: intenta entrar
    if is_blocked(ip):
        return render_template_string(HIST_PAGE_LOCKED)

    pwd = request.form.get("pass","")
    if pwd != HIST_PASS:
        FAILED_ATTEMPTS[ip] = FAILED_ATTEMPTS.get(ip,0) + 1
        return render_template_string(HIST_PAGE_LOCKED)

    # Resetea intentos al acertar
    FAILED_ATTEMPTS[ip] = 0
    autolimpiar_historial()
    try:
        with open(HISTORIAL_FILE, "r", encoding="utf-8") as f:
            contenido = f.read()
    except:
        contenido = "No hay historial.\n"
    return render_template_string(HIST_PAGE, contenido=contenido)

# ----- Búsqueda avanzada en historial (JSON) -----
@app.route("/buscar", methods=["GET"])
def buscar():
    fecha = request.args.get("fecha","").strip()
    accion = request.args.get("accion","").strip().lower()
    ip = request.args.get("ip","").strip()
    palabra = request.args.get("palabra","").strip().lower()
    out = []
    try:
        with open(HISTORIAL_FILE,"r",encoding="utf-8") as f:
            for line in f:
                ok = True
                if fecha and fecha not in line:
                    ok = False
                if accion and accion not in line.lower():
                    ok = False
                if ip and f"IP:{ip}" not in line:
                    ok = False
                if palabra and palabra not in line.lower():
                    ok = False
                if ok:
                    out.append(line.rstrip("\n"))
    except:
        out = ["(sin historial)"]
    return jsonify(out)

# ----- Descargar historial -----
@app.route("/descargar_historial", methods=["GET"])
def descargar_historial():
    if not os.path.exists(HISTORIAL_FILE):
        return "No hay historial para descargar."
    with open(HISTORIAL_FILE,"rb") as f:
        data = f.read()
    return send_file(io.BytesIO(data), as_attachment=True, download_name="historial.txt", mimetype="text/plain")

# ----- Estadísticas (sin contraseña) -----
@app.route("/estadisticas", methods=["GET"])
def stats():
    try:
        with open(STATS_FILE,"r",encoding="utf-8") as f:
            d = json.load(f)
    except:
        d = {"cifrados":0,"descifrados":0,"puntos":0}
    return render_template_string(STATS_PAGE, c=d.get("cifrados",0), d=d.get("descifrados",0), p=d.get("puntos",0))

# ----- Ayuda -----
@app.route("/ayuda", methods=["GET"])
def ayuda():
    return render_template_string(HELP_PAGE, hist_pass=HIST_PASS, days=AUTOLIMPIEZA_DIAS)

# --------------- Arranque ---------------
if __name__ == "__main__":
    # Puertos para Render/Heroku: respeta PORT si existe
    port = int(os.environ.get("PORT", "10000"))
    print(f"🚀 {APP_TITLE} en http://0.0.0.0:{port}")
    # Flask dev server (para producción usa gunicorn/uwsgi detrás de proxy HTTPS)
    app.run(host="0.0.0.0", port=port)
