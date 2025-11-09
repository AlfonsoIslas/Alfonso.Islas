import os
import csv
import io
import re
from datetime import date
from flask import Flask, render_template, request, redirect, url_for, flash, Response, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

# --- BLOQUE DE DIAGNÓSTICO INICIO ---
print("**************************************************")
print("INICIANDO DIAGNÓSTICO DE BASE DE DATOS...")
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    print("✅ 1. Librería 'psycopg2' encontrada.")
    HAS_PSYCOPG2 = True
except ImportError:
    print("❌ 1. ERROR CRÍTICO: Librería 'psycopg2' NO encontrada. Revisa requirements.txt")
    HAS_PSYCOPG2 = False

db_url = os.environ.get('DATABASE_URL')
if db_url:
    print(f"✅ 2. Variable DATABASE_URL encontrada (empieza por {db_url[:10]}...)")
else:
    print("❌ 2. ERROR CRÍTICO: Variable DATABASE_URL NO encontrada en el entorno.")

if HAS_PSYCOPG2 and db_url:
    print("🚀 CONCLUSIÓN: Intentaremos usar PostgreSQL.")
    DB_TYPE = 'postgres'
else:
    print("⚠️ CONCLUSIÓN: Faltan ingredientes. Usaremos SQLite temporal (se borrará al reiniciar).")
    DB_TYPE = 'sqlite'
print("**************************************************")
# --- BLOQUE DE DIAGNÓSTICO FIN ---

import sqlite3 # Importamos siempre por si hace falta el fallback

app = Flask(__name__)
app.secret_key = 'mi_clave_secreta_super_segura'

# --- CONFIGURACIÓN DEL CORREO (MODO PRO: BREVO) ---
app.config['MAIL_SERVER'] = 'smtp-relay.brevo.com'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
# REMITENTE GLOBAL: Todos los correos saldrán de aquí automáticamente
app.config['MAIL_DEFAULT_SENDER'] = ('FinWise App', 'foffy202020@gmail.com')

mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)

# --- CONFIGURACIÓN DE LOGIN ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, email, password_hash):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash

@login_manager.user_loader
def load_user(user_id):
    conn = conectar_db()
    u = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if u: return User(u['id'], u['username'], u['email'], u['password_hash'])
    return None

# --- BASE DE DATOS ---
def conectar_db():
    conn = sqlite3.connect('finanzas.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = conectar_db()
    conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL)')
    conn.execute('CREATE TABLE IF NOT EXISTS movimientos (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, fecha TEXT NOT NULL, tipo TEXT NOT NULL, categoria TEXT NOT NULL, monto REAL NOT NULL, descripcion TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id))')
    conn.execute('CREATE TABLE IF NOT EXISTS presupuestos (user_id INTEGER NOT NULL, categoria TEXT NOT NULL, monto_limite REAL NOT NULL, PRIMARY KEY (user_id, categoria), FOREIGN KEY(user_id) REFERENCES users(id))')
    conn.commit()
    conn.close()

init_db()

# --- RUTAS DE AUTENTICACIÓN ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if len(password) < 8 or not re.search(r"[A-Z]", password) or not re.search(r"\d", password):
             flash('La contraseña no cumple los requisitos de seguridad.', 'error')
             return redirect(url_for('register'))
        conn = conectar_db()
        try:
            hashed_pw = generate_password_hash(password)
            conn.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', (username, email, hashed_pw))
            conn.commit()
            flash('¡Cuenta creada! Inicia sesión.', 'exito')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Usuario o correo ya registrados.', 'error')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = conectar_db()
        user_db = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user_db and check_password_hash(user_db['password_hash'], password):
            user = User(user_db['id'], user_db['username'], user_db['email'], user_db['password_hash'])
            login_user(user)
            return redirect(url_for('inicio'))
        else:
            flash('Credenciales incorrectas.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Sesión cerrada.', 'exito')
    return redirect(url_for('login'))

# --- RUTAS DE RECUPERACIÓN ---
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form['email']
        conn = conectar_db()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        if user:
            token = s.dumps(email, salt='email-recover')
            link = url_for('reset_token', token=token, _external=True)
            # ¡MIRA QUÉ LIMPIO! Ya no hace falta especificar 'sender' aquí
            msg = Message('Recuperar Contraseña - FinWise', recipients=[email])
            msg.body = f'Para cambiar tu contraseña, haz clic aquí: {link}\nEl enlace expira en 1 hora.'
            try:
                mail.send(msg)
                flash('Correo enviado. Revisa tu bandeja (y spam).', 'exito')
                return redirect(url_for('login'))
            except Exception as e:
                print(f"ERROR CORREO: {e}") # Para ver en logs de Render si falla
                flash(f'Error al enviar correo.', 'error')
        else:
            flash('Este correo no está registrado.', 'error')
    return render_template('reset_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    try:
        email = s.loads(token, salt='email-recover', max_age=3600)
    except:
        flash('Enlace inválido o expirado.', 'error')
        return redirect(url_for('reset_request'))
    if request.method == 'POST':
        password = request.form['password']
        conn = conectar_db()
        hashed_pw = generate_password_hash(password)
        conn.execute('UPDATE users SET password_hash = ? WHERE email = ?', (hashed_pw, email))
        conn.commit()
        conn.close()
        flash('¡Contraseña actualizada!', 'exito')
        return redirect(url_for('login'))
    return render_template('reset_token.html', token=token)

# --- RUTAS PRINCIPALES ---
@app.route('/', methods=['GET', 'POST'])
@login_required
def inicio():
    conn = conectar_db()
    if request.method == 'POST':
        conn.execute('INSERT INTO movimientos (user_id, fecha, tipo, categoria, monto, descripcion) VALUES (?, ?, ?, ?, ?, ?)',
                     (current_user.id, request.form['fecha'], request.form['tipo'], request.form['categoria'], float(request.form['monto']), request.form['descripcion']))
        conn.commit()
        conn.close()
        flash('Movimiento registrado.', 'exito')
        return redirect(url_for('inicio'))
    mes_seleccionado = request.args.get('mes')
    query = 'SELECT * FROM movimientos WHERE user_id = ? AND strftime("%Y-%m", fecha) = ? ORDER BY fecha DESC, id DESC' if mes_seleccionado else 'SELECT * FROM movimientos WHERE user_id = ? ORDER BY fecha DESC, id DESC'
    params = (current_user.id, mes_seleccionado) if mes_seleccionado else (current_user.id,)
    movimientos = conn.execute(query, params).fetchall()
    titulo_periodo = f"({mes_seleccionado})" if mes_seleccionado else "(Histórico Total)"
    total_ingresos = sum(m['monto'] for m in movimientos if m['tipo'] == 'ingreso')
    total_gastos = sum(m['monto'] for m in movimientos if m['tipo'] == 'gasto')
    
    gastos_cat = {}
    trend = {}
    for m in movimientos:
        if m['tipo'] == 'gasto': gastos_cat[m['categoria']] = gastos_cat.get(m['categoria'], 0) + m['monto']
        d = m['fecha']
        if d not in trend: trend[d] = {'ingreso': 0, 'gasto': 0}
        trend[d][m['tipo']] += m['monto']
    
    sorted_dates = sorted(trend.keys())
    
    presupuestos = {row['categoria']: row['monto_limite'] for row in conn.execute('SELECT * FROM presupuestos WHERE user_id = ?', (current_user.id,)).fetchall()}
    gastos_mes = {row['categoria']: row['total'] for row in conn.execute('SELECT categoria, SUM(monto) as total FROM movimientos WHERE user_id = ? AND tipo="gasto" AND strftime("%Y-%m", fecha) = ? GROUP BY categoria', (current_user.id, date.today().strftime('%Y-%m'))).fetchall()}
    estado_presupuestos = [{'categoria': c, 'gastado': gastos_mes.get(c,0), 'limite': presupuestos[c], 'porcentaje': min((gastos_mes.get(c,0)/presupuestos[c]*100), 100) if presupuestos[c]>0 else 0, 'excedido': gastos_mes.get(c,0)>presupuestos[c]} for c in ['Vivienda', 'Alimentación', 'Transporte', 'Servicios', 'Ocio', 'Salud', 'Otros'] if c in presupuestos]
    conn.close()
    return render_template('index.html', username=current_user.username, balance=total_ingresos-total_gastos, ingresos=total_ingresos, gastos=total_gastos, lista_movimientos=movimientos, fecha_hoy=date.today().isoformat(), mes_seleccionado=mes_seleccionado, titulo_periodo=titulo_periodo, categorias_labels=list(gastos_cat.keys()), categorias_data=list(gastos_cat.values()), estado_presupuestos=estado_presupuestos, trend_labels=sorted_dates, trend_ingresos=[trend[d]['ingreso'] for d in sorted_dates], trend_gastos=[trend[d]['gasto'] for d in sorted_dates])

@app.route('/guardar_presupuesto', methods=['POST'])
@login_required
def guardar_presupuesto():
    conn = conectar_db()
    conn.execute('REPLACE INTO presupuestos (user_id, categoria, monto_limite) VALUES (?, ?, ?)', (current_user.id, request.form['categoria_presupuesto'], float(request.form['monto_limite'])))
    conn.commit()
    conn.close()
    flash('Presupuesto actualizado.', 'exito')
    return redirect(url_for('inicio'))

@app.route('/editar/<int:id_movimiento>', methods=['GET', 'POST'])
@login_required
def editar(id_movimiento):
    conn = conectar_db()
    mov = conn.execute('SELECT * FROM movimientos WHERE id = ? AND user_id = ?', (id_movimiento, current_user.id)).fetchone()
    if not mov:
        conn.close()
        return redirect(url_for('inicio'))
    if request.method == 'POST':
        conn.execute('UPDATE movimientos SET fecha=?, tipo=?, categoria=?, monto=?, descripcion=? WHERE id=?', (request.form['fecha'], request.form['tipo'], request.form['categoria'], float(request.form['monto']), request.form['descripcion'], id_movimiento))
        conn.commit()
        conn.close()
        flash('Movimiento actualizado.', 'exito')
        return redirect(url_for('inicio'))
    conn.close()
    return render_template('editar.html', movimiento=mov)

@app.route('/eliminar/<int:id_movimiento>', methods=['POST'])
@login_required
def eliminar(id_movimiento):
    conn = conectar_db()
    cursor = conn.execute('DELETE FROM movimientos WHERE id = ? AND user_id = ?', (id_movimiento, current_user.id))
    conn.commit()
    success = cursor.rowcount > 0
    conn.close()
    if request.is_json or 'application/json' in request.headers.get('Accept', ''): return jsonify({'success': success, 'message': 'Eliminado' if success else 'Error'})
    flash('Eliminado.' if success else 'Error.', 'exito' if success else 'error')
    return redirect(url_for('inicio'))

@app.route('/exportar')
@login_required
def exportar():
    conn = conectar_db()
    movs = conn.execute('SELECT * FROM movimientos WHERE user_id = ? ORDER BY fecha DESC, id DESC', (current_user.id,)).fetchall()
    conn.close()
    output = io.StringIO()
    output.write('\ufeff')
    writer = csv.writer(output)
    writer.writerow(['Fecha', 'Tipo', 'Categoría', 'Monto', 'Descripción'])
    for m in movs: writer.writerow([m['fecha'], m['tipo'], m['categoria'], m['monto'], m['descripcion']])
    output.seek(0)
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=mis_finanzas.csv"})

if __name__ == '__main__':
    app.run(debug=True)