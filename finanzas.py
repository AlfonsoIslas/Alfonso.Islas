import os
import csv
import io
import re
from datetime import date
# --- LIBRERÍAS DE FLASK ---
from flask import Flask, render_template, request, redirect, url_for, flash, Response, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager

# --- BLOQUE DE DIAGNÓSTICO INICIO ---
print("**************************************************")
print("INICIANDO DIAGNÓSTICO DE BASE DE DATOS...")
DATABASE_URL = os.environ.get('DATABASE_URL')

if DATABASE_URL:
    # ESTAMOS EN RENDER (O PROD)
    print("🔒 MODO NUBE ACTIVADO: Forzando PostgreSQL")
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        print("✅ 1. Librería 'psycopg2' encontrada.")
        DB_TYPE = 'postgres'
    except ImportError:
        # Si estamos en la nube y falta esto, ¡HAY QUE DETENER TODO!
        print("❌ 1. ERROR CRÍTICO: Librería 'psycopg2' NO encontrada. Revisa requirements.txt")
        raise Exception("🔥 ERROR FATAL: Estás en la nube pero falta 'psycopg2-binary'. La app no puede arrancar de forma segura.")
else:
    # ESTAMOS EN LOCAL
    print("💻 MODO LOCAL ACTIVADO: Usando SQLite")
    import sqlite3
    DB_TYPE = 'sqlite'
print("**************************************************")
# --- BLOQUE DE DIAGNÓSTICO FIN ---

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'mi_clave_secreta_super_segura_local')

# --- CONFIGURACIÓN DEL CORREO ---
app.config['MAIL_SERVER'] = 'smtp-relay.brevo.com'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = ('FinWise App', os.environ.get('MAIL_USERNAME'))
app.config["JWT_SECRET_KEY"] = "mi-super-secreta-llave-para-jwt" 
jwt = JWTManager(app)
mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, email, password_hash):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash

# --- FUNCIÓN DE CONEXIÓN ESTRICTA ---
def get_db_connection():
    if DB_TYPE == 'postgres':
        try:
            # Intenta conectar a Postgres. Si falla, dejará que el error explote
            conn = psycopg2.connect(DATABASE_URL)
            print("✅ 2. Conexión a PostgreSQL exitosa.")
            return conn
        except Exception as e:
            print(f"🔥 ERROR DE CONEXIÓN A POSTGRES: {e}")
            raise e # ¡Esto detendrá la app en lugar de usar una DB temporal!
    else:
        # Modo local seguro
        conn = sqlite3.connect('finanzas.db')
        conn.row_factory = sqlite3.Row
        return conn

# Helper para ejecutar queries independientemente de la DB
def query_db(query, args=(), one=False):
    conn = get_db_connection()
    # Detectamos qué tipo de conexión nos devolvió
    is_postgres = hasattr(conn, 'cursor_factory') or type(conn).__module__.startswith('psycopg2')
    
    if not is_postgres: # Es SQLite
        cur = conn.execute(query, args)
        rv = cur.fetchall()
        conn.commit()
        cur.close()
        conn.close()
        return (rv[0] if rv else None) if one else rv
    else: # Es Postgres
        cur = conn.cursor(cursor_factory=RealDictCursor)
        query_pg = query.replace('?', '%s')
        try:
            cur.execute(query_pg, args)
            conn.commit()
            try:
                rv = cur.fetchall()
            except psycopg2.ProgrammingError:
                rv = []
        except Exception as e:
            conn.rollback()
            print(f"ERROR SQL EN POSTGRES: {e}")
            raise e
        finally:
            cur.close()
            conn.close()
        return (rv[0] if rv else None) if one else rv

@login_manager.user_loader
def load_user(user_id):
    u = query_db('SELECT * FROM users WHERE id = ?', (user_id,), one=True)
    if u: return User(u['id'], u['username'], u['email'], u['password_hash'])
    return None

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    id_type = "SERIAL" if DB_TYPE == 'postgres' else "INTEGER PRIMARY KEY AUTOINCREMENT"
    
    cursor.execute(f'CREATE TABLE IF NOT EXISTS users (id {id_type} PRIMARY KEY, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL)')
    cursor.execute(f'CREATE TABLE IF NOT EXISTS movimientos (id {id_type} PRIMARY KEY, user_id INTEGER NOT NULL, fecha TEXT NOT NULL, tipo TEXT NOT NULL, categoria TEXT NOT NULL, monto REAL NOT NULL, descripcion TEXT NOT NULL)')
    cursor.execute('CREATE TABLE IF NOT EXISTS presupuestos (user_id INTEGER NOT NULL, categoria TEXT NOT NULL, monto_limite REAL NOT NULL, PRIMARY KEY (user_id, categoria))')
    
    conn.commit()
    conn.close()

try:
    init_db()
except Exception as e:
    print(f"Nota sobre DB (puede ser normal si ya existe): {e}")

# --- RUTAS DE AUTENTICACIÓN ---
# --- RUTA DE API PARA LOGIN ---
@app.route('/api/login', methods=['POST'])
def api_login():
    # Las apps envían JSON, no formularios
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    
    conn = get_db_connection()
    user_db = query_db('SELECT * FROM users WHERE username = ?', (username,), one=True)
    conn.close()

    if user_db and check_password_hash(user_db['password_hash'], password):
        # ¡Credenciales correctas! Creamos un token para este usuario
        access_token = create_access_token(identity=user_db['id'])
        return jsonify(success=True, access_token=access_token, username=user_db['username'])
    else:
        # Credenciales incorrectas
        return jsonify({"success": False, "msg": "Usuario o contraseña incorrectos"}), 401
    
# --- RUTA DE API PROTEGIDA ---
@app.route('/api/mis_datos', methods=['GET'])
@jwt_required() # ¡Magia! Esto protege la ruta
def api_mis_datos():
    # Obtenemos la identidad (el user_id) que guardamos en el token
    current_user_id = get_jwt_identity()
    
    conn = get_db_connection()
    user = query_db('SELECT username, email FROM users WHERE id = ?', (current_user_id,), one=True)
    conn.close()
    
    if user:
        return jsonify(success=True, user=user)
    else:
        return jsonify(success=False, msg="Usuario no encontrado"), 404

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if len(password) < 8 or not re.search(r"[A-Z]", password) or not re.search(r"\d", password):
             flash('La contraseña no cumple los requisitos.', 'error')
             return redirect(url_for('register'))
        try:
            hashed_pw = generate_password_hash(password)
            query_db('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', (username, email, hashed_pw))
            flash('¡Cuenta creada! Inicia sesión.', 'exito')
            return redirect(url_for('login'))
        except Exception: 
            flash('Usuario o correo ya registrados.', 'error')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_db = query_db('SELECT * FROM users WHERE username = ?', (request.form['username'],), one=True)
        if user_db and check_password_hash(user_db['password_hash'], request.form['password']):
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
        user = query_db('SELECT * FROM users WHERE email = ?', (email,), one=True)
        if user:
            token = s.dumps(email, salt='email-recover')
            link = url_for('reset_token', token=token, _external=True)
            msg = Message('Recuperar Contraseña - FinWise',sender='foffy202020@gmail.com',  # <-- ¡Forzamos el remitente aquí!
            recipients=[email])
            msg.body = f'Para cambiar tu contraseña, haz clic aquí: {link}\nEl enlace expira en 1 hora.'
            try:
                mail.send(msg)
                flash('Correo enviado. Revisa tu bandeja (y spam).', 'exito')
                return redirect(url_for('login'))
            except Exception as e:
                print(f"ERROR CORREO: {e}")
                flash(f'Error al enviar correo.', 'error')
        else:
            flash('Este correo no está registrado.', 'error')
    return render_template('reset_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    try: email = s.loads(token, salt='email-recover', max_age=3600)
    except:
        flash('Enlace inválido o expirado.', 'error')
        return redirect(url_for('reset_request'))
    if request.method == 'POST':
        password = request.form['password']
        query_db('UPDATE users SET password_hash = ? WHERE email = ?', (generate_password_hash(password), email))
        flash('¡Contraseña actualizada!', 'exito')
        return redirect(url_for('login'))
    return render_template('reset_token.html', token=token)

# --- RUTAS PRINCIPALES ---
@app.route('/', methods=['GET', 'POST'])
@login_required
def inicio():
    if request.method == 'POST':
        query_db('INSERT INTO movimientos (user_id, fecha, tipo, categoria, monto, descripcion) VALUES (?, ?, ?, ?, ?, ?)',
                 (current_user.id, request.form['fecha'], request.form['tipo'], request.form['categoria'], float(request.form['monto']), request.form['descripcion']))
        flash('Movimiento registrado.', 'exito')
        return redirect(url_for('inicio'))
    
    mes = request.args.get('mes')
    query = 'SELECT * FROM movimientos WHERE user_id = ? AND strftime("%Y-%m", fecha) = ? ORDER BY fecha DESC, id DESC' if mes else 'SELECT * FROM movimientos WHERE user_id = ? ORDER BY fecha DESC, id DESC'
    params = (current_user.id, mes) if mes else (current_user.id,)
    movimientos = query_db(query, params) or []
    
    total_ingresos = sum(m['monto'] for m in movimientos if m['tipo'] == 'ingreso')
    total_gastos = sum(m['monto'] for m in movimientos if m['tipo'] == 'gasto')
    
    gastos_cat, trend = {}, {}
    for m in movimientos:
        if m['tipo'] == 'gasto': gastos_cat[m['categoria']] = gastos_cat.get(m['categoria'], 0) + m['monto']
        d = m['fecha']
        if d not in trend: trend[d] = {'ingreso': 0, 'gasto': 0}
        trend[d][m['tipo']] += m['monto']
    
    sorted_dates = sorted(trend.keys())
    
    presupuestos = {row['categoria']: row['monto_limite'] for row in (query_db('SELECT * FROM presupuestos WHERE user_id = ?', (current_user.id,)) or [])}
    mes_actual = date.today().strftime('%Y-%m')
    gastos_mes_db = query_db('SELECT categoria, SUM(monto) as total FROM movimientos WHERE user_id = ? AND tipo=\'gasto\' AND fecha LIKE ? GROUP BY categoria', (current_user.id, f'{mes_actual}%')) or []
    gastos_mes = {row['categoria']: row['total'] for row in gastos_mes_db}
    
    estado_presupuestos = [{'categoria': c, 'gastado': gastos_mes.get(c,0), 'limite': presupuestos[c], 'porcentaje': min((gastos_mes.get(c,0)/presupuestos[c]*100), 100) if presupuestos[c]>0 else 0, 'excedido': gastos_mes.get(c,0)>presupuestos[c]} for c in ['Vivienda', 'Alimentación', 'Transporte', 'Ocio', 'Servicios', 'Salud', 'Otros'] if c in presupuestos]

    return render_template('index.html', username=current_user.username, balance=total_ingresos-total_gastos, ingresos=total_ingresos, gastos=total_gastos, lista_movimientos=movimientos, fecha_hoy=date.today().isoformat(), mes_seleccionado=mes, titulo_periodo=f"({mes})" if mes else "(Histórico)", categorias_labels=list(gastos_cat.keys()), categorias_data=list(gastos_cat.values()), estado_presupuestos=estado_presupuestos, trend_labels=sorted_dates, trend_ingresos=[trend[d]['ingreso'] for d in sorted_dates], trend_gastos=[trend[d]['gasto'] for d in sorted_dates])

@app.route('/guardar_presupuesto', methods=['POST'])
@login_required
def guardar_presupuesto():
    if DB_TYPE == 'postgres':
        query_db('INSERT INTO presupuestos (user_id, categoria, monto_limite) VALUES (%s, %s, %s) ON CONFLICT (user_id, categoria) DO UPDATE SET monto_limite = EXCLUDED.monto_limite',
                 (current_user.id, request.form['categoria_presupuesto'], float(request.form['monto_limite'])))
    else:
        query_db('REPLACE INTO presupuestos (user_id, categoria, monto_limite) VALUES (?, ?, ?)',
                 (current_user.id, request.form['categoria_presupuesto'], float(request.form['monto_limite'])))
    flash('Presupuesto actualizado.', 'exito')
    return redirect(url_for('inicio'))

@app.route('/editar/<int:id_movimiento>', methods=['GET', 'POST'])
@login_required
def editar(id_movimiento):
    mov = query_db('SELECT * FROM movimientos WHERE id = ? AND user_id = ?', (id_movimiento, current_user.id), one=True)
    if not mov: return redirect(url_for('inicio'))
    if request.method == 'POST':
        query_db('UPDATE movimientos SET fecha=?, tipo=?, categoria=?, monto=?, descripcion=? WHERE id=? AND user_id=?', (request.form['fecha'], request.form['tipo'], request.form['categoria'], float(request.form['monto']), request.form['descripcion'], id_movimiento, current_user.id))
        flash('Movimiento actualizado.', 'exito')
        return redirect(url_for('inicio'))
    return render_template('editar.html', movimiento=mov)

@app.route('/eliminar/<int:id_movimiento>', methods=['POST'])
@login_required
def eliminar(id_movimiento):
    query_db('DELETE FROM movimientos WHERE id = ? AND user_id = ?', (id_movimiento, current_user.id))
    return jsonify({'success': True, 'message': 'Eliminado'})

@app.route('/exportar')
@login_required
def exportar():
    movs = query_db('SELECT * FROM movimientos WHERE user_id = ? ORDER BY fecha DESC, id DESC', (current_user.id,))
    output = io.StringIO()
    output.write('\ufeff')
    writer = csv.writer(output)
    writer.writerow(['Fecha', 'Tipo', 'Categoría', 'Monto', 'Descripción'])
    for m in movs: writer.writerow([m['fecha'], m['tipo'], m['categoria'], m['monto'], m['descripcion']])
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=finanzas.csv"})

# --- RUTA PARA SERVIR EL SERVICE WORKER ---
@app.route('/sw.js')
def sw():
    return app.send_static_file('sw.js')


if __name__ == '__main__':
    app.run(debug=True)