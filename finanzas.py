import sqlite3
import csv
import io
import re
from datetime import date
from flask import Flask, render_template, request, redirect, url_for, flash, Response, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

app = Flask(__name__)
app.secret_key = 'mi_clave_secreta_super_segura'

# --- CONFIGURACIÓN DEL CORREO ---
# Reemplaza con tus datos REALES si aún no lo has hecho
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'foffy202020@gmail.com'
app.config['MAIL_PASSWORD'] = 'dhpcmbmqvklupkfv'

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
    # Tabla de usuarios AHORA CON EMAIL
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS movimientos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            fecha TEXT NOT NULL,
            tipo TEXT NOT NULL,
            categoria TEXT NOT NULL,
            monto REAL NOT NULL,
            descripcion TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS presupuestos (
            user_id INTEGER NOT NULL,
            categoria TEXT NOT NULL,
            monto_limite REAL NOT NULL,
            PRIMARY KEY (user_id, categoria),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# --- RUTAS DE AUTENTICACIÓN Y RECUPERACIÓN ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if len(password) < 8 or not re.search(r"[A-Z]", password) or not re.search(r"\d", password):
             flash('La contraseña no es segura (mín. 8 caracteres, 1 mayúscula, 1 número).', 'error')
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

# --- NUEVAS RUTAS PARA RECUPERAR CONTRASEÑA ---
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
            msg = Message('Recuperar Contraseña - FinWise', sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f'Para cambiar tu contraseña, haz clic aquí: {link}\nEl enlace expira en 1 hora.'
            try:
                mail.send(msg)
                flash('Correo de recuperación enviado. Revisa tu bandeja.', 'exito')
                return redirect(url_for('login'))
            except Exception as e:
                flash(f'Error al enviar correo: {e}', 'error')
        else:
            flash('Este correo no está registrado.', 'error')
    return render_template('reset_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    try:
        email = s.loads(token, salt='email-recover', max_age=3600)
    except (SignatureExpired, Exception):
        flash('El enlace es inválido o ha expirado.', 'error')
        return redirect(url_for('reset_request'))

    if request.method == 'POST':
        password = request.form['password']
        if len(password) < 8: # (Puedes añadir más validaciones aquí si quieres)
             flash('Contraseña muy corta.', 'error')
             return redirect(request.url)
             
        conn = conectar_db()
        hashed_pw = generate_password_hash(password)
        conn.execute('UPDATE users SET password_hash = ? WHERE email = ?', (hashed_pw, email))
        conn.commit()
        conn.close()
        flash('¡Contraseña actualizada! Inicia sesión.', 'exito')
        return redirect(url_for('login'))
    return render_template('reset_token.html', token=token)

# --- RUTAS PRINCIPALES (INICIO, GUARDAR, EDITAR, ELIMINAR, EXPORTAR) ---
# (Estas no cambian, pero las incluyo para que el archivo esté completo y funcional)

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
    if mes_seleccionado:
        movimientos = conn.execute('SELECT * FROM movimientos WHERE user_id = ? AND strftime("%Y-%m", fecha) = ? ORDER BY fecha DESC, id DESC', (current_user.id, mes_seleccionado)).fetchall()
        titulo_periodo = f"({mes_seleccionado})"
    else:
        movimientos = conn.execute('SELECT * FROM movimientos WHERE user_id = ? ORDER BY fecha DESC, id DESC', (current_user.id,)).fetchall()
        titulo_periodo = "(Histórico Total)"

    total_ingresos = sum(m['monto'] for m in movimientos if m['tipo'] == 'ingreso')
    total_gastos = sum(m['monto'] for m in movimientos if m['tipo'] == 'gasto')
    balance_actual = total_ingresos - total_gastos

    gastos_por_cat_grafico = {}
    trend_data = {}
    for mov in movimientos:
        if mov['tipo'] == 'gasto': gastos_por_cat_grafico[mov['categoria']] = gastos_por_cat_grafico.get(mov['categoria'], 0) + mov['monto']
        fecha = mov['fecha']
        if fecha not in trend_data: trend_data[fecha] = {'ingreso': 0, 'gasto': 0}
        trend_data[fecha][mov['tipo']] += mov['monto']
    sorted_dates = sorted(trend_data.keys())
    trend_labels = sorted_dates
    trend_ingresos = [trend_data[d]['ingreso'] for d in sorted_dates]
    trend_gastos = [trend_data[d]['gasto'] for d in sorted_dates]

    presupuestos_db = conn.execute('SELECT * FROM presupuestos WHERE user_id = ?', (current_user.id,)).fetchall()
    limites = {row['categoria']: row['monto_limite'] for row in presupuestos_db}
    mes_actual_hoy = date.today().strftime('%Y-%m')
    gastos_actuales = {row['categoria']: row['total'] for row in conn.execute('SELECT categoria, SUM(monto) as total FROM movimientos WHERE user_id = ? AND tipo="gasto" AND strftime("%Y-%m", fecha) = ? GROUP BY categoria', (current_user.id, mes_actual_hoy)).fetchall()}
    estado_presupuestos = []
    for cat in ['Vivienda', 'Alimentación', 'Transporte', 'Servicios', 'Ocio', 'Salud', 'Otros']:
        if cat in limites:
            limite, gastado = limites[cat], gastos_actuales.get(cat, 0)
            estado_presupuestos.append({'categoria': cat, 'gastado': gastado, 'limite': limite, 'porcentaje': min((gastado/limite*100) if limite > 0 else 0, 100), 'excedido': gastado > limite})
    conn.close()
    return render_template('index.html', username=current_user.username, balance=balance_actual, ingresos=total_ingresos, gastos=total_gastos, lista_movimientos=movimientos, fecha_hoy=date.today().isoformat(), mes_seleccionado=mes_seleccionado, titulo_periodo=titulo_periodo, categorias_labels=list(gastos_por_cat_grafico.keys()), categorias_data=list(gastos_por_cat_grafico.values()), estado_presupuestos=estado_presupuestos, trend_labels=trend_labels, trend_ingresos=trend_ingresos, trend_gastos=trend_gastos)

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
    movimiento = conn.execute('SELECT * FROM movimientos WHERE id = ? AND user_id = ?', (id_movimiento, current_user.id)).fetchone()
    if not movimiento:
        conn.close()
        return redirect(url_for('inicio'))
    if request.method == 'POST':
        conn.execute('UPDATE movimientos SET fecha=?, tipo=?, categoria=?, monto=?, descripcion=? WHERE id=? AND user_id=?', (request.form['fecha'], request.form['tipo'], request.form['categoria'], float(request.form['monto']), request.form['descripcion'], id_movimiento, current_user.id))
        conn.commit()
        conn.close()
        flash('Movimiento actualizado.', 'exito')
        return redirect(url_for('inicio'))
    conn.close()
    return render_template('editar.html', movimiento=movimiento)

@app.route('/eliminar/<int:id_movimiento>', methods=['POST'])
@login_required
def eliminar(id_movimiento):
    conn = conectar_db()
    cursor = conn.execute('DELETE FROM movimientos WHERE id = ? AND user_id = ?', (id_movimiento, current_user.id))
    conn.commit()
    success = cursor.rowcount > 0
    conn.close()
    if request.is_json or 'application/json' in request.headers.get('Accept', ''): return jsonify({'success': success, 'message': 'Eliminado' if success else 'No encontrado'})
    flash('Movimiento eliminado.' if success else 'Error al eliminar.', 'exito' if success else 'error')
    return redirect(url_for('inicio'))

@app.route('/exportar')
@login_required
def exportar():
    conn = conectar_db()
    movimientos = conn.execute('SELECT * FROM movimientos WHERE user_id = ? ORDER BY fecha DESC, id DESC', (current_user.id,)).fetchall()
    conn.close()
    output = io.StringIO()
    output.write('\ufeff')
    writer = csv.writer(output)
    writer.writerow(['Fecha', 'Tipo', 'Categoría', 'Monto', 'Descripción'])
    for mov in movimientos: writer.writerow([mov['fecha'], mov['tipo'], mov['categoria'], mov['monto'], mov['descripcion']])
    output.seek(0)
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=mis_finanzas.csv"})

if __name__ == '__main__':
    app.run(debug=True)