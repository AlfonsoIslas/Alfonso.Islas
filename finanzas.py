import re # <-- Para validar patrones de contraseña
import sqlite3
import csv
import io
from datetime import date
from flask import Flask, render_template, request, redirect, url_for, flash, Response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import jsonify
app = Flask(__name__)
app.secret_key = 'mi_clave_secreta_super_segura'

# --- CONFIGURACIÓN DE FLASK-LOGIN ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # A dónde te manda si intentas entrar sin permiso

# Clase de usuario para Flask-Login
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

@login_manager.user_loader
def load_user(user_id):
    conn = conectar_db()
    u = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if u:
        return User(u['id'], u['username'], u['password_hash'])
    return None

# --- BASE DE DATOS ---
def conectar_db():
    conn = sqlite3.connect('finanzas.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = conectar_db()
    # TABLA DE USUARIOS
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    # MOVIMIENTOS (Ahora con user_id)
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
    # PRESUPUESTOS (Ahora con user_id y clave compuesta)
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

# --- RUTAS DE AUTENTICACIÓN ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # --- VALIDACIÓN DE SEGURIDAD ---
        if len(password) < 8:
            flash('⚠️ La contraseña es muy corta. Mínimo 8 caracteres.', 'error')
            return redirect(url_for('register'))
        if not re.search(r"[A-Z]", password):
            flash('⚠️ La contraseña necesita al menos una letra MAYÚSCULA.', 'error')
            return redirect(url_for('register'))
        if not re.search(r"\d", password):
            flash('⚠️ La contraseña necesita al menos un NÚMERO.', 'error')
            return redirect(url_for('register'))
        # -------------------------------

        conn = conectar_db()
        try:
            hashed_pw = generate_password_hash(password)
            conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, hashed_pw))
            conn.commit()
            flash('¡Cuenta creada con éxito! Ahora inicia sesión.', 'exito')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Ese nombre de usuario ya está ocupado.', 'error')
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
        # Verificamos si el usuario existe Y si la contraseña coincide con el hash
        if user_db and check_password_hash(user_db['password_hash'], password):
            user = User(user_db['id'], user_db['username'], user_db['password_hash'])
            login_user(user)
            return redirect(url_for('inicio'))
        else:
            flash('Usuario o contraseña incorrectos.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión.', 'exito')
    return redirect(url_for('login'))

# --- RUTAS PRINCIPALES (PROTEGIDAS) ---

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
        query = 'SELECT * FROM movimientos WHERE user_id = ? AND strftime("%Y-%m", fecha) = ? ORDER BY fecha DESC, id DESC'
        movimientos = conn.execute(query, (current_user.id, mes_seleccionado)).fetchall()
        titulo_periodo = f"({mes_seleccionado})"
    else:
        query = 'SELECT * FROM movimientos WHERE user_id = ? ORDER BY fecha DESC, id DESC'
        movimientos = conn.execute(query, (current_user.id,)).fetchall()
        titulo_periodo = "(Histórico Total)"

    total_ingresos = sum(m['monto'] for m in movimientos if m['tipo'] == 'ingreso')
    total_gastos = sum(m['monto'] for m in movimientos if m['tipo'] == 'gasto')
    balance_actual = total_ingresos - total_gastos

    # Datos para el gráfico de DONA (Categorías)
    gastos_por_cat_grafico = {}
    for mov in movimientos:
        if mov['tipo'] == 'gasto':
            gastos_por_cat_grafico[mov['categoria']] = gastos_por_cat_grafico.get(mov['categoria'], 0) + mov['monto']

    # --- NUEVA LÓGICA TENDENCIA (DÍA A DÍA) ---
    trend_data = {}
    for mov in movimientos:
        fecha = mov['fecha']
        if fecha not in trend_data: trend_data[fecha] = {'ingreso': 0, 'gasto': 0}
        trend_data[fecha][mov['tipo']] += mov['monto']

    # Ordenamos fechas de antigua a reciente para que la línea de tiempo tenga sentido
    sorted_dates = sorted(trend_data.keys())
    trend_labels = sorted_dates
    trend_ingresos = [trend_data[d]['ingreso'] for d in sorted_dates]
    trend_gastos = [trend_data[d]['gasto'] for d in sorted_dates]
    # -----------------------------------------

    presupuestos_db = conn.execute('SELECT * FROM presupuestos WHERE user_id = ?', (current_user.id,)).fetchall()
    limites = {row['categoria']: row['monto_limite'] for row in presupuestos_db}
    mes_actual_hoy = date.today().strftime('%Y-%m')
    gastos_mes_actual_db = conn.execute('SELECT categoria, SUM(monto) as total FROM movimientos WHERE user_id = ? AND tipo="gasto" AND strftime("%Y-%m", fecha) = ? GROUP BY categoria', (current_user.id, mes_actual_hoy)).fetchall()
    gastos_actuales = {row['categoria']: row['total'] for row in gastos_mes_actual_db}
    estado_presupuestos = []
    for cat in ['Vivienda', 'Alimentación', 'Transporte', 'Servicios', 'Ocio', 'Salud', 'Otros']:
        if cat in limites:
            limite = limites[cat]
            gastado = gastos_actuales.get(cat, 0)
            estado_presupuestos.append({'categoria': cat, 'gastado': gastado, 'limite': limite, 'porcentaje': min((gastado/limite*100) if limite > 0 else 0, 100), 'excedido': gastado > limite})

    conn.close()
    
    # Enviamos los nuevos datos (trend_*) a la plantilla
    return render_template('index.html', username=current_user.username, balance=balance_actual, ingresos=total_ingresos, gastos=total_gastos, lista_movimientos=movimientos, fecha_hoy=date.today().isoformat(), mes_seleccionado=mes_seleccionado, titulo_periodo=titulo_periodo, categorias_labels=list(gastos_por_cat_grafico.keys()), categorias_data=list(gastos_por_cat_grafico.values()), estado_presupuestos=estado_presupuestos,
                           trend_labels=trend_labels, trend_ingresos=trend_ingresos, trend_gastos=trend_gastos)
@app.route('/guardar_presupuesto', methods=['POST'])
@login_required
def guardar_presupuesto():
    conn = conectar_db()
    # REPLACE ahora usa la clave compuesta (user_id, categoria)
    conn.execute('REPLACE INTO presupuestos (user_id, categoria, monto_limite) VALUES (?, ?, ?)', 
                 (current_user.id, request.form['categoria_presupuesto'], float(request.form['monto_limite'])))
    conn.commit()
    conn.close()
    flash(f'Presupuesto actualizado.', 'exito')
    return redirect(url_for('inicio'))

@app.route('/editar/<int:id_movimiento>', methods=['GET', 'POST'])
@login_required
def editar(id_movimiento):
    conn = conectar_db()
    # IMPORTANTE: Asegurarnos de que el movimiento pertenece al usuario actual
    movimiento = conn.execute('SELECT * FROM movimientos WHERE id = ? AND user_id = ?', (id_movimiento, current_user.id)).fetchone()
    
    if not movimiento:
        conn.close()
        flash('No tienes permiso para editar esto.', 'error')
        return redirect(url_for('inicio'))

    if request.method == 'POST':
        conn.execute('UPDATE movimientos SET fecha=?, tipo=?, categoria=?, monto=?, descripcion=? WHERE id=? AND user_id=?',
                     (request.form['fecha'], request.form['tipo'], request.form['categoria'], float(request.form['monto']), request.form['descripcion'], id_movimiento, current_user.id))
        conn.commit()
        conn.close()
        flash('Movimiento actualizado.', 'exito')
        return redirect(url_for('inicio'))
    
    conn.close()
    return render_template('editar.html', movimiento=movimiento)

@app.route('/eliminar/<int:id_movimiento>', methods=['POST']) # Cambiamos a POST por seguridad
@login_required
def eliminar(id_movimiento):
    conn = conectar_db()
    cursor = conn.execute('DELETE FROM movimientos WHERE id = ? AND user_id = ?', (id_movimiento, current_user.id))
    conn.commit()
    filas_borradas = cursor.rowcount
    conn.close()

    if filas_borradas > 0:
        # Si la petición pide JSON (viene de JS), respondemos con JSON
        if request.is_json or 'application/json' in request.headers.get('Accept', ''):
            return jsonify({'success': True, 'message': 'Movimiento eliminado correctamente'})
        # Si no, comportamiento normal (redirección con flash)
        flash('Movimiento eliminado.', 'borrado')
    else:
        if request.is_json or 'application/json' in request.headers.get('Accept', ''):
             return jsonify({'success': False, 'message': 'No se pudo eliminar'}), 404
        flash('Error al eliminar.', 'error')

    return redirect(url_for('inicio'))

@app.route('/exportar')
@login_required
def exportar():
    conn = conectar_db()
    # Solo exportamos los datos del usuario actual
    movimientos = conn.execute('SELECT * FROM movimientos WHERE user_id = ? ORDER BY fecha DESC, id DESC', (current_user.id,)).fetchall()
    conn.close()
    output = io.StringIO()
    output.write('\ufeff')
    writer = csv.writer(output)
    writer.writerow(['Fecha', 'Tipo', 'Categoría', 'Monto', 'Descripción'])
    for mov in movimientos:
        writer.writerow([mov['fecha'], mov['tipo'], mov['categoria'], mov['monto'], mov['descripcion']])
    output.seek(0)
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=mis_finanzas.csv"})

if __name__ == '__main__':
    app.run(debug=True)