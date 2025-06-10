from flask import Flask, request, jsonify
import sqlite3
import jwt
import datetime
import time
from functools import wraps
import json

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'angel'  # Cambiar en producción

# Función para inicializar la base de datos
def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    
    # Verificar si la tabla users existe y tiene los nuevos campos
    cursor.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cursor.fetchall()]
    
    if 'email' not in columns or 'role_id' not in columns:
        # Si no existe email o role_id, recrear la tabla
        cursor.execute("DROP TABLE IF EXISTS users")
        cursor.execute("DROP TABLE IF EXISTS roles_permisos")
        cursor.execute("DROP TABLE IF EXISTS roles")
        cursor.execute("DROP TABLE IF EXISTS permisos")
    
    # Crear tabla users
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            nombre_usuario TEXT,
            pregunta_secreta TEXT,
            respuesta_secreta TEXT,
            fecha_nacimiento TEXT,
            role_id INTEGER,
            status INTEGER DEFAULT 1,
            FOREIGN KEY (role_id) REFERENCES roles (id)
        )
    """)
    
    # Crear tabla permisos
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS permisos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT UNIQUE NOT NULL
        )
    """)
    
    # Crear tabla roles
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT UNIQUE NOT NULL
        )
    """)
    
    # Crear tabla intermedia roles_permisos
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS roles_permisos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            role_id INTEGER,
            permiso_id INTEGER,
            FOREIGN KEY (role_id) REFERENCES roles (id),
            FOREIGN KEY (permiso_id) REFERENCES permisos (id),
            UNIQUE(role_id, permiso_id)
        )
    """)
    
    # Insertar permisos básicos
    permisos_basicos = [
        'get_user', 'create_user', 'update_user', 'delete_user',
        'get_product', 'create_product', 'update_product', 'delete_product',
        'get_role', 'create_role', 'update_role', 'delete_role',
        'get_permiso', 'create_permiso', 'update_permiso', 'delete_permiso',
        'admin_data'
    ]
    
    for permiso in permisos_basicos:
        cursor.execute("INSERT OR IGNORE INTO permisos (nombre) VALUES (?)", (permiso,))
    
    # Insertar roles básicos
    cursor.execute("INSERT OR IGNORE INTO roles (nombre) VALUES ('admin')")
    cursor.execute("INSERT OR IGNORE INTO roles (nombre) VALUES ('common_user')")
    cursor.execute("INSERT OR IGNORE INTO roles (nombre) VALUES ('seller')")
    
    # Asignar todos los permisos al admin
    cursor.execute("SELECT id FROM roles WHERE nombre = 'admin'")
    admin_role_id = cursor.fetchone()[0]
    
    cursor.execute("SELECT id FROM permisos")
    permisos_ids = cursor.fetchall()
    
    for permiso_id in permisos_ids:
        cursor.execute("INSERT OR IGNORE INTO roles_permisos (role_id, permiso_id) VALUES (?, ?)", 
                      (admin_role_id, permiso_id[0]))
    
    # Asignar algunos permisos a common_user
    cursor.execute("SELECT id FROM roles WHERE nombre = 'common_user'")
    common_role_id = cursor.fetchone()[0]
    
    permisos_common = ['get_user', 'get_product']
    for permiso_nombre in permisos_common:
        cursor.execute("SELECT id FROM permisos WHERE nombre = ?", (permiso_nombre,))
        permiso_id = cursor.fetchone()[0]
        cursor.execute("INSERT OR IGNORE INTO roles_permisos (role_id, permiso_id) VALUES (?, ?)", 
                      (common_role_id, permiso_id))
    
    # Insertar usuarios de prueba con roles
    cursor.execute("INSERT OR IGNORE INTO users (username, password, email, nombre_usuario, role_id, status) VALUES ('admin', '1234', 'admin@test.com', 'Administrador', ?, 1)", (admin_role_id,))
    cursor.execute("INSERT OR IGNORE INTO users (username, password, email, nombre_usuario, role_id, status) VALUES ('user', 'pass', 'user@test.com', 'Usuario', ?, 1)", (common_role_id,))
    
    conn.commit()
    conn.close()

# Decorator para validar token
def token_required(required_permission=None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.headers.get('Authorization')
            
            if not token:
                return jsonify({'error': 'Token requerido'}), 401
            
            if token.startswith('Bearer '):
                token = token[7:]
            
            try:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                current_user_id = data['user_id']
                
                # Verificar si el token ha expirado usando timestamps
                current_timestamp = time.time()
                token_exp = data['exp']
                
                print(f"Tiempo actual: {current_timestamp}")
                print(f"Token expira en: {token_exp}")
                print(f"Diferencia: {token_exp - current_timestamp} segundos")
                
                if current_timestamp > token_exp:
                    return jsonify({'error': 'Token expirado'}), 401
                
                # Si se requiere un permiso específico, verificarlo
                if required_permission:
                    if not check_user_permission(current_user_id, required_permission):
                        return jsonify({'error': 'Permisos insuficientes'}), 403
                
                # Pasar el user_id a la función
                return f(current_user_id=current_user_id, *args, **kwargs)
                
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Token expirado'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'error': 'Token inválido'}), 401
            
        return decorated
    return decorator

# Función para verificar permisos de usuario
def check_user_permission(user_id, permission_name):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT p.nombre FROM permisos p
        JOIN roles_permisos rp ON p.id = rp.permiso_id
        JOIN roles r ON rp.role_id = r.id
        JOIN users u ON u.role_id = r.id
        WHERE u.id = ? AND p.nombre = ?
    """, (user_id, permission_name))
    
    result = cursor.fetchone()
    conn.close()
    return result is not None

# ==================== RUTAS DE AUTENTICACIÓN ====================

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username') or request.args.get('username')
    password = request.form.get('password') or request.args.get('password')
    
    if request.is_json:
        data = request.get_json()
        username = username or data.get('username')
        password = password or data.get('password')
    
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ? AND status = 1", (username, password))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        # Obtener tiempo actual y agregar 5 minutos
        current_time = time.time()
        exp_time = current_time + (5 * 60)  # 5 minutos en segundos
        
        # Debug info
        print(f"Tiempo actual timestamp: {current_time}")
        print(f"Tiempo expiración timestamp: {exp_time}")
        print(f"Fecha actual: {datetime.datetime.fromtimestamp(current_time)}")
        print(f"Fecha expiración: {datetime.datetime.fromtimestamp(exp_time)}")
        
        # Crear token con timestamp directo
        token = jwt.encode({
            'user_id': user[0],
            'username': user[1],
            'exp': exp_time
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({
            "message": "Login exitoso", 
            "token": token,
            "expires_in": "5 minutos",
            "current_time": current_time,
            "exp_time": exp_time
        })
    else:
        return jsonify({"message": "Credenciales inválidas"}), 401

@app.route('/register', methods=['POST'])
def register():
    # Debug: imprimir todo lo que llega
    print(f"Content-Type: {request.content_type}")
    print(f"Form data: {dict(request.form)}")
    print(f"Request data: {request.data}")
    print(f"Request args: {dict(request.args)}")
    
    # Intentar obtener de diferentes fuentes
    username = request.form.get('username') or request.args.get('username')
    password = request.form.get('password') or request.args.get('password')
    email = request.form.get('email') or request.args.get('email')
    nombre_usuario = request.form.get('nombre_usuario') or request.args.get('nombre_usuario')
    pregunta_secreta = request.form.get('pregunta_secreta') or request.args.get('pregunta_secreta')
    respuesta_secreta = request.form.get('respuesta_secreta') or request.args.get('respuesta_secreta')
    fecha_nacimiento = request.form.get('fecha_nacimiento') or request.args.get('fecha_nacimiento')
    
    # Si es JSON, intentar leerlo
    if request.is_json:
        try:
            data = request.get_json()
            username = username or data.get('username')
            password = password or data.get('password')
            email = email or data.get('email')
            nombre_usuario = nombre_usuario or data.get('nombre_usuario')
            pregunta_secreta = pregunta_secreta or data.get('pregunta_secreta')
            respuesta_secreta = respuesta_secreta or data.get('respuesta_secreta')
            fecha_nacimiento = fecha_nacimiento or data.get('fecha_nacimiento')
        except:
            pass
    
    # Asignar rol común por defecto
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM roles WHERE nombre = 'common_user'")
    common_role_id = cursor.fetchone()[0]
    
    try:
        cursor.execute("""
            INSERT INTO users (username, password, email, nombre_usuario, pregunta_secreta, respuesta_secreta, fecha_nacimiento, role_id, status) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
        """, (username, password, email, nombre_usuario, pregunta_secreta, respuesta_secreta, fecha_nacimiento, common_role_id))
        conn.commit()
        print(f"Usuario {username} registrado exitosamente")
        conn.close()
        return jsonify({"message": "Usuario registrado"})
    except Exception as e:
        print(f"Error al registrar: {e}")
        conn.close()
        return jsonify({"error": f"Error al registrar: {str(e)}"}), 400

# ==================== RUTAS DE USUARIOS ====================

@app.route('/users')
@token_required('get_user')
def get_all_users(current_user_id):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.id, u.username, u.email, u.nombre_usuario, u.status, r.nombre as role_name
        FROM users u
        LEFT JOIN roles r ON u.role_id = r.id
        WHERE u.status = 1
    """)
    users = cursor.fetchall()
    conn.close()
    
    users_list = []
    for user in users:
        users_list.append({
            "id": user[0],
            "username": user[1], 
            "email": user[2],
            "nombre_usuario": user[3],
            "status": user[4],
            "role": user[5]
        })
    
    return jsonify({"users": users_list})

@app.route('/user')
@token_required('get_user')
def get_user(current_user_id):
    username = request.args.get('username') or ''
    
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.*, r.nombre as role_name FROM users u
        LEFT JOIN roles r ON u.role_id = r.id
        WHERE u.username = ? AND u.status = 1
    """, (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({
            "id": user[0], 
            "username": user[1], 
            "email": user[3], 
            "nombre_usuario": user[4],
            "role": user[10]
        })
    else:
        return jsonify({"error": f"Usuario '{username}' no encontrado"}), 404

@app.route('/user/<int:user_id>')
@token_required('get_user')
def get_user_by_id(current_user_id, user_id):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.*, r.nombre as role_name FROM users u
        LEFT JOIN roles r ON u.role_id = r.id
        WHERE u.id = ? AND u.status = 1
    """, (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({
            "id": user[0], 
            "username": user[1], 
            "email": user[3], 
            "nombre_usuario": user[4],
            "role": user[10]
        })
    else:
        return jsonify({"error": "Usuario no encontrado"}), 404

@app.route('/update_user/<int:user_id>', methods=['POST'])
@token_required('update_user')
def update_user(current_user_id, user_id):
    if request.is_json:
        data = request.get_json()
        email = data.get('email')
        nombre_usuario = data.get('nombre_usuario')
        pregunta_secreta = data.get('pregunta_secreta')
        respuesta_secreta = data.get('respuesta_secreta')
        fecha_nacimiento = data.get('fecha_nacimiento')
        role_id = data.get('role_id')
    else:
        email = request.form.get('email')
        nombre_usuario = request.form.get('nombre_usuario')
        pregunta_secreta = request.form.get('pregunta_secreta')
        respuesta_secreta = request.form.get('respuesta_secreta')
        fecha_nacimiento = request.form.get('fecha_nacimiento')
        role_id = request.form.get('role_id')
    
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE users SET email=?, nombre_usuario=?, pregunta_secreta=?, respuesta_secreta=?, fecha_nacimiento=?, role_id=?
        WHERE id=? AND status=1
    """, (email, nombre_usuario, pregunta_secreta, respuesta_secreta, fecha_nacimiento, role_id, user_id))
    conn.commit()
    conn.close()
    return jsonify({"message": "Usuario actualizado"})

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@token_required('delete_user')
def delete_user(current_user_id, user_id):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET status=0 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Usuario eliminado"})

# ==================== RUTAS DE PERMISOS ====================

@app.route('/permisos', methods=['GET'])
@token_required('get_permiso')
def get_permisos(current_user_id):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM permisos ORDER BY nombre")
    permisos = cursor.fetchall()
    conn.close()
    
    permisos_list = []
    for permiso in permisos:
        permisos_list.append({
            "id": permiso[0],
            "nombre": permiso[1]
        })
    
    return jsonify({"permisos": permisos_list})

@app.route('/permisos', methods=['POST'])
@token_required('create_permiso')
def create_permiso(current_user_id):
    if request.is_json:
        data = request.get_json()
        nombre = data.get('nombre')
    else:
        nombre = request.form.get('nombre')
    
    if not nombre:
        return jsonify({"error": "Nombre del permiso requerido"}), 400
    
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO permisos (nombre) VALUES (?)", (nombre,))
        conn.commit()
        permiso_id = cursor.lastrowid
        conn.close()
        return jsonify({"message": "Permiso creado", "id": permiso_id}), 201
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "El permiso ya existe"}), 400

@app.route('/permisos/<int:permiso_id>', methods=['PUT'])
@token_required('update_permiso')
def update_permiso(current_user_id, permiso_id):
    if request.is_json:
        data = request.get_json()
        nombre = data.get('nombre')
    else:
        nombre = request.form.get('nombre')
    
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE permisos SET nombre=? WHERE id=?", (nombre, permiso_id))
        conn.commit()
        if cursor.rowcount > 0:
            conn.close()
            return jsonify({"message": "Permiso actualizado"})
        else:
            conn.close()
            return jsonify({"error": "Permiso no encontrado"}), 404
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "El permiso ya existe"}), 400

@app.route('/permisos/<int:permiso_id>', methods=['DELETE'])
@token_required('delete_permiso')
def delete_permiso(current_user_id, permiso_id):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    
    # Verificar si el permiso está siendo usado
    cursor.execute("SELECT COUNT(*) FROM roles_permisos WHERE permiso_id=?", (permiso_id,))
    if cursor.fetchone()[0] > 0:
        conn.close()
        return jsonify({"error": "No se puede eliminar: permiso está siendo usado por roles"}), 400
    
    cursor.execute("DELETE FROM permisos WHERE id=?", (permiso_id,))
    conn.commit()
    if cursor.rowcount > 0:
        conn.close()
        return jsonify({"message": "Permiso eliminado"})
    else:
        conn.close()
        return jsonify({"error": "Permiso no encontrado"}), 404

# ==================== RUTAS DE ROLES ====================

@app.route('/roles', methods=['GET'])
@token_required('get_role')
def get_roles(current_user_id):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM roles ORDER BY nombre")
    roles = cursor.fetchall()
    
    roles_list = []
    for role in roles:
        # Obtener permisos del rol
        cursor.execute("""
            SELECT p.id, p.nombre FROM permisos p
            JOIN roles_permisos rp ON p.id = rp.permiso_id
            WHERE rp.role_id = ?
        """, (role[0],))
        permisos = cursor.fetchall()
        
        permisos_list = [{"id": p[0], "nombre": p[1]} for p in permisos]
        
        roles_list.append({
            "id": role[0],
            "nombre": role[1],
            "permisos": permisos_list
        })
    
    conn.close()
    return jsonify({"roles": roles_list})

@app.route('/roles', methods=['POST'])
@token_required('create_role')
def create_role(current_user_id):
    if request.is_json:
        data = request.get_json()
        nombre = data.get('nombre')
        permisos_ids = data.get('permisos', [])
    else:
        nombre = request.form.get('nombre')
        permisos_ids = request.form.getlist('permisos') or []
    
    if not nombre:
        return jsonify({"error": "Nombre del rol requerido"}), 400
    
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO roles (nombre) VALUES (?)", (nombre,))
        role_id = cursor.lastrowid
        
        # Asignar permisos al rol
        for permiso_id in permisos_ids:
            cursor.execute("INSERT INTO roles_permisos (role_id, permiso_id) VALUES (?, ?)", 
                          (role_id, permiso_id))
        
        conn.commit()
        conn.close()
        return jsonify({"message": "Rol creado", "id": role_id}), 201
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "El rol ya existe"}), 400

@app.route('/roles/<int:role_id>', methods=['PUT'])
@token_required('update_role')
def update_role(current_user_id, role_id):
    if request.is_json:
        data = request.get_json()
        nombre = data.get('nombre')
        permisos_ids = data.get('permisos', [])
    else:
        nombre = request.form.get('nombre')
        permisos_ids = request.form.getlist('permisos') or []
    
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    
    try:
        # Actualizar nombre del rol
        cursor.execute("UPDATE roles SET nombre=? WHERE id=?", (nombre, role_id))
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({"error": "Rol no encontrado"}), 404
        
        # Eliminar permisos actuales del rol
        cursor.execute("DELETE FROM roles_permisos WHERE role_id=?", (role_id,))
        
        # Asignar nuevos permisos
        for permiso_id in permisos_ids:
            cursor.execute("INSERT INTO roles_permisos (role_id, permiso_id) VALUES (?, ?)", 
                          (role_id, permiso_id))
        
        conn.commit()
        conn.close()
        return jsonify({"message": "Rol actualizado"})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "El rol ya existe"}), 400

@app.route('/roles/<int:role_id>', methods=['DELETE'])
@token_required('delete_role')
def delete_role(current_user_id, role_id):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    
    # Verificar si el rol está siendo usado por usuarios
    cursor.execute("SELECT COUNT(*) FROM users WHERE role_id=? AND status=1", (role_id,))
    if cursor.fetchone()[0] > 0:
        conn.close()
        return jsonify({"error": "No se puede eliminar: rol está siendo usado por usuarios"}), 400
    
    # Eliminar permisos del rol
    cursor.execute("DELETE FROM roles_permisos WHERE role_id=?", (role_id,))
    
    # Eliminar rol
    cursor.execute("DELETE FROM roles WHERE id=?", (role_id,))
    conn.commit()
    
    if cursor.rowcount > 0:
        conn.close()
        return jsonify({"message": "Rol eliminado"})
    else:
        conn.close()
        return jsonify({"error": "Rol no encontrado"}), 404

# ==================== RUTAS ADICIONALES ====================

@app.route('/reactivate_admin', methods=['POST'])
@token_required('admin_data')
def reactivate_admin(current_user_id):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET status=1 WHERE username='admin'")
    conn.commit()
    conn.close()
    return jsonify({"message": "Usuario admin reactivado"})

@app.route('/admin/data')
@token_required('admin_data')
def admin_data(current_user_id):
    return jsonify({"data": "Datos confidenciales. Acceso autorizado"})

# Ruta para verificar el token actual
@app.route('/verify_token')
@token_required()
def verify_token(current_user_id):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.username, u.email, r.nombre as role_name FROM users u
        LEFT JOIN roles r ON u.role_id = r.id
        WHERE u.id = ?
    """, (current_user_id,))
    user = cursor.fetchone()
    conn.close()
    
    return jsonify({
        "message": "Token válido",
        "user_id": current_user_id,
        "username": user[0] if user else None,
        "email": user[1] if user else None,
        "role": user[2] if user else None
    })

# Ejecutar servidor  
if __name__ == '__main__':
    init_db()
    app.run()