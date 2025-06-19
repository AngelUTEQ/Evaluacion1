# Sistema RBAC - Flask API

Sistema de Control de Acceso Basado en Roles (Role-Based Access Control) implementado con Flask y SQLite, que proporciona autenticación JWT y autorización granular por permisos.

## 🚀 Características

- **Autenticación JWT** con tokens de corta duración (5 minutos)
- **Autorización granular** basada en permisos específicos
- **Gestión completa de usuarios, roles y permisos** (CRUD)
- **Base de datos SQLite** con relaciones apropiadas
- **API RESTful** con múltiples formatos de entrada
- **Middleware de seguridad** con decoradores Python
- **Inicialización automática** de datos del sistema

## 📋 Tabla de Contenidos

- [Instalación](#instalación)
- [Configuración](#configuración)
- [Uso](#uso)
- [Estructura de la Base de Datos](#estructura-de-la-base-de-datos)
- [Endpoints de la API](#endpoints-de-la-api)
- [Ejemplos de Uso](#ejemplos-de-uso)
- [Seguridad](#seguridad)

## 🛠️ Instalación

### Prerrequisitos

- Python 3.7 o superior
- pip (gestor de paquetes de Python)

### Instalación de dependencias

```bash
pip install flask sqlite3 PyJWT
```

### Clonar y ejecutar

```bash
# Clonar el repositorio
git clone <tu-repositorio>
cd sistema-rbac-flask

# Ejecutar la aplicación
python app.py
```

La aplicación estará disponible en `http://localhost:5000`

## ⚙️ Configuración

### Variables de entorno

```python
# En producción, cambiar la SECRET_KEY
app.config['SECRET_KEY'] = 'tu-clave-secreta-aqui'
app.config['DEBUG'] = False  # Desactivar en producción
```

### Base de datos

La base de datos SQLite se inicializa automáticamente al ejecutar la aplicación por primera vez, creando:

- Tablas necesarias
- Permisos básicos del sistema
- Roles predefinidos (admin, common_user, seller)
- Usuarios de prueba

## 🗄️ Estructura de la Base de Datos

```sql
users (id, username, password, email, nombre_usuario, role_id, status, ...)
├── roles (id, nombre)
│   └── roles_permisos (role_id, permiso_id)
│       └── permisos (id, nombre)
```

### Roles Predefinidos

| Rol | Descripción | Permisos |
|-----|-------------|----------|
| `admin` | Administrador del sistema | Todos los permisos |
| `common_user` | Usuario común | `get_user`, `get_product` |
| `seller` | Vendedor | Configurables |

### Permisos del Sistema

- **Usuarios**: `get_user`, `create_user`, `update_user`, `delete_user`
- **Productos**: `get_product`, `create_product`, `update_product`, `delete_product`
- **Roles**: `get_role`, `create_role`, `update_role`, `delete_role`
- **Permisos**: `get_permiso`, `create_permiso`, `update_permiso`, `delete_permiso`
- **Administración**: `admin_data`

## 🔌 Endpoints de la API

### Autenticación

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| POST | `/login` | Autenticar usuario |
| POST | `/register` | Registrar nuevo usuario |
| GET | `/verify_token` | Verificar token actual |

### Gestión de Usuarios

| Método | Endpoint | Permiso | Descripción |
|--------|----------|---------|-------------|
| GET | `/users` | `get_user` | Listar usuarios |
| GET | `/user?username={user}` | `get_user` | Obtener usuario por nombre |
| GET | `/user/{id}` | `get_user` | Obtener usuario por ID |
| POST | `/update_user/{id}` | `update_user` | Actualizar usuario |
| POST | `/delete_user/{id}` | `delete_user` | Eliminar usuario |

### Gestión de Permisos

| Método | Endpoint | Permiso | Descripción |
|--------|----------|---------|-------------|
| GET | `/permisos` | `get_permiso` | Listar permisos |
| POST | `/permisos` | `create_permiso` | Crear permiso |
| PUT | `/permisos/{id}` | `update_permiso` | Actualizar permiso |
| DELETE | `/permisos/{id}` | `delete_permiso` | Eliminar permiso |

### Gestión de Roles

| Método | Endpoint | Permiso | Descripción |
|--------|----------|---------|-------------|
| GET | `/roles` | `get_role` | Listar roles con permisos |
| POST | `/roles` | `create_role` | Crear rol |
| PUT | `/roles/{id}` | `update_role` | Actualizar rol |
| DELETE | `/roles/{id}` | `delete_role` | Eliminar rol |

## 📝 Ejemplos de Uso

### 1. Autenticación

```bash
# Login
curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "1234"}'

# Respuesta
{
  "message": "Login exitoso",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": "5 minutos"
}
```

### 2. Usar token en requests

```bash
# Obtener usuarios (requiere token y permiso get_user)
curl -X GET http://localhost:5000/users \
  -H "Authorization: Bearer tu-token-jwt-aqui"
```

### 3. Crear nuevo permiso

```bash
curl -X POST http://localhost:5000/permisos \
  -H "Authorization: Bearer tu-token-jwt-aqui" \
  -H "Content-Type: application/json" \
  -d '{"nombre": "manage_reports"}'
```

### 4. Crear rol con permisos

```bash
curl -X POST http://localhost:5000/roles \
  -H "Authorization: Bearer tu-token-jwt-aqui" \
  -H "Content-Type: application/json" \
  -d '{
    "nombre": "reporter",
    "permisos": [1, 2, 5]
  }'
```

### 5. Registrar usuario

```bash
curl -X POST http://localhost:5000/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "nuevo_usuario",
    "password": "password123",
    "email": "usuario@ejemplo.com",
    "nombre_usuario": "Nuevo Usuario"
  }'
```

## 🔒 Seguridad

### Características de Seguridad

- **Tokens JWT** con expiración automática (5 minutos)
- **Verificación de permisos** granular por endpoint
- **Control de estado** de usuarios (activo/inactivo)
- **Validación de entrada** en múltiples formatos
- **Manejo seguro de errores** sin exposición de información sensible

### Mejores Prácticas Implementadas

- Decorador `@token_required` para proteger endpoints
- Verificación manual de expiración de tokens
- Consultas SQL parametrizadas para prevenir inyección
- Separación de responsabilidades en funciones
- Inicialización segura de datos del sistema

### ⚠️ Consideraciones de Producción

```python
# Cambiar configuraciones para producción
app.config['SECRET_KEY'] = 'clave-secreta-muy-fuerte'
app.config['DEBUG'] = False

# Usar HTTPS en producción
# Implementar rate limiting
# Usar contraseñas hasheadas (bcrypt)
# Configurar CORS apropiadamente
```

## 🧪 Usuarios de Prueba

| Usuario | Contraseña | Rol | Permisos |
|---------|------------|-----|----------|
| `admin` | `1234` | admin | Todos |
| `user` | `pass` | common_user | Solo lectura |

## 🤝 Contribuir

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/nueva-funcionalidad`)
3. Commit tus cambios (`git commit -am 'Agregar nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Abre un Pull Request

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Ver el archivo `LICENSE` para más detalles.

## 🔧 Tecnologías Utilizadas

- **Flask** - Framework web de Python
- **SQLite** - Base de datos ligera
- **PyJWT** - Manejo de tokens JWT
- **Python 3.7+** - Lenguaje de programación

---

⭐ Si este proyecto te fue útil, ¡dale una estrella!
