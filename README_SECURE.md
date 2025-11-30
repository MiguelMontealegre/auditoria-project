# 🛡️ APLICACIÓN FASTAPI SEGURA

## Versión Corregida: `vulnerabilities_project_SECURE.py`

Esta es la versión **completamente segura** de la aplicación original, con **TODAS las vulnerabilidades corregidas** siguiendo las mejores prácticas de seguridad y los estándares de OWASP.

---

## ✅ VULNERABILIDADES CORREGIDAS

| # | Vulnerabilidad Original | Corrección Implementada |
|---|------------------------|-------------------------|
| 1 | **SQL Injection** | Consultas preparadas (parameterized queries) |
| 2 | **OS Command Injection** | Validación de input + `shell=False` + lista de argumentos |
| 3 | **RCE (eval)** | **Endpoint eliminado completamente** |
| 4 | **Insecure Deserialization** | JSON + Pydantic en lugar de pickle |
| 5 | **Path Traversal** | UUID para nombres + validación de paths |
| 6 | **Sensitive Data Exposure** | Sin logging de passwords |
| 7 | **Weak Crypto (MD5)** | **Argon2** para hashing de passwords |
| 8 | **CORS Misconfiguration** | Whitelist específica de orígenes |
| 9 | **Missing Authentication** | **JWT obligatorio** en todos los endpoints críticos |
| 10 | **Hardcoded Credentials** | Variables de entorno |
| 11 | **Weak PRNG** | `secrets` module en lugar de `random()` |

---

## 🚀 INSTALACIÓN Y USO

### 1. Instalar dependencias

```bash
# Crear nuevo entorno virtual (opcional pero recomendado)
python3 -m venv venv_secure
source venv_secure/bin/activate  # En Windows: venv_secure\Scripts\activate

# Instalar dependencias
pip install -r requirements_secure.txt
```

### 2. Configurar variables de entorno

```bash
# Copiar archivo de ejemplo
cp .env.example .env

# Editar .env y configurar valores
# IMPORTANTE: Cambiar JWT_SECRET en producción
nano .env  # o el editor que prefieras
```

**Generar JWT_SECRET seguro:**

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### 3. Ejecutar la aplicación

```bash
# Opción 1: Directamente con Python
python3 vulnerabilities_project_SECURE.py

# Opción 2: Con Uvicorn
uvicorn vulnerabilities_project_SECURE:app --host 127.0.0.1 --port 8001 --reload
```

La aplicación estará disponible en: **http://127.0.0.1:8001**

---

## 📋 ENDPOINTS DISPONIBLES

### Públicos (sin autenticación)

- `GET /` - Información de la aplicación
- `GET /health` - Health check
- `POST /register` - Registro de usuarios
- `POST /login` - Login y obtención de JWT

### Protegidos (requieren JWT)

- `GET /ping?host=google.com` - Ping seguro (requiere Bearer token)
- `POST /deserialize` - Deserialización segura con JSON
- `POST /upload` - Upload seguro de archivos
- `GET /random-token` - Generación de token criptográfico
- `GET /me` - Información del usuario autenticado

### Documentación Interactiva

- **Swagger UI:** http://127.0.0.1:8001/docs
- **ReDoc:** http://127.0.0.1:8001/redoc

---

## 🔐 CÓMO USAR LA AUTENTICACIÓN

### 1. Registrar un usuario

```bash
curl -X POST "http://127.0.0.1:8001/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "SecurePass123!"
  }'
```

**Respuesta:**
```json
{
  "message": "Usuario registrado exitosamente",
  "username": "testuser"
}
```

### 2. Hacer login

```bash
curl -X POST "http://127.0.0.1:8001/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "SecurePass123!"
  }'
```

**Respuesta:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

### 3. Usar el token en requests protegidos

```bash
# Guardar el token
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Usar en endpoints protegidos
curl -X GET "http://127.0.0.1:8001/ping?host=google.com" \
  -H "Authorization: Bearer $TOKEN"

curl -X GET "http://127.0.0.1:8001/random-token" \
  -H "Authorization: Bearer $TOKEN"

curl -X GET "http://127.0.0.1:8001/me" \
  -H "Authorization: Bearer $TOKEN"
```

---

## 🛡️ MEJORAS DE SEGURIDAD IMPLEMENTADAS

### 1. Autenticación y Autorización
- ✅ JWT con expiración (1 hora por defecto)
- ✅ Todos los endpoints críticos requieren autenticación
- ✅ Verificación de token en cada request
- ✅ Manejo de tokens expirados

### 2. Criptografía
- ✅ **Argon2** para hashing de passwords (reemplaza MD5)
- ✅ `secrets` module para generación de tokens (reemplaza random)
- ✅ JWT con algoritmo HS256
- ✅ Secrets en variables de entorno

### 3. Validación de Input
- ✅ Pydantic para validación de datos
- ✅ Regex para validación de username y host
- ✅ Validación de extensiones de archivo
- ✅ Límites de tamaño de archivo (5MB)

### 4. Prevención de Inyecciones
- ✅ Consultas preparadas para SQL
- ✅ `shell=False` en subprocess
- ✅ Lista de argumentos en lugar de strings
- ✅ Eliminación del endpoint `/eval`

### 5. Configuración Segura
- ✅ CORS con whitelist específica
- ✅ Logging sin datos sensibles
- ✅ Timeouts en operaciones
- ✅ Manejo centralizado de errores

### 6. Upload Seguro
- ✅ UUID para nombres de archivo
- ✅ Validación de path traversal
- ✅ Whitelist de extensiones
- ✅ Límite de tamaño

---

## 📊 COMPARACIÓN: ANTES vs DESPUÉS

| Aspecto | Versión Vulnerable | Versión Segura |
|---------|-------------------|----------------|
| **Autenticación** | ❌ No existe | ✅ JWT obligatorio |
| **Password Hashing** | ❌ MD5 (quebrado) | ✅ Argon2 (estado del arte) |
| **SQL Queries** | ❌ Concatenación | ✅ Prepared statements |
| **Command Execution** | ❌ shell=True | ✅ shell=False + validación |
| **Deserialización** | ❌ pickle (RCE) | ✅ JSON seguro |
| **File Upload** | ❌ Sin validación | ✅ UUID + validación completa |
| **CORS** | ❌ allow_origins=["*"] | ✅ Whitelist específica |
| **Secrets** | ❌ Hardcodeados | ✅ Variables de entorno |
| **Random Numbers** | ❌ random() | ✅ secrets module |
| **Logging** | ❌ Passwords en logs | ✅ Sin datos sensibles |
| **Eval** | ❌ eval() activo | ✅ Eliminado completamente |

---

## 🧪 TESTING DE SEGURIDAD

### Test 1: Intentar SQL Injection
```bash
# ANTES: Funcionaba
curl -X POST "http://127.0.0.1:8001/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\'' OR '\''1'\''='\''1", "password": "cualquiera"}'

# AHORA: Bloqueado
# Response: {"error": "Credenciales inválidas", "status_code": 401}
```

### Test 2: Intentar Command Injection
```bash
# ANTES: Funcionaba
curl "http://127.0.0.1:8001/ping?host=google.com;ls"

# AHORA: Doble protección
# 1. Requiere autenticación (401 si no hay token)
# 2. Validación rechaza el input (400 si hay token)
```

### Test 3: Intentar acceder sin autenticación
```bash
# ANTES: Todos los endpoints accesibles
curl "http://127.0.0.1:8001/random-token"

# AHORA: Requiere token
# Response: {"detail": "Not authenticated"}
```

---

## 📝 NOTAS PARA PRODUCCIÓN

### ⚠️ IMPORTANTE antes de desplegar:

1. **Cambiar JWT_SECRET:**
   ```bash
   JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
   ```

2. **Configurar ALLOWED_ORIGINS:**
   - Reemplazar con tus dominios reales
   - Nunca usar `["*"]` en producción

3. **Usar base de datos real:**
   - Reemplazar SQLite por PostgreSQL/MySQL
   - Configurar conexiones con SSL
   - Usar pool de conexiones

4. **Configurar HTTPS:**
   - Usar certificados SSL/TLS
   - Configurar reverse proxy (nginx/apache)
   - Habilitar HSTS

5. **Rate Limiting:**
   - Implementar rate limiting por IP
   - Usar redis para tracking
   - Proteger contra brute force

6. **Logging y Monitoreo:**
   - Configurar SIEM
   - Alertas de seguridad
   - Backup de logs

7. **Secrets Management:**
   - Usar HashiCorp Vault o AWS Secrets Manager
   - Rotar secrets periódicamente
   - Nunca commitear .env

---

## 🔍 VALIDACIÓN ISO 27001 / OWASP

Esta versión cumple con:

✅ **ISO/IEC 27001:2022:**
- A.5.15 - Control de acceso
- A.5.16 - Gestión de identidades
- A.8.5 - Autenticación segura
- A.8.8 - Gestión de vulnerabilidades
- A.8.24 - Uso de criptografía
- A.8.28 - Codificación segura

✅ **OWASP Top 10 2021:**
- A01 - Broken Access Control ✅ Corregido
- A02 - Cryptographic Failures ✅ Corregido
- A03 - Injection ✅ Corregido
- A05 - Security Misconfiguration ✅ Corregido
- A08 - Software & Data Integrity Failures ✅ Corregido

---

## 📞 SOPORTE

Para consultas sobre la implementación segura:
- Revisa la documentación en `/docs`
- Consulta el código comentado
- Ejecuta los tests de seguridad

---

**Versión:** 2.0.0  
**Última actualización:** 28 de Noviembre de 2025  
**Estado:** ✅ Producción Ready (con configuración adecuada)

