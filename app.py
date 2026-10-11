from datetime import datetime, timedelta
import os
import requests
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from functools import wraps
from datetime import datetime
from db import db, Usuario, Producto, get_connection
from flask import jsonify, request
import re
import psycopg2.extras
import os
import time
from flask import request, redirect, flash, session, url_for, render_template
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "clave_secreta_segura"
# ==========================================
# --- SISTEMA DE SEGURIDAD PERSISTENTE (BD) ---
# ==========================================

def verificar_seguridad_ip(ip):
    """Verifica en la BD si una IP sigue bloqueada."""
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    ahora = datetime.now()
    try:
        cursor.execute("SELECT intentos, bloqueado_hasta FROM registro_seguridad WHERE ip = %s", (ip,))
        resultado = cursor.fetchone()
        
        if resultado and resultado['bloqueado_hasta']:
            # Si la fecha de bloqueo es mayor a 'ahora', sigue bloqueado
            if resultado['bloqueado_hasta'] > ahora:
                tiempo_restante = int((resultado['bloqueado_hasta'] - ahora).total_seconds())
                return False, tiempo_restante
            else:
                # Si el tiempo ya pasó, desbloqueamos automáticamente reseteando a 0
                cursor.execute("UPDATE registro_seguridad SET intentos = 0, bloqueado_hasta = NULL WHERE ip = %s", (ip,))
                conn.commit()
                
        return True, 0
    except Exception as e:
        print(f"Error al verificar IP en BD: {e}")
        return True, 0
    finally:
        conn.close()

def registrar_fallo_ip(ip, correo):
    """Registra un fallo en la BD, guarda el correo usado y bloquea si llega al límite."""
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    ahora = datetime.now()
    bloqueado_ahora = False
    MAX_INTENTOS = 3
    
    try:
        cursor.execute("SELECT id, intentos FROM registro_seguridad WHERE ip = %s", (ip,))
        resultado = cursor.fetchone()
        
        if resultado:
            nuevos_intentos = resultado['intentos'] + 1
            if nuevos_intentos >= MAX_INTENTOS:
                # Calculamos 10 minutos en el futuro
                bloqueo = ahora + timedelta(minutes=1)
                cursor.execute("""
                    UPDATE registro_seguridad 
                    SET intentos = %s, correo_intentado = %s, bloqueado_hasta = %s 
                    WHERE ip = %s
                """, (nuevos_intentos, correo, bloqueo, ip))
                bloqueado_ahora = True
            else:
                cursor.execute("""
                    UPDATE registro_seguridad 
                    SET intentos = %s, correo_intentado = %s 
                    WHERE ip = %s
                """, (nuevos_intentos, correo, ip))
        else:
            # Primer fallo de esta IP: la registramos
            cursor.execute("""
                INSERT INTO registro_seguridad (ip, correo_intentado, intentos, bloqueado_hasta) 
                VALUES (%s, %s, 1, NULL)
            """, (ip, correo))
            
        conn.commit()
    except Exception as e:
        print(f"Error al registrar fallo en BD: {e}")
    finally:
        conn.close()
    return bloqueado_ahora

def resetear_ip(ip):
    """Limpia el historial de la IP tras un login exitoso."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE registro_seguridad SET intentos = 0, bloqueado_hasta = NULL WHERE ip = %s", (ip,))
        conn.commit()
    except Exception as e:
        print(f"Error al resetear IP: {e}")
    finally:
        conn.close()

# ==========================================
# CONFIGURACIÓN DE SUBIDA DE ARCHIVOS
# ==========================================
# Carpeta donde se guardarán las imágenes (Asegúrate de crearla en tu proyecto)
UPLOAD_FOLDER = 'static/uploads/disenos'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Limitar el tamaño a 5MB por seguridad
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024 
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}

# Crear la carpeta si no existe
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Configuración de Base de Datos
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres.byixvuagnonvxjhhsnkn:SCARFSKYLA21@aws-1-us-west-2.pooler.supabase.com:6543/postgres'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
bcrypt = Bcrypt(app)

# ==========================================
# DECORADORES DE SEGURIDAD
# ==========================================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "usuario_id" not in session:
            flash("Por favor, inicia sesión para continuar.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("rol") == "cliente":
            flash("Acceso denegado: Área exclusiva para personal.", "danger")
            return redirect(url_for('index')) 
        return f(*args, **kwargs)
    return decorated_function

# ==========================================
# RUTAS PÚBLICAS Y DE CLIENTES (FRONT-OFFICE)
# ==========================================
@app.route("/")
def index():
    # Usamos SQL directo para filtrar solo los productos Activos
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Traemos solo los Activos o los nulos (por si hay productos muy antiguos)
        cursor.execute("SELECT * FROM producto WHERE estado = 'Activo' OR estado IS NULL ORDER BY id DESC")
        productos_activos = cursor.fetchall()
    except Exception as e:
        print(f"Error al cargar productos en el catálogo: {e}")
        productos_activos = []
    finally:
        conn.close()
        
    return render_template("index.html", productos=productos_activos)

@app.route("/producto/<int:id>")
def detalle_producto(id):
    producto = Producto.query.get_or_404(id)
    return render_template("detalle.html", producto=producto)

@app.route("/crear_pedido_cliente", methods=["POST"])
@login_required
def crear_pedido_cliente():
    id_usuario = session["usuario_id"]
    id_producto = request.form.get("id_producto")
    cantidad = request.form.get("cantidad", 1)
    
    # Capturamos el material y notas
    material = request.form.get("material", "N/A") 
    notas = request.form.get("notas", "")
    
    # ==========================================
    # DATOS DEL PAGO / ADELANTO (AÑADIDO)
    # ==========================================
    monto_pago = request.form.get("monto_pago") or request.form.get("monto_adelanto")
    metodo_pago = request.form.get("metodo_pago", "Transferencia")
    referencia_voucher = request.form.get("referencia_voucher", "")
    
    especificaciones = f"Material: {material} | Notas: {notas}"
    fecha = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # ==========================================
    # LÓGICA PARA GUARDAR LA IMAGEN DEL CLIENTE
    # ==========================================
    nombre_archivo = None
    if 'imagen_diseno' in request.files:
        file = request.files['imagen_diseno']
        if file and file.filename != '':
            if allowed_file(file.filename):
                filename = secure_filename(file.filename)
                nombre_unico = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
                ruta_guardado = os.path.join(app.config['UPLOAD_FOLDER'], nombre_unico)
                file.save(ruta_guardado)
                nombre_archivo = nombre_unico
            else:
                flash("Formato de imagen no permitido. Usa JPG, PNG o PDF.", "danger")
                return redirect(request.url)

    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        # 1. Insertar el Pedido (RETURNING id asegura obtener el ID en PostgreSQL/Supabase)
        query_pedido = """
            INSERT INTO pedido (id_usuario, id_producto, cantidad, fecha, especificaciones, archivo_diseno, estado)
            VALUES (%s, %s, %s, %s, %s, %s, 'Pendiente')
            RETURNING id
        """
        cursor.execute(query_pedido, (id_usuario, id_producto, cantidad, fecha, especificaciones, nombre_archivo))
        
        # Obtenemos el ID del pedido recién generado
        res = cursor.fetchone()
        pedido_id = res['id'] if isinstance(res, dict) else res[0]
        
        # 2. Registrar el Pago en historial_pagos si existe un monto
        if monto_pago and float(monto_pago) > 0:
            query_pago = """
                INSERT INTO historial_pagos (id_pedido, monto, metodo_pago, "Referencia_voucher")
                VALUES (%s, %s, %s, %s)
            """
            cursor.execute(query_pago, (pedido_id, monto_pago, metodo_pago, referencia_voucher))
        
        # Confirmamos la transacción
        conn.commit()

    except Exception as e:
        conn.rollback()
        print(f"Error al registrar pedido/pago: {e}")
        flash("Ocurrió un error al procesar el pedido.", "danger")
        return redirect(request.url)
    finally:
        conn.close()
    
    return redirect(url_for('pedido_exitoso', id=pedido_id))


@app.route("/pedido_exitoso/<int:id>")
@login_required
def pedido_exitoso(id):
    return render_template("pedido_exitoso.html", pedido_id=id)
#####################################################################################################################
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    ip_cliente = request.remote_addr
    
    # Si la IP está bloqueada por sospecha de hackeo, no puede registrar cuentas
    permitido, tiempo_restante = verificar_seguridad_ip(ip_cliente)
    if not permitido:
        flash(f"Acceso restringido. No puedes registrar cuentas en este momento. Espera {tiempo_restante} segundos.", "danger")
        return render_template('registro.html'), 403

    if request.method == 'POST':
        documento = request.form["documento"]
        tipo_doc = request.form.get("tipo_doc", "dni") # Capturamos el tipo de documento
        
        # LÓGICA DE NOMBRE: Si es RUC usa Razón Social, para cualquier otro tipo (DNI, CE, Pasaporte) construye con nombres y apellidos
        if tipo_doc.lower() == "ruc":
            nombre_completo = request.form.get("razon_social", "")
        else:
            nombres = request.form.get("nombres", "")
            paterno = request.form.get("apellido_paterno", "")
            materno = request.form.get("apellido_materno", "")
            nombre_completo = f"{nombres} {paterno} {materno}".strip()

        telefono = request.form["telefono"]
        correo = request.form["correo"]
        clave = request.form["clave"]
        
        # ==========================================
        # VALIDACIONES ESTRICTAS DE FORMATO
        # ==========================================
        if not re.match(r'^\d{9}$', telefono):
            flash("El número de celular debe tener exactamente 9 dígitos numéricos.", "danger")
            return redirect(url_for("registro"))
            
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', correo):
            flash("El formato del correo electrónico no es válido.", "danger")
            return redirect(url_for("registro"))
        
        # Validar duplicados
        if Usuario.query.filter_by(correo=correo).first() or Usuario.query.filter_by(documento=documento).first():
            flash("El correo o el documento ya están registrados.", "danger")
            return redirect(url_for("registro"))
            
        pw_hash = bcrypt.generate_password_hash(clave).decode('utf-8')
        
        # Guardamos en la base de datos pasando 'tipo_documento'
        nuevo = Usuario(
            tipo_documento=tipo_doc,
            documento=documento, 
            nombre=nombre_completo, 
            telefono=telefono, 
            correo=correo, 
            clave=pw_hash
        )
        
        db.session.add(nuevo)
        db.session.commit()
        
        flash("¡Registro exitoso! Ahora puedes iniciar sesión.", "success")
        return redirect(url_for("login"))
        
    return render_template("registro.html")

##############################################################################################################################

@app.route("/registro_presencial", methods=["GET", "POST"])
def registro_presencial():

    if request.method == "POST":

        documento = request.form["documento"]
        tipo_doc = request.form.get("tipo_doc", "dni") # Capturamos el tipo de documento

        # LÓGICA DE NOMBRE: RUC = Razón Social | Otros (DNI, CE, Pasaporte) = Nombres + Apellidos
        if tipo_doc.lower() == "ruc":
            nombre_completo = request.form.get("razon_social", "")
        else:
            nombres = request.form.get("nombres", "")
            paterno = request.form.get("apellido_paterno", "")
            materno = request.form.get("apellido_materno", "")
            nombre_completo = f"{nombres} {paterno} {materno}".strip()

        telefono = request.form["telefono"]
        correo = request.form["correo"]

        # CONTRASEÑA OPCIONAL
        clave = request.form.get("clave")

        # ==========================================
        # VALIDACIONES ESTRICTAS DE FORMATO
        # ==========================================
        if not re.match(r'^\d{9}$', telefono):
            flash("El número de celular debe tener exactamente 9 dígitos numéricos.", "danger")
            return redirect(url_for("registro_presencial"))
            
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', correo):
            flash("El formato del correo electrónico no es válido.", "danger")
            return redirect(url_for("registro_presencial"))

        # VALIDAR DUPLICADOS
        existe_correo = Usuario.query.filter_by(correo=correo).first()
        existe_documento = Usuario.query.filter_by(documento=documento).first()

        if existe_correo or existe_documento:
            flash("El correo o documento ya están registrados.", "danger")
            return redirect(url_for("registro_presencial"))

        # SI NO ESCRIBE CONTRASEÑA
        if not clave or clave.strip() == "":
            clave = documento

        # GENERAR HASH
        pw_hash = bcrypt.generate_password_hash(clave).decode('utf-8')

        # CREAR USUARIO CON TIPO DE DOCUMENTO
        nuevo = Usuario(
            tipo_documento=tipo_doc,
            documento=documento,
            nombre=nombre_completo,
            telefono=telefono,
            correo=correo,
            clave=pw_hash
        )

        db.session.add(nuevo)
        db.session.commit()

        flash("Cliente presencial registrado correctamente.", "success")
        return redirect(url_for("clientes"))

    return render_template("admin/nuevo_cliente.html")
########################################################################################################

@app.route('/login', methods=['GET', 'POST'])
def login():
    # --- CONFIGURACIÓN DE SEGURIDAD ---
    MAX_INTENTOS = 2        
    MINUTOS_BLOQUEO = 1   
    

    ip_cliente = request.remote_addr
    
    
    permitido, tiempo_restante = verificar_seguridad_ip(ip_cliente)
    if not permitido:
        minutos = tiempo_restante // 60
        segundos = tiempo_restante % 60
        flash(f"Tu dirección IP ha sido bloqueada temporalmente por seguridad. Intenta de nuevo en {minutos} minutos y {segundos} segundos.", "danger")
        return render_template('login.html'), 403

    if request.method == 'POST':
        correo = request.form['correo']
        clave = request.form['clave']

        conn = get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute("SELECT * FROM usuario WHERE correo = %s", (correo,))
        usuario = cursor.fetchone()
        conn.close()

        # Si el usuario existe y la contraseña coincide
        if usuario and bcrypt.check_password_hash(usuario['clave'], clave):
            session['usuario_id'] = usuario['id']
            session['nombre'] = usuario['nombre']
            session['rol'] = 'cliente'
            
            resetear_ip(ip_cliente)
            return redirect('/')
        
        else:
            # 3. LOGIN FALLIDO
            bloqueado_ahora = registrar_fallo_ip(ip_cliente, correo) 
            
            if bloqueado_ahora:
                # El mensaje ahora usa las variables dinámicas
                flash(f"Has superado el límite de {MAX_INTENTOS} intentos permitidos. Tu IP ha sido bloqueada por {MINUTOS_BLOQUEO} minutos.", "danger")
            else:
                conn = get_connection()
                cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cursor.execute("SELECT intentos FROM registro_seguridad WHERE ip = %s", (ip_cliente,))
                registro = cursor.fetchone()
                conn.close()
                
                intentos_actuales = registro['intentos'] if registro else 1
                
                # Calculamos los intentos restantes usando la variable MAX_INTENTOS
                intentos_restantes = MAX_INTENTOS - intentos_actuales
                
                # Mensaje ultra claro con los números exactos
                flash(f"Correo o contraseña incorrectos. Te quedan {intentos_restantes} intentos antes de bloquear tu IP por {MINUTOS_BLOQUEO} minutos.", "warning")

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()  # Limpia por completo los datos del usuario o admin logueado
    flash("Has cerrado sesión correctamente.", "success")
    return redirect(url_for('login'))  # <--- Te manda al login de forma segura

# ==========================================
# RUTAS DE ADMINISTRACIÓN (BACK-OFFICE)
# ==========================================
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    ip_cliente = request.remote_addr
    
    # Validar si la IP está bloqueada
    permitido, tiempo_restante = verificar_seguridad_ip(ip_cliente)
    if not permitido:
        flash(f"Acceso denegado. Tu IP está bloqueada por {tiempo_restante} segundos.", "danger")
        return render_template("admin_login.html"), 403

    if request.method == "POST":
        correo = request.form["correo"]
        clave = request.form["clave"]
        
        conn = get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute("SELECT * FROM usuarios_sistema WHERE correo = %s", (correo,))
        admin = cursor.fetchone()
        conn.close()
        
        if admin and bcrypt.check_password_hash(admin["clave"], clave):
            session["usuario_id"] = admin["id"]
            session["nombre"] = admin["nombres"]
            session["rol"] = admin["rol"]
            
            # Login exitoso: reseteamos contador
            resetear_ip(ip_cliente)
            return redirect(url_for("pedidos"))        
        else:
            # PASAMOS EL IP Y EL CORREO INTENTADO
            bloqueado_ahora = registrar_fallo_ip(ip_cliente, correo) 
            if bloqueado_ahora:
                flash("Has superado el límite de intentos permitidos. Tu IP ha sido bloqueada por 10 minutos.", "danger")
            else:
                # Modificamos esta línea para consultar los intentos actuales directo de la función o dejar un mensaje genérico
                flash("Correo o contraseña incorrectos. Al acumular 5 intentos tu IP será bloqueada por seguridad.", "danger")
                
    return render_template("admin_login.html")


# --- GESTIÓN DE PEDIDOS ---
# --- ACTUALIZACIÓN DE LA RUTA DE ADMINISTRADOR ---
# --- ACTUALIZACIÓN DE LA RUTA DE ADMINISTRADOR ---
# --- ACTUALIZACIÓN DE LA RUTA DE ADMINISTRADOR ---
@app.route('/pedidos') 
@login_required
@admin_required
def pedidos():
    conn = get_connection() 
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    # 1. Traer Pedidos principales sumando dinámicamente lo pagado en historial_pagos
    cursor.execute("""
        SELECT p.id, p.id_usuario, us.nombres AS empleado, c.nombre AS cliente, 
               c.telefono AS telefono, pr.nombre_producto AS producto, 
               p.cantidad, p.especificaciones, pr.precio AS precio_unitario,
               (p.cantidad * pr.precio) AS total_pagado, 
               COALESCE(
                   (SELECT SUM(monto) FROM historial_pagos hp WHERE hp.id_pedido = p.id), 
                   p.adelanto, 
                   0
               ) AS adelanto,
               p.archivo_diseno, p.estado, p.fecha 
        FROM pedido p
        LEFT JOIN usuarios_sistema us ON p.id_usuario_sistema = us.id
        LEFT JOIN usuario c ON p.id_usuario = c.id
        LEFT JOIN producto pr ON p.id_producto = pr.id
        ORDER BY p.id DESC
    """) 
    pedidos_data = cursor.fetchall() 
    
    # 2. Traer todos los mensajes internos para la bitácora
    cursor.execute("SELECT * FROM pedido_mensajes ORDER BY fecha ASC")
    todos_los_mensajes = cursor.fetchall()
    
    mensajes_por_pedido = {}
    for msg in todos_los_mensajes:
        pid = msg['id_pedido']
        if pid not in mensajes_por_pedido:
            mensajes_por_pedido[pid] = []
        mensajes_por_pedido[pid].append(msg)
        
    # 3. Traer todo el historial agrupado para los modales
    historial_por_cliente = {}
    for ped in pedidos_data:
        uid = ped['id_usuario']
        if uid not in historial_por_cliente:
            historial_por_cliente[uid] = []
        historial_por_cliente[uid].append(ped)
        
    conn.close()    
    return render_template(
        'pedidos.html', 
        pedidos=pedidos_data, 
        mensajes=mensajes_por_pedido,
        historial_clientes=historial_por_cliente
    )

############################################
@app.route('/pedido/<int:id_pedido>/enviar_mensaje', methods=['POST'])
def enviar_mensaje(id_pedido):
    mensaje = request.form.get('mensaje', '').strip()
    archivo = request.files.get('adjunto')

    # 1. Determinar el rol actual
    rol_actual = session.get('rol', 'cliente')
    if rol_actual not in ['administrador', 'cliente']:
        rol_actual = 'cliente'

    # 2. OBTENER EL NOMBRE DEL REMITENTE (Cambia 'nombre' o 'usuario' según como guardas en session)
    remitente_nombre = session.get('nombre') or session.get('usuario') or ('Administrador' if rol_actual == 'administrador' else 'Cliente')

    nombre_archivo = None
    carpeta_destino = os.path.join('static', 'uploads', 'mensajes')
    os.makedirs(carpeta_destino, exist_ok=True)

    if archivo and archivo.filename != '':
        filename = f"{int(time.time())}_{secure_filename(archivo.filename)}"
        archivo.save(os.path.join(carpeta_destino, filename))
        nombre_archivo = filename

    if not mensaje and not nombre_archivo:
        flash('Escribe un mensaje o adjunta un archivo/comprobante.', 'warning')
        return redirect(request.referrer or url_for('pedidos'))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        # 3. AGREGAR 'remitente_nombre' A LA SENTENCIA SQL
        cursor.execute("""
            INSERT INTO pedido_mensajes (id_pedido, mensaje, archivo_adjunto, remitente_rol, remitente_nombre, fecha)
            VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
        """, (id_pedido, mensaje, nombre_archivo, rol_actual, remitente_nombre))

        conn.commit()
        flash('Mensaje / Comprobante enviado correctamente.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error al registrar en la bitácora: {e}', 'danger')
    finally:
        cursor.close()
        conn.close()

    return redirect(request.referrer or url_for('pedidos'))
    ##################################
@app.route('/pedido/<int:id>')
def ver_detalle_pedido(id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True) # dictionary=True permite acceder como obj.propiedad

    try:
        # 1. Obtener datos del pedido
        cursor.execute("SELECT * FROM pedidos WHERE id = %s", (id,))
        pedido = cursor.fetchone()

        if not pedido:
            flash('El pedido solicitado no existe.', 'warning')
            return redirect(url_for('pedidos'))

        # 2. Obtener historial de pagos
        cursor.execute("SELECT * FROM pagos WHERE id_pedido = %s ORDER BY fecha ASC", (id,))
        pagos = cursor.fetchall()

        # 3. Obtener historial de la bitácora / comprobantes
        cursor.execute("""
            SELECT id, id_pedido, mensaje, archivo_adjunto, remitente_rol, fecha 
            FROM pedido_mensajes 
            WHERE id_pedido = %s 
            ORDER BY fecha ASC
        """, (id,))
        mensajes = cursor.fetchall()

    except Exception as e:
        flash(f"Error al cargar los detalles: {e}", "danger")
        pedido, pagos, mensajes = None, [], []
    finally:
        cursor.close()
        conn.close()

    # Enviamos pedido, pagos y mensajes al HTML
    return render_template('pedido_detalle.html', pedido=pedido, pagos=pagos, mensajes=mensajes)
######################


@app.route('/mis_pedidos')
@login_required
def mis_pedidos():
    usuario_id = session.get('usuario_id')
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # 1. Traer Pedidos del Cliente calculando el total abonado en historial_pagos
        cursor.execute("""
            SELECT p.id, pr.nombre_producto AS producto, p.especificaciones, p.cantidad, 
                   pr.precio AS precio_unitario,
                   (p.cantidad * pr.precio) AS total_pagado, 
                   COALESCE(
                       (SELECT SUM(monto) FROM historial_pagos hp WHERE hp.id_pedido = p.id), 
                       p.adelanto, 
                       0
                   ) AS adelanto,
                   p.archivo_diseno, p.estado, p.fecha 
            FROM pedido p
            JOIN producto pr ON p.id_producto = pr.id
            WHERE p.id_usuario = %s 
            ORDER BY 
                CASE p.estado 
                    WHEN 'Pendiente' THEN 1 
                    WHEN 'En Proceso' THEN 2 
                    WHEN 'Completado' THEN 3 
                    WHEN 'Anulado' THEN 4 
                    ELSE 5 
                END, p.fecha DESC
        """, (usuario_id,))
        pedidos_cliente = cursor.fetchall()
        
        # 2. Traer mensajes del cliente
        cursor.execute("SELECT * FROM pedido_mensajes ORDER BY fecha ASC")
        todos_los_mensajes = cursor.fetchall()
        
        mensajes_por_pedido = {}
        for msg in todos_los_mensajes:
            pid = msg['id_pedido']
            if pid not in mensajes_por_pedido:
                mensajes_por_pedido[pid] = []
            mensajes_por_pedido[pid].append(msg)
            
    except Exception as e:
        print(f"Error: {e}")
        pedidos_cliente = []
        mensajes_por_pedido = {}
    finally:
        conn.close()
        
    return render_template('cliente/mis_pedidos.html', pedidos=pedidos_cliente, mensajes=mensajes_por_pedido)
#############################################################################21

# --- RUTAS DE GESTIÓN (ESTADO, ANULAR) ---
@app.route('/pedidos/anular/<int:id>')
@login_required
@admin_required
def anular_pedido(id):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE pedido SET estado = 'Anulado' WHERE id = %s", (id,))
        conn.commit()
        flash(f"Pedido #{id} marcado como Anulado. Se conserva en el historial.", "warning")
    except Exception as e:
        flash(f"Error al anular el pedido: {str(e)}", "danger")
    finally:
        conn.close()
    return redirect('/pedidos')

@app.route('/pedidos/estado/<int:id>/<nuevo_estado>')
@login_required
@admin_required
def cambiar_estado(id, nuevo_estado):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE pedido SET estado = %s WHERE id = %s", (nuevo_estado, id))
        conn.commit()
        flash(f"Estado del pedido #{id} actualizado a: {nuevo_estado}", "info")
    except Exception as e:
        flash(f"Error al actualizar estado: {str(e)}", "danger")
    finally:
        conn.close()
    return redirect('/pedidos')

@app.route('/admin/historial_cliente/<int:id_usuario>')
@login_required
@admin_required
def historial_cliente(id_usuario):
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    query = """
        SELECT p.*, prod.nombre_producto, u.nombre as nombre_cliente
        FROM pedido p
        JOIN producto prod ON p.id_producto = prod.id
        JOIN usuario u ON p.id_usuario = u.id
        WHERE p.id_usuario = %s
        ORDER BY p.fecha DESC
    """
    cursor.execute(query, (id_usuario,))
    pedidos_usuario = cursor.fetchall()
    conn.close()
    
    if not pedidos_usuario:
        flash("Este cliente no tiene pedidos registrados.", "info")
        return redirect('/pedidos')
        
    return render_template('admin/historial.html', pedidos=pedidos_usuario, cliente=pedidos_usuario[0]['nombre_cliente'])

#####################################################21
@app.route('/admin/seguridad')
@login_required
# Asegúrate de tener tu decorador @admin_required aquí si lo usas
def admin_seguridad():
    """Muestra el reporte de IPs bloqueadas e intentos de hackeo o fallos."""
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute("SELECT * FROM registro_seguridad WHERE intentos > 0 ORDER BY ultima_actividad DESC")
        reportes = cursor.fetchall()
    except Exception as e:
        print(f"Error al obtener logs de seguridad: {e}")
        reportes = []
    finally:
        conn.close()
        
    # Enviamos 'datetime_now' con la hora exacta actual
    return render_template('admin/seguridad.html', reportes=reportes, datetime_now=datetime.now())
#####################################################21

# ========================================================
# --- ACTUALIZAR PAGOS / ADELANTOS DEL PEDIDO ---
# ========================================================
# ========================================================
# --- REGISTRAR NUEVO ABONO / PAGO DEL PEDIDO ---
# ========================================================
@app.route('/pedido/actualizar_pago/<int:id>', methods=['POST'])
def actualizar_pago(id):
    monto_pago = float(request.form.get('monto_pago', 0))
    metodo_pago = request.form.get('metodo_pago')

    if monto_pago <= 0:
        flash('El monto ingresado debe ser mayor a cero.', 'danger')
        return redirect(url_for('pedidos'))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        # 1. Consultar estado actual del pedido
        cursor.execute("""
            SELECT p.adelanto, p.total_pagado, pr.precio, p.cantidad 
            FROM pedido p
            JOIN producto pr ON p.id_producto = pr.id
            WHERE p.id = %s
        """, (id,))
        pedido = cursor.fetchone()

        if not pedido:
            flash('Pedido no encontrado.', 'danger')
            return redirect(url_for('pedidos'))

        # Compatibilidad tupla/dict
        if isinstance(pedido, dict):
            adelanto_actual = float(pedido['adelanto'] or 0.0)
            total_pagado_bd = float(pedido['total_pagado'] or 0.0)
            precio_unitario = float(pedido['precio'] or 0.0)
            cantidad = int(pedido['cantidad'] or 1)
        else:
            adelanto_actual = float(pedido[0] or 0.0)
            total_pagado_bd = float(pedido[1] or 0.0)
            precio_unitario = float(pedido[2] or 0.0)
            cantidad = int(pedido[3] or 1)

        # Si el costo total está en 0, lo calculamos
        precio_total = total_pagado_bd if total_pagado_bd > 0 else (precio_unitario * cantidad)
        nuevo_adelanto = adelanto_actual + monto_pago

        # Evitar cobrar de más
        if nuevo_adelanto > precio_total:
            nuevo_adelanto = precio_total

        # 2. Actualizar la tabla pedido
        cursor.execute("""
            UPDATE pedido 
            SET adelanto = %s,
                total_pagado = %s,
                metodo_pago = %s
            WHERE id = %s
        """, (nuevo_adelanto, precio_total, metodo_pago, id))

        # 3. Registrar el abono individual en historial_pagos
        cursor.execute("""
            INSERT INTO historial_pagos (id_pedido, monto, metodo_pago, fecha, referencia_voucher)
            VALUES (%s, %s, %s, CURRENT_TIMESTAMP, %s)
        """, (id, monto_pago, metodo_pago, 'Abono registrado por Admin'))

        conn.commit()

        if nuevo_adelanto >= precio_total:
            flash(f'¡Pago completo recibido! El pedido #{id} ha sido pagado al 100%.', 'success')
        else:
            flash(f'Abono de S/ {monto_pago:.2f} registrado correctamente para el pedido #{id}.', 'info')

    except Exception as e:
        conn.rollback()
        flash(f'Error al registrar el pago: {e}', 'danger')

    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('pedidos'))
#####################################################25

# --- GESTIÓN DE PRODUCTOS ---
# ==========================================
# --- VISTA DE PRODUCTOS ---
# ==========================================
@app.route('/productos')
@login_required
@admin_required
def productos():
    # Usamos SQL directo para que lea la nueva columna 'estado'
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute("SELECT id, nombre_producto, precio, estado FROM producto ORDER BY id DESC")
        lista_productos = cursor.fetchall()
    except Exception as e:
        print(f"Error cargando productos: {e}")
        lista_productos = []
    finally:
        conn.close()
        
    return render_template('productos.html', productos=lista_productos)
################################
# ==========================================
# --- MODIFICAR PRODUCTOS Y PRECIOS ---
# ==========================================
@app.route('/productos/editar/<int:id>', methods=['POST'])
@login_required
@admin_required
def editar_producto(id):
    # Buscamos el producto en la base de datos
    producto = Producto.query.get_or_404(id)
    
    # Actualizamos sus valores con los del formulario
    nuevo_nombre = request.form.get('nombre_producto')
    nuevo_precio = request.form.get('precio')
    
    if nuevo_nombre and nuevo_precio:
        producto.nombre_producto = nuevo_nombre
        producto.precio = float(nuevo_precio)
        db.session.commit()
        flash(f"El producto '{producto.nombre_producto}' fue modificado exitosamente.", "success")
    else:
        flash("Todos los campos son obligatorios.", "danger")
        
    return redirect('/productos')
# ==========================================
# --- OCULTAR / MOSTRAR PRODUCTOS ---
# ==========================================
@app.route('/productos/cambiar_estado/<int:id>', methods=['POST'])
@login_required
@admin_required
def cambiar_estado_producto(id):
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Buscamos el estado actual del producto
        cursor.execute("SELECT estado FROM producto WHERE id = %s", (id,))
        prod = cursor.fetchone()
        
        if prod:
            # Alternamos el estado: Si está Activo pasa a Oculto, y viceversa
            nuevo_estado = 'Oculto' if prod.get('estado') == 'Activo' else 'Activo'
            cursor.execute("UPDATE producto SET estado = %s WHERE id = %s", (nuevo_estado, id))
            conn.commit()
            
            if nuevo_estado == 'Oculto':
                flash("Producto ocultado. Ya no aparecerá en el catálogo de clientes.", "warning")
            else:
                flash("Producto activado. Vuelve a estar visible.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error al cambiar estado: {e}", "danger")
    finally:
        conn.close()
        
    return redirect('/productos')
#####################################
# ==========================================
# --- ELIMINAR PRODUCTO ---
# ==========================================
@app.route('/productos/eliminar/<int:id>', methods=['POST'])
@login_required
@admin_required
def eliminar_producto(id):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        # Intentamos borrar el producto de la base de datos
        cursor.execute("DELETE FROM producto WHERE id = %s", (id,))
        conn.commit()
        flash("Producto eliminado correctamente de la base de datos.", "success")
    except Exception as e:
        conn.rollback()
        # Si da error, normalmente es porque un cliente ya compró este producto en el pasado
        # y no se puede borrar para no arruinar el historial de pedidos.
        flash("No se puede eliminar este producto porque ya tiene pedidos asociados. Te recomendamos usar el botón 'Ocultar'.", "danger")
    finally:
        conn.close()
        
    return redirect('/productos')
# IMPORTANTE: Si en tu app.py tienes una clase "class Producto(db.Model):", 
# asegúrate de añadirle esta línea adentro para evitar errores con SQLAlchemy:
# estado = db.Column(db.String(20), default='Activo')
# ==========================================
# --- GESTIÓN DE CLIENTES (CORREGIDO) ---
# ==========================================

@app.route('/clientes') 
@login_required
@admin_required
def clientes():
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) 
    try:
        # ¡AQUÍ ESTÁ EL CAMBIO! Añadimos "estado" al SELECT
        cursor.execute("SELECT id, nombre, documento, correo, telefono, estado FROM usuario ORDER BY id DESC")
        data = cursor.fetchall()
    except Exception as e:
        print(f"Error en BD: {e}")
        data = []
    finally:
        conn.close()
    
    if data is None:
        data = []
        
    return render_template('admin/clientes.html', clientes=data)

# ==========================================
# --- NUEVA RUTA: HABILITAR / INHABILITAR --
# ==========================================
@app.route('/clientes/cambiar_estado/<int:cliente_id>/<string:nuevo_estado>')
@login_required
@admin_required
def cambiar_estado_cliente(cliente_id, nuevo_estado):
    # Validamos que el estado sea correcto por seguridad
    if nuevo_estado not in ['Habilitado', 'Inhabilitado']:
        flash('Estado no válido.', 'danger')
        return redirect(url_for('clientes'))

    conn = get_connection()
    cursor = conn.cursor()
    try:
        # Actualizamos solo la columna estado, NO borramos el registro
        cursor.execute("UPDATE usuario SET estado = %s WHERE id = %s", (nuevo_estado, cliente_id))
        conn.commit()
        
        if nuevo_estado == 'Inhabilitado':
            flash('Cliente inhabilitado correctamente. No podrá realizar operaciones, pero su historial se conserva.', 'warning')
        else:
            flash('Cliente habilitado y restaurado correctamente.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error al cambiar el estado: {str(e)}', 'danger')
    finally:
        conn.close()
        
    return redirect(url_for('clientes'))


@app.route('/admin/nuevo_cliente', methods=['GET', 'POST'])
# ... (de aquí en adelante, tu código de nuevo_cliente sigue exactamente igual)

@app.route('/admin/nuevo_cliente', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_nuevo_cliente():  # Nombre de función único para evitar el AssertionError
    if request.method == 'POST':
        nombre = request.form['nombre']
        correo = request.form['correo']
        documento = request.form['documento']
        telefono = request.form['telefono']
        
        # Usamos el documento como clave por defecto
        clave_hash = bcrypt.generate_password_hash(documento).decode('utf-8')

        conn = get_connection()
        cursor = conn.cursor()
        try:
            # Validar si ya existe el documento
            cursor.execute("SELECT id FROM usuario WHERE documento = %s", (documento,))
            if cursor.fetchone():
                flash(f"El DNI/RUC {documento} ya está registrado.", "warning")
            else:
                query = "INSERT INTO usuario (nombre, correo, documento, telefono, clave) VALUES (%s, %s, %s, %s, %s)"
                cursor.execute(query, (nombre, correo, documento, telefono, clave_hash))
                conn.commit()
                flash(f"¡Cliente {nombre} registrado con éxito!", "success")
                return redirect('/clientes')
        except Exception as e:
            flash(f"Error al guardar: {str(e)}", "danger")
        finally:
            conn.close()

    return render_template('admin/nuevo_cliente.html')
    
# --- GESTIÓN DE SEGURIDAD ---
@app.route("/cambiar_clave", methods=["GET", "POST"])
@login_required
def cambiar_clave():
    if request.method == "POST":
        if request.form["nueva"] == request.form["confirmacion"]:
            h = bcrypt.generate_password_hash(request.form["nueva"]).decode("utf-8")
            conn = get_connection(); cur = conn.cursor()
            tabla = "usuario" if session["rol"] == "cliente" else "usuarios_sistema"
            cur.execute(f"UPDATE {tabla} SET clave = %s WHERE id = %s", (h, session["usuario_id"]))
            conn.commit(); conn.close()
            flash("Clave actualizada correctamente.", "success")
            return redirect(url_for("index"))
        flash("Las claves no coinciden.", "danger")
    return render_template("cambiar_clave.html")

import requests
from flask import jsonify, request

# ========================================================
# --- SISTEMA DE MENSAJES Y CONSTATACIÓN DE PEDIDOS ---
# ========================================================

@app.route('/pedido/<int:pedido_id>/enviar_mensaje', methods=['POST'])
@login_required
def enviar_mensaje_pedido(pedido_id):
    """Ruta única para que Clientes y Admins guarden mensajes de constatación."""
    mensaje = request.form.get('mensaje')
    
    if not mensaje or not mensaje.strip():
        flash("El mensaje no puede estar vacío.", "warning")
        return redirect(request.referrer)
        
    nombre_remitente = session.get('nombre')
    rol_remitente = session.get('rol') # 'cliente' o 'admin'
    
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO pedido_mensajes (id_pedido, remitente_nombre, remitente_rol, mensaje, fecha)
            VALUES (%s, %s, %s, %s, NOW())
        """, (pedido_id, nombre_remitente, rol_remitente, mensaje.strip()))
        conn.commit()
        flash("Mensaje/Observación registrada en el historial del pedido.", "success")
    except Exception as e:
        print(f"Error al registrar mensaje: {e}")
        flash("No se pudo registrar el mensaje.", "danger")
    finally:
        conn.close()
        
    # request.referrer hace magia: devuelve al usuario de donde vino (ya sea el panel admin o cliente)
    return redirect(request.referrer)

####################################################################
@app.route('/nosotros')
def nosotros():
    return render_template('nosotros.html')

##################################################################
@app.route('/admin/nuevo_usuario_sistema', methods=['GET', 'POST'])
def admin_nuevo_usuario_sistema():
    # Proteger la ruta: Solo administradores logueados pueden entrar
    if 'admin_id' not in session or session.get('admin_rol') != 'Administrador':
        flash('Acceso denegado. Se requieren permisos de Administrador principal.', 'danger')
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        nombre_completo = request.form['nombre_completo']
        correo = request.form['correo']
        password = request.form['password']
        rol = request.form['rol']
        estado = request.form['estado']
        
        hashed_password = generate_password_hash(password)
        
        cursor = db.cursor()
        sql = """INSERT INTO usuarios_sistema 
                 (nombre_completo, correo, password, rol, estado) 
                 VALUES (%s, %s, %s, %s, %s)"""
        valores = (nombre_completo, correo, hashed_password, rol, estado)
        
        try:
            cursor.execute(sql, valores)
            db.commit()
            flash('Usuario del sistema registrado correctamente.', 'success')
            return redirect(url_for('admin_usuarios_sistema')) # Asumiendo que tienes una vista que los lista
        except Exception as e:
            flash(f'Error al registrar el usuario: {str(e)}', 'danger')
            
    return render_template('admin/nuevo_usuario_sistema.html')
############################################################################

@app.route('/api/consultar')
def consultar_api():
    numero = request.args.get('numero')
    tipo = request.args.get('tipo')
    
    if not numero or not tipo:
        return jsonify({"error": "Faltan parámetros"}), 400
        
    # Tu token de Decolecta
    token = 'sk_14915.2lHvs9UhJxBgNufMNSeDN9ZdTfyCdmBH' 
    
    if tipo == 'dni':
        url = f"https://api.decolecta.com/v1/reniec/dni?numero={numero}"
    else:
        url = f"https://api.decolecta.com/v1/sunat/ruc?numero={numero}"
        
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json'
    }
    
    try:
        # Hacemos la petición pura, sin .json() para evitar el error de diccionario
        respuesta = requests.get(url, headers=headers)
        
        if respuesta.status_code == 200:
            # Recién aquí, garantizando que todo salió bien, lo pasamos al navegador
            return jsonify(respuesta.json()), 200
        elif respuesta.status_code in [401, 403]:
            return jsonify({"error": "Error de Token: Token de Decolecta inválido."}), 401
        elif respuesta.status_code == 404:
            return jsonify({"error": "El DNI/RUC no existe."}), 404
        elif respuesta.status_code == 422:
            return jsonify({"error": "Formato de documento inválido."}), 422
        else:
            return jsonify({"error": "Error en el servidor de Decolecta."}), 500
            
    except Exception as e:
        return jsonify({"error": f"Error de conexión: {str(e)}"}), 500

if __name__ == '__main__': 
    app.run(debug=True)