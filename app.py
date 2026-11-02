import os
import re
import time
import requests
import psycopg2.extras
import mercadopago
import uuid
from datetime import datetime, timedelta
from functools import wraps
import pandas as pd
import openpyxl
from dotenv import load_dotenv
load_dotenv()

# Inicializar Mercado Pago con el token del .env
mp_access_token = os.getenv("MERCADOPAGO_ACCESS_TOKEN")
sdk = mercadopago.SDK(mp_access_token)

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
from sqlalchemy import func, text
from db import db, Usuario, Producto, Pedido, TipoDocumento, get_connection, MetodoPago, HistorialPagos, Reclamo 
from db import CategoriaProducto, VariacionMaterial
from werkzeug.exceptions import RequestEntityTooLarge
from zoneinfo import ZoneInfo
from io import BytesIO
from supabase import create_client, Client


app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY", "clave_por_defecto_respaldo")

# Configuración de Supabase Storage
supabase_url = os.environ.get("SUPABASE_URL")
supabase_key = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(supabase_url, supabase_key)

# Configurar Zona Horaria de Lima
LIMA_TZ = ZoneInfo("America/Lima")

@app.template_filter('lima_time')
def lima_time_filter(dt):
    """Filtro Jinja2 para convertir cualquier Timestamp UTC a Hora Local de Lima."""
    if not dt:
        return ""
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt)
        except ValueError:
            return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo("UTC"))
    dt_lima = dt.astimezone(LIMA_TZ)
    return dt_lima.strftime('%d/%m/%Y %H:%M')


# ==========================================
# CLASES Y FUNCIONES AUXILIARES PARA PAGINACIÓN
# ==========================================
class PaginacionDict:
    """Simula el objeto de paginación de SQLAlchemy para consultas raw psycopg2."""
    def __init__(self, total, page, per_page):
        self.total = total
        self.page = page
        self.per_page = per_page
        self.pages = (total + per_page - 1) // per_page if per_page > 0 else 1
        self.has_prev = page > 1
        self.has_next = page < self.pages
        self.prev_num = page - 1
        self.next_num = page + 1
        self.first = ((page - 1) * per_page) + 1 if total > 0 else 0
        self.last = min(page * per_page, total)

    def iter_pages(self, left_edge=1, right_edge=1, left_current=2, right_current=2):
        last = 0
        for num in range(1, self.pages + 1):
            if num <= left_edge or \
               (num >= self.page - left_current and num <= self.page + right_current) or \
               num > self.pages - right_edge:
                if last + 1 != num:
                    yield None
                yield num
                last = num

def obtener_parametros_paginacion():
    try:
        page = int(request.args.get('page', 1))
        if page < 1: page = 1
    except ValueError:
        page = 1
    try:
        per_page = int(request.args.get('per_page', 10))
        if per_page not in [10, 25, 50, 100]:
            per_page = 10
    except ValueError:
        per_page = 10
    return page, per_page

# ==========================================
# CONFIGURACIÓN DE BASE DE DATOS (.ENV)
# ==========================================
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
if app.config['SQLALCHEMY_DATABASE_URI'] and app.config['SQLALCHEMY_DATABASE_URI'].startswith("postgresql://"):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace("postgresql://", "postgresql+psycopg2://", 1)
elif app.config['SQLALCHEMY_DATABASE_URI'] and app.config['SQLALCHEMY_DATABASE_URI'].startswith("postgres://"):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace("postgres://", "postgresql+psycopg2://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db.init_app(app)
bcrypt = Bcrypt(app)



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

# Decorador para proteger rutas restringidas a administradores
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or getattr(current_user, 'rol', None) != 'Admin':
            flash("Acceso denegado: Se requieren permisos de administrador.", "danger")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


# ==========================================
# CONFIGURACIÓN DE SUBIDA DE ARCHIVOS (RUTAS ABSOLUTAS)
# ==========================================
# Se usa app.root_path para garantizar que la carpeta siempre se cree dentro de tu proyecto
UPLOAD_FOLDER_DISENOS = os.path.join(app.root_path, 'static', 'uploads', 'disenos')
UPLOAD_FOLDER_MENSAJES = os.path.join(app.root_path, 'static', 'uploads', 'mensajes')

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER_DISENOS
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024

# Crear las subcarpetas físicas automáticamente dentro del proyecto si no existen
os.makedirs(UPLOAD_FOLDER_DISENOS, exist_ok=True)
os.makedirs(UPLOAD_FOLDER_MENSAJES, exist_ok=True)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'ai', 'cdr', 'zip'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.errorhandler(RequestEntityTooLarge)
def handle_file_size_error(e):
    flash("El archivo adjunto supera el tamaño máximo permitido. Intenta subiendo un archivo de menor peso.", "danger")
    return redirect(request.referrer or url_for('index'))    

###########################################################


# 1. Definir extensiones permitidas estrictamente
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'ai', 'cdr', 'zip'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 2. Función segura para guardar archivos
def guardar_archivo_seguro(archivo_obj, carpeta_destino):
    if not archivo_obj or archivo_obj.filename == '':
        return None
        
    if not allowed_file(archivo_obj.filename):
        flash("Extensión de archivo no permitida. Sube solo imágenes, PDFs o archivos de diseño.", "danger")
        return None

    # secure_filename elimina caracteres peligrosos (como / o \ o ..)
    nombre_seguro = secure_filename(archivo_obj.filename)
    
    # Opcional pero RECOMENDADO: Agregar un UUID para evitar sobreescritura de archivos con el mismo nombre
    nombre_unico = f"{uuid.uuid4().hex}_{nombre_seguro}"
    
    ruta_completa = os.path.join(carpeta_destino, nombre_unico)
    archivo_obj.save(ruta_completa)
    
    return nombre_unico # Esto es lo que guardas en la base de datos (ej. en Pedido.archivo_diseno)

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
# PASO 1: PÁGINA PRINCIPAL (Muestra solo las CATEGORÍAS como en la imagen 1)
@app.route("/")
def index():
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Traemos solo las categorías para la pantalla inicial
        cursor.execute("SELECT * FROM categoria_producto WHERE estado = 'Activo' ORDER BY id ASC")
        categorias_activas = cursor.fetchall()
    except Exception as e:
        print(f"Error al cargar categorías: {e}")
        categorias_activas = []
    finally:
        conn.close()
        
    return render_template("index.html", categorias=categorias_activas)

# PASO 2: VISTA DE LA CATEGORÍA (Muestra los PRODUCTOS de esa categoría como en la imagen 2)
@app.route("/categoria/<int:id_categoria>")
def ver_categoria(id_categoria):
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Obtenemos los datos de la categoría actual
        cursor.execute("SELECT * FROM categoria_producto WHERE id = %s", (id_categoria,))
        categoria = cursor.fetchone()
        
        # Obtenemos TODOS los productos que pertenecen a ESTA categoría específica
        cursor.execute("SELECT * FROM producto WHERE id_categoria = %s AND (estado = 'Activo' OR estado IS NULL)", (id_categoria,))
        productos_categoria = cursor.fetchall()
    except Exception as e:
        print(f"Error al cargar productos de la categoría: {e}")
        categoria = None
        productos_categoria = []
    finally:
        conn.close()
        
    if not categoria:
        flash("La categoría no existe.", "warning")
        return redirect(url_for('index'))
        
    return render_template("categoria_productos.html", categoria=categoria, productos=productos_categoria)

# PASO 3: DETALLE DEL PRODUCTO (Donde se elige tela, tinta, etc.)
# (Aquí usamos la ruta /producto/<int:id> que ya habíamos configurado en el paso anterior)

@app.route("/producto/<int:id>")
def detalle_producto(id):
    # 1. Buscamos el producto
    producto = Producto.query.get_or_404(id)
    
    # 2. Traemos todas las variaciones de materiales que pertenecen a la categoría de este producto
    variaciones = VariacionMaterial.query.filter_by(
        id_categoria=producto.id_categoria, 
        estado='Activo'
    ).all()

    # 3. Agrupamos las variaciones por su tipo (Para generar los Selects dinámicos)
    # Ejemplo de resultado: {'Tipo de Tela': [Obj(Jersey), Obj(Franela)], 'Tipo de Tinta': [Obj(Plastisol)]}
    opciones_agrupadas = {}
    for var in variaciones:
        if var.tipo_variacion not in opciones_agrupadas:
            opciones_agrupadas[var.tipo_variacion] = []
        opciones_agrupadas[var.tipo_variacion].append(var)

    return render_template(
        'detalle.html', 
        producto=producto, 
        opciones_agrupadas=opciones_agrupadas
    )

@app.route("/crear_pedido_cliente", methods=["POST"])
@login_required
def crear_pedido_cliente():
    # 1. Obtener ID de usuario y parámetros del formulario
    id_usuario = session.get('usuario_id')
    id_producto = request.form.get("id_producto")
    cantidad = request.form.get("cantidad", 1, type=int)
    
    material = request.form.get("material", "N/A").strip()
    notas = request.form.get("notas", "").strip()
    fecha_sugerida = request.form.get("fecha_sugerida")
    monto_pago_raw = request.form.get("monto_pago") or request.form.get("monto_adelanto")
    metodo_pago_nombre = request.form.get("metodo_pago", "Transferencia").strip()
    referencia_voucher = request.form.get("referencia_voucher", "").strip()
    
    especificaciones = f"Material: {material} | Notas: {notas}"
    
    # 2. Manejo Seguro de la Imagen del Diseño (usando la función auxiliar para Supabase)
    url_imagen_publica = None
    file = request.files.get('imagen_diseno')
    
    if file and file.filename != '':
        if allowed_file(file.filename):
            try:
                # Sube a la carpeta 'disenos' dentro de Supabase Storage
                url_imagen_publica = subir_a_supabase(file, carpeta="disenos")
            except Exception as e:
                print(f"Error al subir imagen a Supabase: {e}")
                flash("Hubo un problema al subir la imagen al servidor. Intenta nuevamente.", "danger")
                return redirect(request.referrer or url_for('index'))
        else:
            flash("Formato de imagen no permitido. Usa JPG, PNG o PDF.", "danger")
            return redirect(request.referrer or url_for('index'))

    # 3. Inserción con SQLAlchemy ORM
    try:
        nuevo_pedido = Pedido(
            id_usuario=id_usuario,
            id_producto=id_producto,
            cantidad=cantidad,
            especificaciones=especificaciones,
            archivo_diseno=url_imagen_publica, 
            estado='Pendiente',
            fecha_sugerida=fecha_sugerida
        )
        db.session.add(nuevo_pedido)
        db.session.flush() 

        # 4. Registrar Pago/Adelanto si existe un monto
        if monto_pago_raw:
            try:
                monto_pago = float(monto_pago_raw)
                if monto_pago > 0:
                    mp = MetodoPago.query.filter(MetodoPago.nombre.ilike(metodo_pago_nombre)).first()
                    mp_id = mp.id if mp else None

                    pago = HistorialPagos(
                        id_pedido=nuevo_pedido.id,
                        monto=monto_pago,
                        id_metodo_pago=mp_id,
                        referencia_voucher=referencia_voucher
                    )
                    db.session.add(pago)

                    nuevo_pedido.adelanto = monto_pago
                    nuevo_pedido.total_pagado = monto_pago

            except ValueError:
                flash("El monto de pago ingresado no es un número válido.", "warning")

        db.session.commit()
        return redirect(url_for('pedido_exitoso', id=nuevo_pedido.id))

    except Exception as e:
        db.session.rollback()
        print(f"Error al registrar pedido/pago: {e}")
        flash("Ocurrió un error al procesar el pedido.", "danger")
        return redirect(request.referrer or url_for('index'))

@app.route("/pedido_exitoso/<int:id>")
@login_required
def pedido_exitoso(id):
    return render_template("pedido_exitoso.html", pedido_id=id)


#####################################################################################################################
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    ip_cliente = request.remote_addr
    
    permitido, tiempo_restante = verificar_seguridad_ip(ip_cliente)
    if not permitido:
        flash(f"Acceso restringido. No puedes registrar cuentas en este momento. Espera {tiempo_restante} segundos.", "danger")
        return render_template('registro.html'), 403

    if request.method == 'POST':
        documento = request.form["documento"]
        tipo_doc = request.form.get("tipo_doc", "dni")
        
        tipo_bd = TipoDocumento.query.filter(TipoDocumento.nombre.ilike(tipo_doc)).first()
        id_tipo_doc = tipo_bd.id if tipo_bd else None
        
        # --- SEPARACIÓN CORRECTA DE NOMBRES Y APELLIDOS ---
        if tipo_doc.lower() == "ruc":
            nombre = request.form.get("razon_social", "").strip()
            apellidos = ""
        else:
            nombre = request.form.get("nombres", "").strip()
            paterno = request.form.get("apellido_paterno", "").strip()
            materno = request.form.get("apellido_materno", "").strip()
            apellidos = f"{paterno} {materno}".strip()

        telefono = request.form["telefono"]
        correo = request.form["correo"]
        clave = request.form["clave"]
        
        direccion = request.form.get("direccion", "")
        departamento = request.form.get("departamento", "")
        provincia = request.form.get("provincia", "")
        distrito = request.form.get("distrito", "")
        
        if not re.match(r'^\d{9}$', telefono):
            flash("El número de celular debe tener exactamente 9 dígitos numéricos.", "danger")
            return redirect(url_for("registro"))
            
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', correo):
            flash("El formato del correo electrónico no es válido.", "danger")
            return redirect(url_for("registro"))
        
        if Usuario.query.filter_by(correo=correo).first() or Usuario.query.filter_by(documento=documento).first():
            flash("El correo o el documento ya están registrados.", "danger")
            return redirect(url_for("registro"))
            
        pw_hash = bcrypt.generate_password_hash(clave).decode('utf-8')
        
        # Guardamos asignando explícitamente nombre y apellidos por separado
        nuevo = Usuario(
            id_tipo_documento=id_tipo_doc,
            documento=documento, 
            nombre=nombre,
            apellidos=apellidos,  # <--- Asignado correctamente a su columna
            telefono=telefono, 
            correo=correo, 
            clave=pw_hash,
            direccion=direccion,
            departamento=departamento,
            provincia=provincia,
            distrito=distrito,
            estado="Habilitado"
        )
        
        db.session.add(nuevo)
        db.session.commit()
        
        flash("¡Registro exitoso! Ahora puedes iniciar sesión.", "success")
        return redirect(url_for("login"))
        
    return render_template("registro.html")

##############################################################################################################################

@app.route("/registro_presencial", methods=["GET", "POST"])
@login_required       # 1. Exige autenticación
@admin_required      # 2. Exige rol de administrador
def registro_presencial():

    if request.method == "POST":
        # Limpieza de espacios en blanco accidentales
        documento = request.form.get("documento", "").strip()
        tipo_doc = request.form.get("tipo_doc", "dni").strip()
        telefono = request.form.get("telefono", "").strip()
        correo = request.form.get("correo", "").strip()
        clave = request.form.get("clave", "").strip()

        # --- BUSCAR TIPO DE DOCUMENTO EN BD ---
        tipo_bd = TipoDocumento.query.filter(TipoDocumento.nombre.ilike(tipo_doc)).first()
        
        if not tipo_bd:
            flash(f"El tipo de documento '{tipo_doc}' no es válido en el sistema.", "danger")
            return redirect(url_for("registro_presencial"))
            
        id_tipo_doc = tipo_bd.id

        # --- LÓGICA DE NOMBRE Y APELLIDOS ---
        # Separación para mantener compatibilidad con la columna 'apellidos' usada en comprobantes
        if tipo_doc.lower() == "ruc":
            nombre = request.form.get("razon_social", "").strip()
            apellidos = ""
        else:
            nombre = request.form.get("nombres", "").strip()
            paterno = request.form.get("apellido_paterno", "").strip()
            materno = request.form.get("apellido_materno", "").strip()
            apellidos = f"{paterno} {materno}".strip()

        # --- VALIDACIONES ESTRICTAS ---
        if not re.match(r'^\d{9}$', telefono):
            flash("El número de celular debe tener exactamente 9 dígitos numéricos.", "danger")
            return redirect(url_for("registro_presencial"))

        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', correo):
            flash("El formato del correo electrónico no es válido.", "danger")
            return redirect(url_for("registro_presencial"))

        # --- VALIDAR DUPLICADOS ---
        existe_correo = Usuario.query.filter_by(correo=correo).first()
        existe_documento = Usuario.query.filter_by(documento=documento).first()

        if existe_correo or existe_documento:
            flash("El correo o documento ya se encuentran registrados.", "danger")
            return redirect(url_for("registro_presencial"))

        # --- CONTRASEÑA POR DEFECTO ---
        if not clave:
            clave = documento

        pw_hash = bcrypt.generate_password_hash(clave).decode('utf-8')

        # --- INSERCIÓN EN BASE DE DATOS (CON ROLLBACK SEGURO) ---
        try:
            nuevo = Usuario(
                id_tipo_documento=id_tipo_doc,
                documento=documento,
                nombre=nombre,
                apellidos=apellidos,  # Agregado para que no falle al generar comprobantes
                telefono=telefono,
                correo=correo,
                clave=pw_hash,
                estado="Habilitado"
            )

            db.session.add(nuevo)
            db.session.commit()

            flash("Cliente presencial registrado correctamente.", "success")
            return redirect(url_for("clientes"))

        except Exception as e:
            db.session.rollback()
            flash("Ocurrió un error en la base de datos al registrar el usuario.", "danger")
            return redirect(url_for("registro_presencial"))

    return render_template("admin/nuevo_cliente.html")
########################################################################################################

@app.route('/login', methods=['GET', 'POST'])
def login():
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
            # --- CORRECCIÓN AUTH-02: Validar si la cuenta está inhabilitada ---
            if usuario.get('estado') == 'Inhabilitado':
                flash("Tu cuenta se encuentra inhabilitada. Por favor, contacta con soporte.", "danger")
                return render_template('login.html')

            session['usuario_id'] = usuario['id']
            session['nombre'] = usuario['nombre']
            session['rol'] = 'cliente'
            
            resetear_ip(ip_cliente)
            return redirect('/')
        
        else:
            bloqueado_ahora = registrar_fallo_ip(ip_cliente, correo) 
            
            if bloqueado_ahora:
                flash(f"Has superado el límite de {MAX_INTENTOS} intentos permitidos. Tu IP ha sido bloqueada por {MINUTOS_BLOQUEO} minutos.", "danger")
            else:
                conn = get_connection()
                cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cursor.execute("SELECT intentos FROM registro_seguridad WHERE ip = %s", (ip_cliente,))
                registro = cursor.fetchone()
                conn.close()
                
                intentos_actuales = registro['intentos'] if registro else 1
                intentos_restantes = MAX_INTENTOS - intentos_actuales
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
@app.route('/pedidos') 
@login_required
@admin_required
def pedidos():
    page, per_page = obtener_parametros_paginacion()
    offset = (page - 1) * per_page

    conn = get_connection() 
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    try:
        # Total de pedidos
        cursor.execute("SELECT COUNT(*) AS total FROM pedido")
        total = cursor.fetchone()['total']

        # 1. Traer Pedidos principales sumando dinámicamente lo pagado en historial_pagos (PAGINADO)
        cursor.execute("""
            SELECT p.id, p.id_usuario, us.nombres AS empleado, CONCAT(c.nombre, ' ', COALESCE(c.apellidos, '')) AS cliente, 
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
            LIMIT %s OFFSET %s
        """, (per_page, offset)) 
        pedidos_data = cursor.fetchall() 
        
        # 2. Traer mensajes y el historial SOLO para los pedidos que se están mostrando en esta página
        pedido_ids = [p['id'] for p in pedidos_data] if pedidos_data else []
        mensajes_por_pedido = {}
        historial_por_cliente = {}

        if pedido_ids:
            cursor.execute("SELECT * FROM pedido_mensajes WHERE id_pedido = ANY(%s) ORDER BY fecha ASC", (pedido_ids,))
            for msg in cursor.fetchall():
                pid = msg['id_pedido']
                mensajes_por_pedido.setdefault(pid, []).append(msg)

        for ped in pedidos_data:
            uid = ped['id_usuario']
            historial_por_cliente.setdefault(uid, []).append(ped)
            
    finally:
        conn.close()    

    paginacion = PaginacionDict(total, page, per_page)
    return render_template(
        'pedidos.html', 
        pedidos=pedidos_data, 
        mensajes=mensajes_por_pedido,
        historial_clientes=historial_por_cliente,
        paginacion=paginacion
    )


    ##################################
@app.route('/pedido/<int:id>')
@login_required
def ver_detalle_pedido(id):
    conn = get_connection()
    # Usamos RealDictCursor compatible con PostgreSQL/psycopg2
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) 

    try:
        # 1. Obtener datos del pedido
        cursor.execute("SELECT * FROM pedido WHERE id = %s", (id,))
        pedido = cursor.fetchone()

        if not pedido:
            flash('El pedido solicitado no existe.', 'warning')
            return redirect(url_for('pedidos'))
            
        # Validación de seguridad: un cliente no puede ver pedidos de otros
        if session.get('rol') == 'cliente' and pedido['id_usuario'] != session.get('usuario_id'):
            flash('No tienes permiso para ver este pedido.', 'danger')
            return redirect(url_for('mis_pedidos'))

        # 2. Obtener historial de pagos (Nombre de tabla correcto)
        cursor.execute("SELECT * FROM historial_pagos WHERE id_pedido = %s ORDER BY fecha ASC", (id,))
        pagos = cursor.fetchall()

        # 3. Obtener historial de la bitácora
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
    return redirect(request.referrer or url_for('pedidos'))

@app.route('/admin/historial_cliente/<int:id_usuario>')
@login_required
@admin_required
def historial_cliente(id_usuario):
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    # 1. Consultar primero los datos del cliente (incluyendo apellidos)
    cursor.execute("SELECT nombre, apellidos FROM usuario WHERE id = %s", (id_usuario,))
    cliente_info = cursor.fetchone()
    
    if not cliente_info:
        conn.close()
        flash("El cliente solicitado no existe.", "danger")
        return redirect(url_for('clientes'))
        
    # Unir nombre y apellidos para mandarlo a la vista
    nombre_completo = f"{cliente_info['nombre']} {cliente_info['apellidos'] or ''}".strip()
    
    # 2. Consultar sus pedidos
    query = """
        SELECT p.*, prod.nombre_producto
        FROM pedido p
        JOIN producto prod ON p.id_producto = prod.id
        WHERE p.id_usuario = %s
        ORDER BY p.fecha DESC
    """
    cursor.execute(query, (id_usuario,))
    pedidos_usuario = cursor.fetchall()
    
    conn.close()
    
    # Renderizamos la plantilla (incluso si pedidos_usuario está vacío)
    return render_template('admin/historial.html', pedidos=pedidos_usuario, cliente=nombre_completo)

#####################################################21
@app.route('/admin/seguridad')
@login_required
@admin_required
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
@app.route('/pedido/actualizar_pago/<int:id>', methods=['POST'])
@login_required
@admin_required
def actualizar_pago(id):
    monto_pago = float(request.form.get('monto_pago', 0))
    metodo_pago_nombre = request.form.get('metodo_pago') # Recibimos el texto del select

    if monto_pago <= 0:
        flash('El monto ingresado debe ser mayor a cero.', 'danger')
        return redirect(url_for('pedidos'))

    conn = get_connection()
    # Importante usar RealDictCursor aquí si tu código original espera diccionarios
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

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

        # Como usamos RealDictCursor, leemos como diccionario seguro
        adelanto_actual = float(pedido['adelanto'] or 0.0)
        total_pagado_bd = float(pedido['total_pagado'] or 0.0)
        precio_unitario = float(pedido['precio'] or 0.0)
        cantidad = int(pedido['cantidad'] or 1)

        # 2. Buscar el ID del método de pago basado en el nombre que vino del formulario
        cursor.execute("SELECT id FROM metodo_pago WHERE nombre = %s", (metodo_pago_nombre,))
        mp_res = cursor.fetchone()
        
        if not mp_res:
            flash(f"El método de pago '{metodo_pago_nombre}' no existe en el sistema.", 'danger')
            return redirect(url_for('pedidos'))
            
        mp_id = mp_res['id']

        # Si el costo total está en 0, lo calculamos
        precio_total = total_pagado_bd if total_pagado_bd > 0 else (precio_unitario * cantidad)
        nuevo_adelanto = adelanto_actual + monto_pago

        # Evitar cobrar de más
        if nuevo_adelanto > precio_total:
            nuevo_adelanto = precio_total

        # 3. Actualizar la tabla pedido usando la llave foránea correcta (id_metodo_pago)
        cursor.execute("""
            UPDATE pedido 
            SET adelanto = %s,
                total_pagado = %s,
                id_metodo_pago = %s
            WHERE id = %s
        """, (nuevo_adelanto, precio_total, mp_id, id))

        # 4. Registrar el abono individual en historial_pagos (con id_metodo_pago)
        cursor.execute("""
            INSERT INTO historial_pagos (id_pedido, monto, id_metodo_pago, fecha, referencia_voucher)
            VALUES (%s, %s, %s, CURRENT_TIMESTAMP, %s)
        """, (id, monto_pago, mp_id, 'Abono registrado por Admin'))

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

# ==========================================
# --- GESTION/VISTA DE PRODUCTOS ---
# ==========================================
@app.route('/productos')
@login_required
@admin_required
def productos():
    page, per_page = obtener_parametros_paginacion()
    offset = (page - 1) * per_page
    busqueda = request.args.get('q', '').strip()

    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # 1. Traer todas las categorías activas para los <select> de los modales
        cursor.execute("SELECT id, nombre FROM categoria_producto WHERE estado = 'Activo' ORDER BY nombre")
        categorias = cursor.fetchall()

        if busqueda:
            filtro = f"%{busqueda}%"
            # Cuenta total de registros filtrados
            cursor.execute("SELECT COUNT(*) AS total FROM producto WHERE nombre_producto ILIKE %s", (filtro,))
            total = cursor.fetchone()['total']

            # Trae registros filtrados y paginados (CON JOIN A CATEGORÍA)
            cursor.execute("""
                SELECT p.id, p.nombre_producto, p.precio, p.estado, p.id_categoria, c.nombre AS categoria_nombre 
                FROM producto p
                LEFT JOIN categoria_producto c ON p.id_categoria = c.id
                WHERE p.nombre_producto ILIKE %s
                ORDER BY p.id DESC 
                LIMIT %s OFFSET %s
            """, (filtro, per_page, offset))
        else:
            # Lógica original sin búsqueda
            cursor.execute("SELECT COUNT(*) AS total FROM producto")
            total = cursor.fetchone()['total']

            # Trae registros (CON JOIN A CATEGORÍA)
            cursor.execute("""
                SELECT p.id, p.nombre_producto, p.precio, p.estado, p.id_categoria, c.nombre AS categoria_nombre 
                FROM producto p
                LEFT JOIN categoria_producto c ON p.id_categoria = c.id
                ORDER BY p.id DESC 
                LIMIT %s OFFSET %s
            """, (per_page, offset))
            
        lista_productos = cursor.fetchall()
    except Exception as e:
        print(f"Error cargando productos: {e}")
        lista_productos = []
        categorias = []
        total = 0
    finally:
        conn.close()
        
    paginacion = PaginacionDict(total, page, per_page)
    # 2. Enviamos 'categorias' a la plantilla
    return render_template('productos.html', productos=lista_productos, categorias=categorias, paginacion=paginacion)

# ==========================================
# --- GUARDAR NUEVO PRODUCTO ---
# ==========================================
@app.route('/productos/guardar', methods=['POST'])
@login_required
@admin_required
def guardar_producto():
    nombre = request.form.get('nombre_producto')
    precio = request.form.get('precio')
    id_categoria = request.form.get('id_categoria')
    imagen = request.files.get('imagen')
    
    if nombre and precio and id_categoria:
        url_imagen_publica = None
        
        # Subir imagen del producto a Supabase (carpeta 'productos')
        if imagen and imagen.filename != '':
            try:
                url_imagen_publica = subir_a_supabase(imagen, carpeta="productos")
            except Exception as e:
                print(f"Error al subir imagen de producto a Supabase: {e}")
                flash("Hubo un error al subir la imagen del producto.", "danger")
                return redirect('/productos')

        # Guardar en base de datos la URL pública
        nuevo_prod = Producto(
            nombre_producto=nombre, 
            precio=float(precio),
            id_categoria=int(id_categoria),
            imagen=url_imagen_publica
        )
        db.session.add(nuevo_prod)
        db.session.commit()
        flash("Producto creado exitosamente en la nube.", "success")
    else:
        flash("Datos inválidos. Asegúrate de completar todos los campos.", "danger")
        
    return redirect('/productos')


# ==========================================
# --- MODIFICAR PRODUCTOS Y PRECIOS ---
# ==========================================
@app.route('/productos/editar/<int:id>', methods=['POST'])
@login_required
@admin_required
def editar_producto(id):
    producto = Producto.query.get_or_404(id)
    
    nuevo_nombre = request.form.get('nombre_producto')
    nuevo_precio = request.form.get('precio')
    nueva_categoria = request.form.get('id_categoria')
    nueva_imagen = request.files.get('imagen')
    
    if nuevo_nombre and nuevo_precio and nueva_categoria:
        producto.nombre_producto = nuevo_nombre
        producto.precio = float(nuevo_precio)
        producto.id_categoria = int(nueva_categoria)
        
        # Subir la nueva imagen a Supabase solo si el administrador subió una nueva
        if nueva_imagen and nueva_imagen.filename != '':
            try:
                url_imagen = subir_a_supabase(nueva_imagen, carpeta="productos")
                if url_imagen:
                    producto.imagen = url_imagen
            except Exception as e:
                print(f"Error al actualizar la imagen en Supabase: {e}")
                flash("Error al subir la nueva imagen a Supabase.", "danger")

        db.session.commit()
        flash(f"El producto '{producto.nombre_producto}' fue modificado exitosamente.", "success")
    else:
        flash("Todos los campos obligatorios deben estar llenos.", "danger")
        
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
    page, per_page = obtener_parametros_paginacion()
    offset = (page - 1) * per_page
    busqueda = request.args.get('q', '').strip()

    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) 
    try:
        if busqueda:
            filtro = f"%{busqueda}%"
            # Puedes buscar en múltiples columnas usando OR
            query_count = "SELECT COUNT(*) AS total FROM usuario WHERE nombre ILIKE %s OR apellidos ILIKE %s OR documento ILIKE %s OR correo ILIKE %s"
            cursor.execute(query_count, (filtro, filtro, filtro, filtro))
            total = cursor.fetchone()['total']

            query_data = """
                SELECT id, nombre, apellidos, documento, correo, telefono, estado 
                FROM usuario 
                WHERE nombre ILIKE %s OR apellidos ILIKE %s OR documento ILIKE %s OR correo ILIKE %s
                ORDER BY id DESC 
                LIMIT %s OFFSET %s
            """
            cursor.execute(query_data, (filtro, filtro, filtro, filtro, per_page, offset))
        else:
            cursor.execute("SELECT COUNT(*) AS total FROM usuario")
            total = cursor.fetchone()['total']

            cursor.execute("""
                SELECT id, nombre, apellidos, documento, correo, telefono, estado 
                FROM usuario 
                ORDER BY id DESC 
                LIMIT %s OFFSET %s
            """, (per_page, offset))
            
        data = cursor.fetchall()
    except Exception as e:
        print(f"Error en BD: {e}")
        data = []
        total = 0
    finally:
        conn.close()
    
    paginacion = PaginacionDict(total, page, per_page)
    return render_template('admin/clientes.html', clientes=data, paginacion=paginacion)

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

# ========================================================
# --- SISTEMA DE MENSAJES Y CONSTATACIÓN DE PEDIDOS ---
# ========================================================
@app.route('/pedido/<int:id_pedido>/enviar_mensaje', methods=['POST'])
@login_required
def enviar_mensaje(id_pedido):
    mensaje = request.form.get('mensaje', '').strip()
    archivo = request.files.get('adjunto')

    rol_actual = session.get('rol', 'cliente')
    if rol_actual not in ['administrador', 'asistente', 'consultor', 'cliente']:
        rol_actual = 'cliente'

    remitente_nombre = session.get('nombre') or ('Administrador' if rol_actual != 'cliente' else 'Cliente')

    url_imagen_publica = None
    if archivo and archivo.filename != '':
        if allowed_file(archivo.filename):
            try:
                url_imagen_publica = subir_a_supabase(archivo, carpeta="mensajes")
            except Exception as e:
                print(f"Error al subir adjunto a Supabase: {e}")
                flash('Hubo un problema al subir el archivo. Inténtalo de nuevo.', 'danger')
                return redirect(request.referrer or url_for('pedidos'))
        else:
            flash('Tipo de archivo no permitido. Sube imágenes (PNG, JPG) o PDF.', 'danger')
            return redirect(request.referrer or url_for('pedidos'))

    if not mensaje and not url_imagen_publica:
        flash('Escribe un mensaje o adjunta un archivo/comprobante.', 'warning')
        return redirect(request.referrer or url_for('pedidos'))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        if rol_actual == 'cliente':
            cursor.execute("SELECT id FROM pedido WHERE id = %s AND id_usuario = %s", (id_pedido, session.get('usuario_id')))
            if not cursor.fetchone():
                flash('No tienes permiso para comentar en este pedido.', 'danger')
                return redirect(url_for('mis_pedidos'))

        cursor.execute("""
            INSERT INTO pedido_mensajes (id_pedido, mensaje, archivo_adjunto, remitente_rol, remitente_nombre, fecha)
            VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
        """, (id_pedido, mensaje, url_imagen_publica, rol_actual, remitente_nombre))

        conn.commit()
        flash('Mensaje / Comprobante registrado correctamente en la bitácora.', 'success')
    except Exception as e:
        conn.rollback()
        print(f"Error al registrar mensaje: {e}")
        flash('Error al registrar en la bitácora.', 'danger')
    finally:
        cursor.close()
        conn.close()

    return redirect(request.referrer or url_for('pedidos'))

#############
@app.route('/pedido/<int:id_pedido>/confirmar_fecha', methods=['POST'])
@login_required
def confirmar_fecha(id_pedido):
    nueva_fecha = request.form.get('fecha_confirmada')
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        # Actualiza la fecha en la tabla de pedidos
        cursor.execute("UPDATE pedido SET fecha_sugerida = %s WHERE id = %s", (nueva_fecha, id_pedido))
        
        # Insertar un mensaje automático en el chat usando las columnas correctas de tu tabla
        mensaje_sistema = f"El administrador ha confirmado la fecha de entrega para: {nueva_fecha}"
        cursor.execute("""
            INSERT INTO pedido_mensajes (id_pedido, remitente_rol, remitente_nombre, mensaje, fecha) 
            VALUES (%s, %s, %s, %s, NOW())
        """, (id_pedido, 'administrador', 'Sistema', mensaje_sistema))
        
        conn.commit()
        flash('Fecha de entrega confirmada exitosamente.', 'success')
    except Exception as e:
        conn.rollback()
        print(f"Error al confirmar fecha: {e}")
        flash('Ocurrió un error al confirmar la fecha.', 'danger')
    finally:
        cursor.close()
        conn.close()
        
    return redirect(request.referrer)
    
########################

@app.route('/libro_reclamaciones', methods=['GET', 'POST'])
def libro_reclamaciones():
    if request.method == 'POST':
        try:
            nuevo_reclamo = Reclamo(
                tipo_documento=request.form.get('tipo_documento'),
                documento=request.form.get('documento'),
                nombres=request.form.get('nombres'),
                correo=request.form.get('correo'),
                telefono=request.form.get('telefono'),
                tipo=request.form.get('tipo', 'Reclamo'),
                descripcion=request.form.get('descripcion')
            )
            db.session.add(nuevo_reclamo)
            db.session.commit()
            flash(f"Tu {nuevo_reclamo.tipo} ha sido registrado exitosamente con el ticket #{nuevo_reclamo.id}. Te contactaremos pronto.", "success")
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash("Ocurrió un error al registrar tu solicitud. Intenta nuevamente.", "danger")
            
    return render_template('libro_reclamaciones.html')
####################################################################
@app.route('/nosotros')
def nosotros():
    return render_template('nosotros.html')

##################################################################
@app.route('/admin/nuevo_usuario_sistema', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_nuevo_usuario_sistema():
    conn = get_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        nombres = request.form['nombre_completo']
        id_tipo_doc = request.form.get('id_tipo_documento')
        documento = request.form.get('documento')
        correo = request.form['correo']
        telefono = request.form.get('telefono', '')        
        direccion = request.form.get('direccion', '')
        departamento = request.form.get('departamento', '')
        provincia = request.form.get('provincia', '')
        distrito = request.form.get('distrito', '')
        password = request.form['password']
        rol = request.form['rol'].lower()  # Se convierte a minúsculas para cumplir el CHECK de BD ('administrador', 'asistente', 'consultor')
        estado = request.form.get('estado', 'Activo')
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        sql = """INSERT INTO usuarios_sistema 
                 (nombres, correo, clave, rol, estado, id_tipo_documento, documento, telefono, direccion, departamento, provincia, distrito) 
                 VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        valores = (nombres, correo, hashed_password, rol, estado, id_tipo_doc, documento, telefono, direccion, departamento, provincia, distrito)
        
        try:
            cursor.execute(sql, valores)
            conn.commit()
            flash('Personal del sistema registrado correctamente.', 'success')
            return redirect('/pedidos')
        except Exception as e:
            conn.rollback()
            flash(f'Error al registrar el usuario: {str(e)}', 'danger')
        finally:
            conn.close()

    # Si es GET, consultamos los tipos de documento activos para el selector
    cursor.execute("SELECT id, nombre FROM tipo_documento WHERE estado = 'Activo'")
    tipos_doc = cursor.fetchall()
    conn.close()

    return render_template('admin/nuevo_usuario_sistema.html', tipos_doc=tipos_doc)

#######
@app.route('/admin/pedido/<int:id_pedido>')
@login_required
@admin_required
def ver_detalle_pedido_individual(id_pedido):
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    try:
        # 1. Traer datos del pedido, el producto y el cliente
        query = """
            SELECT p.*, 
                   pr.nombre_producto, pr.precio AS precio_unitario,
                   u.nombre AS cliente_nombre, u.apellidos AS cliente_apellidos, 
                   u.telefono AS cliente_telefono, u.correo AS cliente_correo
            FROM pedido p
            JOIN producto pr ON p.id_producto = pr.id
            JOIN usuario u ON p.id_usuario = u.id
            WHERE p.id = %s
        """
        cursor.execute(query, (id_pedido,))
        pedido = cursor.fetchone()

        if not pedido:
            flash("El pedido solicitado no existe o fue eliminado.", "danger")
            return redirect(url_for('pedidos'))

        # 2. Traer la bitácora de mensajes de este pedido específico (si existe la tabla)
        try:
            cursor.execute("SELECT * FROM pedido_mensajes WHERE id_pedido = %s ORDER BY fecha ASC", (id_pedido,))
            mensajes = cursor.fetchall()
        except:
            mensajes = [] # Por si tu tabla de mensajes se llama diferente

    except Exception as e:
        print(f"Error al cargar el detalle del pedido: {e}")
        flash("Ocurrió un error al consultar el pedido.", "danger")
        return redirect(url_for('pedidos'))
    finally:
        conn.close()

    # Preparar campos calculados
    pedido['cliente_completo'] = f"{pedido['cliente_nombre']} {pedido['cliente_apellidos'] or ''}".strip()
    pedido['costo_total'] = float(pedido['cantidad'] * pedido['precio_unitario'])
    pedido['saldo'] = float(pedido['costo_total']) - float(pedido['adelanto'] or 0.0)

    return render_template('admin/detalle_pedido.html', pedido=pedido, mensajes=mensajes)

###############################

# ==========================================
# DASHBOARD ADMINISTRATIVO (VERSIÓN OPTIMIZADA CON VISTAS)
# ==========================================
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    # ... código existente ...
    # ----------------------------------------
    # 1. MÉTRICAS DE CLIENTES
    # ----------------------------------------
    total_clientes = Usuario.query.count()
    
    # Consultar la vista de nuevos clientes del mes
    query_nuevos = db.session.execute(text("SELECT nuevos_clientes FROM vista_nuevos_usuarios_mes")).fetchone()
    clientes_mes = query_nuevos[0] if query_nuevos and query_nuevos[0] else 0

    # ----------------------------------------
    # 2. MÉTRICAS GLOBALES (Ingresos y Saldo)
    # ----------------------------------------
    total_pedidos = Pedido.query.count()
    ingresos_totales = db.session.query(func.sum(Pedido.total_pagado)).scalar() or 0.0

    # Saldo pendiente: lo que cuesta el producto menos lo que ya pagaron
    saldo_pendiente = db.session.query(
        func.sum((Pedido.cantidad * Producto.precio) - Pedido.total_pagado)
    ).select_from(Pedido).join(Producto, Pedido.id_producto == Producto.id)\
     .filter(Pedido.estado != 'Anulado').scalar() or 0.0

    # ----------------------------------------
    # 3. HISTÓRICO PARA GRÁFICAS (Usando la vista)
    # ----------------------------------------
    query_historico = db.session.execute(text("SELECT mes, total_ingresos FROM vista_ingresos_historicos")).fetchall()
    historico = [{'mes': row[0], 'total_ingresos': float(row[1])} for row in query_historico]

    # Calcular Crecimiento de ventas (Mes actual vs Mes anterior)
    crecimiento_ventas = 0.0
    if len(historico) >= 2:
        ventas_actual = historico[-1]['total_ingresos']
        ventas_anterior = historico[-2]['total_ingresos']
        if ventas_anterior > 0:
            crecimiento_ventas = ((ventas_actual - ventas_anterior) / ventas_anterior) * 100
    elif len(historico) == 1:
        crecimiento_ventas = 100.0

    # ----------------------------------------
    # 4. ESTADOS DE PEDIDOS Y CUMPLIMIENTO (Usando la vista)
    # ----------------------------------------
    query_estados = db.session.execute(text("SELECT estado, cantidad FROM vista_distribucion_estados")).fetchall()
    estados = [{'estado': row[0], 'cantidad': int(row[1])} for row in query_estados]

    # Calcular Tasa de cumplimiento
    pedidos_entregados = sum(e['cantidad'] for e in estados if e['estado'] in ['Completado', 'Entregado'])
    tasa_cumplimiento = (pedidos_entregados / total_pedidos * 100) if total_pedidos > 0 else 0.0

    # ----------------------------------------
    # 5. PREPARAR DATOS PARA CHART.JS
    # ----------------------------------------
    chart_meses = [item['mes'] for item in historico]
    chart_ingresos = [float(item['total_ingresos']) for item in historico]
    chart_estados_labels = [item['estado'] for item in estados]
    chart_estados_data = [item['cantidad'] for item in estados]

    ingresos_data = {
        'ingresos_totales': ingresos_totales,
        'cantidad_pedidos': total_pedidos
    }

    return render_template(
        'admin/dashboard.html',
        ingresos=ingresos_data,
        saldo_pendiente=saldo_pendiente,
        crecimiento_ventas=round(crecimiento_ventas, 2),
        tasa_cumplimiento=round(tasa_cumplimiento, 2),
        clientes_mes=clientes_mes,
        clientes_totales=total_clientes,
        chart_meses=chart_meses,
        chart_ingresos=chart_ingresos,
        chart_estados_labels=chart_estados_labels,
        chart_estados_data=chart_estados_data
    )
# ==========================================
# PASARELA DE PAGO CON ADELANTO DINÁMICO
# ==========================================
@app.route('/api/crear_preferencia_mp/<int:pedido_id>', methods=['POST'])
@login_required
def crear_preferencia_mp(pedido_id):
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    try:
        cursor.execute('''
            SELECT p.id, pr.nombre_producto, p.cantidad, pr.precio, p.total_pagado, p.adelanto
            FROM pedido p
            JOIN producto pr ON p.id_producto = pr.id
            WHERE p.id = %s AND p.id_usuario = %s
        ''', (pedido_id, session['usuario_id']))
        pedido = cursor.fetchone()
        
        if not pedido:
            return jsonify({"error": "Pedido no encontrado o no autorizado"}), 404
            
        costo_total = float(pedido['total_pagado']) if float(pedido['total_pagado']) > 0 else float(pedido['cantidad'] * pedido['precio'])
        adelanto_actual = float(pedido['adelanto'] or 0)
        saldo_pendiente = round(costo_total - adelanto_actual, 2)
        
        if saldo_pendiente <= 0.01:
            return jsonify({"error": "Este pedido ya se encuentra cancelado al 100%."}), 400

        # Capturar el monto enviado desde el cliente
        data = request.get_json() or {}
        monto_a_pagar = float(data.get('monto', saldo_pendiente))
        
        if monto_a_pagar <= 0:
            return jsonify({"error": "El monto a pagar debe ser mayor a S/ 0.00"}), 400
            
        if round(monto_a_pagar, 2) > saldo_pendiente:
            return jsonify({"error": f"El monto ingresado (S/ {monto_a_pagar:.2f}) no puede superar el saldo pendiente (S/ {saldo_pendiente:.2f})."}), 400

        # Base URL dinámica (Detecta automáticamente si estás en Local, Codespaces o Render)
        base_url = request.host_url.rstrip('/')

        preference_data = {
            "items": [
                {
                    "title": f"Abono / Adelanto - Pedido #{pedido_id} ({pedido['nombre_producto']})",
                    "quantity": 1,
                    "currency_id": "PEN",
                    "unit_price": round(monto_a_pagar, 2)
                }
            ],
            "back_urls": {
                "success": f"{base_url}/pago_mp_respuesta/exito/{pedido_id}",
                "failure": f"{base_url}/pago_mp_respuesta/fallo/{pedido_id}",
                "pending": f"{base_url}/pago_mp_respuesta/pendiente/{pedido_id}"
            },
            "auto_return": "approved",
            "external_reference": str(pedido_id)
        }
        
        preference_response = sdk.preference().create(preference_data)
        preference = preference_response["response"]
        
        if "init_point" not in preference:
            return jsonify({"error": "Error al conectar con Mercado Pago."}), 400

        link_pago = preference.get("sandbox_init_point") or preference.get("init_point")
        return jsonify({"init_point": link_pago})
        
    except Exception as e:
        print(f"Error MercadoPago: {e}")
        return jsonify({"error": "Error interno al procesar la pasarela."}), 500
    finally:
        conn.close()


@app.route('/pago_mp_respuesta/<string:estado>/<int:id_pedido>')
@login_required
def pago_mp_respuesta(estado, id_pedido):
    payment_id = request.args.get('payment_id')
    
    if estado == 'exito' and payment_id:
        payment_info = sdk.payment().get(payment_id)
        
        if payment_info["status"] == 200 and payment_info["response"]["status"] == "approved":
            monto_abonado = float(payment_info["response"]["transaction_amount"])
            
            conn = get_connection()
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            try:
                cursor.execute("SELECT id FROM historial_pagos WHERE referencia_voucher = %s", (f"MP-{payment_id}",))
                if not cursor.fetchone():
                    cursor.execute("""
                        SELECT adelanto, total_pagado, 
                               (cantidad * (SELECT precio FROM producto WHERE id = id_producto)) AS costo_calc 
                        FROM pedido WHERE id = %s
                    """, (id_pedido,))
                    ped = cursor.fetchone()
                    
                    costo_total = float(ped['total_pagado']) if float(ped['total_pagado']) > 0 else float(ped['costo_calc'])
                    adelanto_previo = float(ped['adelanto'] or 0)
                    nuevo_adelanto = min(adelanto_previo + monto_abonado, costo_total)
                    
                    cursor.execute("SELECT id FROM metodo_pago WHERE nombre = 'Mercado Pago'")
                    mp_method = cursor.fetchone()
                    mp_id = mp_method['id'] if mp_method else None
                    
                    # Registrar abono con hora de Lima
                    cursor.execute("""
                        INSERT INTO historial_pagos (id_pedido, monto, id_metodo_pago, referencia_voucher, fecha)
                        VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP AT TIME ZONE 'America/Lima')
                    """, (id_pedido, monto_abonado, mp_id, f"MP-{payment_id}"))
                    
                    cursor.execute("""
                        UPDATE pedido SET adelanto = %s, total_pagado = %s WHERE id = %s
                    """, (nuevo_adelanto, costo_total, id_pedido))
                    
                    conn.commit()
                    
                    saldo_restante = costo_total - nuevo_adelanto
                    if saldo_restante <= 0.01:
                        flash(f"¡Pago completo procesado! El pedido #{id_pedido} fue cancelado al 100%.", "success")
                    else:
                        flash(f"¡Adelanto de S/ {monto_abonado:.2f} registrado con éxito! Saldo restante: S/ {saldo_restante:.2f}", "success")
                else:
                    flash("Este pago ya había sido procesado previamente.", "info")
            except Exception as e:
                conn.rollback()
                print(f"Error al registrar pago MP: {e}")
                flash("Error al registrar el pago en la base de datos.", "warning")
            finally:
                cursor.close()
                conn.close()
        else:
            flash("El pago no fue aprobado por Mercado Pago.", "danger")
            
    elif estado == 'fallo':
        flash(f"El proceso de pago del pedido #{id_pedido} fue cancelado o rechazado.", "danger")
    elif estado == 'pendiente':
        flash(f"El abono para el pedido #{id_pedido} quedó en estado pendiente.", "warning")
        
    return redirect(url_for('mis_pedidos'))
############################################################################

@app.route('/api/consultar')
def consultar_api():
    numero = request.args.get('numero')
    tipo = request.args.get('tipo')
    
    if not numero or not tipo:
        return jsonify({"error": "Faltan parámetros"}), 400
        
    token = os.getenv("DECOLECTA_TOKEN") 
    
    if tipo == 'dni':
        url = f"https://api.decolecta.com/v1/reniec/dni?numero={numero}"
    else:
        url = f"https://api.decolecta.com/v1/sunat/ruc?numero={numero}"
        
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json'
    }
    
    try:
        # AGREGADO: timeout=5 para evitar bloqueos del servidor
        respuesta = requests.get(url, headers=headers, timeout=5)
        
        if respuesta.status_code == 200:
            return jsonify(respuesta.json()), 200
        elif respuesta.status_code in [401, 403]:
            return jsonify({"error": "Error de Token: Token de Decolecta inválido."}), 401
        elif respuesta.status_code == 404:
            return jsonify({"error": "El DNI/RUC no existe."}), 404
        elif respuesta.status_code == 422:
            return jsonify({"error": "Formato de documento inválido."}), 422
        else:
            return jsonify({"error": "Error en el servidor de Decolecta."}), 500
            
    except requests.exceptions.Timeout:
        return jsonify({"error": "El servicio de consulta excedió el tiempo de respuesta. Intenta manualmente."}), 504
    except Exception as e:
        return jsonify({"error": f"Error de conexión: {str(e)}"}), 500

#######

@app.route('/admin/reportes')
@login_required
@admin_required
def panel_reportes():
    return render_template('admin/reportes.html')

@app.route('/admin/reportes/generar', methods=['POST'])
@login_required
@admin_required
def generar_reporte():
    tipo_reporte = request.form.get('tipo_reporte')
    formato = request.form.get('formato')
    fecha_inicio = request.form.get('fecha_inicio')
    fecha_fin = request.form.get('fecha_fin')
    
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    try:
        if tipo_reporte == 'ventas':
            # Consulta con cálculo real de recaudación y saldos
            query = """
                SELECT p.id AS "ID Pedido", 
                       p.fecha AS "Fecha", 
                       CONCAT(u.nombre, ' ', COALESCE(u.apellidos, '')) AS "Cliente",
                       pr.nombre_producto AS "Producto", 
                       p.cantidad AS "Cantidad",
                       (p.cantidad * pr.precio) AS "Total General (S/)",
                       COALESCE(
                           (SELECT SUM(monto) FROM historial_pagos hp WHERE hp.id_pedido = p.id), 
                           p.adelanto, 
                           0
                       ) AS "Recaudado/Abonado (S/)",
                       ((p.cantidad * pr.precio) - COALESCE(
                           (SELECT SUM(monto) FROM historial_pagos hp WHERE hp.id_pedido = p.id), 
                           p.adelanto, 
                           0
                       )) AS "Saldo Pendiente (S/)",
                       p.estado AS "Estado"
                FROM pedido p
                LEFT JOIN usuario u ON p.id_usuario = u.id
                LEFT JOIN producto pr ON p.id_producto = pr.id
                WHERE DATE(p.fecha) BETWEEN %s AND %s
                ORDER BY p.fecha DESC
            """
            cursor.execute(query, (fecha_inicio, fecha_fin))
            datos = cursor.fetchall()
            nombre_archivo = f"Reporte_Ventas_{fecha_inicio}_al_{fecha_fin}"

        elif tipo_reporte == 'deudores':
            # Consulta de Cuentas por Cobrar
            query = """
                SELECT p.id AS "ID Pedido", 
                       CONCAT(u.nombre, ' ', COALESCE(u.apellidos, '')) AS "Cliente",
                       u.telefono AS "Teléfono",
                       (p.cantidad * pr.precio) AS "Total General (S/)",
                       COALESCE(
                           (SELECT SUM(monto) FROM historial_pagos hp WHERE hp.id_pedido = p.id), 
                           p.adelanto, 
                           0
                       ) AS "Abonado (S/)",
                       ((p.cantidad * pr.precio) - COALESCE(
                           (SELECT SUM(monto) FROM historial_pagos hp WHERE hp.id_pedido = p.id), 
                           p.adelanto, 
                           0
                       )) AS "Deuda Pendiente (S/)"
                FROM pedido p
                LEFT JOIN usuario u ON p.id_usuario = u.id
                LEFT JOIN producto pr ON p.id_producto = pr.id
                WHERE ((p.cantidad * pr.precio) - COALESCE(
                           (SELECT SUM(monto) FROM historial_pagos hp WHERE hp.id_pedido = p.id), 
                           p.adelanto, 
                           0
                       )) > 0.01
                ORDER BY "Deuda Pendiente (S/)" DESC
            """
            cursor.execute(query)
            datos = cursor.fetchall()
            nombre_archivo = "Reporte_Cuentas_Por_Cobrar"

        if not datos:
            flash("No se encontraron registros para el filtro seleccionado.", "warning")
            return redirect(url_for('panel_reportes'))

        # Formatear fechas para la salida visual/Excel
        for d in datos:
            if 'Fecha' in d and d['Fecha']:
                d['Fecha_Str'] = d['Fecha'].strftime('%d/%m/%Y %H:%M')

        # EXPORTACIÓN EXCEL
        if formato == 'excel':
            # Crear DataFrame limpiando campos innecesarios
            df_datos = [{k: v for k, v in d.items() if k != 'Fecha'} for d in datos]
            df = pd.DataFrame(df_datos)
            output = BytesIO()
            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                df.to_excel(writer, index=False, sheet_name='Reporte')
                worksheet = writer.sheets['Reporte']
                for idx, col in enumerate(df.columns):
                    max_len = max(df[col].astype(str).map(len).max(), len(col)) + 3
                    col_letter = openpyxl.utils.get_column_letter(idx + 1)
                    worksheet.column_dimensions[col_letter].width = max_len

            output.seek(0)
            return send_file(output, download_name=f"{nombre_archivo}.xlsx", as_attachment=True)

        # VISTA EJECUTIVA PARA PDF / IMPRESIÓN
        elif formato == 'pdf':
            total_general = sum(float(d.get('Total General (S/)', 0)) for d in datos)
            total_recaudado = sum(float(d.get('Recaudado/Abonado (S/)', d.get('Abonado (S/)', 0))) for d in datos)
            total_pendiente = sum(float(d.get('Saldo Pendiente (S/)', d.get('Deuda Pendiente (S/)', 0))) for d in datos)

            resumen = {
                'total_general': total_general,
                'total_recaudado': total_recaudado,
                'total_pendiente': total_pendiente,
                'cantidad_registros': len(datos)
            }
            return render_template(
                'admin/reporte_pdf.html', 
                datos=datos, 
                resumen=resumen,
                titulo=tipo_reporte.upper(),
                fecha_inicio=fecha_inicio,
                fecha_fin=fecha_fin
            )

    finally:
        conn.close()


##########################
# ==========================================
# RUTAS PARA UBIGEO LOCAL (DEPARTAMENTO, PROVINCIA, DISTRITO)
# ==========================================
@app.route('/api/departamentos')
def api_departamentos():
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute("SELECT id, nombre FROM departamentos ORDER BY nombre ASC")
    data = cursor.fetchall()
    conn.close()
    return jsonify(data)

@app.route('/api/provincias/<dep_id>')
def api_provincias(dep_id):
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute("SELECT id, nombre FROM provincias WHERE departamento_id = %s ORDER BY nombre ASC", (dep_id,))
    data = cursor.fetchall()
    conn.close()
    return jsonify(data)

@app.route('/api/distritos/<prov_id>')
def api_distritos(prov_id):
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute("SELECT id, nombre FROM distritos WHERE provincia_id = %s ORDER BY nombre ASC", (prov_id,))
    data = cursor.fetchall()
    conn.close()
    return jsonify(data)

##############################################
# ========================================================
# --- GESTIÓN DE ENVÍOS ---
# ========================================================
@app.route('/pedido/<int:id_pedido>/envio', methods=['POST'])
@login_required
@admin_required
def actualizar_envio(id_pedido):
    agencia = request.form.get('agencia_transporte')
    numero_guia = request.form.get('numero_guia')
    fecha_envio = request.form.get('fecha_envio')
    
    if not agencia or not numero_guia:
        flash("La agencia y el número de guía son obligatorios.", "warning")
        return redirect(request.referrer)

    conn = get_connection()
    cursor = conn.cursor()
    try:
        # Verificar si el pedido ya tiene un registro de envío
        cursor.execute("SELECT id FROM envio_pedido WHERE id_pedido = %s", (id_pedido,))
        envio_existente = cursor.fetchone()

        if envio_existente:
            cursor.execute("""
                UPDATE envio_pedido 
                SET agencia_transporte = %s, numero_guia = %s, fecha_envio = %s 
                WHERE id_pedido = %s
            """, (agencia, numero_guia, fecha_envio, id_pedido))
        else:
            cursor.execute("""
                INSERT INTO envio_pedido (id_pedido, agencia_transporte, numero_guia, fecha_envio) 
                VALUES (%s, %s, %s, %s)
            """, (id_pedido, agencia, numero_guia, fecha_envio))

        # Opcional: Actualizar el estado del pedido a "Enviado" automáticamente
        cursor.execute("UPDATE pedido SET estado = 'Enviado' WHERE id = %s", (id_pedido,))
        
        conn.commit()
        flash('Datos de envío y número de guía registrados con éxito.', 'success')
    except Exception as e:
        conn.rollback()
        print(f"Error al registrar envío: {e}")
        flash('Error al guardar los datos de envío.', 'danger')
    finally:
        cursor.close()
        conn.close()

    return redirect(request.referrer or url_for('pedidos'))    

#######################
def subir_a_supabase(archivo, carpeta=""):
    """
    Sube un archivo a Supabase Storage y retorna su URL pública absoluta.
    """
    if not archivo or archivo.filename == '':
        return None
    
    if allowed_file(archivo.filename):
        nombre_limpio = secure_filename(archivo.filename)
        path_destino = f"{carpeta}/{int(time.time())}_{nombre_limpio}" if carpeta else f"{int(time.time())}_{nombre_limpio}"
        
        file_bytes = archivo.read()
        supabase.storage.from_('uploads_pedidos').upload(
            path=path_destino,
            file=file_bytes,
            file_options={"content-type": archivo.content_type}
        )
        return supabase.storage.from_('uploads_pedidos').get_public_url(path_destino)
    return None

####################################
# ========================================================
# --- GENERACIÓN DE COMPROBANTES ---
# ========================================================
@app.route('/pedido/<int:id_pedido>/comprobante')
@login_required
def ver_comprobante(id_pedido):
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    try:
        # Traer datos del pedido, cliente y producto
        cursor.execute("""
            SELECT p.*, pr.nombre_producto, pr.precio, u.nombre, u.apellidos, u.documento, u.correo 
            FROM pedido p
            JOIN producto pr ON p.id_producto = pr.id
            JOIN usuario u ON p.id_usuario = u.id
            WHERE p.id = %s
        """, (id_pedido,))
        pedido = cursor.fetchone()

        if not pedido:
            flash('El pedido no existe.', 'warning')
            return redirect(url_for('pedidos'))

        # Seguridad: Si es cliente, validar que sea su propio pedido
        if session.get('rol') == 'cliente' and pedido['id_usuario'] != session.get('usuario_id'):
            flash('Acceso denegado al comprobante.', 'danger')
            return redirect(url_for('mis_pedidos'))

        # Traer historial de pagos
        cursor.execute("SELECT monto, fecha, referencia_voucher FROM historial_pagos WHERE id_pedido = %s", (id_pedido,))
        pagos = cursor.fetchall()
        
    except Exception as e:
        print(f"Error al generar comprobante: {e}")
        flash("Error al cargar el comprobante.", "danger")
        return redirect(request.referrer)
    finally:
        cursor.close()
        conn.close()

    # Necesitarás crear un archivo 'comprobante.html' en tu carpeta templates
    return render_template('comprobante.html', pedido=pedido, pagos=pagos)    
###############

# ========================================================
# --- MÓDULO DE EMISIÓN DE FACTURAS Y BOLETAS ---
# ========================================================
@app.route('/pedido/<int:id_pedido>/factura')
@login_required
def ver_factura(id_pedido):
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    try:
        # 1. Consultar datos del pedido, cliente y producto
        query = """
            SELECT p.*, pr.nombre_producto, pr.precio AS precio_unitario,
                   u.nombre AS cliente_nombre, u.apellidos AS cliente_apellidos, 
                   u.documento AS cliente_documento, u.telefono AS cliente_telefono, 
                   u.correo AS cliente_correo, u.direccion AS cliente_direccion,
                   u.departamento AS cliente_dep, u.provincia AS cliente_prov, u.distrito AS cliente_dist,
                   td.nombre AS tipo_doc_nombre
            FROM pedido p
            JOIN producto pr ON p.id_producto = pr.id
            JOIN usuario u ON p.id_usuario = u.id
            LEFT JOIN tipo_documento td ON u.id_tipo_documento = td.id
            WHERE p.id = %s
        """
        cursor.execute(query, (id_pedido,))
        pedido = cursor.fetchone()

        if not pedido:
            flash('El pedido solicitado no existe.', 'warning')
            return redirect(url_for('pedidos'))

        # Seguridad: El cliente solo puede acceder a comprobantes de sus propios pedidos
        if session.get('rol') == 'cliente' and pedido['id_usuario'] != session.get('usuario_id'):
            flash('Acceso denegado a este comprobante.', 'danger')
            return redirect(url_for('mis_pedidos'))

        # 2. Determinar si se emite FACTURA (RUC) o BOLETA (DNI)
        doc_cliente = (pedido['cliente_documento'] or '').strip()
        tipo_doc_str = (pedido['tipo_doc_nombre'] or '').lower()
        
        is_factura = 'ruc' in tipo_doc_str or len(doc_cliente) == 11
        tipo_comprobante = "FACTURA ELECTRÓNICA" if is_factura else "BOLETA DE VENTA ELECTRÓNICA"
        serie_correlativo = f"F001-{pedido['id']:06d}" if is_factura else f"B001-{pedido['id']:06d}"

        # 3. Cálculo del Desglose Fiscal (IGV 18%)
        total_general = float(pedido['cantidad'] * pedido['precio_unitario'])
        subtotal = round(total_general / 1.18, 2)
        igv = round(total_general - subtotal, 2)
        adelanto = float(pedido['adelanto'] or 0.0)
        saldo = max(0.0, round(total_general - adelanto, 2))

        cliente_completo = f"{pedido['cliente_nombre']} {pedido['cliente_apellidos'] or ''}".strip()
        direccion_completa = f"{pedido['cliente_direccion'] or ''} {pedido['cliente_dist'] or ''} {pedido['cliente_prov'] or ''}".strip() or "Lima, Perú"

        factura_data = {
            'tipo_comprobante': tipo_comprobante,
            'serie_correlativo': serie_correlativo,
            'subtotal': subtotal,
            'igv': igv,
            'total': total_general,
            'adelanto': adelanto,
            'saldo': saldo,
            'cliente_completo': cliente_completo,
            'direccion_completa': direccion_completa,
            'is_factura': is_factura
        }

    except Exception as e:
        print(f"Error al generar comprobante: {e}")
        flash("Error al procesar el comprobante.", "danger")
        return redirect(request.referrer or url_for('pedidos'))
    finally:
        cursor.close()
        conn.close()

    return render_template('factura.html', pedido=pedido, factura=factura_data)


#######################################
# ========================================================
# --- MÓDULO DE INVENTARIO Y PROVEEDORES ---
# ========================================================

@app.route('/admin/proveedores', methods=['GET', 'POST'])
@login_required
@admin_required
def gestion_proveedores():
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    if request.method == 'POST':
        razon_social = request.form.get('razon_social')
        ruc = request.form.get('ruc')
        contacto = request.form.get('contacto')
        telefono = request.form.get('telefono')
        
        try:
            cursor.execute("""
                INSERT INTO proveedor (razon_social, ruc, contacto, telefono) 
                VALUES (%s, %s, %s, %s)
            """, (razon_social, ruc, contacto, telefono))
            conn.commit()
            flash('Proveedor registrado exitosamente.', 'success')
        except Exception as e:
            conn.rollback()
            flash(f'Error al guardar proveedor: {str(e)}', 'danger')
        return redirect(url_for('gestion_proveedores'))
        
    cursor.execute("SELECT * FROM proveedor ORDER BY razon_social ASC")
    proveedores = cursor.fetchall()
    conn.close()
    return render_template('admin/proveedores.html', proveedores=proveedores)

@app.route('/admin/inventario', methods=['GET', 'POST'])
@login_required
@admin_required
def gestion_inventario():
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    if request.method == 'POST':
        nombre = request.form.get('nombre_insumo')
        unidad = request.form.get('unidad_medida')
        minimo = request.form.get('stock_minimo', 0)
        categoria = request.form.get('categoria') # NUEVO
        
        try:
            cursor.execute("""
                INSERT INTO inventario (nombre_insumo, unidad_medida, stock_minimo, categoria) 
                VALUES (%s, %s, %s, %s)
            """, (nombre, unidad, minimo, categoria))
            conn.commit()
            flash('Insumo registrado en el inventario.', 'success')
        except Exception as e:
            conn.rollback()
            flash('Error al guardar el insumo.', 'danger')
        return redirect(url_for('gestion_inventario'))
        
    page, per_page = obtener_parametros_paginacion()
    offset = (page - 1) * per_page

    cursor.execute("SELECT COUNT(*) AS total FROM inventario")
    total = cursor.fetchone()['total']

    cursor.execute("""
        SELECT * FROM inventario 
        ORDER BY nombre_insumo ASC 
        LIMIT %s OFFSET %s
    """, (per_page, offset))
    insumos = cursor.fetchall()
    
    cursor.execute("SELECT id, razon_social FROM proveedor WHERE estado = 'Activo'")
    proveedores = cursor.fetchall()
    
    conn.close()
    paginacion = PaginacionDict(total, page, per_page)
    return render_template('admin/inventario.html', insumos=insumos, proveedores=proveedores, paginacion=paginacion)

@app.route('/admin/inventario/movimiento', methods=['POST'])
@login_required
@admin_required
def movimiento_inventario():
    id_insumo = request.form.get('id_insumo')
    tipo = request.form.get('tipo_movimiento')
    motivo = request.form.get('motivo', '').strip()
    
    # Manejar conversión limpia de números y nulos
    try:
        cantidad = float(request.form.get('cantidad', 0))
    except ValueError:
        cantidad = 0.0

    raw_proveedor = request.form.get('id_proveedor')
    id_proveedor = int(raw_proveedor) if raw_proveedor and raw_proveedor.strip() != "" else None
    id_usuario = session.get('usuario_id')

    if cantidad <= 0:
        flash("La cantidad debe ser mayor a cero.", "warning")
        return redirect(url_for('gestion_inventario'))

    conn = get_connection()
    cursor = conn.cursor()
    try:
        # 1. Registrar movimiento en la tabla Kardex
        cursor.execute("""
            INSERT INTO movimiento_inventario 
            (id_insumo, tipo_movimiento, cantidad, motivo, id_proveedor, id_usuario_sistema) 
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (id_insumo, tipo, cantidad, motivo, id_proveedor, id_usuario))

        # 2. Actualizar el stock en la tabla inventario
        if tipo == 'Ingreso':
            cursor.execute("UPDATE inventario SET stock_actual = stock_actual + %s WHERE id = %s", (cantidad, id_insumo))
        else:
            cursor.execute("UPDATE inventario SET stock_actual = stock_actual - %s WHERE id = %s", (cantidad, id_insumo))

        conn.commit()
        flash(f'Movimiento de {tipo.lower()} ({cantidad}) registrado con éxito.', 'success')
    except Exception as e:
        conn.rollback()
        print(f"Error procesando movimiento de inventario: {e}")
        flash('Ocurrió un error al registrar el movimiento.', 'danger')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('gestion_inventario'))

if __name__ == '__main__': 
    app.run(debug=True)