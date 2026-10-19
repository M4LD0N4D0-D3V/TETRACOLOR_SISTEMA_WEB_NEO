import psycopg2
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
import os
from dotenv import load_dotenv


# Cargar variables
load_dotenv()

db = SQLAlchemy()

class TipoDocumento(db.Model):
    __tablename__ = 'tipo_documento'

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False, unique=True)
    estado = db.Column(db.String(20), default='Activo')

    # CORRECCIÓN: Cambiamos 'tipo_documento_rel' por 'tipo_documento'
    usuarios = db.relationship('Usuario', backref='tipo_documento', lazy=True)

class MetodoPago(db.Model):
    __tablename__ = 'metodo_pago'

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False, unique=True)
    estado = db.Column(db.String(20), default='Activo')

    # Relaciones
    pedidos = db.relationship('Pedido', backref='metodo_pago_rel', lazy=True)
    pagos = db.relationship('HistorialPagos', backref='metodo_pago_rel', lazy=True)


class Usuario(db.Model):
    __tablename__ = 'usuario'

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    apellidos = db.Column(db.String(100), nullable=True)  # Agregado para resolver inconsistencia
    correo = db.Column(db.String(100), nullable=False, unique=True)
    clave = db.Column(db.String(255), nullable=False)
    telefono = db.Column(db.String(20), nullable=True)
    documento = db.Column(db.String(20), nullable=True)
    estado = db.Column(db.String(50), default='Habilitado')
    id_tipo_documento = db.Column(db.Integer, db.ForeignKey('tipo_documento.id'), nullable=True)
    direccion = db.Column(db.Text, nullable=True)
    departamento = db.Column(db.String(100), nullable=True)
    provincia = db.Column(db.String(100), nullable=True) 
    distrito = db.Column(db.String(100), nullable=True) 
    fecha_registro = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)

    # Relaciones
    #tipo_documento = db.relationship('TipoDocumento', backref='usuarios')


class UsuariosSistema(db.Model):
    __tablename__ = 'usuarios_sistema'

    id = db.Column(db.Integer, primary_key=True)
    correo = db.Column(db.String(100), unique=True)
    nombres = db.Column(db.String(100))
    apellidos = db.Column(db.String(100))
    clave = db.Column(db.String(255))
    rol = db.Column(db.String(50), nullable=False)
    direccion = db.Column(db.Text)
    telefono = db.Column(db.String(20))
    id_tipo_documento = db.Column(db.Integer, db.ForeignKey('tipo_documento.id'))
    documento = db.Column(db.String(20), nullable=True)
    estado = db.Column(db.String(50), default='Habilitado')
    departamento = db.Column(db.String(100), nullable=True)
    provincia = db.Column(db.String(100), nullable=True)
    distrito = db.Column(db.String(100), nullable=True)
    # Relaciones
    pedidos_atendidos = db.relationship('Pedido', backref='empleado', lazy=True)


class CategoriaProducto(db.Model):
    __tablename__ = 'categoria_producto'

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.Text)
    estado = db.Column(db.String(20), default='Activo')

    # Relaciones existentes y nuevas
    productos = db.relationship('Producto', backref='categoria', lazy=True)
    variaciones = db.relationship('VariacionMaterial', backref='categoria', lazy=True, cascade="all, delete-orphan")
    
class VariacionMaterial(db.Model):
    __tablename__ = 'variacion_material'

    id = db.Column(db.Integer, primary_key=True)
    id_categoria = db.Column(db.Integer, db.ForeignKey('categoria_producto.id'), nullable=False)
    
    # El tipo agrupará las opciones: Ej. "Tipo de Tela", "Tipo de Tinta", "Acabado"
    tipo_variacion = db.Column(db.String(50), nullable=False) 
    
    # El nombre de la opción: Ej. "Jersey de Algodón", "Plastisol", "Foil Dorado"
    nombre = db.Column(db.String(100), nullable=False) 
    
    # Costo adicional: Si elegir "Foil Dorado" suma S/ 5.00 al precio base
    costo_extra = db.Column(db.Numeric(10, 2), default=0.00) 
    
    estado = db.Column(db.String(20), default='Activo')

class Producto(db.Model):
    __tablename__ = 'producto' 

    id = db.Column(db.Integer, primary_key=True)
    nombre_producto = db.Column(db.String(150), nullable=False) 
    
    # Precios (Nuevos campos)
    precio = db.Column(db.Numeric(10, 2), nullable=False) # Precio Unitario Normal
    precio_mayor = db.Column(db.Numeric(10, 2), nullable=True) # Precio al por mayor (Ej: 35.00)
    cantidad_minima_mayor = db.Column(db.Integer, default=12) # A partir de cuántas unidades se aplica el precio_mayor

    descripcion = db.Column(db.Text)    
    imagen = db.Column(db.String(255))
    estado = db.Column(db.String(20), default='Activo')
    id_categoria = db.Column(db.Integer, db.ForeignKey('categoria_producto.id'))

    # Relaciones
    pedidos = db.relationship('Pedido', backref='producto', lazy=True)


class Pedido(db.Model):
    __tablename__ = 'pedido'

    id = db.Column(db.Integer, primary_key=True)
    id_usuario_sistema = db.Column(db.Integer, db.ForeignKey('usuarios_sistema.id'))
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuario.id'))
    id_producto = db.Column(db.Integer, db.ForeignKey('producto.id'))
    fecha = db.Column(db.DateTime, default=datetime.utcnow)
    especificaciones = db.Column(db.Text)
    estado = db.Column(db.String(20), default='Pendiente')
    cantidad = db.Column(db.Integer, default=1)
    archivo_diseno = db.Column(db.String(255))
    adelanto = db.Column(db.Numeric(10, 2), default=0.00)
    total_pagado = db.Column(db.Numeric(10, 2), default=0.00)
    id_metodo_pago = db.Column(db.Integer, db.ForeignKey('metodo_pago.id'))

    # Relaciones
    pagos = db.relationship('HistorialPagos', backref='pedido', lazy=True, cascade="all, delete-orphan")
    mensajes = db.relationship('PedidoMensajes', backref='pedido', lazy=True, cascade="all, delete-orphan")
    detalles = db.relationship('DetallePedido', backref='pedido', lazy=True, cascade="all, delete-orphan")
    envio = db.relationship('EnvioPedido', backref='pedido', uselist=False, cascade="all, delete-orphan")


class HistorialPagos(db.Model):
    __tablename__ = 'historial_pagos'

    id = db.Column(db.Integer, primary_key=True)
    id_pedido = db.Column(db.Integer, db.ForeignKey('pedido.id'), nullable=False)
    monto = db.Column(db.Numeric(10, 2), nullable=False)
    fecha = db.Column(db.DateTime, default=datetime.utcnow)
    referencia_voucher = db.Column(db.String(255))
    id_metodo_pago = db.Column(db.Integer, db.ForeignKey('metodo_pago.id'))


class DetallePedido(db.Model):
    __tablename__ = 'detalle_pedido'

    id = db.Column(db.Integer, primary_key=True)
    id_pedido = db.Column(db.Integer, db.ForeignKey('pedido.id'), nullable=False)
    id_producto = db.Column(db.Integer, db.ForeignKey('producto.id'), nullable=False)
    cantidad = db.Column(db.Integer, nullable=False, default=1)
    precio_unitario = db.Column(db.Numeric(10, 2), nullable=False)
    especificaciones = db.Column(db.Text)
    archivo_diseno = db.Column(db.String(255))  


class PedidoMensajes(db.Model):
    __tablename__ = 'pedido_mensajes'

    id = db.Column(db.Integer, primary_key=True)
    id_pedido = db.Column(db.Integer, db.ForeignKey('pedido.id'), nullable=False)
    remitente_nombre = db.Column(db.String(100), nullable=False)
    remitente_rol = db.Column(db.String(50), nullable=False)
    mensaje = db.Column(db.Text, nullable=False)
    fecha = db.Column(db.DateTime, default=datetime.utcnow)
    archivo_adjunto = db.Column(db.String(255))


class EnvioPedido(db.Model):
    __tablename__ = 'envio_pedido'

    id = db.Column(db.Integer, primary_key=True)
    id_pedido = db.Column(db.Integer, db.ForeignKey('pedido.id'), nullable=False, unique=True)
    tipo_entrega = db.Column(db.String(50), default='Recojo en Tienda')
    direccion_destino = db.Column(db.Text)
    departamento = db.Column(db.String(100))
    provincia = db.Column(db.String(100))
    distrito = db.Column(db.String(100))
    agencia_transporte = db.Column(db.String(100))
    numero_guia = db.Column(db.String(100))
    costo_envio = db.Column(db.Numeric(10, 2), default=0.00)


class RegistroSeguridad(db.Model):
    __tablename__ = 'registro_seguridad'

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), nullable=False, unique=True)
    correo_intentado = db.Column(db.String(100))
    intentos = db.Column(db.Integer, default=1)
    bloqueado_hasta = db.Column(db.DateTime, nullable=True)
    ultima_actividad = db.Column(db.DateTime, default=datetime.utcnow)

class Proveedor(db.Model):
    __tablename__ = 'proveedor'
    id = db.Column(db.Integer, primary_key=True)
    razon_social = db.Column(db.String(150), nullable=False)
    ruc = db.Column(db.String(11), unique=True, nullable=False)
    contacto = db.Column(db.String(100))
    telefono = db.Column(db.String(20))
    correo = db.Column(db.String(100))
    direccion = db.Column(db.Text)
    estado = db.Column(db.String(20), default='Activo')

class Inventario(db.Model):
    __tablename__ = 'inventario'
    id = db.Column(db.Integer, primary_key=True)
    nombre_insumo = db.Column(db.String(150), nullable=False)
    descripcion = db.Column(db.Text)
    unidad_medida = db.Column(db.String(20), nullable=False)
    stock_actual = db.Column(db.Numeric(10, 2), default=0.00)
    stock_minimo = db.Column(db.Numeric(10, 2), default=0.00)
    estado = db.Column(db.String(20), default='Activo')

class MovimientoInventario(db.Model):
    __tablename__ = 'movimiento_inventario'
    id = db.Column(db.Integer, primary_key=True)
    id_insumo = db.Column(db.Integer, db.ForeignKey('inventario.id'))
    tipo_movimiento = db.Column(db.String(20), nullable=False)
    cantidad = db.Column(db.Numeric(10, 2), nullable=False)
    motivo = db.Column(db.String(255))
    id_proveedor = db.Column(db.Integer, db.ForeignKey('proveedor.id'))
    id_usuario_sistema = db.Column(db.Integer, db.ForeignKey('usuarios_sistema.id'))
    fecha = db.Column(db.DateTime, default=datetime.utcnow)

def get_connection():
    uri = os.getenv("DATABASE_URL")
    if uri and uri.startswith("postgresql+psycopg2://"):
        uri = uri.replace("postgresql+psycopg2://", "postgresql://", 1)
    elif uri and uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql://", 1)
    return psycopg2.connect(uri)