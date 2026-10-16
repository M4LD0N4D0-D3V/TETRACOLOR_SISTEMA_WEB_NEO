import csv
import requests
from db import get_connection

def poblar_desde_csv():
    print("Iniciando conexión a la base de datos...")
    conn = get_connection()
    cursor = conn.cursor()

    # El enlace RAW directo de tu hallazgo
    url = "https://raw.githubusercontent.com/geodir/ubigeo-peru/master/geodir-ubigeo-inei.csv"
    print("Descargando el archivo CSV completo...")
    
    try:
        response = requests.get(url)
        response.encoding = 'utf-8'
        
        if response.status_code != 200:
            print(f"Error de descarga. Código: {response.status_code}")
            return

        # Leemos el texto como CSV
        csv_data = response.text.splitlines()
        reader = csv.reader(csv_data, delimiter=',')
        
        # Saltamos la primera línea (que dice "Ubigeo, Distrito, Provincia...")
        next(reader, None)

        departamentos = {}
        provincias = {}
        distritos = []

        print("Procesando datos...")
        for row in reader:
            if len(row) < 4:
                continue
                
            ubigeo = row[0].strip()
            distrito = row[1].strip()
            provincia = row[2].strip()
            departamento = row[3].strip()

            # Lógica del ubigeo: "010203" -> Dep: "01", Prov: "0102", Dist: "010203"
            id_dep = ubigeo[:2]
            id_prov = ubigeo[:4]
            id_dist = ubigeo
            
            # Evitamos duplicados guardándolos en diccionarios
            if id_dep not in departamentos:
                departamentos[id_dep] = departamento
                
            if id_prov not in provincias:
                provincias[id_prov] = (id_dep, provincia)
                
            distritos.append((id_dist, id_prov, distrito))

        # ==========================================
        # INSERCIÓN EN LA BASE DE DATOS
        # ==========================================
        print(f"Insertando {len(departamentos)} Departamentos...")
        for id_dep, nombre in departamentos.items():
            cursor.execute("""
                INSERT INTO departamentos (id, nombre) 
                VALUES (%s, %s) ON CONFLICT (id) DO NOTHING
            """, (id_dep, nombre))

        print(f"Insertando {len(provincias)} Provincias...")
        for id_prov, data in provincias.items():
            cursor.execute("""
                INSERT INTO provincias (id, departamento_id, nombre) 
                VALUES (%s, %s, %s) ON CONFLICT (id) DO NOTHING
            """, (id_prov, data[0], data[1]))

        print(f"Insertando {len(distritos)} Distritos...")
        for dist in distritos:
            cursor.execute("""
                INSERT INTO distritos (id, provincia_id, nombre) 
                VALUES (%s, %s, %s) ON CONFLICT (id) DO NOTHING
            """, (dist[0], dist[1], dist[2]))

        conn.commit()
        print("¡ÉXITO TOTAL! Toda la base de datos del Ubigeo de Perú ha sido cargada en Supabase.")

    except Exception as e:
        conn.rollback()
        print(f"Ocurrió un error: {e}")
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    poblar_desde_csv()