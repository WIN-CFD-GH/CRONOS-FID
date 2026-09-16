from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash
import os
import sys
import datetime
from models import init_db, get_user_by_id, get_user_by_email, registrar_auditoria, get_db_connection, ROOT_DIR
import pandas as pd
import io
from flask import send_file

if getattr(sys, 'frozen', False):
    base_dir = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
    template_dir = os.path.join(base_dir, 'templates')
    if not os.path.exists(template_dir):
        template_dir = os.path.join(base_dir, 'app', 'templates')
    if not os.path.exists(template_dir):
        template_dir = os.path.join(os.path.dirname(sys.executable), 'app', 'templates')
    app = Flask(__name__, template_folder=template_dir)
else:
    app = Flask(__name__)

app.secret_key = 'super_secret_key_win_asesores'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return get_user_by_id(int(user_id))

def log_login_attempt(correo, found, password_valid, estado, reason):
    try:
        log_path = os.path.join(ROOT_DIR, 'logs', 'login.log')
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]\n")
            f.write(f"Correo ingresado: {correo}\n")
            f.write(f"Usuario encontrado: {'SI' if found else 'NO'}\n")
            f.write(f"Contraseña válida: {'SI' if password_valid else 'NO'}\n")
            f.write(f"Estado: {estado}\n")
            f.write(f"Motivo rechazo: {reason}\n")
            f.write("-" * 40 + "\n")
    except:
        pass

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('app_main'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('app_main'))
        
    if request.method == 'POST':
        correo = request.form.get('correo')
        password = request.form.get('password')
        
        user = get_user_by_email(correo)
        found = user is not None
        password_valid = user.check_password(password) if found else False
        estado = user.estado.upper() if found else 'N/A'
        
        if found and password_valid:
            if not user.is_active:
                log_login_attempt(correo, found, password_valid, estado, 'CUENTA INACTIVA')
                flash('Tu cuenta está inactiva. Contacta al administrador.', 'error')
                return redirect(url_for('login'))
                
            log_login_attempt(correo, found, password_valid, estado, 'N/A (ÉXITO)')
            login_user(user)
            registrar_auditoria(user.correo, "Inicio de sesión", "Sistema", request.remote_addr)
            
            # Check if primer_ingreso
            if getattr(user, 'primer_ingreso', 0) == 1:
                resp = redirect(url_for('primer_ingreso'))
            else:
                resp = redirect(url_for('app_main'))
                
            if request.form.get('remember_me'):
                resp.set_cookie('remember_email', correo, max_age=30*24*60*60)
            else:
                resp.set_cookie('remember_email', '', expires=0)
            return resp
        else:
            reason = 'NO EXISTE' if not found else 'CONTRASEÑA INVÁLIDA'
            log_login_attempt(correo, found, password_valid, estado, reason)
            flash('Correo o contraseña incorrectos', 'error')
            
    remember_email = request.cookies.get('remember_email', '')
    return render_template('login.html', remember_email=remember_email)

@app.route('/primer_ingreso', methods=['GET', 'POST'])
@login_required
def primer_ingreso():
    if current_user.primer_ingreso == 0:
        return redirect(url_for('app_main'))
        
    if request.method == 'POST':
        nueva_clave = request.form.get('nueva_clave')
        confirmar_clave = request.form.get('confirmar_clave')
        
        if nueva_clave != confirmar_clave:
            flash('Las contraseñas no coinciden.', 'error')
        elif len(nueva_clave) < 6:
            flash('La contraseña debe tener al menos 6 caracteres.', 'error')
        else:
            conn = get_db_connection()
            pw_hash = generate_password_hash(nueva_clave)
            conn.execute('UPDATE usuarios SET password_hash = ?, primer_ingreso = 0 WHERE id = ?', (pw_hash, current_user.id))
            conn.commit()
            conn.close()
            registrar_auditoria(current_user.correo, "Cambio de contraseña (Primer Ingreso)", "Seguridad", request.remote_addr)
            flash('Contraseña actualizada correctamente.', 'success')
            # Cargar el usuario actualizado en la sesión para que se refresque (opcional, pero reload es automático si se vuelve a loguear, aunque el current_user persistirá con 1 temporalmente. Mejor desloguear y volver a loguear o simplemente redirigir).
            return redirect(url_for('app_main'))
            
    return render_template('primer_ingreso.html')

@app.route('/logout')
@login_required
def logout():
    registrar_auditoria(current_user.correo, "Cierre de sesión", "Sistema", request.remote_addr)
    logout_user()
    return redirect(url_for('login'))

@app.route('/app')
@login_required
def app_main():
    if getattr(current_user, 'primer_ingreso', 0) == 1:
        return redirect(url_for('primer_ingreso'))
    return render_template('app.html', user=current_user)

@app.route('/directorio-escalamiento')
@login_required
def directorio_escalamiento():
    if getattr(current_user, 'primer_ingreso', 0) == 1:
        return redirect(url_for('primer_ingreso'))
    return render_template('directorio.html', user=current_user)

@app.route('/favicon.ico')
def favicon():
    fav_path = os.path.join(ROOT_DIR, 'favicon.ico')
    if not os.path.exists(fav_path) and getattr(sys, 'frozen', False):
        fav_path = os.path.join(getattr(sys, '_MEIPASS', os.path.dirname(sys.executable)), 'favicon.ico')
    if os.path.exists(fav_path):
        return send_file(fav_path)
    return ('', 204)

@app.route('/CRONOS_FID_icon.png')
def cronos_icon():
    icon_path = os.path.join(ROOT_DIR, 'CRONOS_FID_icon.png')
    if not os.path.exists(icon_path) and getattr(sys, 'frozen', False):
        icon_path = os.path.join(getattr(sys, '_MEIPASS', os.path.dirname(sys.executable)), 'CRONOS_FID_icon.png')
    if os.path.exists(icon_path):
        return send_file(icon_path)
    return ('', 204)



@app.route('/api/audit', methods=['POST'])
@login_required
def api_audit():
    data = request.json
    accion = data.get('accion')
    modulo = data.get('modulo')
    detalles = data.get('detalles', '')
    if accion and modulo:
        registrar_auditoria(current_user.correo, accion, modulo, request.remote_addr, detalles)
        return jsonify({"status": "success"}), 200
    return jsonify({"status": "error", "message": "Faltan datos"}), 400

import json
import re

def get_cronos_sla_metrics(conn):
    # Obtener todos los registros de auditoria del modulo CRONOS SLA
    rows = conn.execute("SELECT * FROM auditoria WHERE modulo = 'CRONOS SLA' ORDER BY id DESC").fetchall()
    
    now = datetime.datetime.now()
    today_str = now.strftime('%Y-%m-%d')
    week_ago_str = (now - datetime.timedelta(days=7)).strftime('%Y-%m-%d')
    month_start_str = now.strftime('%Y-%m-01')
    
    inicios_hoy = 0
    inicios_semana = 0
    inicios_mes = 0
    
    pausas_list = []
    reinicios_list = []
    
    rango_0_15 = 0
    rango_16_30 = 0
    rango_31_45 = 0
    rango_46_60 = 0
    rango_mas_60 = 0
    
    pausas_segundos = []
    reinicios_segundos = []
    
    criticos_45 = 0
    criticos_55 = 0
    criticos_60 = 0
    criticos_por_asesor = {}
    criticos_por_dia = {}
    
    pausas_por_asesor = {}
    reinicios_por_asesor = {}
    
    estados_dist = {'Verde': 0, 'Ámbar': 0, 'Rojo': 0, 'Crítico': 0, 'SLA Excedido': 0}
    ranking_asesores = {}
    tendencia_diaria = {}
    tabla_historica = []
    
    for r in rows:
        fecha = r['fecha']
        hora = r['hora']
        usuario = r['usuario_correo']
        accion = r['accion']
        detalles_raw = r['detalles'] or ''
        
        segundos = 0
        tiempo_str = "00:00"
        estado_str = "Verde"
        
        if detalles_raw:
            try:
                data = json.loads(detalles_raw)
                segundos = int(data.get('segundos', 0))
                tiempo_str = data.get('tiempo', f"00:{segundos:02d}")
                estado_str = data.get('estado', 'Verde')
            except Exception:
                m_t = re.search(r'Tiempo:\s*([0-9:]+)', detalles_raw)
                if m_t: tiempo_str = m_t.group(1)
                m_e = re.search(r'Estado:\s*([^|]+)', detalles_raw)
                if m_e: estado_str = m_e.group(1).strip()
                m_s = re.search(r'Segundos:\s*(\d+)', detalles_raw)
                if m_s: segundos = int(m_s.group(1))
        
        # Init estructuras
        if usuario not in ranking_asesores:
            ranking_asesores[usuario] = {
                'usuario': usuario,
                'inicios': 0,
                'pausas': 0,
                'reinicios': 0,
                'segundos_lista': []
            }
        if usuario not in criticos_por_asesor:
            criticos_por_asesor[usuario] = {'45': 0, '55': 0, '60': 0, 'total': 0}
        if usuario not in pausas_por_asesor:
            pausas_por_asesor[usuario] = 0
        if usuario not in reinicios_por_asesor:
            reinicios_por_asesor[usuario] = 0
            
        tendencia_diaria[fecha] = tendencia_diaria.get(fecha, 0) + 1
        
        # Inicios
        if 'Iniciar' in accion:
            if fecha == today_str: inicios_hoy += 1
            if fecha >= week_ago_str: inicios_semana += 1
            if fecha >= month_start_str: inicios_mes += 1
            ranking_asesores[usuario]['inicios'] += 1
            
        # Pausas
        elif 'Pausar' in accion:
            pausas_list.append({
                'fecha': fecha,
                'hora': hora,
                'usuario': usuario,
                'tiempo': tiempo_str,
                'segundos': segundos,
                'estado': estado_str
            })
            pausas_segundos.append(segundos)
            ranking_asesores[usuario]['pausas'] += 1
            ranking_asesores[usuario]['segundos_lista'].append(segundos)
            pausas_por_asesor[usuario] += 1
            
            if segundos <= 15: rango_0_15 += 1
            elif segundos <= 30: rango_16_30 += 1
            elif segundos <= 45: rango_31_45 += 1
            elif segundos <= 60: rango_46_60 += 1
            else: rango_mas_60 += 1
            
        # Reinicios
        elif 'Reiniciar' in accion:
            reinicios_list.append({
                'fecha': fecha,
                'hora': hora,
                'usuario': usuario,
                'tiempo': tiempo_str,
                'segundos': segundos,
                'estado': estado_str
            })
            reinicios_segundos.append(segundos)
            ranking_asesores[usuario]['reinicios'] += 1
            if segundos > 0:
                ranking_asesores[usuario]['segundos_lista'].append(segundos)
            reinicios_por_asesor[usuario] += 1
            
            if segundos <= 15: rango_0_15 += 1
            elif segundos <= 30: rango_16_30 += 1
            elif segundos <= 45: rango_31_45 += 1
            elif segundos <= 60: rango_46_60 += 1
            else: rango_mas_60 += 1
            
        # Alertas críticas
        if '45' in accion:
            criticos_45 += 1
            criticos_por_asesor[usuario]['45'] += 1
            criticos_por_asesor[usuario]['total'] += 1
            if fecha not in criticos_por_dia: criticos_por_dia[fecha] = {'45': 0, '55': 0, '60': 0, 'total': 0}
            criticos_por_dia[fecha]['45'] += 1
            criticos_por_dia[fecha]['total'] += 1
        elif '55' in accion:
            criticos_55 += 1
            criticos_por_asesor[usuario]['55'] += 1
            criticos_por_asesor[usuario]['total'] += 1
            if fecha not in criticos_por_dia: criticos_por_dia[fecha] = {'45': 0, '55': 0, '60': 0, 'total': 0}
            criticos_por_dia[fecha]['55'] += 1
            criticos_por_dia[fecha]['total'] += 1
        elif '60' in accion:
            criticos_60 += 1
            criticos_por_asesor[usuario]['60'] += 1
            criticos_por_asesor[usuario]['total'] += 1
            if fecha not in criticos_por_dia: criticos_por_dia[fecha] = {'45': 0, '55': 0, '60': 0, 'total': 0}
            criticos_por_dia[fecha]['60'] += 1
            criticos_por_dia[fecha]['total'] += 1
            
        # Distribución de estados
        matched = False
        for k in estados_dist.keys():
            if k.lower() in estado_str.lower():
                estados_dist[k] += 1
                matched = True
                break
        if not matched:
            estados_dist['Verde'] += 1
                
        accion_display = "Iniciar"
        if "Pausar" in accion: accion_display = "Pausar"
        elif "Reiniciar" in accion: accion_display = "Reiniciar"
        elif "45" in accion: accion_display = "Alerta 45s"
        elif "55" in accion: accion_display = "Alerta 55s"
        elif "60" in accion: accion_display = "Alerta 60s"
        
        tabla_historica.append({
            'fecha': fecha,
            'hora': hora,
            'usuario': usuario,
            'accion': accion_display,
            'tiempo': tiempo_str,
            'estado': estado_str
        })
        
    promedio_pausa = round(sum(pausas_segundos) / len(pausas_segundos), 1) if pausas_segundos else 0
    promedio_reinicio = round(sum(reinicios_segundos) / len(reinicios_segundos), 1) if reinicios_segundos else 0
    
    ranking_list = []
    for u, data in ranking_asesores.items():
        total_interacciones = data['inicios'] + data['pausas'] + data['reinicios']
        avg_seg = round(sum(data['segundos_lista']) / len(data['segundos_lista']), 1) if data['segundos_lista'] else 0
        ranking_list.append({
            'usuario': u,
            'inicios': data['inicios'],
            'pausas': data['pausas'],
            'reinicios': data['reinicios'],
            'total': total_interacciones,
            'promedio_segundos': avg_seg
        })
    ranking_list.sort(key=lambda x: (x['total'], x['inicios']), reverse=True)
    
    tendencia_fechas = sorted(tendencia_diaria.keys())
    tendencia_valores = [tendencia_diaria[f] for f in tendencia_fechas]
    
    return {
        'inicios_hoy': inicios_hoy,
        'inicios_semana': inicios_semana,
        'inicios_mes': inicios_mes,
        'total_pausas': len(pausas_list),
        'total_reinicios': len(reinicios_list),
        'promedio_pausa': promedio_pausa,
        'promedio_reinicio': promedio_reinicio,
        'rangos': {
            'r0_15': rango_0_15,
            'r16_30': rango_16_30,
            'r31_45': rango_31_45,
            'r46_60': rango_46_60,
            'rmas_60': rango_mas_60
        },
        'criticos': {
            'total_45': criticos_45,
            'total_55': criticos_55,
            'total_60': criticos_60,
            'total_general': criticos_45 + criticos_55 + criticos_60,
            'por_asesor': criticos_por_asesor,
            'por_dia': criticos_por_dia
        },
        'estados_dist': estados_dist,
        'ranking': ranking_list,
        'pausas_por_asesor': pausas_por_asesor,
        'reinicios_por_asesor': reinicios_por_asesor,
        'tendencia': {
            'fechas': tendencia_fechas,
            'valores': tendencia_valores
        },
        'tabla_historica': tabla_historica
    }

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.rol not in ['Administrador', 'Coordinador', 'Supervisor', 'Formador', 'Calidad']:
        flash('No tienes permisos para ver el dashboard', 'error')
        return redirect(url_for('app_main'))
        
    conn = get_db_connection()
    logs = conn.execute('SELECT * FROM auditoria ORDER BY id DESC LIMIT 500').fetchall()
    usuarios = conn.execute('SELECT id, nombre, correo, rol, estado FROM usuarios').fetchall()
    
    # KPI Calculation update for Eliminado
    today = datetime.datetime.now().strftime('%Y-%m-%d')
    activos = conn.execute('SELECT COUNT(DISTINCT usuario_correo) FROM auditoria WHERE fecha = ?', (today,)).fetchone()[0]
    
    consultas = conn.execute('SELECT COUNT(*) FROM auditoria WHERE accion LIKE "%Búsqueda%"').fetchone()[0]
    plantillas = conn.execute('SELECT COUNT(*) FROM auditoria WHERE accion LIKE "%Copió Plantilla%"').fetchone()[0]
    tickets = conn.execute('SELECT COUNT(*) FROM auditoria WHERE modulo = "Tickets" AND accion NOT LIKE "%Búsqueda%"').fetchone()[0]
    derivaciones = conn.execute('SELECT COUNT(*) FROM auditoria WHERE modulo = "Derivaciones Discord"').fetchone()[0]
    
    # New Admin KPIs
    total_usuarios = conn.execute('SELECT COUNT(*) FROM usuarios WHERE estado != "Eliminado"').fetchone()[0]
    us_activos = conn.execute('SELECT COUNT(*) FROM usuarios WHERE estado = "Activo"').fetchone()[0]
    us_inactivos = conn.execute('SELECT COUNT(*) FROM usuarios WHERE estado = "Inactivo"').fetchone()[0]
    asesores = conn.execute('SELECT COUNT(*) FROM usuarios WHERE rol = "Asesor" AND estado != "Eliminado"').fetchone()[0]
    formadores = conn.execute('SELECT COUNT(*) FROM usuarios WHERE rol = "Formador" AND estado != "Eliminado"').fetchone()[0]
    supervisores = conn.execute('SELECT COUNT(*) FROM usuarios WHERE rol = "Supervisor" AND estado != "Eliminado"').fetchone()[0]
    calidad = conn.execute('SELECT COUNT(*) FROM usuarios WHERE rol = "Calidad" AND estado != "Eliminado"').fetchone()[0]
    coordinadores = conn.execute('SELECT COUNT(*) FROM usuarios WHERE rol = "Coordinador" AND estado != "Eliminado"').fetchone()[0]
    administradores = conn.execute('SELECT COUNT(*) FROM usuarios WHERE rol = "Administrador" AND estado != "Eliminado"').fetchone()[0]
    pendientes_cambio = conn.execute('SELECT COUNT(*) FROM usuarios WHERE primer_ingreso = 1 AND estado != "Eliminado"').fetchone()[0]
    
    # NUEVA ANALÍTICA CRONOS SLA
    cronos_metrics = get_cronos_sla_metrics(conn)
    
    conn.close()
    
    kpis = {
        'usuarios_activos': activos,
        'consultas': consultas,
        'plantillas': plantillas,
        'tickets': tickets,
        'derivaciones': derivaciones,
        'total_usuarios': total_usuarios,
        'us_activos': us_activos,
        'us_inactivos': us_inactivos,
        'asesores': asesores,
        'formadores': formadores,
        'supervisores': supervisores,
        'calidad': calidad,
        'coordinadores': coordinadores,
        'administradores': administradores,
        'pendientes_cambio': pendientes_cambio
    }
    
    return render_template('dashboard.html', logs=logs, usuarios=usuarios, user=current_user, kpis=kpis, cronos=cronos_metrics)

@app.route('/admin/usuarios/crear', methods=['POST'])
@login_required
def crear_usuario():
    if current_user.rol not in ['Administrador', 'Coordinador']:
        return "Acceso denegado", 403
    
    nombre = request.form.get('nombre')
    correo = request.form.get('correo')
    password = request.form.get('password')
    rol = request.form.get('rol')
    estado = request.form.get('estado')
    
    conn = get_db_connection()
    exist = conn.execute('SELECT id FROM usuarios WHERE correo = ?', (correo,)).fetchone()
    if exist:
        conn.close()
        flash('El correo ya está registrado.', 'error')
        return redirect(url_for('dashboard'))
        
    pw_hash = generate_password_hash(password)
    conn.execute('INSERT INTO usuarios (nombre, correo, password_hash, rol, estado, primer_ingreso) VALUES (?, ?, ?, ?, ?, 1)',
                 (nombre, correo, pw_hash, rol, estado))
    conn.commit()
    conn.close()
    
    registrar_auditoria(current_user.correo, f"Creó usuario {correo}", "Administración", request.remote_addr)
    flash('Usuario creado exitosamente.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/usuarios/editar/<int:id>', methods=['POST'])
@login_required
def editar_usuario(id):
    if current_user.rol not in ['Administrador', 'Coordinador']:
        return "Acceso denegado", 403
        
    nombre = request.form.get('nombre')
    correo = request.form.get('correo')
    rol = request.form.get('rol')
    estado = request.form.get('estado')
    
    conn = get_db_connection()
    target_user = conn.execute('SELECT correo, rol FROM usuarios WHERE id=?', (id,)).fetchone()
    
    if current_user.rol == 'Coordinador' and target_user['rol'] in ['Administrador', 'Coordinador']:
        conn.close()
        return "No tienes permiso para modificar a este usuario.", 403
        
    conn.execute('UPDATE usuarios SET nombre=?, correo=?, rol=?, estado=? WHERE id=?', (nombre, correo, rol, estado, id))
    conn.commit()
    conn.close()
    
    if target_user['rol'] != rol:
        registrar_auditoria(current_user.correo, "Cambio de Rol", "Administración", request.remote_addr, f"Rol anterior: {target_user['rol']}\nRol nuevo: {rol}\nUsuario afectado: {target_user['correo']}")
    else:
        registrar_auditoria(current_user.correo, f"Editó usuario ID {id}", "Administración", request.remote_addr)
    
    flash('Usuario actualizado.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/usuarios/reset/<int:id>', methods=['POST'])
@login_required
def reset_password(id):
    if current_user.rol not in ['Administrador', 'Coordinador']:
        return "Acceso denegado", 403
        
    conn = get_db_connection()
    target_user = conn.execute('SELECT correo, rol FROM usuarios WHERE id=?', (id,)).fetchone()
    if current_user.rol == 'Coordinador' and target_user['rol'] in ['Administrador', 'Coordinador']:
        conn.close()
        return "No tienes permiso para modificar a este usuario.", 403
        
    nueva_clave = request.form.get('nueva_clave')
    pw_hash = generate_password_hash(nueva_clave)
    
    conn.execute('UPDATE usuarios SET password_hash=?, primer_ingreso=1 WHERE id=?', (pw_hash, id))
    conn.commit()
    conn.close()
    
    registrar_auditoria(current_user.correo, f"Reset contrasena usuario {target_user['correo']}", "Administración", request.remote_addr)
    flash('Contraseña temporal asignada.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/usuarios/estado/<int:id>', methods=['POST'])
@login_required
def cambiar_estado(id):
    if current_user.rol not in ['Administrador', 'Coordinador']:
        return "Acceso denegado", 403
        
    nuevo_estado = request.form.get('estado') # 'Activo', 'Inactivo', 'Eliminado'
    
    conn = get_db_connection()
    target_user = conn.execute('SELECT correo, rol FROM usuarios WHERE id=?', (id,)).fetchone()
    if current_user.rol == 'Coordinador' and target_user['rol'] in ['Administrador', 'Coordinador']:
        conn.close()
        return "No tienes permiso para modificar a este usuario.", 403
        
    conn.execute('UPDATE usuarios SET estado=? WHERE id=?', (nuevo_estado, id))
    conn.commit()
    conn.close()
    
    registrar_auditoria(current_user.correo, f"Cambio estado a {nuevo_estado} de {target_user['correo']}", "Administración", request.remote_addr)
    flash(f'Estado cambiado a {nuevo_estado}.', 'success')
    return redirect(url_for('dashboard'))

def format_excel_sheet(ws, title_color="1E293B"):
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter

    header_fill = PatternFill(start_color=title_color, end_color=title_color, fill_type="solid")
    header_font = Font(name="Segoe UI", size=10, bold=True, color="FFFFFF")
    data_font = Font(name="Segoe UI", size=9)
    thin_border = Border(
        left=Side(style='thin', color='E2E8F0'),
        right=Side(style='thin', color='E2E8F0'),
        top=Side(style='thin', color='E2E8F0'),
        bottom=Side(style='thin', color='E2E8F0')
    )
    
    ws.row_dimensions[1].height = 28
    for cell in ws[1]:
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        cell.border = thin_border
        
    for row in ws.iter_rows(min_row=2, max_row=ws.max_row, min_col=1, max_col=ws.max_column):
        for cell in row:
            cell.font = data_font
            cell.border = thin_border
            col_letter = get_column_letter(cell.column)
            if col_letter in ['A', 'B', 'C', 'G', 'H', 'I', 'J', 'K']:
                cell.alignment = Alignment(horizontal="center", vertical="center")
            else:
                cell.alignment = Alignment(horizontal="left", vertical="center")
                
    if ws.max_row > 1:
        ws.auto_filter.ref = ws.dimensions
        ws.freeze_panes = 'A2'
        
    for col in ws.columns:
        max_len = 0
        col_letter = get_column_letter(col[0].column)
        for cell in col:
            val_str = str(cell.value or '')
            if len(val_str) > max_len:
                max_len = len(val_str)
        ws.column_dimensions[col_letter].width = min(max(max_len + 4, 12), 60)

@app.route('/dashboard/export/excel')
@login_required
def export_excel():
    if current_user.rol not in ['Administrador', 'Coordinador', 'Supervisor', 'Calidad', 'Formador']:
        return "Acceso denegado", 403
        
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    
    export_type = request.args.get('tipo', 'all') # 'audit', 'cronos', 'all'
    filter_q = request.args.get('q', '').strip()
    filter_usuario = request.args.get('usuario', '').strip()
    filter_modulo = request.args.get('modulo', '').strip()
    filter_estado = request.args.get('estado', '').strip()
    
    filters = {
        'q': filter_q,
        'usuario': filter_usuario,
        'modulo': filter_modulo,
        'estado': filter_estado
    }
    
    conn = get_db_connection()
    users_rows = conn.execute("SELECT correo, rol, nombre FROM usuarios").fetchall()
    user_roles = {u['correo']: u['rol'] for u in users_rows}
    user_names = {u['correo']: u['nombre'] for u in users_rows}
    
    wb = openpyxl.Workbook()
    wb.remove(wb.active) # Quitar hoja por defecto
    
    today_str = datetime.datetime.now().strftime('%Y%m%d')
    now_full_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # -------------------------------------------------------------------------
    # 1. HOJA: HISTORIAL AUDITORÍA
    # -------------------------------------------------------------------------
    total_audit_rows = 0
    if export_type in ['audit', 'all']:
        ws_audit = wb.create_sheet(title="Historial Auditoría")
        
        headers_audit = [
            "ID Registro", "Fecha", "Hora", "Usuario", "Nombre Completo",
            "Perfil / Rol", "Módulo", "Acción Realizada", "Descripción / Detalles", "Dirección IP"
        ]
        ws_audit.append(headers_audit)
        
        query = "SELECT * FROM auditoria WHERE 1=1"
        params = []
        if filter_usuario:
            query += " AND usuario_correo LIKE ?"
            params.append(f"%{filter_usuario}%")
        if filter_modulo:
            query += " AND modulo LIKE ?"
            params.append(f"%{filter_modulo}%")
        if filter_q:
            q_val = f"%{filter_q}%"
            query += " AND (usuario_correo LIKE ? OR modulo LIKE ? OR accion LIKE ? OR detalles LIKE ?)"
            params.extend([q_val, q_val, q_val, q_val])
            
        query += " ORDER BY id DESC"
        rows_audit = conn.execute(query, params).fetchall()
        total_audit_rows = len(rows_audit)
        
        for r in rows_audit:
            correo = r['usuario_correo']
            rol = user_roles.get(correo, 'Asesor')
            nombre = user_names.get(correo, correo)
            ws_audit.append([
                r['id'],
                r['fecha'],
                r['hora'],
                correo,
                nombre,
                rol,
                r['modulo'],
                r['accion'],
                r['detalles'] or '',
                r['ip'] or '127.0.0.1'
            ])
            
        format_excel_sheet(ws_audit, title_color="1E293B")
        
    # -------------------------------------------------------------------------
    # 2. HOJA: ANALÍTICA CRONOS SLA
    # -------------------------------------------------------------------------
    total_inicios = 0
    total_pausas = 0
    total_reinicios = 0
    total_criticos = 0
    pausas_segundos = []
    reinicios_segundos = []
    cronos_total_rows = 0
    cronos_users_set = set()
    
    if export_type in ['cronos', 'all']:
        ws_cronos = wb.create_sheet(title="Analítica CRONOS SLA")
        
        headers_cronos = [
            "ID Registro", "Fecha", "Hora", "Usuario", "Nombre Asesor", "Perfil / Rol",
            "Acción", "Tiempo CRONOS SLA", "Segundos", "Estado SLA", "Evento Crítico", "Observaciones / Detalles"
        ]
        ws_cronos.append(headers_cronos)
        
        query_cronos = "SELECT * FROM auditoria WHERE modulo = 'CRONOS SLA'"
        params_cronos = []
        if filter_usuario:
            query_cronos += " AND usuario_correo LIKE ?"
            params_cronos.append(f"%{filter_usuario}%")
        if filter_q:
            q_val = f"%{filter_q}%"
            query_cronos += " AND (usuario_correo LIKE ? OR accion LIKE ? OR detalles LIKE ?)"
            params_cronos.extend([q_val, q_val, q_val])
            
        query_cronos += " ORDER BY id DESC"
        rows_cronos = conn.execute(query_cronos, params_cronos).fetchall()
        
        for r in rows_cronos:
            correo = r['usuario_correo']
            rol = user_roles.get(correo, 'Asesor')
            nombre = user_names.get(correo, correo)
            accion = r['accion']
            detalles_raw = r['detalles'] or ''
            
            cronos_users_set.add(correo)
            
            segundos = 0
            tiempo_str = "00:00"
            estado_str = "Verde"
            
            if detalles_raw:
                try:
                    data = json.loads(detalles_raw)
                    segundos = int(data.get('segundos', 0))
                    tiempo_str = data.get('tiempo', f"00:{segundos:02d}")
                    estado_str = data.get('estado', 'Verde')
                except Exception:
                    m_t = re.search(r'Tiempo:\s*([0-9:]+)', detalles_raw)
                    if m_t: tiempo_str = m_t.group(1)
                    m_e = re.search(r'Estado:\s*([^|]+)', detalles_raw)
                    if m_e: estado_str = m_e.group(1).strip()
                    m_s = re.search(r'Segundos:\s*(\d+)', detalles_raw)
                    if m_s: segundos = int(m_s.group(1))
            
            if filter_estado and filter_estado.lower() not in estado_str.lower():
                continue
                
            cronos_total_rows += 1
            critico_str = "No"
            if 'Iniciar' in accion:
                total_inicios += 1
                accion_display = "Iniciar"
            elif 'Pausar' in accion:
                total_pausas += 1
                pausas_segundos.append(segundos)
                accion_display = "Pausar"
            elif 'Reiniciar' in accion:
                total_reinicios += 1
                reinicios_segundos.append(segundos)
                accion_display = "Reiniciar"
            elif '45' in accion:
                total_criticos += 1
                critico_str = "Sí (45s)"
                accion_display = "Alerta SLA 45s"
            elif '55' in accion:
                total_criticos += 1
                critico_str = "Sí (55s)"
                accion_display = "Alerta SLA 55s"
            elif '60' in accion:
                total_criticos += 1
                critico_str = "Sí (60s)"
                accion_display = "Alerta SLA 60s"
            else:
                accion_display = accion
                
            ws_cronos.append([
                r['id'],
                r['fecha'],
                r['hora'],
                correo,
                nombre,
                rol,
                accion_display,
                tiempo_str,
                segundos,
                estado_str,
                critico_str,
                detalles_raw
            ])
            
        format_excel_sheet(ws_cronos, title_color="FF6B00")
        
    # -------------------------------------------------------------------------
    # 3. HOJA: RESUMEN
    # -------------------------------------------------------------------------
    ws_resumen = wb.create_sheet(title="RESUMEN")
    ws_resumen.views.sheetView[0].showGridLines = True
    
    ws_resumen.merge_cells('A1:D1')
    title_cell = ws_resumen['A1']
    title_cell.value = "📊 RESUMEN EJECUTIVO DE AUDITORÍA Y CRONOS SLA - WIN"
    title_cell.font = Font(name="Segoe UI", size=13, bold=True, color="FFFFFF")
    title_cell.fill = PatternFill(start_color="1E293B", end_color="1E293B", fill_type="solid")
    title_cell.alignment = Alignment(horizontal="center", vertical="center")
    ws_resumen.row_dimensions[1].height = 36
    
    filtro_desc = []
    if filter_q: filtro_desc.append(f"Término: '{filter_q}'")
    if filter_usuario: filtro_desc.append(f"Usuario: '{filter_usuario}'")
    if filter_modulo: filtro_desc.append(f"Módulo: '{filter_modulo}'")
    if filter_estado: filtro_desc.append(f"Estado SLA: '{filter_estado}'")
    filtros_str = ", ".join(filtro_desc) if filtro_desc else "Sin filtros (Totalidad de registros)"
    
    tipo_nombre = "Consolidado General" if export_type == 'all' else ("Historial Auditoría" if export_type == 'audit' else "Analítica CRONOS SLA")
    
    summary_data = [
        ("Fecha de Generación:", now_full_str),
        ("Exportado por:", f"{current_user.correo} ({current_user.rol})"),
        ("Tipo de Reporte:", tipo_nombre),
        ("Filtros Aplicados:", filtros_str),
        ("", ""),
        ("--- MÉTRICAS GENERALES DE OPERACIÓN ---", ""),
        ("Total Registros Exportados (Auditoría):", total_audit_rows),
        ("Total Registros Exportados (CRONOS SLA):", cronos_total_rows),
        ("Total Usuarios Únicos Registrados:", len(users_rows)),
        ("Total Asesores con Interacciones CRONOS:", len(cronos_users_set)),
        ("Total Inicios / Activaciones:", total_inicios),
        ("Total Pausas Registradas:", total_pausas),
        ("Total Reinicios Registrados:", total_reinicios),
        ("Total Eventos Críticos (45s / 55s / 60s):", total_criticos),
        ("Tiempo Promedio de Pausa:", f"{round(sum(pausas_segundos)/len(pausas_segundos), 1)}s" if pausas_segundos else "0s"),
        ("Tiempo Promedio antes de Reiniciar:", f"{round(sum(reinicios_segundos)/len(reinicios_segundos), 1)}s" if reinicios_segundos else "0s"),
    ]
    
    lbl_font = Font(name="Segoe UI", size=10, bold=True, color="1E293B")
    val_font = Font(name="Segoe UI", size=10, color="0F172A")
    section_font = Font(name="Segoe UI", size=10, bold=True, color="FF6B00")
    
    row_idx = 3
    for label, val in summary_data:
        ws_resumen.cell(row=row_idx, column=1, value=label)
        ws_resumen.cell(row=row_idx, column=2, value=val)
        
        c1 = ws_resumen.cell(row=row_idx, column=1)
        c2 = ws_resumen.cell(row=row_idx, column=2)
        
        if label.startswith("---"):
            c1.font = section_font
        else:
            c1.font = lbl_font
            c2.font = val_font
        row_idx += 1
        
    ws_resumen.column_dimensions['A'].width = 44
    ws_resumen.column_dimensions['B'].width = 50
    
    conn.close()
    
    if export_type == 'audit':
        filename = f"Historial_Auditoria_{today_str}.xlsx"
    elif export_type == 'cronos':
        filename = f"Analitica_CRONOS_SLA_{today_str}.xlsx"
    else:
        filename = f"Historial_Auditoria_{today_str}.xlsx"
        
    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    
    return send_file(output, download_name=filename, as_attachment=True, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

def launch_browser(port):
    import time
    import webbrowser
    import urllib.request
    
    app_url = f"http://127.0.0.1:{port}/app"
    test_url = f"http://127.0.0.1:{port}/login"
    opened = False
    
    # Esperar entre 2 y 5 segundos verificando que el servidor esté activo
    for _ in range(10):
        time.sleep(0.5)
        try:
            req = urllib.request.Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=1) as resp:
                if resp.status in [200, 302, 301]:
                    print(f"[WIN] Servidor activo. Abriendo navegador en: {app_url}")
                    webbrowser.open(app_url)
                    opened = True
                    break
        except Exception:
            pass
            
    if not opened:
        time.sleep(1.5)
        print(f"[WIN] Abriendo navegador en: {app_url}")
        try:
            webbrowser.open(app_url)
        except Exception as err:
            print(f"[WIN] Error al abrir navegador: {err}")

if __name__ == '__main__':
    from models import init_db
    import threading
    import os
    
    # Inicializar DB en caso de ser necesario (en producción suele hacerse mediante scripts de migración)
    try:
        init_db()
        print("Base de datos y tablas inicializadas correctamente.")
    except Exception as e:
        print(f"Error crítico en init_db: {e}")
    
    port = int(os.environ.get('PORT', 3000))
    # Lanzar hilo en segundo plano para abrir automáticamente el navegador
    threading.Thread(target=launch_browser, args=(port,), daemon=True).start()
    
    app.run(host='0.0.0.0', port=port, debug=False)
