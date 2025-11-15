# main.py — UnisaCare (Permissões por grupo + Tema Claro/Escuro por usuário)
import sqlite3
import uuid
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, Response, flash, abort
import os
from datetime import datetime, date
import statistics
import collections
import csv
import io
from werkzeug.security import generate_password_hash, check_password_hash
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key')
DATABASE = 'questionario.db'

# ----------------- CONFIG (guardar/ler base_url dinâmica) -----------------
def ensure_config_table():
    conn = sqlite3.connect(DATABASE)
    conn.execute("CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)")
    conn.commit()
    conn.close()

def get_config(key):
    ensure_config_table()
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT value FROM config WHERE key = ?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else None

def set_config(key, value):
    ensure_config_table()
    conn = sqlite3.connect(DATABASE)
    conn.execute(
        "INSERT INTO config(key,value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )
    conn.commit()
    conn.close()

@app.before_request
def _capture_base_url():
    # salva a Dev URL atual (ex.: ...replit.dev) ou o .repl.co se existir
    try:
        base = request.url_root.rstrip('/')
        if base and (base.endswith('.replit.dev') or base.endswith('.repl.co')):
            atual = get_config('base_url')
            if atual != base:
                set_config('base_url', base)
    except Exception:
        pass

# ----------------- DB -----------------
def column_exists(cursor, table, column):
    cols = cursor.execute(f"PRAGMA table_info({table})").fetchall()
    names = [c[1] for c in cols]
    return column in names

def table_exists(cursor, table):
    row = cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
    return row is not None

def init_db():
    conn = sqlite3.connect(DATABASE); cursor = conn.cursor()

    # Tabelas principais (idempotentes)
    cursor.execute('CREATE TABLE IF NOT EXISTS respostas (id INTEGER PRIMARY KEY, timestamp TEXT, nome TEXT, departamento_id INTEGER, q1 INTEGER, q2 INTEGER, q3 INTEGER, FOREIGN KEY(departamento_id) REFERENCES departamentos(id));')
    cursor.execute('CREATE TABLE IF NOT EXISTS usuarios (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT NOT NULL);')
    cursor.execute('CREATE TABLE IF NOT EXISTS perguntas (id INTEGER PRIMARY KEY, texto TEXT NOT NULL);')
    cursor.execute('CREATE TABLE IF NOT EXISTS departamentos (id INTEGER PRIMARY KEY, nome TEXT UNIQUE NOT NULL);')
    cursor.execute('CREATE TABLE IF NOT EXISTS colaboradores (id INTEGER PRIMARY KEY, nome TEXT NOT NULL, email TEXT UNIQUE NOT NULL, departamento_id INTEGER, FOREIGN KEY(departamento_id) REFERENCES departamentos(id));')
    cursor.execute('CREATE TABLE IF NOT EXISTS pesquisas (id INTEGER PRIMARY KEY, titulo TEXT NOT NULL, status TEXT NOT NULL DEFAULT "Rascunho", email_titulo TEXT, email_corpo TEXT, agendamento TEXT);')
    cursor.execute('CREATE TABLE IF NOT EXISTS pesquisa_perguntas (pesquisa_id INTEGER, pergunta_id INTEGER, FOREIGN KEY(pesquisa_id) REFERENCES pesquisas(id) ON DELETE CASCADE, FOREIGN KEY(pergunta_id) REFERENCES perguntas(id) ON DELETE CASCADE, PRIMARY KEY (pesquisa_id, pergunta_id));')
    cursor.execute('CREATE TABLE IF NOT EXISTS pesquisa_colaboradores (pesquisa_id INTEGER, colaborador_id INTEGER, token TEXT UNIQUE NOT NULL, respondido INTEGER DEFAULT 0, FOREIGN KEY(pesquisa_id) REFERENCES pesquisas(id) ON DELETE CASCADE, FOREIGN KEY(colaborador_id) REFERENCES colaboradores(id) ON DELETE CASCADE, PRIMARY KEY (pesquisa_id, colaborador_id));')
    cursor.execute('CREATE TABLE IF NOT EXISTS pesquisa_respostas (id INTEGER PRIMARY KEY, pesquisa_id INTEGER, colaborador_id INTEGER, pergunta_id INTEGER, resposta_valor INTEGER, FOREIGN KEY(pesquisa_id) REFERENCES pesquisas(id), FOREIGN KEY(colaborador_id) REFERENCES colaboradores(id), FOREIGN KEY(pergunta_id) REFERENCES perguntas(id));')
    cursor.execute('CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)')

    # Grupos
    cursor.execute('CREATE TABLE IF NOT EXISTS grupos (id INTEGER PRIMARY KEY, nome TEXT UNIQUE NOT NULL);')
    if cursor.execute("SELECT COUNT(*) FROM grupos").fetchone()[0] == 0:
        cursor.executemany("INSERT INTO grupos (nome) VALUES (?)", [("admin",), ("gestor",), ("colaborador",)])

    # Migração de colunas em usuarios: grupo_id, tema
    if not column_exists(cursor, 'usuarios', 'grupo_id'):
        cursor.execute("ALTER TABLE usuarios ADD COLUMN grupo_id INTEGER")
    if not column_exists(cursor, 'usuarios', 'tema'):
        cursor.execute("ALTER TABLE usuarios ADD COLUMN tema TEXT DEFAULT 'escuro'")
    conn.commit()

    # Seeds mínimos
    if cursor.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0] == 0:
        admin_group_id = cursor.execute("SELECT id FROM grupos WHERE nome='admin'").fetchone()[0]
        cursor.execute("INSERT INTO usuarios (username, password_hash, grupo_id, tema) VALUES (?, ?, ?, ?)",
                       ('admin', generate_password_hash('senha123'), admin_group_id, 'escuro'))
    if cursor.execute("SELECT COUNT(*) FROM perguntas").fetchone()[0] == 0:
        cursor.executemany("INSERT INTO perguntas (texto) VALUES (?)", [
            ("Sinto-me fisicamente e mentalmente esgotado após o trabalho.",),
            ("Tenho dificuldade em recuperar minha energia mesmo após períodos de descanso.",),
            ("Frequentemente me sinto sobrecarregado pelas demandas do meu trabalho.",),
        ])
    if cursor.execute("SELECT COUNT(*) FROM departamentos").fetchone()[0] == 0:
        cursor.executemany("INSERT INTO departamentos (nome) VALUES (?)", [
            ("T.I",),("RH",),("Comercial",),("Projetos",),("Fiscal",),
            ("Contas a pagar",),("Carteira de Clientes",),("Novos Negócios",),
        ])
    conn.commit(); conn.close()

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# ----------------- Auth Helpers & Roles -----------------
ROLE_LEVEL = {"colaborador": 1, "gestor": 2, "admin": 3}

def get_current_user():
    if not session.get('logged_in'):
        return None
    return {
        "id": session['user_id'],
        "username": session['username'],
        "grupo": session.get('grupo', 'colaborador'),
        "tema": session.get('tema', 'escuro')
    }

def require_role(required):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if not user:
                return redirect(url_for('login'))
            user_level = ROLE_LEVEL.get(user['grupo'], 0)
            req_level = ROLE_LEVEL.get(required, 0)
            if user_level < req_level:
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ----------------- E-mail HTML -----------------
def build_email_html(mensagem_usuario: str, link_pesquisa: str, nome_colaborador: str) -> str:
    msg = (mensagem_usuario or "")
    msg = msg.replace("{nome_colaborador}", nome_colaborador)
    msg = msg.replace("{link_pesquisa}", "")  # evita duplicar link no corpo
    if link_pesquisa:
        msg = msg.replace(link_pesquisa, "")
    msg = msg.replace("\n", "<br>")
    return f"""<!doctype html>
<html lang="pt-BR">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Convite</title></head>
<body style="margin:0;padding:0;background:#f6f7fb;color:#111827;font-family:Arial,Helvetica,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="padding:24px 12px;">
    <tr><td align="center">
      <table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="max-width:600px;background:#ffffff;border-radius:14px;overflow:hidden;box-shadow:0 2px 10px rgba(17,24,39,0.06);">
        <tr><td style="background:#2563eb;color:#ffffff;padding:22px 24px;font-weight:bold;text-align:center;font-size:20px;">UnisaCare – Pesquisa de Bem-Estar</td></tr>
        <tr><td style="padding:26px 24px;font-size:15px;line-height:1.6;">
          <div style="margin:0 0 16px;">{msg}</div>
          <div style="text-align:center;margin:22px 0 6px;">
            <a href="{link_pesquisa}" style="background:#2563eb;color:#ffffff;text-decoration:none;font-weight:600;padding:12px 20px;border-radius:10px;display:inline-block;">Responder pesquisa</a>
          </div>
          <p style="font-size:12px;color:#6b7280;text-align:center;margin:10px 0 0;">Se o botão não funcionar, copie e cole no navegador:<br>{link_pesquisa}</p>
        </td></tr>
        <tr><td style="padding:16px 24px;font-size:12px;color:#9ca3af;text-align:center;">Este e-mail foi enviado automaticamente pelo sistema UnisaCare. Não responda.</td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""

# ----------------- Disparo de e-mail -----------------
def enviar_emails_pesquisa(pesquisa_id):
    print(f"Iniciando disparo para pesquisa ID: {pesquisa_id}")
    with app.app_context():
        SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY')
        FROM_EMAIL = os.environ.get('FROM_EMAIL', 'no-reply@example.com')
        if not SENDGRID_API_KEY:
            print("ERRO CRÍTICO: SENDGRID_API_KEY não encontrada nos Secrets.")
            return

        conn = get_db_connection()
        pesquisa = conn.execute('SELECT * FROM pesquisas WHERE id = ?', (pesquisa_id,)).fetchone()
        colaboradores_com_token = conn.execute(
            'SELECT c.*, pc.token FROM colaboradores c '
            'JOIN pesquisa_colaboradores pc ON c.id = pc.colaborador_id '
            'WHERE pc.pesquisa_id = ?',
            (pesquisa_id,)
        ).fetchall()

        if not colaboradores_com_token:
            print(f"Nenhum colaborador encontrado para a pesquisa ID: {pesquisa_id}")
            conn.close()
            return

        try:
            sg = SendGridAPIClient(SENDGRID_API_KEY)
            base_url = os.environ.get('EXTERNAL_BASE_URL', '').rstrip('/')
            if not base_url:
                base_url = get_config("base_url")
            if not base_url:
                print("ATENÇÃO: base_url não definida. Acesse qualquer rota do app (ex.: /login) e reenvie.")
                conn.close()
                return

            mensagem_padrao = pesquisa['email_corpo'] or "Sua opinião é muito importante. Clique no botão abaixo para responder à pesquisa."
            enviados = 0
            for colaborador in colaboradores_com_token:
                link_pesquisa = f"{base_url}/responder/{colaborador['token']}"
                html_final = build_email_html(mensagem_padrao, link_pesquisa, colaborador['nome'])
                message = Mail(from_email=FROM_EMAIL, to_emails=colaborador['email'],
                               subject=pesquisa['email_titulo'] or "Pesquisa",
                               html_content=html_final)
                response = sg.send(message)
                enviados += 1
                print(f"E-mail enviado para {colaborador['email']} (status {response.status_code})")

            conn.execute('UPDATE pesquisas SET status = ? WHERE id = ?', ('Enviado', pesquisa_id))
            conn.commit()
            print(f"Pesquisa ID {pesquisa_id} marcada como 'Enviada'. Total enviados: {enviados}")
        except Exception as e:
            print(f'Erro ao enviar e-mails da pesquisa {pesquisa_id}: {e}')
        finally:
            conn.close()

# ----------------- Agendador -----------------
def disparar_pesquisas_agendadas():
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Verificando pesquisas agendadas...")
    conn = get_db_connection()
    agora = datetime.now().strftime('%Y-%m-%d %H:%M')
    pesquisas_para_enviar = conn.execute(
        "SELECT * FROM pesquisas WHERE status = 'Agendado' AND agendamento <= ?",
        (agora,)
    ).fetchall()
    conn.close()
    if not pesquisas_para_enviar:
        print("Nenhuma pesquisa para enviar no momento.")
        return
    for pesquisa in pesquisas_para_enviar:
        enviar_emails_pesquisa(pesquisa['id'])

# ----------------- Rotas públicas -----------------
@app.route('/')
def index():
    conn = get_db_connection()
    departamentos = conn.execute("SELECT * FROM departamentos ORDER BY nome").fetchall()
    conn.close()
    return render_template('index.html', departamentos=departamentos)

@app.route('/submit', methods=['POST'])
def submit():
    try:
        data = request.json
        nome = data.get('nome')
        departamento_id = data.get('departamento_id')
        q1, q2, q3 = data.get('q1'), data.get('q2'), data.get('q3')
        timestamp = datetime.now().isoformat()
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO respostas (timestamp, nome, departamento_id, q1, q2, q3) VALUES (?, ?, ?, ?, ?, ?)",
            (timestamp, nome, departamento_id, q1, q2, q3)
        )
        conn.commit(); conn.close()
        return jsonify({'success': True, 'message': 'Respostas enviadas com sucesso!'}), 200
    except Exception as e:
        print(f"Erro no servidor: {e}")
        return jsonify({'success': False, 'message': 'Ocorreu um erro interno.'}), 500

@app.route('/responder/<token>')
def responder_pesquisa(token):
    conn = get_db_connection()
    dados_convite = conn.execute('SELECT * FROM pesquisa_colaboradores WHERE token = ?', (token,)).fetchone()
    if not dados_convite:
        conn.close()
        return render_template('mensagem.html', titulo="Link Inválido", mensagem="Este link de pesquisa é inválido ou não existe mais."), 404
    if dados_convite['respondido']:
        conn.close()
        return render_template('mensagem.html', titulo="Pesquisa Já Respondida", mensagem="Você já respondeu a esta pesquisa. Obrigado!")

    pesquisa = conn.execute('SELECT * FROM pesquisas WHERE id = ?', (dados_convite['pesquisa_id'],)).fetchone()
    perguntas = conn.execute(
        'SELECT p.* FROM perguntas p JOIN pesquisa_perguntas pp ON p.id = pp.pergunta_id '
        'WHERE pp.pesquisa_id = ? ORDER BY p.id', (pesquisa['id'],)
    ).fetchall()
    conn.close()
    return render_template('responder_pesquisa.html', pesquisa=pesquisa, perguntas=perguntas, token=token)

@app.route('/responder/submit/<token>', methods=['POST'])
def submit_pesquisa(token):
    conn = get_db_connection()
    dados_convite = conn.execute('SELECT * FROM pesquisa_colaboradores WHERE token = ?', (token,)).fetchone()
    if not dados_convite or dados_convite['respondido']:
        conn.close()
        return render_template('mensagem.html', titulo="Link Inválido", mensagem="Link inválido ou pesquisa já respondida."), 403

    pesquisa_id = dados_convite['pesquisa_id']
    colaborador_id = dados_convite['colaborador_id']

    # 1) Coleta respostas do formulário
    respostas = []
    valores = []
    for key, value in request.form.items():
        if key.startswith('resposta-'):
            pergunta_id = int(key.split('-')[1])
            valor = int(value)
            respostas.append((pesquisa_id, colaborador_id, pergunta_id, valor))
            valores.append(valor)

    # 2) Persiste
    conn.executemany(
        "INSERT INTO pesquisa_respostas (pesquisa_id, colaborador_id, pergunta_id, resposta_valor) VALUES (?, ?, ?, ?)",
        respostas
    )
    conn.execute("UPDATE pesquisa_colaboradores SET respondido = 1 WHERE token = ?", (token,))
    conn.commit()
    conn.close()

    # 3) Calcula média (ajuste a regra conforme seu modelo)
    media = sum(valores) / len(valores) if valores else 0

    if media >= 4.0:
        status_emoji = "🙂"
        status_titulo = "Tudo bem"
        status_texto = "Pelas suas respostas, seu nível geral parece bom."
        status_cor = "#10b981"
    elif media >= 2.6:
        status_emoji = "😐"
        status_titulo = "Atenção"
        status_texto = "Há sinais de cansaço. Vale observar e, se possível, fazer pequenos ajustes."
        status_cor = "#f59e0b"
    else:
        status_emoji = "😟"
        status_titulo = "Sinal de alerta"
        status_texto = "Seu nível indica exaustão. Recomendamos conversar com sua liderança/recursos de apoio."
        status_cor = "#ef4444"

    return render_template(
        'mensagem.html',
        titulo="Obrigado por Responder!",
        mensagem="Sua participação foi registrada com sucesso.",
        pesquisa_id=pesquisa_id,
        status_emoji=status_emoji,
        status_titulo=status_titulo,
        status_texto=status_texto,
        status_cor=status_cor,
        media=round(media, 2)
    )

# ----------------- Auth & Tema -----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = get_db_connection()
        user = conn.execute('SELECT u.*, g.nome as grupo_nome FROM usuarios u LEFT JOIN grupos g ON u.grupo_id=g.id WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password_hash'], password):
            session['logged_in'] = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['grupo'] = user['grupo_nome'] or 'colaborador'
            session['tema'] = user['tema'] or 'escuro'
            return redirect(url_for('dashboard'))
        else:
            flash('Usuário ou senha inválidos.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/usuarios/tema', methods=['POST'])
def atualizar_tema():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    novo = request.form.get('tema', 'escuro')
    uid = session['user_id']
    conn = get_db_connection()
    conn.execute("UPDATE usuarios SET tema=? WHERE id=?", (novo, uid))
    conn.commit(); conn.close()
    session['tema'] = novo
    flash("Preferência de tema atualizada!", "success")
    return redirect(request.referrer or url_for('dashboard'))

# ----------------- Painel (com permissões) -----------------
@app.route('/dashboard')
@require_role('gestor')  # gestor e admin podem ver
def dashboard():
    conn = get_db_connection()
    respostas = conn.execute(
        'SELECT pr.resposta_valor, d.nome as departamento FROM pesquisa_respostas pr '
        'JOIN colaboradores c ON pr.colaborador_id = c.id '
        'JOIN departamentos d ON c.departamento_id = d.id'
    ).fetchall()
    convites = conn.execute('SELECT respondido FROM pesquisa_colaboradores').fetchall()
    respostas_contagem_unica = conn.execute('SELECT DISTINCT colaborador_id FROM pesquisa_respostas').fetchall()
    conn.close()

    overall_score = 0
    depto_scores_raw = {}
    engagement_rate = 0

    if respostas:
        overall_score = sum(r['resposta_valor'] for r in respostas) / len(respostas) if len(respostas) > 0 else 0
        for r in respostas:
            depto_scores_raw.setdefault(r['departamento'], []).append(r['resposta_valor'])

    if convites:
        total_convites = len(convites)
        total_respondidos = sum(c['respondido'] for c in convites)
        engagement_rate = (total_respondidos / total_convites) * 100 if total_convites > 0 else 0

    depto_scores = [{'departamento': depto, 'score': sum(scores) / len(scores)} for depto, scores in depto_scores_raw.items()]
    depto_scores.sort(key=lambda x: x['score'])

    return render_template('dashboard.html',
                           active_page='dashboard',
                           overall_score=overall_score,
                           total_respostas=len(respostas_contagem_unica),
                           engagement_rate=engagement_rate,
                           depto_scores=depto_scores)

@app.route('/relatorio')
@require_role('gestor')
def relatorio():
    start_date_str = request.args.get('start_date', date.min.isoformat())
    end_date_str = request.args.get('end_date', date.today().isoformat())
    end_date_full_str = f"{end_date_str}T23:59:59"

    conn = get_db_connection()
    query = (
        "SELECT r.*, d.nome as depto_nome FROM respostas r "
        "JOIN departamentos d ON r.departamento_id = d.id "
        "WHERE r.timestamp BETWEEN ? AND ? ORDER BY r.timestamp DESC"
    )
    respostas = conn.execute(query, (start_date_str, end_date_full_str)).fetchall()
    conn.close()

    stats = {'total_respostas': 0, 'media_geral': 0, 'pergunta_maior_media': 'N/A', 'consolidado_por_pergunta': []}

    if respostas:
        question_labels = {1: "Esgotamento", 2: "Recuperação", 3: "Sobrecarga"}
        stats['total_respostas'] = len(respostas)
        all_q_values = [r[f'q{i}'] for r in respostas for i in range(1, 4)]
        stats['media_geral'] = sum(all_q_values) / len(all_q_values) if all_q_values else 0

        consolidado, medias = [], {}
        for i in range(1, 4):
            pergunta_descritiva = question_labels[i]
            valores = [r[f'q{i}'] for r in respostas]
            media = sum(valores) / len(valores) if valores else 0
            try:
                moda = statistics.mode(valores)
            except statistics.StatisticsError:
                moda = "N/A"
            consolidado.append({'pergunta': pergunta_descritiva, 'media': media, 'moda': moda})
            medias[pergunta_descritiva] = media

        stats['consolidado_por_pergunta'] = consolidado
        stats['pergunta_maior_media'] = max(medias, key=medias.get) if medias else "N/A"

    filters = {'start_date': start_date_str, 'end_date': end_date_str}
    return render_template('relatorio.html', active_page='relatorio', stats=stats, filters=filters, respostas=respostas)

# ----------------- Usuários (ADMIN) -----------------
@app.route('/usuarios')
@require_role('admin')
def usuarios():
    conn = get_db_connection()
    lista_usuarios = conn.execute("SELECT u.id, u.username, u.tema, u.grupo_id, g.nome as grupo FROM usuarios u LEFT JOIN grupos g ON u.grupo_id=g.id ORDER BY username").fetchall()
    grupos = conn.execute("SELECT * FROM grupos ORDER BY id").fetchall()
    conn.close()
    return render_template('usuarios.html', active_page='usuarios', usuarios=lista_usuarios, grupos=grupos)

@app.route('/usuarios/adicionar', methods=['POST'])
@require_role('admin')
def adicionar_usuario():
    username = request.form.get('username')
    password = request.form.get('password')
    grupo_id = request.form.get('grupo_id')
    tema = request.form.get('tema', 'escuro')
    if not username or not password or not grupo_id:
        flash("Usuário, senha e grupo são obrigatórios.", "error")
        return redirect(url_for('usuarios'))
    hashed_password = generate_password_hash(password)
    try:
        conn = get_db_connection()
        conn.execute("INSERT INTO usuarios (username, password_hash, grupo_id, tema) VALUES (?, ?, ?, ?)",
                     (username, hashed_password, grupo_id, tema))
        conn.commit(); conn.close()
        flash(f"Usuário '{username}' adicionado com sucesso!", "success")
    except sqlite3.IntegrityError:
        flash(f"Usuário '{username}' já existe.", "error")
    return redirect(url_for('usuarios'))

@app.route('/usuarios/editar/<int:user_id>', methods=['GET', 'POST'])
@require_role('admin')
def editar_usuario(user_id):
    conn = get_db_connection()
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        grupo_id = request.form.get('grupo_id')
        tema = request.form.get('tema', 'escuro')
        if not username or not grupo_id:
            flash('Usuário e grupo são obrigatórios.', 'error')
            return redirect(url_for('editar_usuario', user_id=user_id))
        if password:
            conn.execute('UPDATE usuarios SET username = ?, password_hash = ?, grupo_id=?, tema=? WHERE id = ?',
                         (username, generate_password_hash(password), grupo_id, tema, user_id))
        else:
            conn.execute('UPDATE usuarios SET username = ?, grupo_id=?, tema=? WHERE id = ?',
                         (username, grupo_id, tema, user_id))
        conn.commit(); conn.close()
        flash('Usuário atualizado com sucesso!', 'success')
        return redirect(url_for('usuarios'))
    user = conn.execute('SELECT * FROM usuarios WHERE id = ?', (user_id,)).fetchone()
    grupos = conn.execute("SELECT * FROM grupos ORDER BY id").fetchall()
    conn.close()
    return render_template('editar_usuario.html', active_page='usuarios', user=user, grupos=grupos)

@app.route('/usuarios/excluir/<int:user_id>', methods=['POST'])
@require_role('admin')
def excluir_usuario(user_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM usuarios WHERE id = ?", (user_id,))
    conn.commit(); conn.close()
    flash("Usuário excluído com sucesso!", "success")
    return redirect(url_for('usuarios'))

# ----------------- Colaboradores / Perguntas / Departamentos / Pesquisas (GESTOR+) -----------------
@app.route('/colaboradores')
@require_role('gestor')
def colaboradores():
    conn = get_db_connection()
    lista_colaboradores = conn.execute(
        "SELECT c.id, c.nome, c.email, d.nome as depto_nome FROM colaboradores c "
        "JOIN departamentos d ON c.departamento_id = d.id ORDER BY c.nome"
    ).fetchall()
    departamentos = conn.execute("SELECT * FROM departamentos ORDER BY nome").fetchall()
    conn.close()
    return render_template('colaboradores.html', active_page='colaboradores',
                           colaboradores=lista_colaboradores, departamentos=departamentos)

@app.route('/colaboradores/adicionar', methods=['POST'])
@require_role('gestor')
def adicionar_colaborador():
    nome = request.form.get('nome')
    email = request.form.get('email')
    departamento_id = request.form.get('departamento_id')
    try:
        conn = get_db_connection()
        conn.execute("INSERT INTO colaboradores (nome, email, departamento_id) VALUES (?, ?, ?)", (nome, email, departamento_id))
        conn.commit(); conn.close()
        flash(f"Colaborador '{nome}' adicionado com sucesso!", "success")
    except sqlite3.IntegrityError:
        flash(f"O e-mail '{email}' já está cadastrado.", "error")
    return redirect(url_for('colaboradores'))

@app.route('/colaboradores/editar/<int:colaborador_id>', methods=['GET', 'POST'])
@require_role('gestor')
def editar_colaborador(colaborador_id):
    conn = get_db_connection()
    if request.method == 'POST':
        nome = request.form.get('nome')
        email = request.form.get('email')
        departamento_id = request.form.get('departamento_id')
        try:
            conn.execute('UPDATE colaboradores SET nome = ?, email = ?, departamento_id = ? WHERE id = ?', (nome, email, departamento_id, colaborador_id))
            conn.commit()
            flash('Colaborador atualizado com sucesso!', 'success')
            return redirect(url_for('colaboradores'))
        except sqlite3.IntegrityError:
            flash(f"O e-mail '{email}' já pertence a outro colaborador.", "error")
    colaborador = conn.execute('SELECT * FROM colaboradores WHERE id = ?', (colaborador_id,)).fetchone()
    departamentos = conn.execute("SELECT * FROM departamentos ORDER BY nome").fetchall()
    conn.close()
    return render_template('editar_colaborador.html', active_page='colaboradores', colaborador=colaborador, departamentos=departamentos)

@app.route('/colaboradores/excluir/<int:colaborador_id>', methods=['POST'])
@require_role('gestor')
def excluir_colaborador(colaborador_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM colaboradores WHERE id = ?", (colaborador_id,))
    conn.commit(); conn.close()
    flash("Colaborador excluído com sucesso!", "success")
    return redirect(url_for('colaboradores'))

@app.route('/perguntas')
@require_role('gestor')
def perguntas():
    conn = get_db_connection()
    lista_perguntas = conn.execute("SELECT * FROM perguntas ORDER BY id").fetchall()
    conn.close()
    return render_template('perguntas.html', active_page='perguntas', perguntas=lista_perguntas)

@app.route('/perguntas/adicionar', methods=['POST'])
@require_role('gestor')
def adicionar_pergunta():
    texto = request.form.get('texto')
    if not texto:
        flash("O texto da pergunta é obrigatório.", "error")
    else:
        conn = get_db_connection()
        conn.execute("INSERT INTO perguntas (texto) VALUES (?)", (texto,))
        conn.commit(); conn.close()
        flash("Pergunta adicionada com sucesso!", "success")
    return redirect(url_for('perguntas'))

@app.route('/perguntas/editar/<int:pergunta_id>', methods=['GET', 'POST'])
@require_role('gestor')
def editar_pergunta(pergunta_id):
    conn = get_db_connection()
    if request.method == 'POST':
        texto = request.form.get('texto')
        if not texto:
            flash("O texto da pergunta é obrigatório.", "error")
        else:
            conn.execute('UPDATE perguntas SET texto = ? WHERE id = ?', (texto, pergunta_id))
            conn.commit()
            flash('Pergunta atualizada com sucesso!', 'success')
        conn.close()
        return redirect(url_for('perguntas'))
    pergunta = conn.execute('SELECT * FROM perguntas WHERE id = ?', (pergunta_id,)).fetchone()
    conn.close()
    return render_template('editar_pergunta.html', active_page='perguntas', pergunta=pergunta)

@app.route('/perguntas/excluir/<int:pergunta_id>', methods=['POST'])
@require_role('gestor')
def excluir_pergunta(pergunta_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM perguntas WHERE id = ?", (pergunta_id,))
    conn.commit(); conn.close()
    flash("Pergunta excluída com sucesso!", "success")
    return redirect(url_for('perguntas'))

@app.route('/departamentos')
@require_role('gestor')
def departamentos():
    conn = get_db_connection()
    lista_deptos = conn.execute("SELECT * FROM departamentos ORDER BY nome").fetchall()
    conn.close()
    return render_template('departamentos.html', active_page='departamentos', departamentos=lista_deptos)

@app.route('/departamentos/adicionar', methods=['POST'])
@require_role('gestor')
def adicionar_departamento():
    nome = request.form.get('nome')
    if nome:
        try:
            conn = get_db_connection()
            conn.execute("INSERT INTO departamentos (nome) VALUES (?)", (nome,))
            conn.commit(); conn.close()
            flash(f"Departamento '{nome}' adicionado!", "success")
        except sqlite3.IntegrityError:
            flash(f"Departamento '{nome}' já existe.", "error")
    return redirect(url_for('departamentos'))

@app.route('/departamentos/excluir/<int:depto_id>', methods=['POST'])
@require_role('gestor')
def excluir_departamento(depto_id):
    conn = get_db_connection()
    em_uso = conn.execute("SELECT 1 FROM colaboradores WHERE departamento_id = ?", (depto_id,)).fetchone()
    if em_uso:
        flash("Não é possível excluir. Departamento está em uso por colaboradores.", "error")
    else:
        conn.execute("DELETE FROM departamentos WHERE id = ?", (depto_id,))
        conn.commit()
        flash("Departamento excluído.", "success")
    conn.close()
    return redirect(url_for('departamentos'))

@app.route('/pesquisas')
@require_role('gestor')
def pesquisas():
    conn = get_db_connection()
    pesquisas_criadas = conn.execute("SELECT * FROM pesquisas ORDER BY id DESC").fetchall()
    todas_as_perguntas = conn.execute("SELECT * FROM perguntas ORDER BY id").fetchall()
    todos_os_colaboradores = conn.execute("SELECT * FROM colaboradores ORDER BY nome").fetchall()
    conn.close()
    return render_template('pesquisas.html', active_page='pesquisas',
                           pesquisas=pesquisas_criadas,
                           todas_as_perguntas=todas_as_perguntas,
                           todos_os_colaboradores=todos_os_colaboradores)

@app.route('/pesquisas/criar', methods=['POST'])
@require_role('gestor')
def criar_pesquisa():
    titulo = request.form.get('titulo')
    email_titulo = request.form.get('email_titulo')
    email_corpo = request.form.get('email_corpo')
    agendamento_data = request.form.get('agendamento_data')
    agendamento_hora = request.form.get('agendamento_hora')
    pergunta_ids = request.form.getlist('pergunta_ids')
    colaborador_ids = request.form.getlist('colaborador_ids')

    if not all([titulo, email_titulo, email_corpo, agendamento_data, agendamento_hora, pergunta_ids, colaborador_ids]):
        flash("Todos os campos são obrigatórios.", "error")
        return redirect(url_for('pesquisas'))

    agendamento_completo = f"{agendamento_data} {agendamento_hora}"
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO pesquisas (titulo, email_titulo, email_corpo, agendamento, status) VALUES (?, ?, ?, ?, ?)",
        (titulo, email_titulo, email_corpo, agendamento_completo, 'Agendado')
    )
    pesquisa_id = cursor.lastrowid

    for p_id in pergunta_ids:
        cursor.execute("INSERT INTO pesquisa_perguntas (pesquisa_id, pergunta_id) VALUES (?, ?)", (pesquisa_id, p_id))
    for c_id in colaborador_ids:
        cursor.execute("INSERT INTO pesquisa_colaboradores (pesquisa_id, colaborador_id, token) VALUES (?, ?, ?)",
                       (pesquisa_id, c_id, str(uuid.uuid4())))

    conn.commit(); conn.close()
    flash(f"Pesquisa '{titulo}' agendada com sucesso para {agendamento_data} às {agendamento_hora}!", "success")
    return redirect(url_for('pesquisas'))

@app.route('/pesquisas/resultados/<int:pesquisa_id>')
@require_role('gestor')
def resultados_pesquisa(pesquisa_id):
    conn = get_db_connection()
    pesquisa = conn.execute('SELECT * FROM pesquisas WHERE id = ?', (pesquisa_id,)).fetchone()
    if not pesquisa:
        conn.close()
        return "Pesquisa não encontrada.", 404

    perguntas = conn.execute(
        'SELECT p.* FROM perguntas p JOIN pesquisa_perguntas pp ON p.id = pp.pergunta_id '
        'WHERE pp.pesquisa_id = ? ORDER BY p.id', (pesquisa_id,)
    ).fetchall()
    respostas = conn.execute(
        'SELECT pr.*, c.nome as colaborador_nome, d.nome as depto_nome FROM pesquisa_respostas pr '
        'JOIN colaboradores c ON pr.colaborador_id = c.id '
        'JOIN departamentos d ON c.departamento_id = d.id '
        'WHERE pr.pesquisa_id = ?', (pesquisa_id,)
    ).fetchall()
    convidados = conn.execute(
        'SELECT c.*, d.nome as depto_nome FROM colaboradores c '
        'JOIN pesquisa_colaboradores pc ON c.id = pc.colaborador_id '
        'JOIN departamentos d ON c.departamento_id = d.id '
        'WHERE pc.pesquisa_id = ?', (pesquisa_id,)
    ).fetchall()
    conn.close()

    chart_data = {'labels': [], 'data': []}
    pie_chart_data = {'labels': [], 'data': []}
    ids_colaboradores_responderam = {r['colaborador_id'] for r in respostas}

    if respostas:
        for p in perguntas:
            respostas_da_pergunta = [r['resposta_valor'] for r in respostas if r['pergunta_id'] == p['id']]
            media = sum(respostas_da_pergunta) / len(respostas_da_pergunta) if respostas_da_pergunta else 0
            chart_data['labels'].append(p['texto'][:20] + '...')
            chart_data['data'].append(media)

        dept_counts = collections.Counter(r['depto_nome'] for r in respostas)
        pie_chart_data['labels'] = list(dept_counts.keys())
        pie_chart_data['data'] = list(dept_counts.values())

    respostas_por_colaborador = {}
    colaboradores_que_responderam = sorted(
        [c for c in convidados if c['id'] in ids_colaboradores_responderam],
        key=lambda x: x['nome']
    )
    for c in colaboradores_que_responderam:
        respostas_por_colaborador[c] = {r['pergunta_id']: r['resposta_valor'] for r in respostas if r['colaborador_id'] == c['id']}

    return render_template(
        'resultados_pesquisa.html',
        active_page='pesquisas',
        pesquisa=pesquisa,
        perguntas=perguntas,
        chart_data=chart_data,
        pie_chart_data=pie_chart_data,
        respostas_por_colaborador=respostas_por_colaborador,
        total_respostas=len(ids_colaboradores_responderam),
        total_convidados=len(convidados)
    )

@app.route('/exportar_csv')
@require_role('gestor')
def exportar_csv():
    start_date_str = request.args.get('start_date', date.min.isoformat())
    end_date_str = request.args.get('end_date', date.today().isoformat())
    end_date_full_str = f"{end_date_str}T23:59:59"

    conn = get_db_connection()
    query = "SELECT timestamp, nome, departamento_id, q1, q2, q3 FROM respostas WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp DESC"
    respostas = conn.execute(query, (start_date_str, end_date_full_str)).fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')
    writer.writerow(['Timestamp', 'Nome Completo', 'Departamento ID', 'Q1', 'Q2', 'Q3'])
    for resposta in respostas:
        writer.writerow(resposta)
    output.seek(0)
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=relatorio_burnout.csv"})

# ----------------- Execução -----------------
if __name__ == '__main__':
    init_db()

    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(disparar_pesquisas_agendadas, 'interval', minutes=1)
    scheduler.start()
    print("Agendador iniciado. Verificando pesquisas a cada minuto.")

    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
