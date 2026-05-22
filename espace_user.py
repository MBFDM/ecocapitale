import streamlit as st
import mysql.connector
from mysql.connector import Error
import hashlib
import uuid
import json
from datetime import datetime
import time
import os
from streamlit_option_menu import option_menu
from streamlit_lottie import st_lottie
import requests
from fpdf import FPDF
from num2words import num2words
import qrcode
from io import BytesIO
from PIL import Image

# ============================================================
# CONFIGURATION STREAMLIT
# ============================================================
st.set_page_config(
    page_title="Eco Capital - Espace Client",
    page_icon="assets/logo.png",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================
# CSS STYLE (IDENTIQUE AU CODE 2)
# ============================================================
def set_custom_theme():
    """Définit les thèmes light et dark avec animations (identique au Code 2)"""
    st.markdown(f"""
    <style>
        /* ===== THÈME LIGHT ===== */
        [data-testid="stAppViewContainer"] > .main {{
            background-color: #f8f9fa;
            background-image: linear-gradient(135deg, rgba(174, 176, 202, 0.05) 0%, #f8f9fa 100%);
        }}
        
        /* ===== THÈME DARK ===== */
        @media (prefers-color-scheme: dark) {{
            [data-testid="stAppViewContainer"] > .main {{
                background-color: #0e1117;
                background-image: linear-gradient(135deg, rgba(19, 23, 34, 0.8) 0%, #0e1117 100%);
                color: #f0f2f6;
            }}
        }}
        
        /* ===== ANIMATIONS COMMUNES ===== */
        @keyframes gradientBG {{
            0% {{ background-position: 0% 50%; }}
            50% {{ background-position: 100% 50%; }}
            100% {{ background-position: 0% 50%; }}
        }}
        
        /* Header animé */
        [data-testid="stHeader"] {{
            background-color: rgba(255, 255, 255, 0.9);
            backdrop-filter: blur(5px);
            transition: all 0.3s ease;
            box-shadow: 0 2px 15px rgba(0, 0, 0, 0.1);
        }}
        
        @media (prefers-color-scheme: dark) {{
            [data-testid="stHeader"] {{
                background-color: rgba(14, 17, 23, 0.9);
                box-shadow: 0 2px 15px rgba(0, 0, 0, 0.3);
            }}
        }}
        
        /* Titres animés */
        h1, h2, h3, h4, h5, h6 {{
            animation: fadeIn 0.8s ease-out;
        }}
        
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(10px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        
        /* Boutons avec effets */
        .stButton>button {{
            border-radius: 8px;
            transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
            transform: translateY(0);
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }}
        
        .stButton>button {{
            background-color: #4a6fa5;
            color: white;
        }}
        
        .stButton>button:hover {{
            background-color: #3a5a8f;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
        }}
        
        @media (prefers-color-scheme: dark) {{
            .stButton>button {{
                background-color: #166088;
                color: white;
            }}
            
            .stButton>button:hover {{
                background-color: #0d4b6e;
            }}
        }}
        
        /* Cartes métriques */
        [data-testid="metric-container"] {{
            border-radius: 10px;
            padding: 1rem;
            transition: all 0.3s ease;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }}
        
        [data-testid="metric-container"] {{
            background-color: white;
            border-left: 4px solid #4a6fa5;
        }}
        
        @media (prefers-color-scheme: dark) {{
            [data-testid="metric-container"] {{
                background-color: #1e2130;
                border-left: 4px solid #166088;
            }}
        }}
        
        [data-testid="metric-container"]:hover {{
            transform: translateY(-5px);
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.15);
        }}
        
        /* Tableaux */
        [data-testid="stDataFrame"] {{
            border-radius: 10px;
            animation: fadeInUp 0.6s ease-out;
        }}
        
        @keyframes fadeInUp {{
            from {{ opacity: 0; transform: translateY(20px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        
        /* Conteneur principal */
        .main-container {{
            background: linear-gradient(135deg, #f8faff 0%, #e6ecff 100%);
            border-radius: 18px;
            padding: 2rem;
            box-shadow: 0 12px 24px rgba(0,0,0,0.08);
            margin-bottom: 2rem;
            transition: all 0.5s ease;
        }}
        
        @media (prefers-color-scheme: dark) {{
            .main-container {{
                background: linear-gradient(145deg, #1a1a2e 0%, #16213e 100%);
                box-shadow: 0 12px 28px rgba(16, 20, 58, 0.3);
            }}
        }}
        
        .main-container:hover {{
            transform: translateY(-5px);
            box-shadow: 0 20px 40px rgba(0,0,0,0.15);
        }}
        
        .animated-entry {{
            animation: fadeInSlide 0.8s ease-out;
        }}
        
        @keyframes fadeInSlide {{
            from {{ 
                opacity: 0;
                transform: translateY(20px);
            }}
            to {{ 
                opacity: 1;
                transform: translateY(0);
            }}
        }}
        
        /* Onglets stylisés */
        [data-testid="stTabs"] [role="tablist"] {{
            gap: 5px;
        }}
        
        [data-testid="stTabs"] [role="tab"] {{
            padding: 10px 20px;
            border-radius: 8px 8px 0 0;
            transition: all 0.3s ease;
        }}
        
        [data-testid="stTabs"] [role="tab"] {{
            background-color: rgba(74, 111, 165, 0.1);
        }}
        
        [data-testid="stTabs"] [aria-selected="true"] {{
            background-color: #4a6fa5;
            color: white;
            font-weight: bold;
        }}
        
        @media (prefers-color-scheme: dark) {{
            [data-testid="stTabs"] [role="tab"] {{
                background-color: rgba(22, 96, 136, 0.2);
            }}
            
            [data-testid="stTabs"] [aria-selected="true"] {{
                background-color: #166088;
            }}
        }}
        
        /* Cartes personnalisées */
        .custom-card {{
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            transition: all 0.3s ease;
            border-left: 4px solid #4a6fa5;
        }}
        
        .custom-card {{
            background-color: white;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }}
        
        @media (prefers-color-scheme: dark) {{
            .custom-card {{
                background-color: #1e2130;
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
                border-left: 4px solid #166088;
            }}
        }}
        
        .custom-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 8px 16px rgba(0, 0, 0, 0.15);
        }}
        
        /* Login container */
        .login-container {{
            background: linear-gradient(-45deg, #ee7752, #e73c7e, #23a6d5, #23d5ab);
            background-size: 400% 400%;
            animation: gradientBG 15s ease infinite;
            padding: 2em;
            border-radius: 15px;
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
            color: white;
        }}
        
        /* Scrollbar */
        ::-webkit-scrollbar {{
            width: 8px;
        }}
        
        ::-webkit-scrollbar-track {{
            background: #f1f1f1;
            border-radius: 10px;
        }}
        
        ::-webkit-scrollbar-thumb {{
            background: #4a6fa5;
            border-radius: 10px;
        }}
        
        ::-webkit-scrollbar-thumb:hover {{
            background: #3a5a8f;
        }}
    </style>
    """, unsafe_allow_html=True)

# ============================================================
# CLASSE DATABASE
# ============================================================
class Database:
    def __init__(self):
        self.connection = None
        self.cursor = None
        self._connect()
        self._fix_and_create_tables()

    def _connect(self):
        """Connexion à MySQL"""
        try:
            self.connection = mysql.connector.connect(
                host='ecocapital-mbfdm.c.aivencloud.com',
                user='avnadmin',
                password='AVNS_3a2plzaevzttmJ4Tcs9',
                database='ecocapital',
                port=14431,
                connect_timeout=30,
                buffered=True,
                charset='utf8mb4',
                collation='utf8mb4_unicode_ci'
            )
            self.cursor = self.connection.cursor(dictionary=True)
            self.cursor.execute("SELECT 1")
            print("✅ Connexion MySQL réussie")
        except Error as e:
            st.error(f"❌ Erreur de connexion MySQL : {e}")
            st.stop()

    def _get_existing_columns(self, table_name):
        try:
            self.cursor.execute(f"SHOW COLUMNS FROM {table_name}")
            columns = self.cursor.fetchall()
            return [col['Field'] for col in columns]
        except Error:
            return []

    def _fix_utilisateurs_table(self):
        existing_columns = self._get_existing_columns('utilisateurs')
        
        if not existing_columns:
            print("Création de la table utilisateurs...")
            return False
        
        required_columns = {
            'id': 'VARCHAR(36) NOT NULL PRIMARY KEY',
            'first_name': 'VARCHAR(100) NOT NULL',
            'last_name': 'VARCHAR(100) NOT NULL',
            'email': 'VARCHAR(255) NOT NULL UNIQUE',
            'phone': 'VARCHAR(50)',
            'password': 'VARCHAR(255) NOT NULL',
            'created_at': 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP',
            'last_login': 'TIMESTAMP NULL',
            'is_active': 'BOOLEAN DEFAULT TRUE'
        }
        
        for col_name, col_def in required_columns.items():
            if col_name not in existing_columns:
                try:
                    if col_name == 'id':
                        self.cursor.execute(f"ALTER TABLE utilisateurs ADD COLUMN {col_name} {col_def} FIRST")
                    elif col_name == 'first_name':
                        if 'name' in existing_columns:
                            self.cursor.execute("ALTER TABLE utilisateurs CHANGE name first_name VARCHAR(100) NOT NULL")
                            continue
                        self.cursor.execute(f"ALTER TABLE utilisateurs ADD COLUMN {col_name} {col_def} AFTER id")
                    elif col_name == 'last_name':
                        self.cursor.execute(f"ALTER TABLE utilisateurs ADD COLUMN {col_name} {col_def} AFTER first_name")
                    elif col_name == 'email':
                        if 'email' in existing_columns:
                            try:
                                self.cursor.execute("ALTER TABLE utilisateurs MODIFY COLUMN email VARCHAR(255) NOT NULL UNIQUE")
                            except Error:
                                pass
                            continue
                        self.cursor.execute(f"ALTER TABLE utilisateurs ADD COLUMN {col_name} {col_def} AFTER last_name")
                    elif col_name == 'phone':
                        self.cursor.execute(f"ALTER TABLE utilisateurs ADD COLUMN {col_name} {col_def} AFTER email")
                    elif col_name == 'password':
                        if 'password' in existing_columns:
                            continue
                        self.cursor.execute(f"ALTER TABLE utilisateurs ADD COLUMN {col_name} {col_def} AFTER phone")
                    else:
                        self.cursor.execute(f"ALTER TABLE utilisateurs ADD COLUMN {col_name} {col_def}")
                except Error as e:
                    print(f"⚠️ Impossible d'ajouter {col_name}: {e}")
        
        try:
            self.cursor.execute("SHOW KEYS FROM utilisateurs WHERE Key_name = 'PRIMARY'")
            pk = self.cursor.fetchall()
            if not pk or pk[0]['Column_name'] != 'id':
                try:
                    self.cursor.execute("ALTER TABLE utilisateurs DROP PRIMARY KEY")
                except Error:
                    pass
                self.cursor.execute("ALTER TABLE utilisateurs ADD PRIMARY KEY (id)")
        except Error as e:
            print(f"⚠️ Erreur clé primaire: {e}")
        
        self.connection.commit()
        return True

    def _fix_and_create_tables(self):
        try:
            self.cursor.execute("SET FOREIGN_KEY_CHECKS = 0")
            
            self.cursor.execute("""
                SELECT COUNT(*) as cnt FROM information_schema.tables 
                WHERE table_schema = 'ecocapital' AND table_name = 'utilisateurs'
            """)
            table_exists = self.cursor.fetchone()['cnt'] > 0
            
            if table_exists:
                self._fix_utilisateurs_table()
            else:
                self.cursor.execute("""
                    CREATE TABLE IF NOT EXISTS utilisateurs (
                        id VARCHAR(36) NOT NULL,
                        first_name VARCHAR(100) NOT NULL,
                        last_name VARCHAR(100) NOT NULL,
                        email VARCHAR(255) NOT NULL,
                        phone VARCHAR(50),
                        password VARCHAR(255) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP NULL,
                        is_active BOOLEAN DEFAULT TRUE,
                        PRIMARY KEY (id),
                        UNIQUE KEY uk_email (email)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """)
            
            tables_sql = [
                """CREATE TABLE IF NOT EXISTS avi_requests (
                    id VARCHAR(50) NOT NULL PRIMARY KEY,
                    user_id VARCHAR(36) NOT NULL,
                    user_email VARCHAR(255),
                    request_data JSON,
                    status VARCHAR(50) DEFAULT 'En attente',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    KEY idx_avi_user (user_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
                
                """CREATE TABLE IF NOT EXISTS messages (
                    id VARCHAR(36) NOT NULL PRIMARY KEY,
                    user_id VARCHAR(36) NOT NULL,
                    sender VARCHAR(50) NOT NULL,
                    content TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_read BOOLEAN DEFAULT FALSE,
                    KEY idx_msg_user (user_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
                
                """CREATE TABLE IF NOT EXISTS conversations (
                    id VARCHAR(36) NOT NULL PRIMARY KEY,
                    user_id VARCHAR(36) NOT NULL,
                    name VARCHAR(255) NOT NULL,
                    last_message TEXT,
                    unread_count INT DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    KEY idx_conv_user (user_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
                
                """CREATE TABLE IF NOT EXISTS documents (
                    id VARCHAR(36) NOT NULL PRIMARY KEY,
                    user_id VARCHAR(36) NOT NULL,
                    request_id VARCHAR(50),
                    filename VARCHAR(255) NOT NULL,
                    file_type VARCHAR(50),
                    file_size INT,
                    file_data LONGBLOB,
                    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    KEY idx_doc_user (user_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"""
            ]
            
            for sql in tables_sql:
                self.cursor.execute(sql)
            
            self.cursor.execute("SET FOREIGN_KEY_CHECKS = 1")
            self.connection.commit()
            
        except Error as e:
            print(f"❌ Erreur: {e}")
            st.error(f"Erreur MySQL: {e}")

    # ==================== UTILISATEURS ====================
    def create_user(self, first_name, last_name, email, phone, password):
        try:
            user_id = str(uuid.uuid4())
            hashed_pw = hashlib.sha256(password.encode()).hexdigest()
            
            existing = self.get_user_by_email(email)
            if existing:
                return False, "Cet email est déjà utilisé"
            
            self.cursor.execute(
                "INSERT INTO utilisateurs (id, first_name, last_name, email, phone, password) VALUES (%s,%s,%s,%s,%s,%s)",
                (user_id, first_name, last_name, email, phone, hashed_pw)
            )
            self.connection.commit()
            return True, user_id
        except Error as e:
            return False, str(e)

    def authenticate_user(self, email, password):
        try:
            hashed_pw = hashlib.sha256(password.encode()).hexdigest()
            self.cursor.execute(
                "SELECT * FROM utilisateurs WHERE email=%s AND password=%s AND is_active=TRUE",
                (email, hashed_pw)
            )
            user = self.cursor.fetchone()
            if user:
                self.cursor.execute("UPDATE utilisateurs SET last_login=NOW() WHERE id=%s", (user['id'],))
                self.connection.commit()
            return user
        except Error as e:
            return None

    def get_user_by_email(self, email):
        try:
            self.cursor.execute("SELECT * FROM utilisateurs WHERE email=%s", (email,))
            return self.cursor.fetchone()
        except Error:
            return None

    # ==================== AVI ====================
    def create_avi_request(self, user_id, user_email, request_data):
        try:
            date_str = datetime.now().strftime('%Y%m%d')
            self.cursor.execute("SELECT COUNT(*) as c FROM avi_requests WHERE id LIKE %s", (f"AVI-{date_str}-%",))
            count = self.cursor.fetchone()['c'] + 1
            request_id = f"AVI-{date_str}-{count:03d}"
            self.cursor.execute(
                "INSERT INTO avi_requests (id, user_id, user_email, request_data) VALUES (%s,%s,%s,%s)",
                (request_id, user_id, user_email, json.dumps(request_data))
            )
            self.connection.commit()
            return True, request_id
        except Error as e:
            return False, str(e)

    def get_user_avi_requests(self, user_id):
        try:
            self.cursor.execute("SELECT * FROM avi_requests WHERE user_id=%s ORDER BY created_at DESC", (user_id,))
            requests = self.cursor.fetchall()
            for r in requests:
                if isinstance(r.get('request_data'), str):
                    r['request_data'] = json.loads(r['request_data'])
            return requests
        except Error:
            return []

    def get_avi_stats(self, user_id):
        stats = {}
        queries = {
            'total': "SELECT COUNT(*) as c FROM avi_requests WHERE user_id=%s",
            'validated': "SELECT COUNT(*) as c FROM avi_requests WHERE user_id=%s AND status='Validée'",
            'pending': "SELECT COUNT(*) as c FROM avi_requests WHERE user_id=%s AND status='En attente'",
            'rejected': "SELECT COUNT(*) as c FROM avi_requests WHERE user_id=%s AND status='Rejetée'"
        }
        for key, query in queries.items():
            try:
                self.cursor.execute(query, (user_id,))
                stats[key] = self.cursor.fetchone()['c']
            except Error:
                stats[key] = 0
        return stats

    # ==================== MESSAGES ====================
    def create_conversation(self, user_id, name):
        try:
            conv_id = str(uuid.uuid4())
            self.cursor.execute("INSERT INTO conversations (id, user_id, name) VALUES (%s,%s,%s)", (conv_id, user_id, name))
            self.connection.commit()
            return conv_id
        except Error:
            return None

    def get_user_conversations(self, user_id):
        try:
            self.cursor.execute("SELECT * FROM conversations WHERE user_id=%s ORDER BY created_at DESC", (user_id,))
            return self.cursor.fetchall()
        except Error:
            return []

    def send_message(self, user_id, sender, content):
        try:
            msg_id = str(uuid.uuid4())
            self.cursor.execute(
                "INSERT INTO messages (id, user_id, sender, content) VALUES (%s,%s,%s,%s)",
                (msg_id, user_id, sender, content)
            )
            self.connection.commit()
            return True, msg_id
        except Error as e:
            return False, str(e)

    def get_user_messages(self, user_id, limit=50):
        try:
            self.cursor.execute("SELECT * FROM messages WHERE user_id=%s ORDER BY timestamp DESC LIMIT %s", (user_id, limit))
            msgs = self.cursor.fetchall()
            self.cursor.execute("UPDATE messages SET is_read=TRUE WHERE user_id=%s AND sender='support' AND is_read=FALSE", (user_id,))
            self.connection.commit()
            return msgs[::-1]
        except Error:
            return []

    def get_unread_messages_count(self, user_id):
        try:
            self.cursor.execute("SELECT COUNT(*) as c FROM messages WHERE user_id=%s AND sender='support' AND is_read=FALSE", (user_id,))
            return self.cursor.fetchone()['c']
        except Error:
            return 0

    def save_document(self, user_id, filename, file_data, file_type):
        try:
            doc_id = str(uuid.uuid4())
            self.cursor.execute(
                "INSERT INTO documents (id, user_id, filename, file_type, file_size, file_data) VALUES (%s,%s,%s,%s,%s,%s)",
                (doc_id, user_id, filename, file_type, len(file_data), file_data)
            )
            self.connection.commit()
            return True, doc_id
        except Error as e:
            return False, str(e)

    def get_user_avis(self, user_id):
        try:
            self.cursor.execute('''
            SELECT 
                reference,
                nom_complet,
                code_banque,
                numero_compte,
                devise,
                iban,
                bic,
                montant,
                date_creation,
                date_expiration,
                statut,
                commentaires,
                created_at
            FROM avis
            ORDER BY date_creation DESC
            ''')
            return self.cursor.fetchall()
        except Error as e:
            return []

# ============================================================
# INIT DB
# ============================================================
@st.cache_resource
def get_db():
    return Database()

db = get_db()

# ============================================================
# ANIMATION LOTTIE
# ============================================================
def load_lottieurl(url):
    try:
        r = requests.get(url)
        if r.status_code != 200:
            return None
        return r.json()
    except:
        return None

# ============================================================
# PAGE D'AUTHENTIFICATION
# ============================================================
def auth_page():
    set_custom_theme()
    
    lottie_banking = load_lottieurl("https://assets5.lottiefiles.com/packages/lf20_xyadoh9h.json")
    
    st.markdown("""
    <div style="text-align: center; padding: 2rem; background: linear-gradient(135deg, #4a6fa5, #166088); border-radius: 20px; margin-bottom: 2rem;">
        <h1 style="color: white; font-size: 2.5rem;">🏦 Eco Capital</h1>
        <p style="color: rgba(255,255,255,0.9);">Votre Partenaire Financier de Confiance</p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        if lottie_banking:
            st_lottie(lottie_banking, height=350, key="banking")
    
    with col2:
        st.markdown('<div class="login-container">', unsafe_allow_html=True)
        
        tab1, tab2 = st.tabs(["🔑 Connexion", "📝 Inscription"])
        
        with tab1:
            with st.form("login_form"):
                email = st.text_input("Email", placeholder="exemple@email.com")
                password = st.text_input("Mot de passe", type="password")
                
                if st.form_submit_button("Se connecter", use_container_width=True):
                    if email and password:
                        user = db.authenticate_user(email, password)
                        if user:
                            st.session_state.logged_in = True
                            st.session_state.user = user
                            st.success("Connexion réussie !")
                            st.rerun()
                        else:
                            st.error("Email ou mot de passe incorrect")
        
        with tab2:
            with st.form("register_form"):
                col1, col2 = st.columns(2)
                with col1:
                    first_name = st.text_input("Prénom")
                with col2:
                    last_name = st.text_input("Nom")
                
                email = st.text_input("Email")
                phone = st.text_input("Téléphone")
                password = st.text_input("Mot de passe", type="password")
                confirm = st.text_input("Confirmer", type="password")
                terms = st.checkbox("J'accepte les conditions générales")
                
                if st.form_submit_button("Créer mon compte", use_container_width=True):
                    if password == confirm and terms:
                        ok, res = db.create_user(first_name, last_name, email, phone, password)
                        if ok:
                            st.success("Compte créé avec succès !")
                        else:
                            st.error(f"Erreur : {res}")
                    else:
                        st.error("Vérifiez les informations")
        
        st.markdown('</div>', unsafe_allow_html=True)

# ============================================================
# DASHBOARD
# ============================================================
def dashboard_page():
    set_custom_theme()
    
    st.markdown(f"""
    <div class="main-container animated-entry">
        <h1>👋 Bienvenue, {st.session_state.user.get('first_name', 'Utilisateur')} !</h1>
        <p>Voici votre tableau de bord personnalisé</p>
    </div>
    """, unsafe_allow_html=True)
    
    stats = db.get_avi_stats(st.session_state.user['id'])
    unread = db.get_unread_messages_count(st.session_state.user['id'])
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("📋 Demandes AVI", stats['total'])
    with col2:
        st.metric("✅ Validées", stats['validated'])
    with col3:
        st.metric("⏳ En attente", stats['pending'])
    with col4:
        st.metric("💬 Messages", unread)
    
    st.markdown("## 📊 Activités Récentes")
    
    user_requests = db.get_user_avi_requests(st.session_state.user['id'])
    
    if user_requests:
        for req in user_requests[:5]:
            with st.container():
                st.markdown(f"""
                <div class="custom-card">
                    <strong>{req['id']}</strong><br>
                    📅 {req['created_at'].strftime('%d/%m/%Y %H:%M')}<br>
                    💰 {req['request_data'].get('avi_amount', 'N/A')}<br>
                    <span style="color: {'orange' if req['status'] == 'En attente' else 'green' if req['status'] == 'Validée' else 'red'}">
                        {req['status']}
                    </span>
                </div>
                """, unsafe_allow_html=True)
    else:
        st.info("Aucune activité récente")

# ============================================================
# PAGE DEMANDE AVI
# ============================================================
def avi_request_page():
    set_custom_theme()
    
    st.markdown("""
    <div class="main-container animated-entry">
        <h2>📋 Nouvelle Demande d'AVI</h2>
        <p>Attestation de Vérification d'Identité - Traitement sous 48h</p>
    </div>
    """, unsafe_allow_html=True)
    
    if 'avi_step' not in st.session_state:
        st.session_state.avi_step = 1
    
    steps = ["📝 Informations", "📎 Documents", "✅ Validation"]
    step = st.session_state.avi_step
    
    st.progress(step / 3)
    
    if step == 1:
        with st.container():
            st.markdown("### 📝 Informations Personnelles")
            
            col1, col2 = st.columns(2)
            with col1:
                last_name = st.text_input("Nom *")
                birth_date = st.date_input("Date de naissance *")
                nationality = st.text_input("Nationalité *")
            with col2:
                first_name = st.text_input("Prénom(s) *")
                birth_place = st.text_input("Lieu de naissance *")
            
            st.markdown("### 🏠 Adresse")
            col1, col2 = st.columns(2)
            with col1:
                address = st.text_input("Adresse *")
                postal_code = st.text_input("Code postal *")
            with col2:
                city = st.text_input("Ville *")
                country = st.selectbox("Pays *", ["Congo Brazzaville", "Chine", "Maroc", "Gabon", "Turquie"])
            
            if st.button("Suivant ➡️", use_container_width=True):
                if all([last_name, first_name, birth_date, birth_place, nationality, address, postal_code, city, country]):
                    st.session_state.avi_data = {
                        'last_name': last_name, 'first_name': first_name,
                        'birth_date': str(birth_date), 'birth_place': birth_place,
                        'nationality': nationality, 'address': address,
                        'postal_code': postal_code, 'city': city, 'country': country
                    }
                    st.session_state.avi_step = 2
                    st.rerun()
                else:
                    st.error("Veuillez remplir tous les champs")
    
    elif step == 2:
        with st.container():
            st.markdown("### 📎 Pièces Justificatives")
            
            identity_doc = st.file_uploader("Pièce d'identité *", type=['jpg','jpeg','png','pdf'])
            avi_amount = st.text_input("Montant AVI *", placeholder="500000 XAF")
            consent = st.checkbox("Je certifie l'exactitude des informations *")
            
            col1, col2, col3 = st.columns([1, 1, 1])
            if col1.button("⬅️ Précédent"):
                st.session_state.avi_step = 1
                st.rerun()
            if col3.button("Suivant ➡️"):
                if identity_doc and avi_amount and consent:
                    db.save_document(st.session_state.user['id'], identity_doc.name, identity_doc.read(), identity_doc.type)
                    st.session_state.avi_data['avi_amount'] = avi_amount
                    st.session_state.avi_step = 3
                    st.rerun()
                else:
                    st.error("Veuillez remplir tous les champs")
    
    elif step == 3:
        with st.container():
            st.markdown("### ✅ Validation Finale")
            
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"**Nom:** {st.session_state.avi_data.get('first_name')} {st.session_state.avi_data.get('last_name')}")
                st.write(f"**Date naissance:** {st.session_state.avi_data.get('birth_date')}")
            with col2:
                st.write(f"**Adresse:** {st.session_state.avi_data.get('address')}")
                st.write(f"**Montant:** {st.session_state.avi_data.get('avi_amount')}")
            
            final_consent = st.checkbox("Je confirme les informations")
            
            col1, col2, col3 = st.columns([1, 1, 1])
            if col1.button("⬅️ Précédent"):
                st.session_state.avi_step = 2
                st.rerun()
            if col3.button("📤 Soumettre"):
                if final_consent:
                    ok, ref = db.create_avi_request(st.session_state.user['id'], st.session_state.user['email'], st.session_state.avi_data)
                    if ok:
                        st.success(f"Demande {ref} soumise avec succès !")
                        st.session_state.avi_step = 1
                        st.session_state.avi_data = {}
                    else:
                        st.error(f"Erreur: {ref}")

# ============================================================
# PAGE MES AVI (DESIGN AMÉLIORÉ) - VERSION COMPLÈTE
# ============================================================
def my_avi_page():
    set_custom_theme()
    
    st.markdown("""
    <div class="animate-fadeInDown" style="margin-bottom: 2rem;">
        <h2 style="font-weight: 800; background: linear-gradient(135deg, #667eea, #764ba2); 
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
            📋 Mes Demandes d'AVI
        </h2>
        <p style="color: #718096; font-weight: 300;">
            Historique complet de vos attestations
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Section 1: Demandes soumises
    st.markdown("### 📝 Demandes soumises")
    user_requests = db.get_user_avi_requests(st.session_state.user['id'])
    
    if not user_requests:
        st.info("📭 Aucune demande trouvée. Créez votre première demande !")
        if st.button("➕ Nouvelle Demande", use_container_width=True):
            st.session_state.avi_step = 1
            st.session_state.menu = "Demande AVI"
            st.rerun()
    else:
        st.markdown('<div class="timeline-premium">', unsafe_allow_html=True)
        
        for i, req in enumerate(user_requests):
            status_color = {'En attente': '#ed8936', 'Validée': '#48bb78', 'Rejetée': '#f56565'}.get(req['status'], '#a0aec0')
            status_emoji = {'En attente': '⏳', 'Validée': '✅', 'Rejetée': '❌'}.get(req['status'], '📋')
            
            st.markdown(f"""
            <div class="timeline-item-premium" style="animation-delay: {i * 0.1}s;">
                <div class="timeline-dot-premium" style="background: linear-gradient(135deg, {status_color}, {status_color}dd);"></div>
                <div class="card-premium">
                    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;">
                        <div>
                            <h4 style="margin: 0; font-size: 1.2rem;">{req['id']}</h4>
                            <p style="color: #718096; margin: 0.25rem 0;">
                                📅 {req['created_at'].strftime('%d/%m/%Y à %H:%M')}
                            </p>
                            <p style="margin: 0.25rem 0;">
                                💰 <strong>{req['request_data'].get('avi_amount', 'N/A')}</strong>
                            </p>
                        </div>
                        <div style="text-align: right;">
                            <span class="badge-premium" style="background: {status_color}20; color: {status_color}; 
                                border: 1px solid {status_color}; font-size: 0.9rem; padding: 0.5rem 1.2rem;">
                                {status_emoji} {req['status']}
                            </span>
                        </div>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown('</div>', unsafe_allow_html=True)

    # Section 2: AVI générées (nouvelles)
    st.markdown("---")
    st.markdown("### 📄 Attestations AVI Générées")

    user_avis = db.get_user_avis(st.session_state.user['id'])

    if not user_avis:
        st.info("📭 Aucune attestation AVI n'a encore été générée pour vous")
    else:
        from fpdf import FPDF
        from num2words import num2words
        import qrcode
        from io import BytesIO
        from PIL import Image
        
        def montant_en_lettres(montant):
            """Convertit un montant numérique en lettres françaises avec devise"""
            try:
                partie_entiere = int(montant)
                partie_decimale = int(round((montant - partie_entiere) * 100))
                
                texte = num2words(partie_entiere, lang='fr')
                
                if partie_entiere > 1:
                    texte += " francs CFA"
                else:
                    texte += " franc CFA"
                
                if partie_decimale > 0:
                    texte += " et " + num2words(partie_decimale, lang='fr') + " centimes"
                
                return texte.capitalize()
            except:
                return f"{montant:,.2f} francs CFA"
        
        def generate_avi_pdf(avi_data):
            try:
                pdf = FPDF()
                pdf.add_page()
                
                # ---- Ajout des logos floutés en arrière-plan (comme dans Code 2) ----
                try:
                    logo_path = "assets/logo.png"
                    if os.path.exists(logo_path):
                        img = Image.open(logo_path)
                        
                        if img.mode != 'RGBA':
                            img = img.convert('RGBA')
                        
                        data = img.getdata()
                        new_data = []
                        for item in data:
                            new_data.append((item[0], item[1], item[2], int(item[3] * 0.2)))
                        img.putdata(new_data)
                        
                        temp_logo = BytesIO()
                        img.save(temp_logo, format='PNG')
                        temp_logo.seek(0)
                        
                        for position in [(30, 30), (120, 200), (50, 300), (100, 100)]:
                            pdf.image(temp_logo, x=position[0], y=position[1], w=100)
                except Exception as e:
                    pass
                
                # ---- En-tête ----
                pdf.set_font('Arial', 'B', 16)
                pdf.cell(0, 30, 'ATTESTATION DE VIREMENT IRREVOCABLE', 0, 1, 'C')
                
                # Référence du document
                pdf.set_font('Arial', 'B', 10)
                pdf.cell(0, 0, f"DGF/EC-{avi_data.get('reference', 'N/A')}", 0, 1, 'C')
                pdf.ln(10)
                
                # ---- Logo principal ----
                try:
                    if os.path.exists("assets/logo.png"):
                        pdf.image("assets/logo.png", x=10, y=10, w=30)
                except:
                    pass
                
                # ---- Corps du document (identique au Code 2) ----
                pdf.set_font('Arial', '', 12)
                intro = [
                    "Nous soussignés, Eco Capital (E.C), établissement de microfinance agréé pour exercer des",
                    "activités bancaires en République du Congo conformément au décret n°7236/MEFB-CAB du",
                    "15 novembre 2007, après avis conforme de la COBAC D-2007/2018, déclarons avoir notre",
                    "siège au n°1636 Boulevard Denis Sassou Nguesso, Batignol Brazzaville.",
                    "",
                    "Représenté par son Directeur Général, Monsieur ILOKO Charmant.",
                    "",
                    f"Nous certifions par la présente que Monsieur/Madame {avi_data.get('nom_complet', 'N/A')}",
                    "détient un compte courant enregistré dans nos livres avec les caractéristiques suivantes :",
                    ""
                ]
                
                for line in intro:
                    pdf.cell(0, 5, line, 0, 1)
                
                # Informations bancaires
                pdf.set_font('Arial', 'B', 12)
                pdf.cell(40, 5, "CODE BANQUE :", 0, 0)
                pdf.set_font('Arial', '', 12)
                pdf.cell(0, 5, avi_data.get('code_banque', 'N/A'), 0, 1)
                
                pdf.set_font('Arial', 'B', 12)
                pdf.cell(45, 5, "NUMERO COMPTE : ", 0, 0)
                pdf.set_font('Arial', '', 12)
                pdf.cell(0, 5, avi_data.get('numero_compte', 'N/A'), 0, 1)
                
                pdf.set_font('Arial', 'B', 12)
                pdf.cell(20, 5, "Devise :", 0, 0)
                pdf.set_font('Arial', '', 12)
                pdf.cell(0, 5, avi_data.get('devise', 'XAF'), 0, 1)
                pdf.ln(5)
                
                # Détails du virement
                montant = avi_data.get('montant', 0)
                try:
                    montant_float = float(montant) if montant else 0
                except:
                    montant_float = 0
                
                details = [
                    f"Il est l'ordonnateur d'un virement irrévocable et permanent d'un montant total de {montant_float:,.2f} FCFA",
                    f"({montant_en_lettres(montant_float)}), équivalant actuellement à {montant_float/650:,.2f} euros,",
                    "destiné à couvrir les frais liés à ses études en France.",
                    "",
                    "Il est précisé que ce compte demeurera bloqué jusqu'à la présentation, par le donneur",
                    "d'ordre, de ses nouvelles coordonnées bancaires ouvertes en France.",
                    "",
                    "À défaut, les fonds ne pourront être remis à sa disposition qu'après présentation de son",
                    "passeport attestant d'un refus de visa. Toutefois, nous autorisons le donneur d'ordre, à",
                    "toutes fins utiles, à utiliser notre compte ouvert auprès de United Bank for Africa (UBA).",
                    ""
                ]
                
                for line in details:
                    pdf.cell(0, 5, line, 0, 1)
                
                # Coordonnées bancaires
                pdf.set_font('Arial', 'B', 12)
                pdf.cell(16, 5, "IBAN :", 0, 0)
                pdf.set_font('Arial', '', 12)
                pdf.cell(0, 5, avi_data.get('iban', 'N/A'), 0, 1)
                
                pdf.set_font('Arial', 'B', 12)
                pdf.cell(16, 5, "BIC :", 0, 0)
                pdf.set_font('Arial', '', 12)
                pdf.cell(0, 5, avi_data.get('bic', 'N/A'), 0, 1)
                pdf.ln(10)
                
                # Clause de validation
                pdf.cell(0, 5, "En foi de quoi, cette attestation lui est délivrée pour servir et valoir ce que de droit.", 0, 1)
                pdf.ln(10)
                
                # Date et signature
                date_val = avi_data.get('date_creation')
                if date_val:
                    if hasattr(date_val, 'strftime'):
                        date_str = date_val.strftime('%d %B %Y')
                    else:
                        date_str = str(date_val)
                else:
                    date_str = datetime.now().strftime('%d %B %Y')
                
                pdf.cell(0, 5, f"Fait à Brazzaville, le {date_str}", 0, 1, 'R')
                pdf.ln(5)
                
                pdf.cell(0, 5, "Rubain MOUNGALA", 0, 1)
                pdf.set_font('Arial', 'B', 12)
                pdf.cell(0, 5, "Directeur de la Gestion Financière", 0, 1)
                pdf.ln(15)
                
                # Pied de page (identique au Code 2)
                footer = [
                    "Eco capital Sarl",
                    "Société a responsabilité limité au capital de 60.000.000 XAF",
                    "Siège social : 1636 Boulevard Denis Sassou Nguesso Brazzaville",
                    "Contact: 00242 06 931 31 06 /04 001 79 40",
                    "Web : www.ecocapitale.com mail : contacts@ecocapitale.com",
                    "RCCM N°CG/BZV/B12-00320NIU N°M24000000665934H",
                    "Brazzaville République du Congo"
                ]
                
                pdf.set_font('Arial', 'I', 10)
                for line in footer:
                    pdf.cell(1, 4.5, line, 0, 1, 'L')
                
                # QR Code (identique au Code 2)
                try:
                    qr_data = {
                        "Référence": avi_data.get('reference', 'N/A'),
                        "Nom": avi_data.get('nom_complet', 'N/A'),
                        "Code Banque": avi_data.get('code_banque', 'N/A'),
                        "Numéro Compte": avi_data.get('numero_compte', 'N/A'),
                        "BIC": avi_data.get('bic', 'N/A'),
                        "Montant": f"{montant_float:,.2f} FCFA",
                        "Date Création": date_str
                    }
                    
                    qr = qrcode.QRCode(
                        version=1,
                        error_correction=qrcode.constants.ERROR_CORRECT_L,
                        box_size=3,
                        border=2,
                    )
                    
                    qr.add_data(str(qr_data))
                    qr.make(fit=True)
                    
                    img = qr.make_image(fill_color="black", back_color="white")
                    img_bytes = BytesIO()
                    img.save(img_bytes, format='PNG')
                    img_bytes.seek(0)
                    pdf.image(img_bytes, x=150, y=pdf.get_y() - 40, w=40)
                except Exception as e:
                    pass
                
                # Conversion du PDF en bytes
                output = pdf.output(dest='S')
                if isinstance(output, bytearray):
                    return bytes(output)
                elif isinstance(output, bytes):
                    return output
                else:
                    return output.encode('latin1') if hasattr(output, 'encode') else output
                    
            except Exception as e:
                print(f"Erreur generate_avi_pdf: {e}")
                return None
        
        # Affichage des AVI dans des expanders
        for i, avi in enumerate(user_avis):
            reference = avi.get('reference', 'N/A') if avi.get('reference') else f'AVI_{i+1}'
            nom_complet = avi.get('nom_complet', 'Bénéficiaire non spécifié')
            
            try:
                montant_val = float(avi.get('montant', 0)) if avi.get('montant') else 0
                montant_display = f"{montant_val:,.2f} FCFA"
            except (ValueError, TypeError):
                montant_display = f"{avi.get('montant', 0)} FCFA"
            
            with st.expander(f"📄 {reference} - {nom_complet} - {montant_display}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown(f"""
                    **👤 Informations du bénéficiaire:**
                    - Nom complet: **{avi.get('nom_complet', 'N/A')}**
                    - Code Banque: **{avi.get('code_banque', 'N/A')}**
                    - Numéro de compte: **{avi.get('numero_compte', 'N/A')}**
                    - Devise: **{avi.get('devise', 'XAF')}**
                    """)
                
                with col2:
                    st.markdown(f"""
                    **📄 Détails de l'attestation:**
                    - Référence: **{reference}**
                    - IBAN: **{avi.get('iban', 'N/A')}**
                    - BIC: **{avi.get('bic', 'N/A')}**
                    - Montant: **{montant_display}**
                    - Statut: **{avi.get('statut', 'N/A')}**
                    - Date d'émission: **{avi.get('date_creation').strftime('%d/%m/%Y') if avi.get('date_creation') else 'Date inconnue'}**
                    """)
                
                if avi.get('commentaires'):
                    st.markdown(f"""
                    **📝 Commentaires:**
                    {avi.get('commentaires')}
                    """)
                
                st.markdown("---")
                
                # Bouton de téléchargement
                try:
                    pdf_bytes = generate_avi_pdf(avi)
                    if pdf_bytes:
                        col1, col2, col3 = st.columns([1, 2, 1])
                        with col2:
                            st.download_button(
                                label=f"📥 Télécharger l'attestation {reference}",
                                data=pdf_bytes,
                                file_name=f"AVI_{reference}.pdf",
                                mime="application/pdf",
                                use_container_width=True,
                                key=f"download_{reference}_{i}"
                            )
                    else:
                        st.error(f"Impossible de générer le PDF pour {reference}")
                except Exception as e:
                    st.error(f"Erreur lors de la génération du PDF: {str(e)}")
                    
# ============================================================
# PAGE MESSAGES (DESIGN AMÉLIORÉ)
# ============================================================
def messages_page():
    set_custom_theme()
    
    st.markdown("""
    <div class="animate-fadeInDown" style="margin-bottom: 2rem;">
        <h2 style="font-weight: 800; background: linear-gradient(135deg, #667eea, #764ba2); 
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
            💬 Centre de Messages
        </h2>
        <p style="color: #718096; font-weight: 300;">
            Communiquez directement avec notre équipe support
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.markdown('<div class="card-premium animate-fadeInLeft">', unsafe_allow_html=True)
        st.markdown("### 📋 Conversations")
        
        conversations = db.get_user_conversations(st.session_state.user['id'])
        
        # Vérifier si la liste est vide ou contient des None
        if not conversations or all(conv is None for conv in conversations):
            # Créer des conversations par défaut si nécessaire
            default_conversations = ["Support Technique", "Service AVI", "Comptabilité"]
            for name in default_conversations:
                db.create_conversation(st.session_state.user['id'], name)
            conversations = db.get_user_conversations(st.session_state.user['id'])
        
        # Filtrer les conversations None et s'assurer qu'elles ont les propriétés nécessaires
        valid_conversations = []
        for conv in conversations:
            if conv is not None and isinstance(conv, dict):
                # S'assurer que la conversation a les champs nécessaires
                if 'name' in conv:
                    valid_conversations.append(conv)
                else:
                    # Si la conversation existe mais n'a pas de 'name', on la corrige
                    conv['name'] = f"Conversation {conv.get('id', '')[:8]}"
                    conv['last_message'] = conv.get('last_message', 'Nouvelle conversation')
                    conv['unread_count'] = conv.get('unread_count', 0)
                    valid_conversations.append(conv)
        
        if valid_conversations:
            for conv in valid_conversations:
                # Utiliser .get() avec des valeurs par défaut sécurisées
                conv_name = conv.get('name', 'Conversation')
                conv_last_message = conv.get('last_message', 'Nouvelle conversation')
                conv_unread_count = conv.get('unread_count', 0)
                
                # S'assurer que last_message est une chaîne de caractères
                if conv_last_message is None:
                    conv_last_message = 'Nouvelle conversation'
                elif not isinstance(conv_last_message, str):
                    conv_last_message = str(conv_last_message)
                
                # Tronquer le message si nécessaire
                last_message_preview = conv_last_message[:50] if len(conv_last_message) > 50 else conv_last_message
                
                badge = f'<span class="badge-premium bg-gradient-1" style="font-size: 0.7rem;">{conv_unread_count}</span>' if conv_unread_count > 0 else ""
                
                st.markdown(f"""
                <div style="padding: 1rem; margin-bottom: 0.5rem; border-radius: 12px; 
                    background: white; cursor: pointer; transition: all 0.3s; border: 2px solid transparent;"
                    onmouseover="this.style.borderColor='#667eea'" onmouseout="this.style.borderColor='transparent'">
                    <strong>{conv_name}</strong> {badge}
                    <br>
                    <small style="color: #718096;">{last_message_preview}...</small>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("💬 Aucune conversation disponible")
        
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown('<div class="card-premium animate-fadeInRight">', unsafe_allow_html=True)
        st.markdown("### 💭 Support Technique")
        
        user_messages = db.get_user_messages(st.session_state.user['id'])
        
        if user_messages:
            for msg in user_messages:
                if msg and isinstance(msg, dict):
                    if msg.get('sender') == 'user':
                        st.markdown(f"""
                        <div class="message-sent-premium">
                            <strong>👤 Vous</strong>
                            <p style="margin: 0.5rem 0;">{msg.get('content', 'Message vide')}</p>
                            <small style="opacity: 0.8;">{msg.get('timestamp', datetime.now()).strftime('%d/%m %H:%M') if msg.get('timestamp') else datetime.now().strftime('%d/%m %H:%M')}</small>
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.markdown(f"""
                        <div class="message-received-premium">
                            <strong>🏦 Support</strong>
                            <p style="margin: 0.5rem 0;">{msg.get('content', 'Message vide')}</p>
                            <small style="opacity: 0.8;">{msg.get('timestamp', datetime.now()).strftime('%d/%m %H:%M') if msg.get('timestamp') else datetime.now().strftime('%d/%m %H:%M')}</small>
                        </div>
                        """, unsafe_allow_html=True)
        else:
            st.info("💬 Aucun message pour le moment. Commencez une conversation !")
        
        st.markdown("<br>", unsafe_allow_html=True)
        with st.form("send_msg", clear_on_submit=True):
            c1, c2 = st.columns([4, 1])
            with c1:
                msg_text = st.text_area("", placeholder="Écrivez votre message ici...", label_visibility="collapsed")
            with c2:
                st.markdown("<br>", unsafe_allow_html=True)
                if st.form_submit_button("📤 Envoyer", use_container_width=True):
                    if msg_text and msg_text.strip():
                        success, result = db.send_message(st.session_state.user['id'], 'user', msg_text.strip())
                        if success:
                            st.success("Message envoyé avec succès !")
                            st.rerun()
                        else:
                            st.error(f"Erreur lors de l'envoi : {result}")
                    else:
                        st.warning("Veuillez écrire un message avant d'envoyer.")
        
        st.markdown('</div>', unsafe_allow_html=True)

# ============================================================
# MAIN
# ============================================================
def main():
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'user' not in st.session_state:
        st.session_state.user = None
    if 'menu' not in st.session_state:
        st.session_state.menu = "Dashboard"

    if not st.session_state.logged_in:
        auth_page()
        return

    set_custom_theme()
    
    with st.sidebar:
        st.markdown(f"""
        <div style="text-align: center; padding: 1rem; background: linear-gradient(135deg, #4a6fa5, #166088); border-radius: 15px; color: white;">
            <div style="font-size: 3rem;">👤</div>
            <h4>{st.session_state.user.get('first_name', '')} {st.session_state.user.get('last_name', '')}</h4>
            <small>{st.session_state.user.get('email', '')}</small>
        </div>
        """, unsafe_allow_html=True)
        
        menu = option_menu(
            None,
            ["Dashboard", "Demande AVI", "Mes AVI", "Messages", "Déconnexion"],
            icons=["speedometer2", "file-text", "folder-check", "chat-dots", "box-arrow-right"],
            default_index=["Dashboard", "Demande AVI", "Mes AVI", "Messages", "Déconnexion"].index(st.session_state.menu) if st.session_state.menu in ["Dashboard", "Demande AVI", "Mes AVI", "Messages", "Déconnexion"] else 0,
            styles={
                "container": {"padding": "0!important"},
                "icon": {"color": "#4a6fa5", "font-size": "18px"},
                "nav-link": {"font-size": "14px", "margin": "5px 0", "border-radius": "10px"},
                "nav-link-selected": {"background": "linear-gradient(135deg, #4a6fa5, #166088)"},
            }
        )
        
        if menu == "Déconnexion":
            st.session_state.logged_in = False
            st.session_state.user = None
            st.rerun()
        
        st.session_state.menu = menu

    pages = {
        "Dashboard": dashboard_page,
        "Demande AVI": avi_request_page,
        "Mes AVI": my_avi_page,
        "Messages": messages_page,
    }
    
    pages.get(st.session_state.menu, dashboard_page)()

if __name__ == "__main__":
    main()