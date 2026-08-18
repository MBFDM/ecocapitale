"""
Application de Gestion Administrateur avec Streamlit (version MySQL)

Structure:
1. Imports et configuration
2. Classes de gestion de base de données
3. Fonctions utilitaires
4. Pages de l'interface utilisateur
5. Fonction principale
"""

# =============================================
# 1. IMPORTS ET CONFIGURATION
# =============================================
from io import BytesIO
import logging
import re
import PyPDF2
import urllib.request
from PIL import Image, ImageFilter
from docx import Document
from fpdf import FPDF
import mysql.connector
import pdfplumber
import qrcode
import streamlit as st
from datetime import datetime
import pandas as pd
import hashlib
import time
from typing import List, Dict, Optional
import streamlit as st
from streamlit_option_menu import option_menu
import plotly.express as px
from database import BankDatabase
from receipt_generator import generate_receipt_pdf
from faker import Faker
import base64
import os
from datetime import datetime, timedelta
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader
from streamlit.components.v1 import html
from streamlit_extras.let_it_rain import rain
from streamlit_extras.add_vertical_space import add_vertical_space
import bcrypt
import secrets
import string
import json
import uuid

#db-mav-1.cdeaqqe46t76.eu-north-1.rds.amazonaws.com ecocapital-mbfdm.c.aivencloud.com
#admin avnadmin
#Frz5E1LTv49J7xF6MQleP0hgrYrCO3ybyHpJujA AVNS_3a2plzaevzttmJ4Tcs9 14431

# ⚠️ STREAMLIT CONFIG DOIT ÊTRE LA PREMIÈRE COMMANDE STREAMLIT
st.set_page_config(
    page_title="GESTION BANQUE",
    page_icon="assets/logo.png",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Le reste de votre configuration...
MYSQL_CONFIG = {
    'host': 'ecocapital-mbfdm.c.aivencloud.com',
    'user': 'avnadmin',
    'password': 'AVNS_3a2plzaevzttmJ4Tcs9',
    'database': 'ecocapital',
    'port': 14431,
}

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Dans votre fichier Python (avant le main())
def set_custom_theme():
    """Définit les thèmes light et dark avec animations"""
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
        
        /* Light mode buttons */
        .stButton>button {{
            background-color: #4a6fa5;
            color: white;
        }}
        
        .stButton>button:hover {{
            background-color: #3a5a8f;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
        }}
        
        /* Dark mode buttons */
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
        
        /* Light cards */
        [data-testid="metric-container"] {{
            background-color: white;
            border-left: 4px solid #4a6fa5;
        }}
        
        /* Dark cards */
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
        
        /* Onglets stylisés */
        [data-testid="stTabs"] [role="tablist"] {{
            gap: 5px;
        }}
        
        [data-testid="stTabs"] [role="tab"] {{
            padding: 10px 20px;
            border-radius: 8px 8px 0 0;
            transition: all 0.3s ease;
        }}
        
        /* Light tabs */
        [data-testid="stTabs"] [role="tab"] {{
            background-color: rgba(74, 111, 165, 0.1);
        }}
        
        [data-testid="stTabs"] [aria-selected="true"] {{
            background-color: #4a6fa5;
            color: white;
            font-weight: bold;
        }}
        
        /* Dark tabs */
        @media (prefers-color-scheme: dark) {{
            [data-testid="stTabs"] [role="tab"] {{
                background-color: rgba(22, 96, 136, 0.2);
            }}
            
            [data-testid="stTabs"] [aria-selected="true"] {{
                background-color: #166088;
            }}
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
        
        /* Effet de chargement */
        .stSpinner>div>div {{
            animation: pulse 1.5s infinite ease-in-out;
        }}
        
        @keyframes pulse {{
            0% {{ opacity: 0.6; }}
            50% {{ opacity: 1; }}
            100% {{ opacity: 0.6; }}
        }}
        
        /* Style personnalisé pour les cartes */
        .custom-card {{
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            transition: all 0.3s ease;
            border-left: 4px solid #4a6fa5;
        }}
        
        /* Light cards */
        .custom-card {{
            background-color: white;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }}
        
        /* Dark cards */
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
        
        
        /* Protection contre le clickjacking */
        body {{
            display: none;
        }}
        
        @media only screen {{
            body {{
                display: block;
            }}
        }}
    </style>
    """, unsafe_allow_html=True)


# =============================================
# 2. CLASSES DE GESTION DE BASE DE DONNÉES
# =============================================

class EnhancedUserManager:
    """Gestionnaire complet des utilisateurs et de l'administration"""
    
    def __init__(self, conn: mysql.connector.MySQLConnection):
        """Initialise la connexion et crée les tables"""
        self.conn = conn
        self._create_tables()

    def _create_tables(self):
        """Crée les tables nécessaires dans la base de données"""
        with self.conn.cursor() as cursor:
            try:
                # Table des utilisateurs
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(50) DEFAULT 'user',
                    status VARCHAR(50) DEFAULT 'actif',
                    last_login TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    CONSTRAINT chk_role CHECK (role IN ('user', 'manager', 'admin')),
                    CONSTRAINT chk_status CHECK (status IN ('actif', 'inactif', 'suspended'))
                )''')

                # Table des demandes admin
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS admin_requests (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    justification TEXT,
                    request_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status VARCHAR(50) DEFAULT 'pending',
                    approved_by INT,
                    FOREIGN KEY (approved_by) REFERENCES users (id)
                )''')

                # Table des logs d'activité
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS activity_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    action VARCHAR(255) NOT NULL,
                    details TEXT,
                    ip_address VARCHAR(50),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )''')
                
                self.conn.commit()
            except mysql.connector.Error as err:
                logger.error(f"Erreur lors de la création des tables: {err}")
                raise
            
    def get_users_from_code3(self) -> List[Dict]:
        """Récupère tous les utilisateurs de la table utilisateurs (Code 3)"""
        with self.conn.cursor(dictionary=True) as cursor:
            try:
                cursor.execute('''
                SELECT 
                    id,
                    first_name,
                    last_name,
                    email,
                    phone,
                    is_active,
                    created_at,
                    last_login
                FROM utilisateurs
                ORDER BY created_at DESC
                ''')
                return cursor.fetchall()
            except mysql.connector.Error as e:
                logger.error(f"Erreur lors de la récupération des utilisateurs Code 3: {e}")
                return []

    # Méthodes de gestion des utilisateurs
    def add_user(self, username: str, email: str, password_hash: str, role: str = 'user') -> int:
        """Ajoute un nouvel utilisateur à la base de données"""
        try:
            with self.conn.cursor() as cursor:
                cursor.execute('''
                INSERT INTO users (username, email, password_hash, role)
                VALUES (%s, %s, %s, %s)
                ''', (username, email, password_hash, role))
                self.conn.commit()
                return cursor.lastrowid
        except mysql.connector.Error as e:
            raise mysql.connector.Error(f"Erreur MySQL: {str(e)}")

    def get_user_by_username(self, username: str) -> Optional[Dict]:
        """Récupère un utilisateur par son nom d'utilisateur"""
        with self.conn.cursor(dictionary=True) as cursor:
            cursor.execute('SELECT * FROM users WHERE username=%s', (username,))
            return cursor.fetchone()
    
    def get_all_users(self) -> List[Dict]:
        """Récupère tous les utilisateurs"""
        with self.conn.cursor(dictionary=True) as cursor:
            cursor.execute('SELECT * FROM users ORDER BY username')
            return cursor.fetchall()

    def update_user_role(self, user_id: int, new_role: str) -> None:
        """Met à jour le rôle d'un utilisateur"""
        with self.conn.cursor() as cursor:
            cursor.execute(
                'UPDATE users SET role=%s, updated_at=CURRENT_TIMESTAMP WHERE id=%s',
                (new_role, user_id))
            self.conn.commit()

    def update_user_status(self, user_id: int, new_status: str) -> None:
        """Met à jour le statut d'un utilisateur"""
        with self.conn.cursor() as cursor:
            cursor.execute(
                'UPDATE users SET status=%s, updated_at=CURRENT_TIMESTAMP WHERE id=%s',
                (new_status, user_id))
            self.conn.commit()

    def count_active_users(self) -> int:
        """Compte les utilisateurs actifs"""
        with self.conn.cursor() as cursor:
            try:
                # D'abord, vérifier si la colonne status existe
                cursor.execute("""
                    SELECT COUNT(*) FROM information_schema.columns 
                    WHERE table_schema = DATABASE() 
                    AND table_name = 'users' 
                    AND column_name = 'status'
                """)
                has_status_column = cursor.fetchone()[0] > 0
                
                if has_status_column:
                    # Compter les utilisateurs avec status = 'actif'
                    cursor.execute('SELECT COUNT(*) FROM users WHERE status = "actif"')
                else:
                    # Fallback: compter tous les utilisateurs
                    cursor.execute('SELECT COUNT(*) FROM users')
                
                return cursor.fetchone()[0]
            except mysql.connector.Error as e:
                logger.error(f"Erreur count_active_users: {e}")
                # Fallback ultime: compter tous les utilisateurs
                cursor.execute('SELECT COUNT(*) FROM users')
                return cursor.fetchone()[0]

    def log_activity(self, user_id: int, action: str, details: str = "", ip_address: str = "") -> None:
        """Enregistre une activité utilisateur"""
        with self.conn.cursor() as cursor:
            cursor.execute('''
            INSERT INTO activity_logs (user_id, action, details, ip_address)
            VALUES (%s, %s, %s, %s)
            ''', (user_id, action, details, ip_address))
            self.conn.commit()

    def get_activity_logs(self, date_filter: str = None, user_id: int = None) -> List[Dict]:
        """Récupère les logs d'activité avec filtres"""
        query = '''
        SELECT l.*, u.username 
        FROM activity_logs l
        JOIN users u ON l.user_id = u.id
        WHERE 1=1
        '''
        params = []
        
        if date_filter:
            query += ' AND DATE(l.created_at) = DATE(%s)'
            params.append(date_filter)
        
        if user_id:
            query += ' AND l.user_id = %s'
            params.append(user_id)
        
        query += ' ORDER BY l.created_at DESC'
        
        with self.conn.cursor(dictionary=True) as cursor:
            cursor.execute(query, params)
            return cursor.fetchall()

    # Méthodes de gestion des comptes admin
    def create_admin_account(self, username: str, email: str, password: str, justification: str = "") -> bool:
        """Crée un compte administrateur immédiatement"""
        try:
            with self.conn.cursor() as cursor:
                password_hash = hash_password(password)
                cursor.execute('''
                INSERT INTO users (username, email, password_hash, role)
                VALUES (%s, %s, %s, 'admin')
                ''', (username, email, password_hash))
                self.conn.commit()
                return True
        except mysql.connector.Error as e:
            st.error(f"Erreur lors de la création du compte admin: {str(e)}")
            return False

    def request_admin_account(self, username: str, email: str, password: str, justification: str) -> bool:
        """Enregistre une demande de création de compte admin"""
        try:
            with self.conn.cursor() as cursor:
                password_hash = hash_password(password)
                cursor.execute('''
                INSERT INTO admin_requests (username, email, password_hash, justification)
                VALUES (%s, %s, %s, %s)
                ''', (username, email, password_hash, justification))
                self.conn.commit()
                return True
        except mysql.connector.Error as e:
            st.error(f"Erreur lors de la demande de compte admin: {str(e)}")
            return False

    def get_pending_admin_requests(self) -> List[Dict]:
        """Récupère les demandes de compte admin en attente"""
        with self.conn.cursor(dictionary=True) as cursor:
            try:
                # Essayer avec 'pending' (anglais)
                cursor.execute('SELECT * FROM admin_requests WHERE status = "pending"')
                return cursor.fetchall()
            except mysql.connector.Error:
                try:
                    # Essayer avec 'en_attente' (français)
                    cursor.execute('SELECT * FROM admin_requests WHERE status = "en_attente"')
                    return cursor.fetchall()
                except mysql.connector.Error:
                    try:
                        # Vérifier si la colonne existe et retourner toutes les demandes
                        cursor.execute('SELECT * FROM admin_requests')
                        all_requests = cursor.fetchall()
                        # Filtrer en mémoire si possible
                        return [r for r in all_requests if r.get('status', '') in ['pending', 'en_attente', 'waiting']]
                    except:
                        return []

    def approve_admin_request(self, request_id: int, approved_by: int) -> bool:
        """Approuve une demande de compte admin"""
        try:
            with self.conn.cursor(dictionary=True) as cursor:
                cursor.execute('SELECT * FROM admin_requests WHERE id=%s', (request_id,))
                request = cursor.fetchone()
                
                if request:
                    cursor.execute('''
                    INSERT INTO users (username, email, password_hash, role)
                    VALUES (%s, %s, %s, 'admin')
                    ''', (request['username'], request['email'], request['password_hash']))
                    
                    cursor.execute('''
                    UPDATE admin_requests 
                    SET status="approved", approved_by=%s
                    WHERE id=%s
                    ''', (approved_by, request_id))
                    self.conn.commit()
                    return True
                return False
        except mysql.connector.Error as e:
            st.error(f"Erreur lors de l'approbation: {str(e)}")
            return False

# =============================================
# 3. FONCTIONS UTILITAIRES
# =============================================

def hash_password(password: str) -> str:
    """Hash un mot de passe avec SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def get_db_connection() -> mysql.connector.MySQLConnection:
    """Établit une connexion à la base de données MySQL"""
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        return conn
    except mysql.connector.Error as err:
        logger.error(f"Erreur de connexion à MySQL: {err}")
        raise

def init_session():
    """Initialise les variables de session"""
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
        st.session_state.user = None

def get_last_activity(user_manager: EnhancedUserManager) -> str:
    """Récupère la dernière activité enregistrée"""
    logs = user_manager.get_activity_logs()
    return logs[0]['created_at'].strftime('%Y-%m-%d %H:%M') if logs else "Aucune"


def generate_secure_token(length=32):
    """Génère un token sécurisé pour les sessions"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def hash_password_secure(password: str) -> str:
    """Hash un mot de passe avec bcrypt (plus sécurisé que SHA-256)"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(hashed_password: str, input_password: str) -> bool:
    """Vérifie un mot de passe contre son hash (support bcrypt et legacy SHA-256)"""
    try:
        # Essayer d'abord avec bcrypt
        if hashed_password.startswith("$2b$") or hashed_password.startswith("$2a$"):
            return bcrypt.checkpw(input_password.encode('utf-8'), hashed_password.encode('utf-8'))
        
        # Fallback pour l'ancien système SHA-256
        return hashed_password == hash_password(input_password)
    except Exception as e:
        logger.error(f"Erreur de vérification de mot de passe: {str(e)}")
        return False

def check_csrf():
    """Protection contre les attaques CSRF"""
    if 'csrf_token' not in st.session_state:
        st.session_state.csrf_token = generate_secure_token()
    
    if st.query_params.get('csrf_token'):
        if st.query_params['csrf_token'] != st.session_state.csrf_token:
            st.error("Token de sécurité invalide. Veuillez rafraîchir la page.")
            st.stop()

def migrate_password_hash(conn, user_id, plain_password):
    """Migre un hash SHA-256 vers bcrypt"""
    try:
        new_hash = hash_password_secure(plain_password)
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE users SET password_hash=%s WHERE id=%s",
                (new_hash, user_id)
            )
            conn.commit()
        return True
    except Exception as e:
        logger.error(f"Erreur migration hash: {str(e)}")
        return False

# =============================================
# 3. COMPOSANTS UI AMÉLIORÉS
# =============================================

def animated_rain_effect():
    """Effet de pluie animé pour les succès"""
    rain(
        emoji="💰",
        font_size=20,
        falling_speed=5,
        animation_length=1,
    )

def loading_spinner_with_message(message):
    """Spinner de chargement avec message"""
    with st.spinner(message):
        time.sleep(1.5)

def loading_animation(message: str = "Chargement en cours..."):
    """Affiche une animation de chargement stylisée"""
    with st.spinner(message):
        time.sleep(0.5)  # Simulation de chargement

def success_animation():
    """Effet visuel pour succès"""
    st.balloons()

def error_animation():
    """Effet visuel pour erreur"""
    st.snow()

# =============================================
# 4. PAGES DE L'INTERFACE UTILISATEUR
# =============================================
def login_page():
    """Page de connexion avec design amélioré"""
    st.title("🔐 Connexion")
    # Chargement des styles CSS et des assets
    def load_css(file_name):
        with open(file_name) as f:
            st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

    load_css("assets/styles.css")
    
    # Effet de fond animé
    st.markdown("""
    <style>
        @keyframes gradientBG {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        
        .login-container {
            background: linear-gradient(-45deg, #ee7752, #e73c7e, #23a6d5, #23d5ab);
            background-size: 400% 400%;
            animation: gradientBG 15s ease infinite;
            padding: 2em;
            border-radius: 15px;
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
            color: white;
        }
    </style>
    """, unsafe_allow_html=True)
    
    #set_custom_theme()
    
    with st.container():
        st.markdown('<div class="login-container">', unsafe_allow_html=True)
        
        with st.form("login_form"):
            username = st.text_input("Nom d'utilisateur", placeholder="Entrez votre identifiant")
            password = st.text_input("Mot de passe", type="password", placeholder="Entrez votre mot de passe")
            
            cols = st.columns([1, 1, 2])
            with cols[0]:
                login_btn = st.form_submit_button("Se connecter", type="secondary")
            
            if login_btn:
                try:
                    conn = get_db_connection()
                    user_manager = EnhancedUserManager(conn)
                    user = user_manager.get_user_by_username(username)
                    
                    if user and verify_password(user['password_hash'], password):
                        # Création de la session sécurisée
                        st.session_state.authenticated = True
                        st.session_state.user = user
                        st.session_state.session_token = generate_secure_token()
                        st.session_state.last_activity = datetime.now()
                        
                        # Journalisation
                        client_ip = st.query_params.get('client_ip', [''])[0]  # Updated line
                        user_manager.log_activity(
                            user['id'],
                            "Connexion réussie",
                            f"Connexion depuis {client_ip}",
                            ip_address=client_ip
                        )
                        
                        # Notification et redirection
                        st.success("Connexion réussie! Redirection en cours...")
                        #animated_rain_effect()
                        time.sleep(1.5)
                        st.rerun()
                    else:
                        st.error("Identifiants incorrects")
                        logger.warning(f"Tentative de connexion échouée pour l'utilisateur: {username}")
                
                except Exception as e:
                    st.error(f"Erreur de connexion: {str(e)}")
                    logger.error(f"Erreur de connexion: {str(e)}")
                finally:
                    if 'conn' in locals():
                        conn.close()
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Section d'aide
        with st.expander("🔍 Aide à la connexion", expanded=False):
            st.info("""
            - Utilisez votre nom d'utilisateur et mot de passe fournis par l'administrateur
            - Le système est sensible à la casse (majuscules/minuscules)
            - Après 3 tentatives échouées, votre compte sera temporairement bloqué
            """)

def initial_admin_setup():
    """Page de configuration initiale du premier admin"""
    st.title("🔧 Configuration Initiale")
    st.warning("Aucun compte administrateur trouvé. Créez le compte administrateur initial.")
    
    with st.form("initial_admin_form"):
        username = st.text_input("Nom d'utilisateur admin*")
        email = st.text_input("Email admin*")
        password = st.text_input("Mot de passe*", type="password")
        confirm_password = st.text_input("Confirmer le mot de passe*", type="password")
        
        if st.form_submit_button("Créer le compte admin"):
            if password != confirm_password:
                st.error("Les mots de passe ne correspondent pas")
            elif not all([username, email, password]):
                st.error("Tous les champs obligatoires (*) doivent être remplis")
            else:
                conn = get_db_connection()
                user_manager = EnhancedUserManager(conn)
                
                if user_manager.create_admin_account(username, email, password):
                    st.success("Compte admin créé! Redirection...")
                    time.sleep(2)
                    st.session_state.authenticated = True
                    st.session_state.user = {
                        'username': username,
                        'email': email,
                        'role': 'admin'
                    }
                    st.rerun()
                conn.close()

def admin_request_page():
    """Page pour demander un compte admin"""
    st.title("👑 Demande de Compte Admin")
    
    with st.form("admin_request_form"):
        st.info("Remplissez ce formulaire pour demander un compte administrateur.")
        
        username = st.text_input("Nom d'utilisateur*")
        email = st.text_input("Email*")
        password = st.text_input("Mot de passe*", type="password")
        confirm_password = st.text_input("Confirmer le mot de passe*", type="password")
        justification = st.text_area("Justification*")
        
        if st.form_submit_button("Soumettre la demande"):
            if password != confirm_password:
                st.error("Les mots de passe ne correspondent pas")
            elif not all([username, email, password, justification]):
                st.error("Tous les champs obligatoires (*) doivent être remplis")
            else:
                conn = get_db_connection()
                user_manager = EnhancedUserManager(conn)
                
                if user_manager.request_admin_account(username, email, password, justification):
                    st.success("Demande envoyée! Un admin examinera votre demande.")
                    time.sleep(3)
                    st.rerun()
                conn.close()

def admin_approval_page(user_manager: EnhancedUserManager):
    """Page d'approbation des demandes admin"""
    st.header("📋 Demandes Admin en Attente")
    
    requests = user_manager.get_pending_admin_requests()
    
    if not requests:
        st.info("Aucune demande en attente")
        return
    
    for req in requests:
        with st.expander(f"Demande de {req['username']}"):
            st.write(f"**Email:** {req['email']}")
            st.write(f"**Date:** {req['request_date'].strftime('%Y-%m-%d %H:%M')}")
            st.write(f"**Justification:** {req['justification']}")
            
            if st.button(f"Approuver {req['username']}", key=f"approve_{req['id']}"):
                if user_manager.approve_admin_request(req['id'], st.session_state.user['id']):
                    st.success("Demande approuvée!")
                    time.sleep(2)
                    st.rerun()

def show_user_management(user_manager: EnhancedUserManager):
    """Affiche l'interface de gestion des utilisateurs"""
    st.header("Gestion des Utilisateurs")
    
    # Création d'utilisateur
    with st.expander("➕ Créer un nouvel utilisateur", expanded=False):
        with st.form("create_user_form"):
            cols = st.columns(2)
            with cols[0]:
                new_username = st.text_input("Nom d'utilisateur*")
                new_email = st.text_input("Email*")
            with cols[1]:
                new_password = st.text_input("Mot de passe*", type="password")
                new_role = st.selectbox("Rôle*", ["user", "manager", "admin"])
            
            if st.form_submit_button("Créer l'utilisateur"):
                if not all([new_username, new_email, new_password]):
                    st.error("Tous les champs sont obligatoires")
                else:
                    try:
                        hashed_pwd = hash_password(new_password)
                        user_id = user_manager.add_user(new_username, new_email, hashed_pwd, new_role)
                        user_manager.log_activity(
                            st.session_state.user['id'], 
                            "Création utilisateur",
                            f"Nouvel utilisateur: {new_username} (ID:{user_id})"
                        )
                        st.success(f"Utilisateur {new_username} créé avec succès!")
                    except mysql.connector.Error as e:
                        st.error(str(e))
    
    # Liste et édition des utilisateurs
    st.subheader("Liste des Utilisateurs")
    users = user_manager.get_all_users()
    
    if users:
        df = pd.DataFrame(users)
        
        # Colonnes à afficher
        cols_to_show = ['id', 'username', 'email', 'role', 'status', 'last_login', 'created_at']
        
        # Éditeur de données
        edited_df = st.data_editor(
            df[cols_to_show],
            disabled=["id", "created_at", "last_login"],
            column_config={
                "created_at": st.column_config.DatetimeColumn("Créé le"),
                "last_login": st.column_config.DatetimeColumn("Dernière connexion"),
                "role": st.column_config.SelectboxColumn(
                    "Rôle",
                    options=["user", "manager", "admin"]
                ),
                "status": st.column_config.SelectboxColumn(
                    "Statut",
                    options=["actif", "inactif", "suspended"]
                )
            },
            hide_index=True,
            use_container_width=True
        )
        
        if st.button("💾 Enregistrer les modifications"):
            # Comparaison pour détecter les changements
            original_df = df[cols_to_show].set_index('id')
            edited_df = edited_df.set_index('id')
            
            for user_id in original_df.index:
                original = original_df.loc[user_id]
                edited = edited_df.loc[user_id]
                
                # Vérifier les changements de rôle
                if original['role'] != edited['role']:
                    user_manager.update_user_role(user_id, edited['role'])
                    user_manager.log_activity(
                        st.session_state.user['id'],
                        "Modification rôle",
                        f"Utilisateur ID:{user_id} nouveau rôle: {edited['role']}"
                    )
                
                # Vérifier les changements de statut
                if original['status'] != edited['status']:
                    user_manager.update_user_status(user_id, edited['status'])
                    user_manager.log_activity(
                        st.session_state.user['id'],
                        "Modification statut",
                        f"Utilisateur ID:{user_id} nouveau statut: {edited['status']}"
                    )
            
            st.success("Modifications enregistrées!")
            st.rerun()
    else:
        st.info("Aucun utilisateur trouvé")

def show_activity_logs(user_manager: EnhancedUserManager):
    """Affiche les logs d'activité"""
    st.header("Journal des Activités")
    
    # Filtres
    with st.expander("🔍 Filtres", expanded=True):
        cols = st.columns(3)
        with cols[0]:
            date_filter = st.date_input("Date", value=datetime.now().date())
        with cols[1]:
            user_filter = st.selectbox(
                "Utilisateur",
                ["Tous"] + [u['username'] for u in user_manager.get_all_users()]
            )
        with cols[2]:
            action_filter = st.text_input("Action contenant")
    
    # Récupération des logs
    logs = user_manager.get_activity_logs(
        date_filter=str(date_filter),
        user_id=None if user_filter == "Tous" else next(
            u['id'] for u in user_manager.get_all_users() if u['username'] == user_filter
        )
    )
    
    # Filtrage supplémentaire
    if action_filter:
        logs = [log for log in logs if action_filter.lower() in log['action'].lower()]
    
    # Affichage
    if logs:
        # Formatage des données pour l'affichage
        log_data = [{
            "Date": log['created_at'].strftime('%Y-%m-%d %H:%M:%S'),
            "Utilisateur": log['username'],
            "Action": log['action'],
            "Détails": log.get('details', ''),
            "IP": log.get('ip_address', '')
        } for log in logs]
        
        st.dataframe(
            pd.DataFrame(log_data),
            hide_index=True,
            use_container_width=True,
            column_config={
                "Date": st.column_config.DatetimeColumn("Date/heure"),
                "Détails": st.column_config.TextColumn("Détails", width="large")
            }
        )
        
        # Bouton d'export
        csv = pd.DataFrame(log_data).to_csv(index=False).encode('utf-8')
        st.download_button(
            "📤 Exporter en CSV",
            data=csv,
            file_name=f"logs_activite_{date_filter}.csv",
            mime="text/csv"
        )
    else:
        st.info("Aucune activité trouvée pour ces critères")

def show_system_settings():
    """Affiche les paramètres système"""
    st.header("Paramètres Système")
    
    with st.form("system_settings"):
        maintenance_mode = st.checkbox("Mode maintenance")
        log_level = st.selectbox(
            "Niveau de log",
            ["DEBUG", "INFO", "WARNING", "ERROR"],
            index=1
        )
        max_file_size = st.number_input(
            "Taille maximale des fichiers (MB)",
            min_value=1,
            value=10
        )
        
        if st.form_submit_button("Enregistrer les paramètres"):
            st.success("Paramètres système mis à jour!")

def show_code3_users(user_manager: EnhancedUserManager):
    """Affiche les utilisateurs de l'espace client (Code 3)"""
    st.header("👥 Utilisateurs Espace Client")
    st.markdown("Liste des utilisateurs inscrits depuis l'application Eco Capital Client")

    users = user_manager.get_users_from_code3()
    
    if not users:
        st.info("Aucun utilisateur trouvé dans la base clients")
        return

    # Statistiques
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("👥 Total utilisateurs", len(users))
    with col2:
        active_count = sum(1 for u in users if u.get('is_active', True))
        st.metric("✅ Utilisateurs actifs", active_count)
    with col3:
        inactive_count = len(users) - active_count
        st.metric("⭕ Utilisateurs inactifs", inactive_count)
    with col4:
        # Dernière inscription
        if users:
            latest = max(users, key=lambda x: x.get('created_at', datetime.min))
            if latest.get('created_at'):
                st.metric("📅 Dernière inscription", latest['created_at'].strftime('%d/%m/%Y'))
            else:
                st.metric("📅 Dernière inscription", "N/A")

    st.markdown("---")
    
    # Préparation du DataFrame
    df = pd.DataFrame(users)
    
    # Renommer les colonnes pour l'affichage
    df_display = df.rename(columns={
        'id': 'ID',
        'first_name': 'Prénom',
        'last_name': 'Nom',
        'email': 'Email',
        'phone': 'Téléphone',
        'is_active': 'Actif',
        'created_at': 'Date inscription',
        'last_login': 'Dernière connexion'
    })
    
    # Ajouter une colonne "Statut" lisible
    df_display['Statut'] = df_display['Actif'].apply(lambda x: '🟢 Actif' if x else '🔴 Inactif')
    
    # Ordre des colonnes
    column_order = ['ID', 'Prénom', 'Nom', 'Email', 'Téléphone', 'Statut', 'Date inscription', 'Dernière connexion']
    
    # Configuration des colonnes
    column_config = {
        "ID": st.column_config.TextColumn("ID", width="medium"),
        "Prénom": st.column_config.TextColumn("Prénom"),
        "Nom": st.column_config.TextColumn("Nom"),
        "Email": st.column_config.TextColumn("Email", width="large"),
        "Téléphone": st.column_config.TextColumn("Téléphone"),
        "Statut": st.column_config.TextColumn("Statut"),
        "Date inscription": st.column_config.DatetimeColumn("Date inscription", format="DD/MM/YYYY HH:mm"),
        "Dernière connexion": st.column_config.DatetimeColumn("Dernière connexion", format="DD/MM/YYYY HH:mm")
    }
    
    # Affichage du tableau
    st.dataframe(
        df_display[column_order],
        column_config=column_config,
        use_container_width=True,
        hide_index=True
    )
    
    # Section d'export
    st.markdown("---")
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        csv = df_display[column_order].to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Exporter la liste des utilisateurs (CSV)",
            data=csv,
            file_name=f"utilisateurs_espace_client_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True
        )


def admin_dashboard():
    """Tableau de bord admin avec nouveau design"""
    #st.set_page_config(
    #    page_title="GESTION BANQUE",
    #    page_icon="assets/logo.png",
    #    layout="wide",
    #    initial_sidebar_state="expanded"
    #)

    # Chargement des styles CSS et des assets
    def load_css(file_name):
        with open(file_name) as f:
            st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

    load_css("assets/styles.css")
    set_custom_theme()
    
    # Sidebar avec animations et personnalisation dynamique
    with st.sidebar:
        # Logo avec animation au hover
        st.markdown("""
        <style>
            .logo-animation:hover {
                transform: rotate(5deg) scale(1.05);
                transition: all 0.3s ease;
            }
        </style>
        """, unsafe_allow_html=True)
        
        logo_col = st.columns([1, 4, 1])[1]
        with logo_col:
            st.image("assets/logo.png", width=400, 
                    use_container_width=True, clamp=True, 
                    caption="", channels="RGB", 
                    output_format="PNG", 
                )
        
        # Informations utilisateur avec animation
        st.markdown(f"""
        <div class="element-enter">
            <h3 style='text-align: center; color: var(--primary-color);'>
                {st.session_state.user['username']}
            </h3>
            <p style='text-align: center; color: #666;'>
                {st.session_state.user['role'].capitalize()}
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        add_vertical_space(2)

        if st.button(
            "🔄 Rafraîchir", 
            use_container_width=True,
            key="rafraichir",
            help="Actualiser",
            type="secondary"
        ):st.rerun()
        
        # Bouton de déconnexion avec effet
        if st.button(
            "🚪 Déconnexion", 
            use_container_width=True,
            key="logout_btn",
            help="Se déconnecter du tableau de bord",
            type="secondary"
        ):
            st.session_state.authenticated = False
            st.session_state.user = None
            st.balloons()
            st.success("Déconnexion réussie")
            time.sleep(1)
            st.rerun()
    
    st.markdown("""
    <style>
        /* Conteneur principal - Version premium */
        .main-container {
            background: linear-gradient(135deg, var(--surface) 0%, var(--border) 150%);
            animation: gradientBG 18s ease infinite, float 6s ease-in-out infinite;
            background-size: 300% 300%;
            border-radius: 18px;
            padding: 2.5rem;
            box-shadow: 0 12px 24px rgba(0,0,0,0.08);
            margin-bottom: 2.5rem;
            transition: all 0.5s cubic-bezier(0.22, 1, 0.36, 1);
            border: none;
            position: relative;
            overflow: hidden;
            backdrop-filter: blur(8px);
        }

        /* Effet de bordure animée */
        .main-container::before {
            content: '';
            position: absolute;
            inset: 0;
            border-radius: 18px;
            padding: 2px;
            background: linear-gradient(135deg, var(--primary), var(--accent));
            -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
            -webkit-mask-composite: xor;
            mask-composite: exclude;
            animation: borderRotate 8s linear infinite;
            pointer-events: none;
            z-index: -1;
        }

        /* Thème Light */
        [data-theme="light"] .main-container {
            background: linear-gradient(145deg, #f8faff 0%, #e6ecff 100%);
            box-shadow: 0 12px 28px rgba(67, 97, 238, 0.15);
        }

        /* Thème Dark */
        [data-theme="dark"] .main-container {
            background: linear-gradient(145deg, #1a1a2e 0%, #16213e 100%);
            box-shadow: 0 12px 28px rgba(16, 20, 58, 0.3);
        }

        /* Animation d'entrée améliorée */
        .animated-entry {
            animation: fadeInSlide 0.8s cubic-bezier(0.16, 1, 0.3, 1), 
                    pulse 2s ease-in-out 0.8s 3;
            transform-origin: center bottom;
        }

        /* Animations */
        @keyframes gradientBG {
            0% { background-position: 0% 0%; }
            50% { background-position: 100% 100%; }
            100% { background-position: 0% 0%; }
        }

        @keyframes fadeInSlide {
            from { 
                opacity: 0;
                transform: translateY(20px) scale(0.98);
                filter: blur(2px);
            }
            to { 
                opacity: 1;
                transform: translateY(0) scale(1);
                filter: blur(0);
            }
        }

        @keyframes float {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-8px); }
        }

        @keyframes borderRotate {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.02); }
        }

        /* Effet hover premium */
        .main-container:hover {
            transform: translateY(-6px) scale(1.01);
            box-shadow: 0 20px 40px rgba(0,0,0,0.2);
        }

        [data-theme="light"] .main-container:hover {
            box-shadow: 0 20px 40px rgba(67, 97, 238, 0.25);
            background: linear-gradient(145deg, #f0f4ff 0%, #d9e2ff 100%);
        }

        [data-theme="dark"] .main-container:hover {
            box-shadow: 0 20px 40px rgba(106, 143, 199, 0.4);
            background: linear-gradient(145deg, #1f1f3d 0%, #1a2a4a 100%);
        }

        /* Effet de brillance au survol */
        .main-container:hover::after {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, 
                rgba(255,255,255,0.15) 0%, 
                transparent 70%);
            animation: shine 1.5s ease-out;
            transform: rotate(30deg);
        }

        @keyframes shine {
            0% { transform: translateY(-100%) rotate(30deg); }
            100% { transform: translateY(100%) rotate(30deg); }
        }
    </style>
    """, unsafe_allow_html=True)

    # Contenu principal
    st.markdown( 
        f"""<div class="main-container animated-entry">
            <h1>🏠 Tableau de bord {st.session_state.user['role'].capitalize()}</h1>
        </div>""", unsafe_allow_html=True
    )
    
    try:
        conn = get_db_connection()
        user_manager = EnhancedUserManager(conn)
        
        cols = st.columns(4)
        with cols[0]:
            st.metric(label="👥 Utilisateurs actifs", value=user_manager.count_active_users())
        with cols[1]:
            st.metric(label="🕒 Dernière activité", value=get_last_activity(user_manager))
        with cols[2]:
            st.metric(label="📊 Actions aujourd'hui", value=len(user_manager.get_activity_logs(date_filter=datetime.now().date())))
        with cols[3]:
            st.metric(label="⏳ Demandes en attente", value=len(user_manager.get_pending_admin_requests()))
        
        # Graphiques avec Plotly
        st.markdown("## Activité récente")
        logs = user_manager.get_activity_logs()
        if logs:
            df_logs = pd.DataFrame(logs)
            df_logs['date'] = pd.to_datetime(df_logs['created_at']).dt.date
            
            # Graphique d'activité
            fig = px.bar(
                df_logs.groupby(['date', 'action']).size().reset_index(name='count'),
                x='date',
                y='count',
                color='action',
                title="Activité par jour",
                color_discrete_sequence=px.colors.qualitative.Pastel
            )
            st.plotly_chart(fig, use_container_width=True)

        # Onglets
        tab1, tab2, tab3, tab4 = st.tabs(["👥 Gestion Utilisateurs", "📊 Activités", "⚙ Paramètres", "👥 Clients"])
        
        with tab1:
            show_user_management(user_manager)
        
        with tab2:
            show_activity_logs(user_manager)
        
        with tab3:
            show_system_settings()

        with tab4:
            show_code3_users(user_manager)

        #st.success("Tableau de bord chargé avec succès !")
        
    except Exception as e:
        st.error(f"Erreur: {str(e)} ❌")
    finally:
        if 'conn' in locals():
            conn.close()

def show_clients_list():
    """Affiche la liste complète des clients (table clients du Code 3)"""
    st.header("👥 Liste des Clients")
    
    try:
        # Connexion à la base de données
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Récupérer tous les clients
        cursor.execute("""
            SELECT 
                id,
                first_name,
                last_name,
                email,
                phone,
                type,
                status,
                created_at
            FROM utilisateurs 
            ORDER BY created_at DESC
        """)
        
        clients = cursor.fetchall()
        
        if not clients:
            st.info("📭 Aucun client enregistré dans la base de données")
            return
        
        # Statistiques rapides
        col1, col2, col3, col4 = st.columns(4)
        
        total_clients = len(clients)
        active_clients = sum(1 for c in clients if c.get('status') == 'Actif')
        vip_clients = sum(1 for c in clients if c.get('type') == 'VIP')
        entreprise_clients = sum(1 for c in clients if c.get('type') == 'Entreprise')
        
        with col1:
            st.metric("👥 Total Clients", total_clients)
        with col2:
            st.metric("✅ Clients Actifs", active_clients)
        with col3:
            st.metric("⭐ Clients VIP", vip_clients)
        with col4:
            st.metric("🏢 Entreprises", entreprise_clients)
        
        st.markdown("---")
        
        # Barre de recherche
        search_col1, search_col2 = st.columns([3, 1])
        with search_col1:
            search_query = st.text_input("🔍 Rechercher un client", 
                                        placeholder="Nom, prénom, email ou téléphone...",
                                        key="client_search_admin")
        with search_col2:
            type_filter = st.selectbox("📋 Type de client", 
                                      ["Tous", "Particulier", "Entreprise", "VIP"],
                                      key="client_type_filter_admin")
        
        # Filtrage
        filtered_clients = clients.copy()
        
        if search_query:
            search_lower = search_query.lower()
            filtered_clients = [
                c for c in filtered_clients 
                if search_lower in c.get('first_name', '').lower() 
                or search_lower in c.get('last_name', '').lower()
                or search_lower in c.get('email', '').lower()
                or search_lower in (c.get('phone', '') or '').lower()
            ]
        
        if type_filter != "Tous":
            filtered_clients = [c for c in filtered_clients if c.get('type') == type_filter]
        
        st.caption(f"📊 {len(filtered_clients)} client(s) trouvé(s)")
        
        # Préparation du DataFrame pour l'affichage
        if filtered_clients:
            df = pd.DataFrame(filtered_clients)
            
            # Renommer les colonnes pour un meilleur affichage
            df_display = df.copy()
            df_display['Nom complet'] = df_display['first_name'] + " " + df_display['last_name']
            df_display['Date inscription'] = pd.to_datetime(df_display['created_at']).dt.strftime('%d/%m/%Y')
            
            # Sélection des colonnes à afficher
            columns_to_show = ['id', 'Nom complet', 'email', 'phone', 'type', 'status', 'Date inscription']
            
            # Configuration des colonnes
            column_config = {
                "id": st.column_config.TextColumn("ID", width="small"),
                "Nom complet": st.column_config.TextColumn("Nom complet", width="medium"),
                "email": st.column_config.TextColumn("Email", width="large"),
                "phone": st.column_config.TextColumn("Téléphone", width="medium"),
                "type": st.column_config.SelectboxColumn(
                    "Type",
                    options=["Particulier", "Entreprise", "VIP"],
                    width="small"
                ),
                "status": st.column_config.SelectboxColumn(
                    "Statut",
                    options=["Actif", "Inactif", "En attente"],
                    width="small"
                ),
                "Date inscription": st.column_config.TextColumn("Inscription", width="medium")
            }
            
            # Affichage du tableau éditable
            edited_df = st.data_editor(
                df_display[columns_to_show],
                column_config=column_config,
                use_container_width=True,
                hide_index=True,
                disabled=["id", "Nom complet", "email", "phone", "Date inscription"],
                key="clients_admin_editor"
            )
            
            # Section des détails du client sélectionné
            st.markdown("---")
            st.subheader("🔍 Détails du client")
            
            # Sélection d'un client pour voir les détails
            client_options = {f"{c['first_name']} {c['last_name']} (ID: {c['id']})": c['id'] for c in filtered_clients}
            selected_client_key = st.selectbox(
                "Sélectionner un client pour voir ses détails",
                options=list(client_options.keys()),
                key="client_detail_select"
            )
            
            if selected_client_key:
                selected_id = client_options[selected_client_key]
                selected_client = next((c for c in filtered_clients if c['id'] == selected_id), None)
                
                if selected_client:
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown(f"""
                        <div class="custom-card">
                            <h4>📋 Informations personnelles</h4>
                            <p><strong>Nom complet:</strong> {selected_client.get('first_name', '')} {selected_client.get('last_name', '')}</p>
                            <p><strong>Email:</strong> {selected_client.get('email', 'Non renseigné')}</p>
                            <p><strong>Téléphone:</strong> {selected_client.get('phone', 'Non renseigné')}</p>
                            <p><strong>Type:</strong> {selected_client.get('type', 'N/A')}</p>
                            <p><strong>Statut:</strong> <span style="color: {'green' if selected_client.get('status') == 'Actif' else 'orange'}">{selected_client.get('status', 'N/A')}</span></p>
                            <p><strong>Date d'inscription:</strong> {selected_client.get('created_at').strftime('%d/%m/%Y %H:%M') if selected_client.get('created_at') else 'N/A'}</p>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    with col2:
                        # Récupérer les comptes du client
                        cursor.execute("""
                            SELECT iban, currency, type as account_type, balance, bank_name
                            FROM ibans 
                            WHERE client_id = %s
                        """, (selected_id,))
                        accounts = cursor.fetchall()
                        
                        if accounts:
                            st.markdown("### 💳 Comptes bancaires")
                            accounts_df = pd.DataFrame(accounts)
                            accounts_df['balance'] = accounts_df['balance'].apply(lambda x: f"{x:,.2f} XAF")
                            st.dataframe(
                                accounts_df,
                                use_container_width=True,
                                hide_index=True,
                                column_config={
                                    "iban": st.column_config.TextColumn("IBAN", width="large"),
                                    "currency": st.column_config.TextColumn("Devise", width="small"),
                                    "account_type": st.column_config.TextColumn("Type de compte", width="medium"),
                                    "balance": st.column_config.TextColumn("Solde", width="medium"),
                                    "bank_name": st.column_config.TextColumn("Banque", width="medium")
                                }
                            )
                        else:
                            st.info("Aucun compte bancaire associé à ce client")
                        
                        # Récupérer les transactions du client
                        cursor.execute("""
                            SELECT t.date, t.type, t.amount, t.description, i.iban
                            FROM transactions t
                            JOIN ibans i ON t.iban_id = i.id
                            WHERE t.client_id = %s
                            ORDER BY t.date DESC
                            LIMIT 10
                        """, (selected_id,))
                        transactions = cursor.fetchall()
                        
                        if transactions:
                            st.markdown("### 📊 Dernières transactions")
                            trans_df = pd.DataFrame(transactions)
                            trans_df['amount'] = trans_df['amount'].apply(lambda x: f"{x:,.2f} XAF")
                            st.dataframe(
                                trans_df,
                                use_container_width=True,
                                hide_index=True,
                                column_config={
                                    "date": st.column_config.DatetimeColumn("Date", format="DD/MM/YYYY HH:mm"),
                                    "type": st.column_config.TextColumn("Type", width="small"),
                                    "amount": st.column_config.TextColumn("Montant", width="medium"),
                                    "description": st.column_config.TextColumn("Description", width="large"),
                                    "iban": st.column_config.TextColumn("IBAN", width="medium")
                                }
                            )
                        else:
                            st.info("Aucune transaction trouvée pour ce client")
            
            # Bouton d'export
            st.markdown("---")
            col1, col2, col3 = st.columns([1, 2, 1])
            with col2:
                csv_data = df[['first_name', 'last_name', 'email', 'phone', 'type', 'status']].to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="📥 Exporter la liste des clients (CSV)",
                    data=csv_data,
                    file_name=f"clients_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                    use_container_width=True
                )
        
        cursor.close()
        conn.close()
        
    except mysql.connector.Error as e:
        st.error(f"❌ Erreur de base de données: {str(e)}")
        logger.error(f"Erreur show_clients_list: {str(e)}")
    except Exception as e:
        st.error(f"❌ Erreur: {str(e)}")
        logger.error(f"Erreur show_clients_list: {str(e)}")

def check_authentication(required_role: str = None) -> None:
    """
    Vérifie si l'utilisateur est authentifié et a le rôle requis
    """
    # Vérifie si un admin existe
    conn = get_db_connection()
    user_manager = EnhancedUserManager(conn)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
    admin_count = cursor.fetchone()[0]
    conn.close()

    # Initialise l'état de session si nécessaire
    if 'authenticated' not in st.session_state:
        st.session_state['authenticated'] = False
    
    # Redirige vers la page d'authentification si non connecté
    if admin_count == 0:
        initial_admin_setup()
    elif not st.session_state['authenticated']:
        login_page()
        st.stop()
    else:
        user_role = st.session_state.user.get('role')
        if user_role == 'admin':
            admin_dashboard()
            st.stop()
        else: 
            if user_role == 'manager' or user_role == 'user':
                show_admin_dashboard()
                st.stop()
    
    # Vérifie les autorisations si un rôle est requis
    if required_role and st.session_state.get('role') != required_role:
        st.error("Vous n'avez pas les permissions nécessaires pour accéder à cette page")
        logger.warning(
            f"Tentative d'accès non autorisé par {st.session_state['username']} "
            f"(requiert: {required_role})"
        )

def logout() -> None:
    """
    Déconnecte l'utilisateur et nettoie la session
    """
    username = st.session_state.get('username', 'Inconnu')
    st.session_state.clear()
    logger.info(f"Utilisateur {username} déconnecté")
    st.rerun()

# =============================================
# INTÉGRATION AVEC LES AUTRES COMPOSANTS
# =============================================

# Pour les DataFrames
def show_animated_dataframe(data):
    """Affiche un DataFrame avec animation"""
    st.markdown("""
    <style>
        @keyframes fadeInData {{
            from {{ opacity: 0; }}
            to {{ opacity: 1; }}
        }}
        
        .dataframe {{
            animation: fadeInData 1s ease-out;
        }}
    </style>
    """, unsafe_allow_html=True)
    
    st.dataframe(data)

# Pour les graphiques
def show_animated_chart(fig):
    """Affiche un graphique avec animation"""
    st.markdown("""
    <style>
        @keyframes chartEntrance {{
            from {{ transform: scale(0.9); opacity: 0; }}
            to {{ transform: scale(1); opacity: 1; }}
        }}
        
        .stPlotlyChart {{
            animation: chartEntrance 0.5s ease-out;
        }}
    </style>
    """, unsafe_allow_html=True)
    
    st.plotly_chart(fig)

# =============================================
# 5. FONCTION PRINCIPALE
# =============================================

def main():
    """Point d'entrée principal avec animations"""
    #set_custom_theme()
    init_session()

    # Chargement des styles CSS et des assets
    def load_css(file_name):
        with open(file_name) as f:
            st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

    load_css("assets/styles.css")
    
    # Vérification initiale avec animation
    loading_animation("Vérification de la session...")
    
    try:
        conn = get_db_connection()
        user_manager = EnhancedUserManager(conn)
        conn.close()
        
        # Notification discrète
        #st.info("Connecté à la base de données")
    except Exception as e:
        st.error(f"Erreur de connexion: {str(e)}")
        logger.error(f"Erreur initiale: {str(e)}")
        return
    
    check_authentication()

def show_admin_dashboard():
    """Page de tableau de bord pour les utilisateurs non admin"""
    # Configuration de la page
    #st.set_page_config(
    #    page_title="GESTION BANQUE",
    #    page_icon="assets/logo.png",
    #    layout="wide",
    #    initial_sidebar_state="expanded"
    #)

    set_custom_theme()
    init_session()

    st.markdown("""
    <style>
        /* Conteneur principal - Version premium */
        .main-container {
            background: linear-gradient(135deg, var(--surface) 0%, var(--border) 150%);
            animation: gradientBG 18s ease infinite, float 6s ease-in-out infinite;
            background-size: 300% 300%;
            border-radius: 18px;
            padding: 2.5rem;
            box-shadow: 0 12px 24px rgba(0,0,0,0.08);
            margin-bottom: 2.5rem;
            transition: all 0.5s cubic-bezier(0.22, 1, 0.36, 1);
            border: none;
            position: relative;
            overflow: hidden;
            backdrop-filter: blur(8px);
        }

        /* Effet de bordure animée */
        .main-container::before {
            content: '';
            position: absolute;
            inset: 0;
            border-radius: 18px;
            padding: 2px;
            background: linear-gradient(135deg, var(--primary), var(--accent));
            -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
            -webkit-mask-composite: xor;
            mask-composite: exclude;
            animation: borderRotate 8s linear infinite;
            pointer-events: none;
            z-index: -1;
        }

        /* Thème Light */
        [data-theme="light"] .main-container {
            background: linear-gradient(145deg, #f8faff 0%, #e6ecff 100%);
            box-shadow: 0 12px 28px rgba(67, 97, 238, 0.15);
        }

        /* Thème Dark */
        [data-theme="dark"] .main-container {
            background: linear-gradient(145deg, #1a1a2e 0%, #16213e 100%);
            box-shadow: 0 12px 28px rgba(16, 20, 58, 0.3);
        }

        /* Animation d'entrée améliorée */
        .animated-entry {
            animation: fadeInSlide 0.8s cubic-bezier(0.16, 1, 0.3, 1), 
                    pulse 2s ease-in-out 0.8s 3;
            transform-origin: center bottom;
        }

        /* Animations */
        @keyframes gradientBG {
            0% { background-position: 0% 0%; }
            50% { background-position: 100% 100%; }
            100% { background-position: 0% 0%; }
        }

        @keyframes fadeInSlide {
            from { 
                opacity: 0;
                transform: translateY(20px) scale(0.98);
                filter: blur(2px);
            }
            to { 
                opacity: 1;
                transform: translateY(0) scale(1);
                filter: blur(0);
            }
        }

        @keyframes float {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-8px); }
        }

        @keyframes borderRotate {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.02); }
        }

        /* Effet hover premium */
        .main-container:hover {
            transform: translateY(-6px) scale(1.01);
            box-shadow: 0 20px 40px rgba(0,0,0,0.2);
        }

        [data-theme="light"] .main-container:hover {
            box-shadow: 0 20px 40px rgba(67, 97, 238, 0.25);
            background: linear-gradient(145deg, #f0f4ff 0%, #d9e2ff 100%);
        }

        [data-theme="dark"] .main-container:hover {
            box-shadow: 0 20px 40px rgba(106, 143, 199, 0.4);
            background: linear-gradient(145deg, #1f1f3d 0%, #1a2a4a 100%);
        }

        /* Effet de brillance au survol */
        .main-container:hover::after {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, 
                rgba(255,255,255,0.15) 0%, 
                transparent 70%);
            animation: shine 1.5s ease-out;
            transform: rotate(30deg);
        }

        @keyframes shine {
            0% { transform: translateY(-100%) rotate(30deg); }
            100% { transform: translateY(100%) rotate(30deg); }
        }
    </style>
    """, unsafe_allow_html=True)
    
    # Chargement des styles CSS et des assets
    def load_css(file_name):
        with open(file_name) as f:
            st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

    def load_image(image_path):
        return Image.open(image_path)

    load_css("assets/styles.css")
    logo_img = load_image("assets/logo.png")
    
    # Barre latérale
    with st.sidebar:
        st.image(logo_img, width=20, use_container_width=True)
        st.markdown("<h2 style='text-align: center;'>Digital Financial Service</h2>", unsafe_allow_html=True)
        st.markdown(f"<h4 style='text-align: center;'>Rôle: {st.session_state.user['role'].capitalize()}</h4>", unsafe_allow_html=True)
        st.markdown(f"<h4 style='text-align: center;'>{st.session_state.user['username']}</h4>", unsafe_allow_html=True)
            

        if st.button(
            "🔄 Rafraîchir", 
            use_container_width=True,
            key="rafraichir",
            help="Actualiser",
            type="secondary"
        ):st.rerun()

        # Bouton de déconnexion avec effet
        if st.button(
            "🚪 Déconnexion", 
            use_container_width=True,
            key="logout_btn",
            help="Se déconnecter du tableau de bord",
            type="secondary"
        ):
            st.session_state.authenticated = False
            st.session_state.user = None
            st.balloons()
            st.success("Déconnexion réussie")
            time.sleep(2)
            st.rerun()
            
    # Contenu principal avec animations
    st.markdown( 
        f"""<div class="main-container animated-entry">
            <h1>🏠 Tableau de bord {st.session_state.user['role'].capitalize()}</h1>
        </div>""", unsafe_allow_html=True
    )

    # Effet de fond animé
    st.markdown("""
    <style>
        @keyframes gradientBG {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        
        .login-container {
            background: linear-gradient(-45deg, #ee7752, #e73c7e, #23a6d5, #23d5ab);
            background-size: 400% 400%;
            animation: gradientBG 15s ease infinite;
            padding: 2em;
            border-radius: 15px;
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
            color: white;
        }
    </style>
    """, unsafe_allow_html=True)

    st.markdown('<div class="login-container">', unsafe_allow_html=True)
    
    try:
        conn = get_db_connection()
        user_manager = EnhancedUserManager(conn)
        
        # Contenu différent selon le rôle
        if st.session_state.user['role'] == 'manager':
            # Tableau de bord manager
            st.subheader("Fonctionnalités Manager")
            st.write("Vous avez accès aux fonctionnalités de gestion limitées.")
            
            # Exemple de fonctionnalité manager
            with st.expander("📊 Statistiques"):
                st.metric("Utilisateurs actifs", user_manager.count_active_users())
                st.write(f"Dernière activité système: {get_last_activity(user_manager)}")
                
        else:
            # Tableau de bord utilisateur standard
            st.subheader("Votre Espace Personnel")
            st.write("Bienvenue dans votre espace utilisateur.")
            
            # Exemple de fonctionnalité utilisateur
            with st.expander("📝 Mon Profil"):
                user = user_manager.get_user_by_username(st.session_state.user['username'])
                st.write(f"**Nom d'utilisateur:** {user['username']}")
                st.write(f"**Email:** {user['email']}")
                st.write(f"**Dernière connexion:** {user['last_login'] or 'Jamais'}")
                
        # Fonctionnalités communes à tous les utilisateurs non-admin
        with st.expander("📋 Mes Activités"):
            logs = user_manager.get_activity_logs(user_id=st.session_state.user['id'])
            if logs:
                st.dataframe(pd.DataFrame([{
                    "Date": log['created_at'].strftime('%Y-%m-%d %H:%M:%S'),
                    "Action": log['action'],
                    "Détails": log.get('details', '')
                } for log in logs]))
            else:
                st.info("Aucune activité récente")

        # Initialisation des composants
        db = BankDatabase()
        fake = Faker()

        # Fonctions utilitaires améliorées
        def generate_iban(country_code="FR"):
            """Génère un IBAN valide avec vérification"""
            bank_code = f"{fake.random_number(digits=5, fix_len=True):05d}"
            branch_code = f"{fake.random_number(digits=5, fix_len=True):05d}"
            account_number = f"{fake.random_number(digits=11, fix_len=True):011d}"
            national_check = f"{fake.random_number(digits=2, fix_len=True):02d}"
            
            bban = bank_code + branch_code + account_number + national_check + "00"
            check_digits = 98 - (int(bban) % 97)
            
            return f"{country_code}{check_digits:02d}{bank_code}{branch_code}{account_number}{national_check}"

        def generate_account_number():
            return f"C{fake.random_number(digits=10, fix_len=True):010d}"

        def format_currency(amount):
            return f"{amount:,.2f} XAF"

        # Barre latérale améliorée
        with st.sidebar:
            
            # Menu de navigation amélioré
            selected = option_menu(
                menu_title=None,
                options=["Tableau de Bord", "Gestion Clients", "Gestion des Comptes", "Gestion AVI", "Transactions", "Reçus", "Reçus RIB", "Générateur", "Messages"],
                icons=["speedometer2", "people-fill", "credit-card-2-back-fill", "arrow-left-right", "file-earmark-text", "file-earmark-pdf", "file-earmark-check", "file-earmark-check"],
                default_index=0,
                styles={
                    "container": {"padding": "0!important"},
                    "icon": {"font-size": "16px"}, 
                    "nav-link": {"font-size": "14px", "text-align": "left", "margin": "4px"},
                    "nav-link-selected": {"background": "linear-gradient(45deg, #4a6fa5, #166088)"},
                }
            )


        # Style pour les KPI
        def kpi_card(title, value, delta=None, delta_color="normal"):
            return st.markdown(
                f"""
                <div class="kpi-card {'delta-' + delta_color if delta else ''}">
                    <div class="kpi-title">{title}</div>
                    <div class="kpi-value">{value}</div>
                    {f'<div class="kpi-delta">{delta}</div>' if delta else ''}
                </div>
                """,
                unsafe_allow_html=True
            )

        # Page Tableau de Bord
        if selected == "Tableau de Bord":
            
            # Section KPI
            st.subheader("Indicateurs Clés", divider="blue")
            # KPI
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Clients Actifs", db.count_active_clients(), "+5%")
            with col2:
                st.metric("Transactions Journalières", db.count_daily_transactions(), "12%")
            with col3:
                st.metric("Dépôts Totaux", f"{db.total_deposits():,.2f} XAF", "8%")
            with col4:
                st.metric("Retraits Totaux", f"{db.total_withdrawals():,.2f} XAF", "3%")
            
            # Graphiques
            st.subheader("Analytiques", divider="blue")
            col1, col2 = st.columns([3, 2])

            # Graphiques
            col1, col2 = st.columns(2)

            with col1:
                st.subheader("Dépôts vs Retraits (7 jours)")
                df_trans = pd.DataFrame(db.get_last_week_transactions())
                if not df_trans.empty:
                    fig = px.bar(df_trans, x="date", y=["deposit", "withdrawal"], 
                                barmode="group", color_discrete_sequence=["#4CAF50", "#F44336"])
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.warning("Pas de transactions disponibles pour les 7 derniers jours.")

            with col2:
                st.subheader("Répartition des Clients par Type")
                data = db.get_clients_by_type()
                df_clients = pd.DataFrame(data)

                if not df_clients.empty:
                    if len(df_clients.columns) == 2:
                        df_clients.columns = ["Type de Client", "count"]

                    fig = px.pie(df_clients, values="count", names="Type de Client", 
                                color_discrete_sequence=px.colors.qualitative.Pastel)
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.warning("Pas de données clients disponibles.")

            # Nouveau graphique pour les reçus générés
            st.subheader("Reçus Générés (30 derniers jours)")
            
            # Compter les reçus générés (simulation - à adapter avec votre système de stockage)
            receipts_dir = "receipts"
            if os.path.exists(receipts_dir):
                receipt_files = [f for f in os.listdir(receipts_dir) if f.endswith('.pdf')]
                receipt_dates = [datetime.fromtimestamp(os.path.getmtime(os.path.join(receipts_dir, f))) for f in receipt_files]
                
                if receipt_dates:
                    df_receipts = pd.DataFrame({
                        'date': [d.date() for d in receipt_dates],
                        'count': 1
                    })
                    df_receipts = df_receipts.groupby('date').sum().reset_index()
                    
                    fig = px.line(df_receipts, x='date', y='count', 
                                title="Nombre de reçus générés par jour",
                                labels={'date': 'Date', 'count': 'Nombre de reçus'},
                                markers=True)
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.warning("Aucun reçu généré dans les 30 derniers jours.")
            else:
                st.warning("Aucun répertoire de reçus trouvé.")

            # Dernières transactions avec filtres
            st.subheader("Dernières Transactions", divider="blue")
            transactions = db.get_recent_transactions(100)
            # Barre de recherche
            search_query = st.text_input("Rechercher dans les transactions", "")

            if transactions:
                df = pd.DataFrame(transactions)
                
                # Filtres avancés
                col1, col2, col3 = st.columns(3)
                with col1:
                    type_filter = st.multiselect("Filtrer par type", options=df['type'].unique())
                with col2:
                    min_amount = st.number_input("Montant minimum", min_value=0, value=0)
                with col3:
                    date_range = st.date_input("Période", value=[])
                
                # Application des filtres
                if type_filter:
                    df = df[df['type'].isin(type_filter)]
                if min_amount:
                    df = df[df['amount'] >= min_amount]
                if len(date_range) == 2:
                    df = df[(df['date'].dt.date >= date_range[0]) & 
                            (df['date'].dt.date <= date_range[1])]
                
                # Affichage avec ag-grid pour plus de fonctionnalités
                st.dataframe(
                    df.style.format({"amount": "{:.2f} XAF"}),
                    use_container_width=True,
                    column_config={
                        "date": st.column_config.DatetimeColumn("Date", format="DD/MM/YYYY HH:mm"),
                        "amount": st.column_config.NumberColumn("Montant", format="%.2f XAF")
                    },
                    hide_index=True
                )
            else:
                st.info("Aucune transaction récente")

        # Page Gestion Clients (version améliorée)
        elif selected == "Gestion Clients":
            st.title("👥 Gestion Clients")
            
            tab1, tab2, tab3 = st.tabs(["📋 Liste", "➕ Ajouter", "✏️ Modifier"])
            
            with tab1:
                st.subheader("Liste des Clients")
                
                # Récupération des données
                try:
                    clients = db.get_all_clients()
                    
                    if not clients:
                        st.info("Aucun client enregistré", icon="ℹ️")
                        st.stop()
                    
                    # Préparation du DataFrame
                    df = pd.DataFrame(clients)
                    df.insert(0, 'Supprimer', False)  # Colonne de suppression en première position
                    
                    # Section Recherche et Filtres
                    with st.container():
                        cols = st.columns([3, 1, 2])
                        with cols[0]:
                            search_query = st.text_input("🔍 Rechercher", 
                                                    placeholder="Nom, email, téléphone...",
                                                    help="Recherche dans tous les champs du client",
                                                    key="client_search_input")
                        with cols[1]:
                            status_filter = st.selectbox("Statut", ["Tous", "Actif", "Inactif"],
                                                    key="client_status_filter")
                        with cols[2]:
                            st.write("")  # Espace pour alignement
                    
                    # Création d'une copie pour le filtrage
                    filtered_df = df.copy()
                    
                    # Application des filtres
                    if search_query:
                        mask = df.astype(str).apply(lambda x: x.str.contains(search_query, case=False)).any(axis=1)
                        df = df[mask]
                    
                    if status_filter != "Tous":
                        filtered_df = filtered_df[filtered_df['status'] == status_filter]
                    
                    # Configuration de l'éditeur de données
                    def configure_client_editor(dataframe, key_suffix):
                        return st.data_editor(
                            dataframe,
                            use_container_width=True,
                            hide_index=True,
                            column_config={
                                "Supprimer": st.column_config.CheckboxColumn("Supprimer"),
                                "email": st.column_config.TextColumn("Email", help="Email du client"),
                                "phone": st.column_config.TextColumn("Téléphone", help="Numéro de téléphone"),
                                "type": st.column_config.SelectboxColumn(
                                    "Type",
                                    options=["Particulier", "Entreprise", "VIP"],
                                    help="Type de client"
                                ),
                                "status": st.column_config.SelectboxColumn(
                                    "Statut",
                                    options=["Actif", "Inactif"],
                                    help="Statut du compte client"
                                )
                            },
                            disabled=["id", "first_name", "last_name", "email", "phone", "type", "status"],
                            key=f"client_editor_{key_suffix}"
                        )
                    
                    # Affichage par onglets (sans argument key)
                    client_types = sorted(filtered_df['type'].unique())
                    tab_labels = [f"Tous ({len(filtered_df)})"] + [f"{t} ({len(filtered_df[filtered_df['type']==t])})" for t in client_types]
                    tabs = st.tabs(tab_labels)
                    
                    edited_dfs = []  # Pour stocker tous les DataFrames édités
                    
                    for i, client_type in enumerate([None] + client_types):
                        with tabs[i]:
                            display_df = filtered_df if client_type is None else filtered_df[filtered_df['type'] == client_type]
                            
                            # Définir l'ordre des colonnes
                            column_order = ['Supprimer', 'id', 'first_name', 'last_name', 
                                        'email', 'phone', 'type', 'status']
                            column_order = [col for col in column_order if col in display_df.columns]
                            
                            # Créer une clé unique basée sur l'index et le type
                            tab_key = f"tab_{i}_{str(client_type).lower() if client_type else 'all'}"
                            edited_df = configure_client_editor(display_df[column_order], tab_key)
                            edited_dfs.append(edited_df)
                    
                    # Gestion de la suppression
                    delete_button = st.button("🗑️ Supprimer les clients sélectionnés", 
                                            type="primary", 
                                            key="delete_clients_button")

                    if delete_button and edited_dfs:
                        all_to_delete = []
                        for edf in edited_dfs:
                            if not edf.empty and 'Supprimer' in edf.columns and 'id' in edf.columns:
                                to_delete = edf[edf['Supprimer']]['id'].tolist()
                                all_to_delete.extend(to_delete)
                        
                        if not all_to_delete:
                            st.warning("Aucun client sélectionné pour suppression")
                        else:
                            try:
                                success_count = 0
                                with st.spinner(f"Suppression de {len(all_to_delete)} clients..."):
                                    try:
                                        # Utilisation de la méthode delete_client de BankDatabase
                                        for client_id in all_to_delete:
                                            try:
                                                # Vérifier d'abord s'il y a des comptes associés
                                                accounts = db.get_ibans_by_client(client_id)
                                                if accounts:
                                                    st.warning(f"Le client ID {client_id} a des comptes associés. Suppression des comptes d'abord...")
                                                    for account in accounts:
                                                        db.delete_account(account['id'])
                                                
                                                # Maintenant supprimer le client
                                                db.delete_client(client_id)
                                                success_count += 1
                                            except Exception as e:
                                                st.error(f"Erreur avec le client ID {client_id}: {str(e)}")
                                                continue
                                        
                                        if success_count > 0:
                                            st.success(f"{success_count}/{len(all_to_delete)} clients supprimés avec succès!")
                                            time.sleep(1)
                                            st.rerun()
                                    except Exception as e:
                                        st.error(f"Erreur de base de données: {str(e)}")
                                            
                            except Exception as e:
                                st.error(f"Erreur inattendue: {str(e)}")
                
                except Exception as e:
                    st.error(f"Erreur lors du chargement des clients: {str(e)}")
            
            with tab2:
                st.subheader("Ajouter un Client")
                with st.form("add_client_form", clear_on_submit=True):
                    cols = st.columns(2)
                    with cols[0]:
                        first_name = st.text_input("Prénom*", placeholder="Jean")
                        email = st.text_input("Email*", placeholder="jean.dupont@example.com")
                        client_type = st.selectbox("Type*", ["Particulier", "Entreprise", "VIP"])
                    with cols[1]:
                        last_name = st.text_input("Nom*", placeholder="Dupont")
                        phone = st.text_input("Téléphone", placeholder="0612345678")
                        status = st.selectbox("Statut*", ["Actif", "Inactif"])
                    
                    st.markdown("<small>* Champs obligatoires</small>", unsafe_allow_html=True)
                    
                    if st.form_submit_button("Enregistrer", type="primary"):
                        try:
                            client_id = db.add_client(first_name, last_name, email, phone, client_type, status)
                            st.toast(f"✅ Client {first_name} {last_name} ajouté (ID: {client_id})")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Erreur: {str(e)}")
            
            with tab3:
                st.subheader("Modifier un Client")
                clients = db.get_all_clients()
                
                if clients:
                    # Sélection du client
                    selected_client = st.selectbox(
                        "Choisir un client",
                        options=[f"{c['first_name']} {c['last_name']} (ID: {c['id']})" for c in clients],
                        index=0
                    )
                    
                    client_id = int(selected_client.split("(ID: ")[1][:-1])
                    client_data = db.get_client_by_id(client_id)
                    
                    if client_data:
                        with st.form("update_client_form"):
                            cols = st.columns(2)
                            with cols[0]:
                                new_first = st.text_input("Prénom", value=client_data['first_name'])
                                new_email = st.text_input("Email", value=client_data['email'])
                            with cols[1]:
                                new_last = st.text_input("Nom", value=client_data['last_name'])
                                new_phone = st.text_input("Téléphone", value=client_data['phone'])
                            
                            new_type = st.selectbox(
                                "Type",
                                ["Particulier", "Entreprise", "VIP"],
                                index=["Particulier", "Entreprise", "VIP"].index(client_data['type'])
                            )
                            new_status = st.selectbox(
                                "Statut",
                                ["Actif", "Inactif"],
                                index=["Actif", "Inactif"].index(client_data['status'])
                            )
                            
                            if st.form_submit_button("Mettre à jour", type="primary"):
                                db.update_client(
                                    client_id, new_first, new_last, 
                                    new_email, new_phone, new_type, new_status
                                )
                                st.toast("✅ Client mis à jour")
                                time.sleep(1)
                                st.rerun()
                else:
                    st.info("Aucun client à modifier", icon="ℹ️")
                    

        # Page Gestion des Comptes
        elif selected == "Gestion des Comptes":
            st.title("💳 Gestion des Comptes Bancaires")
            
            tab1, tab2 = st.tabs(["📋 Liste des Comptes", "➕ Associer un Compte"])
    
            with tab1:
                st.subheader("Liste Complète des Comptes")
                
                # Section Filtres avec barre de recherche
                with st.container():
                    cols = st.columns([3, 1, 1, 1])
                    with cols[0]:
                        search_query = st.text_input("🔍 Rechercher", placeholder="IBAN, nom banque ou client")
                    with cols[1]:
                        type_filter = st.multiselect(
                            "Type",
                            options=["Courant", "Épargne", "Entreprise"],
                            default=["Courant", "Épargne", "Entreprise"]
                        )
                    with cols[2]:
                        currency_filter = st.multiselect(
                            "Devise",
                            options=["XAF", "USD", "EUR"],
                            default=["XAF", "USD", "EUR"]
                        )
                    with cols[3]:
                        balance_filter = st.number_input(
                            "Solde min (XAF)", 
                            min_value=0,
                            value=0,
                            step=10000
                        )
                
                # Récupération des données
                try:
                    accounts = db.get_all_ibans()
                    if not accounts:
                        st.info("Aucun compte trouvé", icon="ℹ️")
                        st.stop()
                        
                    # Préparation du DataFrame
                    df = pd.DataFrame(accounts)
                    df.insert(0, 'Supprimer', False)
                    
                    # Application des filtres
                    if search_query:
                        mask = df.astype(str).apply(lambda x: x.str.contains(search_query, case=False)).any(axis=1)
                        df = df[mask]
                    if type_filter:
                        df = df[df['type'].isin(type_filter)]
                    if currency_filter:
                        df = df[df['currency'].isin(currency_filter)]
                    df = df[df['balance'] >= balance_filter]
                    
                    # Configuration de l'affichage
                    def configure_columns():
                        return {
                            "Supprimer": st.column_config.CheckboxColumn("Supprimer"),
                            "iban": st.column_config.TextColumn("IBAN", width="large"),
                            "bank_name": st.column_config.TextColumn("Banque"),
                            "bank_code": st.column_config.TextColumn("Code Banque"),
                            "branch_code": st.column_config.TextColumn("Code Guichet"),
                            "account_number": st.column_config.TextColumn("Numéro Compte"),
                            "rib_key": st.column_config.TextColumn("Clé RIB"),
                            "bic": st.column_config.TextColumn("BIC/SWIFT"),
                            "first_name": st.column_config.TextColumn("Prénom Client"),
                            "last_name": st.column_config.TextColumn("Nom Client"),
                            "balance": st.column_config.NumberColumn("Solde", format="%.2f XAF"),
                            "currency": st.column_config.TextColumn("Devise"),
                            "type": st.column_config.TextColumn("Type"),
                            "created_at": st.column_config.DatetimeColumn("Création", format="DD/MM/YYYY")
                        }
                    
                    # Affichage par onglets
                    currencies = sorted(df['currency'].unique())
                    tab_labels = [f"Tous ({len(df)})"] + [f"{c} ({len(df[df['currency']==c])})" for c in currencies]
                    tabs = st.tabs(tab_labels)
                    
                    edited_dfs = []  # Pour stocker tous les DataFrames édités
                    
                    for i, currency in enumerate([None] + currencies):
                        with tabs[i]:
                            display_df = df if currency is None else df[df['currency'] == currency]
                            
                            # Ordre des colonnes
                            column_order = [
                                'Supprimer', 
                                'id',
                                'iban', 
                                'bank_name',
                                'bank_code',
                                'branch_code',
                                'account_number',
                                'rib_key',
                                'bic',
                                'first_name',
                                'last_name',
                                'balance', 
                                'currency', 
                                'type', 
                                'created_at' 
                            ]
                            
                            # Filtrer pour n'afficher que les colonnes existantes
                            column_order = [col for col in column_order if col in display_df.columns]
 

                            edited_df = st.data_editor(
                                display_df[column_order],
                                use_container_width=True,
                                column_config=configure_columns(),
                                disabled=['id', 'iban', 'bank_name', 'bank_code', 'branch_code', 
                                        'account_number', 'rib_key', 'bic', 'first_name', 'last_name',
                                        'balance', 'currency', 'type', 'created_at'],
                                hide_index=True,
                                key=f"account_editor_{i}"
                            )
                            edited_dfs.append(edited_df)
                    
                    if st.button("🗑️ Supprimer les sélections", type="primary", key="delete_accounts"):
                        to_delete = []
                        for edf in edited_dfs:
                            if not edf.empty and 'Supprimer' in edf.columns and 'id' in edf.columns:
                                to_delete.extend(edf[edf['Supprimer']]['id'].tolist())
                        
                        if not to_delete:
                            st.warning("Aucun compte sélectionné")
                        else:
                            try:
                                with st.spinner(f"Vérification des transactions associées..."):
                                    conn = mysql.connector.connect(
                                        host='db-mav-1.cdeaqqe46t76.eu-north-1.rds.amazonaws.com',
                                        user='admin',
                                        password='Frz5E1LTv49J7xF6MQleP0hgrYrCO3ybyHpJujA',
                                        database='ecocapital'
                                    )
                                    try:
                                        cursor = conn.cursor()
                                        
                                        # Check transaction counts
                                        cursor.execute("""
                                            SELECT i.id, i.iban, COUNT(t.id) as transaction_count 
                                            FROM ibans i
                                            LEFT JOIN transactions t ON i.id = t.iban_id
                                            WHERE i.id IN (%s)
                                            GROUP BY i.id, i.iban
                                        """ % ','.join(['%s']*len(to_delete)), to_delete)
                                        
                                        affected = cursor.fetchall()
                                        total_transactions = sum(row[2] for row in affected)
                                        
                                        if total_transactions > 0:
                                            st.warning(f"Attention: Cette suppression supprimera également {total_transactions} transactions associées!")
                                            st.write("Comptes affectés:")
                                            for row in affected:
                                                st.write(f"- IBAN: {row[1]} ({row[2]} transactions)")
                                            
                                            if st.checkbox("Je confirme la suppression des comptes et transactions associées"):
                                                # First delete transactions
                                                cursor.execute("""
                                                    DELETE FROM transactions 
                                                    WHERE iban_id IN (%s)
                                                """ % ','.join(['%s']*len(to_delete)), to_delete)
                                                
                                                # Then delete ibans
                                                cursor.execute("""
                                                    DELETE FROM ibans 
                                                    WHERE id IN (%s)
                                                """ % ','.join(['%s']*len(to_delete)), to_delete)
                                                
                                                conn.commit()
                                                st.success(f"{len(to_delete)} comptes et {total_transactions} transactions supprimés!")
                                                time.sleep(1)
                                                st.rerun()
                                        else:
                                            # No transactions, just delete ibans
                                            cursor.execute("""
                                                DELETE FROM ibans 
                                                WHERE id IN (%s)
                                            """ % ','.join(['%s']*len(to_delete)), to_delete)
                                            conn.commit()
                                            st.success(f"{len(to_delete)} comptes supprimés!")
                                            time.sleep(1)
                                            st.rerun()
                                            
                                    finally:
                                        conn.close()
                            except Exception as e:
                                st.error(f"Erreur: {str(e)}")
                                
                except Exception as e:
                    st.error(f"Erreur de chargement: {str(e)}")
            
                # Dans la section "Associer un Nouveau Compte", modifiez le code comme suit :

                with tab2:
                    st.subheader("Associer un Nouveau Compte")
                    
                    # Sélection du client
                    clients = db.get_all_clients()
                    client_options = {f"{c['first_name']} {c['last_name']}": c['id'] for c in clients}
                    selected_client = st.selectbox("Client*", options=list(client_options.keys()))
                    
                    # Sélection de la banque
                    bank_name = st.selectbox(
                        "Banque*",
                        options=list(db.BANK_DATA.keys()),
                        index=0
                    )
                    
                    # Bouton de génération
                    if st.button("Générer les informations bancaires"):
                        account_data = db.generate_iban(bank_name)
                        st.session_state.new_account = account_data
                    
                    # Affichage et édition des données générées
                    if 'new_account' in st.session_state:
                        acc = st.session_state.new_account
                        
                        st.markdown("### Informations bancaires générées")
                        cols = st.columns(2)
                        
                        cols[0].markdown(f"""
                        **Banque:** {acc['bank_name']}  
                        **Code Banque:** {acc['bank_code']}  
                        **Code Guichet:** {acc['branch_code']}  
                        **Numéro de compte:** {acc['account_number']}  
                        **Clé RIB:** {acc['rib_key']}
                        """)
                        
                        cols[1].markdown(f"""
                        **IBAN:** {(acc['iban'])}  
                        **BIC/SWIFT:** {acc['bic']}  
                        **Type de compte:** {acc.get('type', 'Courant')}  
                        **Devise:** {acc.get('currency', 'XAF')}
                        """)
                        
                        # Formulaire d'édition des informations bancaires
                        with st.expander("✏️ Modifier les informations bancaires", expanded=False):
                            cols = st.columns(2)
                            with cols[0]:
                                acc['bank_name'] = st.text_input(
                                    "Banque*",
                                    value=acc['bank_name']
                                )
                                acc['bank_code'] = st.text_input(
                                    "Code Banque*",
                                    value=acc['bank_code'],
                                    max_chars=5
                                )
                                acc['branch_code'] = st.text_input(
                                    "Code Guichet*",
                                    value=acc['branch_code'],
                                    max_chars=5
                                )
                                acc['account_number'] = st.text_input(
                                    "Numéro de compte*",
                                    value=acc['account_number'],
                                    max_chars=11
                                )
                                acc['rib_key'] = st.text_input(
                                    "Clé RIB*",
                                    value=acc['rib_key'],
                                    max_chars=2
                                )
                            
                            with cols[1]:
                                acc['iban'] = st.text_input(
                                    "IBAN*",
                                    value=acc['iban'],
                                    max_chars=27
                                )
                                acc['bic'] = st.text_input(
                                    "BIC/SWIFT*",
                                    value=acc['bic'],
                                    max_chars=11
                                )
                        
                        # Formulaire complémentaire
                        with st.form("account_details_form"):
                            account_type = st.selectbox(
                                "Type de compte*",
                                options=["Courant", "Épargne", "Entreprise"]
                            )
                            
                            currency = st.selectbox(
                                "Devise*",
                                options=["XAF", "USD", "EUR"],
                            )
                            
                            initial_balance = st.number_input(
                                "Solde initial*",
                                min_value=0.0,
                                value=0.0,
                                step=50.0
                            )
                            
                            if st.form_submit_button("Enregistrer le compte"):
                                try:
                                    # Construction des données complètes
                                    full_account_data = {
                                        **st.session_state.new_account,
                                        "client_id": client_options[selected_client],
                                        "type": account_type,
                                        "currency": currency,
                                        "balance": initial_balance,
                                        "status": "ACTIF",
                                        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                    }
                                    
                                    # Validation des données
                                    if not all([full_account_data['bank_code'], full_account_data['branch_code'], 
                                            full_account_data['account_number'], full_account_data['rib_key'],
                                            full_account_data['iban'], full_account_data['bic']]):
                                        st.error("Tous les champs bancaires doivent être remplis")
                                    else:
                                        # Enregistrement dans la base de données
                                        db.add_account(full_account_data)
                                        st.success("Compte créé avec succès!")
                                        del st.session_state.new_account
                                except Exception as e:
                                    st.error(f"Erreur: {str(e)}")

                        # Fonction utilitaire pour formater l'IBAN
                        def format_iban(iban):
                            """Formate l'IBAN pour l'affichage (espace tous les 4 caractères)"""
                            return ' '.join([iban[i:i+4] for i in range(0, len(iban), 4)])


        # Page Transactions
        elif selected == "Transactions":
            st.title("⇄ Gestion des Transactions")
            
            tab1, tab2 = st.tabs(["Historique", "Nouvelle Transaction"])
            
            with tab1:
                st.subheader("Historique des Transactions")
                
                try:
                    # Récupération des transactions depuis la base de données
                    transactions = db.get_all_transactions()
                    
                    if not transactions:
                        st.info("Aucune transaction trouvée", icon="ℹ️")
                    else:
                        # Création du DataFrame
                        df = pd.DataFrame(transactions)
                        
                        # Ajout d'une colonne de sélection
                        df['Supprimer'] = False
                        
                        # Barre de recherche intelligente
                        with st.expander("🔍 Options de recherche avancée", expanded=False):
                            cols = st.columns([3, 1, 1, 1])
                            with cols[0]:
                                search_query = st.text_input("Rechercher", placeholder="IBAN, nom, type, montant...")
                            with cols[1]:
                                type_filter = st.multiselect(
                                    "Type",
                                    options=sorted(df['type'].unique()),
                                    default=[]
                                )
                            with cols[2]:
                                min_amount = st.number_input("Montant min", min_value=0, value=0)
                            with cols[3]:
                                date_range = st.date_input(
                                    "Période",
                                    value=[datetime.now() - timedelta(days=30), datetime.now()],
                                    max_value=datetime.now()
                                )
                        
                        # Filtrage des données
                        if search_query:
                            mask = df.astype(str).apply(lambda x: x.str.contains(search_query, case=False)).any(axis=1)
                            df = df[mask]
                        
                        if type_filter:
                            df = df[df['type'].isin(type_filter)]
                        
                        if min_amount > 0:
                            df = df[df['amount'] >= min_amount]
                        
                        if len(date_range) == 2:
                            start_date, end_date = date_range
                            df = df[(df['date'].dt.date >= start_date) & (df['date'].dt.date <= end_date)]
                        
                        # Configuration des colonnes pour l'affichage
                        column_config = {
                            "id": None,
                            "client_id": None,
                            "iban_id": None,
                            "date": st.column_config.DatetimeColumn("Date", format="DD/MM/YYYY HH:mm"),
                            "type": st.column_config.TextColumn("Type"),
                            "amount": st.column_config.NumberColumn("Montant", format="%.2f XAF"),
                            "description": st.column_config.TextColumn("Description"),
                            "iban": st.column_config.TextColumn("IBAN"),
                            "first_name": st.column_config.TextColumn("Prénom"),
                            "last_name": st.column_config.TextColumn("Nom"),
                            "Supprimer": st.column_config.CheckboxColumn("Supprimer")
                        }
                        
                        # Réorganisation des colonnes
                        column_order = [
                            'Supprimer', 'date', 'type', 'amount', 
                            'description', 'iban', 'first_name', 'last_name'
                        ]
                        
                        # Affichage du nombre de résultats
                        st.caption(f"📊 {len(df)} transactions trouvées")
                        
                        # Éditeur de données
                        edited_df = st.data_editor(
                            df,
                            column_config=column_config,
                            column_order=column_order,
                            use_container_width=True,
                            hide_index=True,
                            disabled=["id", "client_id", "iban_id", "date", "type", "amount", "description", "iban", "first_name", "last_name"]
                        )
                        
                        # Bouton pour supprimer les transactions sélectionnées
                        if st.button("🗑️ Supprimer les sélections", type="primary", key="delete_transactions"):
                            to_delete = edited_df[edited_df['Supprimer']]['id'].tolist()
                            
                            if not to_delete:
                                st.warning("Aucune transaction sélectionnée pour suppression")
                            else:
                                try:
                                    with st.spinner(f"Suppression de {len(to_delete)} transactions..."):
                                        # Suppression des transactions sélectionnées
                                        success_count = 0
                                        for trans_id in to_delete:
                                            try:
                                                db.delete_transaction(trans_id)
                                                success_count += 1
                                            except Exception as e:
                                                st.error(f"Erreur avec la transaction {trans_id}: {str(e)}")
                                        
                                        if success_count > 0:
                                            st.success(f"{success_count} transactions supprimées!")
                                            time.sleep(1)
                                            st.rerun()
                                
                                except Exception as e:
                                    st.error(f"Erreur lors de la suppression : {str(e)}")
                
                except Exception as e:
                    st.error(f"Erreur lors du chargement : {str(e)}")
            
            with tab2:
                st.subheader("Effectuer une Transaction")
                transaction_type = st.radio("Type de Transaction", ["Dépôt", "Retrait", "Virement"], horizontal=True)
                
                clients = db.get_all_clients()
                if clients:
                    # Barre de recherche pour trouver un client
                    search_query = st.text_input("Rechercher un client", "")
                    
                    if search_query:
                        filtered_clients = [c for c in clients if search_query.lower() in f"{c['first_name']} {c['last_name']}".lower()]
                    else:
                        filtered_clients = clients
                        
                    client_options = {f"{c['first_name']} {c['last_name']} (ID: {c['id']})": c['id'] for c in filtered_clients}
                    selected_client = st.selectbox("Sélectionner un Client", options=list(client_options.keys()))
                    
                    if selected_client:
                        client_id = client_options[selected_client]
                        client_ibans = db.get_ibans_by_client(client_id)
                        
                        if client_ibans:
                            iban_options = {i['iban']: i['id'] for i in client_ibans}
                            selected_iban = st.selectbox("Sélectionner un IBAN", options=list(iban_options.keys()))
                            
                            with st.form("transaction_form"):
                                amount = st.number_input("Montant", min_value=0.01, value=100.0, step=50.0)
                                description = st.text_area("Description")
                                
                                # Initialisation de target_accounts seulement si nécessaire
                                target_accounts = []
                                if transaction_type == "Virement":
                                    all_accounts = db.get_all_ibans()
                                    source_id = iban_options[selected_iban]
                                    target_accounts = [a for a in all_accounts if a['id'] != source_id]
                                    
                                    if target_accounts:
                                        target_options = {f"{a['iban']} - {a['first_name']} {a['last_name']}": a['id'] for a in target_accounts}
                                        target_account = st.selectbox("Compte destinataire", options=list(target_options.keys()))
                                        target_id = target_options[target_account]
                                    else:
                                        st.warning("Aucun autre compte disponible pour le virement")
                                        target_id = None
                                
                                if st.form_submit_button("Exécuter la Transaction"):
                                    iban_id = iban_options[selected_iban]
                                    if transaction_type == "Dépôt":
                                        db.deposit(iban_id, amount, description)
                                        st.success(f"Dépôt de XAF{amount:,.2f} effectué avec succès!")
                                    elif transaction_type == "Retrait":
                                        # Vérifier le solde avant retrait
                                        iban_data = next(i for i in client_ibans if i['id'] == iban_id)
                                        if iban_data['balance'] >= amount:
                                            db.withdraw(iban_id, amount, description)
                                            st.success(f"Retrait de XAF{amount:,.2f} effectué avec succès!")
                                        else:
                                            st.error("Solde insuffisant pour effectuer ce retrait.")
                                    elif transaction_type == "Virement" and target_id:
                                        # Vérifier le solde avant virement
                                        iban_data = next(i for i in client_ibans if i['id'] == iban_id)
                                        if iban_data['balance'] >= amount:
                                            # Transaction atomique
                                            db.withdraw(iban_id, amount, f"Virement vers {target_account}")
                                            db.deposit(target_id, amount, f"Virement depuis {iban_data['iban']}")
                                            st.success(f"Virement de XAF{amount:,.2f} effectué avec succès!")
                                        else:
                                            st.error("Solde insuffisant pour effectuer ce virement.")
                                    time.sleep(1)
                                    st.rerun()

                                if selected_iban:
                                    # Si vous avez besoin de chercher par IBAN
                                    all_accounts = db.get_all_ibans()
                                    account_details = next((acc for acc in all_accounts if acc['iban'] == selected_iban), None)
                                    if account_details:
                                        with st.expander("🔍 Détails du compte source"):
                                            cols = st.columns(2)
                                            cols[0].markdown(f"""
                                            **Banque:** {account_details.get('bank_name', 'N/A')}  
                                            **Code Banque:** {account_details.get('bank_code', 'N/A')}  
                                            **BIC:** {account_details.get('bic', 'N/A')}  
                                            **Solde actuel:** {account_details.get('balance', 0):.2f}€
                                            """)
                                            
                                            cols[1].markdown(f"""
                                            **IBAN:** {account_details.get('iban', 'N/A')}  
                                            **Code Guichet:** {account_details.get('branch_code', 'N/A')}  
                                            **Clé RIB:** {account_details.get('rib_key', 'N/A')}  
                                            **Type:** {account_details.get('type', 'N/A')}
                                            """)
                                    else:
                                        st.warning("Ce client n'a aucun IBAN associé.")

        # Page Générer Reçu
        elif selected == "Reçus":
            st.markdown("""
        <style>
            /* Structure principale avec animations */
            .receipt-card {
                border-radius: 16px;
                padding: 28px;
                margin: 20px 0;
                background: var(--surface);
                box-shadow: 0 6px 30px rgba(0,0,0,0.08);
                transition: all 0.5s cubic-bezier(0.22, 1, 0.36, 1);
                position: relative;
                overflow: hidden;
                border: 1px solid var(--border);
                animation: fadeInUp 0.8s ease-out;
            }

            /* Thème Light */
            [data-theme="light"] .receipt-card {
                background: linear-gradient(145deg, #ffffff 0%, #f8f9ff 100%);
                box-shadow: 0 8px 32px rgba(67, 97, 238, 0.12);
            }

            /* Thème Dark */
            [data-theme="dark"] .receipt-card {
                background: linear-gradient(145deg, #1e1e2e 0%, #232339 100%);
                box-shadow: 0 8px 32px rgba(16, 20, 58, 0.3);
            }

            /* Effet hover élégant */
            .receipt-card:hover {
                transform: translateY(-5px);
                box-shadow: 0 15px 45px rgba(0,0,0,0.15);
            }

            [data-theme="light"] .receipt-card:hover {
                box-shadow: 0 15px 45px rgba(67, 97, 238, 0.2);
            }

            [data-theme="dark"] .receipt-card:hover {
                box-shadow: 0 15px 45px rgba(106, 143, 199, 0.35);
            }

            /* En-tête avec effet de vague */
            .receipt-header {
                border-bottom: 2px solid var(--primary);
                padding-bottom: 15px;
                margin-bottom: 20px;
                position: relative;
                animation: fadeIn 0.6s ease-out;
            }

            .receipt-header::after {
                content: '';
                position: absolute;
                bottom: -2px;
                left: 0;
                width: 100%;
                height: 2px;
                background: linear-gradient(90deg, var(--primary), var(--accent));
                transform: scaleX(0);
                transform-origin: left;
                animation: headerUnderline 1.5s ease-in-out forwards;
            }

            /* Sections avec entrée séquentielle */
            .receipt-section {
                margin-bottom: 20px;
                padding: 15px;
                border-radius: 10px;
                background-color: rgba(var(--primary-rgb), 0.03);
                transition: all 0.3s ease;
                animation: fadeIn 0.6s ease-out;
                animation-fill-mode: both;
            }

            [data-theme="dark"] .receipt-section {
                background-color: rgba(106, 143, 199, 0.08);
            }

            .receipt-section:nth-child(1) { animation-delay: 0.1s; }
            .receipt-section:nth-child(2) { animation-delay: 0.2s; }
            .receipt-section:nth-child(3) { animation-delay: 0.3s; }

            .receipt-section:hover {
                transform: translateX(5px);
                background-color: rgba(var(--primary-rgb), 0.08);
            }

            /* Signature avec effet de tracé */
            .receipt-signature {
                margin-top: 40px;
                text-align: right;
                position: relative;
                animation: fadeIn 0.8s ease-out;
            }

            .signature-line {
                width: 200px;
                margin-top: 5px;
                display: inline-block;
                position: relative;
                height: 2px;
                background: linear-gradient(90deg, transparent, var(--text));
                opacity: 0.7;
            }

            .signature-line::after {
                content: '';
                position: absolute;
                top: -3px;
                right: 0;
                width: 0;
                height: 8px;
                background-color: var(--primary);
                animation: drawLine 1s ease-in-out 0.5s forwards;
            }

            /* Bouton de téléchargement premium */
            .stDownloadButton button {
                background: linear-gradient(135deg, var(--primary), var(--secondary)) !important;
                color: white !important;
                border: none !important;
                border-radius: 10px !important;
                padding: 10px 24px !important;
                font-weight: 500 !important;
                letter-spacing: 0.5px !important;
                box-shadow: 0 4px 12px rgba(var(--primary-rgb), 0.2) !important;
                transition: all 0.3s ease !important;
                position: relative;
                overflow: hidden;
            }

            .stDownloadButton button:hover {
                transform: translateY(-2px) !important;
                box-shadow: 0 8px 20px rgba(var(--primary-rgb), 0.3) !important;
            }

            .stDownloadButton button::after {
                content: '';
                position: absolute;
                top: -50%;
                left: -50%;
                width: 200%;
                height: 200%;
                background: linear-gradient(
                    to bottom right,
                    rgba(255,255,255,0.3) 0%,
                    rgba(255,255,255,0) 60%
                );
                transform: rotate(30deg);
                animation: shine 2s infinite;
            }

            /* Animations personnalisées */
            @keyframes fadeIn {
                from { opacity: 0; }
                to { opacity: 1; }
            }

            @keyframes fadeInUp {
                from { 
                    opacity: 0;
                    transform: translateY(20px);
                }
                to { 
                    opacity: 1;
                    transform: translateY(0);
                }
            }

            @keyframes headerUnderline {
                0% { transform: scaleX(0); }
                100% { transform: scaleX(1); }
            }

            @keyframes drawLine {
                0% { width: 0; }
                100% { width: 200px; }
            }

            @keyframes shine {
                0% { transform: translateY(-100%) rotate(30deg); }
                100% { transform: translateY(100%) rotate(30deg); }
            }
        </style>
        """, unsafe_allow_html=True)

            st.title("🧾 Gestion des Reçus")
            
            # Section de statistiques
            with st.container():
                st.subheader("Statistiques", divider="blue")
                col1, col2 = st.columns(2)
                with col1:
                    receipts_dir = "receipts"
                    if os.path.exists(receipts_dir):
                        receipt_count = len([f for f in os.listdir(receipts_dir) if f.endswith('.pdf')])
                        st.metric("📄 Reçus générés", receipt_count)
                    else:
                        st.metric("📄 Reçus générés", 0)
                
                with col2:
                    transactions = db.get_all_transactions()
                    transactions_count = len(transactions) if transactions else 0
                    st.metric("💸 Transactions éligibles", transactions_count)
            
            if not transactions:
                st.warning("Aucune transaction disponible pour générer un reçu.")
                st.stop()
            
            # Conversion des dates en format string pour l'affichage
            df_transactions = pd.DataFrame(transactions)
            df_transactions['date_str'] = df_transactions['date'].dt.strftime('%Y-%m-%d %H:%M')
            
            # Barre de recherche améliorée
            search_cols = st.columns([4, 1])
            with search_cols[0]:
                search_query = st.text_input("🔍 Rechercher une transaction", "", 
                                        placeholder="ID, montant, type...")
            with search_cols[1]:
                transaction_type_filter = st.selectbox("Filtrer", ["Tous"] + list(set(t['type'] for t in transactions)))
            
            # Filtrage des transactions
            filtered_transactions = df_transactions.to_dict('records')
            if search_query:
                filtered_transactions = [t for t in filtered_transactions if search_query.lower() in str(t).lower()]
            if transaction_type_filter != "Tous":
                filtered_transactions = [t for t in filtered_transactions if t['type'] == transaction_type_filter]
            
            if not filtered_transactions:
                st.warning("Aucune transaction ne correspond aux critères de recherche.")
                st.stop()
            
            # Sélecteur de transaction amélioré
            selected_transaction = st.selectbox(
                "Choisir une transaction à documenter",
                options=filtered_transactions,
                format_func=lambda t: f"#{t['id']} • {t['type']} • {t['amount']:.2f}XAF • {t['date_str']} • {t.get('description', '')[:30]}{'...' if len(t.get('description', '')) > 30 else ''}",
                index=0
            )

            # Récupération des données
            transaction_data = selected_transaction
            client_data = db.get_client_by_id(transaction_data['client_id'])
            iban_data = db.get_iban_by_id(transaction_data['iban_id'])
            
            # Affichage des informations
            with st.expander("📋 Aperçu des informations", expanded=True):
                tab1, tab2 = st.tabs(["Client", "Transaction"])
                
                with tab1:
                    st.write(f"**👤 Nom complet:** {client_data['first_name']} {client_data['last_name']}")
                    st.write(f"**📧 Email:** {client_data['email'] or 'Non renseigné'}")
                    st.write(f"**📞 Téléphone:** {client_data['phone'] or 'Non renseigné'}")
                    st.write(f"**🏷 Type client:** {client_data['type']}")
                
                with tab2:
                    st.write(f"**💰 Montant:** {transaction_data['amount']:.2f}XAF")
                    st.write(f"**📅 Date:** {transaction_data['date_str']}")  # Utilisation de la version string
                    st.write(f"**🔢 Référence:** {transaction_data['id']}")
                    st.write(f"**🏦 IBAN:** {iban_data['iban']}")
                    st.write(f"**📝 Description:** {transaction_data.get('description', 'Aucune description')}")
            
            # Personnalisation du reçu
            st.subheader("🛠 Personnalisation du reçu", divider="blue")
            with st.form("receipt_form"):
                cols = st.columns(2)
                
                with cols[0]:
                    st.markdown("**Paramètres principaux**")
                    company_name = st.text_input("Nom de l'institution", value="Digital Financial Service")
                    receipt_title = st.text_input("Titre du document", value="REÇU DE TRANSACTION")
                    company_logo = st.file_uploader("Logo (PNG/JPG)", type=["png", "jpg"])
                
                with cols[1]:
                    st.markdown("**Options avancées**")
                    additional_notes = st.text_area(
                        "Notes additionnelles", 
                        value="Merci pour votre confiance.\nPour toute question, contactez notre service client.",
                        height=100
                    )
                    include_signature = st.checkbox("Inclure une ligne de signature", value=True)
                    include_qr = st.checkbox("Inclure un QR code de vérification", value=True)
                
                # Bouton de génération
                submitted = st.form_submit_button(
                    "🖨 Générer le reçu", 
                    type="primary", 
                    use_container_width=True
                )
            
            # Génération du PDF
            if submitted:
                with st.spinner("Génération du reçu en cours..."):
                    try:
                        # Sauvegarde temporaire du logo
                        logo_path = None
                        if company_logo:
                            logo_path = f"temp_logo_{transaction_data['id']}.png"
                            with open(logo_path, "wb") as f:
                                f.write(company_logo.getbuffer())
                        
                        # Gestion robuste des différents formats de date
                        date_value = transaction_data['date']
                        
                        if isinstance(date_value, pd.Timestamp):
                            formatted_date = date_value.strftime('%d/%m/%Y %H:%M')
                        elif isinstance(date_value, datetime.datetime):
                            formatted_date = date_value.strftime('%d/%m/%Y %H:%M')
                        elif isinstance(date_value, str):
                            try:
                                # Essayer de parser si c'est une string
                                parsed_date = datetime.strptime(date_value, '%Y-%m-%d %H:%M:%S')
                                formatted_date = parsed_date.strftime('%d/%m/%Y %H:%M')
                            except ValueError:
                                # Si le parsing échoue, utiliser la valeur directement
                                formatted_date = date_value
                        else:
                            formatted_date = "Date non disponible"
                        
                        # Création d'une copie des données avec la date formatée
                        receipt_data = {
                            **transaction_data,
                            'date_str': formatted_date,
                            'formatted_amount': f"{transaction_data['amount']:,.2f} XAF"
                        }
                        
                        # Génération du PDF
                        pdf_path = generate_receipt_pdf(
                            transaction_data=receipt_data,
                            client_data=client_data,
                            iban_data=iban_data,
                            company_name=company_name,
                            logo_path=logo_path,
                            receipt_title=receipt_title,
                            additional_notes=additional_notes,
                            include_signature=include_signature,
                            include_qr=include_qr
                        )
                        
                        # Nettoyage du logo temporaire
                        if logo_path and os.path.exists(logo_path):
                            os.remove(logo_path)
                        
                        # Téléchargement
                        with open(pdf_path, "rb") as f:
                            st.download_button(
                                label="⬇️ Télécharger le reçu",
                                data=f,
                                file_name=f"reçu_{transaction_data['id']}.pdf",
                                mime="application/pdf",
                                use_container_width=True
                            )
                        
                        # Aperçu stylisé
                        st.success("Reçu généré avec succès !")
                        st.markdown("**Aperçu:** (le PDF peut différer légèrement)")
                        
                        # Simulation d'aperçu
                        with st.container():
                            st.markdown(f"""
                            <div class="receipt-preview">
                                <div class="receipt-header">
                                    <h1>{company_name}</h1>
                                    {f'<img src="data:image/png;base64,{base64.b64encode(company_logo.getvalue()).decode()}" class="receipt-logo">' if company_logo else ''}
                                    <h2>{receipt_title}</h2>
                                </div>
                                <div class="receipt-body">
                                    <div class="receipt-section">
                                        <h3>Informations Client</h3>
                                        <p><strong>Nom:</strong> {client_data['first_name']} {client_data['last_name']}</p>
                                        <p><strong>IBAN:</strong> {iban_data['iban']}</p>
                                    </div>
                                    <div class="receipt-section">
                                        <h3>Détails de la Transaction</h3>
                                        <p><strong>Type:</strong> {transaction_data['type']}</p>
                                        <p><strong>Montant:</strong> {receipt_data['formatted_amount']}</p>
                                        <p><strong>Date:</strong> {formatted_date}</p>
                                        <p><strong>Référence:</strong> {transaction_data['id']}</p>
                                    </div>
                                    <div class="receipt-notes">
                                        <p>{additional_notes.replace('\n', '<br>')}</p>
                                    </div>
                                    {'''<div class="receipt-signature">
                                        <p>Signature</p>
                                        <div class="signature-line"></div>
                                    </div>''' if include_signature else ''}
                                </div>
                            </div>
                            """, unsafe_allow_html=True)
                    
                    except Exception as e:
                        st.error(f"Erreur lors de la génération du reçu: {str(e)}")
                        if logo_path and os.path.exists(logo_path):
                            os.remove(logo_path)

        # Ajoutez cette section dans votre page "Reçus" (ou créez une nouvelle page)
        elif selected == "Reçus RIB":
            st.title("📋 Reçus RIB")
            
            # Sélection du compte
            accounts = db.get_all_ibans()
            if not accounts:
                st.warning("Aucun compte disponible pour générer un RIB")
                st.stop()
            
            selected_account = st.selectbox(
                "Sélectionner un compte",
                options=accounts,
                format_func=lambda acc: f"{acc['first_name']} {acc['last_name']} - {acc['iban']} ({acc['balance']:,.2f} {acc['currency']})"
            )
            
            if st.button("Générer le RIB", type="primary"):
                with st.spinner("Génération du RIB en cours..."):
                    try:
                        # Création d'un répertoire pour les reçus s'il n'existe pas
                        os.makedirs("rib_receipts", exist_ok=True)
                        
                        # Génération du RIB
                        receipt_path = db.generate_rib_receipt(
                            iban=selected_account['iban'],
                            output_path=f"rib_receipts/RIB_{selected_account['iban']}.pdf"
                        )
                        
                        # Affichage du résultat
                        st.success("RIB généré avec succès!")
                        
                        # Prévisualisation
                        with open(receipt_path, "rb") as f:
                            base64_pdf = base64.b64encode(f.read()).decode('utf-8')
                            pdf_display = f'<iframe src="data:application/pdf;base64,{base64_pdf}" width="100%" height="600" type="application/pdf"></iframe>'
                            st.markdown(pdf_display, unsafe_allow_html=True)
                        
                        # Bouton de téléchargement
                        with open(receipt_path, "rb") as f:
                            st.download_button(
                                "Télécharger le RIB",
                                data=f,
                                file_name=f"RIB_{selected_account['iban']}.pdf",
                                mime="application/pdf"
                            )
                            
                    except Exception as e:
                        st.error(f"Erreur lors de la génération: {str(e)}")
        
        elif selected == "Gestion AVI":
            st.title("📑 Gestion des Attestations de Virement Irrévocable (AVI)")
            
            tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs(["📋 Liste des AVI", "➕ Ajouter AVI", "✏️ Modifier AVI", "🖨 Générer AVI", "📤 Importer PDF", "📋 Demandes Clients", "📤 Envoyer AVI"])
            
            with tab1:
                st.subheader("Liste des Attestations")
                
                avis = db.get_all_avis(with_details=True)
                if avis:
                    df = pd.DataFrame(avis)
                    df['Supprimer'] = False
                    
                    edited_df = st.data_editor(
                        df,
                        use_container_width=True,
                        column_config={
                            "date_creation": st.column_config.DateColumn("Date création", format="DD/MM/YYYY"),
                            "date_expiration": st.column_config.DateColumn("Date expiration", format="DD/MM/YYYY"),
                            "montant": st.column_config.NumberColumn("Montant", format="%.2f FCFA"),
                            "Supprimer": st.column_config.CheckboxColumn("Supprimer")
                        },
                        hide_index=True,
                        disabled=["reference", "nom_complet", "code_banque", "iban", "bic", 
                                "montant", "date_creation", "date_expiration", "statut", "commentaires"],
                        column_order=["Supprimer", "reference", "nom_complet", "code_banque", "iban", 
                                    "montant", "date_creation", "statut"]
                    )
                    
                    if st.button("Supprimer les AVI sélectionnées", type="primary"):
                        to_delete = edited_df[edited_df['Supprimer']]['reference'].tolist()
                        if to_delete:
                            for avi_ref in to_delete:
                                db.delete_avi(avi_ref)
                            st.success(f"{len(to_delete)} AVI supprimées avec succès!")
                            st.rerun()
                        else:
                            st.warning("Aucune AVI sélectionnée pour suppression")
            
            with tab2:
                st.subheader("Ajouter une Nouvelle Attestation")
                with st.form("add_avi_form", clear_on_submit=True):
                    cols = st.columns(2)
                    with cols[0]:
                        nom_complet = st.text_input("Nom complet*", placeholder="Nom Prénom")
                        code_banque = st.text_input("Code Banque*", placeholder="12345")
                        numero_compte = st.text_input("Numéro de Compte*", placeholder="12345678901")
                    with cols[1]:
                        devise = st.selectbox("Devise*", options=["XAF", "EUR", "USD"], index=0)
                        iban = st.text_input("IBAN*", placeholder="CG12345678901234567890")
                        bic = st.text_input("BIC*", placeholder="BANKCGCGXXX")
                    
                    montant = st.number_input("Montant (FCFA)*", min_value=0, value=5000000)
                    date_creation = st.date_input("Date de création*", value=datetime.now())
                    date_expiration = st.date_input("Date d'expiration (optionnel)")
                    statut = st.selectbox("Statut*", options=["Etudiant", "Fonctionnaire"], index=0)  # Ajouté
                    commentaires = st.text_area("Commentaires (optionnel)")
                    
                    if st.form_submit_button("Enregistrer l'AVI", type="primary"):
                        try:
                            avi_data = {
                                "nom_complet": nom_complet,
                                "code_banque": code_banque,
                                "numero_compte": numero_compte,
                                "devise": devise,
                                "iban": iban,
                                "bic": bic,
                                "montant": montant,
                                "date_creation": date_creation.strftime("%Y-%m-%d"),
                                "date_expiration": date_expiration.strftime("%Y-%m-%d") if date_expiration else None,
                                "statut": statut,
                                "commentaires": commentaires
                            }
                            
                            avi_id = db.add_avi(avi_data)
                            avi_info = db.get_avi_by_id(avi_id)  # Nouvelle méthode à implémenter
                            st.success(f"Attestation enregistrée avec succès! Référence: {avi_info['reference']}")
                            time.sleep(2)
                            st.rerun()
                        except Exception as e:
                            st.error(f"Erreur: {str(e)}")
            
            with tab3:
                st.subheader("Modifier une Attestation")
                avis = db.get_all_avis(with_details=True)
            
                if avis:
                    selected_avi = st.selectbox(
                        "Choisir une attestation à modifier",
                        options=[a['reference'] for a in avis],
                        format_func=lambda ref: f"{ref} - {next(a['nom_complet'] for a in avis if a['reference'] == ref)}",
                        index=0
                    )
                    
                    avi_data = db.get_avi_by_reference(selected_avi)
                    
                    if avi_data:
                        with st.form("update_avi_form"):
                            cols = st.columns(2)
                            with cols[0]:
                                new_nom = st.text_input("Nom complet", value=avi_data['nom_complet'])
                                new_code_banque = st.text_input("Code Banque", value=avi_data['code_banque'])
                                new_numero = st.text_input("Numéro de Compte", value=avi_data['numero_compte'])
                            with cols[1]:
                                new_devise = st.selectbox(
                                    "Devise",
                                    options=["XAF", "EUR", "USD"],
                                    index=["XAF", "EUR", "USD"].index(avi_data['devise'])
                                )
                                new_iban = st.text_input("IBAN", value=avi_data['iban'])
                                new_bic = st.text_input("BIC", value=avi_data['bic'])
                            
                            try:
                                montant_value = float(avi_data['montant']) if avi_data['montant'] is not None else 0.0
                                new_montant = st.number_input(
                                    "Montant (FCFA)",
                                    min_value=0.0,
                                    value=montant_value,
                                    step=1.0,
                                    format="%.2f"  # Format à 2 décimales
                                )
                            except (ValueError, TypeError) as e:
                                st.error(f"Erreur de format du montant: {str(e)}")
                                new_montant = 0.0

                            new_date_creation = st.date_input(
                                "Date de création",
                                value=avi_data['date_creation']  # Utilise directement l'objet date
                            )
                            # Gestion de la date d'expiration (peut être None)
                            new_date_expiration = st.date_input(
                                "Date d'expiration",
                                value=avi_data['date_expiration'] if avi_data['date_expiration'] else None
                            )
                            
                            new_statut = st.selectbox(
                                "Statut",
                                options=["Etudiant", "Fonctionnaire"],
                                index=["Etudiant", "Fonctionnaire"].index(avi_data['statut'])
                            )
                            new_commentaires = st.text_area("Commentaires", value=avi_data.get('commentaires', ''))
                            
                            if st.form_submit_button("Mettre à jour", type="primary"):
                                updated_data = {
                                    "nom_complet": new_nom,
                                    "code_banque": new_code_banque,
                                    "numero_compte": new_numero,
                                    "devise": new_devise,
                                    "iban": new_iban,
                                    "bic": new_bic,
                                    "montant": new_montant,
                                    "date_creation": new_date_creation.strftime("%Y-%m-%d"),
                                    "date_expiration": new_date_expiration.strftime("%Y-%m-%d") if new_date_expiration else None,
                                    "statut": new_statut,
                                    "commentaires": new_commentaires
                                }
                                
                                try:
                                    if db.update_avi(selected_avi, updated_data):
                                        st.success("Attestation mise à jour avec succès!")
                                        time.sleep(1)
                                        st.rerun()
                                    else:
                                        st.error("Échec de la mise à jour - l'attestation n'a pas été trouvée")
                                except Exception as e:
                                    st.error(f"Erreur lors de la mise à jour: {str(e)}")
                else:
                    st.info("Aucune attestation à modifier", icon="ℹ️")
            
            with tab4: 
                st.subheader("Générer une Attestation")
                # Récupérer la liste des AVI
                avis = db.get_all_avis()
                
                if not avis:
                    st.warning("Aucune attestation disponible à générer")
                else:
                    selected_avi = st.selectbox(
                        "Choisir une attestation à générer",
                        options=[f"{a['reference']} - {a['nom_complet']}" for a in avis],
                        index=0
                    )
                    
                    reference = selected_avi.split(" - ")[0]
                    avi_data = db.get_avi_by_reference(reference)
                    
                    if st.button("Générer l'Attestation PDF", type="primary"):
                        with st.spinner("Génération en cours..."):
                            try:                          
                                # Création du PDF
                                pdf = FPDF()
                                pdf.add_page()

                                # ---- Ajout d'une couleur de fond sur la page ----
                                pdf.set_fill_color(241, 248, 252)  # Gris très clair 150, 201, 235
                                pdf.rect(0, 0, 210, 297, 'F')

                                def montant_en_lettres(montant):
                                    """Convertit un montant numérique en lettres françaises avec devise"""
                                    from num2words import num2words
                                    
                                    partie_entiere = int(montant)
                                    partie_decimale = int(round((montant - partie_entiere) * 100))
                                    
                                    texte = num2words(partie_entiere, lang='fr')
                                    
                                    # Ajout de la devise
                                    if partie_entiere > 1:
                                        texte += " francs CFA"
                                    else:
                                        texte += " franc CFA"
                                    
                                    # Gestion des décimales si nécessaire
                                    if partie_decimale > 0:
                                        texte += " et " + num2words(partie_decimale, lang='fr') + " centimes"
                                    
                                    return texte.capitalize()
                                
                                # ---- Ajout des logos floutés en arrière-plan ----
                                try:
                                    logo_path = "assets/logo.png"
                                    img = Image.open(logo_path)
                                    
                                    # Créer une version avec opacité réduite
                                    if img.mode != 'RGBA':
                                        img = img.convert('RGBA')
                                    
                                    data = img.getdata()
                                    new_data = []
                                    for item in data:
                                        new_data.append((item[0], item[1], item[2], int(item[3] * 0.2)))  # 30% opacity
                                    img.putdata(new_data)
                                    
                                    # Convertir en format utilisable par FPDF
                                    temp_logo = BytesIO()
                                    img.save(temp_logo, format='PNG')
                                    temp_logo.seek(0)
                                    
                                    # Images en arrière-plan / filigranes
                                    for position in [(30, 30), (120, 200), (50, 300), (100, 100)]: 
                                        pdf.image(temp_logo, x=position[0], y=position[1], w=100)
                                        
                                except Exception as e:
                                    st.warning(f"Logo non trouvé ou erreur de traitement: {str(e)}")

                                # ---- Logo et entête ----
                                try:
                                    pdf.image("assets/logo.png", x=3, y=5, w=45)
                                except:
                                    pass  # Continue sans logo si non trouvé

                                # Créer le dossier fonts
                                os.makedirs("fonts", exist_ok=True)
                                
                                # Télécharger les fichiers Calibri (s'ils n'existent pas déjà)
                                calibri_urls = {
                                    'calibri.ttf': 'https://github.com/suhajda3/ttf/raw/master/Calibri.ttf',
                                    'calibrib.ttf': 'https://github.com/suhajda3/ttf/raw/master/Calibri%20Bold.ttf'
                                }
                                
                                for font_file, url in calibri_urls.items():
                                    font_path = f"fonts/{font_file}"
                                    if not os.path.exists(font_path):
                                        try:
                                            urllib.request.urlretrieve(url, font_path)
                                        except:
                                            pass  # Ignorer si le téléchargement échoue
                                
                                # Ajouter les polices Calibri
                                try:
                                    pdf.add_font('Calibri', '', 'fonts/calibri.ttf', uni=True)
                                    pdf.add_font('Calibri', 'B', 'fonts/calibrib.ttf', uni=True)
                                    font_name = 'Calibri'
                                except:
                                    font_name = 'Helvetica'  # Fallback
                                
                                                                # ---- En-tête avec cadre ----
                                # Définir la couleur de fond blanc et bordure noire
                                pdf.ln(20)
                                pdf.set_fill_color(255, 255, 255)  # Fond blanc
                                pdf.set_draw_color(0, 0, 0)        # Bordure noire
                                #pdf.set_line_width(1)              # Épaisseur de la bordure : 1
                                
                                # Calculer la largeur du texte
                                pdf.set_font(font_name, 'B', 11)
                                text_width = pdf.get_string_width('ATTESTATION DE VIREMENT IRREVOCABLE')
                                padding = 20  # Marge intérieure
                                
                                # Position du cadre
                                x_start = (210 - text_width - (padding * 2)) / 2  # Centré horizontalement
                                y_start = pdf.get_y() + 5
                                frame_width = text_width + (padding * 2)
                                frame_height = 12  # Hauteur suffisante
                                
                                # Dessiner le cadre avec fond blanc
                                pdf.rect(x_start, y_start, frame_width, frame_height, 'FD')
                                
                                # Ajouter le texte centré dans le cadre
                                pdf.set_xy(x_start, y_start + 3)
                                pdf.set_font(font_name, 'B', 14)
                                pdf.set_text_color(0, 0, 0)
                                pdf.cell(frame_width, 10, 'ATTESTATION DE VIREMENT IRREVOCABLE', 0, 1, 'C')
                                
                                # Positionner le curseur après le cadre
                                pdf.set_y(y_start + frame_height + 5)
                                
                                # Référence du document
                                pdf.set_font(font_name, 'B', 10.5)
                                pdf.cell(0, 0, f"DGF-EC / {avi_data['reference']}", 0, 1, 'C')
                                pdf.ln(5)
                                
                                # Fonction pour texte justifié
                                def justified_text(text, line_height=5):
                                    lines = text.split('\n')
                                    for line in lines:
                                        if line.strip() == "":
                                            pdf.ln(line_height)
                                        else:
                                            pdf.multi_cell(0, line_height, line, 0, 'J')

                                # ---- Corps du document ----
                                pdf.set_font(font_name, '', 11.25)
                                intro = [
                                    "Nous, soussignés, Eco Capital (E.C), Société à Responsabilité Limitée (SARL), constituée conformément au",
                                    "droit OHADA ayant pour siège social sis au n°1636, Boulevard Denis Sassou Nguesso Batignolles,",
                                    "Brazzaville , disposons d'un capital social de 60 000 000 Xaf, soit 91 469,94 euros. Immatriculée au Registre",
                                    "du Commerce et du Crédit Mobilier sous le numéro RCCM/BZV/B12/00320-NIUM24000000665934H, et",
                                    "agréée par les autorités monétaires sous le numéro n°078/MFBPP/AETF/DR-SAR-BOTC, conformément aux",
                                    "disposition légales en vigueur du règlement COBAC EMF R-2017/01.",
                                    f"Nous certifions par la présente que {avi_data['nom_complet']} détient un compte",
                                    "courant enregistré dans nos livres avec les caractéristiques suivantes :",
                                    ""
                                ]
                                
                                for line in intro:
                                    pdf.cell(0, 5.2, line, 0, 2)
                                
                                # Informations bancaires en gras
                                pdf.set_font(font_name, 'B', 11)
                                pdf.cell(40, 5, "CODE BANQUE :", 0, 0)
                                pdf.set_font(font_name, 'B', 11)
                                pdf.cell(0, 5, avi_data['code_banque'], 0, 1)
                                
                                pdf.set_font(font_name, 'B', 11)
                                pdf.cell(45, 5, "NUMERO DE COMPTE : ", 0, 0)
                                pdf.set_font(font_name, 'B', 11)
                                pdf.cell(0, 5, avi_data['numero_compte'], 0, 1)
                                
                                pdf.set_font(font_name, 'B', 11)
                                pdf.cell(20, 5, "Devise :", 0, 0)
                                pdf.set_font(font_name, '', 11)
                                pdf.cell(0, 5, avi_data['devise'], 0, 1)
                                pdf.ln(5)
                                
                                # ---- Détails du virement ----
                                pdf.set_font(font_name, '', 10.75)
                                details = [
                                    f"Il est l'ordonnateur d'un virement irrévocable et permanent d'un montant total de {avi_data['montant']} FCFA",
                                    f"({montant_en_lettres(avi_data['montant'])}), équivalant actuellement à {avi_data['montant']/650:,.2f} euros, cette somme est destinée à couvrir les frais liés",
                                    "à ses études en France.",
                                    ""
                                ]

                                for line in details:
                                    pdf.cell(0, 5, line, 0, 1)

                                # ---- Détails du virement ----
                                pdf.set_font(font_name, '', 12)
                                details = [
                                    "Il est précisé que ce compte demeurera bloqué jusqu'à la présentation, par le donneur d'ordre, de ses",
                                    "nouvelles coordonnées bancaires ouvertes en France.",
                                    ""
                                ]

                                for line in details:
                                    pdf.cell(0, 5, line, 0, 1)

                                pdf.set_font(font_name, '', 12)
                                detail = [
                                    "À défaut, les fonds ne pourront être remis à sa disposition qu'après présentation de son passeport",
                                    "attestant d'un refus de visa. Toutefois, nous autorisons le donneur d'ordre, à toutes fins utiles, à utiliser",
                                    "notre compte ouvert auprès de United Bank for Africa (UBA).",
                                    ""
                                ]
                                
                                for line in detail:
                                    pdf.cell(0, 5, line, 0, 1, 'L')
                                
                                # ---- Coordonnées bancaires ----
                                #pdf.ln(5)
                                pdf.set_font(font_name, 'B', 11)
                                pdf.cell(16, 4.5, "IBAN :", 0, 0)
                                pdf.set_font(font_name, 'B', 11)
                                pdf.cell(0, 4.5, avi_data['iban'], 0, 1)
                                
                                pdf.set_font(font_name, 'B', 11)
                                pdf.cell(16, 4.5, "BIC :", 0, 0)
                                pdf.set_font(font_name, '', 11)
                                pdf.cell(0, 4.5, avi_data['bic'], 0, 1)
                                pdf.ln(2)
                                
                                # ---- Clause de validation ----
                                pdf.set_font(font_name, 'B', 11)
                                pdf.cell(0, 5, "En foi de quoi, cette attestation lui est délivrée pour servir et valoir ce que de droit.", 0, 1)
                                pdf.ln(3)
                                
                                # ---- Date et signature ----
                                pdf.set_font(font_name, 'B', 10)
                                pdf.cell(0, 4, f"Fait à Brazzaville, le {datetime.now().strftime('%d %B %Y')}", 0, 1, 'R')
                                pdf.cell(0, 5, "Rubain MOUNGALA", 0, 1)
                                pdf.cell(0, 5, "Responsable des Opérations", 0, 1)
                                pdf.ln(1)

                                # ---- INSERTION DES IMAGES SIGNATURE ET CACHET ----
                                try:
                                    # Signature (à gauche)
                                    pdf.image("assets/signature.png", x=10, y=pdf.get_y(), w=30)
                                    # Cachet (à droite)
                                    pdf.image("assets/cachet.png", x=40, y=pdf.get_y(), w=80)
                                    pdf.ln(25)  # Saut de ligne après les images
                                except Exception as e:
                                    pdf.ln(3)
                                    st.warning(f"Images de signature ou cachet non trouvées: {str(e)}")

                                
                                pdf.set_font(font_name, '', 9)
                                footer = [
                                    "Eco capital Sarl",
                                    "Société a responsabilité limité au capital de 60.000.000 XAF",
                                    "Siège social : 1636 Bd Denis Sassou Nguesso Batignolles Brazzaville",
                                    "RCCM N°CG/BZV/B12-00320NIU N°M24000000665934H",
                                    "Contacts : 00242 06 113 56 12 /06 113 56 05",
                                    "Web : www.ecocapitale.com mail : contacts@ecocapitale.com",
                                    "Brazzaville République du Congo"
                                ]
                                for line in footer:
                                    pdf.cell(0, 4, line, 0, 2, 'L')

                                # ---- QR Code ----
                                qr_data = {
                                    "Référence": avi_data['reference'],
                                    "Nom": avi_data['nom_complet'],
                                    "Code Banque": avi_data['code_banque'],
                                    "Numéro Compte": avi_data['numero_compte'],
                                    #"IBAN": avi_data['iban'],
                                    "BIC": avi_data['bic'],
                                    "Montant": f"{avi_data['montant']:,.2f} FCFA",
                                    "Date Création": avi_data['date_creation']
                                }
                                
                                qr = qrcode.QRCode(
                                    version=1,
                                    error_correction=qrcode.constants.ERROR_CORRECT_L,
                                    box_size=3,
                                    border=2,
                                )   
                                
                                qr.add_data(qr_data)
                                qr.make(fit=True)
                                
                                img = qr.make_image(fill_color="black", back_color="white")
                                img_bytes = BytesIO()
                                img.save(img_bytes, format='PNG')
                                img_bytes.seek(0)
                                
                                pdf.image(img_bytes, x=160, y=pdf.get_y()-40, w=40)
                                pdf.ln(3)

                                # ---- Pied de page (texte légal en anglais) ----
                                pdf.set_font(font_name, '', 6)
                                pdf.set_text_color(0, 0, 0)  # Gris pour un aspect plus professionnel
                                
                                # ---- Pied de page ----
                                fin = [
                                    "The purpose of this AVI is to confirm the existence of an account in our records. The undersigned assumes no obligation or commitment of any kind. This document connot be considered as a guarantee",
                                    "endorsement, surety, or any other similar form of commitment. The signatory diclaims all liability for any damage resulting from the improper, exaggerated, or abusive use of this AVI.",
                                ]
                                for line in fin:
                                    pdf.cell(0, 3, line, 0, 2, 'C')
                                
                                # ---- Sauvegarde du fichier ----
                                os.makedirs("avi_documents", exist_ok=True)
                                output_path = f"avi_documents/AVI_{avi_data['reference']}.pdf"
                                pdf.output(output_path)
                                
                                # ---- Affichage et téléchargement ----
                                st.success("✅ Attestation générée avec succès!")
                                
                                # Colonnes pour les boutons et la prévisualisation
                                col1, col2 = st.columns([1, 3])
                                
                                with col1:
                                    # Bouton de téléchargement
                                    with open(output_path, "rb") as f:
                                        st.download_button(
                                            "⬇️ Télécharger l'AVI",
                                            data=f,
                                            file_name=f"AVI_{avi_data['reference']}.pdf",
                                            mime="application/pdf",
                                            use_container_width=True
                                        )

                                # ---- Fonction de prévisualisation améliorée ----
                                def show_pdf_preview(file_path):
                                    """Affiche un aperçu du PDF avec plusieurs méthodes de fallback"""
                                    try:
                                        # Méthode 1: Affichage direct avec object (fonctionne sur la plupart des navigateurs)
                                        with open(file_path, "rb") as f:
                                            pdf_bytes = f.read()
                                            base64_pdf = base64.b64encode(pdf_bytes).decode('utf-8')
                                        
                                        # Créer un conteneur pour l'aperçu
                                        preview_container = st.container(border=True)
                                        
                                        with preview_container:
                                            # Ajouter un en-tête pour l'aperçu
                                            st.markdown("### 📄 Aperçu du document")
                                            
                                            # Affichage direct du PDF avec object
                                            st.markdown(f"""
                                            <div style="height: 700px; width: 100%; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden;">
                                                <object 
                                                    data="data:application/pdf;base64,{base64_pdf}"
                                                    type="application/pdf"
                                                    width="100%" 
                                                    height="100%"
                                                    style="border: none;"
                                                >
                                                    <div style="text-align: center; padding: 50px 20px; background: #f8f9fa; height: 100%; display: flex; flex-direction: column; justify-content: center; align-items: center;">
                                                        <p style="font-size: 18px; margin-bottom: 20px;">📄 Votre navigateur ne supporte pas l'affichage direct des PDF</p>
                                                        <p style="color: #666; margin-bottom: 20px;">Vous pouvez utiliser les options ci-dessous :</p>
                                                        <div style="display: flex; gap: 10px; justify-content: center; flex-wrap: wrap;">
                                                            <a href="data:application/pdf;base64,{base64_pdf}" download="AVI_{avi_data['reference']}.pdf" 
                                                               style="background: #0066cc; color: white; padding: 10px 20px; border-radius: 5px; text-decoration: none; display: inline-block;">
                                                                ⬇️ Télécharger le PDF
                                                            </a>
                                                            <a href="data:application/pdf;base64,{base64_pdf}" target="_blank"
                                                               style="background: #28a745; color: white; padding: 10px 20px; border-radius: 5px; text-decoration: none; display: inline-block;">
                                                                🔗 Ouvrir dans un nouvel onglet
                                                            </a>
                                                        </div>
                                                    </div>
                                                </object>
                                            </div>
                                            """, unsafe_allow_html=True)
                                            
                                            # Ajouter des informations sur le document
                                            with st.expander("📋 Informations sur le document"):
                                                col_info1, col_info2 = st.columns(2)
                                                with col_info1:
                                                    st.write(f"**Référence:** {avi_data['reference']}")
                                                    st.write(f"**Bénéficiaire:** {avi_data['nom_complet']}")
                                                with col_info2:
                                                    st.write(f"**Montant:** {avi_data['montant']:,} FCFA")
                                                    st.write(f"**Date:** {datetime.now().strftime('%d/%m/%Y')}")
                                            
                                    except Exception as e:
                                        # Méthode 2: Fallback avec iframe
                                        try:
                                            st.warning("⚠️ Affichage alternatif du PDF")
                                            
                                            with open(file_path, "rb") as f:
                                                pdf_bytes = f.read()
                                                base64_pdf = base64.b64encode(pdf_bytes).decode('utf-8')
                                            
                                            # Utiliser iframe comme alternative
                                            st.markdown(f"""
                                            <iframe src="data:application/pdf;base64,{base64_pdf}" 
                                                    style="width:100%; height:700px; border:1px solid #ddd; border-radius:8px;">
                                            </iframe>
                                            """, unsafe_allow_html=True)
                                            
                                        except Exception as e2:
                                            # Méthode 3: Simple lien de téléchargement
                                            st.error("❌ Impossible d'afficher l'aperçu du PDF")
                                            st.info("💡 Vous pouvez télécharger le document avec le bouton ci-dessus")
                                            
                                            # Afficher un aperçu textuel des informations
                                            with st.expander("📋 Aperçu des données du document"):
                                                st.json({
                                                    "Référence": avi_data['reference'],
                                                    "Bénéficiaire": avi_data['nom_complet'],
                                                    "Code Banque": avi_data['code_banque'],
                                                    "Numéro Compte": avi_data['numero_compte'],
                                                    "Montant": f"{avi_data['montant']:,} FCFA",
                                                    "IBAN": avi_data['iban'],
                                                    "BIC": avi_data['bic'],
                                                    "Date": datetime.now().strftime('%d/%m/%Y')
                                                })
                                
                                # Appeler la fonction de prévisualisation
                                show_pdf_preview(output_path)
                                
                            except Exception as e:
                                st.error(f"❌ Erreur lors de la génération: {str(e)}")
                                st.exception(e)
                        
            # Fonctions utilitaires (à mettre AVANT le with tab5)
            def extract_between(text, start, end):
                """Extrait le texte entre deux chaînes"""
                start_idx = text.find(start)
                if start_idx == -1: return None
                start_idx += len(start)
                end_idx = text.find(end, start_idx)
                return text[start_idx:end_idx].strip() if end_idx != -1 else None

            def extract_regex(text, pattern):
                """Extrait avec une expression régulière"""
                match = re.search(pattern, text)
                return match.group(1).strip() if match else None

            def generate_qr_code(data, fill_color="#000000", back_color="#FFFFFF", size=100):
                """Génère un QR code"""
                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_H,
                    box_size=10,
                    border=4,
                )
                qr.add_data(data)
                qr.make(fit=True)
                return qr.make_image(fill_color=fill_color, back_color=back_color).convert('RGB')

            def add_qr_to_pdf(pdf_file, qr_img, position="Bas droite"):
                """Ajoute un QR code au PDF original"""
                temp_qr = BytesIO()
                qr_img.save(temp_qr, format="PNG")
                temp_qr.seek(0)
                
                # Lire le PDF original
                pdf_reader = PyPDF2.PdfReader(pdf_file)
                pdf_writer = PyPDF2.PdfWriter()
                
                # Créer un calque avec le QR code
                packet = BytesIO()
                can = canvas.Canvas(packet, pagesize=letter)
                
                # Positions ajustées pour ne pas dépasser des marges
                pos_map = {
                    "Bas droite": (450, 60),
                    "Bas gauche": (30, 30),
                    "Haut droite": (letter[0] - 120, letter[1] - 120),
                    "Haut gauche": (30, letter[1] - 120),
                    "Centre": ((letter[0] - 100)/2, (letter[1] - 100)/2)
                }
                
                x, y = pos_map.get(position, pos_map["Bas droite"])
                
                # Dessiner le QR code sur le calque
                can.drawImage(ImageReader(temp_qr), x, y, width=100, height=100, mask='auto')
                can.save()
                
                # Fusionner le calque avec chaque page du PDF original
                packet.seek(0)
                qr_pdf = PyPDF2.PdfReader(packet)
                
                for page in pdf_reader.pages:
                    # Créer une nouvelle page avec le contenu original
                    new_page = page
                    
                    # Fusionner avec le calque QR code
                    new_page.merge_page(qr_pdf.pages[0])
                    pdf_writer.add_page(new_page)
                
                # Sauvegarder le résultat
                output = BytesIO()
                pdf_writer.write(output)
                output.seek(0)
                return output

            def show_pdf(file):
                """Affiche un PDF dans l'interface"""
                if hasattr(file, 'read'):
                    file.seek(0)
                    pdf_bytes = file.read()
                else:
                    with open(file, "rb") as f:
                        pdf_bytes = f.read()
                
                base64_pdf = base64.b64encode(pdf_bytes).decode('utf-8')
                
                pdf_display = f"""
                <div style="height: 600px; overflow: auto; margin: 1rem 0; border: 1px solid #ddd; border-radius: 8px;">
                    <embed
                        src="data:application/pdf;base64,{base64_pdf}"
                        type="application/pdf"
                        width="100%"
                        height="100%"
                        style="border: none;"
                    >
                </div>
                """
                st.markdown(pdf_display, unsafe_allow_html=True)

            def convert_word_to_pdf(word_file):
                """Convertit un fichier Word en PDF"""
                try:
                    # Lire le fichier Word
                    doc = Document(word_file)
                    
                    # Créer un fichier PDF temporaire
                    temp_pdf = BytesIO()
                    
                    # Convertir en PDF
                    doc.save(temp_pdf)
                    temp_pdf.seek(0)
                    
                    return temp_pdf
                except Exception as e:
                    st.error(f"Erreur lors de la conversion Word en PDF: {str(e)}")
                    return None

            # Maintenant le code de l'onglet
            with tab5:
                st.subheader("📤 Importer Word/PDF et Ajouter QR Code")
                
                uploaded_file = st.file_uploader("Choisir un fichier Word ou PDF", type=["docx", "pdf"], key="file_uploader")
                
                if uploaded_file is not None:
                    try:
                        # Convertir en PDF si c'est un fichier Word
                        if uploaded_file.name.endswith('.docx'):
                            with st.spinner("Conversion du Word en PDF..."):
                                pdf_file = convert_word_to_pdf(uploaded_file)
                                if pdf_file is None:
                                    st.error("Échec de la conversion Word en PDF")
                                    st.stop()
                        else:
                            pdf_file = uploaded_file
                        
                        # Extraire le texte du PDF
                        with st.spinner("Analyse du PDF en cours..."):
                            pdf_text = ""
                            with pdfplumber.open(pdf_file) as pdf:
                                for page in pdf.pages:
                                    pdf_text += page.extract_text() + "\n"

                            extracted_data = {
                                'nom': extract_between(pdf_text, "Nous certifions par la présente que", "détient un compte"),
                                'code_banque': extract_regex(pdf_text, r"CODE BANQUE : (\d+)"),
                                'numero_compte': extract_regex(pdf_text, r"NUMERO DE COMPTE : ([^\n]+)"),
                                'devise': extract_regex(pdf_text, r"Devise : ([^\n]+)"),
                                'iban': extract_regex(pdf_text, r"IBAN: ([^\n]+)"),
                                'bic': extract_regex(pdf_text, r"BIC: ([^\n]+)"),
                                'montant': extract_regex(pdf_text, r"montant total de ([^\n]+ FCFA)")
                            }

                        with st.expander("🔍 Données extraites", expanded=True):
                            st.json({k: v for k, v in extracted_data.items() if v})

                        qr_content = "\n".join([f"{k}: {v}" for k, v in extracted_data.items() if v])
                        
                        # Variables pour stocker le résultat
                        if 'modified_pdf' not in st.session_state:
                            st.session_state.modified_pdf = None
                        
                        with st.form("qr_settings"):
                            st.subheader("⚙️ Paramètres du QR Code")
                            
                            col1, col2 = st.columns(2)
                            with col1:
                                qr_position = st.selectbox("Position", ["Bas droite", "Bas gauche", "Haut droite", "Haut gauche"], index=0)
                                qr_size = st.slider("Taille (px)", 50, 150, 80)
                            
                            with col2:
                                qr_color = st.color_picker("Couleur", "#000000")
                                bg_color = st.color_picker("Fond", "#FFFFFF")
                            
                            # Modifiez la partie génération du QR code dans votre onglet tab5 comme suit :
                            if st.form_submit_button("🔄 Générer le PDF avec QR Code"):
                                with st.spinner("Création du nouveau PDF..."):
                                    try:
                                        # Vérification et préparation des données pour le QR code
                                        if not qr_content:
                                            st.warning("Aucune donnée extraite - Utilisation des informations basiques")
                                            qr_content = f"Document: {uploaded_file.name}\nDate: {datetime.now().strftime('%Y-%m-%d')}"
                                        else:
                                            # Formatage avancé des données
                                            qr_content = "=== INFORMATIONS DOCUMENT ===\n" + qr_content
                                        
                                        # Debug: afficher le contenu qui sera encodé
                                        st.session_state.qr_debug_content = qr_content
                                        st.write(f"Données à encoder dans le QR code ({(len(qr_content))} caractères):")
                                        st.code(qr_content[:200] + ("..." if len(qr_content) > 200 else ""))
                                        
                                        # Génération robuste du QR code
                                        qr = qrcode.QRCode(
                                            version=None,  # Auto-détection de la version
                                            error_correction=qrcode.constants.ERROR_CORRECT_H,
                                            box_size=8,  # Meilleure résolution
                                            border=2,
                                        )
                                        
                                        # Encodage des données
                                        qr.add_data(qr_content)
                                        qr.make(fit=True)
                                        
                                        # Création de l'image avec vérification
                                        qr_img = qr.make_image(fill_color=qr_color, back_color=bg_color).convert('RGB')
                                        
                                        # Vérification visuelle immédiate
                                        with st.expander("Aperçu du QR Code", expanded=True):
                                            st.image(qr_img, caption="QR Code généré", width=200)
                                        
                                        # Insertion dans le PDF
                                        output_pdf = add_qr_to_pdf(pdf_file, qr_img, position=qr_position)
                                        st.session_state.modified_pdf = output_pdf
                                        st.success("✅ PDF généré avec succès!")
                                        
                                    except Exception as e:
                                        st.error(f"❌ Erreur lors de la génération: {str(e)}")
                                        # Création d'un QR code d'erreur comme fallback
                                        error_qr = qrcode.make(f"ERREUR: {str(e)}")
                                        st.session_state.modified_pdf = add_qr_to_pdf(pdf_file, error_qr, position=qr_position)
                        
                        # Section de téléchargement et prévisualisation (HORS DU FORMULAIRE)
                        if st.session_state.modified_pdf:
                            col1, col2 = st.columns(2)
                            with col1:
                                # Bouton de téléchargement
                                st.download_button(
                                    "💾 Télécharger",
                                    data=st.session_state.modified_pdf,
                                    file_name="document_avec_qr.pdf",
                                    mime="application/pdf"
                                )
                            
                            with col2:
                                if st.button("👁️ Aperçu"):
                                    show_pdf(st.session_state.modified_pdf)
                            
                            # Affichage automatique
                            st.subheader("📄 Aperçu du document final")
                            show_pdf(st.session_state.modified_pdf)
                        
                        # Aperçu du document original
                        st.subheader("📄 Aperçu du document original")
                        show_pdf(pdf_file)

                    except Exception as e:
                        st.error(f"Erreur lors du traitement: {str(e)}")
            # NOUVEAU TAB 6 : Demandes des clients (Code 1)
            with tab6:
                st.subheader("📋 Demandes d'AVI des Clients")
                st.info("Cette section affiche les demandes d'AVI soumises par les clients depuis leur espace.")
                
                try:
                    avi_requests = db.get_avi_requests_from_users()
                    
                    if not avi_requests:
                        st.info("Aucune demande d'AVI de la part des clients")
                    else:
                        st.markdown(f"**{len(avi_requests)} demande(s) en attente de traitement**")
                        
                        for req in avi_requests:
                            status_color = {
                                'En attente': '🟡',
                                'Validée': '🟢',
                                'Rejetée': '🔴'
                            }.get(req.get('status', 'En attente'), '⚪')
                            
                            with st.expander(f"{status_color} {req['id']} - {req.get('user_email', 'Email inconnu')} - {req.get('created_at', datetime.now()).strftime('%d/%m/%Y %H:%M') if req.get('created_at') else 'Date inconnue'}"):
                                col1, col2 = st.columns(2)
                                
                                with col1:
                                    st.markdown("**📋 Informations Client**")
                                    st.write(f"**Nom:** {req.get('first_name', 'N/A')} {req.get('last_name', 'N/A')}")
                                    st.write(f"**Email:** {req.get('user_email', 'N/A')}")
                                    st.write(f"**Téléphone:** {req.get('phone', 'N/A')}")
                                    st.write(f"**ID Utilisateur:** {req.get('user_id', 'N/A')}")
                                
                                with col2:
                                    st.markdown("**📝 Détails de la Demande**")
                                    st.write(f"**Statut actuel:** {req.get('status', 'En attente')}")
                                    st.write(f"**Date de soumission:** {req.get('created_at').strftime('%d/%m/%Y à %H:%M') if req.get('created_at') else 'Date inconnue'}")
                                    if req.get('updated_at'):
                                        st.write(f"**Dernière mise à jour:** {req['updated_at'].strftime('%d/%m/%Y à %H:%M')}")
                                
                                # Afficher les données de la demande
                                request_data = req.get('request_data', {})
                                if request_data:
                                    st.markdown("**📄 Informations de la demande**")
                                    
                                    if isinstance(request_data, dict):
                                        data_col1, data_col2, data_col3 = st.columns(3)
                                        
                                        with data_col1:
                                            st.write("**Identité**")
                                            st.write(f"- Nom: {request_data.get('last_name', 'N/A')}")
                                            st.write(f"- Prénom: {request_data.get('first_name', 'N/A')}")
                                            st.write(f"- Date naiss.: {request_data.get('birth_date', 'N/A')}")
                                            st.write(f"- Lieu naiss.: {request_data.get('birth_place', 'N/A')}")
                                            st.write(f"- Nationalité: {request_data.get('nationality', 'N/A')}")
                                        
                                        with data_col2:
                                            st.write("**Adresse**")
                                            st.write(f"- Adresse: {request_data.get('address', 'N/A')}")
                                            st.write(f"- Code postal: {request_data.get('postal_code', 'N/A')}")
                                            st.write(f"- Ville: {request_data.get('city', 'N/A')}")
                                            st.write(f"- Pays: {request_data.get('country', 'N/A')}")
                                        
                                        with data_col3:
                                            st.write("**Informations AVI**")
                                            st.write(f"- Montant: {request_data.get('avi_amount', 'N/A')}")
                                            if request_data.get('identity_doc'):
                                                st.write(f"- Documents: {', '.join(request_data['identity_doc'])}")
                                
                                # Actions sur la demande
                                st.markdown("---")
                                st.markdown("**🔧 Actions**")
                                
                                col_action1, col_action2, col_action3 = st.columns(3)
                                
                                with col_action1:
                                    if st.button(f"✅ Valider", key=f"validate_{req['id']}"):
                                        if db.update_avi_request_status(req['id'], 'Validée'):
                                            # Envoyer une notification à l'utilisateur
                                            db.send_message_to_user(
                                                req['user_id'], 
                                                'support',
                                                f"Votre demande d'AVI {req['id']} a été validée. Vous serez contacté prochainement."
                                            )
                                            st.success(f"Demande {req['id']} validée avec succès!")
                                            time.sleep(1)
                                            st.rerun()
                                        else:
                                            st.error("Erreur lors de la validation")
                                
                                with col_action2:
                                    if st.button(f"❌ Rejeter", key=f"reject_{req['id']}"):
                                        if db.update_avi_request_status(req['id'], 'Rejetée'):
                                            db.send_message_to_user(
                                                req['user_id'], 
                                                'support',
                                                f"Votre demande d'AVI {req['id']} a été rejetée. Veuillez contacter le support pour plus d'informations."
                                            )
                                            st.success(f"Demande {req['id']} rejetée")
                                            time.sleep(1)
                                            st.rerun()
                                        else:
                                            st.error("Erreur lors du rejet")
                                
                                with col_action3:
                                    if st.button(f"💬 Contacter", key=f"contact_{req['id']}"):
                                        st.session_state.selected_user_for_message = req['user_id']
                                        st.session_state.user_name = f"{req.get('first_name', '')} {req.get('last_name', '')}"
                                        st.info(f"Redirection vers la messagerie pour contacter {st.session_state.user_name}")
                                        time.sleep(1)
                                        st.rerun()
                
                except Exception as e:
                    st.error(f"Erreur lors du chargement des demandes: {str(e)}")
            
            # NOUVEAU TAB 7 : Envoyer AVI aux utilisateurs
            # Dans la page "Gestion AVI", remplacez le contenu du tab7 (Envoyer AVI) par ceci :
            with tab7:
                st.subheader("📤 Envoyer une AVI à un ou plusieurs utilisateurs")
                
                # Récupérer la liste des AVI existantes
                avis_existants = db.get_all_avis(with_details=True)
                
                if not avis_existants:
                    st.warning("Aucune AVI disponible. Veuillez d'abord créer une AVI dans l'onglet 'Ajouter AVI'")
                else:
                    # Sélectionner l'AVI à envoyer
                    st.markdown("### 📄 Sélection de l'AVI à envoyer")
                    
                    avi_options = {}
                    for avi in avis_existants:
                        display_text = f"{avi['reference']} - {avi['nom_complet']} - {avi['montant']:,.2f} FCFA"
                        avi_options[display_text] = avi
                    
                    selected_avi_display = st.selectbox(
                        "Choisir une AVI existante",
                        options=list(avi_options.keys()),
                        help="Sélectionnez l'attestation que vous souhaitez envoyer"
                    )
                    
                    selected_avi = avi_options[selected_avi_display]
                    
                    # Aperçu des informations de l'AVI sélectionnée
                    with st.expander("📋 Aperçu de l'AVI sélectionnée", expanded=True):
                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown(f"""
                            **Référence:** {selected_avi['reference']}  
                            **Bénéficiaire:** {selected_avi['nom_complet']}  
                            **Code Banque:** {selected_avi['code_banque']}  
                            **Numéro Compte:** {selected_avi['numero_compte']}  
                            **IBAN:** {selected_avi['iban']}
                            """)
                        with col2:
                            st.markdown(f"""
                            **BIC:** {selected_avi['bic']}  
                            **Montant:** {selected_avi['montant']:,.2f} {selected_avi.get('devise', 'XAF')}  
                            **Date création:** {selected_avi['date_creation']}  
                            **Statut:** {selected_avi.get('statut', 'N/A')}
                            """)
                    
                    # Vérifier si le fichier PDF existe déjà
                    pdf_path = f"avi_documents/AVI_{selected_avi['reference']}.pdf"
                    
                    if not os.path.exists(pdf_path):
                        st.warning(f"⚠️ Le fichier PDF pour cette AVI n'existe pas encore. Veuillez d'abord le générer dans l'onglet 'Générer AVI'.")
                        
                        # Bouton pour générer directement
                        if st.button("🎯 Générer le PDF maintenant"):
                            with st.spinner("Génération du PDF en cours..."):
                                try:
                                    # Générer le PDF AVI
                                    pdf = FPDF()
                                    pdf.add_page()
                                    
                                    # Fonction pour convertir montant en lettres
                                    def montant_en_lettres(montant):
                                        from num2words import num2words
                                        partie_entiere = int(montant)
                                        texte = num2words(partie_entiere, lang='fr')
                                        if partie_entiere > 1:
                                            texte += " francs CFA"
                                        else:
                                            texte += " franc CFA"
                                        return texte.capitalize()
                                    
                                    # En-tête
                                    pdf.set_font(font_name, 'B', 16)
                                    pdf.cell(0, 30, 'ATTESTATION DE VIREMENT IRREVOCABLE', 0, 1, 'C')
                                    
                                    # Référence
                                    pdf.set_font(font_name, 'B', 10)
                                    pdf.cell(0, 0, f"DGF/EC-{selected_avi['reference']}", 0, 1, 'C')
                                    pdf.ln(10)
                                    
                                    # Logo
                                    try:
                                        pdf.image("assets/logo.png", x=10, y=10, w=30)
                                    except:
                                        pass
                                    
                                    # Corps du document
                                    pdf.set_font(font_name, '', 12)
                                    
                                    intro = [
                                        "Nous soussignés, Eco Capital (E.C), établissement de microfinance agréé pour exercer des",
                                        "activités bancaires en République du Congo conformément au décret n°7236/MEFB-CAB du",
                                        "15 novembre 2007, après avis conforme de la COBAC D-2007/2018, déclarons avoir notre",
                                        "siège au n°1636 Boulevard Denis Sassou Nguesso, Batignol Brazzaville.",
                                        "",
                                        "Représenté par son Directeur Général, Monsieur ILOKO Charmant.",
                                        "",
                                        f"Nous certifions par la présente que Monsieur/Madame {selected_avi['nom_complet']}",
                                        "détient un compte courant enregistré dans nos livres avec les caractéristiques suivantes :",
                                        ""
                                    ]
                                    
                                    for line in intro:
                                        pdf.cell(0, 5, line, 0, 2)
                                    
                                    # Informations bancaires
                                    pdf.set_font(font_name, 'B', 12)
                                    pdf.cell(40, 5, "CODE BANQUE :", 0, 0)
                                    pdf.set_font(font_name, '', 12)
                                    pdf.cell(0, 5, selected_avi['code_banque'], 0, 1)
                                    
                                    pdf.set_font(font_name, 'B', 12)
                                    pdf.cell(45, 5, "NUMERO COMPTE : ", 0, 0)
                                    pdf.set_font(font_name, '', 12)
                                    pdf.cell(0, 5, selected_avi['numero_compte'], 0, 1)
                                    
                                    pdf.set_font(font_name, 'B', 12)
                                    pdf.cell(20, 5, "Devise :", 0, 0)
                                    pdf.set_font(font_name, '', 12)
                                    pdf.cell(0, 5, selected_avi.get('devise', 'XAF'), 0, 1)
                                    pdf.ln(5)
                                    
                                    # Montant
                                    montant_lettres = montant_en_lettres(selected_avi['montant'])
                                    pdf.multi_cell(0, 5, f"Il est l'ordonnateur d'un virement irrévocable et permanent d'un montant total de {selected_avi['montant']:,.2f} FCFA ({montant_lettres})", 0, 'L')
                                    pdf.ln(5)
                                    
                                    # IBAN et BIC
                                    pdf.set_font(font_name, 'B', 12)
                                    pdf.cell(16, 5, "IBAN :", 0, 0)
                                    pdf.set_font(font_name, '', 12)
                                    pdf.cell(0, 5, selected_avi['iban'], 0, 1)
                                    
                                    pdf.set_font(font_name, 'B', 12)
                                    pdf.cell(16, 5, "BIC :", 0, 0)
                                    pdf.set_font(font_name, '', 12)
                                    pdf.cell(0, 5, selected_avi['bic'], 0, 1)
                                    pdf.ln(10)
                                    
                                    # Date et signature
                                    pdf.cell(0, 5, f"Fait à Brazzaville, le {datetime.now().strftime('%d %B %Y')}", 0, 1, 'R')
                                    pdf.ln(10)
                                    
                                    pdf.cell(0, 5, "Rubain MOUNGALA", 0, 1)
                                    pdf.set_font(font_name, 'B', 12)
                                    pdf.cell(0, 5, "Directeur de la Gestion Financière", 0, 1)
                                    
                                    # Pied de page
                                    footer = [
                                        "Eco capital Sarl",
                                        "Société a responsabilité limité au capital de 60.000.000 XAF",
                                        "Siège social : 1636 Boulevard Denis Sassou Nguesso Brazzaville",
                                        "Contact: 00242 06 931 31 06 /04 001 79 40"
                                    ]
                                    
                                    pdf.set_font(font_name, 'I', 10)
                                    for line in footer:
                                        pdf.cell(1, 4.5, line, 0, 2, 'L')
                                    
                                    # Sauvegarde
                                    os.makedirs("avi_documents", exist_ok=True)
                                    pdf.output(pdf_path)
                                    st.success("✅ PDF généré avec succès!")
                                    st.rerun()
                                    
                                except Exception as e:
                                    st.error(f"Erreur lors de la génération: {str(e)}")
                    
                    st.markdown("---")
                    st.markdown("### 👥 Sélection des destinataires")
                    
                    # Récupérer la liste des utilisateurs
                    users = db.get_all_users_from_code1()
                    
                    if not users:
                        st.warning("Aucun utilisateur trouvé dans la base")
                    else:
                        user_options = {f"{u['first_name']} {u['last_name']} ({u['email']})": u['id'] for u in users}
                        
                        selected_users = st.multiselect(
                            "Sélectionner les utilisateurs",
                            options=list(user_options.keys()),
                            help="Vous pouvez sélectionner plusieurs utilisateurs"
                        )
                        
                        if selected_users:
                            st.markdown(f"**{len(selected_users)} utilisateur(s) sélectionné(s)**")
                            for selected in selected_users:
                                st.caption(f"- {selected}")
                        
                        st.markdown("---")
                        
                        # Bouton d'envoi
                        col1, col2, col3 = st.columns([1, 2, 1])
                        with col2:
                            if st.button("📤 Envoyer l'AVI aux utilisateurs sélectionnés", type="primary", use_container_width=True):
                                if not selected_users:
                                    st.error("Veuillez sélectionner au moins un utilisateur")
                                elif not os.path.exists(pdf_path):
                                    st.error("Le fichier PDF n'existe pas. Veuillez d'abord le générer.")
                                else:
                                    success_count = 0
                                    failed_users = []
                                    
                                    with st.spinner(f"Envoi de l'AVI à {len(selected_users)} utilisateur(s)..."):
                                        # Lire le fichier PDF
                                        with open(pdf_path, "rb") as pdf_file:
                                            pdf_bytes = pdf_file.read()
                                        
                                        for selected_user in selected_users:
                                            user_id = user_options[selected_user]
                                            user_name = selected_user
                                            
                                            # Envoyer le message avec le PDF en pièce jointe
                                            message = f"""📄 **Attestation de Virement Irrévocable**

            Bonjour,

            Veuillez trouver ci-joint votre attestation AVI.

            **Référence:** {selected_avi['reference']}
            **Bénéficiaire:** {selected_avi['nom_complet']}
            **Montant:** {selected_avi['montant']:,.2f} FCFA

            Cordialement,
            Eco Capital Service Client
            """
                                            
                                            if db.send_message_to_user_with_attachment(user_id, 'support', message, pdf_bytes, f"AVI_{selected_avi['reference']}.pdf"):
                                                success_count += 1
                                            else:
                                                failed_users.append(user_name)
                                        
                                        # Enregistrer l'envoi dans l'historique
                                        if success_count > 0:
                                            db.log_avi_sending(selected_avi['reference'], success_count, len(selected_users))
                                    
                                    if success_count > 0:
                                        st.success(f"✅ AVI envoyée avec succès à {success_count} utilisateur(s)")
                                        st.balloons()
                                    if failed_users:
                                        st.error(f"❌ Échec d'envoi pour {len(failed_users)} utilisateur(s): {', '.join(failed_users)}")


        elif selected == "Générateur":
            st.markdown("""
                <div class="animated-entry">
                    <h2>📑 Générateur QR</h2>
                </div>
                """, unsafe_allow_html=True)
            #st.title("📑 Générateur QR")
            
            # Correction: Utiliser st.tabs() correctement et créer un seul onglet
            tab1, = st.tabs(["📤 Importer PDF"])  # Notez la virgule après tab1 pour unpack le tuple
            
            # Fonctions utilitaires
            def extract_between_1(text, start, end):
                """Extrait le texte entre deux chaînes"""
                start_idx = text.find(start)
                if start_idx == -1: return None
                start_idx += len(start)
                end_idx = text.find(end, start_idx)
                return text[start_idx:end_idx].strip() if end_idx != -1 else None

            def extract_regex_1(text, pattern):
                """Extrait avec une expression régulière"""
                match = re.search(pattern, text)
                return match.group(1).strip() if match else None

            def generate_qr_code_1(data, fill_color="#000000", back_color="#FFFFFF", size=100):
                """Génère un QR code"""
                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_H,
                    box_size=10,
                    border=4,
                )
                qr.add_data(data)
                qr.make(fit=True)
                return qr.make_image(fill_color=fill_color, back_color=back_color).convert('RGB')

            def add_qr_to_pdf_1(pdf_file, qr_img, position="Bas droite"):
                """Ajoute un QR code au PDF original"""
                temp_qr = BytesIO()
                qr_img.save(temp_qr, format="PNG")
                temp_qr.seek(0)
                
                # Lire le PDF original
                pdf_reader = PyPDF2.PdfReader(pdf_file)
                pdf_writer = PyPDF2.PdfWriter()
                
                # Créer un calque avec le QR code
                packet = BytesIO()
                can = canvas.Canvas(packet, pagesize=letter)
                
                # Positions ajustées pour ne pas dépasser des marges
                pos_map = {
                    "Bas droite": (450, 60),
                    "Bas gauche": (30, 30),
                    "Haut droite": (500, (letter[1])/2),
                    "Haut gauche": (30, letter[1] - 120),
                    "Centre": ((letter[0] - 100)/2, (letter[1] - 100)/2)
                }
                
                x, y = pos_map.get(position, pos_map["Haut droite"])
                
                # Dessiner le QR code sur le calque
                can.drawImage(ImageReader(temp_qr), x, y, width=100, height=100, mask='auto')
                can.save()
                
                # Fusionner le calque avec chaque page du PDF original
                packet.seek(0)
                qr_pdf = PyPDF2.PdfReader(packet)
                
                for page in pdf_reader.pages:
                    # Créer une nouvelle page avec le contenu original
                    new_page = page
                    
                    # Fusionner avec le calque QR code
                    new_page.merge_page(qr_pdf.pages[0])
                    pdf_writer.add_page(new_page)
                
                # Sauvegarder le résultat
                output = BytesIO()
                pdf_writer.write(output)
                output.seek(0)
                return output

            def show_pdf_1(file):
                """Affiche un PDF dans l'interface"""
                if hasattr(file, 'read'):
                    file.seek(0)
                    pdf_bytes = file.read()
                else:
                    with open(file, "rb") as f:
                        pdf_bytes = f.read()
                
                base64_pdf = base64.b64encode(pdf_bytes).decode('utf-8')
                
                pdf_display = f"""
                <div style="height: 600px; overflow: auto; margin: 1rem 0; border: 1px solid #ddd; border-radius: 8px;">
                    <embed
                        src="data:application/pdf;base64,{base64_pdf}"
                        type="application/pdf"
                        width="100%"
                        height="100%"
                        style="border: none;"
                    >
                </div>
                """
                st.markdown(pdf_display, unsafe_allow_html=True)

            def convert_word_to_pdf_1(word_file):
                """Convertit un fichier Word en PDF"""
                try:
                    # Lire le fichier Word
                    doc = Document(word_file)
                    
                    # Créer un fichier PDF temporaire
                    temp_pdf = BytesIO()
                    
                    # Convertir en PDF
                    doc.save(temp_pdf)
                    temp_pdf.seek(0)
                    
                    return temp_pdf
                except Exception as e:
                    st.error(f"Erreur lors de la conversion Word en PDF: {str(e)}")
                    return None

            # Maintenant le code de l'onglet
            with tab1:  # Maintenant cela fonctionne car tab1 est un seul onglet
                st.subheader("📤 Importer Word/PDF et Ajouter QR Code")
                
                uploaded_file = st.file_uploader("Choisir un fichier Word ou PDF", type=["docx", "pdf"], key="file_uploader")
                
                if uploaded_file is not None:
                    try:
                        # Convertir en PDF si c'est un fichier Word
                        if uploaded_file.name.endswith('.docx'):
                            with st.spinner("Conversion du Word en PDF..."):
                                pdf_file = convert_word_to_pdf_1(uploaded_file)
                                if pdf_file is None:
                                    st.error("Échec de la conversion Word en PDF")
                                    st.stop()
                        else:
                            pdf_file = uploaded_file
                        
                        # Extraire le texte du PDF
                        with st.spinner("Analyse du PDF en cours..."):
                            pdf_text = ""
                            with pdfplumber.open(pdf_file) as pdf:
                                for page in pdf.pages:
                                    pdf_text += page.extract_text() + "\n"

                            extracted_data = {
                                'Client': extract_regex_1(pdf_text, r"Client : ([^\n]+)"),
                                'Période': extract_regex_1(pdf_text, r"Période : (\d+)"),
                                'Compte N°': extract_regex_1(pdf_text, r"Compte N° : ([^\n]+)"),
                                'devise': extract_regex_1(pdf_text, r"Devise : ([^\n]+)"),
                                'Type de Compte': extract_regex_1(pdf_text, r"Type de Compte : ([^\n]+)"),
                                'Bénéficiaire': extract_regex_1(pdf_text, r"Bénéficiaire : ([^\n]+)"),
                                'montant': extract_regex_1(pdf_text, r"Montant : ([^\n]+)")
                            }

                        with st.expander("🔍 Données extraites", expanded=True):
                            st.json({k: v for k, v in extracted_data.items() if v})

                        qr_content = "\n".join([f"{k}: {v}" for k, v in extracted_data.items() if v])
                        
                        # Variables pour stocker le résultat
                        if 'modified_pdf' not in st.session_state:
                            st.session_state.modified_pdf = None
                        
                        with st.form("qr_settings"):
                            st.subheader("⚙️ Paramètres du QR Code")
                            
                            col1, col2 = st.columns(2)
                            with col1:
                                qr_position = st.selectbox("Position", ["Bas droite", "Bas gauche", "Haut droite", "Haut gauche"], index=0)
                                qr_size = st.slider("Taille (px)", 50, 150, 80)
                            
                            with col2:
                                qr_color = st.color_picker("Couleur", "#000000")
                                bg_color = st.color_picker("Fond", "#FFFFFF")
                            
                            # Modifiez la partie génération du QR code dans votre onglet tab5 comme suit :
                            if st.form_submit_button("🔄 Générer le PDF avec QR Code"):
                                with st.spinner("Création du nouveau PDF..."):
                                    try:
                                        # Vérification et préparation des données pour le QR code
                                        if not qr_content:
                                            st.warning("Aucune donnée extraite - Utilisation des informations basiques")
                                            qr_content = f"Document: {uploaded_file.name}\nDate: {datetime.now().strftime('%Y-%m-%d')}"
                                        else:
                                            # Formatage avancé des données
                                            qr_content = "=== INFORMATIONS DOCUMENT ===\n" + qr_content
                                        
                                        # Debug: afficher le contenu qui sera encodé
                                        st.session_state.qr_debug_content = qr_content
                                        st.write(f"Données à encoder dans le QR code ({(len(qr_content))} caractères):")
                                        st.code(qr_content[:200] + ("..." if len(qr_content) > 200 else ""))
                                        
                                        # Génération robuste du QR code
                                        qr = qrcode.QRCode(
                                            version=None,  # Auto-détection de la version
                                            error_correction=qrcode.constants.ERROR_CORRECT_H,
                                            box_size=8,  # Meilleure résolution
                                            border=2,
                                        )
                                        
                                        # Encodage des données
                                        qr.add_data(qr_content)
                                        qr.make(fit=True)
                                        
                                        # Création de l'image avec vérification
                                        qr_img = qr.make_image(fill_color=qr_color, back_color=bg_color).convert('RGB')
                                        
                                        # Vérification visuelle immédiate
                                        with st.expander("Aperçu du QR Code", expanded=True):
                                            st.image(qr_img, caption="QR Code généré", width=200)
                                        
                                        # Insertion dans le PDF
                                        output_pdf = add_qr_to_pdf_1(pdf_file, qr_img, position=qr_position)
                                        st.session_state.modified_pdf = output_pdf
                                        st.success("✅ PDF généré avec succès!")
                                        
                                    except Exception as e:
                                        st.error(f"❌ Erreur lors de la génération: {str(e)}")
                                        # Création d'un QR code d'erreur comme fallback
                                        error_qr = qrcode.make(f"ERREUR: {str(e)}")
                                        st.session_state.modified_pdf = add_qr_to_pdf_1(pdf_file, error_qr, position=qr_position)
                        
                        # Section de téléchargement et prévisualisation (HORS DU FORMULAIRE)
                        if st.session_state.modified_pdf:
                            col1, col2 = st.columns(2)
                            with col1:
                                # Bouton de téléchargement
                                st.download_button(
                                    "💾 Télécharger",
                                    data=st.session_state.modified_pdf,
                                    file_name="document_avec_qr.pdf",
                                    mime="application/pdf"
                                )
                            
                            with col2:
                                if st.button("👁️ Aperçu"):
                                    show_pdf_1(st.session_state.modified_pdf)
                            
                            # Affichage automatique
                            st.subheader("📄 Aperçu du document final")
                            show_pdf_1(st.session_state.modified_pdf)
                        
                        # Aperçu du document original
                        st.subheader("📄 Aperçu du document original")
                        show_pdf_1(pdf_file)

                    except Exception as e:
                        st.error(f"Erreur lors du traitement: {str(e)}")

        elif selected == "Messages":
            st.title("💬 Centre de Messagerie")
            
            tab1, tab2 = st.tabs(["📨 Conversations avec les Clients", "📝 Nouveau Message"])
            
            with tab1:
                st.subheader("📨 Conversations avec les Clients")
                
                # Récupérer tous les utilisateurs avec qui il y a des conversations
                users = db.get_all_users_from_code1()
                
                if not users:
                    st.info("Aucun utilisateur trouvé")
                else:
                    # Créer une liste des utilisateurs avec leurs messages
                    user_conversations = []
                    for user in users:
                        messages = db.get_conversation_with_user(user['id'])
                        if messages:
                            last_message = messages[-1] if messages else None
                            user_conversations.append({
                                'user': user,
                                'messages': messages,
                                'last_message': last_message,
                                'unread_count': sum(1 for m in messages if m.get('sender') == 'user' and not m.get('is_read', False))
                            })
                    
                    if not user_conversations:
                        st.info("Aucune conversation avec les clients")
                    else:
                        # Sélection d'un utilisateur
                        user_options = {f"{conv['user']['first_name']} {conv['user']['last_name']} ({conv['user']['email']}) - {conv['unread_count']} non lu(s)": conv for conv in user_conversations}
                        
                        selected_conversation = st.selectbox(
                            "Sélectionner une conversation",
                            options=list(user_options.keys()),
                            key="conversation_select"
                        )
                        
                        if selected_conversation:
                            conv = user_options[selected_conversation]
                            user = conv['user']
                            messages = conv['messages']
                            
                            st.markdown(f"""
                            <div style="background: linear-gradient(135deg, #667eea, #764ba2); 
                                        padding: 1rem; border-radius: 10px; margin-bottom: 1rem; color: white;">
                                <h4 style="margin: 0;">💬 Conversation avec {user['first_name']} {user['last_name']}</h4>
                                <p style="margin: 0.5rem 0 0 0; opacity: 0.9;">📧 {user['email']} | 📱 {user.get('phone', 'Non renseigné')}</p>
                            </div>
                            """, unsafe_allow_html=True)
                            
                            # Affichage des messages
                            st.markdown("### 📝 Historique des messages")
                            
                            messages_container = st.container()
                            with messages_container:
                                for msg in messages:
                                    if msg['sender'] == 'support':
                                        # Message du support
                                        st.markdown(f"""
                                        <div style="background: linear-gradient(135deg, #667eea, #764ba2); 
                                                    color: white; padding: 0.75rem 1rem; border-radius: 15px 15px 5px 15px; 
                                                    margin: 0.5rem 0; max-width: 80%; margin-left: auto;">
                                            <strong>🏦 Support</strong>
                                            <p style="margin: 0.25rem 0;">{msg['content']}</p>
                                        """, unsafe_allow_html=True)
                                        
                                        # Afficher la pièce jointe si elle existe
                                        if msg.get('attachment') and msg.get('attachment_filename'):
                                            file_bytes = msg['attachment']
                                            filename = msg['attachment_filename']
                                            file_ext = filename.split('.')[-1].lower() if '.' in filename else ''
                                            
                                            if file_ext in ['jpg', 'jpeg', 'png', 'gif', 'webp']:
                                                # Image - afficher un aperçu
                                                try:
                                                    img_data = base64.b64encode(file_bytes).decode('utf-8')
                                                    st.markdown(f"""
                                                    <div style="margin-top: 0.5rem;">
                                                        <img src="data:image/{file_ext};base64,{img_data}" 
                                                            style="max-width: 200px; max-height: 150px; border-radius: 8px; cursor: pointer;"
                                                            onclick="window.open(this.src)" />
                                                        <br>
                                                        <small>📎 {filename}</small>
                                                    </div>
                                                    """, unsafe_allow_html=True)
                                                except:
                                                    st.markdown(f'<div style="margin-top: 0.5rem;">📎 {filename}</div>', unsafe_allow_html=True)
                                            else:
                                                # Bouton de téléchargement pour les autres fichiers
                                                st.download_button(
                                                    label=f"📎 Télécharger {filename}",
                                                    data=file_bytes,
                                                    file_name=filename,
                                                    mime="application/octet-stream",
                                                    key=f"download_admin_{msg.get('id', '')}"
                                                )
                                        
                                        st.markdown(f"""
                                            <small style="opacity: 0.8;">📅 {msg['timestamp'].strftime('%d/%m/%Y %H:%M') if msg.get('timestamp') else 'Date inconnue'}</small>
                                        </div>
                                        """, unsafe_allow_html=True)
                                    else:
                                        # Message du client
                                        st.markdown(f"""
                                        <div style="background: #f0f0f0; 
                                                    color: #333; padding: 0.75rem 1rem; border-radius: 15px 15px 15px 5px; 
                                                    margin: 0.5rem 0; max-width: 80%;">
                                            <strong>👤 {user['first_name']} {user['last_name']}</strong>
                                            <p style="margin: 0.25rem 0;">{msg['content']}</p>
                                        """, unsafe_allow_html=True)
                                        
                                        # Afficher la pièce jointe du client si elle existe
                                        if msg.get('attachment') and msg.get('attachment_filename'):
                                            file_bytes = msg['attachment']
                                            filename = msg['attachment_filename']
                                            file_ext = filename.split('.')[-1].lower() if '.' in filename else ''
                                            
                                            if file_ext in ['jpg', 'jpeg', 'png', 'gif', 'webp']:
                                                try:
                                                    img_data = base64.b64encode(file_bytes).decode('utf-8')
                                                    st.markdown(f"""
                                                    <div style="margin-top: 0.5rem;">
                                                        <img src="data:image/{file_ext};base64,{img_data}" 
                                                            style="max-width: 200px; max-height: 150px; border-radius: 8px; cursor: pointer;"
                                                            onclick="window.open(this.src)" />
                                                        <br>
                                                        <small>📎 {filename}</small>
                                                    </div>
                                                    """, unsafe_allow_html=True)
                                                except:
                                                    st.markdown(f'<div style="margin-top: 0.5rem;">📎 {filename}</div>', unsafe_allow_html=True)
                                            else:
                                                st.download_button(
                                                    label=f"📎 Télécharger {filename}",
                                                    data=file_bytes,
                                                    file_name=filename,
                                                    mime="application/octet-stream",
                                                    key=f"download_client_{msg.get('id', '')}"
                                                )
                                        
                                        st.markdown(f"""
                                            <small style="opacity: 0.8;">📅 {msg['timestamp'].strftime('%d/%m/%Y %H:%M') if msg.get('timestamp') else 'Date inconnue'}</small>
                                        </div>
                                        """, unsafe_allow_html=True)
                            
                            # Formulaire d'envoi de message avec pièce jointe
                            st.markdown("---")
                            st.markdown("### ✏️ Répondre")
                            
                            with st.form("reply_message_form"):
                                reply_content = st.text_area("Votre message", placeholder="Écrivez votre réponse ici...", height=80)
                                
                                # Upload de fichier
                                uploaded_file = st.file_uploader(
                                    "📎 Joindre un fichier (optionnel)",
                                    type=['pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx', 'xls', 'xlsx', 'txt', 'zip'],
                                    help="Vous pouvez joindre des documents, images, PDF, etc.",
                                    key="reply_attachment"
                                )
                                
                                col1, col2, col3 = st.columns([1, 2, 1])
                                with col2:
                                    submitted = st.form_submit_button("📤 Envoyer", type="primary", use_container_width=True)
                                
                                if submitted:
                                    if not reply_content.strip() and not uploaded_file:
                                        st.warning("Veuillez écrire un message ou joindre un fichier.")
                                    else:
                                        if uploaded_file:
                                            file_bytes = uploaded_file.read()
                                            filename = uploaded_file.name
                                            file_type = uploaded_file.type
                                            
                                            success = db.send_message_to_user_with_attachment(
                                                user['id'], 
                                                'support', 
                                                reply_content if reply_content.strip() else "[Message avec pièce jointe]", 
                                                file_bytes, 
                                                filename
                                            )
                                        else:
                                            success = db.send_message_to_user(user['id'], 'support', reply_content)
                                        
                                        if success:
                                            st.success("Message envoyé avec succès!")
                                            time.sleep(1)
                                            st.rerun()
                                        else:
                                            st.error("Erreur lors de l'envoi du message")
            
            with tab2:
                st.subheader("📝 Nouveau Message")
                st.markdown("Envoyer un message à un ou plusieurs utilisateurs")
                
                users = db.get_all_users_from_code1()
                
                if not users:
                    st.warning("Aucun utilisateur trouvé")
                else:
                    user_options = {f"{u['first_name']} {u['last_name']} ({u['email']})": u['id'] for u in users}
                    
                    selected_users = st.multiselect(
                        "Destinataires *",
                        options=list(user_options.keys()),
                        help="Sélectionnez un ou plusieurs utilisateurs"
                    )
                    
                    message_subject = st.text_input("Objet (optionnel)", placeholder="Sujet du message")
                    message_content = st.text_area("Message *", placeholder="Écrivez votre message ici...", height=150)
                    
                    # Upload de fichier pour nouveau message
                    st.markdown("### 📎 Pièce jointe (optionnelle)")
                    uploaded_file_new = st.file_uploader(
                        "Choisir un fichier à joindre",
                        type=['pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx', 'xls', 'xlsx', 'txt', 'zip'],
                        help="PDF, images, documents Word/Excel...",
                        key="new_message_attachment"
                    )
                    
                    col1, col2, col3 = st.columns([1, 2, 1])
                    with col2:
                        if st.button("📤 Envoyer", type="primary", use_container_width=True):
                            if not selected_users:
                                st.error("Veuillez sélectionner au moins un destinataire")
                            elif not message_content.strip() and not uploaded_file_new:
                                st.error("Veuillez écrire un message ou joindre un fichier")
                            else:
                                subject_line = f"[{message_subject}] " if message_subject else ""
                                full_message = f"{subject_line}{message_content}"
                                
                                success_count = 0
                                failed_users = []
                                
                                with st.spinner(f"Envoi du message à {len(selected_users)} utilisateur(s)..."):
                                    for selected_user in selected_users:
                                        user_id = user_options[selected_user]
                                        
                                        if uploaded_file_new:
                                            file_bytes = uploaded_file_new.read()
                                            filename = uploaded_file_new.name
                                            success = db.send_message_to_user_with_attachment(
                                                user_id, 'support', full_message, file_bytes, filename
                                            )
                                        else:
                                            success = db.send_message_to_user(user_id, 'support', full_message)
                                        
                                        if success:
                                            success_count += 1
                                        else:
                                            failed_users.append(selected_user)
                                
                                if success_count > 0:
                                    st.success(f"✅ Message envoyé à {success_count} utilisateur(s)")
                                    st.balloons()
                                if failed_users:
                                    st.error(f"❌ Échec d'envoi pour {len(failed_users)} utilisateur(s)")
                                
                                time.sleep(2)
                                st.rerun()
    
    except Exception as e:
        st.error(f"Erreur: {str(e)}")
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    main()
