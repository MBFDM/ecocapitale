import mysql.connector
from mysql.connector import Error
import hashlib
import uuid
from datetime import datetime
import streamlit as st
import json

class Database:
    def __init__(self):
        """Initialisation de la connexion à la base de données"""
        self.connection = None
        self.cursor = None
        self.connect()
        self.create_tables()
    
    def connect(self):
        """Établir la connexion à MySQL"""
        try:
            self.connection = mysql.connector.connect(
                host='ecocapital-mbfdm.c.aivencloud.com',
                user='avnadmin',
                password='AVNS_3a2plzaevzttmJ4Tcs9',
                database='ecocapital',
                port=14431
            )
            self.cursor = self.connection.cursor(dictionary=True)
            print("✅ Connexion à MySQL réussie")
        except Error as e:
            print(f"❌ Erreur de connexion à MySQL: {e}")
            st.error(f"Erreur de connexion à la base de données: {e}")
    
    def create_database(self):
        """Créer la base de données si elle n'existe pas"""
        try:
            conn = mysql.connector.connect(
                host='ecocapital-mbfdm.c.aivencloud.com',
                user='avnadmin',
                password='AVNS_3a2plzaevzttmJ4Tcs9',
                port=14431
            )
            cursor = conn.cursor()
            self.create_tables()
            conn.close()
            print("✅ Base de données créée ou déjà existante")
        except Error as e:
            print(f"❌ Erreur création base de données: {e}")
    
    def create_tables(self):
        """Créer les tables nécessaires"""
        try:
            # Table des utilisateurs
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id VARCHAR(36) PRIMARY KEY,
                    first_name VARCHAR(100) NOT NULL,
                    last_name VARCHAR(100) NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    phone VARCHAR(50),
                    password VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    avatar LONGBLOB NULL
                )
            """)
            
            # Table des demandes AVI
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS avi_requests (
                    id VARCHAR(50) PRIMARY KEY,
                    user_id VARCHAR(36) NOT NULL,
                    user_email VARCHAR(255),
                    request_data JSON,
                    status VARCHAR(50) DEFAULT 'En attente',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            
            # Table des messages
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(36) NOT NULL,
                    sender VARCHAR(50) NOT NULL,
                    content TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_read BOOLEAN DEFAULT FALSE,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            
            # Table des conversations
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS conversations (
                    id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(36) NOT NULL,
                    name VARCHAR(255) NOT NULL,
                    last_message TEXT,
                    unread_count INT DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            
            # Table des documents uploadés
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS documents (
                    id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(36) NOT NULL,
                    request_id VARCHAR(50),
                    filename VARCHAR(255) NOT NULL,
                    file_type VARCHAR(50),
                    file_size INT,
                    file_data LONGBLOB,
                    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            
            self.connection.commit()
            print("✅ Tables créées avec succès")
        except Error as e:
            print(f"❌ Erreur création tables: {e}")
    
    # === FONCTIONS UTILISATEURS ===
    
    def create_user(self, first_name, last_name, email, phone, password):
        """Créer un nouvel utilisateur"""
        try:
            user_id = str(uuid.uuid4())
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            
            query = """
                INSERT INTO users (id, first_name, last_name, email, phone, password)
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            self.cursor.execute(query, (user_id, first_name, last_name, email, phone, hashed_password))
            self.connection.commit()
            return True, user_id
        except Error as e:
            print(f"❌ Erreur création utilisateur: {e}")
            return False, str(e)
    
    def authenticate_user(self, email, password):
        """Authentifier un utilisateur"""
        try:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            
            query = "SELECT * FROM users WHERE email = %s AND password = %s AND is_active = TRUE"
            self.cursor.execute(query, (email, hashed_password))
            user = self.cursor.fetchone()
            
            if user:
                # Mettre à jour last_login
                update_query = "UPDATE users SET last_login = NOW() WHERE id = %s"
                self.cursor.execute(update_query, (user['id'],))
                self.connection.commit()
                
                if user.get('avatar') and isinstance(user['avatar'], bytes):
                    user['avatar'] = user['avatar']
                
                return user
            return None
        except Error as e:
            print(f"❌ Erreur authentification: {e}")
            return None
    
    def get_user_by_email(self, email):
        """Récupérer un utilisateur par email"""
        try:
            query = "SELECT * FROM users WHERE email = %s"
            self.cursor.execute(query, (email,))
            return self.cursor.fetchone()
        except Error as e:
            print(f"❌ Erreur récupération utilisateur: {e}")
            return None
    
    def update_user(self, user_id, **kwargs):
        """Mettre à jour les informations d'un utilisateur"""
        try:
            update_fields = []
            values = []
            
            for key, value in kwargs.items():
                if value is not None:
                    update_fields.append(f"{key} = %s")
                    values.append(value)
            
            if update_fields:
                values.append(user_id)
                query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = %s"
                self.cursor.execute(query, values)
                self.connection.commit()
                return True
            return False
        except Error as e:
            print(f"❌ Erreur mise à jour utilisateur: {e}")
            return False
    
    # === FONCTIONS DEMANDES AVI ===
    
    def create_avi_request(self, user_id, user_email, request_data):
        """Créer une nouvelle demande AVI"""
        try:
            date_str = datetime.now().strftime('%Y%m%d')
            
            query = "SELECT COUNT(*) as count FROM avi_requests WHERE id LIKE %s"
            self.cursor.execute(query, (f"AVI-{date_str}-%",))
            count = self.cursor.fetchone()['count'] + 1
            
            request_id = f"AVI-{date_str}-{count:03d}"
            
            query = """
                INSERT INTO avi_requests (id, user_id, user_email, request_data, status)
                VALUES (%s, %s, %s, %s, 'En attente')
            """
            self.cursor.execute(query, (request_id, user_id, user_email, json.dumps(request_data)))
            self.connection.commit()
            return True, request_id
        except Error as e:
            print(f"❌ Erreur création demande AVI: {e}")
            return False, str(e)
    
    def get_user_avi_requests(self, user_id):
        """Récupérer toutes les demandes AVI d'un utilisateur"""
        try:
            query = """
                SELECT * FROM avi_requests 
                WHERE user_id = %s 
                ORDER BY created_at DESC
            """
            self.cursor.execute(query, (user_id,))
            requests = self.cursor.fetchall()
            
            for req in requests:
                if isinstance(req['request_data'], str):
                    req['request_data'] = json.loads(req['request_data'])
            
            return requests
        except Error as e:
            print(f"❌ Erreur récupération demandes AVI: {e}")
            return []
    
    def get_avi_request_by_id(self, request_id):
        """Récupérer une demande AVI par son ID"""
        try:
            query = "SELECT * FROM avi_requests WHERE id = %s"
            self.cursor.execute(query, (request_id,))
            request = self.cursor.fetchone()
            
            if request and isinstance(request['request_data'], str):
                request['request_data'] = json.loads(request['request_data'])
            
            return request
        except Error as e:
            print(f"❌ Erreur récupération demande AVI: {e}")
            return None
    
    def get_avi_stats(self, user_id):
        """Obtenir les statistiques des demandes AVI"""
        try:
            stats = {}
            
            query = "SELECT COUNT(*) as count FROM avi_requests WHERE user_id = %s"
            self.cursor.execute(query, (user_id,))
            stats['total'] = self.cursor.fetchone()['count']
            
            query = "SELECT COUNT(*) as count FROM avi_requests WHERE user_id = %s AND status = 'Validée'"
            self.cursor.execute(query, (user_id,))
            stats['validated'] = self.cursor.fetchone()['count']
            
            query = "SELECT COUNT(*) as count FROM avi_requests WHERE user_id = %s AND status = 'En attente'"
            self.cursor.execute(query, (user_id,))
            stats['pending'] = self.cursor.fetchone()['count']
            
            query = "SELECT COUNT(*) as count FROM avi_requests WHERE user_id = %s AND status = 'Rejetée'"
            self.cursor.execute(query, (user_id,))
            stats['rejected'] = self.cursor.fetchone()['count']
            
            return stats
        except Error as e:
            print(f"❌ Erreur statistiques AVI: {e}")
            return {'total': 0, 'validated': 0, 'pending': 0, 'rejected': 0}
    
    # === FONCTIONS MESSAGES ===
    
    def create_conversation(self, user_id, name):
        """Créer une nouvelle conversation"""
        try:
            conv_id = str(uuid.uuid4())
            query = """
                INSERT INTO conversations (id, user_id, name)
                VALUES (%s, %s, %s)
            """
            self.cursor.execute(query, (conv_id, user_id, name))
            self.connection.commit()
            return conv_id
        except Error as e:
            print(f"❌ Erreur création conversation: {e}")
            return None
    
    def get_user_conversations(self, user_id):
        try:
            self.cursor.execute("""
                SELECT id, user_id, name, 
                    COALESCE(last_message, 'Nouvelle conversation') as last_message,
                    COALESCE(unread_count, 0) as unread_count,
                    created_at 
                FROM conversations 
                WHERE user_id=%s 
                ORDER BY created_at DESC
            """, (user_id,))
            results = self.cursor.fetchall()
            return [row for row in results if row is not None]
        except Error as e:
            print(f"Erreur get_user_conversations: {e}")
            return []
    
    def send_message(self, user_id, sender, content):
        """Envoyer un message"""
        try:
            message_id = str(uuid.uuid4())
            query = """
                INSERT INTO messages (id, user_id, sender, content)
                VALUES (%s, %s, %s, %s)
            """
            self.cursor.execute(query, (message_id, user_id, sender, content))
            self.connection.commit()
            return True, message_id
        except Error as e:
            print(f"❌ Erreur envoi message: {e}")
            return False, str(e)
    
    def get_user_messages(self, user_id, limit=50):
        """Récupérer les messages d'un utilisateur"""
        try:
            query = """
                SELECT * FROM messages 
                WHERE user_id = %s 
                ORDER BY timestamp DESC 
                LIMIT %s
            """
            self.cursor.execute(query, (user_id, limit))
            messages = self.cursor.fetchall()
            
            update_query = """
                UPDATE messages SET is_read = TRUE 
                WHERE user_id = %s AND sender = 'support' AND is_read = FALSE
            """
            self.cursor.execute(update_query, (user_id,))
            self.connection.commit()
            
            return messages[::-1]
        except Error as e:
            print(f"❌ Erreur récupération messages: {e}")
            return []
    
    def get_unread_messages_count(self, user_id):
        """Compter les messages non lus"""
        try:
            query = """
                SELECT COUNT(*) as count FROM messages 
                WHERE user_id = %s AND sender = 'support' AND is_read = FALSE
            """
            self.cursor.execute(query, (user_id,))
            result = self.cursor.fetchone()
            return result['count'] if result else 0
        except Error as e:
            print(f"❌ Erreur comptage messages: {e}")
            return 0
    
    # === FONCTIONS DOCUMENTS ===
    
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
    
    def get_document(self, doc_id):
        """Récupérer un document"""
        try:
            query = "SELECT * FROM documents WHERE id = %s"
            self.cursor.execute(query, (doc_id,))
            return self.cursor.fetchone()
        except Error as e:
            print(f"❌ Erreur récupération document: {e}")
            return None
    
    def get_user_documents(self, user_id):
        """Récupérer tous les documents d'un utilisateur"""
        try:
            query = "SELECT id, filename, file_type, file_size, upload_date FROM documents WHERE user_id = %s"
            self.cursor.execute(query, (user_id,))
            return self.cursor.fetchall()
        except Error as e:
            print(f"❌ Erreur récupération documents: {e}")
            return []
    
    # ==================== AVI RECUES (DEPUIS ADMIN) ====================
    def get_user_avis(self, user_id):
        """Récupère les AVI envoyées à l'utilisateur par l'administrateur"""
        try:
            # Récupérer les informations de l'utilisateur
            self.cursor.execute('''
            SELECT first_name, last_name, email FROM users WHERE id = %s
            ''', (user_id,))
            user = self.cursor.fetchone()
            
            if not user:
                return []
            
            first_name = user.get('first_name', '')
            last_name = user.get('last_name', '')
            email = user.get('email', '')
            
            # Récupérer les AVI qui correspondent à l'utilisateur
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
            WHERE nom_complet LIKE %s OR nom_complet LIKE %s OR email LIKE %s
            ORDER BY date_creation DESC
            ''', (f'%{first_name}%', f'%{last_name}%', f'%{email}%'))
            
            results = self.cursor.fetchall()
            
            # Si aucun résultat, essayer une recherche plus large
            if not results:
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
                LIMIT 20
                ''')
                results = self.cursor.fetchall()
            
            return results
        except Error as e:
            print(f"Erreur get_user_avis: {e}")
            return []
    
    def close(self):
        """Fermer la connexion à la base de données"""
        if self.connection and self.connection.is_connected():
            self.cursor.close()
            self.connection.close()
            print("✅ Connexion MySQL fermée")

# Fonction d'initialisation de la base de données
@st.cache_resource
def init_database():
    """Initialiser la connexion à la base de données"""
    db = Database()
    return db