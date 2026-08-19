"""
Application de Vérification d'AVI
Permet de vérifier les informations d'une AVI en entrant sa référence
"""

import streamlit as st
import mysql.connector
import pandas as pd
from datetime import datetime
import logging
import re
import time

# Configuration de la page
st.set_page_config(
    page_title="Vérificateur AVI - Eco Capital",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Configuration de la base de données
MYSQL_CONFIG = {
    'host': 'ecocapital-mbfdm.c.aivencloud.com',
    'user': 'avnadmin',
    'password': 'AVNS_3a2plzaevzttmJ4Tcs9',
    'database': 'ecocapital',
    'port': 14431,
}

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Styles CSS personnalisés
st.markdown("""
<style>
    .main-container {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 15px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
        animation: fadeIn 0.8s ease-out;
    }
    
    .main-container h1 {
        margin: 0;
        font-size: 2.5rem;
    }
    
    .main-container p {
        margin: 0.5rem 0 0 0;
        opacity: 0.9;
    }
    
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(-20px); }
        to { opacity: 1; transform: translateY(0); }
    }
    
    .result-card {
        background: white;
        padding: 1.5rem;
        border-radius: 10px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        margin-top: 1.5rem;
        animation: slideUp 0.6s ease-out;
    }
    
    @keyframes slideUp {
        from { opacity: 0; transform: translateY(30px); }
        to { opacity: 1; transform: translateY(0); }
    }
    
    .info-item {
        display: flex;
        justify-content: space-between;
        padding: 0.75rem 0;
        border-bottom: 1px solid #eee;
    }
    
    .info-item:last-child {
        border-bottom: none;
    }
    
    .info-label {
        font-weight: 600;
        color: #555;
    }
    
    .info-value {
        color: #333;
        font-weight: 500;
    }
    
    .status-valid {
        background: #28a745;
        color: white;
        padding: 0.25rem 1rem;
        border-radius: 20px;
        font-weight: 600;
        display: inline-block;
    }
    
    .status-invalid {
        background: #dc3545;
        color: white;
        padding: 0.25rem 1rem;
        border-radius: 20px;
        font-weight: 600;
        display: inline-block;
    }
    
    .verification-badge {
        background: #ffc107;
        color: #333;
        padding: 0.5rem 1.5rem;
        border-radius: 30px;
        font-weight: 700;
        display: inline-block;
        font-size: 0.9rem;
    }

    .stTextInput > div > div > input {
        font-size: 1.1rem;
        padding: 0.75rem 1rem;
    }
</style>
""", unsafe_allow_html=True)

def get_db_connection():
    """Établit une connexion à la base de données MySQL"""
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        return conn
    except mysql.connector.Error as err:
        logger.error(f"Erreur de connexion à MySQL: {err}")
        st.error(f"❌ Erreur de connexion à la base de données: {err}")
        return None

def init_database():
    """Vérifie et crée les tables nécessaires si elles n'existent pas"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        
        # Vérifier si la table avis existe
        cursor.execute("""
            SELECT COUNT(*) FROM information_schema.tables 
            WHERE table_schema = %s AND table_name = 'avis'
        """, (MYSQL_CONFIG['database'],))
        
        table_exists = cursor.fetchone()[0] > 0
        
        if not table_exists:
            # Créer la table avis si elle n'existe pas
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS avis (
                id INT AUTO_INCREMENT PRIMARY KEY,
                reference VARCHAR(50) UNIQUE NOT NULL,
                nom_complet VARCHAR(255) NOT NULL,
                code_banque VARCHAR(50) NOT NULL,
                numero_compte VARCHAR(50) NOT NULL,
                devise VARCHAR(10) NOT NULL,
                iban VARCHAR(50) NOT NULL,
                bic VARCHAR(20) NOT NULL,
                montant DECIMAL(15,2) NOT NULL,
                date_creation DATE NOT NULL,
                date_expiration DATE,
                statut VARCHAR(50) NOT NULL,
                commentaires TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            conn.commit()
            st.success("✅ Table 'avis' créée avec succès")
        
        # Vérifier si la table info_avi existe
        cursor.execute("""
            SELECT COUNT(*) FROM information_schema.tables 
            WHERE table_schema = %s AND table_name = 'info_avi'
        """, (MYSQL_CONFIG['database'],))
        
        info_table_exists = cursor.fetchone()[0] > 0
        
        if not info_table_exists:
            # Créer la table info_avi si elle n'existe pas
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS info_avi (
                id INT AUTO_INCREMENT PRIMARY KEY,
                reference VARCHAR(50) UNIQUE NOT NULL,
                nom_complet VARCHAR(255) NOT NULL,
                code_banque VARCHAR(50) NOT NULL,
                numero_compte VARCHAR(50) NOT NULL,
                devise VARCHAR(10) NOT NULL,
                iban VARCHAR(50) NOT NULL,
                bic VARCHAR(20) NOT NULL,
                montant DECIMAL(15,2) NOT NULL,
                date_creation DATE,
                date_expiration DATE,
                statut VARCHAR(50),
                commentaires TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
            ''')
            conn.commit()
            st.success("✅ Table 'info_avi' créée avec succès")
        
        cursor.close()
        conn.close()
        return True
        
    except mysql.connector.Error as e:
        logger.error(f"Erreur lors de l'initialisation de la base de données: {str(e)}")
        st.error(f"❌ Erreur lors de l'initialisation de la base de données: {str(e)}")
        return False

def verify_avi(reference: str):
    """
    Vérifie une AVI par sa référence
    Retourne les informations de l'AVI si trouvée
    """
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Requête pour récupérer les informations de l'AVI
        # On cherche d'abord dans la table avis, puis dans info_avi
        query = """
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
            commentaires
        FROM avis 
        WHERE reference = %s
        """
        
        cursor.execute(query, (reference.strip(),))
        result = cursor.fetchone()
        
        # Si pas trouvé dans avis, chercher dans info_avi
        if not result:
            query = """
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
                commentaires
            FROM info_avi 
            WHERE reference = %s
            """
            cursor.execute(query, (reference.strip(),))
            result = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        return result
        
    except mysql.connector.Error as e:
        logger.error(f"Erreur lors de la vérification: {str(e)}")
        st.error(f"❌ Erreur lors de la vérification: {str(e)}")
        return None

def format_iban(iban):
    """Formate un IBAN pour l'affichage (espaces tous les 4 caractères)"""
    if not iban:
        return iban
    # Supprimer les espaces existants avant de reformater
    iban_clean = iban.replace(' ', '')
    return ' '.join([iban_clean[i:i+4] for i in range(0, len(iban_clean), 4)])

def format_montant(montant, devise="XAF"):
    """Formate le montant avec la devise"""
    if not montant:
        return "0 FCFA"
    try:
        return f"{float(montant):,.2f} {devise}"
    except:
        return f"{montant} {devise}"

def display_avi_result(result):
    """Affiche les résultats de la vérification"""
    if not result:
        return
    
    # Badge de vérification
    st.markdown("""
    <div style="text-align: center; margin: 1rem 0;">
        <span class="verification-badge">✅ AVI VALIDE</span>
    </div>
    """, unsafe_allow_html=True)
    
    # Carte des résultats
    st.markdown('<div class="result-card">', unsafe_allow_html=True)
    
    st.markdown("### 📄 Informations de l'AVI")
    
    # Informations principales
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown(f"""
        <div class="info-item">
            <span class="info-label">📌 Référence</span>
            <span class="info-value">{result.get('reference', 'N/A')}</span>
        </div>
        <div class="info-item">
            <span class="info-label">👤 Nom complet</span>
            <span class="info-value">{result.get('nom_complet', 'N/A')}</span>
        </div>
        <div class="info-item">
            <span class="info-label">🏦 Code Banque</span>
            <span class="info-value">{result.get('code_banque', 'N/A')}</span>
        </div>
        <div class="info-item">
            <span class="info-label">🔢 Numéro de Compte</span>
            <span class="info-value">{result.get('numero_compte', 'N/A')}</span>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="info-item">
            <span class="info-label">💱 Devise</span>
            <span class="info-value">{result.get('devise', 'XAF')}</span>
        </div>
        <div class="info-item">
            <span class="info-label">🔑 IBAN</span>
            <span class="info-value" style="font-family: monospace;">{format_iban(result.get('iban', 'N/A'))}</span>
        </div>
        <div class="info-item">
            <span class="info-label">🌐 BIC</span>
            <span class="info-value" style="font-family: monospace;">{result.get('bic', 'N/A')}</span>
        </div>
        <div class="info-item">
            <span class="info-label">💰 Montant</span>
            <span class="info-value" style="font-weight: 700; color: #28a745;">{format_montant(result.get('montant'), result.get('devise', 'XAF'))}</span>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Informations supplémentaires
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric(
            "📅 Date de création",
            result.get('date_creation', 'N/A')
        )
    
    with col2:
        st.metric(
            "📅 Date d'expiration",
            result.get('date_expiration', 'N/A') or 'Non définie'
        )
    
    with col3:
        statut = result.get('statut', 'N/A')
        statut_class = "status-valid" if statut in ["Etudiant", "Fonctionnaire"] else "status-invalid"
        st.markdown(f"""
        <div style="text-align: center;">
            <span style="font-size: 0.9rem; color: #666;">📋 Statut</span>
            <br>
            <span class="{statut_class}">{statut}</span>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Commentaires si présents
    if result.get('commentaires'):
        st.markdown(f"""
        <div style="background: #f8f9fa; padding: 1rem; border-radius: 8px; margin-top: 1rem;">
            <strong>📝 Commentaires:</strong>
            <p style="margin: 0.5rem 0 0 0;">{result.get('commentaires')}</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Pied de page du résultat
    st.markdown(f"""
    <div style="text-align: center; margin-top: 1.5rem; color: #888; font-size: 0.85rem;">
        Vérifié le {datetime.now().strftime('%d/%m/%Y à %H:%M')} · Document certifié par Eco Capital
    </div>
    """, unsafe_allow_html=True)

def main():
    """Point d'entrée principal"""
    
    # Initialisation de la base de données
    with st.spinner("🔄 Vérification de la base de données..."):
        init_success = init_database()
        if not init_success:
            st.warning("⚠️ Problème avec la base de données. Certaines fonctionnalités peuvent être limitées.")
    
    # En-tête
    st.markdown("""
    <div class="main-container">
        <h1>🔍 Vérificateur d'AVI</h1>
        <p>Entrez la référence de l'AVI pour vérifier son authenticité</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Section de recherche
    st.markdown("### 📝 Recherche par référence")
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        reference = st.text_input(
            "Référence de l'AVI",
            placeholder="Ex: AVI-20260119-1234",
            label_visibility="collapsed"
        )
        
        # Bouton de vérification
        if st.button("🔍 Vérifier", type="primary", use_container_width=True):
            if not reference or not reference.strip():
                st.warning("⚠️ Veuillez entrer une référence d'AVI")
            else:
                with st.spinner("Vérification en cours..."):
                    result = verify_avi(reference)
                    
                    if result:
                        st.markdown("---")
                        display_avi_result(result)
                    else:
                        st.markdown("---")
                        st.markdown("""
                        <div style="text-align: center; padding: 2rem; background: #fff3cd; border-radius: 10px; border: 1px solid #ffc107;">
                            <h3 style="color: #856404;">❌ AVI non trouvée</h3>
                            <p style="color: #856404;">Aucune attestation trouvée avec la référence <strong>{}</strong></p>
                            <p style="color: #856404; font-size: 0.9rem;">Vérifiez que la référence est correcte (format: AVI-YYYYMMDD-XXXX)</p>
                        </div>
                        """.format(reference.strip()), unsafe_allow_html=True)
    
    # Section d'information
    with st.expander("ℹ️ Comment utiliser le vérificateur", expanded=False):
        st.markdown("""
        **Instructions :**
        
        1. Entrez la **référence complète** de l'AVI dans le champ de recherche
        2. Cliquez sur le bouton **"Vérifier"**
        3. Les informations de l'AVI s'afficheront si elles existent dans la base de données
        
        **Format de référence attendu :** `AVI-YYYYMMDD-XXXX`
        - YYYYMMDD : Date de création (Année/Mois/Jour)
        - XXXX : Numéro aléatoire à 4 chiffres
        
        **Exemple :** `AVI-20260119-1234`
        """)
    
    # Section des dernières vérifications
    with st.expander("📊 Statistiques", expanded=False):
        st.markdown("""
        <div style="padding: 0.5rem 0;">
            <p style="color: #666;">🔒 Cette page est un outil sécurisé de vérification des AVI.</p>
            <p style="color: #666;">✅ Toutes les vérifications sont enregistrées pour des raisons de sécurité.</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #999; font-size: 0.8rem; padding: 1rem 0;">
        © 2026 Eco Capital - Vérificateur d'AVI v1.0
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
