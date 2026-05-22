import streamlit as st
import pandas as pd
from datetime import datetime
import base64
from PIL import Image
import io
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

# Configuration de la page
st.set_page_config(
    page_title="Demande d'AVI - Eco Capital",
    page_icon="🏦",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Styles CSS personnalisés
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #383a5f, #0d1152);
        padding: 1rem;
        border-radius: 10px;
        margin-bottom: 2rem;
    }
    
    .step-container {
        display: flex;
        justify-content: space-between;
        margin-bottom: 2rem;
        padding: 1rem;
        background: #f8f9fa;
        border-radius: 10px;
    }
    
    .step-item {
        text-align: center;
        flex: 1;
    }
    
    .step-number {
        width: 40px;
        height: 40px;
        border-radius: 50%;
        background-color: #e0e0e0;
        color: #718096;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        font-weight: 600;
        margin-bottom: 0.5rem;
    }
    
    .step-active .step-number {
        background-color: #0d1152;
        color: white;
    }
    
    .step-completed .step-number {
        background-color: #28a745;
        color: white;
    }
    
    .step-label {
        font-size: 0.875rem;
        color: #718096;
    }
    
    .step-active .step-label {
        color: #0d1152;
        font-weight: 600;
    }
    
    .form-container {
        background: white;
        padding: 2rem;
        border-radius: 10px;
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
    }
    
    .stButton > button {
        background: linear-gradient(135deg, #0d1152, #3a3f8a);
        color: white;
        border-radius: 10px;
        padding: 0.75rem 1.5rem;
        font-weight: 600;
        border: none;
        transition: all 0.3s;
    }
    
    .stButton > button:hover {
        background: linear-gradient(135deg, #3a3f8a, #0d1152);
        transform: translateY(-2px);
    }
    
    .success-message {
        background: #d4edda;
        border: 1px solid #c3e6cb;
        border-radius: 10px;
        padding: 2rem;
        text-align: center;
    }
    
    .footer {
        background: linear-gradient(135deg, #0d1152, #0a335c);
        color: white;
        padding: 2rem;
        border-radius: 10px;
        margin-top: 3rem;
    }
</style>
""", unsafe_allow_html=True)

# Initialisation des variables de session
if 'step' not in st.session_state:
    st.session_state.step = 1
if 'form_data' not in st.session_state:
    st.session_state.form_data = {}
if 'submitted' not in st.session_state:
    st.session_state.submitted = False

# Fonction pour afficher le logo
def display_logo():
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<h1 style='text-align: center; color: #0d1152;'>🏦 Eco Capital</h1>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center; color: #718096;'>Demande d'Attestation de Vérification d'Identité (AVI)</p>", unsafe_allow_html=True)

# Fonction pour afficher les étapes
def display_steps(current_step):
    st.markdown("<div class='step-container'>", unsafe_allow_html=True)
    
    steps = [
        {"number": 1, "label": "Informations personnelles"},
        {"number": 2, "label": "Pièces justificatives"},
        {"number": 3, "label": "Validation"}
    ]
    
    for step in steps:
        if step["number"] < current_step:
            status_class = "step-completed"
        elif step["number"] == current_step:
            status_class = "step-active"
        else:
            status_class = ""
        
        st.markdown(f"""
        <div class='step-item {status_class}'>
            <div class='step-number'>{step["number"]}</div>
            <div class='step-label'>{step["label"]}</div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("</div>", unsafe_allow_html=True)

# Fonction pour valider l'étape 1
def validate_step1():
    required_fields = ['lastName', 'firstName', 'birthDate', 'birthPlace', 
                      'nationality', 'address', 'postalCode', 'city', 'country']
    
    for field in required_fields:
        if field not in st.session_state.form_data or not st.session_state.form_data[field]:
            st.error(f"Veuillez remplir tous les champs obligatoires.")
            return False
    
    return True

# Fonction pour valider l'étape 2
def validate_step2():
    if 'identityDoc' not in st.session_state.form_data or not st.session_state.form_data['identityDoc']:
        st.error("Veuillez téléverser votre pièce d'identité.")
        return False
    
    if 'consentCheck' not in st.session_state.form_data or not st.session_state.form_data['consentCheck']:
        st.error("Veuillez accepter la déclaration de certification.")
        return False
    
    return True

# Fonction pour envoyer l'email
def send_email(form_data):
    try:
        # Configuration email (à adapter avec vos paramètres)
        sender_email = "votre_email@ecocapitale.com"
        receiver_email = "contacts@ecocapitale.com"
        password = "votre_mot_de_passe"
        
        # Création du message
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = f"Nouvelle demande d'AVI - {form_data['firstName']} {form_data['lastName']}"
        
        body = f"""
        Nouvelle demande d'AVI reçue le {datetime.now().strftime('%d/%m/%Y à %H:%M')}
        
        INFORMATIONS PERSONNELLES
        -------------------------
        Nom : {form_data['lastName']}
        Prénom : {form_data['firstName']}
        Date de naissance : {form_data['birthDate']}
        Lieu de naissance : {form_data['birthPlace']}
        Nationalité : {form_data['nationality']}
        
        ADRESSE
        -------
        {form_data['address']} {form_data.get('addressComplement', '')}
        {form_data['postalCode']} {form_data['city']}
        {form_data['country']}
        
        MONTANT AVI
        -----------
        {form_data.get('aviAmount', 'Non spécifié')}
        
        DOCUMENTS FOURNIS
        -----------------
        Pièce d'identité : Téléversée
        Attestation d'inscription : {'Téléversée' if form_data.get('otherDocs') else 'Non fournie'}
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Envoi de l'email (à décommenter et configurer pour l'environnement de production)
        # server = smtplib.SMTP('smtp.gmail.com', 587)
        # server.starttls()
        # server.login(sender_email, password)
        # server.send_message(msg)
        # server.quit()
        
        return True
    except Exception as e:
        st.error(f"Erreur lors de l'envoi de l'email : {str(e)}")
        return False

# Interface principale
def main():
    # Affichage du logo et des étapes
    display_logo()
    display_steps(st.session_state.step)
    
    st.markdown("<div class='form-container'>", unsafe_allow_html=True)
    
    # Étape 1 : Informations personnelles
    if st.session_state.step == 1:
        st.markdown("### 📋 Informations personnelles")
        
        col1, col2 = st.columns(2)
        with col1:
            lastName = st.text_input("Nom de famille *", 
                                    value=st.session_state.form_data.get('lastName', ''),
                                    key="lastName_input")
            birthDate = st.date_input("Date de naissance *", 
                                     value=datetime.strptime(st.session_state.form_data.get('birthDate', '2000-01-01'), '%Y-%m-%d').date() if st.session_state.form_data.get('birthDate') else None,
                                     key="birthDate_input")
            nationality = st.text_input("Nationalité *", 
                                       value=st.session_state.form_data.get('nationality', ''),
                                       key="nationality_input")
        
        with col2:
            firstName = st.text_input("Prénom(s) *", 
                                     value=st.session_state.form_data.get('firstName', ''),
                                     key="firstName_input")
            birthPlace = st.text_input("Lieu de naissance *", 
                                      value=st.session_state.form_data.get('birthPlace', ''),
                                      key="birthPlace_input")
        
        st.markdown("### 🏠 Adresse")
        
        col1, col2 = st.columns(2)
        with col1:
            address = st.text_input("Adresse *", 
                                   value=st.session_state.form_data.get('address', ''),
                                   key="address_input")
            postalCode = st.text_input("Code postal *", 
                                      value=st.session_state.form_data.get('postalCode', ''),
                                      key="postalCode_input")
        
        with col2:
            addressComplement = st.text_input("Complément d'adresse", 
                                             value=st.session_state.form_data.get('addressComplement', ''),
                                             key="addressComplement_input")
            city = st.text_input("Ville *", 
                               value=st.session_state.form_data.get('city', ''),
                               key="city_input")
        
        country = st.selectbox("Pays *", 
                              ["", "Congo Brazzaville", "Chine", "Maroc", "Gabon", "Turquie", "Autre pays"],
                              index=0 if 'country' not in st.session_state.form_data else ["", "Congo Brazzaville", "Chine", "Maroc", "Gabon", "Turquie", "Autre pays"].index(st.session_state.form_data.get('country', '')),
                              key="country_input")
        
        if st.button("Suivant ➡️", key="next_step1"):
            # Sauvegarde des données
            st.session_state.form_data.update({
                'lastName': lastName,
                'firstName': firstName,
                'birthDate': str(birthDate) if birthDate else '',
                'birthPlace': birthPlace,
                'nationality': nationality,
                'address': address,
                'addressComplement': addressComplement,
                'postalCode': postalCode,
                'city': city,
                'country': country
            })
            
            if validate_step1():
                st.session_state.step = 2
                st.rerun()
    
    # Étape 2 : Pièces justificatives
    elif st.session_state.step == 2:
        st.markdown("### 📎 Pièces justificatives")
        
        st.info("📌 Téléversez des copies claires et lisibles de vos documents. Formats acceptés : JPG, PNG, PDF (max. 5MB chacun).")
        
        # Upload pièce d'identité
        identityDoc = st.file_uploader(
            "Pièce d'identité (recto et verso) *",
            type=['jpg', 'jpeg', 'png', 'pdf'],
            accept_multiple_files=True,
            key="identityDoc_uploader"
        )
        
        if identityDoc:
            st.success(f"✅ {len(identityDoc)} fichier(s) téléversé(s) pour la pièce d'identité")
            # Affichage preview pour les images
            for file in identityDoc:
                if file.type.startswith('image'):
                    st.image(file, caption=file.name, width=200)
        
        # Montant AVI
        aviAmount = st.text_input("Montant AVI *", 
                                 value=st.session_state.form_data.get('aviAmount', ''),
                                 key="aviAmount_input",
                                 placeholder="Ex: 500000 XAF")
        
        # Upload autres documents
        otherDocs = st.file_uploader(
            "Attestation d'Inscription",
            type=['jpg', 'jpeg', 'png', 'pdf'],
            accept_multiple_files=True,
            key="otherDocs_uploader"
        )
        
        if otherDocs:
            st.success(f"✅ {len(otherDocs)} document(s) complémentaire(s) téléversé(s)")
        
        # Checkbox consentement
        consentCheck = st.checkbox(
            "Je certifie que les informations fournies sont exactes et que les documents téléversés sont authentiques et à jour. *",
            key="consentCheck_checkbox"
        )
        
        col1, col2, col3 = st.columns([1, 1, 1])
        with col1:
            if st.button("⬅️ Précédent", key="prev_step2"):
                st.session_state.step = 1
                st.rerun()
        
        with col3:
            if st.button("Suivant ➡️", key="next_step2"):
                # Sauvegarde des données
                st.session_state.form_data.update({
                    'identityDoc': identityDoc,
                    'aviAmount': aviAmount,
                    'otherDocs': otherDocs,
                    'consentCheck': consentCheck
                })
                
                if validate_step2():
                    st.session_state.step = 3
                    st.rerun()
    
    # Étape 3 : Validation
    elif st.session_state.step == 3:
        st.markdown("### ✅ Validation de votre demande")
        
        st.success("Votre formulaire est complet. Veuillez vérifier les informations ci-dessous avant soumission.")
        
        # Affichage récapitulatif
        with st.expander("📋 Informations personnelles", expanded=True):
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"**Nom :** {st.session_state.form_data.get('lastName', '')}")
                st.write(f"**Date de naissance :** {st.session_state.form_data.get('birthDate', '')}")
                st.write(f"**Nationalité :** {st.session_state.form_data.get('nationality', '')}")
            with col2:
                st.write(f"**Prénom :** {st.session_state.form_data.get('firstName', '')}")
                st.write(f"**Lieu de naissance :** {st.session_state.form_data.get('birthPlace', '')}")
        
        with st.expander("🏠 Adresse", expanded=True):
            st.write(f"**Adresse :** {st.session_state.form_data.get('address', '')} {st.session_state.form_data.get('addressComplement', '')}")
            st.write(f"**Code postal :** {st.session_state.form_data.get('postalCode', '')} **Ville :** {st.session_state.form_data.get('city', '')}")
            st.write(f"**Pays :** {st.session_state.form_data.get('country', '')}")
        
        with st.expander("💰 Montant AVI", expanded=True):
            st.write(f"**Montant :** {st.session_state.form_data.get('aviAmount', 'Non spécifié')}")
        
        with st.expander("📎 Documents fournis", expanded=True):
            if st.session_state.form_data.get('identityDoc'):
                st.write(f"**Pièce d'identité :** {len(st.session_state.form_data['identityDoc'])} fichier(s)")
            if st.session_state.form_data.get('otherDocs'):
                st.write(f"**Attestation d'inscription :** {len(st.session_state.form_data['otherDocs'])} fichier(s)")
        
        # Conditions générales
        with st.expander("📜 Conditions générales", expanded=False):
            st.markdown("""
            **1. Traitement des données personnelles**
            Les informations recueillies font l'objet d'un traitement informatique destiné à la vérification d'identité.
            
            **2. Délai de traitement**
            Votre demande sera traitée dans un délai maximum de 48 heures ouvrables.
            
            **3. Conservation des données**
            Vos données seront conservées pendant une durée de 5 ans.
            
            **4. Droits d'accès et de rectification**
            Vous bénéficiez d'un droit d'accès et de rectification aux informations qui vous concernent.
            """)
        
        finalConsent = st.checkbox(
            "Je confirme que toutes les informations sont correctes et j'accepte les conditions générales. *",
            key="finalConsent_checkbox"
        )
        
        col1, col2, col3 = st.columns([1, 1, 1])
        with col1:
            if st.button("⬅️ Précédent", key="prev_step3"):
                st.session_state.step = 2
                st.rerun()
        
        with col3:
            if st.button("📤 Soumettre la demande", key="submit_form"):
                if not finalConsent:
                    st.error("Veuillez accepter les conditions générales avant de soumettre.")
                else:
                    with st.spinner("Envoi de votre demande en cours..."):
                        # Simulation d'envoi (à remplacer par l'envoi réel)
                        success = send_email(st.session_state.form_data)
                        
                        if success:
                            st.session_state.submitted = True
                            st.balloons()
                            st.success("✅ Votre demande d'AVI a été envoyée avec succès !")
                            st.info("📧 Vous recevrez une confirmation par email sous 48 heures.")
                            
                            # Bouton pour nouvelle demande
                            if st.button("🔄 Faire une nouvelle demande"):
                                st.session_state.step = 1
                                st.session_state.form_data = {}
                                st.session_state.submitted = False
                                st.rerun()
                        else:
                            st.error("Une erreur est survenue. Veuillez réessayer.")
    
    st.markdown("</div>", unsafe_allow_html=True)
    
    # Footer
    st.markdown("---")
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("""
        <div style='text-align: center; padding: 2rem;'>
            <p style='color: #718096;'>
                © 2024 Eco Capital. Tous droits réservés.<br>
                <a href='#' style='color: #0d1152; text-decoration: none;'>Conditions d'utilisation</a> | 
                <a href='#' style='color: #0d1152; text-decoration: none;'>Politique de confidentialité</a>
            </p>
        </div>
        """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()