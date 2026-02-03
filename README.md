📌 SafeMail – Système de Détection de Phishing & Sécurité des Comptes

Ce projet consiste à développer un programme Python permettant aux utilisateurs de :

Créer un compte (username + mot de passe)

Vérifier la force d’un mot de passe

Analyser un email et détecter s’il s’agit d’un phishing ou non

Lancer un détecteur basé sur un système de règles (rule-based)

Toutes ces actions seront accessibles à travers un menu interactif dans le terminal.

🧭 Menu principal du programme

L’utilisateur pourra choisir :

1️⃣ Créer un utilisateur
2️⃣ Tester la force d’un mot de passe
3️⃣ Entrer un email et analyser son contenu
4️⃣ Exécuter le détecteur (rule-based) pour savoir si c’est du phishing
5️⃣ Quitter

Ce fonctionnement simple facilite les tests et la démonstration du projet.

👥 Répartition des tâches (Travail collaboratif)

Chaque membre de l’équipe est responsable d’un module spécifique dans src/safemail/ :

🔵 Personne A – Malek

Module : Base de données & Gestion des utilisateurs

Création des utilisateurs

Système d’enregistrement (JSON)

Gestion login, stockage sécurisé des mots de passe

Intégration avec le menu principal

🟢 Personne B – Bouchra

Module : Password Strength & Security Utilities

Vérification de force des mots de passe

Règles de sécurité (longueur, complexité, caractères spéciaux…)

Fonctions de hachage & vérification

Retour d’un score + détails des faiblesses

🟣 Personne C – Maroua

Module : Email Parser (Extraction & Analyse)

Extraction du texte, URLs, HTML

Détection de mots suspects (“urgent”, “verify”, “bank”… )

Préparation des features pour le détecteur

Nettoyage et pré-traitement

🟠 Personne D – Imène

Module : Rule-Based Detector (Détection du phishing)

Mise en place de règles simples (URLs, mots suspicieux, IP-links…)

Score de suspicion



Organisation github:

Advanced-Programming-project/
├── README.md
├── requirements.txt
├── .gitignore
├── scripts/
│   └── init_db.py
├── src/
│   └── safemail/
│  
│       ── users.py
│        ── attachment_scanner.py
│        ── attachment_worker.py
         ── app.py                    # Application FastAPI principale
         ── db.py                     # Connexion base de données
         ── users.py                  # Gestion des utilisateurs
         ── imap_fetcher.py          # Récupération emails IMAP
         ── phishing.py              # Analyse anti-phishing    
         ── scheduler.py             # Tâches planifiées
├── static/                  # Fichiers frontend
│   ├── login.html
│   ├── dashboard.html
│   ├── inbox.html
│   └── quarantine.html
├── tests/
│   ├── test_db.py
│   ├── test_users.py
│   ├── test_password_strength.py
│   ├── test_phishing.py
│   └── test_rule_engine.py
└── work/
    ├── malek/      # prototypes Malek (DB)
    ├── bouchra/    # prototypes Bouchra (mot de passe)
    ├── maroua/     # prototypes Maroua (phishing)
    └── imene/      # prototypes Imene (rules)


Explication detaille:

requirements.txt

Liste des dépendances pip (pytest, pyyaml, etc.).
But : reproductibilité de l’environnement.

.gitignore

Fichiers/dossiers à ignorer (.venv/, *.db, __pycache__/, etc.).

scripts/init_db.py

Script d’initialisation de la base SQLite (création des tables users, actions, etc.).
But : créer rapidement une base de test locale.

src/safemail/

Racine du code produit (code « prêt »). Chaque sous-dossier correspond à un module fonctionnel.

__init__.py : rend le package importable.

cli.py : interface en ligne de commande (menu principal qui appelle les modules).
But : point d’entrée utilisateur (ex : python -m src.safemail.cli).


src/safemail/users/

users.py : fonctions create_user, get_user_by_username, list_users, hashing.
Responsable : Malek (intégration avec vérif mot de passe de Bouchra).

src/safemail/password_strength/

strength_checker.py : evaluate_password_strength(password) → {score,label,reasons}.
Responsable : Bouchra.
But : donner score et suggestions d’amélioration.

src/safemail/phishing/

phishing_detector.py : heuristiques pour détecter phishing (mots clefs, URL mismatches, pièces jointes).
Responsable : Maroua.

src/safemail/attachment_scanner/
src/safemail/attachment_worker/

rule_engine.py : moteur qui applique des règles configurables (YAML/JSON) et retourne les résultats détaillés.
Responsable : Imene.
But : permettre d’ajouter/supprimer règles sans changer le code.

tests/

Fichiers pytest pour chaque module (test_db.py, test_users.py, etc.).
But : garantir que chaque PR garde la base stable (coverage basique).

work/



📧 SafeMail - Détecteur de Phishing Intelligent
📋 Description du Projet
SafeMail est une application web intelligente de détection de phishing par email qui permet aux utilisateurs de connecter leur boîte Gmail, d'analyser automatiquement leurs emails, et d'identifier les tentatives de phishing grâce à une analyse multi-couches.

🎯 Fonctionnalités Principales
🔐 Gestion des Utilisateurs
Inscription sécurisée avec hachage des mots de passe

Connexion personnalisée avec tableau de bord individuel

Gestion de compte IMAP par utilisateur

📩 Intégration Gmail IMAP
Connexion sécurisée aux comptes Gmail via IMAP

Récupération automatique des emails (toutes les 5 heures)

Support du mot de passe d'application Google pour une sécurité maximale

🔍 Analyse Anti-Phishing Avancée
Détection d'URLs malveillantes via VirusTotal API

Analyse des pièces jointes avec scanning antivirus

Détection de mots suspects dans le contenu des emails

Classification intelligente basée sur plusieurs indicateurs

Mise en quarantaine automatique des emails suspects

📊 Interface Utilisateur
Tableau de bord avec statistiques

Boîte de réception organisée

Section quarantaine pour emails suspects

Détails d'analyse complets pour chaque email

🚀 Comment Commencer
Étape 1 : Création de Compte Utilisateur
Accédez à la page d'inscription

Entrez votre nom d'utilisateur, email et mot de passe

Votre compte est automatiquement créé avec un profil IMAP vide

Étape 2 : Configuration du Compte Gmail IMAP
⚠️ Problème IMAP résolu : Plus besoin d'activer manuellement IMAP dans Gmail

🔐 Configuration de la Double Authentification Google
Accédez à : myaccount.google.com

Connectez-vous avec votre compte Gmail

Allez dans : Sécurité → Validation en 2 étapes

Activez la double authentification en suivant les étapes :

Entrez votre mot de passe

Ajoutez votre numéro de téléphone

Validez avec le code SMS

🔑 Génération du Mot de Passe d'Application
Retournez à : Sécurité → Mots de passe des applications

Sélectionnez :

App : Mail

Device : Windows Computer

Cliquez sur : "Générer"

Copiez immédiatement le mot de passe affiché (ex: abcd efgh ijkl mnop)

⚙️ Configuration dans SafeMail
Dans votre tableau de bord SafeMail, ajoutez votre compte IMAP

Utilisez :

Email : votre adresse Gmail complète

Mot de passe : le mot de passe d'application généré (pas votre mot de passe Gmail normal)

Étape 3 : Utilisation de l'Application
📥 Boîte de Réception (Inbox)
Bouton "Fetch Gmail" : Récupère les nouveaux emails

Liste des emails : Affiche tous vos emails avec statut

Indicateurs visuels :

✅ Safe : Email normal

🛑 Quarantined : Email suspect mis en quarantaine

🔍 Analyse d'Email
Cliquez sur "Details" à côté d'un email

L'application analyse automatiquement :

URLs : Vérification via VirusTotal

Pièces jointes : Scanning antivirus

Mots-clés suspects : Détection de langage de phishing

Rapport d'analyse affiché avec :

Statut de suspicion

Raisons de la classification

Liste des URLs détectées

Analyse des pièces jointes

🛑 Section Quarantaine
Accès rapide depuis le tableau de bord

Liste des emails bloqués avec raisons

Possibilité de consulter les emails mis en quarantaine

🔧 Architecture Technique
🗄️ Base de Données (SQL Server)
Utilisateurs : Informations de connexion

Comptes IMAP : Configuration par utilisateur

Emails : Stockage des emails récupérés

Quarantaine : Emails suspects bloqués

Pièces jointes : Fichiers attachés analysés

🔗 API Integration
VirusTotal API : Analyse d'URLs et fichiers

IMAP Gmail : Récupération des emails

FastAPI : Backend RESTful

🛡️ Sécurité
Hachage SHA256 des mots de passe

Tokens d'application Google pour IMAP

Validation des entrées utilisateur

Isolation des données par utilisateur













