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
│       ├── __init__.py
│       ├── cli.py
│       ├── database/
│       │   ├── __init__.py
│       │   └── db_manager.py
│       ├── users/
│       │   ├── __init__.py
│       │   └── users.py
│       ├── password_strength/
│       │   ├── __init__.py
│       │   └── strength_checker.py
│       ├── phishing/
│       │   ├── __init__.py
│       │   └── phishing_detector.py
│       └── rule_based/
│           ├── __init__.py
│           └── rule_engine.py
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

src/safemail/database/

db_manager.py : wrapper pour sqlite3 (connexion, exécution de requêtes, migrations simples).
Responsable : Malek.
But : centraliser accès DB et éviter duplication.

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

src/safemail/rule_based/

rule_engine.py : moteur qui applique des règles configurables (YAML/JSON) et retourne les résultats détaillés.
Responsable : Imene.
But : permettre d’ajouter/supprimer règles sans changer le code.

tests/

Fichiers pytest pour chaque module (test_db.py, test_users.py, etc.).
But : garantir que chaque PR garde la base stable (coverage basique).

work/

Dossiers personnels pour prototypes et brouillons (non intégrés directement en production).
Ex : work/malek/README.md décrit l’état du prototype.
Règle d’or : rien dans work/ n’est considéré comme « prêt » — pour intégrer il faut ouvrir une PR et déplacer le code vers src/safemail/....


Décision finale : “phishing” / “non-phishing”

