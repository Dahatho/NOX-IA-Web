NOX-IA WEB — PHASE 1
====================

OBJECTIF
--------
Lancer NOX-IA directement dans Chrome/Edge/Firefox avec une URL,
sans télécharger NOX-IA.exe.

Cette phase Web est volontairement séparée de la version desktop :
elle ne remplace pas et ne modifie pas ton NOX-IA Windows actuel.

INCLUS
------
- connexion sécurisée
- rôles Administrateur / Responsable / Technicien / Lecture seule
- Dashboard
- Clients
- Sites
- Équipements
- Interventions
- PostgreSQL prêt pour le cloud
- SQLite possible en développement local
- protection CSRF
- session signée
- endpoint /healthz
- render.yaml pour Render

LANCEMENT LOCAL
---------------
Dans PowerShell, depuis le dossier où se trouvent ces fichiers :

    python -m pip install -r requirements-web.txt

Puis définir le mot de passe admin :

    $env:NOXIA_ADMIN_PASSWORD="TON_MOT_DE_PASSE"

Puis :

    python -m uvicorn web_app:app --reload

Ouvre ensuite :

    http://127.0.0.1:8000

Identifiant :
    admin

Le mot de passe est celui placé dans NOXIA_ADMIN_PASSWORD.

MISE EN LIGNE RENDER
--------------------
1. Mets ces fichiers dans un dépôt GitHub.
2. Sur Render, crée un Blueprint / Web Service depuis ce dépôt.
3. Render lit render.yaml.
4. Quand Render demande NOXIA_ADMIN_PASSWORD, choisis ton mot de passe admin.
5. Une fois le déploiement terminé, Render fournit une URL publique.

IMPORTANT
---------
N'utilise pas noxia.db comme base de production sur un hébergement
dont le disque est éphémère.

Cette phase utilise PostgreSQL en ligne pour que les données persistent.

FUTURES PHASES
--------------
Phase 2 :
- modification/clôture/réouverture interventions
- actions/solution
- matériel & stock
- photos
- rapports PDF

Phase 3 :
- diagnostics NOX-Core
- mémoire technique
- maintenance préventive
- contrats
- alertes
- actions de suivi

Phase 4 :
- migration contrôlée des données desktop vers le cloud
- synchronisation / comptes entreprise
- mobile responsive renforcé
