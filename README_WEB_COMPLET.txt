NOX-IA WEB COMPLET
===================

Ce pack remplace la petite interface Web initiale par une version NOX-IA beaucoup plus complète.
L'interface n'affiche plus "Phase 1", "Phase 2" ni "Web Beta" : elle s'appelle simplement NOX-IA.

FONCTIONS INCLUSES
------------------
- Connexion + rôles
- Dashboard
- Clients
- Sites
- Équipements + mémoire technique
- Interventions : création, modification, clôture, réouverture
- Matériel consommé + décrément automatique du stock
- Installation d'équipements depuis le stock + création automatique sur le site
- Photos d'intervention stockées en base
- PDF client
- PDF technique
- Planning multi-créneaux
- Stock
- Fournisseurs + prix
- Maintenance préventive + génération intervention/planning
- Contrats + renouvellement
- Alertes globales
- Actions de suivi
- NOX-Core intégré
- Diagnostics persistants
- Utilisateurs / rôles
- Santé / audit cloud
- Export JSON de sauvegarde

MISE A JOUR GITHUB
------------------
Dans le dépôt NOX-IA-Web, remplace à la racine :
- web_app.py
- web_models.py
- web_security.py
- requirements-web.txt
- render.yaml
- nox_core_catalog.json

Les anciens dossiers templates/ et static/ ne sont plus utilisés par cette version.
Tu peux les laisser dans GitHub : ils ne gêneront pas.

Render étant en Auto-Deploy, un Commit GitHub déclenche automatiquement la mise à jour du site.

IMPORTANT
---------
Les tables Phase-1 existantes gardent exactement les mêmes noms : les données déjà présentes restent utilisables.
Les nouvelles fonctions créent seulement de nouvelles tables au démarrage.
Aucune suppression automatique de données existantes n'est effectuée.

Photos : 5 Mo maximum par image.
