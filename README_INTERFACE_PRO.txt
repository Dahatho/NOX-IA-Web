NOX-IA 3.2.0 — INTERFACE PRO
============================

FICHIER À REMPLACER SUR GITHUB
------------------------------
Remplace uniquement :
- web_app.py

Ne remplace pas web_models.py, web_security.py ni la base de données pour cette mise à jour.

CORRECTIONS / AMÉLIORATIONS
---------------------------
- Suppression de la grande barre de navigation horizontale et de son défilement.
- Nouvelle barre latérale professionnelle, organisée par groupes :
  Vue générale / Opérations / Gestion / Suivi / Intelligence / Administration.
- L'onglet de la page actuelle reste visuellement sélectionné.
- NOX-Core ne provoque plus le retour visuel du menu au début à chaque chargement.
- Menu mobile avec bouton d'ouverture et fermeture.
- Interface responsive ordinateur / tablette / mobile.
- Cartes, tableaux, formulaires, boutons, champs et états modernisés.
- Meilleurs espacements, contrastes, focus et effets de survol.
- Suppression du débordement horizontal global de la page.
- Page NOX-Core améliorée : recherche plus claire, nombre de résultats, bouton Effacer, meilleur affichage des fiches.
- Toutes les routes et fonctions métier existantes sont conservées.
- Aucune suppression ni migration de données.

INSTALLATION
------------
1. Décompresse NOX_IA_3.2_INTERFACE_PRO.zip.
2. Sur GitHub, ouvre web_app.py.
3. Clique sur le crayon Modifier.
4. Remplace tout le contenu par le nouveau web_app.py.
5. Clique sur « Valider les modifications » / « Commit changes ».
6. Render redéploie ensuite automatiquement si Auto-Deploy est activé.
7. Quand Render affiche Live, recharge le site avec Ctrl + F5.

VERSION
-------
APP_VERSION = 3.2.0
