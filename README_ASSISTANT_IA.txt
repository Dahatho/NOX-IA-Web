NOX-IA — ASSISTANT IA COMPLET
================================

Ajout en une seule mise à jour :
- onglet Assistant IA
- zone de question technicien
- recherche automatique dans NOX-Core
- réponse structurée : vérifications / causes / étapes / vigilance / sources
- contexte automatique : client / site / équipement / intervention / diagnostics
- bouton pour ajouter la réponse dans Actions réalisées
- historique persistant par intervention
- assistant général sans intervention
- garde-fou incendie / SSI
- historique assistant inclus dans l'export JSON

MISE À JOUR GITHUB
------------------
Dans NOX-IA-Web, remplace :
1. web_app.py
2. web_models.py

Puis Commit changes.
Render redéploiera automatiquement.

La table web_assistant_exchanges est créée automatiquement au démarrage.
Aucune table existante n'est supprimée.
