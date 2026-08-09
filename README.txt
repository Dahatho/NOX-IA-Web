NOX-IA 4.1.0 — Atlas symptômes + IA terrain

Nouveautés :
- 1189 symptômes documentés dans un atlas transversal, dont de nombreux cas rares.
- NOX-Core affiche les symptômes associés au type d'équipement.
- Page /nox-core/symptomes pour chercher par domaine et rareté.
- L'assistant utilise l'atlas pour rechercher plus intelligemment sans considérer les cas rares comme probables sans preuve.
- Mémoire : observations du technicien séparées des pistes IA ; cas résolus et diagnostics clôturés ont une priorité supérieure.
- Recherche NOX-Core enrichie par les synonymes de symptômes.

À remplacer sur GitHub : web_app.py + nox_core_catalog.json.
web_models.py est identique à la 4.0/3.9 et n'a pas besoin d'être remplacé si déjà installé.
