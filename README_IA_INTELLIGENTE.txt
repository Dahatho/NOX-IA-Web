NOX-IA — IA TECHNIQUE INTELLIGENTE
======================================

Cette mise à jour améliore l'Assistant IA sans retirer les fonctions existantes.

CE QUI CHANGE
-------------
- Recherche NOX-Core plus précise avec un classement de pertinence de type BM25.
- Prise en compte de la marque, du modèle, du type d'équipement et du contexte de l'intervention.
- Mémoire conversationnelle : NOX-IA tient compte des derniers échanges et évite de répéter les mêmes vérifications.
- Mémoire terrain : NOX-IA recherche les anciennes interventions terminées qui ressemblent au problème actuel et exploite leurs solutions.
- Réponses structurées :
  DIAGNOSTIC PROBABLE
  QUESTION À CONFIRMER
  VÉRIFICATIONS IMMÉDIATES
  HYPOTHÈSES CLASSÉES
  PROCÉDURE RECOMMANDÉE
  CRITÈRE DE RÉSOLUTION
  POINTS DE VIGILANCE
  NIVEAU DE CONFIANCE
- Citations internes [S1], [S2] pour NOX-Core et [C1], [C2] pour les anciens cas terrain.
- Si la documentation ne confirme pas un détail, l'assistant doit l'indiquer au lieu de l'inventer.
- Garde-fous spécifiques incendie/SSI et cybersécurité.
- Mode local amélioré disponible même si l'API externe n'est pas configurée.
- Mode avancé optionnel via l'API OpenAI.

FICHIERS À REMPLACER SUR GITHUB
--------------------------------
1. web_app.py
2. web_models.py
3. requirements-web.txt

Puis Commit changes. Render redéploiera automatiquement.

ACTIVER LE MODE IA AVANCÉ SUR RENDER
------------------------------------
Dans Render > ton service NOX-IA > Environment, ajouter :

OPENAI_API_KEY = ta clé API OpenAI

Optionnel :
OPENAI_MODEL = gpt-5.6-terra
OPENAI_REASONING_EFFORT = medium

Le modèle par défaut du pack est gpt-5.6-terra.
Si OPENAI_API_KEY n'est pas définie, NOX-IA continue automatiquement avec
le moteur local NOX-Core + mémoire terrain.

CONFIDENTIALITÉ
---------------
Le mode avancé utilise store=False.
Par défaut, NOX-IA n'envoie pas l'adresse IP ni le numéro de série de l'équipement.
Pour les envoyer explicitement :
NOXIA_AI_SEND_TECH_IDENTIFIERS = true

Ne mets jamais la clé API directement dans GitHub ou dans web_app.py.
Utilise uniquement une variable d'environnement Render.
