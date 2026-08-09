NOX-IA — BASE TECHNIQUE MAX 2026
================================

CATALOGUE
---------
Fiches NOX-Core d'origine : 1173
Nouvelles fiches techniques génériques : 229
Total après déduplication : 1402

COUVERTURE AJOUTÉE
------------------
- Vidéosurveillance: 33 fiches
- Contrôle d'accès: 28 fiches
- Réseau IP: 24 fiches
- Intrusion: 21 fiches
- GTB / Automatisme: 18 fiches
- Serveur / VMS: 18 fiches
- Incendie / SSI: 15 fiches
- Électricité / Alimentation: 14 fiches
- Cybersécurité: 13 fiches
- Outils de diagnostic: 12 fiches
- Câblage / Transmission: 10 fiches
- Interphonie: 9 fiches
- Générique: 8 fiches
- Calcul technique: 5 fiches
- Réseau / Alimentation: 1 fiches

La base couvre notamment :
- réseau IPv4, DHCP, DNS, NTP, VLAN, multicast, PoE, TLS
- vidéosurveillance, ONVIF, RTSP, codecs, image, VMS, NVR, stockage
- contrôle d'accès, OSDP, Wiegand, RS-485, lecteurs, portes, serrures
- intrusion, boucles, détecteurs, sirènes, batteries, transmetteurs
- incendie/SSI avec diagnostic non intrusif et règles de sécurité
- alimentation 12/24 V, batteries, UPS, relais, chute de tension
- cuivre, fibre, SFP, RS-485
- serveurs Windows/Linux, VMS, bases de données, RAID, certificats
- interphonie SIP/RTP
- GTB : Modbus, BACnet, KNX
- cybersécurité défensive
- commandes et outils de diagnostic terrain
- arbres de diagnostic universels

AMÉLIORATION RECHERCHE
----------------------
web_app.py ajoute aussi une expansion de vocabulaire :
caméra -> vidéo / ONVIF / RTSP / PoE
badge -> lecteur / OSDP / Wiegand
SSI -> incendie / ECS / CMSI
etc.

L'Assistant IA sélectionne maintenant jusqu'à 10 sources NOX-Core pertinentes.

INSTALLATION
------------
Dans le dépôt GitHub NOX-IA-Web, remplace :
1. web_app.py
2. nox_core_catalog.json

Conserve web_models.py et requirements-web.txt de la version IA intelligente déjà installée.

Puis Commit changes. Render redéploiera automatiquement.

LIMITES
-------
Cette base augmente fortement la couverture mais ne remplace pas la documentation
propriétaire d'un modèle précis. Les procédures constructeur, tensions, broches,
codes erreur, menus et firmwares spécifiques doivent rester confirmés par une
source fabricant avant une action intrusive.

Pour l'incendie/SSI, NOX-IA doit rester sur les constats et tests autorisés,
sans neutralisation ni shunt.
