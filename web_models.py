import os
from datetime import datetime, date
from sqlalchemy import Boolean, Date, DateTime, Float, ForeignKey, Integer, LargeBinary, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///./noxia_web.db')
kwargs = {'pool_pre_ping': True}
if DATABASE_URL.startswith('sqlite'):
    kwargs['connect_args'] = {'check_same_thread': False}
engine = create_engine(DATABASE_URL, **kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

class Base(DeclarativeBase): pass

# Phase-1 tables preserved exactly.
class User(Base):
    __tablename__='web_users'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    username: Mapped[str]=mapped_column(String(100), unique=True, index=True)
    password_hash: Mapped[str]=mapped_column(String(300))
    role: Mapped[str]=mapped_column(String(50), default='Lecture seule')
    active: Mapped[bool]=mapped_column(Boolean, default=True)
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)

class Client(Base):
    __tablename__='web_clients'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    nom: Mapped[str]=mapped_column(String(200), index=True)
    contact: Mapped[str]=mapped_column(String(200), default='')
    telephone: Mapped[str]=mapped_column(String(80), default='')
    email: Mapped[str]=mapped_column(String(200), default='')
    notes: Mapped[str]=mapped_column(Text, default='')
    actif: Mapped[bool]=mapped_column(Boolean, default=True)

class Site(Base):
    __tablename__='web_sites'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    client_id: Mapped[int]=mapped_column(ForeignKey('web_clients.id'), index=True)
    nom: Mapped[str]=mapped_column(String(200))
    adresse: Mapped[str]=mapped_column(String(300), default='')
    ville: Mapped[str]=mapped_column(String(150), default='')
    notes: Mapped[str]=mapped_column(Text, default='')
    actif: Mapped[bool]=mapped_column(Boolean, default=True)

class Equipement(Base):
    __tablename__='web_equipements'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    site_id: Mapped[int]=mapped_column(ForeignKey('web_sites.id'), index=True)
    reference: Mapped[str]=mapped_column(String(100), unique=True, index=True)
    type_equipement: Mapped[str]=mapped_column(String(150))
    marque: Mapped[str]=mapped_column(String(150), default='')
    modele: Mapped[str]=mapped_column(String(150), default='')
    numero_serie: Mapped[str]=mapped_column(String(150), default='')
    ip: Mapped[str]=mapped_column(String(100), default='')
    statut: Mapped[str]=mapped_column(String(80), default='Actif')
    actif: Mapped[bool]=mapped_column(Boolean, default=True)

class Intervention(Base):
    __tablename__='web_interventions'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    site_id: Mapped[int]=mapped_column(ForeignKey('web_sites.id'), index=True)
    equipement_id: Mapped[int|None]=mapped_column(ForeignKey('web_equipements.id'), nullable=True, index=True)
    date_creation: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)
    technicien: Mapped[str]=mapped_column(String(150))
    type_intervention: Mapped[str]=mapped_column(String(100), default='Dépannage')
    priorite: Mapped[str]=mapped_column(String(50), default='Normale')
    probleme: Mapped[str]=mapped_column(Text)
    actions_realisees: Mapped[str]=mapped_column(Text, default='')
    solution: Mapped[str]=mapped_column(Text, default='')
    statut: Mapped[str]=mapped_column(String(50), default='À faire')
    date_cloture: Mapped[datetime|None]=mapped_column(DateTime, nullable=True)

class StockItem(Base):
    __tablename__='web_stock_items'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    reference: Mapped[str]=mapped_column(String(100), unique=True, index=True)
    designation: Mapped[str]=mapped_column(String(220), index=True)
    type_article: Mapped[str]=mapped_column(String(60), default='Consommable')
    marque: Mapped[str]=mapped_column(String(120), default='')
    modele: Mapped[str]=mapped_column(String(120), default='')
    quantite: Mapped[int]=mapped_column(Integer, default=0)
    seuil_alerte: Mapped[int]=mapped_column(Integer, default=1)
    prix_achat: Mapped[float]=mapped_column(Float, default=0.0)
    actif: Mapped[bool]=mapped_column(Boolean, default=True)

class StockMovement(Base):
    __tablename__='web_stock_movements'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    stock_item_id: Mapped[int]=mapped_column(ForeignKey('web_stock_items.id'), index=True)
    intervention_id: Mapped[int|None]=mapped_column(ForeignKey('web_interventions.id'), nullable=True, index=True)
    utilisateur: Mapped[str]=mapped_column(String(120), default='')
    type_mouvement: Mapped[str]=mapped_column(String(80))
    quantite: Mapped[int]=mapped_column(Integer)
    commentaire: Mapped[str]=mapped_column(Text, default='')
    date_mouvement: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)

class InterventionMaterial(Base):
    __tablename__='web_intervention_materials'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    intervention_id: Mapped[int]=mapped_column(ForeignKey('web_interventions.id'), index=True)
    stock_item_id: Mapped[int]=mapped_column(ForeignKey('web_stock_items.id'), index=True)
    quantite: Mapped[int]=mapped_column(Integer)
    date_ajout: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)

class Supplier(Base):
    __tablename__='web_suppliers'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    nom: Mapped[str]=mapped_column(String(180), unique=True)
    contact: Mapped[str]=mapped_column(String(180), default='')
    email: Mapped[str]=mapped_column(String(180), default='')
    telephone: Mapped[str]=mapped_column(String(100), default='')
    site_web: Mapped[str]=mapped_column(String(300), default='')
    actif: Mapped[bool]=mapped_column(Boolean, default=True)

class SupplierPrice(Base):
    __tablename__='web_supplier_prices'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    supplier_id: Mapped[int]=mapped_column(ForeignKey('web_suppliers.id'), index=True)
    stock_item_id: Mapped[int]=mapped_column(ForeignKey('web_stock_items.id'), index=True)
    prix: Mapped[float]=mapped_column(Float, default=0.0)
    date_prix: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)

class PlanningEntry(Base):
    __tablename__='web_planning'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    intervention_id: Mapped[int|None]=mapped_column(ForeignKey('web_interventions.id'), nullable=True, index=True)
    technicien: Mapped[str]=mapped_column(String(150), default='')
    titre: Mapped[str]=mapped_column(String(220))
    debut: Mapped[datetime]=mapped_column(DateTime)
    fin: Mapped[datetime|None]=mapped_column(DateTime, nullable=True)
    statut: Mapped[str]=mapped_column(String(60), default='Prévu')
    notes: Mapped[str]=mapped_column(Text, default='')

class MaintenancePlan(Base):
    __tablename__='web_maintenance_plans'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    equipement_id: Mapped[int]=mapped_column(ForeignKey('web_equipements.id'), index=True)
    contrat_id: Mapped[int|None]=mapped_column(Integer, nullable=True, index=True)
    periodicite_mois: Mapped[int]=mapped_column(Integer, default=12)
    prochaine_echeance: Mapped[date]=mapped_column(Date)
    technicien_prefere: Mapped[str]=mapped_column(String(150), default='')
    priorite: Mapped[str]=mapped_column(String(50), default='Normale')
    notes: Mapped[str]=mapped_column(Text, default='')
    actif: Mapped[bool]=mapped_column(Boolean, default=True)

class MaintenanceHistory(Base):
    __tablename__='web_maintenance_history'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    maintenance_plan_id: Mapped[int]=mapped_column(ForeignKey('web_maintenance_plans.id'), index=True)
    intervention_id: Mapped[int|None]=mapped_column(ForeignKey('web_interventions.id'), nullable=True)
    date_realisation: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)
    ancienne_echeance: Mapped[date|None]=mapped_column(Date, nullable=True)
    nouvelle_echeance: Mapped[date|None]=mapped_column(Date, nullable=True)

class Contract(Base):
    __tablename__='web_contracts'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    reference: Mapped[str]=mapped_column(String(100), unique=True, index=True)
    client_id: Mapped[int]=mapped_column(ForeignKey('web_clients.id'), index=True)
    nom: Mapped[str]=mapped_column(String(220))
    type_contrat: Mapped[str]=mapped_column(String(120), default='Maintenance')
    date_debut: Mapped[date]=mapped_column(Date)
    date_fin: Mapped[date]=mapped_column(Date)
    renouvellement_auto: Mapped[bool]=mapped_column(Boolean, default=False)
    preavis_jours: Mapped[int]=mapped_column(Integer, default=30)
    visites_annuelles: Mapped[int]=mapped_column(Integer, default=1)
    delai_intervention_heures: Mapped[int]=mapped_column(Integer, default=24)
    montant_annuel: Mapped[float]=mapped_column(Float, default=0.0)
    actif: Mapped[bool]=mapped_column(Boolean, default=True)
    notes: Mapped[str]=mapped_column(Text, default='')

class ContractScope(Base):
    __tablename__='web_contract_scope'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    contract_id: Mapped[int]=mapped_column(ForeignKey('web_contracts.id'), index=True)
    site_id: Mapped[int|None]=mapped_column(ForeignKey('web_sites.id'), nullable=True)
    equipement_id: Mapped[int|None]=mapped_column(ForeignKey('web_equipements.id'), nullable=True)

class FollowAction(Base):
    __tablename__='web_follow_actions'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    titre: Mapped[str]=mapped_column(String(240))
    description: Mapped[str]=mapped_column(Text, default='')
    priorite: Mapped[str]=mapped_column(String(50), default='Normale')
    statut: Mapped[str]=mapped_column(String(60), default='À faire')
    assigne_a: Mapped[str]=mapped_column(String(150), default='')
    source_type: Mapped[str]=mapped_column(String(80), default='')
    source_id: Mapped[int|None]=mapped_column(Integer, nullable=True)
    date_echeance: Mapped[date|None]=mapped_column(Date, nullable=True)
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)
    closed_at: Mapped[datetime|None]=mapped_column(DateTime, nullable=True)

class AlertState(Base):
    __tablename__='web_alert_states'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    alert_key: Mapped[str]=mapped_column(String(250), unique=True, index=True)
    acquittee: Mapped[bool]=mapped_column(Boolean, default=False)
    utilisateur: Mapped[str]=mapped_column(String(150), default='')
    commentaire: Mapped[str]=mapped_column(Text, default='')
    date_acquittement: Mapped[datetime|None]=mapped_column(DateTime, nullable=True)

class Diagnostic(Base):
    __tablename__='web_diagnostics'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    intervention_id: Mapped[int]=mapped_column(ForeignKey('web_interventions.id'), index=True)
    equipement_id: Mapped[int|None]=mapped_column(ForeignKey('web_equipements.id'), nullable=True, index=True)
    utilisateur: Mapped[str]=mapped_column(String(150), default='')
    constructeur: Mapped[str]=mapped_column(String(150), default='')
    fiche_titre: Mapped[str]=mapped_column(String(260), default='')
    symptome: Mapped[str]=mapped_column(Text, default='')
    statut: Mapped[str]=mapped_column(String(60), default='En cours')
    conclusion: Mapped[str]=mapped_column(Text, default='')
    date_debut: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)
    date_fin: Mapped[datetime|None]=mapped_column(DateTime, nullable=True)

class DiagnosticStep(Base):
    __tablename__='web_diagnostic_steps'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    diagnostic_id: Mapped[int]=mapped_column(ForeignKey('web_diagnostics.id'), index=True)
    ordre: Mapped[int]=mapped_column(Integer, default=1)
    controle: Mapped[str]=mapped_column(Text)
    resultat: Mapped[str]=mapped_column(String(50), default='Non testé')
    reaction: Mapped[str]=mapped_column(Text, default='')
    date_resultat: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)

class InterventionPhoto(Base):
    __tablename__='web_intervention_photos'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    intervention_id: Mapped[int]=mapped_column(ForeignKey('web_interventions.id'), index=True)
    filename: Mapped[str]=mapped_column(String(250))
    content_type: Mapped[str]=mapped_column(String(120))
    data: Mapped[bytes]=mapped_column(LargeBinary)
    commentaire: Mapped[str]=mapped_column(Text, default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)

class AuditRun(Base):
    __tablename__='web_audit_runs'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    date_run: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)
    utilisateur: Mapped[str]=mapped_column(String(150), default='')
    score: Mapped[int]=mapped_column(Integer, default=100)
    statut: Mapped[str]=mapped_column(String(80), default='OK')
    detail_json: Mapped[str]=mapped_column(Text, default='{}')


class AssistantExchange(Base):
    __tablename__='web_assistant_exchanges'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    intervention_id: Mapped[int|None]=mapped_column(ForeignKey('web_interventions.id'), nullable=True, index=True)
    equipement_id: Mapped[int|None]=mapped_column(ForeignKey('web_equipements.id'), nullable=True, index=True)
    user_id: Mapped[int|None]=mapped_column(ForeignKey('web_users.id'), nullable=True, index=True)
    utilisateur: Mapped[str]=mapped_column(String(150), default='')
    question: Mapped[str]=mapped_column(Text)
    contexte: Mapped[str]=mapped_column(Text, default='')
    reponse: Mapped[str]=mapped_column(Text)
    sources_json: Mapped[str]=mapped_column(Text, default='[]')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)


class AssistantMemory(Base):
    """Mémoire technique persistante de NOX-IA.

    Cette table est volontairement indépendante des interventions et des utilisateurs
    afin qu'une réinitialisation métier n'efface pas l'apprentissage accumulé.
    """
    __tablename__='web_assistant_memory'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    signature: Mapped[str]=mapped_column(String(64), unique=True, index=True)
    memory_type: Mapped[str]=mapped_column(String(60), default='observation', index=True)
    source: Mapped[str]=mapped_column(String(80), default='assistant', index=True)
    title: Mapped[str]=mapped_column(String(320), default='')
    content: Mapped[str]=mapped_column(Text)
    keywords: Mapped[str]=mapped_column(Text, default='')
    constructeur: Mapped[str]=mapped_column(String(150), default='', index=True)
    reference: Mapped[str]=mapped_column(String(180), default='', index=True)
    confidence: Mapped[str]=mapped_column(String(30), default='moyenne')
    utilisateur: Mapped[str]=mapped_column(String(150), default='')
    source_ref: Mapped[str]=mapped_column(String(180), default='')
    times_used: Mapped[int]=mapped_column(Integer, default=0)
    protected: Mapped[bool]=mapped_column(Boolean, default=True)
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class MarketPrice(Base):
    """Observation de prix public / marché pour une référence de stock."""
    __tablename__='web_market_prices'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    stock_item_id: Mapped[int]=mapped_column(ForeignKey('web_stock_items.id'), index=True)
    source: Mapped[str]=mapped_column(String(180), default='Marché')
    source_url: Mapped[str]=mapped_column(String(600), default='')
    prix: Mapped[float]=mapped_column(Float, default=0.0)
    devise: Mapped[str]=mapped_column(String(12), default='EUR')
    date_prix: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)



class PriceSource(Base):
    """Source automatisée de prix fournisseur ou marché. Aucun secret brut n'est stocké."""
    __tablename__='web_price_sources'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    nom: Mapped[str]=mapped_column(String(180), unique=True, index=True)
    categorie: Mapped[str]=mapped_column(String(40), default='Marché', index=True)
    supplier_id: Mapped[int|None]=mapped_column(ForeignKey('web_suppliers.id'), nullable=True, index=True)
    mode: Mapped[str]=mapped_column(String(40), default='Pull URL')
    format_donnees: Mapped[str]=mapped_column(String(20), default='JSON')
    url: Mapped[str]=mapped_column(String(900), default='')
    root_key: Mapped[str]=mapped_column(String(180), default='items')
    reference_field: Mapped[str]=mapped_column(String(180), default='reference')
    price_field: Mapped[str]=mapped_column(String(180), default='price')
    currency_field: Mapped[str]=mapped_column(String(180), default='currency')
    url_field: Mapped[str]=mapped_column(String(180), default='url')
    auth_type: Mapped[str]=mapped_column(String(40), default='Aucune')
    auth_header: Mapped[str]=mapped_column(String(120), default='Authorization')
    auth_env_var: Mapped[str]=mapped_column(String(180), default='')
    actif: Mapped[bool]=mapped_column(Boolean, default=True, index=True)
    statut: Mapped[str]=mapped_column(String(80), default='À configurer')
    derniere_synchro: Mapped[datetime|None]=mapped_column(DateTime, nullable=True)
    notes: Mapped[str]=mapped_column(Text, default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)

class PriceSourceAlias(Base):
    """Fait correspondre une référence fournisseur externe à une référence de stock NOX-IA."""
    __tablename__='web_price_source_aliases'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    source_id: Mapped[int]=mapped_column(ForeignKey('web_price_sources.id'), index=True)
    stock_item_id: Mapped[int]=mapped_column(ForeignKey('web_stock_items.id'), index=True)
    external_reference: Mapped[str]=mapped_column(String(220), index=True)
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)

class PriceSourceCredential(Base):
    """Jeton pour une source Push API. Seul le hash est conservé."""
    __tablename__='web_price_source_credentials'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    source_id: Mapped[int]=mapped_column(ForeignKey('web_price_sources.id'), unique=True, index=True)
    token_hash: Mapped[str]=mapped_column(String(64), unique=True, index=True)
    token_hint: Mapped[str]=mapped_column(String(24), default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)
    rotated_at: Mapped[datetime|None]=mapped_column(DateTime, nullable=True)

class PriceSyncRun(Base):
    __tablename__='web_price_sync_runs'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    source_id: Mapped[int]=mapped_column(ForeignKey('web_price_sources.id'), index=True)
    started_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)
    finished_at: Mapped[datetime|None]=mapped_column(DateTime, nullable=True)
    statut: Mapped[str]=mapped_column(String(60), default='En cours', index=True)
    recus: Mapped[int]=mapped_column(Integer, default=0)
    correspondances: Mapped[int]=mapped_column(Integer, default=0)
    importes: Mapped[int]=mapped_column(Integer, default=0)
    ignores: Mapped[int]=mapped_column(Integer, default=0)
    erreurs: Mapped[int]=mapped_column(Integer, default=0)
    message: Mapped[str]=mapped_column(Text, default='')

class Quote(Base):
    __tablename__='web_quotes'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    reference: Mapped[str]=mapped_column(String(100), unique=True, index=True)
    client_id: Mapped[int]=mapped_column(ForeignKey('web_clients.id'), index=True)
    site_id: Mapped[int|None]=mapped_column(ForeignKey('web_sites.id'), nullable=True, index=True)
    commercial: Mapped[str]=mapped_column(String(150), default='')
    objet: Mapped[str]=mapped_column(String(280), default='')
    statut: Mapped[str]=mapped_column(String(60), default='Brouillon', index=True)
    remise_pct: Mapped[float]=mapped_column(Float, default=0.0)
    notes: Mapped[str]=mapped_column(Text, default='')
    date_creation: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)
    date_validite: Mapped[date|None]=mapped_column(Date, nullable=True)

class QuoteLine(Base):
    __tablename__='web_quote_lines'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    quote_id: Mapped[int]=mapped_column(ForeignKey('web_quotes.id'), index=True)
    type_ligne: Mapped[str]=mapped_column(String(60), default='Matériel')
    stock_item_id: Mapped[int|None]=mapped_column(ForeignKey('web_stock_items.id'), nullable=True, index=True)
    supplier_id: Mapped[int|None]=mapped_column(ForeignKey('web_suppliers.id'), nullable=True, index=True)
    designation: Mapped[str]=mapped_column(String(300))
    quantite: Mapped[float]=mapped_column(Float, default=1.0)
    cout_unitaire: Mapped[float]=mapped_column(Float, default=0.0)
    vente_unitaire: Mapped[float]=mapped_column(Float, default=0.0)
    notes: Mapped[str]=mapped_column(Text, default='')

class InterventionFeedback(Base):
    __tablename__='web_intervention_feedback'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    intervention_id: Mapped[int]=mapped_column(ForeignKey('web_interventions.id'), unique=True, index=True)
    note: Mapped[int]=mapped_column(Integer, default=5)
    resolu: Mapped[bool]=mapped_column(Boolean, default=True)
    point_positif: Mapped[str]=mapped_column(Text, default='')
    point_negatif: Mapped[str]=mapped_column(Text, default='')
    commentaire: Mapped[str]=mapped_column(Text, default='')
    source: Mapped[str]=mapped_column(String(80), default='Interne')
    date_feedback: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)

class IntegrationConnector(Base):
    __tablename__='web_integration_connectors'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    nom: Mapped[str]=mapped_column(String(180), unique=True, index=True)
    logiciel: Mapped[str]=mapped_column(String(180), default='')
    site_id: Mapped[int|None]=mapped_column(ForeignKey('web_sites.id'), nullable=True, index=True)
    type_connecteur: Mapped[str]=mapped_column(String(80), default='API')
    endpoint: Mapped[str]=mapped_column(String(500), default='')
    statut: Mapped[str]=mapped_column(String(60), default='À configurer')
    actif: Mapped[bool]=mapped_column(Boolean, default=True)
    derniere_synchro: Mapped[datetime|None]=mapped_column(DateTime, nullable=True)
    notes: Mapped[str]=mapped_column(Text, default='')

class ConnectorEvent(Base):
    __tablename__='web_connector_events'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    connector_id: Mapped[int|None]=mapped_column(ForeignKey('web_integration_connectors.id'), nullable=True, index=True)
    site_id: Mapped[int|None]=mapped_column(ForeignKey('web_sites.id'), nullable=True, index=True)
    equipement_id: Mapped[int|None]=mapped_column(ForeignKey('web_equipements.id'), nullable=True, index=True)
    external_id: Mapped[str]=mapped_column(String(180), default='', index=True)
    severite: Mapped[str]=mapped_column(String(50), default='Information', index=True)
    titre: Mapped[str]=mapped_column(String(280))
    message: Mapped[str]=mapped_column(Text, default='')
    statut: Mapped[str]=mapped_column(String(60), default='Ouverte', index=True)
    date_evenement: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)
    date_acquittement: Mapped[datetime|None]=mapped_column(DateTime, nullable=True)
    acquittee_par: Mapped[str]=mapped_column(String(150), default='')
    raw_json: Mapped[str]=mapped_column(Text, default='{}')

class AuditLog(Base):
    """Journal append-only applicatif. Pas de FK utilisateur pour préserver l'historique."""
    __tablename__='web_audit_log'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    date_evenement: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)
    user_id: Mapped[int|None]=mapped_column(Integer, nullable=True, index=True)
    utilisateur: Mapped[str]=mapped_column(String(150), default='')
    role: Mapped[str]=mapped_column(String(80), default='')
    action: Mapped[str]=mapped_column(String(220), index=True)
    objet_type: Mapped[str]=mapped_column(String(100), default='', index=True)
    objet_id: Mapped[str]=mapped_column(String(100), default='')
    resume: Mapped[str]=mapped_column(Text, default='')
    adresse_ip: Mapped[str]=mapped_column(String(100), default='')
    user_agent: Mapped[str]=mapped_column(String(500), default='')
    succes: Mapped[bool]=mapped_column(Boolean, default=True)



class ConnectorCredential(Base):
    """Jeton d'authentification d'un connecteur. Le secret brut n'est jamais stocké."""
    __tablename__='web_connector_credentials'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    connector_id: Mapped[int]=mapped_column(ForeignKey('web_integration_connectors.id'), unique=True, index=True)
    token_hash: Mapped[str]=mapped_column(String(64), unique=True, index=True)
    token_hint: Mapped[str]=mapped_column(String(24), default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)
    rotated_at: Mapped[datetime|None]=mapped_column(DateTime, nullable=True)

class NotificationRule(Base):
    """Règle simple : un rôle reçoit les événements à partir d'un niveau donné."""
    __tablename__='web_notification_rules'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    connector_id: Mapped[int|None]=mapped_column(ForeignKey('web_integration_connectors.id'), nullable=True, index=True)
    role: Mapped[str]=mapped_column(String(80), index=True)
    minimum_severity: Mapped[str]=mapped_column(String(50), default='Avertissement')
    active: Mapped[bool]=mapped_column(Boolean, default=True)
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)

class Notification(Base):
    """Notification applicative NOX-IA, volontairement indépendante pour conserver l'historique."""
    __tablename__='web_notifications'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    user_id: Mapped[int]=mapped_column(Integer, index=True)
    event_id: Mapped[int|None]=mapped_column(Integer, nullable=True, index=True)
    niveau: Mapped[str]=mapped_column(String(50), default='Information', index=True)
    categorie: Mapped[str]=mapped_column(String(100), default='Supervision', index=True)
    titre: Mapped[str]=mapped_column(String(280))
    message: Mapped[str]=mapped_column(Text, default='')
    lien: Mapped[str]=mapped_column(String(500), default='/supervision')
    lue: Mapped[bool]=mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)
    read_at: Mapped[datetime|None]=mapped_column(DateTime, nullable=True)


# NOX-IA 6.3 — Guidage logiciels PRO
class SoftwareUiTerm(Base):
    """Libellé réellement visible dans un logiciel, avec traduction française et chemin connu."""
    __tablename__='web_software_ui_terms'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    software: Mapped[str]=mapped_column(String(180), index=True)
    vendor: Mapped[str]=mapped_column(String(180), default='', index=True)
    version: Mapped[str]=mapped_column(String(120), default='', index=True)
    interface_language: Mapped[str]=mapped_column(String(80), default='Auto', index=True)
    ui_label: Mapped[str]=mapped_column(String(240), index=True)
    french_label: Mapped[str]=mapped_column(String(240), default='')
    element_type: Mapped[str]=mapped_column(String(80), default='Bouton')
    menu_path: Mapped[str]=mapped_column(String(700), default='')
    notes: Mapped[str]=mapped_column(Text, default='')
    verified: Mapped[bool]=mapped_column(Boolean, default=False, index=True)
    usage_count: Mapped[int]=mapped_column(Integer, default=0)
    created_by: Mapped[str]=mapped_column(String(150), default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)

class SoftwareProcedure(Base):
    """Procédure de guidage versionnée. Une procédure validée terrain gagne en priorité."""
    __tablename__='web_software_procedures'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    software: Mapped[str]=mapped_column(String(180), index=True)
    vendor: Mapped[str]=mapped_column(String(180), default='', index=True)
    version: Mapped[str]=mapped_column(String(120), default='', index=True)
    interface_language: Mapped[str]=mapped_column(String(80), default='Auto', index=True)
    objective: Mapped[str]=mapped_column(String(500), index=True)
    procedure_text: Mapped[str]=mapped_column(Text)
    source: Mapped[str]=mapped_column(String(120), default='terrain')
    verified: Mapped[bool]=mapped_column(Boolean, default=False, index=True)
    success_count: Mapped[int]=mapped_column(Integer, default=0)
    failure_count: Mapped[int]=mapped_column(Integer, default=0)
    confidence: Mapped[str]=mapped_column(String(40), default='moyenne', index=True)
    created_by: Mapped[str]=mapped_column(String(150), default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)

class SoftwareGuideFeedback(Base):
    """Retour technicien sur une réponse de guidage, utile pour corriger la base."""
    __tablename__='web_software_guide_feedback'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    software: Mapped[str]=mapped_column(String(180), index=True)
    version: Mapped[str]=mapped_column(String(120), default='', index=True)
    interface_language: Mapped[str]=mapped_column(String(80), default='Auto')
    task: Mapped[str]=mapped_column(Text)
    response_text: Mapped[str]=mapped_column(Text)
    verdict: Mapped[str]=mapped_column(String(60), default='À revoir', index=True)
    details: Mapped[str]=mapped_column(Text, default='')
    utilisateur: Mapped[str]=mapped_column(String(150), default='', index=True)
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)


# NOX-IA 6.4 — Commercial / Devis PRO
class CommercialCatalogItem(Base):
    """Bibliothèque commerciale : matériel, main-d’œuvre, services et déplacements."""
    __tablename__='web_commercial_catalog'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    code: Mapped[str]=mapped_column(String(120), unique=True, index=True)
    categorie: Mapped[str]=mapped_column(String(80), default='Matériel', index=True)
    stock_item_id: Mapped[int|None]=mapped_column(ForeignKey('web_stock_items.id'), nullable=True, index=True)
    designation: Mapped[str]=mapped_column(String(320), index=True)
    unite: Mapped[str]=mapped_column(String(40), default='u')
    cout_unitaire: Mapped[float]=mapped_column(Float, default=0.0)
    vente_unitaire: Mapped[float]=mapped_column(Float, default=0.0)
    tva_pct: Mapped[float]=mapped_column(Float, default=20.0)
    notes: Mapped[str]=mapped_column(Text, default='')
    actif: Mapped[bool]=mapped_column(Boolean, default=True, index=True)
    updated_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)

class QuoteVersion(Base):
    """Photo immuable d'un devis à un instant donné."""
    __tablename__='web_quote_versions'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    quote_id: Mapped[int]=mapped_column(ForeignKey('web_quotes.id'), index=True)
    version_no: Mapped[int]=mapped_column(Integer, default=1, index=True)
    snapshot_json: Mapped[str]=mapped_column(Text)
    totals_json: Mapped[str]=mapped_column(Text, default='{}')
    note: Mapped[str]=mapped_column(Text, default='')
    created_by: Mapped[str]=mapped_column(String(150), default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)

class QuoteApproval(Base):
    """Validation responsable lorsque marge/remise dépasse les seuils internes."""
    __tablename__='web_quote_approvals'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    quote_id: Mapped[int]=mapped_column(ForeignKey('web_quotes.id'), index=True)
    snapshot_hash: Mapped[str]=mapped_column(String(64), index=True)
    statut: Mapped[str]=mapped_column(String(40), default='En attente', index=True)
    motif: Mapped[str]=mapped_column(Text, default='')
    commentaire: Mapped[str]=mapped_column(Text, default='')
    marge_pct: Mapped[float]=mapped_column(Float, default=0.0)
    remise_pct: Mapped[float]=mapped_column(Float, default=0.0)
    requested_by: Mapped[str]=mapped_column(String(150), default='')
    requested_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)
    decided_by: Mapped[str]=mapped_column(String(150), default='')
    decided_at: Mapped[datetime|None]=mapped_column(DateTime, nullable=True)

class QuoteActualLine(Base):
    """Coûts réellement constatés après acceptation, pour comparer prévision et réalisation."""
    __tablename__='web_quote_actual_lines'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    quote_id: Mapped[int]=mapped_column(ForeignKey('web_quotes.id'), index=True)
    type_ligne: Mapped[str]=mapped_column(String(80), default='Matériel')
    designation: Mapped[str]=mapped_column(String(320))
    quantite: Mapped[float]=mapped_column(Float, default=1.0)
    cout_unitaire_reel: Mapped[float]=mapped_column(Float, default=0.0)
    source: Mapped[str]=mapped_column(String(120), default='Saisie')
    notes: Mapped[str]=mapped_column(Text, default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)

class QuoteWorkOrder(Base):
    """Affaire/chantier créé à partir d'un devis accepté."""
    __tablename__='web_quote_work_orders'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    quote_id: Mapped[int]=mapped_column(ForeignKey('web_quotes.id'), unique=True, index=True)
    reference: Mapped[str]=mapped_column(String(120), unique=True, index=True)
    client_id: Mapped[int]=mapped_column(ForeignKey('web_clients.id'), index=True)
    site_id: Mapped[int|None]=mapped_column(ForeignKey('web_sites.id'), nullable=True, index=True)
    intervention_id: Mapped[int|None]=mapped_column(ForeignKey('web_interventions.id'), nullable=True, index=True)
    responsable: Mapped[str]=mapped_column(String(150), default='')
    statut: Mapped[str]=mapped_column(String(60), default='À planifier', index=True)
    notes: Mapped[str]=mapped_column(Text, default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)
    closed_at: Mapped[datetime|None]=mapped_column(DateTime, nullable=True)


# NOX-IA 6.5 — Administration / sécurité / gouvernance
class EnterpriseSetting(Base):
    """Paramètre entreprise persistant, volontairement simple et auditable."""
    __tablename__='web_enterprise_settings'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    key: Mapped[str]=mapped_column(String(120), unique=True, index=True)
    value: Mapped[str]=mapped_column(Text, default='')
    updated_by: Mapped[str]=mapped_column(String(150), default='')
    updated_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)

class RolePermission(Base):
    """Restriction fonctionnelle par rôle. L'Administrateur conserve toujours l'accès total."""
    __tablename__='web_role_permissions'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    role: Mapped[str]=mapped_column(String(80), index=True)
    module: Mapped[str]=mapped_column(String(80), index=True)
    can_view: Mapped[bool]=mapped_column(Boolean, default=True)
    can_edit: Mapped[bool]=mapped_column(Boolean, default=False)
    updated_by: Mapped[str]=mapped_column(String(150), default='')
    updated_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)

class LoginSecurityState(Base):
    """État anti-bruteforce et dernière connexion par identifiant."""
    __tablename__='web_login_security'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    username: Mapped[str]=mapped_column(String(150), unique=True, index=True)
    failed_attempts: Mapped[int]=mapped_column(Integer, default=0)
    locked_until: Mapped[datetime|None]=mapped_column(DateTime, nullable=True, index=True)
    last_attempt_at: Mapped[datetime|None]=mapped_column(DateTime, nullable=True)
    last_success_at: Mapped[datetime|None]=mapped_column(DateTime, nullable=True)
    last_ip: Mapped[str]=mapped_column(String(100), default='')

class BackupRun(Base):
    """Historique des sauvegardes logiques téléchargées depuis NOX-IA."""
    __tablename__='web_backup_runs'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)
    created_by: Mapped[str]=mapped_column(String(150), default='')
    format: Mapped[str]=mapped_column(String(40), default='ZIP-JSON')
    table_count: Mapped[int]=mapped_column(Integer, default=0)
    row_count: Mapped[int]=mapped_column(Integer, default=0)
    size_bytes: Mapped[int]=mapped_column(Integer, default=0)
    sha256: Mapped[str]=mapped_column(String(64), default='')
    status: Mapped[str]=mapped_column(String(50), default='Créée')


# NOX-IA 6.6 — Centre opérations
class SupervisionIncident(Base):
    """Incident opérationnel créé depuis un événement de supervision ou manuellement."""
    __tablename__='web_supervision_incidents'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    event_id: Mapped[int|None]=mapped_column(ForeignKey('web_connector_events.id'), nullable=True, unique=True, index=True)
    connector_id: Mapped[int|None]=mapped_column(ForeignKey('web_integration_connectors.id'), nullable=True, index=True)
    site_id: Mapped[int|None]=mapped_column(ForeignKey('web_sites.id'), nullable=True, index=True)
    equipement_id: Mapped[int|None]=mapped_column(ForeignKey('web_equipements.id'), nullable=True, index=True)
    intervention_id: Mapped[int|None]=mapped_column(ForeignKey('web_interventions.id'), nullable=True, index=True)
    titre: Mapped[str]=mapped_column(String(280))
    resume: Mapped[str]=mapped_column(Text, default='')
    severite: Mapped[str]=mapped_column(String(50), default='Avertissement', index=True)
    statut: Mapped[str]=mapped_column(String(60), default='Nouveau', index=True)
    assigne_a: Mapped[str]=mapped_column(String(150), default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)
    closed_at: Mapped[datetime|None]=mapped_column(DateTime, nullable=True)

class MaintenanceWindow(Base):
    """Fenêtre de maintenance qui garde les événements mais évite les fausses alertes."""
    __tablename__='web_maintenance_windows'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    site_id: Mapped[int|None]=mapped_column(ForeignKey('web_sites.id'), nullable=True, index=True)
    connector_id: Mapped[int|None]=mapped_column(ForeignKey('web_integration_connectors.id'), nullable=True, index=True)
    titre: Mapped[str]=mapped_column(String(220))
    motif: Mapped[str]=mapped_column(Text, default='')
    start_at: Mapped[datetime]=mapped_column(DateTime, index=True)
    end_at: Mapped[datetime]=mapped_column(DateTime, index=True)
    actif: Mapped[bool]=mapped_column(Boolean, default=True, index=True)
    created_by: Mapped[str]=mapped_column(String(150), default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)


# NOX-IA 6.7 — Découverte systèmes & connecteurs universels
class DiscoveredSystem(Base):
    """Logiciel/système aperçu sur un site, même si son nom exact est encore inconnu."""
    __tablename__='web_discovered_systems'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    site_id: Mapped[int|None]=mapped_column(ForeignKey('web_sites.id'), nullable=True, index=True)
    nom_temporaire: Mapped[str]=mapped_column(String(220), default='Système à identifier', index=True)
    logiciel: Mapped[str]=mapped_column(String(220), default='', index=True)
    fabricant: Mapped[str]=mapped_column(String(180), default='', index=True)
    version: Mapped[str]=mapped_column(String(120), default='')
    categorie: Mapped[str]=mapped_column(String(100), default='Autre', index=True)
    interface_language: Mapped[str]=mapped_column(String(80), default='Inconnue')
    adresse: Mapped[str]=mapped_column(String(500), default='')
    indices: Mapped[str]=mapped_column(Text, default='')
    notes: Mapped[str]=mapped_column(Text, default='')
    statut_identification: Mapped[str]=mapped_column(String(80), default='À identifier', index=True)
    confiance: Mapped[str]=mapped_column(String(40), default='faible', index=True)
    methodes_suggerees_json: Mapped[str]=mapped_column(Text, default='[]')
    methode_retenue: Mapped[str]=mapped_column(String(100), default='')
    connector_id: Mapped[int|None]=mapped_column(ForeignKey('web_integration_connectors.id'), nullable=True, index=True)
    capture_name: Mapped[str]=mapped_column(String(260), default='')
    capture_mime: Mapped[str]=mapped_column(String(120), default='')
    capture_data: Mapped[bytes|None]=mapped_column(LargeBinary, nullable=True)
    created_by: Mapped[str]=mapped_column(String(150), default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)


# NOX-IA 6.8 — Parc matériel PRO
class EquipmentAssetProfile(Base):
    """Données de parc complémentaires, séparées de la table équipement historique."""
    __tablename__='web_equipment_asset_profiles'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    equipement_id: Mapped[int]=mapped_column(ForeignKey('web_equipements.id'), unique=True, index=True)
    stock_item_id: Mapped[int|None]=mapped_column(ForeignKey('web_stock_items.id'), nullable=True, index=True)
    asset_tag: Mapped[str]=mapped_column(String(120), default='', index=True)
    emplacement: Mapped[str]=mapped_column(String(220), default='')
    zone: Mapped[str]=mapped_column(String(180), default='')
    baie_coffret: Mapped[str]=mapped_column(String(180), default='')
    mac_address: Mapped[str]=mapped_column(String(100), default='')
    firmware_version: Mapped[str]=mapped_column(String(160), default='')
    firmware_checked_at: Mapped[date|None]=mapped_column(Date, nullable=True)
    installation_date: Mapped[date|None]=mapped_column(Date, nullable=True)
    purchase_date: Mapped[date|None]=mapped_column(Date, nullable=True)
    warranty_end: Mapped[date|None]=mapped_column(Date, nullable=True, index=True)
    supplier_name: Mapped[str]=mapped_column(String(220), default='')
    purchase_price: Mapped[float]=mapped_column(Float, default=0.0)
    expected_lifetime_years: Mapped[int]=mapped_column(Integer, default=0)
    criticite: Mapped[str]=mapped_column(String(60), default='Normale', index=True)
    notes: Mapped[str]=mapped_column(Text, default='')
    updated_by: Mapped[str]=mapped_column(String(150), default='')
    updated_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)

class EquipmentPhoto(Base):
    """Photo terrain attachée à un équipement : vue générale, étiquette, câblage, etc."""
    __tablename__='web_equipment_photos'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    equipement_id: Mapped[int]=mapped_column(ForeignKey('web_equipements.id'), index=True)
    categorie: Mapped[str]=mapped_column(String(80), default='Vue générale', index=True)
    caption: Mapped[str]=mapped_column(String(500), default='')
    filename: Mapped[str]=mapped_column(String(260), default='')
    mime_type: Mapped[str]=mapped_column(String(120), default='image/jpeg')
    data: Mapped[bytes]=mapped_column(LargeBinary)
    created_by: Mapped[str]=mapped_column(String(150), default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)

class EquipmentHistoryEntry(Base):
    """Journal métier lisible de la vie d'un équipement, distinct du journal de sécurité."""
    __tablename__='web_equipment_history'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    equipement_id: Mapped[int]=mapped_column(ForeignKey('web_equipements.id'), index=True)
    intervention_id: Mapped[int|None]=mapped_column(ForeignKey('web_interventions.id'), nullable=True, index=True)
    event_type: Mapped[str]=mapped_column(String(80), default='Information', index=True)
    title: Mapped[str]=mapped_column(String(260))
    detail: Mapped[str]=mapped_column(Text, default='')
    source: Mapped[str]=mapped_column(String(100), default='NOX-IA')
    utilisateur: Mapped[str]=mapped_column(String(150), default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)

# NOX-IA 6.9 — ERP / Odoo / ITESA
class CRMLead(Base):
    __tablename__='web_crm_leads'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    nom: Mapped[str]=mapped_column(String(240), index=True)
    client_id: Mapped[int|None]=mapped_column(ForeignKey('web_clients.id'), nullable=True, index=True)
    contact_nom: Mapped[str]=mapped_column(String(180), default='')
    email: Mapped[str]=mapped_column(String(180), default='')
    telephone: Mapped[str]=mapped_column(String(100), default='')
    source: Mapped[str]=mapped_column(String(120), default='Manuel')
    etape: Mapped[str]=mapped_column(String(80), default='Nouveau', index=True)
    probabilite: Mapped[int]=mapped_column(Integer, default=10)
    revenu_attendu: Mapped[float]=mapped_column(Float, default=0.0)
    commercial: Mapped[str]=mapped_column(String(150), default='')
    prochaine_action: Mapped[date|None]=mapped_column(Date, nullable=True)
    notes: Mapped[str]=mapped_column(Text, default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)

class PurchaseOrder(Base):
    __tablename__='web_purchase_orders'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    reference: Mapped[str]=mapped_column(String(100), unique=True, index=True)
    supplier_id: Mapped[int]=mapped_column(ForeignKey('web_suppliers.id'), index=True)
    statut: Mapped[str]=mapped_column(String(80), default='Brouillon', index=True)
    date_commande: Mapped[date]=mapped_column(Date, default=date.today)
    date_prevue: Mapped[date|None]=mapped_column(Date, nullable=True)
    sous_total: Mapped[float]=mapped_column(Float, default=0.0)
    taxes: Mapped[float]=mapped_column(Float, default=0.0)
    total: Mapped[float]=mapped_column(Float, default=0.0)
    created_by: Mapped[str]=mapped_column(String(150), default='')
    notes: Mapped[str]=mapped_column(Text, default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)

class PurchaseOrderLine(Base):
    __tablename__='web_purchase_order_lines'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    purchase_order_id: Mapped[int]=mapped_column(ForeignKey('web_purchase_orders.id'), index=True)
    stock_item_id: Mapped[int|None]=mapped_column(ForeignKey('web_stock_items.id'), nullable=True, index=True)
    reference_fournisseur: Mapped[str]=mapped_column(String(140), default='')
    designation: Mapped[str]=mapped_column(String(260))
    quantite: Mapped[float]=mapped_column(Float, default=1.0)
    prix_unitaire: Mapped[float]=mapped_column(Float, default=0.0)
    tva_pct: Mapped[float]=mapped_column(Float, default=20.0)
    total_ht: Mapped[float]=mapped_column(Float, default=0.0)

class CustomerInvoice(Base):
    __tablename__='web_customer_invoices'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    reference: Mapped[str]=mapped_column(String(100), unique=True, index=True)
    client_id: Mapped[int]=mapped_column(ForeignKey('web_clients.id'), index=True)
    quote_id: Mapped[int|None]=mapped_column(ForeignKey('web_quotes.id'), nullable=True, index=True)
    statut: Mapped[str]=mapped_column(String(80), default='Brouillon', index=True)
    date_emission: Mapped[date]=mapped_column(Date, default=date.today)
    date_echeance: Mapped[date|None]=mapped_column(Date, nullable=True)
    sous_total: Mapped[float]=mapped_column(Float, default=0.0)
    taxes: Mapped[float]=mapped_column(Float, default=0.0)
    total: Mapped[float]=mapped_column(Float, default=0.0)
    paye: Mapped[float]=mapped_column(Float, default=0.0)
    notes: Mapped[str]=mapped_column(Text, default='')
    created_by: Mapped[str]=mapped_column(String(150), default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)

class BusinessEmail(Base):
    __tablename__='web_business_emails'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    destinataire: Mapped[str]=mapped_column(String(300), index=True)
    sujet: Mapped[str]=mapped_column(String(300))
    corps: Mapped[str]=mapped_column(Text, default='')
    related_type: Mapped[str]=mapped_column(String(80), default='')
    related_id: Mapped[int|None]=mapped_column(Integer, nullable=True)
    statut: Mapped[str]=mapped_column(String(60), default='Brouillon', index=True)
    created_by: Mapped[str]=mapped_column(String(150), default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)
    sent_at: Mapped[datetime|None]=mapped_column(DateTime, nullable=True)
    erreur: Mapped[str]=mapped_column(Text, default='')

class ExternalBusinessConnector(Base):
    __tablename__='web_external_business_connectors'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    provider: Mapped[str]=mapped_column(String(80), index=True)
    nom: Mapped[str]=mapped_column(String(180), default='')
    base_url: Mapped[str]=mapped_column(String(500), default='')
    database_name: Mapped[str]=mapped_column(String(180), default='')
    api_mode: Mapped[str]=mapped_column(String(80), default='JSON-2')
    username: Mapped[str]=mapped_column(String(180), default='')
    secret_env_var: Mapped[str]=mapped_column(String(180), default='')
    actif: Mapped[bool]=mapped_column(Boolean, default=True, index=True)
    last_status: Mapped[str]=mapped_column(String(80), default='Non testé')
    last_message: Mapped[str]=mapped_column(Text, default='')
    last_sync_at: Mapped[datetime|None]=mapped_column(DateTime, nullable=True)
    notes: Mapped[str]=mapped_column(Text, default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)

class BusinessSyncLog(Base):
    __tablename__='web_business_sync_logs'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    connector_id: Mapped[int|None]=mapped_column(ForeignKey('web_external_business_connectors.id'), nullable=True, index=True)
    provider: Mapped[str]=mapped_column(String(80), default='')
    action: Mapped[str]=mapped_column(String(140), default='')
    statut: Mapped[str]=mapped_column(String(60), default='OK', index=True)
    detail: Mapped[str]=mapped_column(Text, default='')
    rows_count: Mapped[int]=mapped_column(Integer, default=0)
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)


# ---------------------------------------------------------------------------
# NOX-IA 7.1 — Suite métier intégrée (projets, support, temps, RH, documents…)
# ---------------------------------------------------------------------------
class ERPProject(Base):
    __tablename__='web_erp_projects'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    nom: Mapped[str]=mapped_column(String(240), index=True)
    client_id: Mapped[int|None]=mapped_column(ForeignKey('web_clients.id'), nullable=True, index=True)
    site_id: Mapped[int|None]=mapped_column(ForeignKey('web_sites.id'), nullable=True, index=True)
    responsable: Mapped[str]=mapped_column(String(150), default='')
    statut: Mapped[str]=mapped_column(String(80), default='Nouveau', index=True)
    priorite: Mapped[str]=mapped_column(String(40), default='Normale')
    date_debut: Mapped[date|None]=mapped_column(Date, nullable=True)
    date_fin: Mapped[date|None]=mapped_column(Date, nullable=True)
    budget: Mapped[float]=mapped_column(Float, default=0.0)
    avancement: Mapped[int]=mapped_column(Integer, default=0)
    description: Mapped[str]=mapped_column(Text, default='')
    created_by: Mapped[str]=mapped_column(String(150), default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ERPTask(Base):
    __tablename__='web_erp_tasks'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    project_id: Mapped[int]=mapped_column(ForeignKey('web_erp_projects.id'), index=True)
    titre: Mapped[str]=mapped_column(String(300), index=True)
    assignee: Mapped[str]=mapped_column(String(150), default='', index=True)
    etape: Mapped[str]=mapped_column(String(80), default='À faire', index=True)
    priorite: Mapped[str]=mapped_column(String(40), default='Normale')
    deadline: Mapped[date|None]=mapped_column(Date, nullable=True)
    heures_prevues: Mapped[float]=mapped_column(Float, default=0.0)
    description: Mapped[str]=mapped_column(Text, default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class HelpdeskTicket(Base):
    __tablename__='web_helpdesk_tickets'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    reference: Mapped[str]=mapped_column(String(80), unique=True, index=True)
    titre: Mapped[str]=mapped_column(String(300), index=True)
    client_id: Mapped[int|None]=mapped_column(ForeignKey('web_clients.id'), nullable=True, index=True)
    site_id: Mapped[int|None]=mapped_column(ForeignKey('web_sites.id'), nullable=True, index=True)
    equipement_id: Mapped[int|None]=mapped_column(ForeignKey('web_equipements.id'), nullable=True, index=True)
    assignee: Mapped[str]=mapped_column(String(150), default='', index=True)
    equipe: Mapped[str]=mapped_column(String(120), default='Support')
    statut: Mapped[str]=mapped_column(String(80), default='Nouveau', index=True)
    priorite: Mapped[str]=mapped_column(String(40), default='Normale', index=True)
    canal: Mapped[str]=mapped_column(String(40), default='Interne')
    sla_deadline: Mapped[datetime|None]=mapped_column(DateTime, nullable=True)
    description: Mapped[str]=mapped_column(Text, default='')
    resolution: Mapped[str]=mapped_column(Text, default='')
    satisfaction: Mapped[int|None]=mapped_column(Integer, nullable=True)
    created_by: Mapped[str]=mapped_column(String(150), default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    closed_at: Mapped[datetime|None]=mapped_column(DateTime, nullable=True)

class TimesheetEntry(Base):
    __tablename__='web_timesheets'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    date_travail: Mapped[date]=mapped_column(Date, default=date.today, index=True)
    utilisateur: Mapped[str]=mapped_column(String(150), index=True)
    project_id: Mapped[int|None]=mapped_column(ForeignKey('web_erp_projects.id'), nullable=True, index=True)
    task_id: Mapped[int|None]=mapped_column(ForeignKey('web_erp_tasks.id'), nullable=True, index=True)
    intervention_id: Mapped[int|None]=mapped_column(ForeignKey('web_interventions.id'), nullable=True, index=True)
    heures: Mapped[float]=mapped_column(Float, default=0.0)
    facturable: Mapped[bool]=mapped_column(Boolean, default=True)
    description: Mapped[str]=mapped_column(Text, default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)

class ExpenseClaim(Base):
    __tablename__='web_expense_claims'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    reference: Mapped[str]=mapped_column(String(80), unique=True, index=True)
    utilisateur: Mapped[str]=mapped_column(String(150), index=True)
    date_depense: Mapped[date]=mapped_column(Date, default=date.today, index=True)
    categorie: Mapped[str]=mapped_column(String(100), default='Autre')
    description: Mapped[str]=mapped_column(String(350), default='')
    montant: Mapped[float]=mapped_column(Float, default=0.0)
    tva: Mapped[float]=mapped_column(Float, default=0.0)
    statut: Mapped[str]=mapped_column(String(80), default='Brouillon', index=True)
    projet_id: Mapped[int|None]=mapped_column(ForeignKey('web_erp_projects.id'), nullable=True, index=True)
    justificatif_nom: Mapped[str]=mapped_column(String(260), default='')
    notes: Mapped[str]=mapped_column(Text, default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)

class BusinessDocument(Base):
    __tablename__='web_business_documents'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    nom: Mapped[str]=mapped_column(String(300), index=True)
    dossier: Mapped[str]=mapped_column(String(240), default='Général', index=True)
    tags: Mapped[str]=mapped_column(String(500), default='')
    version: Mapped[int]=mapped_column(Integer, default=1)
    contenu: Mapped[str]=mapped_column(Text, default='')
    related_type: Mapped[str]=mapped_column(String(80), default='')
    related_id: Mapped[int|None]=mapped_column(Integer, nullable=True)
    owner: Mapped[str]=mapped_column(String(150), default='')
    statut: Mapped[str]=mapped_column(String(60), default='Actif')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ApprovalRequest(Base):
    __tablename__='web_approval_requests'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    reference: Mapped[str]=mapped_column(String(80), unique=True, index=True)
    type_demande: Mapped[str]=mapped_column(String(100), default='Général', index=True)
    titre: Mapped[str]=mapped_column(String(300), index=True)
    demandeur: Mapped[str]=mapped_column(String(150), default='', index=True)
    approbateur: Mapped[str]=mapped_column(String(150), default='', index=True)
    montant: Mapped[float]=mapped_column(Float, default=0.0)
    statut: Mapped[str]=mapped_column(String(80), default='À approuver', index=True)
    justification: Mapped[str]=mapped_column(Text, default='')
    decision_note: Mapped[str]=mapped_column(Text, default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)
    decided_at: Mapped[datetime|None]=mapped_column(DateTime, nullable=True)

class KnowledgeArticle(Base):
    __tablename__='web_knowledge_articles'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    titre: Mapped[str]=mapped_column(String(320), index=True)
    categorie: Mapped[str]=mapped_column(String(120), default='Interne', index=True)
    contenu: Mapped[str]=mapped_column(Text, default='')
    tags: Mapped[str]=mapped_column(String(700), default='')
    auteur: Mapped[str]=mapped_column(String(150), default='')
    verifie: Mapped[bool]=mapped_column(Boolean, default=False)
    actif: Mapped[bool]=mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class BusinessCalendarEvent(Base):
    __tablename__='web_business_calendar_events'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    titre: Mapped[str]=mapped_column(String(280), index=True)
    debut: Mapped[datetime]=mapped_column(DateTime, index=True)
    fin: Mapped[datetime|None]=mapped_column(DateTime, nullable=True)
    utilisateur: Mapped[str]=mapped_column(String(150), default='', index=True)
    type_event: Mapped[str]=mapped_column(String(80), default='Rendez-vous')
    related_type: Mapped[str]=mapped_column(String(80), default='')
    related_id: Mapped[int|None]=mapped_column(Integer, nullable=True)
    lieu: Mapped[str]=mapped_column(String(260), default='')
    notes: Mapped[str]=mapped_column(Text, default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)

class EmployeeProfile(Base):
    __tablename__='web_employee_profiles'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    user_id: Mapped[int|None]=mapped_column(ForeignKey('web_users.id'), nullable=True, index=True)
    nom: Mapped[str]=mapped_column(String(220), index=True)
    poste: Mapped[str]=mapped_column(String(180), default='')
    equipe: Mapped[str]=mapped_column(String(150), default='')
    manager: Mapped[str]=mapped_column(String(150), default='')
    email_pro: Mapped[str]=mapped_column(String(250), default='')
    telephone_pro: Mapped[str]=mapped_column(String(80), default='')
    date_entree: Mapped[date|None]=mapped_column(Date, nullable=True)
    cout_horaire: Mapped[float]=mapped_column(Float, default=0.0)
    competences: Mapped[str]=mapped_column(Text, default='')
    actif: Mapped[bool]=mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)

class LeaveRequest(Base):
    __tablename__='web_leave_requests'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    employee_id: Mapped[int]=mapped_column(ForeignKey('web_employee_profiles.id'), index=True)
    type_conge: Mapped[str]=mapped_column(String(100), default='Congé')
    date_debut: Mapped[date]=mapped_column(Date, index=True)
    date_fin: Mapped[date]=mapped_column(Date, index=True)
    statut: Mapped[str]=mapped_column(String(80), default='À approuver', index=True)
    motif: Mapped[str]=mapped_column(Text, default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)

class VendorBill(Base):
    __tablename__='web_vendor_bills'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    reference: Mapped[str]=mapped_column(String(100), unique=True, index=True)
    supplier_id: Mapped[int|None]=mapped_column(ForeignKey('web_suppliers.id'), nullable=True, index=True)
    purchase_order_id: Mapped[int|None]=mapped_column(ForeignKey('web_purchase_orders.id'), nullable=True, index=True)
    date_facture: Mapped[date]=mapped_column(Date, default=date.today, index=True)
    date_echeance: Mapped[date|None]=mapped_column(Date, nullable=True)
    total_ht: Mapped[float]=mapped_column(Float, default=0.0)
    tva: Mapped[float]=mapped_column(Float, default=0.0)
    total_ttc: Mapped[float]=mapped_column(Float, default=0.0)
    paye: Mapped[float]=mapped_column(Float, default=0.0)
    statut: Mapped[str]=mapped_column(String(80), default='Brouillon', index=True)
    notes: Mapped[str]=mapped_column(Text, default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)

class ServiceSubscription(Base):
    __tablename__='web_service_subscriptions'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    reference: Mapped[str]=mapped_column(String(100), unique=True, index=True)
    client_id: Mapped[int|None]=mapped_column(ForeignKey('web_clients.id'), nullable=True, index=True)
    site_id: Mapped[int|None]=mapped_column(ForeignKey('web_sites.id'), nullable=True, index=True)
    nom: Mapped[str]=mapped_column(String(300), index=True)
    periodicite: Mapped[str]=mapped_column(String(50), default='Mensuelle')
    montant: Mapped[float]=mapped_column(Float, default=0.0)
    prochaine_facture: Mapped[date|None]=mapped_column(Date, nullable=True, index=True)
    statut: Mapped[str]=mapped_column(String(80), default='Actif', index=True)
    contrat_id: Mapped[int|None]=mapped_column(ForeignKey('web_contracts.id'), nullable=True, index=True)
    notes: Mapped[str]=mapped_column(Text, default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)

class ChatterMessage(Base):
    __tablename__='web_chatter_messages'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    model: Mapped[str]=mapped_column(String(80), index=True)
    record_id: Mapped[int]=mapped_column(Integer, index=True)
    auteur: Mapped[str]=mapped_column(String(150), default='')
    message: Mapped[str]=mapped_column(Text)
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)

class AutomationRule(Base):
    __tablename__='web_automation_rules'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    nom: Mapped[str]=mapped_column(String(240), index=True)
    modele: Mapped[str]=mapped_column(String(100), default='Intervention')
    declencheur: Mapped[str]=mapped_column(String(120), default='Création')
    condition_text: Mapped[str]=mapped_column(Text, default='')
    action_type: Mapped[str]=mapped_column(String(120), default='Notification')
    action_config: Mapped[str]=mapped_column(Text, default='')
    actif: Mapped[bool]=mapped_column(Boolean, default=True, index=True)
    created_by: Mapped[str]=mapped_column(String(150), default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)


# ---------------------------------------------------------------------------
# NOX-IA 7.2 — Odoo Power : activités, fichiers, visa, Studio, portail, reporting
# ---------------------------------------------------------------------------
class BusinessActivity(Base):
    __tablename__='web_business_activities'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    summary: Mapped[str]=mapped_column(String(320), index=True)
    activity_type: Mapped[str]=mapped_column(String(100), default='À faire', index=True)
    assigned_to: Mapped[str]=mapped_column(String(150), default='', index=True)
    due_date: Mapped[date|None]=mapped_column(Date, nullable=True, index=True)
    priority: Mapped[str]=mapped_column(String(40), default='Normale', index=True)
    status: Mapped[str]=mapped_column(String(60), default='À faire', index=True)
    related_type: Mapped[str]=mapped_column(String(80), default='')
    related_id: Mapped[int|None]=mapped_column(Integer, nullable=True)
    note: Mapped[str]=mapped_column(Text, default='')
    created_by: Mapped[str]=mapped_column(String(150), default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)
    done_at: Mapped[datetime|None]=mapped_column(DateTime, nullable=True)

class DocumentAttachment(Base):
    __tablename__='web_document_attachments'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    document_id: Mapped[int]=mapped_column(ForeignKey('web_business_documents.id'), index=True)
    filename: Mapped[str]=mapped_column(String(320))
    mime_type: Mapped[str]=mapped_column(String(160), default='application/octet-stream')
    content: Mapped[bytes]=mapped_column(LargeBinary)
    size_bytes: Mapped[int]=mapped_column(Integer, default=0)
    sha256: Mapped[str]=mapped_column(String(64), index=True)
    version: Mapped[int]=mapped_column(Integer, default=1)
    uploaded_by: Mapped[str]=mapped_column(String(150), default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)

class InternalSignatureRequest(Base):
    __tablename__='web_internal_signature_requests'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    reference: Mapped[str]=mapped_column(String(100), unique=True, index=True)
    title: Mapped[str]=mapped_column(String(320), index=True)
    related_type: Mapped[str]=mapped_column(String(80), default='Document', index=True)
    related_id: Mapped[int|None]=mapped_column(Integer, nullable=True, index=True)
    requested_by: Mapped[str]=mapped_column(String(150), default='')
    signer: Mapped[str]=mapped_column(String(150), default='', index=True)
    status: Mapped[str]=mapped_column(String(60), default='À signer', index=True)
    signer_name: Mapped[str]=mapped_column(String(220), default='')
    note: Mapped[str]=mapped_column(Text, default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)
    signed_at: Mapped[datetime|None]=mapped_column(DateTime, nullable=True)

class CustomFieldDefinition(Base):
    __tablename__='web_custom_field_definitions'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    model: Mapped[str]=mapped_column(String(100), index=True)
    technical_name: Mapped[str]=mapped_column(String(120), index=True)
    label: Mapped[str]=mapped_column(String(220))
    field_type: Mapped[str]=mapped_column(String(60), default='Texte')
    choices: Mapped[str]=mapped_column(Text, default='')
    required: Mapped[bool]=mapped_column(Boolean, default=False)
    active: Mapped[bool]=mapped_column(Boolean, default=True, index=True)
    created_by: Mapped[str]=mapped_column(String(150), default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)

class CustomFieldValue(Base):
    __tablename__='web_custom_field_values'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    definition_id: Mapped[int]=mapped_column(ForeignKey('web_custom_field_definitions.id'), index=True)
    record_id: Mapped[int]=mapped_column(Integer, index=True)
    value_text: Mapped[str]=mapped_column(Text, default='')
    updated_by: Mapped[str]=mapped_column(String(150), default='')
    updated_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, index=True)

class AutomationExecution(Base):
    __tablename__='web_automation_executions'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    rule_id: Mapped[int]=mapped_column(ForeignKey('web_automation_rules.id'), index=True)
    record_model: Mapped[str]=mapped_column(String(100), default='')
    record_id: Mapped[int|None]=mapped_column(Integer, nullable=True, index=True)
    dedupe_key: Mapped[str]=mapped_column(String(64), unique=True, index=True)
    status: Mapped[str]=mapped_column(String(60), default='OK', index=True)
    detail: Mapped[str]=mapped_column(Text, default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)

class CustomerPortalShare(Base):
    __tablename__='web_customer_portal_shares'
    id: Mapped[int]=mapped_column(Integer, primary_key=True)
    reference: Mapped[str]=mapped_column(String(100), unique=True, index=True)
    token_hash: Mapped[str]=mapped_column(String(64), unique=True, index=True)
    resource_type: Mapped[str]=mapped_column(String(80), index=True)
    resource_id: Mapped[int]=mapped_column(Integer, index=True)
    client_id: Mapped[int|None]=mapped_column(ForeignKey('web_clients.id'), nullable=True, index=True)
    expires_at: Mapped[datetime|None]=mapped_column(DateTime, nullable=True, index=True)
    active: Mapped[bool]=mapped_column(Boolean, default=True, index=True)
    created_by: Mapped[str]=mapped_column(String(150), default='')
    created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow, index=True)
    last_access_at: Mapped[datetime|None]=mapped_column(DateTime, nullable=True)
