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
