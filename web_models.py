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
