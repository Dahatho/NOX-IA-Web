import base64, csv, hashlib, hmac, io, ipaddress, json, math, os, re, secrets, socket, zipfile, smtplib
from collections import Counter
from datetime import date, datetime, timedelta
from html import escape, unescape
from xml.sax.saxutils import escape as xml_escape
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request as UrlRequest, build_opener
from email.message import EmailMessage
from xmlrpc.client import ServerProxy

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from web_models import (
    AlertState, AssistantExchange, AssistantMemory, AuditLog, AuditRun, Base, Client, Contract, ConnectorCredential, ConnectorEvent, Diagnostic, DiagnosticStep,
    Equipement, EquipmentAssetProfile, EquipmentPhoto, EquipmentHistoryEntry, FollowAction, IntegrationConnector, Intervention, InterventionFeedback, InterventionMaterial, InterventionPhoto,
    MaintenanceHistory, MaintenancePlan, MarketPrice, Notification, NotificationRule, SupervisionIncident, MaintenanceWindow, PlanningEntry, PriceSource, PriceSourceAlias, PriceSourceCredential, PriceSyncRun, Quote, QuoteLine, QuoteActualLine, QuoteApproval, QuoteVersion, QuoteWorkOrder, CommercialCatalogItem, EnterpriseSetting, RolePermission, LoginSecurityState, BackupRun, SessionLocal, Site,
    SoftwareGuideFeedback, SoftwareProcedure, SoftwareUiTerm, DiscoveredSystem, StockItem, StockMovement, Supplier, SupplierPrice, User, engine,
    CRMLead, PurchaseOrder, PurchaseOrderLine, CustomerInvoice, BusinessEmail, ExternalBusinessConnector, BusinessSyncLog,
    ERPProject, ERPTask, HelpdeskTicket, TimesheetEntry, ExpenseClaim, BusinessDocument, ApprovalRequest, KnowledgeArticle, BusinessCalendarEvent, EmployeeProfile, LeaveRequest, VendorBill, ServiceSubscription, ChatterMessage, AutomationRule, BusinessActivity, DocumentAttachment, InternalSignatureRequest, CustomFieldDefinition, CustomFieldValue, AutomationExecution, CustomerPortalShare,
    BusinessContact, FinanceAccount, FinanceTransaction, RecruitmentPosition, RecruitmentApplicant, LeaveAllocation, MarketingCampaign, MarketingRecipient, PublicBusinessForm, PublicFormSubmission, PublishedCatalogItem, SavedBusinessView
)
from web_security import hash_password, new_csrf_token, verify_password

APP_VERSION = '7.3.1'
BASE_DIR = Path(__file__).resolve().parent
CORE_PATH = BASE_DIR / 'nox_core_catalog.json'
SOFTWARE_PATH = BASE_DIR / 'software_catalog.json'
ROLES = ('Administrateur','Responsable','Technicien','Commercial','Lecture seule')
MANAGERS = {'Administrateur','Responsable'}
TECHS = {'Administrateur','Responsable','Technicien'}
COMMERCIALS = {'Administrateur','Responsable','Commercial'}
ASSISTANT_USERS = {'Administrateur','Responsable','Technicien','Commercial'}

MODULE_DEFS={
    'dashboard':('Tableau de bord',('/dashboard','/search')),
    'operations':('Opérations',('/clients','/sites','/equipements','/interventions','/planning')),
    'gestion':('Gestion',('/stock','/fournisseurs','/comparateur-prix','/prix-marche','/prix-sources','/maintenance','/contrats')),
    'commercial':('Commercial',('/devis','/catalogue-commercial','/affaires','/portail-admin','/catalogue-en-ligne')),
    'workspace':('Travail & services',('/apps','/projets','/support','/temps','/documents','/connaissances','/agenda','/activites','/signatures','/formulaires')),
    'erp':('ERP & intégrations',('/erp','/crm','/achats','/facturation','/messagerie','/integrations-business','/integrations/odoo','/integrations/itesa','/factures-fournisseurs','/abonnements','/contacts-pro','/finance','/campagnes')),
    'organisation':('Organisation',('/depenses','/approbations','/rh','/automatisations','/studio','/recrutement','/conges','/studio/vues')),
    'suivi':('Suivi & supervision',('/supervision','/incidents','/decouverte-systemes','/notifications','/alertes','/actions','/analyses','/reporting')),
    'intelligence':('Intelligence',('/assistant','/logiciels','/nox-core','/diagnostics')),
    'administration':('Administration',('/utilisateurs','/permissions','/parametres','/sauvegardes','/securite','/journal','/sante','/administration','/export-json','/backup')),
}
DEFAULT_ROLE_PERMISSIONS={
    'Responsable':{
        'dashboard':(True,True),'operations':(True,True),'gestion':(True,True),'commercial':(True,True),'workspace':(True,True),'erp':(True,True),'organisation':(True,True),'suivi':(True,True),'intelligence':(True,True),'administration':(True,False),
    },
    'Technicien':{
        'dashboard':(True,False),'operations':(True,True),'gestion':(True,True),'commercial':(False,False),'workspace':(True,True),'erp':(False,False),'organisation':(False,False),'suivi':(True,True),'intelligence':(True,True),'administration':(False,False),
    },
    'Commercial':{
        'dashboard':(True,False),'operations':(True,False),'gestion':(True,False),'commercial':(True,True),'workspace':(True,True),'erp':(True,True),'organisation':(True,False),'suivi':(True,False),'intelligence':(True,True),'administration':(False,False),
    },
    'Lecture seule':{
        'dashboard':(True,False),'operations':(True,False),'gestion':(True,False),'commercial':(True,False),'workspace':(True,False),'erp':(True,False),'organisation':(False,False),'suivi':(True,False),'intelligence':(False,False),'administration':(False,False),
    },
}
ENTERPRISE_DEFAULTS={
    'company_name':'NOXIA Groupe',
    'company_support_email':'',
    'company_phone':'',
    'company_city':'',
    'quote_min_margin_pct':'20',
    'quote_max_discount_pct':'10',
    'notification_poll_seconds':'15',
    'audit_retention_days':'365',
    'timezone':'Europe/Paris',
}

app = FastAPI(title='NOX-IA', version=APP_VERSION)
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get('SECRET_KEY', secrets.token_urlsafe(48)),
    https_only=bool(os.environ.get('RENDER')),
    same_site='lax',
    max_age=int(os.environ.get('NOXIA_SESSION_MAX_AGE','43200')),
)

def get_db():
    db=SessionLocal()
    try: yield db
    finally: db.close()

def current_user(request, db):
    uid=request.session.get('user_id')
    return db.get(User,int(uid)) if uid else None

def _client_ip(request):
    forwarded=(request.headers.get('x-forwarded-for') or '').split(',')[0].strip()
    return (forwarded or (request.client.host if request.client else ''))[:100]

def get_setting(db,key,default=''):
    row=db.scalar(select(EnterpriseSetting).where(EnterpriseSetting.key==key))
    return row.value if row else default

def set_setting(db,key,value,user=''):
    row=db.scalar(select(EnterpriseSetting).where(EnterpriseSetting.key==key))
    if not row:
        row=EnterpriseSetting(key=key,value=str(value),updated_by=user,updated_at=datetime.utcnow());db.add(row)
    else:
        row.value=str(value);row.updated_by=user;row.updated_at=datetime.utcnow()
    return row

def ensure_enterprise_defaults(db):
    changed=False
    for key,value in ENTERPRISE_DEFAULTS.items():
        if not db.scalar(select(EnterpriseSetting).where(EnterpriseSetting.key==key)):
            db.add(EnterpriseSetting(key=key,value=value,updated_by='Système'));changed=True
    if changed: db.commit()

def ensure_default_role_permissions(db):
    changed=False
    for role,mods in DEFAULT_ROLE_PERMISSIONS.items():
        for module,(can_view,can_edit) in mods.items():
            row=db.scalar(select(RolePermission).where(RolePermission.role==role,RolePermission.module==module))
            if not row:
                db.add(RolePermission(role=role,module=module,can_view=can_view,can_edit=can_edit,updated_by='Système'));changed=True
    if changed: db.commit()

def module_for_path(path):
    for code,(_,prefixes) in MODULE_DEFS.items():
        if any(path==p or path.startswith(p+'/') or (p=='/backup' and path.startswith('/backup')) for p in prefixes):
            return code
    return None

def role_permission(db,role,module):
    if role=='Administrateur': return (True,True)
    row=db.scalar(select(RolePermission).where(RolePermission.role==role,RolePermission.module==module))
    if row:return (bool(row.can_view),bool(row.can_edit))
    return DEFAULT_ROLE_PERMISSIONS.get(role,{}).get(module,(False,False))

def can_access_module(db,user,module,edit=False):
    if not module:return True
    view,write=role_permission(db,user.role,module)
    return bool(write if edit else view)

def require_login(request,db):
    u=current_user(request,db)
    if not u or not u.active: raise HTTPException(401,'Connexion requise')
    module=module_for_path(request.url.path)
    edit=request.method.upper() in {'POST','PUT','PATCH','DELETE'}
    if module and not can_access_module(db,u,module,edit=edit):
        raise HTTPException(403,'Accès désactivé pour ton rôle dans ce module')
    return u

def require_role(user, allowed):
    if user.role not in allowed: raise HTTPException(403,'Permission insuffisante')

def csrf_token(request):
    token=request.session.get('csrf_token')
    if not token:
        token=new_csrf_token(); request.session['csrf_token']=token
    return token

def check_csrf(request, token):
    expected=request.session.get('csrf_token','')
    if not expected or not secrets.compare_digest(expected,token or ''):
        raise HTTPException(403,'CSRF invalide')

def dfr(v):
    if not v:return '—'
    if isinstance(v,datetime): return v.strftime('%d/%m/%Y %H:%M')
    if isinstance(v,date): return v.strftime('%d/%m/%Y')
    return escape(str(v))

def money(v):
    try:return f'{float(v):.2f} €'
    except:return '0.00 €'

def badge(v):
    s=escape(str(v or ''))
    low=s.lower(); cls='b'
    if any(x in low for x in ('urgent','critique','défaut','retard','expir','rupture')): cls+=' danger'
    elif any(x in low for x in ('termin','ok','actif','disponible')): cls+=' good'
    elif any(x in low for x in ('haute','alerte','avert','bientôt','stock bas')): cls+=' warn'
    return f'<span class="{cls}">{s}</span>'

CSS='''
:root{
  --bg:#07101d;--bg-soft:#0a1422;--panel:#0e1a2b;--panel2:#13233a;--panel3:#172a45;
  --line:#233855;--line-soft:#172943;--text:#f4f8ff;--muted:#9db0ca;--accent:#59adff;
  --accent-strong:#2f96f7;--good:#46d19a;--warn:#ffca6a;--danger:#ff7785;
  --sidebar:268px;--topbar:68px;--radius:16px;--shadow:0 18px 50px rgba(0,0,0,.18)
}
*{box-sizing:border-box}
html{background:var(--bg);scroll-behavior:smooth}
body{margin:0;min-height:100vh;max-width:100%;overflow-x:hidden;background:radial-gradient(circle at 82% -10%,rgba(61,145,235,.10),transparent 34%),var(--bg);color:var(--text);font-family:"Segoe UI Variable Text","Segoe UI Variable","Segoe UI",Inter,Roboto,Arial,sans-serif;font-size:15px;font-weight:400;line-height:1.56;letter-spacing:.005em;text-rendering:optimizeLegibility;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;font-synthesis:none}
a{color:inherit}
button,input,select,textarea{font-family:"Segoe UI Variable Text","Segoe UI Variable","Segoe UI",Inter,Roboto,Arial,sans-serif;font-size:inherit;font-weight:450;letter-spacing:.002em}
h1{font-size:clamp(28px,3vw,36px);line-height:1.16;margin:0 0 8px;letter-spacing:-.55px;font-weight:760}h2{font-size:20px;line-height:1.25;margin:0 0 14px;font-weight:720}h3{font-size:16px;line-height:1.3;margin:18px 0 8px;font-weight:680}p{margin:8px 0 14px}

.app-shell{min-height:100vh}
.sidebar{position:fixed;inset:0 auto 0 0;width:var(--sidebar);z-index:40;display:flex;flex-direction:column;background:linear-gradient(180deg,#081321 0%,#07101c 100%);border-right:1px solid var(--line-soft);box-shadow:12px 0 34px rgba(0,0,0,.12)}
.sidebar-brand{height:var(--topbar);display:flex;align-items:center;gap:11px;padding:0 18px;border-bottom:1px solid var(--line-soft);text-decoration:none}
.brand-mark{width:36px;height:36px;display:grid;place-items:center;border-radius:11px;background:linear-gradient(145deg,var(--accent),#347be8);color:#03101d;font-weight:950;box-shadow:0 7px 24px rgba(67,157,246,.25)}
.brand-copy{display:grid;line-height:1.08}.brand-name{font-size:19px;font-weight:900;letter-spacing:.4px}.brand-sub{font-size:10px;color:var(--muted);margin-top:4px;text-transform:uppercase;letter-spacing:1.15px}
.sidebar-nav{padding:14px 10px 22px;overflow-y:auto;overscroll-behavior:contain;scrollbar-width:thin;scrollbar-color:#284261 transparent}
.nav-group{margin:4px 0 15px}.nav-label{padding:0 11px 7px;color:#7186a3;font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:1.15px}
.nav-item{position:relative;display:flex;align-items:center;gap:10px;min-height:42px;margin:2px 0;padding:9px 11px;border:1px solid transparent;border-radius:11px;text-decoration:none;color:#bdcce0;font-size:14.5px;font-weight:610;transition:background .16s ease,color .16s ease,border-color .16s ease,transform .16s ease}
.nav-item:hover{background:#101f33;color:#fff;border-color:#182c47;transform:translateX(2px)}
.nav-item.active{background:linear-gradient(90deg,rgba(79,166,255,.18),rgba(79,166,255,.08));border-color:rgba(89,173,255,.24);color:#fff}
.nav-item.active:before{content:'';position:absolute;left:-1px;top:9px;bottom:9px;width:3px;border-radius:0 3px 3px 0;background:var(--accent)}
.nav-icon{width:24px;height:24px;display:grid;place-items:center;flex:0 0 24px;border-radius:7px;background:#12233a;color:#9bcaff;font-size:11px;font-weight:900}.nav-item.active .nav-icon{background:#183b60;color:#dff0ff}

.app-main{min-width:0;margin-left:var(--sidebar);min-height:100vh}
.app-topbar{position:sticky;top:0;z-index:30;height:var(--topbar);display:flex;align-items:center;justify-content:space-between;gap:18px;padding:0 24px;background:rgba(7,16,29,.88);backdrop-filter:blur(18px);border-bottom:1px solid var(--line-soft)}
.topbar-left{display:flex;align-items:center;gap:12px;min-width:0}.menu-toggle{display:none;width:40px;height:40px;border:1px solid var(--line);border-radius:11px;background:#0e1b2d;color:var(--text);cursor:pointer;font-size:20px}.page-kicker{color:var(--muted);font-size:11px;font-weight:750;text-transform:uppercase;letter-spacing:1px}.page-current{font-size:15px;font-weight:800;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.userbox{display:flex;align-items:center;gap:10px}.user-avatar{width:36px;height:36px;display:grid;place-items:center;border-radius:50%;background:#142842;border:1px solid #284464;color:#d8ebff;font-weight:900}.user-meta{display:grid;line-height:1.15;text-align:right}.user-name{font-size:13px;font-weight:800}.user-role{font-size:11px;color:var(--muted);margin-top:3px}
.logout-form{margin:0}.logout-btn{width:38px;height:38px;display:grid;place-items:center;border:1px solid var(--line);border-radius:10px;background:#102039;color:#cbd9eb;cursor:pointer;font-size:16px}.logout-btn:hover{background:#172c49;color:#fff}
.notif-link{position:relative;width:38px;height:38px;display:grid;place-items:center;border:1px solid var(--line);border-radius:10px;background:#102039;color:#dbeaff;text-decoration:none;font-size:17px}.notif-link:hover{background:#172c49}.notif-count{position:absolute;right:-5px;top:-6px;min-width:18px;height:18px;padding:0 5px;display:grid;place-items:center;border-radius:999px;background:#ff6677;color:white;border:2px solid var(--bg);font-size:10px;font-weight:900}.notif-count.zero{display:none}.nox-toast-stack{position:fixed;right:18px;top:82px;z-index:90;display:grid;gap:10px;width:min(390px,calc(100vw - 28px))}.nox-toast{background:#102039;border:1px solid #345473;border-left:4px solid var(--accent);border-radius:12px;padding:13px 14px;box-shadow:0 18px 50px rgba(0,0,0,.35);animation:noxToastIn .18s ease}.nox-toast.critical{border-left-color:var(--danger)}.nox-toast.warning{border-left-color:var(--warn)}.nox-toast a{color:#dff0ff;text-decoration:none}.nox-toast-title{font-weight:850}.nox-toast-msg{margin-top:4px;color:#aabdd4;font-size:13px}@keyframes noxToastIn{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:none}}

.wrap{width:min(1460px,calc(100% - 48px));margin:0 auto;padding:34px 0 72px}.muted{color:var(--muted)}
.head{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap;margin-bottom:4px}
.card{background:linear-gradient(180deg,rgba(16,29,48,.96),rgba(13,25,42,.96));border:1px solid var(--line);border-radius:var(--radius);padding:19px;margin:16px 0;box-shadow:0 8px 30px rgba(0,0,0,.08);overflow-x:auto}
.grid{display:grid;gap:14px}.g4{grid-template-columns:repeat(4,minmax(0,1fr))}.g2{grid-template-columns:repeat(2,minmax(0,1fr))}
.metric{position:relative;overflow:hidden;background:linear-gradient(145deg,#101e32,#0d192a);border:1px solid var(--line);border-radius:var(--radius);padding:19px;box-shadow:0 10px 34px rgba(0,0,0,.08)}.metric:after{content:'';position:absolute;width:90px;height:90px;border-radius:50%;right:-35px;top:-45px;background:rgba(85,169,255,.08)}.metric span{color:var(--muted);font-size:13px}.metric strong{display:block;font-size:31px;line-height:1.1;margin-top:8px;letter-spacing:-.5px}

table{width:100%;border-collapse:separate;border-spacing:0;min-width:max-content}th,td{text-align:left;padding:11px 12px;border-bottom:1px solid var(--line-soft);vertical-align:top}th{position:sticky;top:0;background:var(--panel);color:#91a8c5;font-size:11.5px;text-transform:uppercase;letter-spacing:.5px;font-weight:700}tr:last-child td{border-bottom:0}tbody tr:hover td{background:rgba(73,145,220,.045)}.scroll{overflow:auto;border-radius:12px}
input,select,textarea{width:100%;border:1px solid var(--line);outline:0;background:#091525;color:var(--text);padding:11px 12px;border-radius:10px;transition:border-color .15s ease,box-shadow .15s ease,background .15s ease}input::placeholder,textarea::placeholder{color:#667e9d}input:focus,select:focus,textarea:focus{border-color:#4d9be7;background:#0a1829;box-shadow:0 0 0 3px rgba(74,153,230,.12)}textarea{min-height:100px;resize:vertical}label{display:grid;gap:6px;color:#a9bad0;font-size:13px;font-weight:650}.form{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:13px}.full{grid-column:1/-1}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;min-height:40px;border:1px solid #2a4262;border-radius:10px;padding:9px 13px;background:#152842;color:var(--text);font-weight:680;cursor:pointer;text-decoration:none;transition:transform .14s ease,background .14s ease,border-color .14s ease,box-shadow .14s ease}.btn:hover{background:#1a3150;border-color:#3b5b82;transform:translateY(-1px)}.btn:disabled{opacity:.45;cursor:not-allowed;transform:none}.primary{background:linear-gradient(180deg,#62b4ff,#459eea);border-color:#63b4ff;color:#04111d;box-shadow:0 7px 20px rgba(64,154,235,.16)}.primary:hover{background:linear-gradient(180deg,#72bdff,#50a7f2);border-color:#7ac2ff}.goodbtn{background:#174b3a}.dangerbtn{background:#4a1d29;border-color:#7a3343;color:#ffdbe0}.dangerbtn:hover{background:#612534;border-color:#994052}.small{min-height:32px;padding:6px 9px;font-size:12px}.b{display:inline-flex;align-items:center;padding:4px 8px;border:1px solid var(--line);border-radius:999px;font-size:11px;font-weight:750;background:#0b1727}.b.good{color:#9af0ca;border-color:#285c4b}.b.warn{color:#ffe0a2;border-color:#6a5230}.b.danger{color:#ffb7c0;border-color:#6e3540}.actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.login{min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at 50% 18%,rgba(65,150,235,.14),transparent 35%)}.login .card{width:min(450px,100%);padding:28px;box-shadow:var(--shadow)}.login h1{font-size:34px}.alert{padding:11px 12px;border:1px solid #7b3944;background:#321a22;border-radius:10px;color:#ffd6db}.notice{margin:0 0 18px;padding:12px 14px;border:1px solid #2c6554;background:#123328;border-radius:11px;color:#c9f7e5;font-weight:700}.danger-zone{border-color:#713342;background:linear-gradient(180deg,rgba(60,24,34,.55),rgba(28,19,29,.72))}.danger-zone h2{color:#ffc3cb}.hint{font-size:12px;color:var(--muted);margin-top:5px}.inline-form{display:flex;gap:7px;align-items:center;flex-wrap:wrap}.inline-form select,.inline-form input{width:auto;min-width:130px}.kv{display:grid;grid-template-columns:190px 1fr;gap:8px 15px}.pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#081322;border:1px solid var(--line);border-radius:11px;padding:13px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:13px;line-height:1.58}.bubble.user .pre{font-family:"Segoe UI Variable Text","Segoe UI",Inter,system-ui,sans-serif;font-size:14.5px;line-height:1.6;background:#0d2038}.bubble.ai .pre,.ai-response{white-space:pre-wrap;overflow-wrap:anywhere;background:linear-gradient(180deg,#0c1626,#0a1422);border:1px solid #1f3654;border-radius:14px;padding:18px 19px;font-family:"Segoe UI Variable Text","Segoe UI",Inter,system-ui,sans-serif;font-size:15.5px;line-height:1.72;letter-spacing:.01em;color:#eef5ff;box-shadow:inset 0 1px 0 rgba(255,255,255,.03)}.bubble.ai{background:linear-gradient(180deg,#102237,#0d1c2f)}
details{border:1px solid var(--line);border-radius:12px;padding:0;margin:10px 0;background:#0c1829;overflow:hidden}summary{cursor:pointer;font-weight:800;padding:13px 14px;list-style:none;transition:background .14s ease}summary::-webkit-details-marker{display:none}summary:before{content:'›';display:inline-block;margin-right:9px;color:#7ebdff;transition:transform .15s ease}details[open] summary:before{transform:rotate(90deg)}summary:hover{background:#11223a}details>p,details>.pre,details>.btn{margin-left:14px;margin-right:14px}details>.btn{margin-bottom:14px}
.chat{display:grid;gap:12px}.bubble{border:1px solid var(--line);border-radius:15px;padding:15px}.bubble.user{background:#0b1b31}.bubble.ai{background:#10253a}.bubble .meta{font-size:11px;color:var(--muted);margin-bottom:7px}.source-card{border-left:3px solid var(--accent);padding-left:11px;margin:8px 0}.web-result{border:1px solid #28527d;background:linear-gradient(180deg,#0e2137,#0b192b);border-radius:14px;padding:18px;margin-top:14px}.web-result h3{margin-top:0}.web-sources{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}.web-source{display:inline-flex;align-items:center;gap:6px;border:1px solid #2c5076;background:#0a1727;border-radius:999px;padding:7px 10px;text-decoration:none;color:#acd3ff;font-size:12px}.web-source:hover{background:#112b47}.search-mode{display:inline-flex;align-items:center;gap:6px;border-radius:999px;padding:6px 10px;border:1px solid var(--line);font-size:12px;color:var(--muted)}.search-mode.on{border-color:#2e674f;color:#a9f5d4}.context-chip{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:5px 9px;margin:3px;color:var(--muted);font-size:11px}.ai-status{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:6px 10px;color:var(--muted);font-size:11px}.ai-status.on{color:#a9f5d4;border-color:#315d50}.assistant-note{border-left:3px solid var(--accent);padding:12px 14px;background:#0b1728;border-radius:10px;line-height:1.6}.answer-label{font-weight:720;letter-spacing:.1px}.memory-card{border:1px solid #24466b;background:linear-gradient(180deg,#0d2035,#0b1a2d);border-radius:14px;padding:14px 16px;margin:10px 0}.memory-card .memory-meta{display:flex;gap:8px;flex-wrap:wrap;align-items:center;color:var(--muted);font-size:12px;margin-bottom:7px}.memory-count{display:inline-flex;align-items:center;gap:7px;border:1px solid #31577d;background:#102641;border-radius:999px;padding:6px 10px;color:#cfe7ff;font-size:12px}.memory-state.good{color:#a9f5d4;border-color:#315d50}.memory-state.warn{color:#ffda8d;border-color:#70572f}.reply-box{background:rgba(10,20,34,.97);backdrop-filter:blur(14px);border:1px solid var(--line);border-radius:18px;padding:16px;box-shadow:0 20px 60px rgba(0,0,0,.34)}.reply-box textarea{min-height:112px;font-size:15px;line-height:1.6}.reply-toggle{position:fixed;opacity:0;pointer-events:none}.reply-launcher{position:fixed;right:24px;bottom:22px;z-index:70;display:flex;gap:8px;align-items:center;flex-wrap:wrap;justify-content:flex-end}.reply-launcher .btn{box-shadow:0 14px 38px rgba(0,0,0,.35);cursor:pointer}.reply-launcher button.btn{pointer-events:auto;user-select:none;-webkit-user-select:none}.reply-launcher .assistant-local-launch{background:#132b46;border-color:#31577e}.reply-dock{display:none;position:fixed;right:22px;bottom:20px;z-index:72;width:min(680px,calc(100vw - 44px));max-height:min(78vh,720px);overflow:auto}.reply-toggle:checked~.reply-launcher{display:none}.reply-toggle:checked~.reply-dock{display:block;animation:replyUp .16s ease-out}.reply-dock-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:11px}.reply-dock-head b{font-size:15px}.reply-mini{display:inline-flex;align-items:center;gap:7px}.conversation-tools{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.chat{scroll-margin-top:90px}.bubble .pre{margin-top:5px}.bubble.ai .pre{font-size:15.5px;line-height:1.76}.bubble.user .pre{font-size:14.5px;line-height:1.65}.assistant-quick-replies{display:flex;gap:7px;align-items:center;flex-wrap:wrap;margin-top:10px}.quick-replies-visible{margin:4px 0 6px;padding:10px 0;border-bottom:1px solid var(--line-soft)}.quick-reply-form{display:inline;margin:0}.local-status{font-weight:650}.assistant-local-btn.ready{border-color:#2f765e;background:#12382d;color:#b8f7de}.assistant-quick-replies .quick-reply{border:1px solid #31577d;background:#0d2138;color:#d7eaff;border-radius:999px;padding:7px 11px;font:600 12.5px/1.2 "Segoe UI Variable Text","Segoe UI",Inter,system-ui,sans-serif;cursor:pointer;transition:.14s ease}.assistant-quick-replies .quick-reply:hover{background:#173555;border-color:#4b83b9;transform:translateY(-1px)}.assistant-mode-pill{display:inline-flex;align-items:center;gap:7px;border:1px solid #2f6655;background:#102d27;color:#adf3d8;border-radius:999px;padding:6px 10px;font-size:12px;font-weight:700}.assistant-turn-hint{margin-top:8px;color:#8faac8;font-size:12px}.last-exchange{scroll-margin-top:92px}@keyframes replyUp{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
.core-search-input{font-family:"Segoe UI Variable Text","Segoe UI",Inter,system-ui,sans-serif!important;font-size:15.5px!important;font-weight:520!important;letter-spacing:.002em}.core-result{border-color:#27435f;background:linear-gradient(180deg,#0d1c30,#0b1727)}.core-result summary{font-family:"Segoe UI Variable Text","Segoe UI",Inter,system-ui,sans-serif;font-size:15.5px;font-weight:720;letter-spacing:.002em}.core-readable{display:grid;gap:8px;margin:12px 14px 16px}.core-row{display:grid;grid-template-columns:minmax(150px,230px) 1fr;gap:14px;padding:9px 11px;border:1px solid #1d3551;border-radius:10px;background:#0a1728;font-family:"Segoe UI Variable Text","Segoe UI",Inter,system-ui,sans-serif;font-size:14px;line-height:1.58}.core-key{color:#91b8df;font-weight:650}.core-value{color:#edf5ff;overflow-wrap:anywhere}.core-raw{margin:8px 14px 16px}.core-raw summary{font-size:13px;color:#8fa8c6;font-weight:600}.core-code{white-space:pre-wrap;overflow-wrap:anywhere;background:#07111e;border:1px solid #172b44;border-radius:10px;padding:12px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;line-height:1.55;color:#b9c9dc}.core-toolbar{display:flex;gap:10px;align-items:end}.core-toolbar label{flex:1}.core-stats{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0 2px}.core-chip{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);background:#0b1829;border-radius:999px;padding:6px 10px;color:#a9bad0;font-size:12px}.empty-state{text-align:center;padding:30px 18px;color:var(--muted)}

.symptom-tools{display:flex;gap:9px;flex-wrap:wrap;align-items:center;margin:12px 0}.symptom-stat{display:inline-flex;align-items:center;gap:7px;border:1px solid #31577d;background:#0f223a;border-radius:999px;padding:7px 11px;color:#cfe7ff;font-size:12.5px}.symptom-panel{border:1px solid #27435f;border-radius:14px;background:linear-gradient(180deg,#0d1d31,#0a1728);padding:14px 16px;margin:12px 0}.symptom-panel summary{font-family:"Segoe UI Variable Text","Segoe UI",Inter,system-ui,sans-serif;font-size:15px}.symptom-group{margin:12px 0}.symptom-group-title{font-size:12px;text-transform:uppercase;letter-spacing:.07em;color:#8eb4dc;font-weight:750;margin-bottom:7px}.symptom-chips{display:flex;flex-wrap:wrap;gap:7px}.symptom-chip{display:inline-flex;padding:7px 10px;border:1px solid #294665;border-radius:999px;background:#0b1b2e;color:#e6f1ff;font-family:"Segoe UI Variable Text","Segoe UI",Inter,system-ui,sans-serif;font-size:13px;line-height:1.25}.symptom-chip.rare{border-color:#6b4b2c;background:#241b12;color:#ffd7a0}.symptom-atlas-grid{display:grid;gap:10px}.symptom-row{display:grid;grid-template-columns:minmax(180px,280px) 1fr auto;gap:12px;align-items:start;border:1px solid #203b59;border-radius:11px;padding:11px 13px;background:#0b192b}.symptom-row .domain{color:#8eb4dc;font-size:12px}.symptom-row .name{font-size:14px;line-height:1.5}.symptom-row .rarity{font-size:11px;color:#b9c9db;border:1px solid #334b66;border-radius:999px;padding:4px 7px}.symptom-row .rarity.rare{color:#ffd7a0;border-color:#6b4b2c}.core-result .symptom-panel{margin:12px 14px 16px}.core-search-input, .core-readable, .core-row, .core-value, .core-key, .symptom-chip, .symptom-row{font-family:"Segoe UI Variable Text","Segoe UI",Inter,system-ui,-apple-system,sans-serif!important}


.local-brain-bar{display:flex;align-items:center;gap:9px;flex-wrap:wrap;margin-top:9px}.local-dot{width:9px;height:9px;border-radius:999px;background:#63758f;box-shadow:0 0 0 3px rgba(99,117,143,.12)}.local-dot.ready{background:var(--good);box-shadow:0 0 0 3px rgba(70,209,154,.14)}.local-dot.error{background:var(--warn)}.local-status{font-size:12px;color:var(--muted)}
.software-hero{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(300px,.85fr);gap:14px}.software-panel{border:1px solid var(--line);border-radius:14px;background:#0b1727;padding:16px}.software-results{display:grid;gap:8px;margin-top:10px}.software-app{display:flex;align-items:center;justify-content:space-between;gap:10px;border:1px solid var(--line);border-radius:11px;padding:10px 12px;background:#0a1626}.software-app strong{font-weight:650}.software-guide-output{white-space:pre-wrap;overflow-wrap:anywhere;border:1px solid var(--line);border-radius:14px;background:#091524;padding:18px;font-size:15px;line-height:1.68;min-height:130px}.software-guide-output:empty:before{content:'La réponse du guide apparaîtra ici.';color:var(--muted)}.software-profile-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:9px}.software-profile{border:1px solid var(--line);border-radius:12px;padding:12px;background:#0b1727}.software-profile b{display:block;margin-bottom:3px}.software-profile .muted{font-size:12px}.local-mode-toggle{display:inline-flex;align-items:center;gap:7px;border:1px solid var(--line);border-radius:999px;padding:6px 10px;background:#0a1728;font-size:12px;color:var(--muted)}.local-mode-toggle input{width:auto;margin:0}.assistant-local-btn{border-color:#315d50}.assistant-local-btn.ready{color:#a9f5d4}.software-shot-preview{max-width:320px;max-height:190px;border:1px solid var(--line);border-radius:10px;display:none;margin-top:8px}.bridge-help{border-left:3px solid var(--accent);padding:10px 12px;background:#0b1728;border-radius:9px;font-size:13px}.software-steps{display:grid;gap:7px}.software-steps .step{border:1px solid var(--line);border-radius:10px;padding:10px;background:#0a1626}
@media(max-width:900px){.software-hero{grid-template-columns:1fr}}

.business-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.business-kpi{border:1px solid var(--line);border-radius:14px;padding:15px;background:#0b1727}.business-kpi .label{font-size:12px;color:var(--muted)}.business-kpi .value{font-size:25px;font-weight:800;margin-top:5px}.margin-good{color:#9af0ca}.margin-warn{color:#ffe0a2}.margin-bad{color:#ffb7c0}.chart-wrap{min-height:220px;border:1px solid var(--line-soft);border-radius:13px;background:#091524;padding:12px}.chart-wrap svg{display:block;width:100%;height:auto;min-height:190px}.chart-legend{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--muted);margin-top:8px}.event-critical{border-left:3px solid var(--danger)}.event-warning{border-left:3px solid var(--warn)}.event-info{border-left:3px solid var(--accent)}.quote-summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.quote-summary>div{border:1px solid var(--line);border-radius:12px;padding:12px;background:#0a1728}.quote-summary small{display:block;color:var(--muted)}.quote-summary strong{display:block;font-size:20px;margin-top:4px}.journal-line{display:grid;grid-template-columns:150px 150px 150px minmax(220px,1fr);gap:10px;padding:10px 0;border-bottom:1px solid var(--line-soft);align-items:start}.journal-line:last-child{border-bottom:0}.price-compare{font-size:12px;white-space:nowrap}.software-help-card{border:1px solid #2b4d70;background:#0a1b2e;border-radius:13px;padding:13px}
@media(max-width:950px){.business-grid,.quote-summary{grid-template-columns:repeat(2,minmax(0,1fr))}.journal-line{grid-template-columns:1fr 1fr}}
@media(max-width:620px){.business-grid,.quote-summary,.journal-line{grid-template-columns:1fr}}
.asset-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px}.asset-kpi{border:1px solid var(--line);background:#0a1728;border-radius:13px;padding:14px}.asset-kpi span{display:block;color:var(--muted);font-size:12px}.asset-kpi strong{display:block;font-size:24px;margin-top:4px}.photo-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.equipment-photo{border:1px solid var(--line);border-radius:13px;overflow:hidden;background:#081321}.equipment-photo img{display:block;width:100%;height:180px;object-fit:cover}.equipment-photo .cap{padding:10px;font-size:12px}.timeline{display:grid;gap:10px}.timeline-item{display:grid;grid-template-columns:155px 120px minmax(0,1fr);gap:12px;border-left:3px solid #315b85;background:#0a1728;border-radius:0 12px 12px 0;padding:11px 13px}.timeline-item small{color:var(--muted)}.qr-box{display:grid;grid-template-columns:190px minmax(0,1fr);gap:18px;align-items:center}.qr-box img{width:180px;height:180px;background:#fff;border-radius:10px;padding:8px}.completeness{height:10px;background:#13233a;border-radius:999px;overflow:hidden}.completeness>span{display:block;height:100%;background:linear-gradient(90deg,#3d8bff,#5dd6a0)}@media(max-width:1050px){.asset-grid{grid-template-columns:repeat(3,minmax(0,1fr));}.photo-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
.app-switcher{width:36px;height:36px;display:grid;place-items:center;border:1px solid var(--line);border-radius:10px;background:#0e1b2d;color:#ddecff;text-decoration:none;font-size:19px}.app-switcher:hover{background:#17304e;border-color:#3e6898}
.app-launcher-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(185px,1fr));gap:14px}.app-tile{min-height:145px;display:flex;flex-direction:column;justify-content:space-between;padding:18px;border:1px solid var(--line);border-radius:18px;background:linear-gradient(145deg,#102239,#0c1829);text-decoration:none;color:var(--text);box-shadow:0 10px 28px rgba(0,0,0,.12);transition:.15s}.app-tile:hover{transform:translateY(-2px);border-color:#41698f;background:linear-gradient(145deg,#142a46,#0e1c30)}.app-tile-icon{width:48px;height:48px;display:grid;place-items:center;border-radius:14px;background:#183657;border:1px solid #2d527a;font-size:20px;font-weight:850}.app-tile b{font-size:16px}.app-tile small{color:var(--muted);line-height:1.45}.app-category{margin:26px 0 10px;font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#8fa9c9}
.kanban{display:grid;grid-template-columns:repeat(auto-fit,minmax(245px,1fr));gap:13px;align-items:start}.kanban-col{border:1px solid var(--line);border-radius:15px;background:#0a1626;padding:10px;min-height:130px}.kanban-col-head{display:flex;justify-content:space-between;gap:8px;align-items:center;padding:5px 5px 10px;color:#aac0da;font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:.05em}.kanban-card{border:1px solid #243e5d;border-radius:12px;background:#10213a;padding:12px;margin-bottom:9px}.kanban-card:last-child{margin-bottom:0}.kanban-card h3{font-size:14px;margin:0 0 7px}.kanban-meta{display:flex;gap:6px;flex-wrap:wrap;color:var(--muted);font-size:11px}.progress-track{height:7px;border-radius:99px;background:#07111d;overflow:hidden;margin-top:9px}.progress-track span{display:block;height:100%;background:#53a9f8;border-radius:99px}.chatter{display:grid;gap:9px}.chatter-msg{border-left:3px solid #31577d;padding:9px 12px;background:#0a1728;border-radius:8px}.chatter-msg .meta{font-size:11px;color:var(--muted);margin-bottom:4px}.viewbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:14px}.viewbar .pill{border:1px solid var(--line);border-radius:999px;padding:7px 10px;color:#bcd1e9;text-decoration:none;font-size:12px}.viewbar .pill.active{background:#173757;border-color:#3c6e9f}.split{display:grid;grid-template-columns:minmax(0,2fr) minmax(300px,1fr);gap:15px}@media(max-width:1050px){.split{grid-template-columns:1fr}}.activity-row{display:grid;grid-template-columns:minmax(0,1.6fr) .7fr .8fr auto;gap:10px;align-items:center;padding:12px;border-bottom:1px solid var(--line-soft)}.activity-row.overdue{border-left:3px solid var(--danger);background:rgba(255,119,133,.045)}.activity-row.today{border-left:3px solid var(--warn)}.file-card{display:flex;justify-content:space-between;gap:12px;align-items:center;padding:12px;border:1px solid var(--line);border-radius:12px;background:#0a1728;margin:8px 0}.report-bars{display:grid;gap:9px}.report-bar{display:grid;grid-template-columns:86px 1fr 100px;gap:10px;align-items:center}.report-track{height:16px;border-radius:999px;background:#07111d;overflow:hidden}.report-fill{height:100%;background:linear-gradient(90deg,#3b8ed8,#67b8ff);border-radius:999px}.portal-shell{max-width:980px;margin:0 auto;padding:34px 18px}.portal-brand{font-size:28px;font-weight:850;margin-bottom:22px}.studio-field{display:grid;grid-template-columns:minmax(160px,.8fr) minmax(0,1.4fr);gap:12px;align-items:center;padding:10px 0;border-bottom:1px solid var(--line-soft)}@media(max-width:720px){.activity-row,.report-bar,.studio-field{grid-template-columns:1fr}}

@media(max-width:720px){.asset-grid,.photo-grid{grid-template-columns:1fr}.timeline-item{grid-template-columns:1fr}.qr-box{grid-template-columns:1fr}}

.global-search{display:flex;align-items:center;gap:8px;flex:1;max-width:520px;margin-left:auto;margin-right:8px}.global-search input{width:100%;height:38px;border-radius:11px;background:#0d1a2b;border:1px solid var(--line);color:var(--text);padding:0 12px;outline:none}.global-search input:focus{border-color:#4f9ce8;box-shadow:0 0 0 3px rgba(79,156,232,.12)}.global-search button{height:38px;min-width:38px;border:1px solid var(--line);border-radius:10px;background:#102039;color:#dbeaff;cursor:pointer}.global-search button:hover{background:#172c49}.admin-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.admin-tile{display:block;text-decoration:none;padding:18px;border-radius:15px;background:#101e31;border:1px solid var(--line);min-height:128px}.admin-tile:hover{border-color:#3d6794;background:#13243a}.admin-tile b{display:block;font-size:17px;margin-bottom:7px}.admin-tile span{color:var(--muted);font-size:13px}.permission-table input[type=checkbox]{width:18px;height:18px}.search-group{margin-bottom:18px}.search-result{display:flex;justify-content:space-between;gap:16px;padding:12px 0;border-bottom:1px solid var(--line-soft)}.search-result:last-child{border-bottom:0}.search-result a{font-weight:750;text-decoration:none}.search-result small{display:block;color:var(--muted);margin-top:2px}.security-ok{color:var(--good)}.security-warn{color:var(--warn)}
.sidebar-overlay{display:none}
@media(max-width:1180px){.g4{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:980px){:root{--topbar:62px}.sidebar{transform:translateX(-103%);transition:transform .2s ease;box-shadow:20px 0 60px rgba(0,0,0,.42)}.sidebar.open{transform:translateX(0)}.app-main{margin-left:0}.menu-toggle{display:grid;place-items:center}.sidebar-overlay{display:block;position:fixed;inset:0;z-index:35;background:rgba(0,0,0,.48);opacity:0;pointer-events:none;transition:opacity .2s ease}.sidebar-overlay.show{opacity:1;pointer-events:auto}.wrap{width:min(100% - 28px,1460px);padding-top:24px}.app-topbar{padding:0 14px}.user-meta{display:none}}
@media(max-width:720px){.global-search{display:none}.admin-grid{grid-template-columns:1fr}.g4,.g2,.form{grid-template-columns:1fr}.full{grid-column:auto}.kv{grid-template-columns:1fr}.core-toolbar{align-items:stretch;flex-direction:column}.core-toolbar .btn{width:100%}.core-row{grid-template-columns:1fr;gap:4px}.card{padding:15px;border-radius:14px}.wrap{width:min(100% - 20px,1460px)}.userbox{gap:7px}.user-avatar{width:32px;height:32px}.logout-btn{width:34px;height:34px}.page-kicker{display:none}.reply-launcher{right:12px;bottom:12px}.reply-dock{left:10px;right:10px;bottom:10px;width:auto;max-height:82vh}.reply-box{padding:13px}.reply-box textarea{min-height:96px}}
'''

NAV_GROUPS=[
    ('Vue générale', [('/dashboard','Tableau de bord','TB'),('/apps','Applications','▦')]),
    ('Opérations', [('/clients','Clients','CL'),('/sites','Sites','SI'),('/equipements','Parc matériel','EQ'),('/interventions','Interventions','IN'),('/planning','Planning','PL')]),
    ('Gestion', [('/stock','Stock','ST'),('/fournisseurs','Fournisseurs','FO'),('/comparateur-prix','Comparateur prix','CP'),('/prix-marche','Prix marché','PM'),('/prix-sources','Sources prix','SP'),('/maintenance','Maintenance','MA'),('/contrats','Contrats','CO')]),
    ('Commercial', [('/devis','Devis','DV'),('/catalogue-commercial','Catalogue commercial','CA'),('/catalogue-en-ligne','Catalogue en ligne','EC'),('/affaires','Affaires / chantiers','AF'),('/portail-admin','Portail client','PC')]),
    ('Travail', [('/projets','Projets','PJ'),('/support','Support / SAV','HD'),('/temps','Feuilles de temps','TS'),('/agenda','Agenda','AG'),('/activites','Activités','AT'),('/documents','Documents','DO'),('/signatures','Signatures','SG'),('/connaissances','Connaissances','KN'),('/formulaires','Formulaires','FM')]),
    ('ERP & Gestion', [('/erp','Centre ERP','ER'),('/crm','CRM','CR'),('/contacts-pro','Contacts','CT'),('/achats','Achats','AH'),('/facturation','Facturation','FA'),('/finance','Finance & trésorerie','FI'),('/factures-fournisseurs','Factures fournisseurs','FF'),('/abonnements','Abonnements','AB'),('/campagnes','Campagnes','MK'),('/messagerie','E-mails','EM'),('/integrations-business','Intégrations métier','IT')]),
    ('Organisation', [('/depenses','Dépenses','DE'),('/approbations','Approbations','AP'),('/rh','Employés / RH','RH'),('/recrutement','Recrutement','RC'),('/conges','Congés','CG'),('/studio','Studio','SD'),('/studio/vues','Vues personnalisées','VU'),('/automatisations','Automatisations','AU')]),
    ('Suivi', [('/supervision','Supervision','SV'),('/incidents','Incidents','IN'),('/decouverte-systemes','Découverte systèmes','DS'),('/notifications','Notifications','NT'),('/alertes','Alertes','AL'),('/actions','Actions','AC'),('/analyses','Analyses','AN'),('/reporting','Reporting','RP')]),
    ('Intelligence', [('/assistant','Assistant IA','IA'),('/logiciels','Guidage logiciels','SW'),('/nox-core','NOX-Core','NX'),('/diagnostics','Diagnostics','DG')]),
    ('Administration', [('/administration','Centre admin','AD'),('/utilisateurs','Utilisateurs','UT'),('/permissions','Permissions','PR'),('/parametres','Paramètres','PA'),('/sauvegardes','Sauvegardes','BK'),('/securite','Sécurité','SE'),('/journal','Journal','JR'),('/sante','Santé / Audit','SA')]),
]
NAV=[item[:2] for _,items in NAV_GROUPS for item in items]

def _nav_active(path, href):
    if href=='/dashboard':
        return path=='/dashboard'
    return path==href or path.startswith(href+'/')

def page(request,user,title,body):
    if not user:
        return HTMLResponse(f'<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#07101d"><title>{escape(title)} · NOX-IA</title><style>{CSS}</style></head><body>{body}</body></html>')

    path=request.url.path
    nav_parts=[]
    with SessionLocal() as pdb:
        for group,items in NAV_GROUPS:
            visible=[]
            for href,label,icon in items:
                module=module_for_path(href)
                if can_access_module(pdb,user,module,edit=False):visible.append((href,label,icon))
            if not visible:continue
            nav_parts.append(f'<div class="nav-group"><div class="nav-label">{escape(group)}</div>')
            for href,label,icon in visible:
                active=' active' if _nav_active(path,href) else ''
                aria=' aria-current="page"' if active else ''
                nav_parts.append(f'<a class="nav-item{active}" href="{href}"{aria}><span class="nav-icon">{escape(icon)}</span><span>{escape(label)}</span></a>')
            nav_parts.append('</div>')
    nav=''.join(nav_parts)
    initial=escape((user.username or '?')[:1].upper())
    username=escape(user.username)
    role=escape(user.role)
    token=csrf_token(request)
    unread_notifications=0
    try:
        with SessionLocal() as ndb:
            unread_notifications=ndb.scalar(select(func.count(Notification.id)).where(Notification.user_id==user.id,Notification.lue.is_(False))) or 0
    except Exception:
        unread_notifications=0
    notif_badge=('99+' if unread_notifications>99 else str(int(unread_notifications)))
    try:
        with SessionLocal() as sdb:
            company_name=get_setting(sdb,'company_name','NOXIA Groupe') or 'NOXIA Groupe'
            poll_seconds=max(5,min(120,int(float(get_setting(sdb,'notification_poll_seconds','15') or 15))))
    except Exception:
        company_name='NOXIA Groupe';poll_seconds=15
    message=(request.query_params.get('msg') or '').strip()
    notice=f'<div class="notice">{escape(message)}</div>' if message else ''
    shell=f'''<div class="app-shell">
      <aside class="sidebar" id="sidebar" aria-label="Navigation principale">
        <a class="sidebar-brand" href="/dashboard"><span class="brand-mark">N</span><span class="brand-copy"><span class="brand-name">NOX-IA</span><span class="brand-sub">{escape(company_name)}</span></span></a>
        <nav class="sidebar-nav">{nav}</nav>
      </aside>
      <div class="sidebar-overlay" id="sidebarOverlay" onclick="closeSidebar()"></div>
      <section class="app-main">
        <header class="app-topbar">
          <div class="topbar-left"><button class="menu-toggle" type="button" aria-label="Ouvrir le menu" onclick="toggleSidebar()">☰</button><div><div class="page-kicker">NOX-IA</div><div class="page-current">{escape(title)}</div></div></div>
          <form class="global-search" method="get" action="/search" role="search"><input name="q" value="{escape((request.query_params.get('q') or '') if path=='/search' else '')}" placeholder="Rechercher client, site, équipement, devis…" aria-label="Recherche universelle"><button title="Rechercher" aria-label="Rechercher">⌕</button></form>
          <div class="userbox"><a class="app-switcher" href="/apps" title="Applications" aria-label="Applications">▦</a><a class="notif-link" href="/notifications" title="Notifications" aria-label="Notifications">🔔<span id="noxNotifCount" class="notif-count{' zero' if unread_notifications==0 else ''}">{notif_badge}</span></a><div class="user-meta"><span class="user-name">{username}</span><span class="user-role">{role}</span></div><div class="user-avatar" title="{username} · {role}">{initial}</div><form class="logout-form" method="post" action="/logout"><input type="hidden" name="csrf_token" value="{token}"><button class="logout-btn" title="Se déconnecter" aria-label="Se déconnecter">↪</button></form></div>
        </header>
        <main class="wrap">{notice}{body}</main>
      </section>
    </div>
    <script>
      const sidebar=document.getElementById('sidebar');
      const overlay=document.getElementById('sidebarOverlay');
      const sidebarNav=document.querySelector('.sidebar-nav');
      const scrollKey='noxia.sidebar.scroll.v1';
      const pageScrollKey='noxia.page.scroll.v1';
      const pageScrollTTL=15*60*1000;
      function savePageScrollForReturn(){{
        try{{
          sessionStorage.setItem(pageScrollKey,JSON.stringify({{
            path:window.location.pathname,
            x:Math.max(0,Math.round(window.scrollX||0)),
            y:Math.max(0,Math.round(window.scrollY||0)),
            at:Date.now()
          }}));
        }}catch(e){{}}
      }}
      function restorePageScrollIfNeeded(){{
        let state=null;
        try{{state=JSON.parse(sessionStorage.getItem(pageScrollKey)||'null');}}catch(e){{state=null;}}
        if(!state)return;
        if(state.path!==window.location.pathname || !state.at || Date.now()-Number(state.at)>pageScrollTTL){{
          try{{sessionStorage.removeItem(pageScrollKey);}}catch(e){{}}
          return;
        }}
        try{{sessionStorage.removeItem(pageScrollKey);}}catch(e){{}}
        const x=Math.max(0,Number(state.x)||0),y=Math.max(0,Number(state.y)||0);
        const apply=()=>{{
          const root=document.documentElement,old=root.style.scrollBehavior;
          root.style.scrollBehavior='auto';
          window.scrollTo(x,y);
          root.style.scrollBehavior=old;
        }};
        apply();requestAnimationFrame(apply);setTimeout(apply,0);setTimeout(apply,70);
      }}
      restorePageScrollIfNeeded();
      document.addEventListener('pointerdown',e=>{{
        const a=e.target&&e.target.closest?e.target.closest('a[href]'):null;
        if(!a || a.hasAttribute('download') || (a.target&&a.target!=='_self'))return;
        let url;try{{url=new URL(a.href,window.location.href);}}catch(err){{return;}}
        if(url.origin!==window.location.origin || url.pathname!==window.location.pathname)return;
        const sameDocumentHash=(url.search===window.location.search && !!url.hash && url.hash!==window.location.hash);
        if(!sameDocumentHash)savePageScrollForReturn();
      }},true);
      document.addEventListener('submit',e=>{{
        const form=e.target;
        if(!(form instanceof HTMLFormElement) || form.classList.contains('logout-form') || form.classList.contains('global-search'))return;
        savePageScrollForReturn();
      }},true);
      function toggleSidebar(){{sidebar.classList.toggle('open');overlay.classList.toggle('show');}}
      function closeSidebar(){{sidebar.classList.remove('open');overlay.classList.remove('show');}}
      function saveSidebarScroll(){{
        if(!sidebarNav) return;
        const value=String(Math.max(0,Math.round(sidebarNav.scrollTop)));
        try{{sessionStorage.setItem(scrollKey,value);localStorage.setItem(scrollKey,value);}}catch(e){{}}
      }}
      function savedSidebarScroll(){{
        try{{return Number(sessionStorage.getItem(scrollKey) ?? localStorage.getItem(scrollKey) ?? 0)||0;}}catch(e){{return 0;}}
      }}
      function restoreSidebarScroll(){{if(sidebarNav) sidebarNav.scrollTop=savedSidebarScroll();}}
      restoreSidebarScroll();
      requestAnimationFrame(restoreSidebarScroll);
      setTimeout(restoreSidebarScroll,0);
      setTimeout(restoreSidebarScroll,60);
      setTimeout(restoreSidebarScroll,220);
      window.addEventListener('pageshow',restoreSidebarScroll);
      window.addEventListener('pagehide',saveSidebarScroll);
      if(sidebarNav) sidebarNav.addEventListener('scroll',saveSidebarScroll,{{passive:true}});
      document.addEventListener('keydown',e=>{{if(e.key==='Escape')closeSidebar();}});
      document.querySelectorAll('.nav-item').forEach(a=>{{
        a.addEventListener('pointerdown',saveSidebarScroll);
        a.addEventListener('click',()=>{{saveSidebarScroll();if(window.innerWidth<=980)closeSidebar();}});
      }});
      const noxToastStack=document.createElement('div');noxToastStack.className='nox-toast-stack';document.body.appendChild(noxToastStack);
      function noxShowToast(n){{
        if(!n||!n.id)return;
        const last=Number(sessionStorage.getItem('noxia.last.notification')||0);
        if(Number(n.id)<=last)return;
        sessionStorage.setItem('noxia.last.notification',String(n.id));
        const box=document.createElement('div');const level=String(n.niveau||'').toLowerCase();box.className='nox-toast '+(level.includes('crit')?'critical':(level.includes('avert')?'warning':''));
        const a=document.createElement('a');a.href=n.lien||'/notifications';
        const title=document.createElement('div');title.className='nox-toast-title';title.textContent=n.titre||'Nouvelle notification';
        const msg=document.createElement('div');msg.className='nox-toast-msg';msg.textContent=n.message||'';a.append(title,msg);box.appendChild(a);noxToastStack.prepend(box);
        setTimeout(()=>box.remove(),9000);
      }}
      async function noxPollNotifications(){{
        try{{const r=await fetch('/api/notifications/status',{{credentials:'same-origin',cache:'no-store'}});if(!r.ok)return;const d=await r.json();const el=document.getElementById('noxNotifCount');if(el){{const c=Number(d.unread||0);el.textContent=c>99?'99+':String(c);el.classList.toggle('zero',c===0);}}if(d.latest)noxShowToast(d.latest);}}catch(e){{}}
      }}
      setTimeout(noxPollNotifications,1200);setInterval(noxPollNotifications,{poll_seconds*1000});
    </script>'''
    return HTMLResponse(f'<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#07101d"><title>{escape(title)} · NOX-IA</title><style>{CSS}</style></head><body>{shell}</body></html>')

def option_rows(rows,value_fn,label_fn,selected=None,empty=None):
    parts=[]
    if empty is not None: parts.append(f'<option value="">{escape(empty)}</option>')
    for r in rows:
        v=value_fn(r); sel=' selected' if str(v)==str(selected) else ''
        parts.append(f'<option value="{escape(str(v))}"{sel}>{escape(label_fn(r))}</option>')
    if not parts:
        return '<option value="">Aucun élément disponible</option>'
    return ''.join(parts)


NOXIA_PRODUCT_HELP=[
    (('tableau de bord','dashboard','accueil'), 'Tableau de bord', 'Le menu « Tableau de bord » donne la vue synthétique : interventions ouvertes, alertes, stock, maintenance, contrats, devis, supervision et satisfaction.'),
    (('client','clients'), 'Clients', 'Menu Opérations → Clients. On y crée et archive les clients. Les sites sont ensuite rattachés à un client.'),
    (('site','sites'), 'Sites', 'Menu Opérations → Sites. Chaque site appartient à un client et sert de point de rattachement aux équipements, interventions et connecteurs.'),
    (('équipement','equipement','matériel installé','materiel installe','parc matériel','qr code','garantie','firmware'), 'Parc matériel', 'Menu Opérations → Parc matériel. Chaque équipement possède une fiche de parc avec localisation, série/IP/MAC, firmware, criticité, dates d’installation/achat/garantie, photos, QR code imprimable, maintenance préventive et historique consolidé.'),
    (('intervention','rapport','photo','diagnostic'), 'Interventions', 'Menu Opérations → Interventions. Une intervention peut contenir problème, actions, solution, matériel consommé/installé, photos, diagnostics et rapports PDF.'),
    (('stock','article','quantité','quantite'), 'Stock', 'Menu Gestion → Stock. NOX-IA suit quantité, seuil, prix d’achat et compare maintenant les moyennes fournisseurs et marché lorsqu’elles existent.'),
    (('fournisseur','prix fournisseur'), 'Fournisseurs', 'Menu Gestion → Fournisseurs. On enregistre les fournisseurs et leurs prix par article. NOX-IA utilise les derniers prix connus de chaque fournisseur pour calculer une moyenne.'),
    (('prix marché','prix marche','marché','marche'), 'Prix marché', 'Menu Gestion → Prix marché. Les observations manuelles et les sources automatisées alimentent la moyenne marché visible dans le Stock.'),
    (('comparateur prix','meilleur fournisseur','moins cher','prix achat'), 'Comparateur prix', 'Menu Gestion → Comparateur prix. NOX-IA compare le meilleur prix fournisseur, la moyenne fournisseurs, la moyenne marché et le prix achat interne pour chaque référence.'),
    (('source prix','synchronisation prix','api prix','csv prix','json prix'), 'Sources prix', 'Menu Gestion → Sources prix. Une source Pull URL lit un flux JSON/CSV ; une source Push API reçoit automatiquement des prix avec un jeton secret. Les références externes peuvent être reliées au stock avec des alias.'),
    (('devis','commercial','marge','bénéfice','benefice','main d’œuvre','main oeuvre'), 'Devis', 'Menu Commercial → Devis. NOX-IA 6.4 gère bibliothèque commerciale, marge prévisionnelle et réelle, versions, validation responsable, export Excel XLSX, vue client imprimable/PDF et transformation d’un devis accepté en affaire/intervention.'),
    (('catalogue commercial','bibliothèque commerciale','tarif','main oeuvre','main d’œuvre'), 'Catalogue commercial', 'Menu Commercial → Catalogue commercial. Référentiel des matériels, heures de main-d’œuvre, services et déplacements avec coût, prix de vente, unité et TVA.'),
    (('affaire','chantier','devis accepté','devis accepte'), 'Affaires / chantiers', 'Menu Commercial → Affaires / chantiers. Un devis accepté peut être transformé en affaire et, si un site est lié, en intervention à planifier.'),
    (('satisfaction','insatisfaction','analyse','courbe','évolution','evolution'), 'Analyses', 'Menu Suivi → Analyses. NOX-IA suit les notes de satisfaction, points positifs/négatifs, évolution mensuelle, interventions et marges des devis.'),
    (('supervision','alerte site','connecteur','logiciel site','panne site','webhook','incident','maintenance'), 'Supervision', 'Menu Suivi → Supervision et Incidents. NOX-IA reçoit les événements externes, les déduplique, crée automatiquement un incident sur les événements critiques, permet de transformer un incident en intervention et sait mettre un site/connecteur en fenêtre de maintenance pour éviter les fausses alertes.'),
    (('logiciel inconnu','identifier logiciel','découverte système','decouverte systeme','capture logiciel','api snmp syslog'), 'Découverte systèmes', 'Menu Suivi → Découverte systèmes. Tu peux enregistrer un logiciel même sans connaître son nom : site, fabricant éventuel, URL/IP, texte visible, version, langue et capture. NOX-IA propose des méthodes de connexion à vérifier puis permet de transformer la fiche en connecteur de supervision.'),
    (('notification','notifications','cloche','non lue','non lu'), 'Notifications', 'Menu Suivi → Notifications ou cloche en haut. Les événements de supervision créent des notifications selon les règles par rôle et niveau de gravité.'),
    (('recherche','recherche universelle','chercher','retrouver'), 'Recherche universelle', 'La barre de recherche en haut retrouve clients, sites, équipements, interventions, stock, fournisseurs, contrats, devis, événements de supervision et procédures logicielles, en respectant les permissions du rôle.'),
    (('administration','centre admin','centre administration'), 'Centre d’administration', 'Menu Administration → Centre admin. Il regroupe utilisateurs, permissions, paramètres entreprise, sauvegardes, sécurité, journal et santé/audit.'),
    (('permission','permissions','droits','role','rôle'), 'Permissions', 'Menu Administration → Permissions. Un administrateur peut restreindre par rôle les modules visibles et modifiables ; l’administrateur conserve toujours l’accès total.'),
    (('parametre','paramètre','parametres','paramètres','entreprise'), 'Paramètres entreprise', 'Menu Administration → Paramètres. On règle le nom de l’entreprise, les seuils de validation des devis, la fréquence des notifications, le fuseau et la cible de rétention du journal.'),
    (('sauvegarde','backup','archive','export complet'), 'Sauvegardes', 'Menu Administration → Sauvegardes. Un administrateur peut générer une archive ZIP logique contenant les données NOX-IA, un manifeste et le journal CSV, avec empreinte SHA-256.'),
    (('sécurité','securite','bruteforce','verrouillage','connexion'), 'Sécurité', 'Menu Administration → Sécurité. NOX-IA suit les tentatives de connexion et bloque temporairement un couple identifiant/IP après plusieurs échecs.'),
    (('journal','connexion','historique changement','changement'), 'Journal', 'Menu Administration → Journal. Il conserve l’activité applicative : opérations d’écriture, utilisateur, rôle, chemin, résultat, IP et navigateur, sans enregistrer les mots de passe.'),
    (('crm','prospect','opportunité','opportunite','pipeline'), 'CRM', 'Menu ERP & Gestion → CRM. NOX-IA suit prospects, opportunités, revenu attendu, probabilité, commercial et prochaine action.'),
    (('achat','achats','commande fournisseur','bon de commande','rfq','demande de prix'), 'Achats', 'Menu ERP & Gestion → Achats. NOX-IA gère les commandes fournisseurs, lignes d’achat, taxes, réception et mise à jour automatique du stock.'),
    (('facture','facturation','paiement','client'), 'Facturation', 'Menu ERP & Gestion → Facturation. NOX-IA suit les factures clients et paiements opérationnels. La comptabilité légale complète reste à synchroniser avec Odoo ou le logiciel comptable.'),
    (('mail','email','e-mail','messagerie'), 'E-mails', 'Menu ERP & Gestion → E-mails. NOX-IA prépare et historise les e-mails et peut envoyer via SMTP si les variables Render sont configurées.'),
    (('odoo','erp odoo','synchroniser odoo'), 'Connexion Odoo', 'Menu ERP & Gestion → Intégrations métier → Odoo. Le connecteur peut tester l’API et synchroniser contacts, fournisseurs et produits en lecture vers NOX-IA lorsqu’un accès API Odoo autorisé est configuré.'),
    (('itesa','fournisseur itesa','boutique itesa'), 'Connexion ITESA', 'Menu ERP & Gestion → Intégrations métier → ITESA. ITESA est préconfiguré comme fournisseur. NOX-IA peut importer une fiche produit publique ou un catalogue CSV/JSON autorisé ; les prix client nécessitent un accès ITESA authentifié ou un flux/API/EDI fourni par ITESA.'),
    (('applications','app launcher','lanceur'), 'Applications', 'Menu Applications (icône ▦) : lanceur central inspiré des suites ERP modernes, pour ouvrir CRM, ventes, achats, projets, support, temps, documents, connaissances, agenda, RH, dépenses, approbations et les modules techniques NOX-IA.'),
    (('projet','projets','tâche','tache','kanban'), 'Projets', 'Menu Travail → Projets. Gestion de projets et tâches avec étapes Kanban, responsable, client/site, budget, échéances, avancement, temps et fil de discussion.'),
    (('support','sav','helpdesk','ticket'), 'Support / SAV', 'Menu Travail → Support / SAV. Tickets avec client/site/équipement, priorité, SLA, équipe, technicien, statut, résolution, satisfaction et fil de discussion.'),
    (('feuille de temps','timesheet','heures'), 'Feuilles de temps', 'Menu Travail → Feuilles de temps. Saisie des heures sur projet, tâche ou intervention, avec distinction facturable/non facturable.'),
    (('document','documents','dossier'), 'Documents', 'Menu Travail → Documents. Bibliothèque documentaire interne avec dossiers, tags, versions, contenu, propriétaire et rattachement métier.'),
    (('connaissance','knowledge','wiki','article'), 'Connaissances', 'Menu Travail → Connaissances. Base collaborative interne complémentaire à NOX-Core, pour procédures métier et savoir interne validé.'),
    (('agenda','calendrier','rendez-vous','rendez vous'), 'Agenda', 'Menu Travail → Agenda. Rendez-vous et événements rattachables aux dossiers métier.'),
    (('dépense','depense','note de frais'), 'Dépenses', 'Menu Organisation → Dépenses. Notes de frais, TVA, projet, justificatif, soumission et statut de validation.'),
    (('approbation','validation','approval'), 'Approbations', 'Menu Organisation → Approbations. Circuit simple de validation pour achats, remises, dépenses ou demandes internes.'),
    (('rh','employé','employe','congé','conge'), 'Employés / RH', 'Menu Organisation → Employés / RH. Profils employés, équipes, managers, compétences, coût horaire et demandes de congés.'),
    (('facture fournisseur','factures fournisseurs','vendor bill'), 'Factures fournisseurs', 'Menu ERP & Gestion → Factures fournisseurs. Suivi des factures d’achat, échéances, montants, TVA et paiements.'),
    (('abonnement','récurrent','recurrent'), 'Abonnements', 'Menu ERP & Gestion → Abonnements. Services récurrents avec périodicité, montant, prochaine facturation, client/site et contrat.'),
    (('automatisation','automatisations','règle automatique','regle automatique'), 'Automatisations', 'Menu Organisation → Automatisations. Catalogue de règles métier préparées pour déclencheurs/conditions/actions ; les actions sensibles restent sous contrôle et journalisation.'),
    (('activité','activite','relance','rappel','prochaine action'), 'Activités', 'Menu Travail → Activités. NOX-IA planifie des rappels/relances sur n’importe quel dossier, les assigne, signale les retards et permet de les terminer.'),
    (('signature','visa','signer'), 'Signatures', 'Menu Travail → Signatures. Workflow de visa interne authentifié avec demandeur, signataire, rattachement métier, horodatage et journalisation. Ce module n’est pas présenté comme une signature électronique qualifiée.'),
    (('studio','champ personnalisé','champ personnalise','personnaliser'), 'Studio', 'Menu Organisation → Studio. Création de champs personnalisés sans modifier les tables métier : définition par modèle puis valeurs rattachées aux enregistrements.'),
    (('reporting','rapport','pivot','kpi'), 'Reporting', 'Menu Suivi → Reporting. Vue analytique transversale sur ventes, achats, support, temps, satisfaction et stock avec séries mensuelles et export CSV.'),
    (('portail client','partage client','lien client'), 'Portail client', 'Menu Commercial → Portail client. Génère un lien lecture seule, révocable et expirant, pour partager un devis, une facture, un ticket SAV ou un abonnement sans exposer le reste de NOX-IA.'),
    (('contact','contacts','carnet adresse','carnet d adresse'), 'Contacts', 'Menu ERP & Gestion → Contacts. Carnet de contacts avancé rattachable aux clients : fonction, entreprise, e-mail, téléphone, mobile, langue, type et tags.'),
    (('finance','trésorerie','tresorerie','banque','encaissement','décaissement','decaissement'), 'Finance & trésorerie', 'Menu ERP & Gestion → Finance & trésorerie. Pilotage interne des comptes et mouvements de trésorerie, rapprochement et soldes. Ce module ne remplace pas une comptabilité légale certifiée.'),
    (('recrutement','candidat','candidature','poste'), 'Recrutement', 'Menu Organisation → Recrutement. Postes ouverts et candidatures avec pipeline Nouveau → Qualification → Entretien → Proposition → Embauché/Refusé.'),
    (('congé','conge','absence','solde congé','solde conge'), 'Congés', 'Menu Organisation → Congés. Allocations annuelles, demandes, jours approuvés/en attente et décision responsable.'),
    (('formulaire','formulaires','questionnaire','form public'), 'Formulaires', 'Menu Travail → Formulaires. Création de formulaires publics à lien secret, champs configurables et collecte des réponses directement dans NOX-IA.'),
    (('campagne','campagnes','marketing','mailing'), 'Campagnes', 'Menu ERP & Gestion → Campagnes. Prépare une campagne à partir des contacts/clients autorisés et génère des brouillons e-mail vérifiables avant envoi.'),
    (('catalogue en ligne','catalogue public','produit public'), 'Catalogue en ligne', 'Menu Commercial → Catalogue en ligne. Publication contrôlée d’articles du catalogue commercial sur une page publique ; aucun paiement en ligne n’est activé dans cette version.'),
    (('vue personnalisée','vue personnalisee','filtre sauvegardé','filtre sauvegarde'), 'Vues personnalisées', 'Menu Organisation → Vues personnalisées. Enregistre des filtres/colonnes de travail partageables ou personnels pour préparer des vues métier réutilisables.'),
    (('nox-ia','noxia','application nox','menu nox'), 'Assistant NOX-IA', 'Tu peux demander à l’Assistant IA comment utiliser NOX-IA. Il reçoit un guide interne des fonctions réellement disponibles et doit dire clairement quand une fonction n’est pas encore branchée.'),
]

def noxia_product_context(question,limit=7):
    q=assistant_norm(question or '') if 'assistant_norm' in globals() else str(question or '').lower()
    scored=[]
    for keys,title,text_value in NOXIA_PRODUCT_HELP:
        score=sum(3 for k in keys if (assistant_norm(k) if 'assistant_norm' in globals() else k.lower()) in q)
        if score:scored.append((score,title,text_value))
    if not scored and any(x in q for x in ('nox ia','noxia','application nox','dans nox','menu nox')):
        scored=[(1,t,v) for _,t,v in NOXIA_PRODUCT_HELP[:limit]]
    scored.sort(key=lambda x:(-x[0],x[1]))
    return '\n'.join(f'- {title}: {value}' for _,title,value in scored[:limit]) or 'Aucune aide NOX-IA spécifique détectée.'

def add_months(d,months):
    y=d.year+(d.month-1+months)//12; m=(d.month-1+months)%12+1
    md=[31,29 if y%4==0 and (y%100!=0 or y%400==0) else 28,31,30,31,30,31,31,30,31,30,31][m-1]
    return date(y,m,min(d.day,md))

def core_payload():
    try:return json.loads(CORE_PATH.read_text(encoding='utf-8'))
    except:return {}

def core_catalog():
    return core_payload().get('fiches',[])


def software_payload():
    try:
        data=json.loads(SOFTWARE_PATH.read_text(encoding='utf-8'))
        return data if isinstance(data,dict) else {}
    except Exception:
        return {}

def software_catalog():
    rows=software_payload().get('software') or []
    return rows if isinstance(rows,list) else []

def software_profile_search(query='',limit=12):
    q=' '.join(str(query or '').lower().split())
    q_tokens=set(re.findall(r'[a-z0-9à-ÿ]+',q))
    scored=[]
    for row in software_catalog():
        hay=' '.join([str(row.get('name','')),str(row.get('vendor','')),' '.join(row.get('aliases') or []),' '.join(row.get('domains') or []),' '.join(row.get('focus') or [])]).lower()
        tokens=set(re.findall(r'[a-z0-9à-ÿ]+',hay))
        score=len(q_tokens & tokens)*2
        if q and q in hay:score+=8
        if not q:score=1
        if score>0:scored.append((score,row))
    scored.sort(key=lambda item:(item[0],item[1].get('name','')),reverse=True)
    return [row for _,row in scored[:limit]]

def software_profile_text(query):
    rows=software_profile_search(query,limit=4)
    if not rows:return 'Aucun profil logiciel local précis. Demander le nom et la version affichés.'
    out=[]
    for row in rows:
        out.append(
            f"Logiciel: {row.get('name','')} | Éditeur: {row.get('vendor','')} | "
            f"Domaines: {', '.join(row.get('domains') or [])} | "
            f"Fonctions connues: {', '.join(row.get('focus') or [])}"
        )
    return '\n'.join(out)

def core_symptom_atlas():
    atlas=core_payload().get('symptom_atlas') or {}
    return atlas.get('entries',[]) if isinstance(atlas,dict) else []

def core_symptom_domains():
    out=[]
    for row in core_symptom_atlas():
        domain=str(row.get('domaine','')).strip()
        if domain and domain not in out:out.append(domain)
    return out

def core_symptom_domain_from_text(text_value):
    low=str(text_value or '').lower()
    rules=[
        ('Incendie / SSI',('incendie','ssi','cmsi','ecs','boucle','das','détecteur incendie')),
        ('Contrôle d’accès / Lecteurs / Portes',('badge','lecteur','contrôle accès','controle acces','porte','serrure','wiegand','osdp','acu')),
        ('Intrusion / Alarme',('intrusion','alarme','pir','zone','centrale intrusion','gsm')),
        ('Interphonie / SIP / Audio',('interphone','sip','rtp','dtmf','audio','appel')),
        ('VMS / NVR / Enregistrement',('vms','nvr','dvr','archiver','recording','enregistrement','playback','archive')),
        ('Vidéosurveillance / Caméra IP',('caméra','camera','vidéo','video','ptz','rtsp','onvif','image','flux')),
        ('Réseau / PoE / Infrastructure',('réseau','reseau','switch','vlan','poe','dhcp','dns','ntp','ethernet','fibre')),
        ('Cloud / Accès distant / Mobile',('cloud','mobile','distant','remote','hik-connect')),
        ('IA vidéo / Analytics / Métadonnées',('analytics','analyt','métadonnée','metadata','lpr','anpr','tracking')),
        ('Alimentation / UPS / Électricité',('alimentation','batterie','ups','secteur','tension','chargeur')),
        ('Serveurs / OS / Base de données / Stockage',('serveur','server','database','base de données','stockage','storage','disque','raid')),
        ('Cybersécurité défensive / Authentification',('cyber','authentification','tls','certificat','oauth','saml','kerberos','mfa')),
    ]
    for domain,terms in rules:
        if any(term in low for term in terms):return domain
    return ''

def core_symptom_search(query='',context_text='',domain='',rarity='',limit=80):
    rows=core_symptom_atlas();q=' '.join(str(query or '').lower().split());ctx=' '.join(str(context_text or '').lower().split())
    q_tokens=assistant_tokens(q+' '+ctx) if 'assistant_tokens' in globals() else set(re.findall(r'[a-z0-9à-ÿ-]+',q+' '+ctx))
    detected=domain or core_symptom_domain_from_text(q+' '+ctx)
    scored=[]
    for row in rows:
        if domain and row.get('domaine')!=domain:continue
        if rarity and row.get('rarete')!=rarity:continue
        hay=' '.join([str(row.get('symptome','')),str(row.get('domaine','')),' '.join(row.get('aliases') or [])]).lower()
        tokens=assistant_tokens(hay) if 'assistant_tokens' in globals() else set(re.findall(r'[a-z0-9à-ÿ-]+',hay))
        score=len(q_tokens & tokens)*2.0
        if q and q in hay:score+=10
        if detected and row.get('domaine')==detected:score+=3
        if not q and not domain:score=1
        if score>0:scored.append((score,row))
    scored.sort(key=lambda x:(x[0],x[1].get('rarete')=='rare'),reverse=True)
    return [row for _,row in scored[:limit]]

def core_symptoms_for_item(item,limit=140):
    title,maker,typ,summary=core_meta(item)
    data=item.get('data') or {}
    context=' '.join([title,maker,typ,summary,str(data.get('categorie','')),str(data.get('type','')),str(data.get('modele',''))])
    domain=core_symptom_domain_from_text(context)
    if not domain:return []
    return core_symptom_search('',domain=domain,limit=limit)

def core_symptom_html(rows,compact=False):
    if not rows:return '<span class="muted">Aucun symptôme associé dans l’atlas.</span>'
    groups={}
    for row in rows:groups.setdefault(row.get('rarete','documenté'),[]).append(row)
    order=['courant','moins courant','rare','déjà documenté','documenté']
    parts=[]
    for rarity in order:
        values=groups.get(rarity) or []
        if not values:continue
        chips=''.join(f'<span class="symptom-chip {"rare" if rarity=="rare" else ""}">{escape(v.get("symptome",""))}</span>' for v in values)
        parts.append(f'<div class="symptom-group"><div class="symptom-group-title">{escape(rarity.capitalize())} · {len(values)}</div><div class="symptom-chips">{chips}</div></div>')
    return ''.join(parts)

def core_meta(item):
    d=item.get('data') or {}
    def first(*ks):
        for k in ks:
            if d.get(k) not in (None,'',[]): return d.get(k)
        return ''
    return tuple(str(x) for x in (first('titre','title','nom','logiciel','procedure') or item.get('source_file','Fiche'), first('constructeur','fabricant','marque','manufacturer'), first('type_fiche','type','categorie','catégorie'), first('resume','résumé','description','probleme','symptome','objet')))



def core_readable_html(data,max_rows=34):
    """Rend une fiche NOX-Core lisible sans l'apparence JSON/terminal."""
    rows=[]
    def walk(value,prefix='',depth=0):
        if len(rows)>=max_rows or depth>4:return
        if isinstance(value,dict):
            for key,val in value.items():
                label=(str(key).replace('_',' ').replace('-', ' ').strip())
                full=(f'{prefix} › {label}' if prefix else label)
                if isinstance(val,(dict,list)):
                    walk(val,full,depth+1)
                elif val not in (None,''):
                    rows.append((full,str(val)))
                    if len(rows)>=max_rows:return
        elif isinstance(value,list):
            scalar=[str(v) for v in value if not isinstance(v,(dict,list)) and v not in (None,'')]
            if scalar:
                rows.append((prefix or 'Informations',' · '.join(scalar)))
            for val in value:
                if isinstance(val,(dict,list)):walk(val,prefix,depth+1)
    walk(data or {})
    if not rows:return '<div class="muted">Aucune donnée détaillée.</div>'
    return ''.join(
        f'<div class="core-row"><div class="core-key">{escape(k[:180].capitalize())}</div><div class="core-value">{escape(v[:1800])}</div></div>'
        for k,v in rows
    )

def derive_alerts(db):
    a=[]; today=date.today(); now=datetime.utcnow()
    for c in db.scalars(select(Contract).where(Contract.actif.is_(True))).all():
        days=(c.date_fin-today).days
        if days<0:a.append(('critique','Contrats',f'contrat:{c.id}',f'Contrat {c.reference} expiré',dfr(c.date_fin)))
        elif days<=c.preavis_jours:a.append(('avertissement','Contrats',f'contrat:{c.id}',f'Contrat {c.reference} en préavis',f'{days} jour(s)'))
    for m in db.scalars(select(MaintenancePlan).where(MaintenancePlan.actif.is_(True))).all():
        days=(m.prochaine_echeance-today).days; e=db.get(Equipement,m.equipement_id); ref=e.reference if e else f'EQ#{m.equipement_id}'
        if days<0:a.append(('critique','Maintenance',f'maint:{m.id}',f'Maintenance en retard {ref}',f'{abs(days)} jour(s)'))
        elif days<=30:a.append(('avertissement','Maintenance',f'maint:{m.id}',f'Maintenance proche {ref}',f'{days} jour(s)'))
    for p in db.scalars(select(EquipmentAssetProfile).where(EquipmentAssetProfile.warranty_end.is_not(None))).all():
        e=db.get(Equipement,p.equipement_id)
        if not e or not e.actif or not p.warranty_end: continue
        days=(p.warranty_end-today).days
        if 0<=days<=60:
            level='critique' if days<=7 else 'avertissement'
            a.append((level,'Parc matériel',f'warranty:{p.id}',f'Garantie bientôt terminée {e.reference}',f'{days} jour(s) · {dfr(p.warranty_end)}'))
    for s in db.scalars(select(StockItem).where(StockItem.actif.is_(True))).all():
        if s.quantite<=0:a.append(('critique','Stock',f'stock:{s.id}',f'Rupture {s.designation}',s.reference))
        elif s.quantite<=s.seuil_alerte:a.append(('avertissement','Stock',f'stock:{s.id}',f'Stock bas {s.designation}',str(s.quantite)))
    for i in db.scalars(select(Intervention).where(Intervention.statut!='Terminée')).all():
        if i.priorite in ('Urgente','Haute'):a.append(('critique' if i.priorite=='Urgente' else 'avertissement','Interventions',f'inter:{i.id}',f'Intervention #{i.id} {i.priorite}',i.probleme[:120]))
    for p in db.scalars(select(PlanningEntry).where(PlanningEntry.statut!='Terminée')).all():
        if p.debut<now:a.append(('avertissement','Planning',f'plan:{p.id}',f'Planning dépassé : {p.titre}',dfr(p.debut)))
    for ev in db.scalars(select(ConnectorEvent).where(ConnectorEvent.statut!='Fermée').order_by(ConnectorEvent.date_evenement.desc()).limit(250)).all():
        sev=(ev.severite or '').lower(); level='critique' if sev in ('critique','critical','urgent') else ('avertissement' if sev in ('avertissement','warning','majeure','major') else 'information')
        a.append((level,'Supervision',f'event:{ev.id}',ev.titre,ev.message[:120]))
    return a


def audit_add(db,request,user,action,objet_type='',objet_id='',resume='',succes=True):
    try:
        forwarded=(request.headers.get('x-forwarded-for') or '').split(',')[0].strip()
        ip=forwarded or (request.client.host if request.client else '')
        db.add(AuditLog(user_id=(user.id if user else None),utilisateur=(user.username if user else ''),role=(user.role if user else ''),action=action[:220],objet_type=(objet_type or '')[:100],objet_id=str(objet_id or '')[:100],resume=(resume or '')[:3000],adresse_ip=ip[:100],user_agent=(request.headers.get('user-agent') or '')[:500],succes=bool(succes)))
        db.commit()
    except Exception:
        db.rollback()

@app.middleware('http')
async def audit_write_requests(request:Request,call_next):
    # Journalise les opérations d'écriture sans lire ni stocker le corps des formulaires.
    method=request.method.upper(); path=request.url.path
    before_user_id=None; before_username=''; before_role=''
    try:
        session=request.scope.get('session') or {}
        before_user_id=session.get('user_id')
        if before_user_id:
            with SessionLocal() as adb:
                au=adb.get(User,int(before_user_id))
                if au:before_username=au.username;before_role=au.role
    except Exception:pass
    response=await call_next(request)
    if method in {'POST','PUT','PATCH','DELETE'} and path not in {'/assistant/local-payload'}:
        try:
            session=request.scope.get('session') or {}
            uid=session.get('user_id') or before_user_id
            with SessionLocal() as adb:
                user=adb.get(User,int(uid)) if uid else None
                if not user and before_user_id:
                    class _U:pass
                    user=_U();user.id=before_user_id;user.username=before_username;user.role=before_role
                pieces=[p for p in path.split('/') if p]
                obj_type=pieces[0] if pieces else 'application'
                obj_id=next((p for p in pieces[1:] if p.isdigit()),'')
                audit_add(adb,request,user,f'{method} {path}',obj_type,obj_id,f'HTTP {response.status_code}',response.status_code<400)
        except Exception:pass
    return response

@app.middleware('http')
async def security_headers(request:Request,call_next):
    response=await call_next(request)
    response.headers.setdefault('X-Content-Type-Options','nosniff')
    response.headers.setdefault('X-Frame-Options','SAMEORIGIN')
    response.headers.setdefault('Referrer-Policy','same-origin')
    response.headers.setdefault('Permissions-Policy','geolocation=(), microphone=(), camera=()')
    response.headers.setdefault('Cache-Control','no-store' if request.url.path.startswith(('/login','/administration','/permissions','/parametres','/sauvegardes','/securite')) else 'private, max-age=0, must-revalidate')
    return response

def ensure_itesa_supplier(db):
    row=db.scalar(select(Supplier).where(func.lower(Supplier.nom)=='itesa'))
    changed=False
    if not row:
        row=Supplier(nom='ITESA',contact='Service professionnel',email='contact@itesa.eu',telephone='04 91 09 17 97',site_web='https://boutique.itesa.eu',actif=True)
        db.add(row);changed=True
    else:
        if not row.site_web: row.site_web='https://boutique.itesa.eu';changed=True
    conn=db.scalar(select(ExternalBusinessConnector).where(ExternalBusinessConnector.provider=='ITESA'))
    if not conn:
        db.add(ExternalBusinessConnector(provider='ITESA',nom='ITESA Boutique Pro',base_url='https://boutique.itesa.eu',api_mode='Catalogue public + import compte',username='',secret_env_var='',actif=True,last_status='Prêt',last_message='Catalogue public accessible ; prix professionnels soumis à connexion ITESA.',notes='Ne jamais stocker le mot de passe ITESA dans NOX-IA. Utiliser un flux/API/EDI ou un export de compte autorisé.'))
        changed=True
    if changed: db.commit()

def bootstrap_database():
    Base.metadata.create_all(bind=engine)
    username=os.environ.get('NOXIA_ADMIN_USERNAME','admin').strip() or 'admin'; password=os.environ.get('NOXIA_ADMIN_PASSWORD','').strip()
    with SessionLocal() as db:
        if password and not db.scalar(select(User).where(User.username==username)):
            db.add(User(username=username,password_hash=hash_password(password),role='Administrateur',active=True));db.commit()
        ensure_default_notification_rules(db)
        ensure_enterprise_defaults(db)
        ensure_default_role_permissions(db)
        ensure_itesa_supplier(db)

@app.on_event('startup')
def startup():bootstrap_database()

@app.get('/healthz')
def healthz():return {'status':'ok','app':'NOX-IA','version':APP_VERSION,'supervision':'webhook-json','notifications':'in-app','pricing':'json-csv-push','software_guidance':'multilingual-vision-versioned','commercial':'catalog-approval-xlsx-actuals-workorder','enterprise':'permissions-search-backup-security','operations_center':'incidents-maintenance-event-to-intervention','discovery_connectors':'inventory-evidence-methods-to-connector','equipment_fleet':'qr-profile-warranty-photos-history-maintenance','erp':'crm-purchase-invoice-email','odoo':'json2-xmlrpc-read-sync','itesa':'public-catalog-authorized-import','assistant_engine':'fluid-general-deep-memory','business_suite':'projects-helpdesk-timesheets-docs-hr-approvals','ux':'apps-kanban-chatter','odoo_power':'activities-files-signatures-studio-portal-reporting','automation_engine':'safe-rules-executable','business_plus':'contacts-finance-recruitment-leave-forms-campaigns-catalog','studio_plus':'saved-views','scroll_memory':'global-same-page'}

@app.get('/')
def root(request:Request):return RedirectResponse('/dashboard' if request.session.get('user_id') else '/login',303)

@app.get('/login')
def login_page(request:Request):
    body=f'<div class="login"><section class="card"><h1>NOX-IA</h1><p class="muted">Assistant technique intelligent.</p><form method="post" action="/login" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label class="full">Utilisateur<input name="username" required></label><label class="full">Mot de passe<input type="password" name="password" required></label><button class="btn primary full">Se connecter</button></form></section></div>'
    return page(request,None,'Connexion',body)

@app.post('/login')
def login_submit(request:Request,username:str=Form(...),password:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value)
    login_name=username.strip();ip=_client_ip(request);identity=(login_name.lower()+'|'+ip)[:150];now=datetime.utcnow()
    state=db.scalar(select(LoginSecurityState).where(LoginSecurityState.username==identity))
    if state and state.locked_until and state.locked_until>now:
        wait=max(1,math.ceil((state.locked_until-now).total_seconds()/60))
        body=f'<div class="login"><section class="card"><h1>NOX-IA</h1><div class="alert">Trop de tentatives. Réessaie dans environ {wait} minute(s).</div><form method="post" action="/login" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label class="full">Utilisateur<input name="username" required></label><label class="full">Mot de passe<input type="password" name="password" required></label><button class="btn primary full">Se connecter</button></form></section></div>'
        return page(request,None,'Connexion',body)
    u=db.scalar(select(User).where(User.username==login_name))
    valid=bool(u and u.active and verify_password(password,u.password_hash))
    if not state:
        state=LoginSecurityState(username=identity);db.add(state)
    state.last_attempt_at=now;state.last_ip=ip
    if not valid:
        state.failed_attempts=int(state.failed_attempts or 0)+1
        if state.failed_attempts>=5:
            state.locked_until=now+timedelta(minutes=10);state.failed_attempts=0
        db.commit();audit_add(db,request,None,'LOGIN_FAILED','auth','',f'Identifiant={login_name[:80]} · IP={ip}',False)
        body=f'<div class="login"><section class="card"><h1>NOX-IA</h1><div class="alert">Identifiant ou mot de passe incorrect.</div><form method="post" action="/login" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label class="full">Utilisateur<input name="username" required></label><label class="full">Mot de passe<input type="password" name="password" required></label><button class="btn primary full">Se connecter</button></form></section></div>'
        return page(request,None,'Connexion',body)
    state.failed_attempts=0;state.locked_until=None;state.last_success_at=now;db.commit();audit_add(db,request,u,'LOGIN_SUCCESS','auth',u.id,f'IP={ip}',True)
    next_path=request.session.get('post_login_next','');request.session.clear();request.session['user_id']=u.id;request.session['csrf_token']=new_csrf_token();safe_next=next_path if isinstance(next_path,str) and next_path.startswith('/') and not next_path.startswith('//') else '/dashboard';return RedirectResponse(safe_next,303)

@app.post('/logout')
def logout(request:Request,csrf_token_value:str=Form(...,alias='csrf_token')):
    check_csrf(request,csrf_token_value);request.session.clear();return RedirectResponse('/login',303)


@app.get('/dashboard')
def dashboard(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db); alerts=derive_alerts(db)
    open_quotes=db.scalars(select(Quote).where(Quote.statut.notin_(['Accepté','Refusé','Annulé']))).all()
    feedbacks=db.scalars(select(InterventionFeedback)).all()
    avg_sat=(sum(f.note for f in feedbacks)/len(feedbacks)) if feedbacks else None
    supervision_open=db.scalar(select(func.count(ConnectorEvent.id)).where(ConnectorEvent.statut!='Fermée')) or 0
    counts={
        'Interventions ouvertes':db.scalar(select(func.count(Intervention.id)).where(Intervention.statut!='Terminée')) or 0,
        'Alertes critiques':sum(1 for x in alerts if x[0]=='critique'),
        'Supervision ouverte':supervision_open,
        'Stock bas / rupture':sum(1 for x in alerts if x[1]=='Stock'),
        'Devis en cours':len(open_quotes),
        'Satisfaction':(f'{avg_sat:.1f}/5' if avg_sat is not None else '—'),
        'Maintenances à traiter':sum(1 for x in alerts if x[1]=='Maintenance'),
        'Contrats à traiter':sum(1 for x in alerts if x[1]=='Contrats'),
    }
    metrics=''.join(f'<div class="metric"><span>{escape(k)}</span><strong>{v}</strong></div>' for k,v in counts.items())
    rec=db.scalars(select(Intervention).order_by(Intervention.date_creation.desc()).limit(8)).all();rows=''
    for i in rec:
        s=db.get(Site,i.site_id);rows+=f'<tr><td><a href="/interventions/{i.id}">#{i.id}</a></td><td>{dfr(i.date_creation)}</td><td>{escape(s.nom if s else "—")}</td><td>{escape(i.technicien)}</td><td>{badge(i.priorite)}</td><td>{badge(i.statut)}</td></tr>'
    critical=[x for x in alerts if x[0]=='critique'][:6]
    critical_html=''.join(f'<div class="software-help-card"><b>{escape(x[1])} · {escape(x[3])}</b><div class="muted">{escape(x[4])}</div></div>' for x in critical) or '<span class="muted">Aucune alerte critique.</span>'
    return page(request,u,'Tableau de bord',f'<div class="head"><div><h1>Tableau de bord</h1><p class="muted">Vue opérationnelle de NOX-IA : technique, supervision, stock, commercial et qualité.</p></div><a class="btn primary" href="/assistant">Demander à NOX-IA</a></div><div class="grid g4">{metrics}</div><div class="grid g2"><section class="card"><h2>À traiter en priorité</h2><div class="software-results">{critical_html}</div></section><section class="card"><h2>Interventions récentes</h2><div class="scroll"><table><tr><th>ID</th><th>Date</th><th>Site</th><th>Technicien</th><th>Priorité</th><th>Statut</th></tr>{rows or "<tr><td colspan=6>Aucune intervention.</td></tr>"}</table></div></section></div>')

@app.get('/clients')
def clients(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db)
    rows=db.scalars(select(Client).order_by(Client.nom)).all()
    trs=''
    for c in rows:
        actions='—'
        if u.role in MANAGERS:
            label='Réactiver' if not c.actif else 'Archiver'
            cls='goodbtn' if not c.actif else 'dangerbtn'
            actions=(f'<form method="post" action="/clients/{c.id}/etat" onsubmit="return confirm(\'Confirmer cette modification ?\')">'
                     f'<input type="hidden" name="csrf_token" value="{csrf_token(request)}">'
                     f'<button class="btn small {cls}">{label}</button></form>')
        trs+=f'<tr><td>{c.id}</td><td>{escape(c.nom)}</td><td>{escape(c.contact)}</td><td>{escape(c.telephone)}</td><td>{escape(c.email)}</td><td>{badge("Actif" if c.actif else "Archivé")}</td><td>{actions}</td></tr>'
    form=''
    if u.role in MANAGERS:
        form=f'<section class="card"><h2>Ajouter un client</h2><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Nom<input name="nom" required></label><label>Contact<input name="contact"></label><label>Téléphone<input name="telephone"></label><label>E-mail<input name="email" type="email"></label><label class="full">Notes<textarea name="notes"></textarea></label><button class="btn primary">Ajouter</button></form></section>'
    return page(request,u,'Clients',f'<h1>Clients</h1>{form}<section class="card"><div class="scroll"><table><tr><th>ID</th><th>Nom</th><th>Contact</th><th>Téléphone</th><th>E-mail</th><th>Statut</th><th>Actions</th></tr>{trs or "<tr><td colspan=7>Aucun client.</td></tr>"}</table></div></section>')

@app.post('/clients')
def clients_add(request:Request,nom:str=Form(...),contact:str=Form(''),telephone:str=Form(''),email:str=Form(''),notes:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS)
    db.add(Client(nom=nom.strip(),contact=contact.strip(),telephone=telephone.strip(),email=email.strip(),notes=notes.strip(),actif=True));db.commit()
    return RedirectResponse('/clients?msg=Client+ajouté',303)

@app.post('/clients/{cid}/etat')
def client_toggle(cid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS)
    c=db.get(Client,cid)
    if not c: raise HTTPException(404,'Client introuvable')
    c.actif=not c.actif
    if not c.actif:
        site_ids=list(db.scalars(select(Site.id).where(Site.client_id==cid)).all())
        db.execute(Site.__table__.update().where(Site.client_id==cid).values(actif=False))
        if site_ids:
            db.execute(Equipement.__table__.update().where(Equipement.site_id.in_(site_ids)).values(actif=False))
    db.commit()
    return RedirectResponse('/clients?msg='+('Client+réactivé' if c.actif else 'Client+archivé'),303)

@app.get('/sites')
def sites(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(Site).order_by(Site.nom)).all();clients_=db.scalars(select(Client).where(Client.actif.is_(True)).order_by(Client.nom)).all();trs=''
    for site in rows:
        c=db.get(Client,site.client_id)
        actions='—'
        if u.role in MANAGERS:
            label='Réactiver' if not site.actif else 'Archiver';cls='goodbtn' if not site.actif else 'dangerbtn'
            actions=(f'<form method="post" action="/sites/{site.id}/etat" onsubmit="return confirm(\'Confirmer cette modification ?\')"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn small {cls}">{label}</button></form>')
        trs+=f'<tr><td>{site.id}</td><td>{escape(c.nom if c else "—")}</td><td>{escape(site.nom)}</td><td>{escape(site.ville)}</td><td>{escape(site.adresse)}</td><td>{badge("Actif" if site.actif else "Archivé")}</td><td>{actions}</td></tr>'
    form=''
    if u.role in MANAGERS:
        if clients_:
            form=f'<section class="card"><h2>Ajouter un site</h2><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Client<select name="client_id" required>{option_rows(clients_,lambda x:x.id,lambda x:x.nom)}</select></label><label>Nom<input name="nom" required></label><label>Adresse<input name="adresse"></label><label>Ville<input name="ville"></label><label class="full">Notes<textarea name="notes"></textarea></label><button class="btn primary">Ajouter</button></form></section>'
        else:
            form='<section class="card"><h2>Ajouter un site</h2><div class="alert">Aucun client actif. Crée ou réactive d’abord un client.</div><div style="margin-top:12px"><a class="btn primary" href="/clients">Ouvrir Clients</a></div></section>'
    return page(request,u,'Sites',f'<h1>Sites</h1>{form}<section class="card"><div class="scroll"><table><tr><th>ID</th><th>Client</th><th>Site</th><th>Ville</th><th>Adresse</th><th>Statut</th><th>Actions</th></tr>{trs or "<tr><td colspan=7>Aucun site.</td></tr>"}</table></div></section>')

@app.post('/sites')
def sites_add(request:Request,client_id:int=Form(...),nom:str=Form(...),adresse:str=Form(''),ville:str=Form(''),notes:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS)
    c=db.get(Client,client_id)
    if not c or not c.actif: raise HTTPException(409,'Le client doit être actif')
    db.add(Site(client_id=client_id,nom=nom.strip(),adresse=adresse.strip(),ville=ville.strip(),notes=notes.strip(),actif=True));db.commit()
    return RedirectResponse('/sites?msg=Site+ajouté',303)

@app.post('/sites/{sid}/etat')
def site_toggle(sid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS)
    site=db.get(Site,sid)
    if not site: raise HTTPException(404,'Site introuvable')
    if not site.actif:
        parent=db.get(Client,site.client_id)
        if not parent or not parent.actif: raise HTTPException(409,'Réactive d’abord le client de ce site')
    site.actif=not site.actif
    if not site.actif:
        db.execute(Equipement.__table__.update().where(Equipement.site_id==sid).values(actif=False))
    db.commit()
    return RedirectResponse('/sites?msg='+('Site+réactivé' if site.actif else 'Site+archivé'),303)

def _equipment_profile(db,eid,create=False,user=''):
    p=db.scalar(select(EquipmentAssetProfile).where(EquipmentAssetProfile.equipement_id==eid))
    if not p and create:
        p=EquipmentAssetProfile(equipement_id=eid,updated_by=user,updated_at=datetime.utcnow());db.add(p);db.flush()
    return p

def _date_or_none(value):
    value=(value or '').strip()
    if not value:return None
    try:return date.fromisoformat(value)
    except Exception:raise HTTPException(400,'Date invalide')

def _equipment_history_add(db,eid,title,detail='',event_type='Information',source='NOX-IA',user='',intervention_id=None):
    db.add(EquipmentHistoryEntry(equipement_id=eid,intervention_id=intervention_id,event_type=event_type,title=(title or 'Événement')[:260],detail=(detail or '')[:12000],source=(source or 'NOX-IA')[:100],utilisateur=(user or '')[:150]))

def _equipment_completeness(e,p):
    values=[e.reference,e.type_equipement,e.marque,e.modele,e.numero_serie,e.ip]
    if p: values += [p.emplacement,p.mac_address,p.firmware_version,p.installation_date,p.warranty_end,p.criticite]
    total=len(values);filled=sum(1 for x in values if x not in (None,''))
    return int(round(100*filled/max(1,total)))

def _equipment_warranty_badge(p):
    if not p or not p.warranty_end:return badge('Non renseignée')
    days=(p.warranty_end-date.today()).days
    if days<0:return badge('Garantie expirée')
    if days<=60:return badge(f'Garantie {days} j')
    return badge('Sous garantie')

def _equipment_maintenance_state(db,eid):
    plans=db.scalars(select(MaintenancePlan).where(MaintenancePlan.equipement_id==eid,MaintenancePlan.actif.is_(True)).order_by(MaintenancePlan.prochaine_echeance)).all()
    if not plans:return ('Non planifiée',None,plans)
    nxt=plans[0];days=(nxt.prochaine_echeance-date.today()).days
    if days<0:return ('En retard',days,plans)
    if days<=30:return ('≤30 jours',days,plans)
    return ('Planifiée',days,plans)

@app.get('/equipements')
def equipements(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);all_rows=db.scalars(select(Equipement).order_by(Equipement.reference)).all();sites_=db.scalars(select(Site).where(Site.actif.is_(True)).order_by(Site.nom)).all();q=(request.query_params.get('q') or '').strip().lower();rows=[]
    for e in all_rows:
        p=_equipment_profile(db,e.id)
        hay=' '.join([e.reference,e.type_equipement,e.marque,e.modele,e.numero_serie,e.ip,(p.asset_tag if p else ''),(p.emplacement if p else ''),(p.zone if p else ''),(p.mac_address if p else ''),(p.firmware_version if p else '')]).lower()
        if q and q not in hay:continue
        rows.append((e,p))
    active=sum(1 for e in all_rows if e.actif)
    failures=sum(1 for e in all_rows if e.actif and (e.statut or '').lower() in {'en panne','hors service','dégradé','degrade'})
    warranty_soon=0;maintenance_due=0;missing_firmware=0
    for e in all_rows:
        if not e.actif:continue
        p=_equipment_profile(db,e.id)
        if p and p.warranty_end and 0 <= (p.warranty_end-date.today()).days <= 60:warranty_soon+=1
        state,days,_=_equipment_maintenance_state(db,e.id)
        if state in ('En retard','≤30 jours'):maintenance_due+=1
        if not p or not p.firmware_version:missing_firmware+=1
    trs=''
    for e,p in rows:
        site=db.get(Site,e.site_id);c=db.get(Client,site.client_id) if site else None;maint,days,_=_equipment_maintenance_state(db,e.id);comp=_equipment_completeness(e,p)
        actions='—'
        if u.role in MANAGERS:
            label='Réactiver' if not e.actif else 'Archiver';cls='goodbtn' if not e.actif else 'dangerbtn';actions=f'<form method="post" action="/equipements/{e.id}/etat" onsubmit="return confirm(\'Confirmer cette modification ?\')"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn small {cls}">{label}</button></form>'
        trs+=f'<tr><td><a href="/equipements/{e.id}"><b>{escape(e.reference)}</b></a><div class="muted">{escape(p.asset_tag if p and p.asset_tag else "")}</div></td><td>{escape(c.nom if c else "—")}</td><td>{escape(site.nom if site else "—")}<div class="muted">{escape(p.emplacement if p else "")}</div></td><td>{escape((e.marque+" "+e.modele).strip() or e.type_equipement)}</td><td>{badge(e.statut)}</td><td>{_equipment_warranty_badge(p)}</td><td>{badge(maint)}</td><td>{comp}%</td><td>{actions}</td></tr>'
    form=''
    if u.role in MANAGERS:
        if sites_:
            form=f'<section class="card"><h2>Ajouter au parc</h2><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Site<select name="site_id" required>{option_rows(sites_,lambda x:x.id,lambda x:x.nom)}</select></label><label>Référence parc<input name="reference" required placeholder="EQ-0001"></label><label>Type<input name="type_equipement" required></label><label>Marque<input name="marque"></label><label>Modèle<input name="modele"></label><label>N° série<input name="numero_serie"></label><label>IP<input name="ip"></label><label>Statut<select name="statut_equipement"><option>Actif</option><option>En panne</option><option>Hors service</option></select></label><button class="btn primary">Ajouter</button></form></section>'
        else:form='<section class="card"><div class="alert">Aucun site actif. Crée ou réactive d’abord un site.</div></section>'
    metrics=f'<div class="asset-grid"><div class="asset-kpi"><span>Équipements actifs</span><strong>{active}</strong></div><div class="asset-kpi"><span>En panne / hors service</span><strong>{failures}</strong></div><div class="asset-kpi"><span>Garanties ≤ 60 j</span><strong>{warranty_soon}</strong></div><div class="asset-kpi"><span>Maintenances à traiter</span><strong>{maintenance_due}</strong></div><div class="asset-kpi"><span>Firmware non renseigné</span><strong>{missing_firmware}</strong></div></div>'
    search=f'<section class="card"><form method="get" class="inline-form"><input name="q" value="{escape(q,quote=True)}" placeholder="Référence, série, IP, emplacement, firmware…" style="min-width:320px"><button class="btn">Rechercher</button><a class="btn" href="/equipements">Effacer</a></form></section>'
    return page(request,u,'Parc matériel',f'<div class="head"><div><h1>Parc matériel</h1><p class="muted">Inventaire installé, garanties, firmware, QR codes, photos, maintenance et historique terrain.</p></div><a class="btn" href="/maintenance">Maintenance préventive</a></div>{metrics}{search}{form}<section class="card"><div class="scroll"><table><tr><th>Réf / asset</th><th>Client</th><th>Site / emplacement</th><th>Matériel</th><th>État</th><th>Garantie</th><th>Maintenance</th><th>Fiche</th><th></th></tr>{trs or "<tr><td colspan=9>Aucun équipement.</td></tr>"}</table></div></section>')

@app.post('/equipements')
def equipements_add(request:Request,site_id:int=Form(...),reference:str=Form(...),type_equipement:str=Form(...),marque:str=Form(''),modele:str=Form(''),numero_serie:str=Form(''),ip:str=Form(''),statut_equipement:str=Form('Actif'),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);site=db.get(Site,site_id)
    if not site or not site.actif:raise HTTPException(409,'Le site doit être actif')
    ref=reference.strip()
    if db.scalar(select(Equipement).where(Equipement.reference==ref)):raise HTTPException(409,'Cette référence équipement existe déjà')
    e=Equipement(site_id=site_id,reference=ref,type_equipement=type_equipement.strip(),marque=marque.strip(),modele=modele.strip(),numero_serie=numero_serie.strip(),ip=ip.strip(),statut=statut_equipement,actif=True);db.add(e);db.flush();_equipment_profile(db,e.id,True,u.username);_equipment_history_add(db,e.id,'Équipement ajouté au parc',f'{e.marque} {e.modele} · site #{site_id}','Création','NOX-IA',u.username);db.commit();return RedirectResponse(f'/equipements/{e.id}?msg=Équipement+ajouté',303)

@app.post('/equipements/{eid}/etat')
def equipement_toggle(eid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);e=db.get(Equipement,eid)
    if not e:raise HTTPException(404,'Équipement introuvable')
    if not e.actif:
        site=db.get(Site,e.site_id)
        if not site or not site.actif:raise HTTPException(409,'Réactive d’abord le site de cet équipement')
    e.actif=not e.actif;_equipment_history_add(db,e.id,'Fiche réactivée' if e.actif else 'Fiche archivée','', 'Administration','NOX-IA',u.username);db.commit();return RedirectResponse(f'/equipements/{eid}?msg='+('Équipement+réactivé' if e.actif else 'Équipement+archivé'),303)

@app.get('/equipements/{eid}')
def equipement_detail(eid:int,request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);e=db.get(Equipement,eid)
    if not e:raise HTTPException(404)
    p=_equipment_profile(db,eid,False);s=db.get(Site,e.site_id);c=db.get(Client,s.client_id) if s else None;ints=db.scalars(select(Intervention).where(Intervention.equipement_id==eid).order_by(Intervention.date_creation.desc()).limit(100)).all();diags=db.scalars(select(Diagnostic).where(Diagnostic.equipement_id==eid).order_by(Diagnostic.date_debut.desc()).limit(100)).all();photos=db.scalars(select(EquipmentPhoto).where(EquipmentPhoto.equipement_id==eid).order_by(EquipmentPhoto.created_at.desc()).limit(50)).all();hist=db.scalars(select(EquipmentHistoryEntry).where(EquipmentHistoryEntry.equipement_id==eid).order_by(EquipmentHistoryEntry.created_at.desc()).limit(100)).all();events=db.scalars(select(ConnectorEvent).where(ConnectorEvent.equipement_id==eid).order_by(ConnectorEvent.date_evenement.desc()).limit(50)).all();maint_state,maint_days,plans=_equipment_maintenance_state(db,eid);stock_items=db.scalars(select(StockItem).where(StockItem.actif.is_(True)).order_by(StockItem.designation)).all()
    rec={}
    for i in ints:
        k=(i.probleme or '').strip().lower()[:80]
        if k:rec[k]=rec.get(k,0)+1
    mem=''.join(f'<li>{escape(k)} — {v} occurrence(s)</li>' for k,v in sorted(rec.items(),key=lambda x:x[1],reverse=True)[:5]) or '<li>Aucune récurrence détectée.</li>'
    comp=_equipment_completeness(e,p);firmware=(p.firmware_version if p else '') or 'Non renseigné';location=' · '.join(x for x in [(p.emplacement if p else ''),(p.zone if p else ''),(p.baie_coffret if p else '')] if x) or 'Non renseigné'
    top=f'''<div class="head"><div><h1>{escape(e.reference)}</h1><p class="muted">{escape((e.marque+' '+e.modele).strip() or e.type_equipement)} · {escape(s.nom if s else 'site inconnu')} · {badge(e.statut)}</p></div><div class="actions"><a class="btn" href="/equipements">Parc matériel</a><a class="btn" href="/equipements/{eid}/etiquette" target="_blank">Imprimer QR</a><a class="btn primary" href="/interventions?equipement_id={eid}">Interventions</a></div></div>'''
    summary=f'''<div class="asset-grid"><div class="asset-kpi"><span>Complétude fiche</span><strong>{comp}%</strong><div class="completeness"><span style="width:{comp}%"></span></div></div><div class="asset-kpi"><span>Garantie</span><strong>{escape(dfr(p.warranty_end) if p and p.warranty_end else '—')}</strong>{_equipment_warranty_badge(p)}</div><div class="asset-kpi"><span>Maintenance</span><strong>{escape(maint_state)}</strong><div class="muted">{(str(maint_days)+' j') if maint_days is not None else 'aucun plan'}</div></div><div class="asset-kpi"><span>Firmware</span><strong style="font-size:18px">{escape(firmware)}</strong></div><div class="asset-kpi"><span>Criticité</span><strong style="font-size:18px">{escape(p.criticite if p else 'Normale')}</strong></div></div>'''
    base_card=f'''<section class="card"><div class="grid g2"><div><h2>Identité & localisation</h2><div class="kv"><b>Client</b><span>{escape(c.nom if c else '—')}</span><b>Site</b><span>{escape(s.nom if s else '—')}</span><b>Emplacement</b><span>{escape(location)}</span><b>Asset tag</b><span>{escape(p.asset_tag if p and p.asset_tag else '—')}</span><b>N° série</b><span>{escape(e.numero_serie or '—')}</span><b>IP</b><span>{escape(e.ip or '—')}</span><b>MAC</b><span>{escape(p.mac_address if p and p.mac_address else '—')}</span><b>Installation</b><span>{escape(dfr(p.installation_date) if p and p.installation_date else '—')}</span></div></div><div class="qr-box"><img src="/equipements/{eid}/qr.svg" alt="QR équipement"><div><h2>QR terrain</h2><p class="muted">À coller sur l’équipement ou l’armoire. Le scan ouvre directement cette fiche NOX-IA après connexion.</p><a class="btn primary" href="/equipements/{eid}/etiquette" target="_blank">Ouvrir l’étiquette imprimable</a></div></div></div></section>'''
    tech_form=''
    if u.role in TECHS:
        tech_form=f'''<section class="card"><h2>Profil technique</h2><form method="post" action="/equipements/{eid}/profil-technique" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Asset tag<input name="asset_tag" value="{escape(p.asset_tag if p else '',quote=True)}" placeholder="NOX-EQ-0001"></label><label>État technique<select name="statut_equipement"><option>{escape(e.statut)}</option><option>Actif</option><option>Dégradé</option><option>En panne</option><option>Hors service</option></select></label><label>N° série<input name="numero_serie" value="{escape(e.numero_serie,quote=True)}"></label><label>IP<input name="ip" value="{escape(e.ip,quote=True)}"></label><label>MAC<input name="mac_address" value="{escape(p.mac_address if p else '',quote=True)}"></label><label>Firmware<input name="firmware_version" value="{escape(p.firmware_version if p else '',quote=True)}"></label><label>Firmware vérifié le<input type="date" name="firmware_checked_at" value="{p.firmware_checked_at.isoformat() if p and p.firmware_checked_at else ''}"></label><label>Date installation<input type="date" name="installation_date" value="{p.installation_date.isoformat() if p and p.installation_date else ''}"></label><label>Emplacement<input name="emplacement" value="{escape(p.emplacement if p else '',quote=True)}" placeholder="Local technique RDC"></label><label>Zone<input name="zone" value="{escape(p.zone if p else '',quote=True)}" placeholder="Accueil / parking / porte 12"></label><label>Baie / coffret<input name="baie_coffret" value="{escape(p.baie_coffret if p else '',quote=True)}"></label><label>Criticité<select name="criticite"><option>{escape(p.criticite if p else 'Normale')}</option><option>Faible</option><option>Normale</option><option>Haute</option><option>Critique</option></select></label><label class="full">Notes techniques<textarea name="notes">{escape(p.notes if p else '')}</textarea></label><button class="btn primary">Enregistrer le profil technique</button></form></section>'''
    manager_form=''
    if u.role in MANAGERS:
        manager_form=f'''<section class="card"><h2>Achat & garantie</h2><form method="post" action="/equipements/{eid}/profil-gestion" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Référence stock liée<select name="stock_item_id">{option_rows(stock_items,lambda x:x.id,lambda x:f'{x.reference} · {x.designation}',selected=(p.stock_item_id if p else None),empty='Aucune')}</select></label><label>Fournisseur<input name="supplier_name" value="{escape(p.supplier_name if p else '',quote=True)}"></label><label>Date achat<input type="date" name="purchase_date" value="{p.purchase_date.isoformat() if p and p.purchase_date else ''}"></label><label>Fin de garantie<input type="date" name="warranty_end" value="{p.warranty_end.isoformat() if p and p.warranty_end else ''}"></label><label>Prix achat HT<input type="number" min="0" step="0.01" name="purchase_price" value="{p.purchase_price if p else 0}"></label><label>Durée de vie cible (ans)<input type="number" min="0" max="50" name="expected_lifetime_years" value="{p.expected_lifetime_years if p else 0}"></label><button class="btn primary">Enregistrer achat / garantie</button></form></section>'''
    photo_cards=''.join(f'<div class="equipment-photo"><a href="/equipements/{eid}/photos/{ph.id}" target="_blank"><img src="/equipements/{eid}/photos/{ph.id}" alt="Photo"></a><div class="cap"><b>{escape(ph.categorie)}</b><div>{escape(ph.caption or ph.filename)}</div><small>{dfr(ph.created_at)} · {escape(ph.created_by)}</small></div></div>' for ph in photos) or '<p class="muted">Aucune photo.</p>'
    photo_form=''
    if u.role in TECHS:
        photo_form=f'''<form method="post" action="/equipements/{eid}/photos" enctype="multipart/form-data" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Type<select name="categorie"><option>Vue générale</option><option>Étiquette / série</option><option>Câblage</option><option>Baie / coffret</option><option>Défaut</option><option>Après intervention</option><option>Autre</option></select></label><label>Légende<input name="caption"></label><label class="full">Photo<input type="file" name="photo" accept="image/png,image/jpeg,image/webp" required></label><button class="btn primary">Ajouter la photo</button></form>'''
    photos_section=f'<section class="card"><div class="head"><div><h2>Photos terrain</h2><p class="muted">Maximum 4 Mo par photo.</p></div></div>{photo_form}<div class="photo-grid">{photo_cards}</div></section>'
    mrows=''.join(f'<tr><td>#{mp.id}</td><td>{mp.periodicite_mois} mois</td><td>{dfr(mp.prochaine_echeance)}</td><td>{badge("En retard" if mp.prochaine_echeance<date.today() else "Planifiée")}</td><td>{escape(mp.technicien_prefere or "—")}</td><td><form method="post" action="/maintenance/{mp.id}/generer"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn small">Créer intervention</button></form></td></tr>' for mp in plans)
    maint_form=''
    if u.role in MANAGERS:
        maint_form=f'''<form method="post" action="/equipements/{eid}/maintenance" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Périodicité (mois)<input type="number" min="1" max="120" name="periodicite_mois" value="12"></label><label>Prochaine échéance<input type="date" name="prochaine_echeance" required></label><label>Technicien préféré<input name="technicien_prefere"></label><label>Priorité<select name="priorite"><option>Normale</option><option>Haute</option><option>Urgente</option></select></label><button class="btn primary">Ajouter un plan</button></form>'''
    maint_section=f'<section class="card"><h2>Maintenance préventive</h2>{maint_form}<div class="scroll"><table><tr><th>Plan</th><th>Périodicité</th><th>Échéance</th><th>État</th><th>Technicien</th><th></th></tr>{mrows or "<tr><td colspan=6>Aucun plan de maintenance.</td></tr>"}</table></div></section>'
    timeline=[]
    for h in hist:timeline.append((h.created_at,h.event_type,h.title,h.detail,h.source,h.utilisateur))
    for i in ints:timeline.append((i.date_creation,'Intervention',f'Intervention #{i.id} · {i.type_intervention}',i.probleme,'Interventions',i.technicien))
    for d in diags:timeline.append((d.date_debut,'Diagnostic',d.fiche_titre,d.conclusion or d.symptome,'Diagnostics',d.utilisateur))
    for ev in events:timeline.append((ev.date_evenement,'Supervision',ev.titre,ev.message,'Supervision',''))
    timeline=sorted(timeline,key=lambda x:x[0] or datetime.min,reverse=True)[:120]
    timeline_html=''.join(f'<div class="timeline-item"><small>{dfr(t[0])}</small><div>{badge(t[1])}</div><div><b>{escape(t[2])}</b><div>{escape((t[3] or "")[:1200])}</div><small>{escape(t[4])}{(" · "+escape(t[5])) if t[5] else ""}</small></div></div>' for t in timeline) or '<p class="muted">Aucun historique.</p>'
    history_form=''
    if u.role in TECHS:history_form=f'<form method="post" action="/equipements/{eid}/historique" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Type<select name="event_type"><option>Observation</option><option>Modification</option><option>Contrôle</option><option>Information</option></select></label><label>Titre<input name="title" required></label><label class="full">Détail<textarea name="detail"></textarea></label><button class="btn">Ajouter à l’historique</button></form>'
    history_section=f'<section class="card"><h2>Historique complet</h2>{history_form}<div class="timeline">{timeline_html}</div></section>'
    rows=''.join(f'<tr><td><a href="/interventions/{i.id}">#{i.id}</a></td><td>{dfr(i.date_creation)}</td><td>{escape(i.probleme[:100])}</td><td>{badge(i.statut)}</td><td>{escape(i.solution[:120])}</td></tr>' for i in ints) or '<tr><td colspan=5>Aucune intervention.</td></tr>';drows=''.join(f'<tr><td>#{d.id}</td><td>{dfr(d.date_debut)}</td><td>{escape(d.fiche_titre)}</td><td>{badge(d.statut)}</td><td>{escape(d.conclusion[:100])}</td></tr>' for d in diags) or '<tr><td colspan=5>Aucun diagnostic.</td></tr>'
    technical_history=f'<div class="grid g2"><section class="card"><h2>Mémoire technique</h2><ul>{mem}</ul></section><section class="card"><h2>Derniers diagnostics</h2><div class="scroll"><table><tr><th>ID</th><th>Date</th><th>Fiche</th><th>Statut</th><th>Conclusion</th></tr>{drows}</table></div></section></div><section class="card"><h2>Interventions liées</h2><div class="scroll"><table><tr><th>ID</th><th>Date</th><th>Problème</th><th>Statut</th><th>Solution</th></tr>{rows}</table></div></section>'
    return page(request,u,'Parc matériel',top+summary+base_card+tech_form+manager_form+maint_section+photos_section+history_section+technical_history)

@app.post('/equipements/{eid}/profil-technique')
def equipment_technical_profile(eid:int,request:Request,asset_tag:str=Form(''),statut_equipement:str=Form('Actif'),numero_serie:str=Form(''),ip:str=Form(''),mac_address:str=Form(''),firmware_version:str=Form(''),firmware_checked_at:str=Form(''),installation_date:str=Form(''),emplacement:str=Form(''),zone:str=Form(''),baie_coffret:str=Form(''),criticite:str=Form('Normale'),notes:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,TECHS);e=db.get(Equipement,eid)
    if not e:raise HTTPException(404)
    p=_equipment_profile(db,eid,True,u.username);old=f'{e.statut}|{e.ip}|{e.numero_serie}|{p.firmware_version}|{p.emplacement}'
    e.statut=statut_equipement[:80];e.numero_serie=numero_serie.strip()[:150];e.ip=ip.strip()[:100];p.asset_tag=asset_tag.strip()[:120];p.mac_address=mac_address.strip()[:100];p.firmware_version=firmware_version.strip()[:160];p.firmware_checked_at=_date_or_none(firmware_checked_at);p.installation_date=_date_or_none(installation_date);p.emplacement=emplacement.strip()[:220];p.zone=zone.strip()[:180];p.baie_coffret=baie_coffret.strip()[:180];p.criticite=(criticite if criticite in {'Faible','Normale','Haute','Critique'} else 'Normale');p.notes=notes.strip()[:12000];p.updated_by=u.username;p.updated_at=datetime.utcnow();new=f'{e.statut}|{e.ip}|{e.numero_serie}|{p.firmware_version}|{p.emplacement}'
    _equipment_history_add(db,eid,'Profil technique mis à jour',f'{old} → {new}','Modification','Parc matériel',u.username);db.commit();return RedirectResponse(f'/equipements/{eid}?msg=Profil+technique+enregistré',303)

@app.post('/equipements/{eid}/profil-gestion')
def equipment_management_profile(eid:int,request:Request,stock_item_id:str=Form(''),supplier_name:str=Form(''),purchase_date:str=Form(''),warranty_end:str=Form(''),purchase_price:float=Form(0),expected_lifetime_years:int=Form(0),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);e=db.get(Equipement,eid)
    if not e:raise HTTPException(404)
    p=_equipment_profile(db,eid,True,u.username);p.stock_item_id=int(stock_item_id) if stock_item_id else None;p.supplier_name=supplier_name.strip()[:220];p.purchase_date=_date_or_none(purchase_date);p.warranty_end=_date_or_none(warranty_end);p.purchase_price=max(0,float(purchase_price));p.expected_lifetime_years=max(0,min(50,int(expected_lifetime_years)));p.updated_by=u.username;p.updated_at=datetime.utcnow();_equipment_history_add(db,eid,'Informations achat / garantie mises à jour',f'Garantie : {dfr(p.warranty_end) if p.warranty_end else "—"} · fournisseur : {p.supplier_name or "—"}','Gestion','Parc matériel',u.username);db.commit();return RedirectResponse(f'/equipements/{eid}?msg=Achat+et+garantie+enregistrés',303)

@app.post('/equipements/{eid}/maintenance')
def equipment_maintenance_add(eid:int,request:Request,periodicite_mois:int=Form(12),prochaine_echeance:str=Form(...),technicien_prefere:str=Form(''),priorite:str=Form('Normale'),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);e=db.get(Equipement,eid)
    if not e:raise HTTPException(404)
    due=_date_or_none(prochaine_echeance)
    if not due:raise HTTPException(400,'Échéance requise')
    mp=MaintenancePlan(equipement_id=eid,periodicite_mois=max(1,min(120,periodicite_mois)),prochaine_echeance=due,technicien_prefere=technicien_prefere.strip()[:150],priorite=priorite[:50],notes='',actif=True);db.add(mp);_equipment_history_add(db,eid,'Plan de maintenance créé',f'{mp.periodicite_mois} mois · prochaine échéance {dfr(due)}','Maintenance','Parc matériel',u.username);db.commit();return RedirectResponse(f'/equipements/{eid}?msg=Maintenance+planifiée',303)

@app.post('/equipements/{eid}/photos')
async def equipment_photo_add(eid:int,request:Request,categorie:str=Form('Vue générale'),caption:str=Form(''),photo:UploadFile=File(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,TECHS);e=db.get(Equipement,eid)
    if not e:raise HTTPException(404)
    mime=(photo.content_type or '').lower()
    if mime not in {'image/jpeg','image/png','image/webp'}:raise HTTPException(400,'Format image accepté : JPG, PNG ou WebP')
    data=await photo.read(4*1024*1024+1)
    if not data:raise HTTPException(400,'Photo vide')
    if len(data)>4*1024*1024:raise HTTPException(413,'Photo trop volumineuse (4 Mo maximum)')
    ph=EquipmentPhoto(equipement_id=eid,categorie=categorie[:80],caption=caption.strip()[:500],filename=(photo.filename or 'photo')[:260],mime_type=mime,data=data,created_by=u.username);db.add(ph);_equipment_history_add(db,eid,'Photo terrain ajoutée',f'{categorie} · {caption or photo.filename}','Photo','Parc matériel',u.username);db.commit();return RedirectResponse(f'/equipements/{eid}?msg=Photo+ajoutée',303)

@app.get('/equipements/{eid}/photos/{pid}')
def equipment_photo_get(eid:int,pid:int,request:Request,db:Session=Depends(get_db)):
    require_login(request,db);ph=db.get(EquipmentPhoto,pid)
    if not ph or ph.equipement_id!=eid:raise HTTPException(404)
    return Response(bytes(ph.data),media_type=ph.mime_type or 'application/octet-stream',headers={'Content-Disposition':f'inline; filename="{(ph.filename or "photo").replace(chr(34),"")}"'})

@app.post('/equipements/{eid}/historique')
def equipment_history_manual(eid:int,request:Request,event_type:str=Form('Observation'),title:str=Form(...),detail:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,TECHS)
    if not db.get(Equipement,eid):raise HTTPException(404)
    _equipment_history_add(db,eid,title.strip(),detail.strip(),event_type[:80],'Terrain',u.username);db.commit();return RedirectResponse(f'/equipements/{eid}?msg=Historique+mis+à+jour',303)

@app.get('/scan/equipement/{eid}')
def equipment_scan_entry(eid:int,request:Request,db:Session=Depends(get_db)):
    e=db.get(Equipement,eid)
    if not e:raise HTTPException(404,'Équipement introuvable')
    if request.session.get('user_id'):return RedirectResponse(f'/equipements/{eid}?source=qr',303)
    request.session['post_login_next']=f'/equipements/{eid}?source=qr'
    return RedirectResponse('/login',303)

@app.get('/equipements/{eid}/qr.svg')
def equipment_qr(eid:int,request:Request,db:Session=Depends(get_db)):
    require_login(request,db);e=db.get(Equipement,eid)
    if not e:raise HTTPException(404)
    from reportlab.graphics.barcode.qr import QrCodeWidget
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics import renderSVG
    target=str(request.base_url).rstrip('/')+f'/scan/equipement/{eid}'
    qr=QrCodeWidget(target);b=qr.getBounds();w=max(1,b[2]-b[0]);h=max(1,b[3]-b[1]);size=220;drawing=Drawing(size,size,transform=[size/w,0,0,size/h,0,0]);drawing.add(qr);svg=renderSVG.drawToString(drawing)
    return Response(svg.encode('utf-8'),media_type='image/svg+xml',headers={'Cache-Control':'private, max-age=3600'})

@app.get('/equipements/{eid}/etiquette')
def equipment_label(eid:int,request:Request,db:Session=Depends(get_db)):
    require_login(request,db);e=db.get(Equipement,eid)
    if not e:raise HTTPException(404)
    p=_equipment_profile(db,eid);s=db.get(Site,e.site_id);company=get_setting(db,'company_name','NOXIA Groupe')
    loc=' · '.join(x for x in [(p.emplacement if p else ''),(p.zone if p else '')] if x) or (s.nom if s else '')
    html=f'''<!doctype html><html lang="fr"><head><meta charset="utf-8"><title>Étiquette {escape(e.reference)}</title><style>body{{font-family:Arial,sans-serif;margin:24px;color:#111}}.label{{width:92mm;min-height:54mm;border:2px solid #111;border-radius:10px;padding:10mm;display:grid;grid-template-columns:36mm 1fr;gap:7mm;align-items:center}}img{{width:34mm;height:34mm}}h1{{font-size:18px;margin:0 0 4px}}p{{margin:3px 0;font-size:12px}}.ref{{font-size:22px;font-weight:800}}button{{margin-bottom:15px;padding:10px 14px}}@media print{{button{{display:none}}body{{margin:0}}}}</style></head><body><button onclick="window.print()">Imprimer</button><div class="label"><img src="/equipements/{eid}/qr.svg"><div><h1>{escape(company)}</h1><div class="ref">{escape(e.reference)}</div><p>{escape((e.marque+' '+e.modele).strip() or e.type_equipement)}</p><p>S/N : {escape(e.numero_serie or '—')}</p><p>{escape(loc or '—')}</p><p>Scan → fiche NOX-IA</p></div></div></body></html>'''
    return HTMLResponse(html)

@app.get('/interventions')
def interventions(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(Intervention).order_by(Intervention.date_creation.desc())).all();sites_=db.scalars(select(Site).where(Site.actif.is_(True)).order_by(Site.nom)).all();eqs=db.scalars(select(Equipement).where(Equipement.actif.is_(True)).order_by(Equipement.reference)).all();trs=''
    for i in rows:
        s=db.get(Site,i.site_id);c=db.get(Client,s.client_id) if s else None;e=db.get(Equipement,i.equipement_id) if i.equipement_id else None;trs+=f'<tr><td><a href="/interventions/{i.id}">#{i.id}</a></td><td>{dfr(i.date_creation)}</td><td>{escape(c.nom if c else "—")}</td><td>{escape(s.nom if s else "—")}</td><td>{escape(e.reference if e else "—")}</td><td>{escape(i.technicien)}</td><td>{badge(i.priorite)}</td><td>{badge(i.statut)}</td></tr>'
    form=''
    if u.role in TECHS:
        if sites_:
            form=f'<section class="card"><h2>Nouvelle intervention</h2><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Site<select name="site_id" required>{option_rows(sites_,lambda x:x.id,lambda x:x.nom)}</select></label><label>Équipement<select name="equipement_id">{option_rows(eqs,lambda x:x.id,lambda x:f"{x.reference} · {x.type_equipement}",empty="Aucun équipement")}</select></label><label>Technicien<input name="technicien" value="{escape(u.username)}"></label><label>Type<select name="type_intervention"><option>Dépannage</option><option>Maintenance</option><option>Installation</option><option>Mise en service</option></select></label><label>Priorité<select name="priorite"><option>Basse</option><option selected>Normale</option><option>Haute</option><option>Urgente</option></select></label><label class="full">Problème<textarea name="probleme" required></textarea></label><button class="btn primary">Créer</button></form></section>'
        else:
            form='<section class="card"><h2>Nouvelle intervention</h2><div class="alert">Aucun site actif. Crée d’abord un client puis un site.</div><div style="margin-top:12px"><a class="btn primary" href="/clients">Commencer par un client</a></div></section>'
    return page(request,u,'Interventions',f'<h1>Interventions</h1>{form}<section class="card"><div class="scroll"><table><tr><th>ID</th><th>Date</th><th>Client</th><th>Site</th><th>Équipement</th><th>Technicien</th><th>Priorité</th><th>Statut</th></tr>{trs}</table></div></section>')

@app.post('/interventions')
def interventions_add(request:Request,site_id:int=Form(...),equipement_id:str=Form(''),technicien:str=Form(...),type_intervention:str=Form('Dépannage'),priorite:str=Form('Normale'),probleme:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,TECHS);eid=int(equipement_id) if equipement_id else None;i=Intervention(site_id=site_id,equipement_id=eid,technicien=technicien.strip(),type_intervention=type_intervention,priorite=priorite,probleme=probleme.strip(),statut='À faire');db.add(i);db.commit();db.refresh(i);return RedirectResponse(f'/interventions/{i.id}',303)

@app.get('/interventions/{iid}')
def intervention_detail(iid:int,request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);i=db.get(Intervention,iid)
    if not i:raise HTTPException(404)
    s=db.get(Site,i.site_id);c=db.get(Client,s.client_id) if s else None;e=db.get(Equipement,i.equipement_id) if i.equipement_id else None;stocks=db.scalars(select(StockItem).where(StockItem.actif.is_(True)).order_by(StockItem.designation)).all();mats=db.scalars(select(InterventionMaterial).where(InterventionMaterial.intervention_id==iid)).all();photos=db.scalars(select(InterventionPhoto).where(InterventionPhoto.intervention_id==iid)).all();diags=db.scalars(select(Diagnostic).where(Diagnostic.intervention_id==iid).order_by(Diagnostic.date_debut.desc())).all();feedback=db.scalar(select(InterventionFeedback).where(InterventionFeedback.intervention_id==iid))
    mrows=''.join(f'<tr><td>{escape((db.get(StockItem,m.stock_item_id).reference if db.get(StockItem,m.stock_item_id) else "—"))}</td><td>{escape((db.get(StockItem,m.stock_item_id).designation if db.get(StockItem,m.stock_item_id) else "—"))}</td><td>{m.quantite}</td></tr>' for m in mats);ph=''.join(f'<a class="btn small" href="/photos/{p.id}" target="_blank">{escape(p.filename)}</a>' for p in photos) or 'Aucune photo';drows=''.join(f'<tr><td><a href="/diagnostics/{d.id}">#{d.id}</a></td><td>{dfr(d.date_debut)}</td><td>{escape(d.fiche_titre)}</td><td>{badge(d.statut)}</td></tr>' for d in diags)
    edit=''
    if u.role in TECHS and i.statut!='Terminée':
        edit=f'<section class="card"><h2>Travail intervention</h2><form method="post" action="/interventions/{iid}/modifier" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Priorité<select name="priorite"><option>{escape(i.priorite)}</option><option>Basse</option><option>Normale</option><option>Haute</option><option>Urgente</option></select></label><label>Statut<select name="statut"><option>{escape(i.statut)}</option><option>À faire</option><option>En cours</option><option>En attente</option></select></label><label class="full">Problème<textarea name="probleme">{escape(i.probleme)}</textarea></label><label class="full">Actions réalisées<textarea name="actions_realisees">{escape(i.actions_realisees)}</textarea></label><label class="full">Solution<textarea name="solution">{escape(i.solution)}</textarea></label><button class="btn primary">Enregistrer</button></form></section><section class="card"><h2>Matériel / installation</h2><form method="post" action="/interventions/{iid}/materiel" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Article<select name="stock_item_id">{option_rows(stocks,lambda x:x.id,lambda x:f"{x.reference} · {x.designation} · stock {x.quantite}")}</select></label><label>Quantité<input type="number" min="1" name="quantite" value="1"></label><button class="btn primary">Utiliser</button></form></section><section class="card"><h2>Photo</h2><form method="post" action="/interventions/{iid}/photo" enctype="multipart/form-data" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Image<input type="file" accept="image/*" name="file" required></label><label>Commentaire<input name="commentaire"></label><button class="btn primary">Ajouter</button></form></section>'
    controls=''
    if i.statut!='Terminée' and u.role in TECHS:controls=f'<form method="post" action="/interventions/{iid}/cloturer"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn goodbtn">Terminer</button></form>'
    elif i.statut=='Terminée' and u.role in MANAGERS:controls=f'<form method="post" action="/interventions/{iid}/rouvrir"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn">↻ Rouvrir</button></form>'
    sat_card=(f'<section class="card"><h2>Satisfaction / bilan</h2><div class="kv"><b>Note</b><span>{feedback.note}/5</span><b>Résolu</b><span>{"Oui" if feedback.resolu else "Non"}</span><b>Point positif</b><span>{escape(feedback.point_positif or "—")}</span><b>Point négatif</b><span>{escape(feedback.point_negatif or "—")}</span></div><p class="muted">{escape(feedback.commentaire or "")}</p></section>' if feedback else '')
    sat_form=''
    if u.role in TECHS or u.role in MANAGERS:
        sat_form=f'<section class="card"><h2>{"Modifier" if feedback else "Ajouter"} le bilan de satisfaction</h2><form method="post" action="/interventions/{iid}/satisfaction" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Note / 5<input type="number" min="1" max="5" name="note" value="{feedback.note if feedback else 5}"></label><label>Résolu<select name="resolu"><option value="1"{" selected" if not feedback or feedback.resolu else ""}>Oui</option><option value="0"{" selected" if feedback and not feedback.resolu else ""}>Non</option></select></label><label>Point positif<input name="point_positif" value="{escape(feedback.point_positif if feedback else "")}"></label><label>Point négatif<input name="point_negatif" value="{escape(feedback.point_negatif if feedback else "")}"></label><label class="full">Commentaire<textarea name="commentaire">{escape(feedback.commentaire if feedback else "")}</textarea></label><button class="btn primary">Enregistrer le bilan</button></form></section>'
    body=f'<div class="head"><div><h1>Intervention #{iid}</h1><p class="muted">{escape(c.nom if c else "—")} · {escape(s.nom if s else "—")} · {escape(e.reference if e else "sans équipement")}</p></div><div class="actions"><a class="btn" href="/interventions/{iid}/rapport/client">PDF client</a><a class="btn" href="/interventions/{iid}/rapport/technique">PDF technique</a><a class="btn primary" href="/assistant?intervention_id={iid}">Assistant IA</a><a class="btn" href="/nox-core?intervention_id={iid}">NOX-Core</a>{controls}</div></div><section class="card"><div class="kv"><b>Date</b><span>{dfr(i.date_creation)}</span><b>Technicien</b><span>{escape(i.technicien)}</span><b>Priorité</b><span>{badge(i.priorite)}</span><b>Statut</b><span>{badge(i.statut)}</span></div><h3>Problème</h3><div class="pre">{escape(i.probleme)}</div><h3>Actions</h3><div class="pre">{escape(i.actions_realisees)}</div><h3>Solution</h3><div class="pre">{escape(i.solution)}</div></section>{edit}{sat_card}{sat_form}<section class="card"><h2>Matériel</h2><table><tr><th>Réf</th><th>Désignation</th><th>Qté</th></tr>{mrows}</table></section><section class="card"><h2>Photos</h2><div class="actions">{ph}</div></section><section class="card"><h2>Diagnostics</h2><a class="btn primary" href="/diagnostics/nouveau?intervention_id={iid}">Nouveau diagnostic</a><table><tr><th>ID</th><th>Date</th><th>Fiche</th><th>Statut</th></tr>{drows}</table></section>'
    return page(request,u,f'Intervention #{iid}',body)

@app.post('/interventions/{iid}/modifier')
def intervention_modify(iid:int,request:Request,probleme:str=Form(...),actions_realisees:str=Form(''),solution:str=Form(''),priorite:str=Form('Normale'),statut_intervention:str=Form(None,alias='statut'),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,TECHS);i=db.get(Intervention,iid)
    if not i or i.statut=='Terminée':raise HTTPException(409)
    i.probleme=probleme.strip();i.actions_realisees=actions_realisees.strip();i.solution=solution.strip();i.priorite=priorite;i.statut=statut_intervention or i.statut;db.commit();return RedirectResponse(f'/interventions/{iid}',303)

@app.post('/interventions/{iid}/materiel')
def intervention_material(iid:int,request:Request,stock_item_id:int=Form(...),quantite:int=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,TECHS);i=db.get(Intervention,iid);si=db.get(StockItem,stock_item_id)
    if not i or not si or i.statut=='Terminée' or quantite<=0 or si.quantite<quantite:raise HTTPException(400)
    si.quantite-=quantite
    if si.type_article=='Équipement':
        for _ in range(quantite):
            n=(db.scalar(select(func.max(Equipement.id))) or 0)+1;db.add(Equipement(site_id=i.site_id,reference=f'NOX-EQ-{n:06d}',type_equipement=si.designation,marque=si.marque,modele=si.modele,numero_serie='',ip='',statut='Actif',actif=True))
        typ='Installation équipement'
    else:
        db.add(InterventionMaterial(intervention_id=iid,stock_item_id=si.id,quantite=quantite));typ='Consommation intervention'
    db.add(StockMovement(stock_item_id=si.id,intervention_id=iid,utilisateur=u.username,type_mouvement=typ,quantite=-quantite,commentaire=''));db.commit();return RedirectResponse(f'/interventions/{iid}',303)

@app.post('/interventions/{iid}/photo')
async def intervention_photo(iid:int,request:Request,file:UploadFile=File(...),commentaire:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,TECHS);i=db.get(Intervention,iid)
    if not i or i.statut=='Terminée':raise HTTPException(409)
    data=await file.read()
    if len(data)>5_000_000 or not (file.content_type or '').startswith('image/'):raise HTTPException(400)
    db.add(InterventionPhoto(intervention_id=iid,filename=file.filename or 'photo',content_type=file.content_type or 'image/jpeg',data=data,commentaire=commentaire.strip()));db.commit();return RedirectResponse(f'/interventions/{iid}',303)

@app.get('/photos/{pid}')
def photo_get(pid:int,request:Request,db:Session=Depends(get_db)):
    require_login(request,db);p=db.get(InterventionPhoto,pid)
    if not p:raise HTTPException(404)
    return Response(p.data,media_type=p.content_type)

@app.post('/interventions/{iid}/cloturer')
def intervention_close(iid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,TECHS);i=db.get(Intervention,iid)
    if not i:raise HTTPException(404)
    i.statut='Terminée';i.date_cloture=datetime.utcnow()
    if i.equipement_id:
        for m in db.scalars(select(MaintenancePlan).where(MaintenancePlan.equipement_id==i.equipement_id,MaintenancePlan.actif.is_(True))).all():
            old=m.prochaine_echeance;new=add_months(max(old,date.today()),m.periodicite_mois);m.prochaine_echeance=new;db.add(MaintenanceHistory(maintenance_plan_id=m.id,intervention_id=i.id,ancienne_echeance=old,nouvelle_echeance=new))
    assistant_memory_learn_intervention(db,i,u)
    db.commit();return RedirectResponse(f'/interventions/{iid}',303)

@app.post('/interventions/{iid}/rouvrir')
def intervention_reopen(iid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);i=db.get(Intervention,iid)
    if not i:raise HTTPException(404)
    for h in db.scalars(select(MaintenanceHistory).where(MaintenanceHistory.intervention_id==iid)).all():
        m=db.get(MaintenancePlan,h.maintenance_plan_id)
        if m and h.ancienne_echeance:m.prochaine_echeance=h.ancienne_echeance
        db.delete(h)
    i.statut='En cours';i.date_cloture=None;db.commit();return RedirectResponse(f'/interventions/{iid}',303)


@app.post('/interventions/{iid}/satisfaction')
def intervention_satisfaction(iid:int,request:Request,note:int=Form(...),resolu:str=Form('1'),point_positif:str=Form(''),point_negatif:str=Form(''),commentaire:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,TECHS|MANAGERS);i=db.get(Intervention,iid)
    if not i:raise HTTPException(404,'Intervention introuvable')
    note=max(1,min(5,int(note)));f=db.scalar(select(InterventionFeedback).where(InterventionFeedback.intervention_id==iid))
    if not f:f=InterventionFeedback(intervention_id=iid);db.add(f)
    f.note=note;f.resolu=(resolu=='1');f.point_positif=point_positif.strip();f.point_negatif=point_negatif.strip();f.commentaire=commentaire.strip();f.source='Interne';f.date_feedback=datetime.utcnow();db.commit();return RedirectResponse(f'/interventions/{iid}?msg=Bilan+satisfaction+enregistré',303)

@app.get('/planning')
def planning(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(PlanningEntry).order_by(PlanningEntry.debut.desc())).all();ints=db.scalars(select(Intervention).where(Intervention.statut!='Terminée').order_by(Intervention.id.desc())).all();trs=''.join(f'<tr><td>{p.id}</td><td>{dfr(p.debut)}</td><td>{dfr(p.fin)}</td><td>{escape(p.titre)}</td><td>{escape(p.technicien)}</td><td>{badge(p.statut)}</td><td>{f"<a href=/interventions/{p.intervention_id}>#{p.intervention_id}</a>" if p.intervention_id else "—"}</td></tr>' for p in rows);form=''
    if u.role in MANAGERS:form=f'<section class="card"><h2>Planifier</h2><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Intervention<select name="intervention_id">{option_rows(ints,lambda x:x.id,lambda x:f"#{x.id} · {x.probleme[:60]}",empty="Aucune")}</select></label><label>Titre<input name="titre" required></label><label>Technicien<input name="technicien"></label><label>Début<input type="datetime-local" name="debut" required></label><label>Fin<input type="datetime-local" name="fin"></label><button class="btn primary">Ajouter</button></form></section>'
    return page(request,u,'Planning',f'<h1>Planning</h1>{form}<section class="card"><table><tr><th>ID</th><th>Début</th><th>Fin</th><th>Titre</th><th>Technicien</th><th>Statut</th><th>Intervention</th></tr>{trs}</table></section>')

@app.post('/planning')
def planning_add(request:Request,titre:str=Form(...),technicien:str=Form(''),debut:str=Form(...),fin:str=Form(''),intervention_id:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);db.add(PlanningEntry(intervention_id=int(intervention_id) if intervention_id else None,technicien=technicien.strip(),titre=titre.strip(),debut=datetime.fromisoformat(debut),fin=datetime.fromisoformat(fin) if fin else None,statut='Prévu',notes=''));db.commit();return RedirectResponse('/planning',303)


def latest_supplier_prices(db,stock_item_id):
    rows=db.scalars(select(SupplierPrice).where(SupplierPrice.stock_item_id==stock_item_id).order_by(SupplierPrice.date_prix.desc())).all()
    latest={}
    for row in rows:
        if row.supplier_id not in latest:latest[row.supplier_id]=row
    return list(latest.values())

def latest_market_prices(db,stock_item_id):
    rows=db.scalars(select(MarketPrice).where(MarketPrice.stock_item_id==stock_item_id).order_by(MarketPrice.date_prix.desc())).all()
    latest={}
    for row in rows:
        key=(row.source or 'Marché').strip().lower()
        if key not in latest:latest[key]=row
    return list(latest.values())

def mean_price(rows):
    vals=[float(r.prix or 0) for r in rows if float(r.prix or 0)>0]
    return (sum(vals)/len(vals)) if vals else None

@app.get('/stock')
def stock(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);items=db.scalars(select(StockItem).order_by(StockItem.designation)).all();trs=''
    for s in items:
        supplier_avg=mean_price(latest_supplier_prices(db,s.id));market_avg=mean_price(latest_market_prices(db,s.id));best,sup=best_supplier_price(db,s.id)
        best_value=float(best.prix) if best else None;gap=((best_value-market_avg)/market_avg*100) if best_value is not None and market_avg else None
        state='Rupture' if s.quantite<=0 else ('Stock bas' if s.quantite<=s.seuil_alerte else 'Disponible')
        gap_txt='—' if gap is None else f'{gap:+.1f} %';best_txt=(f'{money(best_value)}<div class="muted">{escape(sup.nom if sup else "")}</div>' if best_value is not None else '—')
        trs+=f'<tr><td>{escape(s.reference)}</td><td>{escape(s.designation)}</td><td>{escape(s.type_article)}</td><td>{escape(s.marque)}</td><td>{s.quantite}</td><td>{s.seuil_alerte}</td><td>{money(s.prix_achat)}</td><td>{best_txt}</td><td>{money(supplier_avg) if supplier_avg is not None else "—"}</td><td>{money(market_avg) if market_avg is not None else "—"}</td><td><span class="price-compare">{gap_txt}</span></td><td>{badge(state)}</td></tr>'
    form=''
    if u.role in MANAGERS:
        form=f'<section class="card"><h2>Ajouter au stock</h2><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Référence<input name="reference" required></label><label>Désignation<input name="designation" required></label><label>Type<select name="type_article"><option>Consommable</option><option>Équipement</option></select></label><label>Marque<input name="marque"></label><label>Modèle<input name="modele"></label><label>Quantité<input type="number" name="quantite" value="0"></label><label>Seuil alerte<input type="number" name="seuil_alerte" value="1"></label><label>Prix achat interne<input type="number" step="0.01" min="0" name="prix_achat" value="0"></label><button class="btn primary">Ajouter</button></form></section>'
    return page(request,u,'Stock',f'<div class="head"><div><h1>Stock & Matériel</h1><p class="muted">Comparaison achat interne, derniers prix fournisseurs et observations marché.</p></div><div class="actions"><a class="btn" href="/comparateur-prix">Comparateur</a><a class="btn" href="/fournisseurs">Fournisseurs</a><a class="btn" href="/prix-marche">Prix marché</a><a class="btn" href="/prix-sources">Sources prix</a></div></div>{form}<section class="card"><div class="scroll"><table><tr><th>Réf</th><th>Désignation</th><th>Type</th><th>Marque</th><th>Qté</th><th>Seuil</th><th>Achat interne</th><th>Meilleur fournisseur</th><th>Moy. fournisseurs</th><th>Moy. marché</th><th>Écart meilleur/marché</th><th>État</th></tr>{trs or "<tr><td colspan=12>Aucun article.</td></tr>"}</table></div></section>')

@app.post('/stock')
def stock_add(request:Request,reference:str=Form(...),designation:str=Form(...),type_article:str=Form('Consommable'),marque:str=Form(''),modele:str=Form(''),quantite:int=Form(0),seuil_alerte:int=Form(1),prix_achat:float=Form(0),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);o=StockItem(reference=reference.strip(),designation=designation.strip(),type_article=type_article,marque=marque.strip(),modele=modele.strip(),quantite=max(0,quantite),seuil_alerte=max(0,seuil_alerte),prix_achat=max(0,prix_achat),actif=True);db.add(o);db.commit();db.refresh(o);db.add(StockMovement(stock_item_id=o.id,intervention_id=None,utilisateur=u.username,type_mouvement='Stock initial',quantite=o.quantite,commentaire=''));db.commit();return RedirectResponse('/stock',303)

@app.get('/fournisseurs')
def suppliers(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);sups=db.scalars(select(Supplier).order_by(Supplier.nom)).all();items=db.scalars(select(StockItem).order_by(StockItem.designation)).all();prices=db.scalars(select(SupplierPrice).order_by(SupplierPrice.date_prix.desc()).limit(300)).all();trs=''
    for p in prices:
        s=db.get(Supplier,p.supplier_id);i=db.get(StockItem,p.stock_item_id);trs+=f'<tr><td>{escape(s.nom if s else "—")}</td><td>{escape(i.reference if i else "—")}</td><td>{escape(i.designation if i else "—")}</td><td>{money(p.prix)}</td><td>{dfr(p.date_prix)}</td></tr>'
    form=''
    if u.role in MANAGERS:
        form=f'<section class="card"><h2>Fournisseur</h2><form method="post" action="/fournisseurs/ajouter" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Nom<input name="nom" required></label><label>Contact<input name="contact"></label><label>E-mail<input name="email" type="email"></label><label>Téléphone<input name="telephone"></label><button class="btn primary">Ajouter</button></form></section><section class="card"><h2>Nouveau prix fournisseur</h2><form method="post" action="/fournisseurs/prix" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Fournisseur<select name="supplier_id">{option_rows(sups,lambda x:x.id,lambda x:x.nom)}</select></label><label>Article<select name="stock_item_id">{option_rows(items,lambda x:x.id,lambda x:f"{x.reference} · {x.designation}")}</select></label><label>Prix<input type="number" min="0" step="0.01" name="prix" required></label><button class="btn primary">Enregistrer</button></form></section>'
    return page(request,u,'Fournisseurs',f'<div class="head"><div><h1>Fournisseurs</h1><p class="muted">Les moyennes utilisent le dernier prix enregistré pour chaque fournisseur.</p></div><a class="btn" href="/stock">Voir le stock</a></div>{form}<section class="card"><div class="scroll"><table><tr><th>Fournisseur</th><th>Réf</th><th>Article</th><th>Prix</th><th>Date</th></tr>{trs or "<tr><td colspan=5>Aucun prix.</td></tr>"}</table></div></section>')

@app.post('/fournisseurs/ajouter')
def supplier_add(request:Request,nom:str=Form(...),contact:str=Form(''),email:str=Form(''),telephone:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);db.add(Supplier(nom=nom.strip(),contact=contact.strip(),email=email.strip(),telephone=telephone.strip(),site_web='',actif=True));db.commit();return RedirectResponse('/fournisseurs',303)

@app.post('/fournisseurs/prix')
def supplier_price(request:Request,supplier_id:int=Form(...),stock_item_id:int=Form(...),prix:float=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);db.add(SupplierPrice(supplier_id=supplier_id,stock_item_id=stock_item_id,prix=max(0,prix)));db.commit();return RedirectResponse('/fournisseurs',303)

@app.get('/prix-marche')
def market_prices(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);items=db.scalars(select(StockItem).order_by(StockItem.designation)).all();rows=db.scalars(select(MarketPrice).order_by(MarketPrice.date_prix.desc()).limit(400)).all();trs=''
    for p in rows:
        i=db.get(StockItem,p.stock_item_id);src=escape(p.source);link=(f'<a href="{escape(p.source_url)}" target="_blank" rel="noopener">Source</a>' if p.source_url.startswith(('http://','https://')) else '—');trs+=f'<tr><td>{dfr(p.date_prix)}</td><td>{escape(i.reference if i else "—")}</td><td>{escape(i.designation if i else "—")}</td><td>{src}</td><td>{money(p.prix)}</td><td>{link}</td></tr>'
    form=''
    if u.role in MANAGERS:
        form=f'<section class="card"><h2>Ajouter une observation marché</h2><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Article<select name="stock_item_id">{option_rows(items,lambda x:x.id,lambda x:f"{x.reference} · {x.designation}")}</select></label><label>Source<input name="source" placeholder="Distributeur / catalogue public" required></label><label>Prix observé<input type="number" step="0.01" min="0" name="prix" required></label><label>URL source<input type="url" name="source_url" placeholder="https://..."></label><button class="btn primary">Enregistrer</button></form></section>'
    return page(request,u,'Prix marché',f'<div class="head"><div><h1>Prix marché</h1><p class="muted">Historique des observations publiques manuelles et automatisées. Les sources JSON/CSV/Push alimentent cette moyenne sans ressaisie.</p></div><div class="actions"><a class="btn" href="/stock">Stock</a><a class="btn" href="/comparateur-prix">Comparateur</a><a class="btn primary" href="/prix-sources">Sources automatisées</a></div></div>{form}<section class="card"><div class="scroll"><table><tr><th>Date</th><th>Réf</th><th>Article</th><th>Source</th><th>Prix</th><th>Lien</th></tr>{trs or "<tr><td colspan=6>Aucune observation.</td></tr>"}</table></div></section>')

@app.post('/prix-marche')
def market_price_add(request:Request,stock_item_id:int=Form(...),source:str=Form(...),prix:float=Form(...),source_url:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);db.add(MarketPrice(stock_item_id=stock_item_id,source=source.strip(),source_url=source_url.strip(),prix=max(0,prix),devise='EUR'));db.commit();return RedirectResponse('/prix-marche',303)

PRICE_SOURCE_MODES=('Pull URL','Push API')
PRICE_SOURCE_CATEGORIES=('Fournisseur','Marché')
PRICE_SOURCE_FORMATS=('JSON','CSV')
PRICE_MAX_BYTES=5*1024*1024

def price_token_hash(raw):
    return hashlib.sha256(('noxia-price-v1:'+str(raw or '')).encode('utf-8')).hexdigest()

def _nested_value(obj,path,default=''):
    cur=obj
    for part in [x for x in str(path or '').split('.') if x]:
        if isinstance(cur,dict):cur=cur.get(part,default)
        else:return default
    return cur

def _price_number(value):
    if isinstance(value,(int,float)):
        return float(value)
    raw=str(value or '').strip().replace('\u00a0',' ').replace('€','').replace('$','').replace('£','')
    raw=''.join(ch for ch in raw if ch.isdigit() or ch in ',.-')
    if not raw:return None
    if ',' in raw and '.' in raw:
        if raw.rfind(',')>raw.rfind('.'):
            raw=raw.replace('.','').replace(',','.')
        else:
            raw=raw.replace(',','')
    elif ',' in raw:
        raw=raw.replace(',','.')
    try:
        n=float(raw)
        return n if n>=0 else None
    except Exception:return None

def _safe_remote_url(url):
    parsed=urlparse(str(url or '').strip())
    if parsed.scheme not in ('http','https') or not parsed.hostname:
        raise ValueError('URL HTTP/HTTPS valide requise')
    try:
        infos=socket.getaddrinfo(parsed.hostname,parsed.port or (443 if parsed.scheme=='https' else 80),type=socket.SOCK_STREAM)
    except Exception as e:
        raise ValueError(f'Hôte introuvable : {e}')
    for info in infos:
        ip=ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise ValueError('Adresse locale/privée interdite pour une source distante')
    return parsed.geturl()

def _source_headers(source):
    headers={'User-Agent':'NOX-IA/6.2 PriceSync','Accept':'application/json,text/csv,text/plain;q=0.9,*/*;q=0.5'}
    mode=(source.auth_type or 'Aucune').strip(); env=(source.auth_env_var or '').strip()
    if env:
        secret=os.environ.get(env,'')
        if mode=='Bearer env' and secret:headers['Authorization']='Bearer '+secret
        elif mode=='Header env' and secret:headers[(source.auth_header or 'X-API-Key').strip()]=secret
    return headers

def _parse_source_payload(source,raw):
    text=raw.decode('utf-8-sig',errors='replace')
    if (source.format_donnees or 'JSON').upper()=='CSV':
        return list(csv.DictReader(io.StringIO(text)))
    data=json.loads(text)
    if source.root_key:
        nested=_nested_value(data,source.root_key,None)
        if nested is not None:data=nested
    if isinstance(data,list):return data
    if isinstance(data,dict):return [data]
    raise ValueError('Le flux doit contenir une liste JSON, un objet JSON ou un CSV avec en-têtes')

class _PriceSafeRedirect(HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        _safe_remote_url(newurl)
        return super().redirect_request(req,fp,code,msg,headers,newurl)

def _fetch_price_source(source):
    safe=_safe_remote_url(source.url)
    req=UrlRequest(safe,headers=_source_headers(source),method='GET')
    opener=build_opener(_PriceSafeRedirect())
    with opener.open(req,timeout=15) as r:raw=r.read(PRICE_MAX_BYTES+1)
    if len(raw)>PRICE_MAX_BYTES:raise ValueError('Flux trop volumineux (>5 Mo)')
    return _parse_source_payload(source,raw)

def _find_stock_for_external_ref(db,source,external_ref):
    ref=str(external_ref or '').strip()
    if not ref:return None
    alias=db.scalar(select(PriceSourceAlias).where(PriceSourceAlias.source_id==source.id,func.lower(PriceSourceAlias.external_reference)==ref.lower()).order_by(PriceSourceAlias.id.desc()))
    if alias:return db.get(StockItem,alias.stock_item_id)
    return db.scalar(select(StockItem).where(func.lower(StockItem.reference)==ref.lower()))

def _price_change_notify(db,source,item,old,new,label):
    if not old or old<=0 or new<=0:return
    pct=(new-old)/old*100
    if abs(pct)<5:return
    direction='baisse' if pct<0 else 'hausse'; level='Information' if pct<0 else 'Avertissement'
    title=f'Prix {direction} · {item.reference}'; msg=f'{source.nom} : {money(old)} → {money(new)} ({pct:+.1f} %). {label}.'
    users=db.scalars(select(User).where(User.active.is_(True),User.role.in_(['Administrateur','Responsable','Commercial']))).all()
    for user in users:db.add(Notification(user_id=user.id,event_id=None,niveau=level,categorie='Prix',titre=title[:280],message=msg,lien='/comparateur-prix',lue=False))

def _ingest_price_rows(db,source,rows):
    stats={'recus':0,'correspondances':0,'importes':0,'ignores':0,'erreurs':0}
    for row in rows:
        stats['recus']+=1
        try:
            if not isinstance(row,dict):stats['ignores']+=1;continue
            external_ref=_nested_value(row,source.reference_field,''); price=_price_number(_nested_value(row,source.price_field,None))
            if not str(external_ref or '').strip() or price is None or price<=0:stats['ignores']+=1;continue
            item=_find_stock_for_external_ref(db,source,external_ref)
            if not item:stats['ignores']+=1;continue
            stats['correspondances']+=1
            if source.categorie=='Fournisseur':
                if not source.supplier_id:stats['erreurs']+=1;continue
                previous=db.scalar(select(SupplierPrice).where(SupplierPrice.supplier_id==source.supplier_id,SupplierPrice.stock_item_id==item.id).order_by(SupplierPrice.date_prix.desc()).limit(1))
                old=float(previous.prix or 0) if previous else 0
                if previous and abs(old-price)<0.0001:stats['ignores']+=1;continue
                db.add(SupplierPrice(supplier_id=source.supplier_id,stock_item_id=item.id,prix=price)); _price_change_notify(db,source,item,old,price,'Prix fournisseur')
            else:
                source_url=str(_nested_value(row,source.url_field,'') or '').strip()
                if not source_url:source_url=source.url if source.mode=='Pull URL' else ''
                previous=db.scalar(select(MarketPrice).where(MarketPrice.stock_item_id==item.id,func.lower(MarketPrice.source)==source.nom.lower()).order_by(MarketPrice.date_prix.desc()).limit(1))
                old=float(previous.prix or 0) if previous else 0
                if previous and abs(old-price)<0.0001:stats['ignores']+=1;continue
                currency=str(_nested_value(row,source.currency_field,'EUR') or 'EUR').strip()[:12]
                db.add(MarketPrice(stock_item_id=item.id,source=source.nom,source_url=source_url[:600],prix=price,devise=currency or 'EUR')); _price_change_notify(db,source,item,old,price,'Observation marché')
            stats['importes']+=1
        except Exception:stats['erreurs']+=1
    return stats

def _run_price_sync(db,source,rows=None):
    run=PriceSyncRun(source_id=source.id,statut='En cours'); db.add(run); db.commit(); db.refresh(run)
    try:
        if rows is None:rows=_fetch_price_source(source)
        stats=_ingest_price_rows(db,source,rows)
        run.recus=stats['recus'];run.correspondances=stats['correspondances'];run.importes=stats['importes'];run.ignores=stats['ignores'];run.erreurs=stats['erreurs'];run.statut='OK' if not stats['erreurs'] else 'Partiel';run.message=f"{stats['importes']} prix importé(s), {stats['ignores']} ignoré(s), {stats['erreurs']} erreur(s)."
        source.derniere_synchro=datetime.utcnow();source.statut='Synchronisé' if run.statut=='OK' else 'Partiel';db.commit()
    except Exception as e:
        db.rollback();run=db.get(PriceSyncRun,run.id);source=db.get(PriceSource,source.id);run.statut='Erreur';run.erreurs=max(1,run.erreurs or 0);run.message=str(e)[:2000];run.finished_at=datetime.utcnow();source.statut='Erreur';db.commit();return run
    run.finished_at=datetime.utcnow();db.commit();return run

def _price_source_token(request,db,sid):
    source=db.get(PriceSource,sid)
    if not source or not source.actif or source.mode!='Push API':raise HTTPException(404,'Source Push API introuvable')
    auth=request.headers.get('authorization','');raw=auth[7:].strip() if auth.lower().startswith('bearer ') else request.headers.get('x-noxia-token','').strip();cred=db.scalar(select(PriceSourceCredential).where(PriceSourceCredential.source_id==sid))
    if not raw or not cred or not hmac.compare_digest(cred.token_hash,price_token_hash(raw)):raise HTTPException(401,'Jeton source prix invalide')
    return source

def best_supplier_price(db,item_id):
    rows=latest_supplier_prices(db,item_id);valid=[r for r in rows if float(r.prix or 0)>0]
    if not valid:return None,None
    best=min(valid,key=lambda r:float(r.prix or 0));return best,db.get(Supplier,best.supplier_id)

@app.get('/comparateur-prix')
def price_comparator(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);items=db.scalars(select(StockItem).where(StockItem.actif.is_(True)).order_by(StockItem.designation)).all();rows='';covered_supplier=0;covered_market=0;below_market=0
    for item in items:
        latest_sup=latest_supplier_prices(db,item.id);sup_avg=mean_price(latest_sup);market_avg=mean_price(latest_market_prices(db,item.id));best,supplier=best_supplier_price(db,item.id)
        if best:covered_supplier+=1
        if market_avg:covered_market+=1
        gap=None
        if best and market_avg:
            gap=(float(best.prix)-market_avg)/market_avg*100
            if float(best.prix)<market_avg:below_market+=1
        if not best:rec='Prix fournisseur manquant'
        elif market_avg is None:rec='Marché à compléter'
        elif float(best.prix)<=market_avg*0.90:rec='Très bon prix'
        elif float(best.prix)<=market_avg:rec='Sous le marché'
        else:rec='Au-dessus marché'
        rows+=f'<tr><td><b>{escape(item.reference)}</b><div class="muted">{escape(item.designation)}</div></td><td>{item.quantite}</td><td>{money(item.prix_achat)}</td><td>{money(best.prix) if best else "—"}<div class="muted">{escape(supplier.nom if supplier else "")}</div></td><td>{money(sup_avg) if sup_avg is not None else "—"}</td><td>{money(market_avg) if market_avg is not None else "—"}</td><td>{(f"{gap:+.1f} %" if gap is not None else "—")}</td><td>{badge(rec)}</td></tr>'
    metrics=f'<div class="grid g4"><div class="metric"><span>Références actives</span><strong>{len(items)}</strong></div><div class="metric"><span>Couvertes fournisseurs</span><strong>{covered_supplier}</strong></div><div class="metric"><span>Couvertes marché</span><strong>{covered_market}</strong></div><div class="metric"><span>Meilleur prix sous marché</span><strong>{below_market}</strong></div></div>'
    return page(request,u,'Comparateur prix',f'<div class="head"><div><h1>Comparateur prix</h1><p class="muted">Le meilleur dernier prix fournisseur est comparé au prix achat interne et à la moyenne marché.</p></div><div class="actions"><a class="btn" href="/stock">Stock</a><a class="btn primary" href="/prix-sources">Automatiser les prix</a></div></div>{metrics}<section class="card"><div class="scroll"><table><tr><th>Référence</th><th>Stock</th><th>Achat interne</th><th>Meilleur fournisseur</th><th>Moy. fournisseurs</th><th>Moy. marché</th><th>Écart meilleur/marché</th><th>Lecture</th></tr>{rows or "<tr><td colspan=8>Aucune référence.</td></tr>"}</table></div></section>')

@app.get('/prix-sources')
def price_sources_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);sources=db.scalars(select(PriceSource).order_by(PriceSource.nom)).all();sups=db.scalars(select(Supplier).where(Supplier.actif.is_(True)).order_by(Supplier.nom)).all();items=db.scalars(select(StockItem).where(StockItem.actif.is_(True)).order_by(StockItem.designation)).all();aliases=db.scalars(select(PriceSourceAlias).order_by(PriceSourceAlias.id.desc()).limit(200)).all();runs=db.scalars(select(PriceSyncRun).order_by(PriceSyncRun.started_at.desc()).limit(100)).all();srows='';arows='';rrows=''
    for src in sources:
        sup=db.get(Supplier,src.supplier_id) if src.supplier_id else None;cred=db.scalar(select(PriceSourceCredential).where(PriceSourceCredential.source_id==src.id));entry=(f'/api/prix-sources/{src.id}/push' if src.mode=='Push API' else src.url);token=f' · jeton …{escape(cred.token_hint)}' if cred else '';actions=''
        if u.role in MANAGERS:
            if src.mode=='Pull URL':actions+=f'<form method="post" action="/prix-sources/{src.id}/synchroniser"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn small">Synchroniser</button></form>'
            else:actions+=f'<form method="post" action="/prix-sources/{src.id}/rotater"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn small">Nouveau jeton</button></form>'
        srows+=f'<tr><td><b>{escape(src.nom)}</b><div class="muted">{escape(sup.nom if sup else src.categorie)}</div></td><td>{escape(src.mode)}</td><td>{escape(src.format_donnees)}</td><td><code>{escape(entry)}</code><div class="muted">{escape(src.auth_env_var or "")}{token}</div></td><td>{badge(src.statut)}</td><td>{dfr(src.derniere_synchro)}</td><td><div class="actions">{actions}</div></td></tr>'
    for a in aliases:
        src=db.get(PriceSource,a.source_id);item=db.get(StockItem,a.stock_item_id);arows+=f'<tr><td>{escape(src.nom if src else "—")}</td><td><code>{escape(a.external_reference)}</code></td><td>{escape(item.reference if item else "—")} · {escape(item.designation if item else "")}</td></tr>'
    for run in runs:
        src=db.get(PriceSource,run.source_id);rrows+=f'<tr><td>{dfr(run.started_at)}</td><td>{escape(src.nom if src else "—")}</td><td>{badge(run.statut)}</td><td>{run.recus}</td><td>{run.correspondances}</td><td>{run.importes}</td><td>{run.ignores}</td><td>{run.erreurs}</td><td>{escape((run.message or "")[:300])}</td></tr>'
    forms=''
    if u.role in MANAGERS:
        source_options=option_rows(sources,lambda x:x.id,lambda x:x.nom)
        supplier_options=option_rows(sups,lambda x:x.id,lambda x:x.nom,empty='Aucun / marché')
        item_options=option_rows(items,lambda x:x.id,lambda x:f'{x.reference} · {x.designation}')
        token=csrf_token(request)
        forms=(f'<div class="grid g2"><section class="card"><h2>Nouvelle source automatisée</h2><p class="muted">Pull URL lit un JSON/CSV distant. Push API crée une URL NOX-IA protégée par jeton. Les secrets sont lus depuis une variable d’environnement, jamais enregistrés en clair.</p><form method="post" action="/prix-sources" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Nom<input name="nom" required placeholder="Catalogue fournisseur X"></label><label>Catégorie<select name="categorie"><option>Fournisseur</option><option>Marché</option></select></label><label>Fournisseur<select name="supplier_id">{supplier_options}</select></label><label>Mode<select name="mode"><option>Pull URL</option><option>Push API</option></select></label><label>Format<select name="format_donnees"><option>JSON</option><option>CSV</option></select></label><label>URL Pull<input name="url" type="url" placeholder="https://fournisseur.example/prices.json"></label><label>Clé racine JSON<input name="root_key" value="items"></label><label>Champ référence<input name="reference_field" value="reference"></label><label>Champ prix<input name="price_field" value="price"></label><label>Champ devise<input name="currency_field" value="currency"></label><label>Champ URL produit<input name="url_field" value="url"></label><label>Authentification<select name="auth_type"><option>Aucune</option><option>Bearer env</option><option>Header env</option></select></label><label>Variable d’environnement<input name="auth_env_var" placeholder="SUPPLIER_API_TOKEN"></label><label>Nom header<input name="auth_header" value="X-API-Key"></label><button class="btn primary">Créer la source</button></form></section><section class="card"><h2>Alias de référence</h2><p class="muted">Si le fournisseur appelle une référence différemment de NOX-IA.</p><form method="post" action="/prix-sources/alias" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Source<select name="source_id">{source_options}</select></label><label>Référence externe<input name="external_reference" required></label><label class="full">Article NOX-IA<select name="stock_item_id">{item_options}</select></label><button class="btn primary">Relier</button></form><form method="post" action="/prix-sources/synchroniser-tout"><input type="hidden" name="csrf_token" value="{token}"><button class="btn">Synchroniser toutes les sources Pull</button></form></section></div>')
    return page(request,u,'Sources prix',f'<div class="head"><div><h1>Sources prix</h1><p class="muted">Automatisation fournisseur/marché par JSON, CSV ou Push API. Une synchro alimente directement Stock, Devis et Comparateur.</p></div><a class="btn" href="/comparateur-prix">Voir le comparateur</a></div>{forms}<section class="card"><h2>Sources</h2><div class="scroll"><table><tr><th>Source</th><th>Mode</th><th>Format</th><th>Entrée</th><th>État</th><th>Dernière synchro</th><th>Action</th></tr>{srows or "<tr><td colspan=7>Aucune source.</td></tr>"}</table></div></section><div class="grid g2"><section class="card"><h2>Correspondances de références</h2><div class="scroll"><table><tr><th>Source</th><th>Réf externe</th><th>Article NOX-IA</th></tr>{arows or "<tr><td colspan=3>Aucun alias.</td></tr>"}</table></div></section><section class="card"><h2>Historique des synchronisations</h2><div class="scroll"><table><tr><th>Date</th><th>Source</th><th>État</th><th>Reçus</th><th>Match</th><th>Importés</th><th>Ignorés</th><th>Erreurs</th><th>Détail</th></tr>{rrows or "<tr><td colspan=9>Aucune synchronisation.</td></tr>"}</table></div></section></div>')

@app.post('/prix-sources')
def price_source_add(request:Request,nom:str=Form(...),categorie:str=Form('Marché'),supplier_id:str=Form(''),mode:str=Form('Pull URL'),format_donnees:str=Form('JSON'),url:str=Form(''),root_key:str=Form('items'),reference_field:str=Form('reference'),price_field:str=Form('price'),currency_field:str=Form('currency'),url_field:str=Form('url'),auth_type:str=Form('Aucune'),auth_env_var:str=Form(''),auth_header:str=Form('X-API-Key'),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS)
    if categorie not in PRICE_SOURCE_CATEGORIES or mode not in PRICE_SOURCE_MODES or format_donnees not in PRICE_SOURCE_FORMATS:raise HTTPException(400,'Configuration source invalide')
    if categorie=='Fournisseur' and not supplier_id:raise HTTPException(400,'Choisis un fournisseur pour une source fournisseur')
    if mode=='Pull URL':
        try:_safe_remote_url(url)
        except ValueError as e:raise HTTPException(400,str(e))
    src=PriceSource(nom=nom.strip(),categorie=categorie,supplier_id=(int(supplier_id) if supplier_id else None),mode=mode,format_donnees=format_donnees,url=url.strip(),root_key=root_key.strip(),reference_field=reference_field.strip() or 'reference',price_field=price_field.strip() or 'price',currency_field=currency_field.strip(),url_field=url_field.strip(),auth_type=auth_type,auth_header=auth_header.strip() or 'X-API-Key',auth_env_var=auth_env_var.strip(),actif=True,statut='Prêt' if mode=='Pull URL' else 'Prêt à recevoir',notes='');db.add(src);db.commit();db.refresh(src)
    if mode=='Push API':
        raw='noxprice_'+secrets.token_urlsafe(32);db.add(PriceSourceCredential(source_id=src.id,token_hash=price_token_hash(raw),token_hint=raw[-6:]));db.commit();endpoint=str(request.base_url).rstrip('/')+f'/api/prix-sources/{src.id}/push';sample='{"items":[{"reference":"REF-001","price":129.90,"currency":"EUR","url":"https://..."}]}'
        return page(request,u,'Source prix créée',f'<div class="head"><div><h1>Source Push API créée</h1><p class="muted">Copie ce jeton maintenant : seule son empreinte est conservée.</p></div></div><section class="card"><div class="kv"><b>Endpoint</b><code>{escape(endpoint)}</code><b>Bearer token</b><code style="word-break:break-all">{escape(raw)}</code><b>Exemple JSON</b><code>{escape(sample)}</code></div><a class="btn primary" href="/prix-sources">J’ai copié le jeton</a></section>')
    return RedirectResponse('/prix-sources',303)

@app.post('/prix-sources/alias')
def price_alias_add(request:Request,source_id:int=Form(...),stock_item_id:int=Form(...),external_reference:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS)
    if not db.get(PriceSource,source_id) or not db.get(StockItem,stock_item_id):raise HTTPException(404)
    ref=external_reference.strip();old=db.scalar(select(PriceSourceAlias).where(PriceSourceAlias.source_id==source_id,func.lower(PriceSourceAlias.external_reference)==ref.lower()))
    if old:old.stock_item_id=stock_item_id
    else:db.add(PriceSourceAlias(source_id=source_id,stock_item_id=stock_item_id,external_reference=ref))
    db.commit();return RedirectResponse('/prix-sources',303)

@app.post('/prix-sources/{sid}/synchroniser')
def price_source_sync(sid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);src=db.get(PriceSource,sid)
    if not src or src.mode!='Pull URL':raise HTTPException(404)
    _run_price_sync(db,src);return RedirectResponse('/prix-sources',303)

@app.post('/prix-sources/synchroniser-tout')
def price_source_sync_all(request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);sources=db.scalars(select(PriceSource).where(PriceSource.actif.is_(True),PriceSource.mode=='Pull URL').order_by(PriceSource.id)).all()
    for src in sources:_run_price_sync(db,src)
    return RedirectResponse('/prix-sources',303)

@app.post('/prix-sources/{sid}/rotater')
def price_source_rotate(sid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);src=db.get(PriceSource,sid)
    if not src or src.mode!='Push API':raise HTTPException(404)
    raw='noxprice_'+secrets.token_urlsafe(32);cred=db.scalar(select(PriceSourceCredential).where(PriceSourceCredential.source_id==sid))
    if cred:cred.token_hash=price_token_hash(raw);cred.token_hint=raw[-6:];cred.rotated_at=datetime.utcnow()
    else:db.add(PriceSourceCredential(source_id=sid,token_hash=price_token_hash(raw),token_hint=raw[-6:]))
    db.commit();endpoint=str(request.base_url).rstrip('/')+f'/api/prix-sources/{sid}/push';return page(request,u,'Nouveau jeton prix',f'<div class="head"><div><h1>Nouveau jeton généré</h1><p class="muted">L’ancien jeton est invalide immédiatement.</p></div></div><section class="card"><div class="kv"><b>Endpoint</b><code>{escape(endpoint)}</code><b>Nouveau token</b><code style="word-break:break-all">{escape(raw)}</code></div><a class="btn primary" href="/prix-sources">J’ai copié le jeton</a></section>')

@app.post('/api/prix-sources/{sid}/push')
async def price_source_push(sid:int,request:Request,db:Session=Depends(get_db)):
    src=_price_source_token(request,db,sid)
    try:data=await request.json()
    except Exception:raise HTTPException(400,'JSON invalide')
    if isinstance(data,dict) and src.root_key:
        nested=_nested_value(data,src.root_key,None);rows=nested if nested is not None else [data]
    else:rows=data
    if isinstance(rows,dict):rows=[rows]
    if not isinstance(rows,list):raise HTTPException(400,'Liste de prix attendue')
    run=_run_price_sync(db,src,rows=rows)
    return {'ok':run.statut in ('OK','Partiel'),'status':run.statut,'received':run.recus,'matched':run.correspondances,'imported':run.importes,'ignored':run.ignores,'errors':run.erreurs,'message':run.message}

@app.post('/api/prix-sources/sync-all')
def scheduled_price_sync(request:Request,db:Session=Depends(get_db)):
    expected=os.environ.get('NOXIA_PRICE_SYNC_TOKEN','').strip();auth=request.headers.get('authorization','');raw=auth[7:].strip() if auth.lower().startswith('bearer ') else ''
    if not expected:raise HTTPException(503,'NOXIA_PRICE_SYNC_TOKEN non configuré')
    if not raw or not hmac.compare_digest(raw,expected):raise HTTPException(401,'Jeton de synchronisation invalide')
    sources=db.scalars(select(PriceSource).where(PriceSource.actif.is_(True),PriceSource.mode=='Pull URL').order_by(PriceSource.id)).all();out=[]
    for src in sources:
        run=_run_price_sync(db,src);out.append({'source_id':src.id,'name':src.nom,'status':run.statut,'imported':run.importes,'errors':run.erreurs})
    return {'ok':True,'sources':out,'count':len(out)}

@app.get('/maintenance')
def maintenance(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);plans=db.scalars(select(MaintenancePlan).order_by(MaintenancePlan.prochaine_echeance)).all();eqs=db.scalars(select(Equipement).where(Equipement.actif.is_(True)).order_by(Equipement.reference)).all();trs='';today=date.today()
    for m in plans:
        e=db.get(Equipement,m.equipement_id);days=(m.prochaine_echeance-today).days;state='En retard' if days<0 else '≤30 jours' if days<=30 else 'À venir';trs+=f'<tr><td>{m.id}</td><td>{escape(e.reference if e else "—")}</td><td>{m.periodicite_mois} mois</td><td>{dfr(m.prochaine_echeance)}</td><td>{badge(state)}</td><td><form method="post" action="/maintenance/{m.id}/generer"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn small">Générer intervention</button></form></td></tr>'
    form=''
    if u.role in MANAGERS:form=f'<section class="card"><h2>Nouveau plan</h2><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Équipement<select name="equipement_id">{option_rows(eqs,lambda x:x.id,lambda x:f"{x.reference} · {x.type_equipement}")}</select></label><label>Périodicité mois<input type="number" min="1" name="periodicite_mois" value="12"></label><label>Prochaine échéance<input type="date" name="prochaine_echeance" required></label><label>Technicien préféré<input name="technicien_prefere"></label><button class="btn primary">Créer</button></form></section>'
    return page(request,u,'Maintenance',f'<h1>Maintenance préventive</h1>{form}<section class="card"><table><tr><th>ID</th><th>Équipement</th><th>Périodicité</th><th>Échéance</th><th>État</th><th></th></tr>{trs}</table></section>')

@app.post('/maintenance')
def maintenance_add(request:Request,equipement_id:int=Form(...),periodicite_mois:int=Form(12),prochaine_echeance:str=Form(...),technicien_prefere:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);db.add(MaintenancePlan(equipement_id=equipement_id,periodicite_mois=periodicite_mois,prochaine_echeance=date.fromisoformat(prochaine_echeance),technicien_prefere=technicien_prefere.strip(),priorite='Normale',notes='',actif=True));db.commit();return RedirectResponse('/maintenance',303)

@app.post('/maintenance/{mid}/generer')
def maintenance_generate(mid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);m=db.get(MaintenancePlan,mid);e=db.get(Equipement,m.equipement_id) if m else None
    if not m or not e:raise HTTPException(404)
    i=Intervention(site_id=e.site_id,equipement_id=e.id,technicien=m.technicien_prefere or u.username,type_intervention='Maintenance',priorite=m.priorite,probleme=f'Maintenance préventive plan #{m.id}',statut='À faire');db.add(i);db.commit();db.refresh(i);db.add(PlanningEntry(intervention_id=i.id,technicien=i.technicien,titre=f'Maintenance {e.reference}',debut=datetime.combine(m.prochaine_echeance,datetime.min.time()),statut='Prévu',notes='Généré automatiquement'));db.commit();return RedirectResponse(f'/interventions/{i.id}',303)

@app.get('/contrats')
def contracts(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(Contract).order_by(Contract.date_fin)).all();clients_=db.scalars(select(Client).where(Client.actif.is_(True)).order_by(Client.nom)).all();trs=''
    for c in rows:
        cl=db.get(Client,c.client_id);trs+=f'<tr><td>{escape(c.reference)}</td><td>{escape(cl.nom if cl else "—")}</td><td>{escape(c.nom)}</td><td>{dfr(c.date_fin)}</td><td>{c.visites_annuelles}</td><td>{money(c.montant_annuel)}</td><td>{badge("Expiré" if c.date_fin<date.today() else "Actif")}</td><td><form method="post" action="/contrats/{c.id}/renouveler"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn small">+12 mois</button></form></td></tr>'
    form=''
    if u.role in MANAGERS:form=f'<section class="card"><h2>Nouveau contrat</h2><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Référence<input name="reference" required></label><label>Client<select name="client_id">{option_rows(clients_,lambda x:x.id,lambda x:x.nom)}</select></label><label>Nom<input name="nom" required></label><label>Début<input type="date" name="date_debut" required></label><label>Fin<input type="date" name="date_fin" required></label><label>Préavis jours<input type="number" name="preavis_jours" value="30"></label><label>Visites/an<input type="number" name="visites_annuelles" value="1"></label><label>Montant annuel<input type="number" step=".01" name="montant_annuel" value="0"></label><button class="btn primary">Créer</button></form></section>'
    return page(request,u,'Contrats',f'<h1>Contrats</h1>{form}<section class="card"><table><tr><th>Réf</th><th>Client</th><th>Nom</th><th>Fin</th><th>Visites/an</th><th>Montant</th><th>État</th><th></th></tr>{trs}</table></section>')

@app.post('/contrats')
def contract_add(request:Request,reference:str=Form(...),client_id:int=Form(...),nom:str=Form(...),date_debut:str=Form(...),date_fin:str=Form(...),preavis_jours:int=Form(30),visites_annuelles:int=Form(1),montant_annuel:float=Form(0),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);db.add(Contract(reference=reference.strip(),client_id=client_id,nom=nom.strip(),type_contrat='Maintenance',date_debut=date.fromisoformat(date_debut),date_fin=date.fromisoformat(date_fin),renouvellement_auto=False,preavis_jours=preavis_jours,visites_annuelles=visites_annuelles,delai_intervention_heures=24,montant_annuel=montant_annuel,actif=True,notes=''));db.commit();return RedirectResponse('/contrats',303)

@app.post('/contrats/{cid}/renouveler')
def contract_renew(cid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);c=db.get(Contract,cid);c.date_fin=add_months(c.date_fin,12);db.commit();return RedirectResponse('/contrats',303)

@app.get('/alertes')
def alerts(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=''
    for lvl,domain,key,title,detail in derive_alerts(db):
        st=db.scalar(select(AlertState).where(AlertState.alert_key==key));ack=st.acquittee if st else False;rows+=f'<tr><td>{badge("Acquittée" if ack else lvl)}</td><td>{escape(domain)}</td><td>{escape(title)}</td><td>{escape(detail)}</td><td><form method="post" action="/alertes/acquitter"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><input type="hidden" name="alert_key" value="{escape(key)}"><button class="btn small">Acquitter</button></form></td><td><form method="post" action="/actions/depuis-alerte"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><input type="hidden" name="alert_key" value="{escape(key)}"><input type="hidden" name="titre" value="{escape(title)}"><button class="btn small">Créer action</button></form></td></tr>'
    return page(request,u,'Alertes',f'<h1>Centre d\'alertes</h1><section class="card"><table><tr><th>Niveau</th><th>Domaine</th><th>Alerte</th><th>Détail</th><th></th><th></th></tr>{rows or "<tr><td colspan=6>Aucune alerte active</td></tr>"}</table></section>')

@app.post('/alertes/acquitter')
def alert_ack(request:Request,alert_key:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,TECHS);st=db.scalar(select(AlertState).where(AlertState.alert_key==alert_key))
    if not st:st=AlertState(alert_key=alert_key);db.add(st)
    st.acquittee=True;st.utilisateur=u.username;st.date_acquittement=datetime.utcnow();db.commit();return RedirectResponse('/alertes',303)

@app.get('/actions')
def actions_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(FollowAction).order_by(FollowAction.created_at.desc())).all();trs=''.join(f'<tr><td>{a.id}</td><td>{escape(a.titre)}</td><td>{badge(a.priorite)}</td><td>{badge(a.statut)}</td><td>{escape(a.assigne_a)}</td><td>{dfr(a.date_echeance)}</td><td><form method="post" action="/actions/{a.id}/statut"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><select name="statut"><option>À faire</option><option>En cours</option><option>Terminée</option><option>Annulée</option></select><button class="btn small">OK</button></form></td></tr>' for a in rows);form=''
    if u.role in MANAGERS:form=f'<section class="card"><h2>Nouvelle action</h2><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Titre<input name="titre" required></label><label>Priorité<select name="priorite"><option>Normale</option><option>Haute</option><option>Urgente</option></select></label><label>Assignée à<input name="assigne_a"></label><label>Échéance<input type="date" name="date_echeance"></label><label class="full">Description<textarea name="description"></textarea></label><button class="btn primary">Créer</button></form></section>'
    return page(request,u,'Actions',f'<h1>Actions de suivi</h1>{form}<section class="card"><table><tr><th>ID</th><th>Titre</th><th>Priorité</th><th>Statut</th><th>Assignée</th><th>Échéance</th><th>Changer</th></tr>{trs}</table></section>')

@app.post('/actions')
def action_add(request:Request,titre:str=Form(...),priorite:str=Form('Normale'),assigne_a:str=Form(''),date_echeance:str=Form(''),description:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);db.add(FollowAction(titre=titre.strip(),description=description.strip(),priorite=priorite,statut='À faire',assigne_a=assigne_a.strip(),date_echeance=date.fromisoformat(date_echeance) if date_echeance else None));db.commit();return RedirectResponse('/actions',303)

@app.post('/actions/depuis-alerte')
def action_from_alert(request:Request,alert_key:str=Form(...),titre:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);db.add(FollowAction(titre=titre,description=alert_key,priorite='Haute',statut='À faire',source_type='alerte'));db.commit();return RedirectResponse('/actions',303)

@app.post('/actions/{aid}/statut')
def action_status(aid:int,request:Request,statut_action:str=Form(...,alias='statut'),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,TECHS);a=db.get(FollowAction,aid)
    if not a:raise HTTPException(404)
    if u.role=='Technicien' and a.assigne_a and a.assigne_a!=u.username:raise HTTPException(403)
    if u.role=='Technicien' and not a.assigne_a:a.assigne_a=u.username
    a.statut=statut_action;a.closed_at=datetime.utcnow() if statut_action in ('Terminée','Annulée') else None;db.commit();return RedirectResponse('/actions',303)


# ============================================================
# ASSISTANT IA NOX-IA — moteur hybride intelligent
# NOX-Core + mémoire terrain + raisonnement avancé optionnel
# ============================================================

ASSISTANT_STOPWORDS={
    'le','la','les','un','une','des','du','de','d','et','ou','à','a','au','aux',
    'en','dans','sur','pour','par','avec','sans','ce','cet','cette','ces',
    'mon','ma','mes','ton','ta','tes','son','sa','ses','il','elle','ils','elles',
    'je','tu','nous','vous','est','sont','être','faire','fait','plus','pas','ne',
    'que','qui','quoi','comment','pourquoi','problème','probleme','intervention',
    'équipement','equipement','système','systeme','avoir','mais','donc','alors'
}

_CORE_SEARCH_CACHE=None

def assistant_token_list(texte):
    return [
        token
        for token in re.findall(
            r"[a-zàâäéèêëîïôöùûüç0-9][a-zàâäéèêëîïôöùûüç0-9._/-]{1,}",
            str(texte or '').lower()
        )
        if token not in ASSISTANT_STOPWORDS
    ]

def assistant_tokens(texte):
    return set(assistant_token_list(texte))

def assistant_flatten(value,prefix='',depth=0):
    if depth>5:
        return []
    rows=[]
    if isinstance(value,dict):
        for key,item in value.items():
            label=f'{prefix}.{key}' if prefix else str(key)
            if isinstance(item,(dict,list)):
                rows.extend(assistant_flatten(item,label,depth+1))
            elif item not in (None,''):
                rows.append((label,str(item)))
    elif isinstance(value,list):
        for idx,item in enumerate(value):
            label=f'{prefix}[{idx}]'
            if isinstance(item,(dict,list)):
                rows.extend(assistant_flatten(item,label,depth+1))
            elif item not in (None,''):
                rows.append((label,str(item)))
    elif value not in (None,''):
        rows.append((prefix,str(value)))
    return rows

def assistant_item_text(item):
    data=item.get('data') or {}
    title,maker,typ,summary=core_meta(item)
    return ' '.join(
        [
            str(title),str(maker),str(typ),str(summary),
            str(item.get('source_group','')),
            str(item.get('source_file','')),
        ]
        + [f'{key} {value}' for key,value in assistant_flatten(data)]
    )

def assistant_build_core_index():
    global _CORE_SEARCH_CACHE
    catalog=core_catalog()
    signature=(len(catalog),CORE_PATH.stat().st_mtime if CORE_PATH.exists() else 0)
    if _CORE_SEARCH_CACHE and _CORE_SEARCH_CACHE.get('signature')==signature:
        return _CORE_SEARCH_CACHE

    docs=[]
    df=Counter()
    total_len=0

    for item in catalog:
        text_value=assistant_item_text(item)
        tokens=assistant_token_list(text_value)
        tf=Counter(tokens)
        unique=set(tokens)
        for token in unique:
            df[token]+=1
        total_len+=len(tokens)
        docs.append({
            'item':item,
            'text':text_value.lower(),
            'normalized':assistant_normalize_reference(text_value),
            'tf':tf,
            'length':max(1,len(tokens)),
        })

    _CORE_SEARCH_CACHE={
        'signature':signature,
        'docs':docs,
        'df':df,
        'n':max(1,len(docs)),
        'avgdl':max(1,total_len/max(1,len(docs))),
    }
    return _CORE_SEARCH_CACHE

def assistant_context(db,intervention_id):
    if not intervention_id:
        return {
            'intervention':None,
            'client':None,
            'site':None,
            'equipement':None,
            'texte':'',
            'chips':[],
        }

    intervention=db.get(Intervention,intervention_id)
    if not intervention:
        raise HTTPException(404,detail='Intervention introuvable')

    site=db.get(Site,intervention.site_id)
    client=db.get(Client,site.client_id) if site else None
    equipement=db.get(Equipement,intervention.equipement_id) if intervention.equipement_id else None

    parts=[
        f'Intervention {intervention.id}',
        f'Problème {intervention.probleme}',
        f'Actions {intervention.actions_realisees}',
        f'Solution {intervention.solution}',
        f'Type {intervention.type_intervention}',
        f'Priorité {intervention.priorite}',
        f'Statut {intervention.statut}',
    ]
    chips=[
        f'Intervention #{intervention.id}',
        f'Statut : {intervention.statut}',
        f'Priorité : {intervention.priorite}',
    ]

    if client:
        parts.append(f'Client {client.nom}')
        chips.append(f'Client : {client.nom}')

    if site:
        parts.extend([
            f'Site {site.nom}',
            f'Adresse {site.adresse}',
            f'Ville {site.ville}',
        ])
        chips.append(f'Site : {site.nom}')

    if equipement:
        parts.extend([
            f'Équipement {equipement.reference}',
            f'Type équipement {equipement.type_equipement}',
            f'Marque {equipement.marque}',
            f'Modèle {equipement.modele}',
            f'Numéro série {equipement.numero_serie}',
            f'IP {equipement.ip}',
            f'Statut équipement {equipement.statut}',
        ])
        chips.extend([
            f'Équipement : {equipement.reference}',
            f'{equipement.marque} {equipement.modele}'.strip(),
        ])

    diagnostics=db.scalars(
        select(Diagnostic)
        .where(Diagnostic.intervention_id==intervention_id)
        .order_by(Diagnostic.date_debut.desc())
        .limit(5)
    ).all()

    for diag in diagnostics:
        parts.extend([
            f'Diagnostic {diag.fiche_titre}',
            f'Symptôme diagnostic {diag.symptome}',
            f'Conclusion diagnostic {diag.conclusion}',
        ])

    return {
        'intervention':intervention,
        'client':client,
        'site':site,
        'equipement':equipement,
        'texte':' '.join(parts),
        'chips':chips,
    }

def assistant_external_context(context_data):
    """Contexte technique minimisé avant envoi à un modèle externe."""
    intervention=context_data.get('intervention')
    equipement=context_data.get('equipement')

    if not intervention:
        return 'Aucune intervention sélectionnée.'

    lines=[
        f'Type intervention: {intervention.type_intervention}',
        f'Priorité: {intervention.priorite}',
        f'Statut: {intervention.statut}',
        f'Problème signalé: {intervention.probleme}',
    ]

    if intervention.actions_realisees:
        lines.append(f'Actions déjà réalisées: {intervention.actions_realisees}')
    if intervention.solution:
        lines.append(f'Solution déjà renseignée: {intervention.solution}')

    if equipement:
        lines.extend([
            f'Type équipement: {equipement.type_equipement}',
            f'Marque: {equipement.marque}',
            f'Modèle: {equipement.modele}',
            f'Statut équipement: {equipement.statut}',
        ])

        # Les identifiants techniques sensibles restent locaux par défaut.
        if os.environ.get('NOXIA_AI_SEND_TECH_IDENTIFIERS','false').lower()=='true':
            if equipement.numero_serie:
                lines.append(f'Numéro de série: {equipement.numero_serie}')
            if equipement.ip:
                lines.append(f'Adresse IP: {equipement.ip}')

    return '\n'.join(lines)



def assistant_normalize_reference(value):
    raw=str(value or '').upper()
    raw=raw.replace('–','-').replace('—','-').replace('−','-')
    return re.sub(r'[^A-Z0-9]+','',raw)


def assistant_reference_tokens(value):
    raw=str(value or '').upper().replace('–','-').replace('—','-')
    candidates=re.findall(r'(?=[A-Z0-9()_./-]{5,})(?=[A-Z0-9()_./-]*[A-Z])(?=[A-Z0-9()_./-]*\d)[A-Z0-9][A-Z0-9()_./-]{3,}',raw)
    out=[]
    for token in candidates:
        norm=assistant_normalize_reference(token.strip('.,;:'))
        if len(norm)>=5 and norm not in out:out.append(norm)
    return out[:8]


def assistant_core_brands():
    brands=[];seen=set()
    for item in core_catalog():
        _,maker,_,_=core_meta(item);maker=' '.join(str(maker or '').split()).strip()
        if not maker or maker.lower().startswith('générique'):continue
        key=maker.lower()
        if key not in seen:seen.add(key);brands.append(maker)
    return sorted(brands,key=str.lower)


def assistant_detect_brand(value):
    low=str(value or '').lower();normalized=assistant_normalize_reference(value)
    aliases={
        'hanwha':'Hanwha Vision','wisenet':'Hanwha Vision','hikvision':'Hikvision','dahua':'Dahua','axis':'Axis','avigilon':'Avigilon','aritech':'Aritech','bosch':'Bosch','risco':'RISCO','genetec':'Genetec','pelco':'Pelco','mobotix':'MOBOTIX','texecom':'Texecom','finsecur':'FINSECUR','uniview':'Uniview','ipro':'i-PRO','i-pro':'i-PRO','milestone':'Milestone','network optix':'Network Optix','optex':'OPTEX','pyronix':'Pyronix','hid':'HID','assa abloy':'ASSA ABLOY','neutronic':'Neutronic','kentec':'Kentec','notifier':'NOTIFIER / Honeywell','scantronic':'Eaton / Scantronic','dsc':'DSC','galaxy':'Honeywell / Galaxy','ajax':'Ajax Systems','hkc':'HKC','vanderbilt':'Acre / Vanderbilt SPC','paxton':'Paxton','kantech':'Kantech','suprema':'Suprema','zkteco':'ZKTeco','salto':'SALTO','gallagher':'Gallagher Security','apollo':'Apollo Fire Detectors','esser':'ESSER / Honeywell','siemens':'Siemens'
    }
    for alias,brand in sorted(aliases.items(),key=lambda kv:len(kv[0]),reverse=True):
        if alias in low:return brand
    for brand in assistant_core_brands():
        bnorm=assistant_normalize_reference(brand)
        if brand.lower() in low or (len(bnorm)>=4 and bnorm in normalized):return brand
    return ''


def assistant_web_lookup_enabled():
    return assistant_ai_enabled() and os.environ.get('NOXIA_AI_WEB_SEARCH','true').strip().lower() not in {'0','false','no','off'}


def assistant_extract_web_sources(response,limit=8):
    rows=[];seen=set()
    def add(url,title=''):
        if not url or str(url) in seen or not str(url).startswith(('http://','https://')):return
        seen.add(str(url));rows.append({'url':str(url),'title':str(title or url)[:180]})
    for item in getattr(response,'output',[]) or []:
        if getattr(item,'type',None)=='message':
            for content in getattr(item,'content',[]) or []:
                for ann in getattr(content,'annotations',[]) or []:
                    if getattr(ann,'type',None)=='url_citation':add(getattr(ann,'url',None),getattr(ann,'title',None))
        if getattr(item,'type',None)=='web_search_call':
            action=getattr(item,'action',None)
            for src in getattr(action,'sources',[]) or []:
                if isinstance(src,dict):add(src.get('url'),src.get('title'))
                else:add(getattr(src,'url',None),getattr(src,'title',None))
    return rows[:limit]


def assistant_web_reference_lookup(query):
    if not assistant_web_lookup_enabled():return None
    from openai import OpenAI
    brand=assistant_detect_brand(query)
    prompt=(
        f"Tu aides NOX-IA à identifier une référence technique de sûreté/sécurité électronique.\n"
        f"Recherche sur le web la référence demandée : {query}\n"
        f"Marque détectée : {brand or 'à déterminer'}.\n"
        "Priorité absolue : page produit officielle du fabricant, fiche technique officielle, manuel/support officiel. "
        "Si aucune source officielle n'est disponible, utilise une source technique fiable et signale-le.\n"
        "Réponds en français avec : RÉFÉRENCE IDENTIFIÉE, FABRICANT, TYPE D'ÉQUIPEMENT, À QUOI ÇA SERT, "
        "CARACTÉRISTIQUES IMPORTANTES confirmées, VARIANTES/ALIAS utiles et CONSEIL POUR LE DIAGNOSTIC. "
        "Si la référence semble mal écrite, propose la référence officielle la plus proche et indique clairement la correction."
    )
    client=OpenAI(api_key=os.environ.get('OPENAI_API_KEY','').strip(),timeout=float(os.environ.get('OPENAI_TIMEOUT_SECONDS','55')))
    response=client.responses.create(model=assistant_ai_model(),reasoning={'effort':'low'},tools=[{'type':'web_search'}],tool_choice='required',include=['web_search_call.action.sources'],input=prompt,store=False)
    output=(response.output_text or '').strip()
    if not output:return None
    return {'text':output,'sources':assistant_extract_web_sources(response),'brand':brand}


def assistant_web_result_html(result):
    if not result:return ''
    links=''.join(f'<a class="web-source" href="{escape(row["url"],quote=True)}" target="_blank" rel="noopener noreferrer">↗ {escape(row.get("title") or row["url"])}</a>' for row in result.get('sources',[])[:8])
    return '<div class="web-result"><h3>🌐 Recherche web technique</h3><p class="muted">Résultat trouvé en direct sur le web. Les sources constructeur sont prioritaires.</p>'+f'<div class="ai-response">{escape(result.get("text", ""))}</div><div class="web-sources">{links}</div></div>'


def assistant_search_nox_core(question,context_text='',limit=8):
    index=assistant_build_core_index();symptom_hints=core_symptom_search(question,context_text,limit=6);expanded=' '.join([str(question or '')]+[str(x.get('domaine',''))+' '+str(x.get('symptome',''))+' '+' '.join(x.get('aliases') or []) for x in symptom_hints]);q_terms=assistant_token_list(expanded);c_terms=assistant_token_list(context_text)[:80]
    if not q_terms and not c_terms:return []
    q_counter=Counter(q_terms);c_counter=Counter(c_terms);k1=1.5;b=0.75;scored=[]
    exact_query=' '.join(str(question or '').lower().split());norm_query=assistant_normalize_reference(question);ref_tokens=assistant_reference_tokens(question);detected_brand=assistant_detect_brand(question)
    for doc in index['docs']:
        score=0.0;tf=doc['tf'];dl=doc['length']
        for token,freq_q in q_counter.items():
            if token not in tf:continue
            df=index['df'].get(token,0);idf=math.log(1+(index['n']-df+0.5)/(df+0.5));freq=tf[token];denom=freq+k1*(1-b+b*dl/index['avgdl']);score+=3.0*freq_q*idf*((freq*(k1+1))/denom)
        for token,freq_c in c_counter.items():
            if token not in tf:continue
            df=index['df'].get(token,0);idf=math.log(1+(index['n']-df+0.5)/(df+0.5));freq=tf[token];denom=freq+k1*(1-b+b*dl/index['avgdl']);score+=0.55*min(freq_c,2)*idf*((freq*(k1+1))/denom)
        title,maker,typ,summary=core_meta(doc['item']);title_low=str(title).lower();maker_low=str(maker).lower();doc_norm=doc.get('normalized','')
        for token in set(q_terms):
            if token and token in maker_low:score+=4.5
            if token and token in title_low:score+=3.5
        if detected_brand and detected_brand.lower() in maker_low:score+=6.0
        if exact_query and len(exact_query)>5 and exact_query in doc['text']:score+=12
        if norm_query and len(norm_query)>=6 and norm_query in doc_norm:score+=18
        for ref in ref_tokens:
            if ref in doc_norm:score+=15
            elif len(ref)>=8 and ref[:max(6,len(ref)-3)] in doc_norm:score+=4
        if score>0:scored.append((score,doc['item']))
    scored.sort(key=lambda row:row[0],reverse=True);output=[];seen=set()
    for score,item in scored:
        title,maker,typ,summary=core_meta(item);key=(str(maker).lower(),str(title).lower(),str(item.get('source_file','')).lower())
        if key in seen:continue
        seen.add(key);output.append(item)
        if len(output)>=limit:break
    return output

def assistant_symptom_atlas_text(question,context_text='',limit=18):
    rows=core_symptom_search(question,context_text,limit=limit)
    if not rows:return 'Aucun symptôme suffisamment proche dans l’atlas.'
    return '\n'.join(f'- [{row.get("domaine","")}] {row.get("symptome","")} (rareté: {row.get("rarete","")})' for row in rows)

def assistant_source_excerpt(item,index_number,max_chars=2200):
    title,maker,typ,summary=core_meta(item)
    data=item.get('data') or {}

    important_keys=(
        'verification','vérification','controle','contrôle','test',
        'cause','origine','symptome','symptôme','defaut','défaut',
        'procedure','procédure','etape','étape','action','solution',
        'conseil','attention','avertissement','securite','sécurité',
        'firmware','version','configuration','parametre','paramètre',
        'port','reseau','réseau','alimentation'
    )

    prioritized=[]
    secondary=[]

    for key,value in assistant_flatten(data):
        line=f'{key}: {" ".join(str(value).split())}'
        if any(word in key.lower() for word in important_keys):
            prioritized.append(line)
        else:
            secondary.append(line)

    body='\n'.join(prioritized+secondary)
    body=body[:max_chars]

    return (
        f'[S{index_number}] '
        f'Constructeur: {maker or "non précisé"} | '
        f'Fiche: {title or "sans titre"} | '
        f'Type: {typ or "non précisé"} | '
        f'Source: {item.get("source_file","NOX-Core")}\n'
        f'Résumé: {summary or ""}\n'
        f'Extraits:\n{body}'
    )

def assistant_similar_interventions(db,question,context_data,limit=4):
    query_tokens=assistant_tokens(question+' '+context_data.get('texte',''))
    current=context_data.get('intervention')
    current_id=current.id if current else None
    current_eq=context_data.get('equipement')

    rows=db.scalars(
        select(Intervention)
        .where(Intervention.statut=='Terminée')
        .order_by(Intervention.date_cloture.desc())
        .limit(250)
    ).all()

    scored=[]

    for intervention in rows:
        if intervention.id==current_id:
            continue

        eq=db.get(Equipement,intervention.equipement_id) if intervention.equipement_id else None

        technical_text=' '.join([
            intervention.probleme or '',
            intervention.actions_realisees or '',
            intervention.solution or '',
            eq.type_equipement if eq else '',
            eq.marque if eq else '',
            eq.modele if eq else '',
        ])

        tokens=assistant_tokens(technical_text)
        overlap=len(query_tokens & tokens)
        score=overlap

        if current_eq and eq:
            if current_eq.marque and current_eq.marque.lower()==(eq.marque or '').lower():
                score+=6
            if current_eq.modele and current_eq.modele.lower()==(eq.modele or '').lower():
                score+=10
            if current_eq.type_equipement and current_eq.type_equipement.lower()==(eq.type_equipement or '').lower():
                score+=4

        if score>1 and (intervention.solution or intervention.actions_realisees):
            scored.append((score,intervention,eq))

    scored.sort(key=lambda row:row[0],reverse=True)
    return scored[:limit]

def assistant_similar_cases_text(similar):
    if not similar:
        return 'Aucun cas terrain suffisamment similaire retrouvé.'

    blocks=[]
    for idx,(score,intervention,eq) in enumerate(similar,1):
        equipment=(
            f'{eq.type_equipement} {eq.marque} {eq.modele}'.strip()
            if eq else 'Équipement non précisé'
        )
        blocks.append(
            f'[C{idx}] {equipment}\n'
            f'Problème: {(intervention.probleme or "")[:700]}\n'
            f'Actions: {(intervention.actions_realisees or "")[:900]}\n'
            f'Solution: {(intervention.solution or "")[:900]}'
        )
    return '\n\n'.join(blocks)




def assistant_reply_polarity(text_value):
    raw=' '.join(str(text_value or '').strip().lower().split())
    clean=re.sub(r'[^a-zà-ÿ0-9 ]+',' ',raw)
    clean=' '.join(clean.split())
    positive={
        'oui','oui ok','oui ca marche','oui ça marche','ok','c est bon','c’est bon','ça marche','ca marche',
        'fonctionne','elle fonctionne','il fonctionne','oui toujours','oui je peux','oui je l ouvre','oui je l ouvre bien'
    }
    negative={
        'non','non toujours pas','toujours pas','non ca marche pas','non ça marche pas','marche pas','ne marche pas',
        'ko','non impossible','non je peux pas','rien','pareil','toujours pareil'
    }
    if clean in positive or clean.startswith('oui '):return 'yes'
    if clean in negative or clean.startswith('non '):return 'no'
    if clean in {'pareil','toujours pareil','toujours pas'}:return 'no'
    return None


def assistant_question_target(answer_text):
    """Déduit ce que testait la dernière question de NOX-IA pour interpréter « oui/non »."""
    low=str(answer_text or '').lower()
    # On regarde surtout la fin de la réponse, où NOX-IA place sa question suivante.
    tail=low[-1800:]
    if any(x in tail for x in ('interface web','accès web','acces web','page web de la caméra','ouvrir la caméra dans le navigateur')):
        return 'web'
    if 'onvif' in tail and any(x in tail for x in ('actif','fonctionne','tester','service','activé','active')):
        return 'onvif'
    if 'rtsp' in tail or 'flux vidéo' in tail or 'flux video' in tail:
        return 'rtsp'
    if 'ping' in tail and any(x in tail for x in ('répond','repond','joignable','tester','fonctionne')):
        return 'ping'
    if any(x in tail for x in ('alimentée','alimentee','alimentation','poe')) and '?' in tail:
        return 'power'
    if any(x in tail for x in ('tous les badges','tous les badge','uniquement un badge','seulement un badge')):
        return 'all_badges'
    if any(x in tail for x in ('lecteur réagit','lecteur reagit','voyant','bip')) and 'badge' in tail:
        return 'reader_reacts'
    if any(x in tail for x in ('image en direct','live','vue en direct')):
        return 'live'
    return None


def assistant_conversation_state(db,intervention_id,user_id,limit=18):
    """Construit l'état de panne à partir des faits explicites ET des réponses oui/non aux questions précédentes."""
    stmt=select(AssistantExchange)
    if intervention_id:
        stmt=stmt.where(AssistantExchange.intervention_id==intervention_id)
    else:
        stmt=stmt.where(AssistantExchange.user_id==user_id,AssistantExchange.intervention_id.is_(None))
    rows=list(reversed(db.scalars(stmt.order_by(AssistantExchange.created_at.desc()).limit(limit)).all()))
    if not rows:return 'Aucun fait conversationnel confirmé.'

    states={}
    notes=[]
    def set_state(key,value):states[key]=value
    def add_note(value):
        if value and value not in notes:notes.append(value)

    def consume_explicit(message):
        low=str(message or '').lower()
        if any(x in low for x in ('ping répond','ping repond','ping ok','répond au ping','repond au ping','joignable en ping')):set_state('ping','ok')
        if any(x in low for x in ('ping ne répond pas','ping ne repond pas','pas de ping','ping ko','injoignable')):set_state('ping','ko')
        if any(x in low for x in ('alimentée','alimenté','alimentation ok','alim ok','poe ok','s’allume','s allume')):set_state('power','ok')
        if any(x in low for x in ('pas alimenté','pas alimente','pas alimentée','pas alimentee','poe ko','ne s’allume pas','ne s allume pas')):set_state('power','ko')
        if any(x in low for x in ('interface web ok','web ok','interface web s ouvre','interface web s’ouvre','j arrive sur l interface','j’arrive sur l’interface','interface web marche','interface web fonctionne')):set_state('web','ok')
        if any(x in low for x in ('interface web ne s ouvre pas','interface web ne s’ouvre pas','pas accès web','pas acces web','web ko')):set_state('web','ko')
        if any(x in low for x in ('remonte pas au nvr','remonte plus au nvr','ne remonte pas au nvr','hors ligne sur le nvr','offline sur le nvr','pas visible sur le nvr')):set_state('nvr','ko')
        if any(x in low for x in ('rtsp ok','flux rtsp ok','rtsp fonctionne','rtsp marche')):set_state('rtsp','ok')
        if any(x in low for x in ('rtsp ko','rtsp marche pas','rtsp ne fonctionne pas','pas de flux rtsp')):set_state('rtsp','ko')
        if any(x in low for x in ('onvif ok','onvif fonctionne','onvif activé','onvif active','onvif marche')):set_state('onvif','ok')
        if any(x in low for x in ('onvif ko','onvif marche pas','onvif ne fonctionne pas','onvif désactivé','onvif desactive')):set_state('onvif','ko')
        if any(x in low for x in ('live ok','image en direct ok','direct fonctionne','vue en direct fonctionne')):set_state('live','ok')
        if any(x in low for x in ('pas d image en direct','pas d’image en direct','live ko','vue en direct ne marche pas')):set_state('live','ko')
        if any(x in low for x in ('tous les badges','aucun badge','plus aucun badge')):set_state('badge_scope','all')
        if any(x in low for x in ('un seul badge','badge précis','badge precis')):set_state('badge_scope','single')
        if any(x in low for x in ('lecteur bip','lecteur réagit','lecteur reagit')):set_state('reader','reacts')
        if any(x in low for x in ('pas d enregistrement','pas d’enregistrement','enregistrement marche pas','aucun enregistrement')):set_state('recording','ko')
        if any(x in low for x in ('disque plein','storage full','stockage plein')):set_state('storage','full')
        if any(x in low for x in ('porte s ouvre','porte s’ouvre','serrure fonctionne')):set_state('door','ok')
        # Retours NVR courants : on les garde comme observation sans les transformer en vérité constructeur.
        for marker,label in (
            ('mot de passe incorrect','NVR indique « mot de passe incorrect ».d'),
            ('password incorrect','NVR indique une erreur d’authentification / mot de passe.'),
            ('wrong password','NVR indique une erreur d’authentification / mot de passe.'),
            ('network unreachable','NVR indique que le réseau / l’hôte est inaccessible.'),
            ('réseau inaccessible','NVR indique que le réseau / l’hôte est inaccessible.'),
            ('reseau inaccessible','NVR indique que le réseau / l’hôte est inaccessible.'),
            ('connexion échouée','NVR indique un échec de connexion.'),
            ('connexion echouee','NVR indique un échec de connexion.'),
        ):
            if marker in low:
                add_note(label.replace('.d','.'))
                break
        if any(x in low for x in ('code défaut','code defaut','fault code')):add_note('Un code défaut a été mentionné : le conserver comme donnée prioritaire du diagnostic.')

    previous_ai=''
    for row in rows:
        current=row.question or ''
        polarity=assistant_reply_polarity(current)
        if polarity and previous_ai:
            target=assistant_question_target(previous_ai)
            if target:
                ok=(polarity=='yes')
                if target=='all_badges':set_state('badge_scope','all' if ok else 'partial')
                elif target=='reader_reacts':set_state('reader','reacts' if ok else 'silent')
                else:set_state(target,'ok' if ok else 'ko')
        consume_explicit(current)
        previous_ai=row.reponse or ''

    labels={
        ('ping','ok'):'Ping / connectivité IP de base déjà confirmé OK.',
        ('ping','ko'):'Ping / connectivité IP signalé en échec.',
        ('power','ok'):'Alimentation / démarrage déjà confirmé OK.',
        ('power','ko'):'Alimentation / démarrage signalé en échec.',
        ('web','ok'):'Accès à l’interface web déjà confirmé OK.',
        ('web','ko'):'Accès à l’interface web signalé en échec.',
        ('nvr','ko'):'Défaut de remontée NVR/VMS déjà confirmé.',
        ('rtsp','ok'):'Flux RTSP déjà confirmé fonctionnel.',
        ('rtsp','ko'):'Flux RTSP signalé en échec.',
        ('onvif','ok'):'ONVIF déjà confirmé actif/fonctionnel.',
        ('onvif','ko'):'ONVIF signalé en échec.',
        ('live','ok'):'Vidéo live/direct déjà confirmée fonctionnelle.',
        ('live','ko'):'Vidéo live/direct signalée en échec.',
        ('badge_scope','all'):'Le défaut contrôle d’accès touche tous les badges.',
        ('badge_scope','single'):'Le défaut contrôle d’accès semble limité à un badge.',
        ('reader','reacts'):'Le lecteur réagit à la présentation du badge.',
        ('reader','silent'):'Le lecteur ne réagit pas à la présentation du badge.',
        ('recording','ko'):'Défaut d’enregistrement confirmé.',
        ('storage','full'):'Stockage signalé plein.',
        ('door','ok'):'Ouverture physique de porte déjà confirmée fonctionnelle.',
    }
    facts=[]
    for key,value in states.items():
        label=labels.get((key,value))
        if label:facts.append(label)
    facts.extend(notes)
    return '\n'.join(f'- {fact}' for fact in facts) if facts else 'Aucun fait technique explicite consolidé.'

def assistant_history_for_prompt(db,intervention_id,user_id,limit=5):
    stmt=select(AssistantExchange)

    if intervention_id:
        stmt=stmt.where(AssistantExchange.intervention_id==intervention_id)
    else:
        stmt=stmt.where(
            AssistantExchange.user_id==user_id,
            AssistantExchange.intervention_id.is_(None)
        )

    rows=db.scalars(
        stmt.order_by(AssistantExchange.created_at.desc()).limit(limit)
    ).all()

    rows=list(reversed(rows))
    if not rows:
        return 'Aucun échange précédent.'

    blocks=[]
    for row in rows:
        blocks.append(
            f'Technicien: {row.question[:1000]}\n'
            f'NOX-IA: {row.reponse[:1800]}'
        )
    return '\n\n'.join(blocks)



def assistant_memory_storage_status():
    backend=engine.url.get_backend_name().lower()
    on_render=bool(os.environ.get('RENDER'))
    if backend=='sqlite' and on_render:
        return ('warn','Mémoire protégée des réinitialisations NOX-IA, mais SQLite local sur Render peut être perdu si le disque du service est remplacé. Utilise PostgreSQL via DATABASE_URL ou un disque persistant pour une vraie conservation serveur.')
    if backend=='sqlite':
        return ('good','Mémoire stockée dans la base SQLite locale et protégée des réinitialisations NOX-IA. Pense à exporter une sauvegarde régulièrement.')
    return ('good',f'Mémoire stockée dans la base {backend.upper()} et protégée des réinitialisations NOX-IA.')


def assistant_memory_signature(memory_type,title,content,source_ref=''):
    raw='|'.join([
        str(memory_type or '').strip().lower(),
        re.sub(r'\s+',' ',str(title or '').strip().lower()),
        re.sub(r'\s+',' ',str(content or '').strip().lower()),
        str(source_ref or '').strip().lower(),
    ])
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def assistant_memory_add(db,memory_type,title,content,keywords='',source='assistant',constructeur='',reference='',confidence='moyenne',utilisateur='',source_ref=''):
    content=' '.join(str(content or '').split()) if len(str(content or ''))<600 else str(content or '').strip()
    if len(content)<12:return None
    sig=assistant_memory_signature(memory_type,title,content,source_ref)
    existing=db.scalar(select(AssistantMemory).where(AssistantMemory.signature==sig))
    if existing:
        existing.updated_at=datetime.utcnow()
        if keywords and not existing.keywords:existing.keywords=keywords[:2500]
        if constructeur and not existing.constructeur:existing.constructeur=constructeur[:150]
        if reference and not existing.reference:existing.reference=reference[:180]
        return existing
    row=AssistantMemory(
        signature=sig,
        memory_type=(memory_type or 'observation')[:60],
        source=(source or 'assistant')[:80],
        title=(title or 'Mémoire technique')[:320],
        content=content[:18000],
        keywords=(keywords or '')[:2500],
        constructeur=(constructeur or '')[:150],
        reference=(reference or '')[:180],
        confidence=(confidence or 'moyenne')[:30],
        utilisateur=(utilisateur or '')[:150],
        source_ref=(source_ref or '')[:180],
        protected=True,
    )
    db.add(row)
    return row


def assistant_memory_search(db,query,limit=8):
    rows=db.scalars(select(AssistantMemory).order_by(AssistantMemory.updated_at.desc()).limit(3000)).all()
    q_tokens=assistant_tokens(query)
    q_norm=assistant_normalize_reference(query)
    scored=[]
    type_boost={'cas_resolu':7.8,'validation_terrain':7.4,'test_valide':7.0,'diagnostic':6.6,'test_invalide':5.9,'memo_manuel':5.8,'web_constructeur':5.6,'observation_terrain':4.8,'conversation':0.4}
    conf_boost={'élevée':2.2,'elevee':2.2,'haute':2.2,'moyenne':1.0,'faible':0.0}
    for row in rows:
        hay=' '.join([row.title or '',row.content or '',row.keywords or '',row.constructeur or '',row.reference or ''])
        tokens=assistant_tokens(hay)
        overlap=len(q_tokens & tokens)
        exact=0
        row_ref=assistant_normalize_reference(row.reference or '')
        if q_norm and len(q_norm)>=6 and row_ref and (q_norm in row_ref or row_ref in q_norm):exact=10
        if not overlap and not exact:continue
        score=overlap*1.8+exact+type_boost.get(row.memory_type,1.0)+conf_boost.get((row.confidence or '').lower(),0.5)
        if (row.confidence or '').lower() in {'élevée','elevee','haute'}:score+=min(2.0,math.log1p(max(0,row.times_used or 0)))
        if row.constructeur and row.constructeur.lower() in str(query).lower():score+=3
        scored.append((score,row))
    scored.sort(key=lambda item:item[0],reverse=True)
    selected=[row for _,row in scored[:limit]]
    for row in selected:row.times_used=(row.times_used or 0)+1
    return selected


def assistant_memory_text(rows,max_chars=9000):
    if not rows:return 'Aucune mémoire interne suffisamment proche.'
    blocks=[];total=0
    for idx,row in enumerate(rows,1):
        block=(f'[M{idx}] Type={row.memory_type} | Confiance={row.confidence} | Source={row.source}\n'
               f'Titre: {row.title}\nMémoire: {row.content}')
        if row.reference:block+=f'\nRéférence: {row.reference}'
        if row.constructeur:block+=f'\nConstructeur: {row.constructeur}'
        if total+len(block)>max_chars:break
        blocks.append(block);total+=len(block)
    return '\n\n'.join(blocks)


def assistant_memory_keywords(text_value):
    tokens=assistant_token_list(text_value)
    stop={'avec','dans','pour','mais','plus','moins','cette','cela','comme','être','avoir','fait','faire','sur','une','des','les','est','sont','que','qui','quoi','comment','salut','bonjour'}
    out=[]
    for token in tokens:
        if len(token)<3 or token in stop or token in out:continue
        out.append(token)
        if len(out)>=28:break
    return ' '.join(out)


ASSISTANT_TECH_TERMS=(
    'caméra','camera','nvr','dvr','vms','rtsp','onvif','poe','switch','vlan','ip ','adresse ip','firmware',
    'badge','lecteur','contrôle d’accès','controle acces','porte','serrure','gâche','gache','ventouse','wiegand','osdp',
    'alarme','intrusion','centrale','détecteur','detecteur','ssi','cmsi','ecs','incendie','boucle','sirène','sirene',
    'interphone','sip','serveur','stockage','disque','raid','réseau','reseau','ethernet','fibre','ping','port réseau','port reseau',
    'hikvision','dahua','axis','hanwha','wisenet','aritech','genetec','milestone','paxton','salto','hid','bosch','texecom'
)
ASSISTANT_BUSINESS_TERMS=(
    'client','site','intervention','stock','fournisseur','devis','facture','facturation','achat','commande fournisseur',
    'crm','prospect','opportunité','opportunite','commercial','marge','itesa','odoo','erp','nox-ia','noxia','tableau de bord',
    'projet','tâche','tache','support','sav','ticket','temps','timesheet','dépense','depense','document','approbation','agenda','rh','employé','employe','congé','conge','abonnement','facture fournisseur','automatisation','connaissance'
)


def assistant_query_mode(question,context_data=None,recent_history=''):
    """Route le message sans casser la conversation : général, métier NOX-IA ou technique terrain."""
    raw=' '.join(str(question or '').strip().lower().split())
    context_data=context_data or {}
    if not raw:return 'general'
    # Une réponse courte doit être comprise à partir du fil précédent, pas isolément.
    continuity=(str(recent_history or '')[-2600:]+' '+raw).lower() if assistant_short_reply(raw) else raw
    # Salutations/remerciements restent conversationnels, même si une intervention est sélectionnée.
    if assistant_conversation_intent(raw):return 'general'
    # Un vrai symptôme technique reste technique même si le mot « intervention » ou « site » apparaît.
    if assistant_detect_brand(continuity) or assistant_reference_tokens(continuity):return 'technical'
    if assistant_is_fire_context(continuity) or any(term in continuity for term in ASSISTANT_TECH_TERMS):return 'technical'
    if any(term in continuity for term in ASSISTANT_BUSINESS_TERMS):return 'noxia'
    if context_data.get('intervention'):return 'technical'
    return 'general'


def assistant_live_noxia_data(db,user,question):
    """Expose uniquement des données métier que le rôle a déjà le droit de consulter."""
    low=' '.join(str(question or '').lower().split())
    lines=[]
    try:
        if can_access_module(db,user,'operations'):
            if 'client' in low:
                lines.append(f'Clients actifs: {db.scalar(select(func.count(Client.id)).where(Client.actif.is_(True))) or 0}')
            if 'site' in low:
                lines.append(f'Sites actifs: {db.scalar(select(func.count(Site.id)).where(Site.actif.is_(True))) or 0}')
            if 'intervention' in low or 'dépannage' in low or 'depannage' in low:
                opened=db.scalar(select(func.count(Intervention.id)).where(Intervention.statut!='Terminée')) or 0
                lines.append(f'Interventions non terminées: {opened}')
                recent=db.scalars(select(Intervention).where(Intervention.statut!='Terminée').order_by(Intervention.date_creation.desc()).limit(5)).all()
                for row in recent:lines.append(f'Intervention #{row.id}: {row.probleme[:180]} | priorité {row.priorite} | statut {row.statut}')
        if can_access_module(db,user,'gestion'):
            if any(x in low for x in ('stock','matériel','materiel','référence','reference')):
                total=db.scalar(select(func.count(StockItem.id)).where(StockItem.actif.is_(True))) or 0
                low_stock=db.scalar(select(func.count(StockItem.id)).where(StockItem.actif.is_(True),StockItem.quantite<=StockItem.seuil_alerte)) or 0
                lines.append(f'Stock: {total} référence(s) active(s), {low_stock} sous ou au seuil d’alerte.')
                qtokens=assistant_tokens(question)
                if qtokens:
                    rows=db.scalars(select(StockItem).where(StockItem.actif.is_(True)).order_by(StockItem.reference).limit(700)).all()
                    scored=[]
                    for row in rows:
                        hay=' '.join([row.reference or '',row.designation or '',row.marque or '',row.modele or ''])
                        score=len(qtokens & assistant_tokens(hay))
                        if score:scored.append((score,row))
                    scored.sort(key=lambda x:x[0],reverse=True)
                    for _,row in scored[:5]:lines.append(f'Stock {row.reference}: {row.designation} | quantité {row.quantite} | achat {float(row.prix_achat or 0):.2f} €')
            if 'fournisseur' in low or 'itesa' in low:
                count=db.scalar(select(func.count(Supplier.id)).where(Supplier.actif.is_(True))) or 0
                lines.append(f'Fournisseurs actifs: {count}')
                if 'itesa' in low:
                    itesa=db.scalar(select(Supplier).where(func.lower(Supplier.nom)=='itesa'))
                    lines.append('ITESA est enregistré comme fournisseur dans NOX-IA.' if itesa else 'ITESA n’est pas encore enregistré dans cette base.')
        if can_access_module(db,user,'commercial') and any(x in low for x in ('devis','marge','commercial')):
            opened=db.scalar(select(func.count(Quote.id)).where(Quote.statut.notin_(['Accepté','Refusé','Annulé']))) or 0
            lines.append(f'Devis encore ouverts: {opened}')
        if can_access_module(db,user,'erp'):
            if any(x in low for x in ('achat','commande fournisseur')):
                count=db.scalar(select(func.count(PurchaseOrder.id)).where(PurchaseOrder.statut.notin_(['Reçue','Annulée','Annulé']))) or 0
                lines.append(f'Commandes fournisseur non terminées: {count}')
            if 'facture' in low or 'facturation' in low:
                rows=db.scalars(select(CustomerInvoice).order_by(CustomerInvoice.created_at.desc()).limit(500)).all()
                unpaid=[r for r in rows if float(r.paye or 0)+0.005<float(r.total or 0)]
                due=sum(max(0.0,float(r.total or 0)-float(r.paye or 0)) for r in unpaid)
                lines.append(f'Factures avec reste à payer: {len(unpaid)} | reste cumulé {due:.2f} €')
            if any(x in low for x in ('crm','prospect','opportunité','opportunite')):
                count=db.scalar(select(func.count(CRMLead.id))) or 0
                lines.append(f'Éléments CRM: {count}')
            if any(x in low for x in ('projet','tâche','tache')) and can_access_module(db,user,'workspace'):
                open_projects=db.scalar(select(func.count(ERPProject.id)).where(ERPProject.statut.notin_(['Terminé','Annulé']))) or 0
                open_tasks=db.scalar(select(func.count(ERPTask.id)).where(ERPTask.etape.notin_(['Terminé','Annulé']))) or 0
                lines.append(f'Projets ouverts: {open_projects} | tâches ouvertes: {open_tasks}')
            if any(x in low for x in ('support','sav','ticket')) and can_access_module(db,user,'workspace'):
                tickets=db.scalar(select(func.count(HelpdeskTicket.id)).where(HelpdeskTicket.statut.notin_(['Résolu','Fermé']))) or 0
                lines.append(f'Tickets support ouverts: {tickets}')
            if any(x in low for x in ('temps','timesheet','heure')) and can_access_module(db,user,'workspace'):
                month_start=date.today().replace(day=1)
                hours=db.scalar(select(func.sum(TimesheetEntry.heures)).where(TimesheetEntry.date_travail>=month_start)) or 0
                lines.append(f'Heures saisies ce mois: {float(hours):.2f} h')
            if any(x in low for x in ('dépense','depense','approbation')) and can_access_module(db,user,'organisation'):
                pending_exp=db.scalar(select(func.count(ExpenseClaim.id)).where(ExpenseClaim.statut.in_(['Soumise','À approuver']))) or 0
                pending_app=db.scalar(select(func.count(ApprovalRequest.id)).where(ApprovalRequest.statut=='À approuver')) or 0
                lines.append(f'Dépenses en attente: {pending_exp} | approbations en attente: {pending_app}')
            if any(x in low for x in ('contact','carnet')):
                lines.append(f'Contacts actifs: {db.scalar(select(func.count(BusinessContact.id)).where(BusinessContact.active.is_(True))) or 0}')
            if any(x in low for x in ('finance','trésorerie','tresorerie','encaissement','décaissement','decaissement')):
                txs=db.scalars(select(FinanceTransaction)).all();net=sum((float(x.amount or 0) if x.direction=='Entrée' else -float(x.amount or 0)) for x in txs)
                lines.append(f'Flux de trésorerie saisis: {len(txs)} | net des mouvements {net:.2f} €')
            if any(x in low for x in ('campagne','marketing')):
                lines.append(f'Campagnes: {db.scalar(select(func.count(MarketingCampaign.id))) or 0}')
            if any(x in low for x in ('recrutement','candidat','candidature')) and can_access_module(db,user,'organisation'):
                open_app=db.scalar(select(func.count(RecruitmentApplicant.id)).where(RecruitmentApplicant.stage.notin_(['Embauché','Refusé']))) or 0
                lines.append(f'Candidatures actives: {open_app}')
            if any(x in low for x in ('congé','conge','absence')) and can_access_module(db,user,'organisation'):
                pending_leave=db.scalar(select(func.count(LeaveRequest.id)).where(LeaveRequest.statut=='À approuver')) or 0
                lines.append(f'Demandes de congés à approuver: {pending_leave}')

    except Exception:
        # Une donnée métier indisponible ne doit jamais empêcher l’assistant de répondre.
        pass
    return '\n'.join(lines) if lines else 'Aucune donnée métier live nécessaire pour cette question.'


def assistant_merge_sources(groups,limit=8):
    output=[];seen=set()
    for group in groups:
        for item in group or []:
            title,maker,typ,summary=core_meta(item)
            key=(str(maker).lower(),str(title).lower(),str(item.get('source_file','')).lower())
            if key in seen:continue
            seen.add(key);output.append(item)
            if len(output)>=limit:return output
    return output


def assistant_deep_sources(question,context_data,recent_history,conversation_state,memory_text='',limit=8):
    """Cherche avec plusieurs formulations pour exploiter NOX-Core sans envoyer tout le catalogue au 4B."""
    base_context=' '.join([context_data.get('texte',''),conversation_state,str(recent_history or '')[-3200:],str(memory_text or '')[-2200:]])
    variants=[str(question or '').strip()]
    eq=context_data.get('equipement')
    if eq:
        identity=' '.join(x for x in [eq.marque,eq.modele,eq.reference,eq.type_equipement] if x)
        if identity:variants.append(identity+' '+str(question or ''))
    brand=assistant_detect_brand(str(question or '')+' '+base_context)
    refs=assistant_reference_tokens(str(question or '')+' '+base_context)
    if brand or refs:variants.append(' '.join([brand]+refs)+' '+str(question or ''))
    compact=assistant_memory_keywords(str(question or '')+' '+conversation_state)
    if compact:variants.append(compact)
    groups=[];used=set()
    for variant in variants[:4]:
        norm=' '.join(variant.lower().split())
        if not norm or norm in used:continue
        used.add(norm)
        groups.append(assistant_search_nox_core(variant,base_context,limit=6))
    return assistant_merge_sources(groups,limit=limit)


def assistant_should_persist_exchange(question,context_data=None,recent_history=''):
    """La mémoire permanente apprend le métier/terrain, pas toutes les petites questions de culture générale."""
    low=' '.join(str(question or '').lower().split())
    if any(x in low for x in ('mémorise','memorise','retiens ça','retiens ca','garde ça en mémoire','garde ca en memoire')):return True
    return assistant_query_mode(question,context_data,recent_history) in {'technical','noxia'}


def assistant_memory_observation_confidence(text_value):
    low=str(text_value or '').lower()
    if any(x in low for x in ('j’ai mesuré','j ai mesuré','mesuré à','mesure à','j’ai vérifié','j ai verifie','vérifié','confirmé','testé','je confirme','constaté')):return 'élevée'
    return 'moyenne'

def assistant_memory_learn_exchange(db,user,question,response,context_data,intervention_id=None):
    raw=' '.join(str(question or '').split());low=raw.lower()
    if len(raw)<4 or low in {'salut','bonjour','bonsoir','merci','ok'}:return None
    # L'historique garde toutes les conversations, mais la mémoire PERMANENTE n'absorbe
    # que le terrain, le métier NOX-IA ou une demande explicite de mémorisation.
    if not assistant_should_persist_exchange(raw,context_data):return None
    eq=context_data.get('equipement');constructeur=eq.marque if eq else '';reference=(eq.reference or eq.modele) if eq else ''
    context_bits=[]
    if eq:context_bits.append(f'Équipement {eq.marque} {eq.modele} réf {eq.reference}')
    if context_data.get('intervention'):context_bits.append(f'Intervention #{context_data["intervention"].id}')
    content=f'Observation terrain/métier du technicien : {raw}'
    if context_bits:content+=' | Contexte : '+' ; '.join(context_bits)
    obs=assistant_memory_add(db,'observation_terrain',f'Observation — {raw[:140]}',content,keywords=assistant_memory_keywords(raw+' '+' '.join(context_bits)),source='technicien',constructeur=constructeur,reference=reference,confidence=assistant_memory_observation_confidence(raw),utilisateur=user.username,source_ref=f'intervention:{intervention_id}' if intervention_id else 'assistant-general')
    # Une réponse IA n'est qu'une piste faible jusqu'à validation terrain.
    if response and len(str(response).strip())>20:
        assistant_memory_add(db,'conversation',f'Piste NOX-IA — {raw[:100]}',f'Question: {raw}\nPiste générée: {str(response)[:2600]}',keywords=assistant_memory_keywords(raw),source='assistant',constructeur=constructeur,reference=reference,confidence='faible',utilisateur=user.username,source_ref=f'assistant:{intervention_id or "general"}')
    return obs


def assistant_memory_learn_turn_validation(db,user,question,context_data,intervention_id=None):
    """Mémorise uniquement les validations terrain explicites d'une étape précédente.

    Une réponse IA seule reste une hypothèse faible. En revanche, quand le technicien
    confirme ensuite que l'étape a réellement fonctionné / résolu le point testé,
    cette paire devient une connaissance terrain à forte autorité.
    """
    raw=' '.join(str(question or '').strip().split())
    low=raw.lower()
    success_markers=(
        'ça marche','ca marche','c’est bon','c est bon','ça fonctionne','ca fonctionne',
        'fonctionne maintenant','c’est résolu','c est resolu','résolu','resolu',
        'problème réglé','probleme regle','problème résolu','probleme resolu',
        'nickel ça marche','nickel ca marche','oui ça marche','oui ca marche'
    )
    if not any(marker in low for marker in success_markers):
        return None

    stmt=select(AssistantExchange)
    if intervention_id:
        stmt=stmt.where(AssistantExchange.intervention_id==intervention_id)
    else:
        stmt=stmt.where(AssistantExchange.user_id==user.id,AssistantExchange.intervention_id.is_(None))
    previous=db.scalar(stmt.order_by(AssistantExchange.created_at.desc()))
    if not previous or not (previous.reponse or '').strip():
        return None
    if not assistant_should_persist_exchange(previous.question,context_data,(previous.question or '')+' '+(previous.reponse or '')):
        return None

    eq=context_data.get('equipement')
    constructeur=eq.marque if eq else ''
    reference=(eq.reference or eq.modele) if eq else ''
    previous_answer=' '.join((previous.reponse or '').split())
    previous_question=' '.join((previous.question or '').split())
    content=(
        f'Étape précédente proposée par NOX-IA : {previous_answer[:2200]}\n'
        f'Contexte du technicien avant cette étape : {previous_question[:900]}\n'
        f'Validation terrain explicite : {raw}'
    )
    return assistant_memory_add(
        db,'validation_terrain',
        f'Validation terrain — {previous_question[:120] or "étape technique"}',
        content,
        keywords=assistant_memory_keywords(previous_question+' '+previous_answer+' '+raw),
        source='validation_technicien',constructeur=constructeur,reference=reference,
        confidence='élevée',utilisateur=user.username,
        source_ref=f'assistant-exchange:{previous.id}'
    )


def assistant_memory_learn_turn_failure(db,user,question,context_data,intervention_id=None):
    """Apprend qu'une étape proposée n'a PAS résolu le problème, afin d'éviter de tourner en boucle."""
    raw=' '.join(str(question or '').strip().split());low=raw.lower()
    failure_markers=('toujours pas','pareil','toujours pareil','ça marche pas','ca marche pas','ne marche pas','pas résolu','pas resolu','aucun changement','même problème','meme probleme')
    if not any(marker in low for marker in failure_markers):return None
    stmt=select(AssistantExchange)
    if intervention_id:stmt=stmt.where(AssistantExchange.intervention_id==intervention_id)
    else:stmt=stmt.where(AssistantExchange.user_id==user.id,AssistantExchange.intervention_id.is_(None))
    previous=db.scalar(stmt.order_by(AssistantExchange.created_at.desc()))
    if not previous or not (previous.reponse or '').strip():return None
    if not assistant_should_persist_exchange(previous.question,context_data,(previous.question or '')+' '+(previous.reponse or '')):return None
    eq=context_data.get('equipement');constructeur=eq.marque if eq else '';reference=(eq.reference or eq.modele) if eq else ''
    previous_answer=' '.join((previous.reponse or '').split());previous_question=' '.join((previous.question or '').split())
    content=(f'Étape précédente proposée : {previous_answer[:2200]}\nContexte précédent : {previous_question[:900]}\nRetour terrain : {raw}\nConclusion mémoire : cette étape n’a pas résolu ce cas ; ne pas la reproposer en boucle sans fait nouveau.')
    return assistant_memory_add(db,'test_invalide',f'Test sans effet — {previous_question[:120] or "étape technique"}',content,keywords=assistant_memory_keywords(previous_question+' '+previous_answer+' '+raw),source='retour_technicien',constructeur=constructeur,reference=reference,confidence='élevée',utilisateur=user.username,source_ref=f'assistant-exchange:{previous.id}:failure')



def assistant_clean_local_output(value):
    """Nettoie les éventuelles balises/meta de raisonnement d'un petit modèle local."""
    out=str(value or '').strip()
    if not out:
        return ''
    out=re.sub(r'<think>.*?</think>','',out,flags=re.I|re.S).strip()
    # Certains modèles peuvent malgré think:false préfixer une zone de raisonnement.
    markers=('FINAL ANSWER:','RÉPONSE FINALE:','REPONSE FINALE:','FINAL:')
    upper=out.upper()
    for marker in markers:
        idx=upper.rfind(marker)
        if idx!=-1 and idx>=0:
            candidate=out[idx+len(marker):].strip()
            if candidate:
                out=candidate
                break
    # Élimine quelques préfixes purement méta sans supprimer une vraie analyse technique.
    out=re.sub(r'^(?:réponse|answer)\s*:\s*','',out,flags=re.I).strip()
    return out

def assistant_memory_learn_intervention(db,intervention,user):
    site=db.get(Site,intervention.site_id)
    eq=db.get(Equipement,intervention.equipement_id) if intervention.equipement_id else None
    resolution=(intervention.solution or intervention.actions_realisees or '').strip()
    if not resolution:return None
    content=(f'Problème terrain : {intervention.probleme}\nActions réalisées : {intervention.actions_realisees or "—"}\n'
             f'Solution validée : {intervention.solution or "—"}\nType : {intervention.type_intervention} | Priorité : {intervention.priorite}')
    if site:content+=f'\nSite : {site.nom}'
    title=f'Cas résolu #{intervention.id}'
    if eq:title+=f' — {eq.marque} {eq.modele or eq.reference}'
    return assistant_memory_add(
        db,'cas_resolu',title,content,
        keywords=assistant_memory_keywords(content),source='intervention_cloturee',
        constructeur=eq.marque if eq else '',reference=(eq.reference or eq.modele) if eq else '',
        confidence='élevée',utilisateur=user.username,source_ref=f'intervention:{intervention.id}'
    )


def assistant_memory_learn_diagnostic(db,diagnostic,user):
    steps=db.scalars(select(DiagnosticStep).where(DiagnosticStep.diagnostic_id==diagnostic.id).order_by(DiagnosticStep.ordre)).all()
    step_text=' ; '.join(f'{s.controle} => {s.resultat} {s.reaction}'.strip() for s in steps)
    eq=db.get(Equipement,diagnostic.equipement_id) if diagnostic.equipement_id else None
    content=f'Symptôme : {diagnostic.symptome}\nContrôles : {step_text or "—"}\nConclusion : {diagnostic.conclusion or "—"}'
    return assistant_memory_add(
        db,'diagnostic',f'Diagnostic #{diagnostic.id} — {diagnostic.fiche_titre}',content,
        keywords=assistant_memory_keywords(content),source='diagnostic_termine',
        constructeur=eq.marque if eq else '',reference=(eq.reference or eq.modele) if eq else '',
        confidence='élevée' if diagnostic.conclusion else 'moyenne',utilisateur=user.username,
        source_ref=f'diagnostic:{diagnostic.id}'
    )


def assistant_short_reply(question):
    raw=' '.join(str(question or '').strip().lower().split())
    words=raw.split()
    if not words or len(words)>10:return False
    exact={'oui','non','ok','oui ça marche','oui ca marche','non toujours pas','toujours pas','pareil','ça marche','ca marche','c’est bon','c est bon','toujours pareil'}
    if raw in exact:return True
    return words[0] in {'oui','non','ok','pareil','toujours','elle','il','ça','ca'}

def assistant_is_fire_context(text_value):
    full=str(text_value or '').lower()
    return any(term in full for term in (
        'incendie','ssi','cmsi','ecs','détection incendie','detection incendie',
        'notifier','esser','finsecur','neutronic','cerberus','sinteso',
        'apollo fire','kentec','advanced fire','eaton fire'
    ))

def assistant_is_cyber_context(text_value):
    full=str(text_value or '').lower()
    return any(term in full for term in (
        'cyber','pare-feu','firewall','switch','routeur','vlan','vpn',
        'serveur','active directory','mot de passe','credential',
        'ransomware','malware','port réseau','scan réseau'
    ))

def assistant_confidence(question,sources,similar):
    if not sources and not similar:
        return 'Faible'
    if len(sources)>=4 or (len(sources)>=2 and similar):
        return 'Élevé'
    return 'Moyen'



def assistant_detect_signals(question,context_data):
    low=(' '.join(str(question or '').split())+' '+context_data.get('texte','')).lower()
    def has(*terms):
        return any(term in low for term in terms)
    return {
        'camera': has('caméra','camera','dôme','dome','bullet','ptz','nvr','dvr','vms','ivms'),
        'access': has('badge','lecteur','contrôle accès','controle acces','porte','ventouse','gâche','gache'),
        'fire': assistant_is_fire_context(low),
        'cyber': assistant_is_cyber_context(low),
        'network': has('réseau','reseau','ip','switch','vlan','routeur','port réseau','port reseau','ethernet'),
        'power_ok': has('alimenté','alimentée','alim ok','alimentation ok','s allume','s’allume','allumé','allumée','poe ok','poe active','led allumée','voyant allumé'),
        'ping_ok': has('ping répond','ping repond','ping ok','répond au ping','repond au ping','joignable en ping'),
        'web_ok': has('interface web ok','web ok','accès web ok','acces web ok','interface locale ok'),
        'not_visible_nvr': has('remonte pas au nvr','remonte plus au nvr','ne remonte pas au nvr','hors ligne sur le nvr','offline sur le nvr','n apparait pas sur le nvr','n’apparaît pas sur le nvr','pas visible sur le nvr','sur le vms elle remonte pas','sur le nvr elle remonte pas'),
        'all_badges': has('tous les badges','aucun badge','plus aucun badge'),
        'single_badge': has('un seul badge','badge précis','badge precis','ce badge là','ce badge la'),
    }


def assistant_direct_answer(question,context_data,sources):
    low=' '.join(str(question or '').strip().lower().split())
    if any(term in low for term in ("c'est quoi onvif","c est quoi onvif","que veut dire onvif","onvif c est quoi")):
        return "ONVIF, c’est un standard qui permet à une caméra IP, un NVR ou un VMS de se reconnaître et d’échanger les fonctions de base même si les marques sont différentes. En pratique, si une caméra répond en IP mais ne remonte pas bien dans le NVR/VMS, vérifier ONVIF et les identifiants d’intégration est souvent utile."
    if any(term in low for term in ("c'est quoi rtsp","c est quoi rtsp","que veut dire rtsp","rtsp c est quoi")):
        return "RTSP, c’est le protocole utilisé pour appeler un flux vidéo. En pratique, il sert surtout à vérifier si la caméra fournit bien un flux lisible par un NVR, un VMS ou un lecteur réseau. Si le ping répond mais qu’il n’y a pas d’image, tester le flux RTSP aide à savoir si le problème vient du flux ou seulement de l’intégration."
    if any(term in low for term in ("c'est quoi poe","c est quoi poe","que veut dire poe","poe c est quoi")):
        return "PoE signifie Power over Ethernet : l’alimentation électrique passe par le câble réseau. C’est très utilisé pour les caméras et équipements IP. Si un appareil ne démarre pas ou redémarre, il faut vérifier le budget PoE du switch, la classe PoE, le port et le câble."
    if any(term in low for term in ("c'est quoi nvr","c est quoi nvr","que veut dire nvr")):
        return "Un NVR est un enregistreur vidéo réseau. Il dialogue avec des caméras IP via le réseau et récupère leurs flux vidéo. Si une caméra est joignable mais absente du NVR, le souci est souvent côté protocole, identifiants, ports, profil vidéo ou compatibilité."
    if any(term in low for term in ("c'est quoi ssi","c est quoi ssi","que veut dire ssi")):
        return "SSI veut dire Système de Sécurité Incendie. Il regroupe la détection, le traitement des alarmes et les commandes de mise en sécurité. Sur ce type d’installation, on évite toute neutralisation non autorisée et on travaille à partir du code défaut exact et de la documentation constructeur."
    if low.startswith('comment ajouter') and any(t in low for t in ('caméra','camera')):
        return "Pour ajouter une caméra, la logique générale est : 1) confirmer alimentation et présence réseau ; 2) relever IP, ports, protocole, identifiants et profil vidéo ; 3) vérifier l’accès direct à l’interface web ou au flux ; 4) l’ajouter dans le NVR/VMS avec le bon protocole (constructeur ou ONVIF) ; 5) contrôler image, enregistrement et heure. Si tu me donnes la marque de la caméra et du NVR/VMS, je te fais le pas-à-pas."
    if low.startswith('comment') and any(t in low for t in ('badge','lecteur')):
        return "Pour traiter un lecteur de badge, la logique de base est : 1) voir si le défaut touche tous les badges ou un seul ; 2) vérifier alimentation, voyant et communication lecteur/contrôleur ; 3) tester un badge connu fonctionnel ; 4) contrôler les droits d’accès et le relais d’ouverture. Si tu me donnes la marque et le symptôme exact, je te fais une procédure plus précise."
    return None


def assistant_ranked_unique(candidates,limit,minimum_score=1):
    out=[]
    seen=set()
    for score,text_value in sorted(candidates,key=lambda item:(item[0],len(item[1])),reverse=True):
        norm=' '.join(text_value.lower().split())
        if norm in seen:
            continue
        if score<minimum_score:
            continue
        out.append(text_value)
        seen.add(norm)
        if len(out)>=limit:
            break
    return out


def assistant_known_facts(signals):
    facts=[]
    if signals.get('power_ok'):
        facts.append('L’équipement semble déjà alimenté ou démarrer correctement.')
    if signals.get('ping_ok'):
        facts.append('La connectivité IP de base semble déjà confirmée par le ping.')
    if signals.get('web_ok'):
        facts.append('L’interface web ou l’accès local semble déjà fonctionner.')
    if signals.get('not_visible_nvr'):
        facts.append('Le problème paraît surtout lié à la remontée vers le NVR/VMS, pas à l’alimentation seule.')
    if signals.get('all_badges'):
        facts.append('Le défaut touche tous les badges, donc ce n’est probablement pas un badge isolé.')
    if signals.get('single_badge'):
        facts.append('Le défaut semble isolé à un badge précis.')
    return facts




def assistant_specific_symptom_guidance(question,context_data):
    low=(' '.join(str(question or '').split())+' '+context_data.get('texte','')).lower()
    def has(*terms):return any(term in low for term in terms)
    if has('image verte','image violet','image violette','dominante verte','dominante violette','dominante rose'):
        return (
            "Le symptôme « couleur anormale / image verte-violette » est reconnu. Comme le ping et l’accès web peuvent rester normaux, il faut séparer un défaut de traitement d’image d’un défaut de décodage côté VMS.",
            ['Filtre IR-cut bloqué ou commutation jour/nuit incorrecte.','Traitement couleur / balance des blancs / profil image incohérent après changement de configuration ou firmware.','Décodage codec/profil vidéo défectueux dans le client ou le VMS alors que la caméra encode correctement.','Défaut capteur/ISP plus rare si l’anomalie est aussi visible directement dans l’interface caméra.'],
            ['Comparer l’image directement dans l’interface web de la caméra avec l’image affichée dans le NVR/VMS.','Basculer temporairement jour/nuit et observer si les couleurs changent ; écouter si le filtre IR-cut commute lorsque le modèle en possède un.','Tester un autre profil/codec vidéo sans effacer la configuration actuelle.','Si l’image est déjà verte/violette en direct après reboot contrôlé et paramètres image cohérents, relever firmware et envisager un défaut caméra.'],
            'L’image est-elle verte/violette directement dans l’interface web de la caméra aussi, ou seulement dans le NVR/VMS ?'
        )
    if has('image noire','écran noir','ecran noir','pas d image','pas d’image','plus d image','plus d’image'):
        return (
            "Le symptôme est une absence d’image. Il faut d’abord déterminer si la caméra est réellement hors service ou si seule la chaîne vidéo est coupée.",
            ['Flux vidéo arrêté ou profil/codec non exploitable.','Caméra joignable mais capteur/encodeur vidéo bloqué.','NVR/VMS authentifié mais mauvais canal/profil média.','Alimentation/PoE ou réseau seulement si l’équipement lui-même n’est plus joignable.'],
            ['Vérifier si l’interface web et un flux direct sont accessibles.','Comparer flux principal et sous-flux.','Contrôler côté NVR/VMS protocole, identifiants, codec et état du canal.'],
            'La caméra répond-elle au ping et son image est-elle visible directement dans son interface web ?'
        )
    if has('image figée','image figee','freeze','vidéo bloquée','video bloquee'):
        return (
            "Une image figée avec une caméra encore joignable oriente davantage vers le flux, le réseau ou le décodage que vers une coupure totale.",
            ['Flux encodeur bloqué.','Perte de paquets / jitter / saturation réseau.','Décodage client/VMS bloqué.','Firmware ou service vidéo instable.'],
            ['Comparer un flux direct et le flux vu par le VMS.','Observer pertes de paquets, débit et erreurs du port switch.','Tester principal/sous-flux et un codec alternatif si disponible.'],
            'L’horodatage dans l’image continue-t-il d’avancer quand l’image semble figée ?'
        )
    if has('image pixelisée','image pixelisee','macrobloc','pixelisation','artefacts de compression'):
        return (
            "La pixelisation / les macroblocs indiquent souvent une perte de données vidéo ou un encodage trop contraint plutôt qu’un défaut optique.",
            ['Perte de paquets réseau.','Bitrate trop faible pour la scène.','GOP/codec/profil vidéo mal adapté.','Saturation d’un lien, switch, serveur ou décodeur.'],
            ['Vérifier pertes/CRC/drops sur le chemin réseau.','Comparer bitrate réel et réglage caméra.','Tester un flux direct près de la caméra puis via le VMS.'],
            'Le défaut apparaît-il aussi en flux direct sur le même réseau local ?'
        )
    if has('floue','flou','autofocus','mise au point'):
        return (
            "Le symptôme concerne la netteté / mise au point.",
            ['Mise au point incorrecte.','Dôme/optique sale, rayé ou embué.','Focus shift lors du passage jour/nuit.','Vibration ou objectif motorisé qui ne tient pas sa position.'],
            ['Inspecter optique/dôme sans modifier inutilement les réglages.','Comparer jour/nuit et zoom minimal/maximal.','Relancer un autofocus si le modèle le permet et noter si la netteté dérive ensuite.'],
            'Le flou est-il permanent ou apparaît-il surtout la nuit / après un changement de zoom ?'
        )
    if has('live ok','direct ok','live fonctionne') and has('pas d enregistrement','pas d’enregistrement','aucun enregistrement','recording'):
        return (
            "Le live fonctionne mais l’enregistrement manque : la caméra et le réseau de base ne sont donc probablement pas la cause principale.",
            ['Planning/mode d’enregistrement désactivé.','Stockage plein, hors ligne ou non inscriptible.','Service d’enregistrement / Archiver en défaut.','Règle événementielle non déclenchée.'],
            ['Vérifier l’état d’enregistrement du canal.','Contrôler stockage, espace, droits d’écriture et état du service d’enregistrement.','Comparer enregistrement continu et événementiel.'],
            'Le canal est-il configuré en continu, sur mouvement/événement, ou selon un planning ?'
        )
    if has('badge refusé','badge refuse','accès refusé','acces refuse'):
        return (
            "Le badge est lu mais l’accès est refusé : il faut distinguer une décision logique refusée d’un défaut physique de porte.",
            ['Badge expiré/inconnu ou mauvais format.','Droits, planning, zone ou anti-passback bloquants.','Synchronisation contrôleur incomplète.'],
            ['Lire l’événement exact de refus dans le système.','Tester un badge connu valide sur la même porte.','Comparer droits/planning et état du contrôleur.'],
            'Quel motif exact de refus apparaît dans le journal d’événements ?'
        )
    if has('badge accepté','badge accepte') and has('porte ne s ouvre','porte ne s’ouvre','pas d ouverture','pas d’ouverture'):
        return (
            "La décision d’accès semble correcte mais l’ouverture physique échoue : il faut descendre vers relais, alimentation et serrure.",
            ['Relais contrôleur ne commute pas.','Sortie mappée sur le mauvais port.','Alimentation serrure insuffisante.','Ventouse/gâche/serrure ou câblage défaillant.'],
            ['Observer l’état logique de la sortie au passage badge.','Mesurer la commande au relais puis la tension au verrou pendant l’ordre d’ouverture.','Tester mécaniquement la porte et le retour contact.'],
            'Le relais de sortie commute-t-il réellement quand l’accès est accordé ?'
        )
    if has('lecteur hors ligne','reader offline'):
        return (
            "Un lecteur hors ligne se traite d’abord comme un problème de communication/alimentation avant les droits badge.",
            ['Alimentation lecteur absente.','Bus OSDP/RS-485 ou Wiegand en défaut.','Adresse lecteur incorrecte/dupliquée.','Contrôleur ou module lecteur hors ligne.'],
            ['Vérifier alimentation et réaction locale du lecteur.','Contrôler état du contrôleur/module et événements communication.','Sur OSDP, vérifier adresse, polarité, terminaison et Secure Channel selon la configuration.'],
            'Le lecteur est-il totalement éteint ou alimenté avec un voyant/bip mais marqué hors ligne ?'
        )
    if has('défaut terre','defaut terre','earth fault','fuite à la terre'):
        return (
            "Un défaut terre en SSI peut être permanent ou intermittent ; il faut le localiser sans neutraliser les fonctions de sécurité.",
            ['Conducteur ou blindage en contact avec la terre.','Humidité / fuite d’isolement sur un équipement ou une ligne.','Alimentation ou module présentant une fuite à la terre.'],
            ['Relever si le défaut est permanent ou intermittent et les zones affectées.','Suivre la procédure constructeur/site de localisation par tronçons autorisés.','Inspecter particulièrement humidité, blindages et équipements récemment intervenus.'],
            'Le défaut terre est-il permanent, ou apparaît-il seulement à certains moments / avec l’humidité ?'
        )
    if has('court-circuit boucle','court circuit boucle','loop short'):
        return (
            "Un court-circuit de boucle SSI doit être localisé avec la procédure prévue par le constructeur, sans shunt de sécurité improvisé.",
            ['Court-circuit câble.','Équipement ou module en court-circuit.','Polarité/raccordement incorrect après intervention.'],
            ['Relever les isolateurs déclenchés et les appareils encore visibles.','Inspecter la dernière zone modifiée et les dérivations.','Localiser par tronçons uniquement selon la méthode constructeur autorisée.'],
            'Quels isolateurs ou groupes d’appareils restent visibles sur la boucle ?'
        )
    if has('audio dans un seul sens','audio unidirectionnel','one way audio'):
        return (
            "L’audio dans un seul sens en SIP/interphonie indique souvent que la signalisation fonctionne mais qu’un des flux RTP ne passe pas.",
            ['NAT/firewall bloque un sens RTP.','SDP annonce une mauvaise adresse.','SIP ALG modifie les paquets.','Codec ou route audio asymétrique.'],
            ['Comparer les adresses/ports média annoncés.','Vérifier si le problème existe sur LAN local.','Contrôler NAT/firewall/SIP ALG avant de modifier le codec.'],
            'Le défaut existe-t-il aussi lorsque les deux postes sont sur le même réseau local ?'
        )
    if has('perte de paquets','packet loss','crc','port flapping','lien flapping'):
        return (
            "Le symptôme est réseau : il faut quantifier la perte et savoir si elle vient du lien physique, de la saturation ou d’une boucle/configuration L2.",
            ['Câble/SFP marginal.','Erreurs CRC ou négociation.','Saturation/microbursts.','STP/boucle/port flapping.'],
            ['Relever compteurs interface avant/après test.','Tester câble/SFP/port de substitution sans changer plusieurs éléments à la fois.','Comparer perte sous faible charge et forte charge.'],
            'Les compteurs du port montrent-ils des CRC, drops ou changements de lien ?'
        )
    if has('certificat expiré','certificat expire','tls échoue','tls echoue'):
        return (
            "Un problème certificat/TLS peut laisser le ping et parfois le HTTP fonctionner tout en cassant l’intégration applicative.",
            ['Certificat expiré.','Hostname/SAN incompatible.','Chaîne intermédiaire manquante.','Version TLS/cipher incompatible.','Horloge système incorrecte.'],
            ['Vérifier date/heure des deux systèmes.','Inspecter certificat présenté, expiration, nom et chaîne.','Comparer les exigences TLS côté client/serveur.'],
            'Quel message TLS/certificat exact est affiché par le client ou le serveur ?'
        )
    return None

def assistant_default_guidance(signals,question,context_data):
    if signals.get('camera') and signals.get('ping_ok') and signals.get('not_visible_nvr'):
        return (
            "Je comprends que la caméra semble alimentée et joignable en réseau, mais qu’elle ne remonte plus correctement dans le NVR ou le VMS.",
            [
                'Identifiants ou mot de passe de la caméra différents de ceux enregistrés dans le NVR/VMS.',
                'Service ONVIF/RTSP désactivé, modifié ou non compatible avec le NVR/VMS.',
                'Port, protocole ou profil vidéo changé après une mise à jour ou une modification de configuration.',
                'Canal NVR/VMS en défaut, hors service ou mal recréé côté supervision.',
            ],
            [
                'Ouvrir l’interface web de la caméra et vérifier l’état du flux principal, de l’utilisateur d’intégration et des services ONVIF/RTSP.',
                'Contrôler côté NVR/VMS le protocole utilisé, les identifiants, le port, le codec et l’état du canal.',
                'Si la caméra est joignable en direct, supprimer puis recréer le canal ou réimporter la caméra dans le NVR/VMS après avoir confirmé les bons identifiants.',
            ],
            'Tu arrives à ouvrir l’interface web de la caméra et à tester son flux ou son service ONVIF, ou le problème apparaît uniquement côté NVR/VMS ?'
        )
    if signals.get('camera'):
        return (
            "Je comprends qu’il s’agit d’un problème de vidéosurveillance ou de caméra IP.",
            [
                'Alimentation ou PoE instable.',
                'Perte ou dégradation de communication IP.',
                'Problème de flux vidéo, de protocole ou d’intégration NVR/VMS.',
            ],
            [
                'Vérifier l’alimentation réelle, le lien réseau et l’accessibilité directe de la caméra.',
                'Tester si l’interface web ou le flux vidéo est lisible en direct.',
                'Comparer ensuite les paramètres caméra et NVR/VMS : IP, ports, protocole, identifiants et profil vidéo.',
            ],
            'Quel est le comportement exact : hors ligne, pas d’image, image figée, refus d’ajout, ou perte d’enregistrement ?'
        )
    if signals.get('access'):
        return (
            "Je comprends qu’on est sur un problème de contrôle d’accès ou de lecteur de badge.",
            [
                'Badge non valide ou droits d’accès incorrects.',
                'Lecteur alimenté mais non communiqué au contrôleur.',
                'Commande de porte ou relais non fonctionnel.',
            ],
            [
                'Déterminer si le défaut touche tous les badges ou seulement un badge précis.',
                'Contrôler l’alimentation, les voyants, le buzzer éventuel et la communication avec le contrôleur.',
                'Vérifier ensuite les événements remontés, les droits d’accès et le déclenchement du relais d’ouverture.',
            ],
            'Le lecteur réagit-il quand on présente un badge, et le problème concerne-t-il tous les badges ou seulement certains ?'
        )
    if signals.get('fire'):
        return (
            "Je comprends qu’on est sur un contexte SSI / incendie, donc il faut rester sur des contrôles sûrs et documentés.",
            [
                'Défaut de ligne, boucle ou équipement adressé.',
                'Défaut d’alimentation ou de communication interne.',
                'Événement technique ou dérangement lié à une zone précise.',
            ],
            [
                'Relever précisément le code défaut, la zone, la boucle et le ou les éléments concernés.',
                'Comparer avec la documentation constructeur sans neutraliser une fonction de sécurité.',
                'Contrôler ensuite les alimentations, l’adressage et les liaisons autorisées par la procédure du site.',
            ],
            'Quel code défaut exact apparaît, et sur quelle zone, boucle ou carte ?'
        )
    return (
        "Je comprends qu’il y a un symptôme technique à qualifier avant de conclure.",
        [
            'Défaut d’alimentation ou de connectique.',
            'Perte de communication réseau, bus ou liaison terrain.',
            'Paramétrage incohérent ou service logiciel indisponible.',
        ],
        [
            'Relever le symptôme exact, le message affiché et ce qui a déjà été testé.',
            'Contrôler d’abord les éléments simples et non intrusifs : alimentation, câblage, voyants, communication.',
            'Comparer ensuite le comportement observé avec la documentation ou une fiche NOX-Core proche.',
        ],
        'Quel est le symptôme exact observé, avec le message ou le code défaut s’il y en a un ?'
    )


def assistant_local_followup(question,context_data):
    signals=assistant_detect_signals(question,context_data)
    eq=context_data.get('equipement')
    if not eq:
        return 'Quelle est la marque, le modèle et le type exact de l’équipement concerné ?'
    if signals.get('camera') and signals.get('ping_ok') and signals.get('not_visible_nvr'):
        return 'Peux-tu confirmer si l’interface web de la caméra s’ouvre encore et si le flux ou le service ONVIF est toujours actif ?'
    if signals.get('camera'):
        return 'Le défaut observé est-il plutôt : hors ligne, pas d’image, image figée, refus d’ajout dans le NVR/VMS, ou perte d’enregistrement ?'
    if signals.get('access') and signals.get('all_badges'):
        return 'Tous les badges sont refusés : le lecteur réagit-il quand même (voyant, bip, événement) ou reste-t-il totalement muet ?'
    if signals.get('access') and signals.get('single_badge'):
        return 'Le badge concerné fonctionne-t-il sur une autre porte ou avec un autre lecteur ?'
    if signals.get('access'):
        return 'Le problème vient-il du badge, du lecteur, de l’ouverture de porte, ou de la remontée au contrôleur ?'
    if signals.get('fire'):
        return 'Quel code défaut exact, quelle zone et quel équipement sont affichés ?'
    if signals.get('network') and signals.get('ping_ok'):
        return 'Le service applicatif concerné répond-il aussi (interface web, port, supervision), ou seulement le ping ?'
    return 'Quel est le symptôme exact observé, avec le message ou le code défaut s’il y en a un ?'

def assistant_conversation_intent(question):
    raw=' '.join(str(question or '').strip().lower().split())
    stripped=re.sub(r'[^a-zà-ÿ0-9 ]+',' ',raw)
    words=[w for w in stripped.split() if w]
    greetings={'salut','bonjour','bonsoir','hello','hey','yo','coucou'}
    thanks={'merci','thanks','thx'}
    if words and len(words)<=5 and any(w in greetings for w in words):
        return "Salut 👋 Dis-moi simplement ce que tu as devant toi : l’équipement, le symptôme, ce que tu as déjà testé, même en langage normal. Je te guide étape par étape."
    if words and len(words)<=5 and any(w in thanks for w in words):
        return "Avec plaisir. Si tu veux continuer le diagnostic, dis-moi juste ce que tu observes après le dernier test."
    return None





def assistant_state_has(state_text,*needles):
    low=str(state_text or '').lower()
    return any(str(n).lower() in low for n in needles)


def assistant_requested_full_detail(question):
    low=' '.join(str(question or '').lower().split())
    return any(x in low for x in (
        'détaille tout','detaille tout','réponse complète','reponse complete','rapport complet','toutes les étapes','toutes les etapes',
        'toutes les causes','donne tout','analyse complète','analyse complete','liste complète','liste complete'
    ))


def assistant_interactive_next_step(question,context_data,conversation_state):
    """Retourne un guidage terrain court : 1 décision + 1 ou 2 contrôles maximum."""
    low=(' '.join(str(question or '').split())+' '+str(conversation_state or '')+' '+context_data.get('texte','')).lower()
    is_camera=any(x in low for x in ('caméra','camera','nvr','vms','rtsp','onvif','ivms'))
    is_access=any(x in low for x in ('badge','lecteur','contrôle accès','controle acces','porte','ventouse','gâche','gache'))
    is_fire=assistant_is_fire_context(low)

    ping_ok=assistant_state_has(conversation_state,'ping / connectivité ip de base déjà confirmé ok') or any(x in low for x in ('ping ok','ping répond','ping repond'))
    power_ok=assistant_state_has(conversation_state,'alimentation / démarrage déjà confirmé ok') or any(x in low for x in ('alimentée','alimenté','alim ok','alimentation ok','poe ok'))
    web_ok=assistant_state_has(conversation_state,'interface web déjà confirmé ok') or assistant_state_has(conversation_state,'interface web déjà confirmée ok') or assistant_state_has(conversation_state,'accès à l’interface web déjà confirmé ok') or any(x in low for x in ('interface web ok','web ok'))
    web_ko=assistant_state_has(conversation_state,'interface web signalé en échec') or any(x in low for x in ('web ko','interface web ne s ouvre pas','interface web ne s’ouvre pas'))
    nvr_ko=assistant_state_has(conversation_state,'défaut de remontée nvr/vms déjà confirmé') or any(x in low for x in ('remonte pas au nvr','remonte plus au nvr','hors ligne sur le nvr','offline sur le nvr'))
    onvif_ok=assistant_state_has(conversation_state,'onvif déjà confirmé actif') or 'onvif ok' in low
    onvif_ko=assistant_state_has(conversation_state,'onvif signalé en échec') or 'onvif ko' in low
    rtsp_ok=assistant_state_has(conversation_state,'rtsp déjà confirmé fonctionnel') or 'rtsp ok' in low
    rtsp_ko=assistant_state_has(conversation_state,'rtsp signalé en échec') or 'rtsp ko' in low

    auth_error=any(x in low for x in ('mot de passe incorrect','password incorrect','wrong password','authentification'))
    network_error=any(x in low for x in ('network unreachable','réseau inaccessible','reseau inaccessible','hôte inaccessible','hote inaccessible'))

    if is_camera and nvr_ko:
        confirmed=[]
        if power_ok:confirmed.append('alimentation OK')
        if ping_ok:confirmed.append('ping OK')
        if web_ok:confirmed.append('interface web OK')
        intro='OK, je garde '+', '.join(confirmed)+'.' if confirmed else 'OK, la panne est bien localisée sur la remontée vers le NVR/VMS.'
        if auth_error:
            return {
                'intro':intro+' Le NVR signale maintenant un problème d’authentification.',
                'test':'Dans le canal de cette caméra sur le NVR, regarde simplement le nom d’utilisateur enregistré et compare-le au compte avec lequel tu ouvres la caméra sur le web. Ne change rien pour l’instant.',
                'why':'Ça permet de savoir si le NVR utilise le mauvais compte avant de toucher au mot de passe ou à ONVIF.',
                'question':'C’est le même nom d’utilisateur sur le NVR et sur la caméra : oui ou non ?'
            }
        if network_error and ping_ok and web_ok:
            return {
                'intro':intro+' Le PC atteint la caméra, mais le NVR dit que le réseau est inaccessible.',
                'test':'Depuis le NVR, relève l’adresse IP configurée pour ce canal et compare-la à l’adresse IP actuelle de la caméra. Si le NVR permet un test réseau intégré, lance uniquement ce test.',
                'why':'On doit distinguer une mauvaise IP enregistrée d’un problème de chemin réseau/VLAN entre le NVR et la caméra.',
                'question':'L’adresse IP affichée dans le NVR est exactement la même que celle de la caméra : oui ou non ?'
            }
        if web_ok and not onvif_ok and not onvif_ko:
            return {
                'intro':intro+' Donc la caméra elle-même est accessible ; je ne te fais pas recommencer le réseau.',
                'test':'Sur le NVR, ouvre l’état du canal de cette caméra et relève le message exact affiché. Ne modifie encore aucun paramètre.',
                'why':'Le message du NVR sépare rapidement authentification, protocole/ONVIF et liaison NVR↔caméra.',
                'question':'Il affiche quoi exactement : « mot de passe incorrect », « réseau inaccessible », « hors ligne », ou un autre message ?'
            }
        if onvif_ko:
            return {
                'intro':intro+' ONVIF est maintenant signalé en échec.',
                'test':'Dans l’interface de la caméra, vérifie seulement si ONVIF est activé et si un utilisateur ONVIF existe. Ne recrée pas encore le canal NVR.',
                'why':'Si le NVR utilise ONVIF, un service désactivé ou un compte ONVIF absent suffit à expliquer la panne.',
                'question':'ONVIF est activé et un utilisateur ONVIF est présent : oui ou non ?'
            }
        if onvif_ok and not rtsp_ok and not rtsp_ko:
            return {
                'intro':intro+' ONVIF fonctionne, donc on avance vers le flux vidéo.',
                'test':'Teste maintenant le flux principal de la caméra en direct (via le NVR/VMS si possible, sinon avec un lecteur RTSP autorisé).',
                'why':'ONVIF peut répondre alors que le flux vidéo ou son profil ne fonctionne plus.',
                'question':'Le flux vidéo direct fonctionne : oui ou non ?'
            }
        if rtsp_ok:
            return {
                'intro':intro+' Le flux RTSP fonctionne aussi ; la caméra et son flux sont donc disponibles.',
                'test':'Retourne uniquement sur le canal NVR et relève le protocole choisi, l’utilisateur et le message d’état actuel. Ne supprime pas le canal pour l’instant.',
                'why':'À ce stade la panne est probablement dans l’intégration/configuration du canal NVR plutôt que dans la caméra elle-même.',
                'question':'Quel protocole et quel message d’état sont affichés sur le canal ?'
            }

    if is_camera:
        if ping_ok and not web_ok and not web_ko:
            return {'intro':'OK, le ping fonctionne déjà.','test':'Essaie maintenant d’ouvrir l’interface web de la caméra avec son adresse IP.','why':'Ça permet de savoir si seule la couche ICMP répond ou si les services de la caméra sont réellement disponibles.','question':'L’interface web s’ouvre : oui ou non ?'}
        if web_ok:
            return {'intro':'OK, l’interface web fonctionne.','test':'Dis-moi maintenant le symptôme exact côté vidéo ou supervision sans refaire le ping.','why':'La caméra est accessible ; il faut localiser la panne dans le flux, l’enregistrement ou l’intégration.','question':'Tu as plutôt : pas d’image, image dégradée, hors ligne NVR/VMS, ou pas d’enregistrement ?'}
        return {'intro':'OK, on va avancer sans tout tester d’un coup.','test':'Commence par vérifier uniquement si la caméra est alimentée et si elle répond au ping.','why':'Ces deux constats séparent rapidement alimentation, réseau et problème applicatif.','question':'Alimentation OK et ping OK : oui ou non ?'}

    if is_access:
        if assistant_state_has(conversation_state,'touche tous les badges'):
            return {'intro':'OK, le défaut touche tous les badges.','test':'Présente un badge connu valide et observe uniquement si le lecteur bip/voyant réagit et si un événement remonte au contrôleur.','why':'Ça sépare un lecteur/communication muet d’un problème de droits ou de commande de porte.','question':'Le lecteur réagit et un événement remonte : oui ou non ?'}
        return {'intro':'OK, on va d’abord isoler badge, lecteur ou porte.','test':'Teste un badge connu fonctionnel et regarde si le lecteur réagit (bip/voyant).','why':'C’est le contrôle le plus rapide avant d’aller dans les droits et la configuration.','question':'Le défaut touche tous les badges : oui ou non ?'}

    if is_fire:
        return {'intro':'OK. Comme c’est du SSI/incendie, on reste uniquement sur des constats et contrôles autorisés.','test':'Relève le code défaut exact, la zone/boucle et l’équipement indiqué, sans neutraliser ni shunter quoi que ce soit.','why':'Le code et la localisation déterminent la procédure constructeur sûre à suivre.','question':'Quel code défaut exact et quelle zone/boucle sont affichés ?'}

    return {'intro':'OK, je vais avancer une étape à la fois.','test':'Donne-moi le symptôme exact et ce que tu as déjà confirmé, sans refaire les tests déjà faits.','why':'Je pourrai choisir le contrôle qui élimine le plus d’hypothèses en une fois.','question':'Quel est le symptôme précis ou le message/code affiché ?'}



def assistant_interactive_render(step,conversation_state='',memories=None):
    """Rendu court et naturel pour le moteur déterministe de secours."""
    intro=(step.get('intro') or '').strip()
    test=(step.get('test') or '').strip()
    why=(step.get('why') or '').strip()
    question=(step.get('question') or '').strip()
    paragraphs=[]
    if intro:
        paragraphs.append(intro)
    if test:
        p=test
        if why:
            why_clean=why.rstrip('.').strip()
            if why_clean:
                p+=' '+('Ça permet de '+why_clean[:1].lower()+why_clean[1:] if not why_clean.lower().startswith(('ça ','cela ','ce ','cet ','cette ','le ','la ','l’','l\'','on ')) else why_clean[:1].upper()+why_clean[1:])+'.'
        paragraphs.append(p)
    elif why:
        paragraphs.append(why)
    if question:
        paragraphs.append(question)
    return '\n\n'.join(p for p in paragraphs if p)

def assistant_local_response_detailed(question,context_data,sources,similar,memories=None):
    conversational=assistant_conversation_intent(question)
    if conversational:
        return conversational

    direct=assistant_direct_answer(question,context_data,sources)
    if direct:
        return direct

    signals=assistant_detect_signals(question,context_data)
    query_text=question+' '+context_data.get('texte','')
    query_tokens=assistant_tokens(query_text)

    check_candidates=[]
    cause_candidates=[]
    step_candidates=[]
    warning_candidates=[]

    for item in sources[:5]:
        title,maker,typ,summary=core_meta(item)
        meta_tokens=assistant_tokens(' '.join(x for x in (title,maker,typ,summary) if x))
        meta_boost=max(0,len(query_tokens & meta_tokens))
        data=item.get('data') or {}
        for key,value in assistant_flatten(data):
            key_low=key.lower()
            clean=' '.join(str(value).split()).strip()
            if not clean:
                continue
            direct_score=len(query_tokens & assistant_tokens(clean))
            score=direct_score+meta_boost
            pair=(score,clean)
            if any(x in key_low for x in ('verification','vérification','controle','contrôle','test','prerequis','prérequis')):
                check_candidates.append(pair)
            if any(x in key_low for x in ('cause','origine','hypothese','hypothèse')):
                cause_candidates.append(pair)
            if any(x in key_low for x in ('procedure','procédure','etape','étape','action','solution','conseil','diagnostic')):
                step_candidates.append(pair)
            if any(x in key_low for x in ('attention','avertissement','warning','securite','sécurité','risque','important')):
                warning_candidates.append((direct_score,clean))

    specific=assistant_specific_symptom_guidance(question,context_data)
    summary,default_causes,default_steps,followup=(specific if specific else assistant_default_guidance(signals,question,context_data))

    checks=assistant_ranked_unique(check_candidates,5)
    causes=assistant_ranked_unique(cause_candidates,4)
    steps=assistant_ranked_unique(step_candidates,5)
    warnings=assistant_ranked_unique(warning_candidates,3,minimum_score=1)

    if specific:
        # Pour un symptôme reconnu précisément, les règles ciblées passent avant les fiches génériques hors contexte.
        causes=default_causes
        checks=default_steps
        steps=default_steps
    else:
        if not checks:
            checks=default_steps[:2]+['Éviter de modifier la configuration tant qu’un test simple n’a pas confirmé la cause.']
        if not causes:
            causes=default_causes
        if not steps:
            steps=default_steps

    if signals.get('camera') and signals.get('ping_ok') and signals.get('not_visible_nvr'):
        checks=[
            'Confirmer que la caméra répond toujours en direct : interface web, service ONVIF ou flux RTSP.',
            'Contrôler dans le NVR/VMS les identifiants, le protocole, le port et l’état du canal.',
            'Vérifier si un changement récent (mot de passe, mise à jour, codec, profil vidéo) a pu casser l’intégration.',
        ]
        causes=default_causes
        steps=default_steps

    if signals.get('fire'):
        extra='Contexte incendie/SSI : ne pas neutraliser, shunter ou contourner une fonction de sécurité. Se limiter aux contrôles autorisés et à la documentation constructeur.'
        if extra not in warnings:
            warnings.insert(0,extra)
    if signals.get('cyber'):
        extra='Contexte réseau/cybersécurité : rester sur des opérations défensives et autorisées sur les systèmes de l’entreprise.'
        if extra not in warnings:
            warnings.append(extra)

    known=assistant_known_facts(signals)
    confidence=assistant_confidence(question,sources,similar)

    source_titles=[]
    for idx,item in enumerate(sources[:4],1):
        title,maker,typ,item_summary=core_meta(item)
        label=' · '.join(x for x in (maker,title) if x)
        if label:
            source_titles.append(f'[S{idx}] {label}')

    case_lines=[]
    for idx,(score,intervention,eq) in enumerate(similar[:2],1):
        equipment=f'{eq.marque} {eq.modele}'.strip() if eq else 'équipement non précisé'
        solution=(intervention.solution or intervention.actions_realisees or '').strip()
        if solution:
            case_lines.append(f'[C{idx}] {equipment} — précédent cas résolu : {solution[:260]}')

    lines=['ANALYSE RAPIDE', summary]
    if known:
        lines += ['', 'CE QUI SEMBLE DÉJÀ CONFIRMÉ']
        lines += [f'- {value}' for value in known]

    lines += ['', 'HYPOTHÈSES LES PLUS PLAUSIBLES']
    lines += [f'{idx}. {value}' for idx,value in enumerate(causes,1)]

    lines += ['', 'PROCHAINES VÉRIFICATIONS UTILES']
    lines += [f'{idx}. {value}' for idx,value in enumerate(checks,1)]

    lines += ['', 'PROCHAINE ACTION CONSEILLÉE']
    lines += [f'{idx}. {value}' for idx,value in enumerate(steps,1)]

    lines += ['', 'QUESTION UTILE POUR AVANCER', followup]

    if case_lines:
        lines += ['', 'MÉMOIRE TERRAIN'] + case_lines

    if warnings:
        lines += ['', 'POINTS DE VIGILANCE'] + [f'- {value}' for value in warnings[:3]]

    atlas_neighbours=core_symptom_search(question,context_data.get('texte',''),limit=6)
    if atlas_neighbours:
        lines += ['', 'ATLAS NOX-IA — SYMPTÔMES VOISINS À DISTINGUER']
        for row in atlas_neighbours:
            lines.append(f'- {row.get("symptome","")} · {row.get("domaine","")} · {row.get("rarete","")}')

    lines += ['', f'NIVEAU DE CONFIANCE : {confidence}']
    if source_titles:
        lines += ['', 'SOURCES NOX-CORE'] + source_titles

    if memories:
        lines += ['', 'MÉMOIRE INTERNE PERTINENTE']
        for idx,row in enumerate(memories[:3],1):
            lines.append(f'[M{idx}] {row.title} — {row.content[:260]}')

    return '\n'.join(lines)



def assistant_local_response(question,context_data,sources,similar,memories=None,conversation_state=''):
    conversational=assistant_conversation_intent(question)
    if conversational:return conversational
    direct=assistant_direct_answer(question,context_data,sources)
    if direct:return direct
    if assistant_requested_full_detail(question):
        return assistant_local_response_detailed(question,context_data,sources,similar,memories=memories)
    step=assistant_interactive_next_step(question,context_data,conversation_state)
    return assistant_interactive_render(step,conversation_state,memories)

ASSISTANT_SYSTEM_PROMPT="""Tu es NOX-IA, un assistant conversationnel de niveau expert pour les techniciens terrain en sûreté, sécurité électronique, vidéosurveillance, contrôle d'accès, intrusion, incendie/SSI, réseau, interphonie, VMS/NVR, alimentation, serveurs et systèmes associés.

Parle naturellement avec le technicien. Il peut écrire comme à un collègue : « salut », faire des fautes, employer des abréviations, commencer par une phrase incomplète ou raconter le problème dans le désordre. Comprends l'intention avant de répondre. Une salutation simple mérite une réponse simple. Une question simple mérite une réponse courte. Un diagnostic complexe peut être structuré. Ne force jamais un gros rapport si ce n'est pas utile. Tu es aussi capable de répondre aux questions générales ou basiques : si le message n'est ni technique ni lié à NOX-IA, réponds normalement avec tes connaissances générales au lieu de forcer un diagnostic. Si l'utilisateur change de sujet, suis le nouveau sujet.

Ton objectif est de diagnostiquer intelligemment un problème technique en exploitant d'abord :
1. le contexte réel de l'intervention ;
2. les extraits NOX-Core fournis et identifiés [S1], [S2], etc. ;
3. la mémoire de cas terrain résolus [C1], [C2], etc. ;
4. l'historique de conversation ;
5. l'atlas transversal des symptômes NOX-IA ;
6. la mémoire permanente accumulée sur les cas terrain.

Hiérarchie de confiance : documentation constructeur / sources officielles et cas terrain réellement résolus > diagnostics clôturés > mesures et observations explicites du technicien > mémos manuels > anciennes pistes générées par l'IA. Une ancienne réponse IA n'est jamais une preuve.

Règles de qualité :
- Raisonne à partir du symptôme observé et ne saute pas directement à une conclusion.
- Si le technicien t’a déjà donné une information confirmée (ex. caméra alimentée, ping OK, interface web OK), ne redemande pas la même vérification : pars de ce fait acquis et propose le test suivant le plus utile.
- Pour une question simple de type définition ou mode opératoire (ex. « c’est quoi ONVIF ? », « comment ajouter une caméra ? »), réponds de manière directe, pédagogique et concrète avant de complexifier.
- Évite les procédures trop spécifiques à une marque non mentionnée, sauf si les sources ou le contexte l’indiquent clairement.
- Utilise la mémoire permanente [M1], [M2]... comme expérience terrain : privilégie les cas résolus et diagnostics terminés aux simples anciennes réponses IA.
- Quand plusieurs sources semblent hors sujet, ignore-les plutôt que de les mélanger. Une réponse courte et juste vaut mieux qu'une longue procédure incohérente.
- Termine un diagnostic incomplet par UNE question vraiment utile qui dépend de ce que le technicien vient de dire.
- Construis un état de panne progressif : faits confirmés → hypothèses restantes → meilleur test discriminant → décision suivante.
- Ne répète jamais un test déjà confirmé sauf si une contradiction nouvelle oblige à le revalider.
- Si le technicien répond à ta question précédente, accuse réception implicitement et poursuis directement au test suivant.
- Si une référence exacte, un firmware, un manuel ou une caractéristique constructeur n'est pas suffisamment confirmé par NOX-Core, utilise la recherche web quand elle est disponible. Privilégie les sources officielles fabricant et cite ce qui vient du web.
- Classe les hypothèses par plausibilité : élevée, moyenne ou faible. N'invente pas de pourcentages.
- Quand une information essentielle manque, pose UNE question précise à forte valeur diagnostique, mais donne aussi les vérifications sûres réalisables immédiatement.
- Ne fabrique jamais une référence, un menu constructeur, une valeur électrique, un port, un code erreur ou une procédure absente des sources. Si une information n'est pas étayée, écris "à confirmer sur la documentation constructeur".
- Cite [S1], [S2]... après les affirmations techniques réellement soutenues par NOX-Core. Cite [C1], [C2]... lorsque tu t'appuies sur un ancien cas terrain.
- Distingue clairement : constat, hypothèses, tests, décision suivante.
- Tiens compte de ce qui a déjà été testé dans l'historique et évite de faire répéter inutilement le technicien.
- Privilégie une progression du moins intrusif au plus intrusif.
- Si une action peut provoquer une coupure, une perte de service, une modification de configuration ou un impact client, indique qu'elle doit être validée avant exécution.
- Pour l'incendie/SSI : ne propose jamais de neutraliser, shunter ou contourner une fonction de sécurité. Reste sur les lectures, constats, contrôles autorisés et procédures constructeur.
- Pour réseau/cybersécurité : reste sur du diagnostic défensif et autorisé. Ne propose pas de contournement d'authentification, extraction d'identifiants ou action offensive.
- Si les sources sont insuffisantes, dis-le explicitement.
- Réponds en français naturel, professionnel, concret et utilisable sur le terrain.
- Si le technicien dit qu'un test a déjà été fait (ex. ping OK, alimentation OK, port switch actif), considère ce résultat comme acquis et ne lui demande pas de recommencer sauf raison technique précise.
- Pour une panne, commence par reformuler très brièvement ce qui est déjà certain, puis donne la prochaine vérification qui apporte le plus d'information.
- MODE TERRAIN INTERACTIF PAR DÉFAUT : ne donne PAS toute la procédure d’un coup. Donne au maximum 1 ou 2 contrôles immédiatement utiles, explique brièvement ce que ce test permettra de trancher, puis pose UNE seule question qui permettra de choisir l’étape suivante.
- STYLE DE CONVERSATION : parle comme un excellent collègue technicien, pas comme un rapport automatique. Utilise des phrases naturelles, des transitions courtes et un ton calme. Évite les titres en MAJUSCULES, les blocs répétitifs « TESTE MAINTENANT / POURQUOI / DIS-MOI JUSTE » et les listes si une réponse en 2 à 4 petits paragraphes suffit.
- Ne commence pas chaque réponse par la même formule « OK, je garde… ». Varie naturellement : « D’accord », « Là, ça nous indique que… », « Parfait, donc… », ou entre directement dans le point utile quand le contexte est évident.
- Quand le technicien donne plusieurs faits déjà confirmés, résume-les en UNE phrase maximum, puis avance. Ne récite pas tous les faits à chaque tour.
- Une réponse normale doit être facile à lire à voix haute : phrases plutôt courtes, vocabulaire terrain, pas de jargon inutile. Explique un terme technique seulement s’il peut prêter à confusion.
- Pour une panne courante, vise généralement 3 à 7 phrases et termine par une question unique, directement répondable. Pour un « oui/non », poursuis comme dans une vraie conversation sans répéter le diagnostic depuis le début.
- Exemple de style attendu : « D’accord. Comme l’alimentation, le ping et l’interface web sont bons, je laisse de côté la couche réseau de base. Regarde maintenant le statut exact du canal dans le NVR, sans modifier les paramètres. Ce message va nous dire si on part sur l’authentification, ONVIF ou la configuration du canal. Il affiche quoi exactement ? »
- Si le technicien demande explicitement « détaille tout », « rapport complet », « toutes les causes » ou équivalent, tu peux alors produire une analyse longue et structurée.
- Ne noie pas le technicien avec l’atlas, les sources ou la mémoire : utilise-les en arrière-plan et ne montre que ce qui influence réellement la prochaine décision.
- Structure en rubriques uniquement quand cela améliore vraiment le diagnostic.
- RAISONNEMENT CACHÉ : réfléchis autant que nécessaire en interne, mais n’affiche jamais de chaîne de pensée, d’auto-évaluation, de plan de raisonnement ou de commentaires méta. Montre uniquement la réponse utile au technicien.
- FILTRAGE DES CAUSES RARES : garde les pannes rares dans tes hypothèses internes, mais ne les présente pas tant qu’un fait ne les rend pas crédibles ou que les causes courantes n’ont pas été éliminées.
- QUALITÉ DE LA QUESTION : la question finale doit être facile à répondre depuis le terrain (un état, un message exact, oui/non, une valeur lue). Évite « donne-moi plus de détails » si une question plus précise est possible.
- ADAPTATION : si le technicien veut juste comprendre un terme, réponds directement. S’il dépanne, avance une étape. S’il demande « détaille tout », donne l’analyse complète.
- MÉMOIRE : une validation explicite du technicien (« ça marche », « résolu ») après une étape est une preuve terrain forte. Réutilise ces validations quand un cas similaire revient, sans les généraliser à tort à d’autres modèles/versions.
"""

def assistant_ai_enabled():
    return bool(os.environ.get('OPENAI_API_KEY','').strip())

def assistant_ai_model():
    return os.environ.get('OPENAI_MODEL','gpt-5.6').strip() or 'gpt-5.6'

def assistant_ai_reasoning():
    value=os.environ.get('OPENAI_REASONING_EFFORT','medium').strip().lower()
    if value not in {'none','low','medium','high','xhigh','max'}:
        value='medium'
    return value

def assistant_safety_identifier(user):
    raw=f'nox-ia:{user.id}:{user.username}'.encode('utf-8')
    return hashlib.sha256(raw).hexdigest()[:40]

def assistant_generate_advanced(
    db,
    user,
    question,
    intervention_id,
    context_data,
    sources,
    similar,
    memories=None,
):
    from openai import OpenAI

    api_key=os.environ.get('OPENAI_API_KEY','').strip()
    if not api_key:
        raise RuntimeError('OPENAI_API_KEY absente')

    model=assistant_ai_model()
    history=assistant_history_for_prompt(
        db,
        intervention_id,
        user.id,
        limit=10,
    )
    conversation_state=assistant_conversation_state(db,intervention_id,user.id,limit=14)
    source_text='\n\n'.join(
        assistant_source_excerpt(item,idx)
        for idx,item in enumerate(sources,1)
    ) or 'Aucune source NOX-Core pertinente.'
    cases_text=assistant_similar_cases_text(similar)
    memory_text=assistant_memory_text(memories or [])
    symptom_text=assistant_symptom_atlas_text(question,context_data.get('texte','')+' '+conversation_state,limit=24)

    prompt=f"""MESSAGE ACTUEL DU TECHNICIEN
{question}

CONTEXTE TECHNIQUE DE L'INTERVENTION
{assistant_external_context(context_data)}

HISTORIQUE RÉCENT
{history}

FAITS DÉJÀ ÉTABLIS DANS LA CONVERSATION
{conversation_state}

EXTRAITS NOX-CORE
{source_text}

MÉMOIRE DE CAS TERRAIN RÉSOLUS
{cases_text}

MÉMOIRE INTERNE PERMANENTE NOX-IA
{memory_text}

ATLAS DES SYMPTÔMES CONNUS / RARES
{symptom_text}

IMPORTANT CONVERSATION
Si le message actuel est court (ex. oui, non, toujours pas, ça marche), interprète-le comme la réponse à la dernière question de NOX-IA dans l'historique. Ne repars pas de zéro et ne redemande pas une information déjà confirmée.
Traite la rubrique « FAITS DÉJÀ ÉTABLIS » comme l'état courant du diagnostic. Si un nouveau message contredit un ancien fait, signale simplement la contradiction et demande UNE précision ciblée au lieu d'inventer.
Avance comme un technicien expert : chaque réponse doit utiliser le résultat du test précédent pour choisir le test suivant. Ne donne pas une liste générique si le problème est déjà suffisamment localisé. Utilise l'atlas des symptômes pour envisager aussi des pannes moins courantes, mais ne les présente comme plausibles que si les faits les soutiennent.

MODE TERRAIN INTERACTIF : sauf demande explicite de réponse complète, donne seulement le meilleur test discriminant (éventuellement un second contrôle très lié), explique brièvement pourquoi, puis pose UNE question. Attends la réponse du technicien avant l’étape suivante. Ne déroule pas toutes les hypothèses ni toute la procédure en une fois.

Produis maintenant le diagnostic le plus utile pour le technicien. Ne suppose pas qu'une hypothèse est vraie tant qu'un test ne l'a pas confirmée. Si une référence ou une donnée constructeur manque dans NOX-Core, utilise la recherche web si elle est disponible et privilégie les sources officielles."""

    client=OpenAI(
        api_key=api_key,
        timeout=float(os.environ.get('OPENAI_TIMEOUT_SECONDS','55')),
    )

    kwargs={'model':model,'instructions':ASSISTANT_SYSTEM_PROMPT,'input':prompt,'reasoning':{'effort':assistant_ai_reasoning()},'text':{'verbosity':'medium'},'store':False,'safety_identifier':assistant_safety_identifier(user)}
    if assistant_web_lookup_enabled():
        kwargs['tools']=[{'type':'web_search'}];kwargs['tool_choice']='auto';kwargs['include']=['web_search_call.action.sources']
    response=client.responses.create(**kwargs)

    output=(response.output_text or '').strip()
    if not output:raise RuntimeError('Réponse IA vide')
    web_sources=assistant_extract_web_sources(response,limit=5)
    if web_sources:output += '\n\nSOURCES WEB\n' + '\n'.join(f'- {row["title"]}: {row["url"]}' for row in web_sources)
    return output

def assistant_sources_json(sources):
    out=[]
    for item in sources:
        title,maker,typ,summary=core_meta(item)
        out.append({
            'titre':title,
            'constructeur':maker,
            'type':typ,
            'resume':summary[:500],
            'source_file':item.get('source_file',''),
            'source_group':item.get('source_group',''),
        })
    return json.dumps(out,ensure_ascii=False)

def assistant_sources_html(raw):
    try:
        rows=json.loads(raw or '[]')
    except Exception:
        rows=[]

    if not rows:
        return '<span class="muted">Aucune source NOX-Core associée.</span>'

    return ''.join(
        f'<div class="source-card"><b>{escape(row.get("constructeur",""))} {escape(row.get("titre",""))}</b>'
        f'<div class="muted">{escape(row.get("type",""))} · {escape(row.get("source_file",""))}</div></div>'
        for row in rows
    )





def assistant_local_payload_data(db,user,question,intervention_id=None):
    """Paquet conversationnel local : général + métier + RAG technique, sans noyer le modèle 4B."""
    context_data=assistant_context(db,intervention_id)
    recent_history=assistant_history_for_prompt(db,intervention_id,user.id,limit=9)
    conversation_state=assistant_conversation_state(db,intervention_id,user.id,limit=24)
    mode=assistant_query_mode(question,context_data,recent_history)

    conversation_query=question
    if assistant_short_reply(question) and recent_history!='Aucun échange précédent.':
        conversation_query=recent_history[-4200:]+'\nRéponse actuelle du technicien: '+question

    product_context=noxia_product_context(conversation_query) if mode=='noxia' else 'Aucune aide NOX-IA spécifique nécessaire.'
    live_data=assistant_live_noxia_data(db,user,conversation_query) if mode=='noxia' else 'Aucune donnée métier live nécessaire.'

    # Pour une question générale, le modèle peut utiliser sa culture générale sans être pollué par des fiches techniques.
    if mode=='general':
        system=(
            "Tu es NOX-Local, l'assistant conversationnel local de NOX-IA. Réponds toujours en français naturel et fluide. "
            "Tu peux répondre aux questions générales et basiques avec tes connaissances intégrées : définitions, explications, calculs simples, informatique générale, rédaction courte ou conversation normale. "
            "Ne ramène pas artificiellement une question générale vers la sûreté ou le dépannage. Garde le fil des DERNIERS ÉCHANGES, mais si l'utilisateur change clairement de sujet, suis le nouveau sujet. "
            "Si une information dépend fortement de l'actualité ou si tu n'es pas sûr d'un fait précis, dis simplement que c'est à vérifier plutôt que d'inventer. "
            "N'affiche jamais ton raisonnement interne ni une chaîne de pensée. Donne seulement la réponse utile. Une question simple mérite une réponse simple ; n'ajoute pas systématiquement une question finale."
        )
        prompt=f"""MESSAGE ACTUEL\n{question}\n\nDERNIERS ÉCHANGES\n{recent_history}\n\nTÂCHE\nRéponds comme dans une vraie conversation. Comprends les fautes, abréviations et phrases incomplètes. Si le message répond au tour précédent, poursuis naturellement ; s'il ouvre un nouveau sujet, réponds au nouveau sujet sans mélanger l'ancien."""
        return {'model':'nox-tech:4b','system':system,'messages':[{'role':'user','content':prompt}],'sources_json':'[]','context_data':context_data,'mode':mode}

    search_context=context_data['texte']+' '+recent_history+' '+conversation_state+' '+product_context+' '+live_data
    memories=assistant_memory_search(db,conversation_query+' '+assistant_memory_keywords(search_context),limit=10)
    memory_text=assistant_memory_text(memories,5200)
    symptom_text=assistant_symptom_atlas_text(conversation_query,search_context,limit=12) if mode=='technical' else 'Atlas technique non nécessaire pour cette question métier.'
    sources=assistant_deep_sources(conversation_query,context_data,recent_history,conversation_state,memory_text,limit=8) if mode=='technical' else assistant_search_nox_core(conversation_query,search_context,limit=4)
    similar=assistant_similar_interventions(db,conversation_query,context_data,limit=3) if mode=='technical' else []
    source_text='\n\n'.join(assistant_source_excerpt(item,idx,max_chars=1250) for idx,item in enumerate(sources,1)) or 'Aucune fiche NOX-Core suffisamment proche.'
    cases_text=assistant_similar_cases_text(similar)
    software_text=software_profile_text(conversation_query) if mode=='technical' else 'Aucun profil logiciel nécessaire.'

    system=(
        "Tu es NOX-Local, le cerveau local technique ET métier de NOX-IA. Réponds uniquement en français naturel, comme un excellent collègue qui garde réellement le fil. "
        "Tu peux aussi répondre aux questions basiques avec tes connaissances générales. Ne force jamais un diagnostic si la personne demande juste une explication. "
        "Lis d'abord les FAITS ÉTABLIS et les DERNIERS ÉCHANGES. Un fait confirmé est acquis ; une étape marquée test_invalide a déjà échoué dans ce cas et ne doit pas être répétée sans raison nouvelle. "
        "Pour le terrain, exploite à fond mais silencieusement : contexte, NOX-Core, profils logiciels, cas résolus, atlas et mémoire permanente. Cherche les recoupements avant de conclure. Validation terrain/cas résolu > diagnostic terminé > observation mesurée > mémo > ancienne piste IA. "
        "Pour NOX-IA et les données métier, utilise le GUIDE NOX-IA et DONNÉES LIVE. N'invente jamais un chiffre, un menu ou une fonction absente de ces blocs. Respecte les permissions : seules les données fournies dans le prompt sont autorisées. "
        "Si les sources ne suffisent pas à confirmer une valeur, référence, firmware, port, menu ou procédure constructeur, dis 'à confirmer sur la documentation constructeur'. Tu peux proposer une hypothèse raisonnable en la présentant comme hypothèse, jamais comme fait. "
        "En dépannage : élimine ce qui est déjà prouvé, classe silencieusement les hypothèses restantes, choisis le test le plus discriminant, donne 1 contrôle (2 maximum s'ils sont liés), puis UNE question précise. Ne tourne pas en boucle. "
        "Si l'utilisateur dit 'pareil', 'toujours pas' ou 'ça marche pas', considère que l'étape précédente n'a pas résolu le problème et avance. S'il dit 'ça marche' ou 'résolu', considère la validation terrain comme forte. "
        "Si l'utilisateur change de sujet, change de sujet avec lui. Pour une question générale ou métier simple, réponds directement et ne termine pas obligatoirement par une question. "
        "N'affiche jamais ton raisonnement interne, ton plan ou ton auto-évaluation. Pour SSI/incendie, ne neutralise aucune fonction de sécurité ; en cybersécurité, reste défensif et autorisé. "
        "Style : phrases naturelles, courtes, pas de gabarit robotique, pas de gros titres inutiles. En général 2 à 4 petits paragraphes ; détaille seulement si l'utilisateur le demande ou si c'est nécessaire."
    )

    prompt=f"""MODE DÉTECTÉ\n{mode}\n\nMESSAGE ACTUEL\n{question}\n\nCONTEXTE INTERVENTION\n{assistant_external_context(context_data)}\n\nFAITS ÉTABLIS — PRIORITÉ MAXIMALE\n{conversation_state}\n\nDERNIERS ÉCHANGES\n{recent_history}\n\nMÉMOIRE PERTINENTE (test_invalide = étape déjà sans effet, pas une solution)\n{memory_text}\n\nCAS TERRAIN RÉSOLUS PROCHES\n{cases_text}\n\nNOX-CORE RETROUVÉ PAR RECHERCHE APPROFONDIE\n{source_text}\n\nPROFILS LOGICIELS LOCAUX\n{software_text}\n\nATLAS DES SYMPTÔMES (pistes, jamais preuves)\n{symptom_text}\n\nGUIDE DE L'APPLICATION NOX-IA\n{product_context}\n\nDONNÉES MÉTIER LIVE AUTORISÉES\n{live_data}\n\nTÂCHE\nRéponds au message actuel dans le fil. Utilise tout ce qui est pertinent ci-dessus sans le réciter. Si plusieurs éléments se contredisent, signale la contradiction et demande la précision minimale. Si une solution déjà validée sur un cas très proche existe, utilise-la comme priorité tout en vérifiant la compatibilité du contexte. Si aucune source ne confirme une cause, ne fais pas semblant : continue le diagnostic avec le meilleur test discriminant."""
    return {'model':'nox-tech:4b','system':system,'messages':[{'role':'user','content':prompt}],'sources_json':assistant_sources_json(sources),'context_data':context_data,'mode':mode}


@app.post('/assistant/rapide')
def assistant_quick_reply(request:Request,reply:str=Form(...),intervention_id:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    # Boutons rapides 100 % serveur : ils fonctionnent même si le JavaScript local/extension est indisponible.
    return assistant_analyse(request=request,question=reply,intervention_id=intervention_id,csrf_token_value=csrf_token_value,db=db)

@app.post('/assistant/local-payload')
def assistant_local_payload(request:Request,question:str=Form(...),intervention_id:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);user=require_login(request,db);require_role(user,ASSISTANT_USERS)
    question=question.strip()
    if not question:raise HTTPException(400,detail='Question vide')
    iid=int(intervention_id) if intervention_id.strip() else None
    data=assistant_local_payload_data(db,user,question,iid)
    return JSONResponse({'ok':True,'model':data['model'],'system':data['system'],'messages':data['messages'],'sources_json':data['sources_json']})

@app.post('/assistant/local-save')
def assistant_local_save(request:Request,question:str=Form(...),response_text:str=Form(...),intervention_id:str=Form(''),sources_json:str=Form('[]'),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);user=require_login(request,db);require_role(user,ASSISTANT_USERS)
    question=question.strip();response_text=assistant_clean_local_output(response_text)
    if not question or not response_text:raise HTTPException(400,detail='Question ou réponse locale vide')
    iid=int(intervention_id) if intervention_id.strip() else None
    context_data=assistant_context(db,iid)
    assistant_memory_learn_turn_validation(db,user,question,context_data,iid)
    assistant_memory_learn_turn_failure(db,user,question,context_data,iid)
    try:
        parsed=json.loads(sources_json or '[]')
        if not isinstance(parsed,list):parsed=[]
        safe_sources=json.dumps(parsed[:12],ensure_ascii=False)
    except Exception:safe_sources='[]'
    exchange=AssistantExchange(intervention_id=iid,equipement_id=(context_data['equipement'].id if context_data['equipement'] else None),user_id=user.id,utilisateur=user.username,question=question,contexte=(context_data['texte']+'\nMode: cerveau local')[-12000:],reponse=response_text,sources_json=safe_sources)
    db.add(exchange)
    assistant_memory_learn_exchange(db,user,question,response_text,context_data,iid)
    db.commit();db.refresh(exchange)
    redirect='/assistant'+(f'?intervention_id={iid}' if iid else '')+'#last-exchange'
    return JSONResponse({'ok':True,'redirect':redirect,'exchange_id':exchange.id})



QUOTE_MIN_MARGIN_NO_APPROVAL=float(os.environ.get('NOXIA_QUOTE_MIN_MARGIN_NO_APPROVAL','20'))
QUOTE_MAX_DISCOUNT_NO_APPROVAL=float(os.environ.get('NOXIA_QUOTE_MAX_DISCOUNT_NO_APPROVAL','10'))

def quote_snapshot_payload(db,q):
    lines=db.scalars(select(QuoteLine).where(QuoteLine.quote_id==q.id).order_by(QuoteLine.id)).all()
    return {
        'quote':{'reference':q.reference,'client_id':q.client_id,'site_id':q.site_id,'commercial':q.commercial,'objet':q.objet,'statut':q.statut,'remise_pct':float(q.remise_pct or 0),'notes':q.notes,'date_validite':q.date_validite.isoformat() if q.date_validite else None},
        'lines':[{'id':l.id,'type':l.type_ligne,'stock_item_id':l.stock_item_id,'supplier_id':l.supplier_id,'designation':l.designation,'quantite':float(l.quantite or 0),'cout_unitaire':float(l.cout_unitaire or 0),'vente_unitaire':float(l.vente_unitaire or 0),'notes':l.notes} for l in lines]
    }

def quote_snapshot_hash(db,q):
    raw=json.dumps(quote_snapshot_payload(db,q),ensure_ascii=False,sort_keys=True,separators=(',',':')).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()

def quote_create_version(db,q,user,note=''):
    payload=quote_snapshot_payload(db,q)
    _,cost,sale,margin,margin_pct=quote_totals(db,q)
    last=db.scalar(select(func.max(QuoteVersion.version_no)).where(QuoteVersion.quote_id==q.id)) or 0
    row=QuoteVersion(quote_id=q.id,version_no=int(last)+1,snapshot_json=json.dumps(payload,ensure_ascii=False),totals_json=json.dumps({'cost':cost,'sale':sale,'margin':margin,'margin_pct':margin_pct},ensure_ascii=False),note=(note or '').strip(),created_by=user.username)
    db.add(row);db.flush();return row

def quote_thresholds(db):
    try:
        min_margin=float(get_setting(db,'quote_min_margin_pct',str(QUOTE_MIN_MARGIN_NO_APPROVAL)))
        max_discount=float(get_setting(db,'quote_max_discount_pct',str(QUOTE_MAX_DISCOUNT_NO_APPROVAL)))
        return min_margin,max_discount
    except Exception:return QUOTE_MIN_MARGIN_NO_APPROVAL,QUOTE_MAX_DISCOUNT_NO_APPROVAL

def quote_needs_approval(db,q,margin_pct):
    min_margin,max_discount=quote_thresholds(db)
    return float(margin_pct or 0)<min_margin or float(q.remise_pct or 0)>max_discount

def quote_valid_approval(db,q):
    current=quote_snapshot_hash(db,q)
    return db.scalar(select(QuoteApproval).where(QuoteApproval.quote_id==q.id,QuoteApproval.snapshot_hash==current,QuoteApproval.statut=='Approuvé').order_by(QuoteApproval.decided_at.desc()).limit(1))

def quote_pending_approval(db,q):
    current=quote_snapshot_hash(db,q)
    return db.scalar(select(QuoteApproval).where(QuoteApproval.quote_id==q.id,QuoteApproval.snapshot_hash==current,QuoteApproval.statut=='En attente').order_by(QuoteApproval.requested_at.desc()).limit(1))

def quote_actual_totals(db,q):
    rows=db.scalars(select(QuoteActualLine).where(QuoteActualLine.quote_id==q.id).order_by(QuoteActualLine.created_at)).all()
    actual_cost=sum(float(x.quantite or 0)*float(x.cout_unitaire_reel or 0) for x in rows)
    _,planned_cost,sale,planned_margin,planned_margin_pct=quote_totals(db,q)
    real_margin=sale-actual_cost
    real_margin_pct=(real_margin/sale*100) if sale>0 else 0.0
    return rows,planned_cost,actual_cost,sale,planned_margin,planned_margin_pct,real_margin,real_margin_pct

def _xlsx_col(n):
    out=''
    while n:
        n,rem=divmod(n-1,26);out=chr(65+rem)+out
    return out

def _xlsx_cell(row,col,value,style=0,number=False):
    ref=f'{_xlsx_col(col)}{row}'
    s=f' s="{style}"' if style else ''
    if number:
        try:v=float(value)
        except:v=0.0
        return f'<c r="{ref}"{s}><v>{v}</v></c>'
    txt=xml_escape(str(value if value is not None else ''))
    return f'<c r="{ref}" t="inlineStr"{s}><is><t>{txt}</t></is></c>'

def quote_xlsx_bytes(db,q):
    lines,cost,sale,margin,margin_pct=quote_totals(db,q)
    client=db.get(Client,q.client_id);site=db.get(Site,q.site_id) if q.site_id else None
    rows=[]
    def add(vals,style=0,numeric=None):
        r=len(rows)+1;numeric=set(numeric or [])
        rows.append('<row r="%d">%s</row>'%(r,''.join(_xlsx_cell(r,i+1,v,style,(i in numeric)) for i,v in enumerate(vals))))
    add(['NOX-IA — Devis',q.reference],1)
    add(['Client',client.nom if client else ''])
    add(['Site',site.nom if site else ''])
    add(['Objet',q.objet])
    add(['Commercial',q.commercial])
    add(['Statut',q.statut])
    add([])
    add(['Type','Désignation','Quantité','Coût unitaire','Vente unitaire','Coût total','Vente totale'],1)
    for l in lines:
        add([l.type_ligne,l.designation,float(l.quantite),float(l.cout_unitaire),float(l.vente_unitaire),float(l.quantite)*float(l.cout_unitaire),float(l.quantite)*float(l.vente_unitaire)],0,{2,3,4,5,6})
    add([])
    add(['Remise %',float(q.remise_pct or 0)],1,{1})
    add(['Coût total',cost],1,{1});add(['Vente après remise',sale],1,{1});add(['Marge',margin],1,{1});add(['Marge %',margin_pct],1,{1})
    sheet='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><cols><col min="1" max="1" width="20" customWidth="1"/><col min="2" max="2" width="46" customWidth="1"/><col min="3" max="7" width="16" customWidth="1"/></cols><sheetData>'+''.join(rows)+'</sheetData></worksheet>'
    styles='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border/></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0"/></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>'
    content='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>'
    rootrels='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'
    workbook='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Devis" sheetId="1" r:id="rId1"/></sheets></workbook>'
    wbrels='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>'
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml',content);z.writestr('_rels/.rels',rootrels);z.writestr('xl/workbook.xml',workbook);z.writestr('xl/_rels/workbook.xml.rels',wbrels);z.writestr('xl/styles.xml',styles);z.writestr('xl/worksheets/sheet1.xml',sheet)
    return out.getvalue()

@app.get('/catalogue-commercial')
def commercial_catalog(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(CommercialCatalogItem).order_by(CommercialCatalogItem.categorie,CommercialCatalogItem.designation)).all();stocks=db.scalars(select(StockItem).where(StockItem.actif.is_(True)).order_by(StockItem.designation)).all();trs=''
    for x in rows:
        state='Actif' if x.actif else 'Inactif';m=(float(x.vente_unitaire or 0)-float(x.cout_unitaire or 0));mp=(m/float(x.vente_unitaire)*100) if float(x.vente_unitaire or 0)>0 else 0
        trs+=f'<tr><td><b>{escape(x.code)}</b></td><td>{escape(x.categorie)}</td><td>{escape(x.designation)}</td><td>{escape(x.unite)}</td><td>{money(x.cout_unitaire)}</td><td>{money(x.vente_unitaire)}</td><td>{money(m)} · {mp:.1f}%</td><td>{x.tva_pct:.1f}%</td><td>{badge(state)}</td></tr>'
    form=''
    if u.role in COMMERCIALS:
        form=f'''<section class="card"><h2>Ajouter au catalogue</h2><form method="post" action="/catalogue-commercial" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Code<input name="code" placeholder="MO-TECH / CAM-001" required></label><label>Catégorie<select name="categorie"><option>Matériel</option><option>Main-d’œuvre</option><option>Service</option><option>Déplacement</option><option>Autre</option></select></label><label>Article stock lié<select name="stock_item_id">{option_rows(stocks,lambda x:x.id,lambda x:f"{x.reference} · {x.designation}",empty="Aucun")}</select></label><label>Désignation<input name="designation" required></label><label>Unité<input name="unite" value="u"></label><label>Coût unitaire<input type="number" min="0" step=".01" name="cout_unitaire" value="0"></label><label>Prix de vente<input type="number" min="0" step=".01" name="vente_unitaire" value="0"></label><label>TVA %<input type="number" min="0" step=".1" name="tva_pct" value="20"></label><label class="full">Notes<textarea name="notes"></textarea></label><button class="btn primary">Ajouter</button></form><form method="post" action="/catalogue-commercial/import-stock" style="margin-top:10px"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn">Importer les articles du stock manquants</button></form></section>'''
    return page(request,u,'Catalogue commercial',f'<div class="head"><div><h1>Catalogue commercial</h1><p class="muted">Bibliothèque des matériels, heures, services et déplacements utilisés dans les devis.</p></div></div>{form}<section class="card"><div class="scroll"><table><tr><th>Code</th><th>Catégorie</th><th>Désignation</th><th>Unité</th><th>Coût</th><th>Vente</th><th>Marge</th><th>TVA</th><th>État</th></tr>{trs or "<tr><td colspan=9>Aucune ligne catalogue.</td></tr>"}</table></div></section>')

@app.post('/catalogue-commercial')
def commercial_catalog_add(request:Request,code:str=Form(...),categorie:str=Form('Matériel'),stock_item_id:str=Form(''),designation:str=Form(...),unite:str=Form('u'),cout_unitaire:float=Form(0),vente_unitaire:float=Form(0),tva_pct:float=Form(20),notes:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,COMMERCIALS)
    if db.scalar(select(CommercialCatalogItem).where(CommercialCatalogItem.code==code.strip())):raise HTTPException(400,'Code catalogue déjà utilisé')
    item=db.get(StockItem,int(stock_item_id)) if stock_item_id else None
    cost=max(0,float(cout_unitaire or 0));
    if item and cost<=0:cost=default_stock_cost(db,item)
    db.add(CommercialCatalogItem(code=code.strip(),categorie=categorie,stock_item_id=(item.id if item else None),designation=designation.strip(),unite=unite.strip() or 'u',cout_unitaire=cost,vente_unitaire=max(0,float(vente_unitaire or 0)),tva_pct=max(0,float(tva_pct or 0)),notes=notes.strip(),actif=True));db.commit();return RedirectResponse('/catalogue-commercial',303)

@app.post('/catalogue-commercial/import-stock')
def commercial_catalog_import_stock(request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,COMMERCIALS);created=0
    for item in db.scalars(select(StockItem).where(StockItem.actif.is_(True)).order_by(StockItem.id)).all():
        if db.scalar(select(CommercialCatalogItem).where(CommercialCatalogItem.stock_item_id==item.id)):continue
        code=('MAT-'+re.sub(r'[^A-Za-z0-9]+','-',item.reference).strip('-'))[:120]
        base=code;i=2
        while db.scalar(select(CommercialCatalogItem).where(CommercialCatalogItem.code==code)):
            code=(base[:110]+f'-{i}')[:120];i+=1
        db.add(CommercialCatalogItem(code=code,categorie='Matériel',stock_item_id=item.id,designation=item.designation,unite='u',cout_unitaire=default_stock_cost(db,item),vente_unitaire=0,tva_pct=20,notes='Importé depuis le stock',actif=True));created+=1
    db.commit();return RedirectResponse(f'/catalogue-commercial?msg={created}+article(s)+importé(s)',303)

@app.get('/affaires')
def workorders_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(QuoteWorkOrder).order_by(QuoteWorkOrder.created_at.desc())).all();trs=''
    for w in rows:
        q=db.get(Quote,w.quote_id);c=db.get(Client,w.client_id);s=db.get(Site,w.site_id) if w.site_id else None
        ilink=f'<a href="/interventions/{w.intervention_id}">#{w.intervention_id}</a>' if w.intervention_id else '—'
        trs+=f'<tr><td><b>{escape(w.reference)}</b></td><td><a href="/devis/{w.quote_id}">{escape(q.reference if q else "—")}</a></td><td>{escape(c.nom if c else "—")}</td><td>{escape(s.nom if s else "—")}</td><td>{badge(w.statut)}</td><td>{ilink}</td><td>{escape(w.responsable or "—")}</td><td>{dfr(w.created_at)}</td></tr>'
    return page(request,u,'Affaires / chantiers',f'<div class="head"><div><h1>Affaires / chantiers</h1><p class="muted">Suivi des devis acceptés transformés en réalisation.</p></div></div><section class="card"><div class="scroll"><table><tr><th>Affaire</th><th>Devis</th><th>Client</th><th>Site</th><th>Statut</th><th>Intervention</th><th>Responsable</th><th>Créée</th></tr>{trs or "<tr><td colspan=8>Aucune affaire.</td></tr>"}</table></div></section>')

@app.post('/devis/{qid}/versions')
def quote_version_create(qid:int,request:Request,note:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,COMMERCIALS);q=db.get(Quote,qid)
    if not q:raise HTTPException(404)
    row=quote_create_version(db,q,u,note);db.commit();return RedirectResponse(f'/devis/{qid}/versions?msg=Version+V{row.version_no}+créée',303)

@app.get('/devis/{qid}/versions')
def quote_versions(qid:int,request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);q=db.get(Quote,qid)
    if not q:raise HTTPException(404)
    rows=db.scalars(select(QuoteVersion).where(QuoteVersion.quote_id==qid).order_by(QuoteVersion.version_no.desc())).all();trs=''
    for x in rows:
        try:t=json.loads(x.totals_json or '{}')
        except:t={}
        trs+=f'<tr><td><b>V{x.version_no}</b></td><td>{dfr(x.created_at)}</td><td>{escape(x.created_by)}</td><td>{money(t.get("sale",0))}</td><td>{money(t.get("margin",0))} · {float(t.get("margin_pct",0)):.1f}%</td><td>{escape(x.note or "—")}</td></tr>'
    form=f'<section class="card"><h2>Créer une version</h2><form method="post" action="/devis/{qid}/versions" class="inline-form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><input name="note" placeholder="Ex. V2 après modification client"><button class="btn primary">Enregistrer la version</button></form></section>' if u.role in COMMERCIALS else ''
    return page(request,u,f'Versions {q.reference}',f'<div class="head"><div><h1>Versions · {escape(q.reference)}</h1></div><a class="btn" href="/devis/{qid}">Retour</a></div>{form}<section class="card"><div class="scroll"><table><tr><th>Version</th><th>Date</th><th>Auteur</th><th>Vente</th><th>Marge</th><th>Note</th></tr>{trs or "<tr><td colspan=6>Aucune version.</td></tr>"}</table></div></section>')

@app.post('/devis/{qid}/approbation/demander')
def quote_approval_request(qid:int,request:Request,commentaire:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,COMMERCIALS);q=db.get(Quote,qid)
    if not q:raise HTTPException(404)
    _,_,_,_,mp=quote_totals(db,q);current=quote_snapshot_hash(db,q)
    if quote_valid_approval(db,q):return RedirectResponse(f'/devis/{qid}?msg=Déjà+approuvé',303)
    if quote_pending_approval(db,q):return RedirectResponse(f'/devis/{qid}?msg=Validation+déjà+en+attente',303)
    min_margin,max_discount=quote_thresholds(db);motif=f'Marge {mp:.1f}% (seuil {min_margin:.1f}%) · Remise {float(q.remise_pct or 0):.1f}% (seuil {max_discount:.1f}%)'
    quote_create_version(db,q,u,'Snapshot automatique avant demande de validation')
    db.add(QuoteApproval(quote_id=qid,snapshot_hash=current,statut='En attente',motif=motif,commentaire=commentaire.strip(),marge_pct=mp,remise_pct=float(q.remise_pct or 0),requested_by=u.username));db.commit();return RedirectResponse(f'/devis/{qid}?msg=Validation+responsable+demandée',303)

@app.post('/devis/{qid}/approbation/{aid}')
def quote_approval_decide(qid:int,aid:int,request:Request,decision:str=Form(...),commentaire:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);q=db.get(Quote,qid);a=db.get(QuoteApproval,aid)
    if not q or not a or a.quote_id!=qid:raise HTTPException(404)
    if decision not in {'Approuvé','Refusé'}:raise HTTPException(400)
    if a.snapshot_hash!=quote_snapshot_hash(db,q):raise HTTPException(409,'Le devis a changé depuis la demande : nouvelle validation nécessaire')
    a.statut=decision;a.decided_by=u.username;a.decided_at=datetime.utcnow();a.commentaire=((a.commentaire+'\n') if a.commentaire else '')+commentaire.strip();db.commit();return RedirectResponse(f'/devis/{qid}?msg=Validation+{decision}',303)

@app.get('/devis/{qid}/reel')
def quote_actual_page(qid:int,request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);require_role(u,COMMERCIALS);q=db.get(Quote,qid)
    if not q:raise HTTPException(404)
    rows,planned,actual,sale,pm,pm_pct,rm,rm_pct=quote_actual_totals(db,q);trs=''
    for x in rows:trs+=f'<tr><td>{escape(x.type_ligne)}</td><td>{escape(x.designation)}</td><td>{x.quantite:g}</td><td>{money(x.cout_unitaire_reel)}</td><td>{money(float(x.quantite)*float(x.cout_unitaire_reel))}</td><td>{escape(x.source)}</td></tr>'
    delta=actual-planned;cls='margin-good' if rm_pct>=25 else ('margin-warn' if rm_pct>=15 else 'margin-bad')
    form=f'''<section class="card"><h2>Ajouter un coût réel</h2><form method="post" action="/devis/{qid}/reel" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Type<select name="type_ligne"><option>Matériel</option><option>Main-d’œuvre</option><option>Service</option><option>Déplacement</option><option>Autre</option></select></label><label>Désignation<input name="designation" required></label><label>Quantité<input type="number" min=".01" step=".01" name="quantite" value="1"></label><label>Coût unitaire réel<input type="number" min="0" step=".01" name="cout_unitaire_reel" required></label><label>Source<input name="source" value="Saisie"></label><label class="full">Notes<input name="notes"></label><button class="btn primary">Ajouter</button></form></section>'''
    return page(request,u,f'Réel {q.reference}',f'<div class="head"><div><h1>Prévu vs réel · {escape(q.reference)}</h1><p class="muted">Mesure la rentabilité réellement obtenue après réalisation.</p></div><a class="btn" href="/devis/{qid}">Retour devis</a></div><div class="quote-summary"><div><small>Coût prévu</small><strong>{money(planned)}</strong></div><div><small>Coût réel</small><strong>{money(actual)}</strong></div><div><small>Écart coût</small><strong>{money(delta)}</strong></div><div><small>Marge réelle</small><strong class="{cls}">{money(rm)} · {rm_pct:.1f}%</strong></div></div>{form}<section class="card"><div class="scroll"><table><tr><th>Type</th><th>Désignation</th><th>Qté</th><th>Coût U. réel</th><th>Total réel</th><th>Source</th></tr>{trs or "<tr><td colspan=6>Aucun coût réel saisi.</td></tr>"}</table></div></section>')

@app.post('/devis/{qid}/reel')
def quote_actual_add(qid:int,request:Request,type_ligne:str=Form('Matériel'),designation:str=Form(...),quantite:float=Form(1),cout_unitaire_reel:float=Form(...),source:str=Form('Saisie'),notes:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,COMMERCIALS);q=db.get(Quote,qid)
    if not q:raise HTTPException(404)
    db.add(QuoteActualLine(quote_id=qid,type_ligne=type_ligne,designation=designation.strip(),quantite=max(.01,float(quantite)),cout_unitaire_reel=max(0,float(cout_unitaire_reel)),source=source.strip() or 'Saisie',notes=notes.strip()));db.commit();return RedirectResponse(f'/devis/{qid}/reel',303)

@app.post('/devis/{qid}/convertir')
def quote_convert_workorder(qid:int,request:Request,responsable:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,COMMERCIALS);q=db.get(Quote,qid)
    if not q:raise HTTPException(404)
    if q.statut!='Accepté':raise HTTPException(409,'Le devis doit être accepté avant conversion')
    existing=db.scalar(select(QuoteWorkOrder).where(QuoteWorkOrder.quote_id==qid))
    if existing:return RedirectResponse('/affaires',303)
    iid=None
    if q.site_id:
        inter=Intervention(site_id=q.site_id,equipement_id=None,technicien='À affecter',type_intervention='Installation',priorite='Normale',probleme=f'Réalisation devis {q.reference} — {q.objet}',actions_realisees='',solution='',statut='À faire')
        db.add(inter);db.flush();iid=inter.id
    ref=f'AFF-{datetime.utcnow().strftime("%Y%m%d")}-{secrets.token_hex(2).upper()}'
    db.add(QuoteWorkOrder(quote_id=qid,reference=ref,client_id=q.client_id,site_id=q.site_id,intervention_id=iid,responsable=responsable.strip() or u.username,statut='À planifier',notes=f'Créée depuis {q.reference}'));db.commit();return RedirectResponse('/affaires',303)

@app.post('/devis/{qid}/dupliquer')
def quote_duplicate(qid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,COMMERCIALS);q=db.get(Quote,qid)
    if not q:raise HTTPException(404)
    ref=f'DEV-{datetime.utcnow().strftime("%Y%m%d-%H%M%S")}-{secrets.token_hex(2).upper()}'
    nq=Quote(reference=ref,client_id=q.client_id,site_id=q.site_id,commercial=u.username,objet=q.objet+' — copie',statut='Brouillon',remise_pct=q.remise_pct,notes=q.notes,date_validite=q.date_validite);db.add(nq);db.flush()
    for l in db.scalars(select(QuoteLine).where(QuoteLine.quote_id==qid).order_by(QuoteLine.id)).all():
        db.add(QuoteLine(quote_id=nq.id,type_ligne=l.type_ligne,stock_item_id=l.stock_item_id,supplier_id=l.supplier_id,designation=l.designation,quantite=l.quantite,cout_unitaire=l.cout_unitaire,vente_unitaire=l.vente_unitaire,notes=l.notes))
    db.commit();return RedirectResponse(f'/devis/{nq.id}',303)

@app.get('/devis/{qid}/export.xlsx')
def quote_export_xlsx(qid:int,request:Request,db:Session=Depends(get_db)):
    require_login(request,db);q=db.get(Quote,qid)
    if not q:raise HTTPException(404)
    data=quote_xlsx_bytes(db,q);return Response(data,media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',headers={'Content-Disposition':f'attachment; filename="{q.reference}.xlsx"'})

@app.get('/devis/{qid}/client')
def quote_client_view(qid:int,request:Request,db:Session=Depends(get_db)):
    require_login(request,db);q=db.get(Quote,qid)
    if not q:raise HTTPException(404)
    client=db.get(Client,q.client_id);site=db.get(Site,q.site_id) if q.site_id else None;lines,_,sale,_,_=quote_totals(db,q)
    bodyrows=''.join(f'<tr><td>{escape(l.designation)}</td><td>{l.quantite:g}</td><td>{money(l.vente_unitaire)}</td><td>{money(float(l.quantite)*float(l.vente_unitaire))}</td></tr>' for l in lines)
    html=f'''<!doctype html><html lang="fr"><head><meta charset="utf-8"><title>{escape(q.reference)}</title><style>body{{font-family:Arial,sans-serif;color:#111;margin:40px;line-height:1.45}}.top{{display:flex;justify-content:space-between;gap:30px}}h1{{margin:0}}.muted{{color:#666}}table{{width:100%;border-collapse:collapse;margin-top:28px}}th,td{{padding:10px;border-bottom:1px solid #ddd;text-align:left}}th{{background:#f3f5f7}}.total{{text-align:right;font-size:22px;font-weight:700;margin-top:24px}}.actions{{margin-bottom:20px}}@media print{{.actions{{display:none}}body{{margin:12mm}}}}</style></head><body><div class="actions"><button onclick="window.print()">Imprimer / Enregistrer en PDF</button></div><div class="top"><div><h1>Devis {escape(q.reference)}</h1><div class="muted">{escape(q.objet)}</div></div><div><b>Client</b><br>{escape(client.nom if client else '—')}<br>{escape(site.nom if site else '')}</div></div><p>Commercial : {escape(q.commercial)}<br>Validité : {dfr(q.date_validite)}</p><table><tr><th>Désignation</th><th>Qté</th><th>Prix unitaire</th><th>Total</th></tr>{bodyrows}</table><div class="total">Total : {money(sale)}</div><p class="muted">Remise globale incluse : {float(q.remise_pct or 0):.1f}%</p></body></html>'''
    return HTMLResponse(html)

def quote_totals(db,q):
    lines=db.scalars(select(QuoteLine).where(QuoteLine.quote_id==q.id)).all()
    cost=sum(float(l.quantite or 0)*float(l.cout_unitaire or 0) for l in lines)
    sale=sum(float(l.quantite or 0)*float(l.vente_unitaire or 0) for l in lines)
    discount=max(0.0,min(100.0,float(q.remise_pct or 0)))
    sale_after=sale*(1-discount/100)
    margin=sale_after-cost
    margin_pct=(margin/sale_after*100) if sale_after>0 else 0.0
    return lines,cost,sale_after,margin,margin_pct

def default_stock_cost(db,item):
    best,_=best_supplier_price(db,item.id)
    return float(best.prix) if best else float(item.prix_achat or 0)

def supplier_stock_cost(db,item,supplier_id=None):
    if supplier_id:
        row=db.scalar(select(SupplierPrice).where(SupplierPrice.stock_item_id==item.id,SupplierPrice.supplier_id==int(supplier_id)).order_by(SupplierPrice.date_prix.desc()).limit(1))
        if row and float(row.prix or 0)>0:return float(row.prix)
    return default_stock_cost(db,item)

@app.get('/devis')
def quotes_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);quotes=db.scalars(select(Quote).order_by(Quote.date_creation.desc())).all();clients_=db.scalars(select(Client).where(Client.actif.is_(True)).order_by(Client.nom)).all();sites_=db.scalars(select(Site).where(Site.actif.is_(True)).order_by(Site.nom)).all();trs=''
    for q in quotes:
        c=db.get(Client,q.client_id);_,cost,sale,margin,margin_pct=quote_totals(db,q);cls='margin-good' if margin_pct>=25 else ('margin-warn' if margin_pct>=15 else 'margin-bad');trs+=f'<tr><td><a href="/devis/{q.id}">{escape(q.reference)}</a></td><td>{dfr(q.date_creation)}</td><td>{escape(c.nom if c else "—")}</td><td>{escape(q.objet)}</td><td>{badge(q.statut)}</td><td>{money(cost)}</td><td>{money(sale)}</td><td class="{cls}">{money(margin)} · {margin_pct:.1f}%</td><td>{escape(q.commercial)}</td></tr>'
    form=''
    if u.role in COMMERCIALS:
        form=f'<section class="card"><h2>Nouveau devis</h2><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Référence (optionnel)<input name="reference" placeholder="Auto si vide"></label><label>Client<select name="client_id" required>{option_rows(clients_,lambda x:x.id,lambda x:x.nom)}</select></label><label>Site<select name="site_id">{option_rows(sites_,lambda x:x.id,lambda x:x.nom,empty="Aucun site")}</select></label><label>Commercial<input name="commercial" value="{escape(u.username)}"></label><label class="full">Objet<input name="objet" placeholder="Installation vidéo / extension contrôle d’accès..." required></label><label>Validité<input type="date" name="date_validite"></label><label>Remise %<input type="number" min="0" max="100" step="0.1" name="remise_pct" value="0"></label><label class="full">Notes<textarea name="notes"></textarea></label><button class="btn primary">Créer le devis</button></form></section>'
    return page(request,u,'Devis',f'<div class="head"><div><h1>Devis</h1><p class="muted">Devis versionnés, catalogue commercial, validation responsable et comparaison prévu/réel.</p></div><div class="actions"><a class="btn" href="/catalogue-commercial">Catalogue</a><a class="btn" href="/affaires">Affaires</a></div></div>{form}<section class="card"><div class="scroll"><table><tr><th>Référence</th><th>Date</th><th>Client</th><th>Objet</th><th>Statut</th><th>Coût</th><th>Vente</th><th>Marge</th><th>Commercial</th></tr>{trs or "<tr><td colspan=9>Aucun devis.</td></tr>"}</table></div></section>')

@app.post('/devis')
def quote_add(request:Request,client_id:int=Form(...),site_id:str=Form(''),commercial:str=Form(''),objet:str=Form(...),reference:str=Form(''),date_validite:str=Form(''),remise_pct:float=Form(0),notes:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,COMMERCIALS)
    ref=reference.strip() or f'DEV-{datetime.utcnow().strftime("%Y%m%d-%H%M%S")}-{secrets.token_hex(2).upper()}'
    q=Quote(reference=ref,client_id=client_id,site_id=(int(site_id) if site_id else None),commercial=commercial.strip() or u.username,objet=objet.strip(),statut='Brouillon',remise_pct=max(0,min(100,remise_pct)),notes=notes.strip(),date_validite=(date.fromisoformat(date_validite) if date_validite else None));db.add(q);db.commit();db.refresh(q);return RedirectResponse(f'/devis/{q.id}',303)

@app.get('/devis/{qid}')
def quote_detail(qid:int,request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);q=db.get(Quote,qid)
    if not q:raise HTTPException(404,'Devis introuvable')
    c=db.get(Client,q.client_id);s=db.get(Site,q.site_id) if q.site_id else None;lines,cost,sale,margin,margin_pct=quote_totals(db,q);stocks=db.scalars(select(StockItem).where(StockItem.actif.is_(True)).order_by(StockItem.designation)).all();sups=db.scalars(select(Supplier).where(Supplier.actif.is_(True)).order_by(Supplier.nom)).all();catalog=db.scalars(select(CommercialCatalogItem).where(CommercialCatalogItem.actif.is_(True)).order_by(CommercialCatalogItem.categorie,CommercialCatalogItem.designation)).all();rows=''
    for l in lines:
        rows+=f'<tr><td>{escape(l.type_ligne)}</td><td>{escape(l.designation)}</td><td>{l.quantite:g}</td><td>{money(l.cout_unitaire)}</td><td>{money(l.vente_unitaire)}</td><td>{money(float(l.quantite)*float(l.cout_unitaire))}</td><td>{money(float(l.quantite)*float(l.vente_unitaire))}</td>'+(f'<td><form method="post" action="/devis/{qid}/lignes/{l.id}/supprimer" onsubmit="return confirm(\'Supprimer cette ligne ?\')"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn">Supprimer</button></form></td>' if u.role in COMMERCIALS and q.statut not in ('Accepté','Refusé','Annulé') else '<td>—</td>')+'</tr>'
    cls='margin-good' if margin_pct>=25 else ('margin-warn' if margin_pct>=15 else 'margin-bad')
    needs=quote_needs_approval(db,q,margin_pct);approved=quote_valid_approval(db,q);pending=quote_pending_approval(db,q);approval_box=''
    if needs:
        if approved:approval_box='<section class="card"><h2>Validation commerciale</h2><p>'+badge('Approuvé')+f' par {escape(approved.decided_by)} le {dfr(approved.decided_at)}. Cette validation correspond exactement à la version actuelle.</p></section>'
        elif pending:
            manager_actions=f'<form method="post" action="/devis/{qid}/approbation/{pending.id}" class="inline-form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><input type="hidden" name="decision" value="Approuvé"><input name="commentaire" placeholder="Commentaire"><button class="btn primary">Approuver</button></form><form method="post" action="/devis/{qid}/approbation/{pending.id}" class="inline-form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><input type="hidden" name="decision" value="Refusé"><input name="commentaire" placeholder="Motif"><button class="btn">Refuser</button></form>' if u.role in MANAGERS else ''
            approval_box=f'<section class="card"><h2>Validation commerciale</h2><p>{badge("En attente")} · {escape(pending.motif)}</p>{manager_actions}</section>'
        elif u.role in COMMERCIALS:
            min_margin,max_discount=quote_thresholds(db);approval_box=f'<section class="card"><h2>Validation responsable requise</h2><p class="muted">Marge minimale sans validation : {min_margin:.1f}% · remise maximale sans validation : {max_discount:.1f}%.</p><form method="post" action="/devis/{qid}/approbation/demander" class="inline-form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><input name="commentaire" placeholder="Justification commerciale"><button class="btn primary">Demander la validation</button></form></section>'
    editor=''
    if u.role in COMMERCIALS and q.statut not in ('Accepté','Refusé','Annulé'):
        stock_opts='<option value="">Aucun / ligne libre</option>'+''.join(f'<option value="{x.id}" data-cost="{default_stock_cost(db,x):.2f}">{escape(x.reference)} · {escape(x.designation)}</option>' for x in stocks)
        catalog_opts='<option value="">— Choisir dans le catalogue —</option>'+''.join(f'<option value="{x.id}" data-type="{escape(x.categorie,quote=True)}" data-name="{escape(x.designation,quote=True)}" data-cost="{float(x.cout_unitaire or 0):.2f}" data-sale="{float(x.vente_unitaire or 0):.2f}">{escape(x.code)} · {escape(x.designation)}</option>' for x in catalog)
        editor=f'''<section class="card"><h2>Ajouter une ligne</h2><form method="post" action="/devis/{qid}/lignes" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Catalogue<select id="quoteCatalog">{catalog_opts}</select></label><label>Type<select name="type_ligne" id="quoteType"><option>Matériel</option><option>Main-d’œuvre</option><option>Service</option><option>Déplacement</option><option>Autre</option></select></label><label>Article stock<select name="stock_item_id" id="quoteStock">{stock_opts}</select></label><label>Fournisseur<select name="supplier_id">{option_rows(sups,lambda x:x.id,lambda x:x.nom,empty="Aucun")}</select></label><label>Désignation<input name="designation" id="quoteName" placeholder="Auto depuis catalogue/stock si vide"></label><label>Quantité<input type="number" min="0.01" step="0.01" name="quantite" value="1"></label><label>Coût unitaire<input type="number" min="0" step="0.01" name="cout_unitaire" id="quoteCost" value="0"></label><label>Prix de vente unitaire<input type="number" min="0" step="0.01" name="vente_unitaire" id="quoteSale" required value="0"></label><label>Notes<input name="notes"></label><button class="btn primary">Ajouter</button></form><script>(function(){{const cat=document.getElementById("quoteCatalog"),typ=document.getElementById("quoteType"),nam=document.getElementById("quoteName"),cost=document.getElementById("quoteCost"),sale=document.getElementById("quoteSale"),stock=document.getElementById("quoteStock");if(cat)cat.addEventListener("change",()=>{{const o=cat.options[cat.selectedIndex];if(!o||!o.value)return;typ.value=o.dataset.type||typ.value;nam.value=o.dataset.name||nam.value;cost.value=o.dataset.cost||0;sale.value=o.dataset.sale||0;}});if(stock)stock.addEventListener("change",()=>{{const o=stock.options[stock.selectedIndex];if(o&&o.dataset.cost&&Number(cost.value||0)===0)cost.value=o.dataset.cost;}});}})();</script></section><section class="card"><h2>État du devis</h2><form method="post" action="/devis/{qid}/statut" class="inline-form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><select name="statut"><option>{escape(q.statut)}</option><option>Brouillon</option><option>Envoyé</option><option>En négociation</option><option>Accepté</option><option>Refusé</option><option>Annulé</option></select><button class="btn">Mettre à jour</button></form></section>'''
    work=db.scalar(select(QuoteWorkOrder).where(QuoteWorkOrder.quote_id==qid));convert=''
    if q.statut=='Accepté' and u.role in COMMERCIALS and not work:
        convert=f'<section class="card"><h2>Passer en réalisation</h2><p class="muted">Crée une affaire. Si le devis est lié à un site, NOX-IA crée aussi une intervention à planifier.</p><form method="post" action="/devis/{qid}/convertir" class="inline-form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><input name="responsable" value="{escape(u.username,quote=True)}" placeholder="Responsable"><button class="btn primary">Créer affaire + intervention</button></form></section>'
    elif work:convert=f'<section class="card"><h2>Réalisation</h2><p>{badge(work.statut)} · Affaire <b>{escape(work.reference)}</b> · <a href="/affaires">ouvrir les affaires</a></p></section>'
    body=f'''<div class="head"><div><h1>{escape(q.reference)}</h1><p class="muted">{escape(c.nom if c else "—")} · {escape(s.nom if s else "sans site")} · {escape(q.objet)}</p></div><div class="actions"><a class="btn" href="/devis/{qid}/client" target="_blank">Imprimer / PDF client</a><a class="btn" href="/devis/{qid}/export.xlsx">Excel XLSX</a><a class="btn" href="/devis/{qid}/versions">Versions</a><a class="btn" href="/devis/{qid}/reel">Prévu / réel</a><a class="btn" href="/devis">Retour</a></div></div><section class="card"><div class="quote-summary"><div><small>Coût estimé</small><strong>{money(cost)}</strong></div><div><small>Vente après remise</small><strong>{money(sale)}</strong></div><div><small>Marge</small><strong class="{cls}">{money(margin)}</strong></div><div><small>Marge %</small><strong class="{cls}">{margin_pct:.1f}%</strong></div></div><p class="muted">Statut : {badge(q.statut)} · Commercial : {escape(q.commercial)} · Remise : {q.remise_pct:.1f}%</p><form method="post" action="/devis/{qid}/dupliquer"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn">Dupliquer ce devis</button></form></section>{approval_box}{editor}{convert}<section class="card"><h2>Lignes du devis</h2><div class="scroll"><table><tr><th>Type</th><th>Désignation</th><th>Qté</th><th>Coût U.</th><th>Vente U.</th><th>Coût total</th><th>Vente totale</th><th></th></tr>{rows or "<tr><td colspan=8>Aucune ligne.</td></tr>"}</table></div></section>'''
    return page(request,u,f'Devis {q.reference}',body)

@app.post('/devis/{qid}/lignes')
def quote_line_add(qid:int,request:Request,type_ligne:str=Form('Matériel'),stock_item_id:str=Form(''),supplier_id:str=Form(''),designation:str=Form(''),quantite:float=Form(1),cout_unitaire:float=Form(0),vente_unitaire:float=Form(...),notes:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,COMMERCIALS);q=db.get(Quote,qid)
    if not q:raise HTTPException(404)
    item=db.get(StockItem,int(stock_item_id)) if stock_item_id else None
    # La ligne libre reste possible pour main-d’œuvre / services.
    des=designation.strip() or (item.designation if item else '')
    if not des:raise HTTPException(400,'Désignation obligatoire')
    cost=float(cout_unitaire or 0)
    if item and cost<=0:cost=supplier_stock_cost(db,item,(int(supplier_id) if supplier_id else None))
    db.add(QuoteLine(quote_id=qid,type_ligne=type_ligne,stock_item_id=(item.id if item else None),supplier_id=(int(supplier_id) if supplier_id else None),designation=des,quantite=max(0.01,float(quantite)),cout_unitaire=max(0,cost),vente_unitaire=max(0,float(vente_unitaire)),notes=notes.strip()));db.commit();return RedirectResponse(f'/devis/{qid}',303)


@app.post('/devis/{qid}/lignes/{lid}/supprimer')
def quote_line_delete(qid:int,lid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,COMMERCIALS);q=db.get(Quote,qid);line=db.get(QuoteLine,lid)
    if not q or not line or line.quote_id!=qid:raise HTTPException(404)
    if q.statut in ('Accepté','Refusé','Annulé'):raise HTTPException(409,'Ce devis est verrouillé')
    db.delete(line);db.commit();return RedirectResponse(f'/devis/{qid}',303)

@app.post('/devis/{qid}/statut')
def quote_status(qid:int,request:Request,statut:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,COMMERCIALS);q=db.get(Quote,qid)
    if not q:raise HTTPException(404)
    allowed={'Brouillon','Envoyé','En négociation','Accepté','Refusé','Annulé'}
    if statut not in allowed:raise HTTPException(400)
    _,_,_,_,margin_pct=quote_totals(db,q)
    if statut in {'Envoyé','Accepté'} and quote_needs_approval(db,q,margin_pct) and not quote_valid_approval(db,q):
        return RedirectResponse(f'/devis/{qid}?msg=Validation+responsable+requise+avant+{statut}',303)
    if statut=='Envoyé':quote_create_version(db,q,u,'Version envoyée au client')
    q.statut=statut;db.commit();return RedirectResponse(f'/devis/{qid}',303)

@app.get('/devis/{qid}/export.csv')
def quote_export_csv(qid:int,request:Request,db:Session=Depends(get_db)):
    require_login(request,db);q=db.get(Quote,qid)
    if not q:raise HTTPException(404)
    import csv
    buf=io.StringIO();w=csv.writer(buf,delimiter=';',quoting=csv.QUOTE_MINIMAL);w.writerow(['Référence devis',q.reference]);w.writerow(['Objet',q.objet]);w.writerow([]);w.writerow(['Type','Désignation','Quantité','Coût unitaire','Vente unitaire','Coût total','Vente totale'])
    lines,cost,sale,margin,margin_pct=quote_totals(db,q)
    for l in lines:w.writerow([l.type_ligne,l.designation,f'{l.quantite:.2f}',f'{l.cout_unitaire:.2f}',f'{l.vente_unitaire:.2f}',f'{l.quantite*l.cout_unitaire:.2f}',f'{l.quantite*l.vente_unitaire:.2f}'])
    w.writerow([]);w.writerow(['Coût total',f'{cost:.2f}']);w.writerow(['Vente après remise',f'{sale:.2f}']);w.writerow(['Marge',f'{margin:.2f}']);w.writerow(['Marge %',f'{margin_pct:.2f}'])
    data=('\ufeff'+buf.getvalue()).encode('utf-8');return Response(data,media_type='text/csv; charset=utf-8',headers={'Content-Disposition':f'attachment; filename="{q.reference}.csv"'})


DISCOVERY_METHODS=('API REST','Webhook JSON','SNMP','Syslog','E-mail d’alerte','CSV / JSON','Base de données','Autre')

def discovery_methods(fabricant='',logiciel='',adresse='',indices='',notes=''):
    """Propose des pistes sans déclarer une compatibilité non vérifiée."""
    text=' '.join([fabricant,logiciel,adresse,indices,notes]).lower()
    scored=[]
    def add(name,reason,score):
        if not any(x['name']==name for x in scored):
            scored.append({'name':name,'reason':reason,'score':score})
    if any(x in text for x in ('api','rest','swagger','openapi','http api')): add('API REST','Une mention API/REST est visible dans les indices.',95)
    if any(x in text for x in ('webhook','callback','push event')): add('Webhook JSON','Une fonction webhook/push semble mentionnée.',94)
    if 'snmp' in text: add('SNMP','SNMP est explicitement mentionné.',95)
    if 'syslog' in text: add('Syslog','Syslog est explicitement mentionné.',95)
    if any(x in text for x in ('smtp','email','e-mail','mail alert','notification mail')): add('E-mail d’alerte','Des alertes par e-mail semblent possibles.',88)
    if any(x in text for x in ('csv','json','export','rapport fichier')): add('CSV / JSON','Un export fichier semble disponible.',80)
    if any(x in text for x in ('sql','database','base de données','odbc')): add('Base de données','Un accès base de données est évoqué.',78)
    if adresse.strip().lower().startswith(('http://','https://')): add('API REST','Une interface web existe ; vérifier si elle expose une API officielle.',62)
    for name,reason,score in (
        ('API REST','À vérifier dans la documentation ou les paramètres du logiciel.',45),
        ('Webhook JSON','À vérifier si le logiciel sait pousser des événements.',42),
        ('SNMP','À vérifier pour les états/équipements réseau ou sûreté compatibles.',38),
        ('Syslog','À vérifier pour les journaux et événements techniques.',36),
        ('E-mail d’alerte','Solution intermédiaire si le logiciel peut envoyer des alertes SMTP.',32),
        ('CSV / JSON','Solution d’import si le logiciel sait exporter des données.',28),
    ): add(name,reason,score)
    return sorted(scored,key=lambda x:(-x['score'],x['name']))[:6]

def discovery_methods_html(row):
    try: methods=json.loads(row.methodes_suggerees_json or '[]')
    except Exception: methods=[]
    if not methods: return '<p class="muted">Aucune piste calculée.</p>'
    return '<div class="grid g2">'+''.join(f'<div class="software-help-card"><b>{escape(x.get("name",""))}</b><div class="muted">Indice technique : {int(x.get("score",0))}%</div><p>{escape(x.get("reason",""))}</p></div>' for x in methods)+'</div>'

@app.get('/decouverte-systemes')
def discovery_list(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db)
    rows=db.scalars(select(DiscoveredSystem).order_by(DiscoveredSystem.updated_at.desc()).limit(500)).all()
    sites_=db.scalars(select(Site).where(Site.actif.is_(True)).order_by(Site.nom)).all()
    trs=''
    for x in rows:
        s=db.get(Site,x.site_id) if x.site_id else None
        display=x.logiciel.strip() or x.nom_temporaire or 'Système à identifier'
        trs+=f'<tr><td>{dfr(x.updated_at)}</td><td><a href="/decouverte-systemes/{x.id}"><b>{escape(display)}</b></a><div class="muted">{escape(x.fabricant or "Fabricant inconnu")}</div></td><td>{escape(s.nom if s else "Non rattaché")}</td><td>{escape(x.categorie)}</td><td>{badge(x.statut_identification)}</td><td>{badge(x.methode_retenue or "À étudier")}</td></tr>'
    form=''
    if u.role in TECHS:
        form=f'''<section class="card"><div class="head"><div><h2>J’ai trouvé un logiciel / système</h2><p class="muted">Tu n’as pas besoin de connaître son nom. Mets seulement ce que tu vois réellement.</p></div></div><form method="post" action="/decouverte-systemes" enctype="multipart/form-data" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Site<select name="site_id">{option_rows(sites_,lambda x:x.id,lambda x:x.nom,empty="Non rattaché")}</select></label><label>Nom temporaire<input name="nom_temporaire" value="Système à identifier" placeholder="Ex. logiciel vidéo du PC accueil"></label><label>Nom logiciel (si connu)<input name="logiciel" placeholder="Laisse vide si inconnu"></label><label>Fabricant (si visible)<input name="fabricant" placeholder="Ex. Hikvision, Aritech…"></label><label>Version (si visible)<input name="version" placeholder="Ex. 3.12.0"></label><label>Catégorie<select name="categorie"><option>Vidéosurveillance</option><option>Contrôle d’accès</option><option>Intrusion</option><option>SSI / incendie</option><option>Interphonie</option><option>Réseau</option><option>Supervision</option><option selected>Autre</option></select></label><label>Langue interface<select name="interface_language"><option>Inconnue</option><option>Français</option><option>English</option><option>Deutsch</option><option>Español</option><option>Autre</option></select></label><label>URL / IP visible<input name="adresse" placeholder="Ex. https://192.168.1.20 ou 10.0.0.15"></label><label class="full">Textes / boutons / indices visibles<textarea name="indices" placeholder="Recopie le titre de la fenêtre, les menus, le logo, un message d’alerte…"></textarea></label><label class="full">Capture d’écran (facultatif, 2 Mo max)<input type="file" name="capture" accept="image/png,image/jpeg,image/webp"></label><label class="full">Notes<textarea name="notes" placeholder="À quoi sert le logiciel ? Sur quel PC ? Que fait-il quand il y a une panne ?"></textarea></label><button class="btn primary">Enregistrer et proposer les pistes</button></form></section>'''
    checklist='''<section class="card"><h2>Checklist terrain</h2><div class="grid g3"><div class="software-help-card"><b>1 · Nom / logo</b><p class="muted">Titre de fenêtre, icône, écran de connexion.</p></div><div class="software-help-card"><b>2 · Version</b><p class="muted">About / À propos / Help → About.</p></div><div class="software-help-card"><b>3 · Connexion</b><p class="muted">URL/IP, API, SNMP, Syslog, e-mail, export.</p></div></div></section>'''
    body=f'<div class="head"><div><h1>Découverte systèmes</h1><p class="muted">Inventorie les logiciels déjà présents sur les sites même quand leur nom exact est inconnu, puis transforme-les en connecteurs quand la méthode est confirmée.</p></div><a class="btn" href="/supervision">Supervision</a></div>{form}{checklist}<section class="card"><h2>Systèmes repérés</h2><div class="scroll"><table><tr><th>Mis à jour</th><th>Système</th><th>Site</th><th>Catégorie</th><th>Identification</th><th>Connexion</th></tr>{trs or "<tr><td colspan=6>Aucun système repéré.</td></tr>"}</table></div></section>'
    return page(request,u,'Découverte systèmes',body)

@app.post('/decouverte-systemes')
async def discovery_create(request:Request,site_id:str=Form(''),nom_temporaire:str=Form('Système à identifier'),logiciel:str=Form(''),fabricant:str=Form(''),version:str=Form(''),categorie:str=Form('Autre'),interface_language:str=Form('Inconnue'),adresse:str=Form(''),indices:str=Form(''),notes:str=Form(''),capture:UploadFile|None=File(None),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value); u=require_login(request,db); require_role(u,TECHS)
    data=None; mime=''; fname=''
    if capture and capture.filename:
        mime=(capture.content_type or '').lower()
        if mime not in {'image/png','image/jpeg','image/webp'}: raise HTTPException(400,'Capture : PNG, JPEG ou WebP uniquement')
        data=await capture.read(2*1024*1024+1)
        if len(data)>2*1024*1024: raise HTTPException(413,'Capture trop volumineuse (2 Mo max)')
        fname=Path(capture.filename).name[:260]
    methods=discovery_methods(fabricant,logiciel,adresse,indices,notes)
    status='Identifié' if logiciel.strip() else 'À identifier'
    conf='moyenne' if logiciel.strip() else 'faible'
    x=DiscoveredSystem(site_id=(int(site_id) if site_id else None),nom_temporaire=(nom_temporaire.strip() or 'Système à identifier')[:220],logiciel=logiciel.strip()[:220],fabricant=fabricant.strip()[:180],version=version.strip()[:120],categorie=categorie[:100],interface_language=interface_language[:80],adresse=adresse.strip()[:500],indices=indices.strip()[:12000],notes=notes.strip()[:12000],statut_identification=status,confiance=conf,methodes_suggerees_json=json.dumps(methods,ensure_ascii=False),capture_name=fname,capture_mime=mime,capture_data=data,created_by=u.username,created_at=datetime.utcnow(),updated_at=datetime.utcnow())
    db.add(x); db.commit(); db.refresh(x); audit_add(db,request,u,'Découverte système créée','discovered_system',x.id,(x.logiciel or x.nom_temporaire)); db.commit()
    return RedirectResponse(f'/decouverte-systemes/{x.id}?msg=Fiche+créée',303)

@app.get('/decouverte-systemes/{did}')
def discovery_detail(did:int,request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db); x=db.get(DiscoveredSystem,did)
    if not x: raise HTTPException(404,'Système introuvable')
    s=db.get(Site,x.site_id) if x.site_id else None
    connector=db.get(IntegrationConnector,x.connector_id) if x.connector_id else None
    capture=f'<img src="/decouverte-systemes/{x.id}/capture" alt="Capture" style="max-width:100%;max-height:560px;border-radius:12px;border:1px solid var(--line)">' if x.capture_data else '<p class="muted">Aucune capture enregistrée.</p>'
    try: methods=json.loads(x.methodes_suggerees_json or '[]')
    except Exception: methods=[]
    method_options=''.join(f'<option>{escape(z.get("name",""))}</option>' for z in methods if z.get('name')) or ''.join(f'<option>{escape(z)}</option>' for z in DISCOVERY_METHODS)
    actions=''
    if u.role in TECHS:
        actions=f'''<section class="card"><h2>Mettre à jour l’identification</h2><form method="post" action="/decouverte-systemes/{x.id}/identifier" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Nom logiciel<input name="logiciel" value="{escape(x.logiciel,quote=True)}" placeholder="Nom exact si découvert"></label><label>Fabricant<input name="fabricant" value="{escape(x.fabricant,quote=True)}"></label><label>Version<input name="version" value="{escape(x.version,quote=True)}"></label><label>Confiance<select name="confiance"><option>{escape(x.confiance)}</option><option>faible</option><option>moyenne</option><option>forte</option></select></label><label class="full">Nouveaux indices<textarea name="indices">{escape(x.indices)}</textarea></label><button class="btn primary">Mettre à jour</button></form></section>'''
    if u.role in MANAGERS and not connector:
        suggested_name=((x.logiciel or x.nom_temporaire)+' · '+(s.nom if s else 'global'))[:180]
        actions+=f'''<section class="card"><h2>Transformer en connecteur</h2><p class="muted">Choisis seulement une méthode confirmée ou à tester. La création n’envoie aucune commande au logiciel source.</p><form method="post" action="/decouverte-systemes/{x.id}/connecteur" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Méthode<select name="type_connecteur">{method_options}</select></label><label>Nom du connecteur<input name="nom" value="{escape(suggested_name,quote=True)}"></label><label class="full">Endpoint / description<input name="endpoint" value="{escape(x.adresse,quote=True)}" placeholder="URL, destination ou description"></label><button class="btn primary">Créer le connecteur</button></form></section>'''
    elif connector:
        actions+=f'<section class="card"><h2>Connecteur lié</h2><p>{badge(connector.statut)} · <b>{escape(connector.nom)}</b> · {escape(connector.type_connecteur)}</p><a class="btn primary" href="/supervision">Ouvrir Supervision</a></section>'
    body=f'''<div class="head"><div><h1>{escape(x.logiciel or x.nom_temporaire)}</h1><p class="muted">{escape(x.fabricant or 'Fabricant inconnu')} · {escape(s.nom if s else 'site non rattaché')} · {escape(x.categorie)}</p></div><a class="btn" href="/decouverte-systemes">Retour</a></div><div class="grid g2"><section class="card"><h2>Fiche</h2><div class="kv"><b>Identification</b>{badge(x.statut_identification)}<b>Confiance</b>{badge(x.confiance)}<b>Version</b><span>{escape(x.version or '—')}</span><b>Langue</b><span>{escape(x.interface_language)}</span><b>URL / IP</b><code>{escape(x.adresse or '—')}</code><b>Créé par</b><span>{escape(x.created_by or '—')}</span></div><h3>Indices</h3><div class="pre">{escape(x.indices or 'Aucun indice')}</div><h3>Notes</h3><div class="pre">{escape(x.notes or 'Aucune note')}</div></section><section class="card"><h2>Capture</h2>{capture}</section></div><section class="card"><h2>Pistes de connexion à vérifier</h2><p class="muted">Ce sont des pistes techniques, pas une promesse de compatibilité. On confirme avec la documentation ou un test contrôlé avant activation.</p>{discovery_methods_html(x)}</section>{actions}'''
    return page(request,u,'Découverte systèmes',body)

@app.get('/decouverte-systemes/{did}/capture')
def discovery_capture(did:int,request:Request,db:Session=Depends(get_db)):
    require_login(request,db); x=db.get(DiscoveredSystem,did)
    if not x or not x.capture_data: raise HTTPException(404)
    filename=(x.capture_name or 'capture').replace('"','')
    return Response(bytes(x.capture_data),media_type=x.capture_mime or 'application/octet-stream',headers={'Content-Disposition':f'inline; filename="{filename}"'})

@app.post('/decouverte-systemes/{did}/identifier')
def discovery_identify(did:int,request:Request,logiciel:str=Form(''),fabricant:str=Form(''),version:str=Form(''),confiance:str=Form('moyenne'),indices:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value); u=require_login(request,db); require_role(u,TECHS); x=db.get(DiscoveredSystem,did)
    if not x: raise HTTPException(404)
    x.logiciel=logiciel.strip()[:220]; x.fabricant=fabricant.strip()[:180]; x.version=version.strip()[:120]; x.indices=indices.strip()[:12000]
    x.confiance=confiance if confiance in {'faible','moyenne','forte'} else 'moyenne'
    x.statut_identification='Identifié' if x.logiciel else 'À identifier'
    x.methodes_suggerees_json=json.dumps(discovery_methods(x.fabricant,x.logiciel,x.adresse,x.indices,x.notes),ensure_ascii=False); x.updated_at=datetime.utcnow(); db.commit()
    return RedirectResponse(f'/decouverte-systemes/{did}?msg=Identification+mise+à+jour',303)

@app.post('/decouverte-systemes/{did}/connecteur')
def discovery_to_connector(did:int,request:Request,type_connecteur:str=Form(...),nom:str=Form(...),endpoint:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value); u=require_login(request,db); require_role(u,MANAGERS); x=db.get(DiscoveredSystem,did)
    if not x: raise HTTPException(404)
    if x.connector_id: raise HTTPException(409,'Un connecteur est déjà lié')
    existing=db.scalar(select(IntegrationConnector).where(IntegrationConnector.nom==nom.strip()))
    if existing: raise HTTPException(409,'Ce nom de connecteur existe déjà')
    c=IntegrationConnector(nom=nom.strip()[:180],logiciel=(x.logiciel or x.nom_temporaire)[:180],site_id=x.site_id,type_connecteur=type_connecteur[:80],endpoint=endpoint.strip()[:500],statut='À configurer',actif=True,notes=f'Créé depuis Découverte systèmes #{x.id}. Vérifier la compatibilité avant activation.')
    db.add(c); db.commit(); db.refresh(c)
    x.connector_id=c.id; x.methode_retenue=type_connecteur; x.statut_identification='Connecteur préparé'; x.updated_at=datetime.utcnow(); db.commit()
    audit_add(db,request,u,'Découverte convertie en connecteur','discovered_system',x.id,f'{c.nom} · {type_connecteur}'); db.commit()
    return RedirectResponse(f'/decouverte-systemes/{did}?msg=Connecteur+préparé',303)

SEVERITY_RANK={'Information':0,'Avertissement':1,'Critique':2}

def normalize_severity(value):
    low=str(value or '').strip().lower()
    if low in {'critical','critique','urgent','urgente','fatal','high','haute','major','majeure'}:return 'Critique'
    if low in {'warning','warn','avertissement','alerte','medium','moyenne'}:return 'Avertissement'
    return 'Information'

def connector_token_hash(raw):
    return hashlib.sha256((raw or '').encode('utf-8')).hexdigest()

def connector_token_from_request(request):
    auth=(request.headers.get('authorization') or '').strip()
    if auth.lower().startswith('bearer '):return auth[7:].strip()
    return (request.headers.get('x-noxia-token') or request.query_params.get('token') or '').strip()

def require_connector_token(request,db,cid):
    connector=db.get(IntegrationConnector,cid)
    if not connector or not connector.actif:raise HTTPException(404,'Connecteur introuvable')
    cred=db.scalar(select(ConnectorCredential).where(ConnectorCredential.connector_id==cid))
    raw=connector_token_from_request(request)
    if not cred or not raw or not hmac.compare_digest(cred.token_hash,connector_token_hash(raw)):
        raise HTTPException(401,'Jeton connecteur invalide')
    return connector

def ensure_default_notification_rules(db):
    if (db.scalar(select(func.count(NotificationRule.id))) or 0)>0:return
    defaults=[('Administrateur','Avertissement'),('Responsable','Avertissement'),('Technicien','Critique')]
    for role,minsev in defaults:db.add(NotificationRule(connector_id=None,role=role,minimum_severity=minsev,active=True))
    db.commit()

def create_notifications_for_event(db,ev):
    ensure_default_notification_rules(db)
    sev=normalize_severity(ev.severite);rank=SEVERITY_RANK.get(sev,0)
    rules=db.scalars(select(NotificationRule).where(NotificationRule.active.is_(True))).all();roles=set()
    for rule in rules:
        if rule.connector_id not in (None,ev.connector_id):continue
        if rank>=SEVERITY_RANK.get(normalize_severity(rule.minimum_severity),1):roles.add(rule.role)
    if not roles:return 0
    users=db.scalars(select(User).where(User.active.is_(True),User.role.in_(list(roles)))).all();created=0
    for user in users:
        exists=db.scalar(select(Notification.id).where(Notification.user_id==user.id,Notification.event_id==ev.id))
        if exists:continue
        db.add(Notification(user_id=user.id,event_id=ev.id,niveau=sev,categorie='Supervision',titre=ev.titre[:280],message=(ev.message or '')[:4000],lien=(f'/incidents' if normalize_severity(ev.severite)=='Critique' else f'/supervision#event-{ev.id}'),lue=False));created+=1
    if created:db.commit()
    return created

def active_maintenance_window(db,connector_id=None,site_id=None,when=None):
    when=when or datetime.utcnow()
    rows=db.scalars(select(MaintenanceWindow).where(MaintenanceWindow.actif.is_(True),MaintenanceWindow.start_at<=when,MaintenanceWindow.end_at>=when)).all()
    for row in rows:
        if row.connector_id not in (None,connector_id):continue
        if row.site_id not in (None,site_id):continue
        return row
    return None

def ensure_incident_for_event(db,ev):
    existing=db.scalar(select(SupervisionIncident).where(SupervisionIncident.event_id==ev.id))
    if existing:return existing,False
    incident=SupervisionIncident(event_id=ev.id,connector_id=ev.connector_id,site_id=ev.site_id,equipement_id=ev.equipement_id,titre=ev.titre[:280],resume=(ev.message or '')[:12000],severite=normalize_severity(ev.severite),statut='Nouveau',created_at=datetime.utcnow(),updated_at=datetime.utcnow())
    db.add(incident);db.commit();db.refresh(incident);return incident,True

def create_connector_event(db,connector,*,external_id='',severite='Information',titre='',message='',site_id=None,equipement_id=None,raw=None):
    ext=str(external_id or '').strip()[:180]
    if ext:
        existing=db.scalar(select(ConnectorEvent).where(ConnectorEvent.connector_id==connector.id,ConnectorEvent.external_id==ext).order_by(ConnectorEvent.id.desc()))
        if existing:return existing,False
    resolved_site=(site_id if site_id is not None else connector.site_id)
    maintenance=active_maintenance_window(db,connector.id,resolved_site)
    ev=ConnectorEvent(connector_id=connector.id,site_id=resolved_site,equipement_id=equipement_id,external_id=ext,severite=normalize_severity(severite),titre=(str(titre or 'Événement externe').strip() or 'Événement externe')[:280],message=str(message or '').strip()[:12000],statut=('Maintenance' if maintenance else 'Ouverte'),date_evenement=datetime.utcnow(),raw_json=json.dumps(raw or {},ensure_ascii=False)[:50000])
    db.add(ev);connector.derniere_synchro=datetime.utcnow();connector.statut='Connecté';db.commit();db.refresh(ev)
    if not maintenance:
        create_notifications_for_event(db,ev)
        if normalize_severity(ev.severite)=='Critique':ensure_incident_for_event(db,ev)
    return ev,True

@app.get('/notifications')
def notifications_page(request:Request,etat:str='toutes',db:Session=Depends(get_db)):
    u=require_login(request,db);q=select(Notification).where(Notification.user_id==u.id)
    if etat=='non-lues':q=q.where(Notification.lue.is_(False))
    rows=db.scalars(q.order_by(Notification.created_at.desc()).limit(500)).all();unread=db.scalar(select(func.count(Notification.id)).where(Notification.user_id==u.id,Notification.lue.is_(False))) or 0;critical=db.scalar(select(func.count(Notification.id)).where(Notification.user_id==u.id,Notification.lue.is_(False),Notification.niveau=='Critique')) or 0;trs=''
    for n in rows:
        action='' if n.lue else f'<form method="post" action="/notifications/{n.id}/lire"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn small">Marquer lue</button></form>'
        trs+=f'<tr><td>{dfr(n.created_at)}</td><td>{badge(n.niveau)}</td><td>{escape(n.categorie)}</td><td><a href="{escape(n.lien or "/supervision")}" style="color:#dff0ff;text-decoration:none"><b>{escape(n.titre)}</b></a><div class="muted">{escape((n.message or "")[:350])}</div></td><td>{badge("Lue" if n.lue else "Non lue")}</td><td>{action}</td></tr>'
    token=csrf_token(request);controls=f'<div class="actions"><a class="btn" href="/notifications">Toutes</a><a class="btn" href="/notifications?etat=non-lues">Non lues</a><form method="post" action="/notifications/lire-tout"><input type="hidden" name="csrf_token" value="{token}"><button class="btn">Tout marquer lu</button></form></div>'
    return page(request,u,'Notifications',f'<div class="head"><div><h1>Notifications</h1><p class="muted">Alertes reçues par NOX-IA et destinées à ton rôle.</p></div>{controls}</div><div class="grid g2"><div class="metric"><span>Non lues</span><strong>{unread}</strong></div><div class="metric"><span>Critiques non lues</span><strong>{critical}</strong></div></div><section class="card"><div class="scroll"><table><tr><th>Date</th><th>Niveau</th><th>Catégorie</th><th>Notification</th><th>État</th><th>Action</th></tr>{trs or "<tr><td colspan=6>Aucune notification.</td></tr>"}</table></div></section>')

@app.post('/notifications/{nid}/lire')
def notification_read(nid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);n=db.get(Notification,nid)
    if not n or n.user_id!=u.id:raise HTTPException(404)
    n.lue=True;n.read_at=datetime.utcnow();db.commit();return RedirectResponse(request.headers.get('referer') or '/notifications',303)

@app.post('/notifications/lire-tout')
def notification_read_all(request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);rows=db.scalars(select(Notification).where(Notification.user_id==u.id,Notification.lue.is_(False))).all();now=datetime.utcnow()
    for n in rows:n.lue=True;n.read_at=now
    db.commit();return RedirectResponse('/notifications',303)

@app.get('/api/notifications/status')
def notification_status(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);unread=db.scalar(select(func.count(Notification.id)).where(Notification.user_id==u.id,Notification.lue.is_(False))) or 0;n=db.scalar(select(Notification).where(Notification.user_id==u.id,Notification.lue.is_(False)).order_by(Notification.id.desc()).limit(1));latest=None
    if n:latest={'id':n.id,'niveau':n.niveau,'titre':n.titre,'message':(n.message or '')[:500],'lien':n.lien}
    return {'unread':unread,'latest':latest}

@app.post('/api/connecteurs/{cid}/events')
async def connector_webhook_ingest(cid:int,request:Request,db:Session=Depends(get_db)):
    connector=require_connector_token(request,db,cid)
    try:payload=await request.json()
    except Exception:raise HTTPException(400,'JSON invalide')
    if not isinstance(payload,dict):raise HTTPException(400,'Objet JSON attendu')
    external_id=payload.get('external_id') or payload.get('event_id') or payload.get('id') or '';severite=payload.get('severity') or payload.get('severite') or payload.get('level') or 'Information';titre=payload.get('title') or payload.get('titre') or payload.get('event') or 'Événement externe';message=payload.get('message') or payload.get('description') or payload.get('detail') or '';site_id=connector.site_id
    raw_site=payload.get('site_id')
    if raw_site not in (None,''):
        try:site_id=int(raw_site)
        except Exception:pass
    equipement_id=None;raw_eq=payload.get('equipement_id') or payload.get('equipment_id')
    if raw_eq not in (None,''):
        try:equipement_id=int(raw_eq)
        except Exception:pass
    if equipement_id is None:
        ref=str(payload.get('equipment_ref') or payload.get('equipement_reference') or payload.get('reference') or '').strip()
        if ref:
            eq=db.scalar(select(Equipement).where(Equipement.reference==ref));equipement_id=eq.id if eq else None
    ev,created=create_connector_event(db,connector,external_id=external_id,severite=severite,titre=titre,message=message,site_id=site_id,equipement_id=equipement_id,raw=payload)
    return {'ok':True,'created':created,'event_id':ev.id,'status':ev.statut,'severity':ev.severite}

@app.post('/api/connecteurs/{cid}/heartbeat')
async def connector_heartbeat(cid:int,request:Request,db:Session=Depends(get_db)):
    connector=require_connector_token(request,db,cid);connector.derniere_synchro=datetime.utcnow();connector.statut='Connecté';db.commit();return {'ok':True,'connector_id':connector.id,'status':connector.statut,'server_time':datetime.utcnow().isoformat()}

@app.get('/api/connecteurs/{cid}/status')
def connector_status(cid:int,request:Request,db:Session=Depends(get_db)):
    connector=require_connector_token(request,db,cid)
    open_events=db.scalar(select(func.count(ConnectorEvent.id)).where(ConnectorEvent.connector_id==cid,ConnectorEvent.statut.in_(['Ouverte','Acquittée']))) or 0
    open_incidents=db.scalar(select(func.count(SupervisionIncident.id)).where(SupervisionIncident.connector_id==cid,SupervisionIncident.statut!='Fermé')) or 0
    return {'ok':True,'connector_id':connector.id,'name':connector.nom,'status':connector.statut,'last_sync':connector.derniere_synchro.isoformat() if connector.derniere_synchro else None,'open_events':open_events,'open_incidents':open_incidents}

@app.get('/incidents')
def incidents_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db)
    rows=db.scalars(select(SupervisionIncident).order_by(SupervisionIncident.created_at.desc()).limit(500)).all()
    sites_=db.scalars(select(Site).where(Site.actif.is_(True)).order_by(Site.nom)).all();connectors=db.scalars(select(IntegrationConnector).where(IntegrationConnector.actif.is_(True)).order_by(IntegrationConnector.nom)).all();trs=''
    for x in rows:
        site=db.get(Site,x.site_id) if x.site_id else None;eq=db.get(Equipement,x.equipement_id) if x.equipement_id else None
        action=''
        if u.role in TECHS and x.statut!='Fermé':
            action=(f'<div class="actions"><form method="post" action="/incidents/{x.id}/assign"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn small">Me l\'assigner</button></form>'
                    f'<form method="post" action="/incidents/{x.id}/intervention"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn small primary">Créer intervention</button></form>'
                    f'<form method="post" action="/incidents/{x.id}/close"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn small">Fermer</button></form></div>')
        linked=(f'<a class="btn small" href="/interventions/{x.intervention_id}">Intervention #{x.intervention_id}</a>' if x.intervention_id else action)
        eqname=((eq.reference+' · '+eq.nom) if eq else '—')
        trs+=f'<tr id="incident-{x.id}"><td>{dfr(x.created_at)}</td><td>{badge(x.severite)}</td><td>{escape(site.nom if site else "—")}</td><td><b>{escape(x.titre)}</b><div class="muted">{escape((x.resume or "")[:260])}</div><div class="muted">Équipement : {escape(eqname)}</div></td><td>{badge(x.statut)}<div class="muted">{escape(x.assigne_a or "Non assigné")}</div></td><td>{linked}</td></tr>'
    open_count=sum(1 for x in rows if x.statut!='Fermé');critical=sum(1 for x in rows if x.statut!='Fermé' and normalize_severity(x.severite)=='Critique');assigned=sum(1 for x in rows if x.statut!='Fermé' and x.assigne_a)
    maintenance=db.scalars(select(MaintenanceWindow).order_by(MaintenanceWindow.start_at.desc()).limit(100)).all();mrows=''
    for m in maintenance:
        site=db.get(Site,m.site_id) if m.site_id else None;c=db.get(IntegrationConnector,m.connector_id) if m.connector_id else None;state='Active' if m.actif and m.start_at<=datetime.utcnow()<=m.end_at else ('Planifiée' if m.actif and m.start_at>datetime.utcnow() else 'Terminée')
        mrows+=f'<tr><td>{escape(m.titre)}</td><td>{escape(site.nom if site else "Tous")}</td><td>{escape(c.nom if c else "Tous")}</td><td>{dfr(m.start_at)} → {dfr(m.end_at)}</td><td>{badge(state)}</td></tr>'
    form=''
    if u.role in MANAGERS:
        form=(f'<section class="card"><h2>Fenêtre de maintenance</h2><p class="muted">Les événements sont conservés mais ne déclenchent ni notification ni incident pendant la période.</p><form method="post" action="/incidents/maintenance" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}">'
              f'<label>Titre<input name="titre" required placeholder="Maintenance programmée"></label><label>Site<select name="site_id">{option_rows(sites_,lambda x:x.id,lambda x:x.nom,empty="Tous les sites")}</select></label><label>Connecteur<select name="connector_id">{option_rows(connectors,lambda x:x.id,lambda x:x.nom,empty="Tous les connecteurs")}</select></label><label>Début<input type="datetime-local" name="start_at" required></label><label>Fin<input type="datetime-local" name="end_at" required></label><label class="full">Motif<input name="motif"></label><button class="btn primary">Planifier</button></form></section>')
    return page(request,u,'Incidents',f'<div class="head"><div><h1>Centre opérations</h1><p class="muted">Incidents issus de la supervision, affectation, intervention et maintenance planifiée.</p></div><a class="btn" href="/supervision">Supervision</a></div><div class="grid g3"><div class="metric"><span>Incidents ouverts</span><strong>{open_count}</strong></div><div class="metric"><span>Critiques</span><strong>{critical}</strong></div><div class="metric"><span>Assignés</span><strong>{assigned}</strong></div></div>{form}<section class="card"><h2>Incidents</h2><div class="scroll"><table><tr><th>Date</th><th>Niveau</th><th>Site</th><th>Incident</th><th>État</th><th>Action</th></tr>{trs or "<tr><td colspan=6>Aucun incident.</td></tr>"}</table></div></section><section class="card"><h2>Maintenances</h2><div class="scroll"><table><tr><th>Titre</th><th>Site</th><th>Connecteur</th><th>Période</th><th>État</th></tr>{mrows or "<tr><td colspan=5>Aucune fenêtre.</td></tr>"}</table></div></section>')

@app.post('/incidents/maintenance')
def maintenance_add(request:Request,titre:str=Form(...),site_id:str=Form(''),connector_id:str=Form(''),start_at:str=Form(...),end_at:str=Form(...),motif:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS)
    try:start=datetime.fromisoformat(start_at);end=datetime.fromisoformat(end_at)
    except Exception:raise HTTPException(400,'Dates invalides')
    if end<=start:raise HTTPException(400,'La fin doit être après le début')
    db.add(MaintenanceWindow(site_id=(int(site_id) if site_id else None),connector_id=(int(connector_id) if connector_id else None),titre=titre.strip(),motif=motif.strip(),start_at=start,end_at=end,actif=True,created_by=u.username));db.commit();return RedirectResponse('/incidents',303)

@app.post('/incidents/{iid}/assign')
def incident_assign(iid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,TECHS);x=db.get(SupervisionIncident,iid)
    if not x:raise HTTPException(404)
    x.assigne_a=u.username;x.statut='En cours';x.updated_at=datetime.utcnow();db.commit();return RedirectResponse('/incidents',303)

@app.post('/incidents/{iid}/close')
def incident_close(iid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,TECHS);x=db.get(SupervisionIncident,iid)
    if not x:raise HTTPException(404)
    x.statut='Fermé';x.closed_at=datetime.utcnow();x.updated_at=datetime.utcnow();db.commit();return RedirectResponse('/incidents',303)

@app.post('/incidents/{iid}/intervention')
def incident_to_intervention(iid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,TECHS);x=db.get(SupervisionIncident,iid)
    if not x:raise HTTPException(404)
    if x.intervention_id:return RedirectResponse(f'/interventions/{x.intervention_id}',303)
    if not x.site_id:raise HTTPException(400,'Associe d’abord l’incident à un site')
    inter=Intervention(site_id=x.site_id,equipement_id=x.equipement_id,technicien=(x.assigne_a or u.username),type_intervention='Dépannage supervision',priorite=('Urgente' if normalize_severity(x.severite)=='Critique' else 'Normale'),probleme=(x.titre+'\n'+(x.resume or '')).strip(),statut='À faire')
    db.add(inter);db.commit();db.refresh(inter);x.intervention_id=inter.id;x.statut='Intervention créée';x.assigne_a=x.assigne_a or u.username;x.updated_at=datetime.utcnow();db.commit();return RedirectResponse(f'/interventions/{inter.id}',303)

@app.get('/supervision')
def supervision(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);ensure_default_notification_rules(db);connectors=db.scalars(select(IntegrationConnector).order_by(IntegrationConnector.nom)).all();events=db.scalars(select(ConnectorEvent).order_by(ConnectorEvent.date_evenement.desc()).limit(250)).all();sites_=db.scalars(select(Site).where(Site.actif.is_(True)).order_by(Site.nom)).all();rules=db.scalars(select(NotificationRule).order_by(NotificationRule.role,NotificationRule.id)).all();crows='';erows='';rrows=''
    for c in connectors:
        s=db.get(Site,c.site_id) if c.site_id else None;cred=db.scalar(select(ConnectorCredential).where(ConnectorCredential.connector_id==c.id));hook=f'/api/connecteurs/{c.id}/events';token_state=f'Configuré · …{escape(cred.token_hint)}' if cred else 'Aucun jeton';crows+=f'<tr><td><b>{escape(c.nom)}</b><div class="muted">{escape(c.logiciel)}</div></td><td>{escape(s.nom if s else "Global")}</td><td>{escape(c.type_connecteur)}</td><td>{badge(c.statut)}</td><td>{dfr(c.derniere_synchro)}</td><td><code>{hook}</code><div class="muted">{token_state}</div></td><td><div class="actions"><form method="post" action="/supervision/connecteurs/{c.id}/test"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn small">Tester</button></form><form method="post" action="/supervision/connecteurs/{c.id}/rotater"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn small">Nouveau jeton</button></form></div></td></tr>'
    for ev in events:
        s=db.get(Site,ev.site_id) if ev.site_id else None;cls='event-critical' if normalize_severity(ev.severite)=='Critique' else ('event-warning' if normalize_severity(ev.severite)=='Avertissement' else 'event-info');action=''
        if ev.statut not in {'Fermée','Maintenance'} and u.role in TECHS:
            has_incident=db.scalar(select(SupervisionIncident.id).where(SupervisionIncident.event_id==ev.id))
            extra='' if has_incident else f'<form method="post" action="/supervision/evenements/{ev.id}/incident"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn small primary">Créer incident</button></form>'
            action=f'<div class="actions"><form method="post" action="/supervision/evenements/{ev.id}/acquitter"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn small">Acquitter</button></form>{extra}</div>'
        erows+=f'<tr id="event-{ev.id}" class="{cls}"><td>{dfr(ev.date_evenement)}</td><td>{badge(ev.severite)}</td><td>{escape(s.nom if s else "—")}</td><td><b>{escape(ev.titre)}</b><div class="muted">{escape(ev.message[:300])}</div></td><td>{badge(ev.statut)}</td><td>{action}</td></tr>'
    for rule in rules:
        c=db.get(IntegrationConnector,rule.connector_id) if rule.connector_id else None;rrows+=f'<tr><td>{escape(c.nom if c else "Tous les connecteurs")}</td><td>{escape(rule.role)}</td><td>{badge(rule.minimum_severity)}</td><td>{badge("Active" if rule.active else "Inactive")}</td></tr>'
    forms=''
    if u.role in MANAGERS:
        role_options=''.join(f'<option>{escape(r)}</option>' for r in ROLES)
        forms=f'''<div class="grid g2"><section class="card"><h2>Brancher un logiciel</h2><p class="muted">Le mode Webhook / JSON est opérationnel : le logiciel externe envoie ses alertes directement à NOX-IA avec un jeton secret.</p><form method="post" action="/supervision/connecteurs" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Nom<input name="nom" required placeholder="Connecteur site Paris"></label><label>Logiciel<input name="logiciel" placeholder="Nom exact du logiciel"></label><label>Site<select name="site_id">{option_rows(sites_,lambda x:x.id,lambda x:x.nom,empty="Global")}</select></label><label>Type<select name="type_connecteur"><option>Webhook JSON</option><option>API</option><option>SNMP</option><option>Syslog</option><option>E-mail</option><option>Autre</option></select></label><label class="full">Endpoint / description<input name="endpoint" placeholder="Optionnel : URL ou note sur la source"></label><button class="btn primary">Créer et générer le jeton</button></form></section><section class="card"><h2>Règles de notification</h2><p class="muted">Choisis qui doit être averti et à partir de quel niveau.</p><form method="post" action="/supervision/regles" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Connecteur<select name="connector_id">{option_rows(connectors,lambda x:x.id,lambda x:x.nom,empty="Tous les connecteurs")}</select></label><label>Rôle<select name="role">{role_options}</select></label><label>Niveau minimum<select name="minimum_severity"><option>Information</option><option selected>Avertissement</option><option>Critique</option></select></label><button class="btn primary">Ajouter la règle</button></form><div class="scroll"><table><tr><th>Connecteur</th><th>Rôle</th><th>Minimum</th><th>État</th></tr>{rrows or '<tr><td colspan=4>Aucune règle.</td></tr>'}</table></div></section></div>'''
    return page(request,u,'Supervision',f'<div class="head"><div><h1>Supervision</h1><p class="muted">Réception des événements, déduplication, heartbeat, incidents critiques automatiques et maintenance planifiée.</p></div><div class="actions"><a class="btn primary" href="/incidents">Centre opérations</a><a class="btn" href="/notifications">Voir les notifications</a></div></div>{forms}<section class="card"><h2>Connecteurs</h2><div class="scroll"><table><tr><th>Connecteur</th><th>Site</th><th>Type</th><th>Statut</th><th>Dernière synchro</th><th>Entrée NOX-IA</th><th>Actions</th></tr>{crows or "<tr><td colspan=7>Aucun connecteur.</td></tr>"}</table></div></section><section class="card"><h2>Événements</h2><div class="scroll"><table><tr><th>Date</th><th>Sévérité</th><th>Site</th><th>Événement</th><th>Statut</th><th>Action</th></tr>{erows or "<tr><td colspan=6>Aucun événement.</td></tr>"}</table></div></section>')

@app.post('/supervision/connecteurs')
def connector_add(request:Request,nom:str=Form(...),logiciel:str=Form(''),site_id:str=Form(''),type_connecteur:str=Form('Webhook JSON'),endpoint:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);connector=IntegrationConnector(nom=nom.strip(),logiciel=logiciel.strip(),site_id=(int(site_id) if site_id else None),type_connecteur=type_connecteur,endpoint=endpoint.strip(),statut='Prêt à recevoir',actif=True,notes='');db.add(connector);db.commit();db.refresh(connector);raw='noxia_'+secrets.token_urlsafe(32);cred=ConnectorCredential(connector_id=connector.id,token_hash=connector_token_hash(raw),token_hint=raw[-6:]);db.add(cred);db.commit();base=str(request.base_url).rstrip('/');hook=f'{base}/api/connecteurs/{connector.id}/events';heartbeat=f'{base}/api/connecteurs/{connector.id}/heartbeat';body=f'<div class="head"><div><h1>Connecteur créé</h1><p class="muted">Copie le jeton maintenant : NOX-IA ne stocke pas sa valeur brute.</p></div></div><section class="card"><h2>{escape(connector.nom)}</h2><div class="kv"><b>URL événements</b><code>{escape(hook)}</code><b>URL heartbeat</b><code>{escape(heartbeat)}</code><b>Jeton Bearer</b><code style="word-break:break-all">{escape(raw)}</code></div><p class="muted">Envoie l’en-tête <b>Authorization: Bearer &lt;jeton&gt;</b> et un JSON avec au minimum title/titre, message et severity/severite.</p><a class="btn primary" href="/supervision">J’ai copié le jeton</a></section>'
    return page(request,u,'Connecteur créé',body)

@app.post('/supervision/connecteurs/{cid}/rotater')
def connector_rotate(cid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);c=db.get(IntegrationConnector,cid)
    if not c:raise HTTPException(404)
    raw='noxia_'+secrets.token_urlsafe(32);cred=db.scalar(select(ConnectorCredential).where(ConnectorCredential.connector_id==cid))
    if not cred:cred=ConnectorCredential(connector_id=cid,token_hash=connector_token_hash(raw),token_hint=raw[-6:]);db.add(cred)
    else:cred.token_hash=connector_token_hash(raw);cred.token_hint=raw[-6:];cred.rotated_at=datetime.utcnow()
    db.commit();base=str(request.base_url).rstrip('/');hook=f'{base}/api/connecteurs/{cid}/events';return page(request,u,'Nouveau jeton',f'<div class="head"><div><h1>Nouveau jeton généré</h1><p class="muted">L’ancien jeton est immédiatement invalide.</p></div></div><section class="card"><div class="kv"><b>URL événements</b><code>{escape(hook)}</code><b>Nouveau jeton</b><code style="word-break:break-all">{escape(raw)}</code></div><a class="btn primary" href="/supervision">J’ai copié le jeton</a></section>')

@app.post('/supervision/connecteurs/{cid}/test')
def connector_test(cid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);c=db.get(IntegrationConnector,cid)
    if not c:raise HTTPException(404)
    ev,_=create_connector_event(db,c,external_id=f'test-{secrets.token_hex(6)}',severite='Critique',titre=f'Test connecteur · {c.nom}',message='Événement de test généré depuis NOX-IA.',raw={'source':'NOX-IA','test':True});return RedirectResponse(f'/supervision#event-{ev.id}',303)

@app.post('/supervision/regles')
def notification_rule_add(request:Request,connector_id:str=Form(''),role:str=Form(...),minimum_severity:str=Form('Avertissement'),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS)
    if role not in ROLES:raise HTTPException(400,'Rôle invalide')
    db.add(NotificationRule(connector_id=(int(connector_id) if connector_id else None),role=role,minimum_severity=normalize_severity(minimum_severity),active=True));db.commit();return RedirectResponse('/supervision',303)

@app.post('/supervision/evenements')
def connector_event_add(request:Request,connector_id:str=Form(''),site_id:str=Form(''),equipement_id:str=Form(''),severite:str=Form('Information'),titre:str=Form(...),message:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS)
    if connector_id:
        c=db.get(IntegrationConnector,int(connector_id))
        if not c:raise HTTPException(404)
        create_connector_event(db,c,severite=severite,titre=titre,message=message,site_id=(int(site_id) if site_id else c.site_id),equipement_id=(int(equipement_id) if equipement_id else None),raw={'source':'manual'})
    else:
        ev=ConnectorEvent(connector_id=None,site_id=(int(site_id) if site_id else None),equipement_id=(int(equipement_id) if equipement_id else None),severite=normalize_severity(severite),titre=titre.strip(),message=message.strip(),statut='Ouverte',raw_json='{}');db.add(ev);db.commit();db.refresh(ev);create_notifications_for_event(db,ev)
    return RedirectResponse('/supervision',303)

@app.post('/supervision/evenements/{eid}/incident')
def event_to_incident(eid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,TECHS);ev=db.get(ConnectorEvent,eid)
    if not ev:raise HTTPException(404)
    incident,_=ensure_incident_for_event(db,ev);return RedirectResponse(f'/incidents#incident-{incident.id}',303)

@app.post('/supervision/evenements/{eid}/acquitter')
def connector_event_ack(eid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,TECHS);ev=db.get(ConnectorEvent,eid)
    if not ev:raise HTTPException(404)
    ev.statut='Acquittée';ev.date_acquittement=datetime.utcnow();ev.acquittee_par=u.username;db.commit();return RedirectResponse(f'/supervision#event-{eid}',303)

def svg_line(values,labels,title='Évolution'):
    if not values:return '<div class="muted">Pas encore assez de données.</div>'
    w,h,pad=720,220,34;mn=min(values);mx=max(values)
    if mx==mn:mx=mn+1
    pts=[]
    for idx,val in enumerate(values):
        x=pad+(w-2*pad)*(idx/(max(1,len(values)-1)));y=h-pad-(h-2*pad)*((val-mn)/(mx-mn));pts.append((x,y,val))
    poly=' '.join(f'{x:.1f},{y:.1f}' for x,y,_ in pts);dots=''.join(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4" fill="var(--accent)"/><text x="{x:.1f}" y="{y-9:.1f}" text-anchor="middle" fill="#cfe7ff" font-size="11">{v:.1f}</text>' for x,y,v in pts)
    labs=''.join(f'<text x="{(pad+(w-2*pad)*(i/(max(1,len(labels)-1)))):.1f}" y="{h-8}" text-anchor="middle" fill="#8297b3" font-size="10">{escape(str(lab))}</text>' for i,lab in enumerate(labels))
    return f'<div class="chart-wrap"><svg viewBox="0 0 {w} {h}" role="img" aria-label="{escape(title)}"><line x1="{pad}" y1="{h-pad}" x2="{w-pad}" y2="{h-pad}" stroke="#29415f"/><polyline points="{poly}" fill="none" stroke="var(--accent)" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>{dots}{labs}</svg></div>'

@app.get('/analyses')
def analyses(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);feedbacks=db.scalars(select(InterventionFeedback).order_by(InterventionFeedback.date_feedback)).all();ints=db.scalars(select(Intervention)).all();quotes=db.scalars(select(Quote)).all()
    avg=(sum(f.note for f in feedbacks)/len(feedbacks)) if feedbacks else 0;positive=sum(1 for f in feedbacks if f.note>=4);negative=sum(1 for f in feedbacks if f.note<=2);resolved=sum(1 for f in feedbacks if f.resolu);resolved_pct=(resolved/len(feedbacks)*100) if feedbacks else 0
    months={}
    for f in feedbacks:
        key=f.date_feedback.strftime('%Y-%m');months.setdefault(key,[]).append(f.note)
    keys=sorted(months)[-12:];vals=[sum(months[k])/len(months[k]) for k in keys];labels=[k[5:]+'/'+k[:4] for k in keys]
    quote_cost=quote_sale=quote_margin=0
    for q in quotes:
        _,c,s,m,_=quote_totals(db,q);quote_cost+=c;quote_sale+=s;quote_margin+=m
    recurring=0;by_eq={}
    for i in ints:
        if i.equipement_id:by_eq[i.equipement_id]=by_eq.get(i.equipement_id,0)+1
    recurring=sum(1 for n in by_eq.values() if n>=2)
    pos_text=''.join(f'<li>{escape(f.point_positif)}</li>' for f in reversed(feedbacks) if f.point_positif)[:8000] or '<li>Aucun point positif saisi.</li>';neg_text=''.join(f'<li>{escape(f.point_negatif)}</li>' for f in reversed(feedbacks) if f.point_negatif)[:8000] or '<li>Aucun point négatif saisi.</li>'
    return page(request,u,'Analyses',f'<div class="head"><div><h1>Analyses</h1><p class="muted">Qualité des interventions, satisfaction et lecture commerciale.</p></div></div><div class="business-grid"><div class="business-kpi"><div class="label">Satisfaction moyenne</div><div class="value">{avg:.2f}/5</div></div><div class="business-kpi"><div class="label">Satisfaits (4–5)</div><div class="value">{positive}</div></div><div class="business-kpi"><div class="label">Insatisfaits (1–2)</div><div class="value">{negative}</div></div><div class="business-kpi"><div class="label">Résolution déclarée</div><div class="value">{resolved_pct:.1f}%</div></div><div class="business-kpi"><div class="label">Équipements avec interventions répétées</div><div class="value">{recurring}</div></div><div class="business-kpi"><div class="label">Marge devis cumulée</div><div class="value">{money(quote_margin)}</div></div></div><section class="card"><h2>Évolution de la satisfaction</h2>{svg_line(vals,labels,"Satisfaction mensuelle")}</section><div class="grid g2"><section class="card"><h2>Points positifs</h2><ul>{pos_text}</ul></section><section class="card"><h2>Points négatifs</h2><ul>{neg_text}</ul></section></div><section class="card"><h2>Commercial</h2><div class="quote-summary"><div><small>Coûts devis</small><strong>{money(quote_cost)}</strong></div><div><small>Ventes après remises</small><strong>{money(quote_sale)}</strong></div><div><small>Marge</small><strong>{money(quote_margin)}</strong></div><div><small>Devis</small><strong>{len(quotes)}</strong></div></div></section>')

@app.get('/journal')
def journal(request:Request,utilisateur:str='',action:str='',objet:str='',resultat:str='',db:Session=Depends(get_db)):
    u=require_login(request,db);require_role(u,MANAGERS);q=select(AuditLog).order_by(AuditLog.date_evenement.desc())
    if utilisateur.strip():q=q.where(AuditLog.utilisateur.ilike(_search_like(utilisateur)))
    if action.strip():q=q.where(AuditLog.action.ilike(_search_like(action)))
    if objet.strip():q=q.where(AuditLog.objet_type.ilike(_search_like(objet)))
    if resultat=='ok':q=q.where(AuditLog.succes.is_(True))
    elif resultat=='erreur':q=q.where(AuditLog.succes.is_(False))
    rows=db.scalars(q.limit(1000)).all();trs=''
    for a in rows:
        trs+=f'<tr><td>{dfr(a.date_evenement)}</td><td>{escape(a.utilisateur or "Système")}</td><td>{escape(a.role or "—")}</td><td>{escape(a.action)}</td><td>{escape(a.objet_type)}</td><td>{escape(a.objet_id)}</td><td>{badge("OK" if a.succes else "Erreur")}</td><td>{escape(a.adresse_ip)}</td><td>{escape(a.resume[:220])}</td></tr>'
    qs=f'utilisateur={escape(utilisateur)}&action={escape(action)}&objet={escape(objet)}&resultat={escape(resultat)}'
    filters=f'''<section class="card"><form method="get" class="form"><label>Utilisateur<input name="utilisateur" value="{escape(utilisateur)}"></label><label>Action<input name="action" value="{escape(action)}"></label><label>Objet<input name="objet" value="{escape(objet)}"></label><label>Résultat<select name="resultat"><option value="">Tous</option><option value="ok" {'selected' if resultat=='ok' else ''}>OK</option><option value="erreur" {'selected' if resultat=='erreur' else ''}>Erreur</option></select></label><button class="btn primary">Filtrer</button><a class="btn" href="/journal">Réinitialiser</a><a class="btn" href="/journal/export.csv?{qs}">Exporter CSV</a></form></section>'''
    return page(request,u,'Journal',f'<div class="head"><div><h1>Journal d’activité</h1><p class="muted">Traçabilité des changements et connexions. Les corps de formulaires et mots de passe ne sont pas enregistrés.</p></div></div>{filters}<section class="card"><div class="scroll"><table><tr><th>Date</th><th>Utilisateur</th><th>Rôle</th><th>Action</th><th>Objet</th><th>ID</th><th>Résultat</th><th>IP</th><th>Détail</th></tr>{trs or "<tr><td colspan=9>Aucune activité enregistrée.</td></tr>"}</table></div></section>')

@app.get('/assistant')
def assistant_page(request:Request,intervention_id:int|None=None,db:Session=Depends(get_db)):
    user=require_login(request,db)
    interventions=db.scalars(select(Intervention).order_by(Intervention.date_creation.desc()).limit(150)).all()
    context_data=assistant_context(db,intervention_id)
    if intervention_id:
        history=db.scalars(select(AssistantExchange).where(AssistantExchange.intervention_id==intervention_id).order_by(AssistantExchange.created_at.asc())).all()
    else:
        history=db.scalars(select(AssistantExchange).where(AssistantExchange.user_id==user.id,AssistantExchange.intervention_id.is_(None)).order_by(AssistantExchange.created_at.asc()).limit(80)).all()

    context_html=''.join(f'<span class="context-chip">{escape(chip)}</span>' for chip in context_data['chips'] if chip)
    options=option_rows(interventions,lambda row:row.id,lambda row:f'#{row.id} · {row.probleme[:80]}',selected=intervention_id,empty='Assistant général')
    history_html=''
    last_id=history[-1].id if history else None
    for exchange in history:
        action_button=''
        if exchange.intervention_id and user.role in TECHS:
            action_button=(f'<form method="post" action="/assistant/{exchange.id}/ajouter-actions">'
                           f'<input type="hidden" name="csrf_token" value="{csrf_token(request)}">'
                           f'<button class="btn goodbtn">Ajouter dans Actions réalisées</button></form>')
        last_attr=' id="last-exchange" class="bubble ai last-exchange"' if exchange.id==last_id else ' class="bubble ai"'
        history_html+=(f'<div class="bubble user"><div class="meta">{dfr(exchange.created_at)} · {escape(exchange.utilisateur)}</div>'
                       f'<div class="answer-label">Technicien</div><div class="pre">{escape(exchange.question)}</div></div>'
                       f'<div{last_attr}><div class="meta">NOX-IA</div><div class="pre">{escape(exchange.reponse)}</div>'
                       f'<details><summary>Sources NOX-Core utilisées</summary>{assistant_sources_html(exchange.sources_json)}</details>{action_button}</div>')

    suggested=escape(context_data['intervention'].probleme if context_data['intervention'] and not history else '')
    memory_count=db.scalar(select(func.count(AssistantMemory.id))) or 0
    memory_recent=db.scalars(select(AssistantMemory).order_by(AssistantMemory.updated_at.desc()).limit(4)).all()
    state_cls,state_text=assistant_memory_storage_status()
    memory_preview=''.join(f'<div class="memory-card"><div class="memory-meta"><span>{escape(m.memory_type)}</span><span>·</span><span>{escape(m.confidence)}</span></div><b>{escape(m.title)}</b><div class="muted">{escape(m.content[:240])}</div></div>' for m in memory_recent)

    if assistant_ai_enabled():
        status_html=(f'<span class="ai-status on">Mode avancé · {escape(assistant_ai_model())} · raisonnement {escape(assistant_ai_reasoning())}</span>')
    else:
        status_html='<span class="ai-status">Mode local · NOX-Core + mémoire interne</span>'

    conv_tools=''
    if history:
        conv_tools='<div class="conversation-tools"><a class="btn small" href="#last-exchange">↓ Dernière réponse</a><label for="replyToggle" class="btn small" style="cursor:pointer">Répondre</label></div>'

    reply_form=(
        '<section class="reply-box">'
        '<div class="reply-dock-head"><div><b>Répondre / continuer la discussion</b><div class="hint">Le panneau peut rester réduit pendant que tu lis.</div></div>'
        '<label for="replyToggle" class="btn small" style="cursor:pointer">— Réduire</label></div>'
        '<form method="post" action="/assistant/analyser" class="form" id="assistantReplyForm">'
        f'<input type="hidden" name="csrf_token" value="{csrf_token(request)}"><input type="hidden" name="intervention_id" value="{intervention_id or ""}">'
        '<label class="full">Ton message<textarea id="assistantReplyText" name="question" required placeholder="Écris comme tu parlerais à un collègue...">'+suggested+'</textarea></label>'
        f'<div class="assistant-quick-replies quick-replies-visible"><span class="hint">Réponse rapide :</span><button type="submit" formaction="/assistant/rapide" formmethod="post" formnovalidate name="reply" value="oui" class="quick-reply">Oui</button><button type="submit" formaction="/assistant/rapide" formmethod="post" formnovalidate name="reply" value="non" class="quick-reply">Non</button><button type="submit" formaction="/assistant/rapide" formmethod="post" formnovalidate name="reply" value="toujours pas" class="quick-reply">Toujours pas</button><button type="submit" formaction="/assistant/rapide" formmethod="post" formnovalidate name="reply" value="ça marche" class="quick-reply">Ça marche</button><button type="submit" formaction="/assistant/rapide" formmethod="post" formnovalidate name="reply" value="pareil" class="quick-reply">Pareil</button></div>'
        f'<div class="assistant-turn-hint">NOX-IA avance maintenant une étape à la fois. Tu peux aussi écrire « détaille tout » si tu veux l’analyse complète.</div><div class="actions"><button class="btn primary">Envoyer à NOX-IA</button><button type="button" class="btn assistant-local-btn" id="assistantLocalBtn">🧠 Réponse locale</button><a class="btn" href="/assistant/memoire">Mémoire interne</a></div><div class="local-brain-bar"><span class="local-dot" id="assistantLocalDot"></span><span class="local-status" id="assistantLocalStatus">Cerveau local : prêt à connecter</span><span class="hint" id="assistantLocalHint">La réponse locale passe directement par le service NOX-IA installé sur ton PC.</span></div></form></section>'
    )

    body=(
        '<div class="head"><div><h1>Assistant IA</h1><p class="muted">Conversation fluide, questions générales, données NOX-IA, diagnostic terrain approfondi et apprentissage à partir des validations réelles.</p></div><div class="actions"><span class="assistant-mode-pill">🧠 Assistant vivant 7.0</span>'+status_html+'</div></div>'
        f'<div class="core-stats"><span class="memory-count">{memory_count} mémoire(s) permanente(s)</span><span class="memory-count memory-state {state_cls}">{escape(state_text[:115])}</span><span class="memory-count" id="localBrainPageStatus">🧠 Cerveau local : vérification…</span><a class="btn small" href="/assistant/memoire">Ouvrir la mémoire</a></div>'
        '<section class="card"><form method="get" action="/assistant" class="form">'
        f'<label class="full">Contexte intervention<select name="intervention_id" onchange="this.form.submit()">{options}</select></label></form>'
        f'<div style="margin-top:12px">{context_html or "<span class=muted>Assistant général : tu peux aussi discuter sans intervention sélectionnée.</span>"}</div></section>'
        '<section class="card"><h2>Comment discuter avec NOX-IA</h2><div class="assistant-note muted">Parle-lui normalement, même avec des fautes. Tu peux poser une question basique, demander quelque chose sur NOX-IA, lancer un diagnostic, puis répondre seulement « oui », « pareil » ou « ça marche ». Il garde le fil, fouille NOX-Core et sa mémoire quand c’est utile, et apprend les solutions validées ainsi que les tests qui n’ont rien changé.</div></section>'
        f'<section class="card" id="conversation"><div class="head"><div><h2>Conversation</h2><span class="muted">{len(history)} échange(s)</span></div>{conv_tools}</div><div class="chat">{history_html or "<span class=muted>Aucun échange pour le moment.</span>"}</div></section>'
        '<section class="card"><div class="head"><div><h2>Derniers apprentissages</h2><p class="muted">Cette mémoire n’est pas effacée par le bouton de réinitialisation NOX-IA.</p></div></div>'+ (memory_preview or '<span class="muted">La mémoire est vide pour le moment. Elle va se remplir avec les échanges, diagnostics et interventions résolues.</span>')+'</section>'
        '<input type="checkbox" class="reply-toggle" id="replyToggle">'
        '<div class="reply-launcher" id="replyLauncher"><button type="button" class="btn primary" id="assistantReplyLaunch">💬 Répondre à NOX-IA</button><button type="button" class="btn assistant-local-launch" id="assistantLocalLaunch">🧠 Réponse locale</button></div>'
        '<div class="reply-dock" id="replyDock">'+reply_form+'</div>'
        '''<script>
        (function(){
          const field=document.getElementById('assistantReplyText');
          const form=document.getElementById('assistantReplyForm');
          const replyToggle=document.getElementById('replyToggle');
          const localBtn=document.getElementById('assistantLocalBtn');
          const replyLaunch=document.getElementById('assistantReplyLaunch');
          const localLaunch=document.getElementById('assistantLocalLaunch');
          const localDot=document.getElementById('assistantLocalDot');
          const localStatus=document.getElementById('assistantLocalStatus');
          const localHint=document.getElementById('assistantLocalHint');
          const pageStatus=document.getElementById('localBrainPageStatus');
          const BRIDGE='http://127.0.0.1:8765';
          let localReady=false;
          let localBusy=false;
          let localModel='nox-tech:4b';

          if(replyToggle&&field){
            replyToggle.addEventListener('change',function(){
              if(replyToggle.checked)setTimeout(function(){field.focus();},80);
            });
          }
          if(field){
            field.addEventListener('keydown',function(e){
              if((e.ctrlKey||e.metaKey)&&e.key==='Enter'){
                e.preventDefault();
                if(form)form.requestSubmit();
              }
            });
          }

          function setLocalVisual(kind,message,model){
            if(kind==='ready'){
              localReady=true;
              if(model)localModel=model;
            }else if(kind==='error'){
              localReady=false;
            }
            if(localBtn){
              localBtn.disabled=localBusy;
              localBtn.classList.toggle('ready',localReady);
              localBtn.textContent=localBusy?'🧠 NOX-IA local réfléchit…':'🧠 Réponse locale';
            }
            if(localDot)localDot.className='local-dot '+(localReady?'ready':(kind==='busy'?'':'error'));
            if(localStatus)localStatus.textContent=message;
            if(localHint)localHint.textContent=localReady
              ?'Le modèle local répond ici, directement dans NOX-IA.'
              :'Clique sur Réponse locale. Si Chrome demande l’accès au réseau local/loopback, choisis Autoriser.';
            if(pageStatus){
              pageStatus.textContent=localReady?('🧠 Local prêt · '+localModel+' · direct'):('🧠 '+message);
              pageStatus.style.borderColor=localReady?'#315d50':'#70572f';
              pageStatus.style.color=localReady?'#a9f5d4':'#ffda8d';
            }
          }

          async function bridgeFetch(path,options,timeoutMs){
            const ctrl=new AbortController();
            const timer=setTimeout(function(){ctrl.abort();},timeoutMs||10000);
            const opts=Object.assign({cache:'no-store'},options||{});
            opts.signal=ctrl.signal;
            opts.targetAddressSpace='loopback';
            try{
              const response=await fetch(BRIDGE+path,opts);
              const data=await response.json().catch(function(){return {};});
              if(!response.ok)throw new Error(data.error||data.detail||('HTTP '+response.status));
              return data;
            }finally{
              clearTimeout(timer);
            }
          }

          async function detectLocal(showError){
            try{
              const d=await bridgeFetch('/health',{method:'GET'},4500);
              if(d.ok&&d.model_ready){
                setLocalVisual('ready','Cerveau local prêt · '+(d.model||'nox-tech:4b'),d.model||'nox-tech:4b');
                return d;
              }
              throw new Error(d.error||'Ollama ou le modèle local n’est pas prêt.');
            }catch(e){
              const msg=(e&&e.name==='AbortError')?'Le pont local ne répond pas.':((e&&e.message)||'Pont local non détecté.');
              if(showError)setLocalVisual('error',msg);
              else setLocalVisual('error','Cerveau local : clique sur Réponse locale pour connecter.');
              return null;
            }
          }

          async function sendLocal(){
            if(localBusy||!field||!form)return;
            const question=field.value.trim();
            if(!question){
              if(replyToggle)replyToggle.checked=true;
              field.focus();
              setLocalVisual('error','Écris d’abord ton message.');
              return;
            }
            localBusy=true;
            setLocalVisual('busy','Connexion au cerveau local…');
            try{
              const health=await detectLocal(true);
              if(!health)throw new Error('Le cerveau local n’est pas joignable.');

              setLocalVisual('busy','Préparation du contexte technique…');
              const fd=new FormData(form);
              const prep=await fetch('/assistant/local-payload',{method:'POST',body:fd,credentials:'include'});
              const payload=await prep.json().catch(function(){return {};});
              if(!prep.ok||!payload.ok)throw new Error(payload.detail||payload.error||'Impossible de préparer le contexte local.');

              setLocalVisual('busy','NOX-IA local réfléchit…');
              const brain=await bridgeFetch('/chat',{
                method:'POST',
                headers:{'Content-Type':'application/json; charset=utf-8'},
                body:JSON.stringify({
                  model:payload.model||localModel,
                  system:payload.system||'',
                  messages:payload.messages||[],
                  think:false
                })
              },300000);
              if(!brain||!brain.response)throw new Error('Le modèle local n’a renvoyé aucune réponse.');

              setLocalVisual('busy','Réponse reçue · enregistrement…');
              const save=new FormData();
              save.append('csrf_token',fd.get('csrf_token'));
              save.append('intervention_id',fd.get('intervention_id')||'');
              save.append('question',fd.get('question'));
              save.append('response_text',brain.response);
              save.append('sources_json',payload.sources_json||'[]');
              const savedResp=await fetch('/assistant/local-save',{method:'POST',body:save,credentials:'include'});
              const saved=await savedResp.json().catch(function(){return {};});
              if(!savedResp.ok||!saved.ok)throw new Error(saved.detail||saved.error||'Impossible d’enregistrer la réponse locale.');
              location.href=saved.redirect||'/assistant#last-exchange';
            }catch(e){
              const msg=(e&&e.name==='AbortError')?'délai dépassé':((e&&e.message)||'erreur inconnue');
              setLocalVisual('error','Réponse locale impossible : '+msg);
            }finally{
              localBusy=false;
              if(localBtn){localBtn.disabled=false;localBtn.textContent='🧠 Réponse locale';}
            }
          }

          function openReplyDock(preferLocal){
            if(replyToggle)replyToggle.checked=true;
            setTimeout(function(){
              if(field)field.focus();
              if(preferLocal&&localBtn){
                localBtn.animate([{transform:'scale(1)'},{transform:'scale(1.035)'},{transform:'scale(1)'}],{duration:320,easing:'ease-out'});
              }
            },70);
          }

          if(localBtn)localBtn.addEventListener('click',sendLocal);
          if(replyLaunch)replyLaunch.addEventListener('click',function(){openReplyDock(false);});
          if(localLaunch)localLaunch.addEventListener('click',function(){openReplyDock(true);});

          setTimeout(function(){detectLocal(false);},500);
        })();
        </script>'''
    )
    return page(request,user,'Assistant IA',body)

@app.post('/assistant/analyser')
def assistant_analyse(request:Request,question:str=Form(...),intervention_id:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);user=require_login(request,db);require_role(user,ASSISTANT_USERS)
    question=question.strip()
    if len(question)<1:raise HTTPException(400,detail='Question vide')
    iid=int(intervention_id) if intervention_id.strip() else None
    context_data=assistant_context(db,iid)
    recent_history=assistant_history_for_prompt(db,iid,user.id,limit=10)
    conversation_state=assistant_conversation_state(db,iid,user.id,limit=14)

    # Pour une réponse courte ("oui", "non", "toujours pas"), le moteur local récupère explicitement le fil précédent.
    conversation_query=question
    if assistant_short_reply(question) and recent_history!='Aucun échange précédent.':
        conversation_query=recent_history[-4200:]+'\nRéponse actuelle du technicien: '+question

    search_context=context_data['texte']+' '+recent_history+' '+conversation_state
    memories=assistant_memory_search(db,conversation_query+' '+search_context,limit=14)
    sources=assistant_search_nox_core(conversation_query,search_context+' '+assistant_memory_text(memories,6000)+' '+assistant_symptom_atlas_text(conversation_query,search_context,18),limit=10)
    similar=assistant_similar_interventions(db,conversation_query,context_data,limit=4)

    response=None
    if assistant_ai_enabled():
        try:response=assistant_generate_advanced(db,user,question,iid,context_data,sources,similar,memories=memories)
        except Exception:response=None
    if not response:
        response=assistant_local_response(conversation_query,context_data,sources,similar,memories=memories,conversation_state=conversation_state)

    assistant_memory_learn_turn_validation(db,user,question,context_data,iid)
    assistant_memory_learn_turn_failure(db,user,question,context_data,iid)
    exchange=AssistantExchange(intervention_id=iid,equipement_id=(context_data['equipement'].id if context_data['equipement'] else None),user_id=user.id,utilisateur=user.username,question=question,contexte=(context_data['texte']+' '+recent_history)[-12000:],reponse=response,sources_json=assistant_sources_json(sources))
    db.add(exchange)
    assistant_memory_learn_exchange(db,user,question,response,context_data,iid)
    db.commit()
    return RedirectResponse('/assistant'+(f'?intervention_id={iid}' if iid else '')+'#last-exchange',303)

@app.get('/assistant/memoire')
def assistant_memory_page(request:Request,q:str='',db:Session=Depends(get_db)):
    user=require_login(request,db)
    state_cls,state_text=assistant_memory_storage_status()
    if q.strip():rows=assistant_memory_search(db,q,limit=80)
    else:rows=db.scalars(select(AssistantMemory).order_by(AssistantMemory.updated_at.desc()).limit(100)).all()
    cards=''.join(
        f'<div class="memory-card"><div class="memory-meta"><span>{escape(m.memory_type)}</span><span>·</span><span>confiance {escape(m.confidence)}</span><span>·</span><span>{dfr(m.updated_at)}</span><span>·</span><span>utilisée {m.times_used or 0}×</span></div>'
        f'<h3>{escape(m.title)}</h3><div>{escape(m.content)}</div>'
        f'<div class="muted" style="margin-top:8px">{escape((m.constructeur+" "+m.reference).strip())}</div></div>' for m in rows)
    manual=''
    if user.role in TECHS:
        manual=(f'<section class="card"><h2>Ajouter une connaissance manuellement</h2><form method="post" action="/assistant/memoire/ajouter" class="form">'
                f'<input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Titre<input name="title" required></label>'
                '<label>Marque<input name="constructeur"></label><label>Référence<input name="reference"></label>'
                '<label class="full">Information à retenir<textarea name="content" required placeholder="Ex. Sur tel contrôleur, ce symptôme venait de... "></textarea></label>'
                '<button class="btn primary">Mémoriser</button></form></section>')
    import_form=''
    if user.role=='Administrateur':
        import_form=(f'<form method="post" action="/assistant/memoire/import" enctype="multipart/form-data" class="inline-form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><input type="file" name="file" accept="application/json,.json" required><button class="btn">Importer une sauvegarde</button></form>')
    body=(f'<div class="head"><div><h1>Mémoire interne NOX-IA</h1><p class="muted">Connaissances techniques apprises des échanges, diagnostics, interventions résolues et recherches constructeur.</p></div><span class="memory-count memory-state {state_cls}">{escape(state_text)}</span></div>'
          '<section class="card"><div class="actions"><a class="btn" href="/assistant">← Assistant</a><a class="btn" href="/assistant/memoire/export">Exporter la mémoire JSON</a>'+import_form+'</div>'
          f'<form method="get" class="core-toolbar" style="margin-top:14px"><label>Rechercher dans la mémoire<input name="q" value="{escape(q)}" placeholder="Ex. caméra Hikvision hors ligne NVR"></label><button class="btn primary">Rechercher</button></form></section>'+manual+
          f'<section class="card"><div class="head"><h2>{len(rows)} élément(s)</h2></div>{cards or "<div class=empty-state>Aucune mémoire trouvée.</div>"}</section>')
    return page(request,user,'Mémoire IA',body)

@app.post('/assistant/memoire/ajouter')
def assistant_memory_manual(request:Request,title:str=Form(...),content:str=Form(...),constructeur:str=Form(''),reference:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);user=require_login(request,db);require_role(user,TECHS)
    assistant_memory_add(db,'memo_manuel',title.strip(),content.strip(),keywords=assistant_memory_keywords(title+' '+content+' '+constructeur+' '+reference),source='manuel',constructeur=constructeur.strip(),reference=reference.strip(),confidence='élevée',utilisateur=user.username,source_ref='memo-manuel')
    db.commit();return RedirectResponse('/assistant/memoire',303)

@app.get('/assistant/memoire/export')
def assistant_memory_export(request:Request,db:Session=Depends(get_db)):
    require_login(request,db)
    rows=db.scalars(select(AssistantMemory).order_by(AssistantMemory.id)).all();payload=[]
    for m in rows:
        payload.append({c.name:(getattr(m,c.name).isoformat() if isinstance(getattr(m,c.name),(datetime,date)) else getattr(m,c.name)) for c in m.__table__.columns})
    data=json.dumps({'version':APP_VERSION,'exported_at':datetime.utcnow().isoformat(),'memory':payload},ensure_ascii=False,indent=2).encode('utf-8')
    return Response(data,media_type='application/json',headers={'Content-Disposition':'attachment; filename="NOX-IA_memoire_permanente.json"'})

@app.post('/assistant/memoire/import')
async def assistant_memory_import(request:Request,file:UploadFile=File(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);user=require_login(request,db)
    if user.role!='Administrateur':raise HTTPException(403)
    raw=await file.read()
    if len(raw)>8_000_000:raise HTTPException(400,'Fichier trop volumineux')
    try:payload=json.loads(raw.decode('utf-8'));rows=payload.get('memory',payload if isinstance(payload,list) else [])
    except Exception:raise HTTPException(400,'Sauvegarde JSON invalide')
    imported=0
    for item in rows[:10000]:
        if not isinstance(item,dict) or not item.get('content'):continue
        row=assistant_memory_add(db,item.get('memory_type','memo_manuel'),item.get('title','Mémoire importée'),item.get('content',''),keywords=item.get('keywords',''),source=item.get('source','import'),constructeur=item.get('constructeur',''),reference=item.get('reference',''),confidence=item.get('confidence','moyenne'),utilisateur=item.get('utilisateur',user.username),source_ref=item.get('source_ref','import'))
        if row:imported+=1
    db.commit();return RedirectResponse(f'/assistant/memoire?msg={imported}+memoire(s)+importee(s)',303)

@app.post('/assistant/{exchange_id}/ajouter-actions')
def assistant_add_to_actions(
    exchange_id:int,
    request:Request,
    csrf_token_value:str=Form(...,alias='csrf_token'),
    db:Session=Depends(get_db),
):
    check_csrf(request,csrf_token_value)
    user=require_login(request,db)
    require_role(user,TECHS)

    exchange=db.get(AssistantExchange,exchange_id)
    if not exchange or not exchange.intervention_id:
        raise HTTPException(404,detail='Échange introuvable')

    intervention=db.get(Intervention,exchange.intervention_id)
    if not intervention:
        raise HTTPException(404,detail='Intervention introuvable')

    if intervention.statut=='Terminée':
        raise HTTPException(409,detail='Intervention clôturée')

    bloc=(
        f'\n\n--- Assistant IA NOX-IA · {datetime.utcnow().strftime("%d/%m/%Y %H:%M")} ---\n'
        f'{exchange.reponse}'
    )
    intervention.actions_realisees=(
        (intervention.actions_realisees or '').rstrip()+bloc
    ).strip()

    db.commit()

    return RedirectResponse(
        f'/interventions/{intervention.id}',
        303,
    )



SOFTWARE_GUIDE_SYSTEM_PROMPT="""Tu es le guide logiciel PRO de NOX-IA pour techniciens de sûreté et d'infrastructure.
Tu guides l'utilisateur dans des logiciels de vidéosurveillance, VMS/NVR, contrôle d'accès, intrusion, SSI, réseau, supervision et outils de diagnostic.

Règles obligatoires :
- Réponds toujours en français clair, concret et professionnel.
- Les noms visibles dans le logiciel doivent rester EXACTEMENT dans la langue de l'interface. Exemple : si le bouton affiche "Device Management", écris **Device Management** puis, si utile, « (Gestion des appareils) ».
- Ne remplace jamais un vrai libellé anglais/allemand/etc. par une traduction française qui n'existe pas à l'écran.
- Guide une étape à la fois : donne 1 action principale, éventuellement 1 vérification, puis demande ce que l'utilisateur voit avant de continuer.
- N'invente jamais un menu, un bouton, un chemin ou une fonction. Si le chemin dépend de la version ou si la confiance est insuffisante, écris « à confirmer sur cette version » et demande la version ou une capture.
- Si une capture est jointe, base-toi en priorité sur les libellés réellement visibles dans l'image. N'affirme pas qu'un bouton existe s'il n'est pas visible ou connu dans une source fiable.
- Si l'utilisateur indique une langue d'interface, adapte les libellés à cette langue et conserve les traductions uniquement comme aide entre parenthèses.
- Les procédures validées terrain et les termes vérifiés sont prioritaires sur une ancienne réponse IA.
- Pour les actions pouvant couper un service, effacer une configuration, mettre à jour un firmware ou modifier un système de sécurité, avertis AVANT l'action.
- Pour SSI/incendie, ne propose aucune neutralisation, shunt ou contournement de sécurité.
- Pour réseau/cybersécurité, reste sur des opérations défensives, autorisées et réversibles.
- N'affiche jamais de raisonnement interne. Donne seulement la réponse utile au technicien.
"""

SOFTWARE_LANGUAGES=('Auto','Français','English','Deutsch','Español','Italiano','Nederlands','Português','Autre')
SOFTWARE_MODES=('Guidage pas à pas','Trouver une fonction','Diagnostic','Comprendre l’écran')

def _soft_tokens(value):
    return set(re.findall(r'[a-z0-9à-ÿ_-]+',str(value or '').lower()))

def _soft_score(query, *parts):
    q=' '.join(str(query or '').lower().split())
    if not q:return 1
    hay=' '.join(str(x or '').lower() for x in parts)
    score=len(_soft_tokens(q)&_soft_tokens(hay))*3
    if q in hay:score+=12
    return score

def software_terms_search(db,software='',version='',interface_language='Auto',query='',limit=18):
    rows=db.scalars(select(SoftwareUiTerm).order_by(SoftwareUiTerm.verified.desc(),SoftwareUiTerm.usage_count.desc(),SoftwareUiTerm.id.desc()).limit(500)).all()
    ranked=[]
    for row in rows:
        if software and row.software and software.lower() not in row.software.lower() and row.software.lower() not in software.lower():continue
        if version and row.version and version.lower() not in row.version.lower() and row.version.lower() not in version.lower():continue
        if interface_language not in ('','Auto') and row.interface_language not in ('','Auto',interface_language):continue
        score=_soft_score(query or software,row.ui_label,row.french_label,row.menu_path,row.notes,row.software,row.vendor)
        if row.verified:score+=8
        if score>0:ranked.append((score,row))
    ranked.sort(key=lambda x:(x[0],x[1].verified,x[1].usage_count,x[1].id),reverse=True)
    return [r for _,r in ranked[:limit]]

def software_procedure_search(db,software='',version='',interface_language='Auto',query='',limit=8):
    rows=db.scalars(select(SoftwareProcedure).order_by(SoftwareProcedure.verified.desc(),SoftwareProcedure.success_count.desc(),SoftwareProcedure.id.desc()).limit(400)).all()
    ranked=[]
    for row in rows:
        if software and row.software and software.lower() not in row.software.lower() and row.software.lower() not in software.lower():continue
        if version and row.version and version.lower() not in row.version.lower() and row.version.lower() not in version.lower():continue
        if interface_language not in ('','Auto') and row.interface_language not in ('','Auto',interface_language):continue
        score=_soft_score(query or software,row.objective,row.procedure_text,row.software,row.vendor)
        score+=row.success_count*2-row.failure_count*2
        if row.verified:score+=12
        if row.confidence=='élevée':score+=5
        if score>0:ranked.append((score,row))
    ranked.sort(key=lambda x:(x[0],x[1].verified,x[1].success_count,x[1].id),reverse=True)
    return [r for _,r in ranked[:limit]]

def software_terms_text(rows):
    if not rows:return 'Aucun libellé d’interface vérifié enregistré pour ce cas.'
    out=[]
    for r in rows:
        trans=f" → FR: {r.french_label}" if r.french_label else ''
        path=f" | Chemin: {r.menu_path}" if r.menu_path else ''
        ver=f" | Version: {r.version}" if r.version else ''
        state='vérifié terrain' if r.verified else 'à confirmer'
        out.append(f"- {r.ui_label}{trans} | {r.element_type} | langue {r.interface_language}{ver}{path} | {state}")
    return '\n'.join(out)

def software_procedures_text(rows):
    if not rows:return 'Aucune procédure terrain versionnée correspondante.'
    out=[]
    for r in rows:
        state='VALIDÉE' if r.verified else 'à confirmer'
        out.append(f"[{state} · succès {r.success_count} / échecs {r.failure_count}] {r.software} {r.version or ''} · {r.objective}\n{r.procedure_text[:2200]}")
    return '\n\n'.join(out)

def software_guide_context(db,user,software,task,version='',interface_language='Auto',mode='Guidage pas à pas',screen_description=''):
    query=' '.join(x for x in (software,version,task,screen_description) if x)
    profiles=software_profile_text(software or query)
    terms=software_terms_search(db,software,version,interface_language,task+' '+screen_description,limit=14)
    procedures=software_procedure_search(db,software,version,interface_language,task+' '+screen_description,limit=5)
    memories=assistant_memory_search(db,query,limit=10)
    memory_text=assistant_memory_text(memories,5200)
    sources=assistant_search_nox_core(query,profiles+' '+software_terms_text(terms)+' '+software_procedures_text(procedures)+' '+memory_text,limit=6)
    source_text='\n\n'.join(assistant_source_excerpt(item,idx) for idx,item in enumerate(sources,1)) or 'Aucune fiche NOX-Core spécifique.'
    lang_rule=(f"Langue d’interface déclarée : {interface_language}. Conserver les libellés exactement dans cette langue et expliquer en français." if interface_language!='Auto' else "Langue d’interface : automatique. Déduire uniquement des éléments connus/visibles ; sinon demander la langue.")
    return {
        'profiles':profiles,'memories':memories,'sources':sources,'terms':terms,'procedures':procedures,
        'context':f"MODE\n{mode}\n\nLOGICIEL / VERSION\nLogiciel: {software or 'non précisé'}\nVersion: {version or 'non précisée'}\n{lang_rule}\n\nPROFIL LOGICIEL / FAMILLE\n{profiles}\n\nLIBELLÉS D’INTERFACE CONNUS\n{software_terms_text(terms)}\n\nPROCÉDURES TERRAIN\n{software_procedures_text(procedures)}\n\nMÉMOIRE PERMANENTE NOX-IA\n{memory_text}\n\nNOX-CORE\n{source_text}",
    }

@app.get('/logiciels')
def software_guide_page(request:Request,q:str='',db:Session=Depends(get_db)):
    user=require_login(request,db)
    rows=software_profile_search(q,limit=35 if q else 18)
    datalist=''.join(f'<option value="{escape(row.get("name",""),quote=True)}">{escape(row.get("vendor",""))}</option>' for row in software_catalog())
    cards=''.join(
        f'<div class="software-profile"><b>{escape(row.get("name",""))}</b><div class="muted">{escape(row.get("vendor",""))} · {escape(" · ".join(row.get("domains") or []))}</div><div class="hint">{escape(" · ".join(row.get("focus") or [])[:220])}</div><button type="button" class="btn small" onclick="noxiaChooseSoftware({json.dumps(row.get("name",""),ensure_ascii=False)})">Choisir</button></div>'
        for row in rows
    ) or '<span class="muted">Aucun profil correspondant. Tu peux quand même saisir n’importe quel logiciel installé sur ton PC.</span>'
    known_terms=db.scalars(select(SoftwareUiTerm).order_by(SoftwareUiTerm.verified.desc(),SoftwareUiTerm.id.desc()).limit(12)).all()
    known_procs=db.scalars(select(SoftwareProcedure).order_by(SoftwareProcedure.verified.desc(),SoftwareProcedure.success_count.desc(),SoftwareProcedure.id.desc()).limit(8)).all()
    term_rows=''.join(f'<tr><td><b>{escape(x.software)}</b><div class="muted">{escape(x.version or "Toutes versions")}</div></td><td><code>{escape(x.ui_label)}</code><div class="muted">{escape(x.french_label or "")}</div></td><td>{escape(x.interface_language)}</td><td>{badge("Vérifié" if x.verified else "À confirmer")}</td></tr>' for x in known_terms) or '<tr><td colspan="4">Aucun libellé appris.</td></tr>'
    proc_rows=''.join(f'<tr><td><b>{escape(x.software)}</b><div class="muted">{escape(x.version or "Toutes versions")}</div></td><td>{escape(x.objective[:160])}</td><td>{x.success_count}</td><td>{badge("Validée" if x.verified else x.confidence)}</td></tr>' for x in known_procs) or '<tr><td colspan="4">Aucune procédure terrain.</td></tr>'
    token=csrf_token(request);token_js=json.dumps(token);q_value=escape(q,quote=True)
    lang_options=''.join(f'<option value="{escape(x,quote=True)}">{escape(x)}</option>' for x in SOFTWARE_LANGUAGES)
    mode_options=''.join(f'<option value="{escape(x,quote=True)}">{escape(x)}</option>' for x in SOFTWARE_MODES)
    knowledge_form=''
    if user.role in TECHS:
        knowledge_form=(f'<section class="card"><div class="head"><div><h2>Enrichir la base logiciels</h2><p class="muted">Ajoute le vrai texte visible dans le logiciel. Le guide réutilisera ce libellé au lieu d’inventer une traduction.</p></div></div>'
                        f'<form method="post" action="/logiciels/connaissance/terme" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Logiciel<input name="software" required placeholder="Ex. iVMS-4200"></label><label>Version<input name="version" placeholder="Ex. 3.12.0"></label><label>Langue<select name="interface_language">{lang_options}</select></label><label>Type<select name="element_type"><option>Bouton</option><option>Menu</option><option>Onglet</option><option>Champ</option><option>Message</option><option>Option</option></select></label><label>Libellé EXACT<input name="ui_label" required placeholder="Ex. Device Management"></label><label>Traduction française<input name="french_label" placeholder="Gestion des appareils"></label><label class="full">Chemin connu<input name="menu_path" placeholder="Maintenance and Management → Device Management"></label><label class="full">Notes<input name="notes" placeholder="Optionnel"></label><button class="btn primary">Ajouter à la base</button></form></section>')
    body=(
        '<div class="head"><div><h1>Guidage logiciels PRO</h1><p class="muted">Guidage versionné, multilingue et visuel. NOX-IA parle français mais conserve exactement les noms de menus et boutons affichés dans le logiciel.</p></div><span class="ai-status" id="softwareBrainTop">Cerveau local : détection...</span></div>'
        '<section class="card software-hero"><div class="software-panel"><h2>Logiciel et contexte</h2>'
        f'<label>Logiciel<input id="softwareName" list="softwareCatalog" value="{q_value}" placeholder="Ex. iVMS-4200, ATS8600, Wisenet Viewer..."></label><datalist id="softwareCatalog">{datalist}</datalist>'
        '<div class="grid g2"><label>Version<input id="softwareVersion" placeholder="Ex. 3.12.0 ou inconnue"></label>'
        f'<label>Langue de l’interface<select id="softwareLanguage">{lang_options}</select></label></div>'
        f'<label>Mode<select id="softwareMode">{mode_options}</select></label>'
        '<div class="actions" style="margin-top:10px"><button type="button" class="btn" id="detectAppsBtn">Détecter sur mon PC</button><button type="button" class="btn" id="openSoftwareBtn">Ouvrir le logiciel</button></div><div class="software-results" id="softwareApps"></div>'
        '<label style="margin-top:12px">Ce que tu veux faire ou le problème rencontré<textarea id="softwareTask" placeholder="Ex. Je veux ajouter une caméra qui ping mais n’apparaît pas dans le logiciel."></textarea></label>'
        '<label>Ce que tu vois actuellement à l’écran<textarea id="softwareScreen" placeholder="Ex. Je suis dans Maintenance and Management et je vois Device Management."></textarea></label>'
        '<label>Capture d’écran facultative<input type="file" id="softwareShot" accept="image/png,image/jpeg,image/webp"></label><img id="softwareShotPreview" class="software-shot-preview" alt="Aperçu de la capture">'
        '<div class="actions" style="margin-top:12px"><button type="button" class="btn primary" id="localGuideBtn">Me guider maintenant</button><button type="button" class="btn" id="cloudGuideBtn">Analyse approfondie</button><button type="button" class="btn" id="clearGuideBtn">Nouvelle discussion</button></div>'
        '<div class="local-brain-bar"><span class="local-dot" id="softwareLocalDot"></span><span class="local-status" id="softwareLocalStatus">Détection du pont local...</span></div></div>'
        '<div class="software-panel"><h2>Réponse du guide</h2><div class="software-guide-output" id="softwareGuideOutput"></div>'
        '<div class="actions" id="softwareQuickActions" style="display:none;margin-top:10px"><button type="button" class="btn small" data-follow="Ça marche. Donne-moi l’étape suivante.">Ça marche</button><button type="button" class="btn small" data-follow="Je ne trouve pas ce bouton ou ce menu. Guide-moi à partir de ce que je vois.">Je ne trouve pas</button><button type="button" class="btn small" data-follow="Chez moi l’écran est différent. Repars uniquement de ce que je vois actuellement.">C’est différent</button></div>'
        '<div class="actions" id="softwareMemoryActions" style="display:none;margin-top:10px"><button type="button" class="btn goodbtn" id="softwareSolvedBtn">Résolu : valider la procédure</button><button type="button" class="btn dangerbtn" id="softwareWrongBtn">Réponse incorrecte</button></div>'
        '<div class="bridge-help" style="margin-top:12px"><b>Règle multilingue</b><br>NOX-IA t’explique en français. Si le logiciel affiche <b>Settings</b>, il te dira « <b>Settings</b> (Paramètres) » : il ne te demandera pas de chercher un bouton français qui n’existe pas.</div></div></section>'
        f'<section class="card"><div class="head"><div><h2>Profils logiciels connus</h2><p class="muted">Le catalogue reconnaît les familles. Les libellés et procédures terrain ci-dessous rendent le guidage précis selon la version et la langue.</p></div></div><div class="software-profile-list">{cards}</div></section>'
        f'<div class="grid g2"><section class="card"><h2>Libellés appris</h2><div class="scroll"><table><tr><th>Logiciel</th><th>Libellé exact</th><th>Langue</th><th>Fiabilité</th></tr>{term_rows}</table></div></section><section class="card"><h2>Procédures terrain</h2><div class="scroll"><table><tr><th>Logiciel</th><th>Objectif</th><th>Succès</th><th>Fiabilité</th></tr>{proc_rows}</table></div></section></div>'
        +knowledge_form+
        f'''<script>
        (function(){{
          const bridge='http://127.0.0.1:8765',csrf={token_js};
          const name=document.getElementById('softwareName'),version=document.getElementById('softwareVersion'),language=document.getElementById('softwareLanguage'),mode=document.getElementById('softwareMode'),task=document.getElementById('softwareTask'),screen=document.getElementById('softwareScreen'),out=document.getElementById('softwareGuideOutput');
          const dot=document.getElementById('softwareLocalDot'),status=document.getElementById('softwareLocalStatus'),top=document.getElementById('softwareBrainTop'),localBtn=document.getElementById('localGuideBtn'),shot=document.getElementById('softwareShot'),preview=document.getElementById('softwareShotPreview'),appsBox=document.getElementById('softwareApps'),memoryActions=document.getElementById('softwareMemoryActions'),quick=document.getElementById('softwareQuickActions');
          let localReady=false,lastResponse='',guideHistory=[];
          window.noxiaChooseSoftware=function(v){{name.value=v;name.focus();}};
          async function timeoutFetch(url,options,ms){{const c=new AbortController();const t=setTimeout(()=>c.abort(),ms);const o=Object.assign({{}},options||{{}},{{signal:c.signal}});if(url.startsWith(bridge))o.targetAddressSpace='loopback';try{{return await fetch(url,o);}}finally{{clearTimeout(t);}}}}
          async function detectBrain(){{try{{const r=await timeoutFetch(bridge+'/health',{{cache:'no-store'}},1800),d=await r.json();localReady=!!(d.ok&&d.model_ready);dot.className='local-dot '+(localReady?'ready':'error');status.textContent=localReady?('Prêt · '+(d.model||'nox-tech:4b')):'Ollama répond mais le modèle NOX-Local n’est pas prêt.';top.className='ai-status '+(localReady?'on':'');top.textContent=localReady?'Cerveau local prêt':'Cerveau local indisponible';localBtn.disabled=false;}}catch(e){{localReady=false;dot.className='local-dot error';status.textContent='Pont local non détecté.';top.textContent='Cerveau local indisponible';localBtn.disabled=false;}}}}
          function renderApps(rows){{appsBox.innerHTML='';(rows||[]).slice(0,8).forEach(a=>{{const div=document.createElement('div');div.className='software-app';const b=document.createElement('strong');b.textContent=a.name;const btn=document.createElement('button');btn.type='button';btn.className='btn small';btn.textContent='Choisir';btn.onclick=()=>name.value=a.name;div.append(b,btn);appsBox.appendChild(div);}});if(!(rows||[]).length)appsBox.innerHTML='<span class="muted">Aucune application correspondante trouvée.</span>';}}
          document.getElementById('detectAppsBtn').onclick=async()=>{{if(!localReady)await detectBrain();if(!localReady)return alert('Le cerveau local n’est pas joignable.');try{{const r=await timeoutFetch(bridge+'/apps?q='+encodeURIComponent(name.value),{{cache:'no-store'}},5000),d=await r.json();renderApps(d.apps||[]);}}catch(e){{alert('Impossible de lire les applications installées.');}}}};
          document.getElementById('openSoftwareBtn').onclick=async()=>{{if(!localReady)await detectBrain();if(!localReady)return alert('Le cerveau local n’est pas joignable.');if(!name.value.trim())return alert('Indique le logiciel à ouvrir.');try{{const r=await timeoutFetch(bridge+'/open',{{method:'POST',headers:{{'Content-Type':'application/json; charset=utf-8'}},body:JSON.stringify({{name:name.value}})}},8000),d=await r.json();if(!d.ok){{renderApps(d.candidates||[]);throw new Error(d.error||'Application non trouvée');}}status.textContent='Ouverture demandée : '+(d.opened&&d.opened.name?d.opened.name:name.value);}}catch(e){{alert(e.message||'Impossible d’ouvrir le logiciel.');}}}};
          shot.onchange=()=>{{const f=shot.files&&shot.files[0];if(!f){{preview.style.display='none';return;}}const url=URL.createObjectURL(f);preview.src=url;preview.style.display='block';}};
          async function imageBase64(){{const f=shot.files&&shot.files[0];if(!f)return [];if(f.size>6500000)throw new Error('Capture trop volumineuse (maximum 6,5 Mo).');const buf=await f.arrayBuffer();let binary='';const bytes=new Uint8Array(buf),chunk=0x8000;for(let i=0;i<bytes.length;i+=chunk)binary+=String.fromCharCode.apply(null,bytes.subarray(i,Math.min(i+chunk,bytes.length)));return [btoa(binary)];}}
          async function serverContext(){{const fd=new FormData();fd.append('csrf_token',csrf);fd.append('software',name.value);fd.append('version',version.value);fd.append('interface_language',language.value);fd.append('mode',mode.value);fd.append('task',task.value);fd.append('screen_description',screen.value);const r=await fetch('/logiciels/context',{{method:'POST',body:fd,credentials:'same-origin'}}),d=await r.json();if(!r.ok)throw new Error(d.detail||'Contexte indisponible');return d;}}
          async function runLocal(followText=''){{if(!localReady)await detectBrain();if(!localReady){{out.textContent='Le cerveau local n’est pas joignable.';return;}}if(!task.value.trim()&&!followText)return alert('Explique ce que tu veux faire.');localBtn.disabled=true;const old=localBtn.textContent;localBtn.textContent='Analyse locale...';out.textContent='';try{{const ctx=await serverContext(),images=await imageBase64();const current=followText||task.value;let prompt='Logiciel : '+(name.value||'non précisé')+'\\nVersion : '+(version.value||'non précisée')+'\\nLangue interface : '+language.value+'\\nMode : '+mode.value+'\\nObjectif / message : '+current+'\\nCe que je vois : '+(screen.value||'non précisé')+'\\nCapture jointe : '+(images.length?'oui':'non')+'\\n\\nContexte NOX-IA :\\n'+ctx.context;const messages=guideHistory.slice(-12);messages.push({{role:'user',content:prompt}});const r=await timeoutFetch(bridge+'/chat',{{method:'POST',headers:{{'Content-Type':'application/json; charset=utf-8'}},body:JSON.stringify({{model:ctx.model||'nox-tech:4b',system:ctx.system,messages:messages,images:images,think:false}})}},260000),d=await r.json();if(!r.ok||!d.response)throw new Error(d.error||'Aucune réponse locale');lastResponse=d.response;guideHistory.push({{role:'user',content:current}});guideHistory.push({{role:'assistant',content:lastResponse}});out.textContent=lastResponse;memoryActions.style.display='flex';quick.style.display='flex';}}catch(e){{out.textContent='Erreur : '+(e.message||e);}}finally{{localBtn.disabled=false;localBtn.textContent=old;}}}}
          localBtn.onclick=()=>runLocal('');
          quick.querySelectorAll('[data-follow]').forEach(btn=>btn.onclick=()=>runLocal(btn.dataset.follow));
          document.getElementById('cloudGuideBtn').onclick=async()=>{{if(!task.value.trim())return alert('Explique ce que tu veux faire.');const btn=document.getElementById('cloudGuideBtn');btn.disabled=true;const old=btn.textContent;btn.textContent='Analyse approfondie...';out.textContent='';try{{const fd=new FormData();fd.append('csrf_token',csrf);fd.append('software',name.value);fd.append('version',version.value);fd.append('interface_language',language.value);fd.append('mode',mode.value);fd.append('task',task.value);fd.append('screen_description',screen.value);fd.append('history_json',JSON.stringify(guideHistory.slice(-10)));const r=await fetch('/logiciels/cloud-guide',{{method:'POST',body:fd,credentials:'same-origin'}}),d=await r.json();if(!r.ok||!d.response)throw new Error(d.detail||d.error||'Aucune réponse');lastResponse=d.response;guideHistory.push({{role:'user',content:task.value}});guideHistory.push({{role:'assistant',content:lastResponse}});out.textContent=lastResponse;memoryActions.style.display='flex';quick.style.display='flex';}}catch(e){{out.textContent='Erreur : '+(e.message||e);}}finally{{btn.disabled=false;btn.textContent=old;}}}};
          document.getElementById('clearGuideBtn').onclick=()=>{{guideHistory=[];lastResponse='';out.textContent='';task.value='';screen.value='';memoryActions.style.display='none';quick.style.display='none';shot.value='';preview.style.display='none';}};
          document.getElementById('softwareSolvedBtn').onclick=async()=>{{if(!lastResponse)return;const fd=new FormData();fd.append('csrf_token',csrf);fd.append('software',name.value);fd.append('version',version.value);fd.append('interface_language',language.value);fd.append('task',task.value);fd.append('response_text',lastResponse);const r=await fetch('/logiciels/memoriser',{{method:'POST',body:fd,credentials:'same-origin'}}),d=await r.json();if(r.ok&&d.ok){{alert('Procédure validée et enregistrée dans la mémoire terrain NOX-IA.');memoryActions.style.display='none';}}else alert(d.detail||'Impossible de mémoriser.');}};
          document.getElementById('softwareWrongBtn').onclick=async()=>{{if(!lastResponse)return;const details=prompt('Qu’est-ce qui est faux ou différent ? (facultatif)')||'';const fd=new FormData();fd.append('csrf_token',csrf);fd.append('software',name.value);fd.append('version',version.value);fd.append('interface_language',language.value);fd.append('task',task.value);fd.append('response_text',lastResponse);fd.append('details',details);const r=await fetch('/logiciels/feedback',{{method:'POST',body:fd,credentials:'same-origin'}});const d=await r.json();if(r.ok&&d.ok){{alert('Retour enregistré. NOX-IA évitera de considérer cette réponse comme validée.');memoryActions.style.display='none';}}else alert(d.detail||'Impossible d’enregistrer le retour.');}};
          detectBrain();
        }})();
        </script>'''
    )
    return page(request,user,'Guidage logiciels',body)

@app.post('/logiciels/context')
def software_local_context(request:Request,software:str=Form(''),version:str=Form(''),interface_language:str=Form('Auto'),mode:str=Form('Guidage pas à pas'),task:str=Form(''),screen_description:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);user=require_login(request,db);require_role(user,TECHS)
    task=task.strip();software=software.strip();version=version.strip();screen_description=screen_description.strip()
    if not task:raise HTTPException(400,detail='Objectif ou problème manquant')
    if interface_language not in SOFTWARE_LANGUAGES:interface_language='Auto'
    if mode not in SOFTWARE_MODES:mode='Guidage pas à pas'
    ctx=software_guide_context(db,user,software,task,version,interface_language,mode,screen_description)
    return JSONResponse({'ok':True,'model':'nox-tech:4b','system':SOFTWARE_GUIDE_SYSTEM_PROMPT,'context':ctx['context'],'term_count':len(ctx['terms']),'procedure_count':len(ctx['procedures'])})

@app.post('/logiciels/cloud-guide')
def software_cloud_guide(request:Request,software:str=Form(''),version:str=Form(''),interface_language:str=Form('Auto'),mode:str=Form('Guidage pas à pas'),task:str=Form(''),screen_description:str=Form(''),history_json:str=Form('[]'),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);user=require_login(request,db);require_role(user,TECHS)
    software=software.strip();version=version.strip();task=task.strip();screen_description=screen_description.strip()
    if not task:raise HTTPException(400,detail='Objectif ou problème manquant')
    if interface_language not in SOFTWARE_LANGUAGES:interface_language='Auto'
    if mode not in SOFTWARE_MODES:mode='Guidage pas à pas'
    ctx=software_guide_context(db,user,software,task,version,interface_language,mode,screen_description)
    try:
        history=json.loads(history_json or '[]');history=history if isinstance(history,list) else []
    except Exception:history=[]
    history_text='\n'.join(f"{str(x.get('role',''))}: {str(x.get('content',''))[:1600]}" for x in history[-8:] if isinstance(x,dict))
    prompt=f"""LOGICIEL
{software or 'non précisé'}
VERSION
{version or 'non précisée'}
LANGUE INTERFACE
{interface_language}
MODE
{mode}
OBJECTIF / PROBLÈME
{task}
CE QUE L'UTILISATEUR VOIT
{screen_description or 'non précisé'}
CONVERSATION RÉCENTE
{history_text or 'Aucune'}
CONTEXTE NOX-IA
{ctx['context']}

Guide l'utilisateur en français, une étape à la fois. Garde les libellés d'interface dans leur langue exacte et ajoute la traduction française entre parenthèses seulement comme aide. Si le chemin n'est pas suffisamment fiable pour la version indiquée, demande confirmation au lieu d'inventer."""
    response_text=''
    if assistant_ai_enabled():
        try:
            from openai import OpenAI
            client=OpenAI(api_key=os.environ.get('OPENAI_API_KEY','').strip(),timeout=float(os.environ.get('OPENAI_TIMEOUT_SECONDS','55')))
            kwargs={'model':assistant_ai_model(),'instructions':SOFTWARE_GUIDE_SYSTEM_PROMPT,'input':prompt,'reasoning':{'effort':'medium'},'text':{'verbosity':'medium'},'store':False,'safety_identifier':assistant_safety_identifier(user)}
            if assistant_web_lookup_enabled():kwargs['tools']=[{'type':'web_search'}]
            result=client.responses.create(**kwargs);response_text=(result.output_text or '').strip()
        except Exception:response_text=''
    if not response_text:
        response_text=(f"Je peux te guider sur {software or 'ce logiciel'}, mais je ne vais pas inventer un chemin. "
                       f"Version : {version or 'non précisée'}, interface : {interface_language}. "
                       f"Indique ce que tu vois actuellement à l’écran ou joins une capture au cerveau local ; je te donnerai ensuite une seule action précise.")
    profiles=software_profile_search(software,1);vendor=profiles[0].get('vendor','') if profiles else ''
    assistant_memory_add(db,'conversation',f'Guide logiciel — {(software or task)[:120]}',f'Version: {version or "?"} | Langue: {interface_language}\nQuestion: {task}\nRéponse: {response_text[:3200]}',keywords=assistant_memory_keywords(software+' '+version+' '+task),source='guide_logiciel_ia',constructeur=vendor,confidence='faible',utilisateur=user.username,source_ref='guide-logiciel')
    db.commit();return JSONResponse({'ok':True,'response':response_text})

@app.post('/logiciels/memoriser')
def software_memorize_resolved(request:Request,software:str=Form(''),version:str=Form(''),interface_language:str=Form('Auto'),task:str=Form(...),response_text:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);user=require_login(request,db);require_role(user,TECHS)
    software=software.strip();version=version.strip();task=task.strip();response_text=response_text.strip()
    if not task or not response_text:raise HTTPException(400,detail='Procédure vide')
    profiles=software_profile_search(software,1);vendor=profiles[0].get('vendor','') if profiles else ''
    row=db.scalar(select(SoftwareProcedure).where(SoftwareProcedure.software==software,SoftwareProcedure.version==version,SoftwareProcedure.interface_language==interface_language,SoftwareProcedure.objective==task).limit(1))
    if row:
        row.procedure_text=response_text[:12000];row.success_count+=1;row.confidence='élevée';row.verified=True;row.updated_at=datetime.utcnow()
    else:
        row=SoftwareProcedure(software=software or 'Logiciel non précisé',vendor=vendor,version=version,interface_language=interface_language,objective=task[:500],procedure_text=response_text[:12000],source='validation_terrain',verified=True,success_count=1,failure_count=0,confidence='élevée',created_by=user.username)
        db.add(row)
    mem=assistant_memory_add(db,'cas_resolu',f'Procédure logiciel résolue — {(software or "Logiciel")[:120]}',f'Version: {version or "non précisée"}\nLangue interface: {interface_language}\nObjectif: {task}\nProcédure ayant fonctionné selon le technicien:\n{response_text[:6000]}',keywords=assistant_memory_keywords(software+' '+version+' '+task+' '+response_text),source='guide_logiciel_resolu',constructeur=vendor,confidence='élevée',utilisateur=user.username,source_ref='guide-logiciel-resolu')
    db.flush();audit_add(db,request,user,'Validation procédure logiciel','SoftwareProcedure',row.id,f'{software} {version} · {task[:180]}',True);db.commit()
    return JSONResponse({'ok':True,'memory_id':mem.id if mem else None,'procedure_id':row.id})

@app.post('/logiciels/feedback')
def software_feedback(request:Request,software:str=Form(''),version:str=Form(''),interface_language:str=Form('Auto'),task:str=Form(...),response_text:str=Form(...),details:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);user=require_login(request,db);require_role(user,TECHS)
    row=SoftwareGuideFeedback(software=software.strip() or 'Logiciel non précisé',version=version.strip(),interface_language=interface_language,task=task[:7000],response_text=response_text[:12000],verdict='Incorrecte',details=details[:5000],utilisateur=user.username)
    db.add(row);audit_add(db,request,user,'Retour guidage logiciel incorrect','SoftwareGuideFeedback','',f'{software} {version} · {task[:180]}',True);db.commit()
    return JSONResponse({'ok':True,'feedback_id':row.id})

@app.post('/logiciels/connaissance/terme')
def software_term_add(request:Request,software:str=Form(...),version:str=Form(''),interface_language:str=Form('Auto'),element_type:str=Form('Bouton'),ui_label:str=Form(...),french_label:str=Form(''),menu_path:str=Form(''),notes:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);user=require_login(request,db);require_role(user,TECHS)
    software=software.strip();ui_label=ui_label.strip();version=version.strip()
    if not software or not ui_label:raise HTTPException(400,detail='Logiciel et libellé obligatoires')
    profiles=software_profile_search(software,1);vendor=profiles[0].get('vendor','') if profiles else ''
    existing=db.scalar(select(SoftwareUiTerm).where(SoftwareUiTerm.software==software,SoftwareUiTerm.version==version,SoftwareUiTerm.interface_language==interface_language,SoftwareUiTerm.ui_label==ui_label).limit(1))
    if existing:
        existing.french_label=french_label.strip();existing.element_type=element_type;existing.menu_path=menu_path.strip();existing.notes=notes.strip();existing.usage_count+=1;existing.updated_at=datetime.utcnow();row=existing
    else:
        row=SoftwareUiTerm(software=software,vendor=vendor,version=version,interface_language=interface_language,ui_label=ui_label,french_label=french_label.strip(),element_type=element_type,menu_path=menu_path.strip(),notes=notes.strip(),verified=(user.role in MANAGERS),usage_count=1,created_by=user.username)
        db.add(row)
    db.flush();audit_add(db,request,user,'Ajout libellé logiciel','SoftwareUiTerm',row.id,f'{software} · {ui_label}',True);db.commit()
    return RedirectResponse('/logiciels',303)

@app.get('/nox-core')
def nox_core(request:Request,q:str='',intervention_id:int|None=None,db:Session=Depends(get_db)):
    u=require_login(request,db);all_fiches=core_catalog();qn=q.strip();fiches=all_fiches;web_result=None
    if qn:
        norm=assistant_normalize_reference(qn);exact=[]
        for item in all_fiches:
            raw=json.dumps(item,ensure_ascii=False)
            if qn.lower() in raw.lower() or (len(norm)>=6 and norm in assistant_normalize_reference(raw)):exact.append(item)
        ranked=assistant_search_nox_core(qn,limit=80);fiches=[];seen=set()
        for item in exact+ranked:
            t,m,typ,_=core_meta(item);key=(str(m).lower(),str(t).lower(),str(item.get('source_file','')).lower())
            if key in seen:continue
            seen.add(key);fiches.append(item)
            if len(fiches)>=80:break
        ref_query=bool(assistant_reference_tokens(qn));exact_norm=any(len(norm)>=6 and norm in assistant_normalize_reference(json.dumps(item,ensure_ascii=False)) for item in exact)
        if ref_query and not exact_norm and assistant_web_lookup_enabled():
            try:web_result=assistant_web_reference_lookup(qn)
            except Exception:web_result=None
            if web_result and web_result.get('text'):
                assistant_memory_add(db,'web_constructeur',f'Recherche constructeur — {qn[:180]}',web_result.get('text',''),keywords=assistant_memory_keywords(qn+' '+web_result.get('text','')),source='recherche_web',constructeur=web_result.get('brand',''),reference=qn,confidence='élevée',utilisateur=u.username,source_ref='web:'+assistant_normalize_reference(qn));db.commit()
    cards=''
    for item in fiches[:80]:
        t,m,typ,s=core_meta(item);raw_data=json.dumps(item.get('data',{}),ensure_ascii=False,indent=2)[:8000];readable=core_readable_html(item.get('data',{}));related_symptoms=core_symptoms_for_item(item,limit=180);symptom_block=(f'<details class="symptom-panel"><summary>🩺 Symptômes connus pour ce type d’équipement · {len(related_symptoms)}</summary>{core_symptom_html(related_symptoms)}</details>' if related_symptoms else '');link=f'/diagnostics/nouveau?intervention_id={intervention_id}&titre={escape(t)}&maker={escape(m)}' if intervention_id else '';subtitle=' · '.join(x for x in (m,typ) if x);diagnostic_button=f'<a class="btn primary" href="{link}">Utiliser pour diagnostic</a>' if link else '';summary_text=(' · '+escape(s[:220])) if s else '';cards+=f'<details class="core-result"><summary>{escape(t)}</summary><p class="muted">{escape(subtitle)}{summary_text}</p><div class="core-readable">{readable}</div>{symptom_block}<details class="core-raw"><summary>Voir les données brutes</summary><div class="core-code">{escape(raw_data)}</div></details>{diagnostic_button}</details>'
    hidden=f'<input type="hidden" name="intervention_id" value="{intervention_id}">' if intervention_id else '';back=f'?intervention_id={intervention_id}' if intervention_id else '';clear=f'<a class="btn" href="/nox-core{back}">Effacer</a>' if qn else '';local_text=f'{len(fiches)} résultat(s) local(aux)' if qn else f'{len(all_fiches)} fiche(s) disponibles';symptom_hits=core_symptom_search(qn,limit=120) if qn else [];symptom_search_html=(f'<section class="card"><div class="head"><h2>Symptômes correspondant à la recherche</h2><span class="symptom-stat">{len(symptom_hits)} trouvé(s)</span></div><div class="symptom-panel">{core_symptom_html(symptom_hits)}</div></section>' if symptom_hits else '');web_mode='<span class="search-mode on">🌐 Web technique actif</span>' if assistant_web_lookup_enabled() else '<span class="search-mode">Web technique inactif</span>';brand_count=len(assistant_core_brands());results_html=(assistant_web_result_html(web_result)+cards) if (web_result or cards) else '<div class="empty-state">Aucune fiche locale ne correspond. Si la recherche web est active, essaie la référence complète avec sa marque.</div>'
    body=('<div class="head"><div><h1>NOX-Core</h1><p class="muted">Recherche locale intelligente + recherche web constructeur + atlas transversal des symptômes.</p></div></div>'+f'<div class="core-stats"><span class="core-chip">{len(all_fiches)} fiches intégrées</span><span class="core-chip">{brand_count} marques couvertes</span><span class="core-chip">🩺 {len(core_symptom_atlas())} symptômes documentés</span><span class="core-chip">{local_text}</span>{web_mode}<a class="btn small" href="/nox-core/symptomes">Ouvrir l’atlas des symptômes</a></div>'+f'<section class="card"><form method="get" class="core-toolbar"><label>Recherche technique<input class="core-search-input" name="q" value="{escape(q)}" placeholder="Ex. Hikvision DS-2CD1763G2-LIZSU(2.8-12MM), AXIS P3265-LVE, ATS4500..." autofocus></label>{hidden}<button class="btn primary">Rechercher</button>{clear}</form></section>'+f'{symptom_search_html}<section class="card"><h2>Résultats</h2>{results_html}</section>')
    return page(request,u,'NOX-Core',body)

@app.get('/nox-core/symptomes')
def nox_core_symptoms(request:Request,q:str='',domaine:str='',rarete:str='',db:Session=Depends(get_db)):
    u=require_login(request,db);all_rows=core_symptom_atlas();rows=core_symptom_search(q,domain=domaine,rarity=rarete,limit=1000) if (q or domaine or rarete) else all_rows[:1000]
    domains=core_symptom_domains();domain_opts='<option value="">Tous les domaines</option>'+''.join(f'<option value="{escape(d)}"{" selected" if d==domaine else ""}>{escape(d)}</option>' for d in domains)
    rarities=['courant','moins courant','rare','déjà documenté'];rarity_opts='<option value="">Toutes les raretés</option>'+''.join(f'<option value="{escape(r)}"{" selected" if r==rarete else ""}>{escape(r)}</option>' for r in rarities)
    cards=''.join(f'<div class="symptom-row"><div><div class="domain">{escape(row.get("domaine",""))}</div><div class="name">{escape(row.get("symptome",""))}</div></div><div class="muted">{escape(" · ".join(row.get("aliases") or []))}</div><span class="rarity {"rare" if row.get("rarete")=="rare" else ""}">{escape(row.get("rarete",""))}</span></div>' for row in rows)
    body=(f'<div class="head"><div><h1>Atlas des symptômes</h1><p class="muted">Bibliothèque transversale de symptômes observables, des plus fréquents aux cas rares. Elle complète les fiches constructeur et sert aussi au raisonnement de l’assistant IA.</p></div><span class="symptom-stat">{len(all_rows)} symptômes documentés</span></div>'
          f'<section class="card"><form method="get" class="form"><label class="full">Recherche<input class="core-search-input" name="q" value="{escape(q)}" placeholder="Ex. image verte, OSDP, earth fault, RTSP, playback..."></label><label>Domaine<select name="domaine">{domain_opts}</select></label><label>Rareté<select name="rarete">{rarity_opts}</select></label><button class="btn primary">Filtrer</button><a class="btn" href="/nox-core/symptomes">Effacer</a><a class="btn" href="/nox-core">← NOX-Core</a></form></section>'
          f'<section class="card"><div class="head"><h2>Symptômes</h2><span class="muted">{len(rows)} affiché(s)</span></div><div class="symptom-atlas-grid">{cards or "<div class=empty-state>Aucun symptôme trouvé.</div>"}</div></section>')
    return page(request,u,'Atlas des symptômes',body)

@app.get('/diagnostics')
def diagnostics(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(Diagnostic).order_by(Diagnostic.date_debut.desc())).all();trs=''.join(f'<tr><td><a href="/diagnostics/{d.id}">#{d.id}</a></td><td><a href="/interventions/{d.intervention_id}">#{d.intervention_id}</a></td><td>{dfr(d.date_debut)}</td><td>{escape(d.constructeur)}</td><td>{escape(d.fiche_titre)}</td><td>{badge(d.statut)}</td></tr>' for d in rows);return page(request,u,'Diagnostics',f'<h1>Diagnostics</h1><section class="card"><table><tr><th>ID</th><th>Intervention</th><th>Date</th><th>Constructeur</th><th>Fiche</th><th>Statut</th></tr>{trs}</table></section>')

@app.get('/diagnostics/nouveau')
def diagnostic_new(request:Request,intervention_id:int,titre:str='',maker:str='',db:Session=Depends(get_db)):
    u=require_login(request,db);require_role(u,TECHS);i=db.get(Intervention,intervention_id)
    if not i:raise HTTPException(404)
    return page(request,u,'Nouveau diagnostic',f'<h1>Nouveau diagnostic · intervention #{intervention_id}</h1><section class="card"><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><input type="hidden" name="intervention_id" value="{intervention_id}"><label>Constructeur<input name="constructeur" value="{escape(maker)}"></label><label>Fiche NOX-Core<input name="fiche_titre" value="{escape(titre)}"></label><label class="full">Symptôme<textarea name="symptome">{escape(i.probleme)}</textarea></label><button class="btn primary">Démarrer</button></form></section>')

@app.post('/diagnostics/nouveau')
def diagnostic_create(request:Request,intervention_id:int=Form(...),constructeur:str=Form(''),fiche_titre:str=Form(''),symptome:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,TECHS);i=db.get(Intervention,intervention_id);d=Diagnostic(intervention_id=intervention_id,equipement_id=i.equipement_id if i else None,utilisateur=u.username,constructeur=constructeur.strip(),fiche_titre=fiche_titre.strip(),symptome=symptome.strip(),statut='En cours',conclusion='');db.add(d);db.commit();db.refresh(d);return RedirectResponse(f'/diagnostics/{d.id}',303)

@app.get('/diagnostics/{did}')
def diagnostic_detail(did:int,request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);d=db.get(Diagnostic,did)
    if not d:raise HTTPException(404)
    steps=db.scalars(select(DiagnosticStep).where(DiagnosticStep.diagnostic_id==did).order_by(DiagnosticStep.ordre)).all();trs=''.join(f'<tr><td>{s.ordre}</td><td>{escape(s.controle)}</td><td>{badge(s.resultat)}</td><td>{escape(s.reaction)}</td></tr>' for s in steps);form=''
    if u.role in TECHS and d.statut=='En cours':form=f'<section class="card"><h2>Ajouter un contrôle</h2><form method="post" action="/diagnostics/{did}/etape" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label class="full">Contrôle<textarea name="controle" required></textarea></label><label>Résultat<select name="resultat"><option>OK</option><option>Défaut</option><option>Non testé</option></select></label><label>Réaction<input name="reaction"></label><button class="btn primary">Ajouter</button></form><form method="post" action="/diagnostics/{did}/terminer" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label class="full">Conclusion<textarea name="conclusion"></textarea></label><button class="btn goodbtn">Terminer</button></form></section>'
    return page(request,u,f'Diagnostic #{did}',f'<h1>Diagnostic #{did}</h1><section class="card"><div class="kv"><b>Statut</b><span>{badge(d.statut)}</span><b>Fiche</b><span>{escape(d.fiche_titre)}</span></div><h3>Symptôme</h3><div class="pre">{escape(d.symptome)}</div><h3>Conclusion</h3><div class="pre">{escape(d.conclusion)}</div></section>{form}<section class="card"><table><tr><th>#</th><th>Contrôle</th><th>Résultat</th><th>Réaction</th></tr>{trs}</table></section>')

@app.post('/diagnostics/{did}/etape')
def diagnostic_step(did:int,request:Request,controle:str=Form(...),resultat:str=Form(...),reaction:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,TECHS);ordre=(db.scalar(select(func.max(DiagnosticStep.ordre)).where(DiagnosticStep.diagnostic_id==did)) or 0)+1;db.add(DiagnosticStep(diagnostic_id=did,ordre=ordre,controle=controle.strip(),resultat=resultat,reaction=reaction.strip()));db.commit();return RedirectResponse(f'/diagnostics/{did}',303)

@app.post('/diagnostics/{did}/terminer')
def diagnostic_finish(did:int,request:Request,conclusion:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,TECHS);d=db.get(Diagnostic,did)
    if not d:raise HTTPException(404)
    d.statut='Terminé';d.conclusion=conclusion.strip();d.date_fin=datetime.utcnow();assistant_memory_learn_diagnostic(db,d,u);db.commit();return RedirectResponse(f'/diagnostics/{did}',303)

def _active_admin_count(db,exclude_id=None):
    q=select(func.count(User.id)).where(User.active.is_(True),User.role=='Administrateur')
    if exclude_id is not None:q=q.where(User.id!=exclude_id)
    return db.scalar(q) or 0

def _admin_only(request,db):
    u=require_login(request,db)
    if u.role!='Administrateur':raise HTTPException(403,'Accès administrateur requis')
    return u

@app.get('/utilisateurs')
def users_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db)
    if u.role not in MANAGERS:return page(request,u,'Utilisateurs','<h1>Utilisateurs</h1><div class="alert">Accès réservé.</div>')
    rows=db.scalars(select(User).order_by(User.username)).all();trs='';form=''
    for x in rows:
        actions='—'
        if u.role=='Administrateur':
            role_options=''.join(f'<option{(" selected" if r==x.role else "")}>{escape(r)}</option>' for r in ROLES)
            self_note='<span class="muted">Compte connecté</span>' if x.id==u.id else ''
            state_button='' if x.id==u.id else f'<form method="post" action="/utilisateurs/{x.id}/etat" onsubmit="return confirm(\'Confirmer ?\')"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn small {"dangerbtn" if x.active else "goodbtn"}">{"Désactiver" if x.active else "Réactiver"}</button></form>'
            delete_button='' if x.id==u.id else f'<form method="post" action="/utilisateurs/{x.id}/supprimer" onsubmit="return confirm(\'Supprimer ce compte ? L’historique technique sera conservé.\')"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn small dangerbtn">Supprimer</button></form>'
            actions=(f'<div class="inline-form"><form method="post" action="/utilisateurs/{x.id}/role" class="inline-form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><select name="role">{role_options}</select><button class="btn small">Rôle</button></form>'
                     f'<form method="post" action="/utilisateurs/{x.id}/mot-de-passe" class="inline-form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><input type="password" name="password" minlength="10" placeholder="Nouveau mot de passe" required><button class="btn small">Changer</button></form>{state_button}{delete_button}{self_note}</div>')
        trs+=f'<tr><td>{x.id}</td><td>{escape(x.username)}</td><td>{badge(x.role)}</td><td>{badge("Actif" if x.active else "Inactif")}</td><td>{actions}</td></tr>'
    if u.role=='Administrateur':
        form=f'<section class="card"><h2>Créer un utilisateur</h2><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Utilisateur<input name="username" required></label><label>Mot de passe<input type="password" name="password" minlength="10" required></label><label>Rôle<select name="role">{"".join(f"<option>{r}</option>" for r in ROLES)}</select></label><button class="btn primary">Créer</button></form></section>'
    return page(request,u,'Utilisateurs',f'<h1>Utilisateurs</h1>{form}<section class="card"><div class="scroll"><table><tr><th>ID</th><th>Utilisateur</th><th>Rôle</th><th>État</th><th>Actions</th></tr>{trs}</table></div></section>')

@app.post('/utilisateurs')
def users_add(request:Request,username:str=Form(...),password:str=Form(...),role:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);_admin_only(request,db)
    username=username.strip()
    if len(username)<2:raise HTTPException(400,'Nom utilisateur trop court')
    if len(password)<10:raise HTTPException(400,'Mot de passe : 10 caractères minimum')
    if db.scalar(select(User).where(func.lower(User.username)==username.lower())):raise HTTPException(409,'Cet utilisateur existe déjà')
    db.add(User(username=username,password_hash=hash_password(password),role=role if role in ROLES else 'Lecture seule',active=True));db.commit()
    return RedirectResponse('/utilisateurs?msg=Utilisateur+créé',303)

@app.post('/utilisateurs/{uid}/role')
def user_role(uid:int,request:Request,role:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);_admin_only(request,db);target=db.get(User,uid)
    if not target:raise HTTPException(404,'Utilisateur introuvable')
    if role not in ROLES:raise HTTPException(400,'Rôle invalide')
    if target.active and target.role=='Administrateur' and role!='Administrateur' and _active_admin_count(db,exclude_id=target.id)<1:raise HTTPException(409,'Impossible de retirer le dernier administrateur actif')
    target.role=role;db.commit();return RedirectResponse('/utilisateurs?msg=Rôle+mis+à+jour',303)

@app.post('/utilisateurs/{uid}/mot-de-passe')
def user_password(uid:int,request:Request,password:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);_admin_only(request,db);target=db.get(User,uid)
    if not target:raise HTTPException(404,'Utilisateur introuvable')
    if len(password)<10:raise HTTPException(400,'Mot de passe : 10 caractères minimum')
    target.password_hash=hash_password(password);db.commit();return RedirectResponse('/utilisateurs?msg=Mot+de+passe+modifié',303)

@app.post('/utilisateurs/{uid}/etat')
def user_state(uid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=_admin_only(request,db);target=db.get(User,uid)
    if not target:raise HTTPException(404,'Utilisateur introuvable')
    if target.id==u.id:raise HTTPException(409,'Tu ne peux pas désactiver le compte connecté')
    if target.active and target.role=='Administrateur' and _active_admin_count(db,exclude_id=target.id)<1:raise HTTPException(409,'Impossible de désactiver le dernier administrateur actif')
    target.active=not target.active;db.commit();return RedirectResponse('/utilisateurs?msg='+('Utilisateur+réactivé' if target.active else 'Utilisateur+désactivé'),303)

@app.post('/utilisateurs/{uid}/supprimer')
def user_delete(uid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=_admin_only(request,db);target=db.get(User,uid)
    if not target:raise HTTPException(404,'Utilisateur introuvable')
    if target.id==u.id:raise HTTPException(409,'Tu ne peux pas supprimer le compte connecté')
    if target.active and target.role=='Administrateur' and _active_admin_count(db,exclude_id=target.id)<1:raise HTTPException(409,'Impossible de supprimer le dernier administrateur actif')
    db.execute(AssistantExchange.__table__.update().where(AssistantExchange.user_id==uid).values(user_id=None))
    db.execute(Notification.__table__.delete().where(Notification.user_id==target.id));db.delete(target);db.commit();return RedirectResponse('/utilisateurs?msg=Utilisateur+supprimé',303)

# ============================== NOX-IA 6.5 — Entreprise PRO ==============================

def _search_like(value):
    return f"%{(value or '').strip()}%"

def _search_card(title,rows):
    if not rows:return ''
    return f'<section class="card search-group"><h2>{escape(title)}</h2>'+''.join(rows)+'</section>'

@app.get('/search')
def universal_search(request:Request,q:str='',db:Session=Depends(get_db)):
    u=require_login(request,db);q=(q or '').strip()
    if len(q)<2:
        return page(request,u,'Recherche',f'<div class="head"><div><h1>Recherche universelle</h1><p class="muted">Saisis au moins 2 caractères. NOX-IA cherche dans les données auxquelles ton rôle a accès.</p></div></div>')
    like=_search_like(q);groups=[];total=0
    if can_access_module(db,u,'operations'):
        rows=[]
        for x in db.scalars(select(Client).where((Client.nom.ilike(like))|(Client.contact.ilike(like))|(Client.email.ilike(like))).limit(12)).all():
            rows.append(f'<div class="search-result"><div><a href="/clients">{escape(x.nom)}</a><small>Client · {escape(x.contact or x.email or "")}</small></div><span class="b">CL</span></div>')
        total+=len(rows);groups.append(_search_card('Clients',rows))
        rows=[]
        for x in db.scalars(select(Site).where((Site.nom.ilike(like))|(Site.ville.ilike(like))|(Site.adresse.ilike(like))).limit(12)).all():
            rows.append(f'<div class="search-result"><div><a href="/sites">{escape(x.nom)}</a><small>Site · {escape(x.ville or x.adresse or "")}</small></div><span class="b">SI</span></div>')
        total+=len(rows);groups.append(_search_card('Sites',rows))
        rows=[];seen_eq=set()
        for x in db.scalars(select(Equipement).where((Equipement.reference.ilike(like))|(Equipement.marque.ilike(like))|(Equipement.modele.ilike(like))|(Equipement.numero_serie.ilike(like))|(Equipement.ip.ilike(like))).limit(15)).all():
            seen_eq.add(x.id);p=_equipment_profile(db,x.id);extra=(' · '+p.emplacement) if p and p.emplacement else ''
            rows.append(f'<div class="search-result"><div><a href="/equipements/{x.id}">{escape(x.reference)}</a><small>{escape((x.marque+" "+x.modele).strip())} · {escape(x.ip)}{escape(extra)}</small></div><span class="b">EQ</span></div>')
        if len(rows)<15:
            profiles=db.scalars(select(EquipmentAssetProfile).where((EquipmentAssetProfile.asset_tag.ilike(like))|(EquipmentAssetProfile.emplacement.ilike(like))|(EquipmentAssetProfile.zone.ilike(like))|(EquipmentAssetProfile.mac_address.ilike(like))|(EquipmentAssetProfile.firmware_version.ilike(like))).limit(15)).all()
            for p in profiles:
                if p.equipement_id in seen_eq:continue
                x=db.get(Equipement,p.equipement_id)
                if not x:continue
                seen_eq.add(x.id);rows.append(f'<div class="search-result"><div><a href="/equipements/{x.id}">{escape(x.reference)}</a><small>{escape((x.marque+" "+x.modele).strip())} · {escape(p.asset_tag or p.emplacement or p.firmware_version)}</small></div><span class="b">EQ</span></div>')
                if len(rows)>=15:break
        total+=len(rows);groups.append(_search_card('Parc matériel',rows))
        rows=[]
        for x in db.scalars(select(Intervention).where((Intervention.probleme.ilike(like))|(Intervention.solution.ilike(like))|(Intervention.technicien.ilike(like))).order_by(Intervention.date_creation.desc()).limit(15)).all():
            rows.append(f'<div class="search-result"><div><a href="/interventions/{x.id}">Intervention #{x.id}</a><small>{escape(x.probleme[:180])} · {escape(x.technicien)}</small></div><span class="b">IN</span></div>')
        total+=len(rows);groups.append(_search_card('Interventions',rows))
    if can_access_module(db,u,'gestion'):
        rows=[]
        for x in db.scalars(select(StockItem).where((StockItem.reference.ilike(like))|(StockItem.designation.ilike(like))|(StockItem.marque.ilike(like))|(StockItem.modele.ilike(like))).limit(15)).all():
            rows.append(f'<div class="search-result"><div><a href="/stock">{escape(x.reference)} · {escape(x.designation)}</a><small>Stock {x.quantite} · {money(x.prix_achat)}</small></div><span class="b">ST</span></div>')
        total+=len(rows);groups.append(_search_card('Stock',rows))
        rows=[]
        for x in db.scalars(select(Supplier).where((Supplier.nom.ilike(like))|(Supplier.contact.ilike(like))|(Supplier.email.ilike(like))).limit(12)).all():
            rows.append(f'<div class="search-result"><div><a href="/fournisseurs">{escape(x.nom)}</a><small>Fournisseur · {escape(x.contact or x.email or "")}</small></div><span class="b">FO</span></div>')
        total+=len(rows);groups.append(_search_card('Fournisseurs',rows))
        rows=[]
        for x in db.scalars(select(Contract).where((Contract.reference.ilike(like))|(Contract.nom.ilike(like))|(Contract.type_contrat.ilike(like))).limit(12)).all():
            rows.append(f'<div class="search-result"><div><a href="/contrats">{escape(x.reference)} · {escape(x.nom)}</a><small>{escape(x.type_contrat)} · fin {dfr(x.date_fin)}</small></div><span class="b">CO</span></div>')
        total+=len(rows);groups.append(_search_card('Contrats',rows))
    if can_access_module(db,u,'commercial'):
        rows=[]
        for x in db.scalars(select(Quote).where((Quote.reference.ilike(like))|(Quote.objet.ilike(like))|(Quote.commercial.ilike(like))).order_by(Quote.date_creation.desc()).limit(15)).all():
            rows.append(f'<div class="search-result"><div><a href="/devis/{x.id}">{escape(x.reference)}</a><small>{escape(x.objet)} · {escape(x.commercial)} · {escape(x.statut)}</small></div><span class="b">DV</span></div>')
        total+=len(rows);groups.append(_search_card('Devis',rows))
    if can_access_module(db,u,'erp'):
        rows=[]
        for x in db.scalars(select(CRMLead).where((CRMLead.nom.ilike(like))|(CRMLead.contact_nom.ilike(like))|(CRMLead.email.ilike(like))|(CRMLead.commercial.ilike(like))).order_by(CRMLead.updated_at.desc()).limit(12)).all():
            rows.append(f'<div class="search-result"><div><a href="/crm">{escape(x.nom)}</a><small>CRM · {escape(x.etape)} · {money(x.revenu_attendu)}</small></div><span class="b">CR</span></div>')
        total+=len(rows);groups.append(_search_card('CRM',rows))
        rows=[]
        for x in db.scalars(select(PurchaseOrder).where(PurchaseOrder.reference.ilike(like)).order_by(PurchaseOrder.created_at.desc()).limit(12)).all():
            rows.append(f'<div class="search-result"><div><a href="/achats/{x.id}">{escape(x.reference)}</a><small>Achat · {escape(x.statut)} · {money(x.total)}</small></div><span class="b">AH</span></div>')
        total+=len(rows);groups.append(_search_card('Achats',rows))
        rows=[]
        for x in db.scalars(select(CustomerInvoice).where(CustomerInvoice.reference.ilike(like)).order_by(CustomerInvoice.created_at.desc()).limit(12)).all():
            rows.append(f'<div class="search-result"><div><a href="/facturation">{escape(x.reference)}</a><small>Facture · {escape(_invoice_state(x))} · {money(x.total)}</small></div><span class="b">FA</span></div>')
        total+=len(rows);groups.append(_search_card('Facturation',rows))
        rows=[]
        for x in db.scalars(select(BusinessContact).where((BusinessContact.name.ilike(like))|(BusinessContact.company.ilike(like))|(BusinessContact.email.ilike(like))|(BusinessContact.phone.ilike(like))).limit(15)).all():
            rows.append(f'<div class="search-result"><div><a href="/contacts-pro">{escape(x.name)}</a><small>Contact · {escape(x.company or x.email or x.phone)}</small></div><span class="b">CT</span></div>')
        total+=len(rows);groups.append(_search_card('Contacts',rows))
        rows=[]
        for x in db.scalars(select(MarketingCampaign).where((MarketingCampaign.name.ilike(like))|(MarketingCampaign.subject.ilike(like))).limit(12)).all():
            rows.append(f'<div class="search-result"><div><a href="/campagnes">{escape(x.reference)} · {escape(x.name)}</a><small>Campagne · {escape(x.status)}</small></div><span class="b">MK</span></div>')
        total+=len(rows);groups.append(_search_card('Campagnes',rows))
    if can_access_module(db,u,'organisation'):
        rows=[]
        for x in db.scalars(select(RecruitmentApplicant).where((RecruitmentApplicant.name.ilike(like))|(RecruitmentApplicant.email.ilike(like))|(RecruitmentApplicant.source.ilike(like))).limit(12)).all():
            rows.append(f'<div class="search-result"><div><a href="/recrutement">{escape(x.name)}</a><small>Candidat · {escape(x.stage)} · score {x.score}</small></div><span class="b">RC</span></div>')
        total+=len(rows);groups.append(_search_card('Recrutement',rows))
    if can_access_module(db,u,'suivi'):
        rows=[]
        for x in db.scalars(select(ConnectorEvent).where((ConnectorEvent.titre.ilike(like))|(ConnectorEvent.message.ilike(like))|(ConnectorEvent.external_id.ilike(like))).order_by(ConnectorEvent.date_evenement.desc()).limit(15)).all():
            rows.append(f'<div class="search-result"><div><a href="/supervision">{escape(x.titre)}</a><small>{escape(x.severite)} · {escape(x.message[:180])}</small></div><span class="b">SV</span></div>')
        total+=len(rows);groups.append(_search_card('Supervision',rows))
    if can_access_module(db,u,'intelligence'):
        rows=[]
        for x in db.scalars(select(SoftwareProcedure).where((SoftwareProcedure.software.ilike(like))|(SoftwareProcedure.objective.ilike(like))).order_by(SoftwareProcedure.verified.desc(),SoftwareProcedure.success_count.desc()).limit(12)).all():
            rows.append(f'<div class="search-result"><div><a href="/logiciels">{escape(x.software)} · {escape(x.objective[:160])}</a><small>Procédure · {escape(x.version or "toutes versions")} · confiance {escape(x.confidence)}</small></div><span class="b">SW</span></div>')
        total+=len(rows);groups.append(_search_card('Guidage logiciels',rows))
        rows=[]
        for x in db.scalars(select(DiscoveredSystem).where((func.lower(DiscoveredSystem.nom_temporaire).like(like)) | (func.lower(DiscoveredSystem.logiciel).like(like)) | (func.lower(DiscoveredSystem.fabricant).like(like)) | (func.lower(DiscoveredSystem.indices).like(like))).order_by(DiscoveredSystem.updated_at.desc()).limit(12)).all():
            rows.append(f'<div class="search-result"><div><a href="/decouverte-systemes/{x.id}">{escape(x.logiciel or x.nom_temporaire)}</a><small>Système repéré · {escape(x.fabricant or "fabricant inconnu")} · {escape(x.statut_identification)}</small></div><span class="b">DS</span></div>')
        total+=len(rows);groups.append(_search_card('Découverte systèmes',rows))
    body=''.join(g for g in groups if g) or '<section class="card"><p>Aucun résultat.</p></section>'
    return page(request,u,'Recherche',f'<div class="head"><div><h1>Résultats pour « {escape(q)} »</h1><p class="muted">{total} résultat(s) affiché(s), filtrés selon tes droits.</p></div></div>{body}')

@app.get('/administration')
def administration_center(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);require_role(u,MANAGERS)
    cards=[]
    if u.role=='Administrateur':
        cards += [
            ('/utilisateurs','Utilisateurs','Comptes, rôles, activation et mots de passe.'),
            ('/permissions','Permissions','Restreindre les modules visibles et modifiables par rôle.'),
            ('/parametres','Paramètres entreprise','Identité, seuils commerciaux, notifications et gouvernance.'),
            ('/sauvegardes','Sauvegardes','Créer une sauvegarde logique ZIP et suivre son historique.'),
        ]
    cards += [('/securite','Sécurité','Tentatives de connexion, verrouillages et protections actives.'),('/journal','Journal','Traçabilité des changements et export CSV.'),('/sante','Santé / Audit','État de la base, IA, supervision, prix et alertes.')]
    html=''.join(f'<a class="admin-tile" href="{href}"><b>{escape(title)}</b><span>{escape(desc)}</span></a>' for href,title,desc in cards)
    return page(request,u,'Centre admin',f'<div class="head"><div><h1>Centre d’administration</h1><p class="muted">Gouvernance, sécurité, audit et configuration entreprise.</p></div></div><div class="admin-grid">{html}</div>')

@app.get('/permissions')
def permissions_page(request:Request,db:Session=Depends(get_db)):
    u=_admin_only(request,db);ensure_default_role_permissions(db);rows=''
    for role in ('Responsable','Technicien','Commercial','Lecture seule'):
        for module,(label,_) in MODULE_DEFS.items():
            view,edit=role_permission(db,role,module)
            rows+=f'''<tr><td>{escape(role)}</td><td>{escape(label)}</td><td colspan="2"><form class="inline-form" method="post" action="/permissions"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><input type="hidden" name="role" value="{escape(role)}"><input type="hidden" name="module" value="{escape(module)}"><label><input type="checkbox" name="can_view" value="1" {'checked' if view else ''}> Voir</label><label><input type="checkbox" name="can_edit" value="1" {'checked' if edit else ''}> Modifier</label><button class="btn small">Enregistrer</button></form></td></tr>'''
    return page(request,u,'Permissions',f'<div class="head"><div><h1>Permissions par rôle</h1><p class="muted">Les permissions 6.5 peuvent restreindre l’accès à un module entier. Les contrôles sensibles déjà prévus dans NOX-IA restent prioritaires.</p></div></div><section class="card permission-table"><div class="scroll"><table><tr><th>Rôle</th><th>Module</th><th colspan="2">Accès</th></tr>{rows}</table></div></section>')

@app.post('/permissions')
def permissions_save(request:Request,role:str=Form(...),module:str=Form(...),can_view:str=Form(''),can_edit:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=_admin_only(request,db)
    if role not in DEFAULT_ROLE_PERMISSIONS or module not in MODULE_DEFS:raise HTTPException(400,'Permission invalide')
    view=can_view=='1';edit=can_edit=='1'
    if edit:view=True
    row=db.scalar(select(RolePermission).where(RolePermission.role==role,RolePermission.module==module))
    if not row:row=RolePermission(role=role,module=module);db.add(row)
    row.can_view=view;row.can_edit=edit;row.updated_by=u.username;row.updated_at=datetime.utcnow();db.commit();audit_add(db,request,u,'Permission modifiée','RolePermission',row.id,f'{role} · {module} · voir={view} · modifier={edit}',True)
    return RedirectResponse('/permissions?msg=Permission+mise+à+jour',303)

@app.get('/parametres')
def settings_page(request:Request,db:Session=Depends(get_db)):
    u=_admin_only(request,db);ensure_enterprise_defaults(db)
    v={k:get_setting(db,k,d) for k,d in ENTERPRISE_DEFAULTS.items()}
    return page(request,u,'Paramètres',f'''<div class="head"><div><h1>Paramètres entreprise</h1><p class="muted">Réglages centraux appliqués à NOX-IA sans modifier le code.</p></div></div><section class="card"><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Nom entreprise<input name="company_name" value="{escape(v['company_name'])}" required></label><label>Email support<input type="email" name="company_support_email" value="{escape(v['company_support_email'])}"></label><label>Téléphone<input name="company_phone" value="{escape(v['company_phone'])}"></label><label>Ville / agence<input name="company_city" value="{escape(v['company_city'])}"></label><label>Marge minimale sans validation (%)<input type="number" step="0.1" min="0" max="100" name="quote_min_margin_pct" value="{escape(v['quote_min_margin_pct'])}"></label><label>Remise maximale sans validation (%)<input type="number" step="0.1" min="0" max="100" name="quote_max_discount_pct" value="{escape(v['quote_max_discount_pct'])}"></label><label>Rafraîchissement notifications (secondes)<input type="number" min="5" max="120" name="notification_poll_seconds" value="{escape(v['notification_poll_seconds'])}"></label><label>Rétention audit souhaitée (jours)<input type="number" min="30" max="3650" name="audit_retention_days" value="{escape(v['audit_retention_days'])}"></label><label>Fuseau horaire<input name="timezone" value="{escape(v['timezone'])}"></label><button class="btn primary full">Enregistrer les paramètres</button></form></section>''')

@app.post('/parametres')
def settings_save(request:Request,company_name:str=Form(...),company_support_email:str=Form(''),company_phone:str=Form(''),company_city:str=Form(''),quote_min_margin_pct:float=Form(20),quote_max_discount_pct:float=Form(10),notification_poll_seconds:int=Form(15),audit_retention_days:int=Form(365),timezone:str=Form('Europe/Paris'),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=_admin_only(request,db)
    if not company_name.strip():raise HTTPException(400,'Nom entreprise requis')
    quote_min_margin_pct=max(0,min(100,float(quote_min_margin_pct)));quote_max_discount_pct=max(0,min(100,float(quote_max_discount_pct)));notification_poll_seconds=max(5,min(120,int(notification_poll_seconds)));audit_retention_days=max(30,min(3650,int(audit_retention_days)))
    values={'company_name':company_name.strip(),'company_support_email':company_support_email.strip(),'company_phone':company_phone.strip(),'company_city':company_city.strip(),'quote_min_margin_pct':str(quote_min_margin_pct),'quote_max_discount_pct':str(quote_max_discount_pct),'notification_poll_seconds':str(notification_poll_seconds),'audit_retention_days':str(audit_retention_days),'timezone':timezone.strip() or 'Europe/Paris'}
    for k,v in values.items():set_setting(db,k,v,u.username)
    db.commit();audit_add(db,request,u,'Paramètres entreprise modifiés','EnterpriseSetting','',f'{len(values)} paramètre(s)',True)
    return RedirectResponse('/parametres?msg=Paramètres+enregistrés',303)

def _backup_model_list():
    return [EnterpriseSetting,RolePermission,LoginSecurityState,BackupRun,AssistantMemory,AssistantExchange,AuditLog,Client,Site,Equipement,EquipmentAssetProfile,EquipmentPhoto,EquipmentHistoryEntry,Intervention,InterventionFeedback,StockItem,StockMovement,InterventionMaterial,Supplier,SupplierPrice,MarketPrice,PriceSource,PriceSourceAlias,PriceSourceCredential,PriceSyncRun,PlanningEntry,MaintenancePlan,MaintenanceHistory,Contract,Quote,QuoteLine,CommercialCatalogItem,QuoteVersion,QuoteApproval,QuoteActualLine,QuoteWorkOrder,IntegrationConnector,ConnectorCredential,ConnectorEvent,SupervisionIncident,MaintenanceWindow,NotificationRule,Notification,FollowAction,AlertState,Diagnostic,DiagnosticStep,SoftwareUiTerm,SoftwareProcedure,SoftwareGuideFeedback,DiscoveredSystem,CRMLead,PurchaseOrder,PurchaseOrderLine,CustomerInvoice,BusinessEmail,ExternalBusinessConnector,BusinessSyncLog,ERPProject,ERPTask,HelpdeskTicket,TimesheetEntry,ExpenseClaim,BusinessDocument,ApprovalRequest,KnowledgeArticle,BusinessCalendarEvent,EmployeeProfile,LeaveRequest,VendorBill,ServiceSubscription,ChatterMessage,AutomationRule,BusinessActivity,DocumentAttachment,InternalSignatureRequest,CustomFieldDefinition,CustomFieldValue,AutomationExecution,CustomerPortalShare,BusinessContact,FinanceAccount,FinanceTransaction,RecruitmentPosition,RecruitmentApplicant,LeaveAllocation,MarketingCampaign,MarketingRecipient,PublicBusinessForm,PublicFormSubmission,PublishedCatalogItem,SavedBusinessView,User]

def _logical_backup_payload(db):
    payload={'format':'NOX-IA logical backup','version':APP_VERSION,'created_at':datetime.utcnow().isoformat(),'tables':{}}
    total=0
    for model in _backup_model_list():
        out=[]
        for row in db.scalars(select(model)).all():
            data={}
            for col in model.__table__.columns:
                value=getattr(row,col.name)
                if isinstance(value,(datetime,date)):value={'__datetime__':value.isoformat()}
                elif isinstance(value,(bytes,bytearray)):value={'__bytes_b64__':base64.b64encode(bytes(value)).decode('ascii')}
                data[col.name]=value
            out.append(data)
        payload['tables'][model.__tablename__]=out;total+=len(out)
    return payload,total

@app.get('/sauvegardes')
def backups_page(request:Request,db:Session=Depends(get_db)):
    u=_admin_only(request,db);runs=db.scalars(select(BackupRun).order_by(BackupRun.created_at.desc()).limit(30)).all();trs=''
    for r in runs:
        trs+=f'<tr><td>{dfr(r.created_at)}</td><td>{escape(r.created_by)}</td><td>{r.table_count}</td><td>{r.row_count}</td><td>{r.size_bytes/1024:.1f} Ko</td><td><code>{escape((r.sha256 or "")[:14])}…</code></td><td>{badge(r.status)}</td></tr>'
    return page(request,u,'Sauvegardes',f'''<div class="head"><div><h1>Sauvegardes</h1><p class="muted">Sauvegarde logique portable : données métier, configuration, journal et données binaires encodées dans une archive ZIP.</p></div><a class="btn primary" href="/backup/export.zip">Créer et télécharger une sauvegarde</a></div><section class="card"><div class="notice">Cette sauvegarde est un export logique applicatif. Pour une reprise après sinistre complète de PostgreSQL, conserve aussi les sauvegardes gérées par ton hébergeur.</div></section><section class="card"><h2>Historique</h2><div class="scroll"><table><tr><th>Date</th><th>Créée par</th><th>Tables</th><th>Lignes</th><th>Taille</th><th>SHA-256</th><th>État</th></tr>{trs or '<tr><td colspan="7">Aucune sauvegarde créée depuis NOX-IA.</td></tr>'}</table></div></section>''')

@app.get('/backup/export.zip')
def backup_export(request:Request,db:Session=Depends(get_db)):
    u=_admin_only(request,db);payload,total=_logical_backup_payload(db)
    raw=json.dumps(payload,ensure_ascii=False,indent=2).encode('utf-8');buf=io.BytesIO()
    audit_buf=io.StringIO();writer=csv.writer(audit_buf);writer.writerow(['date','utilisateur','role','action','objet_type','objet_id','succes','ip','resume'])
    for a in db.scalars(select(AuditLog).order_by(AuditLog.date_evenement.desc())).all():writer.writerow([a.date_evenement.isoformat(),a.utilisateur,a.role,a.action,a.objet_type,a.objet_id,a.succes,a.adresse_ip,a.resume])
    manifest={'app':'NOX-IA','version':APP_VERSION,'created_at':datetime.utcnow().isoformat(),'tables':len(payload['tables']),'rows':total,'database_backend':engine.url.get_backend_name()}
    with zipfile.ZipFile(buf,'w',zipfile.ZIP_DEFLATED) as z:
        z.writestr('NOX-IA_backup.json',raw);z.writestr('manifest.json',json.dumps(manifest,ensure_ascii=False,indent=2));z.writestr('journal_audit.csv',audit_buf.getvalue().encode('utf-8-sig'));z.writestr('README.txt','Sauvegarde logique NOX-IA. Conserver cette archive dans un emplacement sécurisé.\n')
    data=buf.getvalue();digest=hashlib.sha256(data).hexdigest();run=BackupRun(created_by=u.username,format='ZIP-JSON',table_count=len(payload['tables']),row_count=total,size_bytes=len(data),sha256=digest,status='Créée');db.add(run);db.commit();audit_add(db,request,u,'Sauvegarde logique créée','BackupRun',run.id,f'{total} lignes · SHA256 {digest[:16]}',True)
    stamp=datetime.utcnow().strftime('%Y%m%d_%H%M%S');return Response(data,media_type='application/zip',headers={'Content-Disposition':f'attachment; filename="NOX-IA_backup_{stamp}.zip"','X-NOXIA-SHA256':digest})

@app.get('/securite')
def security_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);require_role(u,MANAGERS);now=datetime.utcnow();states=db.scalars(select(LoginSecurityState).order_by(LoginSecurityState.last_attempt_at.desc()).limit(100)).all();active=sum(1 for x in states if x.locked_until and x.locked_until>now);recent_fail=db.scalar(select(func.count(AuditLog.id)).where(AuditLog.action=='LOGIN_FAILED',AuditLog.date_evenement>=now-timedelta(hours=24))) or 0;active_users=db.scalar(select(func.count(User.id)).where(User.active.is_(True))) or 0
    trs=''
    for x in states[:30]:
        identity=x.username.split('|',1)[0];locked=bool(x.locked_until and x.locked_until>now);action=''
        if locked and u.role=='Administrateur':action=f'<form method="post" action="/securite/deverrouiller"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><input type="hidden" name="sid" value="{x.id}"><button class="btn small">Déverrouiller</button></form>'
        trs+=f'<tr><td>{escape(identity)}</td><td>{escape(x.last_ip)}</td><td>{dfr(x.last_attempt_at)}</td><td>{badge("Verrouillé" if locked else "OK")}</td><td>{dfr(x.last_success_at)}</td><td>{action}</td></tr>'
    empty_row='<tr><td colspan="6">Aucune donnée de connexion.</td></tr>'
    return page(request,u,'Sécurité',f'''<div class="head"><div><h1>Sécurité</h1><p class="muted">Protection des connexions et état des contrôles applicatifs.</p></div></div><div class="grid g4"><div class="metric"><span>Utilisateurs actifs</span><strong>{active_users}</strong></div><div class="metric"><span>Échecs connexion 24 h</span><strong>{recent_fail}</strong></div><div class="metric"><span>Verrouillages actifs</span><strong>{active}</strong></div><div class="metric"><span>Expiration session</span><strong>12 h</strong></div></div><section class="card"><h2>Protections actives</h2><div class="kv"><b>Anti-bruteforce</b><span class="security-ok">5 échecs / IP / identifiant → 10 min</span><b>Cookies session</b><span>Secure sur Render · SameSite=Lax</span><b>CSRF</b><span>Jeton obligatoire sur les écritures</span><b>En-têtes HTTP</b><span>nosniff · SAMEORIGIN · Referrer-Policy · Permissions-Policy</span><b>Secrets connecteurs</b><span>Jetons stockés sous forme de hash</span></div></section><section class="card"><h2>Connexions récentes</h2><div class="scroll"><table><tr><th>Identifiant</th><th>IP</th><th>Dernière tentative</th><th>État</th><th>Dernier succès</th><th></th></tr>{trs or empty_row}</table></div></section>''')

@app.post('/securite/deverrouiller')
def security_unlock(request:Request,sid:int=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=_admin_only(request,db);row=db.get(LoginSecurityState,sid)
    if not row:raise HTTPException(404)
    row.locked_until=None;row.failed_attempts=0;db.commit();audit_add(db,request,u,'Verrouillage connexion levé','LoginSecurityState',sid,row.username.split('|',1)[0],True);return RedirectResponse('/securite?msg=Accès+déverrouillé',303)

@app.get('/journal/export.csv')
def journal_export(request:Request,utilisateur:str='',action:str='',objet:str='',resultat:str='',db:Session=Depends(get_db)):
    u=require_login(request,db);require_role(u,MANAGERS);q=select(AuditLog).order_by(AuditLog.date_evenement.desc())
    if utilisateur.strip():q=q.where(AuditLog.utilisateur.ilike(_search_like(utilisateur)))
    if action.strip():q=q.where(AuditLog.action.ilike(_search_like(action)))
    if objet.strip():q=q.where(AuditLog.objet_type.ilike(_search_like(objet)))
    if resultat=='ok':q=q.where(AuditLog.succes.is_(True))
    elif resultat=='erreur':q=q.where(AuditLog.succes.is_(False))
    rows=db.scalars(q.limit(5000)).all();buf=io.StringIO();w=csv.writer(buf);w.writerow(['date','utilisateur','role','action','objet','id','resultat','ip','detail'])
    for a in rows:w.writerow([a.date_evenement.isoformat(),a.utilisateur,a.role,a.action,a.objet_type,a.objet_id,'OK' if a.succes else 'Erreur',a.adresse_ip,a.resume])
    data=buf.getvalue().encode('utf-8-sig');return Response(data,media_type='text/csv; charset=utf-8',headers={'Content-Disposition':'attachment; filename="NOX-IA_journal.csv"'})


def pdf_bytes(db,i,technical):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table
    buf=io.BytesIO();styles=getSampleStyleSheet();doc=SimpleDocTemplate(buf,pagesize=A4);s=db.get(Site,i.site_id);c=db.get(Client,s.client_id) if s else None;e=db.get(Equipement,i.equipement_id) if i.equipement_id else None;story=[Paragraph('NOX-IA — Rapport technique' if technical else 'NOX-IA — Rapport client',styles['Title']),Spacer(1,12),Table([['Intervention',f'#{i.id}'],['Client',c.nom if c else '—'],['Site',s.nom if s else '—'],['Équipement',e.reference if e else '—'],['Technicien',i.technicien],['Statut',i.statut]])]
    for lab,val in [('Problème',i.probleme),('Actions',i.actions_realisees),('Solution',i.solution)]:story+=[Spacer(1,8),Paragraph(lab,styles['Heading2']),Paragraph(escape(val or '—'),styles['BodyText'])]
    if technical:
        for d in db.scalars(select(Diagnostic).where(Diagnostic.intervention_id==i.id)).all():story+=[Spacer(1,8),Paragraph(f'Diagnostic #{d.id} — {escape(d.fiche_titre)}',styles['Heading2']),Paragraph(escape(d.conclusion or d.symptome),styles['BodyText'])]
    doc.build(story);return buf.getvalue()

@app.get('/interventions/{iid}/rapport/{kind}')
def report(iid:int,kind:str,request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);i=db.get(Intervention,iid)
    if not i:raise HTTPException(404)
    technical=kind=='technique'
    if technical and u.role not in TECHS:raise HTTPException(403)
    return Response(pdf_bytes(db,i,technical),media_type='application/pdf',headers={'Content-Disposition':f'inline; filename="NOX-IA_{iid}_{kind}.pdf"'})

def _require_admin_confirmation(request,db,confirmation,expected='SUPPRIMER'):
    u=_admin_only(request,db)
    if (confirmation or '').strip()!=expected:raise HTTPException(400,f'Tape exactement {expected}')
    return u

def _wipe_interventions(db):
    # Enfants directs de l'intervention d'abord.
    db.execute(AssistantExchange.__table__.delete().where(AssistantExchange.intervention_id.is_not(None)))
    db.execute(InterventionFeedback.__table__.delete())
    db.execute(DiagnosticStep.__table__.delete())
    db.execute(Diagnostic.__table__.delete())
    db.execute(InterventionPhoto.__table__.delete())
    db.execute(InterventionMaterial.__table__.delete())
    db.execute(MaintenanceHistory.__table__.delete().where(MaintenanceHistory.intervention_id.is_not(None)))
    db.execute(PlanningEntry.__table__.delete().where(PlanningEntry.intervention_id.is_not(None)))
    db.execute(StockMovement.__table__.update().where(StockMovement.intervention_id.is_not(None)).values(intervention_id=None))
    db.execute(EquipmentHistoryEntry.__table__.update().where(EquipmentHistoryEntry.intervention_id.is_not(None)).values(intervention_id=None))
    db.execute(Intervention.__table__.delete())

def _wipe_structure(db):
    _wipe_interventions(db)
    # Devis et supervision dépendent aussi des clients/sites/équipements.
    names={'web_notifications','web_notification_rules','web_connector_credentials','web_quote_actual_lines','web_quote_approvals','web_quote_versions','web_quote_work_orders','web_quote_lines','web_quotes','web_connector_events','web_integration_connectors','web_contract_scope','web_maintenance_history','web_maintenance_plans','web_contracts','web_assistant_exchanges','web_equipment_photos','web_equipment_history','web_equipment_asset_profiles','web_equipements','web_sites','web_clients'}
    for table in reversed(Base.metadata.sorted_tables):
        if table.name in names:db.execute(table.delete())

def _wipe_management(db):
    # Les profils équipement peuvent pointer vers le stock : on détache la référence avant purge gestion.
    db.execute(EquipmentAssetProfile.__table__.update().where(EquipmentAssetProfile.stock_item_id.is_not(None)).values(stock_item_id=None))
    # Les lignes de devis peuvent référencer stock/fournisseur : on les retire avant ces tables.
    names={'web_price_sync_runs','web_price_source_credentials','web_price_source_aliases','web_price_sources','web_quote_actual_lines','web_quote_approvals','web_quote_versions','web_quote_work_orders','web_quote_lines','web_commercial_catalog','web_market_prices','web_supplier_prices','web_stock_movements','web_intervention_materials','web_contract_scope','web_maintenance_history','web_maintenance_plans','web_contracts','web_follow_actions','web_alert_states','web_planning','web_suppliers','web_stock_items'}
    for table in reversed(Base.metadata.sorted_tables):
        if table.name in names:db.execute(table.delete())

def _wipe_other_users(db,current_id):
    db.execute(AssistantExchange.__table__.update().where(AssistantExchange.user_id!=current_id).values(user_id=None))
    db.execute(Notification.__table__.delete().where(Notification.user_id!=current_id))
    db.execute(User.__table__.delete().where(User.id!=current_id))

@app.get('/sante')
def health(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);score=100;checks=[]
    try:db.execute(text('SELECT 1'));checks.append(('OK','Base de données','Connexion opérationnelle'))
    except Exception as e:score-=30;checks.append(('Critique','Base de données',str(e)))
    cc=len(core_catalog());checks.append(('OK' if cc else 'Avertissement','NOX-Core',f'{cc} fiche(s) chargée(s)'))
    if not cc:score-=7
    mem_count=db.scalar(select(func.count(AssistantMemory.id))) or 0;mem_cls,mem_status=assistant_memory_storage_status();checks.append(('OK' if mem_cls=='good' else 'Avertissement','Mémoire IA',f'{mem_count} élément(s) · {mem_status}'))
    alerts=derive_alerts(db);crit=sum(1 for x in alerts if x[0]=='critique');checks.append(('OK' if not crit else 'Avertissement','Alertes',f'{crit} critique(s), {len(alerts)} alerte(s) active(s)'));score=max(0,score-min(20,crit*5));conn_count=db.scalar(select(func.count(IntegrationConnector.id)).where(IntegrationConnector.actif.is_(True))) or 0;unread_count=db.scalar(select(func.count(Notification.id)).where(Notification.lue.is_(False))) or 0;incident_count=db.scalar(select(func.count(SupervisionIncident.id)).where(SupervisionIncident.statut!='Fermé')) or 0;checks.append(('OK','Supervision',f'{conn_count} connecteur(s) actif(s) · {incident_count} incident(s) ouvert(s) · {unread_count} notification(s) non lue(s)'));discovered_count=db.scalar(select(func.count(DiscoveredSystem.id))) or 0;unknown_count=db.scalar(select(func.count(DiscoveredSystem.id)).where(DiscoveredSystem.statut_identification=='À identifier')) or 0;checks.append(('OK' if not unknown_count else 'Information','Découverte systèmes',f'{discovered_count} système(s) repéré(s) · {unknown_count} à identifier'));fleet_count=db.scalar(select(func.count(Equipement.id)).where(Equipement.actif.is_(True))) or 0;profile_count=db.scalar(select(func.count(EquipmentAssetProfile.id))) or 0;warranty_due=db.scalar(select(func.count(EquipmentAssetProfile.id)).where(EquipmentAssetProfile.warranty_end>=date.today(),EquipmentAssetProfile.warranty_end<=date.today()+timedelta(days=60))) or 0;checks.append(('OK' if profile_count>=fleet_count else 'Information','Parc matériel',f'{fleet_count} équipement(s) actif(s) · {profile_count} profil(s) enrichi(s) · {warranty_due} garantie(s) ≤ 60 j'));price_sources_count=db.scalar(select(func.count(PriceSource.id)).where(PriceSource.actif.is_(True))) or 0;price_errors=db.scalar(select(func.count(PriceSource.id)).where(PriceSource.actif.is_(True),PriceSource.statut=='Erreur')) or 0;checks.append(('OK' if not price_errors else 'Avertissement','Prix automatisés',f'{price_sources_count} source(s) active(s) · {price_errors} en erreur'));perm_count=db.scalar(select(func.count(RolePermission.id))) or 0;checks.append(('OK' if perm_count else 'Avertissement','Permissions',f'{perm_count} règle(s) de permissions enregistrée(s)'));last_backup=db.scalar(select(BackupRun).order_by(BackupRun.created_at.desc()).limit(1));checks.append(('OK' if last_backup else 'Information','Sauvegardes',('Dernière : '+dfr(last_backup.created_at) if last_backup else 'Aucune sauvegarde logique créée depuis NOX-IA')));locked_count=db.scalar(select(func.count(LoginSecurityState.id)).where(LoginSecurityState.locked_until>datetime.utcnow())) or 0;checks.append(('OK' if not locked_count else 'Avertissement','Sécurité',f'{locked_count} verrouillage(s) de connexion actif(s)'));trs=''.join(f'<tr><td>{badge(a)}</td><td>{escape(b)}</td><td>{escape(c)}</td></tr>' for a,b,c in checks)
    admin_zone=''
    if u.role=='Administrateur':
        token=csrf_token(request)
        admin_zone=f'''<section class="card danger-zone"><h2>Zone dangereuse</h2><p class="muted">Ces actions suppriment réellement des données. NOX-Core et la mémoire interne IA permanente ne sont jamais supprimés par ces réinitialisations.</p>
        <div class="grid g2">
          <form method="post" action="/admin/vider/interventions" onsubmit="return confirm('Supprimer toutes les interventions et leurs diagnostics/photos ?')"><input type="hidden" name="csrf_token" value="{token}"><label>Vider les interventions<input name="confirmation" placeholder="Tape SUPPRIMER" required></label><button class="btn dangerbtn">Vider interventions</button></form>
          <form method="post" action="/admin/vider/structure" onsubmit="return confirm('Supprimer clients, sites, équipements et données associées ?')"><input type="hidden" name="csrf_token" value="{token}"><label>Vider clients / sites / équipements<input name="confirmation" placeholder="Tape SUPPRIMER" required></label><button class="btn dangerbtn">Vider structure</button></form>
          <form method="post" action="/admin/vider/gestion" onsubmit="return confirm('Supprimer les données de gestion ?')"><input type="hidden" name="csrf_token" value="{token}"><label>Vider gestion<input name="confirmation" placeholder="Tape SUPPRIMER" required></label><button class="btn dangerbtn">Vider gestion</button></form>
          <form method="post" action="/admin/vider/utilisateurs" onsubmit="return confirm('Supprimer tous les autres utilisateurs ?')"><input type="hidden" name="csrf_token" value="{token}"><label>Supprimer les autres utilisateurs<input name="confirmation" placeholder="Tape SUPPRIMER" required></label><button class="btn dangerbtn">Vider utilisateurs</button></form>
        </div>
        <hr style="border:0;border-top:1px solid #713342;margin:22px 0">
        <h3>Réinitialisation complète</h3><p class="muted">Supprime toutes les données métier et tous les autres utilisateurs. Ton compte administrateur connecté, NOX-Core et la mémoire interne IA sont conservés.</p>
        <form method="post" action="/admin/reinitialiser" class="form" onsubmit="return confirm('DERNIÈRE CONFIRMATION : remettre NOX-IA à zéro ?')"><input type="hidden" name="csrf_token" value="{token}"><label>Confirmation<input name="confirmation" placeholder="SUPPRIMER TOUT" required></label><label>Ton mot de passe administrateur<input type="password" name="password" required></label><button class="btn dangerbtn full">Réinitialiser toutes les données NOX-IA</button></form></section>'''
    return page(request,u,'Santé / Audit',f'<div class="head"><h1>Santé / Audit</h1><div class="metric"><span>Score</span><strong>{score}/100</strong></div></div><section class="card"><table><tr><th>Niveau</th><th>Domaine</th><th>Détail</th></tr>{trs}</table></section><section class="card"><a class="btn" href="/export-json">Export JSON</a></section>{admin_zone}')

@app.post('/admin/vider/interventions')
def admin_wipe_interventions(request:Request,confirmation:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);_require_admin_confirmation(request,db,confirmation)
    try:_wipe_interventions(db);db.commit()
    except Exception:db.rollback();raise
    return RedirectResponse('/sante?msg=Interventions+supprimées',303)

@app.post('/admin/vider/structure')
def admin_wipe_structure(request:Request,confirmation:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);_require_admin_confirmation(request,db,confirmation)
    try:_wipe_structure(db);db.commit()
    except Exception:db.rollback();raise
    return RedirectResponse('/sante?msg=Clients,+sites+et+équipements+supprimés',303)

@app.post('/admin/vider/gestion')
def admin_wipe_management(request:Request,confirmation:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);_require_admin_confirmation(request,db,confirmation)
    try:_wipe_management(db);db.commit()
    except Exception:db.rollback();raise
    return RedirectResponse('/sante?msg=Données+de+gestion+supprimées',303)

@app.post('/admin/vider/utilisateurs')
def admin_wipe_users(request:Request,confirmation:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=_require_admin_confirmation(request,db,confirmation)
    try:_wipe_other_users(db,u.id);db.commit()
    except Exception:db.rollback();raise
    return RedirectResponse('/sante?msg=Autres+utilisateurs+supprimés',303)

@app.post('/admin/reinitialiser')
def admin_reset_all(request:Request,confirmation:str=Form(...),password:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=_require_admin_confirmation(request,db,confirmation,'SUPPRIMER TOUT')
    if not verify_password(password,u.password_hash):raise HTTPException(403,'Mot de passe administrateur incorrect')
    try:
        # Supprime toutes les tables métier dans l'ordre inverse des dépendances FK.
        for table in reversed(Base.metadata.sorted_tables):
            if table.name not in {User.__table__.name,AssistantMemory.__table__.name}:db.execute(table.delete())
        db.execute(User.__table__.delete().where(User.id!=u.id))
        db.commit()
    except Exception:
        db.rollback();raise
    return RedirectResponse('/dashboard?msg=NOX-IA+a+été+réinitialisé',303)

@app.get('/export-json')
def export_json(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);require_role(u,MANAGERS);models=[EnterpriseSetting,RolePermission,LoginSecurityState,BackupRun,AssistantMemory,AssistantExchange,AuditLog,Client,Site,Equipement,EquipmentAssetProfile,EquipmentPhoto,EquipmentHistoryEntry,Intervention,InterventionFeedback,StockItem,StockMovement,InterventionMaterial,Supplier,SupplierPrice,MarketPrice,PriceSource,PriceSourceAlias,PriceSourceCredential,PriceSyncRun,PlanningEntry,MaintenancePlan,MaintenanceHistory,Contract,Quote,QuoteLine,CommercialCatalogItem,QuoteVersion,QuoteApproval,QuoteActualLine,QuoteWorkOrder,IntegrationConnector,ConnectorCredential,ConnectorEvent,SupervisionIncident,MaintenanceWindow,NotificationRule,Notification,FollowAction,AlertState,Diagnostic,DiagnosticStep,SoftwareUiTerm,SoftwareProcedure,SoftwareGuideFeedback,DiscoveredSystem,CRMLead,PurchaseOrder,PurchaseOrderLine,CustomerInvoice,BusinessEmail,ExternalBusinessConnector,BusinessSyncLog,ERPProject,ERPTask,HelpdeskTicket,TimesheetEntry,ExpenseClaim,BusinessDocument,ApprovalRequest,KnowledgeArticle,BusinessCalendarEvent,EmployeeProfile,LeaveRequest,VendorBill,ServiceSubscription,ChatterMessage,AutomationRule,BusinessActivity,DocumentAttachment,InternalSignatureRequest,CustomFieldDefinition,CustomFieldValue,AutomationExecution,CustomerPortalShare,BusinessContact,FinanceAccount,FinanceTransaction,RecruitmentPosition,RecruitmentApplicant,LeaveAllocation,MarketingCampaign,MarketingRecipient,PublicBusinessForm,PublicFormSubmission,PublishedCatalogItem,SavedBusinessView];payload={'exported_at':datetime.utcnow().isoformat(),'version':APP_VERSION,'tables':{}}
    for m in models:
        out=[]
        for r in db.scalars(select(m)).all():
            d={}
            for col in m.__table__.columns:
                v=getattr(r,col.name)
                if isinstance(v,(datetime,date)):v=v.isoformat()
                if isinstance(v,(bytes,bytearray)):continue
                d[col.name]=v
            out.append(d)
        payload['tables'][m.__tablename__]=out
    data=json.dumps(payload,ensure_ascii=False,indent=2).encode('utf-8');return Response(data,media_type='application/json',headers={'Content-Disposition':'attachment; filename="NOX-IA_export.json"'})


# ---------------------------------------------------------------------------
# NOX-IA 7.1 — Applications / projets / support / temps / documents / RH
# ---------------------------------------------------------------------------

def _chatter_add(db,model,record_id,user,message):
    msg=' '.join(str(message or '').split())
    if msg:db.add(ChatterMessage(model=model[:80],record_id=int(record_id),auteur=user.username,message=msg[:12000]))

def _chatter_html(db,model,record_id):
    rows=db.scalars(select(ChatterMessage).where(ChatterMessage.model==model,ChatterMessage.record_id==record_id).order_by(ChatterMessage.created_at.desc()).limit(80)).all()
    return ''.join(f'<div class="chatter-msg"><div class="meta">{escape(r.auteur)} · {dfr(r.created_at)}</div><div>{escape(r.message)}</div></div>' for r in rows) or '<div class="muted">Aucun message.</div>'

def _date_form(v):
    return v.isoformat() if isinstance(v,date) else ''

def _dt_local(v):
    return v.strftime('%Y-%m-%dT%H:%M') if isinstance(v,datetime) else ''

@app.get('/apps')
def apps_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db)
    groups=[
      ('Ventes & relation client',[('/crm','CRM','CR','Prospects, pipeline et prévisions'),('/devis','Devis','DV','Offres, marges et validations'),('/abonnements','Abonnements','AB','Services récurrents et prochaines factures'),('/contacts-pro','Contacts','CT','Carnet de contacts avancé')]),
      ('Achats & finance',[('/achats','Achats','AH','Commandes fournisseurs et réceptions'),('/facturation','Facturation','FA','Factures clients et paiements'),('/factures-fournisseurs','Factures fournisseurs','FF','Achats, échéances et paiements'),('/depenses','Dépenses','DE','Notes de frais et validation'),('/finance','Finance & trésorerie','FI','Pilotage interne des encaissements et décaissements')]),
      ('Travail & services',[('/projets','Projets','PJ','Projets, tâches et Kanban'),('/support','Support / SAV','HD','Tickets, SLA, résolution'),('/temps','Feuilles de temps','TS','Temps projet/intervention'),('/agenda','Agenda','AG','Rendez-vous et événements'),('/activites','Activités','AT','Relances, rappels et prochaines actions'),('/formulaires','Formulaires','FM','Formulaires publics et réponses')]),
      ('Connaissance & collaboration',[('/documents','Documents','DO','Fichiers, dossiers, tags et versions'),('/signatures','Signatures','SG','Visa interne et traçabilité'),('/connaissances','Connaissances','KN','Wiki interne validé'),('/messagerie','E-mails','EM','Brouillons et historique'),('/approbations','Approbations','AP','Décisions et demandes'),('/campagnes','Campagnes','MK','Segments et brouillons de mailing')]),
      ('Technique NOX-IA',[('/interventions','Interventions','IN','Terrain, rapports et diagnostic'),('/equipements','Parc matériel','EQ','QR, garanties et historique'),('/supervision','Supervision','SV','Alertes et connecteurs'),('/assistant','Assistant IA','IA','Cerveau métier et technique')]),
      ('Organisation',[('/rh','Employés / RH','RH','Équipes, compétences et congés'),('/recrutement','Recrutement','RC','Postes et pipeline candidats'),('/conges','Congés','CG','Allocations et demandes'),('/catalogue-en-ligne','Catalogue en ligne','EC','Publication commerciale contrôlée'),('/studio','Studio','SD','Champs personnalisés sans casser le schéma'),('/studio/vues','Vues personnalisées','VU','Filtres et colonnes réutilisables'),('/automatisations','Automatisations','AU','Règles métier exécutables et contrôlées'),('/integrations-business','Intégrations','IT','Odoo, ITESA et systèmes externes'),('/reporting','Reporting','RP','Analyses transversales et exports'),('/analyses','Analyses','AN','KPI et évolution'),('/portail-admin','Portail client','PC','Partages lecture seule sécurisés')]),
    ]
    html='<div class="head"><div><h1>Applications</h1><p class="muted">Toutes les fonctions NOX-IA dans un lanceur unique.</p></div></div>'
    for label,items in groups:
        tiles=[]
        for href,title,icon,desc in items:
            module=module_for_path(href)
            if module and not can_access_module(db,u,module):continue
            tiles.append(f'<a class="app-tile" href="{href}"><span class="app-tile-icon">{escape(icon)}</span><div><b>{escape(title)}</b><small>{escape(desc)}</small></div></a>')
        if tiles:html+=f'<div class="app-category">{escape(label)}</div><div class="app-launcher-grid">{"".join(tiles)}</div>'
    return page(request,u,'Applications',html)

@app.get('/projets')
def projects_page(request:Request,view:str='kanban',q:str='',db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(ERPProject).order_by(ERPProject.updated_at.desc())).all()
    if q.strip():
        low=q.lower();rows=[r for r in rows if low in (r.nom+' '+r.responsable+' '+r.statut+' '+r.description).lower()]
    token=csrf_token(request);clients=db.scalars(select(Client).where(Client.actif.is_(True)).order_by(Client.nom)).all();sites_=db.scalars(select(Site).where(Site.actif.is_(True)).order_by(Site.nom)).all()
    form=f'''<details><summary>+ Nouveau projet</summary><form method="post" action="/projets" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Nom<input name="nom" required></label><label>Responsable<input name="responsable" value="{escape(u.username)}"></label><label>Client<select name="client_id">{option_rows(clients,lambda x:x.id,lambda x:x.nom,empty='Aucun')}</select></label><label>Site<select name="site_id">{option_rows(sites_,lambda x:x.id,lambda x:x.nom,empty='Aucun')}</select></label><label>Statut<select name="statut"><option>Nouveau</option><option>En cours</option><option>En attente</option><option>Terminé</option></select></label><label>Priorité<select name="priorite"><option>Basse</option><option selected>Normale</option><option>Haute</option><option>Urgente</option></select></label><label>Date début<input type="date" name="date_debut"></label><label>Date fin<input type="date" name="date_fin"></label><label>Budget<input type="number" step="0.01" min="0" name="budget" value="0"></label><label>Avancement %<input type="number" min="0" max="100" name="avancement" value="0"></label><label class="full">Description<textarea name="description"></textarea></label><button class="btn primary">Créer</button></form></details>'''
    bar=f'<div class="viewbar"><a class="pill{(" active" if view=="kanban" else "")}" href="/projets?view=kanban">Kanban</a><a class="pill{(" active" if view=="list" else "")}" href="/projets?view=list">Liste</a><form method="get" class="inline-form"><input type="hidden" name="view" value="{escape(view)}"><input name="q" value="{escape(q)}" placeholder="Rechercher un projet"><button class="btn small">Rechercher</button></form></div>'
    if view=='list':
        body='<div class="scroll"><table><tr><th>Projet</th><th>Responsable</th><th>Statut</th><th>Priorité</th><th>Budget</th><th>Avancement</th></tr>'+''.join(f'<tr><td><a href="/projets/{r.id}">{escape(r.nom)}</a></td><td>{escape(r.responsable)}</td><td>{badge(r.statut)}</td><td>{badge(r.priorite)}</td><td>{money(r.budget)}</td><td>{r.avancement}%</td></tr>' for r in rows)+'</table></div>'
    else:
        stages=['Nouveau','En cours','En attente','Terminé'];cols=[]
        for st in stages:
            rs=[r for r in rows if r.statut==st]
            cards=''.join(f'<div class="kanban-card"><h3><a href="/projets/{r.id}">{escape(r.nom)}</a></h3><div class="kanban-meta"><span>{escape(r.responsable or "Non assigné")}</span>{badge(r.priorite)}</div><div class="progress-track"><span style="width:{max(0,min(100,int(r.avancement or 0)))}%"></span></div></div>' for r in rs)
            cols.append(f'<div class="kanban-col"><div class="kanban-col-head"><span>{st}</span><span>{len(rs)}</span></div>{cards}</div>')
        body='<div class="kanban">'+''.join(cols)+'</div>'
    return page(request,u,'Projets',f'<div class="head"><div><h1>Projets</h1><p class="muted">Kanban, tâches, temps, budget et discussion.</p></div></div>{form}{bar}{body}')

@app.post('/projets')
def project_add(request:Request,nom:str=Form(...),responsable:str=Form(''),client_id:str=Form(''),site_id:str=Form(''),statut:str=Form('Nouveau'),priorite:str=Form('Normale'),date_debut:str=Form(''),date_fin:str=Form(''),budget:float=Form(0),avancement:int=Form(0),description:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);row=ERPProject(nom=nom.strip(),responsable=responsable.strip(),client_id=int(client_id) if client_id else None,site_id=int(site_id) if site_id else None,statut=statut,priorite=priorite,date_debut=date.fromisoformat(date_debut) if date_debut else None,date_fin=date.fromisoformat(date_fin) if date_fin else None,budget=max(0,budget),avancement=max(0,min(100,avancement)),description=description.strip(),created_by=u.username);db.add(row);db.commit();return RedirectResponse(f'/projets/{row.id}',303)

@app.get('/projets/{pid}')
def project_detail(pid:int,request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);p=db.get(ERPProject,pid)
    if not p:raise HTTPException(404,'Projet introuvable')
    tasks=db.scalars(select(ERPTask).where(ERPTask.project_id==pid).order_by(ERPTask.updated_at.desc())).all();times=db.scalars(select(TimesheetEntry).where(TimesheetEntry.project_id==pid).order_by(TimesheetEntry.date_travail.desc()).limit(80)).all();hours=sum(float(x.heures or 0) for x in times);token=csrf_token(request)
    task_rows=''.join(f'<tr><td>{escape(t.titre)}</td><td>{escape(t.assignee)}</td><td>{badge(t.etape)}</td><td>{dfr(t.deadline)}</td><td>{float(t.heures_prevues or 0):.1f}h</td><td><form method="post" action="/projets/{pid}/taches/{t.id}/etape" class="inline-form"><input type="hidden" name="csrf_token" value="{token}"><select name="etape"><option>À faire</option><option>En cours</option><option>Bloqué</option><option>Terminé</option></select><button class="btn small">Changer</button></form></td></tr>' for t in tasks)
    body=f'''<div class="head"><div><h1>{escape(p.nom)}</h1><p class="muted">{escape(p.responsable)} · {badge(p.statut)} · {p.avancement}%</p></div><a class="btn" href="/projets">Retour</a></div><div class="g4"><div class="metric"><span>Budget</span><strong>{money(p.budget)}</strong></div><div class="metric"><span>Heures saisies</span><strong>{hours:.1f} h</strong></div><div class="metric"><span>Tâches</span><strong>{len(tasks)}</strong></div><div class="metric"><span>Avancement</span><strong>{p.avancement}%</strong></div></div><div class="split"><section class="card"><h2>Tâches</h2><form method="post" action="/projets/{pid}/taches" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Titre<input name="titre" required></label><label>Assigné à<input name="assignee" value="{escape(u.username)}"></label><label>Étape<select name="etape"><option>À faire</option><option>En cours</option><option>Bloqué</option><option>Terminé</option></select></label><label>Priorité<select name="priorite"><option>Basse</option><option selected>Normale</option><option>Haute</option><option>Urgente</option></select></label><label>Deadline<input type="date" name="deadline"></label><label>Heures prévues<input type="number" step="0.25" min="0" name="heures_prevues" value="0"></label><label class="full">Description<textarea name="description"></textarea></label><button class="btn primary">Ajouter la tâche</button></form><div class="scroll"><table><tr><th>Tâche</th><th>Assigné</th><th>Étape</th><th>Échéance</th><th>Prévu</th><th></th></tr>{task_rows or '<tr><td colspan=6>Aucune tâche.</td></tr>'}</table></div></section><aside class="card"><h2>Discussion</h2><form method="post" action="/chatter/projet/{pid}" class="form"><input type="hidden" name="csrf_token" value="{token}"><label class="full">Message<textarea name="message" required></textarea></label><button class="btn primary">Publier</button></form><div class="chatter">{_chatter_html(db,'projet',pid)}</div></aside></div>'''
    return page(request,u,p.nom,body)

@app.post('/projets/{pid}/taches')
def task_add(pid:int,request:Request,titre:str=Form(...),assignee:str=Form(''),etape:str=Form('À faire'),priorite:str=Form('Normale'),deadline:str=Form(''),heures_prevues:float=Form(0),description:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);require_login(request,db)
    if not db.get(ERPProject,pid):raise HTTPException(404,'Projet introuvable')
    db.add(ERPTask(project_id=pid,titre=titre.strip(),assignee=assignee.strip(),etape=etape,priorite=priorite,deadline=date.fromisoformat(deadline) if deadline else None,heures_prevues=max(0,heures_prevues),description=description.strip()));db.commit();return RedirectResponse(f'/projets/{pid}',303)

@app.post('/projets/{pid}/taches/{tid}/etape')
def task_stage(pid:int,tid:int,request:Request,etape:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);require_login(request,db);t=db.get(ERPTask,tid)
    if not t or t.project_id!=pid:raise HTTPException(404,'Tâche introuvable')
    t.etape=etape;t.updated_at=datetime.utcnow();db.commit();return RedirectResponse(f'/projets/{pid}',303)

@app.post('/chatter/{model}/{rid}')
def chatter_post(model:str,rid:int,request:Request,message:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);allowed={'projet':'/projets','ticket':'/support'}
    if model not in allowed:raise HTTPException(400,'Fil non autorisé')
    _chatter_add(db,model,rid,u,message);db.commit();return RedirectResponse(f'{allowed[model]}/{rid}',303)

@app.get('/support')
def helpdesk_page(request:Request,view:str='kanban',q:str='',db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(HelpdeskTicket).order_by(HelpdeskTicket.updated_at.desc())).all();low=q.strip().lower()
    if low:rows=[r for r in rows if low in (r.reference+' '+r.titre+' '+r.assignee+' '+r.description).lower()]
    clients=db.scalars(select(Client).where(Client.actif.is_(True)).order_by(Client.nom)).all();sites_=db.scalars(select(Site).where(Site.actif.is_(True)).order_by(Site.nom)).all();eqs=db.scalars(select(Equipement).where(Equipement.actif.is_(True)).order_by(Equipement.reference)).all();token=csrf_token(request)
    form=f'''<details><summary>+ Nouveau ticket</summary><form method="post" action="/support" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Titre<input name="titre" required></label><label>Priorité<select name="priorite"><option>Basse</option><option selected>Normale</option><option>Haute</option><option>Urgente</option></select></label><label>Client<select name="client_id">{option_rows(clients,lambda x:x.id,lambda x:x.nom,empty='Aucun')}</select></label><label>Site<select name="site_id">{option_rows(sites_,lambda x:x.id,lambda x:x.nom,empty='Aucun')}</select></label><label>Équipement<select name="equipement_id">{option_rows(eqs,lambda x:x.id,lambda x:f'{x.reference} · {x.marque}',empty='Aucun')}</select></label><label>Assigné à<input name="assignee" value="{escape(u.username)}"></label><label>Canal<select name="canal"><option>Interne</option><option>E-mail</option><option>Téléphone</option><option>Supervision</option><option>Client</option></select></label><label>SLA (heures)<input type="number" name="sla_hours" min="0" value="24"></label><label class="full">Description<textarea name="description" required></textarea></label><button class="btn primary">Créer le ticket</button></form></details>'''
    stages=['Nouveau','En cours','En attente','Résolu','Fermé'];cols=[]
    for st in stages:
        rs=[r for r in rows if r.statut==st];cards=''.join(f'<div class="kanban-card"><h3><a href="/support/{r.id}">{escape(r.reference)} · {escape(r.titre)}</a></h3><div class="kanban-meta">{badge(r.priorite)}<span>{escape(r.assignee or "Non assigné")}</span><span>SLA {dfr(r.sla_deadline)}</span></div></div>' for r in rs);cols.append(f'<div class="kanban-col"><div class="kanban-col-head"><span>{st}</span><span>{len(rs)}</span></div>{cards}</div>')
    return page(request,u,'Support / SAV',f'<div class="head"><div><h1>Support / SAV</h1><p class="muted">Tickets, SLA, priorité, équipement, résolution et satisfaction.</p></div></div>{form}<div class="viewbar"><form method="get" class="inline-form"><input name="q" value="{escape(q)}" placeholder="Rechercher ticket"><button class="btn small">Rechercher</button></form></div><div class="kanban">{"".join(cols)}</div>')

@app.post('/support')
def helpdesk_add(request:Request,titre:str=Form(...),priorite:str=Form('Normale'),client_id:str=Form(''),site_id:str=Form(''),equipement_id:str=Form(''),assignee:str=Form(''),canal:str=Form('Interne'),sla_hours:int=Form(24),description:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);ref=_next_business_ref(db,HelpdeskTicket,'TCK');row=HelpdeskTicket(reference=ref,titre=titre.strip(),priorite=priorite,client_id=int(client_id) if client_id else None,site_id=int(site_id) if site_id else None,equipement_id=int(equipement_id) if equipement_id else None,assignee=assignee.strip(),canal=canal,sla_deadline=datetime.utcnow()+timedelta(hours=max(0,sla_hours)) if sla_hours else None,description=description.strip(),created_by=u.username);db.add(row);db.commit();return RedirectResponse(f'/support/{row.id}',303)

@app.get('/support/{tid}')
def helpdesk_detail(tid:int,request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);t=db.get(HelpdeskTicket,tid)
    if not t:raise HTTPException(404,'Ticket introuvable')
    token=csrf_token(request);client=db.get(Client,t.client_id) if t.client_id else None;site=db.get(Site,t.site_id) if t.site_id else None;eq=db.get(Equipement,t.equipement_id) if t.equipement_id else None
    body=f'''<div class="head"><div><h1>{escape(t.reference)} · {escape(t.titre)}</h1><p class="muted">{badge(t.priorite)} {badge(t.statut)} · assigné {escape(t.assignee or '—')}</p></div><a class="btn" href="/support">Retour</a></div><div class="split"><section class="card"><div class="kv"><b>Client</b><span>{escape(client.nom if client else '—')}</span><b>Site</b><span>{escape(site.nom if site else '—')}</span><b>Équipement</b><span>{escape((eq.reference+' '+eq.marque) if eq else '—')}</span><b>Canal</b><span>{escape(t.canal)}</span><b>SLA</b><span>{dfr(t.sla_deadline)}</span></div><h3>Description</h3><div class="pre">{escape(t.description)}</div><form method="post" action="/support/{tid}/maj" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Statut<select name="statut"><option>Nouveau</option><option>En cours</option><option>En attente</option><option>Résolu</option><option>Fermé</option></select></label><label>Assigné à<input name="assignee" value="{escape(t.assignee)}"></label><label>Satisfaction /5<input type="number" min="1" max="5" name="satisfaction" value="{t.satisfaction or ''}"></label><label class="full">Résolution<textarea name="resolution">{escape(t.resolution)}</textarea></label><button class="btn primary">Mettre à jour</button></form></section><aside class="card"><h2>Discussion</h2><form method="post" action="/chatter/ticket/{tid}" class="form"><input type="hidden" name="csrf_token" value="{token}"><label class="full">Message<textarea name="message" required></textarea></label><button class="btn primary">Publier</button></form><div class="chatter">{_chatter_html(db,'ticket',tid)}</div></aside></div>'''
    return page(request,u,t.reference,body)

@app.post('/support/{tid}/maj')
def helpdesk_update(tid:int,request:Request,statut:str=Form(...),assignee:str=Form(''),resolution:str=Form(''),satisfaction:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);require_login(request,db);t=db.get(HelpdeskTicket,tid)
    if not t:raise HTTPException(404,'Ticket introuvable')
    t.statut=statut;t.assignee=assignee.strip();t.resolution=resolution.strip();t.satisfaction=int(satisfaction) if satisfaction else None;t.updated_at=datetime.utcnow();t.closed_at=datetime.utcnow() if statut in ('Résolu','Fermé') else None;db.commit();return RedirectResponse(f'/support/{tid}',303)

@app.get('/temps')
def timesheets_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(TimesheetEntry).order_by(TimesheetEntry.date_travail.desc(),TimesheetEntry.id.desc()).limit(500)).all();projects=db.scalars(select(ERPProject).order_by(ERPProject.nom)).all();tasks=db.scalars(select(ERPTask).order_by(ERPTask.titre)).all();inters=db.scalars(select(Intervention).order_by(Intervention.date_creation.desc()).limit(200)).all();total=sum(float(r.heures or 0) for r in rows);mine=sum(float(r.heures or 0) for r in rows if r.utilisateur==u.username);token=csrf_token(request)
    trs=''.join(f'<tr><td>{dfr(r.date_travail)}</td><td>{escape(r.utilisateur)}</td><td>{float(r.heures):.2f} h</td><td>{"Oui" if r.facturable else "Non"}</td><td>{escape(r.description)}</td></tr>' for r in rows)
    body=f'''<div class="head"><div><h1>Feuilles de temps</h1><p class="muted">Temps projet, tâche ou intervention.</p></div></div><div class="g2"><div class="metric"><span>Mes heures affichées</span><strong>{mine:.1f} h</strong></div><div class="metric"><span>Total affiché</span><strong>{total:.1f} h</strong></div></div><section class="card"><form method="post" action="/temps" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Date<input type="date" name="date_travail" value="{date.today().isoformat()}"></label><label>Heures<input type="number" step="0.25" min="0.25" name="heures" required></label><label>Projet<select name="project_id">{option_rows(projects,lambda x:x.id,lambda x:x.nom,empty='Aucun')}</select></label><label>Tâche<select name="task_id">{option_rows(tasks,lambda x:x.id,lambda x:x.titre,empty='Aucune')}</select></label><label>Intervention<select name="intervention_id">{option_rows(inters,lambda x:x.id,lambda x:f'#{x.id} {x.probleme[:70]}',empty='Aucune')}</select></label><label>Facturable<select name="facturable"><option value="1">Oui</option><option value="0">Non</option></select></label><label class="full">Description<input name="description" required></label><button class="btn primary">Enregistrer</button></form></section><section class="card"><div class="scroll"><table><tr><th>Date</th><th>Utilisateur</th><th>Heures</th><th>Facturable</th><th>Description</th></tr>{trs or '<tr><td colspan=5>Aucune saisie.</td></tr>'}</table></div></section>'''
    return page(request,u,'Feuilles de temps',body)

@app.post('/temps')
def timesheet_add(request:Request,date_travail:str=Form(...),heures:float=Form(...),project_id:str=Form(''),task_id:str=Form(''),intervention_id:str=Form(''),facturable:str=Form('1'),description:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);db.add(TimesheetEntry(date_travail=date.fromisoformat(date_travail),utilisateur=u.username,project_id=int(project_id) if project_id else None,task_id=int(task_id) if task_id else None,intervention_id=int(intervention_id) if intervention_id else None,heures=max(.25,heures),facturable=facturable=='1',description=description.strip()));db.commit();return RedirectResponse('/temps?msg=Temps+enregistré',303)

@app.get('/documents')
def documents_page(request:Request,q:str='',db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(BusinessDocument).where(BusinessDocument.statut=='Actif').order_by(BusinessDocument.updated_at.desc())).all();low=q.strip().lower()
    if low:rows=[r for r in rows if low in (r.nom+' '+r.dossier+' '+r.tags+' '+r.contenu).lower()]
    token=csrf_token(request);cards=''.join(f'<div class="kanban-card"><h3><a href="/documents/{r.id}">{escape(r.nom)}</a></h3><div class="kanban-meta"><span>{escape(r.dossier)}</span><span>v{r.version}</span><span>{escape(r.tags)}</span></div><p>{escape(r.contenu[:220])}</p></div>' for r in rows)
    return page(request,u,'Documents',f'''<div class="head"><div><h1>Documents</h1><p class="muted">Bibliothèque interne versionnée.</p></div></div><section class="card"><form method="post" action="/documents" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Nom<input name="nom" required></label><label>Dossier<input name="dossier" value="Général"></label><label>Tags<input name="tags"></label><label>Rattachement type<input name="related_type" placeholder="Projet, Client…"></label><label>Rattachement ID<input type="number" name="related_id"></label><label class="full">Contenu<textarea name="contenu"></textarea></label><button class="btn primary">Créer le document</button></form></section><div class="kanban">{cards or '<div class="card">Aucun document.</div>'}</div>''')

@app.post('/documents')
def document_add(request:Request,nom:str=Form(...),dossier:str=Form('Général'),tags:str=Form(''),related_type:str=Form(''),related_id:str=Form(''),contenu:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);db.add(BusinessDocument(nom=nom.strip(),dossier=dossier.strip(),tags=tags.strip(),related_type=related_type.strip(),related_id=int(related_id) if related_id else None,contenu=contenu.strip(),owner=u.username));db.commit();return RedirectResponse('/documents?msg=Document+créé',303)

@app.get('/connaissances')
def knowledge_page(request:Request,q:str='',db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(KnowledgeArticle).where(KnowledgeArticle.actif.is_(True)).order_by(KnowledgeArticle.updated_at.desc())).all();low=q.strip().lower()
    if low:rows=[r for r in rows if low in (r.titre+' '+r.categorie+' '+r.tags+' '+r.contenu).lower()]
    token=csrf_token(request);cards=''.join(f'<details class="card"><summary>{escape(r.titre)} {"✓" if r.verifie else ""}</summary><div class="muted">{escape(r.categorie)} · {escape(r.auteur)} · {escape(r.tags)}</div><div class="pre">{escape(r.contenu)}</div></details>' for r in rows)
    return page(request,u,'Connaissances',f'''<div class="head"><div><h1>Connaissances</h1><p class="muted">Wiki interne métier, complémentaire à NOX-Core.</p></div></div><section class="card"><form method="post" action="/connaissances" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Titre<input name="titre" required></label><label>Catégorie<input name="categorie" value="Interne"></label><label>Tags<input name="tags"></label><label>Vérifié<select name="verifie"><option value="0">Non</option><option value="1">Oui</option></select></label><label class="full">Article<textarea name="contenu" required></textarea></label><button class="btn primary">Publier</button></form></section>{cards or '<section class="card">Aucun article.</section>'}''')

@app.post('/connaissances')
def knowledge_add(request:Request,titre:str=Form(...),categorie:str=Form('Interne'),tags:str=Form(''),verifie:str=Form('0'),contenu:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);db.add(KnowledgeArticle(titre=titre.strip(),categorie=categorie.strip(),tags=tags.strip(),verifie=(verifie=='1' and u.role in MANAGERS),contenu=contenu.strip(),auteur=u.username));db.commit();return RedirectResponse('/connaissances?msg=Article+publié',303)

@app.get('/agenda')
def agenda_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(BusinessCalendarEvent).order_by(BusinessCalendarEvent.debut.desc()).limit(400)).all();token=csrf_token(request);trs=''.join(f'<tr><td>{dfr(r.debut)}</td><td>{escape(r.titre)}</td><td>{escape(r.utilisateur)}</td><td>{escape(r.type_event)}</td><td>{escape(r.lieu)}</td></tr>' for r in rows)
    return page(request,u,'Agenda',f'''<div class="head"><div><h1>Agenda</h1><p class="muted">Rendez-vous et événements métier.</p></div></div><section class="card"><form method="post" action="/agenda" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Titre<input name="titre" required></label><label>Début<input type="datetime-local" name="debut" required></label><label>Fin<input type="datetime-local" name="fin"></label><label>Utilisateur<input name="utilisateur" value="{escape(u.username)}"></label><label>Type<select name="type_event"><option>Rendez-vous</option><option>Réunion</option><option>Intervention</option><option>Relance</option><option>Échéance</option></select></label><label>Lieu<input name="lieu"></label><label class="full">Notes<textarea name="notes"></textarea></label><button class="btn primary">Ajouter</button></form></section><section class="card"><div class="scroll"><table><tr><th>Date</th><th>Événement</th><th>Utilisateur</th><th>Type</th><th>Lieu</th></tr>{trs or '<tr><td colspan=5>Aucun événement.</td></tr>'}</table></div></section>''')

@app.post('/agenda')
def agenda_add(request:Request,titre:str=Form(...),debut:str=Form(...),fin:str=Form(''),utilisateur:str=Form(''),type_event:str=Form('Rendez-vous'),lieu:str=Form(''),notes:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);require_login(request,db);db.add(BusinessCalendarEvent(titre=titre.strip(),debut=datetime.fromisoformat(debut),fin=datetime.fromisoformat(fin) if fin else None,utilisateur=utilisateur.strip(),type_event=type_event,lieu=lieu.strip(),notes=notes.strip()));db.commit();return RedirectResponse('/agenda?msg=Événement+ajouté',303)

@app.get('/depenses')
def expenses_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(ExpenseClaim).order_by(ExpenseClaim.created_at.desc()).limit(500)).all();projects=db.scalars(select(ERPProject).order_by(ERPProject.nom)).all();token=csrf_token(request);pending=sum(float(r.montant or 0) for r in rows if r.statut in ('Soumise','À approuver'));trs=''.join(f'<tr><td>{escape(r.reference)}</td><td>{dfr(r.date_depense)}</td><td>{escape(r.utilisateur)}</td><td>{escape(r.categorie)}</td><td>{money(r.montant)}</td><td>{badge(r.statut)}</td><td><form method="post" action="/depenses/{r.id}/statut" class="inline-form"><input type="hidden" name="csrf_token" value="{token}"><select name="statut"><option>Soumise</option><option>Approuvée</option><option>Refusée</option><option>Payée</option></select><button class="btn small">OK</button></form></td></tr>' for r in rows)
    return page(request,u,'Dépenses',f'''<div class="head"><div><h1>Dépenses</h1><p class="muted">Notes de frais et validation.</p></div><div class="metric"><span>En attente</span><strong>{money(pending)}</strong></div></div><section class="card"><form method="post" action="/depenses" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Date<input type="date" name="date_depense" value="{date.today().isoformat()}"></label><label>Catégorie<select name="categorie"><option>Déplacement</option><option>Repas</option><option>Hôtel</option><option>Matériel</option><option>Autre</option></select></label><label>Montant TTC<input type="number" step="0.01" min="0" name="montant" required></label><label>TVA<input type="number" step="0.01" min="0" name="tva" value="0"></label><label>Projet<select name="projet_id">{option_rows(projects,lambda x:x.id,lambda x:x.nom,empty='Aucun')}</select></label><label>Justificatif (nom/réf)<input name="justificatif_nom"></label><label class="full">Description<input name="description" required></label><button class="btn primary">Soumettre</button></form></section><section class="card"><div class="scroll"><table><tr><th>Réf</th><th>Date</th><th>Utilisateur</th><th>Catégorie</th><th>Montant</th><th>Statut</th><th></th></tr>{trs or '<tr><td colspan=7>Aucune dépense.</td></tr>'}</table></div></section>''')

@app.post('/depenses')
def expense_add(request:Request,date_depense:str=Form(...),categorie:str=Form('Autre'),montant:float=Form(...),tva:float=Form(0),projet_id:str=Form(''),justificatif_nom:str=Form(''),description:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);ref=_next_business_ref(db,ExpenseClaim,'EXP');db.add(ExpenseClaim(reference=ref,utilisateur=u.username,date_depense=date.fromisoformat(date_depense),categorie=categorie,description=description.strip(),montant=max(0,montant),tva=max(0,tva),statut='Soumise',projet_id=int(projet_id) if projet_id else None,justificatif_nom=justificatif_nom.strip()));db.commit();return RedirectResponse('/depenses?msg=Dépense+soumise',303)

@app.post('/depenses/{eid}/statut')
def expense_status(eid:int,request:Request,statut:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);r=db.get(ExpenseClaim,eid)
    if not r:raise HTTPException(404,'Dépense introuvable')
    r.statut=statut;db.commit();return RedirectResponse('/depenses',303)

@app.get('/approbations')
def approvals_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(ApprovalRequest).order_by(ApprovalRequest.created_at.desc()).limit(500)).all();token=csrf_token(request);trs=''.join(f'<tr><td>{escape(r.reference)}</td><td>{escape(r.type_demande)}</td><td>{escape(r.titre)}</td><td>{escape(r.demandeur)}</td><td>{money(r.montant)}</td><td>{badge(r.statut)}</td><td><form method="post" action="/approbations/{r.id}/decision" class="inline-form"><input type="hidden" name="csrf_token" value="{token}"><select name="statut"><option>Approuvée</option><option>Refusée</option></select><input name="note" placeholder="Note"><button class="btn small">Décider</button></form></td></tr>' for r in rows)
    return page(request,u,'Approbations',f'''<div class="head"><div><h1>Approbations</h1><p class="muted">Demandes internes et décisions tracées.</p></div></div><section class="card"><form method="post" action="/approbations" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Type<select name="type_demande"><option>Achat</option><option>Remise</option><option>Dépense</option><option>Congé</option><option>Autre</option></select></label><label>Titre<input name="titre" required></label><label>Approbateur<input name="approbateur"></label><label>Montant<input type="number" step="0.01" min="0" name="montant" value="0"></label><label class="full">Justification<textarea name="justification"></textarea></label><button class="btn primary">Demander</button></form></section><section class="card"><div class="scroll"><table><tr><th>Réf</th><th>Type</th><th>Demande</th><th>Demandeur</th><th>Montant</th><th>Statut</th><th>Décision</th></tr>{trs or '<tr><td colspan=7>Aucune demande.</td></tr>'}</table></div></section>''')

@app.post('/approbations')
def approval_add(request:Request,type_demande:str=Form('Autre'),titre:str=Form(...),approbateur:str=Form(''),montant:float=Form(0),justification:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);ref=_next_business_ref(db,ApprovalRequest,'APR');db.add(ApprovalRequest(reference=ref,type_demande=type_demande,titre=titre.strip(),demandeur=u.username,approbateur=approbateur.strip(),montant=max(0,montant),justification=justification.strip()));db.commit();return RedirectResponse('/approbations?msg=Demande+créée',303)

@app.post('/approbations/{aid}/decision')
def approval_decide(aid:int,request:Request,statut:str=Form(...),note:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);r=db.get(ApprovalRequest,aid)
    if not r:raise HTTPException(404,'Demande introuvable')
    r.statut=statut;r.decision_note=note.strip();r.decided_at=datetime.utcnow();r.approbateur=u.username;db.commit();return RedirectResponse('/approbations',303)

@app.get('/rh')
def hr_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);employees=db.scalars(select(EmployeeProfile).order_by(EmployeeProfile.nom)).all();leaves=db.scalars(select(LeaveRequest).order_by(LeaveRequest.created_at.desc()).limit(200)).all();users=db.scalars(select(User).where(User.active.is_(True)).order_by(User.username)).all();token=csrf_token(request);etrs=''.join(f'<tr><td>{escape(e.nom)}</td><td>{escape(e.poste)}</td><td>{escape(e.equipe)}</td><td>{escape(e.manager)}</td><td>{escape(e.competences)}</td><td>{money(e.cout_horaire)}/h</td></tr>' for e in employees);ltrs=''.join(f'<tr><td>{escape((db.get(EmployeeProfile,l.employee_id).nom if db.get(EmployeeProfile,l.employee_id) else "—"))}</td><td>{escape(l.type_conge)}</td><td>{dfr(l.date_debut)} → {dfr(l.date_fin)}</td><td>{badge(l.statut)}</td></tr>' for l in leaves)
    return page(request,u,'Employés / RH',f'''<div class="head"><div><h1>Employés / RH</h1><p class="muted">Équipes, compétences, coûts horaires et congés.</p></div></div><section class="card"><h2>Ajouter un employé</h2><form method="post" action="/rh/employes" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Utilisateur lié<select name="user_id">{option_rows(users,lambda x:x.id,lambda x:f'{x.username} · {x.role}',empty='Aucun')}</select></label><label>Nom<input name="nom" required></label><label>Poste<input name="poste"></label><label>Équipe<input name="equipe"></label><label>Manager<input name="manager"></label><label>E-mail pro<input name="email_pro"></label><label>Téléphone<input name="telephone_pro"></label><label>Date entrée<input type="date" name="date_entree"></label><label>Coût horaire<input type="number" step="0.01" min="0" name="cout_horaire" value="0"></label><label class="full">Compétences<textarea name="competences"></textarea></label><button class="btn primary">Ajouter</button></form></section><section class="card"><div class="scroll"><table><tr><th>Nom</th><th>Poste</th><th>Équipe</th><th>Manager</th><th>Compétences</th><th>Coût</th></tr>{etrs or '<tr><td colspan=6>Aucun employé.</td></tr>'}</table></div></section><section class="card"><h2>Congés</h2><form method="post" action="/rh/conges" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Employé<select name="employee_id">{option_rows(employees,lambda x:x.id,lambda x:x.nom)}</select></label><label>Type<input name="type_conge" value="Congé"></label><label>Début<input type="date" name="date_debut" required></label><label>Fin<input type="date" name="date_fin" required></label><label class="full">Motif<textarea name="motif"></textarea></label><button class="btn primary">Demander</button></form><div class="scroll"><table><tr><th>Employé</th><th>Type</th><th>Période</th><th>Statut</th></tr>{ltrs or '<tr><td colspan=4>Aucune demande.</td></tr>'}</table></div></section>''')

@app.post('/rh/employes')
def employee_add(request:Request,user_id:str=Form(''),nom:str=Form(...),poste:str=Form(''),equipe:str=Form(''),manager:str=Form(''),email_pro:str=Form(''),telephone_pro:str=Form(''),date_entree:str=Form(''),cout_horaire:float=Form(0),competences:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);db.add(EmployeeProfile(user_id=int(user_id) if user_id else None,nom=nom.strip(),poste=poste.strip(),equipe=equipe.strip(),manager=manager.strip(),email_pro=email_pro.strip(),telephone_pro=telephone_pro.strip(),date_entree=date.fromisoformat(date_entree) if date_entree else None,cout_horaire=max(0,cout_horaire),competences=competences.strip()));db.commit();return RedirectResponse('/rh?msg=Employé+ajouté',303)

@app.post('/rh/conges')
def leave_add(request:Request,employee_id:int=Form(...),type_conge:str=Form('Congé'),date_debut:str=Form(...),date_fin:str=Form(...),motif:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);require_login(request,db);db.add(LeaveRequest(employee_id=employee_id,type_conge=type_conge,date_debut=date.fromisoformat(date_debut),date_fin=date.fromisoformat(date_fin),motif=motif.strip()));db.commit();return RedirectResponse('/rh?msg=Congé+demandé',303)

@app.get('/factures-fournisseurs')
def vendor_bills_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(VendorBill).order_by(VendorBill.date_facture.desc(),VendorBill.id.desc()).limit(500)).all();sups=db.scalars(select(Supplier).where(Supplier.actif.is_(True)).order_by(Supplier.nom)).all();orders=db.scalars(select(PurchaseOrder).order_by(PurchaseOrder.created_at.desc()).limit(300)).all();token=csrf_token(request);due=sum(max(0,float(r.total_ttc or 0)-float(r.paye or 0)) for r in rows);trs=''.join(f'<tr><td>{escape(r.reference)}</td><td>{escape((db.get(Supplier,r.supplier_id).nom if r.supplier_id and db.get(Supplier,r.supplier_id) else "—"))}</td><td>{dfr(r.date_facture)}</td><td>{dfr(r.date_echeance)}</td><td>{money(r.total_ttc)}</td><td>{money(r.paye)}</td><td>{badge(r.statut)}</td></tr>' for r in rows)
    return page(request,u,'Factures fournisseurs',f'''<div class="head"><div><h1>Factures fournisseurs</h1><p class="muted">Factures d’achat, échéances et paiements.</p></div><div class="metric"><span>Reste à payer</span><strong>{money(due)}</strong></div></div><section class="card"><form method="post" action="/factures-fournisseurs" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Référence<input name="reference" required></label><label>Fournisseur<select name="supplier_id">{option_rows(sups,lambda x:x.id,lambda x:x.nom,empty='Aucun')}</select></label><label>Commande liée<select name="purchase_order_id">{option_rows(orders,lambda x:x.id,lambda x:x.reference,empty='Aucune')}</select></label><label>Date facture<input type="date" name="date_facture" value="{date.today().isoformat()}"></label><label>Échéance<input type="date" name="date_echeance"></label><label>Total HT<input type="number" step="0.01" min="0" name="total_ht" value="0"></label><label>TVA<input type="number" step="0.01" min="0" name="tva" value="0"></label><label>Payé<input type="number" step="0.01" min="0" name="paye" value="0"></label><label class="full">Notes<textarea name="notes"></textarea></label><button class="btn primary">Enregistrer</button></form></section><section class="card"><div class="scroll"><table><tr><th>Réf</th><th>Fournisseur</th><th>Date</th><th>Échéance</th><th>TTC</th><th>Payé</th><th>Statut</th></tr>{trs or '<tr><td colspan=7>Aucune facture.</td></tr>'}</table></div></section>''')

@app.post('/factures-fournisseurs')
def vendor_bill_add(request:Request,reference:str=Form(...),supplier_id:str=Form(''),purchase_order_id:str=Form(''),date_facture:str=Form(...),date_echeance:str=Form(''),total_ht:float=Form(0),tva:float=Form(0),paye:float=Form(0),notes:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);require_login(request,db);ttc=max(0,total_ht)+max(0,tva);status='Payée' if ttc>0 and paye>=ttc else ('Partiellement payée' if paye>0 else 'À payer');db.add(VendorBill(reference=reference.strip(),supplier_id=int(supplier_id) if supplier_id else None,purchase_order_id=int(purchase_order_id) if purchase_order_id else None,date_facture=date.fromisoformat(date_facture),date_echeance=date.fromisoformat(date_echeance) if date_echeance else None,total_ht=max(0,total_ht),tva=max(0,tva),total_ttc=ttc,paye=max(0,paye),statut=status,notes=notes.strip()));db.commit();return RedirectResponse('/factures-fournisseurs?msg=Facture+fournisseur+enregistrée',303)

@app.get('/abonnements')
def subscriptions_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(ServiceSubscription).order_by(ServiceSubscription.prochaine_facture.asc().nullslast())).all();clients=db.scalars(select(Client).where(Client.actif.is_(True)).order_by(Client.nom)).all();sites_=db.scalars(select(Site).where(Site.actif.is_(True)).order_by(Site.nom)).all();contracts=db.scalars(select(Contract).order_by(Contract.id.desc())).all();token=csrf_token(request);monthly=sum(float(r.montant or 0) for r in rows if r.statut=='Actif' and r.periodicite=='Mensuelle');trs=''.join(f'<tr><td>{escape(r.reference)}</td><td>{escape(r.nom)}</td><td>{escape((db.get(Client,r.client_id).nom if r.client_id and db.get(Client,r.client_id) else "—"))}</td><td>{escape(r.periodicite)}</td><td>{money(r.montant)}</td><td>{dfr(r.prochaine_facture)}</td><td>{badge(r.statut)}</td></tr>' for r in rows)
    return page(request,u,'Abonnements',f'''<div class="head"><div><h1>Abonnements</h1><p class="muted">Revenus/services récurrents et prochaine facturation.</p></div><div class="metric"><span>Mensuel actif</span><strong>{money(monthly)}</strong></div></div><section class="card"><form method="post" action="/abonnements" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Nom<input name="nom" required></label><label>Client<select name="client_id">{option_rows(clients,lambda x:x.id,lambda x:x.nom,empty='Aucun')}</select></label><label>Site<select name="site_id">{option_rows(sites_,lambda x:x.id,lambda x:x.nom,empty='Aucun')}</select></label><label>Contrat<select name="contrat_id">{option_rows(contracts,lambda x:x.id,lambda x:f'#{x.id} {x.type_contrat}',empty='Aucun')}</select></label><label>Périodicité<select name="periodicite"><option>Mensuelle</option><option>Trimestrielle</option><option>Annuelle</option></select></label><label>Montant<input type="number" step="0.01" min="0" name="montant" required></label><label>Prochaine facture<input type="date" name="prochaine_facture"></label><label class="full">Notes<textarea name="notes"></textarea></label><button class="btn primary">Créer</button></form></section><section class="card"><div class="scroll"><table><tr><th>Réf</th><th>Service</th><th>Client</th><th>Périodicité</th><th>Montant</th><th>Prochaine</th><th>Statut</th></tr>{trs or '<tr><td colspan=7>Aucun abonnement.</td></tr>'}</table></div></section>''')

@app.post('/abonnements')
def subscription_add(request:Request,nom:str=Form(...),client_id:str=Form(''),site_id:str=Form(''),contrat_id:str=Form(''),periodicite:str=Form('Mensuelle'),montant:float=Form(...),prochaine_facture:str=Form(''),notes:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);require_login(request,db);ref=_next_business_ref(db,ServiceSubscription,'SUB');db.add(ServiceSubscription(reference=ref,nom=nom.strip(),client_id=int(client_id) if client_id else None,site_id=int(site_id) if site_id else None,contrat_id=int(contrat_id) if contrat_id else None,periodicite=periodicite,montant=max(0,montant),prochaine_facture=date.fromisoformat(prochaine_facture) if prochaine_facture else None,notes=notes.strip()));db.commit();return RedirectResponse('/abonnements?msg=Abonnement+créé',303)

@app.get('/automatisations')
def automations_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(AutomationRule).order_by(AutomationRule.created_at.desc())).all();logs=db.scalars(select(AutomationExecution).order_by(AutomationExecution.created_at.desc()).limit(40)).all();token=csrf_token(request)
    trs=''.join(f'<tr><td>{escape(r.nom)}</td><td>{escape(r.modele)}</td><td>{escape(r.declencheur)}</td><td>{escape(r.condition_text)}</td><td>{escape(r.action_type)}</td><td>{badge("Actif" if r.actif else "Inactif")}</td></tr>' for r in rows)
    ltrs=''.join(f'<tr><td>{dfr(x.created_at)}</td><td>#{x.rule_id}</td><td>{escape(x.record_model)}</td><td>{x.record_id or "—"}</td><td>{badge(x.status)}</td><td>{escape(x.detail[:240])}</td></tr>' for x in logs)
    body=f'''<div class="head"><div><h1>Automatisations</h1><p class="muted">Moteur de règles contrôlé : détecte des situations métier et exécute uniquement des actions sûres NOX-IA.</p></div><form method="post" action="/automatisations/executer"><input type="hidden" name="csrf_token" value="{token}"><button class="btn primary">▶ Exécuter maintenant</button></form></div><section class="card"><h2>Nouvelle règle</h2><form method="post" action="/automatisations" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Nom<input name="nom" required></label><label>Modèle<select name="modele"><option>Stock</option><option>Support</option><option>Facture</option><option>Devis</option><option>Projet</option><option>Intervention</option></select></label><label>Déclencheur<select name="declencheur"><option>Évaluation</option><option>Création</option><option>Modification</option></select></label><label>Action<select name="action_type"><option>Notification</option><option>Activité</option><option>Approbation</option></select></label><label class="full">Condition<input name="condition_text" placeholder="Ex: stock bas ; ticket urgent ; facture en retard ; projet en retard"></label><label class="full">Configuration action<input name="action_config" placeholder="role=Responsable; assignee=admin; message=À vérifier"></label><button class="btn primary">Créer la règle</button></form><p class="hint">Le moteur ne supprime rien, ne modifie pas d’équipement et n’envoie aucune commande externe. Actions autorisées : notification, activité, approbation.</p></section><section class="card"><h2>Règles</h2><div class="scroll"><table><tr><th>Nom</th><th>Modèle</th><th>Déclencheur</th><th>Condition</th><th>Action</th><th>État</th></tr>{trs or '<tr><td colspan=6>Aucune règle.</td></tr>'}</table></div></section><section class="card"><h2>Dernières exécutions</h2><div class="scroll"><table><tr><th>Date</th><th>Règle</th><th>Objet</th><th>ID</th><th>Résultat</th><th>Détail</th></tr>{ltrs or '<tr><td colspan=6>Aucune exécution.</td></tr>'}</table></div></section>'''
    return page(request,u,'Automatisations',body)

@app.post('/automatisations')
def automation_add(request:Request,nom:str=Form(...),modele:str=Form('Intervention'),declencheur:str=Form('Création'),action_type:str=Form('Notification'),condition_text:str=Form(''),action_config:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);db.add(AutomationRule(nom=nom.strip(),modele=modele,declencheur=declencheur,condition_text=condition_text.strip(),action_type=action_type,action_config=action_config.strip(),created_by=u.username));db.commit();return RedirectResponse('/automatisations?msg=Règle+créée',303)


# ---------------------------------------------------------------------------
# NOX-IA 6.9 — ERP / Odoo / ITESA
# ---------------------------------------------------------------------------

def _next_business_ref(db, model, prefix):
    year=date.today().year
    count=db.scalar(select(func.count(model.id))) or 0
    return f'{prefix}-{year}-{int(count)+1:04d}'

def _purchase_recalc(db, po):
    lines=db.scalars(select(PurchaseOrderLine).where(PurchaseOrderLine.purchase_order_id==po.id)).all()
    subtotal=sum(float(x.total_ht or 0) for x in lines)
    taxes=sum(float(x.total_ht or 0)*float(x.tva_pct or 0)/100 for x in lines)
    po.sous_total=subtotal;po.taxes=taxes;po.total=subtotal+taxes
    return lines

def _invoice_state(inv):
    if float(inv.paye or 0)>=float(inv.total or 0)>0:return 'Payée'
    if float(inv.paye or 0)>0:return 'Partiellement payée'
    if inv.date_echeance and inv.date_echeance<date.today() and inv.statut not in ('Annulée','Payée'):return 'En retard'
    return inv.statut

def _get_business_connector(db,provider):
    return db.scalar(select(ExternalBusinessConnector).where(ExternalBusinessConnector.provider==provider).order_by(ExternalBusinessConnector.id.desc()))

def _business_log(db,connector,provider,action,status,detail='',rows=0):
    db.add(BusinessSyncLog(connector_id=(connector.id if connector else None),provider=provider,action=action,statut=status,detail=str(detail)[:8000],rows_count=int(rows or 0)))
    db.commit()

def _connector_secret(conn):
    env=(conn.secret_env_var or '').strip()
    if not env:return ''
    return os.environ.get(env,'')

def _odoo_json2_call(conn,model,method,payload):
    base=_safe_remote_url(conn.base_url).rstrip('/')
    secret=_connector_secret(conn)
    if not secret:raise ValueError(f'Variable Render {conn.secret_env_var or "NOXIA_ODOO_API_KEY"} absente')
    url=f'{base}/json/2/{model}/{method}'
    headers={'Authorization':'bearer '+secret,'Content-Type':'application/json; charset=utf-8','Accept':'application/json','User-Agent':'NOX-IA/6.9'}
    if (conn.database_name or '').strip():headers['X-Odoo-Database']=conn.database_name.strip()
    req=UrlRequest(url,data=json.dumps(payload,ensure_ascii=False).encode('utf-8'),headers=headers,method='POST')
    opener=build_opener(_PriceSafeRedirect())
    with opener.open(req,timeout=20) as r:
        raw=r.read(4*1024*1024+1)
    if len(raw)>4*1024*1024:raise ValueError('Réponse Odoo trop volumineuse')
    return json.loads(raw.decode('utf-8'))

def _odoo_xmlrpc_auth(conn):
    base=_safe_remote_url(conn.base_url).rstrip('/')
    secret=_connector_secret(conn)
    if not secret:raise ValueError(f'Variable Render {conn.secret_env_var or "NOXIA_ODOO_API_KEY"} absente')
    if not conn.database_name or not conn.username:raise ValueError('Base Odoo et utilisateur requis pour XML-RPC')
    common=ServerProxy(base+'/xmlrpc/2/common',allow_none=True)
    uid=common.authenticate(conn.database_name,conn.username,secret,{})
    if not uid:raise ValueError('Authentification Odoo refusée')
    return base,secret,uid

def _odoo_search_read(conn,model,domain,fields,limit=500):
    if (conn.api_mode or '').upper().startswith('XML'):
        base,secret,uid=_odoo_xmlrpc_auth(conn)
        obj=ServerProxy(base+'/xmlrpc/2/object',allow_none=True)
        return obj.execute_kw(conn.database_name,uid,secret,model,'search_read',[domain],{'fields':fields,'limit':int(limit)})
    return _odoo_json2_call(conn,model,'search_read',{'domain':domain,'fields':fields,'limit':int(limit)})

def _odoo_test(conn):
    rows=_odoo_search_read(conn,'res.users',[],['id','name','login'],1)
    return rows[0] if rows else {'name':'Connexion valide'}

def _html_text(raw):
    text=re.sub(r'(?is)<script.*?</script>|<style.*?</style>',' ',raw)
    text=re.sub(r'(?s)<[^>]+>','\n',text)
    text=unescape(text).replace('\xa0',' ')
    return '\n'.join(x.strip() for x in text.splitlines() if x.strip())

def _itesa_fetch_product(url):
    parsed=urlparse(str(url or '').strip())
    if parsed.scheme!='https' or (parsed.hostname or '').lower() not in {'boutique.itesa.eu','www.boutique.itesa.eu'}:
        raise ValueError('Utilise une URL produit officielle https://boutique.itesa.eu/...')
    if '/produit/' not in parsed.path:raise ValueError('URL produit ITESA attendue')
    req=UrlRequest(parsed.geturl(),headers={'User-Agent':'NOX-IA/6.9','Accept':'text/html'})
    with build_opener(_PriceSafeRedirect()).open(req,timeout=20) as r:raw=r.read(2*1024*1024+1)
    if len(raw)>2*1024*1024:raise ValueError('Page ITESA trop volumineuse')
    html=raw.decode('utf-8',errors='replace')
    h1=re.search(r'(?is)<h1[^>]*>(.*?)</h1>',html)
    designation=_html_text(h1.group(1)).strip() if h1 else ''
    text=_html_text(html)
    ref='';ref_fab=''
    m=re.search(r'(?im)^Référence\s*:\s*(.+)$',text)
    if m:ref=m.group(1).strip()[:120]
    m=re.search(r'(?im)^Réf\.?\s*fab\.?\s*:\s*(.+)$',text)
    if m:ref_fab=m.group(1).strip()[:120]
    if not ref:
        m=re.search(r'(?im)^Réf\.?\s*Itesa\s*:\s*(.+)$',text)
        if m:ref=m.group(1).strip()[:120]
    if not designation:raise ValueError('Désignation introuvable sur la page ITESA')
    if not ref:raise ValueError('Référence ITESA introuvable sur la page')
    return {'reference':ref,'reference_fabricant':ref_fab,'designation':designation,'url':parsed.geturl()}

@app.get('/erp')
def erp_home(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db)
    leads=db.scalar(select(func.count(CRMLead.id)).where(CRMLead.etape.notin_(['Gagné','Perdu']))) or 0
    purchases=db.scalar(select(func.count(PurchaseOrder.id)).where(PurchaseOrder.statut.notin_(['Reçue','Annulée']))) or 0
    invoices=db.scalars(select(CustomerInvoice)).all();unpaid=sum(max(0,float(x.total or 0)-float(x.paye or 0)) for x in invoices if _invoice_state(x)!='Annulée')
    mails=db.scalar(select(func.count(BusinessEmail.id)).where(BusinessEmail.statut!='Envoyé')) or 0
    odoo=_get_business_connector(db,'ODOO');itesa=_get_business_connector(db,'ITESA')
    body=f'''<div class="head"><div><h1>Centre ERP NOX-IA</h1><p class="muted">CRM, achats, facturation, e-mails et connexions métier réunis avec les interventions, le stock et l’IA.</p></div><a class="btn" href="/integrations-business">Intégrations</a></div>
    <div class="grid"><section class="metric"><span>Opportunités ouvertes</span><strong>{leads}</strong></section><section class="metric"><span>Achats en cours</span><strong>{purchases}</strong></section><section class="metric"><span>À encaisser</span><strong>{money(unpaid)}</strong></section><section class="metric"><span>E-mails à traiter</span><strong>{mails}</strong></section></div>
    <section class="card"><h2>Flux entreprise</h2><div class="actions"><a class="btn primary" href="/crm">CRM</a><a class="btn" href="/devis">Ventes / Devis</a><a class="btn" href="/achats">Achats</a><a class="btn" href="/stock">Stock</a><a class="btn" href="/facturation">Facturation</a><a class="btn" href="/messagerie">E-mails</a></div></section>
    <section class="card"><h2>Connecteurs</h2><p>Odoo : {badge(odoo.last_status if odoo else 'À configurer')} &nbsp; ITESA : {badge(itesa.last_status if itesa else 'À configurer')}</p><p class="muted">NOX-IA reste le cockpit technique et IA. Odoo peut rester le back-office comptable/ERP pendant la migration, avec synchronisation pour éviter la double saisie.</p></section>'''
    return page(request,u,'Centre ERP',body)

@app.get('/crm')
def crm_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(CRMLead).order_by(CRMLead.updated_at.desc())).all();clients=db.scalars(select(Client).where(Client.actif.is_(True)).order_by(Client.nom)).all();trs=''
    for x in rows:
        c=db.get(Client,x.client_id) if x.client_id else None
        trs+=f'<tr><td><b>{escape(x.nom)}</b><div class="muted">{escape(x.contact_nom)}</div></td><td>{escape(c.nom if c else "—")}</td><td>{badge(x.etape)}</td><td>{x.probabilite}%</td><td>{money(x.revenu_attendu)}</td><td>{escape(x.commercial or "—")}</td><td>{dfr(x.prochaine_action)}</td><td><form method="post" action="/crm/{x.id}/etape" class="inline-form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><select name="etape"><option>Nouveau</option><option>Qualifié</option><option>Proposition</option><option>Négociation</option><option>Gagné</option><option>Perdu</option></select><button class="btn small">Changer</button></form></td></tr>'
    form=f'''<section class="card"><h2>Nouvelle opportunité</h2><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Opportunité<input name="nom" required></label><label>Client<select name="client_id"><option value="">— Prospect —</option>{option_rows(clients,lambda x:x.id,lambda x:x.nom)}</select></label><label>Contact<input name="contact_nom"></label><label>E-mail<input type="email" name="email"></label><label>Téléphone<input name="telephone"></label><label>Source<input name="source" value="Manuel"></label><label>Revenu attendu<input type="number" min="0" step="0.01" name="revenu_attendu" value="0"></label><label>Probabilité %<input type="number" min="0" max="100" name="probabilite" value="10"></label><label>Commercial<input name="commercial" value="{escape(u.username)}"></label><label>Prochaine action<input type="date" name="prochaine_action"></label><label class="full">Notes<textarea name="notes"></textarea></label><button class="btn primary">Créer l’opportunité</button></form></section>'''
    return page(request,u,'CRM',f'<div class="head"><div><h1>CRM</h1><p class="muted">Pipeline commercial relié aux clients, devis et futures affaires.</p></div><a class="btn" href="/devis">Devis</a></div>{form}<section class="card"><div class="scroll"><table><tr><th>Opportunité</th><th>Client</th><th>Étape</th><th>Prob.</th><th>Revenu</th><th>Commercial</th><th>Action</th><th>Pipeline</th></tr>{trs or "<tr><td colspan=8>Aucune opportunité.</td></tr>"}</table></div></section>')

@app.post('/crm')
def crm_add(request:Request,nom:str=Form(...),client_id:str=Form(''),contact_nom:str=Form(''),email:str=Form(''),telephone:str=Form(''),source:str=Form('Manuel'),revenu_attendu:float=Form(0),probabilite:int=Form(10),commercial:str=Form(''),prochaine_action:str=Form(''),notes:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db)
    row=CRMLead(nom=nom.strip(),client_id=int(client_id) if client_id.strip() else None,contact_nom=contact_nom.strip(),email=email.strip(),telephone=telephone.strip(),source=source.strip(),revenu_attendu=max(0,revenu_attendu),probabilite=max(0,min(100,probabilite)),commercial=(commercial.strip() or u.username),prochaine_action=date.fromisoformat(prochaine_action) if prochaine_action else None,notes=notes.strip(),updated_at=datetime.utcnow())
    db.add(row);db.commit();return RedirectResponse('/crm?msg=Opportunité+créée',303)

@app.post('/crm/{lid}/etape')
def crm_stage(lid:int,request:Request,etape:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);require_login(request,db);row=db.get(CRMLead,lid)
    if not row:raise HTTPException(404)
    if etape not in ('Nouveau','Qualifié','Proposition','Négociation','Gagné','Perdu'):raise HTTPException(400)
    row.etape=etape;row.updated_at=datetime.utcnow();db.commit();return RedirectResponse('/crm',303)

@app.get('/achats')
def purchases_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(PurchaseOrder).order_by(PurchaseOrder.created_at.desc())).all();sups=db.scalars(select(Supplier).where(Supplier.actif.is_(True)).order_by(Supplier.nom)).all();trs=''
    for po in rows:
        sup=db.get(Supplier,po.supplier_id);_purchase_recalc(db,po);trs+=f'<tr><td><a href="/achats/{po.id}">{escape(po.reference)}</a></td><td>{escape(sup.nom if sup else "—")}</td><td>{dfr(po.date_commande)}</td><td>{dfr(po.date_prevue)}</td><td>{badge(po.statut)}</td><td>{money(po.total)}</td></tr>'
    db.commit()
    form=f'''<section class="card"><h2>Nouvel achat / demande de prix</h2><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Fournisseur<select name="supplier_id" required>{option_rows(sups,lambda x:x.id,lambda x:x.nom)}</select></label><label>Date prévue<input type="date" name="date_prevue"></label><label class="full">Notes<textarea name="notes"></textarea></label><button class="btn primary">Créer le brouillon</button></form></section>'''
    return page(request,u,'Achats',f'<div class="head"><div><h1>Achats</h1><p class="muted">Demandes de prix, commandes fournisseurs, réception et mise à jour du stock.</p></div><a class="btn" href="/fournisseurs">Fournisseurs</a></div>{form}<section class="card"><div class="scroll"><table><tr><th>Référence</th><th>Fournisseur</th><th>Date</th><th>Prévue</th><th>Statut</th><th>Total TTC</th></tr>{trs or "<tr><td colspan=6>Aucun achat.</td></tr>"}</table></div></section>')

@app.post('/achats')
def purchase_add(request:Request,supplier_id:int=Form(...),date_prevue:str=Form(''),notes:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);ref=_next_business_ref(db,PurchaseOrder,'ACH');po=PurchaseOrder(reference=ref,supplier_id=supplier_id,date_prevue=date.fromisoformat(date_prevue) if date_prevue else None,created_by=u.username,notes=notes.strip());db.add(po);db.commit();db.refresh(po);return RedirectResponse(f'/achats/{po.id}',303)

@app.get('/achats/{pid}')
def purchase_detail(pid:int,request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);po=db.get(PurchaseOrder,pid)
    if not po:raise HTTPException(404)
    lines=_purchase_recalc(db,po);db.commit();sup=db.get(Supplier,po.supplier_id);items=db.scalars(select(StockItem).where(StockItem.actif.is_(True)).order_by(StockItem.designation)).all();trs=''.join(f'<tr><td>{escape(x.reference_fournisseur)}</td><td>{escape(x.designation)}</td><td>{x.quantite:g}</td><td>{money(x.prix_unitaire)}</td><td>{x.tva_pct:g}%</td><td>{money(x.total_ht)}</td></tr>' for x in lines)
    buttons=''
    if po.statut=='Brouillon':buttons+=f'<form method="post" action="/achats/{po.id}/confirmer"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn primary">Confirmer commande</button></form>'
    if po.statut=='Commandée':buttons+=f'<form method="post" action="/achats/{po.id}/recevoir"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn goodbtn">Réceptionner & entrer en stock</button></form>'
    add=f'''<section class="card"><h2>Ajouter une ligne</h2><form method="post" action="/achats/{po.id}/ligne" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Article stock<select name="stock_item_id"><option value="">— Hors stock —</option>{option_rows(items,lambda x:x.id,lambda x:f"{x.reference} · {x.designation}")}</select></label><label>Réf fournisseur<input name="reference_fournisseur"></label><label>Désignation<input name="designation" required></label><label>Quantité<input type="number" min="0.01" step="0.01" name="quantite" value="1"></label><label>Prix unitaire HT<input type="number" min="0" step="0.01" name="prix_unitaire" value="0"></label><label>TVA %<input type="number" min="0" step="0.1" name="tva_pct" value="20"></label><button class="btn primary">Ajouter</button></form></section>'''
    return page(request,u,f'Achat {po.reference}',f'<div class="head"><div><h1>{escape(po.reference)}</h1><p class="muted">{escape(sup.nom if sup else "—")} · {badge(po.statut)}</p></div><div class="actions">{buttons}</div></div>{add}<section class="card"><div class="scroll"><table><tr><th>Réf fournisseur</th><th>Désignation</th><th>Qté</th><th>PU HT</th><th>TVA</th><th>Total HT</th></tr>{trs or "<tr><td colspan=6>Aucune ligne.</td></tr>"}</table></div><p><b>Sous-total :</b> {money(po.sous_total)} · <b>Taxes :</b> {money(po.taxes)} · <b>Total TTC :</b> {money(po.total)}</p></section>')

@app.post('/achats/{pid}/ligne')
def purchase_line_add(pid:int,request:Request,stock_item_id:str=Form(''),reference_fournisseur:str=Form(''),designation:str=Form(...),quantite:float=Form(1),prix_unitaire:float=Form(0),tva_pct:float=Form(20),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);require_login(request,db);po=db.get(PurchaseOrder,pid)
    if not po or po.statut!='Brouillon':raise HTTPException(400,'Achat introuvable ou non modifiable')
    qty=max(.01,float(quantite));pu=max(0,float(prix_unitaire));line=PurchaseOrderLine(purchase_order_id=pid,stock_item_id=int(stock_item_id) if stock_item_id.strip() else None,reference_fournisseur=reference_fournisseur.strip(),designation=designation.strip(),quantite=qty,prix_unitaire=pu,tva_pct=max(0,float(tva_pct)),total_ht=qty*pu);db.add(line);db.flush();_purchase_recalc(db,po);db.commit();return RedirectResponse(f'/achats/{pid}',303)

@app.post('/achats/{pid}/confirmer')
def purchase_confirm(pid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);require_login(request,db);po=db.get(PurchaseOrder,pid)
    if not po:raise HTTPException(404)
    if not db.scalar(select(func.count(PurchaseOrderLine.id)).where(PurchaseOrderLine.purchase_order_id==pid)):raise HTTPException(400,'Ajoute au moins une ligne')
    po.statut='Commandée';db.commit();return RedirectResponse(f'/achats/{pid}?msg=Commande+confirmée',303)

@app.post('/achats/{pid}/recevoir')
def purchase_receive(pid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);po=db.get(PurchaseOrder,pid)
    if not po or po.statut!='Commandée':raise HTTPException(400,'Commande non réceptionnable')
    lines=db.scalars(select(PurchaseOrderLine).where(PurchaseOrderLine.purchase_order_id==pid)).all()
    for line in lines:
        if not line.stock_item_id:continue
        item=db.get(StockItem,line.stock_item_id)
        if not item:continue
        qty=max(0,int(round(float(line.quantite or 0))))
        item.quantite=int(item.quantite or 0)+qty
        if float(line.prix_unitaire or 0)>0:item.prix_achat=float(line.prix_unitaire)
        db.add(StockMovement(stock_item_id=item.id,intervention_id=None,utilisateur=u.username,type_mouvement='Réception achat',quantite=qty,commentaire=po.reference))
        db.add(SupplierPrice(supplier_id=po.supplier_id,stock_item_id=item.id,prix=float(line.prix_unitaire or 0)))
    po.statut='Reçue';db.commit();return RedirectResponse(f'/achats/{pid}?msg=Réception+enregistrée+dans+le+stock',303)

@app.get('/facturation')
def invoices_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(CustomerInvoice).order_by(CustomerInvoice.created_at.desc())).all();clients=db.scalars(select(Client).where(Client.actif.is_(True)).order_by(Client.nom)).all();quotes=db.scalars(select(Quote).where(Quote.statut.in_(['Accepté','Validé','Gagné'])).order_by(Quote.date_creation.desc())).all();trs=''
    for inv in rows:
        c=db.get(Client,inv.client_id);state=_invoice_state(inv);remaining=max(0,float(inv.total or 0)-float(inv.paye or 0));trs+=f'<tr><td>{escape(inv.reference)}</td><td>{escape(c.nom if c else "—")}</td><td>{dfr(inv.date_emission)}</td><td>{dfr(inv.date_echeance)}</td><td>{badge(state)}</td><td>{money(inv.total)}</td><td>{money(inv.paye)}</td><td>{money(remaining)}</td><td><form method="post" action="/facturation/{inv.id}/paiement" class="inline-form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><input type="number" min="0" step="0.01" name="montant" placeholder="Paiement"><button class="btn small">Encaisser</button></form></td></tr>'
    form=f'''<section class="card"><h2>Nouvelle facture opérationnelle</h2><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Client<select name="client_id" required>{option_rows(clients,lambda x:x.id,lambda x:x.nom)}</select></label><label>Devis accepté<select name="quote_id"><option value="">— Aucun —</option>{option_rows(quotes,lambda x:x.id,lambda x:f"{x.reference} · {x.objet}")}</select></label><label>Total HT manuel<input type="number" min="0" step="0.01" name="sous_total" value="0"></label><label>TVA %<input type="number" min="0" step="0.1" name="tva_pct" value="20"></label><label>Échéance<input type="date" name="date_echeance"></label><label class="full">Notes<textarea name="notes"></textarea></label><button class="btn primary">Créer facture</button></form></section>'''
    return page(request,u,'Facturation',f'<div class="head"><div><h1>Facturation</h1><p class="muted">Suivi commercial des factures et encaissements. La comptabilité légale complète peut rester synchronisée avec Odoo.</p></div><a class="btn" href="/integrations/odoo">Odoo</a></div>{form}<section class="card"><div class="scroll"><table><tr><th>Facture</th><th>Client</th><th>Émission</th><th>Échéance</th><th>Statut</th><th>Total</th><th>Payé</th><th>Reste</th><th>Paiement</th></tr>{trs or "<tr><td colspan=9>Aucune facture.</td></tr>"}</table></div></section>')

@app.post('/facturation')
def invoice_add(request:Request,client_id:int=Form(...),quote_id:str=Form(''),sous_total:float=Form(0),tva_pct:float=Form(20),date_echeance:str=Form(''),notes:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);qid=int(quote_id) if quote_id.strip() else None;subtotal=max(0,float(sous_total))
    if qid:
        q=db.get(Quote,qid)
        if not q:raise HTTPException(404,'Devis introuvable')
        client_id=q.client_id;_,_,sale,_,_=quote_totals(db,q);subtotal=sale
    tax=subtotal*max(0,float(tva_pct))/100;ref=_next_business_ref(db,CustomerInvoice,'FAC');inv=CustomerInvoice(reference=ref,client_id=client_id,quote_id=qid,date_echeance=date.fromisoformat(date_echeance) if date_echeance else date.today()+timedelta(days=30),sous_total=subtotal,taxes=tax,total=subtotal+tax,paye=0,created_by=u.username,notes=notes.strip(),statut='Émise');db.add(inv);db.commit();return RedirectResponse('/facturation?msg=Facture+créée',303)

@app.post('/facturation/{iid}/paiement')
def invoice_payment(iid:int,request:Request,montant:float=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);require_login(request,db);inv=db.get(CustomerInvoice,iid)
    if not inv:raise HTTPException(404)
    inv.paye=min(float(inv.total or 0),float(inv.paye or 0)+max(0,float(montant)))
    inv.statut='Payée' if inv.paye>=float(inv.total or 0) else ('Partiellement payée' if inv.paye>0 else inv.statut);db.commit();return RedirectResponse('/facturation',303)

def _smtp_send(recipient,subject,body):
    host=os.environ.get('NOXIA_SMTP_HOST','').strip();port=int(os.environ.get('NOXIA_SMTP_PORT','587') or 587);user=os.environ.get('NOXIA_SMTP_USER','').strip();password=os.environ.get('NOXIA_SMTP_PASSWORD','');sender=os.environ.get('NOXIA_SMTP_FROM',user).strip();tls=os.environ.get('NOXIA_SMTP_TLS','1').strip().lower() not in ('0','false','non')
    if not host or not sender:raise ValueError('SMTP non configuré dans Render (NOXIA_SMTP_HOST / NOXIA_SMTP_FROM)')
    msg=EmailMessage();msg['From']=sender;msg['To']=recipient;msg['Subject']=subject;msg.set_content(body)
    with smtplib.SMTP(host,port,timeout=20) as smtp:
        if tls:smtp.starttls()
        if user:smtp.login(user,password)
        smtp.send_message(msg)

@app.get('/messagerie')
def mail_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(BusinessEmail).order_by(BusinessEmail.created_at.desc()).limit(300)).all();trs=''.join(f'<tr><td>{dfr(x.created_at)}</td><td>{escape(x.destinataire)}</td><td>{escape(x.sujet)}</td><td>{badge(x.statut)}</td><td>{dfr(x.sent_at)}</td><td>{escape(x.erreur[:120]) if x.erreur else "—"}</td></tr>' for x in rows);smtp_ready=bool(os.environ.get('NOXIA_SMTP_HOST') and os.environ.get('NOXIA_SMTP_FROM',os.environ.get('NOXIA_SMTP_USER','')))
    form=f'''<section class="card"><h2>Nouvel e-mail</h2><p class="muted">SMTP : {"configuré" if smtp_ready else "non configuré — le message sera conservé en brouillon"}</p><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Destinataire<input type="email" name="destinataire" required></label><label>Sujet<input name="sujet" required></label><label class="full">Message<textarea name="corps" required></textarea></label><label>Action<select name="action"><option value="brouillon">Enregistrer brouillon</option><option value="envoyer">Envoyer maintenant</option></select></label><button class="btn primary">Valider</button></form></section>'''
    return page(request,u,'E-mails',f'<div class="head"><div><h1>E-mails</h1><p class="muted">Historique centralisé des communications métier liées à NOX-IA.</p></div></div>{form}<section class="card"><div class="scroll"><table><tr><th>Date</th><th>À</th><th>Sujet</th><th>Statut</th><th>Envoyé</th><th>Erreur</th></tr>{trs or "<tr><td colspan=6>Aucun e-mail.</td></tr>"}</table></div></section>')

@app.post('/messagerie')
def mail_add(request:Request,destinataire:str=Form(...),sujet:str=Form(...),corps:str=Form(...),action:str=Form('brouillon'),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);row=BusinessEmail(destinataire=destinataire.strip(),sujet=sujet.strip(),corps=corps,created_by=u.username,statut='Brouillon');db.add(row);db.commit();db.refresh(row)
    if action=='envoyer':
        try:_smtp_send(row.destinataire,row.sujet,row.corps);row.statut='Envoyé';row.sent_at=datetime.utcnow();row.erreur=''
        except Exception as e:row.statut='Échec';row.erreur=str(e)[:3000]
        db.commit()
    return RedirectResponse('/messagerie',303)

@app.get('/integrations-business')
def integrations_business(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);odoo=_get_business_connector(db,'ODOO');itesa=_get_business_connector(db,'ITESA');logs=db.scalars(select(BusinessSyncLog).order_by(BusinessSyncLog.created_at.desc()).limit(20)).all();trs=''.join(f'<tr><td>{dfr(x.created_at)}</td><td>{escape(x.provider)}</td><td>{escape(x.action)}</td><td>{badge(x.statut)}</td><td>{x.rows_count}</td><td>{escape(x.detail[:180])}</td></tr>' for x in logs)
    body=f'''<div class="head"><div><h1>Intégrations métier</h1><p class="muted">Connecter NOX-IA aux outils et fournisseurs existants au lieu de ressaisir les mêmes données.</p></div></div><div class="grid"><section class="card"><h2>Odoo</h2><p>{badge(odoo.last_status if odoo else 'À configurer')}</p><p class="muted">CRM, contacts, fournisseurs et produits peuvent être synchronisés via l’API autorisée de votre instance.</p><a class="btn primary" href="/integrations/odoo">Configurer Odoo</a></section><section class="card"><h2>ITESA</h2><p>{badge(itesa.last_status if itesa else 'Prêt')}</p><p class="muted">Fournisseur préconfiguré, import de fiches produit publiques et catalogues/export de compte autorisés.</p><a class="btn primary" href="/integrations/itesa">Ouvrir ITESA</a></section></div><section class="card"><h2>Historique synchronisations</h2><div class="scroll"><table><tr><th>Date</th><th>Source</th><th>Action</th><th>Statut</th><th>Lignes</th><th>Détail</th></tr>{trs or "<tr><td colspan=6>Aucune synchronisation.</td></tr>"}</table></div></section>'''
    return page(request,u,'Intégrations métier',body)

@app.get('/integrations/odoo')
def odoo_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);c=_get_business_connector(db,'ODOO');status=badge(c.last_status if c else 'À configurer');base=escape(c.base_url if c else '');dbname=escape(c.database_name if c else '');username=escape(c.username if c else '');env=escape(c.secret_env_var if c else 'NOXIA_ODOO_API_KEY');mode=(c.api_mode if c else 'JSON-2')
    body=f'''<div class="head"><div><h1>Connexion Odoo</h1><p class="muted">Synchronisation en lecture pour éviter la double saisie. Les secrets restent dans les variables Render, jamais en base.</p></div>{status}</div><section class="card"><h2>Configuration</h2><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>URL Odoo<input type="url" name="base_url" value="{base}" placeholder="https://societe.odoo.com" required></label><label>Mode API<select name="api_mode"><option{' selected' if mode=='JSON-2' else ''}>JSON-2</option><option{' selected' if mode=='XML-RPC' else ''}>XML-RPC</option></select></label><label>Base de données<input name="database_name" value="{dbname}"></label><label>Utilisateur API<input name="username" value="{username}"></label><label>Nom variable secret Render<input name="secret_env_var" value="{env}" required></label><label class="full">Notes<textarea name="notes">{escape(c.notes if c else '')}</textarea></label><button class="btn primary">Enregistrer</button></form></section><section class="card"><h2>Actions</h2><div class="actions"><form method="post" action="/integrations/odoo/test"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn">Tester la connexion</button></form><form method="post" action="/integrations/odoo/sync"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn primary">Synchroniser contacts + fournisseurs + produits</button></form></div><p class="muted">Sur Odoo Online 19, l’API externe JSON-2 nécessite un plan qui autorise l’API. Si votre Odoo ne l’autorise pas, NOX-IA garde ses propres modules et on utilisera un export ou une autre intégration autorisée.</p></section>'''
    return page(request,u,'Odoo',body)

@app.post('/integrations/odoo')
def odoo_save(request:Request,base_url:str=Form(...),api_mode:str=Form('JSON-2'),database_name:str=Form(''),username:str=Form(''),secret_env_var:str=Form('NOXIA_ODOO_API_KEY'),notes:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS|{'Commercial'});_safe_remote_url(base_url);c=_get_business_connector(db,'ODOO')
    if not c:c=ExternalBusinessConnector(provider='ODOO',nom='Odoo',actif=True);db.add(c)
    c.base_url=base_url.strip().rstrip('/');c.api_mode=api_mode if api_mode in ('JSON-2','XML-RPC') else 'JSON-2';c.database_name=database_name.strip();c.username=username.strip();c.secret_env_var=secret_env_var.strip() or 'NOXIA_ODOO_API_KEY';c.notes=notes.strip();c.updated_at=datetime.utcnow();c.last_status='Configuré';db.commit();return RedirectResponse('/integrations/odoo?msg=Configuration+Odoo+enregistrée',303)

@app.post('/integrations/odoo/test')
def odoo_test_route(request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);require_login(request,db);c=_get_business_connector(db,'ODOO')
    if not c:raise HTTPException(400,'Configure Odoo d’abord')
    try:info=_odoo_test(c);c.last_status='Connecté';c.last_message=f"Connexion valide : {info.get('name','Odoo')}";c.last_sync_at=datetime.utcnow();db.commit();_business_log(db,c,'ODOO','Test connexion','OK',c.last_message,1);return RedirectResponse('/integrations/odoo?msg=Connexion+Odoo+OK',303)
    except Exception as e:c.last_status='Erreur';c.last_message=str(e)[:3000];db.commit();_business_log(db,c,'ODOO','Test connexion','Erreur',str(e),0);return RedirectResponse('/integrations/odoo?msg=Connexion+Odoo+impossible',303)

@app.post('/integrations/odoo/sync')
def odoo_sync_route(request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);require_login(request,db);c=_get_business_connector(db,'ODOO')
    if not c:raise HTTPException(400,'Configure Odoo d’abord')
    count=0
    try:
        partners=_odoo_search_read(c,'res.partner',[],['name','email','phone','customer_rank','supplier_rank'],1000)
        for x in partners:
            name=str(x.get('name') or '').strip()
            if not name:continue
            if int(x.get('customer_rank') or 0)>0:
                row=db.scalar(select(Client).where(func.lower(Client.nom)==name.lower()))
                if not row:db.add(Client(nom=name,contact='',email=str(x.get('email') or ''),telephone=str(x.get('phone') or ''),actif=True));count+=1
            if int(x.get('supplier_rank') or 0)>0:
                row=db.scalar(select(Supplier).where(func.lower(Supplier.nom)==name.lower()))
                if not row:db.add(Supplier(nom=name,contact='',email=str(x.get('email') or ''),telephone=str(x.get('phone') or ''),site_web='',actif=True));count+=1
        db.flush()
        products=_odoo_search_read(c,'product.product',[],['default_code','name','standard_price','qty_available'],1500)
        for x in products:
            ref=str(x.get('default_code') or '').strip();name=str(x.get('name') or '').strip()
            if not ref or not name:continue
            item=db.scalar(select(StockItem).where(func.lower(StockItem.reference)==ref.lower()))
            if not item:
                db.add(StockItem(reference=ref,designation=name,type_article='Équipement',marque='',modele='',quantite=max(0,int(float(x.get('qty_available') or 0))),seuil_alerte=1,prix_achat=max(0,float(x.get('standard_price') or 0)),actif=True));count+=1
            else:
                item.designation=name or item.designation;item.prix_achat=max(0,float(x.get('standard_price') or item.prix_achat or 0));item.quantite=max(0,int(float(x.get('qty_available') or item.quantite or 0)))
        c.last_status='Connecté';c.last_sync_at=datetime.utcnow();c.last_message=f'{count} création(s)/mise(s) à jour préparées depuis Odoo';db.commit();_business_log(db,c,'ODOO','Synchronisation lecture','OK',c.last_message,count);return RedirectResponse('/integrations/odoo?msg=Synchronisation+Odoo+terminée',303)
    except Exception as e:db.rollback();c=_get_business_connector(db,'ODOO');c.last_status='Erreur';c.last_message=str(e)[:3000];db.commit();_business_log(db,c,'ODOO','Synchronisation lecture','Erreur',str(e),count);return RedirectResponse('/integrations/odoo?msg=Synchronisation+Odoo+en+erreur',303)

@app.get('/integrations/itesa')
def itesa_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);ensure_itesa_supplier(db);sup=db.scalar(select(Supplier).where(func.lower(Supplier.nom)=='itesa'));prices=db.scalars(select(SupplierPrice).where(SupplierPrice.supplier_id==sup.id).order_by(SupplierPrice.date_prix.desc()).limit(100)).all() if sup else [];trs=''
    for p in prices:
        item=db.get(StockItem,p.stock_item_id);trs+=f'<tr><td>{dfr(p.date_prix)}</td><td>{escape(item.reference if item else "—")}</td><td>{escape(item.designation if item else "—")}</td><td>{money(p.prix)}</td></tr>'
    body=f'''<div class="head"><div><h1>ITESA</h1><p class="muted">Fournisseur professionnel déjà préconfiguré dans NOX-IA.</p></div><a class="btn" href="https://boutique.itesa.eu" target="_blank" rel="noopener">Ouvrir boutique ITESA</a></div><section class="card"><h2>Connexion disponible maintenant</h2><p>NOX-IA peut importer les références et désignations depuis une fiche produit publique ITESA. Les prix professionnels ne sont pas publics : ils nécessitent la connexion au compte ITESA. Pour les automatiser proprement, il faut un export catalogue, un flux API/EDI ou une méthode autorisée fournie par ITESA.</p></section><section class="card"><h2>Importer une fiche produit ITESA</h2><form method="post" action="/integrations/itesa/import-url" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label class="full">URL produit ITESA<input type="url" name="url" placeholder="https://boutique.itesa.eu/produit/..." required></label><label>Prix professionnel connu (optionnel)<input type="number" min="0" step="0.01" name="prix" value="0"></label><button class="btn primary">Importer dans Stock + ITESA</button></form></section><section class="card"><h2>Importer un export compte ITESA</h2><form method="post" action="/integrations/itesa/import-csv" enctype="multipart/form-data" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label class="full">CSV avec colonnes reference, designation, prix, marque, modele<input type="file" name="fichier" accept=".csv,text/csv" required></label><button class="btn primary">Importer le catalogue</button></form></section><section class="card"><h2>Prix ITESA connus</h2><div class="scroll"><table><tr><th>Date</th><th>Réf</th><th>Article</th><th>Prix</th></tr>{trs or "<tr><td colspan=4>Aucun prix ITESA importé.</td></tr>"}</table></div></section>'''
    return page(request,u,'ITESA',body)

@app.post('/integrations/itesa/import-url')
def itesa_import_url(request:Request,url:str=Form(...),prix:float=Form(0),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);require_login(request,db);ensure_itesa_supplier(db);sup=db.scalar(select(Supplier).where(func.lower(Supplier.nom)=='itesa'));conn=_get_business_connector(db,'ITESA')
    try:
        data=_itesa_fetch_product(url);item=db.scalar(select(StockItem).where(func.lower(StockItem.reference)==data['reference'].lower()))
        if not item:item=StockItem(reference=data['reference'],designation=data['designation'],type_article='Équipement',marque='',modele=data['reference_fabricant'],quantite=0,seuil_alerte=1,prix_achat=max(0,float(prix)),actif=True);db.add(item);db.flush()
        else:item.designation=data['designation'];item.modele=item.modele or data['reference_fabricant']
        if float(prix)>0:db.add(SupplierPrice(supplier_id=sup.id,stock_item_id=item.id,prix=float(prix)))
        conn.last_status='Connecté catalogue';conn.last_sync_at=datetime.utcnow();conn.last_message=f"Import {data['reference']}";db.commit();_business_log(db,conn,'ITESA','Import URL produit','OK',data['reference'],1);return RedirectResponse('/integrations/itesa?msg=Produit+ITESA+importé',303)
    except Exception as e:db.rollback();conn=_get_business_connector(db,'ITESA');conn.last_status='Erreur';conn.last_message=str(e)[:3000];db.commit();_business_log(db,conn,'ITESA','Import URL produit','Erreur',str(e),0);return RedirectResponse('/integrations/itesa?msg=Import+ITESA+impossible',303)

@app.post('/integrations/itesa/import-csv')
async def itesa_import_csv(request:Request,fichier:UploadFile=File(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);require_login(request,db);ensure_itesa_supplier(db);sup=db.scalar(select(Supplier).where(func.lower(Supplier.nom)=='itesa'));conn=_get_business_connector(db,'ITESA');raw=await fichier.read(5*1024*1024+1)
    if len(raw)>5*1024*1024:raise HTTPException(400,'CSV trop volumineux')
    text_data=raw.decode('utf-8-sig',errors='replace');sample=text_data[:4096]
    try:dialect=csv.Sniffer().sniff(sample,delimiters=';,\t,')
    except Exception:dialect=csv.excel
    reader=csv.DictReader(io.StringIO(text_data),dialect=dialect);count=0
    try:
        for row in reader:
            low={str(k or '').strip().lower():v for k,v in row.items()};ref=str(low.get('reference') or low.get('référence') or low.get('ref') or '').strip();des=str(low.get('designation') or low.get('désignation') or low.get('nom') or '').strip()
            if not ref or not des:continue
            price=_price_number(low.get('prix') or low.get('price') or 0) or 0;brand=str(low.get('marque') or '').strip();model=str(low.get('modele') or low.get('modèle') or low.get('ref_fabricant') or '').strip();item=db.scalar(select(StockItem).where(func.lower(StockItem.reference)==ref.lower()))
            if not item:item=StockItem(reference=ref,designation=des,type_article='Équipement',marque=brand,modele=model,quantite=0,seuil_alerte=1,prix_achat=price,actif=True);db.add(item);db.flush()
            else:item.designation=des;item.marque=item.marque or brand;item.modele=item.modele or model
            if price>0:db.add(SupplierPrice(supplier_id=sup.id,stock_item_id=item.id,prix=price))
            count+=1
        conn.last_status='Connecté import';conn.last_sync_at=datetime.utcnow();conn.last_message=f'{count} ligne(s) ITESA importées';db.commit();_business_log(db,conn,'ITESA','Import CSV compte','OK',conn.last_message,count);return RedirectResponse('/integrations/itesa?msg=Catalogue+ITESA+importé',303)
    except Exception as e:db.rollback();conn=_get_business_connector(db,'ITESA');conn.last_status='Erreur';conn.last_message=str(e)[:3000];db.commit();_business_log(db,conn,'ITESA','Import CSV compte','Erreur',str(e),count);return RedirectResponse('/integrations/itesa?msg=Import+CSV+en+erreur',303)


# ---------------------------------------------------------------------------
# NOX-IA 7.2 — Odoo Power : activités, fichiers, visa interne, Studio, portail
# ---------------------------------------------------------------------------

def _safe_filename(name):
    name=os.path.basename(str(name or 'fichier')).replace('\r','').replace('\n','').strip() or 'fichier'
    return re.sub(r'[^A-Za-z0-9._ ()\-À-ÿ]+','_',name)[:240]

def _ref(prefix):
    return f'{prefix}-{datetime.utcnow().strftime("%Y%m%d")}-{secrets.token_hex(3).upper()}'

def _activity_scope(db,u):
    stmt=select(BusinessActivity)
    if u.role not in MANAGERS:
        stmt=stmt.where((BusinessActivity.assigned_to==u.username)|(BusinessActivity.created_by==u.username))
    return stmt

@app.get('/activites')
def activities_page(request:Request,filter:str='open',db:Session=Depends(get_db)):
    u=require_login(request,db);today=date.today();rows=db.scalars(_activity_scope(db,u).order_by(BusinessActivity.due_date.asc(),BusinessActivity.created_at.desc())).all()
    if filter=='mine':rows=[x for x in rows if x.assigned_to==u.username and x.status!='Terminée']
    elif filter=='late':rows=[x for x in rows if x.status!='Terminée' and x.due_date and x.due_date<today]
    elif filter=='done':rows=[x for x in rows if x.status=='Terminée']
    else:rows=[x for x in rows if x.status!='Terminée']
    token=csrf_token(request);users=db.scalars(select(User).where(User.active.is_(True)).order_by(User.username)).all()
    cards=[]
    for x in rows:
        cls='overdue' if x.status!='Terminée' and x.due_date and x.due_date<today else ('today' if x.due_date==today and x.status!='Terminée' else '')
        done='' if x.status=='Terminée' else f'<form method="post" action="/activites/{x.id}/terminer"><input type="hidden" name="csrf_token" value="{token}"><button class="btn small goodbtn">✓ Terminer</button></form>'
        cards.append(f'<div class="activity-row {cls}"><div><b>{escape(x.summary)}</b><div class="muted">{escape(x.activity_type)} · {escape(x.related_type)} {x.related_id or ""}</div></div><div>{escape(x.assigned_to or "Non assignée")}</div><div>{dfr(x.due_date)} · {badge(x.priority)}</div><div>{done}</div></div>')
    body=f'''<div class="head"><div><h1>Activités</h1><p class="muted">Relances, rappels et prochaines actions sur tous les dossiers.</p></div></div><div class="viewbar"><a class="pill" href="/activites">Ouvertes</a><a class="pill" href="/activites?filter=mine">Mes activités</a><a class="pill" href="/activites?filter=late">En retard</a><a class="pill" href="/activites?filter=done">Terminées</a></div><section class="card"><details><summary>+ Planifier une activité</summary><form method="post" action="/activites" class="form"><input type="hidden" name="csrf_token" value="{token}"><label class="full">Résumé<input name="summary" required></label><label>Type<select name="activity_type"><option>À faire</option><option>Appel</option><option>E-mail</option><option>Rendez-vous</option><option>Relance</option><option>Contrôle</option></select></label><label>Assignée à<select name="assigned_to"><option value="">Non assignée</option>{''.join(f'<option value="{escape(x.username)}">{escape(x.username)}</option>' for x in users)}</select></label><label>Échéance<input type="date" name="due_date"></label><label>Priorité<select name="priority"><option>Basse</option><option selected>Normale</option><option>Haute</option><option>Urgente</option></select></label><label>Objet lié<input name="related_type" placeholder="Client, Projet, Ticket, Devis…"></label><label>ID objet<input type="number" min="1" name="related_id"></label><label class="full">Note<textarea name="note"></textarea></label><button class="btn primary">Planifier</button></form></details></section><section class="card"><h2>{len(rows)} activité(s)</h2>{''.join(cards) or '<div class="muted">Aucune activité dans ce filtre.</div>'}</section>'''
    return page(request,u,'Activités',body)

@app.post('/activites')
def activity_add(request:Request,summary:str=Form(...),activity_type:str=Form('À faire'),assigned_to:str=Form(''),due_date:str=Form(''),priority:str=Form('Normale'),related_type:str=Form(''),related_id:str=Form(''),note:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);row=BusinessActivity(summary=summary.strip(),activity_type=activity_type,assigned_to=assigned_to.strip(),due_date=date.fromisoformat(due_date) if due_date else None,priority=priority,related_type=related_type.strip(),related_id=int(related_id) if related_id else None,note=note.strip(),created_by=u.username);db.add(row);db.commit();audit_add(db,request,u,'Activité créée','BusinessActivity',row.id,row.summary,True);return RedirectResponse('/activites?msg=Activité+créée',303)

@app.post('/activites/{aid}/terminer')
def activity_done(aid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);row=db.get(BusinessActivity,aid)
    if not row:raise HTTPException(404,'Activité introuvable')
    if u.role not in MANAGERS and row.assigned_to not in ('',u.username) and row.created_by!=u.username:raise HTTPException(403,'Activité non assignée à ton compte')
    row.status='Terminée';row.done_at=datetime.utcnow();db.commit();return RedirectResponse('/activites?msg=Activité+terminée',303)

@app.get('/documents/{doc_id}')
def document_detail(doc_id:int,request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);doc=db.get(BusinessDocument,doc_id)
    if not doc:raise HTTPException(404,'Document introuvable')
    files=db.scalars(select(DocumentAttachment).where(DocumentAttachment.document_id==doc_id).order_by(DocumentAttachment.created_at.desc())).all();token=csrf_token(request)
    rows=''.join(f'<div class="file-card"><div><b>{escape(f.filename)}</b><div class="muted">v{f.version} · {f.size_bytes/1024:.1f} Ko · SHA-256 {escape(f.sha256[:12])}… · {dfr(f.created_at)}</div></div><a class="btn small" href="/documents/fichiers/{f.id}">Télécharger</a></div>' for f in files)
    body=f'''<div class="head"><div><h1>{escape(doc.nom)}</h1><p class="muted">{escape(doc.dossier)} · v{doc.version} · {escape(doc.tags)}</p></div><a class="btn" href="/documents">Retour</a></div><section class="card"><h2>Contenu</h2><div class="pre">{escape(doc.contenu)}</div></section><section class="card"><h2>Fichiers</h2><form method="post" action="/documents/{doc_id}/fichiers" enctype="multipart/form-data" class="form"><input type="hidden" name="csrf_token" value="{token}"><label class="full">Ajouter un fichier (10 Mo max)<input type="file" name="fichier" required></label><button class="btn primary">Téléverser une nouvelle version</button></form>{rows or '<p class="muted">Aucun fichier attaché.</p>'}</section>'''
    return page(request,u,'Document',body)

@app.post('/documents/{doc_id}/fichiers')
async def document_upload(doc_id:int,request:Request,fichier:UploadFile=File(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);doc=db.get(BusinessDocument,doc_id)
    if not doc:raise HTTPException(404,'Document introuvable')
    raw=await fichier.read(10*1024*1024+1)
    if len(raw)>10*1024*1024:raise HTTPException(400,'Fichier trop volumineux (10 Mo max)')
    name=_safe_filename(fichier.filename);last=db.scalar(select(func.max(DocumentAttachment.version)).where(DocumentAttachment.document_id==doc_id,DocumentAttachment.filename==name)) or 0
    row=DocumentAttachment(document_id=doc_id,filename=name,mime_type=(fichier.content_type or 'application/octet-stream')[:160],content=raw,size_bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),version=int(last)+1,uploaded_by=u.username);db.add(row);doc.version=int(doc.version or 1)+1;db.commit();return RedirectResponse(f'/documents/{doc_id}?msg=Fichier+ajouté',303)

@app.get('/documents/fichiers/{fid}')
def document_download(fid:int,request:Request,db:Session=Depends(get_db)):
    require_login(request,db);row=db.get(DocumentAttachment,fid)
    if not row:raise HTTPException(404,'Fichier introuvable')
    name=_safe_filename(row.filename)
    return Response(bytes(row.content or b''),media_type=row.mime_type or 'application/octet-stream',headers={'Content-Disposition':f'attachment; filename="{name}"','X-Content-Type-Options':'nosniff'})

@app.get('/signatures')
def signatures_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);stmt=select(InternalSignatureRequest)
    if u.role not in MANAGERS:stmt=stmt.where((InternalSignatureRequest.signer==u.username)|(InternalSignatureRequest.requested_by==u.username))
    rows=db.scalars(stmt.order_by(InternalSignatureRequest.created_at.desc()).limit(300)).all();users=db.scalars(select(User).where(User.active.is_(True)).order_by(User.username)).all();token=csrf_token(request)
    trs=''.join(f'<tr><td>{escape(r.reference)}</td><td>{escape(r.title)}</td><td>{escape(r.related_type)} {r.related_id or ""}</td><td>{escape(r.signer or "—")}</td><td>{badge(r.status)}</td><td>{dfr(r.signed_at)}</td><td>{("<form method=\"post\" action=\"/signatures/%s/signer\"><input type=\"hidden\" name=\"csrf_token\" value=\"%s\"><button class=\"btn small goodbtn\">Signer / viser</button></form>"%(r.id,token)) if r.status=="À signer" and (r.signer in ("",u.username) or u.role in MANAGERS) else ""}</td></tr>' for r in rows)
    body=f'''<div class="head"><div><h1>Signatures / visas</h1><p class="muted">Visa interne authentifié et horodaté. Ce module ne remplace pas une signature électronique qualifiée.</p></div></div><section class="card"><details><summary>+ Demander un visa</summary><form method="post" action="/signatures" class="form"><input type="hidden" name="csrf_token" value="{token}"><label class="full">Titre<input name="title" required></label><label>Type objet<input name="related_type" value="Document"></label><label>ID objet<input type="number" name="related_id"></label><label>Signataire<select name="signer"><option value="">Au choix</option>{''.join(f'<option>{escape(x.username)}</option>' for x in users)}</select></label><label class="full">Note<textarea name="note"></textarea></label><button class="btn primary">Envoyer à signature</button></form></details></section><section class="card"><div class="scroll"><table><tr><th>Référence</th><th>Objet</th><th>Rattachement</th><th>Signataire</th><th>État</th><th>Signé le</th><th></th></tr>{trs or '<tr><td colspan=7>Aucune demande.</td></tr>'}</table></div></section>'''
    return page(request,u,'Signatures',body)

@app.post('/signatures')
def signature_add(request:Request,title:str=Form(...),related_type:str=Form('Document'),related_id:str=Form(''),signer:str=Form(''),note:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);row=InternalSignatureRequest(reference=_ref('SIG'),title=title.strip(),related_type=related_type.strip(),related_id=int(related_id) if related_id else None,requested_by=u.username,signer=signer.strip(),note=note.strip());db.add(row);db.commit();return RedirectResponse('/signatures?msg=Visa+demandé',303)

@app.post('/signatures/{sid}/signer')
def signature_sign(sid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);row=db.get(InternalSignatureRequest,sid)
    if not row:raise HTTPException(404,'Demande introuvable')
    if row.status!='À signer':raise HTTPException(400,'Cette demande n’est plus à signer')
    if row.signer and row.signer!=u.username and u.role not in MANAGERS:raise HTTPException(403,'Tu n’es pas le signataire prévu')
    row.status='Signé';row.signer_name=u.username;row.signed_at=datetime.utcnow();db.commit();audit_add(db,request,u,'Visa interne signé','InternalSignatureRequest',row.id,row.reference,True);return RedirectResponse('/signatures?msg=Visa+enregistré',303)

STUDIO_MODELS=('Projet','Ticket','Client','Site','Équipement','Intervention','Devis','Facture','Stock')

@app.get('/studio')
def studio_page(request:Request,model:str='Projet',record_id:int|None=None,db:Session=Depends(get_db)):
    u=require_login(request,db);require_role(u,MANAGERS);model=model if model in STUDIO_MODELS else 'Projet';defs=db.scalars(select(CustomFieldDefinition).where(CustomFieldDefinition.model==model,CustomFieldDefinition.active.is_(True)).order_by(CustomFieldDefinition.id)).all();token=csrf_token(request);values={}
    if record_id:
        for d in defs:
            v=db.scalar(select(CustomFieldValue).where(CustomFieldValue.definition_id==d.id,CustomFieldValue.record_id==record_id));values[d.id]=v.value_text if v else ''
    fields=''.join(f'<div class="studio-field"><div><b>{escape(d.label)}</b><div class="muted">{escape(d.technical_name)} · {escape(d.field_type)}</div></div><input name="f_{d.id}" value="{escape(values.get(d.id,""))}" {"required" if d.required else ""}></div>' for d in defs)
    body=f'''<div class="head"><div><h1>Studio</h1><p class="muted">Ajoute des champs métier sans modifier les tables principales de NOX-IA.</p></div></div><div class="g2"><section class="card"><h2>Définir un champ</h2><form method="post" action="/studio/champs" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Modèle<select name="model">{''.join(f'<option {"selected" if x==model else ""}>{x}</option>' for x in STUDIO_MODELS)}</select></label><label>Libellé<input name="label" required></label><label>Nom technique<input name="technical_name" placeholder="numero_affaire" required></label><label>Type<select name="field_type"><option>Texte</option><option>Nombre</option><option>Date</option><option>Oui/Non</option><option>Choix</option></select></label><label class="full">Choix (séparés par ;)<input name="choices"></label><label><input type="checkbox" name="required" value="1" style="width:auto"> Obligatoire</label><button class="btn primary">Créer le champ</button></form></section><section class="card"><h2>Fiche personnalisée</h2><form method="get" class="form"><label>Modèle<select name="model">{''.join(f'<option {"selected" if x==model else ""}>{x}</option>' for x in STUDIO_MODELS)}</select></label><label>ID enregistrement<input type="number" min="1" name="record_id" value="{record_id or ""}"></label><button class="btn">Ouvrir</button></form>{('<form method="post" action="/studio/valeurs" class="form"><input type="hidden" name="csrf_token" value="'+token+'"><input type="hidden" name="model" value="'+escape(model)+'"><input type="hidden" name="record_id" value="'+str(record_id)+'"><div class="full">'+(fields or '<p class="muted">Aucun champ défini.</p>')+'</div><button class="btn primary">Enregistrer les champs</button></form>') if record_id else '<p class="muted">Choisis un modèle et l’ID d’un dossier pour renseigner les champs.</p>'}</section></div>'''
    return page(request,u,'Studio',body)

@app.post('/studio/champs')
def studio_field_add(request:Request,model:str=Form(...),label:str=Form(...),technical_name:str=Form(...),field_type:str=Form('Texte'),choices:str=Form(''),required:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);model=model if model in STUDIO_MODELS else 'Projet';tech=re.sub(r'[^a-z0-9_]+','_',technical_name.strip().lower()).strip('_')[:120]
    if not tech:raise HTTPException(400,'Nom technique invalide')
    if db.scalar(select(CustomFieldDefinition).where(CustomFieldDefinition.model==model,CustomFieldDefinition.technical_name==tech,CustomFieldDefinition.active.is_(True))):raise HTTPException(409,'Ce champ existe déjà pour ce modèle')
    db.add(CustomFieldDefinition(model=model,technical_name=tech,label=label.strip(),field_type=field_type,choices=choices.strip(),required=bool(required),created_by=u.username));db.commit();return RedirectResponse('/studio?model='+model,303)

@app.post('/studio/valeurs')
async def studio_values_save(request:Request,model:str=Form(...),record_id:int=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);form=await request.form();defs=db.scalars(select(CustomFieldDefinition).where(CustomFieldDefinition.model==model,CustomFieldDefinition.active.is_(True))).all()
    for d in defs:
        val=str(form.get(f'f_{d.id}','')).strip();row=db.scalar(select(CustomFieldValue).where(CustomFieldValue.definition_id==d.id,CustomFieldValue.record_id==record_id))
        if not row:db.add(CustomFieldValue(definition_id=d.id,record_id=record_id,value_text=val,updated_by=u.username))
        else:row.value_text=val;row.updated_by=u.username;row.updated_at=datetime.utcnow()
    db.commit();return RedirectResponse(f'/studio?model={model}&record_id={record_id}&msg=Champs+enregistrés',303)

def _automation_config(text_value):
    out={}
    for part in re.split(r'[;\n]+',str(text_value or '')):
        if '=' in part:
            k,v=part.split('=',1);out[k.strip().lower()]=v.strip()
    return out

def _automation_candidates(db,rule):
    cond=(rule.condition_text or '').lower();model=(rule.modele or '').lower();today=date.today();now=datetime.utcnow();rows=[]
    if 'stock' in model:
        for x in db.scalars(select(StockItem).where(StockItem.actif.is_(True))).all():
            if ('bas' in cond or 'seuil' in cond or 'rupture' in cond) and int(x.quantite or 0)<=int(x.seuil_alerte or 0):rows.append(('Stock',x.id,f'{x.reference} — stock {x.quantite}/{x.seuil_alerte}'))
    elif 'support' in model or 'ticket' in model:
        for x in db.scalars(select(HelpdeskTicket).where(HelpdeskTicket.statut.notin_(['Résolu','Fermé']))).all():
            if ('urgent' in cond and x.priorite=='Urgente') or ('sla' in cond and x.sla_deadline and x.sla_deadline<now):rows.append(('Support',x.id,f'{x.reference} — {x.titre}'))
    elif 'facture' in model:
        for x in db.scalars(select(CustomerInvoice).where(CustomerInvoice.statut.notin_(['Payée','Annulée']))).all():
            if ('retard' in cond or 'échéance' in cond or 'echeance' in cond) and x.date_echeance and x.date_echeance<today and float(x.paye or 0)<float(x.total or 0):rows.append(('Facture',x.id,f'{x.reference} — reste {money(float(x.total or 0)-float(x.paye or 0))}'))
    elif 'projet' in model:
        for x in db.scalars(select(ERPProject).where(ERPProject.statut.notin_(['Terminé','Annulé']))).all():
            if 'retard' in cond and x.date_fin and x.date_fin<today:rows.append(('Projet',x.id,f'{x.nom} — échéance {dfr(x.date_fin)}'))
    elif 'intervention' in model:
        for x in db.scalars(select(Intervention).where(Intervention.statut!='Terminée')).all():
            if ('urgent' in cond and str(x.priorite).lower() in ('urgente','urgent','critique')):rows.append(('Intervention',x.id,f'Intervention #{x.id} — {x.probleme[:120]}'))
    elif 'devis' in model:
        for x in db.scalars(select(Quote).where(Quote.statut.notin_(['Accepté','Refusé','Annulé']))).all():
            if 'ancien' in cond or 'relance' in cond:
                age=(now-x.date_creation).days if x.date_creation else 0
                if age>=7:rows.append(('Devis',x.id,f'{x.reference} — {age} jours sans clôture'))
    return rows

def _automation_execute_action(db,rule,record_model,record_id,detail):
    cfg=_automation_config(rule.action_config);action=(rule.action_type or '').lower();message=cfg.get('message') or f'{rule.nom} : {detail}'
    if 'notification' in action:
        role=cfg.get('role','Responsable');targets=db.scalars(select(User).where(User.active.is_(True),User.role==role)).all()
        if not targets:targets=db.scalars(select(User).where(User.active.is_(True),User.role.in_(list(MANAGERS)))).all()
        for target in targets:db.add(Notification(user_id=target.id,niveau='Avertissement',categorie='Automatisation',titre=rule.nom[:280],message=message[:4000],lien='/automatisations'))
        return f'{len(targets)} notification(s) créée(s)'
    if 'activité' in action or 'activite' in action:
        assignee=cfg.get('assignee','');db.add(BusinessActivity(summary=message[:320],activity_type='Automatisation',assigned_to=assignee,due_date=date.today(),priority='Haute',related_type=record_model,related_id=record_id,note=detail,created_by='Automatisation'));return 'Activité créée'
    if 'approbation' in action:
        db.add(ApprovalRequest(reference=_ref('APR'),type_demande='Automatisation',titre=message[:300],demandeur='Automatisation',approbateur=cfg.get('approbateur',''),montant=0,statut='À approuver',justification=detail));return 'Approbation créée'
    return 'Action non autorisée ignorée'

def run_safe_automations(db):
    total=0;rules=db.scalars(select(AutomationRule).where(AutomationRule.actif.is_(True))).all()
    for rule in rules:
        for model_name,record_id,detail in _automation_candidates(db,rule):
            raw=f'{rule.id}|{model_name}|{record_id}|{date.today().isoformat()}';key=hashlib.sha256(raw.encode()).hexdigest()
            if db.scalar(select(AutomationExecution).where(AutomationExecution.dedupe_key==key)):continue
            status='OK'
            try:result=_automation_execute_action(db,rule,model_name,record_id,detail)
            except Exception as e:status='Erreur';result=str(e)[:2000]
            db.add(AutomationExecution(rule_id=rule.id,record_model=model_name,record_id=record_id,dedupe_key=key,status=status,detail=result+' · '+detail));total+=1
    db.commit();return total

@app.post('/automatisations/executer')
def automation_run(request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);count=run_safe_automations(db);audit_add(db,request,u,'Moteur automatisations exécuté','AutomationRule','',f'{count} action(s)',True);return RedirectResponse(f'/automatisations?msg={count}+action(s)+exécutée(s)',303)

def _month_keys(n=12):
    out=[];d=date.today().replace(day=1)
    for i in range(n-1,-1,-1):
        y=d.year; m=d.month-i
        while m<=0:y-=1;m+=12
        out.append(f'{y:04d}-{m:02d}')
    return out

def _monthly_series(rows,date_get,value_get=lambda x:1.0,keys=None):
    keys=keys or _month_keys();vals={k:0.0 for k in keys}
    for row in rows:
        v=date_get(row)
        if isinstance(v,datetime):k=v.strftime('%Y-%m')
        elif isinstance(v,date):k=v.strftime('%Y-%m')
        else:continue
        if k in vals:vals[k]+=float(value_get(row) or 0)
    return [(k,vals[k]) for k in keys]

@app.get('/reporting')
def reporting_page(request:Request,metric:str='ventes',db:Session=Depends(get_db)):
    u=require_login(request,db);keys=_month_keys();metric=metric.lower()
    if metric=='achats':rows=db.scalars(select(PurchaseOrder)).all();series=_monthly_series(rows,lambda x:x.created_at,lambda x:x.total_ttc,keys);title='Achats TTC'
    elif metric=='support':rows=db.scalars(select(HelpdeskTicket)).all();series=_monthly_series(rows,lambda x:x.created_at,lambda x:1,keys);title='Tickets créés'
    elif metric=='temps':rows=db.scalars(select(TimesheetEntry)).all();series=_monthly_series(rows,lambda x:x.date_travail,lambda x:x.heures,keys);title='Heures saisies'
    elif metric=='factures':rows=db.scalars(select(CustomerInvoice)).all();series=_monthly_series(rows,lambda x:x.date_emission,lambda x:x.total,keys);title='Facturation TTC'
    else:rows=db.scalars(select(Quote)).all();series=_monthly_series(rows,lambda x:x.date_creation,lambda x:quote_totals(db,x)[2],keys);title='Devis — valeur de vente';metric='ventes'
    vmax=max([v for _,v in series] or [1]) or 1
    bars=''.join(f'<div class="report-bar"><span>{escape(k)}</span><div class="report-track"><div class="report-fill" style="width:{min(100,(v/vmax)*100):.1f}%"></div></div><strong>{money(v) if metric in ("ventes","achats","factures") else f"{v:.1f}"}</strong></div>' for k,v in series)
    open_tickets=db.scalar(select(func.count(HelpdeskTicket.id)).where(HelpdeskTicket.statut.notin_(['Résolu','Fermé']))) or 0;overdue_inv=sum(1 for x in db.scalars(select(CustomerInvoice)).all() if x.date_echeance and x.date_echeance<date.today() and float(x.paye or 0)<float(x.total or 0));low_stock=db.scalar(select(func.count(StockItem.id)).where(StockItem.actif.is_(True),StockItem.quantite<=StockItem.seuil_alerte)) or 0;hours=sum(float(x.heures or 0) for x in db.scalars(select(TimesheetEntry).where(TimesheetEntry.date_travail>=date.today().replace(day=1))).all())
    body=f'''<div class="head"><div><h1>Reporting</h1><p class="muted">Vue transversale des opérations et de l’ERP.</p></div><a class="btn" href="/reporting.csv?metric={metric}">Exporter CSV</a></div><div class="g4"><div class="metric"><span>Tickets ouverts</span><strong>{open_tickets}</strong></div><div class="metric"><span>Factures en retard</span><strong>{overdue_inv}</strong></div><div class="metric"><span>Références stock bas</span><strong>{low_stock}</strong></div><div class="metric"><span>Heures ce mois</span><strong>{hours:.1f} h</strong></div></div><div class="viewbar">{''.join(f'<a class="pill{(" active" if metric==m else "")}" href="/reporting?metric={m}">{label}</a>' for m,label in (("ventes","Ventes"),("factures","Factures"),("achats","Achats"),("support","Support"),("temps","Temps")))}</div><section class="card"><h2>{escape(title)} — 12 mois</h2><div class="report-bars">{bars}</div></section>'''
    return page(request,u,'Reporting',body)

@app.get('/reporting.csv')
def reporting_csv(request:Request,metric:str='ventes',db:Session=Depends(get_db)):
    require_login(request,db);metric=metric.lower();keys=_month_keys()
    if metric=='achats':series=_monthly_series(db.scalars(select(PurchaseOrder)).all(),lambda x:x.created_at,lambda x:x.total_ttc,keys)
    elif metric=='support':series=_monthly_series(db.scalars(select(HelpdeskTicket)).all(),lambda x:x.created_at,lambda x:1,keys)
    elif metric=='temps':series=_monthly_series(db.scalars(select(TimesheetEntry)).all(),lambda x:x.date_travail,lambda x:x.heures,keys)
    elif metric=='factures':series=_monthly_series(db.scalars(select(CustomerInvoice)).all(),lambda x:x.date_emission,lambda x:x.total,keys)
    else:series=_monthly_series(db.scalars(select(Quote)).all(),lambda x:x.date_creation,lambda x:quote_totals(db,x)[2],keys)
    sio=io.StringIO();w=csv.writer(sio,delimiter=';');w.writerow(['mois','valeur']);w.writerows(series);raw='\ufeff'+sio.getvalue();return Response(raw.encode('utf-8'),media_type='text/csv; charset=utf-8',headers={'Content-Disposition':f'attachment; filename="NOX-IA_reporting_{metric}.csv"'})

def _portal_resource_client_id(db,resource_type,resource_id):
    typ=resource_type.lower()
    if typ=='devis':r=db.get(Quote,resource_id);return r.client_id if r else None
    if typ=='facture':r=db.get(CustomerInvoice,resource_id);return r.client_id if r else None
    if typ=='ticket':r=db.get(HelpdeskTicket,resource_id);return r.client_id if r else None
    if typ=='abonnement':r=db.get(ServiceSubscription,resource_id);return r.client_id if r else None
    return None

def _portal_render_resource(db,share):
    typ=share.resource_type.lower();rid=share.resource_id
    if typ=='devis':
        q=db.get(Quote,rid)
        if not q:return '<p>Document introuvable.</p>'
        client=db.get(Client,q.client_id);lines=db.scalars(select(QuoteLine).where(QuoteLine.quote_id==q.id).order_by(QuoteLine.id)).all();_,cost,sale,margin,margin_pct=quote_totals(db,q)
        trs=''.join(f'<tr><td>{escape(x.designation)}</td><td>{x.quantite:g}</td><td>{money(x.vente_unitaire)}</td><td>{money(float(x.quantite or 0)*float(x.vente_unitaire or 0))}</td></tr>' for x in lines)
        return f'<h1>Devis {escape(q.reference)}</h1><p>{escape(client.nom if client else "Client")} · {badge(q.statut)}</p><div class="scroll"><table><tr><th>Désignation</th><th>Qté</th><th>PU</th><th>Total</th></tr>{trs}</table></div><h2>Total : {money(sale)}</h2><p class="muted">Validité : {dfr(q.date_validite)}</p>'
    if typ=='facture':
        x=db.get(CustomerInvoice,rid)
        if not x:return '<p>Facture introuvable.</p>'
        client=db.get(Client,x.client_id);rest=max(0,float(x.total or 0)-float(x.paye or 0));return f'<h1>Facture {escape(x.reference)}</h1><p>{escape(client.nom if client else "Client")} · {badge(x.statut)}</p><div class="g2"><div class="metric"><span>Total TTC</span><strong>{money(x.total)}</strong></div><div class="metric"><span>Reste à payer</span><strong>{money(rest)}</strong></div></div><p>Échéance : {dfr(x.date_echeance)}</p>'
    if typ=='ticket':
        x=db.get(HelpdeskTicket,rid)
        if not x:return '<p>Ticket introuvable.</p>'
        return f'<h1>{escape(x.reference)} · {escape(x.titre)}</h1><p>{badge(x.statut)} · priorité {escape(x.priorite)}</p><section class="card"><h2>Demande</h2><p>{escape(x.description)}</p></section><section class="card"><h2>Résolution</h2><p>{escape(x.resolution or "En cours")}</p></section>'
    if typ=='abonnement':
        x=db.get(ServiceSubscription,rid)
        if not x:return '<p>Abonnement introuvable.</p>'
        return f'<h1>{escape(x.reference)} · {escape(x.nom)}</h1><p>{badge(x.statut)}</p><div class="g2"><div class="metric"><span>Périodicité</span><strong>{escape(x.periodicite)}</strong></div><div class="metric"><span>Montant</span><strong>{money(x.montant)}</strong></div></div><p>Prochaine facturation : {dfr(x.prochaine_facture)}</p>'
    return '<p>Type de ressource non pris en charge.</p>'

@app.get('/portail-admin')
def portal_admin_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);shares=db.scalars(select(CustomerPortalShare).order_by(CustomerPortalShare.created_at.desc()).limit(300)).all();token=csrf_token(request);trs=''.join(f'<tr><td>{escape(x.reference)}</td><td>{escape(x.resource_type)} #{x.resource_id}</td><td>{badge("Actif" if x.active else "Révoqué")}</td><td>{dfr(x.expires_at)}</td><td>{dfr(x.last_access_at)}</td><td>{("<form method=\"post\" action=\"/portail-admin/%s/revoquer\"><input type=\"hidden\" name=\"csrf_token\" value=\"%s\"><button class=\"btn small dangerbtn\">Révoquer</button></form>"%(x.id,token)) if x.active else ""}</td></tr>' for x in shares)
    body=f'''<div class="head"><div><h1>Portail client</h1><p class="muted">Partages lecture seule à durée limitée. Le lien donne accès uniquement à la ressource choisie.</p></div></div><section class="card"><form method="post" action="/portail-admin" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Type<select name="resource_type"><option>Devis</option><option>Facture</option><option>Ticket</option><option>Abonnement</option></select></label><label>ID ressource<input type="number" min="1" name="resource_id" required></label><label>Validité (jours)<input type="number" min="1" max="365" name="days" value="30"></label><button class="btn primary">Créer un lien</button></form></section><section class="card"><div class="scroll"><table><tr><th>Référence</th><th>Ressource</th><th>État</th><th>Expire</th><th>Dernier accès</th><th></th></tr>{trs or '<tr><td colspan=6>Aucun partage.</td></tr>'}</table></div></section>'''
    return page(request,u,'Portail client',body)

@app.post('/portail-admin')
def portal_share_add(request:Request,resource_type:str=Form(...),resource_id:int=Form(...),days:int=Form(30),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,COMMERCIALS|MANAGERS);resource_type=resource_type.title();client_id=_portal_resource_client_id(db,resource_type,resource_id)
    if client_id is None:raise HTTPException(404,'Ressource introuvable ou non partageable')
    raw=secrets.token_urlsafe(32);row=CustomerPortalShare(reference=_ref('PORT'),token_hash=hashlib.sha256(raw.encode()).hexdigest(),resource_type=resource_type,resource_id=resource_id,client_id=client_id,expires_at=datetime.utcnow()+timedelta(days=max(1,min(365,days))),active=True,created_by=u.username);db.add(row);db.commit();link=str(request.base_url).rstrip('/')+'/portail/'+raw
    body=f'''<div class="head"><div><h1>Lien client créé</h1><p class="muted">Copie ce lien maintenant : le jeton brut n’est pas stocké dans la base.</p></div></div><section class="card"><label>Lien lecture seule<input value="{escape(link)}" readonly onclick="this.select()"></label><p class="hint">Expire le {dfr(row.expires_at)}. Tu peux le révoquer depuis Portail client.</p><a class="btn" href="/portail-admin">Retour</a></section>'''
    return page(request,u,'Lien client',body)

@app.post('/portail-admin/{sid}/revoquer')
def portal_share_revoke(sid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,COMMERCIALS|MANAGERS);row=db.get(CustomerPortalShare,sid)
    if not row:raise HTTPException(404,'Partage introuvable')
    row.active=False;db.commit();return RedirectResponse('/portail-admin?msg=Lien+révoqué',303)

@app.get('/portail/{token}')
def public_portal(token:str,request:Request,db:Session=Depends(get_db)):
    token=str(token or '').strip()
    if len(token)<20:raise HTTPException(404,'Lien invalide')
    row=db.scalar(select(CustomerPortalShare).where(CustomerPortalShare.token_hash==hashlib.sha256(token.encode()).hexdigest()))
    if not row or not row.active or (row.expires_at and row.expires_at<datetime.utcnow()):raise HTTPException(404,'Lien invalide ou expiré')
    row.last_access_at=datetime.utcnow();db.commit();resource=_portal_render_resource(db,row);company=escape(get_setting(db,'company_name','NOXIA Groupe'))
    html=f'''<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Portail · {company}</title><style>{CSS}</style></head><body><main class="portal-shell"><div class="portal-brand">{company} · Portail</div><section class="card">{resource}</section><p class="muted">Lien lecture seule · référence {escape(row.reference)} · expiration {dfr(row.expires_at)}</p></main></body></html>'''
    return HTMLResponse(html,headers={'Cache-Control':'no-store','X-Robots-Tag':'noindex, nofollow'})


# =============================================================================
# NOX-IA 7.3 — Business+
# =============================================================================

def _slugify(value):
    s=assistant_norm(value or '') if 'assistant_norm' in globals() else str(value or '').lower()
    s=re.sub(r'[^a-z0-9]+','-',s).strip('-')
    return (s[:150] or secrets.token_hex(5))

@app.get('/contacts-pro')
def contacts_pro_page(request:Request,q:str='',db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(BusinessContact).where(BusinessContact.active.is_(True)).order_by(BusinessContact.updated_at.desc())).all();low=q.strip().lower()
    if low:rows=[x for x in rows if low in ' '.join([x.name,x.company,x.email,x.phone,x.mobile,x.job_title,x.tags]).lower()]
    clients=db.scalars(select(Client).where(Client.actif.is_(True)).order_by(Client.nom)).all();token=csrf_token(request)
    trs=''.join(f'<tr><td><b>{escape(x.name)}</b><div class="muted">{escape(x.job_title)}</div></td><td>{escape(x.company)}</td><td>{escape(x.email or "—")}</td><td>{escape(x.mobile or x.phone or "—")}</td><td>{escape(x.contact_type)}</td><td>{escape(x.tags)}</td></tr>' for x in rows)
    body=f'''<div class="head"><div><h1>Contacts</h1><p class="muted">Carnet de contacts métier rattachable aux clients, avec fonctions, langues et tags.</p></div><form method="get" class="inline-form"><input name="q" value="{escape(q)}" placeholder="Nom, société, e-mail…"><button class="btn">Rechercher</button></form></div><section class="card"><details><summary>+ Nouveau contact</summary><form method="post" action="/contacts-pro" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Nom<input name="name" required></label><label>Société<input name="company"></label><label>Client NOX-IA<select name="client_id">{option_rows(clients,lambda x:x.id,lambda x:x.nom,empty='Aucun')}</select></label><label>Fonction<input name="job_title"></label><label>E-mail<input type="email" name="email"></label><label>Téléphone<input name="phone"></label><label>Mobile<input name="mobile"></label><label>Type<select name="contact_type"><option>Client</option><option>Prospect</option><option>Fournisseur</option><option>Partenaire</option><option>Autre</option></select></label><label>Langue<input name="language" value="fr_FR"></label><label>Tags<input name="tags"></label><button class="btn primary">Créer</button></form></details></section><section class="card"><div class="scroll"><table><tr><th>Contact</th><th>Société</th><th>E-mail</th><th>Téléphone</th><th>Type</th><th>Tags</th></tr>{trs or '<tr><td colspan=6>Aucun contact.</td></tr>'}</table></div></section>'''
    return page(request,u,'Contacts',body)

@app.post('/contacts-pro')
def contacts_pro_add(request:Request,name:str=Form(...),company:str=Form(''),client_id:str=Form(''),job_title:str=Form(''),email:str=Form(''),phone:str=Form(''),mobile:str=Form(''),contact_type:str=Form('Client'),language:str=Form('fr_FR'),tags:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);require_login(request,db);db.add(BusinessContact(name=name.strip(),company=company.strip(),client_id=int(client_id) if client_id else None,job_title=job_title.strip(),email=email.strip(),phone=phone.strip(),mobile=mobile.strip(),contact_type=contact_type.strip()[:80],language=language.strip()[:50],tags=tags.strip()));db.commit();return RedirectResponse('/contacts-pro?msg=Contact+créé',303)

def _finance_balance(db,account):
    txs=db.scalars(select(FinanceTransaction).where(FinanceTransaction.account_id==account.id)).all();return float(account.opening_balance or 0)+sum(float(x.amount or 0)*(1 if x.direction=='Entrée' else -1) for x in txs)

@app.get('/finance')
def finance_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);accounts=db.scalars(select(FinanceAccount).where(FinanceAccount.active.is_(True)).order_by(FinanceAccount.code)).all();txs=db.scalars(select(FinanceTransaction).order_by(FinanceTransaction.date_operation.desc(),FinanceTransaction.id.desc()).limit(400)).all();token=csrf_token(request)
    total=sum(_finance_balance(db,x) for x in accounts);unrec=sum(1 for x in txs if not x.reconciled)
    account_cards=''.join(f'<div class="metric"><span>{escape(x.code)} · {escape(x.name)}</span><strong>{money(_finance_balance(db,x))}</strong></div>' for x in accounts)
    trs=''.join(f'<tr><td>{dfr(x.date_operation)}</td><td>{escape(x.reference)}</td><td>{escape((db.get(FinanceAccount,x.account_id).name if db.get(FinanceAccount,x.account_id) else "—"))}</td><td>{badge(x.direction)}</td><td>{escape(x.label)}</td><td>{money(x.amount)}</td><td>{"✓" if x.reconciled else "—"}</td></tr>' for x in txs)
    body=f'''<div class="head"><div><h1>Finance & trésorerie</h1><p class="muted">Pilotage financier interne. Ce module ne remplace pas la comptabilité légale ni les obligations fiscales.</p></div></div><div class="g2"><div class="metric"><span>Solde interne consolidé</span><strong>{money(total)}</strong></div><div class="metric"><span>Mouvements à rapprocher</span><strong>{unrec}</strong></div></div><div class="g4">{account_cards}</div><div class="g2"><section class="card"><h2>Nouveau compte</h2><form method="post" action="/finance/comptes" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Code<input name="code" required></label><label>Nom<input name="name" required></label><label>Type<select name="account_type"><option>Banque</option><option>Caisse</option><option>Interne</option></select></label><label>Solde initial<input type="number" step="0.01" name="opening_balance" value="0"></label><button class="btn primary">Créer</button></form></section><section class="card"><h2>Nouveau mouvement</h2><form method="post" action="/finance/mouvements" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Compte<select name="account_id" required>{option_rows(accounts,lambda x:x.id,lambda x:f'{x.code} · {x.name}')}</select></label><label>Date<input type="date" name="date_operation" value="{date.today().isoformat()}"></label><label>Sens<select name="direction"><option>Entrée</option><option>Sortie</option></select></label><label>Catégorie<input name="category" value="Autre"></label><label class="full">Libellé<input name="label" required></label><label>Montant<input type="number" step="0.01" min="0" name="amount" required></label><label>Tiers<input name="counterparty"></label><label><input type="checkbox" name="reconciled" value="1" style="width:auto"> Rapproché</label><button class="btn primary">Enregistrer</button></form></section></div><section class="card"><div class="scroll"><table><tr><th>Date</th><th>Référence</th><th>Compte</th><th>Sens</th><th>Libellé</th><th>Montant</th><th>Rapproché</th></tr>{trs or '<tr><td colspan=7>Aucun mouvement.</td></tr>'}</table></div></section>'''
    return page(request,u,'Finance & trésorerie',body)

@app.post('/finance/comptes')
def finance_account_add(request:Request,code:str=Form(...),name:str=Form(...),account_type:str=Form('Banque'),opening_balance:float=Form(0),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,COMMERCIALS|MANAGERS)
    code=code.strip().upper()
    if db.scalar(select(FinanceAccount).where(FinanceAccount.code==code)):raise HTTPException(409,'Code de compte déjà utilisé')
    db.add(FinanceAccount(code=code,name=name.strip(),account_type=account_type,opening_balance=opening_balance));db.commit();return RedirectResponse('/finance?msg=Compte+créé',303)

@app.post('/finance/mouvements')
def finance_tx_add(request:Request,account_id:int=Form(...),date_operation:str=Form(...),direction:str=Form('Entrée'),category:str=Form('Autre'),label:str=Form(...),amount:float=Form(...),counterparty:str=Form(''),reconciled:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,COMMERCIALS|MANAGERS)
    if not db.get(FinanceAccount,account_id):raise HTTPException(404,'Compte introuvable')
    db.add(FinanceTransaction(reference=_ref('FIN'),account_id=account_id,date_operation=date.fromisoformat(date_operation),direction='Sortie' if direction=='Sortie' else 'Entrée',category=category.strip(),label=label.strip(),amount=max(0,float(amount)),counterparty=counterparty.strip(),reconciled=bool(reconciled),created_by=u.username));db.commit();return RedirectResponse('/finance?msg=Mouvement+enregistré',303)

@app.get('/recrutement')
def recruitment_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);positions=db.scalars(select(RecruitmentPosition).order_by(RecruitmentPosition.created_at.desc())).all();apps=db.scalars(select(RecruitmentApplicant).order_by(RecruitmentApplicant.updated_at.desc())).all();token=csrf_token(request);stages=['Nouveau','Qualification','Entretien','Proposition','Embauché','Refusé']
    cols=[]
    for stage in stages:
        cards=[]
        for x in [r for r in apps if r.stage==stage]:
            pos=db.get(RecruitmentPosition,x.position_id) if x.position_id else None
            cards.append(f'<div class="kanban-card"><h3>{escape(x.name)}</h3><div class="kanban-meta"><span>{escape(pos.title if pos else "Sans poste")}</span><span>score {x.score}/100</span><span>{escape(x.source)}</span></div><form method="post" action="/recrutement/candidats/{x.id}/etape" class="inline-form"><input type="hidden" name="csrf_token" value="{token}"><select name="stage">{"".join(f"<option {'selected' if s==x.stage else ''}>{s}</option>" for s in stages)}</select><button class="btn small">Déplacer</button></form></div>')
        cols.append(f'<div class="kanban-col"><div class="kanban-col-title">{escape(stage)} <span>{len(cards)}</span></div>{"".join(cards) or "<div class=\"muted\">Aucun candidat</div>"}</div>')
    body=f'''<div class="head"><div><h1>Recrutement</h1><p class="muted">Postes ouverts et pipeline de candidatures.</p></div></div><div class="g2"><section class="card"><h2>Nouveau poste</h2><form method="post" action="/recrutement/postes" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Titre<input name="title" required></label><label>Service<input name="department"></label><label>Lieu<input name="location"></label><label>Contrat<select name="contract_type"><option>CDI</option><option>CDD</option><option>Alternance</option><option>Stage</option><option>Freelance</option></select></label><label>Recruteur<input name="recruiter" value="{escape(u.username)}"></label><label class="full">Description<textarea name="description"></textarea></label><button class="btn primary">Ouvrir le poste</button></form></section><section class="card"><h2>Nouvelle candidature</h2><form method="post" action="/recrutement/candidats" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Nom<input name="name" required></label><label>Poste<select name="position_id">{option_rows(positions,lambda x:x.id,lambda x:x.title,empty='Sans poste')}</select></label><label>E-mail<input type="email" name="email"></label><label>Téléphone<input name="phone"></label><label>Source<input name="source" value="Direct"></label><label>Score /100<input type="number" min="0" max="100" name="score" value="0"></label><label class="full">Notes<textarea name="notes"></textarea></label><button class="btn primary">Ajouter</button></form></section></div><section class="card"><h2>Postes</h2><div class="scroll"><table><tr><th>Poste</th><th>Service</th><th>Lieu</th><th>Contrat</th><th>Recruteur</th><th>Statut</th></tr>{''.join(f'<tr><td>{escape(x.title)}</td><td>{escape(x.department)}</td><td>{escape(x.location)}</td><td>{escape(x.contract_type)}</td><td>{escape(x.recruiter)}</td><td>{badge(x.status)}</td></tr>' for x in positions) or '<tr><td colspan=6>Aucun poste.</td></tr>'}</table></div></section><div class="kanban">{"".join(cols)}</div>'''
    return page(request,u,'Recrutement',body)

@app.post('/recrutement/postes')
def recruitment_position_add(request:Request,title:str=Form(...),department:str=Form(''),location:str=Form(''),contract_type:str=Form('CDI'),recruiter:str=Form(''),description:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);db.add(RecruitmentPosition(title=title.strip(),department=department.strip(),location=location.strip(),contract_type=contract_type,recruiter=recruiter.strip() or u.username,description=description.strip()));db.commit();return RedirectResponse('/recrutement?msg=Poste+créé',303)

@app.post('/recrutement/candidats')
def recruitment_applicant_add(request:Request,name:str=Form(...),position_id:str=Form(''),email:str=Form(''),phone:str=Form(''),source:str=Form('Direct'),score:int=Form(0),notes:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);db.add(RecruitmentApplicant(name=name.strip(),position_id=int(position_id) if position_id else None,email=email.strip(),phone=phone.strip(),source=source.strip(),score=max(0,min(100,score)),notes=notes.strip()));db.commit();return RedirectResponse('/recrutement?msg=Candidat+ajouté',303)

@app.post('/recrutement/candidats/{aid}/etape')
def recruitment_stage(aid:int,request:Request,stage:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);row=db.get(RecruitmentApplicant,aid)
    if not row:raise HTTPException(404,'Candidat introuvable')
    if stage not in ['Nouveau','Qualification','Entretien','Proposition','Embauché','Refusé']:raise HTTPException(400,'Étape invalide')
    row.stage=stage;row.updated_at=datetime.utcnow();db.commit();return RedirectResponse('/recrutement',303)

def _leave_days(row):
    return max(0,(row.date_fin-row.date_debut).days+1) if row.date_fin and row.date_debut else 0

@app.get('/conges')
def leave_center(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);employees=db.scalars(select(EmployeeProfile).where(EmployeeProfile.actif.is_(True)).order_by(EmployeeProfile.nom)).all();requests_=db.scalars(select(LeaveRequest).order_by(LeaveRequest.created_at.desc()).limit(300)).all();allocs=db.scalars(select(LeaveAllocation).order_by(LeaveAllocation.year.desc())).all();token=csrf_token(request);year=date.today().year
    rows=[]
    for e in employees:
        alloc=sum(float(x.allocated_days or 0) for x in allocs if x.employee_id==e.id and x.year==year)
        approved=sum(_leave_days(x) for x in requests_ if x.employee_id==e.id and x.statut=='Approuvé' and x.date_debut.year==year)
        pending=sum(_leave_days(x) for x in requests_ if x.employee_id==e.id and x.statut=='À approuver' and x.date_debut.year==year)
        rows.append(f'<tr><td>{escape(e.nom)}</td><td>{alloc:.1f} j</td><td>{approved:.1f} j</td><td>{pending:.1f} j</td><td><b>{alloc-approved:.1f} j</b></td></tr>')
    reqtrs=''.join(f'<tr><td>{escape((db.get(EmployeeProfile,x.employee_id).nom if db.get(EmployeeProfile,x.employee_id) else "—"))}</td><td>{escape(x.type_conge)}</td><td>{dfr(x.date_debut)} → {dfr(x.date_fin)}</td><td>{_leave_days(x)} j</td><td>{badge(x.statut)}</td><td>{f"<form method=post action=/conges/{x.id}/decision class=inline-form><input type=hidden name=csrf_token value={token}><button class=\"btn small\" name=decision value=Approuvé>Approuver</button><button class=\"btn small dangerbtn\" name=decision value=Refusé>Refuser</button></form>" if u.role in MANAGERS and x.statut=="À approuver" else "—"}</td></tr>' for x in requests_)
    body=f'''<div class="head"><div><h1>Congés</h1><p class="muted">Allocations, demandes et soldes indicatifs par employé.</p></div></div><div class="g2"><section class="card"><h2>Nouvelle allocation</h2><form method="post" action="/conges/allocations" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Employé<select name="employee_id">{option_rows(employees,lambda x:x.id,lambda x:x.nom)}</select></label><label>Année<input type="number" name="year" value="{year}"></label><label>Type<input name="leave_type" value="Congé payé"></label><label>Jours alloués<input type="number" step="0.5" min="0" name="allocated_days" required></label><button class="btn primary">Allouer</button></form></section><section class="card"><h2>Demande de congé</h2><form method="post" action="/conges/demande" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Employé<select name="employee_id">{option_rows(employees,lambda x:x.id,lambda x:x.nom)}</select></label><label>Type<input name="type_conge" value="Congé payé"></label><label>Du<input type="date" name="date_debut" required></label><label>Au<input type="date" name="date_fin" required></label><label class="full">Motif<textarea name="motif"></textarea></label><button class="btn primary">Soumettre</button></form></section></div><section class="card"><h2>Soldes {year}</h2><div class="scroll"><table><tr><th>Employé</th><th>Alloué</th><th>Approuvé</th><th>En attente</th><th>Solde indicatif</th></tr>{''.join(rows) or '<tr><td colspan=5>Aucun employé.</td></tr>'}</table></div></section><section class="card"><h2>Demandes</h2><div class="scroll"><table><tr><th>Employé</th><th>Type</th><th>Période</th><th>Jours</th><th>Statut</th><th>Action</th></tr>{reqtrs or '<tr><td colspan=6>Aucune demande.</td></tr>'}</table></div></section>'''
    return page(request,u,'Congés',body)

@app.post('/conges/allocations')
def leave_alloc_add(request:Request,employee_id:int=Form(...),year:int=Form(...),leave_type:str=Form('Congé payé'),allocated_days:float=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);db.add(LeaveAllocation(employee_id=employee_id,year=year,leave_type=leave_type.strip(),allocated_days=max(0,allocated_days)));db.commit();return RedirectResponse('/conges?msg=Allocation+enregistrée',303)

@app.post('/conges/demande')
def leave_request_add(request:Request,employee_id:int=Form(...),type_conge:str=Form('Congé payé'),date_debut:str=Form(...),date_fin:str=Form(...),motif:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);require_login(request,db);d1=date.fromisoformat(date_debut);d2=date.fromisoformat(date_fin)
    if d2<d1:raise HTTPException(400,'La date de fin doit être après la date de début')
    db.add(LeaveRequest(employee_id=employee_id,type_conge=type_conge.strip(),date_debut=d1,date_fin=d2,motif=motif.strip(),statut='À approuver'));db.commit();return RedirectResponse('/conges?msg=Demande+envoyée',303)

@app.post('/conges/{lid}/decision')
def leave_decide(lid:int,request:Request,decision:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);row=db.get(LeaveRequest,lid)
    if not row:raise HTTPException(404,'Demande introuvable')
    if decision not in ('Approuvé','Refusé'):raise HTTPException(400,'Décision invalide')
    row.statut=decision;db.commit();return RedirectResponse('/conges',303)

@app.get('/campagnes')
def campaigns_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(MarketingCampaign).order_by(MarketingCampaign.created_at.desc())).all();token=csrf_token(request);cards=[]
    for x in rows:
        count=db.scalar(select(func.count(MarketingRecipient.id)).where(MarketingRecipient.campaign_id==x.id)) or 0;prepared=db.scalar(select(func.count(MarketingRecipient.id)).where(MarketingRecipient.campaign_id==x.id,MarketingRecipient.status=='Brouillon créé')) or 0
        cards.append(f'<div class="kanban-card"><h3>{escape(x.reference)} · {escape(x.name)}</h3><div class="kanban-meta"><span>{badge(x.status)}</span><span>{count} destinataire(s)</span><span>{prepared} brouillon(s)</span></div><p>{escape(x.subject)}</p><form method="post" action="/campagnes/{x.id}/destinataires" class="inline-form"><input type="hidden" name="csrf_token" value="{token}"><button class="btn small">Préparer destinataires</button></form><form method="post" action="/campagnes/{x.id}/brouillons" class="inline-form"><input type="hidden" name="csrf_token" value="{token}"><button class="btn small primary">Créer les brouillons e-mail</button></form></div>')
    body=f'''<div class="head"><div><h1>Campagnes</h1><p class="muted">Segmentation et préparation de brouillons à vérifier avant envoi. NOX-IA ne lance pas de mailing de masse automatiquement.</p></div></div><section class="card"><details><summary>+ Nouvelle campagne</summary><form method="post" action="/campagnes" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Nom<input name="name" required></label><label>Segment<select name="segment"><option>Clients actifs</option><option>Contacts clients</option><option>Tous contacts autorisés</option></select></label><label class="full">Sujet<input name="subject" required></label><label class="full">Message<textarea name="body" required></textarea></label><button class="btn primary">Créer</button></form></details></section><div class="kanban">{"".join(cards) or '<div class="card">Aucune campagne.</div>'}</div>'''
    return page(request,u,'Campagnes',body)

@app.post('/campagnes')
def campaign_add(request:Request,name:str=Form(...),segment:str=Form('Clients actifs'),subject:str=Form(...),body:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,COMMERCIALS|MANAGERS);db.add(MarketingCampaign(reference=_ref('MKT'),name=name.strip(),segment=segment,subject=subject.strip(),body=body.strip(),created_by=u.username));db.commit();return RedirectResponse('/campagnes?msg=Campagne+créée',303)

@app.post('/campagnes/{cid}/destinataires')
def campaign_prepare(cid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,COMMERCIALS|MANAGERS);c=db.get(MarketingCampaign,cid)
    if not c:raise HTTPException(404,'Campagne introuvable')
    existing={x.email.lower() for x in db.scalars(select(MarketingRecipient).where(MarketingRecipient.campaign_id==cid)).all() if x.email};candidates=[]
    if c.segment in ('Clients actifs','Tous contacts autorisés'):
        candidates += [(x.nom,x.email) for x in db.scalars(select(Client).where(Client.actif.is_(True))).all() if x.email]
    if c.segment in ('Contacts clients','Tous contacts autorisés'):
        candidates += [(x.name,x.email) for x in db.scalars(select(BusinessContact).where(BusinessContact.active.is_(True))).all() if x.email]
    for name,email in candidates:
        e=email.strip().lower()
        if e and e not in existing:db.add(MarketingRecipient(campaign_id=cid,name=name,email=email.strip()));existing.add(e)
    c.status='Destinataires prêts';db.commit();return RedirectResponse('/campagnes?msg=Destinataires+préparés',303)

@app.post('/campagnes/{cid}/brouillons')
def campaign_drafts(cid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,COMMERCIALS|MANAGERS);c=db.get(MarketingCampaign,cid)
    if not c:raise HTTPException(404,'Campagne introuvable')
    rows=db.scalars(select(MarketingRecipient).where(MarketingRecipient.campaign_id==cid)).all();made=0
    for r in rows:
        if r.business_email_id:continue
        em=BusinessEmail(destinataire=r.email,sujet=c.subject,corps=c.body,related_type='Campagne',related_id=c.id,statut='Brouillon',created_by=u.username);db.add(em);db.flush();r.business_email_id=em.id;r.status='Brouillon créé';made+=1
    c.status='Brouillons prêts';db.commit();return RedirectResponse(f'/campagnes?msg={made}+brouillon(s)+créé(s)',303)

def _parse_form_fields(raw):
    fields=[]
    for part in [x.strip() for x in re.split(r'[;\n]+',raw or '') if x.strip()]:
        if '|' in part:label,typ=part.split('|',1)
        else:label,typ=part,'text'
        typ=typ.strip().lower()
        if typ not in ('text','email','number','date','textarea','checkbox'):typ='text'
        fields.append({'name':f'f{len(fields)+1}','label':label.strip()[:160],'type':typ})
        if len(fields)>=30:break
    return fields

def _form_token_hash(token):return hashlib.sha256(token.encode('utf-8')).hexdigest()

@app.get('/formulaires')
def forms_page(request:Request,new_token:str='',db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(PublicBusinessForm).order_by(PublicBusinessForm.created_at.desc())).all();token=csrf_token(request)
    notice=''
    if new_token:
        notice=f'<section class="card"><h2>Lien public créé — copie-le maintenant</h2><div class="pre">{escape(str(request.base_url).rstrip("/")+"/f/"+new_token)}</div><p class="muted">Pour la sécurité, le jeton brut n’est pas stocké et ne pourra pas être réaffiché.</p></section>'
    cards=''.join(f'<div class="kanban-card"><h3><a href="/formulaires/{x.id}">{escape(x.name)}</a></h3><div class="kanban-meta"><span>{badge("Actif" if x.active else "Inactif")}</span><span>{db.scalar(select(func.count(PublicFormSubmission.id)).where(PublicFormSubmission.form_id==x.id)) or 0} réponse(s)</span></div><form method="post" action="/formulaires/{x.id}/regenerer" class="inline-form"><input type="hidden" name="csrf_token" value="{token}"><button class="btn small">Régénérer le lien</button></form></div>' for x in rows)
    body=f'''<div class="head"><div><h1>Formulaires</h1><p class="muted">Questionnaires publics à lien secret et collecte directe des réponses dans NOX-IA.</p></div></div>{notice}<section class="card"><form method="post" action="/formulaires" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Nom<input name="name" required></label><label class="full">Champs<textarea name="fields" placeholder="Nom|text; Email|email; Téléphone|text; Message|textarea" required></textarea></label><label class="full">Message de confirmation<input name="success_message" value="Merci, votre réponse a bien été enregistrée."></label><button class="btn primary">Créer le formulaire</button></form></section><div class="kanban">{cards or '<div class="card">Aucun formulaire.</div>'}</div>'''
    return page(request,u,'Formulaires',body)

@app.post('/formulaires')
def form_add(request:Request,name:str=Form(...),fields:str=Form(...),success_message:str=Form('Merci, votre réponse a bien été enregistrée.'),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);raw=secrets.token_urlsafe(24);parsed=_parse_form_fields(fields)
    if not parsed:raise HTTPException(400,'Ajoute au moins un champ')
    db.add(PublicBusinessForm(name=name.strip(),token_hash=_form_token_hash(raw),fields_json=json.dumps(parsed,ensure_ascii=False),success_message=success_message.strip(),created_by=u.username));db.commit();return RedirectResponse('/formulaires?new_token='+raw,303)

@app.post('/formulaires/{fid}/regenerer')
def form_regenerate(fid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);row=db.get(PublicBusinessForm,fid)
    if not row:raise HTTPException(404,'Formulaire introuvable')
    raw=secrets.token_urlsafe(24);row.token_hash=_form_token_hash(raw);row.active=True;db.commit();return RedirectResponse('/formulaires?new_token='+raw,303)

@app.get('/formulaires/{fid}')
def form_detail(fid:int,request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);row=db.get(PublicBusinessForm,fid)
    if not row:raise HTTPException(404,'Formulaire introuvable')
    subs=db.scalars(select(PublicFormSubmission).where(PublicFormSubmission.form_id==fid).order_by(PublicFormSubmission.created_at.desc())).all();fields=json.loads(row.fields_json or '[]');trs=[]
    for s in subs:
        try:data=json.loads(s.data_json or '{}')
        except:data={}
        summary=' · '.join(f'{f.get("label")}: {data.get(f.get("name"),"")}' for f in fields[:8])
        trs.append(f'<tr><td>{dfr(s.created_at)}</td><td>{escape(summary)}</td></tr>')
    return page(request,u,row.name,f'<div class="head"><div><h1>{escape(row.name)}</h1><p class="muted">{len(subs)} réponse(s)</p></div><a class="btn" href="/formulaires">Retour</a></div><section class="card"><div class="scroll"><table><tr><th>Date</th><th>Réponse</th></tr>{"".join(trs) or "<tr><td colspan=2>Aucune réponse.</td></tr>"}</table></div></section>')

@app.get('/f/{raw_token}')
def public_form(raw_token:str,request:Request,db:Session=Depends(get_db)):
    row=db.scalar(select(PublicBusinessForm).where(PublicBusinessForm.token_hash==_form_token_hash(raw_token),PublicBusinessForm.active.is_(True)))
    if not row:raise HTTPException(404,'Formulaire indisponible')
    fields=json.loads(row.fields_json or '[]');inputs=[]
    for f in fields:
        typ=f.get('type','text');name=escape(f.get('name',''));label=escape(f.get('label','Champ'))
        if typ=='textarea':control=f'<textarea name="{name}"></textarea>'
        elif typ=='checkbox':control=f'<input type="checkbox" name="{name}" value="Oui" style="width:auto">'
        else:control=f'<input type="{escape(typ)}" name="{name}">'
        inputs.append(f'<label class="full">{label}{control}</label>')
    body=f'<div class="login"><section class="card" style="width:min(720px,100%)"><h1>{escape(row.name)}</h1><form method="post" class="form">{"".join(inputs)}<button class="btn primary full">Envoyer</button></form></section></div>'
    return page(request,None,row.name,body)

@app.post('/f/{raw_token}')
async def public_form_submit(raw_token:str,request:Request,db:Session=Depends(get_db)):
    row=db.scalar(select(PublicBusinessForm).where(PublicBusinessForm.token_hash==_form_token_hash(raw_token),PublicBusinessForm.active.is_(True)))
    if not row:raise HTTPException(404,'Formulaire indisponible')
    form=await request.form();fields=json.loads(row.fields_json or '[]');payload={}
    for f in fields:
        name=f.get('name');payload[name]=str(form.get(name,'')).strip()[:4000]
    db.add(PublicFormSubmission(form_id=row.id,data_json=json.dumps(payload,ensure_ascii=False)));db.commit();return page(request,None,'Merci',f'<div class="login"><section class="card"><h1>Merci</h1><p>{escape(row.success_message)}</p></section></div>')

@app.get('/catalogue-en-ligne')
def online_catalog_admin(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);items=db.scalars(select(CommercialCatalogItem).where(CommercialCatalogItem.actif.is_(True)).order_by(CommercialCatalogItem.designation)).all();pubs=db.scalars(select(PublishedCatalogItem).order_by(PublishedCatalogItem.updated_at.desc())).all();token=csrf_token(request)
    trs=''.join(f'<tr><td>{escape(x.public_name)}</td><td>{money(x.public_price)}</td><td>{badge("Publié" if x.active else "Masqué")}</td><td>{escape(x.slug)}</td></tr>' for x in pubs)
    body=f'''<div class="head"><div><h1>Catalogue en ligne</h1><p class="muted">Publication contrôlée du catalogue commercial. La version 7.3 n’active ni panier ni paiement en ligne.</p></div><a class="btn" href="/catalogue-public" target="_blank">Voir le catalogue public</a></div><section class="card"><form method="post" action="/catalogue-en-ligne" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Article<select name="catalog_item_id">{option_rows(items,lambda x:x.id,lambda x:f'{x.code} · {x.designation}')}</select></label><label>Nom public<input name="public_name" required></label><label>Prix public<input type="number" step="0.01" min="0" name="public_price" required></label><label><input type="checkbox" name="featured" value="1" style="width:auto"> Mis en avant</label><label class="full">Description<textarea name="description"></textarea></label><button class="btn primary">Publier</button></form></section><section class="card"><div class="scroll"><table><tr><th>Article</th><th>Prix</th><th>État</th><th>Slug</th></tr>{trs or '<tr><td colspan=4>Aucun article publié.</td></tr>'}</table></div></section>'''
    return page(request,u,'Catalogue en ligne',body)

@app.post('/catalogue-en-ligne')
def online_catalog_publish(request:Request,catalog_item_id:int=Form(...),public_name:str=Form(...),public_price:float=Form(...),description:str=Form(''),featured:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,COMMERCIALS|MANAGERS);item=db.get(CommercialCatalogItem,catalog_item_id)
    if not item:raise HTTPException(404,'Article catalogue introuvable')
    base=_slugify(public_name);slug=base;n=2
    while db.scalar(select(PublishedCatalogItem).where(PublishedCatalogItem.slug==slug)):slug=f'{base}-{n}';n+=1
    db.add(PublishedCatalogItem(catalog_item_id=item.id,slug=slug,public_name=public_name.strip(),description=description.strip(),public_price=max(0,public_price),featured=bool(featured),active=True));db.commit();return RedirectResponse('/catalogue-en-ligne?msg=Article+publié',303)

@app.get('/catalogue-public')
def online_catalog_public(request:Request,db:Session=Depends(get_db)):
    rows=db.scalars(select(PublishedCatalogItem).where(PublishedCatalogItem.active.is_(True)).order_by(PublishedCatalogItem.featured.desc(),PublishedCatalogItem.public_name)).all();cards=''.join(f'<section class="card"><h2>{escape(x.public_name)}</h2><p>{escape(x.description)}</p><strong style="font-size:24px">{money(x.public_price)}</strong></section>' for x in rows)
    return page(request,None,'Catalogue',f'<div class="wrap"><div class="head"><div><h1>Catalogue NOXIA</h1><p class="muted">Catalogue public informatif. Prix et disponibilité à confirmer lors du devis.</p></div></div><div class="g2">{cards or "<section class=\"card\">Aucun article publié.</section>"}</div></div>')

@app.get('/studio/vues')
def saved_views_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(SavedBusinessView).where(SavedBusinessView.active.is_(True)).order_by(SavedBusinessView.created_at.desc())).all();rows=[x for x in rows if x.shared or x.created_by==u.username or u.role in MANAGERS];token=csrf_token(request)
    trs=''.join(f'<tr><td>{escape(x.name)}</td><td>{escape(x.model)}</td><td>{escape(x.filter_text)}</td><td>{escape(x.columns_text)}</td><td>{escape(x.created_by)}</td><td>{"Partagée" if x.shared else "Personnelle"}</td></tr>' for x in rows)
    body=f'''<div class="head"><div><h1>Vues personnalisées</h1><p class="muted">Préréglages de filtres et colonnes pour standardiser les vues métier.</p></div><a class="btn" href="/studio">Studio</a></div><section class="card"><form method="post" action="/studio/vues" class="form"><input type="hidden" name="csrf_token" value="{token}"><label>Nom<input name="name" required></label><label>Modèle<input name="model" placeholder="Intervention, Client, Devis…" required></label><label class="full">Filtre<input name="filter_text" placeholder="ex. statut=En cours; priorité=Urgente"></label><label class="full">Colonnes<input name="columns_text" placeholder="Référence; Client; Statut; Responsable"></label><label><input type="checkbox" name="shared" value="1" style="width:auto"> Partager avec l’équipe</label><button class="btn primary">Enregistrer</button></form></section><section class="card"><div class="scroll"><table><tr><th>Nom</th><th>Modèle</th><th>Filtre</th><th>Colonnes</th><th>Auteur</th><th>Visibilité</th></tr>{trs or '<tr><td colspan=6>Aucune vue enregistrée.</td></tr>'}</table></div></section>'''
    return page(request,u,'Vues personnalisées',body)

@app.post('/studio/vues')
def saved_view_add(request:Request,name:str=Form(...),model:str=Form(...),filter_text:str=Form(''),columns_text:str=Form(''),shared:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);db.add(SavedBusinessView(name=name.strip(),model=model.strip(),filter_text=filter_text.strip(),columns_text=columns_text.strip(),created_by=u.username,shared=bool(shared)));db.commit();return RedirectResponse('/studio/vues?msg=Vue+enregistrée',303)
