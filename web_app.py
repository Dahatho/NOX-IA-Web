import io, json, os, secrets
from datetime import date, datetime
from html import escape
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from web_models import (
    AlertState, AuditRun, Base, Client, Contract, Diagnostic, DiagnosticStep,
    Equipement, FollowAction, Intervention, InterventionMaterial, InterventionPhoto,
    MaintenanceHistory, MaintenancePlan, PlanningEntry, SessionLocal, Site,
    StockItem, StockMovement, Supplier, SupplierPrice, User, engine
)
from web_security import hash_password, new_csrf_token, verify_password

APP_VERSION = '3.0.0'
BASE_DIR = Path(__file__).resolve().parent
CORE_PATH = BASE_DIR / 'nox_core_catalog.json'
ROLES = ('Administrateur','Responsable','Technicien','Lecture seule')
MANAGERS = {'Administrateur','Responsable'}
TECHS = {'Administrateur','Responsable','Technicien'}

app = FastAPI(title='NOX-IA', version=APP_VERSION)
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get('SECRET_KEY', secrets.token_urlsafe(48)),
    https_only=bool(os.environ.get('RENDER')),
    same_site='lax',
)

def get_db():
    db=SessionLocal()
    try: yield db
    finally: db.close()

def current_user(request, db):
    uid=request.session.get('user_id')
    return db.get(User,int(uid)) if uid else None

def require_login(request,db):
    u=current_user(request,db)
    if not u or not u.active: raise HTTPException(401,'Connexion requise')
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
:root{--bg:#08111f;--panel:#101c2e;--panel2:#14243b;--line:#263a58;--text:#eef5ff;--muted:#9fb2ce;--accent:#51a9ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,Segoe UI,system-ui,sans-serif}a{color:inherit}
.top{position:sticky;top:0;z-index:10;background:#07101d;border-bottom:1px solid var(--line)}.topin{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:14px 22px}.brand{font-size:25px;font-weight:900}.who{display:flex;align-items:center;gap:12px;color:var(--muted)}
.nav{display:flex;gap:5px;padding:8px 18px;border-top:1px solid #112038;overflow:auto;white-space:nowrap}.nav a{text-decoration:none;padding:9px 11px;border-radius:9px;color:#d9e7f9}.nav a:hover{background:var(--panel2)}
.wrap{width:min(1540px,96%);margin:auto;padding:26px 0 70px}.head{display:flex;justify-content:space-between;align-items:center;gap:14px;flex-wrap:wrap}.muted{color:var(--muted)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:15px;padding:18px;margin:16px 0}.grid{display:grid;gap:14px}.g4{grid-template-columns:repeat(4,minmax(0,1fr))}.g2{grid-template-columns:repeat(2,minmax(0,1fr))}.metric{background:var(--panel);border:1px solid var(--line);border-radius:15px;padding:18px}.metric span{color:var(--muted)}.metric strong{display:block;font-size:30px;margin-top:6px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:650}.scroll{overflow:auto}
input,select,textarea{width:100%;border:1px solid var(--line);background:#091425;color:var(--text);padding:10px;border-radius:9px}textarea{min-height:90px;resize:vertical}label{display:grid;gap:6px;color:var(--muted)}.form{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.full{grid-column:1/-1}
.btn{display:inline-block;border:0;border-radius:9px;padding:10px 13px;background:#1b2e49;color:var(--text);font-weight:750;cursor:pointer;text-decoration:none}.primary{background:var(--accent);color:#05101b}.goodbtn{background:#174b3a}.small{padding:7px 9px;font-size:13px}.b{display:inline-block;padding:4px 8px;border:1px solid var(--line);border-radius:999px;font-size:12px}.b.good{color:#a9f5d4}.b.warn{color:#ffe2a3}.b.danger{color:#ffb9c0}.actions{display:flex;gap:8px;flex-wrap:wrap}
.login{min-height:72vh;display:grid;place-items:center}.login .card{width:min(460px,96%)}.alert{padding:10px;border:1px solid #7b3944;background:#321a22;border-radius:9px;color:#ffd6db}.kv{display:grid;grid-template-columns:190px 1fr;gap:7px 15px}.pre{white-space:pre-wrap;background:#081322;border:1px solid var(--line);border-radius:10px;padding:12px}details{border:1px solid var(--line);border-radius:11px;padding:10px;margin:10px 0;background:#0c1829}summary{cursor:pointer;font-weight:700}
@media(max-width:900px){.g4,.g2,.form{grid-template-columns:1fr}.full{grid-column:auto}.topin{align-items:flex-start;flex-direction:column}}
'''
NAV=[('/dashboard','Dashboard'),('/clients','Clients'),('/sites','Sites'),('/equipements','Équipements'),('/interventions','Interventions'),('/planning','Planning'),('/stock','Stock'),('/fournisseurs','Fournisseurs'),('/maintenance','Maintenance'),('/contrats','Contrats'),('/alertes','Alertes'),('/actions','Actions'),('/nox-core','NOX-Core'),('/diagnostics','Diagnostics'),('/utilisateurs','Utilisateurs'),('/sante','Santé / Audit')]

def page(request,user,title,body):
    nav=who=''
    if user:
        nav='<nav class="nav">'+''.join(f'<a href="{h}">{escape(l)}</a>' for h,l in NAV)+'</nav>'
        who=f'<div class="who"><span>{escape(user.username)} · {escape(user.role)}</span><form method="post" action="/logout"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn small">Se déconnecter</button></form></div>'
    return HTMLResponse(f'<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{escape(title)} · NOX-IA</title><style>{CSS}</style></head><body><header class="top"><div class="topin"><div class="brand">NOX-IA</div>{who}</div>{nav}</header><main class="wrap">{body}</main></body></html>')

def option_rows(rows,value_fn,label_fn,selected=None,empty=None):
    parts=[]
    if empty is not None: parts.append(f'<option value="">{escape(empty)}</option>')
    for r in rows:
        v=value_fn(r); sel=' selected' if str(v)==str(selected) else ''
        parts.append(f'<option value="{escape(str(v))}"{sel}>{escape(label_fn(r))}</option>')
    return ''.join(parts)

def add_months(d,months):
    y=d.year+(d.month-1+months)//12; m=(d.month-1+months)%12+1
    md=[31,29 if y%4==0 and (y%100!=0 or y%400==0) else 28,31,30,31,30,31,31,30,31,30,31][m-1]
    return date(y,m,min(d.day,md))

def core_catalog():
    try:return json.loads(CORE_PATH.read_text(encoding='utf-8')).get('fiches',[])
    except:return []

def core_meta(item):
    d=item.get('data') or {}
    def first(*ks):
        for k in ks:
            if d.get(k) not in (None,'',[]): return d.get(k)
        return ''
    return tuple(str(x) for x in (first('titre','title','nom','logiciel','procedure') or item.get('source_file','Fiche'), first('constructeur','fabricant','marque','manufacturer'), first('type_fiche','type','categorie','catégorie'), first('resume','résumé','description','probleme','symptome','objet')))

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
    for s in db.scalars(select(StockItem).where(StockItem.actif.is_(True))).all():
        if s.quantite<=0:a.append(('critique','Stock',f'stock:{s.id}',f'Rupture {s.designation}',s.reference))
        elif s.quantite<=s.seuil_alerte:a.append(('avertissement','Stock',f'stock:{s.id}',f'Stock bas {s.designation}',str(s.quantite)))
    for i in db.scalars(select(Intervention).where(Intervention.statut!='Terminée')).all():
        if i.priorite in ('Urgente','Haute'):a.append(('critique' if i.priorite=='Urgente' else 'avertissement','Interventions',f'inter:{i.id}',f'Intervention #{i.id} {i.priorite}',i.probleme[:120]))
    for p in db.scalars(select(PlanningEntry).where(PlanningEntry.statut!='Terminée')).all():
        if p.debut<now:a.append(('avertissement','Planning',f'plan:{p.id}',f'Planning dépassé : {p.titre}',dfr(p.debut)))
    return a

def bootstrap_database():
    Base.metadata.create_all(bind=engine)
    username=os.environ.get('NOXIA_ADMIN_USERNAME','admin').strip() or 'admin'; password=os.environ.get('NOXIA_ADMIN_PASSWORD','').strip()
    if password:
        with SessionLocal() as db:
            if not db.scalar(select(User).where(User.username==username)):
                db.add(User(username=username,password_hash=hash_password(password),role='Administrateur',active=True));db.commit()

@app.on_event('startup')
def startup():bootstrap_database()

@app.get('/healthz')
def healthz():return {'status':'ok','app':'NOX-IA','version':APP_VERSION}

@app.get('/')
def root(request:Request):return RedirectResponse('/dashboard' if request.session.get('user_id') else '/login',303)

@app.get('/login')
def login_page(request:Request):
    body=f'<div class="login"><section class="card"><h1>NOX-IA</h1><p class="muted">Assistant technique intelligent.</p><form method="post" action="/login" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label class="full">Utilisateur<input name="username" required></label><label class="full">Mot de passe<input type="password" name="password" required></label><button class="btn primary full">Se connecter</button></form></section></div>'
    return page(request,None,'Connexion',body)

@app.post('/login')
def login_submit(request:Request,username:str=Form(...),password:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=db.scalar(select(User).where(User.username==username.strip()))
    if not u or not u.active or not verify_password(password,u.password_hash):
        body=f'<div class="login"><section class="card"><h1>NOX-IA</h1><div class="alert">Identifiant ou mot de passe incorrect.</div><form method="post" action="/login" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label class="full">Utilisateur<input name="username" required></label><label class="full">Mot de passe<input type="password" name="password" required></label><button class="btn primary full">Se connecter</button></form></section></div>'
        return page(request,None,'Connexion',body)
    request.session.clear();request.session['user_id']=u.id;request.session['csrf_token']=new_csrf_token();return RedirectResponse('/dashboard',303)

@app.post('/logout')
def logout(request:Request,csrf_token_value:str=Form(...,alias='csrf_token')):
    check_csrf(request,csrf_token_value);request.session.clear();return RedirectResponse('/login',303)

@app.get('/dashboard')
def dashboard(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db); alerts=derive_alerts(db)
    counts={'Clients':db.scalar(select(func.count(Client.id))) or 0,'Sites':db.scalar(select(func.count(Site.id))) or 0,'Équipements':db.scalar(select(func.count(Equipement.id))) or 0,'Interventions ouvertes':db.scalar(select(func.count(Intervention.id)).where(Intervention.statut!='Terminée')) or 0,'Stock bas/rupture':sum(1 for x in alerts if x[1]=='Stock'),'Maintenances à traiter':sum(1 for x in alerts if x[1]=='Maintenance'),'Contrats à traiter':sum(1 for x in alerts if x[1]=='Contrats'),'Actions ouvertes':db.scalar(select(func.count(FollowAction.id)).where(FollowAction.statut.notin_(['Terminée','Annulée']))) or 0}
    metrics=''.join(f'<div class="metric"><span>{escape(k)}</span><strong>{v}</strong></div>' for k,v in counts.items())
    rec=db.scalars(select(Intervention).order_by(Intervention.date_creation.desc()).limit(8)).all();rows=''
    for i in rec:
        s=db.get(Site,i.site_id);rows+=f'<tr><td><a href="/interventions/{i.id}">#{i.id}</a></td><td>{dfr(i.date_creation)}</td><td>{escape(s.nom if s else "—")}</td><td>{escape(i.technicien)}</td><td>{badge(i.priorite)}</td><td>{badge(i.statut)}</td></tr>'
    return page(request,u,'Dashboard',f'<h1>Dashboard</h1><div class="grid g4">{metrics}</div><section class="card"><h2>Interventions récentes</h2><div class="scroll"><table><tr><th>ID</th><th>Date</th><th>Site</th><th>Technicien</th><th>Priorité</th><th>Statut</th></tr>{rows}</table></div></section>')

@app.get('/clients')
def clients(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(Client).order_by(Client.nom)).all();trs=''.join(f'<tr><td>{c.id}</td><td>{escape(c.nom)}</td><td>{escape(c.contact)}</td><td>{escape(c.telephone)}</td><td>{escape(c.email)}</td><td>{badge("Actif" if c.actif else "Inactif")}</td></tr>' for c in rows)
    form=''
    if u.role in MANAGERS:form=f'<section class="card"><h2>Ajouter un client</h2><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Nom<input name="nom" required></label><label>Contact<input name="contact"></label><label>Téléphone<input name="telephone"></label><label>E-mail<input name="email" type="email"></label><label class="full">Notes<textarea name="notes"></textarea></label><button class="btn primary">Ajouter</button></form></section>'
    return page(request,u,'Clients',f'<h1>Clients</h1>{form}<section class="card"><table><tr><th>ID</th><th>Nom</th><th>Contact</th><th>Téléphone</th><th>E-mail</th><th>Statut</th></tr>{trs}</table></section>')

@app.post('/clients')
def clients_add(request:Request,nom:str=Form(...),contact:str=Form(''),telephone:str=Form(''),email:str=Form(''),notes:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);db.add(Client(nom=nom.strip(),contact=contact.strip(),telephone=telephone.strip(),email=email.strip(),notes=notes.strip(),actif=True));db.commit();return RedirectResponse('/clients',303)

@app.get('/sites')
def sites(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(Site).order_by(Site.nom)).all();clients_=db.scalars(select(Client).where(Client.actif.is_(True)).order_by(Client.nom)).all();trs=''
    for s in rows:
        c=db.get(Client,s.client_id);trs+=f'<tr><td>{s.id}</td><td>{escape(c.nom if c else "—")}</td><td>{escape(s.nom)}</td><td>{escape(s.ville)}</td><td>{escape(s.adresse)}</td></tr>'
    form=''
    if u.role in MANAGERS:form=f'<section class="card"><h2>Ajouter un site</h2><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Client<select name="client_id">{option_rows(clients_,lambda x:x.id,lambda x:x.nom)}</select></label><label>Nom<input name="nom" required></label><label>Adresse<input name="adresse"></label><label>Ville<input name="ville"></label><label class="full">Notes<textarea name="notes"></textarea></label><button class="btn primary">Ajouter</button></form></section>'
    return page(request,u,'Sites',f'<h1>Sites</h1>{form}<section class="card"><table><tr><th>ID</th><th>Client</th><th>Site</th><th>Ville</th><th>Adresse</th></tr>{trs}</table></section>')

@app.post('/sites')
def sites_add(request:Request,client_id:int=Form(...),nom:str=Form(...),adresse:str=Form(''),ville:str=Form(''),notes:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);db.add(Site(client_id=client_id,nom=nom.strip(),adresse=adresse.strip(),ville=ville.strip(),notes=notes.strip(),actif=True));db.commit();return RedirectResponse('/sites',303)

@app.get('/equipements')
def equipements(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(Equipement).order_by(Equipement.reference)).all();sites_=db.scalars(select(Site).where(Site.actif.is_(True)).order_by(Site.nom)).all();trs=''
    for e in rows:
        s=db.get(Site,e.site_id);c=db.get(Client,s.client_id) if s else None;trs+=f'<tr><td><a href="/equipements/{e.id}">{escape(e.reference)}</a></td><td>{escape(c.nom if c else "—")}</td><td>{escape(s.nom if s else "—")}</td><td>{escape(e.type_equipement)}</td><td>{escape(e.marque)}</td><td>{escape(e.modele)}</td><td>{escape(e.ip)}</td><td>{badge(e.statut)}</td></tr>'
    form=''
    if u.role in MANAGERS:form=f'<section class="card"><h2>Ajouter un équipement</h2><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Site<select name="site_id">{option_rows(sites_,lambda x:x.id,lambda x:x.nom)}</select></label><label>Référence<input name="reference" required></label><label>Type<input name="type_equipement" required></label><label>Marque<input name="marque"></label><label>Modèle<input name="modele"></label><label>N° série<input name="numero_serie"></label><label>IP<input name="ip"></label><label>Statut<select name="statut_equipement"><option>Actif</option><option>En panne</option><option>Hors service</option></select></label><button class="btn primary">Ajouter</button></form></section>'
    return page(request,u,'Équipements',f'<h1>Équipements</h1>{form}<section class="card"><div class="scroll"><table><tr><th>Réf</th><th>Client</th><th>Site</th><th>Type</th><th>Marque</th><th>Modèle</th><th>IP</th><th>Statut</th></tr>{trs}</table></div></section>')

@app.post('/equipements')
def equipements_add(request:Request,site_id:int=Form(...),reference:str=Form(...),type_equipement:str=Form(...),marque:str=Form(''),modele:str=Form(''),numero_serie:str=Form(''),ip:str=Form(''),statut_equipement:str=Form('Actif'),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);db.add(Equipement(site_id=site_id,reference=reference.strip(),type_equipement=type_equipement.strip(),marque=marque.strip(),modele=modele.strip(),numero_serie=numero_serie.strip(),ip=ip.strip(),statut=statut_equipement,actif=True));db.commit();return RedirectResponse('/equipements',303)

@app.get('/equipements/{eid}')
def equipement_detail(eid:int,request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);e=db.get(Equipement,eid)
    if not e:raise HTTPException(404)
    s=db.get(Site,e.site_id);c=db.get(Client,s.client_id) if s else None;ints=db.scalars(select(Intervention).where(Intervention.equipement_id==eid).order_by(Intervention.date_creation.desc())).all();diags=db.scalars(select(Diagnostic).where(Diagnostic.equipement_id==eid).order_by(Diagnostic.date_debut.desc())).all();rec={}
    for i in ints:
        k=(i.probleme or '').strip().lower()[:80]
        if k:rec[k]=rec.get(k,0)+1
    mem=''.join(f'<li>{escape(k)} — {v} occurrence(s)</li>' for k,v in sorted(rec.items(),key=lambda x:x[1],reverse=True)[:5]) or '<li>Aucune récurrence détectée.</li>'
    rows=''.join(f'<tr><td><a href="/interventions/{i.id}">#{i.id}</a></td><td>{dfr(i.date_creation)}</td><td>{escape(i.probleme[:100])}</td><td>{badge(i.statut)}</td><td>{escape(i.solution[:120])}</td></tr>' for i in ints);drows=''.join(f'<tr><td>#{d.id}</td><td>{dfr(d.date_debut)}</td><td>{escape(d.fiche_titre)}</td><td>{badge(d.statut)}</td><td>{escape(d.conclusion[:100])}</td></tr>' for d in diags)
    body=f'<h1>{escape(e.reference)}</h1><section class="card"><div class="kv"><b>Client</b><span>{escape(c.nom if c else "—")}</span><b>Site</b><span>{escape(s.nom if s else "—")}</span><b>Série</b><span>{escape(e.numero_serie)}</span><b>IP</b><span>{escape(e.ip)}</span><b>Statut</b><span>{badge(e.statut)}</span></div></section><section class="card"><h2>Mémoire technique</h2><ul>{mem}</ul></section><section class="card"><h2>Historique interventions</h2><table><tr><th>ID</th><th>Date</th><th>Problème</th><th>Statut</th><th>Solution</th></tr>{rows}</table></section><section class="card"><h2>Diagnostics</h2><table><tr><th>ID</th><th>Date</th><th>Fiche</th><th>Statut</th><th>Conclusion</th></tr>{drows}</table></section>'
    return page(request,u,'Équipement',body)

@app.get('/interventions')
def interventions(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(Intervention).order_by(Intervention.date_creation.desc())).all();sites_=db.scalars(select(Site).where(Site.actif.is_(True)).order_by(Site.nom)).all();eqs=db.scalars(select(Equipement).where(Equipement.actif.is_(True)).order_by(Equipement.reference)).all();trs=''
    for i in rows:
        s=db.get(Site,i.site_id);c=db.get(Client,s.client_id) if s else None;e=db.get(Equipement,i.equipement_id) if i.equipement_id else None;trs+=f'<tr><td><a href="/interventions/{i.id}">#{i.id}</a></td><td>{dfr(i.date_creation)}</td><td>{escape(c.nom if c else "—")}</td><td>{escape(s.nom if s else "—")}</td><td>{escape(e.reference if e else "—")}</td><td>{escape(i.technicien)}</td><td>{badge(i.priorite)}</td><td>{badge(i.statut)}</td></tr>'
    form=''
    if u.role in TECHS:form=f'<section class="card"><h2>Nouvelle intervention</h2><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Site<select name="site_id">{option_rows(sites_,lambda x:x.id,lambda x:x.nom)}</select></label><label>Équipement<select name="equipement_id">{option_rows(eqs,lambda x:x.id,lambda x:f"{x.reference} · {x.type_equipement}",empty="Aucun")}</select></label><label>Technicien<input name="technicien" value="{escape(u.username)}"></label><label>Type<select name="type_intervention"><option>Dépannage</option><option>Maintenance</option><option>Installation</option><option>Mise en service</option></select></label><label>Priorité<select name="priorite"><option>Basse</option><option selected>Normale</option><option>Haute</option><option>Urgente</option></select></label><label class="full">Problème<textarea name="probleme" required></textarea></label><button class="btn primary">Créer</button></form></section>'
    return page(request,u,'Interventions',f'<h1>Interventions</h1>{form}<section class="card"><div class="scroll"><table><tr><th>ID</th><th>Date</th><th>Client</th><th>Site</th><th>Équipement</th><th>Technicien</th><th>Priorité</th><th>Statut</th></tr>{trs}</table></div></section>')

@app.post('/interventions')
def interventions_add(request:Request,site_id:int=Form(...),equipement_id:str=Form(''),technicien:str=Form(...),type_intervention:str=Form('Dépannage'),priorite:str=Form('Normale'),probleme:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,TECHS);eid=int(equipement_id) if equipement_id else None;i=Intervention(site_id=site_id,equipement_id=eid,technicien=technicien.strip(),type_intervention=type_intervention,priorite=priorite,probleme=probleme.strip(),statut='À faire');db.add(i);db.commit();db.refresh(i);return RedirectResponse(f'/interventions/{i.id}',303)

@app.get('/interventions/{iid}')
def intervention_detail(iid:int,request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);i=db.get(Intervention,iid)
    if not i:raise HTTPException(404)
    s=db.get(Site,i.site_id);c=db.get(Client,s.client_id) if s else None;e=db.get(Equipement,i.equipement_id) if i.equipement_id else None;stocks=db.scalars(select(StockItem).where(StockItem.actif.is_(True)).order_by(StockItem.designation)).all();mats=db.scalars(select(InterventionMaterial).where(InterventionMaterial.intervention_id==iid)).all();photos=db.scalars(select(InterventionPhoto).where(InterventionPhoto.intervention_id==iid)).all();diags=db.scalars(select(Diagnostic).where(Diagnostic.intervention_id==iid).order_by(Diagnostic.date_debut.desc())).all()
    mrows=''.join(f'<tr><td>{escape((db.get(StockItem,m.stock_item_id).reference if db.get(StockItem,m.stock_item_id) else "—"))}</td><td>{escape((db.get(StockItem,m.stock_item_id).designation if db.get(StockItem,m.stock_item_id) else "—"))}</td><td>{m.quantite}</td></tr>' for m in mats);ph=''.join(f'<a class="btn small" href="/photos/{p.id}" target="_blank">{escape(p.filename)}</a>' for p in photos) or 'Aucune photo';drows=''.join(f'<tr><td><a href="/diagnostics/{d.id}">#{d.id}</a></td><td>{dfr(d.date_debut)}</td><td>{escape(d.fiche_titre)}</td><td>{badge(d.statut)}</td></tr>' for d in diags)
    edit=''
    if u.role in TECHS and i.statut!='Terminée':
        edit=f'<section class="card"><h2>Travail intervention</h2><form method="post" action="/interventions/{iid}/modifier" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Priorité<select name="priorite"><option>{escape(i.priorite)}</option><option>Basse</option><option>Normale</option><option>Haute</option><option>Urgente</option></select></label><label>Statut<select name="statut"><option>{escape(i.statut)}</option><option>À faire</option><option>En cours</option><option>En attente</option></select></label><label class="full">Problème<textarea name="probleme">{escape(i.probleme)}</textarea></label><label class="full">Actions réalisées<textarea name="actions_realisees">{escape(i.actions_realisees)}</textarea></label><label class="full">Solution<textarea name="solution">{escape(i.solution)}</textarea></label><button class="btn primary">Enregistrer</button></form></section><section class="card"><h2>Matériel / installation</h2><form method="post" action="/interventions/{iid}/materiel" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Article<select name="stock_item_id">{option_rows(stocks,lambda x:x.id,lambda x:f"{x.reference} · {x.designation} · stock {x.quantite}")}</select></label><label>Quantité<input type="number" min="1" name="quantite" value="1"></label><button class="btn primary">Utiliser</button></form></section><section class="card"><h2>Photo</h2><form method="post" action="/interventions/{iid}/photo" enctype="multipart/form-data" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Image<input type="file" accept="image/*" name="file" required></label><label>Commentaire<input name="commentaire"></label><button class="btn primary">Ajouter</button></form></section>'
    controls=''
    if i.statut!='Terminée' and u.role in TECHS:controls=f'<form method="post" action="/interventions/{iid}/cloturer"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn goodbtn">✅ Terminer</button></form>'
    elif i.statut=='Terminée' and u.role in MANAGERS:controls=f'<form method="post" action="/interventions/{iid}/rouvrir"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn">↻ Rouvrir</button></form>'
    body=f'<div class="head"><div><h1>Intervention #{iid}</h1><p class="muted">{escape(c.nom if c else "—")} · {escape(s.nom if s else "—")} · {escape(e.reference if e else "sans équipement")}</p></div><div class="actions"><a class="btn" href="/interventions/{iid}/rapport/client">PDF client</a><a class="btn" href="/interventions/{iid}/rapport/technique">PDF technique</a><a class="btn" href="/nox-core?intervention_id={iid}">NOX-Core</a>{controls}</div></div><section class="card"><div class="kv"><b>Date</b><span>{dfr(i.date_creation)}</span><b>Technicien</b><span>{escape(i.technicien)}</span><b>Priorité</b><span>{badge(i.priorite)}</span><b>Statut</b><span>{badge(i.statut)}</span></div><h3>Problème</h3><div class="pre">{escape(i.probleme)}</div><h3>Actions</h3><div class="pre">{escape(i.actions_realisees)}</div><h3>Solution</h3><div class="pre">{escape(i.solution)}</div></section>{edit}<section class="card"><h2>Matériel</h2><table><tr><th>Réf</th><th>Désignation</th><th>Qté</th></tr>{mrows}</table></section><section class="card"><h2>Photos</h2><div class="actions">{ph}</div></section><section class="card"><h2>Diagnostics</h2><a class="btn primary" href="/diagnostics/nouveau?intervention_id={iid}">Nouveau diagnostic</a><table><tr><th>ID</th><th>Date</th><th>Fiche</th><th>Statut</th></tr>{drows}</table></section>'
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

@app.get('/planning')
def planning(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(PlanningEntry).order_by(PlanningEntry.debut.desc())).all();ints=db.scalars(select(Intervention).where(Intervention.statut!='Terminée').order_by(Intervention.id.desc())).all();trs=''.join(f'<tr><td>{p.id}</td><td>{dfr(p.debut)}</td><td>{dfr(p.fin)}</td><td>{escape(p.titre)}</td><td>{escape(p.technicien)}</td><td>{badge(p.statut)}</td><td>{f"<a href=/interventions/{p.intervention_id}>#{p.intervention_id}</a>" if p.intervention_id else "—"}</td></tr>' for p in rows);form=''
    if u.role in MANAGERS:form=f'<section class="card"><h2>Planifier</h2><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Intervention<select name="intervention_id">{option_rows(ints,lambda x:x.id,lambda x:f"#{x.id} · {x.probleme[:60]}",empty="Aucune")}</select></label><label>Titre<input name="titre" required></label><label>Technicien<input name="technicien"></label><label>Début<input type="datetime-local" name="debut" required></label><label>Fin<input type="datetime-local" name="fin"></label><button class="btn primary">Ajouter</button></form></section>'
    return page(request,u,'Planning',f'<h1>Planning</h1>{form}<section class="card"><table><tr><th>ID</th><th>Début</th><th>Fin</th><th>Titre</th><th>Technicien</th><th>Statut</th><th>Intervention</th></tr>{trs}</table></section>')

@app.post('/planning')
def planning_add(request:Request,titre:str=Form(...),technicien:str=Form(''),debut:str=Form(...),fin:str=Form(''),intervention_id:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);db.add(PlanningEntry(intervention_id=int(intervention_id) if intervention_id else None,technicien=technicien.strip(),titre=titre.strip(),debut=datetime.fromisoformat(debut),fin=datetime.fromisoformat(fin) if fin else None,statut='Prévu',notes=''));db.commit();return RedirectResponse('/planning',303)

@app.get('/stock')
def stock(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);items=db.scalars(select(StockItem).order_by(StockItem.designation)).all();trs=''.join(f'<tr><td>{escape(s.reference)}</td><td>{escape(s.designation)}</td><td>{escape(s.type_article)}</td><td>{escape(s.marque)}</td><td>{s.quantite}</td><td>{s.seuil_alerte}</td><td>{money(s.prix_achat)}</td><td>{badge("Rupture" if s.quantite<=0 else "Stock bas" if s.quantite<=s.seuil_alerte else "OK")}</td></tr>' for s in items);form=''
    if u.role in MANAGERS:form=f'<section class="card"><h2>Ajouter un article</h2><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Référence<input name="reference" required></label><label>Désignation<input name="designation" required></label><label>Type<select name="type_article"><option>Consommable</option><option>Équipement</option><option>Accessoire</option></select></label><label>Marque<input name="marque"></label><label>Modèle<input name="modele"></label><label>Quantité<input type="number" name="quantite" value="0"></label><label>Seuil<input type="number" name="seuil_alerte" value="1"></label><label>Prix achat<input type="number" step=".01" name="prix_achat" value="0"></label><button class="btn primary">Ajouter</button></form></section>'
    return page(request,u,'Stock',f'<h1>Stock & Matériel</h1>{form}<section class="card"><table><tr><th>Réf</th><th>Désignation</th><th>Type</th><th>Marque</th><th>Qté</th><th>Seuil</th><th>Prix</th><th>État</th></tr>{trs}</table></section>')

@app.post('/stock')
def stock_add(request:Request,reference:str=Form(...),designation:str=Form(...),type_article:str=Form('Consommable'),marque:str=Form(''),modele:str=Form(''),quantite:int=Form(0),seuil_alerte:int=Form(1),prix_achat:float=Form(0),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);o=StockItem(reference=reference.strip(),designation=designation.strip(),type_article=type_article,marque=marque.strip(),modele=modele.strip(),quantite=quantite,seuil_alerte=seuil_alerte,prix_achat=prix_achat,actif=True);db.add(o);db.commit();db.refresh(o);db.add(StockMovement(stock_item_id=o.id,utilisateur=u.username,type_mouvement='Stock initial',quantite=quantite,commentaire=''));db.commit();return RedirectResponse('/stock',303)

@app.get('/fournisseurs')
def suppliers(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);sups=db.scalars(select(Supplier).order_by(Supplier.nom)).all();items=db.scalars(select(StockItem).order_by(StockItem.designation)).all();prices=db.scalars(select(SupplierPrice).order_by(SupplierPrice.date_prix.desc())).all();trs=''
    for p in prices:
        s=db.get(Supplier,p.supplier_id);i=db.get(StockItem,p.stock_item_id);trs+=f'<tr><td>{escape(s.nom if s else "—")}</td><td>{escape(i.designation if i else "—")}</td><td>{money(p.prix)}</td><td>{dfr(p.date_prix)}</td></tr>'
    form=''
    if u.role in MANAGERS:form=f'<section class="card"><h2>Fournisseur</h2><form method="post" action="/fournisseurs/ajouter" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Nom<input name="nom" required></label><label>Contact<input name="contact"></label><label>E-mail<input name="email"></label><label>Téléphone<input name="telephone"></label><button class="btn primary">Ajouter</button></form></section><section class="card"><h2>Prix fournisseur</h2><form method="post" action="/fournisseurs/prix" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Fournisseur<select name="supplier_id">{option_rows(sups,lambda x:x.id,lambda x:x.nom)}</select></label><label>Article<select name="stock_item_id">{option_rows(items,lambda x:x.id,lambda x:f"{x.reference} · {x.designation}")}</select></label><label>Prix<input type="number" step=".01" name="prix" required></label><button class="btn primary">Enregistrer</button></form></section>'
    return page(request,u,'Fournisseurs',f'<h1>Fournisseurs & Prix</h1>{form}<section class="card"><table><tr><th>Fournisseur</th><th>Article</th><th>Prix</th><th>Date</th></tr>{trs}</table></section>')

@app.post('/fournisseurs/ajouter')
def supplier_add(request:Request,nom:str=Form(...),contact:str=Form(''),email:str=Form(''),telephone:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);db.add(Supplier(nom=nom.strip(),contact=contact.strip(),email=email.strip(),telephone=telephone.strip(),site_web='',actif=True));db.commit();return RedirectResponse('/fournisseurs',303)

@app.post('/fournisseurs/prix')
def supplier_price(request:Request,supplier_id:int=Form(...),stock_item_id:int=Form(...),prix:float=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS);db.add(SupplierPrice(supplier_id=supplier_id,stock_item_id=stock_item_id,prix=prix));db.commit();return RedirectResponse('/fournisseurs',303)

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

@app.get('/nox-core')
def nox_core(request:Request,q:str='',intervention_id:int|None=None,db:Session=Depends(get_db)):
    u=require_login(request,db);fiches=core_catalog();qn=q.strip().lower()
    if qn:fiches=[x for x in fiches if qn in json.dumps(x,ensure_ascii=False).lower()]
    cards=''
    for item in fiches[:80]:
        t,m,typ,s=core_meta(item);data=escape(json.dumps(item.get('data',{}),ensure_ascii=False,indent=2)[:5000]);link=f'/diagnostics/nouveau?intervention_id={intervention_id}&titre={escape(t)}&maker={escape(m)}' if intervention_id else ''
        cards+=f'<details><summary>{escape(t)} {("· "+escape(m)) if m else ""}</summary><p class="muted">{escape(typ)} · {escape(s[:220])}</p><div class="pre">{data}</div>{f"<a class=\"btn primary\" href=\"{link}\">Utiliser pour diagnostic</a>" if link else ""}</details>'
    return page(request,u,'NOX-Core',f'<h1>NOX-Core</h1><p class="muted">{len(core_catalog())} fiche(s) intégrée(s).</p><section class="card"><form method="get" class="form"><label class="full">Recherche<input name="q" value="{escape(q)}"></label>{f"<input type=hidden name=intervention_id value={intervention_id}>" if intervention_id else ""}<button class="btn primary">Rechercher</button></form></section><section class="card">{cards or "Aucune fiche"}</section>')

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
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,TECHS);d=db.get(Diagnostic,did);d.statut='Terminé';d.conclusion=conclusion.strip();d.date_fin=datetime.utcnow();db.commit();return RedirectResponse(f'/diagnostics/{did}',303)

@app.get('/utilisateurs')
def users_page(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db)
    if u.role not in MANAGERS:return page(request,u,'Utilisateurs','<h1>Utilisateurs</h1><div class="alert">Accès réservé.</div>')
    rows=db.scalars(select(User).order_by(User.username)).all();trs=''.join(f'<tr><td>{x.id}</td><td>{escape(x.username)}</td><td>{badge(x.role)}</td><td>{badge("Actif" if x.active else "Inactif")}</td></tr>' for x in rows);form=''
    if u.role=='Administrateur':form=f'<section class="card"><h2>Créer un utilisateur</h2><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Utilisateur<input name="username" required></label><label>Mot de passe<input type="password" name="password" required></label><label>Rôle<select name="role">{"".join(f"<option>{r}</option>" for r in ROLES)}</select></label><button class="btn primary">Créer</button></form></section>'
    return page(request,u,'Utilisateurs',f'<h1>Utilisateurs</h1>{form}<section class="card"><table><tr><th>ID</th><th>Utilisateur</th><th>Rôle</th><th>État</th></tr>{trs}</table></section>')

@app.post('/utilisateurs')
def users_add(request:Request,username:str=Form(...),password:str=Form(...),role:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db)
    if u.role!='Administrateur':raise HTTPException(403)
    db.add(User(username=username.strip(),password_hash=hash_password(password),role=role if role in ROLES else 'Lecture seule',active=True));db.commit();return RedirectResponse('/utilisateurs',303)

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

@app.get('/sante')
def health(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);score=100;checks=[]
    try:db.execute(text('SELECT 1'));checks.append(('OK','Base de données','Connexion opérationnelle'))
    except Exception as e:score-=30;checks.append(('Critique','Base de données',str(e)))
    cc=len(core_catalog());checks.append(('OK' if cc else 'Avertissement','NOX-Core',f'{cc} fiche(s) chargée(s)'))
    if not cc:score-=7
    alerts=derive_alerts(db);crit=sum(1 for x in alerts if x[0]=='critique');checks.append(('OK' if not crit else 'Avertissement','Alertes',f'{crit} critique(s), {len(alerts)} alerte(s) active(s)'));score=max(0,score-min(20,crit*5));trs=''.join(f'<tr><td>{badge(a)}</td><td>{escape(b)}</td><td>{escape(c)}</td></tr>' for a,b,c in checks)
    return page(request,u,'Santé / Audit',f'<div class="head"><h1>Santé / Audit</h1><div class="metric"><span>Score</span><strong>{score}/100</strong></div></div><section class="card"><table><tr><th>Niveau</th><th>Domaine</th><th>Détail</th></tr>{trs}</table></section><section class="card"><a class="btn" href="/export-json">💾 Export JSON</a></section>')

@app.get('/export-json')
def export_json(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);require_role(u,MANAGERS);models=[Client,Site,Equipement,Intervention,StockItem,StockMovement,InterventionMaterial,Supplier,SupplierPrice,PlanningEntry,MaintenancePlan,MaintenanceHistory,Contract,FollowAction,AlertState,Diagnostic,DiagnosticStep];payload={'exported_at':datetime.utcnow().isoformat(),'version':APP_VERSION,'tables':{}}
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
