import hashlib, io, json, math, os, re, secrets
from collections import Counter
from datetime import date, datetime
from html import escape
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from web_models import (
    AlertState, AssistantExchange, AssistantMemory, AuditRun, Base, Client, Contract, Diagnostic, DiagnosticStep,
    Equipement, FollowAction, Intervention, InterventionMaterial, InterventionPhoto,
    MaintenanceHistory, MaintenancePlan, PlanningEntry, SessionLocal, Site,
    StockItem, StockMovement, Supplier, SupplierPrice, User, engine
)
from web_security import hash_password, new_csrf_token, verify_password

APP_VERSION = '4.5.0'
BASE_DIR = Path(__file__).resolve().parent
CORE_PATH = BASE_DIR / 'nox_core_catalog.json'
SOFTWARE_PATH = BASE_DIR / 'software_catalog.json'
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

@app.middleware('http')
async def noxia_permissions_policy(request:Request, call_next):
    response=await call_next(request)
    # Autorise explicitement les accès demandés vers le compagnon local.
    response.headers['Permissions-Policy']='local-network=(self), loopback-network=(self)'
    return response

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
.chat{display:grid;gap:12px}.bubble{border:1px solid var(--line);border-radius:15px;padding:15px}.bubble.user{background:#0b1b31}.bubble.ai{background:#10253a}.bubble .meta{font-size:11px;color:var(--muted);margin-bottom:7px}.source-card{border-left:3px solid var(--accent);padding-left:11px;margin:8px 0}.web-result{border:1px solid #28527d;background:linear-gradient(180deg,#0e2137,#0b192b);border-radius:14px;padding:18px;margin-top:14px}.web-result h3{margin-top:0}.web-sources{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}.web-source{display:inline-flex;align-items:center;gap:6px;border:1px solid #2c5076;background:#0a1727;border-radius:999px;padding:7px 10px;text-decoration:none;color:#acd3ff;font-size:12px}.web-source:hover{background:#112b47}.search-mode{display:inline-flex;align-items:center;gap:6px;border-radius:999px;padding:6px 10px;border:1px solid var(--line);font-size:12px;color:var(--muted)}.search-mode.on{border-color:#2e674f;color:#a9f5d4}.context-chip{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:5px 9px;margin:3px;color:var(--muted);font-size:11px}.ai-status{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:6px 10px;color:var(--muted);font-size:11px}.ai-status.on{color:#a9f5d4;border-color:#315d50}.assistant-note{border-left:3px solid var(--accent);padding:12px 14px;background:#0b1728;border-radius:10px;line-height:1.6}.answer-label{font-weight:720;letter-spacing:.1px}.memory-card{border:1px solid #24466b;background:linear-gradient(180deg,#0d2035,#0b1a2d);border-radius:14px;padding:14px 16px;margin:10px 0}.memory-card .memory-meta{display:flex;gap:8px;flex-wrap:wrap;align-items:center;color:var(--muted);font-size:12px;margin-bottom:7px}.memory-count{display:inline-flex;align-items:center;gap:7px;border:1px solid #31577d;background:#102641;border-radius:999px;padding:6px 10px;color:#cfe7ff;font-size:12px}.memory-state.good{color:#a9f5d4;border-color:#315d50}.memory-state.warn{color:#ffda8d;border-color:#70572f}.reply-box{background:rgba(10,20,34,.97);backdrop-filter:blur(14px);border:1px solid var(--line);border-radius:18px;padding:16px;box-shadow:0 20px 60px rgba(0,0,0,.34)}.reply-box textarea{min-height:112px;font-size:15px;line-height:1.6}.reply-toggle{position:fixed;opacity:0;pointer-events:none}.reply-launcher{position:fixed;right:24px;bottom:22px;z-index:70;display:flex;gap:8px;align-items:center;flex-wrap:wrap;justify-content:flex-end}.reply-launcher .btn{box-shadow:0 14px 38px rgba(0,0,0,.35);cursor:pointer}.reply-launcher .assistant-local-launch{background:#132b46;border-color:#31577e}.reply-dock{display:none;position:fixed;right:22px;bottom:20px;z-index:72;width:min(680px,calc(100vw - 44px));max-height:min(78vh,720px);overflow:auto}.reply-toggle:checked~.reply-launcher{display:none}.reply-toggle:checked~.reply-dock{display:block;animation:replyUp .16s ease-out}.reply-dock-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:11px}.reply-dock-head b{font-size:15px}.reply-mini{display:inline-flex;align-items:center;gap:7px}.conversation-tools{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.chat{scroll-margin-top:90px}.bubble .pre{margin-top:5px}.bubble.ai .pre{font-size:15.5px;line-height:1.76}.bubble.user .pre{font-size:14.5px;line-height:1.65}.assistant-quick-replies{display:flex;gap:7px;align-items:center;flex-wrap:wrap;margin-top:10px}.quick-reply-form{display:inline;margin:0}.local-status{font-weight:650}.assistant-local-btn.ready{border-color:#2f765e;background:#12382d;color:#b8f7de}.assistant-quick-replies .quick-reply{border:1px solid #31577d;background:#0d2138;color:#d7eaff;border-radius:999px;padding:7px 11px;font:600 12.5px/1.2 "Segoe UI Variable Text","Segoe UI",Inter,system-ui,sans-serif;cursor:pointer;transition:.14s ease}.assistant-quick-replies .quick-reply:hover{background:#173555;border-color:#4b83b9;transform:translateY(-1px)}.assistant-mode-pill{display:inline-flex;align-items:center;gap:7px;border:1px solid #2f6655;background:#102d27;color:#adf3d8;border-radius:999px;padding:6px 10px;font-size:12px;font-weight:700}.assistant-turn-hint{margin-top:8px;color:#8faac8;font-size:12px}.last-exchange{scroll-margin-top:92px}@keyframes replyUp{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
.core-search-input{font-family:"Segoe UI Variable Text","Segoe UI",Inter,system-ui,sans-serif!important;font-size:15.5px!important;font-weight:520!important;letter-spacing:.002em}.core-result{border-color:#27435f;background:linear-gradient(180deg,#0d1c30,#0b1727)}.core-result summary{font-family:"Segoe UI Variable Text","Segoe UI",Inter,system-ui,sans-serif;font-size:15.5px;font-weight:720;letter-spacing:.002em}.core-readable{display:grid;gap:8px;margin:12px 14px 16px}.core-row{display:grid;grid-template-columns:minmax(150px,230px) 1fr;gap:14px;padding:9px 11px;border:1px solid #1d3551;border-radius:10px;background:#0a1728;font-family:"Segoe UI Variable Text","Segoe UI",Inter,system-ui,sans-serif;font-size:14px;line-height:1.58}.core-key{color:#91b8df;font-weight:650}.core-value{color:#edf5ff;overflow-wrap:anywhere}.core-raw{margin:8px 14px 16px}.core-raw summary{font-size:13px;color:#8fa8c6;font-weight:600}.core-code{white-space:pre-wrap;overflow-wrap:anywhere;background:#07111e;border:1px solid #172b44;border-radius:10px;padding:12px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;line-height:1.55;color:#b9c9dc}.core-toolbar{display:flex;gap:10px;align-items:end}.core-toolbar label{flex:1}.core-stats{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0 2px}.core-chip{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);background:#0b1829;border-radius:999px;padding:6px 10px;color:#a9bad0;font-size:12px}.empty-state{text-align:center;padding:30px 18px;color:var(--muted)}

.symptom-tools{display:flex;gap:9px;flex-wrap:wrap;align-items:center;margin:12px 0}.symptom-stat{display:inline-flex;align-items:center;gap:7px;border:1px solid #31577d;background:#0f223a;border-radius:999px;padding:7px 11px;color:#cfe7ff;font-size:12.5px}.symptom-panel{border:1px solid #27435f;border-radius:14px;background:linear-gradient(180deg,#0d1d31,#0a1728);padding:14px 16px;margin:12px 0}.symptom-panel summary{font-family:"Segoe UI Variable Text","Segoe UI",Inter,system-ui,sans-serif;font-size:15px}.symptom-group{margin:12px 0}.symptom-group-title{font-size:12px;text-transform:uppercase;letter-spacing:.07em;color:#8eb4dc;font-weight:750;margin-bottom:7px}.symptom-chips{display:flex;flex-wrap:wrap;gap:7px}.symptom-chip{display:inline-flex;padding:7px 10px;border:1px solid #294665;border-radius:999px;background:#0b1b2e;color:#e6f1ff;font-family:"Segoe UI Variable Text","Segoe UI",Inter,system-ui,sans-serif;font-size:13px;line-height:1.25}.symptom-chip.rare{border-color:#6b4b2c;background:#241b12;color:#ffd7a0}.symptom-atlas-grid{display:grid;gap:10px}.symptom-row{display:grid;grid-template-columns:minmax(180px,280px) 1fr auto;gap:12px;align-items:start;border:1px solid #203b59;border-radius:11px;padding:11px 13px;background:#0b192b}.symptom-row .domain{color:#8eb4dc;font-size:12px}.symptom-row .name{font-size:14px;line-height:1.5}.symptom-row .rarity{font-size:11px;color:#b9c9db;border:1px solid #334b66;border-radius:999px;padding:4px 7px}.symptom-row .rarity.rare{color:#ffd7a0;border-color:#6b4b2c}.core-result .symptom-panel{margin:12px 14px 16px}.core-search-input, .core-readable, .core-row, .core-value, .core-key, .symptom-chip, .symptom-row{font-family:"Segoe UI Variable Text","Segoe UI",Inter,system-ui,-apple-system,sans-serif!important}


.local-brain-bar{display:flex;align-items:center;gap:9px;flex-wrap:wrap;margin-top:9px}.local-dot{width:9px;height:9px;border-radius:999px;background:#63758f;box-shadow:0 0 0 3px rgba(99,117,143,.12)}.local-dot.ready{background:var(--good);box-shadow:0 0 0 3px rgba(70,209,154,.14)}.local-dot.error{background:var(--warn)}.local-status{font-size:12px;color:var(--muted)}
.software-hero{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(300px,.85fr);gap:14px}.software-panel{border:1px solid var(--line);border-radius:14px;background:#0b1727;padding:16px}.software-results{display:grid;gap:8px;margin-top:10px}.software-app{display:flex;align-items:center;justify-content:space-between;gap:10px;border:1px solid var(--line);border-radius:11px;padding:10px 12px;background:#0a1626}.software-app strong{font-weight:650}.software-guide-output{white-space:pre-wrap;overflow-wrap:anywhere;border:1px solid var(--line);border-radius:14px;background:#091524;padding:18px;font-size:15px;line-height:1.68;min-height:130px}.software-guide-output:empty:before{content:'La réponse du guide apparaîtra ici.';color:var(--muted)}.software-profile-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:9px}.software-profile{border:1px solid var(--line);border-radius:12px;padding:12px;background:#0b1727}.software-profile b{display:block;margin-bottom:3px}.software-profile .muted{font-size:12px}.local-mode-toggle{display:inline-flex;align-items:center;gap:7px;border:1px solid var(--line);border-radius:999px;padding:6px 10px;background:#0a1728;font-size:12px;color:var(--muted)}.local-mode-toggle input{width:auto;margin:0}.assistant-local-btn{border-color:#315d50}.assistant-local-btn.ready{color:#a9f5d4}.software-shot-preview{max-width:320px;max-height:190px;border:1px solid var(--line);border-radius:10px;display:none;margin-top:8px}.bridge-help{border-left:3px solid var(--accent);padding:10px 12px;background:#0b1728;border-radius:9px;font-size:13px}.software-steps{display:grid;gap:7px}.software-steps .step{border:1px solid var(--line);border-radius:10px;padding:10px;background:#0a1626}
@media(max-width:900px){.software-hero{grid-template-columns:1fr}}
.sidebar-overlay{display:none}
@media(max-width:1180px){.g4{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:980px){:root{--topbar:62px}.sidebar{transform:translateX(-103%);transition:transform .2s ease;box-shadow:20px 0 60px rgba(0,0,0,.42)}.sidebar.open{transform:translateX(0)}.app-main{margin-left:0}.menu-toggle{display:grid;place-items:center}.sidebar-overlay{display:block;position:fixed;inset:0;z-index:35;background:rgba(0,0,0,.48);opacity:0;pointer-events:none;transition:opacity .2s ease}.sidebar-overlay.show{opacity:1;pointer-events:auto}.wrap{width:min(100% - 28px,1460px);padding-top:24px}.app-topbar{padding:0 14px}.user-meta{display:none}}
@media(max-width:720px){.g4,.g2,.form{grid-template-columns:1fr}.full{grid-column:auto}.kv{grid-template-columns:1fr}.core-toolbar{align-items:stretch;flex-direction:column}.core-toolbar .btn{width:100%}.core-row{grid-template-columns:1fr;gap:4px}.card{padding:15px;border-radius:14px}.wrap{width:min(100% - 20px,1460px)}.userbox{gap:7px}.user-avatar{width:32px;height:32px}.logout-btn{width:34px;height:34px}.page-kicker{display:none}.reply-launcher{right:12px;bottom:12px}.reply-dock{left:10px;right:10px;bottom:10px;width:auto;max-height:82vh}.reply-box{padding:13px}.reply-box textarea{min-height:96px}}
'''

NAV_GROUPS=[
    ('Vue générale', [('/dashboard','Dashboard','DB')]),
    ('Opérations', [('/clients','Clients','CL'),('/sites','Sites','SI'),('/equipements','Équipements','EQ'),('/interventions','Interventions','IN'),('/planning','Planning','PL')]),
    ('Gestion', [('/stock','Stock','ST'),('/fournisseurs','Fournisseurs','FO'),('/maintenance','Maintenance','MA'),('/contrats','Contrats','CO')]),
    ('Suivi', [('/alertes','Alertes','AL'),('/actions','Actions','AC')]),
    ('Intelligence', [('/assistant','Assistant IA','IA'),('/logiciels','Guidage logiciels','SW'),('/nox-core','NOX-Core','NX'),('/diagnostics','Diagnostics','DG')]),
    ('Administration', [('/utilisateurs','Utilisateurs','UT'),('/sante','Santé / Audit','SA')]),
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
    for group,items in NAV_GROUPS:
        nav_parts.append(f'<div class="nav-group"><div class="nav-label">{escape(group)}</div>')
        for href,label,icon in items:
            active=' active' if _nav_active(path,href) else ''
            aria=' aria-current="page"' if active else ''
            nav_parts.append(f'<a class="nav-item{active}" href="{href}"{aria}><span class="nav-icon">{escape(icon)}</span><span>{escape(label)}</span></a>')
        nav_parts.append('</div>')
    nav=''.join(nav_parts)
    initial=escape((user.username or '?')[:1].upper())
    username=escape(user.username)
    role=escape(user.role)
    token=csrf_token(request)
    message=(request.query_params.get('msg') or '').strip()
    notice=f'<div class="notice">{escape(message)}</div>' if message else ''
    shell=f'''<div class="app-shell">
      <aside class="sidebar" id="sidebar" aria-label="Navigation principale">
        <a class="sidebar-brand" href="/dashboard"><span class="brand-mark">N</span><span class="brand-copy"><span class="brand-name">NOX-IA</span><span class="brand-sub">Operations Platform</span></span></a>
        <nav class="sidebar-nav">{nav}</nav>
      </aside>
      <div class="sidebar-overlay" id="sidebarOverlay" onclick="closeSidebar()"></div>
      <section class="app-main">
        <header class="app-topbar">
          <div class="topbar-left"><button class="menu-toggle" type="button" aria-label="Ouvrir le menu" onclick="toggleSidebar()">☰</button><div><div class="page-kicker">NOX-IA</div><div class="page-current">{escape(title)}</div></div></div>
          <div class="userbox"><div class="user-meta"><span class="user-name">{username}</span><span class="user-role">{role}</span></div><div class="user-avatar" title="{username} · {role}">{initial}</div><form class="logout-form" method="post" action="/logout"><input type="hidden" name="csrf_token" value="{token}"><button class="logout-btn" title="Se déconnecter" aria-label="Se déconnecter">↪</button></form></div>
        </header>
        <main class="wrap">{notice}{body}</main>
      </section>
    </div>
    <script>
      const sidebar=document.getElementById('sidebar');
      const overlay=document.getElementById('sidebarOverlay');
      const sidebarNav=document.querySelector('.sidebar-nav');
      const scrollKey='noxia.sidebar.scroll.v1';
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

@app.get('/equipements')
def equipements(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);rows=db.scalars(select(Equipement).order_by(Equipement.reference)).all();sites_=db.scalars(select(Site).where(Site.actif.is_(True)).order_by(Site.nom)).all();trs=''
    for e in rows:
        site=db.get(Site,e.site_id);c=db.get(Client,site.client_id) if site else None
        actions='—'
        if u.role in MANAGERS:
            label='Réactiver' if not e.actif else 'Archiver';cls='goodbtn' if not e.actif else 'dangerbtn'
            actions=(f'<form method="post" action="/equipements/{e.id}/etat" onsubmit="return confirm(\'Confirmer cette modification ?\')"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn small {cls}">{label}</button></form>')
        trs+=f'<tr><td><a href="/equipements/{e.id}">{escape(e.reference)}</a></td><td>{escape(c.nom if c else "—")}</td><td>{escape(site.nom if site else "—")}</td><td>{escape(e.type_equipement)}</td><td>{escape(e.marque)}</td><td>{escape(e.modele)}</td><td>{escape(e.ip)}</td><td>{badge(e.statut)}</td><td>{badge("Actif" if e.actif else "Archivé")}</td><td>{actions}</td></tr>'
    form=''
    if u.role in MANAGERS:
        if sites_:
            form=f'<section class="card"><h2>Ajouter un équipement</h2><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Site<select name="site_id" required>{option_rows(sites_,lambda x:x.id,lambda x:x.nom)}</select></label><label>Référence<input name="reference" required></label><label>Type<input name="type_equipement" required></label><label>Marque<input name="marque"></label><label>Modèle<input name="modele"></label><label>N° série<input name="numero_serie"></label><label>IP<input name="ip"></label><label>Statut<select name="statut_equipement"><option>Actif</option><option>En panne</option><option>Hors service</option></select></label><button class="btn primary">Ajouter</button></form></section>'
        else:
            form='<section class="card"><h2>Ajouter un équipement</h2><div class="alert">Aucun site actif. Crée ou réactive d’abord un site.</div><div style="margin-top:12px"><a class="btn primary" href="/sites">Ouvrir Sites</a></div></section>'
    return page(request,u,'Équipements',f'<h1>Équipements</h1>{form}<section class="card"><div class="scroll"><table><tr><th>Réf</th><th>Client</th><th>Site</th><th>Type</th><th>Marque</th><th>Modèle</th><th>IP</th><th>État technique</th><th>Statut fiche</th><th>Actions</th></tr>{trs or "<tr><td colspan=10>Aucun équipement.</td></tr>"}</table></div></section>')

@app.post('/equipements')
def equipements_add(request:Request,site_id:int=Form(...),reference:str=Form(...),type_equipement:str=Form(...),marque:str=Form(''),modele:str=Form(''),numero_serie:str=Form(''),ip:str=Form(''),statut_equipement:str=Form('Actif'),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS)
    site=db.get(Site,site_id)
    if not site or not site.actif: raise HTTPException(409,'Le site doit être actif')
    db.add(Equipement(site_id=site_id,reference=reference.strip(),type_equipement=type_equipement.strip(),marque=marque.strip(),modele=modele.strip(),numero_serie=numero_serie.strip(),ip=ip.strip(),statut=statut_equipement,actif=True));db.commit()
    return RedirectResponse('/equipements?msg=Équipement+ajouté',303)

@app.post('/equipements/{eid}/etat')
def equipement_toggle(eid:int,request:Request,csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);u=require_login(request,db);require_role(u,MANAGERS)
    e=db.get(Equipement,eid)
    if not e: raise HTTPException(404,'Équipement introuvable')
    if not e.actif:
        site=db.get(Site,e.site_id)
        if not site or not site.actif: raise HTTPException(409,'Réactive d’abord le site de cet équipement')
    e.actif=not e.actif;db.commit()
    return RedirectResponse('/equipements?msg='+('Équipement+réactivé' if e.actif else 'Équipement+archivé'),303)

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
    s=db.get(Site,i.site_id);c=db.get(Client,s.client_id) if s else None;e=db.get(Equipement,i.equipement_id) if i.equipement_id else None;stocks=db.scalars(select(StockItem).where(StockItem.actif.is_(True)).order_by(StockItem.designation)).all();mats=db.scalars(select(InterventionMaterial).where(InterventionMaterial.intervention_id==iid)).all();photos=db.scalars(select(InterventionPhoto).where(InterventionPhoto.intervention_id==iid)).all();diags=db.scalars(select(Diagnostic).where(Diagnostic.intervention_id==iid).order_by(Diagnostic.date_debut.desc())).all()
    mrows=''.join(f'<tr><td>{escape((db.get(StockItem,m.stock_item_id).reference if db.get(StockItem,m.stock_item_id) else "—"))}</td><td>{escape((db.get(StockItem,m.stock_item_id).designation if db.get(StockItem,m.stock_item_id) else "—"))}</td><td>{m.quantite}</td></tr>' for m in mats);ph=''.join(f'<a class="btn small" href="/photos/{p.id}" target="_blank">{escape(p.filename)}</a>' for p in photos) or 'Aucune photo';drows=''.join(f'<tr><td><a href="/diagnostics/{d.id}">#{d.id}</a></td><td>{dfr(d.date_debut)}</td><td>{escape(d.fiche_titre)}</td><td>{badge(d.statut)}</td></tr>' for d in diags)
    edit=''
    if u.role in TECHS and i.statut!='Terminée':
        edit=f'<section class="card"><h2>Travail intervention</h2><form method="post" action="/interventions/{iid}/modifier" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Priorité<select name="priorite"><option>{escape(i.priorite)}</option><option>Basse</option><option>Normale</option><option>Haute</option><option>Urgente</option></select></label><label>Statut<select name="statut"><option>{escape(i.statut)}</option><option>À faire</option><option>En cours</option><option>En attente</option></select></label><label class="full">Problème<textarea name="probleme">{escape(i.probleme)}</textarea></label><label class="full">Actions réalisées<textarea name="actions_realisees">{escape(i.actions_realisees)}</textarea></label><label class="full">Solution<textarea name="solution">{escape(i.solution)}</textarea></label><button class="btn primary">Enregistrer</button></form></section><section class="card"><h2>Matériel / installation</h2><form method="post" action="/interventions/{iid}/materiel" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Article<select name="stock_item_id">{option_rows(stocks,lambda x:x.id,lambda x:f"{x.reference} · {x.designation} · stock {x.quantite}")}</select></label><label>Quantité<input type="number" min="1" name="quantite" value="1"></label><button class="btn primary">Utiliser</button></form></section><section class="card"><h2>Photo</h2><form method="post" action="/interventions/{iid}/photo" enctype="multipart/form-data" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Image<input type="file" accept="image/*" name="file" required></label><label>Commentaire<input name="commentaire"></label><button class="btn primary">Ajouter</button></form></section>'
    controls=''
    if i.statut!='Terminée' and u.role in TECHS:controls=f'<form method="post" action="/interventions/{iid}/cloturer"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn goodbtn">Terminer</button></form>'
    elif i.statut=='Terminée' and u.role in MANAGERS:controls=f'<form method="post" action="/interventions/{iid}/rouvrir"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><button class="btn">↻ Rouvrir</button></form>'
    body=f'<div class="head"><div><h1>Intervention #{iid}</h1><p class="muted">{escape(c.nom if c else "—")} · {escape(s.nom if s else "—")} · {escape(e.reference if e else "sans équipement")}</p></div><div class="actions"><a class="btn" href="/interventions/{iid}/rapport/client">PDF client</a><a class="btn" href="/interventions/{iid}/rapport/technique">PDF technique</a><a class="btn primary" href="/assistant?intervention_id={iid}">Assistant IA</a><a class="btn" href="/nox-core?intervention_id={iid}">NOX-Core</a>{controls}</div></div><section class="card"><div class="kv"><b>Date</b><span>{dfr(i.date_creation)}</span><b>Technicien</b><span>{escape(i.technicien)}</span><b>Priorité</b><span>{badge(i.priorite)}</span><b>Statut</b><span>{badge(i.statut)}</span></div><h3>Problème</h3><div class="pre">{escape(i.probleme)}</div><h3>Actions</h3><div class="pre">{escape(i.actions_realisees)}</div><h3>Solution</h3><div class="pre">{escape(i.solution)}</div></section>{edit}<section class="card"><h2>Matériel</h2><table><tr><th>Réf</th><th>Désignation</th><th>Qté</th></tr>{mrows}</table></section><section class="card"><h2>Photos</h2><div class="actions">{ph}</div></section><section class="card"><h2>Diagnostics</h2><a class="btn primary" href="/diagnostics/nouveau?intervention_id={iid}">Nouveau diagnostic</a><table><tr><th>ID</th><th>Date</th><th>Fiche</th><th>Statut</th></tr>{drows}</table></section>'
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
    type_boost={'cas_resolu':7.0,'diagnostic':6.2,'memo_manuel':5.8,'web_constructeur':5.4,'observation_terrain':4.8,'conversation':0.8}
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


def assistant_memory_observation_confidence(text_value):
    low=str(text_value or '').lower()
    if any(x in low for x in ('j’ai mesuré','j ai mesuré','mesuré à','mesure à','j’ai vérifié','j ai verifie','vérifié','confirmé','testé','je confirme','constaté')):return 'élevée'
    return 'moyenne'

def assistant_memory_learn_exchange(db,user,question,response,context_data,intervention_id=None):
    raw=' '.join(str(question or '').split());low=raw.lower()
    if len(raw)<4 or low in {'salut','bonjour','bonsoir','merci','ok'}:return None
    eq=context_data.get('equipement');constructeur=eq.marque if eq else '';reference=(eq.reference or eq.modele) if eq else ''
    context_bits=[]
    if eq:context_bits.append(f'Équipement {eq.marque} {eq.modele} réf {eq.reference}')
    if context_data.get('intervention'):context_bits.append(f'Intervention #{context_data["intervention"].id}')
    # Le message du technicien est mémorisé comme observation terrain distincte. Il n'est jamais transformé automatiquement en cause certaine.
    content=f'Observation terrain du technicien : {raw}'
    if context_bits:content+=' | Contexte : '+' ; '.join(context_bits)
    obs=assistant_memory_add(db,'observation_terrain',f'Observation — {raw[:140]}',content,keywords=assistant_memory_keywords(raw+' '+' '.join(context_bits)),source='technicien',constructeur=constructeur,reference=reference,confidence=assistant_memory_observation_confidence(raw),utilisateur=user.username,source_ref=f'intervention:{intervention_id}' if intervention_id else 'assistant-general')
    # La réponse IA est gardée séparément et à faible autorité : une piste ne doit pas devenir une vérité par répétition.
    if response and len(str(response).strip())>20:
        assistant_memory_add(db,'conversation',f'Piste NOX-IA — {raw[:100]}',f'Question: {raw}\nPiste générée: {str(response)[:2600]}',keywords=assistant_memory_keywords(raw),source='assistant',constructeur=constructeur,reference=reference,confidence='faible',utilisateur=user.username,source_ref=f'assistant:{intervention_id or "general"}')
    return obs

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
    lines=[step['intro'],'','👉 TESTE MAINTENANT',step['test'],'','Pourquoi : '+step['why'],'','💬 DIS-MOI JUSTE',step['question']]
    return '\n'.join(lines)
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

Parle naturellement avec le technicien. Il peut écrire comme à un collègue : « salut », faire des fautes, employer des abréviations, commencer par une phrase incomplète ou raconter le problème dans le désordre. Comprends l'intention avant de répondre. Une salutation simple mérite une réponse simple. Une question simple mérite une réponse courte. Un diagnostic complexe peut être structuré. Ne force jamais un gros rapport si ce n'est pas utile.

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
- MODE TERRAIN INTERACTIF PAR DÉFAUT : ne donne PAS toute la procédure d’un coup. Donne au maximum 1 ou 2 contrôles immédiatement utiles, explique en une phrase pourquoi, puis pose UNE seule question qui permettra de choisir l’étape suivante.
- Format conseillé pour une panne non résolue : une phrase « OK, je garde… », puis « 👉 Teste maintenant », puis « Pourquoi », puis « 💬 Dis-moi juste ». Garde la réponse courte, typiquement 5 à 12 lignes.
- Si le technicien demande explicitement « détaille tout », « rapport complet », « toutes les causes » ou équivalent, tu peux alors produire une analyse longue et structurée.
- Ne noie pas le technicien avec l’atlas, les sources ou la mémoire : utilise-les en arrière-plan et ne montre que ce qui influence réellement la prochaine décision.
- Structure en rubriques uniquement quand cela améliore vraiment le diagnostic.
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
    """Construit un paquet RAG minimisé à exécuter sur le PC du technicien via NOX Local Bridge."""
    context_data=assistant_context(db,intervention_id)
    recent_history=assistant_history_for_prompt(db,intervention_id,user.id,limit=8)
    conversation_state=assistant_conversation_state(db,intervention_id,user.id,limit=14)
    conversation_query=question
    if assistant_short_reply(question) and recent_history!='Aucun échange précédent.':
        conversation_query=recent_history[-4200:]+'\nRéponse actuelle du technicien: '+question
    search_context=context_data['texte']+' '+recent_history+' '+conversation_state
    memories=assistant_memory_search(db,conversation_query+' '+search_context,limit=12)
    memory_text=assistant_memory_text(memories,6500)
    symptom_text=assistant_symptom_atlas_text(conversation_query,search_context,limit=18)
    sources=assistant_search_nox_core(conversation_query,search_context+' '+memory_text+' '+symptom_text,limit=8)
    similar=assistant_similar_interventions(db,conversation_query,context_data,limit=3)
    source_text='\n\n'.join(assistant_source_excerpt(item,idx) for idx,item in enumerate(sources,1)) or 'Aucune fiche NOX-Core suffisamment proche.'
    cases_text=assistant_similar_cases_text(similar)
    system=(
        "Tu es NOX-Local, le cerveau local de NOX-IA. Réponds en français professionnel et naturel. "
        "Tu es spécialisé en sûreté, vidéosurveillance, contrôle d'accès, intrusion, SSI/incendie, réseau, interphonie, VMS/NVR, serveurs, alimentations et logiciels techniques. "
        "Utilise d'abord les faits et sources fournis. Ne redemande pas une information déjà confirmée. "
        "Une ancienne hypothèse IA n'est pas une preuve. Ne fabrique jamais un menu constructeur, un port, un code erreur ou une valeur absente des sources. "
        "Pour une panne, fonctionne en mode terrain interactif : au maximum 1 ou 2 contrôles à la fois, une phrase expliquant pourquoi, puis UNE seule question. Attends la réponse avant la suite. Ne déroule la procédure complète que si le technicien le demande explicitement. Pour SSI/incendie, ne neutralise jamais une fonction de sécurité. "
        "Pour réseau/cybersécurité, reste défensif et autorisé. Si tu manques d'une donnée exacte, dis-le et demande une précision ciblée."
    )
    prompt=f"""MESSAGE ACTUEL DU TECHNICIEN
{question}

CONTEXTE INTERVENTION
{assistant_external_context(context_data)}

HISTORIQUE RÉCENT
{recent_history}

FAITS DÉJÀ ÉTABLIS
{conversation_state}

MÉMOIRE PERMANENTE PERTINENTE
{memory_text}

ATLAS DES SYMPTÔMES
{symptom_text}

SOURCES NOX-CORE
{source_text}

CAS TERRAIN RÉSOLUS
{cases_text}

Réponds maintenant comme un collègue expert en MODE TERRAIN INTERACTIF. Si le message est une réponse courte comme « oui » ou « non », rattache-la à la dernière question et continue le diagnostic au lieu de repartir de zéro. Sauf demande de détail complet, donne seulement 1 ou 2 contrôles, explique brièvement pourquoi, puis pose UNE question qui décide de la suite."""
    return {
        'model':'nox-tech:4b',
        'system':system,
        'messages':[{'role':'user','content':prompt}],
        'sources_json':assistant_sources_json(sources),
        'context_data':context_data,
    }

@app.post('/assistant/local-payload')
def assistant_local_payload(request:Request,question:str=Form(...),intervention_id:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);user=require_login(request,db);require_role(user,TECHS)
    question=question.strip()
    if not question:raise HTTPException(400,detail='Question vide')
    iid=int(intervention_id) if intervention_id.strip() else None
    data=assistant_local_payload_data(db,user,question,iid)
    return JSONResponse({'ok':True,'model':data['model'],'system':data['system'],'messages':data['messages'],'sources_json':data['sources_json']})

@app.post('/assistant/local-save')
def assistant_local_save(request:Request,question:str=Form(...),response_text:str=Form(...),intervention_id:str=Form(''),sources_json:str=Form('[]'),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);user=require_login(request,db);require_role(user,TECHS)
    question=question.strip();response_text=response_text.strip()
    if not question or not response_text:raise HTTPException(400,detail='Question ou réponse locale vide')
    iid=int(intervention_id) if intervention_id.strip() else None
    context_data=assistant_context(db,iid)
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
        f'<div class="assistant-turn-hint">NOX-IA avance maintenant une étape à la fois. Tu peux aussi écrire « détaille tout » si tu veux l’analyse complète.</div><div class="actions"><button class="btn primary">Envoyer à NOX-IA</button><button type="button" class="btn assistant-local-btn" id="assistantLocalBtn">Tester / Réponse locale</button><a class="btn" href="/assistant/memoire">Mémoire interne</a></div><div class="local-brain-bar"><span class="local-dot" id="assistantLocalDot"></span><span class="local-status" id="assistantLocalStatus">Connecteur Chrome : vérification...</span><span class="hint" id="assistantLocalHint">La réponse locale passe par l’extension NOX-IA pour éviter le blocage de 127.0.0.1 par la page Render.</span></div></form><div class="assistant-quick-replies"><span class="hint">Réponse rapide (envoi immédiat) :</span><form method="post" action="/assistant/analyser" class="quick-reply-form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><input type="hidden" name="intervention_id" value="{intervention_id or ""}"><button type="submit" name="question" value="oui" class="quick-reply">Oui</button></form><form method="post" action="/assistant/analyser" class="quick-reply-form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><input type="hidden" name="intervention_id" value="{intervention_id or ""}"><button type="submit" name="question" value="non" class="quick-reply">Non</button></form><form method="post" action="/assistant/analyser" class="quick-reply-form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><input type="hidden" name="intervention_id" value="{intervention_id or ""}"><button type="submit" name="question" value="toujours pas" class="quick-reply">Toujours pas</button></form><form method="post" action="/assistant/analyser" class="quick-reply-form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><input type="hidden" name="intervention_id" value="{intervention_id or ""}"><button type="submit" name="question" value="ça marche" class="quick-reply">Ça marche</button></form><form method="post" action="/assistant/analyser" class="quick-reply-form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><input type="hidden" name="intervention_id" value="{intervention_id or ""}"><button type="submit" name="question" value="pareil" class="quick-reply">Pareil</button></form></div></section>'
    )

    body=(
        '<div class="head"><div><h1>Assistant IA</h1><p class="muted">Conversation technique continue : NOX-IA avance maintenant une étape à la fois, garde le fil et apprend de l’expérience terrain.</p></div><div class="actions"><span class="assistant-mode-pill">⚡ Mode terrain interactif</span>'+status_html+'</div></div>'
        f'<div class="core-stats"><span class="memory-count">{memory_count} mémoire(s) permanente(s)</span><span class="memory-count memory-state {state_cls}">{escape(state_text[:115])}</span><span class="memory-count" id="localBrainPageStatus">🧠 Cerveau local : connexion à vérifier</span><a class="btn small" href="/assistant/memoire">Ouvrir la mémoire</a></div>'
        '<section class="card"><form method="get" action="/assistant" class="form">'
        f'<label class="full">Contexte intervention<select name="intervention_id" onchange="this.form.submit()">{options}</select></label></form>'
        f'<div style="margin-top:12px">{context_html or "<span class=muted>Assistant général : tu peux aussi discuter sans intervention sélectionnée.</span>"}</div></section>'
        '<section class="card"><h2>Comment discuter avec NOX-IA</h2><div class="assistant-note muted">Tu peux parler normalement : « salut », « la caméra ping mais reste hors ligne », puis répondre simplement « oui », « non », « toujours pas ». NOX-IA relit les échanges précédents, les cas résolus, les diagnostics et la mémoire permanente avant de continuer.</div></section>'
        f'<section class="card" id="conversation"><div class="head"><div><h2>Conversation</h2><span class="muted">{len(history)} échange(s)</span></div>{conv_tools}</div><div class="chat">{history_html or "<span class=muted>Aucun échange pour le moment.</span>"}</div></section>'
        '<section class="card"><div class="head"><div><h2>Derniers apprentissages</h2><p class="muted">Cette mémoire n’est pas effacée par le bouton de réinitialisation NOX-IA.</p></div></div>'+ (memory_preview or '<span class="muted">La mémoire est vide pour le moment. Elle va se remplir avec les échanges, diagnostics et interventions résolues.</span>')+'</section>'
        '<input type="checkbox" class="reply-toggle" id="replyToggle">'
        '<div class="reply-launcher" id="replyLauncher"><label for="replyToggle" class="btn primary">💬 Répondre à NOX-IA</label><label for="replyToggle" class="btn assistant-local-launch" id="assistantLocalLaunch">🧠 Réponse locale</label></div>'
        '<div class="reply-dock" id="replyDock">'+reply_form+'</div>'
        '''<script>
        (function(){
          const field=document.getElementById('assistantReplyText');
          const replyToggle=document.getElementById('replyToggle');
          const localBtn=document.getElementById('assistantLocalBtn');
          const localLaunch=document.getElementById('assistantLocalLaunch');
          const localDot=document.getElementById('assistantLocalDot');
          const localStatus=document.getElementById('assistantLocalStatus');
          const pageStatus=document.getElementById('localBrainPageStatus');
          const bridge='http://127.0.0.1:8765';
          let localReady=false;
          let localBusy=false;
          let extensionReady=false;
          let requestSeq=0;

          if(replyToggle&&field){
            replyToggle.addEventListener('change',function(){
              if(replyToggle.checked)setTimeout(function(){field.focus();},80);
            });
          }
          if(field){
            field.addEventListener('keydown',function(e){
              if((e.ctrlKey||e.metaKey)&&e.key==='Enter'){
                e.preventDefault();
                const form=document.getElementById('assistantReplyForm');
                if(form)form.requestSubmit();
              }
            });
          }


          function setLocalVisual(kind,message,model){
            const ready=kind==='ready';
            if(localBtn){
              localBtn.disabled=false;
              localBtn.classList.toggle('ready',ready);
              localBtn.textContent=ready?'🧠 Réponse locale':'Tester / Réponse locale';
            }
            if(localDot)localDot.className='local-dot '+(ready?'ready':'error');
            if(localStatus)localStatus.textContent=message;
            if(pageStatus){
              pageStatus.textContent=ready?('🧠 Local prêt · '+(model||'nox-tech:4b')+' · Connecteur Chrome'):('🧠 '+message);
              pageStatus.style.borderColor=ready?'#315d50':'#70572f';
              pageStatus.style.color=ready?'#a9f5d4':'#ffda8d';
            }
          }

          // Le connecteur Chrome 1.1 gère directement le bouton local.
          // Ce script de page sert seulement de détection visuelle et de secours.
          let connectorSeen=false;
          document.addEventListener('noxia-connector-ready',function(ev){
            connectorSeen=true;
            let data={};
            try{data=JSON.parse(ev.detail||'{}');}catch(e){}
            if(data&&data.model_ready){
              setLocalVisual('ready','Cerveau local prêt · '+(data.model||'nox-tech:4b'),data.model);
            }else{
              setLocalVisual('error','Connecteur Chrome actif, modèle local non prêt');
            }
          });
          document.addEventListener('noxia-connector-error',function(ev){
            connectorSeen=true;
            let msg='Connecteur Chrome détecté, mais le pont local ne répond pas.';
            try{const d=JSON.parse(ev.detail||'{}');if(d&&d.error)msg=d.error;}catch(e){}
            setLocalVisual('error',msg);
          });
          setTimeout(function(){
            if(!connectorSeen)setLocalVisual('error','Extension NOX-IA non détectée sur cette page. Recharge l’extension puis Ctrl+F5.');
          },2200);

          if(localBtn){
            localBtn.addEventListener('click',function(){
              if(!connectorSeen){
                setLocalVisual('error','Extension NOX-IA non détectée. Ouvre chrome://extensions et vérifie « NOX-IA Connecteur local ».');
              }
              // Si l’extension est active, son content script intercepte ce clic en priorité et envoie la réponse locale.
            });
          }
        })();
        </script>'''
    )
    return page(request,user,'Assistant IA',body)

@app.post('/assistant/analyser')
def assistant_analyse(request:Request,question:str=Form(...),intervention_id:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);user=require_login(request,db);require_role(user,TECHS)
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



SOFTWARE_GUIDE_SYSTEM_PROMPT="""Tu es le guide logiciel de NOX-IA pour techniciens de sûreté et d'infrastructure.
Tu guides l'utilisateur dans des logiciels de vidéosurveillance, VMS/NVR, contrôle d'accès, intrusion, SSI, réseau, supervision et outils de diagnostic.

Règles :
- Réponds en français clair, professionnel et concret.
- Guide étape par étape, en tenant compte de ce que l'utilisateur voit réellement.
- N'invente jamais un menu, un bouton, un chemin de configuration ou une fonction. Si cela dépend de la version, dis « à confirmer sur cette version » et demande le numéro de version ou une capture.
- Quand une capture est fournie au cerveau local, utilise-la pour dire où cliquer en décrivant le libellé visible, pas une position supposée.
- Commence par reformuler l'objectif en une phrase, puis donne la prochaine action utile. Évite une liste de 20 étapes si une seule action doit être vérifiée avant de poursuivre.
- Pour les réglages pouvant couper un service, effacer une configuration, mettre à jour un firmware ou modifier un système de sécurité, avertis avant l'action.
- Pour SSI/incendie, ne propose aucune neutralisation, shunt ou contournement de sécurité.
- Pour réseau/cybersécurité, reste sur des opérations défensives et autorisées.
- Les mémoires de cas réellement résolus sont plus fiables que les anciennes réponses IA.
"""

def software_guide_context(db,user,software,task):
    query=' '.join(x for x in (software,task) if x)
    profiles=software_profile_text(software or query)
    memories=assistant_memory_search(db,query,limit=12)
    memory_text=assistant_memory_text(memories,6500)
    sources=assistant_search_nox_core(query,profiles+' '+memory_text,limit=7)
    source_text='\n\n'.join(assistant_source_excerpt(item,idx) for idx,item in enumerate(sources,1)) or 'Aucune fiche NOX-Core spécifique.'
    return {
        'profiles':profiles,
        'memories':memories,
        'sources':sources,
        'context':f"PROFIL LOGICIEL / FAMILLE\n{profiles}\n\nMÉMOIRE PERMANENTE NOX-IA\n{memory_text}\n\nNOX-CORE\n{source_text}",
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
    token=csrf_token(request)
    token_js=json.dumps(token)
    q_value=escape(q,quote=True)
    body=(
        '<div class="head"><div><h1>Guidage logiciels</h1><p class="muted">NOX-IA peut reconnaître le logiciel, l’ouvrir sur ton PC via le pont local et te guider étape par étape. Une capture d’écran peut être analysée par le cerveau local.</p></div><span class="ai-status" id="softwareBrainTop">Cerveau local : détection...</span></div>'
        '<section class="card software-hero"><div class="software-panel"><h2>Logiciel et objectif</h2>'
        f'<label>Logiciel<input id="softwareName" list="softwareCatalog" value="{q_value}" placeholder="Ex. iVMS-4200, ATS8600, Wisenet Viewer..."></label><datalist id="softwareCatalog">{datalist}</datalist>'
        '<div class="actions" style="margin-top:10px"><button type="button" class="btn" id="detectAppsBtn">Détecter sur mon PC</button><button type="button" class="btn" id="openSoftwareBtn">Ouvrir le logiciel</button></div>'
        '<div class="software-results" id="softwareApps"></div>'
        '<label style="margin-top:12px">Ce que tu veux faire ou le problème rencontré<textarea id="softwareTask" placeholder="Ex. Je veux ajouter une caméra qui ping mais n’apparaît pas dans le logiciel."></textarea></label>'
        '<label>Capture d’écran facultative<input type="file" id="softwareShot" accept="image/png,image/jpeg,image/webp"></label><img id="softwareShotPreview" class="software-shot-preview" alt="Aperçu de la capture">'
        '<div class="actions" style="margin-top:12px"><button type="button" class="btn primary" id="localGuideBtn" disabled>Me guider avec le cerveau local</button><button type="button" class="btn" id="cloudGuideBtn">Analyse approfondie</button><button type="button" class="btn" id="clearGuideBtn">Nouvelle discussion</button></div>'
        '<div class="local-brain-bar"><span class="local-dot" id="softwareLocalDot"></span><span class="local-status" id="softwareLocalStatus">Détection du pont local...</span></div></div>'
        '<div class="software-panel"><h2>Réponse du guide</h2><div class="software-guide-output" id="softwareGuideOutput"></div>'
        '<div class="actions" id="softwareMemoryActions" style="display:none;margin-top:10px"><button type="button" class="btn goodbtn" id="softwareSolvedBtn">Résolu : mémoriser cette procédure</button></div>'
        '<div class="bridge-help" style="margin-top:12px"><b>Pourquoi le pont local ?</b><br>Le site Render ne peut pas ouvrir directement les logiciels de ton PC. NOX Local Bridge reste uniquement sur 127.0.0.1 et sert d’intermédiaire entre ton navigateur, Ollama et les applications Windows.</div></div></section>'
        f'<section class="card"><div class="head"><div><h2>Profils logiciels connus</h2><p class="muted">Le catalogue sert à reconnaître les familles de logiciels. NOX-IA peut aussi travailler avec un logiciel qui n’est pas encore dans cette liste.</p></div></div><div class="software-profile-list">{cards}</div></section>'
        f'''<script>
        (function(){{
          const bridge='http://127.0.0.1:8765';
          const csrf={token_js};
          const name=document.getElementById('softwareName'),task=document.getElementById('softwareTask'),out=document.getElementById('softwareGuideOutput');
          const dot=document.getElementById('softwareLocalDot'),status=document.getElementById('softwareLocalStatus'),top=document.getElementById('softwareBrainTop');
          const localBtn=document.getElementById('localGuideBtn'),shot=document.getElementById('softwareShot'),preview=document.getElementById('softwareShotPreview');
          const appsBox=document.getElementById('softwareApps'),memoryActions=document.getElementById('softwareMemoryActions');
          let localReady=false,lastResponse='',guideHistory=[];
          window.noxiaChooseSoftware=function(v){{name.value=v;name.focus();}};
          async function timeoutFetch(url,options,ms){{const c=new AbortController();const t=setTimeout(()=>c.abort(),ms);try{{return await fetch(url,Object.assign({{}},options||{{}},{{signal:c.signal}}));}}finally{{clearTimeout(t);}}}}
          async function detectBrain(){{try{{const r=await timeoutFetch(bridge+'/health',{{cache:'no-store'}},1800);const d=await r.json();localReady=!!(d.ok&&d.model_ready);dot.className='local-dot '+(localReady?'ready':'error');status.textContent=localReady?('Prêt · '+(d.model||'nox-tech:4b')):'Ollama répond mais le modèle NOX-Local n’est pas prêt.';top.className='ai-status '+(localReady?'on':'');top.textContent=localReady?'Cerveau local prêt':'Cerveau local indisponible';localBtn.disabled=!localReady;}}catch(e){{localReady=false;dot.className='local-dot error';status.textContent='Pont local non détecté. Lance DEMARRER_CERVEAU_LOCAL.bat.';top.textContent='Cerveau local indisponible';localBtn.disabled=true;}}}}
          function renderApps(rows){{appsBox.innerHTML='';(rows||[]).slice(0,8).forEach(a=>{{const div=document.createElement('div');div.className='software-app';const b=document.createElement('strong');b.textContent=a.name;const btn=document.createElement('button');btn.type='button';btn.className='btn small';btn.textContent='Choisir';btn.onclick=()=>{{name.value=a.name;}};div.appendChild(b);div.appendChild(btn);appsBox.appendChild(div);}});if(!(rows||[]).length)appsBox.innerHTML='<span class="muted">Aucune application correspondante trouvée dans le menu Démarrer.</span>';}}
          document.getElementById('detectAppsBtn').onclick=async()=>{{if(!localReady){{alert('Le pont local n’est pas démarré.');return;}}try{{const r=await timeoutFetch(bridge+'/apps?q='+encodeURIComponent(name.value),{{cache:'no-store'}},5000);const d=await r.json();renderApps(d.apps||[]);}}catch(e){{alert('Impossible de lire les applications installées.');}}}};
          document.getElementById('openSoftwareBtn').onclick=async()=>{{if(!localReady){{alert('Le pont local n’est pas démarré.');return;}}if(!name.value.trim()){{alert('Indique le logiciel à ouvrir.');return;}}try{{const r=await timeoutFetch(bridge+'/open',{{method:'POST',headers:{{'Content-Type':'application/json','X-NOX-Local':'1'}},body:JSON.stringify({{name:name.value}})}},8000);const d=await r.json();if(!d.ok){{renderApps(d.candidates||[]);throw new Error(d.error||'Application non trouvée');}}status.textContent='Ouverture demandée : '+(d.opened&&d.opened.name?d.opened.name:name.value);}}catch(e){{alert(e.message||'Impossible d’ouvrir le logiciel.');}}}};
          shot.onchange=()=>{{const f=shot.files&&shot.files[0];if(!f){{preview.style.display='none';return;}}const url=URL.createObjectURL(f);preview.src=url;preview.style.display='block';}};
          async function imageBase64(){{const f=shot.files&&shot.files[0];if(!f)return [];if(f.size>6500000)throw new Error('Capture trop volumineuse (maximum 6,5 Mo).');const buf=await f.arrayBuffer();let binary='';const bytes=new Uint8Array(buf);const chunk=0x8000;for(let i=0;i<bytes.length;i+=chunk)binary+=String.fromCharCode.apply(null,bytes.subarray(i,Math.min(i+chunk,bytes.length)));return [btoa(binary)];}}
          async function serverContext(){{const fd=new FormData();fd.append('csrf_token',csrf);fd.append('software',name.value);fd.append('task',task.value);const r=await fetch('/logiciels/context',{{method:'POST',body:fd,credentials:'same-origin'}});const d=await r.json();if(!r.ok)throw new Error(d.detail||'Contexte indisponible');return d;}}
          localBtn.onclick=async()=>{{if(!localReady)return;if(!task.value.trim()){{alert('Explique ce que tu veux faire.');return;}}localBtn.disabled=true;const old=localBtn.textContent;localBtn.textContent='Analyse locale...';out.textContent='';try{{const ctx=await serverContext();const images=await imageBase64();let prompt='Logiciel : '+(name.value||'non précisé')+'\\nObjectif / problème : '+task.value+'\\n\\nContexte NOX-IA :\\n'+ctx.context;const messages=guideHistory.slice(-10);messages.push({{role:'user',content:prompt}});const r=await timeoutFetch(bridge+'/chat',{{method:'POST',headers:{{'Content-Type':'application/json','X-NOX-Local':'1'}},body:JSON.stringify({{model:ctx.model||'nox-tech:4b',system:ctx.system,messages:messages,images:images,think:'low'}})}},260000);const d=await r.json();if(!r.ok||!d.response)throw new Error(d.error||'Aucune réponse locale');lastResponse=d.response;guideHistory.push({{role:'user',content:task.value}});guideHistory.push({{role:'assistant',content:lastResponse}});out.textContent=lastResponse;memoryActions.style.display='flex';}}catch(e){{out.textContent='Erreur : '+(e.message||e);}}finally{{localBtn.disabled=!localReady;localBtn.textContent=old;}}}};
          document.getElementById('cloudGuideBtn').onclick=async()=>{{if(!task.value.trim()){{alert('Explique ce que tu veux faire.');return;}}const btn=document.getElementById('cloudGuideBtn');btn.disabled=true;const old=btn.textContent;btn.textContent='Analyse approfondie...';out.textContent='';try{{const fd=new FormData();fd.append('csrf_token',csrf);fd.append('software',name.value);fd.append('task',task.value);fd.append('history_json',JSON.stringify(guideHistory.slice(-10)));const r=await fetch('/logiciels/cloud-guide',{{method:'POST',body:fd,credentials:'same-origin'}});const d=await r.json();if(!r.ok||!d.response)throw new Error(d.detail||d.error||'Aucune réponse');lastResponse=d.response;guideHistory.push({{role:'user',content:task.value}});guideHistory.push({{role:'assistant',content:lastResponse}});out.textContent=lastResponse;memoryActions.style.display='flex';}}catch(e){{out.textContent='Erreur : '+(e.message||e);}}finally{{btn.disabled=false;btn.textContent=old;}}}};
          document.getElementById('clearGuideBtn').onclick=()=>{{guideHistory=[];lastResponse='';out.textContent='';task.value='';memoryActions.style.display='none';shot.value='';preview.style.display='none';}};
          document.getElementById('softwareSolvedBtn').onclick=async()=>{{if(!lastResponse)return;const fd=new FormData();fd.append('csrf_token',csrf);fd.append('software',name.value);fd.append('task',task.value);fd.append('response_text',lastResponse);const r=await fetch('/logiciels/memoriser',{{method:'POST',body:fd,credentials:'same-origin'}});const d=await r.json();if(r.ok&&d.ok){{alert('Procédure enregistrée dans la mémoire permanente NOX-IA.');memoryActions.style.display='none';}}else alert(d.detail||'Impossible de mémoriser.');}};
          detectBrain();
        }})();
        </script>'''
    )
    return page(request,user,'Guidage logiciels',body)

@app.post('/logiciels/context')
def software_local_context(request:Request,software:str=Form(''),task:str=Form(''),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);user=require_login(request,db);require_role(user,TECHS)
    task=task.strip();software=software.strip()
    if not task:raise HTTPException(400,detail='Objectif ou problème manquant')
    ctx=software_guide_context(db,user,software,task)
    return JSONResponse({'ok':True,'model':'nox-tech:4b','system':SOFTWARE_GUIDE_SYSTEM_PROMPT,'context':ctx['context']})

@app.post('/logiciels/cloud-guide')
def software_cloud_guide(request:Request,software:str=Form(''),task:str=Form(''),history_json:str=Form('[]'),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);user=require_login(request,db);require_role(user,TECHS)
    software=software.strip();task=task.strip()
    if not task:raise HTTPException(400,detail='Objectif ou problème manquant')
    ctx=software_guide_context(db,user,software,task)
    try:
        history=json.loads(history_json or '[]')
        if not isinstance(history,list):history=[]
    except Exception:history=[]
    history_text='\n'.join(f"{str(x.get('role',''))}: {str(x.get('content',''))[:1600]}" for x in history[-8:] if isinstance(x,dict))
    prompt=f"""LOGICIEL
{software or 'non précisé'}

OBJECTIF / PROBLÈME
{task}

CONVERSATION RÉCENTE
{history_text or 'Aucune'}

CONTEXTE NOX-IA
{ctx['context']}

Guide l'utilisateur étape par étape. Si un chemin de menu dépend de la version, vérifie d'abord la documentation officielle disponible ou demande la version. Privilégie les sources officielles du constructeur."""
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
        profiles=software_profile_search(software or task,limit=2)
        known='; '.join(f"{row.get('name')} ({', '.join(row.get('focus') or [])})" for row in profiles)
        response_text=(f"Je reconnais {known or (software or 'ce logiciel')}. Pour te guider sans inventer un menu, indique-moi la version affichée et ce que tu vois actuellement à l’écran. "
                       f"Ton objectif est : {task}. Si le cerveau local est installé, tu peux aussi joindre une capture d’écran pour un guidage visuel.")
    profiles=software_profile_search(software,1);vendor=profiles[0].get('vendor','') if profiles else ''
    assistant_memory_add(db,'conversation',f'Guide logiciel — {(software or task)[:120]}',f'Question: {task}\nRéponse: {response_text[:3200]}',keywords=assistant_memory_keywords(software+' '+task),source='guide_logiciel_ia',constructeur=vendor,confidence='faible',utilisateur=user.username,source_ref='guide-logiciel')
    db.commit()
    return JSONResponse({'ok':True,'response':response_text})

@app.post('/logiciels/memoriser')
def software_memorize_resolved(request:Request,software:str=Form(''),task:str=Form(...),response_text:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);user=require_login(request,db);require_role(user,TECHS)
    software=software.strip();task=task.strip();response_text=response_text.strip()
    if not task or not response_text:raise HTTPException(400,detail='Procédure vide')
    profiles=software_profile_search(software,1);vendor=profiles[0].get('vendor','') if profiles else ''
    row=assistant_memory_add(db,'cas_resolu',f'Procédure logiciel résolue — {(software or "Logiciel")[:120]}',f'Objectif: {task}\nProcédure ayant fonctionné selon le technicien:\n{response_text[:6000]}',keywords=assistant_memory_keywords(software+' '+task+' '+response_text),source='guide_logiciel_resolu',constructeur=vendor,confidence='élevée',utilisateur=user.username,source_ref='guide-logiciel-resolu')
    db.commit();return JSONResponse({'ok':True,'memory_id':row.id if row else None})

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
                     f'<form method="post" action="/utilisateurs/{x.id}/mot-de-passe" class="inline-form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><input type="password" name="password" minlength="8" placeholder="Nouveau mot de passe" required><button class="btn small">Changer</button></form>{state_button}{delete_button}{self_note}</div>')
        trs+=f'<tr><td>{x.id}</td><td>{escape(x.username)}</td><td>{badge(x.role)}</td><td>{badge("Actif" if x.active else "Inactif")}</td><td>{actions}</td></tr>'
    if u.role=='Administrateur':
        form=f'<section class="card"><h2>Créer un utilisateur</h2><form method="post" class="form"><input type="hidden" name="csrf_token" value="{csrf_token(request)}"><label>Utilisateur<input name="username" required></label><label>Mot de passe<input type="password" name="password" minlength="8" required></label><label>Rôle<select name="role">{"".join(f"<option>{r}</option>" for r in ROLES)}</select></label><button class="btn primary">Créer</button></form></section>'
    return page(request,u,'Utilisateurs',f'<h1>Utilisateurs</h1>{form}<section class="card"><div class="scroll"><table><tr><th>ID</th><th>Utilisateur</th><th>Rôle</th><th>État</th><th>Actions</th></tr>{trs}</table></div></section>')

@app.post('/utilisateurs')
def users_add(request:Request,username:str=Form(...),password:str=Form(...),role:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token'),db:Session=Depends(get_db)):
    check_csrf(request,csrf_token_value);_admin_only(request,db)
    username=username.strip()
    if len(username)<2:raise HTTPException(400,'Nom utilisateur trop court')
    if len(password)<8:raise HTTPException(400,'Mot de passe : 8 caractères minimum')
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
    if len(password)<8:raise HTTPException(400,'Mot de passe : 8 caractères minimum')
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
    db.delete(target);db.commit();return RedirectResponse('/utilisateurs?msg=Utilisateur+supprimé',303)

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
    db.execute(DiagnosticStep.__table__.delete())
    db.execute(Diagnostic.__table__.delete())
    db.execute(InterventionPhoto.__table__.delete())
    db.execute(InterventionMaterial.__table__.delete())
    db.execute(MaintenanceHistory.__table__.delete().where(MaintenanceHistory.intervention_id.is_not(None)))
    db.execute(PlanningEntry.__table__.delete().where(PlanningEntry.intervention_id.is_not(None)))
    db.execute(StockMovement.__table__.update().where(StockMovement.intervention_id.is_not(None)).values(intervention_id=None))
    db.execute(Intervention.__table__.delete())

def _wipe_structure(db):
    _wipe_interventions(db)
    # Les tables dépendantes sont supprimées en suivant l'ordre des FK SQLAlchemy.
    names={'web_contract_scope','web_maintenance_history','web_maintenance_plans','web_contracts','web_assistant_exchanges','web_equipements','web_sites','web_clients'}
    for table in reversed(Base.metadata.sorted_tables):
        if table.name in names:db.execute(table.delete())

def _wipe_management(db):
    names={'web_supplier_prices','web_stock_movements','web_intervention_materials','web_contract_scope','web_maintenance_history','web_maintenance_plans','web_contracts','web_follow_actions','web_alert_states','web_planning','web_suppliers','web_stock_items'}
    for table in reversed(Base.metadata.sorted_tables):
        if table.name in names:db.execute(table.delete())

def _wipe_other_users(db,current_id):
    db.execute(AssistantExchange.__table__.update().where(AssistantExchange.user_id!=current_id).values(user_id=None))
    db.execute(User.__table__.delete().where(User.id!=current_id))

@app.get('/sante')
def health(request:Request,db:Session=Depends(get_db)):
    u=require_login(request,db);score=100;checks=[]
    try:db.execute(text('SELECT 1'));checks.append(('OK','Base de données','Connexion opérationnelle'))
    except Exception as e:score-=30;checks.append(('Critique','Base de données',str(e)))
    cc=len(core_catalog());checks.append(('OK' if cc else 'Avertissement','NOX-Core',f'{cc} fiche(s) chargée(s)'))
    if not cc:score-=7
    mem_count=db.scalar(select(func.count(AssistantMemory.id))) or 0;mem_cls,mem_status=assistant_memory_storage_status();checks.append(('OK' if mem_cls=='good' else 'Avertissement','Mémoire IA',f'{mem_count} élément(s) · {mem_status}'))
    alerts=derive_alerts(db);crit=sum(1 for x in alerts if x[0]=='critique');checks.append(('OK' if not crit else 'Avertissement','Alertes',f'{crit} critique(s), {len(alerts)} alerte(s) active(s)'));score=max(0,score-min(20,crit*5));trs=''.join(f'<tr><td>{badge(a)}</td><td>{escape(b)}</td><td>{escape(c)}</td></tr>' for a,b,c in checks)
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
    u=require_login(request,db);require_role(u,MANAGERS);models=[AssistantMemory,AssistantExchange,Client,Site,Equipement,Intervention,StockItem,StockMovement,InterventionMaterial,Supplier,SupplierPrice,PlanningEntry,MaintenancePlan,MaintenanceHistory,Contract,FollowAction,AlertState,Diagnostic,DiagnosticStep];payload={'exported_at':datetime.utcnow().isoformat(),'version':APP_VERSION,'tables':{}}
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
