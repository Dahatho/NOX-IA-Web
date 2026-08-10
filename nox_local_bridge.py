"""NOX-IA Local Bridge

Companion local Windows de NOX-IA.
- expose seulement 127.0.0.1:8765
- dialogue avec Ollama local
- peut lister/ouvrir des applications présentes dans le menu Démarrer
- génère une voix Windows locale via System.Speech pour NOX Vocal
- ne permet aucune commande shell arbitraire

Python standard library uniquement.
"""
from __future__ import annotations

import base64
import difflib
import json
import os
import re
import subprocess
import sys
import threading
import time
import unicodedata
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BRIDGE_VERSION = "1.3.0"
HOST = "127.0.0.1"
PORT = int(os.environ.get("NOX_LOCAL_BRIDGE_PORT", "8765"))
OLLAMA_BASE = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
DEFAULT_MODEL = os.environ.get("NOX_LOCAL_MODEL", "nox-tech:4b")
MAX_BODY = 14 * 1024 * 1024
APP_CACHE_TTL = 90

ALLOWED_ORIGINS = {
    "https://nox-ia-assistant.onrender.com",
    # Le compagnon intégré est lui-même servi depuis 127.0.0.1:8765.
    # Ses POST /chat et /guide doivent donc être acceptés comme origine locale.
    "http://127.0.0.1:8765",
    "http://localhost:8765",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "http://127.0.0.1:8001",
    "http://localhost:8001",
}
# Toujours autoriser l'origine exacte du pont lui-même, même si le port est personnalisé.
ALLOWED_ORIGINS.add(f"http://{HOST}:{PORT}")
ALLOWED_ORIGINS.add(f"http://localhost:{PORT}")

extra_origin = os.environ.get("NOX_IA_WEB_ORIGIN", "").strip()
if extra_origin:
    ALLOWED_ORIGINS.add(extra_origin.rstrip("/"))

_app_cache = {"at": 0.0, "rows": []}
_app_lock = threading.Lock()


def normalize(value: str) -> str:
    value = unicodedata.normalize("NFKD", str(value or ""))
    value = "".join(ch for ch in value if not unicodedata.combining(ch))
    value = value.lower().replace("•", " ")
    value = re.sub(r"[^a-z0-9]+", " ", value)
    return " ".join(value.split())


def http_json(method: str, url: str, payload=None, timeout=120):
    data = None
    headers = {"Content-Type": "application/json"}
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        return json.loads(raw.decode("utf-8")) if raw else {}


def ollama_tags():
    try:
        data = http_json("GET", f"{OLLAMA_BASE}/api/tags", timeout=3)
        return data.get("models", [])
    except Exception:
        return []


def ollama_chat(model: str, system: str, messages: list, images=None, think="low"):
    msgs = []
    if system.strip():
        msgs.append({"role": "system", "content": system.strip()})
    for item in messages or []:
        role = item.get("role", "user")
        content = str(item.get("content", ""))
        row = {"role": role if role in {"user", "assistant", "system"} else "user", "content": content}
        if role == "user" and images:
            row["images"] = images
            images = None
        msgs.append(row)
    payload = {
        "model": model or DEFAULT_MODEL,
        "messages": msgs,
        "stream": False,
        "think": think if think in {"low", "medium", "high", False, True} else "low",
        "keep_alive": "10m",
        "options": {"temperature": 0.18, "num_ctx": 8192},
    }
    data = http_json("POST", f"{OLLAMA_BASE}/api/chat", payload, timeout=240)
    message = data.get("message") or {}
    return {
        "response": (message.get("content") or "").strip(),
        "thinking": (message.get("thinking") or "").strip(),
        "model": data.get("model", model or DEFAULT_MODEL),
        "eval_count": data.get("eval_count"),
        "total_duration": data.get("total_duration"),
    }


def _powershell_json(command: str, timeout=12):
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if proc.returncode != 0:
        return []
    raw = proc.stdout.strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
        return data if isinstance(data, list) else [data]
    except Exception:
        return []


def installed_apps(force=False):
    now = time.time()
    with _app_lock:
        if not force and _app_cache["rows"] and now - _app_cache["at"] < APP_CACHE_TTL:
            return list(_app_cache["rows"])
        rows = _powershell_json(
            "Get-StartApps | Select-Object Name,AppID | Sort-Object Name | ConvertTo-Json -Compress",
            timeout=15,
        )
        clean = []
        seen = set()
        for row in rows:
            name = str(row.get("Name") or "").strip()
            appid = str(row.get("AppID") or "").strip()
            if not name or not appid:
                continue
            key = (name.lower(), appid.lower())
            if key in seen:
                continue
            seen.add(key)
            clean.append({"name": name, "app_id": appid})
        _app_cache.update({"at": now, "rows": clean})
        return list(clean)


def search_apps(query: str, limit=25):
    rows = installed_apps()
    q = normalize(query)
    if not q:
        return rows[:limit]
    scored = []
    q_words = set(q.split())
    for row in rows:
        name_n = normalize(row["name"])
        words = set(name_n.split())
        overlap = len(q_words & words)
        ratio = difflib.SequenceMatcher(None, q, name_n).ratio()
        contains = 1 if q in name_n or name_n in q else 0
        score = contains * 5 + overlap * 2 + ratio
        if score >= 0.45:
            scored.append((score, row))
    scored.sort(key=lambda x: (-x[0], x[1]["name"].lower()))
    return [row for _, row in scored[:limit]]


def open_app(query: str):
    candidates = search_apps(query, limit=8)
    if not candidates:
        return {"ok": False, "error": "Aucune application correspondante trouvée dans le menu Démarrer.", "candidates": []}
    best = candidates[0]
    q = normalize(query)
    score = difflib.SequenceMatcher(None, q, normalize(best["name"])).ratio()
    if q not in normalize(best["name"]) and score < 0.48:
        return {"ok": False, "error": "Correspondance trop incertaine.", "candidates": candidates}
    app_id = best["app_id"]
    # L'AppID vient exclusivement de Windows Get-StartApps, jamais de l'utilisateur.
    safe = app_id.replace("'", "''")
    cmd = f"Start-Process 'shell:AppsFolder\\{safe}'"
    try:
        subprocess.Popen(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return {"ok": True, "opened": best, "candidates": candidates}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "candidates": candidates}




def windows_tts(text: str, language="fr-FR", gender="male", rate=0):
    """Generate a WAV with Windows System.Speech."""
    if os.name != "nt":
        raise RuntimeError("Le TTS local System.Speech est disponible uniquement sous Windows.")
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    if not text:
        raise ValueError("Texte vocal vide.")
    text = text[:900]
    text_b64 = base64.b64encode(text.encode("utf-8")).decode("ascii")
    try:
        rate_i = max(-2, min(2, int(rate)))
    except Exception:
        rate_i = 0
    ps = f"""
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Speech
$text=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{text_b64}'))
$synth=New-Object System.Speech.Synthesis.SpeechSynthesizer
$synth.Rate={rate_i}
$synth.Volume=100
$voices=@($synth.GetInstalledVoices() | Where-Object {{$_.Enabled}})
$fr=@($voices | Where-Object {{$_.VoiceInfo.Culture.Name -like 'fr*'}})
$male=@($fr | Where-Object {{$_.VoiceInfo.Gender.ToString() -eq 'Male'}})
$chosen=$null
if($male.Count -gt 0){{$chosen=$male[0]}}
elseif($fr.Count -gt 0){{$chosen=$fr[0]}}
elseif($voices.Count -gt 0){{$chosen=$voices[0]}}
if($chosen){{$synth.SelectVoice($chosen.VoiceInfo.Name)}}
$voiceName=if($chosen){{$chosen.VoiceInfo.Name}}else{{$synth.Voice.Name}}
$ms=New-Object IO.MemoryStream
$synth.SetOutputToWaveStream($ms)
$synth.Speak($text)
$synth.SetOutputToNull()
$bytes=$ms.ToArray()
$ms.Dispose()
$synth.Dispose()
[PSCustomObject]@{{voice=$voiceName;audio=[Convert]::ToBase64String($bytes)}} | ConvertTo-Json -Compress
"""
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=35,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or "System.Speech a échoué.")[:800])
    data = json.loads((proc.stdout or "").strip())
    audio = str(data.get("audio") or "")
    if not audio:
        raise RuntimeError("Audio Windows vide.")
    return {
        "ok": True,
        "audio_base64": audio,
        "mime": "audio/wav",
        "voice": str(data.get("voice") or ""),
        "backend": "windows-system-speech",
    }


COMPANION_HTML = r"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NOX-IA · Pont local intégré</title>
<style>html,body{margin:0;background:#07111e;color:#eaf3ff;font-family:Segoe UI,system-ui,sans-serif}main{padding:16px}.card{background:#0d1b2e;border:1px solid #25415f;border-radius:14px;padding:16px}.status{padding:10px;border-radius:9px;background:#081625;border:1px solid #294564}.ok{border-color:#2f765e;color:#b8f7de}.err{border-color:#7a4650;color:#ffc3cb}</style></head>
<body><main><div class="card"><b>🧠 NOX-IA · Pont local</b><div id="status" class="status">Connexion…</div></div></main>
<script>
const ALLOWED=new Set(['https://nox-ia-assistant.onrender.com','http://127.0.0.1:8000','http://localhost:8000','http://127.0.0.1:8001','http://localhost:8001']);
let peerOrigin=null;
try{const u=new URL(document.referrer);if(ALLOWED.has(u.origin))peerOrigin=u.origin;}catch(e){}
function peerWindow(){
  if(window.parent&&window.parent!==window)return window.parent;
  if(window.opener&&!window.opener.closed)return window.opener;
  return null;
}
function post(msg,origin){
  try{const w=peerWindow();if(w)w.postMessage(msg,origin||peerOrigin||'*');}catch(e){}
}
async function jfetch(url,opt){const r=await fetch(url,opt);const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.error||('HTTP '+r.status));return d;}
async function health(){
  const s=document.getElementById('status');
  try{
    const d=await jfetch('/health',{cache:'no-store'});
    const ok=!!(d.ok&&d.model_ready);
    s.textContent=ok?('✅ '+(d.model||'nox-tech:4b')+' · '+(d.bridge_version||'')):'⚠️ Modèle non prêt';
    s.className='status '+(ok?'ok':'err');
    if(peerOrigin)post({type:'noxia-local-ready',data:d},peerOrigin);
  }catch(e){s.textContent='❌ '+e.message;s.className='status err';}
}
window.addEventListener('message',async ev=>{
  if(!ALLOWED.has(ev.origin))return;
  peerOrigin=ev.origin;
  const m=ev.data||{};
  if(m.type!=='noxia-local-request'||!m.id)return;
  try{
    let d;
    if(m.action==='health'){
      d=await jfetch('/health',{cache:'no-store'});
    }else if(m.action==='chat'){
      d=await jfetch('/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(m.payload||{})});
    }else if(m.action==='guide'){
      d=await jfetch('/guide',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(m.payload||{})});
    }else{
      throw new Error('Action locale inconnue');
    }
    post({type:'noxia-local-response',id:m.id,ok:true,data:d},ev.origin);
  }catch(e){
    post({type:'noxia-local-response',id:m.id,ok:false,error:e.message||'Erreur locale'},ev.origin);
  }
});
health();setInterval(health,30000);
</script></body></html>"""

class Handler(BaseHTTPRequestHandler):
    server_version = "NOXLocalBridge/" + BRIDGE_VERSION

    def log_message(self, fmt, *args):
        # Réduit le bruit tout en gardant les erreurs visibles.
        if os.environ.get("NOX_LOCAL_VERBOSE") == "1":
            super().log_message(fmt, *args)

    def _origin(self):
        return (self.headers.get("Origin") or "").rstrip("/")

    def _connector_marker(self):
        direct = (self.headers.get("X-NOX-Local") or "").strip() == "1"
        requested = (self.headers.get("Access-Control-Request-Headers") or "").lower()
        return direct or "x-nox-local" in requested

    def _cors_allowed(self):
        origin = self._origin()
        # Chrome peut présenter les requêtes d'une extension avec
        # chrome-extension://<id>, sans Origin, ou dans certains cas Origin:null.
        # Le cas "null" n'est accepté que si la requête porte le marqueur explicite
        # X-NOX-Local utilisé par le connecteur NOX-IA.
        return (
            not origin
            or origin in ALLOWED_ORIGINS
            or origin.startswith("chrome-extension://")
            or (origin == "null" and self._connector_marker())
        )

    def _headers(self, status=200, content_type="application/json; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        origin = self._origin()
        if origin and (
            origin in ALLOWED_ORIGINS
            or origin.startswith('chrome-extension://')
            or (origin == 'null' and self._connector_marker())
        ):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-NOX-Local")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Cross-Origin-Resource-Policy", "cross-origin")
        self.end_headers()

    def _send(self, payload, status=200):
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._headers(status)
        self.wfile.write(raw)

    def _read_json(self):
        try:
            size = int(self.headers.get("Content-Length") or 0)
        except Exception:
            size = 0
        if size <= 0 or size > MAX_BODY:
            raise ValueError("Taille de requête invalide")
        raw = self.rfile.read(size)
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("JSON attendu")
        return data

    def do_OPTIONS(self):
        if not self._cors_allowed():
            self._send({"error": "Origin non autorisée", "origin": self._origin() or "(aucune)", "bridge_version": BRIDGE_VERSION}, 403)
            return
        self._headers(204)

    def do_GET(self):
        if not self._cors_allowed():
            self._send({"error": "Origin non autorisée", "origin": self._origin() or "(aucune)", "bridge_version": BRIDGE_VERSION}, 403)
            return
        path = self.path.split("?", 1)[0]
        if path == "/companion":
            raw = COMPANION_HTML.encode("utf-8")
            self._headers(200, "text/html; charset=utf-8")
            self.wfile.write(raw)
            return
        if path == "/health":
            models = ollama_tags()
            names = [str(m.get("name") or m.get("model") or "") for m in models]
            ready = any(name == DEFAULT_MODEL or name.startswith(DEFAULT_MODEL + ":") for name in names)
            if DEFAULT_MODEL.startswith("nox-tech") and not ready:
                ready = any(name.startswith("qwen3.5:4b") for name in names)
            self._send({
                "ok": bool(models),
                "bridge_version": BRIDGE_VERSION,
                "ollama": bool(models),
                "model": DEFAULT_MODEL,
                "model_ready": ready,
                "models": names[:30],
                "desktop_control": os.name == "nt",
                "tts": os.name == "nt",
                "tts_backend": "windows-system-speech" if os.name == "nt" else "",
            })
            return
        if path == "/apps":
            from urllib.parse import parse_qs, urlparse
            q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            self._send({"apps": search_apps(q, 40), "query": q})
            return
        if path == "/models":
            self._send({"models": ollama_tags()})
            return
        self._send({"error": "Route inconnue"}, 404)

    def do_POST(self):
        if not self._cors_allowed():
            self._send({"error": "Origin non autorisée", "origin": self._origin() or "(aucune)", "bridge_version": BRIDGE_VERSION}, 403)
            return
        try:
            data = self._read_json()
        except Exception as exc:
            self._send({"error": str(exc)}, 400)
            return
        path = self.path.split("?", 1)[0]
        try:
            if path == "/chat":
                model = str(data.get("model") or DEFAULT_MODEL)
                system = str(data.get("system") or "")
                messages = data.get("messages") or []
                images = data.get("images") or []
                if not isinstance(messages, list):
                    raise ValueError("messages doit être une liste")
                if images and (not isinstance(images, list) or len(images) > 2):
                    raise ValueError("Maximum 2 images")
                # Validation légère de la taille base64.
                for img in images:
                    if len(str(img)) > 9_000_000:
                        raise ValueError("Image trop volumineuse")
                result = ollama_chat(model, system, messages, images=images, think=data.get("think", "low"))
                if not result.get("response"):
                    raise RuntimeError("Ollama n'a renvoyé aucune réponse")
                self._send({"ok": True, **result})
                return
            if path == "/tts":
                result = windows_tts(
                    str(data.get("text") or ""),
                    language=str(data.get("language") or "fr-FR"),
                    gender=str(data.get("gender") or "male"),
                    rate=data.get("rate", 0),
                )
                self._send(result)
                return
            if path == "/guide":
                software = str(data.get("software") or "").strip()
                task = str(data.get("task") or "").strip()
                context = str(data.get("context") or "")
                images = data.get("images") or []
                system = str(data.get("system") or "")
                prompt = (
                    f"LOGICIEL: {software or 'non précisé'}\n"
                    f"OBJECTIF / PROBLÈME: {task}\n\n"
                    f"CONTEXTE FOURNI PAR NOX-IA:\n{context[:18000]}\n\n"
                    "Guide le technicien étape par étape. Donne seulement les étapes justifiées par le contexte. "
                    "Si un menu dépend de la version ou n'est pas certain, dis-le et demande ce qui est visible à l'écran."
                )
                result = ollama_chat(str(data.get("model") or DEFAULT_MODEL), system, [{"role": "user", "content": prompt}], images=images, think="low")
                self._send({"ok": True, **result})
                return
            if path == "/open":
                query = str(data.get("name") or "").strip()
                if not query:
                    raise ValueError("Nom du logiciel manquant")
                result = open_app(query)
                self._send(result, 200 if result.get("ok") else 404)
                return
            if path == "/refresh-apps":
                self._send({"apps": installed_apps(force=True)[:100]})
                return
            self._send({"error": "Route inconnue"}, 404)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace") if hasattr(exc, "read") else str(exc)
            self._send({"error": f"Ollama HTTP {exc.code}: {detail[:600]}"}, 502)
        except urllib.error.URLError:
            self._send({"error": "Ollama n'est pas joignable sur ce PC. Lance Ollama puis réessaie."}, 503)
        except Exception as exc:
            self._send({"error": str(exc)}, 500)


def main():
    if os.name != "nt":
        print("Attention: l'ouverture de logiciels est prévue pour Windows; le chat local reste utilisable.")
    print(f"NOX-IA Local Bridge {BRIDGE_VERSION}")
    print(f"Adresse locale: http://{HOST}:{PORT}")
    print(f"Ollama: {OLLAMA_BASE} | modèle: {DEFAULT_MODEL}")
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
