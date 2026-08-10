"""NOX-IA Local Bridge 2.0.0

Pont Windows minimal entre le site NOX-IA et Ollama.
- écoute uniquement sur 127.0.0.1:8765
- accepte le site NOX-IA officiel et les tests locaux
- aucune extension Chrome, aucun iframe, aucune fenêtre secondaire
- bibliothèque standard Python uniquement
"""
from __future__ import annotations

import difflib
import json
import os
import re
import subprocess
import threading
import time
import unicodedata
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BRIDGE_VERSION = "2.0.0"
HOST = "127.0.0.1"
PORT = int(os.environ.get("NOX_LOCAL_BRIDGE_PORT", "8765"))
OLLAMA_BASE = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
DEFAULT_MODEL = os.environ.get("NOX_LOCAL_MODEL", "nox-tech:4b")
MAX_BODY = 16 * 1024 * 1024

ALLOWED_ORIGINS = {
    "https://nox-ia-assistant.onrender.com",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "http://127.0.0.1:8765",
    "http://localhost:8765",
}
extra = os.environ.get("NOX_IA_WEB_ORIGIN", "").strip().rstrip("/")
if extra:
    ALLOWED_ORIGINS.add(extra)

APP_CACHE_TTL = 120
_app_cache = {"at": 0.0, "rows": []}
_app_lock = threading.Lock()


def normalize(value: str) -> str:
    value = unicodedata.normalize("NFKD", str(value or ""))
    value = "".join(ch for ch in value if not unicodedata.combining(ch))
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", " ", value)
    return " ".join(value.split())


def http_json(method: str, url: str, payload=None, timeout=180):
    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read()
        return json.loads(raw.decode("utf-8")) if raw else {}


def ollama_models():
    try:
        data = http_json("GET", f"{OLLAMA_BASE}/api/tags", timeout=4)
        return data.get("models", []) if isinstance(data, dict) else []
    except Exception:
        return []


def model_names():
    return [str(m.get("name") or m.get("model") or "") for m in ollama_models()]


def model_is_ready(names=None):
    names = names if names is not None else model_names()
    return any(name == DEFAULT_MODEL or name.startswith(DEFAULT_MODEL + ":") for name in names)


def ollama_chat(model: str, system: str, messages: list, images=None):
    rows = []
    if str(system or "").strip():
        rows.append({"role": "system", "content": str(system).strip()})
    image_list = list(images or [])
    for item in messages or []:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "user")
        if role not in {"user", "assistant", "system"}:
            role = "user"
        row = {"role": role, "content": str(item.get("content") or "")}
        if role == "user" and image_list:
            row["images"] = image_list[:2]
            image_list = []
        rows.append(row)
    if not rows:
        raise ValueError("Aucun message à envoyer au modèle")

    payload = {
        "model": model or DEFAULT_MODEL,
        "messages": rows,
        "stream": False,
        "think": False,
        "keep_alive": "10m",
        "options": {"temperature": 0.2, "num_ctx": 8192, "repeat_penalty": 1.05},
    }
    data = http_json("POST", f"{OLLAMA_BASE}/api/chat", payload, timeout=300)
    message = data.get("message") or {}
    response = str(message.get("content") or "").strip()
    if not response:
        raise RuntimeError("Ollama n'a renvoyé aucune réponse finale")
    return {
        "response": response,
        "model": str(data.get("model") or model or DEFAULT_MODEL),
        "eval_count": data.get("eval_count"),
        "total_duration": data.get("total_duration"),
    }


def _powershell_json(command: str, timeout=15):
    if os.name != "nt":
        return []
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return []
    try:
        data = json.loads(proc.stdout.strip())
        return data if isinstance(data, list) else [data]
    except Exception:
        return []


def installed_apps(force=False):
    now = time.time()
    with _app_lock:
        if not force and _app_cache["rows"] and now - _app_cache["at"] < APP_CACHE_TTL:
            return list(_app_cache["rows"])
        rows = _powershell_json("Get-StartApps | Select-Object Name,AppID | Sort-Object Name | ConvertTo-Json -Compress")
        clean, seen = [], set()
        for row in rows:
            name = str(row.get("Name") or "").strip()
            appid = str(row.get("AppID") or "").strip()
            key = (name.lower(), appid.lower())
            if not name or not appid or key in seen:
                continue
            seen.add(key)
            clean.append({"name": name, "app_id": appid})
        _app_cache.update({"at": now, "rows": clean})
        return list(clean)


def search_apps(query: str, limit=25):
    q = normalize(query)
    rows = installed_apps()
    if not q:
        return rows[:limit]
    words = set(q.split())
    scored = []
    for row in rows:
        name_n = normalize(row["name"])
        overlap = len(words & set(name_n.split()))
        ratio = difflib.SequenceMatcher(None, q, name_n).ratio()
        contains = 1 if q in name_n or name_n in q else 0
        score = contains * 5 + overlap * 2 + ratio
        if score >= 0.45:
            scored.append((score, row))
    scored.sort(key=lambda item: (-item[0], item[1]["name"].lower()))
    return [row for _, row in scored[:limit]]


def open_app(query: str):
    if os.name != "nt":
        return {"ok": False, "error": "Ouverture d'applications disponible uniquement sous Windows."}
    candidates = search_apps(query, 8)
    if not candidates:
        return {"ok": False, "error": "Application non trouvée.", "candidates": []}
    best = candidates[0]
    app_id = best["app_id"].replace("'", "''")
    try:
        subprocess.Popen(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", f"Start-Process 'shell:AppsFolder\\{app_id}'"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return {"ok": True, "opened": best, "candidates": candidates}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "candidates": candidates}


class Server(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class Handler(BaseHTTPRequestHandler):
    server_version = "NOXLocalBridge/" + BRIDGE_VERSION

    def log_message(self, fmt, *args):
        if os.environ.get("NOX_LOCAL_VERBOSE") == "1":
            super().log_message(fmt, *args)

    def origin(self):
        return (self.headers.get("Origin") or "").rstrip("/")

    def origin_allowed(self):
        origin = self.origin()
        return not origin or origin in ALLOWED_ORIGINS

    def send_common_headers(self, status=200, content_type="application/json; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        origin = self.origin()
        if origin and origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Cross-Origin-Resource-Policy", "cross-origin")
        self.end_headers()

    def send_json(self, payload, status=200):
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_common_headers(status)
        self.wfile.write(raw)

    def read_json(self):
        try:
            size = int(self.headers.get("Content-Length") or "0")
        except Exception:
            raise ValueError("Content-Length invalide")
        if size <= 0 or size > MAX_BODY:
            raise ValueError("Taille de requête invalide")
        raw = self.rfile.read(size)
        try:
            data = json.loads(raw.decode("utf-8"))
        except UnicodeDecodeError:
            raise ValueError("Le corps doit être encodé en UTF-8")
        except json.JSONDecodeError as exc:
            raise ValueError(f"JSON invalide: {exc.msg}")
        if not isinstance(data, dict):
            raise ValueError("Objet JSON attendu")
        return data

    def do_OPTIONS(self):
        if not self.origin_allowed():
            self.send_json({"ok": False, "error": "Origin non autorisée", "origin": self.origin(), "bridge_version": BRIDGE_VERSION}, 403)
            return
        self.send_common_headers(204)

    def do_GET(self):
        if not self.origin_allowed():
            self.send_json({"ok": False, "error": "Origin non autorisée", "origin": self.origin(), "bridge_version": BRIDGE_VERSION}, 403)
            return
        path = self.path.split("?", 1)[0]
        if path == "/health":
            names = model_names()
            self.send_json({
                "ok": bool(names),
                "bridge_version": BRIDGE_VERSION,
                "ollama": bool(names),
                "model": DEFAULT_MODEL,
                "model_ready": model_is_ready(names),
                "models": names[:30],
                "desktop_control": os.name == "nt",
            })
            return
        if path == "/apps":
            from urllib.parse import parse_qs, urlparse
            q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            self.send_json({"ok": True, "query": q, "apps": search_apps(q, 40)})
            return
        self.send_json({"ok": False, "error": "Route inconnue"}, 404)

    def do_POST(self):
        if not self.origin_allowed():
            self.send_json({"ok": False, "error": "Origin non autorisée", "origin": self.origin(), "bridge_version": BRIDGE_VERSION}, 403)
            return
        try:
            data = self.read_json()
            path = self.path.split("?", 1)[0]
            if path == "/chat":
                messages = data.get("messages") or []
                images = data.get("images") or []
                if not isinstance(messages, list):
                    raise ValueError("messages doit être une liste")
                if not isinstance(images, list) or len(images) > 2:
                    raise ValueError("images doit contenir au maximum 2 éléments")
                result = ollama_chat(
                    str(data.get("model") or DEFAULT_MODEL),
                    str(data.get("system") or ""),
                    messages,
                    images=images,
                )
                self.send_json({"ok": True, **result})
                return
            if path == "/open":
                name = str(data.get("name") or "").strip()
                if not name:
                    raise ValueError("Nom du logiciel manquant")
                result = open_app(name)
                self.send_json(result, 200 if result.get("ok") else 404)
                return
            if path == "/refresh-apps":
                self.send_json({"ok": True, "apps": installed_apps(force=True)[:100]})
                return
            self.send_json({"ok": False, "error": "Route inconnue"}, 404)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace") if hasattr(exc, "read") else str(exc)
            self.send_json({"ok": False, "error": f"Ollama HTTP {exc.code}: {detail[:800]}"}, 502)
        except urllib.error.URLError:
            self.send_json({"ok": False, "error": "Ollama n'est pas joignable. Lance Ollama puis réessaie."}, 503)
        except Exception as exc:
            status = 400 if isinstance(exc, ValueError) else 500
            self.send_json({"ok": False, "error": str(exc)}, status)


def main():
    print(f"NOX-IA Local Bridge {BRIDGE_VERSION}")
    print(f"Adresse : http://{HOST}:{PORT}")
    print(f"Ollama : {OLLAMA_BASE} | Modèle : {DEFAULT_MODEL}")
    print("Extension Chrome : inutile")
    server = Server((HOST, PORT), Handler)
    try:
        server.serve_forever(poll_interval=0.3)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
