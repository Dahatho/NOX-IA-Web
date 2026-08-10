"""NOX-IA Local Bridge

Companion local Windows de NOX-IA.
- expose seulement 127.0.0.1:8765
- dialogue avec Ollama local
- peut lister/ouvrir des applications présentes dans le menu Démarrer
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

BRIDGE_VERSION = "1.0.3"
HOST = "127.0.0.1"
PORT = int(os.environ.get("NOX_LOCAL_BRIDGE_PORT", "8765"))
OLLAMA_BASE = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
DEFAULT_MODEL = os.environ.get("NOX_LOCAL_MODEL", "nox-tech:4b")
MAX_BODY = 14 * 1024 * 1024
APP_CACHE_TTL = 90

ALLOWED_ORIGINS = {
    "https://nox-ia-assistant.onrender.com",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "http://127.0.0.1:8001",
    "http://localhost:8001",
}
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
