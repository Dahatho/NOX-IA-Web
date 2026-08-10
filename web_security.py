import secrets, hashlib

def hash_password(p): return 'x$'+hashlib.sha256(p.encode()).hexdigest()
def verify_password(p,h): return h==hash_password(p)
def new_csrf_token(): return secrets.token_urlsafe(16)
