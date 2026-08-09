import os
import secrets

from pathlib import Path

from fastapi import (
    Depends,
    FastAPI,
    Form,
    HTTPException,
    Request,
    status,
)
from fastapi.responses import (
    HTMLResponse,
    RedirectResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload
from starlette.middleware.sessions import SessionMiddleware

from web_models import (
    Base,
    Client,
    Equipement,
    Intervention,
    SessionLocal,
    Site,
    User,
    engine,
)
from web_security import (
    hash_password,
    new_csrf_token,
    verify_password,
)


APP_VERSION = "3.0.0-web-beta"

ROLES = (
    "Administrateur",
    "Responsable",
    "Technicien",
    "Lecture seule",
)

ROLE_MANAGE_STRUCTURE = {
    "Administrateur",
    "Responsable",
}

ROLE_CREATE_INTERVENTION = {
    "Administrateur",
    "Responsable",
    "Technicien",
}


app = FastAPI(
    title="NOX-IA Web",
    version=APP_VERSION,
)

secret_key = os.environ.get(
    "SECRET_KEY",
    secrets.token_urlsafe(48),
)

app.add_middleware(
    SessionMiddleware,
    secret_key=secret_key,
    https_only=bool(
        os.environ.get(
            "RENDER",
            ""
        )
    ),
    same_site="lax",
)

BASE_DIR = Path(__file__).resolve().parent

app.mount(
    "/static",
    StaticFiles(
        directory=BASE_DIR / "static"
    ),
    name="static",
)

templates = Jinja2Templates(
    directory=BASE_DIR / "templates"
)


def get_db():
    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()


def ensure_csrf(request: Request) -> str:
    token = request.session.get(
        "csrf_token"
    )

    if not token:
        token = new_csrf_token()
        request.session[
            "csrf_token"
        ] = token

    return token


def check_csrf(
    request: Request,
    token: str,
):
    expected = request.session.get(
        "csrf_token",
        "",
    )

    if not (
        expected
        and secrets.compare_digest(
            expected,
            token or "",
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Jeton CSRF invalide.",
        )


def current_user(
    request: Request,
    db: Session,
):
    user_id = request.session.get(
        "user_id"
    )

    if not user_id:
        return None

    return db.get(
        User,
        int(
            user_id
        ),
    )


def require_user(
    request: Request,
    db: Session = Depends(
        get_db
    ),
):
    user = current_user(
        request,
        db,
    )

    if not user or not user.active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Connexion requise.",
        )

    return user


def html(
    request: Request,
    template_name: str,
    context: dict,
):
    context = {
        **context,
        "request": request,
        "csrf_token": ensure_csrf(
            request
        ),
        "app_version": APP_VERSION,
    }

    return templates.TemplateResponse(
        request=request,
        name=template_name,
        context=context,
    )


def bootstrap_database():
    Base.metadata.create_all(
        bind=engine
    )

    admin_password = os.environ.get(
        "NOXIA_ADMIN_PASSWORD",
        "",
    ).strip()

    admin_username = os.environ.get(
        "NOXIA_ADMIN_USERNAME",
        "admin",
    ).strip() or "admin"

    if not admin_password:
        return

    with SessionLocal() as db:
        existing = db.scalar(
            select(
                User
            ).where(
                User.username
                == admin_username
            )
        )

        if existing:
            return

        db.add(
            User(
                username=admin_username,
                password_hash=hash_password(
                    admin_password
                ),
                role="Administrateur",
                active=True,
            )
        )

        db.commit()


@app.on_event(
    "startup"
)
def startup():
    bootstrap_database()


@app.get(
    "/healthz"
)
def healthz():
    return {
        "status": "ok",
        "app": "NOX-IA Web",
        "version": APP_VERSION,
    }


@app.get(
    "/",
    include_in_schema=False,
)
def root(
    request: Request,
):
    if request.session.get(
        "user_id"
    ):
        return RedirectResponse(
            "/dashboard",
            status_code=303,
        )

    return RedirectResponse(
        "/login",
        status_code=303,
    )


@app.get(
    "/login",
    response_class=HTMLResponse,
)
def login_page(
    request: Request,
):
    return html(
        request,
        "login.html",
        {
            "user": None,
            "error": "",
        },
    )


@app.post(
    "/login",
    response_class=HTMLResponse,
)
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(
        get_db
    ),
):
    check_csrf(
        request,
        csrf_token,
    )

    user = db.scalar(
        select(
            User
        ).where(
            User.username == username.strip()
        )
    )

    if not (
        user
        and user.active
        and verify_password(
            password,
            user.password_hash,
        )
    ):
        return html(
            request,
            "login.html",
            {
                "user": None,
                "error": "Identifiant ou mot de passe incorrect.",
            },
        )

    request.session.clear()
    request.session[
        "user_id"
    ] = user.id

    request.session[
        "csrf_token"
    ] = new_csrf_token()

    return RedirectResponse(
        "/dashboard",
        status_code=303,
    )


@app.post(
    "/logout"
)
def logout(
    request: Request,
    csrf_token: str = Form(...),
):
    check_csrf(
        request,
        csrf_token,
    )

    request.session.clear()

    return RedirectResponse(
        "/login",
        status_code=303,
    )


@app.get(
    "/dashboard",
    response_class=HTMLResponse,
)
def dashboard(
    request: Request,
    db: Session = Depends(
        get_db
    ),
):
    user = current_user(
        request,
        db,
    )

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    counts = {
        "clients": db.scalar(
            select(
                func.count(
                    Client.id
                )
            )
        ) or 0,
        "sites": db.scalar(
            select(
                func.count(
                    Site.id
                )
            )
        ) or 0,
        "equipements": db.scalar(
            select(
                func.count(
                    Equipement.id
                )
            )
        ) or 0,
        "interventions_ouvertes": db.scalar(
            select(
                func.count(
                    Intervention.id
                )
            ).where(
                Intervention.statut
                != "Terminée"
            )
        ) or 0,
    }

    recent = db.scalars(
        select(
            Intervention
        )
        .options(
            joinedload(
                Intervention.site
            )
        )
        .order_by(
            Intervention.date_creation.desc()
        )
        .limit(
            8
        )
    ).all()

    return html(
        request,
        "dashboard.html",
        {
            "user": user,
            "counts": counts,
            "recent": recent,
        },
    )


@app.get(
    "/clients",
    response_class=HTMLResponse,
)
def clients_page(
    request: Request,
    db: Session = Depends(
        get_db
    ),
):
    user = current_user(
        request,
        db,
    )

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    rows = db.scalars(
        select(
            Client
        ).order_by(
            Client.nom.asc()
        )
    ).all()

    return html(
        request,
        "clients.html",
        {
            "user": user,
            "clients": rows,
            "can_manage": (
                user.role
                in ROLE_MANAGE_STRUCTURE
            ),
            "error": "",
        },
    )


@app.post(
    "/clients"
)
def client_add(
    request: Request,
    nom: str = Form(...),
    contact: str = Form(""),
    telephone: str = Form(""),
    email: str = Form(""),
    notes: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(
        get_db
    ),
):
    check_csrf(
        request,
        csrf_token,
    )

    user = current_user(
        request,
        db,
    )

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    if user.role not in ROLE_MANAGE_STRUCTURE:
        raise HTTPException(
            status_code=403,
            detail="Permission insuffisante.",
        )

    nom = nom.strip()

    if not nom:
        raise HTTPException(
            status_code=400,
            detail="Nom client obligatoire.",
        )

    db.add(
        Client(
            nom=nom,
            contact=contact.strip(),
            telephone=telephone.strip(),
            email=email.strip(),
            notes=notes.strip(),
            actif=True,
        )
    )

    db.commit()

    return RedirectResponse(
        "/clients",
        status_code=303,
    )


@app.get(
    "/sites",
    response_class=HTMLResponse,
)
def sites_page(
    request: Request,
    db: Session = Depends(
        get_db
    ),
):
    user = current_user(
        request,
        db,
    )

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    rows = db.scalars(
        select(
            Site
        )
        .options(
            joinedload(
                Site.client
            )
        )
        .order_by(
            Site.nom.asc()
        )
    ).all()

    clients = db.scalars(
        select(
            Client
        )
        .where(
            Client.actif.is_(True)
        )
        .order_by(
            Client.nom.asc()
        )
    ).all()

    return html(
        request,
        "sites.html",
        {
            "user": user,
            "sites": rows,
            "clients": clients,
            "can_manage": (
                user.role
                in ROLE_MANAGE_STRUCTURE
            ),
        },
    )


@app.post(
    "/sites"
)
def site_add(
    request: Request,
    client_id: int = Form(...),
    nom: str = Form(...),
    adresse: str = Form(""),
    ville: str = Form(""),
    notes: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(
        get_db
    ),
):
    check_csrf(
        request,
        csrf_token,
    )

    user = current_user(
        request,
        db,
    )

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    if user.role not in ROLE_MANAGE_STRUCTURE:
        raise HTTPException(
            status_code=403,
            detail="Permission insuffisante.",
        )

    client = db.get(
        Client,
        client_id,
    )

    if not client:
        raise HTTPException(
            status_code=404,
            detail="Client introuvable.",
        )

    db.add(
        Site(
            client_id=client.id,
            nom=nom.strip(),
            adresse=adresse.strip(),
            ville=ville.strip(),
            notes=notes.strip(),
            actif=True,
        )
    )

    db.commit()

    return RedirectResponse(
        "/sites",
        status_code=303,
    )


@app.get(
    "/equipements",
    response_class=HTMLResponse,
)
def equipements_page(
    request: Request,
    db: Session = Depends(
        get_db
    ),
):
    user = current_user(
        request,
        db,
    )

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    rows = db.scalars(
        select(
            Equipement
        )
        .options(
            joinedload(
                Equipement.site
            ).joinedload(
                Site.client
            )
        )
        .order_by(
            Equipement.reference.asc()
        )
    ).all()

    sites = db.scalars(
        select(
            Site
        )
        .options(
            joinedload(
                Site.client
            )
        )
        .where(
            Site.actif.is_(True)
        )
        .order_by(
            Site.nom.asc()
        )
    ).all()

    return html(
        request,
        "equipements.html",
        {
            "user": user,
            "equipements": rows,
            "sites": sites,
            "can_manage": (
                user.role
                in ROLE_MANAGE_STRUCTURE
            ),
        },
    )


@app.post(
    "/equipements"
)
def equipement_add(
    request: Request,
    site_id: int = Form(...),
    reference: str = Form(...),
    type_equipement: str = Form(...),
    marque: str = Form(""),
    modele: str = Form(""),
    numero_serie: str = Form(""),
    ip: str = Form(""),
    statut_equipement: str = Form("Actif"),
    csrf_token: str = Form(...),
    db: Session = Depends(
        get_db
    ),
):
    check_csrf(
        request,
        csrf_token,
    )

    user = current_user(
        request,
        db,
    )

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    if user.role not in ROLE_MANAGE_STRUCTURE:
        raise HTTPException(
            status_code=403,
            detail="Permission insuffisante.",
        )

    site = db.get(
        Site,
        site_id,
    )

    if not site:
        raise HTTPException(
            status_code=404,
            detail="Site introuvable.",
        )

    db.add(
        Equipement(
            site_id=site.id,
            reference=reference.strip(),
            type_equipement=type_equipement.strip(),
            marque=marque.strip(),
            modele=modele.strip(),
            numero_serie=numero_serie.strip(),
            ip=ip.strip(),
            statut=statut_equipement.strip() or "Actif",
            actif=True,
        )
    )

    db.commit()

    return RedirectResponse(
        "/equipements",
        status_code=303,
    )


@app.get(
    "/interventions",
    response_class=HTMLResponse,
)
def interventions_page(
    request: Request,
    db: Session = Depends(
        get_db
    ),
):
    user = current_user(
        request,
        db,
    )

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    rows = db.scalars(
        select(
            Intervention
        )
        .options(
            joinedload(
                Intervention.site
            ).joinedload(
                Site.client
            ),
            joinedload(
                Intervention.equipement
            ),
        )
        .order_by(
            Intervention.date_creation.desc()
        )
    ).all()

    sites = db.scalars(
        select(
            Site
        )
        .options(
            joinedload(
                Site.client
            )
        )
        .where(
            Site.actif.is_(True)
        )
        .order_by(
            Site.nom.asc()
        )
    ).all()

    equipements = db.scalars(
        select(
            Equipement
        )
        .where(
            Equipement.actif.is_(True)
        )
        .order_by(
            Equipement.reference.asc()
        )
    ).all()

    return html(
        request,
        "interventions.html",
        {
            "user": user,
            "interventions": rows,
            "sites": sites,
            "equipements": equipements,
            "can_create": (
                user.role
                in ROLE_CREATE_INTERVENTION
            ),
        },
    )


@app.post(
    "/interventions"
)
def intervention_add(
    request: Request,
    site_id: int = Form(...),
    equipement_id: str = Form(""),
    technicien: str = Form(...),
    type_intervention: str = Form("Dépannage"),
    priorite: str = Form("Normale"),
    probleme: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(
        get_db
    ),
):
    check_csrf(
        request,
        csrf_token,
    )

    user = current_user(
        request,
        db,
    )

    if not user:
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    if user.role not in ROLE_CREATE_INTERVENTION:
        raise HTTPException(
            status_code=403,
            detail="Permission insuffisante.",
        )

    site = db.get(
        Site,
        site_id,
    )

    if not site:
        raise HTTPException(
            status_code=404,
            detail="Site introuvable.",
        )

    equipement = None
    equipement_id_value = None

    if equipement_id.strip():
        equipement_id_value = int(
            equipement_id
        )
        equipement = db.get(
            Equipement,
            equipement_id_value,
        )

        if not equipement:
            raise HTTPException(
                status_code=404,
                detail="Équipement introuvable.",
            )

        if equipement.site_id != site.id:
            raise HTTPException(
                status_code=400,
                detail="L'équipement n'appartient pas au site sélectionné.",
            )

    db.add(
        Intervention(
            site_id=site.id,
            equipement_id=equipement_id_value,
            technicien=technicien.strip(),
            type_intervention=type_intervention.strip() or "Dépannage",
            priorite=priorite.strip() or "Normale",
            probleme=probleme.strip(),
            statut="À faire",
        )
    )

    db.commit()

    return RedirectResponse(
        "/interventions",
        status_code=303,
    )
