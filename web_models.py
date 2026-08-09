import os

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
    sessionmaker,
)


DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "sqlite:///./noxia_web.db",
)

engine_kwargs = {
    "pool_pre_ping": True,
}

if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {
        "check_same_thread": False,
    }

engine = create_engine(
    DATABASE_URL,
    **engine_kwargs,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "web_users"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )
    username: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        index=True,
    )
    password_hash: Mapped[str] = mapped_column(
        String(300),
    )
    role: Mapped[str] = mapped_column(
        String(50),
        default="Lecture seule",
    )
    active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )


class Client(Base):
    __tablename__ = "web_clients"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )
    nom: Mapped[str] = mapped_column(
        String(200),
        index=True,
    )
    contact: Mapped[str] = mapped_column(
        String(200),
        default="",
    )
    telephone: Mapped[str] = mapped_column(
        String(80),
        default="",
    )
    email: Mapped[str] = mapped_column(
        String(200),
        default="",
    )
    notes: Mapped[str] = mapped_column(
        Text,
        default="",
    )
    actif: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
    )

    sites: Mapped[list["Site"]] = relationship(
        back_populates="client",
        cascade="all, delete-orphan",
    )


class Site(Base):
    __tablename__ = "web_sites"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )
    client_id: Mapped[int] = mapped_column(
        ForeignKey("web_clients.id"),
        index=True,
    )
    nom: Mapped[str] = mapped_column(
        String(200),
    )
    adresse: Mapped[str] = mapped_column(
        String(300),
        default="",
    )
    ville: Mapped[str] = mapped_column(
        String(150),
        default="",
    )
    notes: Mapped[str] = mapped_column(
        Text,
        default="",
    )
    actif: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
    )

    client: Mapped["Client"] = relationship(
        back_populates="sites",
    )
    equipements: Mapped[list["Equipement"]] = relationship(
        back_populates="site",
        cascade="all, delete-orphan",
    )
    interventions: Mapped[list["Intervention"]] = relationship(
        back_populates="site",
    )


class Equipement(Base):
    __tablename__ = "web_equipements"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )
    site_id: Mapped[int] = mapped_column(
        ForeignKey("web_sites.id"),
        index=True,
    )
    reference: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        index=True,
    )
    type_equipement: Mapped[str] = mapped_column(
        String(150),
    )
    marque: Mapped[str] = mapped_column(
        String(150),
        default="",
    )
    modele: Mapped[str] = mapped_column(
        String(150),
        default="",
    )
    numero_serie: Mapped[str] = mapped_column(
        String(150),
        default="",
    )
    ip: Mapped[str] = mapped_column(
        String(100),
        default="",
    )
    statut: Mapped[str] = mapped_column(
        String(80),
        default="Actif",
    )
    actif: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
    )

    site: Mapped["Site"] = relationship(
        back_populates="equipements",
    )


class Intervention(Base):
    __tablename__ = "web_interventions"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )
    site_id: Mapped[int] = mapped_column(
        ForeignKey("web_sites.id"),
        index=True,
    )
    equipement_id: Mapped[int | None] = mapped_column(
        ForeignKey("web_equipements.id"),
        nullable=True,
        index=True,
    )
    date_creation: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )
    technicien: Mapped[str] = mapped_column(
        String(150),
    )
    type_intervention: Mapped[str] = mapped_column(
        String(100),
        default="Dépannage",
    )
    priorite: Mapped[str] = mapped_column(
        String(50),
        default="Normale",
    )
    probleme: Mapped[str] = mapped_column(
        Text,
    )
    actions_realisees: Mapped[str] = mapped_column(
        Text,
        default="",
    )
    solution: Mapped[str] = mapped_column(
        Text,
        default="",
    )
    statut: Mapped[str] = mapped_column(
        String(50),
        default="À faire",
    )
    date_cloture: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    site: Mapped["Site"] = relationship(
        back_populates="interventions",
    )
    equipement: Mapped["Equipement | None"] = relationship()
