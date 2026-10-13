import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    BigInteger,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    Uuid,
    JSON,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from apps.api.database import Base


def utc_now() -> datetime:
    ### Horodatage standardisé en UTC pour éviter les décalages de fuseaux horaires dans les investigations
    return datetime.now(timezone.utc)


### Modèle Utilisateur / Analyste DFIR (Table UTILISATEUR du CDC 5.2)
### Permet d'identifier qui a ouvert le dossier ou posé un acte d'investigation
class User(Base):
    __tablename__ = "users"

    ### Clé primaire UUID v4 universelle et non séquentielle
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    ### Relations avec les investigations initiées par cet analyste
    investigations: Mapped[List["Investigation"]] = relationship("Investigation", back_populates="creator")


### Modèle Dossier d'Investigation (Table INVESTIGATION du CDC 5.2)
### Représente le conteneur principal de l'incident (ex: Ransomware sur DC01, Beaconing WS04)
class Investigation(Base):
    __tablename__ = "investigations"

    ### Identifiant unique du dossier d'investigation
    case_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ### Lien vers l'analyste responsable du dossier (clé étrangère vers users)
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.user_id", ondelete="SET NULL"), nullable=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ### Statut du dossier : OPEN (ouvert), IN_PROGRESS (analyse en cours), CLOSED (clôturé)
    status: Mapped[str] = mapped_column(String(50), default="OPEN", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    ### Relations : un dossier regroupe des preuves, exécutions, observations, hypothèses, IOCs et rapports
    creator: Mapped[Optional["User"]] = relationship("User", back_populates="investigations")
    artifacts: Mapped[List["Artifact"]] = relationship("Artifact", back_populates="investigation", cascade="all, delete-orphan")
    executions: Mapped[List["ToolExecution"]] = relationship("ToolExecution", back_populates="investigation", cascade="all, delete-orphan")
    observations: Mapped[List["Observation"]] = relationship("Observation", back_populates="investigation", cascade="all, delete-orphan")
    hypotheses: Mapped[List["Hypothesis"]] = relationship("Hypothesis", back_populates="investigation", cascade="all, delete-orphan")
    indicators: Mapped[List["Indicator"]] = relationship("Indicator", back_populates="investigation", cascade="all, delete-orphan")
    reports: Mapped[List["Report"]] = relationship("Report", back_populates="investigation", cascade="all, delete-orphan")


### Modèle Artefact / Preuve brute collectée (Table ARTEFACT du CDC 5.2)
### Règle d'or DFIR : les fichiers originaux sont immuables. On stocke l'URI et le hash SHA-256 pour prouver l'intégrité
class Artifact(Base):
    __tablename__ = "artifacts"

    artifact_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("investigations.case_id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    ### Type d'artefact : EVTX, MEMORY, PCAP, DISK_IMAGE, BINARY, PREFETCH
    artifact_type: Mapped[str] = mapped_column(String(100), nullable=False)
    ### Chemin absolu ou URI vers le fichier préservé sur le stockage local sécurisé
    storage_uri: Mapped[str] = mapped_column(Text, nullable=False)
    ### Empreinte cryptographique SHA-256 calculée dès l'ingestion pour la chaîne de traçabilité (Chain of Custody)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    ### Taille en octets du fichier original
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    ### Métadonnées libres (OS source, hostname, profil mémoire, fuseau horaire collecté)
    extra_metadata: Mapped[Dict[str, Any]] = mapped_column("metadata", JSON, default=dict)

    investigation: Mapped["Investigation"] = relationship("Investigation", back_populates="artifacts")
    executions: Mapped[List["ToolExecution"]] = relationship("ToolExecution", back_populates="artifact")


### Modèle Exécution d'Outil Forensique (Table EXECUTION_OUTIL du CDC 5.2)
### Traçabilité complète : quel outil a tourné, avec quelle commande, sur quel artefact et quel a été le résultat
class ToolExecution(Base):
    __tablename__ = "tool_executions"

    execution_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("investigations.case_id", ondelete="CASCADE"), nullable=False, index=True
    )
    ### Artefact ciblé (peut être null si outil réseau ou appel distant Tavily)
    artifact_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("artifacts.artifact_id", ondelete="SET NULL"), nullable=True
    )
    ### Nom de l'outil appelé via MCP (ex: volatility3_pslist, yara_scanner, evtx_dump)
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False)
    tool_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    ### Statut : PENDING (en attente), RUNNING (en cours), COMPLETED (succès), FAILED (échec)
    status: Mapped[str] = mapped_column(String(50), default="PENDING")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    ### Paramètres passés à l'outil sous forme de dictionnaire JSON
    parameters: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    ### Trace d'erreur en cas d'échec pour débugger l'investigation sans perdre le contexte
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    investigation: Mapped["Investigation"] = relationship("Investigation", back_populates="executions")
    artifact: Mapped[Optional["Artifact"]] = relationship("Artifact", back_populates="executions")
    observations: Mapped[List["Observation"]] = relationship("Observation", back_populates="execution", cascade="all, delete-orphan")


### Modèle Observation / Fait technique brut extrait (Table OBSERVATION du CDC 5.2)
### Représente une preuve atomique extraite sans interprétation préalable (ex: processus suspect, log d'authentification)
class Observation(Base):
    __tablename__ = "observations"

    observation_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    execution_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("tool_executions.execution_id", ondelete="CASCADE"), nullable=False, index=True
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("investigations.case_id", ondelete="CASCADE"), nullable=False, index=True
    )
    ### Catégorie : PROCESS, NETWORK, FILE, LOG_EVENT, REGISTRY, PERSISTENCE
    observation_type: Mapped[str] = mapped_column(String(100), nullable=False)
    ### Résumé synthétique lisible par l'analyste et le LLM
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    ### Horodatage exact de l'événement tel qu'observé dans la preuve d'origine
    observed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    ### Indice de confiance technique (0.0 à 1.0)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    ### Données structurées JSON brutes (PID, IP source, ligne de commande, chemin)
    data: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    ### Référence exacte à la source pour vérification humaine (ex: "evtx:event_4688:record_1042")
    source_reference: Mapped[str] = mapped_column(Text, nullable=False)

    execution: Mapped["ToolExecution"] = relationship("ToolExecution", back_populates="observations")
    investigation: Mapped["Investigation"] = relationship("Investigation", back_populates="observations")
    justifications: Mapped[List["HypothesisEvidence"]] = relationship(
        "HypothesisEvidence", back_populates="observation", cascade="all, delete-orphan"
    )
    indicators: Mapped[List["Indicator"]] = relationship("Indicator", back_populates="observation")


### Modèle Hypothèse d'investigation (Table HYPOTHESE du CDC 5.2)
### Formulé par l'agent ou l'analyste pour expliquer le scénario d'intrusion
class Hypothesis(Base):
    __tablename__ = "hypotheses"

    hypothesis_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("investigations.case_id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    ### Statut : PROPOSED (émise), VALIDATED (prouvée par faits), REFUTED (contredite par preuves)
    status: Mapped[str] = mapped_column(String(50), default="PROPOSED")
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    investigation: Mapped["Investigation"] = relationship("Investigation", back_populates="hypotheses")
    justifications: Mapped[List["HypothesisEvidence"]] = relationship(
        "HypothesisEvidence", back_populates="hypothesis", cascade="all, delete-orphan"
    )
    techniques: Mapped[List["HypothesisTechnique"]] = relationship(
        "HypothesisTechnique", back_populates="hypothesis", cascade="all, delete-orphan"
    )


### Modèle Association Hypothèse - Preuve (Table JUSTIFICATION_HYPOTHESE du CDC 5.2)
### Pilier de la traçabilité IRYX : toute conclusion doit être appuyée ou contredite par des observations concrètes
class HypothesisEvidence(Base):
    __tablename__ = "hypothesis_evidence"

    hypothesis_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("hypotheses.hypothesis_id", ondelete="CASCADE"), primary_key=True
    )
    observation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("observations.observation_id", ondelete="CASCADE"), primary_key=True
    )
    ### Nature du lien logique : SUPPORTS (appuie), CONTRADICTS (contredit), CORROBORATES (corrobore)
    relationship_type: Mapped[str] = mapped_column(String(50), default="SUPPORTS")

    hypothesis: Mapped["Hypothesis"] = relationship("Hypothesis", back_populates="justifications")
    observation: Mapped["Observation"] = relationship("Observation", back_populates="justifications")


### Modèle Indicateur de Compromission / IOC (Table INDICATEUR du CDC 5.2)
### Extrait des observations et enrichissable via Threat Intel
class Indicator(Base):
    __tablename__ = "indicators"

    indicator_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("investigations.case_id", ondelete="CASCADE"), nullable=False, index=True
    )
    ### Observation source ayant révélé l'indicateur
    observation_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("observations.observation_id", ondelete="SET NULL"), nullable=True
    )
    ### Type : IP, DOMAIN, SHA256, REGISTRY_KEY, MUTEX, EMAIL
    indicator_type: Mapped[str] = mapped_column(String(50), nullable=False)
    indicator_value: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    first_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    investigation: Mapped["Investigation"] = relationship("Investigation", back_populates="indicators")
    observation: Mapped[Optional["Observation"]] = relationship("Observation", back_populates="indicators")
    threat_intel: Mapped[List["ThreatIntel"]] = relationship("ThreatIntel", back_populates="indicator", cascade="all, delete-orphan")


### Modèle Renseignement sur les Menaces / CTI (Table RENSEIGNEMENT_MENACE du CDC 5.2)
### Conserve les recherches externes (Tavily Search API) et leurs sources pour justifier les conclusions
class ThreatIntel(Base):
    __tablename__ = "threat_intel"

    intel_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    indicator_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("indicators.indicator_id", ondelete="CASCADE"), nullable=False, index=True
    )
    ### Fournisseur CTI : TAVILY, VIRUSTOTAL, ALIENVAULT, etc.
    provider: Mapped[str] = mapped_column(String(50), default="TAVILY")
    query: Mapped[str] = mapped_column(Text, nullable=False)
    source_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    result_data: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)

    indicator: Mapped["Indicator"] = relationship("Indicator", back_populates="threat_intel")


### Modèle Technique MITRE ATT&CK (Table TECHNIQUE_MITRE du CDC 5.2)
### Base de connaissances tactique référençant les modes opératoires adverses
class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    technique_id: Mapped[str] = mapped_column(String(50), primary_key=True)  # ex: T1059.001
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    hypotheses: Mapped[List["HypothesisTechnique"]] = relationship(
        "HypothesisTechnique", back_populates="technique", cascade="all, delete-orphan"
    )


### Modèle Association Hypothèse - Technique MITRE (Table HYPOTHESE_TECHNIQUE du CDC 5.2)
### Relie une hypothèse à une technique ATT&CK en exigeant une justification textuelle
class HypothesisTechnique(Base):
    __tablename__ = "hypothesis_techniques"

    hypothesis_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("hypotheses.hypothesis_id", ondelete="CASCADE"), primary_key=True
    )
    technique_id: Mapped[str] = mapped_column(
        String(50), ForeignKey("mitre_techniques.technique_id", ondelete="CASCADE"), primary_key=True
    )
    justification: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    hypothesis: Mapped["Hypothesis"] = relationship("Hypothesis", back_populates="techniques")
    technique: Mapped["MitreTechnique"] = relationship("MitreTechnique", back_populates="hypotheses")


### Modèle Rapport d'Incident DFIR (Table RAPPORT du CDC 5.2)
### Synthèse exécutive et technique finale générée avec traçabilité vers les observations
class Report(Base):
    __tablename__ = "reports"

    report_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("investigations.case_id", ondelete="CASCADE"), nullable=False, index=True
    )
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    ### Format : MARKDOWN, JSON, PDF
    report_format: Mapped[str] = mapped_column(String(20), default="MARKDOWN")
    storage_uri: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    investigation: Mapped["Investigation"] = relationship("Investigation", back_populates="reports")
