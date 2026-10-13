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
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


class User(Base):
    """User / Analyst model (UTILISATEUR)."""
    __tablename__ = "users"

    user_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    # Relationships
    investigations: Mapped[List["Investigation"]] = relationship("Investigation", back_populates="creator")


class Investigation(Base):
    """Investigation case model (INVESTIGATION)."""
    __tablename__ = "investigations"

    case_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.user_id", ondelete="SET NULL"), nullable=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="OPEN", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    # Relationships
    creator: Mapped[Optional["User"]] = relationship("User", back_populates="investigations")
    artifacts: Mapped[List["Artifact"]] = relationship("Artifact", back_populates="investigation", cascade="all, delete-orphan")
    executions: Mapped[List["ToolExecution"]] = relationship("ToolExecution", back_populates="investigation", cascade="all, delete-orphan")
    observations: Mapped[List["Observation"]] = relationship("Observation", back_populates="investigation", cascade="all, delete-orphan")
    hypotheses: Mapped[List["Hypothesis"]] = relationship("Hypothesis", back_populates="investigation", cascade="all, delete-orphan")
    indicators: Mapped[List["Indicator"]] = relationship("Indicator", back_populates="investigation", cascade="all, delete-orphan")
    reports: Mapped[List["Report"]] = relationship("Report", back_populates="investigation", cascade="all, delete-orphan")


class Artifact(Base):
    """Raw or collected evidence artifact model (ARTEFACT)."""
    __tablename__ = "artifacts"

    artifact_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("investigations.case_id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    artifact_type: Mapped[str] = mapped_column(String(100), nullable=False)  # e.g., EVTX, MEMORY, PCAP, DISK
    storage_uri: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    extra_metadata: Mapped[Dict[str, Any]] = mapped_column("metadata", JSON, default=dict)

    # Relationships
    investigation: Mapped["Investigation"] = relationship("Investigation", back_populates="artifacts")
    executions: Mapped[List["ToolExecution"]] = relationship("ToolExecution", back_populates="artifact")


class ToolExecution(Base):
    """Forensic tool execution model (EXECUTION_OUTIL)."""
    __tablename__ = "tool_executions"

    execution_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("investigations.case_id", ondelete="CASCADE"), nullable=False, index=True
    )
    artifact_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("artifacts.artifact_id", ondelete="SET NULL"), nullable=True
    )
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False)
    tool_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="PENDING")  # PENDING, RUNNING, COMPLETED, FAILED
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    parameters: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    investigation: Mapped["Investigation"] = relationship("Investigation", back_populates="executions")
    artifact: Mapped[Optional["Artifact"]] = relationship("Artifact", back_populates="executions")
    observations: Mapped[List["Observation"]] = relationship("Observation", back_populates="execution", cascade="all, delete-orphan")


class Observation(Base):
    """Atomic fact/finding produced by a forensic tool (OBSERVATION)."""
    __tablename__ = "observations"

    observation_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    execution_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("tool_executions.execution_id", ondelete="CASCADE"), nullable=False, index=True
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("investigations.case_id", ondelete="CASCADE"), nullable=False, index=True
    )
    observation_type: Mapped[str] = mapped_column(String(100), nullable=False)  # PROCESS, NETWORK, FILE, LOG_EVENT
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    observed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)  # 0.0 to 1.0
    data: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    source_reference: Mapped[str] = mapped_column(Text, nullable=False)

    # Relationships
    execution: Mapped["ToolExecution"] = relationship("ToolExecution", back_populates="observations")
    investigation: Mapped["Investigation"] = relationship("Investigation", back_populates="observations")
    justifications: Mapped[List["HypothesisEvidence"]] = relationship(
        "HypothesisEvidence", back_populates="observation", cascade="all, delete-orphan"
    )
    indicators: Mapped[List["Indicator"]] = relationship("Indicator", back_populates="observation")


class Hypothesis(Base):
    """Investigative hypothesis formulated by the agent or analyst (HYPOTHESE)."""
    __tablename__ = "hypotheses"

    hypothesis_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("investigations.case_id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="PROPOSED")  # PROPOSED, VALIDATED, REFUTED
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    # Relationships
    investigation: Mapped["Investigation"] = relationship("Investigation", back_populates="hypotheses")
    justifications: Mapped[List["HypothesisEvidence"]] = relationship(
        "HypothesisEvidence", back_populates="hypothesis", cascade="all, delete-orphan"
    )
    techniques: Mapped[List["HypothesisTechnique"]] = relationship(
        "HypothesisTechnique", back_populates="hypothesis", cascade="all, delete-orphan"
    )


class HypothesisEvidence(Base):
    """Association table linking hypotheses and supporting/refuting observations (JUSTIFICATION_HYPOTHESE)."""
    __tablename__ = "hypothesis_evidence"

    hypothesis_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("hypotheses.hypothesis_id", ondelete="CASCADE"), primary_key=True
    )
    observation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("observations.observation_id", ondelete="CASCADE"), primary_key=True
    )
    relationship_type: Mapped[str] = mapped_column(String(50), default="SUPPORTS")  # SUPPORTS, CONTRADICTS, CORROBORATES

    # Relationships
    hypothesis: Mapped["Hypothesis"] = relationship("Hypothesis", back_populates="justifications")
    observation: Mapped["Observation"] = relationship("Observation", back_populates="justifications")


class Indicator(Base):
    """Extracted IOC (Indicator of Compromise) model (INDICATEUR)."""
    __tablename__ = "indicators"

    indicator_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("investigations.case_id", ondelete="CASCADE"), nullable=False, index=True
    )
    observation_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("observations.observation_id", ondelete="SET NULL"), nullable=True
    )
    indicator_type: Mapped[str] = mapped_column(String(50), nullable=False)  # IP, DOMAIN, SHA256, REGISTRY, MUTEX
    indicator_value: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    first_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    investigation: Mapped["Investigation"] = relationship("Investigation", back_populates="indicators")
    observation: Mapped[Optional["Observation"]] = relationship("Observation", back_populates="indicators")
    threat_intel: Mapped[List["ThreatIntel"]] = relationship("ThreatIntel", back_populates="indicator", cascade="all, delete-orphan")


class ThreatIntel(Base):
    """Threat intelligence enrichment record via Tavily/etc. (RENSEIGNEMENT_MENACE)."""
    __tablename__ = "threat_intel"

    intel_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    indicator_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("indicators.indicator_id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(String(50), default="TAVILY")
    query: Mapped[str] = mapped_column(Text, nullable=False)
    source_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    result_data: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)

    # Relationships
    indicator: Mapped["Indicator"] = relationship("Indicator", back_populates="threat_intel")


class MitreTechnique(Base):
    """MITRE ATT&CK tactical knowledge base entity (TECHNIQUE_MITRE)."""
    __tablename__ = "mitre_techniques"

    technique_id: Mapped[str] = mapped_column(String(50), primary_key=True)  # e.g., T1059.001
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    hypotheses: Mapped[List["HypothesisTechnique"]] = relationship(
        "HypothesisTechnique", back_populates="technique", cascade="all, delete-orphan"
    )


class HypothesisTechnique(Base):
    """Link between an investigative hypothesis and an ATT&CK technique (HYPOTHESE_TECHNIQUE)."""
    __tablename__ = "hypothesis_techniques"

    hypothesis_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("hypotheses.hypothesis_id", ondelete="CASCADE"), primary_key=True
    )
    technique_id: Mapped[str] = mapped_column(
        String(50), ForeignKey("mitre_techniques.technique_id", ondelete="CASCADE"), primary_key=True
    )
    justification: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    hypothesis: Mapped["Hypothesis"] = relationship("Hypothesis", back_populates="techniques")
    technique: Mapped["MitreTechnique"] = relationship("MitreTechnique", back_populates="hypotheses")


class Report(Base):
    """Generated DFIR incident investigation report (RAPPORT)."""
    __tablename__ = "reports"

    report_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("investigations.case_id", ondelete="CASCADE"), nullable=False, index=True
    )
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    report_format: Mapped[str] = mapped_column(String(20), default="MARKDOWN")  # MARKDOWN, JSON, PDF
    storage_uri: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    investigation: Mapped["Investigation"] = relationship("Investigation", back_populates="reports")
