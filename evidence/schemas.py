import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, AliasChoices


### Schémas Pydantic v2 pour la validation et la sérialisation de l'API
### Pourquoi ? Sépare la logique de stockage SQL des contrats d'interface de l'API (clean architecture)

### Schémas Utilisateur / Analyste
class UserBase(BaseModel):
    display_name: str
    email: str


class UserCreate(UserBase):
    ### Payload attendu lors de l'inscription ou création d'un analyste
    pass


class UserRead(UserBase):
    ### Format retourné par l'API avec identifiant UUID et horodatage de création
    model_config = ConfigDict(from_attributes=True)

    user_id: uuid.UUID
    created_at: datetime


### Schémas Dossier d'Investigation
class InvestigationBase(BaseModel):
    title: str
    description: Optional[str] = None
    status: str = "OPEN"


class InvestigationCreate(InvestigationBase):
    ### Payload de création d'un dossier avec l'analyste responsable facultatif
    created_by: Optional[uuid.UUID] = None


class InvestigationRead(InvestigationBase):
    ### Format de restitution complet d'une investigation
    model_config = ConfigDict(from_attributes=True)

    case_id: uuid.UUID
    created_by: Optional[uuid.UUID] = None
    created_at: datetime
    updated_at: datetime


### Schémas Artefact Forensique
class ArtifactBase(BaseModel):
    name: str
    artifact_type: str
    storage_uri: str
    sha256: str
    size_bytes: int
    ### AliasChoices permet de lire indifféremment 'extra_metadata' (sur l'ORM) ou 'metadata' (en JSON d'entrée)
    ### et sérialise toujours sous la clé 'metadata' vers l'extérieur pour respecter le CDC
    extra_metadata: Dict[str, Any] = Field(
        default_factory=dict,
        validation_alias=AliasChoices("extra_metadata", "metadata"),
        serialization_alias="metadata",
    )


class ArtifactCreate(ArtifactBase):
    model_config = ConfigDict(populate_by_name=True)
    case_id: uuid.UUID


class ArtifactRead(ArtifactBase):
    ### Représentation d'une preuve brute ingérée et archivée avec sa date de collecte
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    artifact_id: uuid.UUID
    case_id: uuid.UUID
    collected_at: datetime


### Schémas Exécution d'Outil Forensique
class ToolExecutionBase(BaseModel):
    tool_name: str
    tool_version: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)


class ToolExecutionCreate(ToolExecutionBase):
    case_id: uuid.UUID
    artifact_id: Optional[uuid.UUID] = None


class ToolExecutionRead(ToolExecutionBase):
    model_config = ConfigDict(from_attributes=True)

    execution_id: uuid.UUID
    case_id: uuid.UUID
    artifact_id: Optional[uuid.UUID] = None
    status: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    error_message: Optional[str] = None


### Schémas Observation / Fait technique brut
class ObservationBase(BaseModel):
    observation_type: str
    summary: str
    observed_at: Optional[datetime] = None
    confidence: Optional[float] = None
    data: Dict[str, Any] = Field(default_factory=dict)
    source_reference: str


class ObservationCreate(ObservationBase):
    case_id: uuid.UUID
    execution_id: uuid.UUID


class ObservationRead(ObservationBase):
    model_config = ConfigDict(from_attributes=True)

    observation_id: uuid.UUID
    case_id: uuid.UUID
    execution_id: uuid.UUID


### Schémas Hypothèse d'Attaque
class HypothesisBase(BaseModel):
    title: str
    description: str
    status: str = "PROPOSED"
    confidence: Optional[float] = None


class HypothesisCreate(HypothesisBase):
    case_id: uuid.UUID


class HypothesisRead(HypothesisBase):
    model_config = ConfigDict(from_attributes=True)

    hypothesis_id: uuid.UUID
    case_id: uuid.UUID
    created_at: datetime
    updated_at: datetime


### Schémas Indicateur de Compromission (IOC)
class IndicatorBase(BaseModel):
    indicator_type: str
    indicator_value: str
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None


class IndicatorCreate(IndicatorBase):
    case_id: uuid.UUID
    observation_id: Optional[uuid.UUID] = None


class IndicatorRead(IndicatorBase):
    model_config = ConfigDict(from_attributes=True)

    indicator_id: uuid.UUID
    case_id: uuid.UUID
    observation_id: Optional[uuid.UUID] = None


### Schémas Renseignement sur les Menaces (CTI)
class ThreatIntelBase(BaseModel):
    provider: str = "TAVILY"
    query: str
    source_url: Optional[str] = None
    result_data: Dict[str, Any] = Field(default_factory=dict)


class ThreatIntelCreate(ThreatIntelBase):
    indicator_id: uuid.UUID


class ThreatIntelRead(ThreatIntelBase):
    model_config = ConfigDict(from_attributes=True)

    intel_id: uuid.UUID
    indicator_id: uuid.UUID
    retrieved_at: datetime


### Schémas Technique MITRE ATT&CK
class MitreTechniqueRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    technique_id: str
    name: str
    description: Optional[str] = None
    url: Optional[str] = None


### Schémas Rapport d'Incident
class ReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    report_id: uuid.UUID
    case_id: uuid.UUID
    generated_at: datetime
    report_format: str
    storage_uri: Optional[str] = None
    version: int
    summary: Optional[str] = None
