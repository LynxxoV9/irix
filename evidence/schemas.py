import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, AliasChoices


class UserBase(BaseModel):
    display_name: str
    email: str


class UserCreate(UserBase):
    pass


class UserRead(UserBase):
    model_config = ConfigDict(from_attributes=True)

    user_id: uuid.UUID
    created_at: datetime


class InvestigationBase(BaseModel):
    title: str
    description: Optional[str] = None
    status: str = "OPEN"


class InvestigationCreate(InvestigationBase):
    created_by: Optional[uuid.UUID] = None


class InvestigationRead(InvestigationBase):
    model_config = ConfigDict(from_attributes=True)

    case_id: uuid.UUID
    created_by: Optional[uuid.UUID] = None
    created_at: datetime
    updated_at: datetime


class ArtifactBase(BaseModel):
    name: str
    artifact_type: str
    storage_uri: str
    sha256: str
    size_bytes: int
    extra_metadata: Dict[str, Any] = Field(
        default_factory=dict,
        validation_alias=AliasChoices("extra_metadata", "metadata"),
        serialization_alias="metadata",
    )


class ArtifactCreate(ArtifactBase):
    model_config = ConfigDict(populate_by_name=True)
    case_id: uuid.UUID


class ArtifactRead(ArtifactBase):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    artifact_id: uuid.UUID
    case_id: uuid.UUID
    collected_at: datetime


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


class MitreTechniqueRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    technique_id: str
    name: str
    description: Optional[str] = None
    url: Optional[str] = None


class ReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    report_id: uuid.UUID
    case_id: uuid.UUID
    generated_at: datetime
    report_format: str
    storage_uri: Optional[str] = None
    version: int
    summary: Optional[str] = None
