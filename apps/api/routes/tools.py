import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from apps.api.database import get_db
from evidence.models import Artifact, Investigation, Observation, ToolExecution, Indicator, ThreatIntel
from evidence.schemas import ObservationRead, ToolExecutionRead
from apps.api.services.mcp_client import mcp_client

router = APIRouter(prefix="/api/v1", tags=["Forensic Tools & MCP"])


class ToolExecutionRequest(BaseModel):
    ### Requête d'exécution d'un outil forensique sur un artefact ou une cible
    tool_name: str
    artifact_id: Optional[uuid.UUID] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)


class ToolExecutionResponse(BaseModel):
    ### Réponse complète incluant la traçabilité de l'exécution et les observations générées
    execution: ToolExecutionRead
    observations_created: List[ObservationRead]
    raw_result: Dict[str, Any]


@router.get("/tools/", response_model=List[Dict[str, Any]])
def list_mcp_tools():
    ### Liste l'ensemble des outils forensiques découverts et disponibles via le protocole MCP
    return mcp_client.list_tools()


@router.post(
    "/investigations/{case_id}/tools/execute",
    response_model=ToolExecutionResponse,
    status_code=status.HTTP_200_OK,
)
def execute_forensic_tool(
    case_id: uuid.UUID,
    payload: ToolExecutionRequest,
    db: Session = Depends(get_db),
):
    ### Exécute un outil forensique MCP, consigne l'exécution et extrait les observations (exigence F03 & F04)

    ### 1. Vérification du dossier d'investigation
    case = db.query(Investigation).filter(Investigation.case_id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dossier d'investigation {case_id} non trouvé",
        )

    ### 2. Récupération de l'artefact si spécifié
    artifact = None
    target_params = dict(payload.parameters)
    if payload.artifact_id:
        artifact = db.query(Artifact).filter(
            Artifact.artifact_id == payload.artifact_id,
            Artifact.case_id == case_id,
        ).first()
        if not artifact:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Artefact {payload.artifact_id} non trouvé dans cette investigation",
            )
        target_params["file_path"] = artifact.storage_uri

    ### 3. Enregistrement initial de l'exécution (traçabilité EXECUTION_OUTIL)
    execution = ToolExecution(
        case_id=case_id,
        artifact_id=artifact.artifact_id if artifact else None,
        tool_name=payload.tool_name,
        status="RUNNING",
        parameters=target_params,
        started_at=datetime.now(timezone.utc),
    )
    db.add(execution)
    db.commit()
    db.refresh(execution)

    ### 4. Appel du serveur MCP
    mcp_resp = mcp_client.execute_tool(payload.tool_name, target_params)
    execution.finished_at = datetime.now(timezone.utc)

    if mcp_resp.get("status") != "SUCCESS":
        execution.status = "FAILED"
        execution.error_message = mcp_resp.get("error", "Erreur inconnue lors de l'exécution MCP")
        db.commit()
        db.refresh(execution)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Échec de l'outil forensique : {execution.error_message}",
        )

    execution.status = "COMPLETED"
    result_data = mcp_resp.get("result", {})

    ### 5. Normalisation et génération automatique des observations (Table OBSERVATION)
    created_observations = []

    if payload.tool_name == "evtx_analyzer":
        for item in result_data.get("findings", []):
            obs = Observation(
                execution_id=execution.execution_id,
                case_id=case_id,
                observation_type="LOG_EVENT",
                summary=f"[{item.get('severity')}] {item.get('description')}: {item.get('matched_text')}",
                confidence=item.get("confidence", 0.8),
                data=item,
                source_reference=f"evtx:{artifact.name if artifact else 'log'}:line_{item.get('line_number')}",
            )
            db.add(obs)
            created_observations.append(obs)

    elif payload.tool_name == "yara_scanner":
        for match in result_data.get("matches", []):
            obs = Observation(
                execution_id=execution.execution_id,
                case_id=case_id,
                observation_type="SIGNATURE_MATCH",
                summary=f"Règle YARA '{match.get('rule_name')}' détectée : {match.get('description')}",
                confidence=0.95,
                data=match,
                source_reference=f"yara:{artifact.name if artifact else 'binary'}:{match.get('rule_name')}",
            )
            db.add(obs)
            created_observations.append(obs)

    elif payload.tool_name == "file_hasher":
        obs = Observation(
            execution_id=execution.execution_id,
            case_id=case_id,
            observation_type="FILE_METADATA",
            summary=f"Analyse structurelle : Type {result_data.get('detected_magic_type')}, Entropie {result_data.get('entropy')}",
            confidence=1.0,
            data=result_data,
            source_reference=f"hasher:{artifact.name if artifact else 'file'}:sha256",
        )
        db.add(obs)
        created_observations.append(obs)

    elif payload.tool_name == "threat_intel":
        obs = Observation(
            execution_id=execution.execution_id,
            case_id=case_id,
            observation_type="THREAT_INTEL",
            summary=f"Renseignement CTI pour {result_data.get('indicator')} : Réputation {result_data.get('reputation', 'N/A')}",
            confidence=result_data.get("confidence", 0.5),
            data=result_data,
            source_reference=f"tavily:{result_data.get('indicator')}",
        )
        db.add(obs)
        created_observations.append(obs)

        ### Enregistrement de l'IOC et de la trace CTI associée
        ioc = Indicator(
            case_id=case_id,
            observation_id=obs.observation_id,
            indicator_type=result_data.get("indicator_type", "IP"),
            indicator_value=result_data.get("indicator", "unknown"),
        )
        db.add(ioc)
        db.flush()

        intel = ThreatIntel(
            indicator_id=ioc.indicator_id,
            provider=result_data.get("provider", "TAVILY"),
            query=result_data.get("indicator", "unknown"),
            source_url=result_data.get("sources", [{}])[0].get("url") if result_data.get("sources") else None,
            result_data=result_data,
        )
        db.add(intel)

    db.commit()
    db.refresh(execution)
    for obs in created_observations:
        db.refresh(obs)

    return ToolExecutionResponse(
        execution=execution,
        observations_created=created_observations,
        raw_result=result_data,
    )
