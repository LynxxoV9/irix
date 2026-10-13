import json
import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.orm import Session
from apps.api.database import get_db
from evidence.models import Artifact, Investigation
from evidence.schemas import ArtifactRead
from evidence.provenance import (
    detect_artifact_type_from_name,
    save_evidence_artifact,
    verify_evidence_integrity,
)

router = APIRouter(tags=["Evidence & Artifacts"])


@router.post(
    "/api/v1/investigations/{case_id}/artifacts/upload",
    response_model=ArtifactRead,
    status_code=status.HTTP_201_CREATED,
)
async def upload_artifact(
    case_id: uuid.UUID,
    file: UploadFile = File(...),
    artifact_type: Optional[str] = Form(None),
    metadata_json: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    ### Ingestion sécurisée d'une preuve numérique (exigence F02 du CDC)
    ### 1. Vérification que le dossier d'investigation existe
    case = db.query(Investigation).filter(Investigation.case_id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dossier d'investigation {case_id} non trouvé",
        )

    ### 2. Détermination du type d'artefact (manuel ou auto-détecté par extension)
    inferred_type = artifact_type or detect_artifact_type_from_name(file.filename or "")

    ### 3. Parse des métadonnées optionnelles
    parsed_metadata = {}
    if metadata_json:
        try:
            parsed_metadata = json.loads(metadata_json)
        except json.JSONDecodeError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Le champ metadata_json doit être un dictionnaire JSON valide",
            )

    ### 4. Génération de l'identifiant unique de la preuve et enregistrement sécurisé sur disque
    artifact_id = uuid.uuid4()
    original_filename = file.filename or f"artifact_{artifact_id}"

    try:
        storage_uri, sha256_hash, size_bytes = save_evidence_artifact(
            case_id=case_id,
            artifact_id=artifact_id,
            original_filename=original_filename,
            file_obj=file.file,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de l'enregistrement de l'artefact sur disque : {str(e)}",
        )

    ### 5. Enregistrement dans la base de données avec sa chaîne de conservation
    artifact = Artifact(
        artifact_id=artifact_id,
        case_id=case_id,
        name=original_filename,
        artifact_type=inferred_type,
        storage_uri=storage_uri,
        sha256=sha256_hash,
        size_bytes=size_bytes,
        extra_metadata=parsed_metadata,
    )
    db.add(artifact)
    db.commit()
    db.refresh(artifact)

    return artifact


@router.get("/api/v1/investigations/{case_id}/artifacts", response_model=List[ArtifactRead])
def list_case_artifacts(
    case_id: uuid.UUID,
    db: Session = Depends(get_db),
):
    ### Liste tous les artefacts rattachés à un dossier d'investigation donné
    case = db.query(Investigation).filter(Investigation.case_id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dossier d'investigation {case_id} non trouvé",
        )
    return db.query(Artifact).filter(Artifact.case_id == case_id).order_by(Artifact.collected_at.asc()).all()


@router.get("/api/v1/artifacts/{artifact_id}", response_model=ArtifactRead)
def get_artifact(
    artifact_id: uuid.UUID,
    db: Session = Depends(get_db),
):
    ### Récupère les métadonnées et la provenance d'un artefact spécifique
    artifact = db.query(Artifact).filter(Artifact.artifact_id == artifact_id).first()
    if not artifact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Artefact {artifact_id} non trouvé",
        )
    return artifact


@router.get("/api/v1/artifacts/{artifact_id}/verify")
def verify_artifact(
    artifact_id: uuid.UUID,
    db: Session = Depends(get_db),
):
    ### Contrôle de la chaîne de conservation (Chain of Custody) :
    ### Recalcule le SHA-256 actuel du fichier sur disque et le confronte à l'empreinte enregistrée
    artifact = db.query(Artifact).filter(Artifact.artifact_id == artifact_id).first()
    if not artifact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Artefact {artifact_id} non trouvé",
        )

    is_valid = verify_evidence_integrity(artifact.storage_uri, artifact.sha256)
    return {
        "artifact_id": str(artifact.artifact_id),
        "name": artifact.name,
        "recorded_sha256": artifact.sha256,
        "integrity_verified": is_valid,
        "status": "VALID_INTEGRITY" if is_valid else "TAMPERED_OR_MISSING",
    }
