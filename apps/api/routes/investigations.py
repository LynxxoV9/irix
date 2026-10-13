import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from apps.api.database import get_db
from evidence.models import Investigation, User
from evidence.schemas import (
    InvestigationCreate,
    InvestigationRead,
)

router = APIRouter(prefix="/api/v1/investigations", tags=["Investigations"])


@router.post("/", response_model=InvestigationRead, status_code=status.HTTP_201_CREATED)
def create_investigation(
    payload: InvestigationCreate,
    db: Session = Depends(get_db),
):
    ### Crée un nouveau dossier d'investigation DFIR (exigence F01 du CDC)
    if payload.created_by:
        user = db.query(User).filter(User.user_id == payload.created_by).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Analyste avec l'identifiant {payload.created_by} introuvable",
            )

    investigation = Investigation(
        title=payload.title,
        description=payload.description,
        status=payload.status,
        created_by=payload.created_by,
    )
    db.add(investigation)
    db.commit()
    db.refresh(investigation)
    return investigation


@router.get("/", response_model=List[InvestigationRead])
def list_investigations(
    status_filter: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    ### Liste les investigations avec filtre optionnel par statut et pagination
    query = db.query(Investigation)
    if status_filter:
        query = query.filter(Investigation.status == status_filter.upper())
    return query.order_by(Investigation.created_at.desc()).offset(offset).limit(limit).all()


@router.get("/{case_id}", response_model=InvestigationRead)
def get_investigation(
    case_id: uuid.UUID,
    db: Session = Depends(get_db),
):
    ### Récupère les métadonnées détaillées d'une investigation par son identifiant unique
    investigation = db.query(Investigation).filter(Investigation.case_id == case_id).first()
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dossier d'investigation {case_id} non trouvé",
        )
    return investigation


@router.patch("/{case_id}/status", response_model=InvestigationRead)
def update_investigation_status(
    case_id: uuid.UUID,
    new_status: str,
    db: Session = Depends(get_db),
):
    ### Met à jour le statut d'un dossier (ex: passer de OPEN à IN_PROGRESS ou CLOSED)
    investigation = db.query(Investigation).filter(Investigation.case_id == case_id).first()
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dossier d'investigation {case_id} non trouvé",
        )

    valid_statuses = {"OPEN", "IN_PROGRESS", "CLOSED"}
    upper_status = new_status.upper()
    if upper_status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Statut invalide. Valeurs autorisées : {', '.join(valid_statuses)}",
        )

    investigation.status = upper_status
    db.commit()
    db.refresh(investigation)
    return investigation
