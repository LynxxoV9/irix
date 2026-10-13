import uuid
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from apps.api.database import get_db
from evidence.models import Investigation, Hypothesis, HypothesisEvidence, Observation
from evidence.schemas import HypothesisRead, ObservationRead
from agent.orchestrator import orchestrator
from agent.state import AgentState

router = APIRouter(prefix="/api/v1/investigations/{case_id}/agent", tags=["Autonomous DFIR Agent"])


@router.post("/run", response_model=AgentState, status_code=status.HTTP_200_OK)
def run_autonomous_investigation(
    case_id: uuid.UUID,
    max_iterations: int = 5,
    db: Session = Depends(get_db),
):
    ### Lance la boucle agentique d'investigation autonome (PLAN -> DO -> SOLVE -> VERIFY)
    case = db.query(Investigation).filter(Investigation.case_id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dossier d'investigation {case_id} non trouvé",
        )

    state = orchestrator.run_investigation(case_id=case_id, db=db, max_iterations=max_iterations)
    return state


@router.get("/hypotheses", response_model=List[Dict[str, Any]])
def get_case_hypotheses_with_evidence(
    case_id: uuid.UUID,
    db: Session = Depends(get_db),
):
    ### Retourne les hypothèses formulées avec l'ensemble des preuves matérielles qui les justifient
    case = db.query(Investigation).filter(Investigation.case_id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dossier d'investigation {case_id} non trouvé",
        )

    hypotheses = db.query(Hypothesis).filter(Hypothesis.case_id == case_id).all()
    results = []

    for hypo in hypotheses:
        justifications = (
            db.query(HypothesisEvidence)
            .filter(HypothesisEvidence.hypothesis_id == hypo.hypothesis_id)
            .all()
        )
        linked_obs = []
        for j in justifications:
            obs = db.query(Observation).filter(Observation.observation_id == j.observation_id).first()
            if obs:
                linked_obs.append({
                    "observation_id": str(obs.observation_id),
                    "observation_type": obs.observation_type,
                    "summary": obs.summary,
                    "confidence": obs.confidence,
                    "source_reference": obs.source_reference,
                    "relationship_type": j.relationship_type,
                })

        results.append({
            "hypothesis_id": str(hypo.hypothesis_id),
            "title": hypo.title,
            "description": hypo.description,
            "status": hypo.status,
            "confidence": hypo.confidence,
            "created_at": hypo.created_at.isoformat(),
            "supporting_evidence": linked_obs,
        })

    return results
