import json
import uuid
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from evidence.models import Hypothesis, Observation, Investigation
from llm.router import llm_router


class AgentSolver:
    ### Étape 3 : SOLVE de la boucle agentique IRYX (CDC Section 4.1)
    ### Corrèle les faits techniques observés, reconstruit la logique d'intrusion et formule l'hypothèse
    def correlate_and_hypothesize(self, case_id: uuid.UUID, db: Session) -> Optional[Hypothesis]:
        case = db.query(Investigation).filter(Investigation.case_id == case_id).first()
        if not case:
            return None

        observations = db.query(Observation).filter(Observation.case_id == case_id).all()
        if not observations:
            return None

        ### 1. Construction du contexte factuel pour le modèle de raisonnement
        obs_summaries = []
        for o in observations:
            obs_summaries.append(f"- [{o.observation_type}] {o.summary} (Confiance: {o.confidence})")

        prompt = (
            f"Cas d'investigation : {case.title}\n"
            f"Faits observés ({len(observations)}) :\n"
            + "\n".join(obs_summaries) + "\n\n"
            "En tant qu'analyste DFIR expert, formule une hypothèse d'attaque claire reliant ces observations. "
            "Réponds au format JSON avec les clés: 'title', 'description', 'confidence'."
        )

        llm_response = llm_router.solve(prompt)
        title = "Activité malveillante confirmée par corrélation multi-sources"
        description = "Plusieurs indicateurs techniques concordants indiquent une intrusion compromise."
        confidence = 0.85

        try:
            parsed = json.loads(llm_response)
            if isinstance(parsed, dict):
                title = parsed.get("title", title)
                description = parsed.get("description", description)
                confidence = float(parsed.get("confidence", confidence))
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

        ### 2. Enregistrement ou mise à jour de l'hypothèse dans la base de données
        existing_hypo = (
            db.query(Hypothesis)
            .filter(Hypothesis.case_id == case_id)
            .order_by(Hypothesis.created_at.desc())
            .first()
        )

        if existing_hypo and existing_hypo.status == "PROPOSED":
            existing_hypo.title = title
            existing_hypo.description = description
            existing_hypo.confidence = confidence
            db.commit()
            db.refresh(existing_hypo)
            return existing_hypo

        new_hypo = Hypothesis(
            case_id=case_id,
            title=title,
            description=description,
            status="PROPOSED",
            confidence=confidence,
        )
        db.add(new_hypo)
        db.commit()
        db.refresh(new_hypo)
        return new_hypo


solver = AgentSolver()
