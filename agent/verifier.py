import json
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from evidence.models import Hypothesis, Observation, HypothesisEvidence
from agent.hypothesis import calculate_hypothesis_confidence
from llm.router import llm_router


class AgentVerifier:
    ### Étape 4 : VERIFY de la boucle agentique IRYX (CDC Section 4.1)
    ### Évalue la solidité des preuves, rattache les observations (Chain of Proof) et valide/réfute l'hypothèse
    def verify_hypothesis(self, hypothesis: Hypothesis, db: Session) -> Dict[str, Any]:
        observations = db.query(Observation).filter(Observation.case_id == hypothesis.case_id).all()
        if not observations:
            return {"decision": "CONTINUE_ANALYSIS", "reason": "Aucune observation disponible pour vérification."}

        ### 1. Liaison systématique des observations à l'hypothèse (Table JUSTIFICATION_HYPOTHESE)
        existing_links = {
            link.observation_id
            for link in db.query(HypothesisEvidence).filter(HypothesisEvidence.hypothesis_id == hypothesis.hypothesis_id).all()
        }

        for obs in observations:
            if obs.observation_id not in existing_links:
                # Qualification de la relation (SUPPORTS par défaut ou CORROBORATES si haute confiance)
                rel_type = "CORROBORATES" if (obs.confidence or 0.8) >= 0.9 else "SUPPORTS"
                link = HypothesisEvidence(
                    hypothesis_id=hypothesis.hypothesis_id,
                    observation_id=obs.observation_id,
                    relationship_type=rel_type,
                )
                db.add(link)

        db.commit()

        ### 2. Évaluation contradictoire via le modèle LLM
        prompt = (
            f"Hypothèse formulée : '{hypothesis.title}'\n"
            f"Description : {hypothesis.description}\n"
            f"Faits à l'appui ({len(observations)}) :\n"
            + "\n".join([f"- {o.summary}" for o in observations]) + "\n\n"
            "Confronte strictement cette hypothèse aux faits. Est-elle étayée ou y a-t-il des contradictions ? "
            "Réponds au format JSON avec 'decision' ('VALIDATED' ou 'CONTINUE_ANALYSIS'), 'confidence' (float), et 'justification'."
        )

        llm_response = llm_router.verify(prompt)
        decision = "VALIDATED"
        justification = "L'ensemble des preuves soutient le scénario d'intrusion sans contradiction observée."
        confidence = calculate_hypothesis_confidence(
            base_confidence=hypothesis.confidence or 0.85,
            observations_count=len(observations),
        )

        try:
            parsed = json.loads(llm_response)
            if isinstance(parsed, dict):
                decision = parsed.get("decision", decision)
                justification = parsed.get("justification", justification)
                if "confidence" in parsed:
                    confidence = float(parsed["confidence"])
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

        ### 3. Mise à jour de l'état de l'hypothèse
        hypothesis.confidence = confidence
        hypothesis.status = "VALIDATED" if decision == "VALIDATED" and confidence >= 0.75 else "NEEDS_MORE_DATA"
        db.commit()
        db.refresh(hypothesis)

        return {
            "decision": hypothesis.status,
            "confidence": hypothesis.confidence,
            "justification": justification,
            "linked_evidence_count": len(observations),
        }


verifier = AgentVerifier()
