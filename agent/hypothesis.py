from typing import Dict, Any, List
from evidence.models import Hypothesis, Observation


def calculate_hypothesis_confidence(
    base_confidence: float,
    observations_count: int,
    contradictions_count: int = 0,
) -> float:
    ### Calcule le score de confiance d'une hypothèse selon la corroboration des preuves
    ### Pourquoi ? Une hypothèse sans preuve doit avoir un score faible, tandis qu'une contradiction le pénalise fortement
    score = base_confidence

    # Bonus pour preuves supplémentaires corroborantes (+0.05 par preuve, max +0.20)
    corroboration_bonus = min(observations_count * 0.05, 0.20)
    score += corroboration_bonus

    # Pénalité sévère en cas de contradictions observées (-0.30 par fait contradictoire)
    penalty = contradictions_count * 0.30
    score -= penalty

    # Borne entre 0.0 et 0.99 (jamais 1.0 car certitude absolue impossible en DFIR sans preuve directe)
    return max(0.0, min(round(score, 2), 0.99))


def format_hypothesis_summary(hypothesis: Hypothesis, observations: List[Observation]) -> str:
    ### Génère un résumé lisible de l'hypothèse et des preuves associées
    lines = [
        f"Hypothèse [{hypothesis.status}] : {hypothesis.title}",
        f"Confiance : {int((hypothesis.confidence or 0.5) * 100)}%",
        f"Description : {hypothesis.description}",
        f"Preuves associées ({len(observations)}) :",
    ]
    for obs in observations:
        lines.append(f" - [{obs.observation_type}] {obs.summary} (Réf: {obs.source_reference})")
    return "\n".join(lines)
