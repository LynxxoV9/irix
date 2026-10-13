import uuid
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class AgentStepLog(BaseModel):
    ### Journal d'une étape du cycle agentique (PLAN, DO, SOLVE, VERIFY)
    iteration: int
    phase: str  # PLAN, DO, SOLVE, VERIFY
    details: Dict[str, Any] = Field(default_factory=dict)


class AgentState(BaseModel):
    ### État d'exécution de la boucle agentique d'investigation
    ### Pourquoi ? Permet de borner le nombre d'itérations et de conserver la traçabilité complète des décisions
    case_id: uuid.UUID
    current_iteration: int = 0
    max_iterations: int = 5
    status: str = "RUNNING"  # RUNNING, CONCLUDED, MAX_ITERATIONS_REACHED, ERROR
    executed_tools: List[str] = Field(default_factory=list)
    steps_history: List[AgentStepLog] = Field(default_factory=list)
    conclusion_summary: Optional[str] = None

    def can_continue(self) -> bool:
        ### Vérifie si l'agent peut engager un nouveau cycle d'investigation
        return self.status == "RUNNING" and self.current_iteration < self.max_iterations

    def increment_iteration(self) -> None:
        self.current_iteration += 1
        if self.current_iteration >= self.max_iterations and self.status == "RUNNING":
            self.status = "MAX_ITERATIONS_REACHED"

    def log_step(self, phase: str, details: Dict[str, Any]) -> None:
        ### Enregistre une étape réalisée dans l'historique
        self.steps_history.append(
            AgentStepLog(iteration=self.current_iteration, phase=phase, details=details)
        )

    def conclude(self, summary: str) -> None:
        ### Clôture l'investigation agentique avec une synthèse des conclusions
        self.status = "CONCLUDED"
        self.conclusion_summary = summary
