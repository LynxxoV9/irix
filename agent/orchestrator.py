import uuid
import logging
from typing import Dict, Any
from sqlalchemy.orm import Session
from evidence.models import Investigation
from agent.state import AgentState
from agent.planner import planner
from agent.executor import executor
from agent.solver import solver
from agent.verifier import verifier

logger = logging.getLogger("iryx.agent")


class AgentOrchestrator:
    ### Moteur de coordination de la boucle agentique DFIR d'IRYX (CDC Section 4.1 & 4.2)
    ### Exécute le cycle : PLAN -> DO -> SOLVE -> VERIFY jusqu'à validation ou limite atteinte
    def run_investigation(
        self,
        case_id: uuid.UUID,
        db: Session,
        max_iterations: int = 5,
    ) -> AgentState:
        state = AgentState(case_id=case_id, max_iterations=max_iterations)

        case = db.query(Investigation).filter(Investigation.case_id == case_id).first()
        if not case:
            state.status = "ERROR"
            state.conclusion_summary = "Dossier introuvable."
            return state

        case.status = "IN_PROGRESS"
        db.commit()

        logger.info(f"Démarrage de l'investigation agentique pour le cas {case_id}")

        while state.can_continue():
            state.increment_iteration()
            iteration = state.current_iteration

            # -------------------------------------------------------------
            # ÉTAPE 1 : PLAN (Choix de l'analyse et de l'outil MCP)
            # -------------------------------------------------------------
            plan = planner.plan_next_step(case_id, db)
            state.log_step("PLAN", plan)

            if plan.get("action") == "CONCLUDE":
                state.conclude(plan.get("reasoning", "Investigation terminée selon la planification."))
                break

            # -------------------------------------------------------------
            # ÉTAPE 2 : DO (Exécution de l'outil forensique via MCP)
            # -------------------------------------------------------------
            tool_name = plan.get("tool_name")
            if tool_name:
                state.executed_tools.append(tool_name)

            new_observations = executor.execute_step(case_id, plan, db)
            state.log_step("DO", {
                "tool_name": tool_name,
                "observations_count": len(new_observations),
            })

            # -------------------------------------------------------------
            # ÉTAPE 3 : SOLVE (Corrélation multi-sources et hypothèse)
            # -------------------------------------------------------------
            hypothesis = solver.correlate_and_hypothesize(case_id, db)
            state.log_step("SOLVE", {
                "hypothesis_id": str(hypothesis.hypothesis_id) if hypothesis else None,
                "title": hypothesis.title if hypothesis else None,
                "confidence": hypothesis.confidence if hypothesis else None,
            })

            if not hypothesis:
                continue

            # -------------------------------------------------------------
            # ÉTAPE 4 : VERIFY (Confrontation critique face aux preuves)
            # -------------------------------------------------------------
            verification = verifier.verify_hypothesis(hypothesis, db)
            state.log_step("VERIFY", verification)

            # Si l'hypothèse est solidement validée par les preuves et qu'aucun nouvel outil n'est requis
            if verification.get("decision") == "VALIDATED" and verification.get("confidence", 0) >= 0.85:
                state.conclude(
                    f"Hypothèse validée avec succès ({int(verification.get('confidence', 0) * 100)}% de confiance) : "
                    f"{hypothesis.title}. {verification.get('justification')}"
                )
                break

        db.commit()
        return state


orchestrator = AgentOrchestrator()
