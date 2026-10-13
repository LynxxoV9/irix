import json
import uuid
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from evidence.models import Artifact, ToolExecution, Observation, Investigation
from llm.router import llm_router


class AgentPlanner:
    ### Étape 1 : PLAN de la boucle agentique IRYX (CDC Section 4.1)
    ### Analyse le contexte du cas, identifie les lacunes d'analyse et planifie la prochaine action pertinente
    def plan_next_step(self, case_id: uuid.UUID, db: Session) -> Dict[str, Any]:
        case = db.query(Investigation).filter(Investigation.case_id == case_id).first()
        if not case:
            return {"action": "CONCLUDE", "reasoning": "Dossier d'investigation introuvable."}

        artifacts = db.query(Artifact).filter(Artifact.case_id == case_id).all()
        executions = db.query(ToolExecution).filter(ToolExecution.case_id == case_id).all()
        observations = db.query(Observation).filter(Observation.case_id == case_id).all()

        executed_artifact_ids = {e.artifact_id for e in executions if e.artifact_id is not None}
        executed_tools = {e.tool_name for e in executions}

        ### 1. Recherche d'artefacts non encore analysés
        for art in artifacts:
            if art.artifact_id not in executed_artifact_ids:
                if art.artifact_type in ("EVTX", "LOG_FILE") or art.name.endswith((".evtx", ".log")):
                    tool_to_run = "evtx_analyzer"
                elif art.artifact_type in ("BINARY", "DRIVER") or art.name.endswith((".exe", ".dll", ".php")):
                    tool_to_run = "yara_scanner"
                else:
                    tool_to_run = "file_hasher"

                return {
                    "action": "EXECUTE_TOOL",
                    "tool_name": tool_to_run,
                    "artifact_id": str(art.artifact_id),
                    "parameters": {"file_path": art.storage_uri},
                    "reasoning": f"L'artefact '{art.name}' ({art.artifact_type}) n'a pas encore été analysé. Lancement de {tool_to_run}.",
                }

        ### 2. Recherche d'indicateurs (IP, domaine) extraits dans les observations nécessitant Threat Intel
        if "threat_intel" not in executed_tools:
            for obs in observations:
                text_to_search = json.dumps(obs.data) + " " + obs.summary
                # Recherche d'IPs suspectes courantes dans les données
                import re
                ip_match = re.search(r"\b(198\.51\.100\.\d+|45\.33\.32\.\d+|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b", text_to_search)
                if ip_match:
                    detected_ip = ip_match.group(0)
                    if not detected_ip.startswith(("127.", "0.", "255.")):
                        return {
                            "action": "EXECUTE_TOOL",
                            "tool_name": "threat_intel",
                            "artifact_id": None,
                            "parameters": {"query": detected_ip, "indicator_type": "IP"},
                            "reasoning": f"L'adresse IP {detected_ip} a été identifiée dans l'observation {obs.observation_id}. Recherche de réputation CTI requise.",
                        }

        ### 3. Consultation du modèle LLM pour arbitrage si tout a été scanné
        prompt = (
            f"Cas d'investigation : {case.title}\n"
            f"Artefacts disponibles ({len(artifacts)}), Outils exécutés ({len(executions)}), Observations enregistrées ({len(observations)}).\n"
            "Détermine s'il faut exécuter un outil supplémentaire ou CONCLURE l'investigation."
        )
        llm_response = llm_router.plan(prompt)
        try:
            parsed = json.loads(llm_response)
            if isinstance(parsed, dict) and "action" in parsed:
                return parsed
        except (json.JSONDecodeError, TypeError):
            pass

        return {
            "action": "CONCLUDE",
            "reasoning": "Tous les artefacts et indicateurs principaux ont été analysés. Phase de corrélation terminée.",
        }


planner = AgentPlanner()
