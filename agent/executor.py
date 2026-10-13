import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from evidence.models import Artifact, Observation, ToolExecution, Indicator, ThreatIntel
from apps.api.services.mcp_client import mcp_client


class AgentExecutor:
    ### Étape 2 : DO de la boucle agentique IRYX (CDC Section 4.1)
    ### Exécute l'outil forensique validé, assure la traçabilité et persiste les observations extraites
    def execute_step(self, case_id: uuid.UUID, plan: Dict[str, Any], db: Session) -> List[Observation]:
        tool_name = plan.get("tool_name")
        artifact_id_str = plan.get("artifact_id")
        parameters = dict(plan.get("parameters", {}))

        artifact_id = uuid.UUID(artifact_id_str) if artifact_id_str else None
        artifact = None

        if artifact_id:
            artifact = db.query(Artifact).filter(Artifact.artifact_id == artifact_id).first()
            if artifact:
                parameters["file_path"] = artifact.storage_uri

        ### 1. Enregistrement de l'exécution dans tool_executions
        execution = ToolExecution(
            case_id=case_id,
            artifact_id=artifact_id,
            tool_name=tool_name,
            status="RUNNING",
            parameters=parameters,
            started_at=datetime.now(timezone.utc),
        )
        db.add(execution)
        db.commit()
        db.refresh(execution)

        ### 2. Exécution de l'outil via le client MCP
        mcp_res = mcp_client.execute_tool(tool_name, parameters)
        execution.finished_at = datetime.now(timezone.utc)

        if mcp_res.get("status") != "SUCCESS":
            execution.status = "FAILED"
            execution.error_message = mcp_res.get("error", "Erreur d'exécution de l'outil MCP")
            db.commit()
            return []

        execution.status = "COMPLETED"
        result_data = mcp_res.get("result", {})
        created_observations = []

        ### 3. Normalisation et création des observations selon le type d'outil
        if tool_name == "evtx_analyzer":
            for finding in result_data.get("findings", []):
                obs = Observation(
                    execution_id=execution.execution_id,
                    case_id=case_id,
                    observation_type="LOG_EVENT",
                    summary=f"[{finding.get('severity')}] {finding.get('description')}: {finding.get('matched_text')}",
                    confidence=finding.get("confidence", 0.8),
                    data=finding,
                    source_reference=f"evtx:{artifact.name if artifact else 'log'}:line_{finding.get('line_number')}",
                )
                db.add(obs)
                created_observations.append(obs)

        elif tool_name == "yara_scanner":
            for match in result_data.get("matches", []):
                obs = Observation(
                    execution_id=execution.execution_id,
                    case_id=case_id,
                    observation_type="SIGNATURE_MATCH",
                    summary=f"Signature YARA '{match.get('rule_name')}' détectée : {match.get('description')}",
                    confidence=0.95,
                    data=match,
                    source_reference=f"yara:{artifact.name if artifact else 'file'}:{match.get('rule_name')}",
                )
                db.add(obs)
                created_observations.append(obs)

        elif tool_name == "file_hasher":
            obs = Observation(
                execution_id=execution.execution_id,
                case_id=case_id,
                observation_type="FILE_METADATA",
                summary=f"Type {result_data.get('detected_magic_type')}, Entropie {result_data.get('entropy')}",
                confidence=1.0,
                data=result_data,
                source_reference=f"hasher:{artifact.name if artifact else 'file'}:sha256",
            )
            db.add(obs)
            created_observations.append(obs)

        elif tool_name == "threat_intel":
            obs = Observation(
                execution_id=execution.execution_id,
                case_id=case_id,
                observation_type="THREAT_INTEL",
                summary=f"CTI pour {result_data.get('indicator')} : Réputation {result_data.get('reputation', 'N/A')}",
                confidence=result_data.get("confidence", 0.8),
                data=result_data,
                source_reference=f"tavily:{result_data.get('indicator')}",
            )
            db.add(obs)
            created_observations.append(obs)

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
        for o in created_observations:
            db.refresh(o)

        return created_observations


executor = AgentExecutor()
