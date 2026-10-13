import uuid
from sqlalchemy.orm import Session
from agent.state import AgentState
from agent.hypothesis import calculate_hypothesis_confidence
from agent.planner import planner
from evidence.models import Investigation, Artifact, Observation, ToolExecution


def test_agent_state_transitions():
    case_id = uuid.uuid4()
    state = AgentState(case_id=case_id, max_iterations=3)

    assert state.can_continue() is True
    assert state.current_iteration == 0

    state.increment_iteration()
    assert state.current_iteration == 1
    state.log_step("PLAN", {"tool": "evtx_analyzer"})

    state.increment_iteration()
    state.increment_iteration()
    assert state.current_iteration == 3
    assert state.can_continue() is False
    assert state.status == "MAX_ITERATIONS_REACHED"

    state.conclude("Investigation finie")
    assert state.status == "CONCLUDED"
    assert state.conclusion_summary == "Investigation finie"


def test_hypothesis_confidence_scoring():
    # Base confidence 0.70 with 4 supporting observations
    conf = calculate_hypothesis_confidence(base_confidence=0.70, observations_count=4)
    assert conf == 0.90  # 0.70 + min(4 * 0.05, 0.20) = 0.90

    # With contradiction penalty
    conf_contradicted = calculate_hypothesis_confidence(
        base_confidence=0.70, observations_count=4, contradictions_count=1
    )
    assert conf_contradicted == 0.60  # 0.90 - 0.30 = 0.60


def test_planner_tool_selection(db_session: Session):
    case = Investigation(title="Case Plan Test", status="OPEN")
    db_session.add(case)
    db_session.commit()

    # Add unanalyzed EVTX artifact
    art = Artifact(
        case_id=case.case_id,
        name="Security.evtx",
        artifact_type="EVTX",
        storage_uri="/tmp/Security.evtx",
        sha256="1234" * 16,
        size_bytes=1024,
    )
    db_session.add(art)
    db_session.commit()

    plan = planner.plan_next_step(case.case_id, db_session)
    assert plan["action"] == "EXECUTE_TOOL"
    assert plan["tool_name"] == "evtx_analyzer"
    assert plan["artifact_id"] == str(art.artifact_id)
