import uuid
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from evidence.models import (
    User,
    Investigation,
    Artifact,
    ToolExecution,
    Observation,
    Hypothesis,
    HypothesisEvidence,
    Indicator,
    ThreatIntel,
    MitreTechnique,
    HypothesisTechnique,
    Report,
)
from evidence.schemas import (
    UserRead,
    InvestigationRead,
    ArtifactRead,
    ObservationRead,
    HypothesisRead,
    IndicatorRead,
)


def test_create_user_and_investigation(db_session: Session):
    """Test creating a DFIR analyst user and an investigation case."""
    user = User(
        display_name="Olivier Fiabi",
        email="olivier.fiabi@iryx.local",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    assert user.user_id is not None
    assert user.display_name == "Olivier Fiabi"

    # Schema serialization test
    user_schema = UserRead.model_validate(user)
    assert user_schema.user_id == user.user_id

    # Create investigation
    case = Investigation(
        created_by=user.user_id,
        title="Incident-2026-001: Suspected Cobalt Strike Beaconing",
        description="Investigation into unauthorized outbound connections from Workstation-04.",
        status="OPEN",
    )
    db_session.add(case)
    db_session.commit()
    db_session.refresh(case)

    assert case.case_id is not None
    assert case.creator.email == "olivier.fiabi@iryx.local"
    assert len(user.investigations) == 1

    case_schema = InvestigationRead.model_validate(case)
    assert case_schema.title == case.title


def test_evidence_artifact_and_tool_execution(db_session: Session):
    """Test registering an artifact, executing a tool, and producing observations."""
    case = Investigation(title="Case Memory Dump Analysis", status="IN_PROGRESS")
    db_session.add(case)
    db_session.commit()

    # Add memory dump artifact
    artifact = Artifact(
        case_id=case.case_id,
        name="memdump_ws04.raw",
        artifact_type="MEMORY",
        storage_uri="/data/artifacts/memdump_ws04.raw",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        size_bytes=4294967296,  # 4 GB
        extra_metadata={"os": "Windows 11", "profile": "Win11x64"},
    )
    db_session.add(artifact)
    db_session.commit()
    db_session.refresh(artifact)

    assert artifact.artifact_id is not None
    assert artifact.sha256.startswith("e3b0")
    artifact_schema = ArtifactRead.model_validate(artifact)
    assert artifact_schema.name == "memdump_ws04.raw"

    # Register tool execution (Volatility 3)
    execution = ToolExecution(
        case_id=case.case_id,
        artifact_id=artifact.artifact_id,
        tool_name="volatility3_pslist",
        tool_version="2.7.0",
        status="COMPLETED",
        parameters={"plugin": "windows.pslist"},
        finished_at=datetime.now(timezone.utc),
    )
    db_session.add(execution)
    db_session.commit()
    db_session.refresh(execution)

    assert execution.execution_id is not None
    assert execution.artifact.name == "memdump_ws04.raw"

    # Add observation produced by execution
    obs = Observation(
        execution_id=execution.execution_id,
        case_id=case.case_id,
        observation_type="PROCESS_ANOMALY",
        summary="Unusual svchost.exe spawned with parent PID not matching services.exe",
        observed_at=datetime.now(timezone.utc),
        confidence=0.92,
        data={"pid": 4912, "ppid": 3120, "name": "svchost.exe", "path": "C:\\Users\\Public\\svchost.exe"},
        source_reference="volatility3:windows.pslist:PID4912",
    )
    db_session.add(obs)
    db_session.commit()
    db_session.refresh(obs)

    assert obs.observation_id is not None
    assert obs.execution.tool_name == "volatility3_pslist"
    assert len(execution.observations) == 1

    obs_schema = ObservationRead.model_validate(obs)
    assert obs_schema.observation_type == "PROCESS_ANOMALY"


def test_hypothesis_and_evidence_correlation(db_session: Session):
    """Test formulating hypothesis and linking observations (chain of proof)."""
    case = Investigation(title="Case Correlation", status="IN_PROGRESS")
    db_session.add(case)
    db_session.commit()

    execution = ToolExecution(
        case_id=case.case_id,
        tool_name="mock_tool",
        status="COMPLETED",
    )
    db_session.add(execution)
    db_session.commit()

    obs1 = Observation(
        execution_id=execution.execution_id,
        case_id=case.case_id,
        observation_type="PROCESS",
        summary="Suspicious PowerShell command invoking encoded script",
        confidence=0.88,
        data={"cli": "powershell -enc JABz..."},
        source_reference="evtx:event_4688:record_1042",
    )
    obs2 = Observation(
        execution_id=execution.execution_id,
        case_id=case.case_id,
        observation_type="NETWORK",
        summary="Outbound connection to known C2 IP 198.51.100.42:443",
        confidence=0.95,
        data={"dest_ip": "198.51.100.42", "dest_port": 443},
        source_reference="tshark:pcap:frame_823",
    )
    db_session.add_all([obs1, obs2])
    db_session.commit()

    # Formulate hypothesis
    hypo = Hypothesis(
        case_id=case.case_id,
        title="Initial Access via Encoded PowerShell and C2 Callback",
        description="Adversary executed obfuscated PowerShell to establish reverse C2 connection.",
        status="PROPOSED",
        confidence=0.85,
    )
    db_session.add(hypo)
    db_session.commit()
    db_session.refresh(hypo)

    # Link both observations to the hypothesis
    link1 = HypothesisEvidence(
        hypothesis_id=hypo.hypothesis_id,
        observation_id=obs1.observation_id,
        relationship_type="SUPPORTS",
    )
    link2 = HypothesisEvidence(
        hypothesis_id=hypo.hypothesis_id,
        observation_id=obs2.observation_id,
        relationship_type="CORROBORATES",
    )
    db_session.add_all([link1, link2])
    db_session.commit()
    db_session.refresh(hypo)

    assert len(hypo.justifications) == 2
    relationships = {j.relationship_type for j in hypo.justifications}
    assert "SUPPORTS" in relationships
    assert "CORROBORATES" in relationships

    # Map to MITRE ATT&CK technique
    tech = MitreTechnique(
        technique_id="T1059.001",
        name="Command and Scripting Interpreter: PowerShell",
        description="Adversaries may abuse PowerShell commands and scripts for execution.",
        url="https://attack.mitre.org/techniques/T1059/001/",
    )
    db_session.add(tech)
    db_session.commit()

    hypo_tech = HypothesisTechnique(
        hypothesis_id=hypo.hypothesis_id,
        technique_id=tech.technique_id,
        justification="Encoded PowerShell command recorded in event 4688.",
    )
    db_session.add(hypo_tech)
    db_session.commit()
    db_session.refresh(hypo)

    assert len(hypo.techniques) == 1
    assert hypo.techniques[0].technique.name.startswith("Command and Scripting")


def test_indicator_threat_intel_and_report(db_session: Session):
    """Test IOC extraction, threat intel enrichment record, and final report."""
    case = Investigation(title="Case Threat Intel", status="IN_PROGRESS")
    db_session.add(case)
    db_session.commit()

    # Create Indicator
    ioc = Indicator(
        case_id=case.case_id,
        indicator_type="IP",
        indicator_value="198.51.100.42",
        first_seen_at=datetime.now(timezone.utc),
    )
    db_session.add(ioc)
    db_session.commit()
    db_session.refresh(ioc)

    # Add Tavily Threat Intelligence record
    intel = ThreatIntel(
        indicator_id=ioc.indicator_id,
        provider="TAVILY",
        query="threat intelligence 198.51.100.42 Cobalt Strike",
        source_url="https://threatpost.example.com/ioc/198.51.100.42",
        result_data={"reputation": "malicious", "tags": ["cobalt_strike", "c2"]},
    )
    db_session.add(intel)
    db_session.commit()
    db_session.refresh(ioc)

    assert len(ioc.threat_intel) == 1
    assert ioc.threat_intel[0].provider == "TAVILY"
    assert ioc.threat_intel[0].result_data["reputation"] == "malicious"

    # Generate Report record
    report = Report(
        case_id=case.case_id,
        report_format="MARKDOWN",
        version=1,
        summary="Confirmed Cobalt Strike beaconing from workstation WS-04 to 198.51.100.42.",
    )
    db_session.add(report)
    db_session.commit()
    db_session.refresh(report)

    assert report.report_id is not None
    assert report.investigation.title == "Case Threat Intel"
