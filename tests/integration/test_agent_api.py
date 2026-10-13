import io
from fastapi.testclient import TestClient


def test_autonomous_agent_investigation_flow_api(client: TestClient):
    ### 1. Création de l'investigation
    case_resp = client.post(
        "/api/v1/investigations/",
        json={"title": "Opération BlackLotus - Autonomous DFIR Case", "status": "OPEN"},
    )
    assert case_resp.status_code == 201
    case_id = case_resp.json()["case_id"]

    ### 2. Téléversement d'un journal Windows hostile avec LOLBAS et adresse IP suspecte
    hostile_log = (
        "2026-10-13T12:00:00Z [4688] New Process Created: powershell.exe -enc JABzAHk... Parent: explorer.exe\n"
        "2026-10-13T12:02:00Z [4688] New Process: vssadmin.exe delete shadows /all /quiet\n"
        "2026-10-13T12:05:00Z [Network] Outbound connection to C2 IP 198.51.100.42 port 443\n"
    )
    files = {"file": ("Endpoint_Security.log", io.BytesIO(hostile_log.encode()), "text/plain")}
    upload_resp = client.post(f"/api/v1/investigations/{case_id}/artifacts/upload", files=files)
    assert upload_resp.status_code == 201

    ### 3. Exécution autonome de la boucle agentique (PLAN -> DO -> SOLVE -> VERIFY)
    run_resp = client.post(f"/api/v1/investigations/{case_id}/agent/run?max_iterations=5")
    assert run_resp.status_code == 200
    agent_state = run_resp.json()

    # Vérifications de l'état agentique
    assert agent_state["status"] == "CONCLUDED"
    assert agent_state["current_iteration"] >= 1
    assert "evtx_analyzer" in agent_state["executed_tools"]

    # Vérification que toutes les phases ont été exécutées
    phases_logged = {step["phase"] for step in agent_state["steps_history"]}
    assert "PLAN" in phases_logged
    assert "DO" in phases_logged
    assert "SOLVE" in phases_logged
    assert "VERIFY" in phases_logged

    ### 4. Récupération des hypothèses et de leurs preuves rattachées
    hypo_resp = client.get(f"/api/v1/investigations/{case_id}/agent/hypotheses")
    assert hypo_resp.status_code == 200
    hypotheses = hypo_resp.json()

    assert len(hypotheses) >= 1
    main_hypo = hypotheses[0]
    assert main_hypo["status"] == "VALIDATED"
    assert main_hypo["confidence"] >= 0.75
    assert len(main_hypo["supporting_evidence"]) >= 1

    # Chaque preuve rattachée doit avoir un type de relation et une référence source
    for evidence in main_hypo["supporting_evidence"]:
        assert evidence["relationship_type"] in ("SUPPORTS", "CORROBORATES")
        assert len(evidence["source_reference"]) > 0
