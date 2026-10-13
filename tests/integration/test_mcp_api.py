import io
from fastapi.testclient import TestClient


def test_list_tools_api(client: TestClient):
    ### Test de l'endpoint de découverte des outils MCP
    resp = client.get("/api/v1/tools/")
    assert resp.status_code == 200
    tools = resp.json()
    names = [t["name"] for t in tools]
    assert "file_hasher" in names
    assert "evtx_analyzer" in names
    assert "yara_scanner" in names
    assert "threat_intel" in names


def test_execute_evtx_and_threat_intel_tools_api(client: TestClient):
    ### 1. Créer une investigation
    case_resp = client.post(
        "/api/v1/investigations/",
        json={"title": "Investigation MCP Tool Execution", "status": "IN_PROGRESS"},
    )
    case_id = case_resp.json()["case_id"]

    ### 2. Téléverser un fichier journal suspect
    malicious_log = (
        "2026-10-13T10:00:00Z Process 4688: powershell.exe -enc JABzAGMA... Parent: cmd.exe\n"
        "2026-10-13T10:05:00Z Service 7045: New service installed: RansomShieldPersistence\n"
    )
    files = {"file": ("Security_Audit.log", io.BytesIO(malicious_log.encode()), "text/plain")}
    upload_resp = client.post(f"/api/v1/investigations/{case_id}/artifacts/upload", files=files)
    assert upload_resp.status_code == 201
    artifact_id = upload_resp.json()["artifact_id"]

    ### 3. Exécuter l'outil EVTX Analyzer via MCP
    exec_evtx_resp = client.post(
        f"/api/v1/investigations/{case_id}/tools/execute",
        json={
            "tool_name": "evtx_analyzer",
            "artifact_id": artifact_id,
        },
    )
    assert exec_evtx_resp.status_code == 200
    evtx_data = exec_evtx_resp.json()

    assert evtx_data["execution"]["tool_name"] == "evtx_analyzer"
    assert evtx_data["execution"]["status"] == "COMPLETED"
    assert len(evtx_data["observations_created"]) >= 1
    assert any("PowerShell" in obs["summary"] for obs in evtx_data["observations_created"])

    ### 4. Exécuter l'outil Threat Intel sur une IP C2
    exec_c2_resp = client.post(
        f"/api/v1/investigations/{case_id}/tools/execute",
        json={
            "tool_name": "threat_intel",
            "parameters": {"query": "198.51.100.42", "indicator_type": "IP"},
        },
    )
    assert exec_c2_resp.status_code == 200
    c2_data = exec_c2_resp.json()

    assert c2_data["execution"]["tool_name"] == "threat_intel"
    assert c2_data["execution"]["status"] == "COMPLETED"
    assert len(c2_data["observations_created"]) == 1
    assert "MALICIOUS" in c2_data["observations_created"][0]["summary"]
