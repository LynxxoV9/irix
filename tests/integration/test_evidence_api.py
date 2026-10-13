import io
import json
import uuid
from fastapi.testclient import TestClient


def test_investigation_lifecycle_api(client: TestClient):
    ### 1. Création d'une nouvelle investigation
    payload = {
        "title": "Opération ShadowHawk - Investigation Ransomware",
        "description": "Analyse d'une compromission suspecte avec exfiltration de données.",
        "status": "OPEN",
    }
    create_resp = client.post("/api/v1/investigations/", json=payload)
    assert create_resp.status_code == 201
    case_data = create_resp.json()
    case_id = case_data["case_id"]
    assert case_data["title"] == payload["title"]
    assert case_data["status"] == "OPEN"

    ### 2. Récupération par identifiant
    get_resp = client.get(f"/api/v1/investigations/{case_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["case_id"] == case_id

    ### 3. Liste des investigations
    list_resp = client.get("/api/v1/investigations/")
    assert list_resp.status_code == 200
    cases = list_resp.json()
    assert any(c["case_id"] == case_id for c in cases)

    ### 4. Mise à jour du statut vers IN_PROGRESS
    patch_resp = client.patch(f"/api/v1/investigations/{case_id}/status?new_status=IN_PROGRESS")
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "IN_PROGRESS"


def test_artifact_upload_and_verification_api(client: TestClient):
    ### 1. Créer une investigation hôte
    case_resp = client.post(
        "/api/v1/investigations/",
        json={"title": "Case Forensics Memory & Network", "status": "OPEN"},
    )
    case_id = case_resp.json()["case_id"]

    ### 2. Téléverser un fichier de preuve (artefact réseau PCAP simulé)
    fake_pcap_bytes = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"MOCK_NETWORK_PACKETS" * 20
    files = {
        "file": ("traffic_capture.pcap", io.BytesIO(fake_pcap_bytes), "application/vnd.tcpdump.pcap")
    }
    data = {
        "metadata_json": json.dumps({"source_host": "gateway-01", "interface": "eth0"})
    }

    upload_resp = client.post(
        f"/api/v1/investigations/{case_id}/artifacts/upload",
        files=files,
        data=data,
    )
    assert upload_resp.status_code == 201
    artifact_data = upload_resp.json()
    artifact_id = artifact_data["artifact_id"]

    assert artifact_data["name"] == "traffic_capture.pcap"
    assert artifact_data["artifact_type"] == "PCAP"
    assert artifact_data["size_bytes"] == len(fake_pcap_bytes)
    assert len(artifact_data["sha256"]) == 64
    assert artifact_data["metadata"]["source_host"] == "gateway-01"

    ### 3. Lister les artefacts du dossier
    list_artifacts_resp = client.get(f"/api/v1/investigations/{case_id}/artifacts")
    assert list_artifacts_resp.status_code == 200
    artifacts = list_artifacts_resp.json()
    assert len(artifacts) == 1
    assert artifacts[0]["artifact_id"] == artifact_id

    ### 4. Consulter l'artefact par son ID
    single_resp = client.get(f"/api/v1/artifacts/{artifact_id}")
    assert single_resp.status_code == 200
    assert single_resp.json()["sha256"] == artifact_data["sha256"]

    ### 5. Vérifier la chaîne de conservation (Chain of Custody)
    verify_resp = client.get(f"/api/v1/artifacts/{artifact_id}/verify")
    assert verify_resp.status_code == 200
    verify_data = verify_resp.json()
    assert verify_data["integrity_verified"] is True
    assert verify_data["status"] == "VALID_INTEGRITY"
