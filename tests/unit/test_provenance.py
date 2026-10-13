import io
import uuid
from pathlib import Path
from evidence.provenance import (
    compute_stream_sha256,
    compute_file_sha256,
    save_evidence_artifact,
    verify_evidence_integrity,
    detect_artifact_type_from_name,
)


def test_compute_stream_sha256_known_hashes():
    ### Test avec un contenu vide dont le SHA-256 officiel est connu
    empty_stream = io.BytesIO(b"")
    empty_hash, empty_size = compute_stream_sha256(empty_stream)
    assert empty_size == 0
    assert empty_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    ### Test avec un contenu textuel connu
    content = b"IRYX Incident Response DFIR Platform"
    stream = io.BytesIO(content)
    calculated_hash, size = compute_stream_sha256(stream)
    assert size == len(content)
    assert len(calculated_hash) == 64


def test_save_evidence_artifact_and_verify(tmp_path: Path, monkeypatch):
    ### Simulation du stockage sécurisé dans un dossier temporaire
    monkeypatch.setattr("apps.api.config.Settings.storage_path", tmp_path)

    case_id = uuid.uuid4()
    artifact_id = uuid.uuid4()
    sample_data = b"EVTX_HEADER_MOCK_EVENT_LOG_DATA"
    stream = io.BytesIO(sample_data)

    storage_uri, sha256_hash, size_bytes = save_evidence_artifact(
        case_id=case_id,
        artifact_id=artifact_id,
        original_filename="Security.evtx",
        file_obj=stream,
    )

    saved_file = Path(storage_uri)
    assert saved_file.exists()
    assert size_bytes == len(sample_data)

    ### Vérification que la chaîne de conservation confirme l'intégrité
    assert verify_evidence_integrity(storage_uri, sha256_hash) is True

    ### Vérification qu'une altération ou un faux hash est détecté
    tampered_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    assert verify_evidence_integrity(storage_uri, tampered_hash) is False


def test_detect_artifact_type_from_name():
    assert detect_artifact_type_from_name("System.evtx") == "EVTX"
    assert detect_artifact_type_from_name("win11_dump.raw") == "MEMORY_DUMP"
    assert detect_artifact_type_from_name("traffic.pcap") == "PCAP"
    assert detect_artifact_type_from_name("CMD.EXE-A1B2C3D4.pf") == "PREFETCH"
    assert detect_artifact_type_from_name("disk.dd") == "DISK_IMAGE"
    assert detect_artifact_type_from_name("malware.exe") == "BINARY"
    assert detect_artifact_type_from_name("unknown.xyz") == "GENERIC_ARTIFACT"
