import hashlib
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Dict, Any, Tuple
from apps.api.config import get_settings

settings = get_settings()

### Taille des blocs de lecture (64 Ko)
### Pourquoi ? Évite de charger des fichiers forensiques volumineux (ex: dumps mémoire de plusieurs Go) en mémoire RAM
BUFFER_SIZE = 65536


def compute_stream_sha256(file_obj: BinaryIO) -> Tuple[str, int]:
    ### Calcule l'empreinte cryptographique SHA-256 et la taille en octets en parcourant le flux par blocs
    hasher = hashlib.sha256()
    total_bytes = 0

    ### On rembobine le pointeur au début du fichier au cas où
    file_obj.seek(0)
    while chunk := file_obj.read(BUFFER_SIZE):
        hasher.update(chunk)
        total_bytes += len(chunk)

    ### On repositionne le curseur au début pour les opérations suivantes
    file_obj.seek(0)
    return hasher.hexdigest(), total_bytes


def compute_file_sha256(file_path: Path | str) -> Tuple[str, int]:
    ### Calcule le SHA-256 et la taille d'un fichier déjà présent sur le disque local
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Fichier introuvable sur le disque : {path}")

    with open(path, "rb") as f:
        return compute_stream_sha256(f)


def save_evidence_artifact(
    case_id: uuid.UUID,
    artifact_id: uuid.UUID,
    original_filename: str,
    file_obj: BinaryIO,
) -> Tuple[str, str, int]:
    ### Stocke l'artefact de manière sécurisée et immuable dans le répertoire dédié du dossier d'investigation
    ### Retourne : (chemin_stockage_absolu, empreinte_sha256, taille_octets)

    ### Création du dossier sécurisé dédié à l'investigation (ex: ./data/artifacts/<case_id>/)
    case_dir = settings.storage_path / str(case_id)
    case_dir.mkdir(parents=True, exist_ok=True)

    ### Prévention des attaques de type path traversal dans le nom du fichier
    safe_name = Path(original_filename).name
    destination_filename = f"{artifact_id}_{safe_name}"
    destination_path = case_dir / destination_filename

    hasher = hashlib.sha256()
    total_bytes = 0

    file_obj.seek(0)
    with open(destination_path, "wb") as out_file:
        while chunk := file_obj.read(BUFFER_SIZE):
            hasher.update(chunk)
            total_bytes += len(chunk)
            out_file.write(chunk)

    sha256_hash = hasher.hexdigest()

    ### Règle d'or DFIR : positionner le fichier stocké en lecture seule (0o444)
    ### Pourquoi ? Garantit qu'aucun processus ni analyste ne puisse altérer la preuve originale
    try:
        os.chmod(destination_path, 0o444)
    except OSError:
        pass

    return str(destination_path.resolve()), sha256_hash, total_bytes


def verify_evidence_integrity(storage_uri: str, expected_sha256: str) -> bool:
    ### Vérifie la conformité de l'empreinte actuelle du fichier avec le hash enregistré lors de l'ingestion
    ### Si le hash ne correspond pas, la chaîne de preuve est compromise
    path = Path(storage_uri)
    if not path.exists():
        return False

    actual_sha256, _ = compute_file_sha256(path)
    return actual_sha256.lower() == expected_sha256.lower()


def detect_artifact_type_from_name(filename: str) -> str:
    ### Détection heuristique initiale du type de preuve d'après son extension
    ext = Path(filename).suffix.lower()
    mapping = {
        ".evtx": "EVTX",
        ".raw": "MEMORY_DUMP",
        ".dmp": "MEMORY_DUMP",
        ".vmem": "MEMORY_DUMP",
        ".pcap": "PCAP",
        ".pcapng": "PCAP",
        ".cap": "PCAP",
        ".pf": "PREFETCH",
        ".dd": "DISK_IMAGE",
        ".e01": "DISK_IMAGE",
        ".img": "DISK_IMAGE",
        ".exe": "BINARY",
        ".dll": "BINARY",
        ".sys": "DRIVER",
        ".log": "LOG_FILE",
        ".json": "JSON_REPORT",
    }
    return mapping.get(ext, "GENERIC_ARTIFACT")
