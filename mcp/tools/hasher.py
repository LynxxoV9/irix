import hashlib
import math
from pathlib import Path
from typing import Dict, Any


def calculate_entropy(data: bytes) -> float:
    ### Calcule l'entropie de Shannon sur les octets du fichier
    ### Pourquoi ? Une entropie supérieure à 7.0/8.0 indique souvent un binaire packé (UPX), chiffré ou obfusqué (ransomware/shellcode)
    if not data:
        return 0.0

    entropy = 0.0
    length = len(data)
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1

    for count in byte_counts:
        if count > 0:
            prob = count / length
            entropy -= prob * math.log2(prob)

    return round(entropy, 4)


def detect_file_magic(header: bytes) -> str:
    ### Identifie les premiers octets magiques (Magic Bytes) pour déjouer les fausses extensions d'attaquants
    if header.startswith(b"MZ"):
        return "Windows PE Executable / DLL (MZ)"
    elif header.startswith(b"\x7fELF"):
        return "Linux ELF Binary"
    elif header.startswith(b"PK\x03\x04"):
        return "ZIP Archive / Office OpenXML"
    elif header.startswith(b"%PDF"):
        return "PDF Document"
    elif header.startswith(b"ElfFile\x00"):
        return "Windows Event Log (EVTX Header)"
    elif header.startswith(b"\xd4\xc3\xb2\xa1") or header.startswith(b"\xa1\xb2\xc3\xd4"):
        return "PCAP Network Capture"
    elif header.startswith(b"\x0a\x0d\x0d\x0a"):
        return "PCAPNG Network Capture"
    elif header.startswith(b"SCCA"):
        return "Windows Prefetch File"
    return "Unknown / Raw Data"


def inspect_file_hashes(file_path: str) -> Dict[str, Any]:
    ### Analyse cryptographique et structurelle complète d'un artefact forensique
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Fichier introuvable pour analyse : {file_path}")

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    total_bytes = 0
    header_bytes = b""

    ### Lecture par blocs de 64 Ko
    with open(path, "rb") as f:
        header_bytes = f.read(16)
        f.seek(0)

        while chunk := f.read(65536):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            total_bytes += len(chunk)

    ### Calcul de l'entropie sur un échantillon significatif (jusqu'à 1 Mo pour la rapidité)
    sample_size = min(total_bytes, 1024 * 1024)
    with open(path, "rb") as f:
        sample_data = f.read(sample_size)
        entropy = calculate_entropy(sample_data)

    file_type = detect_file_magic(header_bytes)
    is_suspicious_entropy = entropy > 7.1

    return {
        "file_name": path.name,
        "file_size_bytes": total_bytes,
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "entropy": entropy,
        "is_suspicious_entropy": is_suspicious_entropy,
        "detected_magic_type": file_type,
    }
