import re
from pathlib import Path
from typing import Dict, Any, List, Optional


### Liste des motifs d'exécution de processus suspects récurrents en DFIR (Living-off-the-Land Binaries - LOLBAS)
SUSPICIOUS_CLI_PATTERNS = [
    (r"powershell.*(-enc|-encodedcommand)", "Encoded PowerShell Execution", "T1059.001", 0.95),
    (r"vssadmin.*delete.*shadows", "Shadow Copies Deletion (Ransomware Inhibition)", "T1490", 0.99),
    (r"certutil.*(-urlcache|-split)", "Certutil Remote Payload Download", "T1105", 0.90),
    (r"whoami.*(/all|/priv)?", "Account Discovery via Whoami", "T1033", 0.65),
    (r"rundll32.*\.dll,.*", "Rundll32 Arbitrary DLL Execution", "T1218.011", 0.85),
    (r"net.*(user|group).*/add", "Unauthorized Account Creation", "T1136.001", 0.90),
    (r"reg.*(add|save).*hklm\\sam", "SAM Registry Hive Dumping", "T1003.002", 0.98),
]


def analyze_log_content(content: str) -> List[Dict[str, Any]]:
    ### Analyse le texte brut d'un log ou export EVTX pour extraire les événements de sécurité DFIR
    findings = []

    lines = content.splitlines()
    for line_idx, line in enumerate(lines, start=1):
        clean_line = line.strip()
        if not clean_line:
            continue

        ### Détection des commandes suspectes (LOLBAS / Ransomware)
        for pattern, label, mitre_id, confidence in SUSPICIOUS_CLI_PATTERNS:
            if re.search(pattern, clean_line, re.IGNORECASE):
                findings.append({
                    "event_type": "SUSPICIOUS_COMMAND",
                    "severity": "HIGH" if confidence > 0.85 else "MEDIUM",
                    "description": label,
                    "mitre_technique": mitre_id,
                    "confidence": confidence,
                    "matched_text": clean_line[:200],
                    "line_number": line_idx,
                })

        ### Détection de suppression de journaux (Event ID 1102)
        if "1102" in clean_line and ("audit log was cleared" in clean_line.lower() or "journal" in clean_line.lower()):
            findings.append({
                "event_type": "SECURITY_LOG_CLEARED",
                "severity": "CRITICAL",
                "description": "Windows Security Event Log was intentionally cleared (Defense Evasion)",
                "mitre_technique": "T1070.001",
                "confidence": 0.98,
                "matched_text": clean_line[:200],
                "line_number": line_idx,
            })

        ### Détection de tentatives d'authentification échouées en série (Event ID 4625)
        if "4625" in clean_line and "failed logon" in clean_line.lower():
            findings.append({
                "event_type": "FAILED_LOGON",
                "severity": "MEDIUM",
                "description": "Failed logon attempt recorded (Potential Brute Force)",
                "mitre_technique": "T1110",
                "confidence": 0.70,
                "matched_text": clean_line[:200],
                "line_number": line_idx,
            })

    return findings


def parse_evtx_records(file_path: str) -> Dict[str, Any]:
    ### Analyse d'un journal Windows Event Log (.evtx ou export texte/JSON)
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Fichier de journal introuvable : {file_path}")

    ### Lecture sécurisée du contenu
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        raise RuntimeError(f"Impossible de lire le fichier journal : {str(e)}")

    findings = analyze_log_content(content)

    return {
        "file_name": path.name,
        "total_anomalies_detected": len(findings),
        "high_severity_count": sum(1 for f in findings if f["severity"] in ("HIGH", "CRITICAL")),
        "findings": findings,
    }
