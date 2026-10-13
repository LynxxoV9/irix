import re
from pathlib import Path
from typing import Dict, Any, List


### Règles de signatures intégrées pour la détection DFIR standard
### Pourquoi ? Fournit un moteur de signatures prêt à l'emploi et déterministe pour le hackathon
BUILTIN_RULES = [
    {
        "rule_name": "Webshell_PHP_Generic",
        "description": "Detects generic PHP webshell execution functions (eval, system, passthru, base64_decode)",
        "severity": "HIGH",
        "mitre_technique": "T1505.003",
        "patterns": [
            rb"(?i)eval\s*\(\s*base64_decode",
            rb"(?i)passthru\s*\(\s*\$_(GET|POST|REQUEST)",
            rb"(?i)system\s*\(\s*\$_(GET|POST|REQUEST)",
            rb"(?i)assert\s*\(\s*\$_(GET|POST|REQUEST)",
        ],
    },
    {
        "rule_name": "HackTool_Mimikatz_Strings",
        "description": "Detects Mimikatz credential dumping artifacts (sekurlsa, logonpasswords, wdigest)",
        "severity": "CRITICAL",
        "mitre_technique": "T1003.001",
        "patterns": [
            rb"(?i)sekurlsa::logonpasswords",
            rb"(?i)wdigest\.dll",
            rb"(?i)lsadump::sam",
            rb"(?i)privilege::debug",
        ],
    },
    {
        "rule_name": "Suspicious_Reverse_Shell_Python",
        "description": "Detects python interactive socket reverse shell payload",
        "severity": "HIGH",
        "mitre_technique": "T1059.006",
        "patterns": [
            rb"socket\.socket.*connect.*os\.dup2",
            rb"pty\.spawn\([\"']/bin/(sh|bash)[\"']\)",
        ],
    },
    {
        "rule_name": "CobaltStrike_Beacon_Indicators",
        "description": "Detects Cobalt Strike default staged/unstaged pipe and user-agent strings",
        "severity": "CRITICAL",
        "mitre_technique": "T1071.001",
        "patterns": [
            rb"\\\\\\.\\\\pipe\\\\msagent_",
            rb"Mozilla/5\.0 \(compatible; MSIE 9\.0; Windows NT 6\.1; Trident/5\.0\)",
            rb"(?i)/pixel\.gif\?session=",
        ],
    },
]


def scan_file_signatures(file_path: str) -> Dict[str, Any]:
    ### Analyse un fichier contre les règles de signatures YARA intégrées
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Fichier introuvable pour scan YARA : {file_path}")

    try:
        content = path.read_bytes()
    except Exception as e:
        raise RuntimeError(f"Erreur de lecture du fichier : {str(e)}")

    matches = []
    for rule in BUILTIN_RULES:
        matched_strings = []
        for pattern in rule["patterns"]:
            for match in re.finditer(pattern, content):
                matched_strings.append({
                    "pattern": pattern.decode("utf-8", errors="ignore"),
                    "offset": match.start(),
                    "matched_bytes": match.group(0)[:60].decode("utf-8", errors="ignore"),
                })

        if matched_strings:
            matches.append({
                "rule_name": rule["rule_name"],
                "description": rule["description"],
                "severity": rule["severity"],
                "mitre_technique": rule["mitre_technique"],
                "hits_count": len(matched_strings),
                "hits": matched_strings[:5],  # Limite pour ne pas surcharger le résultat
            })

    return {
        "file_name": path.name,
        "scanned_size_bytes": len(content),
        "total_rules_scanned": len(BUILTIN_RULES),
        "matches_count": len(matches),
        "matches": matches,
    }
