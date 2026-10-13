from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import httpx
from apps.api.config import get_settings

settings = get_settings()

### Base de connaissances CTI locale de secours (utilisée si aucune clé API Tavily n'est configurée)
KNOWN_INDICATOR_MOCK_DATABASE = {
    "198.51.100.42": {
        "reputation": "MALICIOUS",
        "threat_actor": "APT29 / Cozy Bear",
        "malware_family": "Cobalt Strike",
        "confidence": 0.95,
        "tags": ["c2", "cobalt_strike", "beaconing", "malicious_ip"],
        "sources": [
            {
                "title": "Cobalt Strike Infrastructure Tracking Report",
                "url": "https://threatintel.example.com/indicators/198.51.100.42",
                "snippet": "Active Command & Control server observed directing Cobalt Strike beacons on port 443.",
            }
        ],
    },
    "45.33.32.156": {
        "reputation": "SUSPICIOUS",
        "threat_actor": "Scan / Reconnaissance",
        "malware_family": "Nmap Scanning Node",
        "confidence": 0.70,
        "tags": ["reconnaissance", "scanner"],
        "sources": [
            {
                "title": "Shodan Public Scan Node",
                "url": "https://shodan.example.com/host/45.33.32.156",
                "snippet": "IP associated with distributed port scanning infrastructure.",
            }
        ],
    },
    "evil-c2-domain.com": {
        "reputation": "MALICIOUS",
        "threat_actor": "FIN7",
        "malware_family": "Carbanak / Cobalt Strike",
        "confidence": 0.92,
        "tags": ["c2_domain", "dns_tunneling"],
        "sources": [
            {
                "title": "DNS Telemetry Report on evil-c2-domain.com",
                "url": "https://threatpost.example.com/domains/evil-c2-domain.com",
                "snippet": "Fast-flux domain hosting payload staging scripts and reverse proxies.",
            }
        ],
    },
}


def lookup_threat_intelligence(query: str, indicator_type: str = "IP") -> Dict[str, Any]:
    ### Recherche de renseignements sur les cybermenaces via Tavily Search API (exigence F08 du CDC)
    ### Si la clé TAVILY_API_KEY est absente, bascule sur la base locale pour garantir l'exécution sans erreur

    api_key = settings.TAVILY_API_KEY

    if api_key:
        ### Appel réel à l'API Tavily
        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.post(
                    "https://api.tavily.com/search",
                    json={
                        "api_key": api_key,
                        "query": f"cybersecurity threat intelligence IOC {query}",
                        "search_depth": "advanced",
                        "include_answer": True,
                        "max_results": 5,
                    },
                )
                if response.status_code == 200:
                    data = response.json()
                    results = data.get("results", [])
                    return {
                        "indicator": query,
                        "indicator_type": indicator_type,
                        "provider": "TAVILY_API",
                        "summary": data.get("answer", f"Threat intelligence query completed for {query}"),
                        "sources_count": len(results),
                        "sources": [
                            {
                                "title": r.get("title"),
                                "url": r.get("url"),
                                "snippet": r.get("content", "")[:300],
                            }
                            for r in results
                        ],
                        "retrieved_at": datetime.now(timezone.utc).isoformat(),
                    }
        except Exception:
            ### En cas d'indisponibilité du réseau externe, on poursuit avec le fallback local
            pass

    ### Mode local déterministe (hors ligne ou sans clé API)
    clean_query = query.strip()
    mock_data = KNOWN_INDICATOR_MOCK_DATABASE.get(clean_query)

    if mock_data:
        return {
            "indicator": clean_query,
            "indicator_type": indicator_type,
            "provider": "TAVILY_EMULATED",
            "summary": f"Known malicious IOC detected in threat intelligence feeds ({mock_data['malware_family']})",
            "reputation": mock_data["reputation"],
            "threat_actor": mock_data["threat_actor"],
            "malware_family": mock_data["malware_family"],
            "confidence": mock_data["confidence"],
            "tags": mock_data["tags"],
            "sources": mock_data["sources"],
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
        }

    ### Indicateur inconnu / non répertorié
    return {
        "indicator": clean_query,
        "indicator_type": indicator_type,
        "provider": "TAVILY_EMULATED",
        "summary": f"No active threat intelligence reports found for {clean_query}",
        "reputation": "UNKNOWN",
        "confidence": 0.1,
        "tags": ["unclassified"],
        "sources": [],
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
    }
