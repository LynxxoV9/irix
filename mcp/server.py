from mcp.server.fastmcp import FastMCP
import platform
import socket
import sys
from pathlib import Path
from typing import Dict, Any

# Assure la résolution des outils locaux quel que soit le contexte d'exécution
mcp_root = Path(__file__).parent.resolve()
if str(mcp_root) not in sys.path:
    sys.path.insert(0, str(mcp_root))

from tools.hasher import inspect_file_hashes
from tools.evtx import parse_evtx_records
from tools.yara import scan_file_signatures
from tools.tavily import lookup_threat_intelligence

### Initialisation du serveur MCP pour IRYX
### Pourquoi ? Standardise l'exposition des outils forensiques selon le protocole Model Context Protocol
mcp = FastMCP(
    "IRYX-MCP-Forensics",
    host="0.0.0.0",
    port=8001,
)


@mcp.tool()
def get_system_info() -> Dict[str, Any]:
    ### Retourne les informations système de l'environnement d'exécution forensique
    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
    }


@mcp.tool()
def file_hasher(file_path: str) -> Dict[str, Any]:
    ### Calcule les empreintes MD5, SHA1, SHA256, l'entropie de Shannon et les magic bytes d'un fichier
    return inspect_file_hashes(file_path)


@mcp.tool()
def evtx_analyzer(file_path: str) -> Dict[str, Any]:
    ### Analyse les journaux d'événements Windows (.evtx ou export) et détecte les commandes malveillantes (LOLBAS)
    return parse_evtx_records(file_path)


@mcp.tool()
def yara_scanner(file_path: str) -> Dict[str, Any]:
    ### Scanne un artefact suspect contre des signatures de menaces (Webshells, Mimikatz, Cobalt Strike, Reverse Shells)
    return scan_file_signatures(file_path)


@mcp.tool()
def threat_intel(query: str, indicator_type: str = "IP") -> Dict[str, Any]:
    ### Recherche de renseignements CTI externes sur une IP, un domaine ou un hash via Tavily Search API
    return lookup_threat_intelligence(query=query, indicator_type=indicator_type)


if __name__ == "__main__":
    mcp.run()
