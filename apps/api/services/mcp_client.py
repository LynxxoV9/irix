import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
import httpx
from apps.api.config import get_settings

### Résolution du chemin vers les outils forensiques locaux
mcp_root = Path(__file__).resolve().parents[3] / "mcp"
if str(mcp_root) not in sys.path:
    sys.path.insert(0, str(mcp_root))

from tools.hasher import inspect_file_hashes
from tools.evtx import parse_evtx_records
from tools.yara import scan_file_signatures
from tools.tavily import lookup_threat_intelligence

settings = get_settings()

### Catalogue statique des outils forensiques enregistrés sur le serveur MCP
TOOL_REGISTRY: Dict[str, Dict[str, Any]] = {
    "file_hasher": {
        "name": "file_hasher",
        "description": "Calcule les empreintes (MD5, SHA-1, SHA-256), l'entropie de Shannon et identifie le format via magic bytes.",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Chemin absolu vers l'artefact sur le disque."}
            },
            "required": ["file_path"],
        },
        "handler": inspect_file_hashes,
    },
    "evtx_analyzer": {
        "name": "evtx_analyzer",
        "description": "Analyse les journaux Windows pour détecter les techniques malveillantes (PowerShell obfusqué, vssadmin, vol d'identifiants).",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Chemin absolu vers le journal d'événements."}
            },
            "required": ["file_path"],
        },
        "handler": parse_evtx_records,
    },
    "yara_scanner": {
        "name": "yara_scanner",
        "description": "Scanne un fichier contre des règles YARA intégrées (Webshells, Mimikatz, Cobalt Strike, Reverse Shells).",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Chemin absolu vers le fichier à scanner."}
            },
            "required": ["file_path"],
        },
        "handler": scan_file_signatures,
    },
    "threat_intel": {
        "name": "threat_intel",
        "description": "Interroge Tavily Threat Intelligence pour évaluer la réputation et l'historique d'une IP, d'un domaine ou d'un hash.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Indicateur de compromission à rechercher (ex: 198.51.100.42)."},
                "indicator_type": {"type": "string", "description": "Type d'IOC (IP, DOMAIN, SHA256).", "default": "IP"},
            },
            "required": ["query"],
        },
        "handler": lookup_threat_intelligence,
    },
}


class MCPClient:
    ### Client MCP utilisé par l'API et l'agent IRYX pour interagir avec les outils forensiques
    def __init__(self, server_url: Optional[str] = None):
        self.server_url = server_url or settings.MCP_SERVER_URL

    def list_tools(self) -> List[Dict[str, Any]]:
        ### Liste l'ensemble des outils forensiques exposés avec leur documentation et paramètres
        tools_list = []
        for name, spec in TOOL_REGISTRY.items():
            tools_list.append({
                "name": spec["name"],
                "description": spec["description"],
                "parameters": spec["parameters"],
            })
        return tools_list

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        ### Exécute un outil forensique MCP et retourne le résultat structuré
        spec = TOOL_REGISTRY.get(tool_name)
        if not spec:
            raise ValueError(f"Outil forensique inconnu : '{tool_name}'. Outils disponibles : {list(TOOL_REGISTRY.keys())}")

        handler = spec["handler"]
        try:
            result = handler(**arguments)
            return {
                "tool_name": tool_name,
                "status": "SUCCESS",
                "result": result,
            }
        except Exception as e:
            return {
                "tool_name": tool_name,
                "status": "ERROR",
                "error": str(e),
            }


mcp_client = MCPClient()
