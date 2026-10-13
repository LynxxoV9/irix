import sys
import tempfile
from pathlib import Path

mcp_root = Path(__file__).resolve().parents[2] / "mcp"
if str(mcp_root) not in sys.path:
    sys.path.insert(0, str(mcp_root))

from tools.hasher import inspect_file_hashes, calculate_entropy, detect_file_magic
from tools.evtx import parse_evtx_records, analyze_log_content
from tools.yara import scan_file_signatures
from tools.tavily import lookup_threat_intelligence
from apps.api.services.mcp_client import mcp_client


def test_hasher_tool():
    ### Création d'un binaire factice avec un en-tête MZ (Windows PE)
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
        tmp.write(b"MZ\x90\x00\x03\x00\x00\x00" + b"\x41" * 1000)
        tmp_path = tmp.name

    try:
        res = inspect_file_hashes(tmp_path)
        assert res["file_size_bytes"] == 1008
        assert "Windows PE" in res["detected_magic_type"]
        assert len(res["md5"]) == 32
        assert len(res["sha256"]) == 64
        assert res["entropy"] >= 0.0
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_evtx_tool():
    ### Création d'un log textuel contenant des activités hostiles typiques
    sample_log = (
        "2026-10-13 14:00:00 [4688] New Process Created: powershell.exe -enc JABzAHkAcw... Parent: explorer.exe\n"
        "2026-10-13 14:02:10 [4688] New Process: vssadmin.exe delete shadows /all /quiet\n"
        "2026-10-13 14:05:00 [1102] The audit log was cleared by Administrator\n"
    )

    with tempfile.NamedTemporaryFile(suffix=".log", mode="w", delete=False) as tmp:
        tmp.write(sample_log)
        tmp_path = tmp.name

    try:
        res = parse_evtx_records(tmp_path)
        assert res["total_anomalies_detected"] >= 3
        assert res["high_severity_count"] >= 2
        types = {f["event_type"] for f in res["findings"]}
        assert "SUSPICIOUS_COMMAND" in types
        assert "SECURITY_LOG_CLEARED" in types
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_yara_tool():
    ### Création d'un fichier contenant un artefact Mimikatz et une fonction de webshell
    content = b"<?php eval(base64_decode($_POST['cmd'])); ?>\nsekurlsa::logonpasswords"
    with tempfile.NamedTemporaryFile(suffix=".php", delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        res = scan_file_signatures(tmp_path)
        assert res["matches_count"] >= 2
        rules = {m["rule_name"] for m in res["matches"]}
        assert "Webshell_PHP_Generic" in rules
        assert "HackTool_Mimikatz_Strings" in rules
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_threat_intel_tool():
    ### Test de recherche CTI pour une IP malveillante connue (Cobalt Strike)
    res = lookup_threat_intelligence(query="198.51.100.42", indicator_type="IP")
    assert res["indicator"] == "198.51.100.42"
    assert res["reputation"] == "MALICIOUS"
    assert "cobalt_strike" in res["tags"]

    ### Test pour un indicateur inconnu
    res_unknown = lookup_threat_intelligence(query="1.1.1.1", indicator_type="IP")
    assert res_unknown["indicator"] == "1.1.1.1"
    assert res_unknown["reputation"] == "UNKNOWN"


def test_mcp_client_execution():
    ### Vérifie que le client MCP découvre et exécute les outils
    tools = mcp_client.list_tools()
    tool_names = {t["name"] for t in tools}
    assert "file_hasher" in tool_names
    assert "evtx_analyzer" in tool_names
    assert "yara_scanner" in tool_names
    assert "threat_intel" in tool_names

    ### Exécution via client
    exec_res = mcp_client.execute_tool("threat_intel", {"query": "evil-c2-domain.com", "indicator_type": "DOMAIN"})
    assert exec_res["status"] == "SUCCESS"
    assert exec_res["result"]["reputation"] == "MALICIOUS"
