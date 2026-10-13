import json
from llm.nebius import LLMClient
from llm.router import LLMRouter


def test_llm_client_fallback_mode():
    ### Test du mode de repli déterministe (sans clé API)
    client = LLMClient(api_key="", base_url="https://api.rhodium.ai/v1")

    # 1. Plan prompt
    plan_out = client.generate("plan next action for evidence Security.evtx")
    plan_json = json.loads(plan_out)
    assert plan_json["action"] == "EXECUTE_TOOL"
    assert plan_json["tool_name"] == "evtx_analyzer"

    # 2. Solve prompt
    solve_out = client.generate("solve hypothesis for incident")
    solve_json = json.loads(solve_out)
    assert "title" in solve_json
    assert "description" in solve_json
    assert solve_json["confidence"] > 0.5

    # 3. Verify prompt
    verify_out = client.generate("verify hypothesis against evidence")
    verify_json = json.loads(verify_out)
    assert verify_json["decision"] == "VALIDATED"
    assert verify_json["confidence"] >= 0.8


def test_llm_router():
    ### Test du routeur de modèles (Fast vs Deep)
    router = LLMRouter()
    plan_res = router.plan("plan action for binary.exe")
    assert "EXECUTE_TOOL" in plan_res

    solve_res = router.solve("solve hypothesis")
    assert "title" in solve_res

    verify_res = router.verify("verify hypothesis")
    assert "VALIDATED" in verify_res
