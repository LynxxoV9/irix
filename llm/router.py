from typing import Optional
from llm.nebius import llm_client


class LLMRouter:
    ### Routeur de modèles selon la stratégie à deux niveaux du CDC (Section 3.4)
    ### - Fast Tier : Tâches courtes (planification d'outils, extraction, synthèses rapides)
    ### - Deep Tier : Raisonnement complexe (corrélation d'hypothèses, vérification contradictoire, rapport)
    def __init__(self, client=None):
        self.client = client or llm_client

    def plan(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        ### Planification via le modèle rapide (Fast)
        return self.client.generate(prompt=prompt, system_prompt=system_prompt, model_tier="fast")

    def solve(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        ### Synthèse et corrélation via le modèle profond (Deep)
        return self.client.generate(prompt=prompt, system_prompt=system_prompt, model_tier="deep")

    def verify(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        ### Confrontation d'hypothèses aux faits observés via le modèle profond (Deep)
        return self.client.generate(prompt=prompt, system_prompt=system_prompt, model_tier="deep")


llm_router = LLMRouter()
