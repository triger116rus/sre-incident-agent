"""Vultr Agent Rush — SRE Incident Agent. LLM-слой (Vultr Serverless Inference)."""
import os
import json
from typing import Any

# Base URL по умолчанию — Vultr Serverless Inference (требование хакатона).
# Для локальной разработки можно перекрыть LLM_BASE_URL на OpenAI-compatible
# заглушку; в сабмите на Vultr переменная остаётся дефолтной.
VULTR_INFERENCE_URL = "https://api.vultrinference.com/v1"


def llm_base_url() -> str:
    return os.environ.get("LLM_BASE_URL", VULTR_INFERENCE_URL)


def chat(messages: list[dict[str, str]], model: str | None = None,
         temperature: float = 0.2, response_json: bool = False) -> str:
    """OpenAI-compatible chat completion через Vultr Serverless Inference."""
    import urllib.request

    # 2026-11-03: llama-4-maverick в каталоге Vultr нет. Live-проверка на
    # continue-промпте (2/2 попыток, JSON-объект, finish=stop):
    # deepseek-v4.1-flash-1017 и mimo-v2.6-flash стабильны; qwen3.8-27b и
    # glm-5.3-flash флапают в reasoning-луп (content пуст, finish=length).
    model = model or os.environ.get("LLM_MODEL", "deepseek-v4.1-flash-1017")
    api_key = os.environ.get("VULTR_API_KEY", "")
    if "api.vultrinference.com" in llm_base_url() and not api_key:
        raise RuntimeError("VULTR_API_KEY не задан (окружение Vultr)")
    body: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        # reasoning-модели сжигают токены на размышление до выдачи JSON:
        # 1500 хватало шагу 1; 4000 — с запасом на сложные шаги
        "max_tokens": int(os.environ.get("LLM_MAX_TOKENS", 4000)),
    }
    if response_json:
        body["response_format"] = {"type": "json_object"}
    req = urllib.request.Request(
        f"{llm_base_url()}/chat/completions",
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        data=json.dumps(body).encode("utf-8"),
    )
    with urllib.request.urlopen(req, timeout=90) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    msg = data["choices"][0]["message"]
    # reasoning-модели (qwen3.8/glm/deepseek на Vultr) иногда отдают JSON в
    # reasoning-поле, оставляя content пустым — бери оба, контент приоритетен
    content = (msg.get("content") or "").strip()
    if not content:
        content = (msg.get("reasoning") or "").strip()
    if not content:
        raise RuntimeError("LLM вернул пустой ответ (content и reasoning пусты)")
    return content


def models() -> list[dict[str, Any]]:
    """Список доступных моделей (для выбора в UI/диагностики)."""
    import urllib.request

    req = urllib.request.Request(
        f"{llm_base_url()}/models",
        headers={"Authorization": f"Bearer {os.environ.get('VULTR_API_KEY', '')}"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8")).get("data", [])