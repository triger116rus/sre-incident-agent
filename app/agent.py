"""SRE Incident Agent — планирование триажа и генерация диагностических сниппетов.

Контур агентного цикла:
  1. PLAN:   LLM получает алерт/лог и строит план диагностики (JSON).
  2. EXECUTE: сниппет шага исполняется в изолированной песочнице (sandbox.py),
             верифицированный вывод (stdout/exit code) — результат шага.
  3. ANALYZE: LLM смотрит на реальный вывод и решает — уточнить план,
             перейти к следующему шагу или выдать финальный триаж-отчёт.
Ошибки исполнения скармливаются обратно (retry, максимум RE_STEPS шагов).
"""
import json
import re

from llm import chat

SYSTEM = """You are an experienced Site Reliability Engineer (SRE) performing
incident triage for infrastructure systems (storage arrays, hypervisors, servers).
You analyze an alert/log snippet by writing SMALL python diagnostic snippets that
are executed in an isolated sandbox by the host application.

Rules:
- Snippets get the incident log text in the variable `log` (str).
- Snippets must not access network, filesystem elsewhere, subprocess, or secrets.
- Keep each snippet under 40 lines, deterministic, printing concise findings.
- Think in steps: characterize -> count/aggregate -> correlate -> conclude.

Mandatory protocol:
- Your FIRST response MUST be action=execute (never "done" on the first step):
  start by characterizing the log with a counting/aggregate snippet, even if
  the cause looks obvious. The host executes your snippet and returns the
  VERIFIED output; you conclude ONLY on verified evidence in later steps.

Respond ONLY with a JSON object:
{"thought": "<one line reasoning>", "action": "execute" | "done",
 "snippet": "<python code>" (when action=execute),
 "title": "<short current goal>" (when action=execute),
 "findings": ["..."], "root_cause_hypotheses": ["..."],
 "recommendations": ["<ordered actions for the operator>"]}
"""

def _parse_llm_json(text: str) -> dict:
    """Вытаскивает JSON-объект из ответа LLM (fence / сбалансированные скобки /
    python-dict с одинарными кавычками)."""
    # 1) ```json-фенс — самый надёжный контейнер
    fence = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.S)
    if fence:
        t = fence.group(1).strip()
        try:
            return json.loads(t)
        except json.JSONDecodeError:
            pass
        try:
            import ast
            v = ast.literal_eval(t)
            if isinstance(v, dict):
                return v
        except Exception:
            pass
    # 2) сбалансированный по скобкам скан от первой '{'
    start = text.find("{")
    if start >= 0:
        depth = 0
        in_str = False
        esc = False
        for i, ch in enumerate(text[start:], start):
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    t = text[start:i + 1]
                    try:
                        return json.loads(t)
                    except json.JSONDecodeError:
                        try:
                            import ast
                            v = ast.literal_eval(t)
                            if isinstance(v, dict):
                                return v
                        except Exception:
                            break
                    break
    raise ValueError("LLM ответ без JSON-объекта")


def _chat_json(messages: list[dict[str, str]]) -> dict:
    """chat() с разбором JSON; ретрай на ФОЛЛБЭК-модели (не повторять ту же
    reasoning-модель — она может лупить так же)."""
    import os
    fb = os.environ.get("LLM_FALLBACK_MODEL", "mimo-v2.6-flash")
    try:
        return _parse_llm_json(chat(messages, response_json=True))
    except (ValueError, RuntimeError, json.JSONDecodeError) as e:
        first = repr(e)[:120]
    try:
        return _parse_llm_json(chat(messages, response_json=True, model=fb))
    except (ValueError, RuntimeError, json.JSONDecodeError):
        raise RuntimeError(f"оба вызова LLM без валидного JSON (primary: {first})")


def plan_first(incident_text: str) -> dict:
    """Первый шаг: план в JSON-ответе агента (execute или сразу done)."""
    return _chat_json([
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": f"ALERT / LOG:\n```\n{incident_text}\n```"},
    ])


def continue_triage(incident_text: str, history: list[dict]) -> dict:
    """Шаг с историей исполнения. history — [{title, output, exit_code, snippets?}]."""
    lines = []
    for h in history:
        lines.append(f"== STEP: {h['title']} (exit {h['exit_code']}) ==")
        out = (h.get("output") or "").strip()
        lines.append(out[-4000:] if len(out) > 4000 else out or "(no output)")
    return _chat_json([
        {"role": "system", "content": SYSTEM},
        {
            "role": "user",
            "content": (
                f"ALERT / LOG:\n```\n{incident_text}\n```\n\n"
                "VERIFIED EXECUTION RESULTS so far:\n" + "\n".join(lines)
            ),
        },
    ])


def finalize(incident_text: str, history: list[dict]) -> dict:
    """Финальный отчёт триажа из накопленной истории."""
    msg = continue_triage(incident_text, history)
    if msg.get("action") != "done":
        msg["action"] = "done"
    return msg