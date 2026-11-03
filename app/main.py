"""SRE Incident Agent — веб-приложение (FastAPI), деплой на Vultr VM."""
import os
import time

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

import agent
import sandbox
from llm import llm_base_url

app = FastAPI(title="SRE Incident Agent", docs_url=None, redoc_url=None)

# Демо-стейт в памяти (MVP для хакатона; в prod — SQLite/БД).
INCIDENTS: dict[str, dict] = {}
MAX_STEPS = 5


@app.post("/api/incidents")
async def create_incident(req: Request):
    body = await req.json()
    text = (body.get("text") or "").strip()
    if not text:
        raise HTTPException(400, "text обязателен")
    inc_id = str(int(time.time() * 1000))
    INCIDENTS[inc_id] = {"text": text, "steps": [], "status": "created",
                         "created": time.strftime("%Y-%m-%d %H:%M:%S")}
    return {"id": inc_id}


@app.post("/api/incidents/{inc_id}/triage")
async def triage(inc_id: str):
    inc = INCIDENTS.get(inc_id)
    if not inc:
        raise HTTPException(404, "инцидент не найден")
    steps = inc["steps"]
    try:
        while len(steps) < MAX_STEPS:
            if not steps:
                msg = agent.plan_first(inc["text"])
            else:
                msg = agent.continue_triage(inc["text"], steps)
            if msg.get("action") == "done":
                inc["status"] = "done"
                inc["report"] = {
                    "findings": msg.get("findings", []),
                    "root_cause_hypotheses": msg.get("root_cause_hypotheses", []),
                    "recommendations": msg.get("recommendations", []),
                }
                return {"status": "done", "report": inc["report"], "steps": steps}
            result = sandbox.run(msg.get("snippet", ""), inc["text"])
            steps.append({"title": msg.get("title", "step %d" % (len(steps) + 1)),
                          "snippet": msg.get("snippet", ""),
                          "output": result["output"], "exit_code": result["exit_code"],
                          "duration_s": result["duration_s"],
                          "violated": result["violated"]})
        inc["status"] = "steps-exhausted"
    except sandbox.SandboxedViolation as e:
        steps.append({"title": "BLOCKED", "snippet": "", "output": str(e),
                      "exit_code": -1, "duration_s": 0.0, "violated": True})
        # violation не завершает инцидент — агент продолжает уже без него
    except Exception as e:  # noqa: BLE001
        inc["status"] = "error"
        return {"status": "error", "error": str(e), "steps": steps}
    return {"status": inc["status"], "steps": steps}


@app.get("/api/incidents/{inc_id}")
async def get_incident(inc_id: str):
    inc = INCIDENTS.get(inc_id)
    if not inc:
        raise HTTPException(404, "инцидент не найден")
    return dict(inc)


@app.get("/api/health")
async def health():
    return {"ok": llm_base_url(), "sandbox_image": sandbox.CONTAINER_IMAGE}


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    p = os.path.join(os.path.dirname(__file__), "static", "index.html")
    with open(p, encoding="utf-8") as f:
        return f.read()


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))