"""SRE Incident Agent — исполнитель сниппетов в изолированной Docker-песочнице.

Containment-first (требование кейса Blast Radius Zero):
  • Process isolation: сниппет бежит в одноразовом контейнере; у него нет доступа
    ни к приложению, ни к хосту (docker.sock в песочницу не пробрасывается).
  • Secret hygiene: в контейнер попадает ТОЛЬКО файл сниппета и файл лога;
    VULTR_API_KEY и прочие секреты не передаются вовсе.
  • Resource limits: --memory / --cpus / --pids-limit + программный таймаут.
  • Lifecycle discipline: контейнер с --rm уничтожается после каждого запуска.
Дополнительно — статический фильтр запрещённых конструкций ДО запуска.
"""
import os
import re
import subprocess
import tempfile
import time

# Паттерны, которые не должны появляться в доверенном к исполнению сниппете.
FORBIDDEN = re.compile(
    r"\b(subprocess|os\.system|socket|urllib\.request|httpx|requests|ftplib|"
    r"smtplib|pickle|shutil\.(rmtree|unlink)|os\.(remove|unlink|rename)\b|"
    r"__import__|eval\(|exec\(|open\(.{0,40}\"/|/etc/|\\\\\.\\|\.ssh)",
    re.I,
)

CONTAINER_IMAGE = os.environ.get("SANDBOX_IMAGE", "python:3.12-alpine")
MEM_LIMIT = os.environ.get("SANDBOX_MEM", "256m")
CPU_LIMIT = os.environ.get("SANDBOX_CPUS", "1.0")
PIDS_LIMIT = "64"
TIME_LIMIT = float(os.environ.get("SANDBOX_TIMEOUT", 20))


class SandboxedViolation(ValueError):
    """Сниппет нарушает правила песочницы и не будет исполнен."""


def static_check(snippet: str) -> None:
    m = FORBIDDEN.search(snippet)
    if m:
        raise SandboxedViolation(
            f"forbidden construct in snippet: {m.group(0)!r} — refusing to run"
        )


def _run_local(snippet: str, log_text: str) -> dict:
    """DEV-режим: subprocess вместо контейнера (машина без Docker).

    Лог передаётся argv; изоляция эмулируется только static_check + таймаутом.
    Для Vultr-деплоя и сабмишна НЕ использовать (там всегда Docker-контур)."""
    with tempfile.TemporaryDirectory() as td:
        sp = td + "/snippet.py"
        with open(sp, "w", encoding="utf-8") as f:
            f.write("import sys\nlog = sys.argv[1]\n" + snippet)
        t0 = time.time()
        try:
            proc = subprocess.run(
                ["python", "-I", sp, log_text],
                capture_output=True, text=True, timeout=TIME_LIMIT,
            )
            out = (proc.stdout + ("\n[stderr]\n" + proc.stderr if proc.stderr.strip() else ""))
            return {"output": out.strip(), "exit_code": proc.returncode,
                    "duration_s": round(time.time() - t0, 2), "violated": False}
        except subprocess.TimeoutExpired:
            return {"output": f"[sandbox-emulated] таймаут {TIME_LIMIT}s",
                    "exit_code": 124, "duration_s": round(time.time() - t0, 2),
                    "violated": False}


def run(snippet: str, log_text: str) -> dict:
    """Запускает сниппет в одноразовом контейнере с логом в переменной `log`.

    SANDBOX_LOCAL=1 — dev-режим (эмуляция песочницы subprocess'ом на машине
    разработчика, где нет Docker); для Vultr-деплоя не использовать:
    без этой переменной песочница всегда Docker.
    Возвращает {"output": str, "exit_code": int, "duration_s": float,
                "violated": bool}. Любой исход — контейнер уничтожен."""
    static_check(snippet)
    if os.environ.get("SANDBOX_LOCAL") == "1":
        return _run_local(snippet, log_text)
    with tempfile.TemporaryDirectory() as td:
        task = td + "/task"
        os.makedirs(task)
        with open(task + "/snippet.py", "w", encoding="utf-8") as f:
            f.write("import sys\nlog = open('/task/log.txt', encoding='utf-8', "
                    "errors='replace').read()\n" + snippet)
        with open(task + "/log.txt", "w", encoding="utf-8") as f:
            f.write(log_text)
        t0 = time.time()
        try:
            proc = subprocess.run(
                [
                    "docker", "run", "--rm",
                    "--name", "sre-agent-sandbox-" + str(int(time.time())),
                    "--network", "none",
                    "--memory", MEM_LIMIT,
                    "--memory-swap", MEM_LIMIT,
                    "--cpus", CPU_LIMIT,
                    "--pids-limit", PIDS_LIMIT,
                    "--read-only",
                    "--tmpfs", "/tmp:rw,size=16m",
                    "-v", f"{task}:/task:ro",
                    "-w", "/task",
                    "-u", "65534:65534",          # nobody — не root
                    "--security-opt", "no-new-privileges",
                    CONTAINER_IMAGE,
                    "python", "/task/snippet.py",
                ],
                capture_output=True, text=True, timeout=TIME_LIMIT,
            )
            out = (proc.stdout + ("\n[stderr]\n" + proc.stderr if proc.stderr.strip() else ""))
            return {"output": out.strip(), "exit_code": proc.returncode,
                    "duration_s": round(time.time() - t0, 2), "violated": False}
        except subprocess.TimeoutExpired:
            return {"output": f"[sandbox] таймаут {TIME_LIMIT}s — исполнение принудительно остановлено",
                    "exit_code": 124,
                    "duration_s": round(time.time() - t0, 2), "violated": False}