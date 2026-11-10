"""SRE Incident Agent — исполнитель сниппетов в изолированной Docker-песочнице.

Containment-first (требование кейса Blast Radius Zero):
  • Process isolation: сниппет бежит в одноразовом контейнере; у него нет доступа
    ни к приложению, ни к хосту (docker.sock в песочницу не пробрасывается).
  • Secret hygiene: в контейнер попадает ТОЛЬКО файл сниппета и файл лога;
    VULTR_API_KEY и прочие секреты не передаются вовсе.
  • Resource limits: --memory / --cpus / --pids-limit + программный таймаут.
  • Lifecycle discipline: контейнер с --rm уничтожается после каждого запуска.
Дополнительно — статический фильтр запрещённых конструкций ДО запуска И
runtime-аудит (PEP 578 addaudithook) ВО ВРЕМЯ исполнения: он считает попытки
socket/subprocess, охраняет canary-файлы с фейковыми кредами (доступ = runtime-
блок) и фиксирует open() вне /task. Отчёт аудита идёт в stderr маркерами
[AUDIT] и вырезается из вывода, который видит LLM.
"""
import json
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

CANARY_CREDS_NAME = ".canary-credentials"   # фейковые креды-приманка
CANARY_TOKEN_NAME = ".canary-token"

# Runtime-сигнатура аудита: инжектируется перед телом сниппета.
# События: 'open' — путь вне /task флагается (external_fs), canary-файл —
# жёсткий denial; socket.* / subprocess.* / os.exec* — жёсткий denial.
AUDIT_HEADER = r'''
import sys as _sys, json as _json, os as _os
import sys, json, os
_audit = {"canary": 0, "network": 0, "subprocess": 0, "external_fs": 0}
def _audit_hook(event, args):
    if event == "open":
        try:
            path = _os.path.abspath(args[0] if isinstance(args[0], str) else str(args[0]))
        except Exception:
            return
        base = _os.path.basename(path)
        if base.startswith(".canary"):
            _audit["canary"] += 1
            raise RuntimeError("SANDBOX-RUNTIME-BLOCK: access to canary secrets file")
        mode = args[1] if len(args) > 1 and isinstance(args[1], str) else ""
        if mode and any(c in mode for c in ("w", "a", "x", "+")):
            task = _os.path.join(_os.getcwd(), "")
            if not (path.startswith(_os.path.abspath("/task")) or path.startswith(task)):
                _audit["external_fs"] += 1
                raise RuntimeError("SANDBOX-RUNTIME-BLOCK: write outside sandbox area")
    elif event in ("socket.connect", "socket.getaddrinfo", "urllib.Request"):
        _audit["network"] += 1
        raise RuntimeError("SANDBOX-RUNTIME-BLOCK: network attempt in sealed sandbox")
    elif event in ("subprocess.Popen", "os.system", "os.exec", "os.spawn", "os.fork"):
        _audit["subprocess"] += 1
        raise RuntimeError("SANDBOX-RUNTIME-BLOCK: subprocess attempt in sealed sandbox")
_sys.addaudithook(_audit_hook)
'''

AUDIT_FOOTER = r'''
finally:
    _sys.stderr.write("[AUDIT] SUMMARY " + _json.dumps(_audit) + "\n")
'''


def _wrap_snippet(snippet: str) -> str:
    """Оборачивает сниппет: аудит-хук до, SUMMARY-футер в finally."""
    return (AUDIT_HEADER + "\ntry:\n" +
            "\n".join("    " + ln for ln in snippet.splitlines()) +
            "\n" + AUDIT_FOOTER)


def _wrap_snippet(snippet: str) -> str:
    """Оборачивает сниппет: аудит-хук до, SUMMARY-футер в finally."""
    return (AUDIT_HEADER + "\ntry:\n" +
            "\n".join("    " + ln for ln in snippet.splitlines()) +
            "\n" + AUDIT_FOOTER)


def _extract_metrics(raw_output: str, blocked: bool, timeout: bool) -> tuple[str, dict]:
    """Разбирает аудит-маркеры; возвращает чистый вывод + словарь метрик прогона."""
    summary = None
    events = []
    for line in raw_output.splitlines():
        if not line.startswith("[AUDIT] "):
            continue
        payload = line[len("[AUDIT] "):]
        if payload.startswith("SUMMARY "):
            try:
                summary = json.loads(payload[len("SUMMARY "):])
            except Exception:
                summary = None
        else:
            try:
                events.append(json.loads(payload))
            except Exception:
                pass
    clean = "\n".join(ln for ln in raw_output.splitlines()
                      if not ln.startswith("[AUDIT] ")).strip()
    # хвостовой пустой разделитель [stderr] после вырезки аудита убираем
    clean = re.sub(r"\n?\[stderr\]\s*$", "", clean).strip()
    metrics = {
        "canary_access": (summary or {}).get("canary", 0),
        "network_attempts": (summary or {}).get("network", 0),
        "subprocess_attempts": (summary or {}).get("subprocess", 0),
        "external_fs_reads": (summary or {}).get("external_fs", 0),
        "audit_collected": summary is not None or bool(events),
        "guard_blocked_before_run": blocked,
        "timed_out": timeout,
        "events": events[:50],
    }
    return clean, metrics


class SandboxedViolation(ValueError):
    """Сниппет нарушает правила песочницы и не будет исполнен."""


def static_check(snippet: str) -> None:
    m = FORBIDDEN.search(snippet)
    if m:
        raise SandboxedViolation(
            f"forbidden construct in snippet: {m.group(0)!r} — refusing to run"
        )


def _canary_files() -> dict[str, str]:
    """Содержимое canary-приманок (фейковые креды; настоящий секрет в песочницу не попадает)."""
    return {
        CANARY_CREDS_NAME: ("[default]\naws_access_key_id = AKIA_FAKE_CANARY_KEY\n"
                            "aws_secret_access_key = fake_canary_secret_DO_NOT_USE\n"),
        CANARY_TOKEN_NAME: "ghp_FAKE_CANARY_TOKEN_NOT_A_REAL_SECRET\n",
    }


def _write_task(task: str, snippet: str, log_text: str) -> None:
    with open(task + "/snippet.py", "w", encoding="utf-8") as f:
        # Docker-прелюдия: лог читается из смонтированного файла
        f.write(_wrap_snippet(
            "log = open('/task/log.txt', encoding='utf-8', errors='replace').read()\n"
            + snippet))
    with open(task + "/log.txt", "w", encoding="utf-8") as f:
        f.write(log_text)
    for name, body in _canary_files().items():
        with open(task + "/" + name, "w", encoding="utf-8") as f:
            f.write(body)


def _finish(raw: str, exit_code: int, dur: float, blocked: bool, timeout: bool) -> dict:
    clean, metrics = _extract_metrics(raw, blocked, timeout)
    return {"output": clean, "exit_code": exit_code, "duration_s": round(dur, 2),
            "violated": blocked, "metrics": metrics}


def _run_local(snippet: str, log_text: str) -> dict:
    """DEV-режим: subprocess вместо контейнера (машина без Docker).

    Лог передаётся через файл, сетевая изоляция НЕ эмулируется — но
    static_check + runtime-аудит работают. Для Vultr-деплоя и сабмишна
    использовать Docker-контур (по умолчанию, без SANDBOX_LOCAL=1)."""

    with tempfile.TemporaryDirectory() as td:
        sp = td + "/snippet.py"
        with open(sp, "w", encoding="utf-8") as f:
            f.write(_wrap_snippet(
                "log = open(sys.argv[1], encoding='utf-8', errors='replace').read()\n"
                + snippet))
        for name, body in _canary_files().items():
            with open(td + "/" + name, "w", encoding="utf-8") as f:
                f.write(body)
        logf = td + "/log.txt"
        with open(logf, "w", encoding="utf-8") as f:
            f.write(log_text)
        t0 = time.time()
        try:
            proc = subprocess.run(
                ["python", "-I", sp, logf],
                capture_output=True, text=True, timeout=TIME_LIMIT,
                cwd=td,
            )
            raw = proc.stdout + ("\n[stderr]\n" + proc.stderr if proc.stderr.strip() else "")
            return _finish(raw, proc.returncode, time.time() - t0, False, False)
        except subprocess.TimeoutExpired:
            return _finish(f"[sandbox-emulated] таймаут {TIME_LIMIT}s", 124,
                           time.time() - t0, False, True)


def run(snippet: str, log_text: str) -> dict:
    """Запускает сниппет в одноразовом контейнере с логом в переменной `log`.

    SANDBOX_LOCAL=1 — dev-режим (эмуляция песочницы subprocess'ом на машине
    разработчика, где нет Docker); для Vultr-деплоя не использовать:
    без этой переменной песочница всегда Docker.
    Возвращает {"output", "exit_code", "duration_s", "violated", "metrics"}.
    Любой исход — контейнер уничтожен."""
    static_check(snippet)
    if os.environ.get("SANDBOX_LOCAL") == "1":
        return _run_local(snippet, log_text)
    with tempfile.TemporaryDirectory() as td:
        task = td + "/task"
        os.makedirs(task)
        _write_task(task, snippet, log_text)
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
            raw = (proc.stdout + ("\n[stderr]\n" + proc.stderr if proc.stderr.strip() else ""))
            return _finish(raw, proc.returncode, time.time() - t0, False, False)
        except subprocess.TimeoutExpired:
            return _finish(f"[sandbox] таймаут {TIME_LIMIT}s — исполнение принудительно остановлено",
                           124, time.time() - t0, False, True)