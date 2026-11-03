# SRE Incident Agent — *Blast Radius Zero*

**Live demo:** https://209-250-254-114.sslip.io

Paste an infrastructure incident log. The agent plans a diagnostic step
(Vultr Serverless Inference), **executes it in an isolated Docker sandbox**,
reads the verified output, and repeats — then returns a triage report:
*Findings → Root-cause hypotheses → Recommendations*: with evidence straight
from the executed snippets, not hallucinated.

## The problem it solves

An on-call SRE facing a cryptic 500-line log needs 20–40 minutes of manual
grep/`stat`/correlate work to know what actually broke and what to do first.
This agent compresses that to **one paste — a structured triage report in
~60 seconds**, with every intermediate claim **verified by actually executed
code** rather than the LLM's imagination.

## Architecture (Pattern A: plan → sandboxed execution → verified analysis)

```
[Browser: static/index.html]                      (on Vultr VM)
        │ POST /api/incidents   POST /api/incidents/{id}/triage
        ▼
[FastAPI main.py] ── plan/analyze ──► [Vultr Serverless Inference]  (requirement C1)
        │ snippet
        ▼
[Docker sandbox (sandbox.py)]  — one-shot container per snippet:
   --network none, --memory 256m, --cpus 1, --pids-limit 64,
   --read-only, tmpfs 16m, -u 65534 (nobody), no-new-privileges, --rm
   input: ONLY the snippet + the log (read-only mount);
   no secrets, no host access, docker.sock not exposed
        │ verified output (stdout/exit code)
        ▼
[Agent loop, ≤5 steps] → findings / root-cause hypotheses / recommendations
   snippets violating the guard are shown as BLOCKED — containment is visible
```

## Containment — Blast Radius Zero by design

The LLM writes code that will be executed. That is the attack surface, and it
is closed in layers:

| Layer | Mechanism |
|---|---|
| Static guard | Regex blocklist *before* any execution: `subprocess`, `os.system`, `socket`, `urllib.request`, `eval/exec`, `/etc/...` → **BLOCKED** (exit −1, visible in UI/video) |
| Process isolation | Each snippet runs in a one-shot Docker container; it never runs in the app process; `docker.sock` is never exposed inside |
| Secret hygiene | The sandbox receives *only* the snippet and the incident log — `VULTR_API_KEY` and every other credential never enter the container's env |
| Resource limits | `--memory 256m` (+memory-swap), `--cpus 1`, `--pids-limit 64` — fork bombs and memory burnouts die inside the container |
| Time limit | Hard 20 s wall-clock per snippet (exit 124), enforced by the host |
| Network | `--network none` — the snippet cannot phone home |
| Filesystem | Root fs is `--read-only`, tmpfs 16 MB, log mounted read-only |
| Privileges | Runs as `nobody` (uid 65534) with `no-new-privileges` |
| Lifecycle | Container destroyed after every run (`--rm`) |

A snippet that tries any of the forbidden things is **blocked before it
runs** and displayed as `BLOCKED · contained` — judges can see containment
working, not just read about it.

## Vultr services used

- **Vultr Compute** — `vc2-1c-1gb`, Ubuntu 24.04 LTS, Amsterdam (the entire
  app: FastAPI + Docker sandbox + Caddy/TLS). Provisioned with
  `scripts/bootstrap_vm.sh`, deployed by `scripts/deploy_to_vm.ps1`.
- **Vultr Serverless Inference** — *all LLM calls* go through
  `https://api.vultrinference.com/v1` (OpenAI-compatible). Main model
  `deepseek-v4.1-flash-1017`; on a malformed/empty answer the loop retries
  the *whole step* on fallback model `mimo-v2.6-flash` (both verified live
  against the agent's JSON protocol; see `docs/2026-11-03-build-plan-v0.1.md`
  for the model-selection matrix).

## Agent protocol

The LLM answers **JSON only**:
`{"thought", "action": "execute"|"done", "snippet", "title", "findings",
"root_cause_hypotheses", "recommendations"}`.
`main.py` drives the cycle (≤5 steps); outputs are truncated and fed back as
"VERIFIED EXECUTION RESULTS", so the agent concludes on evidence. Malformed
LLM output triggers one fallback retry on another model; snippets are parsed
defensively (fenced JSON → balanced-brace scan → `ast.literal_eval` fallback
for single-quote dicts).

## Run it yourself

```bash
# on a Docker-capable host
export VULTR_API_KEY=...            # Vultr Serverless Inference key
pip install -r app/requirements.txt
python app/main.py                  # serves http://0.0.0.0:8080
# demo data: data/demo-*.log        # 3 anonymized synthetic incident logs
python scripts/bootstrap_vm.sh      # or: full VM provisioning (docker, venv, systemd, ufw)
```

*Development convenience only:* `SANDBOX_LOCAL=1` runs snippets via a plain
subprocess (no Docker); this mode is **never** used in the deployment or the
submission — the sandbox is always the Docker container path there.

## Demo data

`data/demo-1-array-drive-failure.log` — storage-array drive failure →
degraded VDISK → copyback failure at 62% → recovery.
`data/demo-2-service-oom-crash.log` — service OOM-kill loop: heap leak
(1,142,003 cache slots created / 214 freed) vs 4 GB cgroup limit.
`data/demo-3-hypervisor-ha-storm.log` — datastore latency spike → NIC flap →
host failure → HA restart storm with admission-control shortfall.

All three are **synthetic, anonymized** logs modelled on real-world patterns
storage/virtualization engineers meet daily.

---

Built for **Vultr Agent Rush** (lablab.ai), challenge *Blast Radius Zero* —
November 2026. Backend runs on Vultr Compute; all LLM traffic goes to Vultr
Serverless Inference.