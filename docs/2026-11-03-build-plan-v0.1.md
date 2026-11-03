# Build plan — SRE Incident Agent (Vultr Agent Rush) — v0.1 (2026-11-03)

## Архитектура

```
[Browser: static/index.html]                      (на Vultr VM)
        │ POST /api/incidents  POST /api/incidents/{id}/triage
        ▼
[FastAPI main.py] ── план/анализ ──► [Vultr Serverless Inference]   (требование C1)
        │ сниппет
        ▼
[Docker sandbox (sandbox.py)]  ← одноразовый контейнер:
   --network none, --memory 256m, --cpus 1, --pids-limit 64,
   --read-only, tmpfs 16m, -u 65534, no-new-privileges, --rm
   вход: только сниппет + лог (ro-маунт); секретов нет; хост и docker.sock недоступны
        │ верифицированный вывод (stdout/exit)
        ▼
[Agent loop ≤5 шагов] → findings / root-cause hypotheses / recommendations
   блокированные сниппеты показываются как BLOCKED (containment-момент для демо)
```

Модули: `app/llm.py` (OpenAI-compatible, base URL Vultr; ключ из env),
`app/agent.py` (system-prompt SRE, JSON-протокол, ретраи по stderr),
`app/sandbox.py` (static guard + docker run + таймаут; dev-флаг SANDBOX_LOCAL
только для локальной отладки), `app/main.py` (FastAPI), `app/static/index.html`.

## Что показываем судьям

1. Реальный цикл: лог → план → **исполняется** → вывод читает агент (Pattern A).
2. Containment-момент в видео: сниппет с `subprocess`/`socket` → **BLOCKED**,
   и/или таймаут-контейнер убит (exit 124), и/или сниппет не видит ключи.
3. Бизнес-кейс: MTTR инженера поддержки (триаж инцидентов СХД/вмгиврации) — 18 лет
   доменной экспертизы владельца (Business Value, оригинальность).

## Тайминги (дедлайн 09.11 00:00 CET ≈ 02:00 МСК 09.11)

- **03.11 (сегодня)**: скелет кода ✅; user: кредиты + Vultr VM (Ubuntu 22.04,
  Docker) при получении ключа → деплой через SSH; проверка /v1/models.
- **04.11**: агентный цикл end-to-end (Vultr LLM) на семпл-логах; демо-датасет
  (3 обезличенных лога: crash-куча, ленточник, гипервизор).
- **05–06.11**: деплой на Vultr VM (systemd + nginx TLS), полировка UI,
  стабилизация ретраев/лимитов.
- **07.11**: DEMO-ВИДЕО (экранозапись 3–4 мин, сценарий в этом доке ниже),
  README (арки, Vultr services, containment), форма lablab.
- **08.11**: буфер. Сабмит до дедлайна, не в последний час.

## Открытые вопросы

- Модели на Vultr Serverless Inference — сверить /v1/models после ключа
  (дефолт llama-4-maverick-17b-128e-instruct-fp8 может отличаться).
- Домен/TLS для demo URL: подойдёт http на IP? — по требованиям «Public demo URL»
  — HTTPS через самоподписанный нельзя показывать браузером с предупреждением;
  кандидат: vps.testlab.local-туннель? Лучше просто HTTP на Vultr-IP (допустимо)
  или бесплатный sslip.io + Caddy. Решить при деплое.