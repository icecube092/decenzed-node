# План: TLS-маскировка под собственный сайт с Let's Encrypt

Статус: **реализовано** (все 8 милстоунов, см. §13). Node-wide тумблер `Camouflage`.

Реализация:
- `internal/duckdns` — `SetTXT`/`ClearTXT` (DNS-01).
- `internal/acme` — менеджер серта LE на `x/crypto/acme`, DNS-01, renewBefore 30д,
  per-env account key, атомарная запись. **Окружение staging/prod фиксируется на
  сборке** (`StagingBuild`, build-tag `staging`), не в конфиге. Регистрация в LE
  требует явного согласия оператора (`Params.AgreeTOS`).
- Файлы серта (`cert.pem`/`key.pem`/`account.key`/`cert.pem.env`) лежат в
  **`decenzed-data`** (тот же каталог, что `config.json`/`xray.json`).
- Тестовая сборка: `make build-test` / `make build-test-win` (или
  `go build -tags staging`).
- `internal/site` — встроенный decoy-сайт (`//go:embed`), TCP или Unix-сокет.
- `internal/xraygen` — `TLSSpec` + `fallbacks` для VLESS/Trojan, файловые серты
  без `oneTimeLoading`.
- `internal/config` — `Camouflage`, TLS-поля, `CamouflageTLS/TLSHost/SiteAddr/IsConfigured`.
- `internal/commands` — провижининг+renewal в `runNode`, ветка `setup` (пропуск
  скана в TLS), TLS-ссылки и sing-box в `link`, gate `IsConfigured`.

Тесты зелёные, `go vet` чист, кросс-компиляция под OpenWRT (arm64/mipsle) ок,
размер бинаря без изменений.

## Цель

Научить `decenzed-node` (единый Go-бинарник с встроенным xray-core) в качестве
альтернативы REALITY:

1. Поднимать **свой сайт** (встроенный статик-сервер на localhost).
2. Автоматически получать и продлевать **сертификаты Let's Encrypt**.
3. Маскировать VLESS и Trojan через **TLS + `fallbacks` на этот сайт** — так что
   снаружи это один домен на 443 с настоящим сертификатом, а активное
   зондирование/браузер видят реальный сайт.

Всё — по-прежнему **один бинарник**, без внешних зависимостей рантайма
(nginx/certbot не нужны).

## 0. Текущая архитектура (точки интеграции)

- `internal/config/config.go` — `AppConfig`, единственный источник высокоуровневой
  политики; xray-JSON выводится из него.
- `internal/xraygen/xraygen.go` — единственное место, где `AppConfig` → xray-JSON.
  Сейчас `streamSettings` умеет только `security=reality`. REALITY-параметры
  **шарятся** одним `RealitySpec` между VLESS и Trojan.
- `internal/commands/node.go` — `runNode`: старт xray (`xrayrt`), throttle-прокси в
  горутинах, тикер обслуживания (DuckDNS, stats). `inputFromConfig` собирает
  `xraygen.Input`.
- `internal/xrayrt/xray.go` — встроенный xray; `Start(json)` c restart-семантикой.
- `internal/duckdns/duckdns.go` — обновление A-записи DuckDNS. Домен узла:
  `AppConfig.DuckDNSHost()` = `<sub>.duckdns.org`.
- `internal/commands/link.go` — генерация share-ссылок.
- `internal/throttle` — прокси, фронтит публичный порт; xray при включённом
  троттлинге слушает `127.0.0.1:<innerPort>`.
- `golang.org/x/crypto` уже в графе зависимостей → **`golang.org/x/crypto/acme`
  доступен без новых тяжёлых зависимостей** (важно для OpenWRT — лимит по флешу).

## 1. Поток трафика (TLS-режим)

```
                 :443 (публичный)
клиент ──TLS(SNI=<sub>.duckdns.org)──► xray VLESS+TLS+Vision  (или Trojan+TLS)
                                          │  (сертификат LE, свой домен)
                    ┌─────────────────────┼─────────────────────┐
              валидный VLESS/Trojan   обычный HTTPS (браузер/зонд, плохой пароль)
                    │                      │ fallback dest
                    ▼                      ▼
              выход в интернет      127.0.0.1:<siteport>
                                    встроенный HTTP-сервер приложения (свой сайт)
```

TLS терминирует **xray**, не приложение. При троттлинге сохраняется схема
`throttle :443 → xray 127.0.0.1:<inner>`; сайт живёт на своём localhost-порту и в
троттлинге не участвует.

## 2. Ключевые решения

| Вопрос | Решение | Обоснование |
|---|---|---|
| ACME-клиент | Свой тонкий на `x/crypto/acme` | уже в зависимостях; lego тянет десятки DNS-провайдеров → раздувает бинарь (критично для OpenWRT) |
| Challenge | **DNS-01** через `internal/duckdns` | не требует открытого порта 80/443 (CGNAT, 443 занят xray → TLS-ALPN-01 невозможен); DuckDNS API уже есть |
| Кто терминирует TLS | **xray** (VLESS+TLS+Vision / Trojan+TLS + `fallbacks`) | это и есть корректный «fallback на свой сайт» |
| Домен сертификата | `DuckDNSHost()` = `<sub>.duckdns.org` | настоящий домен, DNS-01 выдаёт на него |
| Хранение серта | файлы `cert.pem`/`key.pem` (0600) в конфиг-каталоге; xray читает как `certificateFile`/`keyFile` (НЕ инлайн, `oneTimeLoading` НЕ ставить) | xray **горячо перечитывает файлы раз в час** (проверено в `setupOcspTicker`) → продление без рестарта и без обрыва соединений |
| Сайт | статика, вшитая `//go:embed`, `net/http` на `127.0.0.1:<siteport>` | один бинарник |
| Тумблер режима | **node-wide `Camouflage` ("reality" \| "tls")**, управляет VLESS **и** Trojan вместе | REALITY уже шарится между ними; per-inbound усложнил бы config/setup без пользы |
| Shadowsocks | **не затрагивается** | TLS-слоя у SS нет — к сайту не подключить; остаётся отдельным менее скрытным типом |

Открытые точки (решить до/по ходу реализации, дефолты предложены):
- **Политика при сбое ACME**: дефолт — не стартовать TLS-инбаунды с понятной
  ошибкой (не тихий откат на REALITY, чтобы оператор не думал, что он в TLS-режиме,
  будучи в reality). Обсуждаемо.
- **Контент сайта**: дефолт — один вшитый скромный правдоподобный шаблон; опционально
  `--site-dir` для подмены каталогом оператора (можно во второй итерации).

## 2a. Сверка с официальной документацией xray (проверено)

Подход подтверждён официальной докой и каноническим примером `XTLS/Xray-examples`:

- **VLESS-TCP-XTLS-Vision — правильный HTTPS-энтрипоинт на 443**: терминирует TLS,
  затем `fallbacks` разводят трафик. Наш план ровно такой.
- **`fallbacks` работают ТОЛЬКО с TCP+TLS.** Если у `fallbacks` есть дочерние
  элементы, TLS-инбаунд **обязан** задать `alpn`: для сайта на http/1.1 —
  `"alpn":["http/1.1"]` (для h2 — `["h2","http/1.1"]`). У нас сайт http/1.1 → берём
  `["http/1.1"]` (уже в §7).
- **Дефолтный fallback** — элемент с пустыми/опущенными `path` и `alpn`; ловит весь
  несопоставленный трафик. Наш единственный `{ "dest": "127.0.0.1:8080" }` без
  `path`/`alpn` — это и есть корректный catch-all.
- **Форматы `dest`**: `"addr:port"`, только-порт (→ localhost) **или Unix-сокет**
  (`"/dev/shm/xxx.sock"`, абстрактный через `@`). См. уточнение ниже.
- **Trojan полностью поддерживает fallback.** Канонический all-in-one цепляет
  VLESS→Trojan→nginx на одном порту. Мы намеренно проще: **каждый протокол на своём
  порту**, у каждого — свой fallback на общий сайт. SNI/ALPN-цепочки нам не нужны.
- **Критерии «правильной» Vision-настройки** (из доки): порт 443; блок CN через
  routing; НЕ смешивать со стандартным TLS/другими прокси на одном порту; fallback
  на **настоящий сайт, а не на другой прокси**; клиент обязан слать **браузерный
  fingerprint** (`fp=chrome` — уже в §10). Один-протокол-на-порт у нас соблюдён.

**Уточнение 1 — Unix-сокет для сайта (Linux).** В каноническом примере decoy-сервер
слушает Unix-сокеты (`/dev/shm/*.sock`), а не TCP. Это чуть скрытнее и убирает
localhost-порт. План: **дефолт — TCP `127.0.0.1:<siteport>`** (портируемо, совпадает
с моделью throttle, работает и на Windows-деве); на Linux/OpenWRT — опционально
`dest` в Unix-сокет (`/dev/shm/decenzed-site.sock`), `internal/site` умеет и то, и
другое. `FallbackDest` в `TLSSpec` тогда — либо `addr:port`, либо путь к сокету.

**Уточнение 2 — сайт должен быть правдоподобным.** Дока прямо требует fallback на
реальный сайт, а не заглушку. Усиливает требование §8: вшитый контент — не «It works»,
а осмысленная страница; предусмотреть `--site-dir` для подмены (2-я итерация).

## 3. Протоколы и режим маскировки

| Протокол | REALITY-режим (сейчас) | TLS-режим |
|---|---|---|
| **VLESS** | REALITY + Vision | TLS + **Vision** + `fallbacks` → сайт |
| **Trojan** | REALITY «плоский» (Vision — только VLESS) | TLS + `fallbacks` → сайт |
| **Shadowsocks** | SS-2022, без маскировки | **без изменений** |

`Camouflage` переключает VLESS и Trojan одновременно. Один сертификат и один
`serverName` на оба; один локальный сайт обслуживает fallback обоих инбаундов.

## 4. Изменения в `AppConfig` (config.go)

```go
// Camouflage управляет ОБОИМИ REALITY-совместимыми протоколами (VLESS, Trojan).
// "reality" (по умолчанию) | "tls". Shadowsocks не затрагивается.
Camouflage string `json:"camouflage,omitempty"`

// TLS-режим: свой сайт + Let's Encrypt (DNS-01 через DuckDNS).
TLSDomain   string `json:"tls_domain,omitempty"`   // = DuckDNSHost(), если пусто
ACMEEmail   string `json:"acme_email,omitempty"`   // контакт для LE (опционально)
ACMEStaging bool   `json:"acme_staging,omitempty"` // тестовый CA LE (для отладки)
SitePort    int    `json:"site_port,omitempty"`    // localhost-порт сайта, default 8080
```

Предусловия режима `tls` (валидация в `setup`): заданы `DuckDNSToken` +
`DuckDNSSubdomain` (нужны и для DNS-01, и как cert-домен). Хелпер
`AppConfig.CamouflageTLS() bool` для читаемости веток.

## 5. `internal/duckdns` — TXT для DNS-01

Добавить к существующему пакету:

```go
// SetTXT ставит TXT-запись _acme-challenge.<sub>.duckdns.org = value.
func SetTXT(ctx context.Context, sub, token, value string) error   // &txt=<value>
// ClearTXT очищает её.
func ClearTXT(ctx context.Context, sub, token string) error        // &txt=&clear=true
```

Тот же endpoint и стиль, что `Update`; ответ DuckDNS — `OK`. Тесты — подменой
`endpoint`, как в существующем `duckdns_test.go`.

## 6. Новый пакет `internal/acme` (certmgr)

Тонкий менеджер поверх `x/crypto/acme`. **Один серт на весь узел** (один домен),
не по инбаунду.

```go
// EnsureCert выдаёт/продлевает серт для domain и возвращает пути к файлам.
func EnsureCert(ctx context.Context, p Params) (certPath, keyPath string, err error)

type Params struct {
    Domain   string
    Email    string
    Staging  bool
    Dir      string   // конфиг-каталог: account.key, cert.pem, key.pem
    SetTXT   func(ctx context.Context, value string) error
    ClearTXT func(ctx context.Context) error
}
```

Логика:
1. Загрузить/сгенерировать `account.key` (registered account).
2. Если `cert.pem` валиден и до истечения **>30 дней** — вернуть пути, ничего не делая.
3. Иначе ACME-ордер: `AuthorizeOrder` → взять `dns-01` → `client.DNS01ChallengeRecord(token)`
   → `SetTXT(value)` → дождаться propagation (poll DNS `_acme-challenge...`, с таймаутом)
   → `Accept` → `WaitOrder` → CSR (ключ → `key.pem`) → `CreateOrderCert` → `cert.pem`.
4. `defer ClearTXT()`.

Файлы — 0600, атомарная запись (как `config.Save`). Тесты — против pebble
(тест-ACME-сервер) или замоканного endpoint; DNS-01 — с моками SetTXT/ClearTXT.

## 7. Изменения в `xraygen`

Расширить схему инбаунда TLS + fallbacks:

```go
type InboundSpec struct {
    ...
    Reality *RealitySpec // security=reality (взаимоисключимо с TLS)
    TLS     *TLSSpec     // security=tls
}
type TLSSpec struct {
    ServerName   string
    CertFile     string
    KeyFile      string
    FallbackDest string // "127.0.0.1:8080"
}
```

В `buildInbound` при `TLS != nil`:

```json
"streamSettings": {
  "network": "tcp",
  "security": "tls",
  "tlsSettings": {
    "serverName": "<sub>.duckdns.org",
    "alpn": ["http/1.1"],
    "certificates": [{ "certificateFile": ".../cert.pem", "keyFile": ".../key.pem" }]
  }
}
```

> Обязательно **файловые** `certificateFile`/`keyFile` (не инлайн `certificate`/`key`)
> и **без** `oneTimeLoading: true` — иначе не сработает горячее перечитывание серта
> при продлении (§9, шаг 3).

В `buildSettings`:
- VLESS+TLS: `clients[].flow = xtls-rprx-vision` (как сейчас) **+**
  `"fallbacks": [{ "dest": "127.0.0.1:8080" }]`.
- Trojan+TLS: клиенты по паролю (как сейчас, без flow) **+** те же `fallbacks`.
- Shadowsocks: ветка не трогается (ни TLS, ни fallbacks).

`fallbacks` требуют `network: tcp`. Golden-JSON тест для TLS+fallbacks (по аналогии
с существующим reality-тестом).

## 8. Новый пакет `internal/site`

- `//go:embed site/*` — скромный правдоподобный статик-контент (НЕ дефолтная
  страница — иначе палево). Держать маленьким (идёт в бинарь → OpenWRT).
- `Serve(ctx, addr) error` — `http.Server` c `http.FileServer` на
  `127.0.0.1:<siteport>`, graceful shutdown по ctx.
- (Опц., 2-я итерация) `--site-dir` для подмены каталогом оператора.

## 9. Проводка в рантайме (`node.go`)

В `inputFromConfig` — выбор per-protocol внутри общего режима; `tlsSpec` собирается
один раз (как `reality`), с `FallbackDest = "127.0.0.1:<siteport>"`, путями к серту,
`ServerName = domain`:

```go
switch ib.Protocol {
case config.ProtoVLESS:
    if c.CamouflageTLS() { spec.TLS = tlsSpec } else { spec.Reality = reality }
    // clients с Vision-flow — как сейчас
case config.ProtoTrojan:
    if c.CamouflageTLS() { spec.TLS = tlsSpec } else { spec.Reality = reality }
    // clients по паролю — как сейчас
case config.ProtoShadowsocks:
    // без изменений
}
```

В `runNode`, до старта xray, при `CamouflageTLS()`:
1. `certmgr.EnsureCert(...)` (с таймаутом; при ошибке — по политике из §2).
2. `go site.Serve(ctx, "127.0.0.1:<siteport>")` (как throttle-горутины).
3. **Renewal** (проверено по исходникам xray):
   - `certmgr.EnsureCert` идемпотентен: продлевает только при **<30 дней** до
     истечения. Вызывать раз в сутки из тикера обслуживания.
   - Подхват нового серта в xray — **горячий, без рестарта**: с `certificateFile`/
     `keyFile` и без `oneTimeLoading` xray-core (`transport/internet/tls`,
     `setupOcspTicker`) перечитывает файлы **раз в час** и подменяет серт в памяти;
     активные соединения не рвутся. Мы просто атомарно перезаписываем `cert.pem`/
     `key.pem` — регенерация конфига и `rt.Start` для продления НЕ нужны.
   - `rt.Start` (рестарт) остаётся только для смены режима `reality↔tls`
     (меняется структура конфига) и добавления/удаления клиентов, как сейчас.

## 9a. Setup: скан доменов НЕ выполняется в TLS-режиме

`internal/commands/setup.go::chooseRealityDomain` сканирует `/24`-соседей и сид-лист
в поисках живого TLS1.3+h2 сайта, чтобы «одолжить» его как REALITY `dest`/`serverName`
(`realityscan.Scan/Probe/Hosts24`). **В TLS-режиме это лишнее и вредное**: мы
маскируемся под собственный домен, чужой сайт для подмены не нужен, `dest` отсутствует
как понятие.

Изменения в `setup`:
- Ветвление по `Camouflage`:
  - `reality` → как сейчас: `chooseRealityDomain` (скан) + генерация REALITY-ключей.
  - `tls` → **скан пропускается полностью**. Вместо него:
    - `serverName` = **собственный домен** (`DuckDNSHost()` / `TLSDomain`);
    - проверка предусловий (`DuckDNSToken`+`DuckDNSSubdomain` заданы);
    - прогон `certmgr.EnsureCert` со **staging LE** (проверка, что DNS-01 через
      DuckDNS реально отрабатывает), затем боевой CA.
- `RealityDest`/`RealityServerName`/ключи в TLS-режиме не заполняются (пустые), их
  наличие больше не является индикатором «узел настроен» — предусловие старта
  (`cmdStart`: `c.RealityPublicKey == ""`) переписать на «настроен для выбранного
  режима»: reality → есть REALITY-ключи; tls → есть домен + валидный серт.
- Вывод статуса (`node.go`/`stats`): в TLS-режиме печатать «TLS site: <domain>»
  вместо «REALITY domain: …».

Пакет `internal/realityscan` остаётся — он нужен REALITY-режиму; просто не
вызывается при `Camouflage=tls`.

## 10. Share-ссылки (`link.go`)

- VLESS+TLS: `security=tls&sni=<domain>&flow=xtls-rprx-vision&fp=chrome&type=tcp`
  (без `pbk`/`sid`).
- Trojan+TLS: `security=tls&sni=<domain>&type=tcp` (без flow).
- Shadowsocks: **без изменений**.

## 11. Ограничения OpenWRT

- Никакого lego — только `x/crypto/acme` (уже есть) → минимальный прирост бинаря.
- Статик-сайт держать маленьким.
- `account.key`/`cert.pem`/`key.pem` пишутся в конфиг-каталог — убедиться, что
  раздел writable.
- Проверить cross-compile и итоговый размер на тест-VM (см.
  `memory/openwrt-deployment.md`).

## 12. Тесты

- `duckdns`: SetTXT/ClearTXT — подмена `endpoint`.
- `xraygen`: golden-JSON для VLESS+TLS+fallbacks и Trojan+TLS+fallbacks.
- `certmgr`: против pebble или мока; DNS-01 с моками SetTXT/ClearTXT.
- e2e (ручной): реальный DuckDNS-домен, **staging LE**, `curl https://<domain>`
  отдаёт сайт; VLESS- и Trojan-клиенты подключаются; SS работает как прежде.

## 13. Порядок работ (милстоуны)

1. `duckdns.SetTXT/ClearTXT` + тесты.
2. `internal/acme` (EnsureCert, DNS-01, staging) + тесты.
3. `xraygen`: `TLSSpec` + fallbacks (VLESS+Trojan) + golden-тесты.
4. `internal/site` + embed.
5. Config-поля (`Camouflage`, TLS-поля, `CamouflageTLS()`) + валидация +
   `inputFromConfig`-ветки.
6. Проводка в `runNode` (site goroutine + renewal).
7. `setup`: ветка `Camouflage=tls` — **пропуск скана `chooseRealityDomain`**,
   `serverName`=свой домен, staging→prod LE; переписать предусловие «узел настроен»
   в `cmdStart` под режим. `link` ветки для tls.
8. Cross-build под OpenWRT, проверка размера и записи сертов.
