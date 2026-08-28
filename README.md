# AI-agent для OpenWrt

Локальный AI-агент для NanoPi R76S/OpenWrt 25.12. Ядро диагностирует сеть, AdGuardHome, netshift/sing-box, zapret и общесистемное состояние через ограниченный набор структурированных tools. `sys_inspect` даёт read-only доступ к firewall/nftables, маршрутам, интерфейсам, портам, установленным NAT-соединениям (conntrack), процессам, сервисам, пакетам, файловым системам, UBus и безопасному представлению UCI. `sys_resource_usage` показывает загрузку CPU по ядрам, температуру, память и место на overlay. Изменения всегда проходят через детерминированный plan/diff, локальное подтверждение, бэкап, проверку исходного хэша и action-specific verifier.

Дополнительно:

- **`firewall_open_wan_port`/`firewall_close_wan_port`** — открыть/закрыть TCP/UDP-порт роутера со стороны WAN (сервис на самом роутере, не port-forward на LAN). Denylist управляющих портов (SSH/DNS/HTTP(S)/админки) не открывается даже с подтверждением.
- **`sys_package_install`/`sys_package_remove`** — установка/удаление пакета через `apk` с планом, бэкапом world-файла и верификацией.
- **Роутинг между моделями** (`ai_agent/model_router.py`) — простые read-only вопросы уходят на дешёвую/быструю модель, сложные диагностические и все mutating-запросы — на более сильную; настраивается через UCI (`simple_model_id`/`complex_model_id`/`model_routing_enabled`).
- **Проактивный мониторинг логов** (`ai-agent-log-monitor`, cron) — раз в несколько часов разбирает новые подозрительные строки `logread` через LLM и присылает алерт в Telegram только при реальной проблеме (не при единичном ожидаемом шуме).
- **Telegram-клиент** (`ai-agent-telegram`) — тонкий клиент к Core API с confirm/rollback-кнопками, markdown→Telegram HTML форматированием, индикатором "печатает" и безопасным разбиением длинных сообщений.

## Установка

На OpenWrt 25.12 с `apk`:

```sh
scp -r ai-agent root@10.110.112.1:/tmp/
ssh root@10.110.112.1 /tmp/ai-agent/install.sh --no-start
```

Создайте секрет непосредственно на роутере, не добавляя его в git или UCI:

```sh
umask 077
printf '%s\n' 'YANDEX_AI_STUDIO_API_KEY=...' > /etc/ai-agent/secrets.env
/etc/init.d/ai-agent restart
```

Проверка и интерактивный CLI:

```sh
ai-agent-cli health
ai-agent-cli chat
ai-agent-cli chat 'какая нода активна в ai_section?'
```

`install.sh` идемпотентен: обновляет код и init-скрипт, но сохраняет существующие `/etc/config/ai-agent`, `/etc/ai-agent/system_prompt.md`, секрет и `/var/lib/ai-agent`. API-ключ можно передать только файлом через `--secret-file`; аргумент с самим ключом намеренно не поддерживается.

## Core API

MVP слушает JSON Lines на Unix-сокете `/var/run/ai-agent.sock` с правами `0600 root:root`. Запрос:

```json
{"method":"chat","params":{"session_id":"optional","message":"проверь chat.z.ai"}}
```

Методы: `chat`, `confirm`, `rollback`, `history`, `health`. `debug_uci` доступен CLI/root-клиенту, но не зарегистрирован как LLM tool. Переход к HTTP в MVP намеренно отсутствует.

## Безопасность

- Нет generic shell tool и нет `shell=True`; команды имеют фиксированный executable/argv allowlist, timeout и лимит вывода.
- Управление установленными procd-сервисами доступно через `sys_service_control`, но каждое действие требует отдельного подтверждения; управление самим `ai-agent` запрещено.
- Специализированные config-tools строят allowlist-представления. URL подписок, UUID/Reality-ключи, пароли и API-токены не отправляются модели.
- Результаты tools маркируются как недоверенные данные. Решение `read_only`/`mutating` и verifier задаются статически кодом.
- Одновременно может существовать только одно mutating-действие. Перед apply проверяются TTL, `uci changes` и SHA-256 целевых файлов.
- Для UCI сохраняются и `uci export`, и побайтовая копия `/etc/config/<package>`. Откат требует отдельного подтверждения.
- `applying`/`rollback_pending`, обнаруженные после падения, переводятся в `manual_review` и не продолжаются автоматически.
- Секрет хранится только в `/etc/ai-agent/secrets.env` с правами `0600`.


Для проверки Telegram и других сервисов через netshift используется `netshift_service_health`. Он различает настроенный маршрут, наблюдаемый активный трафик и фактическую доступность на клиенте. Ping fake-IP, одиночный запрос с самого роутера и `zapret/dwc.sh` сами по себе не считаются доказательством отказа.
`agh_add_user_rule_exception` намеренно не реализован в MVP: безопасный авторизованный REST-путь AdGuardHome пока не настроен, а конкурентная перезапись YAML слишком рискованна.

## Тесты

```sh
python3 -m unittest discover -s tests -v
```

Интеграционные mutating-тесты выполняйте только с тестовым доменом `test-ai-agent-canary.invalid` и готовой параллельной SSH-сессией. CLI никогда не применяет plan без ответа `y`.

