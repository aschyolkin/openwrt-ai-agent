#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
START_SERVICE=1
SECRET_FILE=""

while [ "$#" -gt 0 ]; do
	case "$1" in
		--no-start) START_SERVICE=0 ;;
		--secret-file)
			[ "$#" -ge 2 ] || { echo "error: --secret-file requires a path" >&2; exit 2; }
			SECRET_FILE="$2"
			shift
			;;
		-h|--help)
			echo "usage: ./install.sh [--no-start] [--secret-file /secure/path/secrets.env]"
			exit 0
			;;
		*) echo "error: unknown option: $1" >&2; exit 2 ;;
	esac
	shift
done

[ "$(id -u)" -eq 0 ] || { echo "error: run as root" >&2; exit 1; }
[ -r /etc/openwrt_release ] || { echo "error: this installer is for OpenWrt" >&2; exit 1; }
[ -x /usr/bin/apk ] || { echo "error: apk is required (OpenWrt 25.12+)" >&2; exit 1; }

# busybox на этом образе не содержит applet 'install' — копируем и выставляем права вручную.
install_file() {
	mode="$1"; src="$2"; dst="$3"
	cp "$src" "$dst"
	chmod "$mode" "$dst"
}

echo "==> installing Python runtime dependencies"
apk update
# apk возвращает ненулевой код при ЛЮБОМ несоответствии в системе (например, пакет,
# снятый с репозитория и более недоступный для другого, не связанного ПО), даже если
# запрошенные здесь пакеты встали успешно — поэтому не полагаемся на exit code apk add,
# а проверяем именно нужные пакеты.
apk add python3 python3-sqlite3 python3-yaml python3-requests python3-ubus python3-uci || true
for pkg in python3 python3-sqlite3 python3-yaml python3-requests python3-ubus python3-uci; do
	apk info -e "$pkg" >/dev/null || { echo "error: required package $pkg failed to install" >&2; exit 1; }
done

echo "==> installing ai-agent code"
mkdir -p /etc/ai-agent /var/lib/ai-agent/backups
chmod 700 /etc/ai-agent /var/lib/ai-agent /var/lib/ai-agent/backups

PROMPT_TARGET=/etc/ai-agent/system_prompt.md
PROMPT_BASELINE=/etc/ai-agent/.system_prompt.default.md
PROMPT_MANAGED=0
if [ ! -e "$PROMPT_TARGET" ]; then
	PROMPT_MANAGED=1
elif [ -f "$PROMPT_BASELINE" ] && cmp -s "$PROMPT_TARGET" "$PROMPT_BASELINE"; then
	PROMPT_MANAGED=1
elif [ -f /usr/lib/ai-agent/ai_agent/prompts/system_prompt.md ] \
	&& cmp -s "$PROMPT_TARGET" /usr/lib/ai-agent/ai_agent/prompts/system_prompt.md; then
	# Upgrade from a release that did not yet keep a managed baseline.
	PROMPT_MANAGED=1
fi

CODE_STAGE="$(mktemp -d /usr/lib/ai-agent.new.XXXXXX)"
CODE_OLD=""
cleanup_code_stage() {
	[ -z "$CODE_STAGE" ] || rm -rf "$CODE_STAGE"
	if [ -n "$CODE_OLD" ]; then
		if [ ! -d /usr/lib/ai-agent ]; then
			mv "$CODE_OLD" /usr/lib/ai-agent
		else
			rm -rf "$CODE_OLD"
		fi
	fi
}
trap cleanup_code_stage EXIT
cp -R "$SCRIPT_DIR/ai_agent" "$CODE_STAGE/ai_agent"
chmod 755 "$CODE_STAGE"
find "$CODE_STAGE/ai_agent" -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
find "$CODE_STAGE/ai_agent" -type d -name __pycache__ -exec rm -rf {} +
find "$CODE_STAGE/ai_agent" -type d -exec chmod 755 {} \;
find "$CODE_STAGE/ai_agent" -type f -exec chmod 644 {} \;
if [ -d /usr/lib/ai-agent ]; then
	CODE_OLD="/usr/lib/ai-agent.old.$$"
	mv /usr/lib/ai-agent "$CODE_OLD"
fi
mv "$CODE_STAGE" /usr/lib/ai-agent
CODE_STAGE=""
[ -z "$CODE_OLD" ] || rm -rf "$CODE_OLD"
CODE_OLD=""
install_file 0755 "$SCRIPT_DIR/bin/ai-agent" /usr/bin/ai-agent
install_file 0755 "$SCRIPT_DIR/bin/ai-agent-cli" /usr/bin/ai-agent-cli
install_file 0755 "$SCRIPT_DIR/bin/ai-agent-maintenance" /usr/bin/ai-agent-maintenance
install_file 0755 "$SCRIPT_DIR/bin/ai-agent-log-monitor" /usr/bin/ai-agent-log-monitor
install_file 0755 "$SCRIPT_DIR/bin/ai-agent-metrics-sample" /usr/bin/ai-agent-metrics-sample
install_file 0755 "$SCRIPT_DIR/bin/ai-agent-telegram" /usr/bin/ai-agent-telegram

LUCI_APP_DIR="$SCRIPT_DIR/luci-app-ai-agent"
if [ -d "$LUCI_APP_DIR" ] && [ -d /www/luci-static/resources ]; then
	echo "==> installing LuCI app"
	mkdir -p \
		/www/luci-static/resources/view/ai-agent \
		/usr/share/luci/menu.d \
		/usr/share/rpcd/acl.d \
		/usr/libexec
	install_file 0644 \
		"$LUCI_APP_DIR/htdocs/luci-static/resources/view/ai-agent/overview.js" \
		/www/luci-static/resources/view/ai-agent/overview.js
	install_file 0644 \
		"$LUCI_APP_DIR/root/usr/share/luci/menu.d/luci-app-ai-agent.json" \
		/usr/share/luci/menu.d/luci-app-ai-agent.json
	install_file 0644 \
		"$LUCI_APP_DIR/root/usr/share/rpcd/acl.d/luci-app-ai-agent.json" \
		/usr/share/rpcd/acl.d/luci-app-ai-agent.json
	install_file 0755 \
		"$LUCI_APP_DIR/root/usr/libexec/ai-agent-luci" \
		/usr/libexec/ai-agent-luci
	rm -f /tmp/luci-indexcache.*.json
	/etc/init.d/rpcd restart >/dev/null 2>&1 || true
fi

install_file 0755 "$SCRIPT_DIR/etc/init.d/ai-agent" /etc/init.d/ai-agent
install_file 0755 "$SCRIPT_DIR/etc/init.d/ai-agent-telegram" /etc/init.d/ai-agent-telegram

if [ ! -e /etc/config/ai-agent ]; then
	install_file 0600 "$SCRIPT_DIR/etc/config/ai-agent" /etc/config/ai-agent
else
	echo "    preserving existing /etc/config/ai-agent"
fi
if [ "$PROMPT_MANAGED" -eq 1 ]; then
	install_file 0600 "$SCRIPT_DIR/etc/ai-agent/system_prompt.md" "$PROMPT_TARGET"
	install_file 0600 "$SCRIPT_DIR/etc/ai-agent/system_prompt.md" "$PROMPT_BASELINE"
else
	echo "    preserving customized $PROMPT_TARGET"
fi

if [ -n "$SECRET_FILE" ]; then
	[ -f "$SECRET_FILE" ] || { echo "error: secret file does not exist" >&2; exit 1; }
	grep -q '^YANDEX_AI_STUDIO_API_KEY=' "$SECRET_FILE" || { echo "error: secret file lacks YANDEX_AI_STUDIO_API_KEY" >&2; exit 1; }
	install_file 0600 "$SECRET_FILE" /etc/ai-agent/secrets.env
elif [ -e /etc/ai-agent/secrets.env ]; then
	chmod 600 /etc/ai-agent/secrets.env
	chown root:root /etc/ai-agent/secrets.env
else
	echo "    NOTE: create /etc/ai-agent/secrets.env (0600) before using chat"
fi

uci -q get ai-agent.main >/dev/null || {
	uci set ai-agent.main='main'
	uci commit ai-agent
}

CRON=/etc/crontabs/root
touch "$CRON"
sed -i '/# ai-agent-maintenance$/d' "$CRON"
echo '17 4 * * * /usr/bin/ai-agent-maintenance # ai-agent-maintenance' >> "$CRON"
# Интервал настраивается через UCI ai-agent.main.log_monitor_interval_hours
# (вкладка Runtime в LuCI); при недопустимом/отсутствующем значении — 4 часа.
log_monitor_hours="$(uci -q get ai-agent.main.log_monitor_interval_hours)"
case "$log_monitor_hours" in ''|*[!0-9]*) log_monitor_hours=4 ;; esac
[ "$log_monitor_hours" -ge 1 ] 2>/dev/null && [ "$log_monitor_hours" -le 24 ] 2>/dev/null || log_monitor_hours=4
sed -i '/# ai-agent-log-monitor$/d' "$CRON"
echo "23 */$log_monitor_hours * * * /usr/bin/ai-agent-log-monitor # ai-agent-log-monitor" >> "$CRON"
sed -i '/# ai-agent-metrics-sample$/d' "$CRON"
echo '*/10 * * * * /usr/bin/ai-agent-metrics-sample # ai-agent-metrics-sample' >> "$CRON"
/etc/init.d/cron restart >/dev/null 2>&1 || true

/etc/init.d/ai-agent enable
/etc/init.d/ai-agent-telegram enable
if [ "$START_SERVICE" -eq 1 ]; then
	/etc/init.d/ai-agent restart
	if [ -r /etc/ai-agent/telegram.env ]; then
		/etc/init.d/ai-agent-telegram restart
	fi
fi

echo "==> ai-agent installed"
echo "    health: ai-agent-cli health"
echo "    chat:   ai-agent-cli chat"
