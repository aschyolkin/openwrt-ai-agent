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
mkdir -p /usr/lib/ai-agent /etc/ai-agent /var/lib/ai-agent/backups
chmod 700 /etc/ai-agent /var/lib/ai-agent /var/lib/ai-agent/backups
cp -R "$SCRIPT_DIR/ai_agent" /usr/lib/ai-agent/
find /usr/lib/ai-agent/ai_agent -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
find /usr/lib/ai-agent/ai_agent -type d -name __pycache__ -exec rm -rf {} +
find /usr/lib/ai-agent/ai_agent -type d -exec chmod 755 {} \;
find /usr/lib/ai-agent/ai_agent -type f -exec chmod 644 {} \;
install_file 0755 "$SCRIPT_DIR/bin/ai-agent" /usr/bin/ai-agent
install_file 0755 "$SCRIPT_DIR/bin/ai-agent-cli" /usr/bin/ai-agent-cli
install_file 0755 "$SCRIPT_DIR/bin/ai-agent-maintenance" /usr/bin/ai-agent-maintenance
install_file 0755 "$SCRIPT_DIR/bin/ai-agent-log-monitor" /usr/bin/ai-agent-log-monitor
install_file 0755 "$SCRIPT_DIR/bin/ai-agent-metrics-sample" /usr/bin/ai-agent-metrics-sample
install_file 0755 "$SCRIPT_DIR/bin/ai-agent-telegram" /usr/bin/ai-agent-telegram
install_file 0755 "$SCRIPT_DIR/etc/init.d/ai-agent" /etc/init.d/ai-agent
install_file 0755 "$SCRIPT_DIR/etc/init.d/ai-agent-telegram" /etc/init.d/ai-agent-telegram

if [ ! -e /etc/config/ai-agent ]; then
	install_file 0600 "$SCRIPT_DIR/etc/config/ai-agent" /etc/config/ai-agent
else
	echo "    preserving existing /etc/config/ai-agent"
fi
if [ ! -e /etc/ai-agent/system_prompt.md ]; then
	install_file 0600 "$SCRIPT_DIR/etc/ai-agent/system_prompt.md" /etc/ai-agent/system_prompt.md
else
	echo "    preserving existing /etc/ai-agent/system_prompt.md"
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
sed -i '/# ai-agent-log-monitor$/d' "$CRON"
echo '23 */4 * * * /usr/bin/ai-agent-log-monitor # ai-agent-log-monitor' >> "$CRON"
sed -i '/# ai-agent-metrics-sample$/d' "$CRON"
echo '*/10 * * * * /usr/bin/ai-agent-metrics-sample # ai-agent-metrics-sample' >> "$CRON"
/etc/init.d/cron restart >/dev/null 2>&1 || true

/etc/init.d/ai-agent enable
if [ "$START_SERVICE" -eq 1 ]; then
	/etc/init.d/ai-agent restart
fi

echo "==> ai-agent installed"
echo "    health: ai-agent-cli health"
echo "    chat:   ai-agent-cli chat"
