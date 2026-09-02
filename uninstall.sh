#!/bin/sh
set -eu

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1
[ "$(id -u)" -eq 0 ] || { echo "error: run as root" >&2; exit 1; }

[ -x /etc/init.d/ai-agent-telegram ] && /etc/init.d/ai-agent-telegram disable || true
[ -x /etc/init.d/ai-agent-telegram ] && /etc/init.d/ai-agent-telegram stop || true
[ -x /etc/init.d/ai-agent ] && /etc/init.d/ai-agent disable || true
[ -x /etc/init.d/ai-agent ] && /etc/init.d/ai-agent stop || true
rm -f \
	/usr/bin/ai-agent \
	/usr/bin/ai-agent-cli \
	/usr/bin/ai-agent-maintenance \
	/usr/bin/ai-agent-log-monitor \
	/usr/bin/ai-agent-metrics-sample \
	/usr/bin/ai-agent-telegram \
	/etc/init.d/ai-agent \
	/etc/init.d/ai-agent-telegram \
	/var/run/ai-agent.sock \
	/var/run/ai-agent-log-monitor.lock \
	/var/run/ai-agent-metrics-sample.lock \
	/var/run/ai-agent-telegram-health.json
rm -rf /usr/lib/ai-agent
rm -f \
	/www/luci-static/resources/view/ai-agent/overview.js \
	/usr/share/luci/menu.d/luci-app-ai-agent.json \
	/usr/share/rpcd/acl.d/luci-app-ai-agent.json \
	/usr/libexec/ai-agent-luci
rmdir /www/luci-static/resources/view/ai-agent 2>/dev/null || true
rm -f /tmp/luci-indexcache.*.json
/etc/init.d/rpcd restart >/dev/null 2>&1 || true
if [ -f /etc/crontabs/root ]; then
	sed -i '/# ai-agent-maintenance$/d; /# ai-agent-log-monitor$/d; /# ai-agent-metrics-sample$/d' /etc/crontabs/root
	/etc/init.d/cron restart >/dev/null 2>&1 || true
fi

if [ "$PURGE" -eq 1 ]; then
	rm -rf /etc/ai-agent /var/lib/ai-agent
	rm -f /etc/config/ai-agent
else
	echo "Preserved /etc/config/ai-agent, /etc/ai-agent and /var/lib/ai-agent. Use --purge to remove them."
fi

