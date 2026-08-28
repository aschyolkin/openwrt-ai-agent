#!/bin/sh
set -eu

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1
[ "$(id -u)" -eq 0 ] || { echo "error: run as root" >&2; exit 1; }

[ -x /etc/init.d/ai-agent ] && /etc/init.d/ai-agent disable || true
[ -x /etc/init.d/ai-agent ] && /etc/init.d/ai-agent stop || true
rm -f /usr/bin/ai-agent /usr/bin/ai-agent-cli /usr/bin/ai-agent-maintenance /etc/init.d/ai-agent /var/run/ai-agent.sock
rm -rf /usr/lib/ai-agent
if [ -f /etc/crontabs/root ]; then
	sed -i '/# ai-agent-maintenance$/d' /etc/crontabs/root
	/etc/init.d/cron restart >/dev/null 2>&1 || true
fi

if [ "$PURGE" -eq 1 ]; then
	rm -rf /etc/ai-agent /var/lib/ai-agent
	rm -f /etc/config/ai-agent
else
	echo "Preserved /etc/config/ai-agent, /etc/ai-agent and /var/lib/ai-agent. Use --purge to remove them."
fi

