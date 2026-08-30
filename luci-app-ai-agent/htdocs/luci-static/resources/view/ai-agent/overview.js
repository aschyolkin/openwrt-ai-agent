'use strict';
'require view';
'require form';
'require fs';
'require poll';
'require ui';
'require dom';

var backend = '/usr/libexec/ai-agent-luci';

function backendCall(args) {
	return fs.exec(backend, args).then(function(result) {
		var data;

		try {
			data = JSON.parse(result.stdout || '{}');
		}
		catch (e) {
			throw new Error(_('Некорректный ответ backend'));
		}

		if (result.code !== 0 || !data.ok)
			throw new Error(data.error || _('Операция не выполнена'));

		return data;
	});
}

function statusValue(value, positive) {
	return E('span', {
		'style': 'font-weight:600;color:%s'.format(positive ? '#2a7b2e' : '#b42318')
	}, [ value ]);
}

function row(label, value) {
	return E('div', { 'class': 'tr' }, [
		E('div', { 'class': 'td left', 'style': 'width:40%' }, [ label ]),
		E('div', { 'class': 'td left' }, [ value ])
	]);
}

return view.extend({
	fetchStatus: function() {
		return backendCall([ 'status' ]).catch(function(error) {
			return {
				ok: false,
				error: error.message,
				services: {},
				health: { status: 'unavailable' }
			};
		});
	},

	statusRows: function(data) {
		var services = data.services || {};
		var health = data.health || {};
		var telegram = health.telegram || {};
		var models = health.models || {};
		var coreRunning = !!(services.core && services.core.running);
		var telegramRunning = !!(services.telegram && services.telegram.running);
		var coreReady = health.status === 'ready';
		var telegramReady = telegram.status === 'ready';
		var active = health.active_action;
		var offset = telegram.offset;

		return [
			row(_('Core service'), statusValue(coreRunning ? _('Работает') : _('Остановлен'), coreRunning)),
			row(_('Core health'), statusValue(coreReady ? _('Готов') : String(health.status || _('Недоступен')), coreReady)),
			row(_('Telegram service'), statusValue(telegramRunning ? _('Работает') : _('Остановлен'), telegramRunning)),
			row(_('Telegram health'), statusValue(telegramReady ? _('Готов') : String(telegram.status || _('Неизвестно')), telegramReady)),
			row(_('LLM'), String(health.llm || _('Неизвестно'))),
			row(_('Routing'), models.routing ? _('Включён') : _('Выключен')),
			row(_('Simple model'), String(models.simple_read_only || '—')),
			row(_('Complex model'), String(models.complex || health.model || '—')),
			row(_('Telegram offset'), offset == null ? '—' : String(offset)),
			row(_('Telegram errors'), String(telegram.consecutive_errors || 0)),
			row(_('Active action'), active ? '%s (%s)'.format(active.tool_name || '—', active.state || '—') : _('Нет'))
		];
	},

	updateStatus: function(data) {
		var node = document.getElementById('ai-agent-runtime-rows');

		if (node)
			dom.content(node, this.statusRows(data));
	},

	handleRefresh: function(ev) {
		var button = ev.currentTarget;

		button.disabled = true;
		return this.fetchStatus()
			.then(L.bind(this.updateStatus, this))
			.finally(function() { button.disabled = false; });
	},

	handleRestart: function(target, ev) {
		var button = ev.currentTarget;

		button.disabled = true;
		return backendCall([ 'restart', target ])
			.then(function() {
				ui.addNotification(null, E('p', {}, [ _('Сервис перезапущен') ]));
				return new Promise(function(resolve) { window.setTimeout(resolve, 1500); });
			})
			.then(L.bind(this.fetchStatus, this))
			.then(L.bind(this.updateStatus, this))
			.catch(function(error) {
				ui.addNotification(null, E('p', {}, [ _('Ошибка: '), error.message ]), 'error');
			})
			.finally(function() { button.disabled = false; });
	},

	render: function(initialStatus) {
		var m = new form.Map(
			'ai-agent',
			_('AI Agent'),
			_('Основные настройки локального агента. Секреты здесь не отображаются и не изменяются. Сохранение настроек перезапускает Core через procd reload trigger.')
		);
		var s = m.section(form.NamedSection, 'main', 'main', _('Настройки'));
		var o;

		s.anonymous = true;
		s.addremove = false;
		s.tab('models', _('Модели'));
		s.tab('limits', _('Лимиты'));
		s.tab('runtime', _('Runtime'));

		o = s.taboption('models', form.Flag, 'enable', _('Включить Core'));
		o.default = '1';
		o.rmempty = false;

		o = s.taboption('models', form.Flag, 'model_routing_enabled', _('Двухмодельный routing'));
		o.default = '1';
		o.rmempty = false;

		function validateModel(sectionId, value) {
			if (!/^gpt:\/\/[A-Za-z0-9._~:/-]+$/.test(value || ''))
				return _('Ожидается безопасный Yandex model URI вида gpt://folder/model/version');
			return true;
		}

		o = s.taboption('models', form.Value, 'simple_model_id', _('Модель простых read-only запросов'));
		o.rmempty = false;
		o.depends('model_routing_enabled', '1');
		o.validate = validateModel;

		o = s.taboption('models', form.Value, 'complex_model_id', _('Основная модель'));
		o.rmempty = false;
		o.validate = validateModel;

		o = s.taboption('runtime', form.ListValue, 'log_level', _('Уровень журнала'));
		o.value('ERROR');
		o.value('WARNING');
		o.value('INFO');
		o.value('DEBUG');
		o.default = 'INFO';
		o.rmempty = false;

		o = s.taboption('runtime', form.Value, 'request_timeout_seconds', _('Таймаут LLM-запроса, секунд'));
		o.datatype = 'range(5,180)';
		o.default = '60';
		o.rmempty = false;

		o = s.taboption('runtime', form.Value, 'confirm_ttl_seconds', _('Время подтверждения действия, секунд'));
		o.datatype = 'range(30,3600)';
		o.default = '300';
		o.rmempty = false;

		o = s.taboption('runtime', form.Value, 'backup_retention_days', _('Хранение резервных копий, дней'));
		o.datatype = 'range(1,365)';
		o.default = '30';
		o.rmempty = false;

		o = s.taboption('runtime', form.Value, 'log_monitor_interval_hours', _('Интервал анализа логов, часов'));
		o.datatype = 'range(1,24)';
		o.default = '4';
		o.rmempty = false;
		o.description = _('Как часто фоновый анализ logread через LLM проверяет новые подозрительные записи и присылает алерт в Telegram.');

		o = s.taboption('limits', form.Value, 'max_tool_loop_iterations', _('Максимум циклов tools'));
		o.datatype = 'range(1,20)';
		o.default = '8';
		o.rmempty = false;

		o = s.taboption('limits', form.Value, 'conversation_max_chars', _('Контекст диалога, символов'));
		o.datatype = 'range(4000,64000)';
		o.default = '12000';
		o.rmempty = false;

		o = s.taboption('limits', form.Value, 'tool_context_max_chars', _('Результат tool в контексте, символов'));
		o.datatype = 'range(4000,32768)';
		o.default = '16000';
		o.rmempty = false;

		o = s.taboption('limits', form.Value, 'command_output_limit', _('Лимит вывода команды, байт'));
		o.datatype = 'range(4096,1048576)';
		o.default = '65536';
		o.rmempty = false;

		var statusSection = E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, [ _('Состояние') ]),
			E('div', {
				'class': 'table',
				'id': 'ai-agent-runtime-rows'
			}, this.statusRows(initialStatus)),
			E('div', { 'class': 'right', 'style': 'margin-top:1em' }, [
				E('button', {
					'class': 'btn cbi-button',
					'click': L.bind(this.handleRefresh, this)
				}, [ _('Обновить') ]),
				' ',
				E('button', {
					'class': 'btn cbi-button-action',
					'click': L.bind(this.handleRestart, this, 'core')
				}, [ _('Перезапустить Core') ]),
				' ',
				E('button', {
					'class': 'btn cbi-button-action',
					'click': L.bind(this.handleRestart, this, 'telegram')
				}, [ _('Перезапустить Telegram') ])
			])
		]);

		poll.add(L.bind(function() {
			return this.fetchStatus().then(L.bind(this.updateStatus, this));
		}, this), 5);

		return m.render().then(function(formNode) {
			return E('div', {}, [ statusSection, formNode ]);
		});
	},

	load: function() {
		return this.fetchStatus();
	}
});
