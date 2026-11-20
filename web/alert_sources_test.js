const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const bundle = fs.readFileSync(process.argv[2], 'utf8');
function source(name) {
  const match = new RegExp('^(?:async )?function ' + name + '\\(', 'm').exec(bundle);
  assert(match, name);
  const tail = bundle.slice(match.index);
  const next = /\n(?:async )?function |\n(?:let|const) [A-Za-z]|\n\/\/ /.exec(tail);
  return next ? tail.slice(0, next.index) : tail;
}
const context = {};
vm.createContext(context);
const presetsAt = bundle.indexOf('const ALERT_SOURCE_PRESETS=');
assert(presetsAt >= 0, 'presets');
vm.runInContext(bundle.slice(presetsAt, bundle.indexOf('\n};\n', presetsAt) + 3).replace('const ALERT_SOURCE_PRESETS', 'var ALERT_SOURCE_PRESETS'), context);
for (const name of ['alertSourceFalconFilter', 'alertSourceExtra', 'alertSourcePresetOf', 'alertSourceFormBody', 'alertSourceStatus', 'webhookDeliveryOrigin']) vm.runInContext(source(name), context);
const plain = v => JSON.parse(JSON.stringify(v));

// Falcon: the window filter is always there; an extra FQL clause is ANDed.
const base = "created_timestamp:>='{{ window.sinceIso }}'+created_timestamp:<'{{ window.untilIso }}'";
assert.equal(context.alertSourceFalconFilter(''), base);
assert.equal(context.alertSourceFalconFilter(" +product:'epp' "), base + "+product:'epp'");
const falcon = plain(context.alertSourceFormBody({projectId: 'p', webhookId: 'w', preset: 'falcon', name: ' EDR ', connectionId: 'cn', extra: "product:'epp'", pollMinutes: '2', lookbackHours: '1'}));
assert.deepEqual(falcon, {projectId: 'p', webhookId: 'w', name: 'EDR', connectionId: 'cn', enabled: true, pollSeconds: 120, lookbackSeconds: 3600,
  action: 'list_alert_ids', detailAction: 'get_alerts', detailInput: 'ids', idPath: 'composite_id', timePath: 'created_timestamp',
  inputs: {filter: base + "+product:'epp'", limit: '{{ window.limit }}'}});
// Reading a saved source back gives the form what it showed.
const saved = {...falcon, connectorId: 'crowdstrike'};
assert.equal(context.alertSourcePresetOf(saved), 'falcon');
assert.equal(context.alertSourceExtra('falcon', saved), "product:'epp'");
assert.equal(context.alertSourcePresetOf({...saved, connectorId: 'other'}), 'custom');

// Splunk: the search defaults to the notable index and gets the window.
const splunk = plain(context.alertSourceFormBody({projectId: 'p', webhookId: 'w', preset: 'splunk', name: 'SIEM', connectionId: 'cs', extra: ''}));
assert.equal(splunk.inputs.search, 'search index=notable | sort 0 _time');
assert.equal(splunk.inputs.earliest, '{{ window.since }}');
assert.equal(splunk.pollSeconds, 60);
assert.equal(context.alertSourceExtra('splunk', splunk), 'search index=notable | sort 0 _time');

// Custom: fields come from JSON; bad JSON is reported.
const custom = plain(context.alertSourceFormBody({projectId: 'p', webhookId: 'w', preset: 'custom', name: 'x', connectionId: 'c', custom: '{"action":"search","inputs":{"search":"| makeresults"},"pageLimit":50,"enabled":false}'}));
assert.equal(custom.action, 'search');
assert.equal(custom.pageLimit, 50);
assert.equal(custom.enabled, true, 'custom JSON cannot switch fields the form owns');
assert.throws(() => context.alertSourceFormBody({preset: 'custom', custom: '{'}), /JSON/);

// Status lines.
assert.equal(context.alertSourceStatus({enabled: false, state: {}}).level, 'off');
assert.equal(context.alertSourceStatus({enabled: true, state: {}}).text, '等待首次拉取');
assert.match(context.alertSourceStatus({enabled: true, state: {lastError: 'HTTP 401', failures: 3}}).text, /失败 3 次：HTTP 401/);
const ok = context.alertSourceStatus({enabled: true, state: {lastRunAt: '2026-11-20T08:00:00Z', lastFetched: 5, lastAdmitted: 2, totalAdmitted: 9}});
assert.equal(ok.level, 'ok');
assert.match(ok.text, /拉取 5 条，新增 2 条 · 累计 9 条/);
assert.equal(context.alertSourceStatus({enabled: true, state: {lastRunAt: '2026-11-20T08:00:00Z', lastWarning: '达到上限'}}).level, 'warn');

// Deliveries name the source that pulled them.
assert.equal(context.webhookDeliveryOrigin({sourceId: 'as-1', message: ''}, [{id: 'as-1', name: 'Falcon EDR'}]), '拉取：Falcon EDR');
assert.equal(context.webhookDeliveryOrigin({sourceIp: '10.0.0.1'}, []), '10.0.0.1');
console.log('alert sources ok');
