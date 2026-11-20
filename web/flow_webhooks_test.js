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
for (const name of ['webhookFormBody', 'webhookURL', 'webhookCurlExample', 'webhookDeliveryLabel', 'webhookWindowText']) vm.runInContext(source(name), context);
const plain = v => JSON.parse(JSON.stringify(v));

assert.deepEqual(plain(context.webhookFormBody({projectId: 'p', workflowId: 'w', name: ' SIEM ', titleField: ' alert.title ', dedupFields: 'alert.rule, alert.host，alert.rule', dedupMinutes: '30', allowedCidrs: '10.0.0.0/8\n192.0.2.7', signatureHeader: '', signingSecret: '', enabled: true, methods: ['POST', 'GET']})),
  {projectId: 'p', workflowId: 'w', name: 'SIEM', enabled: true, methods: ['POST', 'GET'], allowedCidrs: ['10.0.0.0/8', '192.0.2.7'], titleField: 'alert.title', severityField: '', caseMode: '', dedupFields: ['alert.rule', 'alert.host', 'alert.rule'], signatureHeader: '', dedupWindowSeconds: 1800});
const noDedup = plain(context.webhookFormBody({projectId: 'p', workflowId: 'w', name: 'n', dedupFields: '', dedupMinutes: '30', signingSecret: ' k ', signatureHeader: 'X-Sig', enabled: false}));
assert.equal(noDedup.dedupWindowSeconds, undefined);
assert.equal(noDedup.rateLimitPerMinute, undefined);
const limited = plain(context.webhookFormBody({projectId: 'p', workflowId: 'w', name: 'n', rateLimitPerMinute: '30', rateLimitBurst: '5'}));
assert.equal(limited.rateLimitPerMinute, 30);
assert.equal(limited.rateLimitBurst, 5);
const burstOnly = plain(context.webhookFormBody({projectId: 'p', workflowId: 'w', name: 'n', rateLimitPerMinute: '', rateLimitBurst: '5'}));
assert.equal(burstOnly.rateLimitBurst, undefined);
assert.equal(context.webhookDeliveryLabel({status: 'rate_limited'}), '超出限流');
assert.equal(noDedup.signingSecret, 'k');
assert.equal(noDedup.enabled, false);
assert.deepEqual(noDedup.methods, ['POST']);
assert.equal(context.webhookURL('https://lf.example.test/', '/api/hooks/wh-1/abc'), 'https://lf.example.test/api/hooks/wh-1/abc');
assert.match(context.webhookCurlExample('https://x/api/hooks/a/b'), /curl -X POST 'https:\/\/x\/api\/hooks\/a\/b'/);
assert.equal(context.webhookDeliveryLabel({status: 'deduplicated'}), '重复告警，已合并');
assert.equal(context.webhookWindowText(7200), '2 小时');
assert.equal(context.webhookWindowText(1800), '30 分钟');
assert.equal(context.webhookWindowText(0), '');
console.log('flow webhooks ok');
