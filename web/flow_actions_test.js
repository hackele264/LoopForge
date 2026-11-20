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
vm.runInContext("const ACTION_CATEGORY_TEXT={enrichment:'情报富化',response:'响应处置',utility:'通用'};const FOR_EACH_BOUNDS={forEachConcurrency:{def:4,max:16},forEachLimit:{def:100,max:1000}};function escapeHTML(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;')}", context);
for (const name of ['forEachTagText', 'forEachOutputRefs', 'applyForEachField', 'forEachResultsHTML', 'actionCategoryText', 'actionCatalogFind', 'actionOutputRefs', 'actionInputsFromForm', 'actionGatedByApproval', 'actionNodeProblems', 'actionNodeMeta', 'connectionFormBody', 'connectionFormMissing']) vm.runInContext(source(name), context);
const plain = v => JSON.parse(JSON.stringify(v));

const catalog = [
  {id: 'loopforge', builtin: true, title: '内置', actions: [{id: 'extract_iocs', title: '提取 IOC', category: 'utility', inputs: [{name: 'value', required: true}], outputFields: ['iocs', 'url']}]},
  {id: 'crowdstrike', title: 'Falcon', baseUrl: 'https://api.crowdstrike.com', secrets: [{name: 'client_id', label: 'ID', required: true}, {name: 'client_secret', label: '密钥', required: true}], params: [],
    actions: [{id: 'contain', title: '网络隔离终端', category: 'response', inputs: [{name: 'device_id', label: '终端 ID', required: true}], outputFields: []}]},
];
const wf = {nodes: [{id: 'x', type: 'action'}, {id: 'ok', type: 'approval'}, {id: 'iso', type: 'action'}], edges: [{source: 'x', target: 'ok'}, {source: 'ok', target: 'iso'}]};
assert.equal(context.actionGatedByApproval(wf, 'iso'), true);
assert.equal(context.actionGatedByApproval({...wf, edges: [{source: 'x', target: 'iso'}]}, 'iso'), false);
assert.equal(context.actionGatedByApproval({...wf, edges: [{source: 'x', target: 'ok'}, {source: 'ok', target: 'iso', when: 'error'}]}, 'iso'), false);

const iso = {id: 'iso', type: 'action', action: {connector: 'crowdstrike', action: 'contain', connectionId: '', inputs: {}}};
assert.deepEqual(plain(context.actionNodeProblems(iso, catalog, wf)), ['未选择连接', '缺少输入「终端 ID」']);
iso.action.connectionId = 'cn'; iso.action.inputs.device_id = '{{ trigger.alert.device_id }}';
assert.deepEqual(plain(context.actionNodeProblems(iso, catalog, wf)), []);
assert.deepEqual(plain(context.actionNodeProblems(iso, catalog, {...wf, edges: []})), ['响应动作前必须有人工门禁']);
const meta = plain(context.actionNodeMeta(iso, catalog, [{id: 'cn', name: '生产 Falcon'}], wf));
assert.equal(meta.subtitle, 'Falcon · 网络隔离终端');
assert.deepEqual(meta.tags, [{text: '响应处置', warn: true}, {text: '生产 Falcon'}]);
assert.equal(plain(context.actionNodeMeta({id: 'n', action: {}}, catalog, [], wf)).subtitle, '未选择动作');

assert.deepEqual(plain(context.actionOutputRefs('vt', {outputFields: ['malicious']})), ['nodes.vt.data.status', 'nodes.vt.data.malicious']);
assert.deepEqual(plain(context.actionOutputRefs('w', {outputFields: []})), ['nodes.w.data.status', 'nodes.w.data.body']);
assert.deepEqual(plain(context.actionInputsFromForm({inputs: [{name: 'a'}, {name: 'b'}]}, {a: ' 1 ', b: '', zzz: 'x'})), {a: '1'});

const def = catalog[1];
assert.deepEqual(plain(context.connectionFormMissing(def, {name: 'x', secrets: {client_id: 'i'}}, null)), ['密钥']);
assert.deepEqual(plain(context.connectionFormMissing(def, {name: 'x', secrets: {}}, {secretsSet: ['client_id', 'client_secret']})), []);
assert.deepEqual(plain(context.connectionFormBody(def, {projectId: 'p', name: ' Falcon ', baseUrl: '', secrets: {client_id: ' i ', client_secret: ''}}, null)),
  {name: 'Falcon', baseUrl: '', params: {}, secrets: {client_id: 'i'}, projectId: 'p', connectorId: 'crowdstrike'});
assert.equal(plain(context.connectionFormBody(def, {name: 'n', secrets: {}}, {id: 'cn'})).projectId, undefined);
assert.deepEqual(plain(context.connectionFormBody(def, {name: 'n', secrets: {}, tlsCertSha256: ' AB:CD ', tlsCaPem: ''}, {id: 'cn'})),
  {name: 'n', baseUrl: '', params: {}, secrets: {}, tlsCertSha256: 'AB:CD', tlsCaPem: ''});
const limits = plain(context.connectionFormBody(def, {name: 'n', secrets: {}, rateLimitPerSecond: '2.5', rateLimitBurst: '4', maxRetries: '0'}, {id: 'cn'}));
assert.equal(limits.rateLimitPerSecond, 2.5);
assert.equal(limits.rateLimitBurst, 4);
assert.equal(limits.maxRetries, 0);
const defaults = plain(context.connectionFormBody(def, {name: 'n', secrets: {}, rateLimitPerSecond: '', rateLimitBurst: '', maxRetries: ''}, {id: 'cn'}));
assert.equal(defaults.rateLimitPerSecond, 0);
assert.equal(defaults.rateLimitBurst, 0);
assert.equal(defaults.maxRetries, null);
// List loops.
const loop = {id: 'vt'};
context.applyForEachField(loop, 'forEach', 'iocs(trigger, "ipv4")');
context.applyForEachField(loop, 'forEachConcurrency', '40');
context.applyForEachField(loop, 'forEachLimit', '');
context.applyForEachField(loop, 'forEachFailOn', 'all');
assert.deepEqual(plain(loop), {id: 'vt', forEach: 'iocs(trigger, "ipv4")', forEachConcurrency: 16, forEachFailOn: 'all'});
assert.equal(context.forEachTagText(loop), '逐项执行 · 并发 16');
context.applyForEachField(loop, 'forEachFailOn', 'any');
context.applyForEachField(loop, 'forEachLimit', '0');
assert.deepEqual(plain(loop), {id: 'vt', forEach: 'iocs(trigger, "ipv4")', forEachConcurrency: 16});
context.applyForEachField(loop, 'forEach', '  ');
assert.deepEqual(plain(loop), {id: 'vt'});
assert.equal(context.forEachTagText({forEach: 'x'}), '逐项执行 · 并发 4');
assert.deepEqual(plain(context.forEachOutputRefs('vt')), ['nodes.vt.data.total', 'nodes.vt.data.succeeded', 'nodes.vt.data.failed', 'nodes.vt.data.results']);
const loopMeta = plain(context.actionNodeMeta({...iso, forEach: 'trigger.devices'}, catalog, [{id: 'cn', name: '生产 Falcon'}], wf));
assert.deepEqual(loopMeta.tags[2], {text: '逐项执行 · 并发 4'});
assert.equal(context.forEachResultsHTML({verdict: 'x'}), '');
const table = context.forEachResultsHTML({total: 2, succeeded: 1, failed: 1, truncated: 'bodies', results: [
  {index: 0, item: '10.0.0.1', ok: true, output: {status: 200, malicious: 3, body: null, bodyTruncated: true}},
  {index: 1, item: '<b>', ok: false, error: 'HTTP 404'}]});
assert.match(table, /共 2 项 · 成功 1 · 失败 1 · 响应原文已省略/);
assert.match(table, /status=200 · malicious=3<\/td>/);
assert.match(table, /<tr class="is-failed"><td>2<\/td><td><code>&lt;b&gt;<\/code><\/td><td>失败<\/td><td>HTTP 404<\/td>/);
assert.equal(context.forEachResultsHTML({total: 0, succeeded: 0, failed: 0, results: []}).includes('<table'), false);
console.log('flow actions ok');
