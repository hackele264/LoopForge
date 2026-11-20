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
const consts = /^const CASE_[A-Z_]+=.*$/gm;
vm.runInContext(bundle.match(consts).join('\n').replace(/^const /gm, 'var '), context);
for (const name of ['caseSeverityText', 'caseStatusText', 'caseActorText', 'caseUpdateBody', 'caseTriggerBody']) vm.runInContext(source(name), context);
const plain = v => JSON.parse(JSON.stringify(v));
assert.equal(context.caseSeverityText('critical'), '严重');
assert.equal(context.caseStatusText('closed', 'false_positive'), '已关闭 · 误报');
assert.equal(context.caseStatusText('investigating', ''), '分析中');
assert.equal(context.caseActorText({actorKind: 'user', actorUserId: 7}), '用户 #7');
assert.equal(context.caseActorText({actorKind: 'system'}), '系统');
const current = {severity: 'medium', status: 'investigating', resolution: ''};
assert.deepEqual(plain(context.caseUpdateBody(current, {severity: 'medium', status: 'investigating', resolution: ''})), {});
assert.deepEqual(plain(context.caseUpdateBody(current, {severity: 'high', status: 'closed', resolution: 'resolved'})), {severity: 'high', status: 'closed', resolution: 'resolved'});
assert.deepEqual(plain(context.caseUpdateBody({severity: 'low', status: 'closed', resolution: 'resolved'}, {severity: 'low', status: 'closed', resolution: 'duplicate'})), {resolution: 'duplicate'});
assert.deepEqual(plain(context.caseTriggerBody({projectId: 'p', workflowId: 'w', name: ' t ', events: ['case.created', ''], minSeverity: ''})), {projectId: 'p', workflowId: 'w', name: 't', enabled: true, events: ['case.created']});
console.log('cases view ok');
