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
for (const name of ['flowSampleFromSchema', 'flowConditionSampleNodes', 'flowConditionCheckRequest', 'flowConditionCheckText', 'flowBranchTags', 'flowRunIfRefs', 'flowUpstream', 'flowRunIfProblem', 'flowApproverSummary', 'flowApproversFromForm', 'flowBranchDiagnostics']) {
  vm.runInContext(source(name), context);
}
const plain = v => JSON.parse(JSON.stringify(v));

assert.deepEqual(plain(context.flowRunIfRefs(`nodes.triage.data.v == "x" && nodes["enrich-ip"].status == 'ok' || nodes[ 'triage' ].data`)), ['triage', 'enrich-ip']);
assert.deepEqual(plain(context.flowRunIfRefs('')), []);

const wf = {
  nodes: [
    {id: 'triage', name: '研判', type: 'script'},
    {id: 'enrich-ip', name: '富化', type: 'script', outputSchema: {type: 'object'}},
    {id: 'isolate', name: '隔离', type: 'script'},
    {id: 'other', name: '旁路', type: 'script'},
  ],
  edges: [
    {id: '1', source: 'triage', target: 'enrich-ip'},
    {id: '2', source: 'enrich-ip', target: 'isolate'},
  ],
};
assert.deepEqual([...context.flowUpstream(wf, 'isolate')].sort(), ['enrich-ip', 'triage']);
assert.equal(context.flowRunIfProblem(wf, {id: 'isolate', runIf: 'nodes["enrich-ip"].data.hits > 0'}), '');
assert.match(context.flowRunIfProblem(wf, {id: 'isolate', runIf: 'nodes.other.status == "succeeded"'}), /不在本步骤上游/);
assert.match(context.flowRunIfProblem(wf, {id: 'isolate', runIf: 'nodes.ghost.status == "x"'}), /不存在/);
assert.match(context.flowRunIfProblem(wf, {id: 'isolate', runIf: 'trigger.severity = "high"'}), /==/);
assert.match(context.flowRunIfProblem(wf, {id: 'isolate', runIf: '(trigger.a == 1'}), /括号/);
assert.equal(context.flowRunIfProblem(wf, {id: 'isolate', runIf: 'trigger.a >= 1 && trigger.b != 2 && trigger.c <= 3'}), '');

assert.deepEqual(plain(context.flowApproversFromForm('42, 7，42 abc -1', ['member', 'boss', 'owner'])), {userIds: [42, 7], roles: ['owner', 'member']});
assert.equal(context.flowApproversFromForm('', []), null);
assert.equal(context.flowApproverSummary({roles: ['owner'], userIds: [1, 2]}), '审批人：项目 Owner、2 位指定用户');
assert.equal(context.flowApproverSummary(undefined), '');

assert.deepEqual(plain(context.flowBranchTags({runIf: ' trigger.x == 1 ', join: 'any'})), [{text: '条件：trigger.x == 1', mono: true}, {text: '任一上游即可'}]);

const diag = plain(context.flowBranchDiagnostics({
  nodes: [
    {id: 'triage', name: '研判', type: 'script'},
    {id: 'act', name: '处置', type: 'script', runIf: 'nodes.triage.data.verdict == "bad"', join: 'any', onFailure: 'reject', rejectTo: 'triage'},
    {id: 'bad', name: '错条件', type: 'script', runIf: 'nodes.act.status = "x"'},
    {id: 'fallback', name: '兜底', type: 'script'},
  ],
  edges: [
    {id: '1', source: 'triage', target: 'act'},
    {id: '2', source: 'act', target: 'bad'},
    {id: '3', source: 'act', target: 'fallback', when: 'error'},
  ],
}));
const details = diag.map(d => `${d.level}:${d.title}:${d.detail}`);
assert(details.some(d => d.startsWith('error:错条件:执行条件')), details);
assert(details.some(d => d.startsWith('warn:处置:设置了「任一上游即可」')), details);
assert(details.some(d => d.startsWith('warn:处置:条件读取的「研判」没有声明输出结构')), details);
assert(details.some(d => d.startsWith('warn:处置:同时配置了失败打回和失败分支')), details);
const joinDiag = plain(context.flowBranchDiagnostics({
  nodes: [{id: 'a', name: 'A'}, {id: 'b', name: 'B', runIf: 'trigger.x == 1'}, {id: 'c', name: 'C'}, {id: 'd', name: 'D', join: 'any'}],
  edges: [{id: '1', source: 'a', target: 'b'}, {id: '2', source: 'a', target: 'c', when: 'error'}, {id: '3', source: 'b', target: 'c'},
          {id: '4', source: 'b', target: 'd'}, {id: '5', source: 'a', target: 'd', when: 'error'}],
})).map(d => `${d.level}:${d.title}:${d.detail}`);
assert(joinDiag.some(d => d.startsWith('warn:C:多个上游里有条件分支或失败分支')), joinDiag);
assert(!joinDiag.some(d => d.startsWith('warn:D:多个上游')), joinDiag);
const agentDiag = plain(context.flowBranchDiagnostics({
  nodes: [{id: 'judge', name: '研判 Agent', type: 'agent'}, {id: 'act', name: '处置', type: 'script', runIf: 'nodes.judge.data.verdict == "bad"'}],
  edges: [{id: '1', source: 'judge', target: 'act'}],
})).map(d => `${d.level}:${d.title}:${d.detail}`);
assert(agentDiag.some(d => d.startsWith('warn:处置:条件读取的「研判 Agent」没有声明输出结构')), agentDiag);
assert.deepEqual(plain(context.flowSampleFromSchema({type: 'object', properties: {verdict: {enum: ['malicious', 'benign']}, score: {type: 'number'}, tags: {type: 'array', items: {type: 'string'}}, ok: {type: 'boolean'}}})),
  {verdict: 'malicious', score: 1, tags: [''], ok: true});
const sampleWf = {nodes: [{id: 'triage', name: '研判', type: 'agent', outputSchema: {type: 'object', properties: {verdict: {enum: ['bad']}}}}, {id: 'raw', name: '原始', type: 'script'}, {id: 'act', name: '处置', type: 'script', runIf: 'nodes.triage.data.verdict == "bad" && nodes.raw.status == "succeeded"'}],
  edges: [{id: '1', source: 'triage', target: 'act', when: 'success'}, {id: '2', source: 'raw', target: 'act'}]};
const act = sampleWf.nodes[2];
assert.deepEqual(plain(context.flowConditionSampleNodes(sampleWf, act)), {triage: {status: 'succeeded', data: {verdict: 'bad'}}, raw: {status: 'succeeded'}});
const req = plain(context.flowConditionCheckRequest(sampleWf, act, '{"severity":"high"}', '{"triage":{"data":{"verdict":"bad"}}}'));
assert.equal(req.body.expression, act.runIf);
assert.deepEqual(req.body.trigger, {severity: 'high'});
assert.equal(req.body.nodeId, 'act');
assert.equal(req.body.workflow.edges.length, 2);
assert.equal(req.body.workflow.nodes[0].outputSchema, undefined);
assert.equal(plain(context.flowConditionCheckRequest(sampleWf, act, '', '')).body.trigger, undefined);
assert.match(context.flowConditionCheckRequest(sampleWf, act, '[1]', '').error, /示例触发负载必须是 JSON 对象/);
assert.match(context.flowConditionCheckRequest(sampleWf, act, '', '{bad').error, /示例上游结果不是合法 JSON/);
assert.deepEqual(plain(context.flowConditionCheckText({valid: true, result: true})), {text: '条件成立：本步骤会执行', bad: false});
assert.equal(context.flowConditionCheckText({valid: true, result: false}).bad, false);
assert.match(context.flowConditionCheckText({valid: false, stage: 'reference', error: 'x'}).text, /条件有误/);
assert.match(context.flowConditionCheckText({valid: true, stage: 'evaluate', error: 'x'}).text, /运行时本步骤会失败/);
console.log('flow branching ok');
