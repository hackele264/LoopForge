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
const context = {URLSearchParams, escapeHTML: s => String(s).replace(/[&<>"']/g, c => '&#' + c.charCodeAt(0) + ';')};
vm.createContext(context);
vm.runInContext(bundle.match(/^const (CASE_VERDICTS|PILOT_TARGETS)=.*$/gm).join('\n').replace(/^const /gm, 'var '), context);
for (const name of ['caseVerdictText', 'caseVerdictHTML', 'pilotPct', 'pilotDuration', 'pilotDefaultRange', 'pilotReportQuery']) vm.runInContext(source(name), context);
assert.equal(context.caseVerdictText('false_positive'), '误报');
assert.equal(context.caseVerdictHTML({}), '');
const html = context.caseVerdictHTML({agentVerdict: 'malicious', agentConfidence: 0.8, agentVerdictRunId: 'run-1', agentRationale: '<b>x</b>'});
assert(html.includes('verdict-malicious') && html.includes('置信度 0.80') && html.includes('data-open-run="run-1"') && !html.includes('<b>x</b>'), html);
assert.equal(context.pilotPct(0.995), '99.5%');
assert.equal(context.pilotDuration(42), '42 秒');
assert.equal(context.pilotDuration(270), '4.5 分钟');
assert.deepEqual(JSON.parse(JSON.stringify(context.pilotDefaultRange(Date.parse('2026-11-21T10:00:00Z')))), {from: '2026-11-08', to: '2026-11-21'});
assert.equal(context.pilotReportQuery('p 1', {from: '2026-11-08', to: '2026-11-21'}, 'csv'), '/api/pilot-report?projectId=p+1&from=2026-11-08&to=2026-11-21&format=csv');
console.log('pilot report view ok');
