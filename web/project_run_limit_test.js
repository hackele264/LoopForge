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
const context = {escapeHTML: s => String(s).replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]))};
vm.createContext(context);
for (const name of ['paRow', 'projectRunLimitText', 'projectRunLimitBody', 'projectRunLimitHTML']) vm.runInContext(source(name), context);

assert.equal(context.projectRunLimitText(null), '读取中…');
assert.equal(context.projectRunLimitText({runLimit: 0, defaultLimit: 10, effectiveLimit: 10}), '10 条（平台默认）');
assert.equal(context.projectRunLimitText({runLimit: 30, defaultLimit: 10, effectiveLimit: 30}), '30 条（本项目设定，平台默认 10 条）');

assert.deepEqual(JSON.parse(JSON.stringify(context.projectRunLimitBody('', 200))), {runLimit: 0});
assert.deepEqual(JSON.parse(JSON.stringify(context.projectRunLimitBody(' 25 ', 200))), {runLimit: 25});
assert.throws(() => context.projectRunLimitBody('2.5', 200), /0-200/);
assert.throws(() => context.projectRunLimitBody('201', 200), /0-200/);
assert.throws(() => context.projectRunLimitBody('-1', 200), /0-200/);

const view = {runLimit: 0, defaultLimit: 10, effectiveLimit: 10, maxLimit: 200};
const admin = context.projectRunLimitHTML(view, true);
assert.match(admin, /data-run-limit-input/);
assert.match(admin, /placeholder="平台默认 10"/);
assert.doesNotMatch(admin, /name="runLimit"/, 'the input stays out of the project settings form fields');
const member = context.projectRunLimitHTML(view, false);
assert.doesNotMatch(member, /data-run-limit-input/);
assert.match(member, /由平台管理员调整/);
console.log('project run limit ok');
