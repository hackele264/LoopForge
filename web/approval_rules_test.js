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
const context = {escapeHTML: s => String(s)};
vm.createContext(context);
vm.runInContext("const APPROVAL_TIMEOUT_MAX_MINUTES=43200;const FLOW_APPROVER_ROLES=[['owner','项目 Owner'],['member','项目成员']];", context);
for (const name of ['flowApproversFromForm', 'approvalRuleFromForm', 'approvalRuleProblem', 'approvalRuleTags', 'approvalRuleFieldHTML', 'approvalVoterText', 'approvalProgressRows', 'approvalProgressSectionHTML', 'approvalToast']) {
  vm.runInContext(source(name), context);
}
const plain = v => JSON.parse(JSON.stringify(v));

// The form keeps absent fields absent: a default gate saves no rule.
assert.equal(context.approvalRuleFromForm({required: '1', timeout: ''}), null);
assert.deepEqual(plain(context.approvalRuleFromForm({required: '2', timeout: ''})), {requiredApprovals: 2});
assert.deepEqual(plain(context.approvalRuleFromForm({required: '9', timeout: '30', onTimeout: 'escalate', escalateUsers: '7, 7 8', escalateRoles: ['owner', 'bogus']})),
  {requiredApprovals: 3, timeoutMinutes: 30, onTimeout: 'escalate', escalateTo: {userIds: [7, 8], roles: ['owner']}});
assert.deepEqual(plain(context.approvalRuleFromForm({required: '1', timeout: '99999', onTimeout: 'reject', escalateUsers: '7'})), {timeoutMinutes: 43200, onTimeout: 'reject'});

assert.match(context.approvalRuleProblem({approvers: {userIds: [1]}, approval: {requiredApprovals: 2}}), /只有 1 人/);
assert.equal(context.approvalRuleProblem({approvers: {userIds: [1], roles: ['member']}, approval: {requiredApprovals: 2}}), '');
assert.match(context.approvalRuleProblem({approval: {timeoutMinutes: 5, onTimeout: 'escalate'}}), /升级给谁/);
assert.deepEqual(plain(context.approvalRuleTags({requiredApprovals: 2, timeoutMinutes: 60, onTimeout: 'reject'})), ['2 人批准', '超时 60 分钟自动拒绝']);
assert.deepEqual(plain(context.approvalRuleTags(undefined)), []);

const html = context.approvalRuleFieldHTML({id: 'g', approval: {requiredApprovals: 2, timeoutMinutes: 15, onTimeout: 'escalate', escalateTo: {roles: ['owner'], userIds: [4]}}});
assert.match(html, /<option value="2" selected>/);
assert.match(html, /value="15"/);
assert.match(html, /data-escalate-role="owner" checked/);
assert.doesNotMatch(html, /data-approval-escalate hidden/);
assert.match(context.approvalRuleFieldHTML({id: 'g'}), /data-approval-timed hidden/);

const nr = {status: 'waiting_approval', approval: {required: 2, votes: [{userId: 8, login: 'alice', at: '2026-01-01T00:00:00Z'}], deadline: '2026-01-01T01:00:00Z', onTimeout: 'escalate', escalated: true}};
const rows = plain(context.approvalProgressRows(nr));
assert.deepEqual(rows[0], ['审批进度', '已批准 1/2']);
assert.match(rows[1][1], /^alice/);
assert.equal(rows[2][0], '审批截止');
assert.equal(rows[3][0], '升级');
assert.match(context.approvalProgressSectionHTML(nr), /已批准 1\/2/);
assert.equal(context.approvalProgressSectionHTML({status: 'succeeded', approval: nr.approval}), '');
assert.deepEqual(plain(context.approvalProgressRows({status: 'waiting_approval'})), []);

assert.match(context.approvalToast({ok: true, approval: {approved: false, approvals: 1, required: 2}}), /1\/2/);
assert.equal(context.approvalToast({ok: true, approval: {approved: true, approvals: 2, required: 2}}), '');
assert.equal(context.approvalToast({ok: true}), '');
assert.equal(context.approvalToast(undefined), '');
