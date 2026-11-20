// Two-person approval and timed escalation of approval nodes: the designer
// fields for node.approval (ApprovalRule) and the run views of
// nodeRun.approval (ApprovalState). See docs/conditional-workflows.md.
const APPROVAL_TIMEOUT_MAX_MINUTES=43200;
function approvalRuleFieldHTML(n){
  const rule=n.approval||{},on=rule.onTimeout||'escalate',esc=rule.escalateTo||{},required=rule.requiredApprovals||1;
  const roles=esc.roles||[],ids=(esc.userIds||[]).join(', '),timed=(rule.timeoutMinutes||0)>0;
  const problem=approvalRuleProblem(n);
  return `<div class="fd-field"><label>需要几人批准</label><select class="select" id="approvalRequired">${[1,2,3].map(v=>`<option value="${v}" ${required===v?'selected':''}>${v===1?'1 人（默认）':`${v} 位不同的人`}</option>`).join('')}</select><p class="prop-hint${problem?' fd-hint-err':''}" id="approvalRuleCheck">${escapeHTML(problem||'多人审批时同一个人不能批准两次，只接受具名用户；任何一位审批人打回都会立即生效。')}</p></div>`
    +`<div class="fd-field"><label>审批时限（分钟，可选）</label><input class="input" id="approvalTimeout" type="number" min="1" max="${APPROVAL_TIMEOUT_MAX_MINUTES}" inputmode="numeric" placeholder="留空表示不限时" value="${timed?rule.timeoutMinutes:''}"></div>`
    +`<div class="fd-field" data-approval-timed ${timed?'':'hidden'}><label>超时后</label><select class="select" id="approvalOnTimeout"><option value="escalate" ${on==='escalate'?'selected':''}>升级给其他审批人</option><option value="reject" ${on==='reject'?'selected':''}>自动拒绝</option></select><p class="prop-hint">自动拒绝：配置了失败打回时打回上游，否则本步骤失败，交给失败分支，没有失败分支时运行失败。</p></div>`
    +`<div class="fd-field" data-approval-escalate ${timed&&on==='escalate'?'':'hidden'}><label>升级给</label><div class="fd-checks">${FLOW_APPROVER_ROLES.map(([r,label])=>`<label class="fd-check"><input type="checkbox" data-escalate-role="${r}" ${roles.includes(r)?'checked':''}><span>${escapeHTML(label)}</span></label>`).join('')}</div><input class="input" id="escalateUserIds" inputmode="numeric" placeholder="另外指定用户 ID，逗号分隔" value="${escapeHTML(ids)}"><p class="prop-hint">超时后这些人也可以审批，原审批人仍然可以；平台会按 SOP 的待处理提醒再发一次通知。</p></div>`;
}
// Parses the approval rule form; null keeps the single-decision gate.
function approvalRuleFromForm(f){
  const required=Math.min(3,Math.max(1,Number(f.required)||1));
  const timeout=Math.floor(Number(f.timeout)||0);
  const rule={};
  if(required>1)rule.requiredApprovals=required;
  if(timeout>0){
    rule.timeoutMinutes=Math.min(APPROVAL_TIMEOUT_MAX_MINUTES,timeout);
    rule.onTimeout=f.onTimeout==='reject'?'reject':'escalate';
    if(rule.onTimeout==='escalate'){const to=flowApproversFromForm(f.escalateUsers,f.escalateRoles);if(to)rule.escalateTo=to}
  }
  return Object.keys(rule).length?rule:null;
}
// Mirrors the server validation so mistakes show while editing.
function approvalRuleProblem(n){
  const rule=n?.approval;if(!rule)return '';
  const users=new Set(n.approvers?.userIds||[]);
  if((rule.requiredApprovals||1)>1&&!(n.approvers?.roles||[]).length&&users.size&&rule.requiredApprovals>users.size)return `需要 ${rule.requiredApprovals} 人批准，但审批人名单只有 ${users.size} 人`;
  if(rule.timeoutMinutes&&rule.onTimeout==='escalate'&&!(rule.escalateTo?.userIds||[]).length&&!(rule.escalateTo?.roles||[]).length)return '超时升级需要选择升级给谁';
  return '';
}
function approvalRuleTags(rule){
  if(!rule)return [];
  const tags=[];
  if((rule.requiredApprovals||1)>1)tags.push(`${rule.requiredApprovals} 人批准`);
  if(rule.timeoutMinutes)tags.push(`超时 ${rule.timeoutMinutes} 分钟${rule.onTimeout==='reject'?'自动拒绝':'升级'}`);
  return tags;
}
function bindApprovalRuleFields(host,n){
  const required=host.querySelector('#approvalRequired');if(!required)return;
  const timeout=host.querySelector('#approvalTimeout'),onTimeout=host.querySelector('#approvalOnTimeout'),users=host.querySelector('#escalateUserIds');
  const roleBoxes=[...host.querySelectorAll('[data-escalate-role]')],check=host.querySelector('#approvalRuleCheck'),hint=check?.textContent||'';
  const sync=()=>{
    flowHistory.record({merge:`p:${n.id}:approval`});
    const rule=approvalRuleFromForm({required:required.value,timeout:timeout?.value,onTimeout:onTimeout?.value,escalateUsers:users?.value,escalateRoles:roleBoxes.filter(b=>b.checked).map(b=>b.dataset.escalateRole)});
    if(rule)n.approval=rule;else delete n.approval;
    const timed=!!rule?.timeoutMinutes;
    host.querySelector('[data-approval-timed]')?.toggleAttribute('hidden',!timed);
    host.querySelector('[data-approval-escalate]')?.toggleAttribute('hidden',!(timed&&rule.onTimeout==='escalate'));
    const problem=approvalRuleProblem(n);
    if(check){check.textContent=problem||hint;check.classList.toggle('fd-hint-err',!!problem)}
    dirty();renderCanvas();
  };
  required.onchange=sync;timeout&&(timeout.oninput=sync);onTimeout&&(onTimeout.onchange=sync);users&&(users.oninput=sync);roleBoxes.forEach(b=>b.onchange=sync);
}
// ---------- run views ----------
function approvalVoterText(v){
  const who=v.login||`用户 #${v.userId}`;
  return `${who}${v.escalation?'（升级审批人）':''}${v.at?` · ${new Date(v.at).toLocaleString()}`:''}`;
}
// Facts rows for the run node panel: votes N/M, voters, deadline, escalation.
function approvalProgressRows(nr){
  const st=nr?.approval;if(!st)return [];
  const rows=[];
  const required=Math.max(1,st.required||1),votes=st.votes||[];
  if(required>1)rows.push(['审批进度',`已批准 ${votes.length}/${required}`]);
  if(votes.length)rows.push(['已批准',votes.map(approvalVoterText).join('；')]);
  if(st.deadline)rows.push(['审批截止',new Date(st.deadline).toLocaleString()+(st.onTimeout==='reject'?'，超时自动拒绝':'，超时升级')]);
  if(st.escalated)rows.push(['升级',`已升级${st.escalatedAt?` · ${new Date(st.escalatedAt).toLocaleString()}`:''}，升级审批人现在也可以审批`]);
  if(st.timedOut)rows.push(['超时处理','审批超时，系统已自动拒绝']);
  return rows;
}
// Section for the waiting-approval card.
function approvalProgressSectionHTML(nr){
  if(nr?.status!=='waiting_approval')return '';
  const rows=approvalProgressRows(nr);if(!rows.length)return '';
  return `<div class="callout-section"><strong class="callout-label">审批进度</strong>${rows.map(([k,v])=>`<p class="callout-text"><b>${escapeHTML(k)}</b>：${escapeHTML(v)}</p>`).join('')}</div>`;
}
// Toast for an approve response that recorded a partial approval.
function approvalToast(res){
  const p=res?.approval;
  if(!p||p.approved)return '';
  return `已记录你的批准（${p.approvals}/${p.required}），还需其他审批人批准`;
}
