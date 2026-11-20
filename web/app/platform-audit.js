// 平台管理 → 审计日志: who did what through which credential, with filters
// and CSV / JSON export. Only platform administrators reach this tab.

const AUDIT_OUTCOME_TEXT={success:'成功',failure:'失败',denied:'拒绝'};
// Turns an audit action into a short Chinese label; API writes keep their
// method and route.
function auditActionText(action){
  const named={'auth.login':'密码登录','auth.login.local':'本地登录','auth.login.exchange':'登录交换','auth.login.oauth':'OAuth 登录','auth.register':'注册账号','auth.setup':'初始化管理员','auth.logout':'退出登录','auth.token.create':'创建访问密钥','auth.token.revoke':'撤销访问密钥','connector.action':'连接器动作'};
  if(named[action])return named[action];
  const m=/^api (\w+) (.+)$/.exec(String(action||''));
  return m?`${m[1]} ${m[2]}`:String(action||'');
}
// Builds the query string for the list and export endpoints.
function auditQuery(filter,extra){
  const p=new URLSearchParams();
  for(const k of ['from','to','action','outcome','projectId','actorUserId']){const v=String((filter||{})[k]||'').trim();if(v)p.set(k,v)}
  for(const [k,v] of Object.entries(extra||{}))p.set(k,v);
  const s=p.toString();return s?'?'+s:'';
}
function auditActorText(e){
  if(e.actorKind==='system')return '系统'+(e.actorUserId?` · 代用户 #${e.actorUserId}`:'');
  const who=e.actorLogin||(e.actorUserId?`用户 #${e.actorUserId}`:'匿名');
  return e.tokenId?`${who} · 访问密钥`:who;
}

const auditState={filter:{outcome:''},list:[],loading:false,error:''};

async function loadPlatformAudit(){
  const host=$('#platformAuditHost');if(!host)return;
  auditState.loading=true;renderPlatformAudit();
  try{auditState.list=await api('/api/audit'+auditQuery(auditState.filter,{limit:'300'}),{silent:true});auditState.error=''}
  catch(e){auditState.error=e.message;auditState.list=[]}
  auditState.loading=false;renderPlatformAudit();
}
function renderPlatformAudit(){
  const host=$('#platformAuditHost');if(!host)return;
  const f=auditState.filter;
  const rows=auditState.list.map(e=>`<tr class="audit-${escapeHTML(e.outcome)}"><td>${escapeHTML(new Date(e.at).toLocaleString())}</td><td>${escapeHTML(auditActorText(e))}</td><td title="${escapeHTML(e.target||'')}">${escapeHTML(auditActionText(e.action))}</td><td>${escapeHTML(e.projectId||'')}</td><td><span class="audit-outcome">${escapeHTML(AUDIT_OUTCOME_TEXT[e.outcome]||e.outcome)}</span>${e.status?` <small>${e.status}</small>`:''}</td><td>${escapeHTML(e.ip||'')}</td></tr>`).join('');
  host.innerHTML=`<form class="audit-filters" id="auditFilters">
      <label class="field"><span>开始日期</span><input class="input" type="date" name="from" value="${escapeHTML(f.from||'')}"></label>
      <label class="field"><span>结束日期</span><input class="input" type="date" name="to" value="${escapeHTML(f.toLabel||'')}"></label>
      <label class="field"><span>动作前缀</span><input class="input" name="action" value="${escapeHTML(f.action||'')}" placeholder="auth. / api POST / connector."></label>
      <label class="field"><span>结果</span><select class="select" name="outcome"><option value="">全部</option>${Object.entries(AUDIT_OUTCOME_TEXT).map(([v,l])=>`<option value="${v}" ${f.outcome===v?'selected':''}>${l}</option>`).join('')}</select></label>
      <div class="audit-actions"><button type="submit" class="button primary small">筛选</button><a class="button ghost small" href="/api/audit/export${escapeHTML(auditQuery(f,{format:'csv'}))}">导出 CSV</a><a class="button ghost small" href="/api/audit/export${escapeHTML(auditQuery(f,{format:'json'}))}">导出 JSON</a></div>
    </form>
    <p class="prop-hint">记录登录、访问密钥变更、所有写操作、被拒绝的请求和连接器动作；不记录请求内容。默认保留 365 天（AGENTFLOW_AUDIT_RETENTION_DAYS）。列表显示最近 300 条，导出最多 10000 条。</p>
    ${auditState.error?`<p class="case-form-error">${escapeHTML(auditState.error)}</p>`:''}
    ${auditState.loading?'<p class="prop-hint">加载中…</p>':`<div class="audit-table-wrap"><table class="audit-table"><thead><tr><th>时间</th><th>操作者</th><th>动作</th><th>项目</th><th>结果</th><th>来源</th></tr></thead><tbody>${rows||'<tr><td colspan="6">没有记录</td></tr>'}</tbody></table></div>`}`;
  host.querySelector('#auditFilters').onsubmit=e=>{
    e.preventDefault();const el=e.target.elements;
    auditState.filter={from:el.from.value,to:el.to.value?new Date(new Date(el.to.value).getTime()+86400000).toISOString().slice(0,10):'',action:el.action.value.trim(),outcome:el.outcome.value};
    if(el.to.value)auditState.filter.toLabel=el.to.value;
    loadPlatformAudit();
  };
}
