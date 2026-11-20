// Security alerts and cases: the 告警与案件 view.

const CASE_SEVERITIES=[['critical','严重'],['high','高'],['medium','中'],['low','低']];
const CASE_STATUSES=[['new','新建'],['investigating','分析中'],['pending_response','待响应'],['closed','已关闭']];
const CASE_RESOLUTIONS=[['false_positive','误报'],['resolved','已处置'],['duplicate','重复']];
const CASE_TRIGGER_EVENTS=[['case.created','案件新建'],['case.alert_added','新告警并入'],['case.escalated','升级为高危及以上'],['case.severity_changed','严重度变化'],['case.status_changed','状态变化']];
const CASE_IOC_TYPES=['ipv4','domain','url','email','md5','sha1','sha256','cve'];

function caseSeverityText(s){return (CASE_SEVERITIES.find(x=>x[0]===s)||[s,s||'—'])[1]}
function caseStatusText(status,resolution){
  const base=(CASE_STATUSES.find(x=>x[0]===status)||[status,status||'—'])[1];
  const res=CASE_RESOLUTIONS.find(x=>x[0]===resolution);
  return res?`${base} · ${res[1]}`:base;
}
function caseActorText(e){
  if(e?.actorKind==='system')return '系统';
  if(e?.actorKind==='service')return '外部调用';
  if(e?.actorKind==='bot')return `机器人 · 用户 #${e.actorUserId||''}`;
  return e?.actorUserId?`用户 #${e.actorUserId}`:'—';
}
// Builds the PUT body for the case header form; only changed fields are sent.
function caseUpdateBody(current,form){
  const body={};
  if(form.severity&&form.severity!==current.severity)body.severity=form.severity;
  if(form.status&&form.status!==current.status)body.status=form.status;
  const resolution=form.status==='closed'?(form.resolution||''):'';
  if(form.status==='closed'&&resolution!==(current.resolution||''))body.resolution=resolution;
  return body;
}
function caseTriggerBody(form){
  return {projectId:form.projectId,workflowId:form.workflowId,name:String(form.name||'').trim(),enabled:form.enabled!==false,events:(form.events||[]).filter(Boolean),...(form.minSeverity?{minSeverity:form.minSeverity}:{})};
}

const casesState={tab:'cases',filter:'open',uncased:true,cases:[],alerts:[],triggers:[],detail:null,detailTab:'timeline',alertOpen:'',loading:false,error:''};

function casesProject(){return state.projectFilter||''}

async function loadCasesView(){
  const host=$('#casesBody');if(!host)return;
  const project=casesProject();
  if(!project){casesState.error='';host.innerHTML='<div class="empty-inline"><p>先在顶部选择一个项目，再查看它的告警与案件。</p></div>';return}
  casesState.loading=true;casesState.error='';renderCasesView();
  try{
    if(casesState.tab==='cases')casesState.cases=await api(`/api/cases?projectId=${encodeURIComponent(project)}&status=${encodeURIComponent(casesState.filter==='all'?'':casesState.filter)}`,{silent:true});
    if(casesState.tab==='alerts')casesState.alerts=await api(`/api/alerts?projectId=${encodeURIComponent(project)}${casesState.uncased?'&uncased=true':''}`,{silent:true});
    if(casesState.tab==='triggers')casesState.triggers=await api(`/api/case-triggers?projectId=${encodeURIComponent(project)}`,{silent:true});
  }catch(e){casesState.error=e.message}
  casesState.loading=false;renderCasesView();
}

async function openCase(id){
  try{casesState.detail=await api(`/api/cases/${encodeURIComponent(id)}`,{silent:true});casesState.detailTab=casesState.detailTab||'timeline'}
  catch(e){toast(e.message);return}
  renderCasesView();
}

function caseSeverityPill(s){return `<span class="case-sev sev-${escapeHTML(s||'medium')}">${escapeHTML(caseSeverityText(s))}</span>`}

function casesListHTML(){
  if(!casesState.cases.length)return `<div class="empty-inline"><p>${casesState.filter==='open'?'没有未关闭的案件。':'没有案件。'}Webhook 可以按指纹自动建案，也可以在告警队列里把告警升级为案件。</p></div>`;
  return `<div class="case-table">${casesState.cases.map(c=>`<button type="button" class="case-row${casesState.detail?.case?.id===c.id?' active':''}" data-open-case="${escapeHTML(c.id)}"><span class="case-no">#${c.number}</span>${caseSeverityPill(c.severity)}<b>${escapeHTML(c.title)}</b><span class="case-status st-${escapeHTML(c.status)}">${escapeHTML(caseStatusText(c.status,c.resolution))}</span><span class="case-meta">${c.alertCount} 条告警 · ${escapeHTML(new Date(c.updatedAt).toLocaleString())}</span></button>`).join('')}</div>`;
}

function alertsListHTML(){
  if(!casesState.alerts.length)return `<div class="empty-inline"><p>${casesState.uncased?'没有待处理的告警。':'还没有告警。'}在流程设置里为 SOP 创建 Webhook 后，外部告警会出现在这里。</p></div>`;
  return `<div class="case-table">${casesState.alerts.map(a=>`<div class="alert-row">${caseSeverityPill(a.severity)}<b title="${escapeHTML(a.title)}">${escapeHTML(a.title)}</b><span class="case-meta">${escapeHTML(a.source||'')} · ${escapeHTML(new Date(a.receivedAt).toLocaleString())}${a.duplicate?' · 重复':''}</span>${a.caseId?`<button type="button" class="button ghost small" data-open-case="${escapeHTML(a.caseId)}">查看案件</button>`:`<button type="button" class="button ghost small" data-escalate="${escapeHTML(a.id)}">升级为案件</button>`}${a.runId?`<button type="button" class="link" data-open-run="${escapeHTML(a.runId)}">运行</button>`:''}</div>`).join('')}</div>`;
}

function triggersHTML(){
  const workflows=(state.data?.workflows||[]).filter(w=>w.projectId===casesProject());
  const list=casesState.triggers.map(t=>`<div class="trigger-row" data-trigger="${escapeHTML(t.id)}"><b>${escapeHTML(t.name)}</b><span class="case-meta">启动「${escapeHTML((workflows.find(w=>w.id===t.workflowId)||{name:t.workflowId}).name)}」 · ${t.events.map(e=>escapeHTML((CASE_TRIGGER_EVENTS.find(x=>x[0]===e)||[e,e])[1])).join('、')}${t.minSeverity?` · 不低于${escapeHTML(caseSeverityText(t.minSeverity))}`:''}</span><label class="fd-check"><input type="checkbox" data-trigger-toggle ${t.enabled?'checked':''}><span>启用</span></label><button type="button" class="button ghost small danger" data-trigger-delete>删除</button></div>`).join('')||'<p class="prop-hint">还没有触发器。</p>';
  return `<p class="prop-hint">案件发生下列事件时自动启动所选 SOP，运行以触发器创建者身份执行，触发负载里包含案件、告警和 IOC。同一触发器对同一案件的上一次运行未结束时不会重复启动，单个案件最多触发 20 次。</p>${list}
  <form class="trigger-form" id="caseTriggerForm"><h4>新建触发器</h4>
    <label class="field"><span>名称</span><input class="input" name="name" maxlength="120" required placeholder="例如：高危案件自动遏制"></label>
    <label class="field"><span>启动的 SOP</span><select class="select" name="workflowId" required>${workflows.map(w=>`<option value="${escapeHTML(w.id)}">${escapeHTML(w.name)}</option>`).join('')}</select></label>
    <div class="trigger-events"><span>事件</span>${CASE_TRIGGER_EVENTS.map(([v,l])=>`<label class="fd-check"><input type="checkbox" name="event" value="${v}" ${v==='case.created'?'checked':''}><span>${l}</span></label>`).join('')}</div>
    <label class="field"><span>最低严重度（可选）</span><select class="select" name="minSeverity"><option value="">不限</option>${CASE_SEVERITIES.map(([v,l])=>`<option value="${v}">${l}</option>`).join('')}</select></label>
    <p class="case-form-error" role="alert"></p><button type="submit" class="button primary small">创建触发器</button></form>`;
}

function caseTimelineHTML(d){
  return `<div class="case-timeline">${d.events.map(e=>`<div class="case-ev ev-${escapeHTML(e.type.replace('case.',''))}"><span class="case-ev-time">${escapeHTML(new Date(e.createdAt).toLocaleString())}</span><span class="case-ev-actor">${escapeHTML(caseActorText(e))}</span><p>${escapeHTML(e.message)}</p></div>`).join('')}</div>
  <form class="case-comment" id="caseCommentForm"><textarea class="input" name="body" rows="3" maxlength="10000" placeholder="写下研判过程、证据或结论"></textarea><button type="submit" class="button primary small">添加评论</button></form>`;
}

function caseAlertsHTML(d){
  return d.alerts.map(a=>`<div class="case-alert">${caseSeverityPill(a.severity)}<b>${escapeHTML(a.title)}</b><span class="case-meta">${escapeHTML(a.source||'')} · ${escapeHTML(new Date(a.receivedAt).toLocaleString())}${a.duplicate?' · 重复':''}</span><button type="button" class="link" data-alert-payload="${escapeHTML(a.id)}">${casesState.alertOpen===a.id?'收起负载':'查看负载'}</button>${casesState.alertOpen===a.id&&casesState.alertPayload?`<pre class="case-payload">${escapeHTML(JSON.stringify(casesState.alertPayload,null,2))}</pre>`:''}</div>`).join('')||'<p class="prop-hint">没有告警。</p>';
}

function caseIOCsHTML(d){
  return `<table class="case-iocs"><thead><tr><th>类型</th><th>值</th><th>首次出现</th></tr></thead><tbody>${d.iocs.map(i=>`<tr><td>${escapeHTML(i.type)}</td><td><code>${escapeHTML(i.value)}</code></td><td>${escapeHTML(new Date(i.firstSeen).toLocaleString())}</td></tr>`).join('')||'<tr><td colspan="3">没有 IOC</td></tr>'}</tbody></table>
  <form class="case-ioc-form" id="caseIOCForm"><select class="select" name="type">${CASE_IOC_TYPES.map(t=>`<option>${t}</option>`).join('')}</select><input class="input" name="value" required placeholder="IOC 值"><button type="submit" class="button ghost small">添加 IOC</button></form>`;
}

function caseRunsHTML(d){
  const workflows=(state.data?.workflows||[]).filter(w=>w.projectId===d.case.projectId);
  return `${d.runs.map(r=>`<div class="case-run"><button type="button" class="link" data-open-run="${escapeHTML(r.id)}">${escapeHTML(r.id)}</button><span>${escapeHTML((workflows.find(w=>w.id===r.workflowId)||{name:r.workflowId}).name)}</span><span class="status ${escapeHTML(r.status)}">${escapeHTML(typeof statusText==='function'?(statusText(r.status)||r.status):r.status)}</span><span class="case-meta">${escapeHTML(new Date(r.createdAt).toLocaleString())}</span></div>`).join('')||'<p class="prop-hint">还没有关联的运行。</p>'}
  <form class="case-run-form" id="caseRunForm"><select class="select" name="workflowId">${workflows.map(w=>`<option value="${escapeHTML(w.id)}">${escapeHTML(w.name)}</option>`).join('')}</select><button type="submit" class="button ghost small" ${workflows.length?'':'disabled'}>对此案件运行 SOP</button></form>`;
}

function caseDetailHTML(){
  const d=casesState.detail;if(!d)return '';
  const c=d.case,tab=casesState.detailTab;
  const tabs=[['timeline',`时间线 ${d.events.length}`],['alerts',`告警 ${d.alerts.length}`],['iocs',`IOC ${d.iocs.length}`],['runs',`运行 ${d.runs.length}`]];
  const body=tab==='alerts'?caseAlertsHTML(d):tab==='iocs'?caseIOCsHTML(d):tab==='runs'?caseRunsHTML(d):caseTimelineHTML(d);
  return `<aside class="case-detail"><header><div><span class="case-no">#${c.number}</span>${caseSeverityPill(c.severity)}<h2>${escapeHTML(c.title)}</h2></div><button type="button" class="button ghost small" data-close-case>关闭</button></header>
    <form class="case-head-form" id="caseHeadForm">
      <label class="field"><span>严重度</span><select class="select" name="severity">${CASE_SEVERITIES.map(([v,l])=>`<option value="${v}" ${v===c.severity?'selected':''}>${l}</option>`).join('')}</select></label>
      <label class="field"><span>状态</span><select class="select" name="status">${CASE_STATUSES.map(([v,l])=>`<option value="${v}" ${v===c.status?'selected':''}>${l}</option>`).join('')}</select></label>
      <label class="field" data-resolution ${c.status==='closed'?'':'hidden'}><span>结论</span><select class="select" name="resolution"><option value="">请选择</option>${CASE_RESOLUTIONS.map(([v,l])=>`<option value="${v}" ${v===c.resolution?'selected':''}>${l}</option>`).join('')}</select></label>
      <button type="submit" class="button primary small">保存</button><span class="case-form-error" role="alert"></span>
    </form>
    ${c.description?`<p class="case-desc">${escapeHTML(c.description)}</p>`:''}
    <div class="case-tabs" role="tablist">${tabs.map(([k,l])=>`<button type="button" role="tab" class="${k===tab?'active':''}" data-case-tab="${k}">${escapeHTML(l)}</button>`).join('')}</div>
    <div class="case-tab-body">${body}</div></aside>`;
}

function renderCasesView(){
  const host=$('#casesBody');if(!host)return;
  if(!casesProject())return;
  $$('#casesView [data-cases-tab]').forEach(b=>b.classList.toggle('active',b.dataset.casesTab===casesState.tab));
  const filters=casesState.tab==='cases'?`<div class="case-filters">${[['open','未关闭'],['closed','已关闭'],['all','全部']].map(([v,l])=>`<button type="button" class="${casesState.filter===v?'active':''}" data-case-filter="${v}">${l}</button>`).join('')}<button type="button" class="button ghost small" data-new-case>+ 新建案件</button></div>`
    :casesState.tab==='alerts'?`<div class="case-filters"><label class="fd-check"><input type="checkbox" data-uncased ${casesState.uncased?'checked':''}><span>只看未建案的告警</span></label></div>`:'';
  const list=casesState.tab==='cases'?casesListHTML():casesState.tab==='alerts'?alertsListHTML():triggersHTML();
  host.innerHTML=`${casesState.error?`<p class="case-form-error">${escapeHTML(casesState.error)}</p>`:''}${filters}<div class="cases-layout${casesState.detail&&casesState.tab!=='triggers'?' with-detail':''}"><div class="cases-list">${casesState.loading?'<p class="prop-hint">加载中…</p>':list}</div>${casesState.tab!=='triggers'?caseDetailHTML():''}</div>`;
  bindCasesView(host);
}

async function refreshCaseDetail(){if(casesState.detail)await openCase(casesState.detail.case.id);await loadCasesView()}

function bindCasesView(host){
  host.querySelectorAll('[data-open-case]').forEach(b=>b.onclick=()=>{if(casesState.tab!=='cases'){casesState.tab='cases'}openCase(b.dataset.openCase)});
  host.querySelectorAll('[data-open-run]').forEach(b=>b.onclick=()=>{location.hash='#/runs/'+b.dataset.openRun});
  host.querySelectorAll('[data-case-filter]').forEach(b=>b.onclick=()=>{casesState.filter=b.dataset.caseFilter;loadCasesView()});
  host.querySelector('[data-uncased]')?.addEventListener('change',e=>{casesState.uncased=e.target.checked;loadCasesView()});
  host.querySelector('[data-close-case]')?.addEventListener('click',()=>{casesState.detail=null;renderCasesView()});
  host.querySelectorAll('[data-case-tab]').forEach(b=>b.onclick=()=>{casesState.detailTab=b.dataset.caseTab;renderCasesView()});
  host.querySelector('[data-new-case]')?.addEventListener('click',async()=>{
    const title=await afPrompt({title:'新建案件',message:'案件标题：',defaultValue:''});if(!title)return;
    try{const c=await api('/api/cases',{method:'POST',body:JSON.stringify({projectId:casesProject(),title,severity:'medium'})});await loadCasesView();openCase(c.id)}catch(e){toast(e.message)}
  });
  host.querySelectorAll('[data-escalate]').forEach(b=>b.onclick=async()=>{
    try{const c=await api(`/api/alerts/${encodeURIComponent(b.dataset.escalate)}/escalate`,{method:'POST',body:'{}'});toast(`已创建案件 #${c.number}`);casesState.tab='cases';await loadCasesView();openCase(c.id)}catch(e){toast(e.message)}
  });
  host.querySelectorAll('[data-alert-payload]').forEach(b=>b.onclick=async()=>{
    const id=b.dataset.alertPayload;
    if(casesState.alertOpen===id){casesState.alertOpen='';renderCasesView();return}
    try{const a=await api(`/api/alerts/${encodeURIComponent(id)}`,{silent:true});casesState.alertOpen=id;casesState.alertPayload=a.payload;renderCasesView()}catch(e){toast(e.message)}
  });
  const head=host.querySelector('#caseHeadForm');
  if(head){
    const status=head.elements.status,res=head.querySelector('[data-resolution]');
    status.onchange=()=>{res.hidden=status.value!=='closed'};
    head.onsubmit=async e=>{
      e.preventDefault();
      const err=head.querySelector('.case-form-error'),c=casesState.detail.case;
      const body=caseUpdateBody(c,{severity:head.elements.severity.value,status:status.value,resolution:head.elements.resolution.value});
      if(!Object.keys(body).length){err.textContent='没有改动';return}
      if(status.value==='closed'&&!head.elements.resolution.value){err.textContent='关闭案件需要选择结论';return}
      try{await api(`/api/cases/${encodeURIComponent(c.id)}`,{method:'PUT',body:JSON.stringify(body)});toast('已更新案件');await refreshCaseDetail()}catch(ex){err.textContent=ex.message}
    };
  }
  host.querySelector('#caseCommentForm')?.addEventListener('submit',async e=>{
    e.preventDefault();const body=e.target.elements.body.value.trim();if(!body)return;
    try{await api(`/api/cases/${encodeURIComponent(casesState.detail.case.id)}/comments`,{method:'POST',body:JSON.stringify({body})});await openCase(casesState.detail.case.id)}catch(ex){toast(ex.message)}
  });
  host.querySelector('#caseIOCForm')?.addEventListener('submit',async e=>{
    e.preventDefault();const f=e.target.elements;
    try{await api(`/api/cases/${encodeURIComponent(casesState.detail.case.id)}/iocs`,{method:'POST',body:JSON.stringify({type:f.type.value,value:f.value.value})});casesState.detailTab='iocs';await openCase(casesState.detail.case.id)}catch(ex){toast(ex.message)}
  });
  host.querySelector('#caseRunForm')?.addEventListener('submit',async e=>{
    e.preventDefault();
    try{const r=await api(`/api/cases/${encodeURIComponent(casesState.detail.case.id)}/runs`,{method:'POST',body:JSON.stringify({workflowId:e.target.elements.workflowId.value})});toast('已启动运行 '+r.runId);casesState.detailTab='runs';await openCase(casesState.detail.case.id)}catch(ex){toast(ex.message)}
  });
  host.querySelector('#caseTriggerForm')?.addEventListener('submit',async e=>{
    e.preventDefault();const f=e.target,err=f.querySelector('.case-form-error');
    const body=caseTriggerBody({projectId:casesProject(),workflowId:f.elements.workflowId.value,name:f.elements.name.value,minSeverity:f.elements.minSeverity.value,events:[...f.querySelectorAll('[name=event]:checked')].map(b=>b.value)});
    try{await api('/api/case-triggers',{method:'POST',body:JSON.stringify(body)});toast('已创建触发器');loadCasesView()}catch(ex){err.textContent=ex.message}
  });
  host.querySelectorAll('[data-trigger]').forEach(row=>{
    const t=casesState.triggers.find(x=>x.id===row.dataset.trigger);
    row.querySelector('[data-trigger-toggle]').onchange=async e=>{try{await api(`/api/case-triggers/${encodeURIComponent(t.id)}`,{method:'PUT',body:JSON.stringify({...t,enabled:e.target.checked})});loadCasesView()}catch(ex){toast(ex.message)}};
    row.querySelector('[data-trigger-delete]').onclick=async()=>{if(!await afConfirm({title:'删除触发器',message:`删除「${t.name}」？已启动的运行不受影响。`,confirmText:'删除',danger:true}))return;try{await api(`/api/case-triggers/${encodeURIComponent(t.id)}`,{method:'DELETE'});loadCasesView()}catch(ex){toast(ex.message)}};
  });
}

function bindCasesTabs(){
  $$('#casesView [data-cases-tab]').forEach(b=>b.onclick=()=>{casesState.tab=b.dataset.casesTab;if(casesState.tab==='triggers')casesState.detail=null;loadCasesView()});
  $('#refreshCases')?.addEventListener('click',()=>refreshCaseDetail());
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bindCasesTabs);else bindCasesTabs();
