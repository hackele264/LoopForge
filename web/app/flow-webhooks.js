// Webhook triggers for the open SOP, shown in the flow settings drawer.
// The URL secret is only known right after creation or rotation; the list
// shows its prefix so rotated URLs can be told apart.

// Builds the create/update body from the form's raw values.
function webhookFormBody(form){
  const list=text=>String(text||'').split(/[\s,，]+/).map(x=>x.trim()).filter(Boolean);
  const minutes=Number(form.dedupMinutes);
  const fields=list(form.dedupFields);
  const body={
    projectId:form.projectId,workflowId:form.workflowId,name:String(form.name||'').trim(),enabled:form.enabled!==false,
    methods:(form.methods||['POST']).filter(Boolean),allowedCidrs:list(form.allowedCidrs),
    titleField:String(form.titleField||'').trim(),severityField:String(form.severityField||'').trim(),caseMode:form.caseMode||'',dedupFields:fields,
    signatureHeader:String(form.signatureHeader||'').trim(),
  };
  if(fields.length&&Number.isFinite(minutes)&&minutes>0)body.dedupWindowSeconds=Math.round(minutes*60);
  if(String(form.signingSecret||'').trim())body.signingSecret=String(form.signingSecret).trim();
  return body;
}
function webhookURL(origin,path){return String(origin||'').replace(/\/+$/,'')+path}
function webhookCurlExample(url){
  return `curl -X POST '${url}' \\\n  -H 'Content-Type: application/json' \\\n  -d '{"alert":{"title":"测试告警","severity":"high"}}'`;
}
function webhookDeliveryLabel(d){
  return ({started:'已启动运行',deduplicated:'重复告警，已合并',rejected:'已拒绝',failed:'启动失败'})[d?.status]||d?.status||'';
}
// Where a delivery came from: the pulling source's name, or the caller.
function webhookDeliveryOrigin(d,sources){
  if(d?.sourceId){
    const all=sources||Object.values((typeof alertSourceState==='object'&&alertSourceState.byWebhook)||{}).flat();
    const src=all.find(s=>s.id===d.sourceId);
    return `拉取：${src?src.name:d.sourceId}${d.message?' · '+d.message:''}`;
  }
  return d?.message||d?.sourceIp||'';
}
function webhookWindowText(seconds){
  const s=Number(seconds)||0;if(!s)return '';
  return s%3600===0?`${s/3600} 小时`:s%60===0?`${s/60} 分钟`:`${s} 秒`;
}

const webhookState={list:[],loadedFor:'',revealed:null,editing:'',deliveries:{},busy:false};

async function loadWorkflowWebhooks(force){
  const wf=state.workflow,host=$('#workflowWebhookEditor');
  if(!host)return;
  const key=wf?`${wf.projectId}/${wf.id}`:'';
  if(!wf||!wf.projectId||catalogGeneric(wf)||!(state.data.workflows||[]).some(w=>w.id===wf.id)){
    webhookState.list=[];webhookState.loadedFor=key;renderWorkflowWebhooks();return;
  }
  if(!force&&webhookState.loadedFor===key){renderWorkflowWebhooks();return}
  // A revealed URL survives a reload of the same SOP's list; switching to
  // another SOP drops it so a secret is never shown next to the wrong flow.
  if(webhookState.loadedFor!==key){webhookState.revealed=null;webhookState.editing='';webhookState.deliveries={}}
  webhookState.loadedFor=key;webhookState.error='';
  try{webhookState.list=await api(`/api/webhooks?projectId=${encodeURIComponent(wf.projectId)}&workflowId=${encodeURIComponent(wf.id)}`,{silent:true})}
  catch(e){webhookState.list=[];webhookState.error=e.message}
  if(typeof loadAlertSources==='function')await loadAlertSources(wf.projectId,force);
  renderWorkflowWebhooks();
}

function webhookFormHTML(w){
  const v=w||{enabled:true,methods:['POST'],dedupWindowSeconds:3600};
  const methods=v.methods?.length?v.methods:['POST'];
  return `<form class="webhook-form" data-webhook-form="${escapeHTML(w?.id||'')}">
    <label class="field"><span>名称</span><input class="input" name="name" maxlength="120" required value="${escapeHTML(v.name||'')}" placeholder="例如：SIEM 高危告警"></label>
    <div class="webhook-row">
      <label class="field"><span>标题字段（作为运行输入）</span><input class="input mono" name="titleField" value="${escapeHTML(v.titleField||'')}" placeholder="alert.title"></label>
      <label class="field"><span>严重度字段</span><input class="input mono" name="severityField" value="${escapeHTML(v.severityField||'')}" placeholder="alert.severity"></label>
    </div>
    <label class="field"><span>建案方式</span><select class="select" name="caseMode"><option value="" ${!v.caseMode||v.caseMode==='none'?'selected':''}>只记录告警，不建案</option><option value="per_fingerprint" ${v.caseMode==='per_fingerprint'?'selected':''}>每个新指纹建一个案件，重复告警并入（需要去重字段）</option><option value="per_alert" ${v.caseMode==='per_alert'?'selected':''}>每条告警建一个案件</option></select></label>
    <div class="webhook-row">
      <label class="field"><span>去重字段（逗号分隔，留空不去重）</span><input class="input mono" name="dedupFields" value="${escapeHTML((v.dedupFields||[]).join(', '))}" placeholder="alert.rule, alert.host"></label>
      <label class="field webhook-narrow"><span>去重窗口（分钟）</span><input class="input" name="dedupMinutes" type="number" min="1" max="10080" value="${Math.round((v.dedupWindowSeconds||3600)/60)}"></label>
    </div>
    <label class="field"><span>来源地址白名单（IP 或 CIDR，留空不限）</span><input class="input mono" name="allowedCidrs" value="${escapeHTML((v.allowedCidrs||[]).join(', '))}" placeholder="10.0.0.0/8, 192.0.2.7"></label>
    <div class="webhook-methods"><span>允许的方法</span>${['POST','PUT','GET'].map(m=>`<label class="fd-check"><input type="checkbox" name="method" value="${m}" ${methods.includes(m)?'checked':''}><span>${m}</span></label>`).join('')}</div>
    <div class="webhook-row">
      <label class="field"><span>签名请求头（可选，HMAC-SHA256）</span><input class="input mono" name="signatureHeader" value="${escapeHTML(v.signatureHeader||'')}" placeholder="X-Hub-Signature-256"></label>
      <label class="field"><span>签名密钥${v.hasSigningSecret?'（已设置，留空保持不变）':''}</span><input class="input mono" name="signingSecret" type="password" autocomplete="new-password" value=""></label>
    </div>
    <label class="fd-check"><input type="checkbox" name="enabled" ${v.enabled!==false?'checked':''}><span>启用</span></label>
    <p class="webhook-form-error" role="alert"></p>
    <div class="webhook-actions"><button type="submit" class="button primary small">${w?'保存':'创建 Webhook'}</button><button type="button" class="button ghost small" data-webhook-cancel>取消</button></div>
  </form>`;
}

function webhookRevealHTML(){
  const r=webhookState.revealed;if(!r)return '';
  const url=webhookURL(location.origin,r.path);
  return `<div class="webhook-reveal" role="status"><b>${r.rotated?'新的调用地址':'调用地址'}只显示这一次，请立即复制保存</b>
    <div class="webhook-url"><code>${escapeHTML(url)}</code><button type="button" class="button ghost small" data-webhook-copy="${escapeHTML(url)}">复制</button></div>
    <details><summary>curl 示例</summary><pre>${escapeHTML(webhookCurlExample(url))}</pre></details>
    <button type="button" class="button ghost small" data-webhook-dismiss>我已保存</button></div>`;
}

function webhookCardHTML(w){
  const editing=webhookState.editing===w.id,dl=webhookState.deliveries[w.id];
  const facts=[
    w.dedupFields?.length?`去重：${w.dedupFields.join(' + ')} · ${webhookWindowText(w.dedupWindowSeconds)}`:'不去重',
    w.caseMode==='per_fingerprint'?'按指纹建案':w.caseMode==='per_alert'?'每条告警建案':'',
    w.allowedCidrs?.length?`白名单 ${w.allowedCidrs.length} 条`:'不限来源',
    w.signatureHeader?`签名：${w.signatureHeader}`:'',
    w.lastTriggeredAt?`最近触发 ${new Date(w.lastTriggeredAt).toLocaleString()}`:'尚未触发',
  ].filter(Boolean);
  const deliveries=dl?`<div class="webhook-deliveries">${dl.length?dl.slice(0,20).map(d=>`<div class="webhook-delivery ${escapeHTML(d.status)}"><span>${escapeHTML(new Date(d.receivedAt).toLocaleString())}</span><b>${escapeHTML(webhookDeliveryLabel(d))}</b><span>${d.httpStatus||''}</span>${d.runId?`<button type="button" class="link" data-open-run="${escapeHTML(d.runId)}">${escapeHTML(d.runId.slice(-10))}</button>`:'<span></span>'}<small>${escapeHTML(webhookDeliveryOrigin(d))}</small></div>`).join(''):'<p class="prop-hint">还没有收到调用</p>'}</div>`:'';
  return `<div class="webhook-card${w.enabled?'':' off'}" data-webhook="${escapeHTML(w.id)}">
    <div class="webhook-card-head"><b>${escapeHTML(w.name)}</b><span class="webhook-pill">${w.enabled?'已启用':'已停用'}</span><code title="地址末段是密钥，完整地址只在创建或轮换时显示">/api/hooks/${escapeHTML(w.id)}/${escapeHTML(w.secretPrefix||'')}…</code></div>
    <p class="webhook-facts">${facts.map(escapeHTML).join(' · ')}</p>
    <div class="webhook-actions"><button type="button" class="button ghost small" data-webhook-edit>${editing?'收起':'配置'}</button><button type="button" class="button ghost small" data-webhook-deliveries>${dl?'隐藏记录':'调用记录'}</button><button type="button" class="button ghost small" data-webhook-rotate>轮换密钥</button><button type="button" class="button ghost small danger" data-webhook-delete>删除</button></div>
    ${editing?webhookFormHTML(w):''}${deliveries}${typeof alertSourcesHTML==='function'?alertSourcesHTML(w):''}
  </div>`;
}

function renderWorkflowWebhooks(){
  const host=$('#workflowWebhookEditor');if(!host)return;
  const wf=state.workflow;
  if(!wf){host.innerHTML='';return}
  if(catalogGeneric(wf)){host.innerHTML='<p class="prop-hint">通用模板不能直接接收 Webhook，复制到项目后再配置。</p>';return}
  if(!wf.projectId||!(state.data.workflows||[]).some(w=>w.id===wf.id)){host.innerHTML='<p class="prop-hint">先保存这条 SOP，再为它创建 Webhook。</p>';return}
  const creating=webhookState.editing==='new';
  host.innerHTML=`${webhookRevealHTML()}
    <p class="prop-hint">外部系统（SIEM、EDR、邮件网关）调用地址即启动本 SOP，请求体作为触发负载，可在执行条件里用 trigger 读取。运行以创建者身份执行。</p>
    ${webhookState.error?`<p class="webhook-form-error">${escapeHTML(webhookState.error)}</p>`:''}
    ${(webhookState.list||[]).map(webhookCardHTML).join('')}
    ${creating?webhookFormHTML(null):'<button type="button" class="button ghost small" data-webhook-new>+ 新建 Webhook</button>'}`;
  bindWorkflowWebhooks(host);
}

function readWebhookForm(form){
  const wf=state.workflow,f=form.elements;
  return webhookFormBody({projectId:wf.projectId,workflowId:wf.id,name:f.name.value,titleField:f.titleField.value,severityField:f.severityField.value,caseMode:f.caseMode.value,dedupFields:f.dedupFields.value,dedupMinutes:f.dedupMinutes.value,allowedCidrs:f.allowedCidrs.value,signatureHeader:f.signatureHeader.value,signingSecret:f.signingSecret.value,enabled:f.enabled.checked,methods:[...form.querySelectorAll('[name=method]:checked')].map(b=>b.value)});
}

function bindWorkflowWebhooks(host){
  host.querySelector('[data-webhook-new]')?.addEventListener('click',()=>{webhookState.editing='new';renderWorkflowWebhooks()});
  host.querySelector('[data-webhook-dismiss]')?.addEventListener('click',()=>{webhookState.revealed=null;renderWorkflowWebhooks()});
  host.querySelectorAll('[data-webhook-copy]').forEach(b=>b.onclick=async()=>{try{await navigator.clipboard.writeText(b.dataset.webhookCopy);toast('已复制调用地址')}catch{toast('请手动选择复制')}});
  host.querySelectorAll('[data-webhook-cancel]').forEach(b=>b.onclick=()=>{webhookState.editing='';renderWorkflowWebhooks()});
  host.querySelectorAll('[data-open-run]').forEach(b=>b.onclick=()=>{location.hash='#/runs/'+b.dataset.openRun});
  host.querySelectorAll('[data-webhook-form]').forEach(form=>form.onsubmit=async e=>{
    e.preventDefault();
    const id=form.dataset.webhookForm,err=form.querySelector('.webhook-form-error'),body=readWebhookForm(form);
    if(!body.methods.length){err.textContent='至少允许一种方法';return}
    try{
      if(id){await api(`/api/webhooks/${encodeURIComponent(id)}`,{method:'PUT',body:JSON.stringify(body)});toast('已保存 Webhook')}
      else{const created=await api('/api/webhooks',{method:'POST',body:JSON.stringify(body)});webhookState.revealed={path:created.path,rotated:false}}
      webhookState.editing='';await loadWorkflowWebhooks(true);
    }catch(ex){err.textContent=ex.message}
  });
  host.querySelectorAll('[data-webhook]').forEach(card=>{
    const id=card.dataset.webhook;
    const w=(webhookState.list||[]).find(x=>x.id===id);
    if(w&&typeof bindAlertSources==='function')bindAlertSources(card,w);
    card.querySelector('[data-webhook-edit]').onclick=()=>{webhookState.editing=webhookState.editing===id?'':id;renderWorkflowWebhooks()};
    card.querySelector('[data-webhook-deliveries]').onclick=async()=>{
      if(webhookState.deliveries[id]){delete webhookState.deliveries[id];renderWorkflowWebhooks();return}
      try{
        webhookState.deliveries[id]=await api(`/api/webhooks/${encodeURIComponent(id)}/deliveries`,{silent:true});
        if(typeof loadAlertSources==='function')await loadAlertSources(state.workflow.projectId,true);
        renderWorkflowWebhooks();
      }catch(e){toast(e.message)}
    };
    card.querySelector('[data-webhook-rotate]').onclick=async()=>{
      if(!await afConfirm({title:'轮换 Webhook 密钥',message:'旧地址会立即失效，调用方需要换成新地址。继续吗？',confirmText:'轮换'}))return;
      try{const r=await api(`/api/webhooks/${encodeURIComponent(id)}/rotate`,{method:'POST'});webhookState.revealed={path:r.path,rotated:true};await loadWorkflowWebhooks(true)}catch(e){toast(e.message)}
    };
    card.querySelector('[data-webhook-delete]').onclick=async()=>{
      if(!await afConfirm({title:'删除 Webhook',message:'删除后地址立即失效，去重记录和调用记录一并删除，不可恢复。',confirmText:'删除',danger:true}))return;
      try{await api(`/api/webhooks/${encodeURIComponent(id)}`,{method:'DELETE'});toast('已删除 Webhook');await loadWorkflowWebhooks(true)}catch(e){toast(e.message)}
    };
  });
}
