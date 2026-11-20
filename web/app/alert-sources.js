// Pull alert sources on a webhook card: for products that cannot push
// (Splunk, CrowdStrike Falcon), poll their API on a schedule and admit what
// comes back through the webhook's mapping, deduplication and SOP.

// Presets fill the source fields a product needs; the form only asks for
// the connection and, per product, an extra filter or search.
const ALERT_SOURCE_PRESETS={
  falcon:{title:'CrowdStrike Falcon 告警',connector:'crowdstrike',action:'list_alert_ids',detailAction:'get_alerts',detailInput:'ids',
    idPath:'composite_id',timePath:'created_timestamp',pollSeconds:120,extraLabel:'附加 FQL 过滤（可选）',extraPlaceholder:"product:'epp'+severity:>=50",
    mapping:'Webhook 建议：标题字段 display_name，严重度字段 severity_name，去重字段 composite_id'},
  splunk:{title:'Splunk 搜索',connector:'splunk',action:'search',idPath:'event_id',timePath:'_time',pollSeconds:60,
    extraLabel:'搜索语句',extraPlaceholder:'search index=notable | sort 0 _time',extraDefault:'search index=notable | sort 0 _time',
    mapping:'Webhook 建议：标题字段 search_name，严重度字段 urgency，去重字段 event_id'},
};
// The window filter Falcon needs; an extra FQL clause is ANDed with +.
function alertSourceFalconFilter(extra){
  const base="created_timestamp:>='{{ window.sinceIso }}'+created_timestamp:<'{{ window.untilIso }}'";
  const more=String(extra||'').trim().replace(/^\++/,'');
  return more?`${base}+${more}`:base;
}
// Reads the extra field back out of a saved source of a preset.
function alertSourceExtra(preset,src){
  const inputs=(src&&src.inputs)||{};
  if(preset==='falcon'){
    const f=String(inputs.filter||''),base=alertSourceFalconFilter('');
    return f.startsWith(base+'+')?f.slice(base.length+1):'';
  }
  if(preset==='splunk')return String(inputs.search||'');
  return '';
}
// Which preset a saved source matches, or custom.
function alertSourcePresetOf(src){
  for(const [key,p] of Object.entries(ALERT_SOURCE_PRESETS)){
    if(src&&src.action===p.action&&(src.detailAction||'')===(p.detailAction||'')&&src.connectorId===p.connector)return key;
  }
  return 'custom';
}
// Builds the create/update body from the form's raw values.
function alertSourceFormBody(form){
  const minutes=Number(form.pollMinutes),hours=Number(form.lookbackHours);
  const body={projectId:form.projectId,webhookId:form.webhookId,name:String(form.name||'').trim(),connectionId:form.connectionId||'',enabled:form.enabled!==false};
  if(Number.isFinite(minutes)&&minutes>0)body.pollSeconds=Math.round(minutes*60);
  if(Number.isFinite(hours)&&hours>=0)body.lookbackSeconds=Math.round(hours*3600);
  const p=ALERT_SOURCE_PRESETS[form.preset];
  if(p){
    Object.assign(body,{action:p.action,detailAction:p.detailAction||'',detailInput:p.detailInput||'',idPath:String(form.idPath??p.idPath).trim(),timePath:String(form.timePath??p.timePath).trim()});
    if(form.preset==='falcon')body.inputs={filter:alertSourceFalconFilter(form.extra),limit:'{{ window.limit }}'};
    if(form.preset==='splunk')body.inputs={search:String(form.extra||p.extraDefault).trim(),earliest:'{{ window.since }}',latest:'{{ window.until }}',count:'{{ window.limit }}'};
    if(!form.pollMinutes)body.pollSeconds=p.pollSeconds;
    return body;
  }
  let custom={};
  try{custom=JSON.parse(form.custom||'{}')}catch{throw new Error('自定义配置不是有效的 JSON')}
  for(const k of ['action','inputs','itemsField','detailAction','detailInput','idPath','timePath','lagSeconds','windowSeconds','pageLimit'])if(custom[k]!==undefined)body[k]=custom[k];
  return body;
}
// One status line: what the last pass did, or why it failed.
function alertSourceStatus(src){
  const s=(src&&src.state)||{};
  if(!src.enabled)return {level:'off',text:'已停用'};
  if(s.lastError)return {level:'bad',text:`失败${s.failures>1?` ${s.failures} 次`:''}：${s.lastError}`};
  if(!s.lastRunAt)return {level:'wait',text:'等待首次拉取'};
  const when=new Date(s.lastRunAt).toLocaleString();
  const text=`${when} 拉取 ${s.lastFetched||0} 条，新增 ${s.lastAdmitted||0} 条 · 累计 ${s.totalAdmitted||0} 条`;
  return s.lastWarning?{level:'warn',text:`${text} · ${s.lastWarning}`}:{level:'ok',text};
}

const alertSourceState={byWebhook:{},loadedFor:'',connections:[],editing:'',preview:{},drafts:{},busy:''};

async function loadAlertSources(projectId,force){
  if(!projectId)return;
  if(!force&&alertSourceState.loadedFor===projectId)return;
  alertSourceState.loadedFor=projectId;
  try{
    const [list,conns]=await Promise.all([api(`/api/alert-sources?projectId=${encodeURIComponent(projectId)}`,{silent:true}),api(`/api/connections?projectId=${encodeURIComponent(projectId)}`,{silent:true})]);
    const by={};
    for(const s of list||[]){
      const conn=(conns||[]).find(c=>c.id===s.connectionId);
      s.connectorId=conn?conn.connectorId:'';
      (by[s.webhookId]=by[s.webhookId]||[]).push(s);
    }
    alertSourceState.byWebhook=by;alertSourceState.connections=conns||[];
  }catch{alertSourceState.byWebhook={};alertSourceState.connections=[]}
}

// The form's raw values, kept across a re-render (a preview shows its
// result inside the form).
function alertSourceFormValues(form){
  const f=form.elements,v=name=>f[name]?f[name].value:undefined;
  return {preset:v('preset'),name:v('name'),connectionId:v('connectionId'),extra:v('extra'),idPath:v('idPath'),timePath:v('timePath'),custom:v('custom'),pollMinutes:v('pollMinutes'),lookbackHours:v('lookbackHours')};
}
function alertSourceFormHTML(webhookId,src){
  const key=src?.id||'new:'+webhookId,d=alertSourceState.drafts[key]||{};
  const preset=src?alertSourcePresetOf(src):(alertSourceState.newPreset||'falcon');
  const p=ALERT_SOURCE_PRESETS[preset];
  const conns=alertSourceState.connections.filter(c=>!p||c.connectorId===p.connector);
  const opt=(v,l,sel)=>`<option value="${escapeHTML(v)}" ${sel?'selected':''}>${escapeHTML(l)}</option>`;
  const extra=d.extra??(src?alertSourceExtra(preset,src):(p?.extraDefault||''));
  const custom=d.custom??(src&&!p?JSON.stringify({action:src.action,inputs:src.inputs,itemsField:src.itemsField,detailAction:src.detailAction,detailInput:src.detailInput,idPath:src.idPath,timePath:src.timePath},null,2):'{\n  "action": "",\n  "inputs": {}\n}');
  const connectionId=d.connectionId??src?.connectionId;
  const pv=alertSourceState.preview[key];
  const preview=pv?(pv.error?`<p class="webhook-form-error">${escapeHTML(pv.error)}</p>`:`<div class="alert-source-preview"><b>最近 ${escapeHTML(webhookWindowText(Math.round((new Date(pv.until)-new Date(pv.since))/1000))||'')}拉到 ${pv.fetched} 条</b>${pv.warning?`<small>${escapeHTML(pv.warning)}</small>`:''}${pv.titles.map((t,i)=>`<div><code>${escapeHTML(pv.ids[i]||'')}</code> ${escapeHTML(t||'（无标题）')}</div>`).join('')}${pv.items[0]?`<details><summary>第一条原始数据</summary><pre>${escapeHTML(JSON.stringify(pv.items[0],null,2))}</pre></details>`:''}</div>`):'';
  return `<form class="alert-source-form webhook-form" data-alert-source-form="${escapeHTML(src?.id||'')}" data-webhook-id="${escapeHTML(webhookId)}">
    ${src?'':`<label class="field"><span>设备</span><select class="select" name="preset">${Object.entries(ALERT_SOURCE_PRESETS).map(([k,v])=>opt(k,v.title,k===preset)).join('')}${opt('custom','自定义（任意只读动作）',preset==='custom')}</select></label>`}
    <label class="field"><span>名称</span><input class="input" name="name" maxlength="120" required value="${escapeHTML(d.name??(src?.name||p?.title||''))}"></label>
    <label class="field"><span>连接</span><select class="select" name="connectionId"><option value="">选择连接</option>${conns.map(c=>opt(c.id,c.name,c.id===connectionId)).join('')}</select></label>
    ${conns.length?'':`<p class="prop-hint">本项目还没有${escapeHTML(p?p.title.replace(/ .*/,''):'')}连接，先在「告警与案件 → 连接」里创建。</p>`}
    ${p?`<label class="field"><span>${escapeHTML(p.extraLabel)}</span><input class="input mono" name="extra" value="${escapeHTML(extra)}" placeholder="${escapeHTML(p.extraPlaceholder)}"></label>
    <details class="alert-source-advanced"><summary>字段</summary><div class="webhook-row"><label class="field"><span>告警 ID 字段</span><input class="input mono" name="idPath" value="${escapeHTML(d.idPath??src?.idPath??p.idPath)}"></label><label class="field"><span>时间字段</span><input class="input mono" name="timePath" value="${escapeHTML(d.timePath??src?.timePath??p.timePath)}"></label></div></details>
    <p class="prop-hint">${escapeHTML(p.mapping)}</p>`:`<label class="field"><span>配置（JSON）</span><textarea class="input mono" name="custom" rows="8" spellcheck="false">${escapeHTML(custom)}</textarea></label><p class="prop-hint">输入可用 {{ window.since }}、{{ window.untilIso }}、{{ window.limit }} 等引用本轮时间窗口。</p>`}
    <div class="webhook-row">
      <label class="field webhook-narrow"><span>拉取间隔（分钟）</span><input class="input" name="pollMinutes" type="number" min="0.5" max="1440" step="0.5" value="${escapeHTML(d.pollMinutes??(src?src.pollSeconds/60:(p?p.pollSeconds/60:1)))}"></label>
      ${src?'':`<label class="field webhook-narrow"><span>首次回溯（小时）</span><input class="input" name="lookbackHours" type="number" min="0" max="168" value="${escapeHTML(d.lookbackHours??'1')}"></label>`}
    </div>
    ${preview}
    <p class="webhook-form-error" role="alert"></p>
    <div class="webhook-actions"><button type="submit" class="button primary small">${src?'保存':'添加'}</button><button type="button" class="button ghost small" data-alert-source-preview>试拉取</button><button type="button" class="button ghost small" data-alert-source-cancel>取消</button></div>
  </form>`;
}

function alertSourcesHTML(w){
  const list=alertSourceState.byWebhook[w.id]||[];
  const rows=list.map(s=>{
    const st=alertSourceStatus(s),editing=alertSourceState.editing===s.id;
    return `<div class="alert-source ${st.level}" data-alert-source="${escapeHTML(s.id)}"><div class="alert-source-head"><b>${escapeHTML(s.name)}</b><span class="webhook-pill">每 ${escapeHTML(webhookWindowText(s.pollSeconds))}</span></div>
      <small class="alert-source-status">${escapeHTML(st.text)}</small>
      <div class="webhook-actions"><button type="button" class="button ghost small" data-alert-source-run ${s.enabled?'':'disabled'}>立即拉取</button><button type="button" class="button ghost small" data-alert-source-toggle>${s.enabled?'停用':'启用'}</button><button type="button" class="button ghost small" data-alert-source-edit>${editing?'收起':'配置'}</button><button type="button" class="button ghost small danger" data-alert-source-delete>删除</button></div>
      ${editing?alertSourceFormHTML(w.id,s):''}</div>`;
  }).join('');
  const adding=alertSourceState.editing==='new:'+w.id;
  return `<div class="alert-sources"><div class="alert-sources-head"><b>定时拉取</b><span class="prop-hint">不能主动推送的设备（Splunk、Falcon），按间隔调用它们的接口拉告警，经本 Webhook 去重、建案并启动 SOP。</span></div>
    ${rows}${adding?alertSourceFormHTML(w.id,null):'<button type="button" class="button ghost small" data-alert-source-new>+ 添加拉取源</button>'}</div>`;
}

function readAlertSourceForm(form){
  const f=form.elements,src=form.dataset.alertSourceForm?Object.values(alertSourceState.byWebhook).flat().find(s=>s.id===form.dataset.alertSourceForm):null;
  return alertSourceFormBody({projectId:state.workflow.projectId,webhookId:form.dataset.webhookId,preset:f.preset?f.preset.value:alertSourcePresetOf(src),
    name:f.name.value,connectionId:f.connectionId.value,extra:f.extra?.value,idPath:f.idPath?.value,timePath:f.timePath?.value,custom:f.custom?.value,
    pollMinutes:f.pollMinutes.value,lookbackHours:f.lookbackHours?.value,enabled:src?src.enabled:true});
}

function bindAlertSources(card,w){
  const rerender=()=>renderWorkflowWebhooks();
  const reload=async()=>{await loadAlertSources(state.workflow.projectId,true);rerender()};
  card.querySelector('[data-alert-source-new]')?.addEventListener('click',()=>{alertSourceState.editing='new:'+w.id;rerender()});
  card.querySelectorAll('[data-alert-source-cancel]').forEach(b=>b.onclick=()=>{alertSourceState.editing='';alertSourceState.drafts={};alertSourceState.preview={};rerender()});
  card.querySelectorAll('[data-alert-source-form]').forEach(form=>{
    const id=form.dataset.alertSourceForm,err=form.querySelector('.webhook-form-error'),key=id||'new:'+w.id;
    form.elements.preset?.addEventListener('change',e=>{alertSourceState.newPreset=e.target.value;delete alertSourceState.drafts[key];delete alertSourceState.preview[key];rerender()});
    form.querySelector('[data-alert-source-preview]').onclick=async()=>{
      let body;try{body=readAlertSourceForm(form)}catch(ex){err.textContent=ex.message;return}
      err.textContent='试拉取中…';alertSourceState.drafts[key]=alertSourceFormValues(form);
      try{alertSourceState.preview[key]=await api('/api/alert-sources/preview',{method:'POST',body:JSON.stringify(body),silent:true})}
      catch(ex){alertSourceState.preview[key]={error:ex.message}}
      rerender();
    };
    form.onsubmit=async e=>{
      e.preventDefault();
      let body;try{body=readAlertSourceForm(form)}catch(ex){err.textContent=ex.message;return}
      if(!body.connectionId){err.textContent='请选择连接';return}
      try{
        if(id){await api(`/api/alert-sources/${encodeURIComponent(id)}`,{method:'PUT',body:JSON.stringify(body)});toast('已保存拉取源')}
        else{await api('/api/alert-sources',{method:'POST',body:JSON.stringify(body)});toast('已添加拉取源，马上开始第一次拉取');setTimeout(reload,3000)}
        alertSourceState.editing='';delete alertSourceState.preview[key];delete alertSourceState.drafts[key];await reload();
      }catch(ex){err.textContent=ex.message}
    };
  });
  card.querySelectorAll('[data-alert-source]').forEach(row=>{
    const id=row.dataset.alertSource,src=(alertSourceState.byWebhook[w.id]||[]).find(s=>s.id===id);
    row.querySelector('[data-alert-source-edit]').onclick=()=>{alertSourceState.editing=alertSourceState.editing===id?'':id;rerender()};
    row.querySelector('[data-alert-source-run]').onclick=async()=>{
      try{await api(`/api/alert-sources/${encodeURIComponent(id)}/run`,{method:'POST'});toast('已安排立即拉取');setTimeout(reload,3000)}catch(e){toast(e.message)}
    };
    row.querySelector('[data-alert-source-toggle]').onclick=async()=>{
      const body={...src,enabled:!src.enabled};delete body.state;
      try{await api(`/api/alert-sources/${encodeURIComponent(id)}`,{method:'PUT',body:JSON.stringify(body)});await reload()}catch(e){toast(e.message)}
    };
    row.querySelector('[data-alert-source-delete]').onclick=async()=>{
      if(!await afConfirm({title:'删除拉取源',message:`删除「${src.name}」？已经入库的告警和案件保留。`,confirmText:'删除',danger:true}))return;
      try{await api(`/api/alert-sources/${encodeURIComponent(id)}`,{method:'DELETE'});await reload()}catch(e){toast(e.message)}
    };
  });
}
