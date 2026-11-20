// 连接 tab of the 告警与案件 view: per-project endpoints and credentials for
// connector actions. Secret values are write-only: the server only reports
// which secrets are set, and an empty field keeps the stored value.

// Builds the create/update body from the form's raw values.
function connectionFormBody(def,form,existing){
  const body={name:String(form.name||'').trim(),baseUrl:String(form.baseUrl||'').trim(),params:{},secrets:{}};
  if(!existing){body.projectId=form.projectId;body.connectorId=def.id}
  for(const p of def.params||[])body.params[p.name]=String((form.params||{})[p.name]||'').trim();
  for(const s of def.secrets||[]){const v=String((form.secrets||{})[s.name]||'').trim();if(v)body.secrets[s.name]=v}
  // TLS fields are sent whenever the form has them: an empty value clears.
  if(form.tlsCertSha256!==undefined)body.tlsCertSha256=String(form.tlsCertSha256||'').trim();
  if(form.tlsCaPem!==undefined)body.tlsCaPem=String(form.tlsCaPem||'').trim();
  // Rate and retry fields, likewise: empty means unlimited / the default
  // number of retries (null restores it).
  const num=v=>{const n=Number(String(v??'').trim());return String(v??'').trim()!==''&&Number.isFinite(n)?n:null};
  if(form.rateLimitPerSecond!==undefined)body.rateLimitPerSecond=num(form.rateLimitPerSecond)||0;
  if(form.rateLimitBurst!==undefined)body.rateLimitBurst=Math.round(num(form.rateLimitBurst)||0);
  if(form.maxRetries!==undefined){const n=num(form.maxRetries);body.maxRetries=n===null?null:Math.round(n)}
  return body;
}
// Required fields the form leaves empty (a stored secret counts as set).
function connectionFormMissing(def,form,existing){
  const missing=[];
  if(!String(form.name||'').trim())missing.push('名称');
  if(!def.baseUrl&&!String(form.baseUrl||'').trim())missing.push('服务地址');
  for(const p of def.params||[])if(p.required&&!p.default&&!String((form.params||{})[p.name]||'').trim())missing.push(p.label||p.name);
  const set=new Set((existing&&existing.secretsSet)||[]);
  for(const s of def.secrets||[])if(s.required&&!set.has(s.name)&&!String((form.secrets||{})[s.name]||'').trim())missing.push(s.label||s.name);
  return missing;
}

const connState={catalog:[],list:[],editing:'',connector:'',tests:{},busy:''};

async function loadCaseConnections(project){
  const [catalog,list]=await Promise.all([api('/api/connectors',{silent:true}),api(`/api/connections?projectId=${encodeURIComponent(project)}`,{silent:true})]);
  connState.catalog=(catalog||[]).filter(c=>!c.builtin);
  connState.list=list||[];
  if(typeof actionState==='object')actionState.connections[project]=connState.list;
}
// Opens the 连接 tab for a project, from the flow designer's action pane.
function openCaseConnections(projectId){
  if(projectId&&state.projectFilter!==projectId&&typeof setProjectFilter==='function')setProjectFilter(projectId);
  casesState.tab='connections';casesState.detail=null;
  if(typeof switchView==='function')switchView('cases');
  loadCasesView();
}
function connectionDef(id){return connState.catalog.find(c=>c.id===id)}
function connectionTestHTML(id){
  const t=connState.tests[id];if(!t)return '';
  if(t.pending)return '<span class="conn-test">测试中…</span>';
  return `<span class="conn-test ${t.ok?'ok':'bad'}">${escapeHTML(t.ok?`${t.action} 成功 · ${t.durationMs} ms`:t.error||'失败')}</span>`;
}
function connectionFormHTML(existing){
  const def=connectionDef(existing?existing.connectorId:connState.connector);
  const choose=existing?'':`<label class="field"><span>连接器</span><select class="select" name="connectorId"><option value="">选择连接器</option>${connState.catalog.map(c=>`<option value="${escapeHTML(c.id)}" ${c.id===connState.connector?'selected':''}>${escapeHTML(c.title)}</option>`).join('')}</select></label>`;
  if(!def)return `<form class="conn-form" id="connForm"><h4>新建连接</h4>${choose}<p class="prop-hint">选择要接入的安全产品。凭据只保存在本项目的连接里，SOP 里的动作节点引用连接而不接触密钥。</p></form>`;
  const field=(name,label,value,extra='')=>`<label class="field"><span>${escapeHTML(label)}</span><input class="input" name="${escapeHTML(name)}" value="${escapeHTML(value||'')}" ${extra}></label>`;
  const params=(def.params||[]).map(p=>field('param:'+p.name,p.label+(p.required?' *':''),existing?.params?.[p.name]||'',`placeholder="${escapeHTML(p.default||p.description||'')}"`)).join('');
  const set=new Set(existing?.secretsSet||[]);
  const secrets=(def.secrets||[]).map(s=>field('secret:'+s.name,s.label+(s.required?' *':''),'',`type="password" autocomplete="new-password" placeholder="${escapeHTML(set.has(s.name)?'已设置，留空保持不变':(s.description||''))}"`)).join('');
  return `<form class="conn-form" id="connForm"><h4>${existing?`编辑「${escapeHTML(existing.name)}」`:'新建连接'}</h4>${choose}
    ${def.description?`<p class="prop-hint">${escapeHTML(def.description)}${def.docs?` <a href="${escapeHTML(def.docs)}" target="_blank" rel="noopener">接口文档</a>`:''}</p>`:''}
    ${field('name','名称 *',existing?.name||def.title,'maxlength="120"')}
    ${field('baseUrl','服务地址',existing?.baseUrl||'',`placeholder="${escapeHTML(def.baseUrl?'默认 '+def.baseUrl:'https://')}"`)}
    ${params}${secrets}
    <details class="conn-tls" ${existing?.tlsCertSha256||existing?.tlsCaPem?'open':''}><summary>HTTPS 证书（服务用自签证书时填写）</summary>
      ${field('tlsCertSha256','证书 SHA-256 指纹',existing?.tlsCertSha256||'','placeholder="openssl x509 -fingerprint -sha256 输出的值，冒号可保留" spellcheck="false"')}
      <label class="field"><span>CA 证书（PEM，可选）</span><textarea class="input" name="tlsCaPem" rows="3" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----">${escapeHTML(existing?.tlsCaPem||'')}</textarea></label>
      <p class="prop-hint">只填指纹时只认这一张证书、不校验签发链；填了 CA 时按 CA 校验，再核对指纹。</p>
    </details>
    <details class="conn-tls" ${existing?.rateLimitPerSecond||existing?.maxRetries!=null?'open':''}><summary>限流与重试</summary>
      ${field('rateLimitPerSecond','每秒请求数（留空不限）',existing?.rateLimitPerSecond||'','type="number" min="0" max="1000" step="any" placeholder="不限"')}
      ${field('rateLimitBurst','突发上限',existing?.rateLimitBurst||'','type="number" min="0" max="1000" placeholder="1"')}
      ${field('maxRetries','失败重试次数',existing?.maxRetries??'','type="number" min="0" max="10" placeholder="默认 3"')}
      <p class="prop-hint">超出限流的调用排队等待。HTTP 429 对所有请求重试；5xx 和网络错误只对 GET 重试，处置类动作不会重复发送。等待遵循 Retry-After，最长 60 秒。限流按平台进程分别计算。</p>
    </details>
    <p class="case-form-error" role="alert"></p>
    <div class="conn-form-actions"><button type="submit" class="button primary small">${existing?'保存':'创建连接'}</button><button type="button" class="button ghost small" data-conn-cancel>取消</button></div></form>`;
}
function connectionsHTML(){
  const rows=connState.list.map(c=>{
    const def=connectionDef(c.connectorId);
    return `<div class="conn-row" data-conn="${escapeHTML(c.id)}"><b>${escapeHTML(c.name)}</b><span class="case-meta">${escapeHTML(def?.title||c.connectorId)} · ${escapeHTML(c.baseUrl||def?.baseUrl||'')}${(c.secretsSet||[]).length?` · 已设置 ${c.secretsSet.length} 项凭据`:' · 未设置凭据'}</span>${connectionTestHTML(c.id)}<button type="button" class="button ghost small" data-conn-test ${def?.testAction?'':'disabled title="该连接器没有只读测试动作"'}>测试</button><button type="button" class="button ghost small" data-conn-edit>编辑</button><button type="button" class="button ghost small danger" data-conn-delete>删除</button></div>`;
  }).join('')||'<p class="prop-hint">还没有连接。</p>';
  const editing=connState.editing==='new'?connectionFormHTML(null):connState.editing?connectionFormHTML(connState.list.find(c=>c.id===connState.editing)):'<button type="button" class="button ghost small" data-conn-new>+ 新建连接</button>';
  return `<p class="prop-hint">SOP 的动作节点通过连接调用外部安全产品。项目成员可以查看连接，只有项目负责人和成员可以修改；密钥写入后不可读出。</p>${rows}${editing}`;
}
function bindConnections(host){
  const project=casesProject();
  host.querySelector('[data-conn-new]')?.addEventListener('click',()=>{connState.editing='new';connState.connector='';renderCasesView()});
  host.querySelector('[data-conn-cancel]')?.addEventListener('click',()=>{connState.editing='';renderCasesView()});
  const form=host.querySelector('#connForm');
  if(form){
    form.elements.connectorId?.addEventListener('change',e=>{connState.connector=e.target.value;renderCasesView()});
    form.onsubmit=async e=>{
      e.preventDefault();
      const existing=connState.editing==='new'?null:connState.list.find(c=>c.id===connState.editing);
      const def=connectionDef(existing?existing.connectorId:connState.connector);if(!def)return;
      const values={projectId:project,name:form.elements.name.value,baseUrl:form.elements.baseUrl.value,params:{},secrets:{},tlsCertSha256:form.elements.tlsCertSha256.value,tlsCaPem:form.elements.tlsCaPem.value,rateLimitPerSecond:form.elements.rateLimitPerSecond.value,rateLimitBurst:form.elements.rateLimitBurst.value,maxRetries:form.elements.maxRetries.value};
      [...form.elements].forEach(el=>{const [kind,name]=String(el.name||'').split(':');if(kind==='param')values.params[name]=el.value;if(kind==='secret')values.secrets[name]=el.value});
      const err=form.querySelector('.case-form-error');
      const missing=connectionFormMissing(def,values,existing);
      if(missing.length){err.textContent='请填写：'+missing.join('、');return}
      try{
        const body=connectionFormBody(def,values,existing);
        await api(existing?`/api/connections/${encodeURIComponent(existing.id)}`:'/api/connections',{method:existing?'PUT':'POST',body:JSON.stringify(body)});
        toast(existing?'已保存连接':'已创建连接');connState.editing='';loadCasesView();
      }catch(ex){err.textContent=ex.message}
    };
  }
  host.querySelectorAll('[data-conn]').forEach(row=>{
    const c=connState.list.find(x=>x.id===row.dataset.conn);
    row.querySelector('[data-conn-edit]').onclick=()=>{connState.editing=c.id;renderCasesView()};
    row.querySelector('[data-conn-test]').onclick=async()=>{
      connState.tests[c.id]={pending:true};renderCasesView();
      try{connState.tests[c.id]=await api(`/api/connections/${encodeURIComponent(c.id)}/test`,{method:'POST',body:'{}',silent:true})}
      catch(ex){connState.tests[c.id]={ok:false,error:ex.message}}
      renderCasesView();
    };
    row.querySelector('[data-conn-delete]').onclick=async()=>{
      if(!await afConfirm({title:'删除连接',message:`删除「${c.name}」？引用它的动作节点会在运行时失败。`,confirmText:'删除',danger:true}))return;
      try{await api(`/api/connections/${encodeURIComponent(c.id)}`,{method:'DELETE'});loadCasesView()}catch(ex){toast(ex.message)}
    };
  });
}
