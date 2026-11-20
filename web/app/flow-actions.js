// Action nodes in the flow designer: pick a connector action, the project
// connection that holds its credentials, and fill its inputs with fixed
// values or {{ expression }} templates over the trigger and upstream nodes.
// Response actions (isolate, disable, block) must sit behind an approval.

const ACTION_CATEGORY_TEXT={enrichment:'情报富化',response:'响应处置',utility:'通用'};
function actionCategoryText(category){return ACTION_CATEGORY_TEXT[category]||category||''}
// Finds a connector and one of its actions in the catalog list.
function actionCatalogFind(catalog,connectorId,actionId){
  const connector=(catalog||[]).find(c=>c.id===connectorId)||null;
  const action=connector?(connector.actions||[]).find(a=>a.id===actionId)||null:null;
  return {connector,action};
}
// Every output field a downstream condition or input can read.
function actionOutputRefs(nodeId,action){
  const fields=['status',...((action&&action.outputFields)||[])];
  if(action&&!(action.outputFields||[]).length)fields.push('body');
  return fields.map(f=>`nodes.${nodeId}.data.${f}`);
}
// Keeps only filled inputs the action declares.
function actionInputsFromForm(action,values){
  const out={};
  for(const input of (action&&action.inputs)||[]){
    const v=String((values||{})[input.name]??'').trim();
    if(v)out[input.name]=v;
  }
  return out;
}
// Mirrors connector.GatedByApproval: every path from a start node to
// nodeId leaves an approval through a success edge.
function actionGatedByApproval(wf,nodeId){
  const nodes=(wf&&wf.nodes)||[],edges=(wf&&wf.edges)||[];
  const type=Object.fromEntries(nodes.map(n=>[n.id,n.type]));
  const incoming={};edges.forEach(e=>{incoming[e.target]=(incoming[e.target]||0)+1});
  const seen=new Set(),stack=nodes.filter(n=>!incoming[n.id]).map(n=>n.id);
  while(stack.length){
    const id=stack.pop();
    if(seen.has(id))continue;
    seen.add(id);
    if(id===nodeId)return false;
    for(const e of edges){
      if(e.source!==id)continue;
      if(type[id]==='approval'&&e.when!=='error')continue;
      stack.push(e.target);
    }
  }
  return true;
}
// Problems that stop the node from running, in the order a user fixes them.
function actionNodeProblems(n,catalog,wf){
  const a=n&&n.action||{};
  if(!a.connector||!a.action)return ['未选择动作'];
  const {connector,action}=actionCatalogFind(catalog,a.connector,a.action);
  if(!connector||!action)return [`动作 ${a.connector}.${a.action} 不存在`];
  const out=[];
  if(!connector.builtin&&!a.connectionId)out.push('未选择连接');
  for(const input of action.inputs||[]){
    if(input.required&&input.default==null&&!String((a.inputs||{})[input.name]||'').trim())out.push(`缺少输入「${input.label||input.name}」`);
  }
  if(action.category==='response'&&!actionGatedByApproval(wf,n.id))out.push('响应动作前必须有人工门禁');
  return out;
}
// Canvas card summary for an action node.
function actionNodeMeta(n,catalog,connections,wf){
  const a=n&&n.action||{};
  const {connector,action}=actionCatalogFind(catalog,a.connector,a.action);
  if(!catalog)return {kind:'action',subtitle:a.connector?`${a.connector} · ${a.action||''}`:'未选择动作',tags:[]};
  if(!connector||!action)return {kind:'action',subtitle:'未选择动作',tags:[{text:'未选择动作',warn:true}]};
  const tags=[{text:actionCategoryText(action.category),warn:action.category==='response'}];
  if(!connector.builtin){
    const conn=(connections||[]).find(c=>c.id===a.connectionId);
    tags.push(conn?{text:conn.name}:{text:a.connectionId?'连接不可用':'未选连接',warn:true});
  }
  const problems=actionNodeProblems(n,catalog,wf).filter(p=>p!=='未选择连接');
  if(problems.length)tags.push({text:problems[0],warn:true});
  return {kind:'action',subtitle:`${connector.title} · ${action.title}`,tags};
}

const actionState={catalog:null,connections:{},loading:{}};

async function loadActionCatalog(){
  if(actionState.catalog)return actionState.catalog;
  if(!actionState.loading.catalog)actionState.loading.catalog=api('/api/connectors').then(list=>{actionState.catalog=list||[];return actionState.catalog}).finally(()=>{delete actionState.loading.catalog});
  return actionState.loading.catalog;
}
async function loadActionConnections(projectId,force){
  if(!projectId)return [];
  if(actionState.connections[projectId]&&!force)return actionState.connections[projectId];
  const key='conn:'+projectId;
  if(!actionState.loading[key])actionState.loading[key]=api(`/api/connections?projectId=${encodeURIComponent(projectId)}`).then(list=>{actionState.connections[projectId]=list||[];return actionState.connections[projectId]}).catch(()=>{actionState.connections[projectId]=[];return []}).finally(()=>{delete actionState.loading[key]});
  return actionState.loading[key];
}
// Loads what action nodes need, then redraws the canvas and drawer once.
function ensureActionData(){
  const wf=state.workflow;if(!wf)return;
  const pid=wf.projectId||state.projectFilter||'';
  const need=(!actionState.catalog)||(pid&&!actionState.connections[pid]);
  if(!need)return;
  Promise.all([loadActionCatalog(),loadActionConnections(pid)]).then(()=>{
    if(typeof renderCanvas==='function')renderCanvas();
    const sel=state.workflow?.nodes.find(x=>x.id===state.selectedNode);
    if(sel&&sel.type==='action'&&typeof renderProperties==='function')renderProperties();
  }).catch(e=>toast(e.message||'加载连接器失败'));
}
function flowActionMeta(n){
  ensureActionData();
  const pid=state.workflow?.projectId||state.projectFilter||'';
  return actionNodeMeta(n,actionState.catalog,actionState.connections[pid],state.workflow);
}
function flowActionPaneHTML(n){
  ensureActionData();
  const catalog=actionState.catalog;
  if(!catalog)return '<p class="prop-hint">正在加载连接器…</p>';
  const a=n.action||(n.action={connector:'',action:'',connectionId:'',inputs:{}});
  const {connector,action}=actionCatalogFind(catalog,a.connector,a.action);
  const pid=state.workflow?.projectId||state.projectFilter||'';
  const conns=(actionState.connections[pid]||[]).filter(c=>c.connectorId===a.connector);
  const opt=(v,label,sel)=>`<option value="${escapeHTML(v)}" ${sel?'selected':''}>${escapeHTML(label)}</option>`;
  const connectorSel=`<div class="fd-field"><label>连接器</label><select class="select" data-action-connector><option value="">选择连接器</option>${catalog.map(c=>opt(c.id,c.title,c.id===a.connector)).join('')}</select>${connector?.description?`<p class="prop-hint">${escapeHTML(connector.description)}</p>`:''}</div>`;
  if(!connector)return connectorSel;
  const groups=['enrichment','response','utility'].map(cat=>{
    const items=(connector.actions||[]).filter(x=>x.category===cat);
    return items.length?`<optgroup label="${escapeHTML(actionCategoryText(cat))}">${items.map(x=>opt(x.id,x.title,x.id===a.action)).join('')}</optgroup>`:'';
  }).join('');
  const actionSel=`<div class="fd-field"><label>动作</label><select class="select" data-action-action><option value="">选择动作</option>${groups}</select>${action?.description?`<p class="prop-hint">${escapeHTML(action.description)}</p>`:''}</div>`;
  const gated=action?.category!=='response'||actionGatedByApproval(state.workflow,n.id);
  const warn=action?.category==='response'?`<p class="prop-hint${gated?'':' fd-hint-err'}">${gated?'响应动作：已在人工门禁之后，审批通过才会执行。':'响应动作会改动外部系统，必须放在人工门禁之后，否则不能保存。'}</p>`:'';
  const connSel=connector.builtin?'':`<div class="fd-field"><label>连接</label><select class="select" data-action-connection><option value="">选择连接</option>${conns.map(c=>opt(c.id,c.name,c.id===a.connectionId)).join('')}</select><p class="prop-hint">${conns.length?'凭据保存在连接里，不会写进流程。':'本项目还没有该连接器的连接。'}<button type="button" class="fd-link" data-open-connections>管理连接</button></p></div>`;
  if(!action)return connectorSel+actionSel+connSel;
  const inputs=(action.inputs||[]).map(input=>{
    const ph=input.default!=null?`默认 ${typeof input.default==='string'?input.default:JSON.stringify(input.default)}`:(input.enum?.length?input.enum.join(' / '):(input.description||''));
    const req=input.required&&input.default==null?' <span class="fd-req">*</span>':'';
    return `<div class="fd-field"><label>${escapeHTML(input.label||input.name)}${req}</label><input class="input fd-mono" data-action-input="${escapeHTML(input.name)}" value="${escapeHTML((a.inputs||{})[input.name]||'')}" placeholder="${escapeHTML(ph)}" spellcheck="false">${input.description&&input.description!==ph?`<p class="prop-hint">${escapeHTML(input.description)}</p>`:''}</div>`;
  }).join('');
  const refs=actionOutputRefs(n.id,action).map(r=>`<code>${escapeHTML(r)}</code>`).join(' ');
  const help=`<p class="prop-hint">输入可写固定值，或用 <code>{{ trigger.alert.sender }}</code>、<code>{{ first(nodes.extract.data.url) }}</code> 引用告警和上游输出。</p><p class="prop-hint">下游可读：${refs}</p>`;
  return connectorSel+actionSel+warn+connSel+inputs+(action.inputs?.length||refs?help:'');
}
function bindFlowActionPane(host,n){
  const a=n.action||(n.action={connector:'',action:'',connectionId:'',inputs:{}});
  const sel=host.querySelector('[data-action-connector]');
  if(sel)sel.onchange=()=>{flowHistory.record();n.action={connector:sel.value,action:'',connectionId:'',inputs:{}};dirty();renderProperties();renderCanvas()};
  const act=host.querySelector('[data-action-action]');
  if(act)act.onchange=()=>{
    flowHistory.record();
    const prevTitle=actionCatalogFind(actionState.catalog,a.connector,a.action).action?.title;
    const {connector,action}=actionCatalogFind(actionState.catalog,a.connector,act.value);
    a.action=act.value;a.inputs=actionInputsFromForm(action,a.inputs);
    if(action&&(!n.name||n.name==='动作节点'||n.name===prevTitle))n.name=action.title;
    if(connector&&!connector.builtin&&!a.connectionId){
      const pid=state.workflow?.projectId||state.projectFilter||'';
      const only=(actionState.connections[pid]||[]).filter(c=>c.connectorId===a.connector);
      if(only.length===1)a.connectionId=only[0].id;
    }
    dirty();renderProperties();renderCanvas();
  };
  const conn=host.querySelector('[data-action-connection]');
  if(conn)conn.onchange=()=>{flowHistory.record();a.connectionId=conn.value;dirty();renderCanvas()};
  host.querySelectorAll('[data-action-input]').forEach(el=>el.oninput=()=>{
    flowHistory.record({merge:`p:${n.id}:action:${el.dataset.actionInput}`});
    const v=el.value;
    a.inputs=a.inputs||{};
    if(String(v).trim())a.inputs[el.dataset.actionInput]=v;else delete a.inputs[el.dataset.actionInput];
    dirty();renderCanvas();
  });
  host.querySelector('[data-open-connections]')?.addEventListener('click',()=>{
    if(typeof openCaseConnections==='function')openCaseConnections(state.workflow?.projectId||state.projectFilter||'');
  });
}
// Readiness check entry for the flow settings checklist.
function flowActionReadiness(n){
  const problems=actionNodeProblems(n,actionState.catalog||[],state.workflow);
  if(!actionState.catalog)return {level:'warn',title:n.name,detail:'连接器目录未加载'};
  return {level:problems.length?'error':'ok',title:n.name,detail:problems.length?problems.join('、'):flowActionMeta(n).subtitle};
}
