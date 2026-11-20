// 试点报告 tab of the 告警与案件 view (docs/pilot.md) and the agent verdict
// block on the case detail. The report is readable by the project owner and
// platform administrators only.

const CASE_VERDICTS=[['malicious','恶意'],['benign','无害'],['false_positive','误报'],['needs_review','需人工判断']];
const PILOT_TARGETS={enrichment:0.99,p95Seconds:300};

function caseVerdictText(v){return (CASE_VERDICTS.find(x=>x[0]===v)||[v,v||'—'])[1]}
function caseVerdictHTML(c){
  if(!c?.agentVerdict)return '';
  const conf=typeof c.agentConfidence==='number'?` · 置信度 ${c.agentConfidence.toFixed(2)}`:'';
  const when=c.agentVerdictAt?` · ${new Date(c.agentVerdictAt).toLocaleString()}`:'';
  const run=c.agentVerdictRunId?`<button type="button" class="link" data-open-run="${escapeHTML(c.agentVerdictRunId)}">运行</button>`:'';
  return `<div class="case-verdict"><span>Agent 研判</span><span><span class="verdict-pill verdict-${escapeHTML(c.agentVerdict)}">${escapeHTML(caseVerdictText(c.agentVerdict))}</span>${escapeHTML(conf+when)} ${run}</span>${c.agentRationale?`<p>${escapeHTML(c.agentRationale)}</p>`:''}</div>`;
}
function pilotPct(v){return typeof v==='number'?(v*100).toFixed(1)+'%':'—'}
function pilotDuration(sec){
  if(typeof sec!=='number'||!isFinite(sec))return '—';
  if(sec<60)return `${Math.round(sec)} 秒`;
  if(sec<3600)return `${(sec/60).toFixed(1)} 分钟`;
  return `${(sec/3600).toFixed(1)} 小时`;
}
function pilotDefaultRange(now){
  const to=new Date(now||Date.now());const from=new Date(to.getTime()-13*86400000);
  const day=d=>d.toISOString().slice(0,10);
  return {from:day(from),to:day(to)};
}
function pilotReportQuery(project,range,format){
  const q=new URLSearchParams({projectId:project,from:range.from,to:range.to});
  if(format)q.set('format',format);
  return '/api/pilot-report?'+q.toString();
}

const pilotState={range:null,report:null,error:''};

async function loadPilotReport(project){
  pilotState.range=pilotState.range||pilotDefaultRange();
  pilotState.error='';pilotState.report=null;
  try{pilotState.report=await api(pilotReportQuery(project,pilotState.range),{silent:true})}
  catch(e){pilotState.error=e.message}
}

function pilotCard(label,value,note,ok){
  const cls=ok===true?' ok':ok===false?' bad':'';
  return `<div class="pilot-card${cls}"><span>${escapeHTML(label)}</span><b>${escapeHTML(value)}</b><span>${escapeHTML(note||'')}</span></div>`;
}

function pilotReportHTML(){
  const range=pilotState.range||pilotDefaultRange();
  const form=`<form class="pilot-form" id="pilotForm"><label class="field"><span>开始日期</span><input class="input" type="date" name="from" value="${escapeHTML(range.from)}"></label><label class="field"><span>结束日期（含）</span><input class="input" type="date" name="to" value="${escapeHTML(range.to)}"></label><button type="submit" class="button primary small">查询</button><button type="button" class="button ghost small" data-pilot-csv>导出 CSV</button></form>`;
  if(pilotState.error)return form+`<p class="case-form-error">${escapeHTML(pilotState.error)}</p>`;
  const r=pilotState.report;if(!r)return form+'<p class="prop-hint">加载中…</p>';
  const enr=r.actions.enrichment,lat=r.latency,agr=r.agreement;
  const cards=[
    pilotCard('告警（准入）',String(r.alerts.admitted),`去重 ${r.alerts.deduplicated} · 限流 ${r.alerts.rateLimited}${r.alerts.deliveriesComplete?'':'（调用记录不完整）'}`),
    pilotCard('运行',String(r.runs.started),`成功 ${r.runs.succeeded} · 失败 ${r.runs.failed} · 进行中/待审批 ${r.runs.active}`),
    pilotCard('富化成功率',pilotPct(enr.total?enr.rate:null),`${enr.succeeded}/${enr.total}，目标 ≥ 99%`,enr.total?enr.rate>=PILOT_TARGETS.enrichment:undefined),
    pilotCard('告警→研判 p95',lat.withVerdict?pilotDuration(lat.p95Seconds):'—',`p50 ${lat.withVerdict?pilotDuration(lat.p50Seconds):'—'} · ${lat.withVerdict} 个有结论，${lat.withoutVerdict} 个没有；目标 ≤ 5 分钟`,lat.withVerdict?lat.p95Seconds<=PILOT_TARGETS.p95Seconds:undefined),
    pilotCard('结论一致率',agr.matched+agr.mismatched?pilotPct(agr.rate):'—',`一致 ${agr.matched} · 不一致 ${agr.mismatched} · 不计 ${agr.excluded} · 未关闭 ${agr.openWithVerdict}`),
  ].join('');
  const connectors=(r.actions.byConnector||[]).map(s=>`<tr><td>${escapeHTML(s.connector)}</td><td>${s.total}</td><td>${s.failed}</td><td>${pilotPct(s.rate)}</td></tr>`).join('')||'<tr><td colspan="4">没有执行过的连接器动作</td></tr>';
  const resolutions=['resolved','false_positive','duplicate'];
  const verdicts=[...CASE_VERDICTS.map(x=>x[0]),'none'].filter(v=>agr.matrix?.[v]);
  const matrix=verdicts.map(v=>`<tr><td>${escapeHTML(v==='none'?'无结论':caseVerdictText(v))}</td>${resolutions.map(res=>`<td>${agr.matrix[v][res]||0}</td>`).join('')}</tr>`).join('')||`<tr><td colspan="${resolutions.length+1}">还没有已关闭的案件</td></tr>`;
  return `${form}<div class="pilot-cards">${cards}</div>
  <h4>连接器动作（不含响应动作；已执行响应动作 ${r.actions.responseExecuted} 次）</h4>
  <table class="pilot-table"><thead><tr><th>连接器</th><th>次数</th><th>失败</th><th>成功率</th></tr></thead><tbody>${connectors}</tbody></table>
  <h4>Agent 结论 × 分析员结论</h4>
  <table class="pilot-table"><thead><tr><th>Agent \\ 关闭结论</th>${resolutions.map(x=>`<th>${escapeHTML((CASE_RESOLUTIONS.find(y=>y[0]===x)||[x,x])[1])}</th>`).join('')}</tr></thead><tbody>${matrix}</tbody></table>
  <p class="prop-hint">对照规则：恶意 ↔ 已处置；无害、误报 ↔ 误报；“需人工判断”和“重复”不计入一致率。统计范围是所选日期内新建的案件，口径见 docs/pilot.md。</p>`;
}

function bindPilotReport(host){
  host.querySelectorAll('[data-open-run]').forEach(b=>b.onclick=()=>{location.hash='#/runs/'+b.dataset.openRun});
  const form=host.querySelector('#pilotForm');if(!form)return;
  form.onsubmit=e=>{e.preventDefault();pilotState.range={from:form.elements.from.value,to:form.elements.to.value};loadCasesView()};
  host.querySelector('[data-pilot-csv]')?.addEventListener('click',()=>{
    const range={from:form.elements.from.value,to:form.elements.to.value};
    window.open(pilotReportQuery(casesProject(),range,'csv'),'_blank','noopener');
  });
}
