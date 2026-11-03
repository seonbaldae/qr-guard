import { sharedStyles } from '../styles/shared-styles.js';
import { icon } from '../utils/icons.js';
import { displayUrl } from '../utils/url.js';

export class QrResultPage extends HTMLElement {
  constructor() {
    super();this.attachShadow({mode:'open'});
    this.shadowRoot.innerHTML=`<style>${sharedStyles}
      .heading { margin:0 0 22px; }
      h1 { font-size:18px; font-weight:650; color:#4e5968; letter-spacing:-.4px; }
      .grid { display:grid; grid-template-columns:1fr; gap:28px; }
      .details h2 { font-size:16px; font-weight:650; margin-bottom:16px; }
      dl { margin:0; } .url-row { padding:12px 0; } .url-row:first-child { padding-top:0; }
      dt { font-size:13px; color:#8b95a1; margin-bottom:5px; } dd { margin:0; font-size:15px; font-weight:550; overflow-wrap:anywhere; line-height:1.6; color:#333d4b; }
      .reports { background:#f2f4f6; padding:18px; border-radius:16px; margin-top:24px; }
      .reports p { font-size:14px; color:#4e5968; } .reports strong { font-size:23px; color:#f04452; margin-right:3px; } .report-history,.report-scope { font-size:12px!important; color:#8b95a1!important; margin-top:5px; }
      .signals-block { margin-top:24px; }
      .decision-reasons { margin-top:24px; }
      .decision-reasons ul { padding-left:18px; margin:0; font-size:14px; color:#4e5968; line-height:1.65; }
      .decision-reasons .references { font-size:12px; color:#8b95a1; margin-top:8px; overflow-wrap:anywhere; }
      .signals { list-style:none; padding:0; margin:0; display:grid; gap:12px; }
      .signals li { display:grid; grid-template-columns:19px 1fr; gap:7px; font-size:14px; color:#4e5968; line-height:1.65; }
      .signals .source { display:none; }
      .signals li:nth-child(n+3) { display:none; }
      .limits { margin-top:24px; padding-top:20px; border-top:1px solid #f2f4f6; }
      summary { cursor:pointer; font-size:14px; font-weight:550; color:#6b7684; }
      .limits ul { padding-left:18px; font-size:13px; color:#8b95a1; line-height:1.7; margin-bottom:0; }
      .signal-details { margin-top:18px; } .signal-details li { margin-top:10px; } .signal-details .source { display:block; font-size:12px; color:#8b95a1; }
      .evidence { margin-top:20px; } .evidence h3 { font-size:13px; color:#6b7684; font-weight:550; } .evidence li { margin-top:10px; } .evidence .source { display:block; font-size:12px; color:#8b95a1; }
      .providers { font-size:12px; color:#8b95a1; line-height:1.8; margin-top:20px; }
      .action-area { position:sticky; bottom:0; background:#fff; padding:24px 0 calc(8px + env(safe-area-inset-bottom,0px)); margin-top:12px; }
      .destination { font-size:12px; color:#8b95a1; overflow-wrap:anywhere; margin-bottom:12px; }
      .actions { display:grid; gap:8px; }
      .actions .button { width:100%; min-height:56px; border-radius:16px; font-size:17px; }
      .actions .rescan { min-height:50px; background:#f2f4f6; color:#4e5968; border:0; }
      .report-status { font-size:13px; color:var(--qr-primary,#3182f6); margin:12px 0 0; }
      .report-status:empty { display:none; }
      .report-status.error { color:var(--qr-danger); }
      .demo-open { font-size:12px; color:#8b95a1; margin-bottom:12px; }
    </style><section aria-labelledby="result-title"><div class="heading"><h1 id="result-title" tabindex="-1">검사 결과</h1></div>
      <qr-verdict-summary></qr-verdict-summary>
      <div class="grid"><qr-site-preview></qr-site-preview><div class="details"><dl><div class="url-row"><dt>원래 QR 주소</dt><dd id="requested"></dd></div><div class="url-row"><dt>실제 도착 주소</dt><dd id="final"></dd></div></dl>
      <div class="reports" hidden><p>신고된 횟수 &nbsp;<strong id="report-count"></strong><span id="count-unit">건</span></p><p class="report-scope">현재 서버에 접수된 신고예요</p><p class="report-history"></p></div><section class="decision-reasons" hidden><h2>판정 이유</h2><ul></ul><p class="references" hidden></p></section><div class="signals-block"><h2>확인한 내용</h2><ul class="signals"></ul></div><details class="limits"><summary>검사 상세</summary><ul class="limitations"></ul><ul class="signal-details" hidden></ul><div class="evidence" hidden><h3>관찰 근거</h3><ul></ul></div><div class="providers" hidden></div></details></div></div>
      <div class="action-area"><p class="destination" hidden></p><p class="demo-open" hidden>데모에서는 사이트를 열 수 없어요</p><div class="actions"><button class="button primary main-action"></button><button class="button secondary rescan">다시 스캔하기</button></div><p class="report-status" role="status" aria-live="polite"></p></div>
    </section>`;
    this.shadowRoot.querySelector('.rescan').addEventListener('click',()=>this.emit('rescan-request'));
    this.shadowRoot.querySelector('.main-action').addEventListener('click',()=>{
      if(this._result?.verdict==='clear') this.emit('open-site-request');
      else if(this._result?.verdict==='phishing') this.emit('report-request');
      else this.emit('scan-retry');
    });
  }
  emit(name) { this.dispatchEvent(new CustomEvent(name,{bubbles:true,composed:true})); }
  set result(value) {
    this._result=value;
    this.shadowRoot.querySelector('qr-verdict-summary').result=value;
    this.shadowRoot.querySelector('qr-site-preview').result=value;
    this.shadowRoot.getElementById('requested').textContent=displayUrl(value.requestedUrl);
    this.shadowRoot.getElementById('final').textContent=value.finalUrl?displayUrl(value.finalUrl):'최종 목적지 미확인';
    const reasons=this.shadowRoot.querySelector('.decision-reasons');const reasonsList=reasons.querySelector('ul');reasonsList.replaceChildren();reasons.hidden=!value.reasons?.length;
    for(const reason of value.reasons||[]) { const li=document.createElement('li');li.textContent=reason;reasonsList.append(li); }
    const linkedEvidence=(value.evidence||[]).filter(item=>value.verdictEvidenceIds?.includes(item.id));
    const referenceSummaries=[...new Set(linkedEvidence.map(item=>item.summary||item.source).filter(Boolean))].slice(0,2);
    const references=reasons.querySelector('.references');references.hidden=!referenceSummaries.length;references.textContent=referenceSummaries.length?`근거: ${referenceSummaries.join(' · ')}`:'';
    const list=this.shadowRoot.querySelector('.signals');list.replaceChildren();
    const signals=value.signals||[];
    this.shadowRoot.querySelector('.signals-block').hidden=!signals.length;
    const signalDetails=this.shadowRoot.querySelector('.signal-details');signalDetails.replaceChildren();signalDetails.hidden=!signals.length;
    for(const signal of signals) {
      const li=document.createElement('li');const mark=document.createElement('span');mark.innerHTML=icon(value.verdict==='clear'?'check':'info',15);
      const content=document.createElement('span');content.textContent=signal.summary;
      if(signal.source) { const source=document.createElement('span');source.className='source';source.textContent=`출처: ${signal.source}`;content.append(source); }
      if(signal.evidenceIds?.length) { const ids=document.createElement('span');ids.className='source';ids.textContent=`근거: ${signal.evidenceIds.join(', ')}`;content.append(ids); }
      li.append(mark,content);list.append(li);
      const detail=document.createElement('li');detail.textContent=signal.summary;
      const attribution=document.createElement('span');attribution.className='source';attribution.textContent=[signal.source,signal.evidenceIds?.length?`근거: ${signal.evidenceIds.join(', ')}`:''].filter(Boolean).join(' · ');
      detail.append(attribution);signalDetails.append(detail);
    }
    const evidenceSection=this.shadowRoot.querySelector('.evidence');const evidenceList=evidenceSection.querySelector('ul');evidenceList.replaceChildren();evidenceSection.hidden=!value.evidence?.length;
    for(const evidence of value.evidence||[]) {
      const li=document.createElement('li');li.textContent=evidence.summary;
      const source=document.createElement('span');source.className='source';
      source.textContent=[evidence.id,evidence.source].filter(Boolean).join(' · ');
      li.append(source);evidenceList.append(li);
    }
    const providers=this.shadowRoot.querySelector('.providers');providers.replaceChildren();providers.hidden=!value.providers?.length;
    for(const provider of value.providers||[]) {
      const p=document.createElement('p');const label={checked:'조회 완료',failed:'조회 실패',stale:'갱신 필요'}[provider.status]||'확인 불가';
      p.textContent=`${provider.name} · ${label}${provider.matched===true?' · 목록 일치':provider.matched===false?' · 목록 미일치':''}`;providers.append(p);
    }
    const limits=this.shadowRoot.querySelector('.limits ul');limits.replaceChildren();
    for(const limitation of [...(value.limitations||[]),'위협 미탐지는 완전한 안전이나 공식 사이트 인증을 의미하지 않습니다.']) { const li=document.createElement('li');li.textContent=limitation;limits.append(li); }
    const button=this.shadowRoot.querySelector('.main-action');const destination=this.shadowRoot.querySelector('.destination');
    button.disabled=false;destination.hidden=true;this.shadowRoot.querySelector('.demo-open').hidden=true;
    if(value.verdict==='clear') {
      button.textContent='사이트 들어가기';
      destination.hidden=false;destination.textContent=`이동할 주소 · ${displayUrl(value.finalUrl||value.requestedUrl)}`;
      if(value.demo) { button.disabled=true;this.shadowRoot.querySelector('.demo-open').hidden=false; }
    } else if(value.verdict==='phishing') button.textContent='신고하기';
    else button.textContent='다시 검사';
    this.shadowRoot.querySelector('.reports').hidden=value.verdict!=='phishing';
    this.shadowRoot.querySelector('.report-scope').textContent=value.reportAvailable===false?'신고 기능을 준비하고 있어요':value.demo?'데모용 신고 건수예요':'현재 서버에 접수된 신고예요';
    this.updateReport({reportCount:value.reportCount,reportedByUser:value.reportedByUser});
  }
  updateReport({reportCount,reportedByUser=false,busy=false,error='',success=false}) {
    if(success)this._result={...this._result,reportCount,reportedByUser,isReported:true};
    const count=this.shadowRoot.getElementById('report-count');count.textContent=Number.isInteger(reportCount)?reportCount.toLocaleString('ko-KR'):'확인 불가';
    this.shadowRoot.getElementById('count-unit').hidden=!Number.isInteger(reportCount);
    this.shadowRoot.querySelector('.report-history').textContent=this._result?.isReported===true?'이전에 신고된 이력이 있는 사이트예요.':this._result?.isReported===false?'현재 제공된 신고 이력은 없어요.':'신고 이력 여부를 확인할 수 없어요.';
    const status=this.shadowRoot.querySelector('.report-status');status.classList.toggle('error',Boolean(error));
    status.textContent=error||(success?(this._result.demo?'모의 신고가 완료됐어요. 실제 신고는 접수되지 않았습니다.':'신고가 접수됐어요. 확인에 도움을 주셔서 감사합니다.'):'');
    if(this._result?.verdict==='phishing') {
      const button=this.shadowRoot.querySelector('.main-action');button.disabled=busy||reportedByUser;
      if(this._result.reportAvailable===false) { button.disabled=true;button.textContent='신고 기능 준비 중'; }
      else button.textContent=busy?'신고 중…':reportedByUser?(this._result.demo?'모의 신고 완료':'신고 완료'):(error?'신고 다시 시도':'신고하기');
    }
  }
  focusHeading() { this.shadowRoot.querySelector('h1').focus({preventScroll:true}); }
}
