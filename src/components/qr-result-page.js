import { sharedStyles } from '../styles/shared-styles.js';
import { icon } from '../utils/icons.js';
import { displayUrl } from '../utils/url.js';

export class QrResultPage extends HTMLElement {
  constructor() {
    super();this.attachShadow({mode:'open'});
    this.shadowRoot.innerHTML=`<style>${sharedStyles}
      .heading { display:flex; align-items:center; justify-content:space-between; margin:34px 0 23px; gap:12px; }
      h1 { font-size:30px; letter-spacing:-1px; margin-top:6px; }
      .checked { font-size:11px; color:#88917f; }
      .grid { display:grid; grid-template-columns:1.05fr 1fr; gap:23px; margin-top:24px; align-items:stretch; }
      .details { background:white; border:1px solid var(--qr-border); border-radius:19px; padding:24px; }
      .details h2 { font-size:14px; margin-bottom:19px; display:flex; gap:8px; align-items:center; }
      dl { margin:0; } .url-row { padding:12px 0; border-bottom:1px solid #edf0e9; } .url-row:first-child { padding-top:0; }
      dt { font-size:11px; color:#7a8475; margin-bottom:4px; } dd { margin:0; font-size:13px; font-weight:600; overflow-wrap:anywhere; line-height:1.65; }
      .different { color:#9a5a3d; } .small { font-size:10px; color:#8c9485; margin:9px 0 23px; }
      .reports { background:#fcf3ee; border:1px solid #f0e1d8; padding:14px; border-radius:11px; margin-top:18px; }
      .reports p { font-size:12px; color:#976452; } .reports strong { font-size:22px; color:#a84836; margin-right:3px; } .report-history { font-size:10px!important; margin-top:4px; }
      .signals { list-style:none; padding:0; margin:0; display:grid; gap:12px; }
      .signals li { display:grid; grid-template-columns:19px 1fr; gap:7px; font-size:12px; color:#5f6d59; line-height:1.7; }
      .signals .source { display:block; font-size:10px; color:#8b9384; margin-top:3px; }
      .limits { margin-top:22px; padding-top:18px; border-top:1px solid var(--qr-border); }
      summary { cursor:pointer; font-size:12px; font-weight:650; color:#6c785f; }
      .limits ul { padding-left:18px; font-size:11px; color:#7f8875; line-height:1.8; margin-bottom:0; }
      .evidence { margin-top:17px; } .evidence ul { padding-left:17px; font-size:11px; color:#75826c; line-height:1.8; } .evidence li { margin-top:8px; } .evidence .source { display:block; font-size:10px; color:#89927f; }
      .providers { font-size:10px; color:#7f8976; line-height:1.9; margin-top:15px; }
      .action-area { padding:23px 0 3px; text-align:center; }
      .destination { font-size:11px; color:#7a8572; overflow-wrap:anywhere; margin-bottom:13px; }
      .actions { display:flex; justify-content:center; gap:10px; }
      .actions .button { min-width:190px; }
      .danger { background:#a74235; color:white; } .danger:hover:not(:disabled) { background:#8c3329; }
      .report-status { font-size:12px; color:var(--qr-green); margin:13px 0 0; min-height:20px; }
      .report-status.error { color:var(--qr-danger); }
      .demo-open { font-size:11px; color:#8b7861; margin-bottom:12px; }
      @media(max-width:760px) { .grid { grid-template-columns:1fr; } .heading { margin-top:27px; } .checked { display:none; } h1 { font-size:27px; } .actions .button { min-width:0; flex:1; max-width:260px; padding:13px 14px; } .action-area { padding-bottom:env(safe-area-inset-bottom,0px); } }
    </style><section aria-labelledby="result-title"><div class="heading"><div><p class="eyebrow">YOUR SCAN REPORT</p><h1 id="result-title" tabindex="-1">검사 결과를 확인하세요</h1></div><span class="checked"></span></div>
      <qr-verdict-summary></qr-verdict-summary>
      <div class="grid"><qr-site-preview></qr-site-preview><div class="details"><h2>${icon('globe',17)} 연결 주소 확인</h2><dl><div class="url-row"><dt>원래 QR 주소</dt><dd id="requested"></dd></div><div class="url-row"><dt>실제 도착 주소</dt><dd id="final"></dd></div></dl><p class="small">주소에 포함된 쿼리와 해시는 개인정보 보호를 위해 표시하지 않아요.</p>
      <h2>${icon('shield',17)} 검사에서 확인한 내용</h2><ul class="signals"></ul><details class="evidence" hidden><summary>관찰 근거 자세히 보기</summary><ul></ul></details><div class="providers" hidden></div><div class="reports" hidden><p>이 사이트의 신고 건수 &nbsp;<strong id="report-count"></strong><span id="count-unit">건</span></p><p class="report-history"></p></div><details class="limits" open><summary>검사 범위와 한계</summary><ul></ul></details></div></div>
      <div class="action-area"><p class="destination" hidden></p><p class="demo-open" hidden>데모에서는 실제 사이트 이동이 비활성화되어 있어요.</p><div class="actions"><button class="button primary main-action"></button><button class="button secondary rescan">${icon('refresh',17)} 다시 스캔하기</button></div><p class="report-status" role="status" aria-live="polite"></p></div>
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
    const list=this.shadowRoot.querySelector('.signals');list.replaceChildren();
    const signals=value.signals?.length?value.signals:[{summary:'추가로 제공된 검사 근거가 없습니다.',source:''}];
    for(const signal of signals) {
      const li=document.createElement('li');const mark=document.createElement('span');mark.innerHTML=icon(value.verdict==='clear'?'check':'info',15);
      const content=document.createElement('span');content.textContent=signal.summary;
      if(signal.source) { const source=document.createElement('span');source.className='source';source.textContent=`출처: ${signal.source}`;content.append(source); }
      if(signal.evidenceIds?.length) { const ids=document.createElement('span');ids.className='source';ids.textContent=`근거: ${signal.evidenceIds.join(', ')}`;content.append(ids); }
      li.append(mark,content);list.append(li);
    }
    const evidenceSection=this.shadowRoot.querySelector('.evidence');const evidenceList=evidenceSection.querySelector('ul');evidenceList.replaceChildren();evidenceSection.hidden=!value.evidence?.length;
    for(const evidence of value.evidence||[]) {
      const li=document.createElement('li');li.textContent=evidence.summary;
      const source=document.createElement('span');source.className='source';
      source.textContent=[evidence.id,evidence.source,evidence.observedAt?new Date(evidence.observedAt).toLocaleString('ko-KR'):''].filter(Boolean).join(' · ');
      li.append(source);evidenceList.append(li);
    }
    const providers=this.shadowRoot.querySelector('.providers');providers.replaceChildren();providers.hidden=!value.providers?.length;
    for(const provider of value.providers||[]) {
      const p=document.createElement('p');const label={checked:'조회 완료',failed:'조회 실패',stale:'갱신 필요'}[provider.status]||'확인 불가';
      p.textContent=`${provider.name} · ${label}${provider.matched===true?' · 목록 일치':provider.matched===false?' · 목록 미일치':''}${provider.checkedAt?` · ${new Date(provider.checkedAt).toLocaleString('ko-KR')}`:''}`;providers.append(p);
    }
    const limits=this.shadowRoot.querySelector('.limits ul');limits.replaceChildren();
    for(const limitation of [...(value.limitations||[]),'위협 미탐지는 완전한 안전이나 공식 사이트 인증을 의미하지 않습니다.']) { const li=document.createElement('li');li.textContent=limitation;limits.append(li); }
    const date=value.checkedAt?new Date(value.checkedAt):null;this.shadowRoot.querySelector('.checked').textContent=!date||Number.isNaN(date.getTime())?'':`${date.toLocaleTimeString('ko-KR',{hour:'2-digit',minute:'2-digit'})} 검사 결과`;
    const button=this.shadowRoot.querySelector('.main-action');const destination=this.shadowRoot.querySelector('.destination');
    button.classList.toggle('danger',value.verdict==='phishing');
    button.disabled=false;destination.hidden=true;this.shadowRoot.querySelector('.demo-open').hidden=true;
    if(value.verdict==='clear') {
      button.innerHTML=`사이트 들어가기 ${icon('external',16)}`;
      destination.hidden=false;destination.textContent=`이동할 주소 · ${displayUrl(value.finalUrl||value.requestedUrl)}`;
      if(value.demo) { button.disabled=true;this.shadowRoot.querySelector('.demo-open').hidden=false; }
    } else if(value.verdict==='phishing') button.innerHTML=`${icon('flag',16)} 신고하기`;
    else button.innerHTML=`${icon('refresh',16)} 다시 검사`;
    this.shadowRoot.querySelector('.reports').hidden=value.verdict!=='phishing';
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
      button.innerHTML=busy?'신고 중…':reportedByUser?`${icon('check',16)} ${this._result.demo?'모의 신고 완료':'신고 완료'}`:`${icon('flag',16)} ${error?'신고 다시 시도':'신고하기'}`;
    }
  }
  focusHeading() { this.shadowRoot.querySelector('h1').focus({preventScroll:true}); }
}
