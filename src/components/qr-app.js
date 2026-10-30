import { sharedStyles } from '../styles/shared-styles.js';
import { icon } from '../utils/icons.js';
import { validateUrl } from '../utils/url.js';
import { analyzeUrl } from '../services/scan-api.js';
import { reportSite } from '../services/report-api.js';
import { demoUrls } from '../data/demo-fixtures.js';

export class QrApp extends HTMLElement {
  constructor() {
    super();this.attachShadow({mode:'open'});
    this._generation=0;this._depth='scan';this._mode='live';this._scenario='clear';this._url=null;this._result=null;
    this.shadowRoot.innerHTML=`<style>${sharedStyles}
      :host { min-height:100svh; display:flex; flex-direction:column; }
      main { width:100%; max-width:1184px; margin:0 auto; padding:32px 32px 44px; flex:1; }
      .topline { display:flex; align-items:center; justify-content:space-between; gap:16px; }
      .secure { display:flex; align-items:center; gap:5px; color:#8a9484; font-size:10px; letter-spacing:.015em; }
      .demo-banner { margin-top:24px; padding:11px 15px; display:flex; align-items:center; gap:9px; color:#7d662b; font-size:12px; background:#faf2d9; border:1px solid #e8dcb7; border-radius:10px; }
      footer { border-top:1px solid var(--qr-border); padding:23px 32px; color:#8d9688; background:#f4f6f1; font-size:10px; }
      .footer-inner { max-width:1120px; margin:auto; display:flex; align-items:center; justify-content:space-between; gap:15px; }
      .footer-brand { font-size:12px; font-weight:700; color:#6f7c67; margin-right:12px; letter-spacing:-.4px; }
      .privacy-foot { display:flex; gap:6px; align-items:center; }
      @media(max-width:760px) { main { padding:25px 20px 30px; } .secure { display:none; } .topline { justify-content:center; } footer { padding:22px 20px calc(22px + env(safe-area-inset-bottom,0px)); } .footer-inner { align-items:flex-start; flex-direction:column; gap:9px; } }
    </style><qr-header></qr-header><main id="main"><div class="topline"><qr-progress-steps></qr-progress-steps><span class="secure">${icon('lock',12)} YOUR NEXT CLICK, PROTECTED.</span></div><p class="demo-banner" role="status" hidden>${icon('info',16)}<span>데모 응답 · 실제 검사 아님 — 미리보기와 신고는 샘플 데이터예요.</span></p><div id="page"></div></main><footer><div class="footer-inner"><div><span class="footer-brand">QR Guard.</span>열기 전에, 먼저 확인.</div><span class="privacy-foot">${icon('shield',13)} 카메라 영상은 저장하거나 서버로 보내지 않아요.</span><span>© 2026 QR Guard</span></div></footer>`;
    this.shadowRoot.addEventListener('scan-request',event=>this.startScan(event.detail.url,'live'));
    this.shadowRoot.addEventListener('demo-request',event=>{
      const scenario=event.detail.scenario;
      this.startScan(['phishing','report-error'].includes(scenario)?demoUrls.phishing:demoUrls.clear,'demo',scenario);
    });
    this.shadowRoot.addEventListener('scan-cancel',()=>this.reset());
    this.shadowRoot.addEventListener('rescan-request',()=>this.reset());
    this.shadowRoot.addEventListener('scan-retry',()=>{if(this._url)this.startScan(this._url,this._mode,this._scenario);});
    this.shadowRoot.addEventListener('report-request',()=>this.report());
    this.shadowRoot.addEventListener('open-site-request',()=>this.openSite());
    this._onPopState=()=>this.reset(false);
  }
  connectedCallback() {
    window.addEventListener('popstate',this._onPopState);
    this.reset();
  }
  disconnectedCallback() {
    window.removeEventListener('popstate',this._onPopState);this.abort();
  }
  abort() { this._generation+=1;this._scanController?.abort();this._reportController?.abort();this._reportBusy=false; }
  reset(writeHistory=true) {
    this.abort();this._depth='scan';this._mode='live';this._url=null;this._result=null;this._scenario='clear';
    if(writeHistory) history.replaceState({qrGuardDepth:'scan'},'',location.href);
    this.showPage('qr-scan-page',1);
  }
  showPage(name,step) {
    const page=document.createElement(name);this.shadowRoot.getElementById('page').replaceChildren(page);
    this.shadowRoot.querySelector('qr-progress-steps').step=step;
    this.shadowRoot.querySelector('qr-header').demo=this._mode==='demo';
    this.shadowRoot.querySelector('.demo-banner').hidden=this._mode!=='demo';
    if(name!=='qr-scan-page'||this._hasShownPage) page.focusHeading?.();
    window.scrollTo({top:0,behavior:'auto'});
    this._hasShownPage=true;
    return page;
  }
  async startScan(raw,mode='live',scenario='clear') {
    let url;
    try { url=validateUrl(raw); } catch { return; }
    if(this._depth==='loading'&&this._scanController&&!this._scanController.signal.aborted&&!this._scanFailed)return;
    const previousDepth=this._depth;this.abort();
    const generation=this._generation;
    this._url=url;this._mode=mode;this._scenario=scenario;this._result=null;this._scanFailed=false;this._depth='loading';
    if(previousDepth==='scan') history.pushState({qrGuardDepth:'loading'},'',location.href);
    else history.replaceState({qrGuardDepth:'loading'},'',location.href);
    const page=this.showPage('qr-loading-page',2);page.url=url;
    const controller=new AbortController();this._scanController=controller;
    try {
      const result=await analyzeUrl(url,{signal:controller.signal,mode,scenario,onProgress:progress=>{if(generation===this._generation)page.progress=progress;}});
      if(generation!==this._generation||!this.isConnected)return;
      this._result=result;this._depth='result';history.replaceState({qrGuardDepth:'result'},'',location.href);
      const resultPage=this.showPage('qr-result-page',3);resultPage.result=result;
    } catch(error) {
      if(generation!==this._generation||controller.signal.aborted)return;
      this._scanFailed=true;page.error=error.message||'검사 서버와 연결하지 못했어요. 잠시 후 다시 시도해 주세요.';
    } finally { if(generation===this._generation)this._scanController=null; }
  }
  async report() {
    const result=this._result;if(this._depth!=='result'||result?.verdict!=='phishing'||result.reportedByUser||this._reportBusy)return;
    this._reportBusy=true;const generation=this._generation;const controller=new AbortController();this._reportController=controller;
    const page=this.shadowRoot.querySelector('qr-result-page');page.updateReport({...result,busy:true});
    try {
      const response=await reportSite(result,{signal:controller.signal});
      if(generation!==this._generation)return;
      this._result={...result,...response,isReported:true};page.updateReport({...this._result,success:true});
    } catch(error) {
      if(generation!==this._generation||controller.signal.aborted)return;
      page.updateReport({...result,error:error.message||'신고를 접수하지 못했어요. 다시 시도해 주세요.'});
    } finally { if(generation===this._generation){this._reportBusy=false;this._reportController=null;} }
  }
  openSite() {
    const result=this._result;
    if(this._depth!=='result'||result?.demo||result?.status!=='completed'||result?.verdict!=='clear')return;
    try { window.open(validateUrl(result.finalUrl||result.requestedUrl),'_blank','noopener,noreferrer'); } catch { /* Invalid destinations remain closed. */ }
  }
}
