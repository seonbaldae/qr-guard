import { sharedStyles } from '../styles/shared-styles.js';
import { validateUrl } from '../utils/url.js';
import { analyzeUrl } from '../services/scan-api.js';
import { reportSite } from '../services/report-api.js';
import { demoUrls } from '../data/demo-fixtures.js';
import { urlVerdictDemoResponse } from '../data/url-verdict-demo.js';
import { frontendConfig } from '../config.js';

export class QrApp extends HTMLElement {
  constructor() {
    super();this.attachShadow({mode:'open'});
    this._generation=0;this._depth='scan';this._mode='live';this._source='qr';this._scenario='clear';this._url=null;this._result=null;this._urlDemo=false;
    this.shadowRoot.innerHTML=`<style>${sharedStyles}
      :host { min-height:100svh; display:block; background:#fff; }
      main { width:100%; max-width:480px; min-height:100svh; margin:0 auto; padding:max(36px,env(safe-area-inset-top)) 24px max(24px,env(safe-area-inset-bottom)); }
      .demo-banner { margin:0 0 22px; color:#8b95a1; font-size:12px; line-height:1.5; }
    </style><main id="main"><p class="demo-banner" role="status" hidden>데모 응답 · 실제 검사 아님</p><div id="page"></div></main>`;
    this.shadowRoot.addEventListener('scan-request',event=>this.startScan(event.detail.url,'live','clear',event.detail.source==='manual'?'manual':'qr'));
    this.shadowRoot.addEventListener('demo-request',event=>{
      const scenario=event.detail.scenario;
      this.startScan(['phishing','report-error'].includes(scenario)?demoUrls.phishing:demoUrls.clear,'demo',scenario);
    });
    this.shadowRoot.addEventListener('scan-cancel',()=>this.reset());
    this.shadowRoot.addEventListener('rescan-request',()=>this.reset());
    this.shadowRoot.addEventListener('scan-retry',()=>{if(this._url)this.startScan(this._url,this._mode,this._scenario,this._source);});
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
    this.abort();this._depth='scan';this._mode='live';this._source='qr';this._url=null;this._result=null;this._scenario='clear';this._urlDemo=false;
    if(writeHistory) history.replaceState({qrGuardDepth:'scan'},'',location.href);
    this.showPage('qr-scan-page');
  }
  showPage(name) {
    const page=document.createElement(name);this.shadowRoot.getElementById('page').replaceChildren(page);
    this.shadowRoot.querySelector('.demo-banner').hidden=this._mode!=='demo'&&!this._urlDemo;
    if(name!=='qr-scan-page'||this._hasShownPage) page.focusHeading?.();
    window.scrollTo({top:0,behavior:'auto'});
    this._hasShownPage=true;
    return page;
  }
  async startScan(raw,mode='live',scenario='clear',source='qr') {
    let url;
    try { url=validateUrl(raw); } catch { return; }
    if(this._depth==='loading'&&this._scanController&&!this._scanController.signal.aborted&&!this._scanFailed)return;
    const previousDepth=this._depth;this.abort();
    const generation=this._generation;
    this._url=url;this._mode=mode;this._source=source;this._scenario=scenario;this._result=null;this._scanFailed=false;this._depth='loading';
    this._urlDemo=mode==='live'&&Boolean(urlVerdictDemoResponse(url));
    if(previousDepth==='scan') history.pushState({qrGuardDepth:'loading'},'',location.href);
    else history.replaceState({qrGuardDepth:'loading'},'',location.href);
    const page=this.showPage('qr-loading-page');page.url=url;page.analysisScope=mode==='live'&&!this._urlDemo?frontendConfig.scanMode:null;
    const controller=new AbortController();this._scanController=controller;
    try {
      const result=await analyzeUrl(url,{signal:controller.signal,mode,source,scenario,onProgress:progress=>{if(generation===this._generation)page.progress=progress;}});
      if(generation!==this._generation||!this.isConnected)return;
      this._result=result;this._depth='result';history.replaceState({qrGuardDepth:'result'},'',location.href);
      const resultPage=this.showPage('qr-result-page');resultPage.result=result;
    } catch(error) {
      if(generation!==this._generation||controller.signal.aborted)return;
      this._scanFailed=true;page.error=error.message||'검사 서버와 연결하지 못했어요. 잠시 후 다시 시도해 주세요.';
    } finally { if(generation===this._generation)this._scanController=null; }
  }
  async report() {
    const result=this._result;if(this._depth!=='result'||result?.verdict!=='phishing'||result.reportAvailable===false||result.reportedByUser||this._reportBusy)return;
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
