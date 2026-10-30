import { sharedStyles } from '../styles/shared-styles.js';
import { getHostname } from '../utils/url.js';

export class QrLoadingPage extends HTMLElement {
  constructor() {
    super(); this.attachShadow({mode:'open'});
    this.shadowRoot.innerHTML=`<style>${sharedStyles}
      section { min-height:calc(100svh - 80px); display:flex; flex-direction:column; padding:80px 0 8px; }
      .spinner { width:40px; height:40px; border:4px solid #e8f3ff; border-top-color:var(--qr-primary,#3182f6); border-radius:50%; animation:rotate 1s linear infinite; margin-bottom:28px; }
      h1 { font-size:28px; font-weight:750; letter-spacing:-.8px; line-height:1.4; margin-bottom:16px; word-break:keep-all; }
      .host { font-size:17px; color:#4e5968; overflow-wrap:anywhere; }
      .status { margin:10px 0 0; color:#8b95a1; font-size:14px; }
      .status:empty { display:none; }
      .scope { margin-top:14px; color:#6b7684; font-size:14px; line-height:1.6; word-break:keep-all; }
      .note { display:none; font-size:14px; color:#6b7684; margin-top:14px; }
      .actions { margin-top:auto; padding-top:56px; display:grid; gap:10px; }
      .actions .button { width:100%; min-height:56px; border-radius:16px; font-size:17px; }
      .error .spinner { animation:none; border-color:#f04452; border-width:0; position:relative; background:#fff0f0; }
      .error .spinner::after { content:'!'; color:#f04452; position:absolute; inset:0; display:grid; place-items:center; font-size:27px; font-weight:700; }
      .error .note { display:block; }
      @keyframes rotate { to { transform:rotate(360deg); } }
    </style><section aria-labelledby="loading-title" aria-busy="true"><div class="spinner" aria-hidden="true"></div><h1 id="loading-title" tabindex="-1">사이트를 검사하고 있어요</h1><p class="host"></p><p class="status" role="status"></p><p class="scope" hidden>지금은 주소만 검사해요. 사이트 화면은 확인하지 않아요.</p><p class="note"></p><div class="actions"><button class="button primary retry" hidden>다시 검사</button><button class="button secondary cancel">검사 취소</button></div></section>`;
    this.shadowRoot.querySelector('.cancel').addEventListener('click',()=>this.dispatchEvent(new CustomEvent('scan-cancel',{bubbles:true,composed:true})));
    this.shadowRoot.querySelector('.retry').addEventListener('click',()=>this.dispatchEvent(new CustomEvent('scan-retry',{bubbles:true,composed:true})));
  }
  set url(value) { this.shadowRoot.querySelector('.host').textContent=getHostname(value); }
  set analysisScope(value) {
    this.shadowRoot.querySelector('.scope').hidden=value!=='static';
    this.shadowRoot.querySelector('h1').textContent=value==='static'?'주소를 검사하고 있어요':'사이트를 검사하고 있어요';
  }
  set progress(value) {
    if(value?.message) this.shadowRoot.querySelector('.status').textContent=value.message===this.shadowRoot.querySelector('h1').textContent?'':value.message;
  }
  set error(value) {
    const section=this.shadowRoot.querySelector('section'); section.classList.add('error'); section.setAttribute('aria-busy','false');
    this.shadowRoot.querySelector('h1').textContent='검사를 완료하지 못했어요';
    this.shadowRoot.querySelector('.status').textContent=value;
    this.shadowRoot.querySelector('.status').setAttribute('role','alert');
    this.shadowRoot.querySelector('.note').textContent='안전 여부는 확인되지 않았어요. 다시 검사하거나 다른 QR을 스캔해 주세요.';
    this.shadowRoot.querySelector('.retry').hidden=false; this.shadowRoot.querySelector('.cancel').textContent='다시 스캔하기';
    this.focusHeading();
  }
  focusHeading() { this.shadowRoot.querySelector('h1').focus({preventScroll:true}); }
}
