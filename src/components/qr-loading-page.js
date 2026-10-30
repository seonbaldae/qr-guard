import { sharedStyles } from '../styles/shared-styles.js';
import { icon } from '../utils/icons.js';
import { getHostname } from '../utils/url.js';

export class QrLoadingPage extends HTMLElement {
  constructor() {
    super(); this.attachShadow({mode:'open'});
    this.shadowRoot.innerHTML=`<style>${sharedStyles}
      section { text-align:center; max-width:720px; margin:44px auto 0; padding:44px 24px; background:#fff; border:1px solid var(--qr-border); border-radius:24px; }
      .orbit { position:relative; width:142px; height:142px; margin:5px auto 30px; display:grid; place-items:center; color:var(--qr-green); }
      .orbit::before { content:''; position:absolute; inset:0; border:1px solid #e2e9dc; border-radius:50%; }
      .orbit::after { content:''; position:absolute; inset:0; border:2px solid transparent; border-top-color:#718d52; border-radius:50%; animation:rotate 2s linear infinite; }
      .center { display:grid; place-items:center; width:100px; height:100px; background:#edf3e8; border-radius:30px; }
      h1 { font-size:29px; letter-spacing:-1px; line-height:1.4; margin-bottom:13px; }
      .host { font-size:13px; color:var(--qr-green); background:#f0f4ed; padding:7px 15px; border-radius:30px; display:inline-block; max-width:100%; overflow-wrap:anywhere; }
      .status { margin:24px 0 8px; color:var(--qr-muted); font-size:14px; }
      .note { color:#899184; font-size:12px; word-break:keep-all; }
      .actions { margin-top:32px; display:flex; justify-content:center; gap:10px; flex-wrap:wrap; }
      .error .orbit { color:var(--qr-danger); } .error .center { background:#fcf0ed; } .error .orbit::after { display:none; }
      @keyframes rotate { to { transform:rotate(360deg); } }
      @media(max-width:600px) { section { padding:34px 19px; margin-top:26px; } h1 { font-size:25px; } }
    </style><section aria-labelledby="loading-title" aria-busy="true"><div class="orbit" aria-hidden="true"><span class="center">${icon('shield',48)}</span></div><h1 id="loading-title" tabindex="-1">사이트를 검사하고 있어요</h1><p class="host"></p><p class="status" role="status">검사 서버의 응답을 기다리고 있어요.</p><p class="note">아직 이 기기에서 사이트를 열지 않았어요.<br>검사가 끝나면 결과를 확인할 수 있어요.</p><div class="actions"><button class="button primary retry" hidden>다시 검사 ${icon('refresh',17)}</button><button class="button secondary cancel">검사 취소</button></div></section>`;
    this.shadowRoot.querySelector('.cancel').addEventListener('click',()=>this.dispatchEvent(new CustomEvent('scan-cancel',{bubbles:true,composed:true})));
    this.shadowRoot.querySelector('.retry').addEventListener('click',()=>this.dispatchEvent(new CustomEvent('scan-retry',{bubbles:true,composed:true})));
  }
  set url(value) { this.shadowRoot.querySelector('.host').textContent=getHostname(value); }
  set progress(value) { if(value?.message) this.shadowRoot.querySelector('.status').textContent=value.message; }
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
