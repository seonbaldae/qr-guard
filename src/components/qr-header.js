import { sharedStyles } from '../styles/shared-styles.js';
import { icon } from '../utils/icons.js';

export class QrHeader extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this.shadowRoot.innerHTML = `<style>${sharedStyles}
      :host { border-bottom:1px solid var(--qr-border); background:rgba(255,255,255,.8); }
      header { max-width:1184px; height:84px; padding:0 32px; margin:auto; display:flex; justify-content:space-between; align-items:center; gap:16px; }
      .brand { color:var(--qr-green); background:none; gap:11px; padding:0; font-size:23px; letter-spacing:-1px; font-weight:780; }
      .brand-mark { width:39px; height:42px; display:grid; place-items:center; background:var(--qr-green); color:var(--qr-accent); border-radius:12px 12px 16px 16px; }
      .right { display:flex; align-items:center; gap:22px; }
      .mode { display:flex; align-items:center; gap:7px; color:#657269; font-size:12px; }
      .dot { width:6px; height:6px; border-radius:50%; background:#78a45d; }
      dialog { color:var(--qr-ink); border:1px solid var(--qr-border); border-radius:24px; padding:30px; width:min(90vw,460px); }
      dialog::backdrop { background:#152e2677; }
      h2 { font-size:23px; margin-bottom:18px; }
      dialog p { margin:12px 0; color:var(--qr-muted); }
      dialog .button { width:100%; margin-top:14px; }
      @media(max-width:600px) { header { height:72px; padding:0 20px; } .brand { font-size:21px; } .right { gap:8px; } .mode { font-size:11px; } .help { font-size:12px; padding:8px; } }
    </style><header>
      <button class="brand" aria-label="QR Guard 처음으로"><span class="brand-mark">${icon('shield',27)}</span><span>QR Guard<span style="color:#90a17f">.</span></span></button>
      <div class="right"><span class="mode"><span class="dot"></span><span id="mode">실제 검사 모드</span></span><button class="text-button help">이용 안내 ${icon('info',16)}</button></div>
    </header><dialog aria-labelledby="guide-title"><h2 id="guide-title">열기 전에, 먼저 확인</h2>
      <p>QR 속 URL을 우리 검사 서버에 전달합니다. 검사 전에는 사용자 기기에서 해당 사이트를 열지 않습니다.</p>
      <p>미리보기는 격리 환경에서 촬영한 이미지입니다. 이미지 안의 링크와 입력창은 동작하지 않습니다.</p>
      <p>위협 미탐지는 안전을 보증하지 않습니다. 실제 도메인과 검사 한계를 확인하고 다음 행동을 선택해 주세요.</p>
      <button class="button primary close">확인했어요</button></dialog>`;
    this.shadowRoot.querySelector('.brand').addEventListener('click', () => this.dispatchEvent(new CustomEvent('rescan-request', { bubbles:true, composed:true })));
    this.shadowRoot.querySelector('.help').addEventListener('click', () => this.shadowRoot.querySelector('dialog').showModal());
    this.shadowRoot.querySelector('.close').addEventListener('click', () => this.shadowRoot.querySelector('dialog').close());
  }
  set demo(value) { this.shadowRoot.getElementById('mode').textContent = value ? '데모 체험 모드' : '실제 검사 모드'; }
}
