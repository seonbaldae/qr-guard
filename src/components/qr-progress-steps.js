import { sharedStyles } from '../styles/shared-styles.js';
import { icon } from '../utils/icons.js';

export class QrProgressSteps extends HTMLElement {
  constructor() {
    super(); this.attachShadow({ mode:'open' });
    this.shadowRoot.innerHTML = `<style>${sharedStyles}
      ol { list-style:none; display:flex; align-items:center; padding:0; margin:0; gap:20px; }
      li { display:flex; align-items:center; gap:9px; font-size:12px; font-weight:600; color:#90998f; white-space:nowrap; }
      .number { width:25px; height:25px; border:1px solid #dfe5dc; border-radius:50%; display:grid; place-items:center; font-size:10px; }
      [aria-current=step] { color:var(--qr-green); } [aria-current=step] .number { color:#fff; background:var(--qr-green); border-color:var(--qr-green); }
      .done { color:var(--qr-green); } .done .number { background:#e9f0e3; border-color:#e9f0e3; }
      li+li::before { content:''; width:36px; height:1px; background:#dfe5dc; margin-right:11px; }
      @media(max-width:600px) { ol { gap:11px; justify-content:center; } li+li::before { width:16px; margin-right:5px; } li { font-size:11px; gap:6px; } }
    </style><nav aria-label="검사 진행 단계"><ol><li><span class="number">01</span>QR 스캔</li><li><span class="number">02</span>위험 검사</li><li><span class="number">03</span>결과 확인</li></ol></nav>`;
  }
  set step(value) {
    this.shadowRoot.querySelectorAll('li').forEach((item,i) => {
      item.removeAttribute('aria-current'); item.classList.toggle('done',i+1<value);
      const number=item.querySelector('.number');
      number.innerHTML=i+1<value ? icon('check',13) : `0${i+1}`;
      if(i+1===value) item.setAttribute('aria-current','step');
    });
  }
}
