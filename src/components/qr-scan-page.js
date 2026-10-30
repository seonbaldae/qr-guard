import { sharedStyles } from '../styles/shared-styles.js';
import { validateUrl } from '../utils/url.js';

export class QrScanPage extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this.shadowRoot.innerHTML = `<style>${sharedStyles}
      h1 { font-size:28px; font-weight:700; line-height:1.4; letter-spacing:-.8px; }
      .instruction { margin-top:12px; color:var(--qr-muted); font-size:15px; line-height:1.6; word-break:keep-all; }
      qr-camera-scanner { margin-top:32px; }
      details { margin-top:12px; }
      summary { list-style:none; display:flex; align-items:center; justify-content:center; min-height:48px; cursor:pointer; color:#6b7684; font-size:14px; border-radius:12px; }
      summary::-webkit-details-marker { display:none; }
      summary:hover { background:#f9fafb; }
      .manual-entry[open] summary { justify-content:flex-start; font-size:15px; font-weight:600; color:#333d4b; }
      form { margin:8px 0 16px; }
      label { display:block; margin-bottom:10px; font-size:14px; font-weight:500; color:#4e5968; }
      input { width:100%; min-width:0; height:56px; padding:0 16px; border:1px solid transparent; border-radius:14px; color:var(--qr-ink); background:#f2f4f6; font-size:16px; }
      input::placeholder { color:#8b95a1; }
      input[aria-invalid=true] { border-color:var(--qr-danger); }
      form .button { width:100%; margin-top:12px; }
      .error { color:#d52e42; font-size:13px; margin-top:8px; line-height:1.6; }
      .error:empty { display:none; }
      .sample-entry { margin-top:0; }
      .sample-entry>summary { color:#8b95a1; font-size:13px; }
      .samples { display:grid; grid-template-columns:1fr 1fr; gap:8px; padding:4px 0 10px; }
      .samples button { min-height:48px; padding:10px; border-radius:12px; color:#4e5968; background:#f2f4f6; font-size:14px; }
      .other-samples { margin-top:0; } .other-samples summary { font-size:12px; }
      .other-samples .samples { grid-template-columns:1fr 1fr; }
      .other-samples button { font-size:12px; }
    </style>
    <section aria-labelledby="scan-title">
      <h1 id="scan-title" tabindex="-1">QR 코드를<br>스캔해 주세요</h1>
      <p class="instruction">사각형 안에 QR 코드를 맞춰주세요</p>
      <qr-camera-scanner></qr-camera-scanner>
      <details class="manual-entry">
        <summary>주소 직접 입력</summary>
        <form novalidate>
          <label for="url-input">검사할 주소</label>
          <input id="url-input" name="url" type="url" inputmode="url" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="https://" aria-describedby="url-error">
          <p id="url-error" class="error" role="alert"></p>
          <button class="button primary" type="submit">검사하기</button>
        </form>
      </details>
      <details class="sample-entry">
        <summary>샘플로 확인하기</summary>
        <div class="samples"><button data-demo="clear">정상 결과</button><button data-demo="phishing">피싱 결과</button></div>
        <details class="other-samples"><summary>다른 상황 보기</summary><div class="samples"><button data-demo="suspicious">사칭 의심</button><button data-demo="inconclusive">확인 불가</button><button data-demo="error">검사 오류</button><button data-demo="no-preview">미리보기 없음</button><button data-demo="report-error">신고 실패</button></div></details>
      </details>
    </section>`;
    this.shadowRoot.querySelector('form').addEventListener('submit', event => {
      event.preventDefault();
      this.submitUrl(this.shadowRoot.querySelector('input').value, 'manual');
    });
    this.shadowRoot.querySelector('input').addEventListener('input', () => {
      this.shadowRoot.getElementById('url-error').textContent = '';
      this.shadowRoot.querySelector('input').removeAttribute('aria-invalid');
    });
    this.shadowRoot.addEventListener('qr-detected', event => {
      event.stopPropagation();
      this.submitUrl(event.detail.value, 'camera');
    });
    this.shadowRoot.querySelectorAll('[data-demo]').forEach(button => button.addEventListener('click', () => {
      this.shadowRoot.querySelector('qr-camera-scanner').stop();
      this.dispatchEvent(new CustomEvent('demo-request', { detail: { scenario: button.dataset.demo }, bubbles: true, composed: true }));
    }));
  }

  submitUrl(raw, source) {
    try {
      const url = validateUrl(raw);
      this.shadowRoot.querySelector('qr-camera-scanner').stop();
      this.dispatchEvent(new CustomEvent('scan-request', { detail: { url, source }, bubbles: true, composed: true }));
    } catch (error) {
      this.shadowRoot.getElementById('url-error').textContent = error.message;
      this.shadowRoot.querySelector('.manual-entry').open = true;
      const input = this.shadowRoot.querySelector('input');
      input.setAttribute('aria-invalid', 'true');
      input.focus();
    }
  }

  focusHeading() { this.shadowRoot.querySelector('h1').focus({ preventScroll: true }); }
}
