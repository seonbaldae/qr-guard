import { sharedStyles } from '../styles/shared-styles.js';
import { icon } from '../utils/icons.js';
import { validateUrl } from '../utils/url.js';

export class QrScanPage extends HTMLElement {
  constructor() {
    super(); this.attachShadow({ mode:'open' });
    this.shadowRoot.innerHTML = `<style>${sharedStyles}
      .intro { margin:38px 0 34px; display:flex; justify-content:space-between; align-items:flex-end; gap:20px; }
      h1 { font-size:46px; line-height:1.27; letter-spacing:-2px; font-weight:760; margin:13px 0 16px; }
      h1 span { color:var(--qr-green); }
      .description { color:var(--qr-muted); font-size:15px; letter-spacing:-.3px; }
      .top-tag { font-size:11px; white-space:nowrap; display:flex; align-items:center; gap:6px; border:1px solid #dbe5d5; border-radius:30px; padding:8px 13px; color:#617550; margin-bottom:3px; }
      .workspace { display:grid; grid-template-columns:minmax(0,1.2fr) minmax(0,1fr); background:#fff; border:1px solid var(--qr-border); border-radius:24px; overflow:hidden; box-shadow:0 7px 24px #243a2b03; }
      .scan-area { min-width:0; padding:24px; border-right:1px solid var(--qr-border); }
      .section-label { display:flex; align-items:center; justify-content:space-between; margin:0 0 17px; font-size:14px; font-weight:700; }
      .camera-local { color:#7b887d; font-size:10px; display:flex; align-items:center; gap:5px; font-weight:500; }
      .manual { margin-top:22px; }
      label { font-size:12px; font-weight:600; display:block; margin-bottom:9px; }
      .input-row { display:flex; gap:8px; }
      input { min-width:0; flex:1; height:48px; padding:0 14px; background:#fafbf9; border:1px solid #dfe5db; border-radius:10px; color:var(--qr-ink); font-size:13px; }
      input::placeholder { color:#8d968b; } .input-row .button { min-height:48px; border-radius:10px; font-size:12px; padding:10px 15px; }
      .error { min-height:0; font-size:12px; color:var(--qr-danger); margin-top:8px; }
      .error:empty { display:none; }
      .guide { padding:34px 35px; display:flex; flex-direction:column; }
      .guide h2 { font-size:22px; letter-spacing:-.8px; line-height:1.4; margin:8px 0 28px; }
      .guide ol { list-style:none; padding:0; margin:0; display:grid; gap:24px; }
      .guide li { display:grid; grid-template-columns:38px 1fr; gap:13px; }
      .guide-icon { background:#f0f4ed; color:var(--qr-green); width:38px; height:38px; border-radius:12px; display:grid; place-items:center; }
      h3 { font-size:14px; letter-spacing:-.3px; margin:0 0 5px; }
      .guide li p { color:var(--qr-muted); font-size:12px; line-height:1.8; word-break:keep-all; }
      .privacy { margin-top:auto; padding-top:27px; display:flex; gap:9px; align-items:flex-start; color:#7c877b; font-size:11px; }
      .demo-bar { border:1px solid #dfe7d6; border-radius:16px; margin-top:18px; padding:20px 24px; display:flex; align-items:center; justify-content:space-between; gap:15px; background:#f0f4e9; }
      .demo-copy { display:flex; align-items:center; gap:12px; } .demo-copy strong { font-size:13px; } .demo-copy p { font-size:11px; color:#7a856e; margin-top:2px; }
      .spark { font-size:25px; color:#83966d; }
      .demo-actions { display:flex; gap:8px; flex-wrap:wrap; }
      .demo-actions button { border:1px solid #d8e1cc; background:#fff; padding:9px 13px; border-radius:9px; color:#36503e; font-size:12px; min-height:40px; }
      details { margin-top:17px; } summary { cursor:pointer; color:#7b8478; font-size:11px; width:fit-content; }
      .extra { display:flex; flex-wrap:wrap; gap:7px; padding-top:12px; } .extra button { font-size:11px; border:1px solid var(--qr-border); border-radius:8px; background:white; padding:8px 11px; color:var(--qr-muted); }
      @media(max-width:900px) { .intro { margin-top:28px; } h1 { font-size:37px; } .workspace { grid-template-columns:1fr; } .scan-area { border-right:0; } .guide { border-top:1px solid var(--qr-border); padding:25px; } .guide h2 { font-size:20px; margin-bottom:22px; } .guide ol { gap:20px; } .privacy { padding-top:22px; } .top-tag { display:none; } .demo-bar { align-items:flex-start; flex-direction:column; } }
      @media(max-width:450px) { h1 { font-size:33px; letter-spacing:-1.5px; } .description { font-size:13px; word-break:keep-all; } .scan-area { padding:17px; } .workspace { border-radius:19px; } .input-row .button { padding:10px 12px; } .demo-bar { padding:18px; } .demo-actions { width:100%; } .demo-actions button { flex:1; } }
    </style>
    <section aria-labelledby="scan-title"><div class="intro"><div><p class="eyebrow">SCAN SMART. STAY PROTECTED.</p><h1 id="scan-title" tabindex="-1">작은 QR 속,<br><span>안전을 먼저 확인하세요.</span></h1><p class="description">QR 속 링크를 바로 열지 않고, 먼저 확인해 드릴게요.</p></div><span class="top-tag">${icon('shield',14)} 접속 전 한 번 더 확인</span></div>
    <div class="workspace"><div class="scan-area"><div class="section-label"><span>QR 코드 스캔</span><span class="camera-local">${icon('lock',12)} 영상은 기기에만</span></div>
      <qr-camera-scanner></qr-camera-scanner>
      <form class="manual" novalidate><label for="url-input">또는, 링크를 직접 입력하세요</label><div class="input-row"><input id="url-input" name="url" type="url" inputmode="url" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="https://example.com" aria-describedby="url-error"><button class="button primary" type="submit">검사하기 ${icon('arrow',15)}</button></div><p id="url-error" class="error" role="alert"></p></form>
    </div><aside class="guide"><p class="eyebrow">A SAFER WAY TO OPEN</p><h2>낯선 링크 앞에서도,<br>한 번 더 안심할 수 있도록.</h2><ol>
      <li><span class="guide-icon">${icon('qr',19)}</span><div><h3>01 &nbsp; QR 속 주소를 읽어요</h3><p>카메라에 QR을 비춰주세요.<br>아직 연결된 사이트는 열리지 않아요.</p></div></li>
      <li><span class="guide-icon">${icon('search',19)}</span><div><h3>02 &nbsp; 대신 확인해 드려요</h3><p>주소를 검사하고, 격리 환경에서<br>사이트 화면과 위험 신호를 확인해요.</p></div></li>
      <li><span class="guide-icon">${icon('shield',19)}</span><div><h3>03 &nbsp; 결과를 보고 선택하세요</h3><p>미리보기와 검사 근거를 확인한 후<br>다음 행동을 직접 결정하세요.</p></div></li>
    </ol><div class="privacy">${icon('info',15)}<span>어떤 검사도 완전한 안전을 보증할 수 없어요.<br>개인정보 입력 전에는 주소를 다시 확인해 주세요.</span></div></aside></div>
    <div class="demo-bar"><div class="demo-copy"><span class="spark" aria-hidden="true">✳</span><div><strong>카메라 없이 먼저 둘러보세요</strong><p>샘플 결과로 검사 흐름을 체험할 수 있어요. 실제 검사는 아닙니다.</p></div></div><div class="demo-actions"><button data-demo="clear">정상 사이트 체험 ${icon('arrow',13)}</button><button data-demo="phishing">피싱 사이트 체험 ${icon('arrow',13)}</button></div></div>
    <details><summary>다른 데모 상황 보기</summary><div class="extra"><button data-demo="suspicious">사칭 의심</button><button data-demo="inconclusive">확인 불가</button><button data-demo="error">검사 오류</button><button data-demo="no-preview">미리보기 없음</button><button data-demo="report-error">신고 실패</button></div></details></section>`;
    this.shadowRoot.querySelector('form').addEventListener('submit', event => {
      event.preventDefault(); this.submitUrl(this.shadowRoot.querySelector('input').value,'manual');
    });
    this.shadowRoot.querySelector('input').addEventListener('input', () => { this.shadowRoot.getElementById('url-error').textContent=''; this.shadowRoot.querySelector('input').removeAttribute('aria-invalid'); });
    this.shadowRoot.addEventListener('qr-detected', event => { event.stopPropagation(); this.submitUrl(event.detail.value,'camera'); });
    this.shadowRoot.querySelectorAll('[data-demo]').forEach(button => button.addEventListener('click', () => {
      this.shadowRoot.querySelector('qr-camera-scanner').stop();
      this.dispatchEvent(new CustomEvent('demo-request',{detail:{scenario:button.dataset.demo},bubbles:true,composed:true}));
    }));
  }
  submitUrl(raw,source) {
    try {
      const url=validateUrl(raw);
      this.shadowRoot.querySelector('qr-camera-scanner').stop();
      this.dispatchEvent(new CustomEvent('scan-request',{detail:{url,source},bubbles:true,composed:true}));
    } catch(error) {
      this.shadowRoot.getElementById('url-error').textContent=error.message;
      const input=this.shadowRoot.querySelector('input'); input.setAttribute('aria-invalid','true'); input.focus();
    }
  }
  focusHeading() { this.shadowRoot.querySelector('h1').focus({preventScroll:true}); }
}
