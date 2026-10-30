import { sharedStyles } from '../styles/shared-styles.js';
import { icon } from '../utils/icons.js';

const labels={
  clear:{title:'검사 범위 내 위협 미탐지',copy:'사이트 주소를 확인한 뒤 이동해 주세요.',icon:'check'},
  phishing:{title:'피싱 사이트로 판정됐어요',copy:'이 사이트에 개인정보를 입력하지 마세요.',icon:'warning'},
  suspicious:{title:'사칭이 의심되는 사이트예요',copy:'접속하기 전에 공식 주소를 확인해 주세요.',icon:'warning'},
  inconclusive:{title:'안전 여부를 확인하지 못했어요',copy:'접속하기 전에 다시 검사해 주세요.',icon:'info'},
};
export class QrVerdictSummary extends HTMLElement {
  constructor() {
    super();this.attachShadow({mode:'open'});
    this.shadowRoot.innerHTML=`<style>${sharedStyles}
      .summary { padding:12px 0 28px; }
      .mark { display:grid; place-items:center; width:52px; height:52px; margin-bottom:19px; border-radius:50%; background:#e8f3ff; color:var(--qr-primary,#3182f6); }
      h2 { font-size:26px; font-weight:750; letter-spacing:-.8px; line-height:1.4; margin-bottom:10px; word-break:keep-all; }
      .copy { font-size:15px; color:#6b7684; line-height:1.6; word-break:keep-all; }
      .phishing .mark { color:#f04452; background:#fff0f0; }
      .suspicious .mark { color:#d98a00; background:#fff6df; }
      .inconclusive .mark { color:#8b95a1; background:#f2f4f6; }
    </style><section class="summary"><span class="mark"></span><h2></h2><p class="copy"></p></section>`;
  }
  set result(value) {
    const verdict=labels[value?.verdict]?value.verdict:'inconclusive'; const text=labels[verdict];
    this.shadowRoot.querySelector('section').className=`summary ${verdict}`;
    this.shadowRoot.querySelector('.mark').innerHTML=icon(text.icon,31);
    this.shadowRoot.querySelector('h2').textContent=text.title;
    this.shadowRoot.querySelector('.copy').textContent=text.copy;
  }
}
