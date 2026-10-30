import { sharedStyles } from '../styles/shared-styles.js';
import { icon } from '../utils/icons.js';

const labels={
  clear:{eyebrow:'CHECK COMPLETE',title:'검사 범위 내 위협 미탐지',copy:'확인한 범위에서 위험 신호를 발견하지 못했어요. 주소와 검사 한계를 확인한 후 이동하세요.',icon:'shield'},
  phishing:{eyebrow:'PHISHING DETECTED',title:'피싱 사이트로 판정됐어요',copy:'개인정보가 노출될 위험이 있어요. 이 화면에서는 해당 사이트로 연결하지 않습니다.',icon:'warning'},
  suspicious:{eyebrow:'CAUTION REQUIRED',title:'사칭이 의심되는 사이트예요',copy:'공식 사이트와 비슷한 위험 신호가 있어요. 공식 주소를 직접 확인해 주세요.',icon:'warning'},
  inconclusive:{eyebrow:'UNABLE TO VERIFY',title:'안전 여부를 확인하지 못했어요',copy:'검사가 충분히 완료되지 않았어요. 사이트에 접속하기 전에 다시 확인해 주세요.',icon:'info'},
};
export class QrVerdictSummary extends HTMLElement {
  constructor() {
    super();this.attachShadow({mode:'open'});
    this.shadowRoot.innerHTML=`<style>${sharedStyles}
      .summary { display:flex; gap:19px; align-items:center; padding:26px 28px; border:1px solid #dce6d3; background:#edf4e8; border-radius:19px; }
      .mark { display:grid; place-items:center; flex:none; width:57px; height:63px; background:#dcebcf; border-radius:18px; color:var(--qr-green); }
      .eyebrow { font-size:9px; margin-bottom:5px; }
      h2 { font-size:23px; letter-spacing:-.9px; line-height:1.4; margin-bottom:6px; }
      .copy { font-size:12px; color:#6d7c63; line-height:1.8; word-break:keep-all; }
      .phishing { background:#fcf0ed; border-color:#efd8d2; } .phishing .mark { background:#f7ddd5; color:var(--qr-danger); } .phishing .eyebrow,.phishing h2 { color:#9d3d33; } .phishing .copy { color:#946f65; }
      .suspicious,.inconclusive { background:#faf5e8; border-color:#e9e0c6; } .suspicious .mark,.inconclusive .mark { background:#f1e7cb; color:#8b702c; } .suspicious h2,.inconclusive h2 { color:#80632c; }
      @media(max-width:600px) { .summary { padding:20px; gap:13px; align-items:flex-start; } .mark { width:43px; height:48px; border-radius:13px; } h2 { font-size:20px; } }
    </style><section class="summary"><span class="mark"></span><div><p class="eyebrow"></p><h2></h2><p class="copy"></p></div></section>`;
  }
  set result(value) {
    const verdict=labels[value?.verdict]?value.verdict:'inconclusive'; const text=labels[verdict];
    this.shadowRoot.querySelector('section').className=`summary ${verdict}`;
    this.shadowRoot.querySelector('.mark').innerHTML=icon(text.icon,31);
    this.shadowRoot.querySelector('.eyebrow').textContent=text.eyebrow;
    this.shadowRoot.querySelector('h2').textContent=text.title;
    this.shadowRoot.querySelector('.copy').textContent=text.copy;
  }
}
