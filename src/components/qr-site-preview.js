import { sharedStyles } from '../styles/shared-styles.js';
import { icon } from '../utils/icons.js';
import { loadPreviewImage } from '../services/preview-api.js';

export class QrSitePreview extends HTMLElement {
  constructor() {
    super(); this.attachShadow({mode:'open'});
    this.shadowRoot.innerHTML=`<style>${sharedStyles}
      :host { height:100%; }
      section { border:1px solid var(--qr-border); border-radius:19px; overflow:hidden; background:#f1f3ef; height:100%; }
      header { background:#fff; padding:16px 19px; display:flex; justify-content:space-between; align-items:center; gap:8px; border-bottom:1px solid var(--qr-border); }
      h2 { font-size:13px; display:flex; align-items:center; gap:8px; }
      .badge { color:#84907b; font-size:10px; background:#f1f5ed; border-radius:5px; padding:3px 6px; }
      .image-wrap { min-height:320px; display:flex; align-items:flex-start; justify-content:center; padding:20px; position:relative; }
      img { display:block; width:100%; height:auto; max-height:440px; object-fit:contain; object-position:top; border-radius:7px; box-shadow:0 5px 18px #2634210a; background:white; }
      .empty { min-height:310px; display:flex; flex-direction:column; align-items:center; justify-content:center; text-align:center; gap:12px; color:#7f8a78; padding:20px; }
      .empty p { max-width:240px; font-size:12px; }
      .caption { padding:0 20px 17px; display:flex; justify-content:center; align-items:center; gap:6px; color:#7a8574; font-size:10px; }
      @media(max-width:600px) { .image-wrap { min-height:230px; padding:15px; } img { max-height:350px; } }
    </style><section aria-labelledby="preview-title"><header><h2 id="preview-title">${icon('image',16)} 사이트 미리보기</h2><span class="badge">읽기 전용 이미지</span></header><div class="image-wrap"><img hidden alt="격리 환경에서 촬영한 사이트의 정적 미리보기"><div class="empty">${icon('image',36)}<p role="status">제공된 미리보기가 없습니다.<br>검사 근거와 주소를 확인해 주세요.</p></div></div><p class="caption">${icon('lock',12)} 이미지 안의 링크와 입력창은 동작하지 않아요</p></section>`;
    this._generation=0;
    this.shadowRoot.querySelector('img').addEventListener('error',()=>this.showError());
  }
  set result(value) {
    this.cleanup();const generation=this._generation;
    const image=this.shadowRoot.querySelector('img'); image.removeAttribute('src'); image.hidden=true;
    this.shadowRoot.querySelector('.empty').hidden=false;
    this.shadowRoot.querySelector('.empty p').textContent=value?.previewUrl?'미리보기를 불러오고 있어요.':'제공된 미리보기가 없습니다. 검사 근거와 주소를 확인해 주세요.';
    if(value?.previewUrl) {
      const controller=new AbortController();this._controller=controller;
      loadPreviewImage(value.previewUrl,{signal:controller.signal,demo:value.demo}).then(blob=>{
        if(generation!==this._generation||!this.isConnected)return;
        this._objectUrl=URL.createObjectURL(blob);
        image.alt=value.demo?'데모용으로 제작한 사이트 미리보기 이미지':'격리 환경에서 촬영한 사이트의 정적 미리보기';
        image.src=this._objectUrl;image.hidden=false;this.shadowRoot.querySelector('.empty').hidden=true;
      }).catch(()=>{if(generation===this._generation&&!controller.signal.aborted)this.showError();});
    }
    this.shadowRoot.querySelector('h2').lastChild.textContent=value?.demo?' 데모 사이트 미리보기':' 사이트 미리보기';
  }
  showError() {
    this.shadowRoot.querySelector('img').hidden=true;this.shadowRoot.querySelector('.empty').hidden=false;
    this.shadowRoot.querySelector('.empty p').textContent='미리보기를 불러오지 못했어요. 검사 결과와 주소를 확인해 주세요.';
  }
  cleanup() { this._generation+=1;this._controller?.abort();if(this._objectUrl)URL.revokeObjectURL(this._objectUrl);this._objectUrl=null; }
  disconnectedCallback() { this.cleanup(); }
}
